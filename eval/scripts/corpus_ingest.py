#!/usr/bin/env python3
"""OSS binary corpus ingestion with provenance manifesting.

This module provides deterministic ingestion for OSS binaries with locked
provenance and license policy enforcement. Emits manifest rows with:
- sha256 checksum
- source URL
- SPDX license
- architecture
- compiler metadata
- acquisition timestamp

Usage:
    # Ingest from a source manifest
    python corpus_ingest.py ingest --source sources.json --output manifest.json

    # Verify an existing manifest
    python corpus_ingest.py verify --manifest manifest.json --data-dir ./binaries

    # Generate lockfile entry from manifest
    python corpus_ingest.py lock --manifest manifest.json --output lockfile_entry.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from license_policy import validate_license, LicenseValidationResult


@dataclass
class BinaryMetadata:
    """Metadata extracted from a binary artifact."""

    architecture: str
    bits: int | None = None
    endian: str | None = None
    format: str | None = None
    compiler: str | None = None
    compiler_version: str | None = None
    stripped: bool | None = None
    dynamic: bool | None = None


@dataclass
class ManifestEntry:
    """A single entry in the corpus manifest."""

    # Required provenance fields
    sha256: str
    source_url: str
    spdx_license: str
    acquired_at: str

    # Binary metadata
    architecture: str
    format: str | None = None
    bits: int | None = None
    endian: str | None = None
    compiler: str | None = None
    compiler_version: str | None = None
    stripped: bool | None = None
    dynamic: bool | None = None

    # Optional fields
    name: str | None = None
    version: str | None = None
    bytes: int | None = None
    local_path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in self.__dict__.items() if v is not None}


@dataclass
class IngestReport:
    """Report from corpus ingestion run."""

    version: str = "1.0.0"
    ingested_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    artifacts: list[dict] = field(default_factory=list)
    license_failures: list[dict] = field(default_factory=list)
    errors: list[dict] = field(default_factory=list)
    command_log: list[str] = field(default_factory=list)
    summary: dict = field(default_factory=dict)


def sha256_file(path: Path) -> str:
    """Compute SHA-256 checksum of a file."""
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def extract_binary_metadata(path: Path) -> BinaryMetadata:
    """
    Extract architecture and compiler metadata from a binary.

    Uses `file` command for format detection and `readelf`/`objdump` for
    detailed metadata extraction on ELF binaries.
    """
    architecture = "unknown"
    bits = None
    endian = None
    fmt = None
    compiler = None
    compiler_version = None
    stripped = None
    dynamic = None

    # Use file command for basic detection
    try:
        result = subprocess.run(
            ["file", "-b", str(path)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        file_output = result.stdout.strip()

        # Parse architecture from file output
        if "x86-64" in file_output or "x86_64" in file_output:
            architecture = "x86_64"
            bits = 64
        elif "x86" in file_output or "i386" in file_output or "i686" in file_output:
            architecture = "x86"
            bits = 32
        elif "aarch64" in file_output or "ARM64" in file_output:
            architecture = "aarch64"
            bits = 64
        elif "ARM" in file_output:
            architecture = "arm"
            bits = 32
        elif "MIPS64" in file_output:
            architecture = "mips64"
            bits = 64
        elif "MIPS" in file_output:
            architecture = "mips"
            bits = 32
        elif "RISC-V" in file_output:
            architecture = "riscv64" if "64" in file_output else "riscv32"
            bits = 64 if "64" in file_output else 32
        elif "PowerPC64" in file_output or "ppc64" in file_output:
            architecture = "ppc64"
            bits = 64
        elif "PowerPC" in file_output or "ppc" in file_output:
            architecture = "ppc"
            bits = 32

        # Parse endianness
        if "LSB" in file_output:
            endian = "little"
        elif "MSB" in file_output:
            endian = "big"

        # Parse format
        if "ELF" in file_output:
            fmt = "ELF"
        elif "PE32+" in file_output:
            fmt = "PE64"
        elif "PE32" in file_output:
            fmt = "PE32"
        elif "Mach-O" in file_output:
            fmt = "Mach-O"

        # Check stripped status
        stripped = "not stripped" not in file_output.lower() and "with debug" not in file_output.lower()

        # Check dynamic linking
        dynamic = "dynamically linked" in file_output.lower()

    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # Try readelf for ELF binaries to get compiler info
    if fmt == "ELF":
        try:
            result = subprocess.run(
                ["readelf", "-p", ".comment", str(path)],
                capture_output=True,
                text=True,
                timeout=30,
            )
            comment = result.stdout

            # Extract GCC version
            gcc_match = re.search(r"GCC[:\s]+[^)]*\)?\s*(\d+\.\d+(?:\.\d+)?)", comment, re.IGNORECASE)
            if gcc_match:
                compiler = "GCC"
                compiler_version = gcc_match.group(1)
            else:
                # Try clang
                clang_match = re.search(r"clang[:\s]+version\s+(\d+\.\d+(?:\.\d+)?)", comment, re.IGNORECASE)
                if clang_match:
                    compiler = "clang"
                    compiler_version = clang_match.group(1)

        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

    return BinaryMetadata(
        architecture=architecture,
        bits=bits,
        endian=endian,
        format=fmt,
        compiler=compiler,
        compiler_version=compiler_version,
        stripped=stripped,
        dynamic=dynamic,
    )


def download_artifact(
    url: str,
    dest_dir: Path,
    expected_sha256: str | None = None,
) -> tuple[Path, str]:
    """
    Download an artifact from URL to destination directory.

    Args:
        url: Source URL.
        dest_dir: Destination directory.
        expected_sha256: Expected SHA-256 checksum (optional).

    Returns:
        Tuple of (local_path, sha256).

    Raises:
        ValueError: If checksum verification fails.
    """
    parsed = urlparse(url)
    filename = Path(parsed.path).name or "artifact"
    dest_path = dest_dir / filename

    # Use curl for download
    result = subprocess.run(
        ["curl", "-fsSL", "-o", str(dest_path), url],
        capture_output=True,
        text=True,
        timeout=300,
    )
    if result.returncode != 0:
        raise ValueError(f"download failed: {result.stderr}")

    actual_sha256 = sha256_file(dest_path)

    if expected_sha256 and actual_sha256 != expected_sha256:
        dest_path.unlink()
        raise ValueError(
            f"checksum mismatch: expected {expected_sha256}, got {actual_sha256}"
        )

    return dest_path, actual_sha256


def ingest_from_source(
    source_path: Path,
    output_dir: Path,
    enforce_license: bool = True,
) -> IngestReport:
    """
    Ingest binaries from a source manifest.

    Source manifest format:
    {
        "sources": [
            {
                "url": "https://example.com/binary.elf",
                "sha256": "abc123...",
                "spdx_license": "MIT",
                "name": "example",
                "version": "1.0.0"
            }
        ]
    }

    Args:
        source_path: Path to source manifest JSON.
        output_dir: Directory to store downloaded binaries.
        enforce_license: Whether to reject unlicensed artifacts.

    Returns:
        IngestReport with results and command log.
    """
    report = IngestReport()
    report.command_log.append(f"ingest --source {source_path} --output-dir {output_dir}")

    try:
        sources = json.loads(source_path.read_text(encoding="utf-8"))
    except Exception as exc:
        report.errors.append({
            "phase": "load_sources",
            "error": str(exc),
        })
        return report

    source_list = sources.get("sources", [])
    output_dir.mkdir(parents=True, exist_ok=True)

    for idx, src in enumerate(source_list):
        url = src.get("url", "")
        expected_sha256 = src.get("sha256")
        spdx_license = src.get("spdx_license", "NOASSERTION")
        name = src.get("name", f"artifact_{idx}")
        version = src.get("version")

        # Validate license first
        license_result = validate_license(spdx_license)
        if not license_result.valid:
            report.license_failures.append({
                "name": name,
                "url": url,
                "spdx_license": spdx_license,
                "rejection_reason": license_result.rejection_reason,
            })
            if enforce_license:
                continue

        # Download artifact
        try:
            local_path, actual_sha256 = download_artifact(
                url, output_dir, expected_sha256
            )
        except ValueError as exc:
            report.errors.append({
                "phase": "download",
                "name": name,
                "url": url,
                "error": str(exc),
            })
            continue
        except Exception as exc:
            report.errors.append({
                "phase": "download",
                "name": name,
                "url": url,
                "error": f"unexpected error: {exc}",
            })
            continue

        # Extract metadata
        metadata = extract_binary_metadata(local_path)

        # Create manifest entry
        entry = ManifestEntry(
            sha256=actual_sha256,
            source_url=url,
            spdx_license=spdx_license,
            acquired_at=datetime.now(timezone.utc).isoformat(),
            architecture=metadata.architecture,
            format=metadata.format,
            bits=metadata.bits,
            endian=metadata.endian,
            compiler=metadata.compiler,
            compiler_version=metadata.compiler_version,
            stripped=metadata.stripped,
            dynamic=metadata.dynamic,
            name=name,
            version=version,
            bytes=local_path.stat().st_size,
            local_path=str(local_path.relative_to(output_dir)),
        )
        report.artifacts.append(entry.to_dict())

    report.summary = {
        "total_sources": len(source_list),
        "ingested": len(report.artifacts),
        "license_rejected": len(report.license_failures),
        "errors": len(report.errors),
    }

    return report


def ingest_from_directory(
    input_dir: Path,
    license_info: dict[str, str] | None = None,
    source_base_url: str | None = None,
) -> IngestReport:
    """
    Ingest binaries from a local directory.

    Args:
        input_dir: Directory containing binary files.
        license_info: Mapping of filename to SPDX license.
        source_base_url: Base URL for source attribution.

    Returns:
        IngestReport with results.
    """
    report = IngestReport()
    report.command_log.append(f"ingest-dir --input {input_dir}")

    if license_info is None:
        license_info = {}

    for path in sorted(input_dir.iterdir()):
        if not path.is_file():
            continue

        name = path.name
        spdx_license = license_info.get(name, "NOASSERTION")
        source_url = f"{source_base_url}/{name}" if source_base_url else f"file://{path.resolve()}"

        # Validate license
        license_result = validate_license(spdx_license)
        if not license_result.valid:
            report.license_failures.append({
                "name": name,
                "spdx_license": spdx_license,
                "rejection_reason": license_result.rejection_reason,
            })
            # Continue anyway for local files, just record the failure

        # Extract metadata
        metadata = extract_binary_metadata(path)

        entry = ManifestEntry(
            sha256=sha256_file(path),
            source_url=source_url,
            spdx_license=spdx_license,
            acquired_at=datetime.now(timezone.utc).isoformat(),
            architecture=metadata.architecture,
            format=metadata.format,
            bits=metadata.bits,
            endian=metadata.endian,
            compiler=metadata.compiler,
            compiler_version=metadata.compiler_version,
            stripped=metadata.stripped,
            dynamic=metadata.dynamic,
            name=name,
            bytes=path.stat().st_size,
            local_path=name,
        )
        report.artifacts.append(entry.to_dict())

    report.summary = {
        "total_files": len(report.artifacts) + len(report.license_failures),
        "ingested": len(report.artifacts),
        "license_warnings": len(report.license_failures),
        "errors": len(report.errors),
    }

    return report


def verify_manifest(manifest_path: Path, data_dir: Path) -> dict:
    """
    Verify an existing manifest against local files.

    Args:
        manifest_path: Path to manifest JSON.
        data_dir: Directory containing binary files.

    Returns:
        Verification report with pass/fail status per artifact.
    """
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    artifacts = manifest.get("artifacts", [])

    results = []
    passed = 0
    failed = 0

    for artifact in artifacts:
        local_path = artifact.get("local_path")
        expected_sha256 = artifact.get("sha256")

        if not local_path or not expected_sha256:
            results.append({
                "name": artifact.get("name", "unknown"),
                "status": "error",
                "reason": "missing local_path or sha256",
            })
            failed += 1
            continue

        file_path = data_dir / local_path
        if not file_path.is_file():
            results.append({
                "name": artifact.get("name", local_path),
                "status": "missing",
                "reason": f"file not found: {file_path}",
            })
            failed += 1
            continue

        actual_sha256 = sha256_file(file_path)
        if actual_sha256 != expected_sha256:
            results.append({
                "name": artifact.get("name", local_path),
                "status": "mismatch",
                "expected": expected_sha256,
                "actual": actual_sha256,
            })
            failed += 1
        else:
            results.append({
                "name": artifact.get("name", local_path),
                "status": "ok",
            })
            passed += 1

    return {
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "manifest_path": str(manifest_path),
        "data_dir": str(data_dir),
        "results": results,
        "summary": {
            "total": len(artifacts),
            "passed": passed,
            "failed": failed,
        },
    }


def generate_lockfile_entry(manifest_path: Path, dataset_name: str) -> dict:
    """
    Generate a lockfile entry from a manifest.

    Args:
        manifest_path: Path to corpus manifest.
        dataset_name: Name for the dataset entry.

    Returns:
        Lockfile entry dict compatible with datasets.lock.json schema.
    """
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    artifacts = manifest.get("artifacts", [])

    files = {}
    for artifact in artifacts:
        local_path = artifact.get("local_path")
        if local_path:
            files[local_path] = {
                "bytes": artifact.get("bytes", 0),
                "sha256": artifact.get("sha256"),
                "spdx_license": artifact.get("spdx_license"),
                "architecture": artifact.get("architecture"),
                "source_url": artifact.get("source_url"),
                "acquired_at": artifact.get("acquired_at"),
            }
            if artifact.get("compiler"):
                files[local_path]["compiler"] = artifact.get("compiler")
            if artifact.get("compiler_version"):
                files[local_path]["compiler_version"] = artifact.get("compiler_version")

    return {
        dataset_name: {
            "version": manifest.get("version", "1.0.0"),
            "kind": "oss_binary_corpus",
            "source": {
                "type": "local_directory",
                "path": f"datasets/registry/{dataset_name}",
            },
            "provenance": {
                "manifest_sha256": sha256_file(manifest_path),
                "ingested_at": manifest.get("ingested_at"),
                "command_log": manifest.get("command_log", []),
            },
            "files": files,
        }
    }


def _cmd_ingest(args: argparse.Namespace) -> int:
    """CLI handler for ingestion."""
    if args.source:
        report = ingest_from_source(
            args.source,
            args.output_dir or Path("datasets/data/corpus"),
            enforce_license=not args.no_enforce_license,
        )
    elif args.input_dir:
        report = ingest_from_directory(
            args.input_dir,
            source_base_url=args.source_base_url,
        )
    else:
        print("[corpus-ingest] ERROR: must specify --source or --input-dir", file=sys.stderr)
        return 2

    output = {
        "version": report.version,
        "ingested_at": report.ingested_at,
        "artifacts": report.artifacts,
        "license_failures": report.license_failures,
        "errors": report.errors,
        "command_log": report.command_log,
        "summary": report.summary,
    }

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
        print(f"[corpus-ingest] wrote manifest to {args.output}")
    else:
        print(json.dumps(output, indent=2))

    if report.license_failures and not args.no_enforce_license:
        print(
            f"[corpus-ingest] WARNING: {len(report.license_failures)} artifact(s) rejected due to license policy",
            file=sys.stderr,
        )

    if report.errors:
        print(
            f"[corpus-ingest] ERROR: {len(report.errors)} artifact(s) failed to ingest",
            file=sys.stderr,
        )
        return 1

    print(f"[corpus-ingest] OK: {report.summary.get('ingested', 0)} artifact(s) ingested")
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    """CLI handler for verification."""
    result = verify_manifest(args.manifest, args.data_dir)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(f"[corpus-ingest] wrote verification report to {args.output}")
    else:
        print(json.dumps(result, indent=2))

    if result["summary"]["failed"] > 0:
        print(
            f"[corpus-ingest] FAILED: {result['summary']['failed']}/{result['summary']['total']} verification failures",
            file=sys.stderr,
        )
        return 1

    print(f"[corpus-ingest] OK: {result['summary']['passed']}/{result['summary']['total']} verified")
    return 0


def _cmd_lock(args: argparse.Namespace) -> int:
    """CLI handler for lockfile generation."""
    entry = generate_lockfile_entry(args.manifest, args.dataset_name)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(entry, indent=2) + "\n", encoding="utf-8")
        print(f"[corpus-ingest] wrote lockfile entry to {args.output}")
    else:
        print(json.dumps(entry, indent=2))

    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="OSS binary corpus ingestion with provenance manifesting"
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # ingest command
    ingest_parser = subparsers.add_parser("ingest", help="Ingest binaries into corpus")
    ingest_group = ingest_parser.add_mutually_exclusive_group()
    ingest_group.add_argument(
        "--source",
        type=Path,
        help="Path to source manifest JSON (for URL-based ingestion)",
    )
    ingest_group.add_argument(
        "--input-dir",
        type=Path,
        help="Directory containing binaries (for local ingestion)",
    )
    ingest_parser.add_argument(
        "--output-dir",
        type=Path,
        help="Output directory for downloaded binaries",
    )
    ingest_parser.add_argument(
        "--output",
        type=Path,
        help="Output path for manifest JSON",
    )
    ingest_parser.add_argument(
        "--source-base-url",
        help="Base URL for source attribution (local ingestion)",
    )
    ingest_parser.add_argument(
        "--no-enforce-license",
        action="store_true",
        help="Don't reject artifacts with invalid licenses",
    )
    ingest_parser.set_defaults(func=_cmd_ingest)

    # verify command
    verify_parser = subparsers.add_parser("verify", help="Verify manifest against local files")
    verify_parser.add_argument(
        "--manifest",
        type=Path,
        required=True,
        help="Path to corpus manifest JSON",
    )
    verify_parser.add_argument(
        "--data-dir",
        type=Path,
        required=True,
        help="Directory containing binary files",
    )
    verify_parser.add_argument(
        "--output",
        type=Path,
        help="Output path for verification report",
    )
    verify_parser.set_defaults(func=_cmd_verify)

    # lock command
    lock_parser = subparsers.add_parser("lock", help="Generate lockfile entry from manifest")
    lock_parser.add_argument(
        "--manifest",
        type=Path,
        required=True,
        help="Path to corpus manifest JSON",
    )
    lock_parser.add_argument(
        "--dataset-name",
        required=True,
        help="Name for the dataset entry",
    )
    lock_parser.add_argument(
        "--output",
        type=Path,
        help="Output path for lockfile entry JSON",
    )
    lock_parser.set_defaults(func=_cmd_lock)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
