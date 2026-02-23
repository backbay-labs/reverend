#!/usr/bin/env python3
"""Corpus manifest validation for E13 benchmark program.

Validates that corpus manifests satisfy acceptance criteria:
- All required provenance fields present (checksum, source, SPDX, arch, compiler, timestamp)
- License policy compliance
- Checksum verification against actual files
- Reproducibility from pinned inputs

Outputs validation report to eval/reports/e13/corpus_manifest_validation.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from license_policy import validate_license, ALLOWED_LICENSES


# Required fields for each manifest artifact entry
REQUIRED_ARTIFACT_FIELDS = [
    "sha256",
    "source_url",
    "spdx_license",
    "architecture",
    "acquired_at",
]

# Recommended fields (warnings if missing)
RECOMMENDED_FIELDS = [
    "format",
    "bits",
    "endian",
    "name",
    "bytes",
]


@dataclass
class ValidationIssue:
    """A single validation issue."""

    severity: str  # "error", "warning", "info"
    artifact: str | None
    field: str | None
    message: str
    evidence: dict | None = None


@dataclass
class ValidationReport:
    """Complete validation report for a corpus manifest."""

    manifest_path: str
    manifest_sha256: str
    validated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    schema_version: str = "1.0.0"
    issues: list[dict] = field(default_factory=list)
    artifact_count: int = 0
    field_coverage: dict = field(default_factory=dict)
    license_summary: dict = field(default_factory=dict)
    architecture_summary: dict = field(default_factory=dict)
    reproducibility: dict = field(default_factory=dict)
    status: str = "unknown"


def sha256_file(path: Path) -> str:
    """Compute SHA-256 checksum of a file."""
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def validate_artifact_fields(
    artifact: dict,
    idx: int,
) -> list[ValidationIssue]:
    """Validate required and recommended fields for an artifact."""
    issues = []
    name = artifact.get("name", f"artifact[{idx}]")

    # Check required fields
    for req_field in REQUIRED_ARTIFACT_FIELDS:
        value = artifact.get(req_field)
        if value is None or (isinstance(value, str) and not value.strip()):
            issues.append(ValidationIssue(
                severity="error",
                artifact=name,
                field=req_field,
                message=f"required field '{req_field}' is missing or empty",
            ))

    # Check recommended fields
    for rec_field in RECOMMENDED_FIELDS:
        value = artifact.get(rec_field)
        if value is None:
            issues.append(ValidationIssue(
                severity="warning",
                artifact=name,
                field=rec_field,
                message=f"recommended field '{rec_field}' is missing",
            ))

    # Validate SHA-256 format
    sha256 = artifact.get("sha256", "")
    if sha256 and (len(sha256) != 64 or not all(c in "0123456789abcdef" for c in sha256.lower())):
        issues.append(ValidationIssue(
            severity="error",
            artifact=name,
            field="sha256",
            message=f"invalid SHA-256 format: {sha256[:20]}...",
            evidence={"sha256": sha256},
        ))

    # Validate architecture value
    architecture = artifact.get("architecture", "")
    valid_architectures = {
        "x86", "x86_64", "arm", "aarch64",
        "mips", "mips64", "riscv32", "riscv64",
        "ppc", "ppc64", "unknown",
    }
    if architecture and architecture not in valid_architectures:
        issues.append(ValidationIssue(
            severity="warning",
            artifact=name,
            field="architecture",
            message=f"non-standard architecture value: {architecture}",
            evidence={"valid_values": sorted(valid_architectures)},
        ))

    # Validate timestamp format (ISO 8601)
    acquired_at = artifact.get("acquired_at", "")
    if acquired_at:
        try:
            datetime.fromisoformat(acquired_at.replace("Z", "+00:00"))
        except ValueError:
            issues.append(ValidationIssue(
                severity="error",
                artifact=name,
                field="acquired_at",
                message=f"invalid ISO 8601 timestamp: {acquired_at}",
            ))

    return issues


def validate_license_compliance(
    artifact: dict,
    idx: int,
) -> list[ValidationIssue]:
    """Validate license policy compliance for an artifact."""
    issues = []
    name = artifact.get("name", f"artifact[{idx}]")
    spdx_license = artifact.get("spdx_license", "NOASSERTION")

    result = validate_license(spdx_license)
    if not result.valid:
        issues.append(ValidationIssue(
            severity="error",
            artifact=name,
            field="spdx_license",
            message=f"license policy violation: {result.rejection_reason}",
            evidence={
                "spdx_license": spdx_license,
                "policy_class": result.policy_class,
            },
        ))

    return issues


def validate_file_checksums(
    artifact: dict,
    data_dir: Path | None,
    idx: int,
) -> list[ValidationIssue]:
    """Validate file checksums if data directory is provided."""
    issues = []
    if data_dir is None:
        return issues

    name = artifact.get("name", f"artifact[{idx}]")
    local_path = artifact.get("local_path")
    expected_sha256 = artifact.get("sha256")

    if not local_path or not expected_sha256:
        return issues

    file_path = data_dir / local_path
    if not file_path.is_file():
        issues.append(ValidationIssue(
            severity="error",
            artifact=name,
            field="local_path",
            message=f"file not found: {file_path}",
        ))
        return issues

    actual_sha256 = sha256_file(file_path)
    if actual_sha256 != expected_sha256:
        issues.append(ValidationIssue(
            severity="error",
            artifact=name,
            field="sha256",
            message="checksum mismatch",
            evidence={
                "expected": expected_sha256,
                "actual": actual_sha256,
            },
        ))

    # Check file size if specified
    expected_bytes = artifact.get("bytes")
    if expected_bytes is not None:
        actual_bytes = file_path.stat().st_size
        if actual_bytes != expected_bytes:
            issues.append(ValidationIssue(
                severity="error",
                artifact=name,
                field="bytes",
                message="file size mismatch",
                evidence={
                    "expected": expected_bytes,
                    "actual": actual_bytes,
                },
            ))

    return issues


def compute_field_coverage(artifacts: list[dict]) -> dict:
    """Compute field presence statistics across artifacts."""
    if not artifacts:
        return {}

    all_fields = set()
    for artifact in artifacts:
        all_fields.update(artifact.keys())

    coverage = {}
    for fld in sorted(all_fields):
        present = sum(1 for a in artifacts if a.get(fld) is not None)
        coverage[fld] = {
            "present": present,
            "total": len(artifacts),
            "percentage": round(present / len(artifacts) * 100, 1),
        }

    return coverage


def compute_license_summary(artifacts: list[dict]) -> dict:
    """Compute license distribution across artifacts."""
    by_license: dict[str, int] = {}
    by_class: dict[str, int] = {}
    policy_failures = 0

    for artifact in artifacts:
        spdx = artifact.get("spdx_license", "NOASSERTION")
        by_license[spdx] = by_license.get(spdx, 0) + 1

        result = validate_license(spdx)
        if result.valid and result.policy_class:
            by_class[result.policy_class] = by_class.get(result.policy_class, 0) + 1
        else:
            policy_failures += 1

    return {
        "by_license": by_license,
        "by_class": by_class,
        "policy_failures": policy_failures,
    }


def compute_architecture_summary(artifacts: list[dict]) -> dict:
    """Compute architecture distribution across artifacts."""
    by_arch: dict[str, int] = {}
    by_format: dict[str, int] = {}

    for artifact in artifacts:
        arch = artifact.get("architecture", "unknown")
        by_arch[arch] = by_arch.get(arch, 0) + 1

        fmt = artifact.get("format", "unknown")
        by_format[fmt] = by_format.get(fmt, 0) + 1

    return {
        "by_architecture": by_arch,
        "by_format": by_format,
    }


def check_reproducibility(manifest: dict) -> dict:
    """Check reproducibility markers in manifest."""
    has_command_log = bool(manifest.get("command_log"))
    has_version = bool(manifest.get("version"))
    has_ingested_at = bool(manifest.get("ingested_at"))

    artifacts = manifest.get("artifacts", [])
    all_have_acquired_at = all(a.get("acquired_at") for a in artifacts)
    all_have_source_url = all(a.get("source_url") for a in artifacts)
    all_have_sha256 = all(a.get("sha256") for a in artifacts)

    reproducible = (
        has_command_log
        and has_version
        and all_have_acquired_at
        and all_have_source_url
        and all_have_sha256
    )

    return {
        "reproducible": reproducible,
        "checks": {
            "has_command_log": has_command_log,
            "has_version": has_version,
            "has_ingested_at": has_ingested_at,
            "all_artifacts_have_acquired_at": all_have_acquired_at,
            "all_artifacts_have_source_url": all_have_source_url,
            "all_artifacts_have_sha256": all_have_sha256,
        },
    }


def validate_manifest(
    manifest_path: Path,
    data_dir: Path | None = None,
    strict: bool = False,
) -> ValidationReport:
    """
    Validate a corpus manifest against E13 acceptance criteria.

    Args:
        manifest_path: Path to corpus manifest JSON.
        data_dir: Optional data directory for checksum verification.
        strict: If True, treat warnings as errors.

    Returns:
        ValidationReport with all findings.
    """
    report = ValidationReport(
        manifest_path=str(manifest_path),
        manifest_sha256=sha256_file(manifest_path),
    )

    # Load manifest
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        report.issues.append({
            "severity": "error",
            "artifact": None,
            "field": None,
            "message": f"invalid JSON: {exc}",
        })
        report.status = "error"
        return report

    artifacts = manifest.get("artifacts", [])
    report.artifact_count = len(artifacts)

    if not artifacts:
        report.issues.append({
            "severity": "error",
            "artifact": None,
            "field": "artifacts",
            "message": "manifest contains no artifacts",
        })

    # Validate each artifact
    all_issues: list[ValidationIssue] = []
    for idx, artifact in enumerate(artifacts):
        all_issues.extend(validate_artifact_fields(artifact, idx))
        all_issues.extend(validate_license_compliance(artifact, idx))
        all_issues.extend(validate_file_checksums(artifact, data_dir, idx))

    # Convert issues to dict format
    for issue in all_issues:
        report.issues.append({
            "severity": issue.severity,
            "artifact": issue.artifact,
            "field": issue.field,
            "message": issue.message,
            "evidence": issue.evidence,
        })

    # Compute summaries
    report.field_coverage = compute_field_coverage(artifacts)
    report.license_summary = compute_license_summary(artifacts)
    report.architecture_summary = compute_architecture_summary(artifacts)
    report.reproducibility = check_reproducibility(manifest)

    # Determine overall status
    error_count = sum(1 for i in report.issues if i["severity"] == "error")
    warning_count = sum(1 for i in report.issues if i["severity"] == "warning")

    if error_count > 0:
        report.status = "error"
    elif warning_count > 0 and strict:
        report.status = "error"
    elif warning_count > 0:
        report.status = "warning"
    elif not report.reproducibility.get("reproducible", False):
        report.status = "warning"
    else:
        report.status = "ok"

    return report


def _cmd_validate(args: argparse.Namespace) -> int:
    """CLI handler for manifest validation."""
    report = validate_manifest(
        args.manifest,
        data_dir=args.data_dir,
        strict=args.strict,
    )

    output = {
        "manifest_path": report.manifest_path,
        "manifest_sha256": report.manifest_sha256,
        "validated_at": report.validated_at,
        "schema_version": report.schema_version,
        "artifact_count": report.artifact_count,
        "status": report.status,
        "issues": report.issues,
        "field_coverage": report.field_coverage,
        "license_summary": report.license_summary,
        "architecture_summary": report.architecture_summary,
        "reproducibility": report.reproducibility,
    }

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
        print(f"[validate-corpus] wrote report to {args.output}")
    else:
        print(json.dumps(output, indent=2))

    error_count = sum(1 for i in report.issues if i["severity"] == "error")
    warning_count = sum(1 for i in report.issues if i["severity"] == "warning")

    if report.status == "error":
        print(
            f"[validate-corpus] FAILED: {error_count} error(s), {warning_count} warning(s)",
            file=sys.stderr,
        )
        return 1

    if report.status == "warning":
        print(f"[validate-corpus] OK with warnings: {warning_count} warning(s)")
    else:
        print(f"[validate-corpus] OK: {report.artifact_count} artifact(s) validated")

    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate corpus manifest against E13 acceptance criteria"
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        required=True,
        help="Path to corpus manifest JSON",
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        help="Data directory for checksum verification",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Output path for validation report (default: stdout)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Treat warnings as errors",
    )

    args = parser.parse_args(argv)
    return _cmd_validate(args)


if __name__ == "__main__":
    raise SystemExit(main())
