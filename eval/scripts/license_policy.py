#!/usr/bin/env python3
"""License policy enforcement for OSS binary corpus ingestion.

This module defines allowed SPDX license classes and provides validation
that rejects unsupported/unknown licenses with explicit failure evidence.
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

# Allowed SPDX license identifiers organized by policy class
# Reference: https://spdx.org/licenses/
ALLOWED_LICENSES: dict[str, list[str]] = {
    "permissive": [
        "MIT",
        "Apache-2.0",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "ISC",
        "Zlib",
        "Unlicense",
        "CC0-1.0",
        "0BSD",
        "BSL-1.0",
    ],
    "copyleft_weak": [
        "LGPL-2.0-only",
        "LGPL-2.0-or-later",
        "LGPL-2.1-only",
        "LGPL-2.1-or-later",
        "LGPL-3.0-only",
        "LGPL-3.0-or-later",
        "MPL-2.0",
        "EPL-1.0",
        "EPL-2.0",
    ],
    "copyleft_strong": [
        "GPL-2.0-only",
        "GPL-2.0-or-later",
        "GPL-3.0-only",
        "GPL-3.0-or-later",
        "AGPL-3.0-only",
        "AGPL-3.0-or-later",
    ],
    "public_domain": [
        "CC0-1.0",
        "Unlicense",
        "WTFPL",
    ],
}

# Default policy: which license classes are allowed for corpus inclusion
DEFAULT_ALLOWED_CLASSES: set[str] = {"permissive", "copyleft_weak", "copyleft_strong", "public_domain"}

# Explicitly rejected patterns (regardless of policy class)
REJECTED_PATTERNS: list[str] = [
    "proprietary",
    "commercial",
    "unknown",
    "NOASSERTION",
]


@dataclass
class LicenseValidationResult:
    """Result of license validation for a single artifact."""

    spdx_id: str
    valid: bool
    policy_class: str | None = None
    rejection_reason: str | None = None
    evaluated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class LicensePolicyReport:
    """Aggregated license policy validation report."""

    policy_version: str = "1.0.0"
    allowed_classes: list[str] = field(default_factory=list)
    results: list[dict] = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    evaluated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


def normalize_spdx_id(spdx_id: str) -> str:
    """Normalize SPDX identifier for comparison."""
    return spdx_id.strip()


def get_license_class(spdx_id: str) -> str | None:
    """Return the policy class for a given SPDX identifier, or None if unknown."""
    normalized = normalize_spdx_id(spdx_id)
    for policy_class, licenses in ALLOWED_LICENSES.items():
        if normalized in licenses:
            return policy_class
    return None


def is_rejected_pattern(spdx_id: str) -> tuple[bool, str | None]:
    """Check if the SPDX ID matches a rejected pattern."""
    normalized = normalize_spdx_id(spdx_id).lower()
    for pattern in REJECTED_PATTERNS:
        if pattern.lower() in normalized:
            return True, f"matches rejected pattern: {pattern}"
    return False, None


def validate_license(
    spdx_id: str,
    allowed_classes: set[str] | None = None,
) -> LicenseValidationResult:
    """
    Validate a single SPDX license identifier against policy.

    Args:
        spdx_id: SPDX license identifier to validate.
        allowed_classes: Set of allowed policy classes. Defaults to DEFAULT_ALLOWED_CLASSES.

    Returns:
        LicenseValidationResult with validation outcome and evidence.
    """
    if allowed_classes is None:
        allowed_classes = DEFAULT_ALLOWED_CLASSES

    normalized = normalize_spdx_id(spdx_id)

    # Check for rejected patterns first
    rejected, reason = is_rejected_pattern(normalized)
    if rejected:
        return LicenseValidationResult(
            spdx_id=normalized,
            valid=False,
            policy_class=None,
            rejection_reason=reason,
        )

    # Check for known license class
    policy_class = get_license_class(normalized)
    if policy_class is None:
        return LicenseValidationResult(
            spdx_id=normalized,
            valid=False,
            policy_class=None,
            rejection_reason=f"unknown SPDX identifier: {normalized}",
        )

    # Check if class is allowed
    if policy_class not in allowed_classes:
        return LicenseValidationResult(
            spdx_id=normalized,
            valid=False,
            policy_class=policy_class,
            rejection_reason=f"license class '{policy_class}' not in allowed classes: {sorted(allowed_classes)}",
        )

    return LicenseValidationResult(
        spdx_id=normalized,
        valid=True,
        policy_class=policy_class,
        rejection_reason=None,
    )


def validate_licenses(
    spdx_ids: list[str],
    allowed_classes: set[str] | None = None,
) -> LicensePolicyReport:
    """
    Validate multiple SPDX license identifiers against policy.

    Args:
        spdx_ids: List of SPDX identifiers to validate.
        allowed_classes: Set of allowed policy classes.

    Returns:
        LicensePolicyReport with all results and summary.
    """
    if allowed_classes is None:
        allowed_classes = DEFAULT_ALLOWED_CLASSES

    results = []
    passed = 0
    failed = 0
    by_class: dict[str, int] = {}

    for spdx_id in spdx_ids:
        result = validate_license(spdx_id, allowed_classes)
        results.append({
            "spdx_id": result.spdx_id,
            "valid": result.valid,
            "policy_class": result.policy_class,
            "rejection_reason": result.rejection_reason,
            "evaluated_at": result.evaluated_at,
        })

        if result.valid:
            passed += 1
            if result.policy_class:
                by_class[result.policy_class] = by_class.get(result.policy_class, 0) + 1
        else:
            failed += 1

    return LicensePolicyReport(
        allowed_classes=sorted(allowed_classes),
        results=results,
        summary={
            "total": len(spdx_ids),
            "passed": passed,
            "failed": failed,
            "by_class": by_class,
        },
    )


def validate_manifest_licenses(
    manifest_path: Path,
    allowed_classes: set[str] | None = None,
) -> LicensePolicyReport:
    """
    Validate licenses from a corpus manifest file.

    Args:
        manifest_path: Path to manifest JSON file with 'artifacts' array.
        allowed_classes: Set of allowed policy classes.

    Returns:
        LicensePolicyReport with all results.

    Raises:
        ValueError: If manifest is invalid or missing required fields.
    """
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError(f"invalid manifest JSON: {exc}") from exc

    artifacts = manifest.get("artifacts", [])
    if not isinstance(artifacts, list):
        raise ValueError("manifest missing 'artifacts' array")

    spdx_ids = []
    for artifact in artifacts:
        spdx_id = artifact.get("spdx_license")
        if not spdx_id:
            spdx_id = "NOASSERTION"
        spdx_ids.append(spdx_id)

    return validate_licenses(spdx_ids, allowed_classes)


def _cmd_validate(args: argparse.Namespace) -> int:
    """CLI handler for license validation."""
    if args.manifest:
        try:
            report = validate_manifest_licenses(
                args.manifest,
                allowed_classes=set(args.allow_class) if args.allow_class else None,
            )
        except ValueError as exc:
            print(f"[license-policy] ERROR: {exc}", file=sys.stderr)
            return 2
    elif args.license:
        report = validate_licenses(
            args.license,
            allowed_classes=set(args.allow_class) if args.allow_class else None,
        )
    else:
        print("[license-policy] ERROR: must specify --manifest or --license", file=sys.stderr)
        return 2

    output = {
        "policy_version": report.policy_version,
        "allowed_classes": report.allowed_classes,
        "results": report.results,
        "summary": report.summary,
        "evaluated_at": report.evaluated_at,
    }

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
        print(f"[license-policy] wrote report to {args.output}")
    else:
        print(json.dumps(output, indent=2))

    if report.summary["failed"] > 0:
        print(
            f"[license-policy] FAILED: {report.summary['failed']}/{report.summary['total']} licenses rejected",
            file=sys.stderr,
        )
        return 1

    print(f"[license-policy] OK: {report.summary['passed']}/{report.summary['total']} licenses passed")
    return 0


def _cmd_list(args: argparse.Namespace) -> int:
    """CLI handler for listing allowed licenses."""
    if args.format == "json":
        output = {
            "allowed_licenses": ALLOWED_LICENSES,
            "default_allowed_classes": sorted(DEFAULT_ALLOWED_CLASSES),
            "rejected_patterns": REJECTED_PATTERNS,
        }
        print(json.dumps(output, indent=2))
    else:
        print("Allowed License Classes:")
        for policy_class in sorted(ALLOWED_LICENSES.keys()):
            print(f"\n  {policy_class}:")
            for spdx_id in sorted(ALLOWED_LICENSES[policy_class]):
                print(f"    - {spdx_id}")
        print(f"\nDefault Allowed Classes: {sorted(DEFAULT_ALLOWED_CLASSES)}")
        print(f"\nRejected Patterns: {REJECTED_PATTERNS}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="License policy enforcement for OSS binary corpus"
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    validate_parser = subparsers.add_parser("validate", help="Validate licenses against policy")
    validate_parser.add_argument(
        "--manifest",
        type=Path,
        help="Path to corpus manifest JSON file",
    )
    validate_parser.add_argument(
        "--license",
        action="append",
        help="SPDX license identifier to validate (repeatable)",
    )
    validate_parser.add_argument(
        "--allow-class",
        action="append",
        choices=list(ALLOWED_LICENSES.keys()),
        help="Allowed license class (repeatable; defaults to all)",
    )
    validate_parser.add_argument(
        "--output",
        type=Path,
        help="Output path for validation report JSON",
    )
    validate_parser.set_defaults(func=_cmd_validate)

    list_parser = subparsers.add_parser("list", help="List allowed licenses and policy")
    list_parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format",
    )
    list_parser.set_defaults(func=_cmd_list)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
