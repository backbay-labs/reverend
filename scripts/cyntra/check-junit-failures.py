#!/usr/bin/env python3
"""Fail if JUnit XML reports any failures or errors."""

from __future__ import annotations

import argparse
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def _int_attr(value: str | None) -> int:
    try:
        return int(value or "0")
    except Exception:
        return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate JUnit XML has zero failures/errors.")
    parser.add_argument(
        "--results-dir",
        default="Ghidra/Framework/Generic/build/test-results/test",
        help="Directory containing TEST-*.xml files",
    )
    args = parser.parse_args()

    results_dir = Path(args.results_dir)
    if not results_dir.exists():
        print(f"[check-junit] ERROR: results directory missing: {results_dir}", file=sys.stderr)
        return 1

    xml_files = sorted(results_dir.glob("TEST-*.xml"))
    if not xml_files:
        print(f"[check-junit] ERROR: no TEST-*.xml files found in {results_dir}", file=sys.stderr)
        return 1

    total_tests = 0
    total_failures = 0
    total_errors = 0
    failing_suites: list[str] = []

    for xml_path in xml_files:
        root = ET.fromstring(xml_path.read_text(encoding="utf-8"))
        tests = _int_attr(root.attrib.get("tests"))
        failures = _int_attr(root.attrib.get("failures"))
        errors = _int_attr(root.attrib.get("errors"))
        total_tests += tests
        total_failures += failures
        total_errors += errors
        if failures or errors:
            suite_name = root.attrib.get("name") or xml_path.name
            failing_suites.append(f"{suite_name} (failures={failures}, errors={errors})")

    print(
        f"[check-junit] suites={len(xml_files)} tests={total_tests} "
        f"failures={total_failures} errors={total_errors}"
    )

    if total_failures or total_errors:
        print("[check-junit] ERROR: junit failures detected:", file=sys.stderr)
        for item in failing_suites:
            print(f"  - {item}", file=sys.stderr)
        return 1

    print("[check-junit] junit results clean")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
