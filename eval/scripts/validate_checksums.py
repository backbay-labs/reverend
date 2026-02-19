#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import datasets


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate dataset checksums against lockfile")
    parser.add_argument(
        "--lockfile",
        type=Path,
        default=datasets.DEFAULT_LOCKFILE,
        help=f"Path to dataset lockfile (default: {datasets.DEFAULT_LOCKFILE})",
    )
    parser.add_argument("--dataset", action="append", help="Dataset name (repeatable)")
    args = parser.parse_args(argv)

    try:
        datasets.validate_lockfile(args.lockfile, dataset_names=args.dataset)
    except ValueError as exc:
        print(f"[validate_checksums] ERROR: {exc}", file=sys.stderr)
        return 2

    selected = args.dataset or datasets.list_datasets(args.lockfile)
    print(f"[validate_checksums] OK ({len(selected)} dataset(s))")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
