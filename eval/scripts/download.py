#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import datasets


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Dataset entrypoint (materializes repo-local datasets; validates checksums). "
            "This is intentionally deterministic and does not require network access."
        )
    )
    parser.add_argument(
        "--lockfile",
        type=Path,
        default=datasets.DEFAULT_LOCKFILE,
        help=f"Path to dataset lockfile (default: {datasets.DEFAULT_LOCKFILE})",
    )
    parser.add_argument("--dataset", action="append", help="Dataset name (repeatable)")
    parser.add_argument(
        "--output",
        type=Path,
        default=datasets.DEFAULT_DATA_ROOT,
        help=f"Materialized dataset root (default: {datasets.DEFAULT_DATA_ROOT})",
    )
    parser.add_argument("--verify", action="store_true", help="Validate lockfile checksums before copying")
    args = parser.parse_args(argv)

    try:
        if args.verify:
            datasets.validate_lockfile(args.lockfile, dataset_names=args.dataset)
        datasets.materialize_datasets(args.lockfile, args.output, dataset_names=args.dataset)
    except ValueError as exc:
        print(f"[download] ERROR: {exc}", file=sys.stderr)
        return 2

    selected = args.dataset or datasets.list_datasets(args.lockfile)
    print(f"[download] OK ({len(selected)} dataset(s)) -> {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
