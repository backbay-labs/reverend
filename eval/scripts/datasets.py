#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path


DEFAULT_LOCKFILE = Path("datasets/datasets.lock.json")
DEFAULT_DATA_ROOT = Path("datasets/data")


def sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def load_lockfile(lockfile: Path) -> dict:
    try:
        data = json.loads(lockfile.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError(f"invalid lockfile JSON: {exc}") from exc

    if data.get("schema_version") != 1:
        raise ValueError("unsupported lockfile schema_version (expected 1)")

    datasets = data.get("datasets")
    if not isinstance(datasets, dict) or not datasets:
        raise ValueError("lockfile missing non-empty 'datasets' object")

    return data


def list_datasets(lockfile: Path) -> list[str]:
    lock = load_lockfile(lockfile)
    return sorted(lock["datasets"].keys())


def _iter_selected_datasets(lock: dict, names: list[str] | None) -> list[tuple[str, dict]]:
    all_datasets: dict = lock["datasets"]
    if not names:
        return sorted(all_datasets.items(), key=lambda item: item[0])

    missing = [name for name in names if name not in all_datasets]
    if missing:
        raise ValueError(f"unknown dataset(s): {', '.join(missing)}")
    return [(name, all_datasets[name]) for name in names]


def validate_lockfile(lockfile: Path, dataset_names: list[str] | None = None) -> None:
    lock = load_lockfile(lockfile)
    selected = _iter_selected_datasets(lock, dataset_names)

    errors: list[str] = []
    for dataset_name, entry in selected:
        source = entry.get("source") or {}
        if source.get("type") != "local_directory":
            errors.append(f"{dataset_name}: unsupported source.type (expected local_directory)")
            continue

        rel_path = source.get("path")
        if not isinstance(rel_path, str) or not rel_path.strip():
            errors.append(f"{dataset_name}: invalid source.path")
            continue

        dataset_dir = Path(rel_path)
        if not dataset_dir.is_dir():
            errors.append(f"{dataset_name}: source directory missing: {dataset_dir}")
            continue

        files = entry.get("files")
        if not isinstance(files, dict) or not files:
            errors.append(f"{dataset_name}: missing non-empty files object")
            continue

        for rel_file, meta in sorted(files.items(), key=lambda item: item[0]):
            if not isinstance(rel_file, str) or not rel_file.strip():
                errors.append(f"{dataset_name}: invalid file entry key")
                continue

            file_path = dataset_dir / rel_file
            if not file_path.is_file():
                errors.append(f"{dataset_name}: missing file: {file_path}")
                continue

            expected_bytes = meta.get("bytes")
            expected_sha256 = meta.get("sha256")
            if not isinstance(expected_bytes, int) or expected_bytes < 0:
                errors.append(f"{dataset_name}: {rel_file}: invalid expected bytes")
                continue
            if not isinstance(expected_sha256, str) or len(expected_sha256) != 64:
                errors.append(f"{dataset_name}: {rel_file}: invalid expected sha256")
                continue

            actual_bytes = file_path.stat().st_size
            if actual_bytes != expected_bytes:
                errors.append(
                    f"{dataset_name}: {rel_file}: bytes mismatch (expected {expected_bytes}, got {actual_bytes})"
                )
                continue

            actual_sha256 = sha256_file(file_path)
            if actual_sha256 != expected_sha256:
                errors.append(
                    f"{dataset_name}: {rel_file}: sha256 mismatch (expected {expected_sha256}, got {actual_sha256})"
                )

    if errors:
        raise ValueError("lockfile validation failed:\n- " + "\n- ".join(errors))


def materialize_datasets(
    lockfile: Path,
    data_root: Path,
    dataset_names: list[str] | None = None,
) -> None:
    validate_lockfile(lockfile, dataset_names=dataset_names)
    lock = load_lockfile(lockfile)
    selected = _iter_selected_datasets(lock, dataset_names)

    data_root.mkdir(parents=True, exist_ok=True)
    for dataset_name, entry in selected:
        dataset_dir = Path(entry["source"]["path"])
        dest_dir = data_root / dataset_name

        if dest_dir.exists():
            if dest_dir.is_file():
                dest_dir.unlink()
            else:
                shutil.rmtree(dest_dir)

        shutil.copytree(dataset_dir, dest_dir)


def _cmd_list(args: argparse.Namespace) -> int:
    for name in list_datasets(args.lockfile):
        print(name)
    return 0


def _cmd_validate(args: argparse.Namespace) -> int:
    validate_lockfile(args.lockfile, dataset_names=args.dataset)
    selected = args.dataset or list_datasets(args.lockfile)
    print(f"[datasets] OK ({len(selected)} dataset(s))")
    return 0


def _cmd_materialize(args: argparse.Namespace) -> int:
    materialize_datasets(args.lockfile, args.data_root, dataset_names=args.dataset)
    selected = args.dataset or list_datasets(args.lockfile)
    print(f"[datasets] materialized ({len(selected)} dataset(s)) -> {args.data_root}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Dataset lock validation/materialization")
    parser.add_argument(
        "--lockfile",
        type=Path,
        default=DEFAULT_LOCKFILE,
        help=f"Path to dataset lockfile (default: {DEFAULT_LOCKFILE})",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    list_parser = subparsers.add_parser("list", help="List datasets in lockfile")
    list_parser.set_defaults(func=_cmd_list)

    validate_parser = subparsers.add_parser("validate", help="Validate datasets against lockfile")
    validate_parser.add_argument("--dataset", action="append", help="Dataset name (repeatable)")
    validate_parser.set_defaults(func=_cmd_validate)

    materialize_parser = subparsers.add_parser("materialize", help="Copy datasets into datasets/data/")
    materialize_parser.add_argument("--dataset", action="append", help="Dataset name (repeatable)")
    materialize_parser.add_argument(
        "--data-root",
        type=Path,
        default=DEFAULT_DATA_ROOT,
        help=f"Materialized dataset root (default: {DEFAULT_DATA_ROOT})",
    )
    materialize_parser.set_defaults(func=_cmd_materialize)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except ValueError as exc:
        print(f"[datasets] ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
