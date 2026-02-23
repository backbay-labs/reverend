#!/usr/bin/env python3
"""Deterministic shard benchmark helper for Reverend retrieval fixtures.

This script provides a stable benchmark summary over JSON fixtures so query/ranking
changes can be compared without introducing nondeterminism in workcell gates.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


def _stable_item_key(item: Any) -> str:
    if isinstance(item, dict):
        canonical = json.dumps(item, sort_keys=True, separators=(",", ":"))
    else:
        canonical = json.dumps(item, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:12]
    return digest


def _load_fixture(path: Path) -> list[Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in ("items", "records", "results", "queries"):
            value = payload.get(key)
            if isinstance(value, list):
                return value
    raise ValueError(f"Unsupported fixture schema in {path}")


def run_benchmark(path: Path, top_k: int) -> dict[str, Any]:
    items = _load_fixture(path)
    ranked = sorted(items, key=_stable_item_key)
    top = ranked[: max(0, top_k)]
    return {
        "fixture": str(path),
        "total_items": len(items),
        "top_k": len(top),
        "top_keys": [_stable_item_key(item) for item in top],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--fixture",
        default="scripts/ml/fixtures/triage_benchmark_v2026_02_1.json",
        help="Path to benchmark fixture JSON",
    )
    parser.add_argument("--top-k", type=int, default=10, help="Number of ranked rows to report")
    args = parser.parse_args()

    summary = run_benchmark(Path(args.fixture), args.top_k)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
