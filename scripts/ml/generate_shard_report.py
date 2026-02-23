#!/usr/bin/env python3
"""Generate the E17-S3 shard latency benchmark report.

This script runs the mixed workload benchmark and generates the required
artifact at eval/reports/e17/shard_latency.json.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# Ensure imports work
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from scripts.ml.shard_benchmark import (
    DEFAULT_SLA,
    MIXED_WORKLOADS,
    WorkloadConfig,
    run_mixed_workload_benchmark,
)


def main() -> int:
    # Use smaller workloads for faster execution while still being representative
    workloads = [
        WorkloadConfig(
            name="read_heavy",
            query_count=200,
            top_k=10,
            cache_enabled=True,
            concurrent_readers=1,
            read_ratio=0.95,
            query_distribution="zipfian",
        ),
        WorkloadConfig(
            name="uniform",
            query_count=200,
            top_k=10,
            cache_enabled=True,
            concurrent_readers=1,
            read_ratio=0.90,
            query_distribution="uniform",
        ),
        WorkloadConfig(
            name="hot_spot",
            query_count=200,
            top_k=10,
            cache_enabled=True,
            concurrent_readers=1,
            read_ratio=0.98,
            query_distribution="hot_spot",
        ),
        WorkloadConfig(
            name="no_cache",
            query_count=100,
            top_k=10,
            cache_enabled=False,
            concurrent_readers=1,
            read_ratio=1.0,
            query_distribution="uniform",
        ),
    ]

    print("[e17-s3] Running mixed workload benchmark...")
    report = run_mixed_workload_benchmark(
        corpus_size=1000,
        shard_count=4,
        vector_dimension=64,
        workloads=workloads,
        sla=DEFAULT_SLA,
        run_id="e17-s3-benchmark",
        commit_sha=os.environ.get("GITHUB_SHA", "local"),
    )

    # Write report to eval/reports/e17/shard_latency.json
    output_dir = Path(__file__).parent.parent.parent / "eval" / "reports" / "e17"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "shard_latency.json"

    output_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print(f"[e17-s3] Wrote report to {output_path}")
    print(f"[e17-s3] Status: {report.get('status')}")
    print(f"[e17-s3] SLA check: {report.get('sla_check', {}).get('overall_passed')}")
    print(f"[e17-s3] p95 latency: {report.get('aggregate_metrics', {}).get('latency', {}).get('p95_ms')} ms")
    print(f"[e17-s3] p99 latency: {report.get('aggregate_metrics', {}).get('latency', {}).get('p99_ms')} ms")

    return 0 if report.get("status") == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
