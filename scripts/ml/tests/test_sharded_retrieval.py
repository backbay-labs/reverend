#!/usr/bin/env python3
"""Tests for E17-S3: Sharded index service and cache layer."""
from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any

try:
    import pytest
except ModuleNotFoundError:
    class _RaisesContext:
        def __init__(self, exc_type: type[BaseException], match: str | None = None) -> None:
            self.exc_type = exc_type
            self.match = match

        def __enter__(self) -> "_RaisesContext":
            return self

        def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None,
                     _tb: Any) -> bool:
            if exc_type is None:
                raise AssertionError(f"Expected {self.exc_type.__name__} to be raised")
            if not issubclass(exc_type, self.exc_type):
                return False
            if self.match and exc is not None and re.search(self.match, str(exc)) is None:
                raise AssertionError(
                    f"Exception message did not match /{self.match}/: {exc}"
                )
            return True

    class _PytestCompat:
        @staticmethod
        def raises(exc_type: type[BaseException], match: str | None = None) -> _RaisesContext:
            return _RaisesContext(exc_type, match)

        @staticmethod
        def fixture(func: Any = None, **_kwargs: Any) -> Any:
            if func is None:
                return lambda wrapped: wrapped
            return func

    pytest = _PytestCompat()

try:
    from scripts.ml.local_embedding_pipeline import FunctionRecord, SearchResult
    from scripts.ml.retrieval_cache import (
        CacheConfig,
        CachedRetrievalService,
        CacheTelemetry,
        ConsistencyPolicy,
        EvictionPolicy,
        LRUCache,
        generate_cache_report,
    )
    from scripts.ml.shard_benchmark import (
        BenchmarkRunner,
        LatencyMetrics,
        LatencySLA,
        WorkloadConfig,
        run_mixed_workload_benchmark,
    )
    from scripts.ml.sharded_retrieval import (
        ConsistentHashRing,
        ShardConfig,
        ShardedIndexService,
        ShardHealth,
        ShardTelemetry,
        generate_shard_health_report,
    )
except ImportError:
    # Allow running from workcell directory
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
    from scripts.ml.local_embedding_pipeline import FunctionRecord, SearchResult
    from scripts.ml.retrieval_cache import (
        CacheConfig,
        CachedRetrievalService,
        CacheTelemetry,
        ConsistencyPolicy,
        EvictionPolicy,
        LRUCache,
        generate_cache_report,
    )
    from scripts.ml.shard_benchmark import (
        BenchmarkRunner,
        LatencyMetrics,
        LatencySLA,
        WorkloadConfig,
        run_mixed_workload_benchmark,
    )
    from scripts.ml.sharded_retrieval import (
        ConsistentHashRing,
        ShardConfig,
        ShardedIndexService,
        ShardHealth,
        ShardTelemetry,
        generate_shard_health_report,
    )


class TestConsistentHashRing:
    def test_get_shard_deterministic(self) -> None:
        shards = [ShardConfig(shard_id=f"shard-{i}") for i in range(4)]
        ring = ConsistentHashRing(shards)

        # Same key should always map to same shard
        key = "test-function-123"
        shard1 = ring.get_shard(key)
        shard2 = ring.get_shard(key)
        assert shard1 == shard2

    def test_get_all_shards(self) -> None:
        shards = [ShardConfig(shard_id=f"shard-{i}") for i in range(4)]
        ring = ConsistentHashRing(shards)
        all_shards = ring.get_all_shards()
        assert len(all_shards) == 4
        assert set(all_shards) == {"shard-0", "shard-1", "shard-2", "shard-3"}

    def test_distribution_roughly_even(self) -> None:
        shards = [ShardConfig(shard_id=f"shard-{i}") for i in range(4)]
        ring = ConsistentHashRing(shards)

        counts: dict[str, int] = {s.shard_id: 0 for s in shards}
        for i in range(1000):
            shard = ring.get_shard(f"key-{i}")
            counts[shard] += 1

        # Each shard should have at least 100 keys (rough balance)
        for shard_id, count in counts.items():
            assert count >= 100, f"Shard {shard_id} has too few keys: {count}"

    def test_empty_ring_raises(self) -> None:
        ring = ConsistentHashRing([])
        with pytest.raises(ValueError, match="No shards configured"):
            ring.get_shard("any-key")


class TestShardTelemetry:
    def test_record_query_updates_metrics(self) -> None:
        telemetry = ShardTelemetry(shard_id="test-shard", record_count=100)

        telemetry.record_query(10.5)
        telemetry.record_query(15.0)
        telemetry.record_query(20.0, error=True)

        assert telemetry.query_count == 3
        assert telemetry.error_count == 1
        assert len(telemetry.latencies_ms) == 3

    def test_to_health_returns_correct_status(self) -> None:
        telemetry = ShardTelemetry(shard_id="test-shard", record_count=100)

        # No queries - should be healthy
        health = telemetry.to_health()
        assert health.status == "healthy"
        assert health.error_rate == 0.0

        # Add some successful queries
        for _ in range(10):
            telemetry.record_query(50.0)
        health = telemetry.to_health()
        assert health.status == "healthy"

        # Add errors to push error rate above 10%
        for _ in range(5):
            telemetry.record_query(50.0, error=True)
        health = telemetry.to_health()
        assert health.status == "unhealthy"

    def test_percentile_calculations(self) -> None:
        telemetry = ShardTelemetry(shard_id="test-shard")

        # Add latencies from 1 to 100
        for i in range(1, 101):
            telemetry.record_query(float(i))

        health = telemetry.to_health()
        assert health.latency_p50_ms == 50.0
        assert health.latency_p95_ms == 95.0
        assert health.latency_p99_ms == 99.0


class TestShardedIndexService:
    @pytest.fixture
    def sample_records(self) -> list[FunctionRecord]:
        return [
            FunctionRecord(
                function_id=f"fn_{i}",
                name=f"function_{i}",
                text=f"sample text for function {i}",
            )
            for i in range(100)
        ]

    def test_initialize_empty(self) -> None:
        service = ShardedIndexService(shard_configs=[ShardConfig(shard_id="s1")])
        service.initialize_empty()
        health = service.get_aggregate_health()
        assert health["total_shards"] == 1
        assert health["status"] == "healthy"

    def test_build_from_records(self, sample_records: list[FunctionRecord]) -> None:
        shard_configs = [ShardConfig(shard_id=f"shard-{i}") for i in range(4)]
        service = ShardedIndexService(shard_configs=shard_configs)
        service.build_from_records(sample_records)

        health = service.get_aggregate_health()
        assert health["total_shards"] == 4
        assert health["total_records"] == 100

    def test_search_returns_results(self, sample_records: list[FunctionRecord]) -> None:
        service = ShardedIndexService()
        service.build_from_records(sample_records)

        result = service.search("sample text function", top_k=5)
        assert len(result.results) <= 5
        assert result.shards_queried > 0
        assert result.shards_succeeded == result.shards_queried

    def test_add_shard(self) -> None:
        service = ShardedIndexService(
            shard_configs=[ShardConfig(shard_id="shard-0")]
        )
        service.initialize_empty()
        assert service.shard_count == 1

        service.add_shard(ShardConfig(shard_id="shard-1"))
        assert service.shard_count == 2

    def test_remove_shard(self) -> None:
        service = ShardedIndexService(
            shard_configs=[
                ShardConfig(shard_id="shard-0"),
                ShardConfig(shard_id="shard-1"),
            ]
        )
        service.initialize_empty()
        assert service.shard_count == 2

        service.remove_shard("shard-1")
        assert service.shard_count == 1

    def test_shard_health_telemetry(self, sample_records: list[FunctionRecord]) -> None:
        service = ShardedIndexService()
        service.build_from_records(sample_records)

        # Run some queries
        for i in range(10):
            service.search(f"query {i}", top_k=5)

        health = service.get_aggregate_health()
        assert health["total_queries"] > 0


class TestLRUCache:
    def test_basic_get_set(self) -> None:
        cache: LRUCache[str] = LRUCache()
        cache.set("key1", "value1")
        assert cache.get("key1") == "value1"

    def test_cache_miss(self) -> None:
        cache: LRUCache[str] = LRUCache()
        assert cache.get("nonexistent") is None

    def test_eviction_on_capacity(self) -> None:
        config = CacheConfig(max_entries=3)
        cache: LRUCache[str] = LRUCache(config=config)

        cache.set("key1", "value1")
        cache.set("key2", "value2")
        cache.set("key3", "value3")
        assert cache.size == 3

        # Adding fourth entry should evict oldest (key1)
        cache.set("key4", "value4")
        assert cache.size == 3
        assert cache.get("key1") is None
        assert cache.get("key4") == "value4"

    def test_lru_access_updates_order(self) -> None:
        config = CacheConfig(max_entries=3)
        cache: LRUCache[str] = LRUCache(config=config)

        cache.set("key1", "value1")
        cache.set("key2", "value2")
        cache.set("key3", "value3")

        # Access key1 to make it recently used
        cache.get("key1")

        # Add key4 - should evict key2 (oldest unused)
        cache.set("key4", "value4")
        assert cache.get("key1") == "value1"
        assert cache.get("key2") is None

    def test_ttl_expiration(self) -> None:
        config = CacheConfig(default_ttl_seconds=0.1)  # 100ms TTL
        cache: LRUCache[str] = LRUCache(config=config)

        cache.set("key1", "value1")
        assert cache.get("key1") == "value1"

        time.sleep(0.15)
        assert cache.get("key1", allow_stale=False) is None

    def test_stale_read_within_budget(self) -> None:
        config = CacheConfig(
            default_ttl_seconds=0.1,
            stale_read_budget_seconds=0.2,
        )
        cache: LRUCache[str] = LRUCache(config=config)

        cache.set("key1", "value1")
        time.sleep(0.15)  # Past TTL but within stale budget

        # Should still return value with stale read
        assert cache.get("key1", allow_stale=True) == "value1"

    def test_invalidate(self) -> None:
        cache: LRUCache[str] = LRUCache()
        cache.set("key1", "value1")
        assert cache.invalidate("key1")
        assert cache.get("key1") is None
        assert not cache.invalidate("nonexistent")

    def test_invalidate_pattern(self) -> None:
        cache: LRUCache[str] = LRUCache()
        cache.set("prefix:key1", "value1")
        cache.set("prefix:key2", "value2")
        cache.set("other:key3", "value3")

        count = cache.invalidate_pattern("prefix:")
        assert count == 2
        assert cache.get("prefix:key1") is None
        assert cache.get("other:key3") == "value3"

    def test_telemetry_tracking(self) -> None:
        cache: LRUCache[str] = LRUCache()
        cache.set("key1", "value1")
        cache.get("key1")  # Hit
        cache.get("key1")  # Hit
        cache.get("nonexistent")  # Miss

        telemetry = cache.telemetry.to_json()
        assert telemetry["hits"] == 2
        assert telemetry["misses"] == 1
        assert telemetry["writes"] == 1


class TestCachedRetrievalService:
    @pytest.fixture
    def mock_retrieval(self) -> tuple[list[int], Any]:
        call_count = [0]

        def retrieval_fn(query: str, top_k: int) -> tuple[SearchResult, ...]:
            call_count[0] += 1
            return (
                SearchResult(
                    function_id=f"fn_{hash(query) % 100}",
                    name=f"function_{hash(query) % 100}",
                    score=0.95,
                ),
            )

        return call_count, retrieval_fn

    def test_cache_hit_avoids_retrieval(
        self, mock_retrieval: tuple[list[int], Any]
    ) -> None:
        call_count, retrieval_fn = mock_retrieval
        service = CachedRetrievalService(retrieval_fn=retrieval_fn)

        # First call - cache miss
        result1 = service.search("test query", top_k=5)
        assert not result1.cache_hit
        assert call_count[0] == 1

        # Second call - cache hit
        result2 = service.search("test query", top_k=5)
        assert result2.cache_hit
        assert call_count[0] == 1  # No additional call

    def test_bypass_cache_forces_retrieval(
        self, mock_retrieval: tuple[list[int], Any]
    ) -> None:
        call_count, retrieval_fn = mock_retrieval
        service = CachedRetrievalService(retrieval_fn=retrieval_fn)

        service.search("test query", top_k=5)
        assert call_count[0] == 1

        service.search("test query", top_k=5, bypass_cache=True)
        assert call_count[0] == 2

    def test_invalidate_query(self, mock_retrieval: tuple[list[int], Any]) -> None:
        call_count, retrieval_fn = mock_retrieval
        service = CachedRetrievalService(retrieval_fn=retrieval_fn)

        service.search("test query", top_k=5)
        assert service.invalidate_query("test query", top_k=5)

        # After invalidation, should be cache miss
        result = service.search("test query", top_k=5)
        assert not result.cache_hit


class TestLatencyMetrics:
    def test_empty_metrics(self) -> None:
        metrics = LatencyMetrics()
        assert metrics.count == 0
        assert metrics.mean == 0.0
        assert metrics.p95 == 0.0

    def test_single_sample(self) -> None:
        metrics = LatencyMetrics()
        metrics.add(100.0)
        assert metrics.count == 1
        assert metrics.mean == 100.0
        assert metrics.p95 == 100.0

    def test_multiple_samples(self) -> None:
        metrics = LatencyMetrics()
        for i in range(1, 101):
            metrics.add(float(i))

        assert metrics.count == 100
        assert metrics.mean == 50.5
        assert metrics.p95 == 95.0
        assert metrics.p99 == 99.0


class TestLatencySLA:
    def test_sla_check_passed(self) -> None:
        sla = LatencySLA(
            p95_target_ms=200.0,
            p99_target_ms=500.0,
            stale_read_budget_seconds=60.0,
        )
        metrics = LatencyMetrics()
        for i in range(100):
            metrics.add(float(i))  # All under 100ms

        check = sla.check(metrics)
        assert check["p95_passed"]
        assert check["p99_passed"]
        assert check["overall_passed"]

    def test_sla_check_failed(self) -> None:
        sla = LatencySLA(
            p95_target_ms=50.0,  # Very strict
            p99_target_ms=100.0,
            stale_read_budget_seconds=60.0,
        )
        metrics = LatencyMetrics()
        for i in range(100):
            metrics.add(float(i))  # p95 = 95ms > 50ms

        check = sla.check(metrics)
        assert not check["p95_passed"]
        assert not check["overall_passed"]


class TestBenchmarkRunner:
    def test_setup_creates_shards(self) -> None:
        runner = BenchmarkRunner(corpus_size=100, shard_count=2)
        runner.setup()
        health = runner.get_shard_health()
        assert health["total_shards"] == 2

    def test_run_workload_collects_metrics(self) -> None:
        runner = BenchmarkRunner(corpus_size=100)
        runner.setup()

        workload = WorkloadConfig(
            name="test",
            query_count=10,
            top_k=5,
            cache_enabled=True,
            concurrent_readers=1,
            read_ratio=1.0,
            query_distribution="uniform",
        )
        result = runner.run_workload(workload)

        assert result.latency_metrics.count == 10
        assert result.errors == 0


class TestMixedWorkloadBenchmark:
    def test_benchmark_generates_report(self) -> None:
        report = run_mixed_workload_benchmark(
            corpus_size=100,
            shard_count=2,
            workloads=[
                WorkloadConfig(
                    name="minimal",
                    query_count=10,
                    top_k=5,
                    cache_enabled=True,
                    concurrent_readers=1,
                    read_ratio=1.0,
                    query_distribution="uniform",
                )
            ],
        )

        assert report["schema_version"] == 1
        assert report["kind"] == "shard_latency_benchmark"
        assert "aggregate_metrics" in report
        assert "shard_health" in report
        assert "sla_check" in report

    def test_benchmark_report_json_serializable(self) -> None:
        report = run_mixed_workload_benchmark(
            corpus_size=50,
            shard_count=2,
            workloads=[
                WorkloadConfig(
                    name="tiny",
                    query_count=5,
                    top_k=3,
                    cache_enabled=True,
                    concurrent_readers=1,
                    read_ratio=1.0,
                    query_distribution="uniform",
                )
            ],
        )
        # Should not raise
        json.dumps(report)


class TestShardHealthReport:
    def test_generate_report(self) -> None:
        service = ShardedIndexService()
        service.initialize_empty()
        report = generate_shard_health_report(service)

        assert report["schema_version"] == 1
        assert report["kind"] == "shard_health_report"
        assert "aggregate" in report
        assert report["aggregate"]["status"] == "healthy"


class TestCacheReport:
    def test_generate_report(self) -> None:
        def dummy_fn(q: str, k: int) -> tuple[SearchResult, ...]:
            return ()

        service = CachedRetrievalService(retrieval_fn=dummy_fn)
        report = generate_cache_report(service)

        assert report["schema_version"] == 1
        assert report["kind"] == "cache_report"
        assert "statistics" in report
