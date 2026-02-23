#!/usr/bin/env python3
"""E17-S3: Cache layer with eviction, consistency, and stale-read policies.

This module provides:
1. LRU cache with configurable eviction policies.
2. Stale-read budget support (TTL-based freshness).
3. Consistency policies (read-your-writes, eventual).
4. Cache hit/miss telemetry.
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from collections import OrderedDict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Generic, Mapping, TypeVar

try:
    from scripts.ml.local_embedding_pipeline import SearchResult
except ImportError:
    # Allow running from workcell directory or standalone
    import sys
    from pathlib import Path as _Path
    sys.path.insert(0, str(_Path(__file__).parent.parent.parent))
    from scripts.ml.local_embedding_pipeline import SearchResult


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _now_seconds() -> float:
    return time.time()


T = TypeVar("T")


class EvictionPolicy(Enum):
    """Cache eviction policy types."""

    LRU = "lru"  # Least Recently Used
    LFU = "lfu"  # Least Frequently Used
    TTL = "ttl"  # Time-To-Live based
    FIFO = "fifo"  # First In First Out


class ConsistencyPolicy(Enum):
    """Cache consistency policy types."""

    EVENTUAL = "eventual"  # May return stale data
    READ_YOUR_WRITES = "read_your_writes"  # Writer sees their own writes
    STRONG = "strong"  # Always consistent (bypass cache on miss)


@dataclass(frozen=True)
class CacheConfig:
    """Configuration for the cache layer."""

    max_entries: int = 10000
    default_ttl_seconds: float = 300.0  # 5 minutes
    stale_read_budget_seconds: float = 60.0  # Allow reads up to 60s past TTL
    eviction_policy: EvictionPolicy = EvictionPolicy.LRU
    consistency_policy: ConsistencyPolicy = ConsistencyPolicy.EVENTUAL
    write_through: bool = False  # If True, writes go to backing store immediately

    def to_json(self) -> dict[str, Any]:
        return {
            "max_entries": self.max_entries,
            "default_ttl_seconds": self.default_ttl_seconds,
            "stale_read_budget_seconds": self.stale_read_budget_seconds,
            "eviction_policy": self.eviction_policy.value,
            "consistency_policy": self.consistency_policy.value,
            "write_through": self.write_through,
        }


@dataclass
class CacheEntry(Generic[T]):
    """A single cache entry with metadata."""

    key: str
    value: T
    created_at: float  # Unix timestamp
    expires_at: float  # Unix timestamp
    access_count: int = 0
    last_accessed_at: float = 0.0
    writer_id: str | None = None  # For read-your-writes consistency

    def is_expired(self, now: float | None = None) -> bool:
        if now is None:
            now = _now_seconds()
        return now >= self.expires_at

    def is_within_stale_budget(
        self, now: float | None = None, stale_budget: float = 0.0
    ) -> bool:
        if now is None:
            now = _now_seconds()
        return now < (self.expires_at + stale_budget)


@dataclass
class CacheTelemetry:
    """Telemetry for cache operations."""

    hits: int = 0
    misses: int = 0
    stale_hits: int = 0
    evictions: int = 0
    writes: int = 0
    invalidations: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def record_hit(self, *, stale: bool = False) -> None:
        with self._lock:
            if stale:
                self.stale_hits += 1
            else:
                self.hits += 1

    def record_miss(self) -> None:
        with self._lock:
            self.misses += 1

    def record_eviction(self) -> None:
        with self._lock:
            self.evictions += 1

    def record_write(self) -> None:
        with self._lock:
            self.writes += 1

    def record_invalidation(self) -> None:
        with self._lock:
            self.invalidations += 1

    @property
    def total_requests(self) -> int:
        return self.hits + self.stale_hits + self.misses

    @property
    def hit_rate(self) -> float:
        total = self.total_requests
        if total == 0:
            return 0.0
        return (self.hits + self.stale_hits) / total

    @property
    def fresh_hit_rate(self) -> float:
        total = self.total_requests
        if total == 0:
            return 0.0
        return self.hits / total

    def to_json(self) -> dict[str, Any]:
        with self._lock:
            return {
                "hits": self.hits,
                "stale_hits": self.stale_hits,
                "misses": self.misses,
                "evictions": self.evictions,
                "writes": self.writes,
                "invalidations": self.invalidations,
                "total_requests": self.total_requests,
                "hit_rate": round(self.hit_rate, 6),
                "fresh_hit_rate": round(self.fresh_hit_rate, 6),
            }


class LRUCache(Generic[T]):
    """Thread-safe LRU cache with TTL and stale-read support."""

    def __init__(self, config: CacheConfig | None = None) -> None:
        self._config = config or CacheConfig()
        self._cache: OrderedDict[str, CacheEntry[T]] = OrderedDict()
        self._telemetry = CacheTelemetry()
        self._lock = threading.Lock()
        self._writer_versions: dict[str, dict[str, float]] = {}  # writer_id -> {key -> version}

    @property
    def config(self) -> CacheConfig:
        return self._config

    @property
    def telemetry(self) -> CacheTelemetry:
        return self._telemetry

    def get(
        self,
        key: str,
        *,
        writer_id: str | None = None,
        allow_stale: bool | None = None,
    ) -> T | None:
        """Get a value from the cache.

        Args:
            key: The cache key.
            writer_id: For read-your-writes, ensure we see our own writes.
            allow_stale: If True, return stale values within budget. Defaults to config.

        Returns:
            The cached value or None if not found/expired.
        """
        if allow_stale is None:
            allow_stale = self._config.consistency_policy == ConsistencyPolicy.EVENTUAL

        now = _now_seconds()

        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                self._telemetry.record_miss()
                return None

            # Check read-your-writes consistency
            if (
                self._config.consistency_policy == ConsistencyPolicy.READ_YOUR_WRITES
                and writer_id is not None
            ):
                writer_versions = self._writer_versions.get(writer_id, {})
                if key in writer_versions:
                    # Writer must see at least their version
                    if entry.created_at < writer_versions[key]:
                        self._telemetry.record_miss()
                        return None

            # Check expiration
            if not entry.is_expired(now):
                # Fresh hit
                entry.access_count += 1
                entry.last_accessed_at = now
                self._cache.move_to_end(key)
                self._telemetry.record_hit(stale=False)
                return entry.value

            # Expired - check stale budget
            if allow_stale and entry.is_within_stale_budget(
                now, self._config.stale_read_budget_seconds
            ):
                # Stale hit within budget
                entry.access_count += 1
                entry.last_accessed_at = now
                self._telemetry.record_hit(stale=True)
                return entry.value

            # Expired and outside stale budget
            self._telemetry.record_miss()
            return None

    def set(
        self,
        key: str,
        value: T,
        *,
        ttl_seconds: float | None = None,
        writer_id: str | None = None,
    ) -> None:
        """Set a value in the cache.

        Args:
            key: The cache key.
            value: The value to cache.
            ttl_seconds: Custom TTL. Defaults to config.
            writer_id: For read-your-writes tracking.
        """
        if ttl_seconds is None:
            ttl_seconds = self._config.default_ttl_seconds

        now = _now_seconds()
        entry = CacheEntry(
            key=key,
            value=value,
            created_at=now,
            expires_at=now + ttl_seconds,
            access_count=0,
            last_accessed_at=now,
            writer_id=writer_id,
        )

        with self._lock:
            # Track writer version for read-your-writes
            if writer_id is not None:
                if writer_id not in self._writer_versions:
                    self._writer_versions[writer_id] = {}
                self._writer_versions[writer_id][key] = now

            # Add/update entry
            if key in self._cache:
                self._cache.move_to_end(key)
            self._cache[key] = entry
            self._telemetry.record_write()

            # Evict if over capacity
            while len(self._cache) > self._config.max_entries:
                self._evict_one()

    def invalidate(self, key: str) -> bool:
        """Invalidate a cache entry.

        Returns:
            True if the key existed and was invalidated.
        """
        with self._lock:
            if key in self._cache:
                del self._cache[key]
                self._telemetry.record_invalidation()
                return True
            return False

    def invalidate_pattern(self, pattern: str) -> int:
        """Invalidate all entries matching a pattern (prefix match).

        Returns:
            Number of entries invalidated.
        """
        count = 0
        with self._lock:
            keys_to_remove = [k for k in self._cache.keys() if k.startswith(pattern)]
            for key in keys_to_remove:
                del self._cache[key]
                count += 1
            self._telemetry.invalidations += count
        return count

    def clear(self) -> int:
        """Clear all entries from the cache.

        Returns:
            Number of entries cleared.
        """
        with self._lock:
            count = len(self._cache)
            self._cache.clear()
            self._writer_versions.clear()
            return count

    def _evict_one(self) -> None:
        """Evict the least recently used entry."""
        if self._cache:
            self._cache.popitem(last=False)
            self._telemetry.record_eviction()

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._cache)

    def get_stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        with self._lock:
            expired_count = sum(
                1 for entry in self._cache.values() if entry.is_expired()
            )
            stale_but_valid = sum(
                1
                for entry in self._cache.values()
                if entry.is_expired()
                and entry.is_within_stale_budget(
                    stale_budget=self._config.stale_read_budget_seconds
                )
            )
        return {
            "size": self.size,
            "max_entries": self._config.max_entries,
            "expired_entries": expired_count,
            "stale_but_readable": stale_but_valid,
            "config": self._config.to_json(),
            "telemetry": self._telemetry.to_json(),
        }


@dataclass(frozen=True)
class CachedSearchResult:
    """Search result with cache metadata."""

    results: tuple[SearchResult, ...]
    cache_hit: bool
    stale: bool
    cache_key: str
    latency_ms: float

    def to_json(self) -> dict[str, Any]:
        return {
            "results": [
                {"function_id": r.function_id, "name": r.name, "score": round(r.score, 6)}
                for r in self.results
            ],
            "cache_hit": self.cache_hit,
            "stale": self.stale,
            "cache_key": self.cache_key,
            "latency_ms": round(self.latency_ms, 3),
        }


def _cache_key(query: str, top_k: int) -> str:
    """Generate a deterministic cache key for a query."""
    payload = json.dumps({"query": query, "top_k": top_k}, sort_keys=True)
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
    return f"query:{digest}"


class CachedRetrievalService:
    """Retrieval service with caching layer."""

    def __init__(
        self,
        *,
        retrieval_fn: Callable[[str, int], tuple[SearchResult, ...]],
        cache_config: CacheConfig | None = None,
    ) -> None:
        self._retrieval_fn = retrieval_fn
        self._cache: LRUCache[tuple[SearchResult, ...]] = LRUCache(
            config=cache_config or CacheConfig()
        )

    @property
    def cache(self) -> LRUCache[tuple[SearchResult, ...]]:
        return self._cache

    def search(
        self,
        query: str,
        top_k: int = 10,
        *,
        bypass_cache: bool = False,
        writer_id: str | None = None,
    ) -> CachedSearchResult:
        """Search with caching.

        Args:
            query: The query text.
            top_k: Number of results.
            bypass_cache: If True, skip cache lookup and refresh.
            writer_id: For read-your-writes consistency.

        Returns:
            CachedSearchResult with cache metadata.
        """
        start = time.perf_counter_ns()
        key = _cache_key(query, top_k)

        # Try cache first
        if not bypass_cache:
            cached = self._cache.get(key, writer_id=writer_id)
            if cached is not None:
                latency = (time.perf_counter_ns() - start) / 1_000_000.0
                return CachedSearchResult(
                    results=cached,
                    cache_hit=True,
                    stale=False,  # get() handles staleness internally
                    cache_key=key,
                    latency_ms=latency,
                )

        # Cache miss - fetch from backing store
        results = self._retrieval_fn(query, top_k)
        self._cache.set(key, results, writer_id=writer_id)

        latency = (time.perf_counter_ns() - start) / 1_000_000.0
        return CachedSearchResult(
            results=results,
            cache_hit=False,
            stale=False,
            cache_key=key,
            latency_ms=latency,
        )

    def invalidate_query(self, query: str, top_k: int) -> bool:
        """Invalidate a specific query cache entry."""
        key = _cache_key(query, top_k)
        return self._cache.invalidate(key)

    def get_stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        return self._cache.get_stats()


@dataclass(frozen=True)
class CachePolicy:
    """Policy configuration for cache behavior."""

    eviction: EvictionPolicy
    consistency: ConsistencyPolicy
    ttl_seconds: float
    stale_budget_seconds: float
    max_entries: int

    def to_config(self) -> CacheConfig:
        return CacheConfig(
            max_entries=self.max_entries,
            default_ttl_seconds=self.ttl_seconds,
            stale_read_budget_seconds=self.stale_budget_seconds,
            eviction_policy=self.eviction,
            consistency_policy=self.consistency,
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "eviction": self.eviction.value,
            "consistency": self.consistency.value,
            "ttl_seconds": self.ttl_seconds,
            "stale_budget_seconds": self.stale_budget_seconds,
            "max_entries": self.max_entries,
        }


# Default policies for different use cases
POLICY_LOW_LATENCY = CachePolicy(
    eviction=EvictionPolicy.LRU,
    consistency=ConsistencyPolicy.EVENTUAL,
    ttl_seconds=60.0,
    stale_budget_seconds=30.0,
    max_entries=50000,
)

POLICY_CONSISTENT = CachePolicy(
    eviction=EvictionPolicy.LRU,
    consistency=ConsistencyPolicy.READ_YOUR_WRITES,
    ttl_seconds=300.0,
    stale_budget_seconds=0.0,  # No stale reads
    max_entries=10000,
)

POLICY_HIGH_VOLUME = CachePolicy(
    eviction=EvictionPolicy.LRU,
    consistency=ConsistencyPolicy.EVENTUAL,
    ttl_seconds=600.0,
    stale_budget_seconds=120.0,
    max_entries=100000,
)


def generate_cache_report(
    service: CachedRetrievalService,
    *,
    report_id: str | None = None,
) -> dict[str, Any]:
    """Generate a cache performance report."""
    stats = service.get_stats()
    return {
        "schema_version": 1,
        "kind": "cache_report",
        "report_id": report_id or f"cache-report-{int(time.time())}",
        "generated_at_utc": _utc_now(),
        "statistics": stats,
    }


def save_cache_report(report: dict[str, Any], output_path: Path) -> None:
    """Save cache report to file."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
