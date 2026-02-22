/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.reverend.query;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.reverend.api.v1.QueryService.QueryContext;
import ghidra.reverend.api.v1.QueryService.QueryResult;

/**
 * Manages query result caching with deterministic invalidation for program changes.
 *
 * <p>The cache manager provides:
 * <ul>
 *   <li>Per-program caches for different query types</li>
 *   <li>LRU eviction with configurable maximum sizes</li>
 *   <li>Fine-grained invalidation for function, symbol, and code changes</li>
 *   <li>Thread-safe operations for concurrent query access</li>
 *   <li>Cache statistics for monitoring</li>
 * </ul>
 *
 * <p>Cache invalidation is triggered by:
 * <ul>
 *   <li>Function changes: invalidates function similarity and semantic search caches</li>
 *   <li>Symbol changes: invalidates semantic search caches (name-based matching)</li>
 *   <li>Code changes: invalidates all query caches for affected regions</li>
 *   <li>Memory changes: invalidates all caches for the program</li>
 * </ul>
 *
 * @since 1.0
 */
public class QueryCacheManager {

	/** Maximum entries per cache type per program */
	private static final int DEFAULT_MAX_CACHE_SIZE = 1000;

	/** Default TTL for cache entries in milliseconds (30 minutes) */
	private static final long DEFAULT_CACHE_TTL_MS = 30 * 60 * 1000;

	private final Map<Program, ProgramQueryCache> programCaches = new ConcurrentHashMap<>();
	private final CacheStatistics statistics = new CacheStatistics();

	private int maxCacheSize = DEFAULT_MAX_CACHE_SIZE;
	private long cacheTtlMs = DEFAULT_CACHE_TTL_MS;

	/**
	 * Creates a new QueryCacheManager with default settings.
	 */
	public QueryCacheManager() {
		// Default constructor
	}

	/**
	 * Initializes caches for the given program.
	 *
	 * @param program the program to initialize caches for
	 */
	public void initializeForProgram(Program program) {
		programCaches.computeIfAbsent(program, ProgramQueryCache::new);
	}

	/**
	 * Invalidates all caches for the given program.
	 *
	 * @param program the program to invalidate caches for
	 */
	public void invalidateProgram(Program program) {
		ProgramQueryCache cache = programCaches.remove(program);
		if (cache != null) {
			statistics.recordInvalidation(cache.getEntryCount());
		}
	}

	/**
	 * Invalidates function-related caches for the given program.
	 * Called when functions are added, removed, or modified.
	 *
	 * @param program the program to invalidate function caches for
	 */
	public void invalidateFunctionCaches(Program program) {
		ProgramQueryCache cache = programCaches.get(program);
		if (cache != null) {
			int count = cache.invalidateFunctionCaches();
			statistics.recordInvalidation(count);
		}
	}

	/**
	 * Invalidates symbol-related caches for the given program.
	 * Called when symbols are added, removed, or renamed.
	 *
	 * @param program the program to invalidate symbol caches for
	 */
	public void invalidateSymbolCaches(Program program) {
		ProgramQueryCache cache = programCaches.get(program);
		if (cache != null) {
			int count = cache.invalidateSymbolCaches();
			statistics.recordInvalidation(count);
		}
	}

	/**
	 * Invalidates code-related caches for the given program.
	 * Called when code is added, removed, or modified.
	 *
	 * @param program the program to invalidate code caches for
	 */
	public void invalidateCodeCaches(Program program) {
		ProgramQueryCache cache = programCaches.get(program);
		if (cache != null) {
			int count = cache.invalidateCodeCaches();
			statistics.recordInvalidation(count);
		}
	}

	/**
	 * Invalidates all caches for the given program.
	 * Called for major changes like memory modifications.
	 *
	 * @param program the program to invalidate all caches for
	 */
	public void invalidateAllCaches(Program program) {
		ProgramQueryCache cache = programCaches.get(program);
		if (cache != null) {
			int count = cache.invalidateAll();
			statistics.recordInvalidation(count);
		}
	}

	// --- Similar Functions Cache ---

	/**
	 * Retrieves cached similar function results.
	 *
	 * @param program the program
	 * @param cacheKey the cache key
	 * @return cached results or null if not found/expired
	 */
	public List<QueryResult> getCachedSimilarFunctions(Program program, String cacheKey) {
		ProgramQueryCache cache = programCaches.get(program);
		if (cache == null) {
			statistics.recordMiss();
			return null;
		}

		List<QueryResult> results = cache.getSimilarFunctions(cacheKey);
		if (results != null) {
			statistics.recordHit();
		} else {
			statistics.recordMiss();
		}
		return results;
	}

	/**
	 * Caches similar function results.
	 *
	 * @param program the program
	 * @param cacheKey the cache key
	 * @param results the results to cache
	 */
	public void cacheSimilarFunctions(Program program, String cacheKey, List<QueryResult> results) {
		ProgramQueryCache cache = programCaches.get(program);
		if (cache != null) {
			cache.cacheSimilarFunctions(cacheKey, results);
		}
	}

	// --- Semantic Search Cache ---

	/**
	 * Retrieves cached semantic search results.
	 *
	 * @param program the program
	 * @param cacheKey the cache key
	 * @return cached results or null if not found/expired
	 */
	public List<QueryResult> getCachedSemanticSearch(Program program, String cacheKey) {
		ProgramQueryCache cache = programCaches.get(program);
		if (cache == null) {
			statistics.recordMiss();
			return null;
		}

		List<QueryResult> results = cache.getSemanticSearch(cacheKey);
		if (results != null) {
			statistics.recordHit();
		} else {
			statistics.recordMiss();
		}
		return results;
	}

	/**
	 * Caches semantic search results.
	 *
	 * @param program the program
	 * @param cacheKey the cache key
	 * @param results the results to cache
	 */
	public void cacheSemanticSearch(Program program, String cacheKey, List<QueryResult> results) {
		ProgramQueryCache cache = programCaches.get(program);
		if (cache != null) {
			cache.cacheSemanticSearch(cacheKey, results);
		}
	}

	// --- Pattern Search Cache ---

	/**
	 * Retrieves cached pattern search results.
	 *
	 * @param program the program
	 * @param cacheKey the cache key
	 * @return cached results or null if not found/expired
	 */
	public List<Address> getCachedPatternSearch(Program program, String cacheKey) {
		ProgramQueryCache cache = programCaches.get(program);
		if (cache == null) {
			statistics.recordMiss();
			return null;
		}

		List<Address> results = cache.getPatternSearch(cacheKey);
		if (results != null) {
			statistics.recordHit();
		} else {
			statistics.recordMiss();
		}
		return results;
	}

	/**
	 * Caches pattern search results.
	 *
	 * @param program the program
	 * @param cacheKey the cache key
	 * @param results the results to cache
	 */
	public void cachePatternSearch(Program program, String cacheKey, List<Address> results) {
		ProgramQueryCache cache = programCaches.get(program);
		if (cache != null) {
			cache.cachePatternSearch(cacheKey, results);
		}
	}

	// --- Context Cache ---

	/**
	 * Retrieves cached context for an address.
	 *
	 * @param program the program
	 * @param address the address
	 * @return cached context or null if not found/expired
	 */
	public QueryContext getCachedContext(Program program, Address address) {
		ProgramQueryCache cache = programCaches.get(program);
		if (cache == null) {
			statistics.recordMiss();
			return null;
		}

		QueryContext context = cache.getContext(address);
		if (context != null) {
			statistics.recordHit();
		} else {
			statistics.recordMiss();
		}
		return context;
	}

	/**
	 * Caches context for an address.
	 *
	 * @param program the program
	 * @param address the address
	 * @param context the context to cache
	 */
	public void cacheContext(Program program, Address address, QueryContext context) {
		ProgramQueryCache cache = programCaches.get(program);
		if (cache != null) {
			cache.cacheContext(address, context);
		}
	}

	// --- Configuration ---

	/**
	 * Sets the maximum cache size per program.
	 *
	 * @param maxSize the maximum size
	 */
	public void setMaxCacheSize(int maxSize) {
		this.maxCacheSize = maxSize;
	}

	/**
	 * Sets the cache TTL.
	 *
	 * @param ttlMs the TTL in milliseconds
	 */
	public void setCacheTtl(long ttlMs) {
		this.cacheTtlMs = ttlMs;
	}

	/**
	 * Returns cache statistics.
	 *
	 * @return the statistics
	 */
	public CacheStatistics getStatistics() {
		return statistics;
	}

	/**
	 * Per-program cache storage.
	 */
	private class ProgramQueryCache {
		private final Program program;

		// Cache types
		private final Map<String, CacheEntry<List<QueryResult>>> similarFunctionsCache =
			new ConcurrentHashMap<>();
		private final Map<String, CacheEntry<List<QueryResult>>> semanticSearchCache =
			new ConcurrentHashMap<>();
		private final Map<String, CacheEntry<List<Address>>> patternSearchCache =
			new ConcurrentHashMap<>();
		private final Map<Address, CacheEntry<QueryContext>> contextCache =
			new ConcurrentHashMap<>();

		ProgramQueryCache(Program program) {
			this.program = program;
		}

		int getEntryCount() {
			return similarFunctionsCache.size() + semanticSearchCache.size() +
				patternSearchCache.size() + contextCache.size();
		}

		// Similar functions
		List<QueryResult> getSimilarFunctions(String key) {
			return getFromCache(similarFunctionsCache, key);
		}

		void cacheSimilarFunctions(String key, List<QueryResult> results) {
			putInCache(similarFunctionsCache, key, results);
		}

		// Semantic search
		List<QueryResult> getSemanticSearch(String key) {
			return getFromCache(semanticSearchCache, key);
		}

		void cacheSemanticSearch(String key, List<QueryResult> results) {
			putInCache(semanticSearchCache, key, results);
		}

		// Pattern search
		List<Address> getPatternSearch(String key) {
			return getFromCache(patternSearchCache, key);
		}

		void cachePatternSearch(String key, List<Address> results) {
			putInCache(patternSearchCache, key, results);
		}

		// Context
		QueryContext getContext(Address address) {
			return getFromCache(contextCache, address);
		}

		void cacheContext(Address address, QueryContext context) {
			putInCache(contextCache, address, context);
		}

		// Invalidation methods
		int invalidateFunctionCaches() {
			int count = similarFunctionsCache.size();
			similarFunctionsCache.clear();
			// Also invalidate semantic search as it depends on function names
			count += semanticSearchCache.size();
			semanticSearchCache.clear();
			return count;
		}

		int invalidateSymbolCaches() {
			int count = semanticSearchCache.size();
			semanticSearchCache.clear();
			return count;
		}

		int invalidateCodeCaches() {
			int count = patternSearchCache.size() + contextCache.size();
			patternSearchCache.clear();
			contextCache.clear();
			return count;
		}

		int invalidateAll() {
			int count = getEntryCount();
			similarFunctionsCache.clear();
			semanticSearchCache.clear();
			patternSearchCache.clear();
			contextCache.clear();
			return count;
		}

		private <K, V> V getFromCache(Map<K, CacheEntry<V>> cache, K key) {
			CacheEntry<V> entry = cache.get(key);
			if (entry == null) {
				return null;
			}
			if (entry.isExpired(cacheTtlMs)) {
				cache.remove(key);
				return null;
			}
			entry.recordAccess();
			return entry.value;
		}

		private <K, V> void putInCache(Map<K, CacheEntry<V>> cache, K key, V value) {
			// Evict if cache is full
			if (cache.size() >= maxCacheSize) {
				evictOldestEntries(cache);
			}
			cache.put(key, new CacheEntry<>(value));
		}

		private <K, V> void evictOldestEntries(Map<K, CacheEntry<V>> cache) {
			// Remove 20% of oldest entries
			int toRemove = maxCacheSize / 5;
			cache.entrySet().stream()
				.sorted((a, b) -> Long.compare(a.getValue().lastAccessTime, b.getValue().lastAccessTime))
				.limit(toRemove)
				.map(Map.Entry::getKey)
				.toList()
				.forEach(cache::remove);
		}
	}

	/**
	 * Cache entry wrapper with timestamps.
	 */
	private static class CacheEntry<T> {
		final T value;
		final long createTime;
		volatile long lastAccessTime;

		CacheEntry(T value) {
			this.value = value;
			this.createTime = System.currentTimeMillis();
			this.lastAccessTime = this.createTime;
		}

		boolean isExpired(long ttlMs) {
			return System.currentTimeMillis() - createTime > ttlMs;
		}

		void recordAccess() {
			this.lastAccessTime = System.currentTimeMillis();
		}
	}

	/**
	 * Cache statistics collector.
	 */
	public static class CacheStatistics {
		private final AtomicLong hits = new AtomicLong();
		private final AtomicLong misses = new AtomicLong();
		private final AtomicLong invalidations = new AtomicLong();
		private final AtomicLong entriesInvalidated = new AtomicLong();

		void recordHit() {
			hits.incrementAndGet();
		}

		void recordMiss() {
			misses.incrementAndGet();
		}

		void recordInvalidation(int count) {
			invalidations.incrementAndGet();
			entriesInvalidated.addAndGet(count);
		}

		/**
		 * Returns the cache hit count.
		 * @return the hit count
		 */
		public long getHits() {
			return hits.get();
		}

		/**
		 * Returns the cache miss count.
		 * @return the miss count
		 */
		public long getMisses() {
			return misses.get();
		}

		/**
		 * Returns the cache hit rate (0.0 to 1.0).
		 * @return the hit rate
		 */
		public double getHitRate() {
			long total = hits.get() + misses.get();
			return total > 0 ? (double) hits.get() / total : 0.0;
		}

		/**
		 * Returns the total invalidation count.
		 * @return the invalidation count
		 */
		public long getInvalidations() {
			return invalidations.get();
		}

		/**
		 * Returns the total entries invalidated.
		 * @return the entries invalidated
		 */
		public long getEntriesInvalidated() {
			return entriesInvalidated.get();
		}

		/**
		 * Resets all statistics.
		 */
		public void reset() {
			hits.set(0);
			misses.set(0);
			invalidations.set(0);
			entriesInvalidated.set(0);
		}
	}
}
