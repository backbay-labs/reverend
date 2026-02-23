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

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;
import java.util.regex.Pattern;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.reverend.api.v1.QueryService.QueryContext;
import ghidra.reverend.api.v1.QueryService.QueryResult;
import ghidra.util.Msg;

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
	private static final int FEATURE_INDEX_SCHEMA_VERSION = 3;
	private static final int FEATURE_INDEX_FORMAT_VERSION = 1;
	private static final long MAX_INCREMENTAL_VERSION_DELTA = 1024;
	private static final String INDEX_DIR_PROPERTY = "ghidra.reverend.query.indexDir";
	private static final String DEFAULT_INDEX_DIR = ".reverend/query-index-v2";
	private static final Pattern TOKEN_SPLIT_PATTERN = Pattern.compile("[^a-z0-9]+");

	private final Map<Program, ProgramQueryCache> programCaches = new ConcurrentHashMap<>();
	private final CacheStatistics statistics = new CacheStatistics();
	private final Path persistenceRoot;

	private int maxCacheSize = DEFAULT_MAX_CACHE_SIZE;
	private long cacheTtlMs = DEFAULT_CACHE_TTL_MS;

	/**
	 * Creates a new QueryCacheManager with default settings.
	 */
	public QueryCacheManager() {
		this(resolvePersistenceRoot());
	}

	QueryCacheManager(Path persistenceRoot) {
		this.persistenceRoot = Objects.requireNonNull(persistenceRoot, "persistenceRoot");
	}

	/**
	 * Initializes caches for the given program.
	 *
	 * @param program the program to initialize caches for
	 */
	public void initializeForProgram(Program program) {
		programCaches.computeIfAbsent(program, p -> {
			ProgramQueryCache cache = new ProgramQueryCache(p);
			cache.loadPersistedFeatureIndex();
			cache.reconcileWithCurrentProgramVersion();
			cache.verifyAndRepairIndexConsistency();
			cache.persistFeatureIndex();
			return cache;
		});
	}

	/**
	 * Invalidates all caches for the given program.
	 *
	 * @param program the program to invalidate caches for
	 */
	public void invalidateProgram(Program program) {
		ProgramQueryCache cache = programCaches.remove(program);
		if (cache != null) {
			cache.persistFeatureIndex();
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
	 * Incrementally invalidates function-related caches for specific function entries.
	 *
	 * @param program the program to invalidate function caches for
	 * @param functionEntries changed function entry points
	 */
	public void invalidateFunctionCaches(Program program, Collection<Address> functionEntries) {
		ProgramQueryCache cache = programCaches.get(program);
		if (cache == null) {
			return;
		}
		if (functionEntries == null || functionEntries.isEmpty()) {
			int count = cache.invalidateFunctionCaches();
			statistics.recordInvalidation(count);
			return;
		}
		int count = cache.invalidateFunctionCaches(functionEntries);
		statistics.recordInvalidation(count);
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
	 * Incrementally invalidates code-related caches for an address range.
	 *
	 * @param program the program to invalidate code caches for
	 * @param start start address (inclusive)
	 * @param end end address (inclusive)
	 */
	public void invalidateCodeCaches(Program program, Address start, Address end) {
		ProgramQueryCache cache = programCaches.get(program);
		if (cache == null) {
			return;
		}
		int count = cache.invalidateCodeCaches(start, end);
		statistics.recordInvalidation(count);
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

	/**
	 * Verifies and repairs index consistency for the given program.
	 *
	 * @param program the program whose index should be checked
	 * @return true if repair actions were performed
	 */
	public boolean verifyAndRepairIndex(Program program) {
		ProgramQueryCache cache = programCaches.get(program);
		return cache != null && cache.verifyAndRepairIndexConsistency();
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

	/**
	 * Ensures indexed function features exist for the provided functions.
	 *
	 * @param program the program
	 * @param functions functions that should have indexed features
	 * @return feature batch containing indexed/reused counts and feature lookup map
	 */
	public FunctionFeatureBatch ensureFunctionFeatures(Program program,
			Collection<Function> functions) {
		ProgramQueryCache cache = programCaches.get(program);
		if (cache == null || functions == null || functions.isEmpty()) {
			return FunctionFeatureBatch.empty();
		}
		return cache.ensureFunctionFeatures(functions);
	}

	/**
	 * Returns indexed features for a function entry if present.
	 *
	 * @param program the program
	 * @param functionEntry function entry address
	 * @return indexed features or {@code null} if not indexed
	 */
	public IndexedFunctionFeatures getIndexedFunctionFeatures(Program program, Address functionEntry) {
		ProgramQueryCache cache = programCaches.get(program);
		if (cache == null || functionEntry == null) {
			return null;
		}
		return cache.getIndexedFunctionFeatures(functionEntry);
	}

	/**
	 * Returns how many function feature entries are indexed for the program.
	 *
	 * @param program the program
	 * @return indexed feature entry count
	 */
	public int getIndexedFunctionFeatureCount(Program program) {
		ProgramQueryCache cache = programCaches.get(program);
		return cache != null ? cache.getIndexedFunctionFeatureCount() : 0;
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
		private final String programIdentity;
		private final Path indexPath;

		// Cache types
		private final Map<String, CacheEntry<List<QueryResult>>> similarFunctionsCache =
			new ConcurrentHashMap<>();
		private final Map<String, CacheEntry<List<QueryResult>>> semanticSearchCache =
			new ConcurrentHashMap<>();
		private final Map<String, CacheEntry<List<Address>>> patternSearchCache =
			new ConcurrentHashMap<>();
		private final Map<Address, CacheEntry<QueryContext>> contextCache =
			new ConcurrentHashMap<>();
		private final Map<String, IndexedFunctionFeatures> functionFeatureIndex =
			new ConcurrentHashMap<>();
		private final Set<String> similarFeatureKeys = ConcurrentHashMap.newKeySet();
		private final Set<String> semanticFeatureKeys = ConcurrentHashMap.newKeySet();
		private final Set<String> patternFeatureKeys = ConcurrentHashMap.newKeySet();
		private final Set<String> contextFeatureAddresses = ConcurrentHashMap.newKeySet();
		private final Map<String, Set<String>> semanticKeysByFunctionEntry = new ConcurrentHashMap<>();
		private final Map<String, Set<String>> functionEntriesBySemanticKey = new ConcurrentHashMap<>();
		private final Map<String, Set<String>> patternKeysByAddress = new ConcurrentHashMap<>();
		private final Map<String, Set<String>> addressesByPatternKey = new ConcurrentHashMap<>();
		private volatile long lastKnownProgramVersion;

		ProgramQueryCache(Program program) {
			this.program = program;
			this.programIdentity = buildProgramIdentity(program);
			this.indexPath = resolveIndexPath(programIdentity);
			this.lastKnownProgramVersion = safeGetProgramVersion(program);
		}

		int getEntryCount() {
			return similarFunctionsCache.size() + semanticSearchCache.size() +
				patternSearchCache.size() + contextCache.size() + functionFeatureIndex.size();
		}

		// Similar functions
		List<QueryResult> getSimilarFunctions(String key) {
			return getFromCache(similarFunctionsCache, key);
		}

		void cacheSimilarFunctions(String key, List<QueryResult> results) {
			putInCache(similarFunctionsCache, key, results);
			similarFeatureKeys.add(key);
			touchProgramVersion();
			persistFeatureIndex();
		}

		// Semantic search
		List<QueryResult> getSemanticSearch(String key) {
			return getFromCache(semanticSearchCache, key);
		}

		void cacheSemanticSearch(String key, List<QueryResult> results) {
			putInCache(semanticSearchCache, key, results);
			semanticFeatureKeys.add(key);
			updateSemanticReverseIndex(key, results);
			touchProgramVersion();
			persistFeatureIndex();
		}

		// Pattern search
		List<Address> getPatternSearch(String key) {
			return getFromCache(patternSearchCache, key);
		}

		void cachePatternSearch(String key, List<Address> results) {
			putInCache(patternSearchCache, key, results);
			patternFeatureKeys.add(key);
			updatePatternReverseIndex(key, results);
			touchProgramVersion();
			persistFeatureIndex();
		}

		// Context
		QueryContext getContext(Address address) {
			QueryContext context = getFromCache(contextCache, address);
			if (context == null) {
				contextFeatureAddresses.remove(addressKey(address));
			}
			return context;
		}

		void cacheContext(Address address, QueryContext context) {
			putInCache(contextCache, address, context);
			contextFeatureAddresses.add(addressKey(address));
			touchProgramVersion();
			persistFeatureIndex();
		}

		FunctionFeatureBatch ensureFunctionFeatures(Collection<Function> functions) {
			if (functions == null || functions.isEmpty()) {
				return FunctionFeatureBatch.empty();
			}

			int indexedCount = 0;
			int reusedCount = 0;
			Map<String, IndexedFunctionFeatures> features = new HashMap<>();
			for (Function function : functions) {
				if (function == null || function.getEntryPoint() == null) {
					continue;
				}
				String entryKey = addressKey(function.getEntryPoint());
				IndexedFunctionFeatures existing = functionFeatureIndex.get(entryKey);
				if (existing != null) {
					reusedCount++;
					features.put(entryKey, existing);
					continue;
				}
				IndexedFunctionFeatures created = IndexedFunctionFeatures.fromFunction(function);
				functionFeatureIndex.put(entryKey, created);
				features.put(entryKey, created);
				indexedCount++;
			}

			if (indexedCount > 0) {
				touchProgramVersion();
				persistFeatureIndex();
			}
			return new FunctionFeatureBatch(features, indexedCount, reusedCount);
		}

		IndexedFunctionFeatures getIndexedFunctionFeatures(Address functionEntry) {
			return functionEntry != null ? functionFeatureIndex.get(addressKey(functionEntry)) : null;
		}

		int getIndexedFunctionFeatureCount() {
			return functionFeatureIndex.size();
		}

		// Invalidation methods
		int invalidateFunctionCaches() {
			int count = similarFunctionsCache.size();
			similarFunctionsCache.clear();
			similarFeatureKeys.clear();
			count += semanticSearchCache.size();
			semanticSearchCache.clear();
			semanticFeatureKeys.clear();
			semanticKeysByFunctionEntry.clear();
			functionEntriesBySemanticKey.clear();
			count += functionFeatureIndex.size();
			functionFeatureIndex.clear();
			touchProgramVersion();
			persistFeatureIndex();
			return count;
		}

		int invalidateFunctionCaches(Collection<Address> functionEntries) {
			Set<String> functionKeys = new HashSet<>();
			for (Address entryPoint : functionEntries) {
				if (entryPoint != null) {
					functionKeys.add(addressKey(entryPoint));
				}
			}
			int count = invalidateFunctionCachesByKeys(functionKeys);
			if (count > 0) {
				touchProgramVersion();
				persistFeatureIndex();
			}
			return count;
		}

		private int invalidateFunctionCachesByKeys(Collection<String> functionKeys) {
			if (functionKeys == null || functionKeys.isEmpty()) {
				return 0;
			}
			int count = 0;
			for (String functionKey : functionKeys) {
				Address entryPoint = resolveAddress(program, functionKey);
				if (entryPoint != null) {
					String similarKey = CacheKeyGenerator.forSimilarFunctions(entryPoint.toString());
					if (similarFunctionsCache.remove(similarKey) != null) {
						count++;
					}
					similarFeatureKeys.remove(similarKey);
				}
				else {
					count += similarFunctionsCache.size();
					similarFunctionsCache.clear();
					similarFeatureKeys.clear();
				}

				if (functionFeatureIndex.remove(functionKey) != null) {
					count++;
				}
				Set<String> semanticKeys = semanticKeysByFunctionEntry.remove(functionKey);
				if (semanticKeys == null) {
					continue;
				}
				for (String semanticKey : semanticKeys) {
					if (semanticSearchCache.remove(semanticKey) != null) {
						count++;
					}
					semanticFeatureKeys.remove(semanticKey);
					Set<String> linkedFunctions = functionEntriesBySemanticKey.remove(semanticKey);
					if (linkedFunctions != null) {
						for (String linkedFunction : linkedFunctions) {
							Set<String> keys = semanticKeysByFunctionEntry.get(linkedFunction);
							if (keys != null) {
								keys.remove(semanticKey);
								if (keys.isEmpty()) {
									semanticKeysByFunctionEntry.remove(linkedFunction);
								}
							}
						}
					}
				}
			}
			return count;
		}

		int invalidateSymbolCaches() {
			int count = semanticSearchCache.size();
			semanticSearchCache.clear();
			semanticFeatureKeys.clear();
			semanticKeysByFunctionEntry.clear();
			functionEntriesBySemanticKey.clear();
			touchProgramVersion();
			persistFeatureIndex();
			return count;
		}

		int invalidateCodeCaches() {
			int count = patternSearchCache.size() + contextCache.size();
			patternSearchCache.clear();
			contextCache.clear();
			patternFeatureKeys.clear();
			contextFeatureAddresses.clear();
			patternKeysByAddress.clear();
			addressesByPatternKey.clear();
			count += similarFunctionsCache.size();
			similarFunctionsCache.clear();
			similarFeatureKeys.clear();
			count += semanticSearchCache.size();
			semanticSearchCache.clear();
			semanticFeatureKeys.clear();
			semanticKeysByFunctionEntry.clear();
			functionEntriesBySemanticKey.clear();
			count += functionFeatureIndex.size();
			functionFeatureIndex.clear();
			touchProgramVersion();
			persistFeatureIndex();
			return count;
		}

		int invalidateCodeCaches(Address start, Address end) {
			if (start == null || end == null) {
				return invalidateCodeCaches();
			}
			if (!Objects.equals(start.getAddressSpace(), end.getAddressSpace())) {
				return invalidateCodeCaches();
			}

			long minOffset = Math.min(start.getOffset(), end.getOffset());
			long maxOffset = Math.max(start.getOffset(), end.getOffset());
			String space = start.getAddressSpace().getName();
			int count = 0;

			Set<String> affectedPatternKeys = new HashSet<>();
			for (String encodedAddress : patternKeysByAddress.keySet()) {
				AddressKey parsed = AddressKey.parse(encodedAddress);
				if (parsed != null && parsed.isWithin(space, minOffset, maxOffset)) {
					Set<String> keys = patternKeysByAddress.remove(encodedAddress);
					if (keys != null) {
						affectedPatternKeys.addAll(keys);
					}
				}
			}
			for (String patternKey : affectedPatternKeys) {
				if (patternSearchCache.remove(patternKey) != null) {
					count++;
				}
				patternFeatureKeys.remove(patternKey);
				Set<String> linkedAddresses = addressesByPatternKey.remove(patternKey);
				if (linkedAddresses != null) {
					for (String linkedAddress : linkedAddresses) {
						Set<String> keys = patternKeysByAddress.get(linkedAddress);
						if (keys != null) {
							keys.remove(patternKey);
							if (keys.isEmpty()) {
								patternKeysByAddress.remove(linkedAddress);
							}
						}
					}
				}
			}

			for (Address address : new ArrayList<>(contextCache.keySet())) {
				if (address != null && Objects.equals(address.getAddressSpace(), start.getAddressSpace())) {
					long offset = address.getOffset();
					if (offset >= minOffset && offset <= maxOffset) {
						if (contextCache.remove(address) != null) {
							count++;
						}
						contextFeatureAddresses.remove(addressKey(address));
					}
				}
			}

			Set<String> affectedFunctionKeys = new HashSet<>();
			for (Map.Entry<String, IndexedFunctionFeatures> entry : new ArrayList<>(functionFeatureIndex.entrySet())) {
				IndexedFunctionFeatures feature = entry.getValue();
				if (feature != null && feature.overlapsRange(space, minOffset, maxOffset)) {
					affectedFunctionKeys.add(entry.getKey());
				}
			}
			if (!affectedFunctionKeys.isEmpty()) {
				count += invalidateFunctionCachesByKeys(affectedFunctionKeys);
			}

			if (count > 0) {
				touchProgramVersion();
				persistFeatureIndex();
			}
			return count;
		}

		int invalidateAll() {
			int count = getEntryCount();
			similarFunctionsCache.clear();
			semanticSearchCache.clear();
			patternSearchCache.clear();
			contextCache.clear();
			functionFeatureIndex.clear();
			similarFeatureKeys.clear();
			semanticFeatureKeys.clear();
			patternFeatureKeys.clear();
			contextFeatureAddresses.clear();
			semanticKeysByFunctionEntry.clear();
			functionEntriesBySemanticKey.clear();
			patternKeysByAddress.clear();
			addressesByPatternKey.clear();
			touchProgramVersion();
			persistFeatureIndex();
			return count;
		}

		private <K, V> V getFromCache(Map<K, CacheEntry<V>> cache, K key) {
			CacheEntry<V> entry = cache.get(key);
			if (entry == null) {
				return null;
			}
			if (entry.isExpired(cacheTtlMs)) {
				cache.remove(key);
				if (cache == semanticSearchCache && key instanceof String semanticKey) {
					removeSemanticIndex(semanticKey);
				} else if (cache == patternSearchCache && key instanceof String patternKey) {
					removePatternIndex(patternKey);
				} else if (cache == similarFunctionsCache && key instanceof String similarKey) {
					similarFeatureKeys.remove(similarKey);
				} else if (cache == contextCache && key instanceof Address address) {
					contextFeatureAddresses.remove(addressKey(address));
				}
				persistFeatureIndex();
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
				.forEach(evictedKey -> {
					cache.remove(evictedKey);
					if (cache == semanticSearchCache && evictedKey instanceof String semanticKey) {
						removeSemanticIndex(semanticKey);
					} else if (cache == patternSearchCache && evictedKey instanceof String patternKey) {
						removePatternIndex(patternKey);
					} else if (cache == similarFunctionsCache && evictedKey instanceof String similarKey) {
						similarFeatureKeys.remove(similarKey);
					} else if (cache == contextCache && evictedKey instanceof Address address) {
						contextFeatureAddresses.remove(addressKey(address));
					}
				});
		}

		boolean verifyAndRepairIndexConsistency() {
			boolean repaired = false;

			repaired |= pruneReverseIndexKeys(functionEntriesBySemanticKey, semanticFeatureKeys);
			repaired |= pruneReverseIndexKeys(addressesByPatternKey, patternFeatureKeys);

			Map<String, Set<String>> rebuiltSemanticByFunction = rebuildInverse(functionEntriesBySemanticKey);
			if (!mapsEqual(semanticKeysByFunctionEntry, rebuiltSemanticByFunction)) {
				semanticKeysByFunctionEntry.clear();
				semanticKeysByFunctionEntry.putAll(rebuiltSemanticByFunction);
				repaired = true;
			}

			Map<String, Set<String>> rebuiltPatternByAddress = rebuildInverse(addressesByPatternKey);
			if (!mapsEqual(patternKeysByAddress, rebuiltPatternByAddress)) {
				patternKeysByAddress.clear();
				patternKeysByAddress.putAll(rebuiltPatternByAddress);
				repaired = true;
			}

			if (repaired) {
				persistFeatureIndex();
			}
			return repaired;
		}

		void reconcileWithCurrentProgramVersion() {
			long currentVersion = safeGetProgramVersion(program);
			if (currentVersion < 0 || lastKnownProgramVersion < 0 || currentVersion == lastKnownProgramVersion) {
				lastKnownProgramVersion = currentVersion;
				return;
			}
			long delta = Math.abs(currentVersion - lastKnownProgramVersion);
			if (delta > MAX_INCREMENTAL_VERSION_DELTA) {
				invalidateAll();
				return;
			}
			lastKnownProgramVersion = currentVersion;
		}

		void loadPersistedFeatureIndex() {
			if (!Files.exists(indexPath)) {
				return;
			}
			try (ObjectInputStream in = new ObjectInputStream(Files.newInputStream(indexPath))) {
				Object object = in.readObject();
				if (!(object instanceof PersistedFeatureIndex persisted)) {
					return;
				}
				if (!persisted.isCompatible(programIdentity)) {
					return;
				}
				similarFeatureKeys.clear();
				similarFeatureKeys.addAll(persisted.similarFeatureKeys);
				semanticFeatureKeys.clear();
				semanticFeatureKeys.addAll(persisted.semanticFeatureKeys);
				patternFeatureKeys.clear();
				patternFeatureKeys.addAll(persisted.patternFeatureKeys);
				contextFeatureAddresses.clear();
				contextFeatureAddresses.addAll(persisted.contextFeatureAddresses);
				functionFeatureIndex.clear();
				functionFeatureIndex.putAll(copyFeatureMap(persisted.functionFeatureIndex));
				functionEntriesBySemanticKey.clear();
				functionEntriesBySemanticKey.putAll(copyMap(persisted.functionEntriesBySemanticKey));
				addressesByPatternKey.clear();
				addressesByPatternKey.putAll(copyMap(persisted.addressesByPatternKey));
				semanticKeysByFunctionEntry.clear();
				semanticKeysByFunctionEntry.putAll(copyMap(persisted.semanticKeysByFunctionEntry));
				patternKeysByAddress.clear();
				patternKeysByAddress.putAll(copyMap(persisted.patternKeysByAddress));
				lastKnownProgramVersion = persisted.lastKnownProgramVersion;
			} catch (IOException | ClassNotFoundException e) {
				Msg.debug(this, "Failed to load query feature index from " + indexPath + ": " + e.getMessage());
			}
		}

		void persistFeatureIndex() {
			try {
				Files.createDirectories(indexPath.getParent());
				PersistedFeatureIndex snapshot = PersistedFeatureIndex.create(
					programIdentity,
					lastKnownProgramVersion,
					similarFeatureKeys,
					semanticFeatureKeys,
					patternFeatureKeys,
					contextFeatureAddresses,
					functionFeatureIndex,
					functionEntriesBySemanticKey,
					semanticKeysByFunctionEntry,
					addressesByPatternKey,
					patternKeysByAddress);
				try (ObjectOutputStream out = new ObjectOutputStream(Files.newOutputStream(indexPath))) {
					out.writeObject(snapshot);
				}
			} catch (IOException e) {
				Msg.debug(this, "Failed to persist query feature index to " + indexPath + ": " + e.getMessage());
			}
		}

		private void touchProgramVersion() {
			lastKnownProgramVersion = safeGetProgramVersion(program);
		}

		private void updateSemanticReverseIndex(String semanticKey, List<QueryResult> results) {
			removeSemanticIndex(semanticKey);
			Set<String> functionEntries = new HashSet<>();
			if (results != null) {
				for (QueryResult result : results) {
					Address address = result.getAddress();
					if (address == null) {
						continue;
					}
					String functionKey = addressKey(address);
					functionEntries.add(functionKey);
					semanticKeysByFunctionEntry
						.computeIfAbsent(functionKey, ignored -> ConcurrentHashMap.newKeySet())
						.add(semanticKey);
				}
			}
			if (!functionEntries.isEmpty()) {
				functionEntriesBySemanticKey.put(semanticKey, functionEntries);
			}
		}

		private void updatePatternReverseIndex(String patternKey, List<Address> addresses) {
			removePatternIndex(patternKey);
			Set<String> addressKeys = new HashSet<>();
			if (addresses != null) {
				for (Address address : addresses) {
					if (address == null) {
						continue;
					}
					String encodedAddress = addressKey(address);
					addressKeys.add(encodedAddress);
					patternKeysByAddress
						.computeIfAbsent(encodedAddress, ignored -> ConcurrentHashMap.newKeySet())
						.add(patternKey);
				}
			}
			if (!addressKeys.isEmpty()) {
				addressesByPatternKey.put(patternKey, addressKeys);
			}
		}

		private void removeSemanticIndex(String semanticKey) {
			semanticFeatureKeys.remove(semanticKey);
			Set<String> linkedFunctions = functionEntriesBySemanticKey.remove(semanticKey);
			if (linkedFunctions == null) {
				return;
			}
			for (String functionKey : linkedFunctions) {
				Set<String> semanticKeys = semanticKeysByFunctionEntry.get(functionKey);
				if (semanticKeys == null) {
					continue;
				}
				semanticKeys.remove(semanticKey);
				if (semanticKeys.isEmpty()) {
					semanticKeysByFunctionEntry.remove(functionKey);
				}
			}
		}

		private void removePatternIndex(String patternKey) {
			patternFeatureKeys.remove(patternKey);
			Set<String> linkedAddresses = addressesByPatternKey.remove(patternKey);
			if (linkedAddresses == null) {
				return;
			}
			for (String addressKey : linkedAddresses) {
				Set<String> patternKeys = patternKeysByAddress.get(addressKey);
				if (patternKeys == null) {
					continue;
				}
				patternKeys.remove(patternKey);
				if (patternKeys.isEmpty()) {
					patternKeysByAddress.remove(addressKey);
				}
			}
		}

		private boolean pruneReverseIndexKeys(Map<String, Set<String>> keyToValues,
				Set<String> validKeys) {
			boolean changed = false;
			for (Map.Entry<String, Set<String>> entry : new ArrayList<>(keyToValues.entrySet())) {
				if (!validKeys.contains(entry.getKey())) {
					keyToValues.remove(entry.getKey());
					changed = true;
				}
			}
			return changed;
		}

		private Map<String, Set<String>> rebuildInverse(Map<String, Set<String>> forward) {
			Map<String, Set<String>> inverse = new HashMap<>();
			for (Map.Entry<String, Set<String>> entry : forward.entrySet()) {
				String key = entry.getKey();
				for (String value : entry.getValue()) {
					inverse.computeIfAbsent(value, ignored -> new HashSet<>()).add(key);
				}
			}
			return inverse;
		}

		private boolean mapsEqual(Map<String, Set<String>> a, Map<String, Set<String>> b) {
			if (a.size() != b.size()) {
				return false;
			}
			for (Map.Entry<String, Set<String>> entry : a.entrySet()) {
				Set<String> otherValues = b.get(entry.getKey());
				if (otherValues == null || !Objects.equals(new HashSet<>(entry.getValue()), new HashSet<>(otherValues))) {
					return false;
				}
			}
			return true;
		}

		private Map<String, Set<String>> copyMap(Map<String, Set<String>> map) {
			Map<String, Set<String>> copy = new HashMap<>();
			for (Map.Entry<String, Set<String>> entry : map.entrySet()) {
				copy.put(entry.getKey(), new HashSet<>(entry.getValue()));
			}
			return copy;
		}

		private Map<String, IndexedFunctionFeatures> copyFeatureMap(
				Map<String, IndexedFunctionFeatures> source) {
			Map<String, IndexedFunctionFeatures> copy = new HashMap<>();
			if (source == null) {
				return copy;
			}
			for (Map.Entry<String, IndexedFunctionFeatures> entry : source.entrySet()) {
				IndexedFunctionFeatures value = entry.getValue();
				if (entry.getKey() != null && value != null) {
					copy.put(entry.getKey(), value);
				}
			}
			return copy;
		}
	}

	private static final class AddressKey {
		private final String spaceName;
		private final long offset;

		private AddressKey(String spaceName, long offset) {
			this.spaceName = spaceName;
			this.offset = offset;
		}

		static AddressKey parse(String encoded) {
			if (encoded == null) {
				return null;
			}
			int separator = encoded.lastIndexOf(':');
			if (separator <= 0 || separator == encoded.length() - 1) {
				return null;
			}
			try {
				String space = encoded.substring(0, separator);
				long parsedOffset = Long.parseUnsignedLong(encoded.substring(separator + 1), 16);
				return new AddressKey(space, parsedOffset);
			} catch (NumberFormatException e) {
				return null;
			}
		}

		boolean isWithin(String space, long minOffset, long maxOffset) {
			return Objects.equals(spaceName, space) && offset >= minOffset && offset <= maxOffset;
		}
	}

	private static Path resolvePersistenceRoot() {
		String configuredDir = System.getProperty(INDEX_DIR_PROPERTY);
		if (configuredDir != null && !configuredDir.isBlank()) {
			return Paths.get(configuredDir);
		}
		String userHome = System.getProperty("user.home", ".");
		return Paths.get(userHome, DEFAULT_INDEX_DIR);
	}

	private Path resolveIndexPath(String programIdentity) {
		String safeIdentity = programIdentity.replaceAll("[^a-zA-Z0-9._-]", "_");
		return persistenceRoot.resolve(safeIdentity + ".bin");
	}

	private static String buildProgramIdentity(Program program) {
		long uniqueId = safeCall(program::getUniqueProgramID, -1L);
		if (uniqueId >= 0) {
			return "program-id:" + uniqueId;
		}
		String executablePath = safeCall(program::getExecutablePath, null);
		if (executablePath != null && !executablePath.isBlank()) {
			return "exec:" + executablePath;
		}
		String name = safeCall(program::getName, "unknown-program");
		return "name:" + name + ":" + Integer.toHexString(System.identityHashCode(program));
	}

	private static long safeGetProgramVersion(Program program) {
		return safeCall(program::getModificationNumber, -1L);
	}

	private static String addressKey(Address address) {
		if (address == null) {
			return "null";
		}
		return address.getAddressSpace().getName() + ":" + Long.toUnsignedString(address.getOffset(), 16);
	}

	private static Address resolveAddress(Program program, String encodedAddress) {
		if (program == null || encodedAddress == null) {
			return null;
		}
		AddressKey key = AddressKey.parse(encodedAddress);
		if (key == null) {
			return null;
		}
		try {
			return program.getAddressFactory()
				.getAddressSpace(key.spaceName)
				.getAddress(key.offset);
		}
		catch (RuntimeException e) {
			return null;
		}
	}

	private static <T> T safeCall(Supplier<T> supplier, T fallback) {
		try {
			T value = supplier.get();
			return value != null ? value : fallback;
		} catch (RuntimeException e) {
			return fallback;
		}
	}

	private static String normalize(String value) {
		if (value == null) {
			return "";
		}
		return value.trim().toLowerCase(Locale.ROOT);
	}

	private static Set<String> tokenize(String... values) {
		Set<String> tokens = new HashSet<>();
		if (values == null) {
			return tokens;
		}
		for (String value : values) {
			if (value == null || value.isBlank()) {
				continue;
			}
			String[] split = TOKEN_SPLIT_PATTERN.split(value);
			for (String token : split) {
				if (!token.isBlank()) {
					tokens.add(token);
				}
			}
		}
		return tokens;
	}

	public static final class FunctionFeatureBatch {
		private static final FunctionFeatureBatch EMPTY =
			new FunctionFeatureBatch(Collections.emptyMap(), 0, 0);

		private final Map<String, IndexedFunctionFeatures> featuresByEntryKey;
		private final int indexedCount;
		private final int reusedCount;

		private FunctionFeatureBatch(Map<String, IndexedFunctionFeatures> featuresByEntryKey,
				int indexedCount, int reusedCount) {
			this.featuresByEntryKey = Collections.unmodifiableMap(new HashMap<>(featuresByEntryKey));
			this.indexedCount = indexedCount;
			this.reusedCount = reusedCount;
		}

		static FunctionFeatureBatch empty() {
			return EMPTY;
		}

		public int getIndexedCount() {
			return indexedCount;
		}

		public int getReusedCount() {
			return reusedCount;
		}

		public int getFeatureCount() {
			return featuresByEntryKey.size();
		}

		public IndexedFunctionFeatures get(Address entryAddress) {
			if (entryAddress == null) {
				return null;
			}
			return featuresByEntryKey.get(addressKey(entryAddress));
		}

		public Map<String, IndexedFunctionFeatures> asMap() {
			return featuresByEntryKey;
		}
	}

	public static final class IndexedFunctionFeatures implements Serializable {
		private static final long serialVersionUID = 1L;

		private final String entryKey;
		private final String functionName;
		private final String normalizedFunctionName;
		private final String normalizedComment;
		private final String normalizedReturnType;
		private final String normalizedCallingConvention;
		private final int parameterCount;
		private final long bodySize;
		private final int callCount;
		private final String bodyMinKey;
		private final String bodyMaxKey;
		private final Set<String> lexicalTokens;

		private IndexedFunctionFeatures(String entryKey, String functionName,
				String normalizedFunctionName, String normalizedComment, String normalizedReturnType,
				String normalizedCallingConvention, int parameterCount, long bodySize,
				int callCount, String bodyMinKey, String bodyMaxKey, Set<String> lexicalTokens) {
			this.entryKey = entryKey;
			this.functionName = functionName;
			this.normalizedFunctionName = normalizedFunctionName;
			this.normalizedComment = normalizedComment;
			this.normalizedReturnType = normalizedReturnType;
			this.normalizedCallingConvention = normalizedCallingConvention;
			this.parameterCount = parameterCount;
			this.bodySize = bodySize;
			this.callCount = callCount;
			this.bodyMinKey = bodyMinKey;
			this.bodyMaxKey = bodyMaxKey;
			this.lexicalTokens = Collections.unmodifiableSet(new HashSet<>(lexicalTokens));
		}

		static IndexedFunctionFeatures fromFunction(Function function) {
			Address entry = function.getEntryPoint();
			Address bodyMin = function.getBody() != null ? function.getBody().getMinAddress() : null;
			Address bodyMax = function.getBody() != null ? function.getBody().getMaxAddress() : null;
			long size = function.getBody() != null ? function.getBody().getNumAddresses() : 0;
			int calls = getCallCount(function);
			String functionName = safeString(function.getName(), "unknown");
			String normalizedName = normalize(functionName);
			String normalizedComment = normalize(function.getComment());
			String normalizedReturnType = normalize(
				function.getReturnType() != null ? function.getReturnType().toString() : "");
			String normalizedCallingConvention = normalize(function.getCallingConventionName());
			Set<String> lexicalTokens = tokenize(normalizedName, normalizedComment);
			return new IndexedFunctionFeatures(
				addressKey(entry),
				functionName,
				normalizedName,
				normalizedComment,
				normalizedReturnType,
				normalizedCallingConvention,
				function.getParameterCount(),
				size,
				calls,
				addressKey(bodyMin != null ? bodyMin : entry),
				addressKey(bodyMax != null ? bodyMax : entry),
				lexicalTokens);
		}

		public String getEntryKey() {
			return entryKey;
		}

		public String getFunctionName() {
			return functionName;
		}

		public String getNormalizedFunctionName() {
			return normalizedFunctionName;
		}

		public String getNormalizedComment() {
			return normalizedComment;
		}

		public String getNormalizedReturnType() {
			return normalizedReturnType;
		}

		public String getNormalizedCallingConvention() {
			return normalizedCallingConvention;
		}

		public int getParameterCount() {
			return parameterCount;
		}

		public long getBodySize() {
			return bodySize;
		}

		public int getCallCount() {
			return callCount;
		}

		public Set<String> getLexicalTokens() {
			return lexicalTokens;
		}

		boolean overlapsRange(String spaceName, long minOffset, long maxOffset) {
			AddressKey min = AddressKey.parse(bodyMinKey);
			AddressKey max = AddressKey.parse(bodyMaxKey);
			if (min == null || max == null) {
				return false;
			}
			if (!Objects.equals(min.spaceName, spaceName) || !Objects.equals(max.spaceName, spaceName)) {
				return false;
			}
			long bodyMin = Math.min(min.offset, max.offset);
			long bodyMax = Math.max(min.offset, max.offset);
			return bodyMax >= minOffset && bodyMin <= maxOffset;
		}

		private static int getCallCount(Function function) {
			if (function == null || function.getBody() == null || function.getBody().isEmpty()) {
				return 0;
			}
			int calls = 0;
			try {
				InstructionIterator instructions = function.getProgram().getListing()
					.getInstructions(function.getBody(), true);
				while (instructions.hasNext()) {
					Instruction instruction = instructions.next();
					if (instruction.getFlowType().isCall()) {
						calls++;
					}
				}
			}
			catch (RuntimeException e) {
				return 0;
			}
			return calls;
		}

		private static String safeString(String value, String fallback) {
			if (value == null) {
				return fallback;
			}
			String trimmed = value.trim();
			return trimmed.isEmpty() ? fallback : trimmed;
		}
	}

	private static final class PersistedFeatureIndex implements Serializable {
		private static final long serialVersionUID = 1L;

		private final int schemaVersion;
		private final int formatVersion;
		private final String programIdentity;
		private final long lastKnownProgramVersion;
		private final Set<String> similarFeatureKeys;
		private final Set<String> semanticFeatureKeys;
		private final Set<String> patternFeatureKeys;
		private final Set<String> contextFeatureAddresses;
		private final Map<String, IndexedFunctionFeatures> functionFeatureIndex;
		private final Map<String, Set<String>> functionEntriesBySemanticKey;
		private final Map<String, Set<String>> semanticKeysByFunctionEntry;
		private final Map<String, Set<String>> addressesByPatternKey;
		private final Map<String, Set<String>> patternKeysByAddress;

		private PersistedFeatureIndex(String programIdentity, long lastKnownProgramVersion,
				Set<String> similarFeatureKeys, Set<String> semanticFeatureKeys,
				Set<String> patternFeatureKeys, Set<String> contextFeatureAddresses,
				Map<String, IndexedFunctionFeatures> functionFeatureIndex,
				Map<String, Set<String>> functionEntriesBySemanticKey,
				Map<String, Set<String>> semanticKeysByFunctionEntry,
				Map<String, Set<String>> addressesByPatternKey,
				Map<String, Set<String>> patternKeysByAddress) {
			this.schemaVersion = FEATURE_INDEX_SCHEMA_VERSION;
			this.formatVersion = FEATURE_INDEX_FORMAT_VERSION;
			this.programIdentity = programIdentity;
			this.lastKnownProgramVersion = lastKnownProgramVersion;
			this.similarFeatureKeys = new TreeSet<>(similarFeatureKeys);
			this.semanticFeatureKeys = new TreeSet<>(semanticFeatureKeys);
			this.patternFeatureKeys = new TreeSet<>(patternFeatureKeys);
			this.contextFeatureAddresses = new TreeSet<>(contextFeatureAddresses);
			this.functionFeatureIndex = normalizeFeatures(functionFeatureIndex);
			this.functionEntriesBySemanticKey = normalize(functionEntriesBySemanticKey);
			this.semanticKeysByFunctionEntry = normalize(semanticKeysByFunctionEntry);
			this.addressesByPatternKey = normalize(addressesByPatternKey);
			this.patternKeysByAddress = normalize(patternKeysByAddress);
		}

		static PersistedFeatureIndex create(String programIdentity, long lastKnownProgramVersion,
				Set<String> similarFeatureKeys, Set<String> semanticFeatureKeys,
				Set<String> patternFeatureKeys, Set<String> contextFeatureAddresses,
				Map<String, IndexedFunctionFeatures> functionFeatureIndex,
				Map<String, Set<String>> functionEntriesBySemanticKey,
				Map<String, Set<String>> semanticKeysByFunctionEntry,
				Map<String, Set<String>> addressesByPatternKey,
				Map<String, Set<String>> patternKeysByAddress) {
			return new PersistedFeatureIndex(programIdentity, lastKnownProgramVersion,
				similarFeatureKeys, semanticFeatureKeys, patternFeatureKeys, contextFeatureAddresses,
				functionFeatureIndex,
				functionEntriesBySemanticKey, semanticKeysByFunctionEntry, addressesByPatternKey,
				patternKeysByAddress);
		}

		boolean isCompatible(String identity) {
			return schemaVersion == FEATURE_INDEX_SCHEMA_VERSION &&
				formatVersion == FEATURE_INDEX_FORMAT_VERSION &&
				Objects.equals(programIdentity, identity);
		}

		private static Map<String, Set<String>> normalize(Map<String, Set<String>> map) {
			Map<String, Set<String>> normalized = new TreeMap<>();
			for (Map.Entry<String, Set<String>> entry : map.entrySet()) {
				normalized.put(entry.getKey(), new TreeSet<>(entry.getValue()));
			}
			return normalized;
		}

		private static Map<String, IndexedFunctionFeatures> normalizeFeatures(
				Map<String, IndexedFunctionFeatures> map) {
			Map<String, IndexedFunctionFeatures> normalized = new TreeMap<>();
			if (map == null) {
				return normalized;
			}
			for (Map.Entry<String, IndexedFunctionFeatures> entry : map.entrySet()) {
				if (entry.getKey() != null && entry.getValue() != null) {
					normalized.put(entry.getKey(), entry.getValue());
				}
			}
			return normalized;
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
