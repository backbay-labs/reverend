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

import static org.junit.Assert.*;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;
import java.util.*;

import org.junit.*;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.StubProgram;
import ghidra.reverend.api.v1.QueryService.QueryContext;
import ghidra.reverend.api.v1.QueryService.QueryResult;

/**
 * Unit tests for {@link QueryCacheManager}.
 */
public class QueryCacheManagerTest {

	private QueryCacheManager cacheManager;
	private Program stubProgram;
	private AddressSpace testSpace;
	private Address testAddress;
	private Address secondAddress;

	@Before
	public void setUp() {
		cacheManager = new QueryCacheManager();
		// Use Ghidra's StubProgram which works as a map key
		stubProgram = new StubProgram();
		// Create a test address space and address for context cache testing
		testSpace = new GenericAddressSpace("test", 32, AddressSpace.TYPE_RAM, 0);
		testAddress = testSpace.getAddress(0x1000);
		secondAddress = testSpace.getAddress(0x2000);
	}

	@After
	public void tearDown() {
		if (stubProgram != null) {
			cacheManager.invalidateProgram(stubProgram);
		}
	}

	@Test
	public void testInitializeAndInvalidateProgram() {
		// Initialize should not throw
		cacheManager.initializeForProgram(stubProgram);

		// Statistics should be empty initially
		QueryCacheManager.CacheStatistics stats = cacheManager.getStatistics();
		assertEquals(0, stats.getHits());
		assertEquals(0, stats.getMisses());

		// Cache miss should increment
		assertNull(cacheManager.getCachedSimilarFunctions(stubProgram, "test-key"));
		assertEquals(1, stats.getMisses());

		// Invalidate should work without error
		cacheManager.invalidateProgram(stubProgram);
	}

	@Test
	public void testSimilarFunctionsCache() {
		cacheManager.initializeForProgram(stubProgram);

		String cacheKey = "similar:func1";
		List<QueryResult> results = createMockResults(3);

		// Initially empty
		assertNull(cacheManager.getCachedSimilarFunctions(stubProgram, cacheKey));

		// Cache and retrieve
		cacheManager.cacheSimilarFunctions(stubProgram, cacheKey, results);
		List<QueryResult> cached = cacheManager.getCachedSimilarFunctions(stubProgram, cacheKey);

		assertNotNull(cached);
		assertEquals(3, cached.size());

		// Verify statistics
		QueryCacheManager.CacheStatistics stats = cacheManager.getStatistics();
		assertEquals(1, stats.getHits());
		assertEquals(1, stats.getMisses()); // From initial null check
	}

	@Test
	public void testSemanticSearchCache() {
		cacheManager.initializeForProgram(stubProgram);

		String cacheKey = "semantic:query1";
		List<QueryResult> results = createMockResults(5);

		// Cache and retrieve
		cacheManager.cacheSemanticSearch(stubProgram, cacheKey, results);
		List<QueryResult> cached = cacheManager.getCachedSemanticSearch(stubProgram, cacheKey);

		assertNotNull(cached);
		assertEquals(5, cached.size());
	}

	@Test
	public void testPatternSearchCache() {
		cacheManager.initializeForProgram(stubProgram);

		String cacheKey = "pattern:mov*";
		List<Address> results = new ArrayList<>();

		// Cache and retrieve
		cacheManager.cachePatternSearch(stubProgram, cacheKey, results);
		List<Address> cached = cacheManager.getCachedPatternSearch(stubProgram, cacheKey);

		assertNotNull(cached);
	}

	@Test
	public void testContextCache() {
		cacheManager.initializeForProgram(stubProgram);

		QueryContext context = createMockContext();

		// Cache and retrieve
		cacheManager.cacheContext(stubProgram, testAddress, context);
		QueryContext cached = cacheManager.getCachedContext(stubProgram, testAddress);

		assertNotNull(cached);
	}

	@Test
	public void testFunctionCacheInvalidation() {
		cacheManager.initializeForProgram(stubProgram);

		// Cache some results
		cacheManager.cacheSimilarFunctions(stubProgram, "similar:key1", createMockResults(2));
		cacheManager.cacheSemanticSearch(stubProgram, "semantic:key1", createMockResults(2));

		// Verify cached
		assertNotNull(cacheManager.getCachedSimilarFunctions(stubProgram, "similar:key1"));
		assertNotNull(cacheManager.getCachedSemanticSearch(stubProgram, "semantic:key1"));

		// Invalidate function caches
		cacheManager.invalidateFunctionCaches(stubProgram);

		// Verify invalidated
		assertNull(cacheManager.getCachedSimilarFunctions(stubProgram, "similar:key1"));
		assertNull(cacheManager.getCachedSemanticSearch(stubProgram, "semantic:key1"));
	}

	@Test
	public void testIncrementalFunctionInvalidationByEntryPoint() {
		cacheManager.initializeForProgram(stubProgram);

		String keyA = CacheKeyGenerator.forSimilarFunctions(testAddress.toString());
		String keyB = CacheKeyGenerator.forSimilarFunctions(secondAddress.toString());

		cacheManager.cacheSimilarFunctions(stubProgram, keyA, createMockResultsForAddresses(testAddress));
		cacheManager.cacheSimilarFunctions(stubProgram, keyB, createMockResultsForAddresses(secondAddress));
		cacheManager.cacheSemanticSearch(stubProgram, "semantic:keyA",
			createMockResultsForAddresses(testAddress));
		cacheManager.cacheSemanticSearch(stubProgram, "semantic:keyB",
			createMockResultsForAddresses(secondAddress));

		cacheManager.invalidateFunctionCaches(stubProgram, List.of(testAddress));

		assertNull(cacheManager.getCachedSimilarFunctions(stubProgram, keyA));
		assertNotNull(cacheManager.getCachedSimilarFunctions(stubProgram, keyB));
		assertNull(cacheManager.getCachedSemanticSearch(stubProgram, "semantic:keyA"));
		assertNotNull(cacheManager.getCachedSemanticSearch(stubProgram, "semantic:keyB"));
	}

	@Test
	public void testCodeRangeInvalidationAlsoInvalidatesIndexedFunctionFeatures() throws Exception {
		cacheManager.initializeForProgram(stubProgram);

		String similarKey = CacheKeyGenerator.forSimilarFunctions(testAddress.toString());
		String semanticKey = "semantic:indexed-range";
		cacheManager.cacheSimilarFunctions(stubProgram, similarKey, createMockResultsForAddresses(testAddress));
		cacheManager.cacheSemanticSearch(stubProgram, semanticKey, createMockResultsForAddresses(testAddress));

		Object perProgramCache = getPerProgramCache();
		Field functionFeatureIndexField = perProgramCache.getClass().getDeclaredField("functionFeatureIndex");
		functionFeatureIndexField.setAccessible(true);
		@SuppressWarnings("unchecked")
		Map<String, QueryCacheManager.IndexedFunctionFeatures> functionFeatureIndex =
			(Map<String, QueryCacheManager.IndexedFunctionFeatures>) functionFeatureIndexField.get(perProgramCache);
		functionFeatureIndex.put(addressKey(testAddress),
			createIndexedFeature(testAddress, testAddress, secondAddress));

		assertEquals(1, cacheManager.getIndexedFunctionFeatureCount(stubProgram));
		cacheManager.invalidateCodeCaches(stubProgram, testAddress, secondAddress);

		assertNull(cacheManager.getCachedSimilarFunctions(stubProgram, similarKey));
		assertNull(cacheManager.getCachedSemanticSearch(stubProgram, semanticKey));
		assertEquals(0, cacheManager.getIndexedFunctionFeatureCount(stubProgram));
	}

	@Test
	public void testSymbolCacheInvalidation() {
		cacheManager.initializeForProgram(stubProgram);

		// Cache semantic search
		cacheManager.cacheSemanticSearch(stubProgram, "semantic:key1", createMockResults(2));
		assertNotNull(cacheManager.getCachedSemanticSearch(stubProgram, "semantic:key1"));

		// Invalidate symbol caches
		cacheManager.invalidateSymbolCaches(stubProgram);

		// Verify invalidated
		assertNull(cacheManager.getCachedSemanticSearch(stubProgram, "semantic:key1"));
	}

	@Test
	public void testCodeCacheInvalidation() {
		cacheManager.initializeForProgram(stubProgram);

		// Cache pattern search and context
		cacheManager.cachePatternSearch(stubProgram, "pattern:key1", new ArrayList<>());
		cacheManager.cacheContext(stubProgram, testAddress, createMockContext());

		assertNotNull(cacheManager.getCachedPatternSearch(stubProgram, "pattern:key1"));
		assertNotNull(cacheManager.getCachedContext(stubProgram, testAddress));

		// Invalidate code caches
		cacheManager.invalidateCodeCaches(stubProgram);

		// Verify invalidated
		assertNull(cacheManager.getCachedPatternSearch(stubProgram, "pattern:key1"));
		assertNull(cacheManager.getCachedContext(stubProgram, testAddress));
	}

	@Test
	public void testAllCacheInvalidation() {
		cacheManager.initializeForProgram(stubProgram);

		// Cache everything
		cacheManager.cacheSimilarFunctions(stubProgram, "similar:key1", createMockResults(2));
		cacheManager.cacheSemanticSearch(stubProgram, "semantic:key1", createMockResults(2));
		cacheManager.cachePatternSearch(stubProgram, "pattern:key1", new ArrayList<>());
		cacheManager.cacheContext(stubProgram, testAddress, createMockContext());

		// Invalidate all
		cacheManager.invalidateAllCaches(stubProgram);

		// Verify all invalidated
		assertNull(cacheManager.getCachedSimilarFunctions(stubProgram, "similar:key1"));
		assertNull(cacheManager.getCachedSemanticSearch(stubProgram, "semantic:key1"));
		assertNull(cacheManager.getCachedPatternSearch(stubProgram, "pattern:key1"));
		assertNull(cacheManager.getCachedContext(stubProgram, testAddress));
	}

	@Test
	public void testVerifyAndRepairIndexDrift() throws Exception {
		cacheManager.initializeForProgram(stubProgram);
		cacheManager.cacheSemanticSearch(stubProgram, "semantic:key",
			createMockResultsForAddresses(testAddress));

		Field programCachesField = QueryCacheManager.class.getDeclaredField("programCaches");
		programCachesField.setAccessible(true);
		@SuppressWarnings("unchecked")
		Map<Program, Object> programCaches = (Map<Program, Object>) programCachesField.get(cacheManager);
		Object perProgramCache = programCaches.get(stubProgram);

		Field reverseMapField =
			perProgramCache.getClass().getDeclaredField("functionEntriesBySemanticKey");
		reverseMapField.setAccessible(true);
		@SuppressWarnings("unchecked")
		Map<String, Set<String>> reverseMap = (Map<String, Set<String>>) reverseMapField.get(perProgramCache);
		reverseMap.put("orphan-semantic-key", new HashSet<>(Set.of("test:1000")));

		assertTrue(cacheManager.verifyAndRepairIndex(stubProgram));
		assertFalse(reverseMap.containsKey("orphan-semantic-key"));
	}

	@Test
	public void testFeatureIndexPersistsAcrossManagerInstances() throws Exception {
		Path tempDir = Files.createTempDirectory("query-cache-manager-test");
		QueryCacheManager first = new QueryCacheManager(tempDir);
		first.initializeForProgram(stubProgram);
		first.cacheSemanticSearch(stubProgram, "semantic:persisted",
			createMockResultsForAddresses(testAddress));
		first.invalidateProgram(stubProgram);
		try (Stream<Path> persisted = Files.list(tempDir)) {
			assertTrue(persisted.findAny().isPresent());
		}

		QueryCacheManager second = new QueryCacheManager(tempDir);
		second.initializeForProgram(stubProgram);
		second.invalidateFunctionCaches(stubProgram, List.of(testAddress));

		assertNull(second.getCachedSemanticSearch(stubProgram, "semantic:persisted"));
	}

	@Test
	public void testHitRate() {
		cacheManager.initializeForProgram(stubProgram);

		// All misses initially
		cacheManager.getCachedSimilarFunctions(stubProgram, "key1");
		cacheManager.getCachedSimilarFunctions(stubProgram, "key2");
		QueryCacheManager.CacheStatistics stats = cacheManager.getStatistics();
		assertEquals(0.0, stats.getHitRate(), 0.001);

		// Add to cache and get hits
		cacheManager.cacheSimilarFunctions(stubProgram, "key1", createMockResults(1));
		cacheManager.getCachedSimilarFunctions(stubProgram, "key1");
		cacheManager.getCachedSimilarFunctions(stubProgram, "key1");

		// 2 hits, 2 misses = 50%
		assertEquals(0.5, stats.getHitRate(), 0.001);
	}

	@Test
	public void testStatisticsReset() {
		cacheManager.initializeForProgram(stubProgram);

		// Generate some activity
		cacheManager.getCachedSimilarFunctions(stubProgram, "key1");
		cacheManager.cacheSimilarFunctions(stubProgram, "key1", createMockResults(1));
		cacheManager.getCachedSimilarFunctions(stubProgram, "key1");
		cacheManager.invalidateFunctionCaches(stubProgram);

		QueryCacheManager.CacheStatistics stats = cacheManager.getStatistics();
		assertTrue(stats.getHits() > 0 || stats.getMisses() > 0);

		// Reset
		stats.reset();

		assertEquals(0, stats.getHits());
		assertEquals(0, stats.getMisses());
		assertEquals(0, stats.getInvalidations());
	}

	// --- Helper methods ---

	private List<QueryResult> createMockResults(int count) {
		List<QueryResult> results = new ArrayList<>();
		for (int i = 0; i < count; i++) {
			final int index = i;
			results.add(new QueryResult() {
				@Override
				public Address getAddress() {
					return null;
				}

				@Override
				public double getScore() {
					return 0.9 - (index * 0.1);
				}

				@Override
				public String getSummary() {
					return "Result " + index;
				}

				@Override
				public Optional<String> getEvidenceId() {
					return Optional.empty();
				}
			});
		}
		return results;
	}

	private List<QueryResult> createMockResultsForAddresses(Address... addresses) {
		List<QueryResult> results = new ArrayList<>();
		for (Address address : addresses) {
			results.add(new QueryResult() {
				@Override
				public Address getAddress() {
					return address;
				}

				@Override
				public double getScore() {
					return 0.5;
				}

				@Override
				public String getSummary() {
					return "Address result";
				}

				@Override
				public Optional<String> getEvidenceId() {
					return Optional.empty();
				}
			});
		}
		return results;
	}

	private QueryContext createMockContext() {
		return new QueryContext() {
			@Override
			public Address getAddress() {
				return null;
			}

			@Override
			public Optional<Function> getFunction() {
				return Optional.empty();
			}

			@Override
			public Optional<String> getDecompiledCode() {
				return Optional.of("int main() { return 0; }");
			}

			@Override
			public List<Address> getReferences() {
				return new ArrayList<>();
			}
		};
	}

	private Object getPerProgramCache() throws Exception {
		Field programCachesField = QueryCacheManager.class.getDeclaredField("programCaches");
		programCachesField.setAccessible(true);
		@SuppressWarnings("unchecked")
		Map<Program, Object> programCaches = (Map<Program, Object>) programCachesField.get(cacheManager);
		return programCaches.get(stubProgram);
	}

	private QueryCacheManager.IndexedFunctionFeatures createIndexedFeature(Address entryPoint,
			Address bodyMin, Address bodyMax) throws Exception {
		Constructor<QueryCacheManager.IndexedFunctionFeatures> constructor =
			QueryCacheManager.IndexedFunctionFeatures.class.getDeclaredConstructor(
				String.class, String.class, String.class, String.class, String.class, String.class,
				int.class, long.class, int.class, String.class, String.class, Set.class);
		constructor.setAccessible(true);
		return constructor.newInstance(
			addressKey(entryPoint),
			"mockFunction",
			"mockfunction",
			"",
			"void",
			"__stdcall",
			1,
			64L,
			2,
			addressKey(bodyMin),
			addressKey(bodyMax),
			Set.of("mock", "function"));
	}

	private String addressKey(Address address) {
		return address.getAddressSpace().getName() + ":" +
			Long.toUnsignedString(address.getOffset(), 16);
	}
}
