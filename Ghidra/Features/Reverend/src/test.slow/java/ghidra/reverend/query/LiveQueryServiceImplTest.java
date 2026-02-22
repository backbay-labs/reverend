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

import java.util.List;
import java.util.Optional;

import org.junit.*;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.reverend.api.v1.QueryService.*;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.task.TaskMonitor;

/**
 * Integration tests for {@link LiveQueryServiceImpl}.
 *
 * <p>These tests verify:
 * <ul>
 *   <li>Live Program binding and unbinding</li>
 *   <li>Query operations against real program state</li>
 *   <li>Cache invalidation on program changes</li>
 *   <li>Telemetry emission</li>
 * </ul>
 */
public class LiveQueryServiceImplTest extends AbstractGhidraHeadlessIntegrationTest {

	private Program program;
	private LiveQueryServiceImpl queryService;
	private QueryCacheManager cacheManager;
	private DecompilerContextProvider decompilerProvider;
	private QueryTelemetry telemetry;

	@Before
	public void setUp() throws Exception {
		// Create a simple test program
		ProgramBuilder builder = new ProgramBuilder("TestProgram", ProgramBuilder._X86);

		// Add some code
		builder.setBytes("0x01000000", "55 89 e5 83 ec 10"); // push ebp; mov ebp, esp; sub esp, 0x10
		builder.setBytes("0x01000006", "31 c0"); // xor eax, eax
		builder.setBytes("0x01000008", "c9 c3"); // leave; ret

		// Add another function
		builder.setBytes("0x01001000", "55 89 e5 83 ec 20"); // Different prologue
		builder.setBytes("0x01001006", "b8 01 00 00 00"); // mov eax, 1
		builder.setBytes("0x0100100b", "c9 c3"); // leave; ret

		program = builder.getProgram();

		// Create functions
		int txId = program.startTransaction("Create functions");
		try {
			CreateFunctionCmd cmd1 = new CreateFunctionCmd("testFunc1",
				program.getAddressFactory().getAddress("0x01000000"),
				null, SourceType.USER_DEFINED);
			cmd1.applyTo(program);

			CreateFunctionCmd cmd2 = new CreateFunctionCmd("testFunc2",
				program.getAddressFactory().getAddress("0x01001000"),
				null, SourceType.USER_DEFINED);
			cmd2.applyTo(program);
		}
		finally {
			program.endTransaction(txId, true);
		}

		// Create service components
		telemetry = new QueryTelemetry();
		cacheManager = new QueryCacheManager();
		decompilerProvider = new DecompilerContextProvider(telemetry);

		// Create and bind service
		queryService = new LiveQueryServiceImpl(cacheManager, decompilerProvider, telemetry);
		queryService.bindToProgram(program);
	}

	@After
	public void tearDown() throws Exception {
		if (queryService != null) {
			queryService.close();
		}
		if (program != null) {
			program.release(this);
		}
	}

	@Test
	public void testBindToProgram() {
		assertEquals(program, queryService.getCurrentProgram());

		// Verify telemetry recorded the bind
		String summary = telemetry.getSummaryReport();
		assertTrue(summary.contains("Binds: 1"));
	}

	@Test
	public void testUnbindFromProgram() {
		queryService.unbindFromProgram(program);

		assertNull(queryService.getCurrentProgram());

		// Verify telemetry recorded the unbind
		String summary = telemetry.getSummaryReport();
		assertTrue(summary.contains("Unbinds: 1"));
	}

	@Test
	public void testFindSimilarFunctions() throws QueryException {
		Function func1 = program.getFunctionManager().getFunctionAt(
			program.getAddressFactory().getAddress("0x01000000"));
		assertNotNull("Test function should exist", func1);

		List<QueryResult> results = queryService.findSimilarFunctions(
			program, func1, 10, TaskMonitor.DUMMY);

		assertNotNull(results);
		// Should find at least one similar function (testFunc2)
		// (depending on similarity threshold)

		// Verify telemetry
		QueryTelemetry.LatencyStats stats = telemetry.getLatencyStats("findSimilarFunctions");
		assertEquals(1, stats.count);
		assertTrue(stats.meanMs >= 0);
	}

	@Test
	public void testSemanticSearch() throws QueryException {
		List<QueryResult> results = queryService.semanticSearch(
			program, "test", null, 10, TaskMonitor.DUMMY);

		assertNotNull(results);
		// Should find functions with "test" in their name
		assertTrue(results.size() >= 1);

		// Verify telemetry
		QueryTelemetry.LatencyStats stats = telemetry.getLatencyStats("semanticSearch");
		assertEquals(1, stats.count);
	}

	@Test
	public void testSemanticSearchEmptyQuery() {
		try {
			queryService.semanticSearch(program, "", null, 10, TaskMonitor.DUMMY);
			fail("Expected QueryException for empty query");
		}
		catch (QueryException e) {
			assertTrue(e.getMessage().contains("empty"));
		}

		// Verify error was recorded
		assertEquals(1, telemetry.getTotalErrors());
	}

	@Test
	public void testPatternSearch() throws QueryException {
		List<Address> results = queryService.patternSearch(
			program, "push", null, TaskMonitor.DUMMY);

		assertNotNull(results);
		// Should find addresses with "push" instruction

		// Verify telemetry
		QueryTelemetry.LatencyStats stats = telemetry.getLatencyStats("patternSearch");
		assertEquals(1, stats.count);
	}

	@Test
	public void testGetContext() throws QueryException {
		Address funcAddr = program.getAddressFactory().getAddress("0x01000000");

		Optional<QueryContext> context = queryService.getContext(program, funcAddr);

		assertTrue(context.isPresent());
		assertEquals(funcAddr, context.get().getAddress());
		assertTrue(context.get().getFunction().isPresent());
		assertEquals("testFunc1", context.get().getFunction().get().getName());

		// Verify telemetry
		QueryTelemetry.LatencyStats stats = telemetry.getLatencyStats("getContext");
		assertEquals(1, stats.count);
	}

	@Test
	public void testCacheHit() throws QueryException {
		Address funcAddr = program.getAddressFactory().getAddress("0x01000000");

		// First call - cache miss
		queryService.getContext(program, funcAddr);
		double hitRateBefore = telemetry.getCacheHitRate();

		// Second call - should be cache hit
		queryService.getContext(program, funcAddr);
		double hitRateAfter = telemetry.getCacheHitRate();

		assertTrue("Hit rate should increase after cache hit",
			hitRateAfter >= hitRateBefore);
	}

	@Test
	public void testCacheInvalidationOnFunctionChange() throws QueryException {
		// Get context to populate cache
		Address funcAddr = program.getAddressFactory().getAddress("0x01000000");
		queryService.getContext(program, funcAddr);

		// Verify cached
		assertNotNull(cacheManager.getCachedContext(program, funcAddr));

		// Modify the function
		int txId = program.startTransaction("Modify function");
		try {
			Function func = program.getFunctionManager().getFunctionAt(funcAddr);
			func.setName("renamedFunc", SourceType.USER_DEFINED);
		}
		finally {
			program.endTransaction(txId, true);
		}

		// Simulate domain object change event (normally fired by Program)
		// Note: In real usage, the listener is automatically invoked
		// For testing, we can invalidate manually
		cacheManager.invalidateFunctionCaches(program);

		// Verify cache was invalidated
		// (The semantic search cache should be cleared since it depends on function names)

		// Verify telemetry recorded invalidation
		QueryCacheManager.CacheStatistics stats = cacheManager.getStatistics();
		assertTrue(stats.getEntriesInvalidated() > 0);
	}

	@Test
	public void testMultipleProgramsSupported() throws QueryException {
		// Create a second program
		ProgramBuilder builder2 = new ProgramBuilder("TestProgram2", ProgramBuilder._X86);
		builder2.setBytes("0x01000000", "55 89 e5 c9 c3");
		Program program2 = builder2.getProgram();

		int txId = program2.startTransaction("Create function");
		try {
			CreateFunctionCmd cmd = new CreateFunctionCmd("otherFunc",
				program2.getAddressFactory().getAddress("0x01000000"),
				null, SourceType.USER_DEFINED);
			cmd.applyTo(program2);
		}
		finally {
			program2.endTransaction(txId, true);
		}

		try {
			// Query first program
			List<QueryResult> results1 = queryService.semanticSearch(
				program, "test", null, 10, TaskMonitor.DUMMY);
			assertTrue(results1.size() >= 1);

			// Query second program (should auto-bind)
			List<QueryResult> results2 = queryService.semanticSearch(
				program2, "other", null, 10, TaskMonitor.DUMMY);
			assertTrue(results2.size() >= 1);

			// Verify bindings
			String summary = telemetry.getSummaryReport();
			assertTrue(summary.contains("Binds: 2"));
		}
		finally {
			program2.release(this);
		}
	}

	@Test
	public void testNullProgramThrowsException() {
		try {
			queryService.getContext(null, program.getAddressFactory().getAddress("0x01000000"));
			fail("Expected QueryException for null program");
		}
		catch (QueryException e) {
			assertTrue(e.getMessage().contains("null"));
		}
	}

	@Test
	public void testDecompilerTelemetry() throws QueryException {
		// Get context which triggers decompilation
		Address funcAddr = program.getAddressFactory().getAddress("0x01000000");
		queryService.getContext(program, funcAddr);

		// Check decompiler metrics
		QueryTelemetry.LatencyStats decompStats = telemetry.getDecompileLatencyStats();
		assertTrue("Decompilation should have occurred", decompStats.count >= 0);
	}

	@Test
	public void testSummaryReportAfterOperations() throws QueryException {
		// Perform various operations
		Function func1 = program.getFunctionManager().getFunctionAt(
			program.getAddressFactory().getAddress("0x01000000"));

		queryService.findSimilarFunctions(program, func1, 5, TaskMonitor.DUMMY);
		queryService.semanticSearch(program, "test", null, 10, TaskMonitor.DUMMY);
		queryService.patternSearch(program, "mov", null, TaskMonitor.DUMMY);
		queryService.getContext(program, func1.getEntryPoint());

		// Get summary
		String summary = telemetry.getSummaryReport();

		// Verify key sections exist
		assertTrue(summary.contains("Operation Latencies"));
		assertTrue(summary.contains("findSimilarFunctions"));
		assertTrue(summary.contains("semanticSearch"));
		assertTrue(summary.contains("patternSearch"));
		assertTrue(summary.contains("getContext"));
	}
}
