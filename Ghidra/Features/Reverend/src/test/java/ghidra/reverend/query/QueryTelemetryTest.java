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
import java.util.Map;

import org.junit.*;

/**
 * Unit tests for {@link QueryTelemetry}.
 */
public class QueryTelemetryTest {

	private QueryTelemetry telemetry;

	@Before
	public void setUp() {
		telemetry = new QueryTelemetry();
	}

	@After
	public void tearDown() {
		telemetry.reset();
	}

	@Test
	public void testStartAndCompleteOperation() {
		String opId = telemetry.startOperation("findSimilarFunctions", null);
		assertNotNull(opId);
		assertTrue(opId.startsWith("findSimilarFunctions-"));

		// Complete successfully
		telemetry.recordOperationSuccess(opId, 5_000_000); // 5ms

		// Check latency stats
		QueryTelemetry.LatencyStats stats = telemetry.getLatencyStats("findSimilarFunctions");
		assertEquals(1, stats.count);
		assertTrue(stats.p50Ms >= 0);
	}

	@Test
	public void testRecordOperationError() {
		String opId = telemetry.startOperation("semanticSearch", null);

		// Record error
		Exception error = new RuntimeException("Test error");
		telemetry.recordOperationError(opId, error);

		// Check error count
		assertEquals(1, telemetry.getTotalErrors());

		// Check error type
		Map<String, Long> errorsByType = telemetry.getErrorsByType();
		assertEquals(Long.valueOf(1), errorsByType.get("RuntimeException"));

		// Check recent errors
		List<QueryTelemetry.ErrorRecord> recentErrors = telemetry.getRecentErrors();
		assertEquals(1, recentErrors.size());
		assertEquals("RuntimeException", recentErrors.get(0).errorType);
		assertEquals("Test error", recentErrors.get(0).message);
	}

	@Test
	public void testCacheMetrics() {
		// Record cache activity
		telemetry.recordCacheHit("op1");
		telemetry.recordCacheHit("op2");
		telemetry.recordCacheMiss("op3");

		// 2 hits / 3 total = 66.7%
		double hitRate = telemetry.getCacheHitRate();
		assertEquals(0.667, hitRate, 0.01);
	}

	@Test
	public void testDecompilerMetrics() {
		// Record decompiler activity
		telemetry.recordDecompilerCacheHit(null, null);
		telemetry.recordDecompilerCacheMiss(null, null);
		telemetry.recordDecompilerCacheMiss(null, null);

		// 1 hit / 3 total = 33.3%
		double hitRate = telemetry.getDecompilerCacheHitRate();
		assertEquals(0.333, hitRate, 0.01);

		// Record latency
		telemetry.recordDecompileLatency(null, null, 10_000_000, true); // 10ms success
		telemetry.recordDecompileLatency(null, null, 5_000_000, false); // 5ms failure

		// Success rate = 1/2 = 50%
		assertEquals(0.5, telemetry.getDecompilerSuccessRate(), 0.001);

		// Check latency stats
		QueryTelemetry.LatencyStats stats = telemetry.getDecompileLatencyStats();
		assertEquals(2, stats.count);
	}

	@Test
	public void testProgramBindingMetrics() {
		// These should not throw
		telemetry.recordProgramBind(null);
		telemetry.recordProgramBind(null);
		telemetry.recordProgramUnbind(null);

		// Summary should include binding counts
		String summary = telemetry.getSummaryReport();
		assertTrue(summary.contains("Binds: 2"));
		assertTrue(summary.contains("Unbinds: 1"));
	}

	@Test
	public void testLatencyPercentiles() {
		// Record multiple latencies
		String opType = "testOperation";
		for (int i = 0; i < 100; i++) {
			String opId = telemetry.startOperation(opType, null);
			// Latencies from 1ms to 100ms
			telemetry.recordOperationSuccess(opId, (i + 1) * 1_000_000L);
		}

		QueryTelemetry.LatencyStats stats = telemetry.getLatencyStats(opType);
		assertEquals(100, stats.count);

		// p50 should be around 50ms
		assertTrue(stats.p50Ms >= 40 && stats.p50Ms <= 60);

		// p90 should be around 90ms
		assertTrue(stats.p90Ms >= 80 && stats.p90Ms <= 95);

		// p99 should be around 99ms
		assertTrue(stats.p99Ms >= 90 && stats.p99Ms <= 100);
	}

	@Test
	public void testGetAllLatencyStats() {
		// Record operations of different types
		String op1 = telemetry.startOperation("findSimilarFunctions", null);
		telemetry.recordOperationSuccess(op1, 5_000_000);

		String op2 = telemetry.startOperation("semanticSearch", null);
		telemetry.recordOperationSuccess(op2, 10_000_000);

		Map<String, QueryTelemetry.LatencyStats> allStats = telemetry.getAllLatencyStats();
		assertTrue(allStats.containsKey("findSimilarFunctions"));
		assertTrue(allStats.containsKey("semanticSearch"));
	}

	@Test
	public void testSummaryReport() {
		// Generate some activity
		String op1 = telemetry.startOperation("findSimilarFunctions", null);
		telemetry.recordOperationSuccess(op1, 5_000_000);

		telemetry.recordCacheHit("op1");
		telemetry.recordCacheMiss("op2");
		telemetry.recordDecompileLatency(null, null, 10_000_000, true);
		telemetry.recordProgramBind(null);

		String summary = telemetry.getSummaryReport();

		// Should contain key sections
		assertTrue(summary.contains("Query Telemetry Summary"));
		assertTrue(summary.contains("Operation Latencies"));
		assertTrue(summary.contains("Decompiler"));
		assertTrue(summary.contains("Query Cache"));
		assertTrue(summary.contains("Program Bindings"));
	}

	@Test
	public void testReset() {
		// Generate activity
		String opId = telemetry.startOperation("test", null);
		telemetry.recordOperationSuccess(opId, 5_000_000);
		telemetry.recordCacheHit("op1");
		telemetry.recordOperationError("op2", new RuntimeException());

		// Verify activity
		assertTrue(telemetry.getTotalErrors() > 0);

		// Reset
		telemetry.reset();

		// Verify reset
		assertEquals(0, telemetry.getTotalErrors());
		assertEquals(0.0, telemetry.getCacheHitRate(), 0.001);
		assertTrue(telemetry.getRecentErrors().isEmpty());
	}

	@Test
	public void testEmptyLatencyStats() {
		QueryTelemetry.LatencyStats stats = telemetry.getLatencyStats("nonexistent");
		assertEquals(0, stats.count);
		assertEquals(0.0, stats.p50Ms, 0.001);
		assertEquals(0.0, stats.meanMs, 0.001);
	}

	@Test
	public void testCacheInvalidationRecording() {
		// Should not throw
		telemetry.recordCacheInvalidation("FUNCTION_CHANGED", null);
		telemetry.recordDecompilerCacheInvalidation(null, "ALL");

		// No direct metrics to check, but summary should not fail
		assertNotNull(telemetry.getSummaryReport());
	}
}
