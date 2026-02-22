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

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.LongAdder;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

/**
 * Telemetry collector for semantic query operations.
 *
 * <p>This class captures:
 * <ul>
 *   <li>Operation latency metrics (p50, p90, p99, mean)</li>
 *   <li>Error rates and error types</li>
 *   <li>Cache hit/miss rates</li>
 *   <li>Program binding events</li>
 *   <li>Decompilation performance</li>
 * </ul>
 *
 * <p>Telemetry is emitted through the standard Ghidra logging infrastructure
 * and can be accessed programmatically for monitoring dashboards.
 *
 * @since 1.0
 */
public class QueryTelemetry {

	/** Maximum number of latency samples to retain */
	private static final int MAX_LATENCY_SAMPLES = 10000;

	/** Interval for logging summary metrics (in milliseconds) */
	private static final long SUMMARY_LOG_INTERVAL_MS = 60000; // 1 minute

	// Operation tracking
	private final AtomicLong operationIdCounter = new AtomicLong();
	private final Map<String, OperationRecord> activeOperations = new ConcurrentHashMap<>();

	// Latency metrics by operation type
	private final Map<String, LatencyMetrics> latencyByOperation = new ConcurrentHashMap<>();

	// Error tracking
	private final LongAdder totalErrors = new LongAdder();
	private final Map<String, LongAdder> errorsByType = new ConcurrentHashMap<>();
	private final Queue<ErrorRecord> recentErrors = new ConcurrentLinkedQueue<>();
	private static final int MAX_RECENT_ERRORS = 100;

	// Cache metrics
	private final LongAdder cacheHits = new LongAdder();
	private final LongAdder cacheMisses = new LongAdder();
	private final LongAdder cacheInvalidations = new LongAdder();

	// Decompiler metrics
	private final LatencyMetrics decompileLatency = new LatencyMetrics("decompile");
	private final LongAdder decompileCacheHits = new LongAdder();
	private final LongAdder decompileCacheMisses = new LongAdder();
	private final LongAdder decompileSuccesses = new LongAdder();
	private final LongAdder decompileFailures = new LongAdder();

	// Program binding metrics
	private final LongAdder programBinds = new LongAdder();
	private final LongAdder programUnbinds = new LongAdder();

	// Summary logging
	private volatile long lastSummaryLogTime = System.currentTimeMillis();

	/**
	 * Creates a new QueryTelemetry instance.
	 */
	public QueryTelemetry() {
		// Initialize common operation types
		for (String opType : Arrays.asList("findSimilarFunctions", "semanticSearch",
				"patternSearch", "getContext")) {
			latencyByOperation.put(opType, new LatencyMetrics(opType));
		}
	}

	/**
	 * Starts tracking a new operation.
	 *
	 * @param operationType the type of operation
	 * @param program the program being queried
	 * @return a unique operation ID for tracking
	 */
	public String startOperation(String operationType, Program program) {
		String operationId = operationType + "-" + operationIdCounter.incrementAndGet();
		OperationRecord record = new OperationRecord(operationId, operationType, program);
		activeOperations.put(operationId, record);
		return operationId;
	}

	/**
	 * Records successful completion of an operation.
	 *
	 * @param operationId the operation ID
	 * @param elapsedNanos the elapsed time in nanoseconds
	 */
	public void recordOperationSuccess(String operationId, long elapsedNanos) {
		OperationRecord record = activeOperations.remove(operationId);
		if (record != null) {
			LatencyMetrics metrics = latencyByOperation.computeIfAbsent(
				record.operationType, LatencyMetrics::new);
			metrics.recordLatency(elapsedNanos);

			logOperationComplete(record, elapsedNanos, true, null);
		}
		maybeLogSummary();
	}

	/**
	 * Records an operation error.
	 *
	 * @param operationId the operation ID
	 * @param error the error that occurred
	 */
	public void recordOperationError(String operationId, Throwable error) {
		OperationRecord record = activeOperations.remove(operationId);
		long elapsedNanos = record != null ?
			System.nanoTime() - record.startTimeNanos : 0;

		totalErrors.increment();

		String errorType = error.getClass().getSimpleName();
		errorsByType.computeIfAbsent(errorType, k -> new LongAdder()).increment();

		// Record recent error
		ErrorRecord errorRecord = new ErrorRecord(
			operationId,
			record != null ? record.operationType : "unknown",
			errorType,
			error.getMessage(),
			Instant.now()
		);
		recentErrors.offer(errorRecord);
		while (recentErrors.size() > MAX_RECENT_ERRORS) {
			recentErrors.poll();
		}

		if (record != null) {
			logOperationComplete(record, elapsedNanos, false, error);
		}

		Msg.error(this, "Query operation error: " + operationId + " - " + error.getMessage());
		maybeLogSummary();
	}

	/**
	 * Records a cache hit for an operation.
	 *
	 * @param operationId the operation ID
	 */
	public void recordCacheHit(String operationId) {
		cacheHits.increment();
	}

	/**
	 * Records a cache miss for an operation.
	 *
	 * @param operationId the operation ID
	 */
	public void recordCacheMiss(String operationId) {
		cacheMisses.increment();
	}

	/**
	 * Records a cache invalidation event.
	 *
	 * @param eventType the type of event that triggered invalidation
	 * @param program the affected program
	 */
	public void recordCacheInvalidation(String eventType, Program program) {
		cacheInvalidations.increment();
		Msg.debug(this, "Cache invalidation: " + eventType + " for " +
			(program != null ? program.getName() : "unknown"));
	}

	/**
	 * Records a program bind event.
	 *
	 * @param program the bound program
	 */
	public void recordProgramBind(Program program) {
		programBinds.increment();
		Msg.debug(this, "Program bound: " + (program != null ? program.getName() : "unknown"));
	}

	/**
	 * Records a program unbind event.
	 *
	 * @param program the unbound program
	 */
	public void recordProgramUnbind(Program program) {
		programUnbinds.increment();
		Msg.debug(this, "Program unbound: " + (program != null ? program.getName() : "unknown"));
	}

	/**
	 * Records a decompiler cache hit.
	 *
	 * @param program the program
	 * @param function the function
	 */
	public void recordDecompilerCacheHit(Program program, Function function) {
		decompileCacheHits.increment();
	}

	/**
	 * Records a decompiler cache miss.
	 *
	 * @param program the program
	 * @param function the function
	 */
	public void recordDecompilerCacheMiss(Program program, Function function) {
		decompileCacheMisses.increment();
	}

	/**
	 * Records decompilation latency.
	 *
	 * @param program the program
	 * @param function the function
	 * @param elapsedNanos the elapsed time in nanoseconds
	 * @param success whether decompilation succeeded
	 */
	public void recordDecompileLatency(Program program, Function function,
			long elapsedNanos, boolean success) {
		decompileLatency.recordLatency(elapsedNanos);
		if (success) {
			decompileSuccesses.increment();
		} else {
			decompileFailures.increment();
		}
	}

	/**
	 * Records a decompiler cache invalidation.
	 *
	 * @param program the program
	 * @param reason the reason for invalidation
	 */
	public void recordDecompilerCacheInvalidation(Program program, String reason) {
		Msg.debug(this, "Decompiler cache invalidation: " + reason + " for " +
			(program != null ? program.getName() : "unknown"));
	}

	// --- Query methods for monitoring ---

	/**
	 * Returns latency statistics for a specific operation type.
	 *
	 * @param operationType the operation type
	 * @return latency statistics
	 */
	public LatencyStats getLatencyStats(String operationType) {
		LatencyMetrics metrics = latencyByOperation.get(operationType);
		return metrics != null ? metrics.getStats() : new LatencyStats(operationType);
	}

	/**
	 * Returns latency statistics for all operation types.
	 *
	 * @return map of operation type to latency stats
	 */
	public Map<String, LatencyStats> getAllLatencyStats() {
		Map<String, LatencyStats> result = new HashMap<>();
		for (Map.Entry<String, LatencyMetrics> entry : latencyByOperation.entrySet()) {
			result.put(entry.getKey(), entry.getValue().getStats());
		}
		return result;
	}

	/**
	 * Returns decompiler latency statistics.
	 *
	 * @return decompiler latency stats
	 */
	public LatencyStats getDecompileLatencyStats() {
		return decompileLatency.getStats();
	}

	/**
	 * Returns the total error count.
	 *
	 * @return total errors
	 */
	public long getTotalErrors() {
		return totalErrors.sum();
	}

	/**
	 * Returns error counts by type.
	 *
	 * @return map of error type to count
	 */
	public Map<String, Long> getErrorsByType() {
		Map<String, Long> result = new HashMap<>();
		for (Map.Entry<String, LongAdder> entry : errorsByType.entrySet()) {
			result.put(entry.getKey(), entry.getValue().sum());
		}
		return result;
	}

	/**
	 * Returns recent errors.
	 *
	 * @return list of recent error records
	 */
	public List<ErrorRecord> getRecentErrors() {
		return new ArrayList<>(recentErrors);
	}

	/**
	 * Returns the cache hit rate.
	 *
	 * @return hit rate (0.0 to 1.0)
	 */
	public double getCacheHitRate() {
		long hits = cacheHits.sum();
		long total = hits + cacheMisses.sum();
		return total > 0 ? (double) hits / total : 0.0;
	}

	/**
	 * Returns the decompiler cache hit rate.
	 *
	 * @return hit rate (0.0 to 1.0)
	 */
	public double getDecompilerCacheHitRate() {
		long hits = decompileCacheHits.sum();
		long total = hits + decompileCacheMisses.sum();
		return total > 0 ? (double) hits / total : 0.0;
	}

	/**
	 * Returns the decompiler success rate.
	 *
	 * @return success rate (0.0 to 1.0)
	 */
	public double getDecompilerSuccessRate() {
		long successes = decompileSuccesses.sum();
		long total = successes + decompileFailures.sum();
		return total > 0 ? (double) successes / total : 1.0;
	}

	/**
	 * Generates a summary report of all metrics.
	 *
	 * @return the summary report as a string
	 */
	public String getSummaryReport() {
		StringBuilder sb = new StringBuilder();
		sb.append("=== Query Telemetry Summary ===\n");

		// Operation latencies
		sb.append("\n--- Operation Latencies ---\n");
		for (Map.Entry<String, LatencyMetrics> entry : latencyByOperation.entrySet()) {
			LatencyStats stats = entry.getValue().getStats();
			if (stats.count > 0) {
				sb.append(String.format("  %s: count=%d, p50=%.2fms, p90=%.2fms, p99=%.2fms, mean=%.2fms%n",
					stats.operationType, stats.count,
					stats.p50Ms, stats.p90Ms, stats.p99Ms, stats.meanMs));
			}
		}

		// Decompiler stats
		LatencyStats decompStats = decompileLatency.getStats();
		sb.append("\n--- Decompiler ---\n");
		sb.append(String.format("  Decompilations: %d (%.1f%% success)%n",
			decompileSuccesses.sum() + decompileFailures.sum(),
			getDecompilerSuccessRate() * 100));
		sb.append(String.format("  Cache hit rate: %.1f%%%n", getDecompilerCacheHitRate() * 100));
		if (decompStats.count > 0) {
			sb.append(String.format("  Latency: p50=%.2fms, p90=%.2fms, mean=%.2fms%n",
				decompStats.p50Ms, decompStats.p90Ms, decompStats.meanMs));
		}

		// Cache stats
		sb.append("\n--- Query Cache ---\n");
		sb.append(String.format("  Hit rate: %.1f%% (hits=%d, misses=%d)%n",
			getCacheHitRate() * 100, cacheHits.sum(), cacheMisses.sum()));
		sb.append(String.format("  Invalidations: %d%n", cacheInvalidations.sum()));

		// Error stats
		sb.append("\n--- Errors ---\n");
		sb.append(String.format("  Total: %d%n", totalErrors.sum()));
		for (Map.Entry<String, Long> entry : getErrorsByType().entrySet()) {
			sb.append(String.format("    %s: %d%n", entry.getKey(), entry.getValue()));
		}

		// Program binding stats
		sb.append("\n--- Program Bindings ---\n");
		sb.append(String.format("  Binds: %d, Unbinds: %d%n",
			programBinds.sum(), programUnbinds.sum()));

		return sb.toString();
	}

	/**
	 * Resets all metrics.
	 */
	public void reset() {
		activeOperations.clear();
		latencyByOperation.values().forEach(LatencyMetrics::reset);
		totalErrors.reset();
		errorsByType.clear();
		recentErrors.clear();
		cacheHits.reset();
		cacheMisses.reset();
		cacheInvalidations.reset();
		decompileLatency.reset();
		decompileCacheHits.reset();
		decompileCacheMisses.reset();
		decompileSuccesses.reset();
		decompileFailures.reset();
		programBinds.reset();
		programUnbinds.reset();
	}

	// --- Private helper methods ---

	private void logOperationComplete(OperationRecord record, long elapsedNanos,
			boolean success, Throwable error) {
		double elapsedMs = elapsedNanos / 1_000_000.0;
		if (success) {
			Msg.debug(this, String.format("Operation %s completed: %s (%.2fms)",
				record.operationType, record.operationId, elapsedMs));
		} else {
			Msg.warn(this, String.format("Operation %s failed: %s (%.2fms) - %s",
				record.operationType, record.operationId, elapsedMs,
				error != null ? error.getMessage() : "unknown error"));
		}
	}

	private void maybeLogSummary() {
		long now = System.currentTimeMillis();
		if (now - lastSummaryLogTime > SUMMARY_LOG_INTERVAL_MS) {
			lastSummaryLogTime = now;
			Msg.info(this, getSummaryReport());
		}
	}

	// --- Inner classes ---

	/**
	 * Tracks an active operation.
	 */
	private static class OperationRecord {
		final String operationId;
		final String operationType;
		final Program program;
		final long startTimeNanos;

		OperationRecord(String operationId, String operationType, Program program) {
			this.operationId = operationId;
			this.operationType = operationType;
			this.program = program;
			this.startTimeNanos = System.nanoTime();
		}
	}

	/**
	 * Record of an error occurrence.
	 */
	public static class ErrorRecord {
		public final String operationId;
		public final String operationType;
		public final String errorType;
		public final String message;
		public final Instant timestamp;

		ErrorRecord(String operationId, String operationType, String errorType,
				String message, Instant timestamp) {
			this.operationId = operationId;
			this.operationType = operationType;
			this.errorType = errorType;
			this.message = message;
			this.timestamp = timestamp;
		}
	}

	/**
	 * Latency metrics collector.
	 */
	private static class LatencyMetrics {
		private final String operationType;
		private final Queue<Long> samples = new ConcurrentLinkedQueue<>();
		private final LongAdder totalNanos = new LongAdder();
		private final LongAdder count = new LongAdder();

		LatencyMetrics(String operationType) {
			this.operationType = operationType;
		}

		void recordLatency(long nanos) {
			samples.offer(nanos);
			totalNanos.add(nanos);
			count.increment();

			// Trim samples if needed
			while (samples.size() > MAX_LATENCY_SAMPLES) {
				Long removed = samples.poll();
				if (removed != null) {
					totalNanos.add(-removed);
					count.decrement();
				}
			}
		}

		LatencyStats getStats() {
			List<Long> sortedSamples = new ArrayList<>(samples);
			Collections.sort(sortedSamples);

			int n = sortedSamples.size();
			if (n == 0) {
				return new LatencyStats(operationType);
			}

			double p50 = sortedSamples.get((int) (n * 0.5)) / 1_000_000.0;
			double p90 = sortedSamples.get((int) (n * 0.9)) / 1_000_000.0;
			double p99 = sortedSamples.get(Math.min((int) (n * 0.99), n - 1)) / 1_000_000.0;
			double mean = (double) totalNanos.sum() / n / 1_000_000.0;

			return new LatencyStats(operationType, n, p50, p90, p99, mean);
		}

		void reset() {
			samples.clear();
			totalNanos.reset();
			count.reset();
		}
	}

	/**
	 * Snapshot of latency statistics.
	 */
	public static class LatencyStats {
		public final String operationType;
		public final int count;
		public final double p50Ms;
		public final double p90Ms;
		public final double p99Ms;
		public final double meanMs;

		LatencyStats(String operationType) {
			this(operationType, 0, 0, 0, 0, 0);
		}

		LatencyStats(String operationType, int count, double p50Ms, double p90Ms,
				double p99Ms, double meanMs) {
			this.operationType = operationType;
			this.count = count;
			this.p50Ms = p50Ms;
			this.p90Ms = p90Ms;
			this.p99Ms = p99Ms;
			this.meanMs = meanMs;
		}
	}
}
