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

import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;

import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/**
 * Manages decompiler interfaces and result caching for live query operations.
 *
 * <p>This provider:
 * <ul>
 *   <li>Maintains per-program decompiler instances with proper lifecycle management</li>
 *   <li>Caches decompilation results with LRU eviction</li>
 *   <li>Provides deterministic invalidation on program changes</li>
 *   <li>Uses the "normalize" simplification style for ML-compatible output</li>
 * </ul>
 *
 * @since 1.0
 */
public class DecompilerContextProvider implements AutoCloseable {

	/** Default timeout for decompilation operations in seconds */
	private static final int DEFAULT_DECOMPILE_TIMEOUT_SECS = 60;

	/** Maximum number of cached decompilation results per program */
	private static final int MAX_CACHE_SIZE_PER_PROGRAM = 500;

	/** Simplification style for normalized p-code output */
	private static final String NORMALIZE_STYLE = "normalize";

	/** Simplification style for full decompilation with C output */
	private static final String DECOMPILE_STYLE = "decompile";

	private final Map<Program, ProgramDecompilerState> decompilerStates = new ConcurrentHashMap<>();
	private final QueryTelemetry telemetry;
	private int decompileTimeoutSecs = DEFAULT_DECOMPILE_TIMEOUT_SECS;

	/**
	 * Creates a new DecompilerContextProvider.
	 *
	 * @param telemetry the telemetry collector
	 */
	public DecompilerContextProvider(QueryTelemetry telemetry) {
		this.telemetry = Objects.requireNonNull(telemetry, "telemetry");
	}

	/**
	 * Initializes decompiler resources for the given program.
	 *
	 * @param program the program to initialize for
	 */
	public void initializeForProgram(Program program) {
		decompilerStates.computeIfAbsent(program, ProgramDecompilerState::new);
	}

	/**
	 * Disposes decompiler resources for the given program.
	 *
	 * @param program the program to dispose resources for
	 */
	public void disposeForProgram(Program program) {
		ProgramDecompilerState state = decompilerStates.remove(program);
		if (state != null) {
			state.dispose();
		}
	}

	/**
	 * Decompiles the given function using the standard decompilation style.
	 *
	 * @param program the program containing the function
	 * @param function the function to decompile
	 * @param monitor task monitor for cancellation
	 * @return the decompilation results, or null if decompilation failed
	 */
	public DecompileResults decompile(Program program, Function function, TaskMonitor monitor) {
		return decompileWithStyle(program, function, DECOMPILE_STYLE, monitor);
	}

	/**
	 * Decompiles the given function using the normalized style suitable for ML features.
	 *
	 * @param program the program containing the function
	 * @param function the function to decompile
	 * @param monitor task monitor for cancellation
	 * @return the decompilation results, or null if decompilation failed
	 */
	public DecompileResults decompileNormalized(Program program, Function function,
			TaskMonitor monitor) {
		return decompileWithStyle(program, function, NORMALIZE_STYLE, monitor);
	}

	/**
	 * Decompiles the given function with the specified simplification style.
	 *
	 * @param program the program containing the function
	 * @param function the function to decompile
	 * @param style the simplification style ("decompile", "normalize", etc.)
	 * @param monitor task monitor for cancellation
	 * @return the decompilation results, or null if decompilation failed
	 */
	public DecompileResults decompileWithStyle(Program program, Function function,
			String style, TaskMonitor monitor) {
		Objects.requireNonNull(program, "program");
		Objects.requireNonNull(function, "function");

		ProgramDecompilerState state = decompilerStates.get(program);
		if (state == null) {
			initializeForProgram(program);
			state = decompilerStates.get(program);
		}

		// Check cache first
		String cacheKey = buildCacheKey(function, style);
		DecompileResults cached = state.getCached(cacheKey);
		if (cached != null) {
			telemetry.recordDecompilerCacheHit(program, function);
			return cached;
		}

		telemetry.recordDecompilerCacheMiss(program, function);

		// Perform decompilation
		long startTime = System.nanoTime();
		DecompileResults results = state.decompile(function, style, decompileTimeoutSecs, monitor);
		long elapsedNanos = System.nanoTime() - startTime;

		if (results != null && results.decompileCompleted()) {
			// Cache successful results
			state.cache(cacheKey, results);
			telemetry.recordDecompileLatency(program, function, elapsedNanos, true);
		} else {
			telemetry.recordDecompileLatency(program, function, elapsedNanos, false);
			if (results != null) {
				Msg.warn(this, "Decompilation incomplete for " + function.getName() +
					": " + results.getErrorMessage());
			}
		}

		return results;
	}

	/**
	 * Invalidates all cached decompilation results for the given program.
	 *
	 * @param program the program to invalidate caches for
	 */
	public void invalidateAllCaches(Program program) {
		ProgramDecompilerState state = decompilerStates.get(program);
		if (state != null) {
			state.invalidateAllCaches();
			telemetry.recordDecompilerCacheInvalidation(program, "ALL");
		}
	}

	/**
	 * Invalidates cached decompilation results for a specific function.
	 *
	 * @param program the program containing the function
	 * @param functionAddress the entry point address of the function
	 */
	public void invalidateFunctionCache(Program program, Address functionAddress) {
		ProgramDecompilerState state = decompilerStates.get(program);
		if (state != null) {
			state.invalidateFunctionCache(functionAddress);
			telemetry.recordDecompilerCacheInvalidation(program, functionAddress.toString());
		}
	}

	/**
	 * Sets the timeout for decompilation operations.
	 *
	 * @param timeoutSecs the timeout in seconds
	 */
	public void setDecompileTimeout(int timeoutSecs) {
		this.decompileTimeoutSecs = timeoutSecs;
	}

	/**
	 * Returns the current decompilation timeout.
	 *
	 * @return the timeout in seconds
	 */
	public int getDecompileTimeout() {
		return decompileTimeoutSecs;
	}

	@Override
	public void close() {
		for (ProgramDecompilerState state : decompilerStates.values()) {
			state.dispose();
		}
		decompilerStates.clear();
	}

	private String buildCacheKey(Function function, String style) {
		return style + ":" + function.getEntryPoint().toString();
	}

	/**
	 * Per-program state for decompiler management and caching.
	 */
	private static class ProgramDecompilerState {
		private final Program program;
		private final ReentrantLock decompilerLock = new ReentrantLock();
		private DecompInterface decompInterface;

		// LRU cache for decompilation results
		private final Map<String, CachedResult> resultCache = new ConcurrentHashMap<>();

		ProgramDecompilerState(Program program) {
			this.program = program;
		}

		DecompileResults decompile(Function function, String style, int timeoutSecs,
				TaskMonitor monitor) {
			decompilerLock.lock();
			try {
				// Initialize or reinitialize decompiler if needed
				if (decompInterface == null) {
					decompInterface = new DecompInterface();
					if (!decompInterface.openProgram(program)) {
						Msg.error(this, "Failed to open program in decompiler");
						return null;
					}
				}

				// Set simplification style
				decompInterface.setSimplificationStyle(style);

				// Perform decompilation
				return decompInterface.decompileFunction(function, timeoutSecs,
					monitor != null ? monitor : TaskMonitor.DUMMY);

			} finally {
				decompilerLock.unlock();
			}
		}

		DecompileResults getCached(String cacheKey) {
			CachedResult cached = resultCache.get(cacheKey);
			if (cached != null) {
				cached.accessTime = System.currentTimeMillis();
				return cached.results;
			}
			return null;
		}

		void cache(String cacheKey, DecompileResults results) {
			// Evict oldest entries if cache is full
			if (resultCache.size() >= MAX_CACHE_SIZE_PER_PROGRAM) {
				evictOldestEntries();
			}
			resultCache.put(cacheKey, new CachedResult(results));
		}

		void invalidateAllCaches() {
			resultCache.clear();
		}

		void invalidateFunctionCache(Address functionAddress) {
			String addressStr = functionAddress.toString();
			resultCache.entrySet().removeIf(entry -> entry.getKey().contains(addressStr));
		}

		void dispose() {
			decompilerLock.lock();
			try {
				if (decompInterface != null) {
					decompInterface.dispose();
					decompInterface = null;
				}
				resultCache.clear();
			} finally {
				decompilerLock.unlock();
			}
		}

		private void evictOldestEntries() {
			// Find and remove the 20% oldest entries
			int toRemove = MAX_CACHE_SIZE_PER_PROGRAM / 5;
			resultCache.entrySet().stream()
				.sorted((a, b) -> Long.compare(a.getValue().accessTime, b.getValue().accessTime))
				.limit(toRemove)
				.map(Map.Entry::getKey)
				.toList()
				.forEach(resultCache::remove);
		}
	}

	/**
	 * Wrapper for cached decompilation results with access time tracking.
	 */
	private static class CachedResult {
		final DecompileResults results;
		long accessTime;

		CachedResult(DecompileResults results) {
			this.results = results;
			this.accessTime = System.currentTimeMillis();
		}
	}
}
