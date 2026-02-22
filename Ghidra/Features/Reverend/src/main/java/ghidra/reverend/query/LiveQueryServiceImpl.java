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

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectListener;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.util.ProgramEvent;
import ghidra.reverend.api.v1.QueryService;
import ghidra.util.task.TaskMonitor;

/**
 * Implementation of {@link QueryService} that binds to live Program and Decompiler state.
 *
 * <p>This implementation:
 * <ul>
 *   <li>Maintains a live binding to the active Program</li>
 *   <li>Caches decompiler results with automatic invalidation on program changes</li>
 *   <li>Emits latency and error telemetry for all query operations</li>
 *   <li>Respects policy controls for egress operations</li>
 * </ul>
 *
 * @since 1.0
 */
public class LiveQueryServiceImpl implements QueryService, DomainObjectListener, AutoCloseable {

	private final QueryCacheManager cacheManager;
	private final DecompilerContextProvider decompilerProvider;
	private final QueryTelemetry telemetry;

	private volatile Program currentProgram;
	private final Map<Program, ProgramBindingState> programBindings = new ConcurrentHashMap<>();

	/**
	 * Creates a new LiveQueryServiceImpl with the given components.
	 *
	 * @param cacheManager the cache manager for query results
	 * @param decompilerProvider the decompiler context provider
	 * @param telemetry the telemetry collector
	 */
	public LiveQueryServiceImpl(QueryCacheManager cacheManager,
			DecompilerContextProvider decompilerProvider, QueryTelemetry telemetry) {
		this.cacheManager = Objects.requireNonNull(cacheManager, "cacheManager");
		this.decompilerProvider = Objects.requireNonNull(decompilerProvider, "decompilerProvider");
		this.telemetry = Objects.requireNonNull(telemetry, "telemetry");
	}

	/**
	 * Binds to the given program, registering for change notifications.
	 *
	 * @param program the program to bind to
	 */
	public void bindToProgram(Program program) {
		if (program == null) {
			return;
		}

		// Remove binding from old program if different
		if (currentProgram != null && currentProgram != program) {
			unbindFromProgram(currentProgram);
		}

		currentProgram = program;

		// Establish new binding
		programBindings.computeIfAbsent(program, p -> {
			p.addListener(this);
			cacheManager.initializeForProgram(p);
			decompilerProvider.initializeForProgram(p);
			return new ProgramBindingState(p);
		});

		telemetry.recordProgramBind(program);
	}

	/**
	 * Unbinds from the given program, removing change listeners and clearing caches.
	 *
	 * @param program the program to unbind from
	 */
	public void unbindFromProgram(Program program) {
		if (program == null) {
			return;
		}

		ProgramBindingState state = programBindings.remove(program);
		if (state != null) {
			program.removeListener(this);
			cacheManager.invalidateProgram(program);
			decompilerProvider.disposeForProgram(program);
		}

		if (currentProgram == program) {
			currentProgram = null;
		}

		telemetry.recordProgramUnbind(program);
	}

	/**
	 * Returns the currently bound program.
	 *
	 * @return the current program, or null if none bound
	 */
	public Program getCurrentProgram() {
		return currentProgram;
	}

	@Override
	public List<QueryResult> findSimilarFunctions(Program program, Function function,
			int maxResults, TaskMonitor monitor) throws QueryException {
		long startTime = System.nanoTime();
		String operationId = telemetry.startOperation("findSimilarFunctions", program);

		try {
			validateProgramBinding(program);
			Objects.requireNonNull(function, "function");

			if (monitor != null) {
				monitor.setMessage("Finding similar functions...");
				monitor.initialize(100);
			}

			// Check cache first
			String cacheKey = buildSimilarFunctionsCacheKey(function);
			List<QueryResult> cached = cacheManager.getCachedSimilarFunctions(program, cacheKey);
			if (cached != null) {
				telemetry.recordCacheHit(operationId);
				return cached.subList(0, Math.min(cached.size(), maxResults));
			}

			telemetry.recordCacheMiss(operationId);

			// Decompile the reference function to extract features
			DecompileResults decompResults = decompilerProvider.decompile(program, function, monitor);
			if (decompResults == null || !decompResults.decompileCompleted()) {
				throw new QueryException("Failed to decompile function: " + function.getName());
			}

			if (monitor != null) {
				monitor.setProgress(30);
			}

			// Find similar functions by comparing decompiler features
			List<QueryResult> results = new ArrayList<>();
			FunctionIterator functions = program.getFunctionManager().getFunctions(true);
			int totalFunctions = program.getFunctionManager().getFunctionCount();
			int processed = 0;

			for (Function candidate : functions) {
				if (monitor != null && monitor.isCancelled()) {
					break;
				}

				if (candidate.equals(function)) {
					continue;
				}

				double similarity = computeFunctionSimilarity(program, function, candidate, monitor);
				if (similarity > 0.3) { // Threshold for relevance
					results.add(new QueryResultImpl(
						candidate.getEntryPoint(),
						similarity,
						buildFunctionSummary(candidate, similarity),
						null
					));
				}

				processed++;
				if (monitor != null && totalFunctions > 0) {
					monitor.setProgress(30 + (int) (70.0 * processed / totalFunctions));
				}
			}

			// Sort by similarity descending
			results.sort((a, b) -> Double.compare(b.getScore(), a.getScore()));

			// Trim to max results
			if (results.size() > maxResults) {
				results = new ArrayList<>(results.subList(0, maxResults));
			}

			// Cache the results
			cacheManager.cacheSimilarFunctions(program, cacheKey, results);

			telemetry.recordOperationSuccess(operationId, System.nanoTime() - startTime);
			return results;

		} catch (QueryException e) {
			telemetry.recordOperationError(operationId, e);
			throw e;
		} catch (Exception e) {
			telemetry.recordOperationError(operationId, e);
			throw new QueryException("Error finding similar functions: " + e.getMessage(), e);
		}
	}

	@Override
	public List<QueryResult> semanticSearch(Program program, String query,
			AddressSetView scope, int maxResults, TaskMonitor monitor) throws QueryException {
		long startTime = System.nanoTime();
		String operationId = telemetry.startOperation("semanticSearch", program);

		try {
			validateProgramBinding(program);
			Objects.requireNonNull(query, "query");

			if (query.trim().isEmpty()) {
				throw new QueryException("Query string cannot be empty");
			}

			if (monitor != null) {
				monitor.setMessage("Performing semantic search: " + query);
				monitor.initialize(100);
			}

			// Check cache
			String cacheKey = buildSemanticSearchCacheKey(query, scope);
			List<QueryResult> cached = cacheManager.getCachedSemanticSearch(program, cacheKey);
			if (cached != null) {
				telemetry.recordCacheHit(operationId);
				return cached.subList(0, Math.min(cached.size(), maxResults));
			}

			telemetry.recordCacheMiss(operationId);

			// Normalize query
			String normalizedQuery = query.toLowerCase().trim();
			String[] queryTerms = normalizedQuery.split("\\s+");

			// Search functions by name, comments, and decompiled output
			List<QueryResult> results = new ArrayList<>();
			FunctionIterator functions = program.getFunctionManager().getFunctions(
				scope != null ? scope : program.getMemory(), true);

			int processed = 0;
			for (Function func : functions) {
				if (monitor != null && monitor.isCancelled()) {
					break;
				}

				double score = computeSemanticScore(program, func, queryTerms, monitor);
				if (score > 0.1) { // Minimum relevance threshold
					results.add(new QueryResultImpl(
						func.getEntryPoint(),
						score,
						buildSemanticSummary(func, query),
						null
					));
				}

				processed++;
				if (monitor != null) {
					monitor.setProgress(processed % 100);
				}
			}

			// Sort by score descending
			results.sort((a, b) -> Double.compare(b.getScore(), a.getScore()));

			// Trim to max results
			if (results.size() > maxResults) {
				results = new ArrayList<>(results.subList(0, maxResults));
			}

			// Cache results
			cacheManager.cacheSemanticSearch(program, cacheKey, results);

			telemetry.recordOperationSuccess(operationId, System.nanoTime() - startTime);
			return results;

		} catch (QueryException e) {
			telemetry.recordOperationError(operationId, e);
			throw e;
		} catch (Exception e) {
			telemetry.recordOperationError(operationId, e);
			throw new QueryException("Error in semantic search: " + e.getMessage(), e);
		}
	}

	@Override
	public List<Address> patternSearch(Program program, String pattern,
			AddressSetView scope, TaskMonitor monitor) throws QueryException {
		long startTime = System.nanoTime();
		String operationId = telemetry.startOperation("patternSearch", program);

		try {
			validateProgramBinding(program);
			Objects.requireNonNull(pattern, "pattern");

			if (monitor != null) {
				monitor.setMessage("Searching for pattern: " + pattern);
			}

			// Check cache
			String cacheKey = buildPatternSearchCacheKey(pattern, scope);
			List<Address> cached = cacheManager.getCachedPatternSearch(program, cacheKey);
			if (cached != null) {
				telemetry.recordCacheHit(operationId);
				return cached;
			}

			telemetry.recordCacheMiss(operationId);

			// Parse pattern and search
			List<Address> results = new ArrayList<>();
			AddressSetView searchScope = scope != null ? scope : program.getMemory();

			// Simple string-based pattern search in disassembly
			InstructionIterator instructions = program.getListing().getInstructions(searchScope, true);

			for (Instruction instr : instructions) {
				if (monitor != null && monitor.isCancelled()) {
					break;
				}

				String instrStr = instr.toString().toLowerCase();
				if (instrStr.contains(pattern.toLowerCase())) {
					results.add(instr.getAddress());
				}
			}

			// Cache results
			cacheManager.cachePatternSearch(program, cacheKey, results);

			telemetry.recordOperationSuccess(operationId, System.nanoTime() - startTime);
			return results;

		} catch (QueryException e) {
			telemetry.recordOperationError(operationId, e);
			throw e;
		} catch (Exception e) {
			telemetry.recordOperationError(operationId, e);
			throw new QueryException("Error in pattern search: " + e.getMessage(), e);
		}
	}

	@Override
	public Optional<QueryContext> getContext(Program program, Address address) throws QueryException {
		long startTime = System.nanoTime();
		String operationId = telemetry.startOperation("getContext", program);

		try {
			validateProgramBinding(program);
			Objects.requireNonNull(address, "address");

			// Check cache
			QueryContext cached = cacheManager.getCachedContext(program, address);
			if (cached != null) {
				telemetry.recordCacheHit(operationId);
				return Optional.of(cached);
			}

			telemetry.recordCacheMiss(operationId);

			// Build context
			Function function = program.getFunctionManager().getFunctionContaining(address);

			// Get decompiled code if in a function
			String decompiledCode = null;
			if (function != null) {
				DecompileResults results = decompilerProvider.decompile(program, function, TaskMonitor.DUMMY);
				if (results != null && results.decompileCompleted() && results.getDecompiledFunction() != null) {
					decompiledCode = results.getDecompiledFunction().getC();
				}
			}

			// Get references
			List<Address> references = new ArrayList<>();
			ReferenceIterator refIter = program.getReferenceManager().getReferencesTo(address);
			while (refIter.hasNext()) {
				Reference ref = refIter.next();
				references.add(ref.getFromAddress());
			}

			QueryContext context = new QueryContextImpl(address, function, decompiledCode, references);

			// Cache the context
			cacheManager.cacheContext(program, address, context);

			telemetry.recordOperationSuccess(operationId, System.nanoTime() - startTime);
			return Optional.of(context);

		} catch (QueryException e) {
			telemetry.recordOperationError(operationId, e);
			throw e;
		} catch (Exception e) {
			telemetry.recordOperationError(operationId, e);
			throw new QueryException("Error getting context: " + e.getMessage(), e);
		}
	}

	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		// Handle program change events for cache invalidation
		Program changedProgram = (Program) ev.getSource();

		// Check for events that require cache invalidation
		if (ev.contains(ProgramEvent.FUNCTION_ADDED, ProgramEvent.FUNCTION_REMOVED,
				ProgramEvent.FUNCTION_CHANGED, ProgramEvent.FUNCTION_BODY_CHANGED)) {

			// Invalidate function-related caches
			ev.forEach(ProgramEvent.FUNCTION_ADDED, record -> {
				cacheManager.invalidateFunctionCaches(changedProgram);
				telemetry.recordCacheInvalidation("FUNCTION_ADDED", changedProgram);
			});
			ev.forEach(ProgramEvent.FUNCTION_REMOVED, record -> {
				cacheManager.invalidateFunctionCaches(changedProgram);
				telemetry.recordCacheInvalidation("FUNCTION_REMOVED", changedProgram);
			});
			ev.forEach(ProgramEvent.FUNCTION_CHANGED, record -> {
				cacheManager.invalidateFunctionCaches(changedProgram);
				telemetry.recordCacheInvalidation("FUNCTION_CHANGED", changedProgram);
			});
			ev.forEach(ProgramEvent.FUNCTION_BODY_CHANGED, record -> {
				cacheManager.invalidateFunctionCaches(changedProgram);
				telemetry.recordCacheInvalidation("FUNCTION_BODY_CHANGED", changedProgram);
			});
		}

		if (ev.contains(ProgramEvent.SYMBOL_ADDED, ProgramEvent.SYMBOL_REMOVED,
				ProgramEvent.SYMBOL_RENAMED)) {
			// Invalidate symbol-related caches
			cacheManager.invalidateSymbolCaches(changedProgram);
			telemetry.recordCacheInvalidation("SYMBOL_CHANGED", changedProgram);
		}

		if (ev.contains(ProgramEvent.CODE_ADDED, ProgramEvent.CODE_REMOVED,
				ProgramEvent.CODE_REPLACED)) {
			// Invalidate code-related caches
			cacheManager.invalidateCodeCaches(changedProgram);
			telemetry.recordCacheInvalidation("CODE_CHANGED", changedProgram);
		}

		if (ev.contains(ProgramEvent.MEMORY_BLOCK_ADDED, ProgramEvent.MEMORY_BLOCK_REMOVED,
				ProgramEvent.MEMORY_BYTES_CHANGED)) {
			// Invalidate all caches for major memory changes
			cacheManager.invalidateAllCaches(changedProgram);
			decompilerProvider.invalidateAllCaches(changedProgram);
			telemetry.recordCacheInvalidation("MEMORY_CHANGED", changedProgram);
		}
	}

	@Override
	public void close() {
		// Unbind from all programs
		for (Program program : new ArrayList<>(programBindings.keySet())) {
			unbindFromProgram(program);
		}
		decompilerProvider.close();
	}

	// --- Private helper methods ---

	private void validateProgramBinding(Program program) throws QueryException {
		if (program == null) {
			throw new QueryException("Program cannot be null");
		}
		if (!programBindings.containsKey(program)) {
			// Auto-bind to the program
			bindToProgram(program);
		}
	}

	private String buildSimilarFunctionsCacheKey(Function function) {
		return CacheKeyGenerator.forSimilarFunctions(function.getEntryPoint().toString());
	}

	private String buildSemanticSearchCacheKey(String query, AddressSetView scope) {
		return CacheKeyGenerator.forSemanticSearch(query, scope);
	}

	private String buildPatternSearchCacheKey(String pattern, AddressSetView scope) {
		return CacheKeyGenerator.forPatternSearch(pattern, scope);
	}

	private double computeFunctionSimilarity(Program program, Function reference,
			Function candidate, TaskMonitor monitor) {
		// Compare basic function characteristics
		double score = 0.0;

		// Compare parameter counts
		int refParamCount = reference.getParameterCount();
		int candParamCount = candidate.getParameterCount();
		if (refParamCount == candParamCount) {
			score += 0.2;
		} else {
			score += 0.1 * (1.0 / (1.0 + Math.abs(refParamCount - candParamCount)));
		}

		// Compare body size
		long refSize = reference.getBody().getNumAddresses();
		long candSize = candidate.getBody().getNumAddresses();
		double sizeSimilarity = 1.0 - (Math.abs(refSize - candSize) / (double) Math.max(refSize, candSize));
		score += 0.3 * Math.max(0, sizeSimilarity);

		// Compare call counts
		int refCalls = getCallCount(reference);
		int candCalls = getCallCount(candidate);
		if (refCalls == candCalls) {
			score += 0.2;
		} else if (Math.abs(refCalls - candCalls) <= 2) {
			score += 0.1;
		}

		// Compare return type
		if (reference.getReturnType().equals(candidate.getReturnType())) {
			score += 0.1;
		}

		// Compare calling convention
		if (reference.getCallingConventionName().equals(candidate.getCallingConventionName())) {
			score += 0.1;
		}

		// TODO: Integrate with embedding-based similarity when available

		return Math.min(1.0, score);
	}

	private int getCallCount(Function function) {
		int count = 0;
		InstructionIterator iter = function.getProgram().getListing()
			.getInstructions(function.getBody(), true);
		while (iter.hasNext()) {
			Instruction instr = iter.next();
			if (instr.getFlowType().isCall()) {
				count++;
			}
		}
		return count;
	}

	private String buildFunctionSummary(Function function, double similarity) {
		return String.format("%s (%.1f%% similar) - %d params, %d bytes",
			function.getName(),
			similarity * 100,
			function.getParameterCount(),
			function.getBody().getNumAddresses());
	}

	private double computeSemanticScore(Program program, Function function,
			String[] queryTerms, TaskMonitor monitor) {
		double score = 0.0;
		int matches = 0;

		// Check function name
		String funcName = function.getName().toLowerCase();
		for (String term : queryTerms) {
			if (funcName.contains(term)) {
				matches++;
				score += 0.3;
			}
		}

		// Check comments
		String comment = function.getComment();
		if (comment != null) {
			String lowerComment = comment.toLowerCase();
			for (String term : queryTerms) {
				if (lowerComment.contains(term)) {
					matches++;
					score += 0.2;
				}
			}
		}

		// Check decompiled output for more context
		try {
			DecompileResults results = decompilerProvider.decompile(program, function, monitor);
			if (results != null && results.decompileCompleted() && results.getDecompiledFunction() != null) {
				String decompiledCode = results.getDecompiledFunction().getC().toLowerCase();
				for (String term : queryTerms) {
					if (decompiledCode.contains(term)) {
						matches++;
						score += 0.15;
					}
				}
			}
		} catch (Exception e) {
			// Ignore decompilation errors for scoring
		}

		// Normalize by query term count
		if (queryTerms.length > 0) {
			score = score / queryTerms.length;
		}

		return Math.min(1.0, score);
	}

	private String buildSemanticSummary(Function function, String query) {
		return String.format("Match in %s: function with %d parameters",
			function.getName(), function.getParameterCount());
	}

	// --- Inner classes ---

	/**
	 * Tracks binding state for a program.
	 */
	private static class ProgramBindingState {
		private final Program program;
		private final long bindTime;

		ProgramBindingState(Program program) {
			this.program = program;
			this.bindTime = System.currentTimeMillis();
		}
	}

	/**
	 * Implementation of QueryResult.
	 */
	private static class QueryResultImpl implements QueryResult {
		private final Address address;
		private final double score;
		private final String summary;
		private final String evidenceId;

		QueryResultImpl(Address address, double score, String summary, String evidenceId) {
			this.address = address;
			this.score = score;
			this.summary = summary;
			this.evidenceId = evidenceId;
		}

		@Override
		public Address getAddress() {
			return address;
		}

		@Override
		public double getScore() {
			return score;
		}

		@Override
		public String getSummary() {
			return summary;
		}

		@Override
		public Optional<String> getEvidenceId() {
			return Optional.ofNullable(evidenceId);
		}
	}

	/**
	 * Implementation of QueryContext.
	 */
	private static class QueryContextImpl implements QueryContext {
		private final Address address;
		private final Function function;
		private final String decompiledCode;
		private final List<Address> references;

		QueryContextImpl(Address address, Function function, String decompiledCode,
				List<Address> references) {
			this.address = address;
			this.function = function;
			this.decompiledCode = decompiledCode;
			this.references = Collections.unmodifiableList(new ArrayList<>(references));
		}

		@Override
		public Address getAddress() {
			return address;
		}

		@Override
		public Optional<Function> getFunction() {
			return Optional.ofNullable(function);
		}

		@Override
		public Optional<String> getDecompiledCode() {
			return Optional.ofNullable(decompiledCode);
		}

		@Override
		public List<Address> getReferences() {
			return references;
		}
	}
}
