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
import ghidra.program.util.ProgramChangeRecord;
import ghidra.reverend.api.v1.QueryService;
import ghidra.util.Msg;
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

	private static final String CONFIG_PREFIX = "ghidra.reverend.semantic.";
	private static final boolean SYMBOLIC_STAGE_ENABLED = getBooleanConfig("symbolic.enabled", true);
	private static final boolean LEXICAL_STAGE_ENABLED = getBooleanConfig("lexical.enabled", true);
	private static final boolean EMBEDDING_STAGE_ENABLED = getBooleanConfig("embedding.enabled", true);
	private static final double LEXICAL_MIN_SCORE = getDoubleConfig("lexical.minScore", 0.05d);
	private static final double EMBEDDING_MIN_SCORE = getDoubleConfig("embedding.minScore", 0.10d);
	private static final int EMBEDDING_STAGE_MULTIPLIER =
		Math.max(1, getIntConfig("embedding.candidateMultiplier", 3));

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
			SymbolicQueryConstraints symbolicConstraints = SymbolicQueryConstraints.parse(normalizedQuery);

			// Stage 1: symbolic candidate generation
			List<Function> symbolicCandidates = new ArrayList<>();
			FunctionIterator functions = program.getFunctionManager().getFunctions(
				scope != null ? scope : program.getMemory(), true);
			int symbolicInputCount = 0;
			for (Function func : functions) {
				if (monitor != null && monitor.isCancelled()) {
					break;
				}
				symbolicInputCount++;
				if (!SYMBOLIC_STAGE_ENABLED || symbolicConstraints.matches(func)) {
					symbolicCandidates.add(func);
				}
			}
			symbolicCandidates.sort(Comparator
				.comparing((Function functionCandidate) -> functionCandidate.getEntryPoint().toString())
				.thenComparing(Function::getName));
			logCandidateStageMetrics(operationId, normalizedQuery, "symbolic",
				symbolicInputCount, symbolicCandidates.size(),
				Map.of(
					"enabled", SYMBOLIC_STAGE_ENABLED,
					"constraintCount", symbolicConstraints.getConstraintCount()
				));

			// Stage 2: lexical filtering
			Map<Function, Double> lexicalScores = new HashMap<>();
			List<Function> lexicalCandidates = new ArrayList<>();
			for (Function candidate : symbolicCandidates) {
				double lexicalScore = computeLexicalScore(candidate, queryTerms);
				lexicalScores.put(candidate, lexicalScore);
				if (!LEXICAL_STAGE_ENABLED || lexicalScore >= LEXICAL_MIN_SCORE) {
					lexicalCandidates.add(candidate);
				}
			}
			if (LEXICAL_STAGE_ENABLED && lexicalCandidates.isEmpty()) {
				lexicalCandidates.addAll(symbolicCandidates);
			}
			logCandidateStageMetrics(operationId, normalizedQuery, "lexical",
				symbolicCandidates.size(), lexicalCandidates.size(),
				Map.of(
					"enabled", LEXICAL_STAGE_ENABLED,
					"minScore", LEXICAL_MIN_SCORE
				));

			// Stage 3: embedding candidate scoring with fallback when backend is unavailable
			boolean embeddingBackendAvailable = EMBEDDING_STAGE_ENABLED && isEmbeddingBackendAvailable();
			List<FunctionScore> scoredCandidates = new ArrayList<>();
			int embeddingWindow = Math.min(
				Math.max(maxResults, maxResults * EMBEDDING_STAGE_MULTIPLIER),
				lexicalCandidates.size());
			for (Function candidate : lexicalCandidates) {
				double lexicalScore = lexicalScores.getOrDefault(candidate, 0.0);
				double finalScore;
				if (embeddingBackendAvailable) {
					double embeddingScore = computeEmbeddingScore(program, candidate, queryTerms, monitor);
					finalScore = (0.65 * embeddingScore) + (0.35 * lexicalScore);
					if (finalScore < EMBEDDING_MIN_SCORE) {
						continue;
					}
				}
				else {
					finalScore = lexicalScore;
				}
				scoredCandidates.add(new FunctionScore(candidate, finalScore));
			}
			scoredCandidates.sort((a, b) -> {
				int scoreCmp = Double.compare(b.score, a.score);
				if (scoreCmp != 0) {
					return scoreCmp;
				}
				return a.function.getEntryPoint().toString().compareTo(b.function.getEntryPoint().toString());
			});
			if (scoredCandidates.size() > embeddingWindow) {
				scoredCandidates = new ArrayList<>(scoredCandidates.subList(0, embeddingWindow));
			}
			logCandidateStageMetrics(operationId, normalizedQuery, "embedding",
				lexicalCandidates.size(), scoredCandidates.size(),
				Map.of(
					"enabled", EMBEDDING_STAGE_ENABLED,
					"backendAvailable", embeddingBackendAvailable,
					"fallbackApplied", !embeddingBackendAvailable,
					"minScore", EMBEDDING_MIN_SCORE,
					"candidateMultiplier", EMBEDDING_STAGE_MULTIPLIER
				));

			// Build result set
			List<QueryResult> results = new ArrayList<>();
			for (FunctionScore scored : scoredCandidates) {
				results.add(new QueryResultImpl(
					scored.function.getEntryPoint(),
					scored.score,
					buildSemanticSummary(scored.function, query),
					null
				));
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
			Set<Address> changedFunctionEntries = new HashSet<>();

			ev.forEach(ProgramEvent.FUNCTION_ADDED, record -> {
				extractFunctionEntry(record).ifPresent(changedFunctionEntries::add);
				telemetry.recordCacheInvalidation("FUNCTION_ADDED", changedProgram);
			});
			ev.forEach(ProgramEvent.FUNCTION_REMOVED, record -> {
				extractFunctionEntry(record).ifPresent(changedFunctionEntries::add);
				telemetry.recordCacheInvalidation("FUNCTION_REMOVED", changedProgram);
			});
			ev.forEach(ProgramEvent.FUNCTION_CHANGED, record -> {
				extractFunctionEntry(record).ifPresent(changedFunctionEntries::add);
				telemetry.recordCacheInvalidation("FUNCTION_CHANGED", changedProgram);
			});
			ev.forEach(ProgramEvent.FUNCTION_BODY_CHANGED, record -> {
				extractFunctionEntry(record).ifPresent(changedFunctionEntries::add);
				telemetry.recordCacheInvalidation("FUNCTION_BODY_CHANGED", changedProgram);
			});
			cacheManager.invalidateFunctionCaches(changedProgram, changedFunctionEntries);
		}

		if (ev.contains(ProgramEvent.SYMBOL_ADDED, ProgramEvent.SYMBOL_REMOVED,
				ProgramEvent.SYMBOL_RENAMED)) {
			// Invalidate symbol-related caches
			cacheManager.invalidateSymbolCaches(changedProgram);
			telemetry.recordCacheInvalidation("SYMBOL_CHANGED", changedProgram);
		}

		if (ev.contains(ProgramEvent.CODE_ADDED, ProgramEvent.CODE_REMOVED,
				ProgramEvent.CODE_REPLACED)) {
			ev.forEach(ProgramEvent.CODE_ADDED, record -> invalidateCodeRecord(changedProgram, record));
			ev.forEach(ProgramEvent.CODE_REMOVED, record -> invalidateCodeRecord(changedProgram, record));
			ev.forEach(ProgramEvent.CODE_REPLACED, record -> invalidateCodeRecord(changedProgram, record));
			telemetry.recordCacheInvalidation("CODE_CHANGED", changedProgram);
		}

		if (ev.contains(ProgramEvent.MEMORY_BLOCK_ADDED, ProgramEvent.MEMORY_BLOCK_REMOVED,
				ProgramEvent.MEMORY_BYTES_CHANGED)) {
			// Invalidate all caches for major memory changes
			cacheManager.invalidateAllCaches(changedProgram);
			decompilerProvider.invalidateAllCaches(changedProgram);
			telemetry.recordCacheInvalidation("MEMORY_CHANGED", changedProgram);
		}

		if (cacheManager.verifyAndRepairIndex(changedProgram)) {
			telemetry.recordCacheInvalidation("INDEX_DRIFT_REPAIRED", changedProgram);
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

	private double computeLexicalScore(Function function, String[] queryTerms) {
		if (queryTerms.length == 0) {
			return 0.0;
		}
		double score = 0.0;
		String functionName = function.getName().toLowerCase();
		String comment = function.getComment() != null ? function.getComment().toLowerCase() : "";
		for (String term : queryTerms) {
			if (functionName.contains(term)) {
				score += 0.6;
			}
			if (!comment.isEmpty() && comment.contains(term)) {
				score += 0.4;
			}
		}
		return Math.min(1.0, score / queryTerms.length);
	}

	private double computeEmbeddingScore(Program program, Function function,
			String[] queryTerms, TaskMonitor monitor) {
		if (queryTerms.length == 0) {
			return 0.0;
		}
		try {
			DecompileResults results = decompilerProvider.decompile(program, function, monitor);
			if (results == null || !results.decompileCompleted() || results.getDecompiledFunction() == null) {
				return 0.0;
			}
			String decompiledCode = results.getDecompiledFunction().getC().toLowerCase();
			int matches = 0;
			for (String term : queryTerms) {
				if (decompiledCode.contains(term)) {
					matches++;
				}
			}
			return Math.min(1.0, matches / (double) queryTerms.length);
		}
		catch (Exception e) {
			return 0.0;
		}
	}

	private boolean isEmbeddingBackendAvailable() {
		String backend = System.getProperty(CONFIG_PREFIX + "embedding.backend", "local");
		if (backend == null) {
			return true;
		}
		String normalized = backend.trim().toLowerCase(Locale.ROOT);
		return !(normalized.isEmpty() || "none".equals(normalized) || "unavailable".equals(normalized));
	}

	private void logCandidateStageMetrics(String operationId, String query, String stage,
			int inputCount, int outputCount, Map<String, Object> details) {
		int contributionCount = Math.max(0, inputCount - outputCount);
		Msg.info(this, String.format(
			"semantic-search-stage op=%s query=\"%s\" stage=%s input=%d output=%d contribution=%d details=%s",
			operationId,
			query,
			stage,
			inputCount,
			outputCount,
			contributionCount,
			details
		));
	}

	private static boolean getBooleanConfig(String suffix, boolean defaultValue) {
		return Boolean.parseBoolean(System.getProperty(CONFIG_PREFIX + suffix, String.valueOf(defaultValue)));
	}

	private static double getDoubleConfig(String suffix, double defaultValue) {
		String raw = System.getProperty(CONFIG_PREFIX + suffix);
		if (raw == null) {
			return defaultValue;
		}
		try {
			return Double.parseDouble(raw);
		}
		catch (NumberFormatException e) {
			return defaultValue;
		}
	}

	private static int getIntConfig(String suffix, int defaultValue) {
		String raw = System.getProperty(CONFIG_PREFIX + suffix);
		if (raw == null) {
			return defaultValue;
		}
		try {
			return Integer.parseInt(raw);
		}
		catch (NumberFormatException e) {
			return defaultValue;
		}
	}

	private void invalidateCodeRecord(Program program, ghidra.framework.model.DomainObjectChangeRecord record) {
		if (record instanceof ProgramChangeRecord changeRecord &&
			changeRecord.getStart() != null && changeRecord.getEnd() != null) {
			cacheManager.invalidateCodeCaches(program, changeRecord.getStart(), changeRecord.getEnd());
			return;
		}
		cacheManager.invalidateCodeCaches(program);
	}

	private Optional<Address> extractFunctionEntry(ghidra.framework.model.DomainObjectChangeRecord record) {
		if (!(record instanceof ProgramChangeRecord changeRecord)) {
			return Optional.empty();
		}
		Object affected = changeRecord.getObject();
		if (affected instanceof Function function && function.getEntryPoint() != null) {
			return Optional.of(function.getEntryPoint());
		}
		if (changeRecord.getStart() != null) {
			return Optional.of(changeRecord.getStart());
		}
		if (changeRecord.getNewValue() instanceof Function function && function.getEntryPoint() != null) {
			return Optional.of(function.getEntryPoint());
		}
		if (changeRecord.getOldValue() instanceof Function function && function.getEntryPoint() != null) {
			return Optional.of(function.getEntryPoint());
		}
		return Optional.empty();
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

	private static class FunctionScore {
		private final Function function;
		private final double score;

		FunctionScore(Function function, double score) {
			this.function = function;
			this.score = score;
		}
	}

	private static class SymbolicQueryConstraints {
		private final Optional<String> nameContains;
		private final Optional<String> commentContains;
		private final OptionalInt minParams;
		private final OptionalInt maxParams;

		private SymbolicQueryConstraints(Optional<String> nameContains, Optional<String> commentContains,
				OptionalInt minParams, OptionalInt maxParams) {
			this.nameContains = nameContains;
			this.commentContains = commentContains;
			this.minParams = minParams;
			this.maxParams = maxParams;
		}

		static SymbolicQueryConstraints parse(String normalizedQuery) {
			Optional<String> nameContains = Optional.empty();
			Optional<String> commentContains = Optional.empty();
			OptionalInt minParams = OptionalInt.empty();
			OptionalInt maxParams = OptionalInt.empty();
			String[] tokens = normalizedQuery.split("\\s+");
			for (String token : tokens) {
				String[] kv = token.split(":", 2);
				if (kv.length != 2) {
					continue;
				}
				String key = kv[0].trim();
				String value = kv[1].trim();
				if (value.isEmpty()) {
					continue;
				}
				switch (key) {
					case "name":
						nameContains = Optional.of(value);
						break;
					case "comment":
						commentContains = Optional.of(value);
						break;
					case "minparams":
						try {
							minParams = OptionalInt.of(Integer.parseInt(value));
						}
						catch (NumberFormatException e) {
							// Ignore malformed symbolic constraint.
						}
						break;
					case "maxparams":
						try {
							maxParams = OptionalInt.of(Integer.parseInt(value));
						}
						catch (NumberFormatException e) {
							// Ignore malformed symbolic constraint.
						}
						break;
					default:
						break;
				}
			}
			return new SymbolicQueryConstraints(
				nameContains, commentContains, minParams, maxParams);
		}

		boolean matches(Function function) {
			String name = function.getName().toLowerCase();
			String comment = function.getComment() != null ? function.getComment().toLowerCase() : "";
			if (nameContains.isPresent() && !name.contains(nameContains.get())) {
				return false;
			}
			if (commentContains.isPresent() && !comment.contains(commentContains.get())) {
				return false;
			}
			int paramCount = function.getParameterCount();
			if (minParams.isPresent() && paramCount < minParams.getAsInt()) {
				return false;
			}
			if (maxParams.isPresent() && paramCount > maxParams.getAsInt()) {
				return false;
			}
			return true;
		}

		int getConstraintCount() {
			int count = 0;
			if (nameContains.isPresent()) {
				count++;
			}
			if (commentContains.isPresent()) {
				count++;
			}
			if (minParams.isPresent()) {
				count++;
			}
			if (maxParams.isPresent()) {
				count++;
			}
			return count;
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
