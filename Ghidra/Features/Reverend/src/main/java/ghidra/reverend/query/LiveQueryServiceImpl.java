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
import java.util.concurrent.atomic.AtomicInteger;

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
	private static final int DECOMPILE_BUDGET_PER_QUERY =
		Math.max(0, getIntConfig("decompile.budgetPerQuery", 64));
	private static final int DECOMPILE_BUDGET_PER_SESSION =
		Math.max(0, getIntConfig("decompile.budgetPerSession", 4096));
	private static final RankingWeightPolicy SIMILARITY_RANKING_POLICY =
		RankingWeightPolicy.fromConfig(
			"ranking.weights.similarity.static", 0.6d,
			"ranking.weights.similarity.dynamic", 0.4d);
	private static final RankingWeightPolicy SEMANTIC_RANKING_POLICY =
		RankingWeightPolicy.fromConfig(
			"ranking.weights.semantic.static", 0.55d,
			"ranking.weights.semantic.dynamic", 0.45d);

	private final QueryCacheManager cacheManager;
	private final DecompilerContextProvider decompilerProvider;
	private final QueryTelemetry telemetry;
	private final DecompileBudgetManager decompileBudgetManager;
	private final TemporalEvidenceGraph temporalEvidenceGraph;
	private final Map<String, String> lastTemporalEventByProgramAddress = new ConcurrentHashMap<>();
	private final ThreadLocal<BudgetStatus> lastSemanticBudgetStatus =
		ThreadLocal.withInitial(BudgetStatus::none);

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
		this.temporalEvidenceGraph = new TemporalEvidenceGraph();
		this.decompileBudgetManager = new DecompileBudgetManager(
			DECOMPILE_BUDGET_PER_QUERY, DECOMPILE_BUDGET_PER_SESSION);
	}

	/**
	 * Returns and clears semantic search budget status for the calling thread.
	 *
	 * <p>The status is set after each semantic search operation.
	 *
	 * @return semantic search budget status
	 */
	public BudgetStatus consumeLastSemanticSearchBudgetStatus() {
		BudgetStatus status = lastSemanticBudgetStatus.get();
		lastSemanticBudgetStatus.remove();
		return status;
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
			String programId = programId(program);
			temporalEvidenceGraph.clearProgram(programId);
			lastTemporalEventByProgramAddress.keySet()
				.removeIf(key -> key.startsWith(programId + "|"));
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

	void ingestTemporalEventForTesting(TemporalEvent event) {
		if (event == null) {
			return;
		}
		temporalEvidenceGraph.upsert(event);
		event.getAddress().ifPresent(address ->
			rememberTemporalEvent(event.getProgramId(), address, event.getEventId()));
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
			List<Function> candidates = new ArrayList<>();
			FunctionIterator functions = program.getFunctionManager().getFunctions(true);
			while (functions.hasNext()) {
				Function candidate = functions.next();
				if (!candidate.equals(function)) {
					candidates.add(candidate);
				}
			}
			List<Function> indexedFunctions = new ArrayList<>(candidates.size() + 1);
			indexedFunctions.add(function);
			indexedFunctions.addAll(candidates);
			QueryCacheManager.FunctionFeatureBatch featureBatch =
				cacheManager.ensureFunctionFeatures(program, indexedFunctions);
			QueryCacheManager.IndexedFunctionFeatures referenceFeatures =
				featureBatch.get(function.getEntryPoint());
			if (referenceFeatures == null) {
				throw new QueryException("Failed to index function features: " + function.getName());
			}
			String[] referenceTerms = referenceFeatures.getLexicalTokens().stream()
				.sorted()
				.toArray(String[]::new);
			if (monitor != null) {
				monitor.setProgress(20);
			}

			// Find similar functions by comparing indexed function features.
			boolean embeddingBackendAvailable = EMBEDDING_STAGE_ENABLED && isEmbeddingBackendAvailable();
			QueryDecompileBudget queryBudget = decompileBudgetManager.startQuery();
			List<FunctionScore> scoredCandidates = new ArrayList<>();
			int totalFunctions = candidates.size();
			int processed = 0;
			int decompileCandidates = 0;

			for (Function candidate : candidates) {
				if (monitor != null && monitor.isCancelled()) {
					break;
				}

				QueryCacheManager.IndexedFunctionFeatures candidateFeatures =
					featureBatch.get(candidate.getEntryPoint());
				if (candidateFeatures == null) {
					continue;
				}

				double indexedSimilarity = computeFunctionSimilarity(referenceFeatures, candidateFeatures);
				double finalSimilarity = indexedSimilarity;
				boolean dynamicSignalApplied = false;
				if (embeddingBackendAvailable) {
					EmbeddingScoreResult embeddingResult = computeEmbeddingScoreWithBudget(
						program, candidate, referenceTerms, monitor, queryBudget);
					if (embeddingResult.usedEmbeddingScore) {
						finalSimilarity = SIMILARITY_RANKING_POLICY.combine(indexedSimilarity,
							embeddingResult.score);
						dynamicSignalApplied = SIMILARITY_RANKING_POLICY.getDynamicWeight() > 0.0d;
						decompileCandidates++;
					}
				}
				if (finalSimilarity > 0.3) { // Threshold for relevance
					scoredCandidates.add(new FunctionScore(candidate, finalSimilarity,
						dynamicSignalApplied));
				}

				processed++;
				if (monitor != null && totalFunctions > 0) {
					monitor.setProgress(30 + (int) (70.0 * processed / totalFunctions));
				}
			}

			List<QueryResult> results = new ArrayList<>(scoredCandidates.size());
			String similarityMode = embeddingBackendAvailable
					? "embedding_rerank"
					: "deterministic_index_fallback";
			for (FunctionScore candidate : scoredCandidates) {
				QueryCacheManager.IndexedFunctionFeatures candidateFeatures =
					featureBatch.get(candidate.function.getEntryPoint());
				results.add(new QueryResultImpl(
					candidate.function.getEntryPoint(),
					candidate.score,
					buildFunctionSummary(candidateFeatures != null
						? candidateFeatures
						: QueryCacheManager.IndexedFunctionFeatures.fromFunction(candidate.function),
						candidate.score),
					buildEvidenceId("similarity", candidate.function.getEntryPoint()),
					buildEvidenceRefs("similarity", candidate.function.getEntryPoint()),
					buildProvenance("similarity", similarityMode, embeddingBackendAvailable,
						candidate.dynamicSignalApplied, SIMILARITY_RANKING_POLICY,
						candidate.function.getEntryPoint())
				));
			}

			// Sort by similarity descending
			results.sort((a, b) -> compareResultsDescending(a.getScore(), b.getScore(),
				a.getAddress(), b.getAddress()));

			// Trim to max results
			if (results.size() > maxResults) {
				results = new ArrayList<>(results.subList(0, maxResults));
			}

			Msg.info(this, String.format(
				"similarity-index-profile op=%s candidates=%d indexedFresh=%d indexedReused=%d decompileCandidates=%d",
				operationId,
				totalFunctions,
				featureBatch.getIndexedCount(),
				featureBatch.getReusedCount(),
				decompileCandidates));

			// Cache the results
			cacheManager.cacheSimilarFunctions(program, cacheKey, results);
			recordTemporalQueryResults(program, "similarity", operationId, results);

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
		BudgetStatus budgetStatus = BudgetStatus.none();

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
				lastSemanticBudgetStatus.set(BudgetStatus.none());
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

			QueryCacheManager.FunctionFeatureBatch featureBatch =
				cacheManager.ensureFunctionFeatures(program, symbolicCandidates);
			Map<Function, QueryCacheManager.IndexedFunctionFeatures> indexedFeatures =
				new IdentityHashMap<>();
			for (Function candidate : symbolicCandidates) {
				QueryCacheManager.IndexedFunctionFeatures feature =
					featureBatch.get(candidate.getEntryPoint());
				if (feature != null) {
					indexedFeatures.put(candidate, feature);
				}
			}

			// Stage 2: lexical filtering
			Map<Function, Double> lexicalScores = new HashMap<>();
			List<Function> lexicalCandidates = new ArrayList<>();
			for (Function candidate : symbolicCandidates) {
				QueryCacheManager.IndexedFunctionFeatures feature = indexedFeatures.get(candidate);
				if (feature == null) {
					continue;
				}
				double lexicalScore = computeLexicalScore(feature, queryTerms);
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

			// Stage 3: index-backed primary ranking
			boolean embeddingBackendAvailable = EMBEDDING_STAGE_ENABLED && isEmbeddingBackendAvailable();
			QueryDecompileBudget queryBudget = decompileBudgetManager.startQuery();
			List<FunctionScore> scoredCandidates = new ArrayList<>();
			int embeddingWindow = Math.min(
				Math.max(maxResults, maxResults * EMBEDDING_STAGE_MULTIPLIER),
				lexicalCandidates.size());
			for (Function candidate : lexicalCandidates) {
				QueryCacheManager.IndexedFunctionFeatures feature = indexedFeatures.get(candidate);
				if (feature == null) {
					continue;
				}
				double lexicalScore = lexicalScores.getOrDefault(candidate, 0.0);
				double indexedScore = computeIndexedSemanticScore(feature, queryTerms, lexicalScore);
				scoredCandidates.add(new FunctionScore(candidate, indexedScore, false));
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
			int refineCandidateCount = scoredCandidates.size();
			boolean queryBudgetExhausted = false;
			boolean sessionBudgetExhausted = false;
			if (embeddingBackendAvailable) {
				List<FunctionScore> refinedCandidates = new ArrayList<>();
				for (FunctionScore candidateScore : scoredCandidates) {
					EmbeddingScoreResult embeddingResult = computeEmbeddingScoreWithBudget(
						program, candidateScore.function, queryTerms, monitor, queryBudget);
					if (embeddingResult.exhaustedScope == BudgetExhaustedScope.QUERY) {
						if (!queryBudgetExhausted) {
							telemetry.recordDecompileBudgetExhausted(operationId, "query");
						}
						queryBudgetExhausted = true;
					}
					else if (embeddingResult.exhaustedScope == BudgetExhaustedScope.SESSION) {
						if (!sessionBudgetExhausted) {
							telemetry.recordDecompileBudgetExhausted(operationId, "session");
						}
						sessionBudgetExhausted = true;
					}
					double finalScore = candidateScore.score;
					if (embeddingResult.usedEmbeddingScore) {
						finalScore = SEMANTIC_RANKING_POLICY.combine(candidateScore.score,
							embeddingResult.score);
						if (finalScore < EMBEDDING_MIN_SCORE) {
							continue;
						}
					}
					boolean dynamicSignalApplied = embeddingResult.usedEmbeddingScore &&
						SEMANTIC_RANKING_POLICY.getDynamicWeight() > 0.0d;
					refinedCandidates.add(new FunctionScore(candidateScore.function, finalScore,
						dynamicSignalApplied));
				}
				scoredCandidates = refinedCandidates;
			}
			logCandidateStageMetrics(operationId, normalizedQuery, "embedding",
				lexicalCandidates.size(), scoredCandidates.size(),
				Map.ofEntries(
					Map.entry("enabled", EMBEDDING_STAGE_ENABLED),
					Map.entry("backendAvailable", embeddingBackendAvailable),
					Map.entry("fallbackApplied", !embeddingBackendAvailable),
					Map.entry("primaryRanker", "indexed-features"),
					Map.entry("indexedFresh", featureBatch.getIndexedCount()),
					Map.entry("indexedReused", featureBatch.getReusedCount()),
					Map.entry("refineCandidateCount", refineCandidateCount),
					Map.entry("queryBudgetExhausted", queryBudgetExhausted),
					Map.entry("sessionBudgetExhausted", sessionBudgetExhausted),
					Map.entry("queryBudgetRemaining", queryBudget.remaining()),
					Map.entry("sessionBudgetRemaining", decompileBudgetManager.remainingSessionBudget()),
					Map.entry("minScore", EMBEDDING_MIN_SCORE),
					Map.entry("candidateMultiplier", EMBEDDING_STAGE_MULTIPLIER)
				));
			if (sessionBudgetExhausted || queryBudgetExhausted) {
				String reason = sessionBudgetExhausted ? "session" : "query";
				String message = String.format(
					"Decompile budget exhausted (%s): queryRemaining=%d, sessionRemaining=%d",
					reason, queryBudget.remaining(), decompileBudgetManager.remainingSessionBudget());
				budgetStatus = BudgetStatus.exhausted(message);
			}

			// Build result set
			List<QueryResult> results = new ArrayList<>();
			String semanticMode = embeddingBackendAvailable
					? "embedding_rerank"
					: "deterministic_index_fallback";
			for (FunctionScore scored : scoredCandidates) {
				results.add(new QueryResultImpl(
					scored.function.getEntryPoint(),
					scored.score,
					buildSemanticSummary(scored.function, query),
					buildEvidenceId("semantic", scored.function.getEntryPoint()),
					buildEvidenceRefs("semantic", scored.function.getEntryPoint()),
					buildProvenance("semantic", semanticMode, embeddingBackendAvailable,
						scored.dynamicSignalApplied, SEMANTIC_RANKING_POLICY,
						scored.function.getEntryPoint())
				));
			}

			// Sort by score descending
			results.sort((a, b) -> compareResultsDescending(a.getScore(), b.getScore(),
				a.getAddress(), b.getAddress()));

			// Trim to max results
			if (results.size() > maxResults) {
				results = new ArrayList<>(results.subList(0, maxResults));
			}

			// Cache results
			cacheManager.cacheSemanticSearch(program, cacheKey, results);
			recordTemporalQueryResults(program, "semantic", operationId, results);

			telemetry.recordOperationSuccess(operationId, System.nanoTime() - startTime);
			lastSemanticBudgetStatus.set(budgetStatus);
			return results;

		} catch (QueryException e) {
			lastSemanticBudgetStatus.set(budgetStatus);
			telemetry.recordOperationError(operationId, e);
			throw e;
		} catch (Exception e) {
			lastSemanticBudgetStatus.set(budgetStatus);
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
			recordTemporalPatternResults(program, operationId, results);

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
			recordTemporalContextEvent(program, operationId, context);

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
	public List<TemporalEvent> queryTemporalWindow(Program program, TemporalWindowRequest request)
			throws QueryException {
		long startTime = System.nanoTime();
		String operationId = telemetry.startOperation("queryTemporalWindow", program);
		try {
			validateProgramBinding(program);
			Objects.requireNonNull(request, "request");
			List<TemporalEvent> results = temporalEvidenceGraph.queryWindow(programId(program), request);
			telemetry.recordOperationSuccess(operationId, System.nanoTime() - startTime);
			return results;
		}
		catch (QueryException e) {
			telemetry.recordOperationError(operationId, e);
			throw e;
		}
		catch (Exception e) {
			telemetry.recordOperationError(operationId, e);
			throw new QueryException("Error in temporal window query: " + e.getMessage(), e);
		}
	}

	@Override
	public List<TemporalIntervalJoinResult> queryTemporalIntervalJoin(Program program,
			TemporalIntervalJoinRequest request) throws QueryException {
		long startTime = System.nanoTime();
		String operationId = telemetry.startOperation("queryTemporalIntervalJoin", program);
		try {
			validateProgramBinding(program);
			Objects.requireNonNull(request, "request");
			List<TemporalIntervalJoinResult> results =
				temporalEvidenceGraph.intervalJoin(programId(program), request);
			telemetry.recordOperationSuccess(operationId, System.nanoTime() - startTime);
			return results;
		}
		catch (QueryException e) {
			telemetry.recordOperationError(operationId, e);
			throw e;
		}
		catch (Exception e) {
			telemetry.recordOperationError(operationId, e);
			throw new QueryException("Error in temporal interval join query: " + e.getMessage(), e);
		}
	}

	@Override
	public List<TemporalEvent> queryTemporalLineage(Program program, String eventId, int maxDepth)
			throws QueryException {
		long startTime = System.nanoTime();
		String operationId = telemetry.startOperation("queryTemporalLineage", program);
		try {
			validateProgramBinding(program);
			if (eventId == null || eventId.isBlank()) {
				throw new QueryException("eventId cannot be blank");
			}
			List<TemporalEvent> results = temporalEvidenceGraph.lineage(programId(program), eventId, maxDepth);
			telemetry.recordOperationSuccess(operationId, System.nanoTime() - startTime);
			return results;
		}
		catch (QueryException e) {
			telemetry.recordOperationError(operationId, e);
			throw e;
		}
		catch (Exception e) {
			telemetry.recordOperationError(operationId, e);
			throw new QueryException("Error in temporal lineage query: " + e.getMessage(), e);
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

	private double computeFunctionSimilarity(QueryCacheManager.IndexedFunctionFeatures reference,
			QueryCacheManager.IndexedFunctionFeatures candidate) {
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
		long refSize = Math.max(1, reference.getBodySize());
		long candSize = Math.max(1, candidate.getBodySize());
		double sizeSimilarity = 1.0 - (Math.abs(refSize - candSize) / (double) Math.max(refSize, candSize));
		score += 0.3 * Math.max(0, sizeSimilarity);

		// Compare call counts
		int refCalls = reference.getCallCount();
		int candCalls = candidate.getCallCount();
		if (refCalls == candCalls) {
			score += 0.2;
		} else if (Math.abs(refCalls - candCalls) <= 2) {
			score += 0.1;
		}

		// Compare return type
		if (Objects.equals(reference.getNormalizedReturnType(), candidate.getNormalizedReturnType())) {
			score += 0.1;
		}

		// Compare calling convention
		if (Objects.equals(reference.getNormalizedCallingConvention(),
			candidate.getNormalizedCallingConvention())) {
			score += 0.1;
		}

		return Math.min(1.0, score);
	}

	private String buildFunctionSummary(QueryCacheManager.IndexedFunctionFeatures function,
			double similarity) {
		return String.format("%s (%.1f%% similar) - %d params, %d bytes",
			function.getFunctionName(),
			similarity * 100,
			function.getParameterCount(),
			function.getBodySize());
	}

	private String buildSemanticSummary(Function function, String query) {
		return String.format("Match in %s: function with %d parameters",
			function.getName(), function.getParameterCount());
	}

	private int compareResultsDescending(double leftScore, double rightScore,
			Address leftAddress, Address rightAddress) {
		int scoreCmp = Double.compare(rightScore, leftScore);
		if (scoreCmp != 0) {
			return scoreCmp;
		}
		String leftKey = leftAddress != null ? leftAddress.toString() : "";
		String rightKey = rightAddress != null ? rightAddress.toString() : "";
		return leftKey.compareTo(rightKey);
	}

	private String buildEvidenceId(String operation, Address address) {
		return "evidence:" + operation + ":" + normalizeAddressKey(address);
	}

	private List<String> buildEvidenceRefs(String operation, Address address) {
		String normalizedAddress = normalizeAddressKey(address);
		return List.of(
			"evidence_ref:" + operation + ":" + normalizedAddress,
			"evidence_ref:static:" + operation + ":" + normalizedAddress,
			"evidence_ref:dynamic:" + operation + ":" + normalizedAddress,
			"provenance_ref:static:" + operation + ":" + normalizedAddress,
			"provenance_ref:dynamic:" + operation + ":" + normalizedAddress
		);
	}

	private Map<String, String> buildProvenance(String operation, String mode,
			boolean embeddingBackendAvailable, boolean dynamicSignalApplied,
			RankingWeightPolicy rankingWeightPolicy, Address address) {
		Map<String, String> provenance = new LinkedHashMap<>();
		String normalizedAddress = normalizeAddressKey(address);
		provenance.put("operation", operation);
		provenance.put("ranking_mode", mode);
		provenance.put("embedding_backend_status",
			embeddingBackendAvailable ? "available" : "unavailable");
		provenance.put("embedding_fallback_applied", String.valueOf(!embeddingBackendAvailable));
		provenance.put("address", normalizedAddress);
		provenance.put("ranker", "indexed-features+embedding");
		provenance.put("weight_policy", rankingWeightPolicy.getPolicyName());
		provenance.put("static_weight", rankingWeightPolicy.getStaticWeightString());
		provenance.put("dynamic_weight", rankingWeightPolicy.getDynamicWeightString());
		provenance.put("dynamic_signal_applied", String.valueOf(dynamicSignalApplied));
		provenance.put("static_evidence_ref",
			"evidence_ref:static:" + operation + ":" + normalizedAddress);
		provenance.put("dynamic_evidence_ref",
			"evidence_ref:dynamic:" + operation + ":" + normalizedAddress);
		provenance.put("static_provenance_ref",
			"provenance_ref:static:" + operation + ":" + normalizedAddress);
		provenance.put("dynamic_provenance_ref",
			"provenance_ref:dynamic:" + operation + ":" + normalizedAddress);
		return Collections.unmodifiableMap(provenance);
	}

	private String normalizeAddressKey(Address address) {
		return address != null ? address.toString() : "none";
	}

	private void recordTemporalQueryResults(Program program, String operation, String operationId,
			List<QueryResult> results) {
		if (program == null || results == null || results.isEmpty()) {
			return;
		}
		Instant baseTime = Instant.now();
		String programId = programId(program);
		for (int index = 0; index < results.size(); index++) {
			QueryResult result = results.get(index);
			Instant eventTime = baseTime.plusMillis(index);
			String eventId = buildTemporalEventId(operationId, operation,
				result.getAddress(), index);
			List<String> predecessors = new ArrayList<>();
			String predecessor = previousTemporalEvent(programId, result.getAddress());
			if (predecessor != null) {
				predecessors.add(predecessor);
			}
			Map<String, String> metadata = new LinkedHashMap<>();
			metadata.put("operation", operation);
			metadata.put("score", String.format(Locale.ROOT, "%.6f", result.getScore()));
			metadata.put("summary", result.getSummary());
			result.getEvidenceId().ifPresent(evidenceId -> metadata.put("evidenceId", evidenceId));
			TemporalEvent temporalEvent = new TemporalEventImpl(
				eventId,
				programId,
				result.getAddress(),
				operation,
				eventTime,
				eventTime,
				predecessors,
				metadata);
			temporalEvidenceGraph.upsert(temporalEvent);
			rememberTemporalEvent(programId, result.getAddress(), eventId);
		}
	}

	private void recordTemporalPatternResults(Program program, String operationId, List<Address> addresses) {
		if (program == null || addresses == null || addresses.isEmpty()) {
			return;
		}
		Instant baseTime = Instant.now();
		String programId = programId(program);
		for (int index = 0; index < addresses.size(); index++) {
			Address address = addresses.get(index);
			Instant eventTime = baseTime.plusMillis(index);
			String eventId = buildTemporalEventId(operationId, "pattern", address, index);
			List<String> predecessors = new ArrayList<>();
			String predecessor = previousTemporalEvent(programId, address);
			if (predecessor != null) {
				predecessors.add(predecessor);
			}
			Map<String, String> metadata = new LinkedHashMap<>();
			metadata.put("operation", "pattern");
			metadata.put("address", normalizeAddressKey(address));
			TemporalEvent temporalEvent = new TemporalEventImpl(
				eventId, programId, address, "pattern", eventTime, eventTime, predecessors, metadata);
			temporalEvidenceGraph.upsert(temporalEvent);
			rememberTemporalEvent(programId, address, eventId);
		}
	}

	private void recordTemporalContextEvent(Program program, String operationId, QueryContext context) {
		if (program == null || context == null || context.getAddress() == null) {
			return;
		}
		String programId = programId(program);
		Address address = context.getAddress();
		String eventId = buildTemporalEventId(operationId, "context", address, 0);
		List<String> predecessors = new ArrayList<>();
		String predecessor = previousTemporalEvent(programId, address);
		if (predecessor != null) {
			predecessors.add(predecessor);
		}
		Map<String, String> metadata = new LinkedHashMap<>();
		metadata.put("operation", "context");
		metadata.put("referenceCount", String.valueOf(context.getReferences().size()));
		context.getFunction().ifPresent(function -> metadata.put("function", function.getName()));
		context.getDecompiledCode().ifPresent(code -> metadata.put("decompiled", String.valueOf(!code.isBlank())));
		Instant eventTime = Instant.now();
		TemporalEvent temporalEvent = new TemporalEventImpl(
			eventId, programId, address, "context", eventTime, eventTime, predecessors, metadata);
		temporalEvidenceGraph.upsert(temporalEvent);
		rememberTemporalEvent(programId, address, eventId);
	}

	private String buildTemporalEventId(String operationId, String operation, Address address, int ordinal) {
		return "temporal:" + operation + ":" + operationId + ":" + normalizeAddressKey(address) + ":" + ordinal;
	}

	private String previousTemporalEvent(String programId, Address address) {
		return lastTemporalEventByProgramAddress.get(programId + "|" + normalizeAddressKey(address));
	}

	private void rememberTemporalEvent(String programId, Address address, String eventId) {
		lastTemporalEventByProgramAddress.put(programId + "|" + normalizeAddressKey(address), eventId);
	}

	private String programId(Program program) {
		if (program == null) {
			return "";
		}
		String executablePath = program.getExecutablePath();
		if (executablePath != null && !executablePath.isBlank()) {
			return executablePath;
		}
		String programName = program.getName();
		if (programName != null && !programName.isBlank()) {
			return programName;
		}
		return "program-" + System.identityHashCode(program);
	}

	private double computeIndexedSemanticScore(QueryCacheManager.IndexedFunctionFeatures feature,
			String[] queryTerms, double lexicalScore) {
		if (feature == null || queryTerms.length == 0) {
			return lexicalScore;
		}
		int tokenMatches = 0;
		for (String term : queryTerms) {
			if (feature.getLexicalTokens().contains(term)) {
				tokenMatches++;
			}
		}
		double tokenCoverage = tokenMatches / (double) queryTerms.length;
		double callDensity = Math.min(1.0, feature.getCallCount() / 8.0);
		return Math.min(1.0, (0.7 * lexicalScore) + (0.2 * tokenCoverage) + (0.1 * callDensity));
	}

	private double computeLexicalScore(QueryCacheManager.IndexedFunctionFeatures function,
			String[] queryTerms) {
		if (queryTerms.length == 0) {
			return 0.0;
		}
		double score = 0.0;
		String functionName = function.getNormalizedFunctionName();
		String comment = function.getNormalizedComment();
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

	private EmbeddingScoreResult computeEmbeddingScoreWithBudget(Program program,
			Function function, String[] queryTerms, TaskMonitor monitor, QueryDecompileBudget queryBudget) {
		if (queryTerms.length == 0) {
			return EmbeddingScoreResult.scored(0.0);
		}
		BudgetAcquireOutcome budgetOutcome = decompileBudgetManager.tryAcquire(queryBudget);
		if (budgetOutcome == BudgetAcquireOutcome.QUERY_EXHAUSTED) {
			return EmbeddingScoreResult.exhausted(BudgetExhaustedScope.QUERY);
		}
		if (budgetOutcome == BudgetAcquireOutcome.SESSION_EXHAUSTED) {
			return EmbeddingScoreResult.exhausted(BudgetExhaustedScope.SESSION);
		}
		try {
			DecompileResults results = decompilerProvider.decompile(program, function, monitor);
			if (results == null || !results.decompileCompleted() || results.getDecompiledFunction() == null) {
				return EmbeddingScoreResult.scored(0.0);
			}
			String decompiledCode = results.getDecompiledFunction().getC().toLowerCase();
			int matches = 0;
			for (String term : queryTerms) {
				if (decompiledCode.contains(term)) {
					matches++;
				}
			}
			return EmbeddingScoreResult.scored(Math.min(1.0, matches / (double) queryTerms.length));
		}
		catch (Exception e) {
			return EmbeddingScoreResult.scored(0.0);
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
		private final boolean dynamicSignalApplied;

		FunctionScore(Function function, double score, boolean dynamicSignalApplied) {
			this.function = function;
			this.score = score;
			this.dynamicSignalApplied = dynamicSignalApplied;
		}
	}

	private static class RankingWeightPolicy {
		private final String policyName;
		private final double staticWeight;
		private final double dynamicWeight;

		private RankingWeightPolicy(String policyName, double staticWeight, double dynamicWeight) {
			this.policyName = policyName;
			this.staticWeight = staticWeight;
			this.dynamicWeight = dynamicWeight;
		}

		static RankingWeightPolicy fromConfig(String staticWeightSuffix, double staticWeightDefault,
				String dynamicWeightSuffix, double dynamicWeightDefault) {
			double staticWeight = Math.max(0.0d, getDoubleConfig(staticWeightSuffix, staticWeightDefault));
			double dynamicWeight = Math.max(0.0d, getDoubleConfig(dynamicWeightSuffix, dynamicWeightDefault));
			double total = staticWeight + dynamicWeight;
			if (total <= 0.0d) {
				return new RankingWeightPolicy("static=1.0000,dynamic=0.0000", 1.0d, 0.0d);
			}
			double normalizedStatic = staticWeight / total;
			double normalizedDynamic = dynamicWeight / total;
			String policyName = String.format(Locale.ROOT, "static=%.4f,dynamic=%.4f",
				normalizedStatic, normalizedDynamic);
			return new RankingWeightPolicy(policyName, normalizedStatic, normalizedDynamic);
		}

		double combine(double staticSignalScore, double dynamicSignalScore) {
			double combined = (staticWeight * staticSignalScore) + (dynamicWeight * dynamicSignalScore);
			return Math.max(0.0d, Math.min(1.0d, combined));
		}

		String getPolicyName() {
			return policyName;
		}

		double getDynamicWeight() {
			return dynamicWeight;
		}

		String getStaticWeightString() {
			return String.format(Locale.ROOT, "%.4f", staticWeight);
		}

		String getDynamicWeightString() {
			return String.format(Locale.ROOT, "%.4f", dynamicWeight);
		}
	}

	/**
	 * Status describing whether a semantic search exhausted decompilation budget.
	 */
	public static final class BudgetStatus {
		private final boolean budgetExhausted;
		private final String message;

		private BudgetStatus(boolean budgetExhausted, String message) {
			this.budgetExhausted = budgetExhausted;
			this.message = message != null ? message : "";
		}

		public static BudgetStatus none() {
			return new BudgetStatus(false, "");
		}

		public static BudgetStatus exhausted(String message) {
			return new BudgetStatus(true, message);
		}

		public boolean isBudgetExhausted() {
			return budgetExhausted;
		}

		public String getMessage() {
			return message;
		}
	}

	private enum BudgetAcquireOutcome {
		ACQUIRED,
		QUERY_EXHAUSTED,
		SESSION_EXHAUSTED
	}

	private enum BudgetExhaustedScope {
		NONE,
		QUERY,
		SESSION
	}

	private static class EmbeddingScoreResult {
		private final boolean usedEmbeddingScore;
		private final double score;
		private final BudgetExhaustedScope exhaustedScope;

		private EmbeddingScoreResult(boolean usedEmbeddingScore, double score,
				BudgetExhaustedScope exhaustedScope) {
			this.usedEmbeddingScore = usedEmbeddingScore;
			this.score = score;
			this.exhaustedScope = exhaustedScope;
		}

		static EmbeddingScoreResult scored(double score) {
			return new EmbeddingScoreResult(true, score, BudgetExhaustedScope.NONE);
		}

		static EmbeddingScoreResult exhausted(BudgetExhaustedScope exhaustedScope) {
			return new EmbeddingScoreResult(false, 0.0, exhaustedScope);
		}
	}

	private static class QueryDecompileBudget {
		private final AtomicInteger remaining;

		QueryDecompileBudget(int budgetPerQuery) {
			this.remaining = new AtomicInteger(Math.max(0, budgetPerQuery));
		}

		int remaining() {
			return Math.max(0, remaining.get());
		}
	}

	private static class DecompileBudgetManager {
		private final int queryBudgetPerSearch;
		private final AtomicInteger sessionBudgetRemaining;

		DecompileBudgetManager(int queryBudgetPerSearch, int sessionBudgetPerService) {
			this.queryBudgetPerSearch = Math.max(0, queryBudgetPerSearch);
			this.sessionBudgetRemaining = new AtomicInteger(Math.max(0, sessionBudgetPerService));
		}

		QueryDecompileBudget startQuery() {
			return new QueryDecompileBudget(queryBudgetPerSearch);
		}

		int remainingSessionBudget() {
			return Math.max(0, sessionBudgetRemaining.get());
		}

		BudgetAcquireOutcome tryAcquire(QueryDecompileBudget queryBudget) {
			if (!decrementIfPositive(queryBudget.remaining)) {
				return BudgetAcquireOutcome.QUERY_EXHAUSTED;
			}
			if (!decrementIfPositive(sessionBudgetRemaining)) {
				return BudgetAcquireOutcome.SESSION_EXHAUSTED;
			}
			return BudgetAcquireOutcome.ACQUIRED;
		}

		private static boolean decrementIfPositive(AtomicInteger counter) {
			int before = counter.get();
			while (before > 0) {
				if (counter.compareAndSet(before, before - 1)) {
					return true;
				}
				before = counter.get();
			}
			return false;
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

	private static class TemporalEventImpl implements TemporalEvent {
		private final String eventId;
		private final String programId;
		private final Address address;
		private final String operation;
		private final Instant startTime;
		private final Instant endTime;
		private final List<String> predecessorEventIds;
		private final Map<String, String> metadata;

		TemporalEventImpl(String eventId, String programId, Address address, String operation,
				Instant startTime, Instant endTime, List<String> predecessorEventIds,
				Map<String, String> metadata) {
			this.eventId = eventId;
			this.programId = programId != null ? programId : "";
			this.address = address;
			this.operation = operation != null ? operation : "";
			this.startTime = startTime;
			this.endTime = endTime != null ? endTime : startTime;
			this.predecessorEventIds = predecessorEventIds != null
					? Collections.unmodifiableList(new ArrayList<>(predecessorEventIds))
					: Collections.emptyList();
			this.metadata = metadata != null
					? Collections.unmodifiableMap(new LinkedHashMap<>(metadata))
					: Collections.emptyMap();
		}

		@Override
		public String getEventId() {
			return eventId;
		}

		@Override
		public String getProgramId() {
			return programId;
		}

		@Override
		public Optional<Address> getAddress() {
			return Optional.ofNullable(address);
		}

		@Override
		public String getOperation() {
			return operation;
		}

		@Override
		public Instant getStartTime() {
			return startTime;
		}

		@Override
		public Instant getEndTime() {
			return endTime;
		}

		@Override
		public List<String> getPredecessorEventIds() {
			return predecessorEventIds;
		}

		@Override
		public Map<String, String> getMetadata() {
			return metadata;
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
		private final List<String> evidenceRefs;
		private final Map<String, String> provenance;

		QueryResultImpl(Address address, double score, String summary, String evidenceId,
				List<String> evidenceRefs, Map<String, String> provenance) {
			this.address = address;
			this.score = score;
			this.summary = summary;
			this.evidenceId = evidenceId;
			this.evidenceRefs = evidenceRefs != null
					? Collections.unmodifiableList(new ArrayList<>(evidenceRefs))
					: Collections.emptyList();
			this.provenance = provenance != null
					? Collections.unmodifiableMap(new LinkedHashMap<>(provenance))
					: Collections.emptyMap();
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

		@Override
		public List<String> getEvidenceRefs() {
			return evidenceRefs;
		}

		@Override
		public Map<String, String> getProvenance() {
			return provenance;
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
