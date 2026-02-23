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
package ghidra.reverend.api.v1;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * Service for semantic search and query operations against the program model
 * and decompiler state.
 *
 * <p>The QueryService provides a unified interface for:
 * <ul>
 *   <li>Semantic similarity search across functions and code blocks</li>
 *   <li>Natural language queries against decompiled code</li>
 *   <li>Pattern-based code search with structural constraints</li>
 *   <li>Cross-reference and data flow queries</li>
 * </ul>
 *
 * <p>All query operations respect the current policy mode and may be rate-limited
 * or restricted based on egress controls.
 *
 * @since 1.0
 * @see PolicyService
 */
public interface QueryService {

	/**
	 * Returns the API version of this service implementation.
	 *
	 * @return the service version
	 */
	default ServiceVersion getVersion() {
		return ServiceVersion.CURRENT;
	}

	/**
	 * Performs a semantic similarity search for functions similar to the given function.
	 *
	 * @param program the program to search within
	 * @param function the reference function to find similar functions for
	 * @param maxResults the maximum number of results to return
	 * @param monitor task monitor for cancellation and progress
	 * @return list of query results ranked by similarity score
	 * @throws QueryException if the query fails
	 */
	List<QueryResult> findSimilarFunctions(Program program, Function function,
			int maxResults, TaskMonitor monitor) throws QueryException;

	/**
	 * Performs a semantic search using a natural language query.
	 *
	 * @param program the program to search within
	 * @param query the natural language query string
	 * @param scope optional address set to limit the search scope (null for entire program)
	 * @param maxResults the maximum number of results to return
	 * @param monitor task monitor for cancellation and progress
	 * @return list of query results ranked by relevance
	 * @throws QueryException if the query fails
	 */
	List<QueryResult> semanticSearch(Program program, String query,
			AddressSetView scope, int maxResults, TaskMonitor monitor) throws QueryException;

	/**
	 * Searches for code patterns matching the given structural pattern.
	 *
	 * @param program the program to search within
	 * @param pattern the structural pattern to match (implementation-defined format)
	 * @param scope optional address set to limit the search scope (null for entire program)
	 * @param monitor task monitor for cancellation and progress
	 * @return list of matching addresses
	 * @throws QueryException if the query fails
	 */
	List<Address> patternSearch(Program program, String pattern,
			AddressSetView scope, TaskMonitor monitor) throws QueryException;

	/**
	 * Retrieves detailed information about a specific address with context.
	 *
	 * @param program the program containing the address
	 * @param address the address to query
	 * @return query context containing decompiler output, references, and metadata
	 * @throws QueryException if the query fails
	 */
	Optional<QueryContext> getContext(Program program, Address address) throws QueryException;

	/**
	 * Queries temporal evidence events in a bounded window before or after an anchor.
	 *
	 * @param program the program to query within
	 * @param request temporal window request
	 * @return deterministic list of temporal events
	 * @throws QueryException if the query fails
	 */
	List<TemporalEvent> queryTemporalWindow(Program program, TemporalWindowRequest request)
			throws QueryException;

	/**
	 * Computes interval joins between temporal evidence events inside the requested bounds.
	 *
	 * @param program the program to query within
	 * @param request temporal interval join request
	 * @return deterministic list of interval join matches
	 * @throws QueryException if the query fails
	 */
	List<TemporalIntervalJoinResult> queryTemporalIntervalJoin(Program program,
			TemporalIntervalJoinRequest request) throws QueryException;

	/**
	 * Returns temporal lineage for an event ID.
	 *
	 * @param program the program to query within
	 * @param eventId root event ID
	 * @param maxDepth maximum predecessor traversal depth
	 * @return deterministic lineage ordered by depth then time
	 * @throws QueryException if the query fails
	 */
	List<TemporalEvent> queryTemporalLineage(Program program, String eventId, int maxDepth)
			throws QueryException;

	/**
	 * Represents a single query result with scoring and evidence.
	 */
	interface QueryResult {

		/**
		 * Returns the address of the match.
		 * @return the match address
		 */
		Address getAddress();

		/**
		 * Returns the relevance/similarity score (0.0 to 1.0).
		 * @return the score
		 */
		double getScore();

		/**
		 * Returns a human-readable summary of the match.
		 * @return the summary text
		 */
		String getSummary();

		/**
		 * Returns the evidence ID linking this result to provenance data.
		 * @return optional evidence ID
		 */
		Optional<String> getEvidenceId();

		/**
		 * Returns stable evidence references associated with this result.
		 *
		 * <p>Implementations should return deterministic references so result payloads
		 * remain stable across repeated queries.
		 *
		 * @return immutable evidence reference list
		 */
		default List<String> getEvidenceRefs() {
			return getEvidenceId().map(List::of).orElseGet(List::of);
		}

		/**
		 * Returns provenance metadata for this result.
		 *
		 * <p>The map keys are implementation-defined but should be stable for
		 * deterministic replay and cockpit rendering.
		 *
		 * @return immutable provenance metadata map
		 */
		default Map<String, String> getProvenance() {
			return Map.of();
		}
	}

	/**
	 * Represents detailed context information for an address.
	 */
	interface QueryContext {

		/**
		 * Returns the address this context describes.
		 * @return the address
		 */
		Address getAddress();

		/**
		 * Returns the containing function, if any.
		 * @return optional containing function
		 */
		Optional<Function> getFunction();

		/**
		 * Returns the decompiled code snippet.
		 * @return optional decompiled code
		 */
		Optional<String> getDecompiledCode();

		/**
		 * Returns cross-references to this address.
		 * @return list of referencing addresses
		 */
		List<Address> getReferences();
	}

	/**
	 * Window direction for temporal event queries.
	 */
	enum TemporalDirection {
		BEFORE,
		AFTER
	}

	/**
	 * Request for bounded-window temporal queries.
	 */
	final class TemporalWindowRequest {
		private final Instant anchor;
		private final long windowMillis;
		private final TemporalDirection direction;
		private final int maxResults;

		public TemporalWindowRequest(Instant anchor, long windowMillis,
				TemporalDirection direction, int maxResults) {
			this.anchor = anchor;
			this.windowMillis = Math.max(0L, windowMillis);
			this.direction = direction != null ? direction : TemporalDirection.BEFORE;
			this.maxResults = Math.max(0, maxResults);
		}

		public Instant getAnchor() {
			return anchor;
		}

		public long getWindowMillis() {
			return windowMillis;
		}

		public TemporalDirection getDirection() {
			return direction;
		}

		public int getMaxResults() {
			return maxResults;
		}
	}

	/**
	 * Request for bounded temporal interval joins.
	 */
	final class TemporalIntervalJoinRequest {
		private final Instant intervalStart;
		private final Instant intervalEnd;
		private final long maxGapMillis;
		private final int maxResults;

		public TemporalIntervalJoinRequest(Instant intervalStart, Instant intervalEnd,
				long maxGapMillis, int maxResults) {
			this.intervalStart = intervalStart;
			this.intervalEnd = intervalEnd;
			this.maxGapMillis = Math.max(0L, maxGapMillis);
			this.maxResults = Math.max(0, maxResults);
		}

		public Instant getIntervalStart() {
			return intervalStart;
		}

		public Instant getIntervalEnd() {
			return intervalEnd;
		}

		public long getMaxGapMillis() {
			return maxGapMillis;
		}

		public int getMaxResults() {
			return maxResults;
		}
	}

	/**
	 * Temporal event emitted from the unified evidence graph.
	 */
	interface TemporalEvent {
		String getEventId();

		String getProgramId();

		Optional<Address> getAddress();

		String getOperation();

		Instant getStartTime();

		Instant getEndTime();

		List<String> getPredecessorEventIds();

		Map<String, String> getMetadata();
	}

	/**
	 * Interval join result between two temporal events.
	 */
	interface TemporalIntervalJoinResult {
		TemporalEvent getLeft();

		TemporalEvent getRight();

		long getStartGapMillis();

		long getOverlapMillis();
	}

	/**
	 * Exception thrown when a query operation fails.
	 */
	class QueryException extends Exception {
		public QueryException(String message) {
			super(message);
		}

		public QueryException(String message, Throwable cause) {
			super(message, cause);
		}
	}
}
