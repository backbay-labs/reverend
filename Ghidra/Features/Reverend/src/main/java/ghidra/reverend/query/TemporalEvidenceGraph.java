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

import ghidra.reverend.api.v1.QueryService;

/**
 * In-memory temporal index over unified evidence graph events.
 */
class TemporalEvidenceGraph {

	private final Map<String, QueryService.TemporalEvent> eventsById = new LinkedHashMap<>();
	private final Map<String, List<QueryService.TemporalEvent>> eventsByProgram = new HashMap<>();

	synchronized void upsert(QueryService.TemporalEvent event) {
		if (event == null || event.getEventId() == null || event.getEventId().isBlank()) {
			return;
		}
		QueryService.TemporalEvent previous = eventsById.put(event.getEventId(), event);
		if (previous != null) {
			removeFromProgramIndex(previous);
		}
		eventsByProgram.computeIfAbsent(safeProgramId(event.getProgramId()), key -> new ArrayList<>())
			.add(event);
	}

	synchronized void clearProgram(String programId) {
		String key = safeProgramId(programId);
		List<QueryService.TemporalEvent> removed = eventsByProgram.remove(key);
		if (removed == null) {
			return;
		}
		for (QueryService.TemporalEvent event : removed) {
			eventsById.remove(event.getEventId());
		}
	}

	synchronized List<QueryService.TemporalEvent> queryWindow(String programId,
			QueryService.TemporalWindowRequest request) {
		if (request == null || request.getAnchor() == null) {
			return List.of();
		}
		List<QueryService.TemporalEvent> candidates = snapshotProgramEvents(programId);
		if (candidates.isEmpty()) {
			return List.of();
		}
		Instant lowerBound = request.getAnchor().minusMillis(request.getWindowMillis());
		Instant upperBound = request.getAnchor().plusMillis(request.getWindowMillis());
		List<QueryService.TemporalEvent> matches = new ArrayList<>();
		for (QueryService.TemporalEvent event : candidates) {
			Instant start = event.getStartTime();
			if (start == null) {
				continue;
			}
			if (request.getDirection() == QueryService.TemporalDirection.BEFORE) {
				if (!start.isAfter(request.getAnchor()) && !start.isBefore(lowerBound)) {
					matches.add(event);
				}
			}
			else {
				if (!start.isBefore(request.getAnchor()) && !start.isAfter(upperBound)) {
					matches.add(event);
				}
			}
		}
		Comparator<QueryService.TemporalEvent> comparator =
			Comparator.comparing(QueryService.TemporalEvent::getStartTime)
				.thenComparing(QueryService.TemporalEvent::getEventId);
		if (request.getDirection() == QueryService.TemporalDirection.BEFORE) {
			comparator = comparator.reversed();
		}
		matches.sort(comparator);
		if (request.getMaxResults() > 0 && matches.size() > request.getMaxResults()) {
			return List.copyOf(matches.subList(0, request.getMaxResults()));
		}
		return List.copyOf(matches);
	}

	synchronized List<QueryService.TemporalIntervalJoinResult> intervalJoin(String programId,
			QueryService.TemporalIntervalJoinRequest request) {
		if (request == null || request.getIntervalStart() == null || request.getIntervalEnd() == null) {
			return List.of();
		}
		List<QueryService.TemporalEvent> candidates = snapshotProgramEvents(programId);
		if (candidates.size() < 2) {
			return List.of();
		}
		List<QueryService.TemporalEvent> bounded = new ArrayList<>();
		for (QueryService.TemporalEvent event : candidates) {
			Instant start = event.getStartTime();
			if (start == null) {
				continue;
			}
			if (!start.isBefore(request.getIntervalStart()) && !start.isAfter(request.getIntervalEnd())) {
				bounded.add(event);
			}
		}
		bounded.sort(Comparator
			.comparing(QueryService.TemporalEvent::getStartTime)
			.thenComparing(QueryService.TemporalEvent::getEventId));
		List<QueryService.TemporalIntervalJoinResult> joined = new ArrayList<>();
		for (int i = 0; i < bounded.size(); i++) {
			QueryService.TemporalEvent left = bounded.get(i);
			for (int j = i + 1; j < bounded.size(); j++) {
				QueryService.TemporalEvent right = bounded.get(j);
				long gapMillis = Math.abs(right.getStartTime().toEpochMilli() - left.getStartTime().toEpochMilli());
				if (gapMillis > request.getMaxGapMillis()) {
					break;
				}
				long overlap = computeOverlapMillis(left, right);
				joined.add(new TemporalIntervalJoinResultImpl(left, right, gapMillis, overlap));
			}
		}
		joined.sort(Comparator
			.comparingLong(QueryService.TemporalIntervalJoinResult::getStartGapMillis)
			.thenComparing(result -> result.getLeft().getStartTime())
			.thenComparing(result -> result.getLeft().getEventId())
			.thenComparing(result -> result.getRight().getEventId()));
		if (request.getMaxResults() > 0 && joined.size() > request.getMaxResults()) {
			return List.copyOf(joined.subList(0, request.getMaxResults()));
		}
		return List.copyOf(joined);
	}

	synchronized List<QueryService.TemporalEvent> lineage(String programId, String eventId, int maxDepth) {
		if (eventId == null || eventId.isBlank()) {
			return List.of();
		}
		QueryService.TemporalEvent root = eventsById.get(eventId);
		if (root == null || !safeProgramId(programId).equals(safeProgramId(root.getProgramId()))) {
			return List.of();
		}
		int depthLimit = Math.max(0, maxDepth);
		List<LineageVisit> visits = new ArrayList<>();
		Set<String> visited = new HashSet<>();
		Deque<LineageVisit> queue = new ArrayDeque<>();
		queue.addLast(new LineageVisit(root, 0));
		visited.add(root.getEventId());

		while (!queue.isEmpty()) {
			LineageVisit visit = queue.removeFirst();
			visits.add(visit);
			if (visit.depth >= depthLimit) {
				continue;
			}
			List<String> predecessors = new ArrayList<>(visit.event.getPredecessorEventIds());
			predecessors.sort(String::compareTo);
			for (String predecessorId : predecessors) {
				QueryService.TemporalEvent predecessor = eventsById.get(predecessorId);
				if (predecessor == null) {
					continue;
				}
				if (!safeProgramId(programId).equals(safeProgramId(predecessor.getProgramId()))) {
					continue;
				}
				if (visited.add(predecessorId)) {
					queue.addLast(new LineageVisit(predecessor, visit.depth + 1));
				}
			}
		}

		visits.sort(Comparator
			.comparingInt((LineageVisit visit) -> visit.depth)
			.thenComparing(visit -> visit.event.getStartTime())
			.thenComparing(visit -> visit.event.getEventId()));
		List<QueryService.TemporalEvent> lineage = new ArrayList<>(visits.size());
		for (LineageVisit visit : visits) {
			lineage.add(visit.event);
		}
		return List.copyOf(lineage);
	}

	private void removeFromProgramIndex(QueryService.TemporalEvent event) {
		List<QueryService.TemporalEvent> existing = eventsByProgram.get(safeProgramId(event.getProgramId()));
		if (existing != null) {
			existing.removeIf(candidate -> event.getEventId().equals(candidate.getEventId()));
			if (existing.isEmpty()) {
				eventsByProgram.remove(safeProgramId(event.getProgramId()));
			}
		}
	}

	private List<QueryService.TemporalEvent> snapshotProgramEvents(String programId) {
		List<QueryService.TemporalEvent> events = eventsByProgram.get(safeProgramId(programId));
		return events != null ? new ArrayList<>(events) : List.of();
	}

	private String safeProgramId(String programId) {
		return programId != null ? programId : "";
	}

	private static long computeOverlapMillis(QueryService.TemporalEvent left, QueryService.TemporalEvent right) {
		Instant leftStart = left.getStartTime();
		Instant leftEnd = left.getEndTime() != null ? left.getEndTime() : leftStart;
		Instant rightStart = right.getStartTime();
		Instant rightEnd = right.getEndTime() != null ? right.getEndTime() : rightStart;
		if (leftStart == null || leftEnd == null || rightStart == null || rightEnd == null) {
			return 0L;
		}
		long overlapStart = Math.max(leftStart.toEpochMilli(), rightStart.toEpochMilli());
		long overlapEnd = Math.min(leftEnd.toEpochMilli(), rightEnd.toEpochMilli());
		return Math.max(0L, overlapEnd - overlapStart);
	}

	private static final class TemporalIntervalJoinResultImpl implements QueryService.TemporalIntervalJoinResult {
		private final QueryService.TemporalEvent left;
		private final QueryService.TemporalEvent right;
		private final long startGapMillis;
		private final long overlapMillis;

		TemporalIntervalJoinResultImpl(QueryService.TemporalEvent left,
				QueryService.TemporalEvent right, long startGapMillis, long overlapMillis) {
			this.left = left;
			this.right = right;
			this.startGapMillis = startGapMillis;
			this.overlapMillis = overlapMillis;
		}

		@Override
		public QueryService.TemporalEvent getLeft() {
			return left;
		}

		@Override
		public QueryService.TemporalEvent getRight() {
			return right;
		}

		@Override
		public long getStartGapMillis() {
			return startGapMillis;
		}

		@Override
		public long getOverlapMillis() {
			return overlapMillis;
		}
	}

	private static final class LineageVisit {
		private final QueryService.TemporalEvent event;
		private final int depth;

		LineageVisit(QueryService.TemporalEvent event, int depth) {
			this.event = event;
			this.depth = depth;
		}
	}
}
