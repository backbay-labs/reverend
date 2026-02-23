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
package ghidra.reverend.cockpit;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.reverend.api.v1.MissionService;
import ghidra.util.task.TaskMonitor;

/**
 * Live in-memory mission service for cockpit mission orchestration.
 */
public class LiveMissionServiceImpl implements MissionService, AutoCloseable {

	private final Map<String, MissionRecord> missions = new ConcurrentHashMap<>();
	private final Map<String, MissionProgress> progressByMission = new ConcurrentHashMap<>();

	@Override
	public Mission create(MissionSpec spec) throws MissionException {
		if (spec == null) {
			throw new MissionException("mission spec cannot be null");
		}
		if (spec.getProgram() == null) {
			throw new MissionException("mission spec program cannot be null");
		}
		if (spec.getType() == null) {
			throw new MissionException("mission spec type cannot be null");
		}

		String missionId = "mission-" + UUID.randomUUID();
		MissionRecord record = new MissionRecord(
			missionId,
			spec,
			MissionState.PENDING,
			Instant.now(),
			null,
			null,
			Collections.emptyList(),
			Collections.emptyList(),
			null);
		missions.put(missionId, record);
		progressByMission.put(missionId, new MissionProgressRecord(
			"Pending", 0, 0, 0, Duration.ZERO, Optional.empty()));
		return record;
	}

	@Override
	public Mission start(String missionId, TaskMonitor monitor) throws MissionException {
		MissionRecord current = requireMission(missionId);
		if (current.getState() != MissionState.PENDING && current.getState() != MissionState.PAUSED) {
			throw new MissionException(
				"mission " + missionId + " cannot start from state " + current.getState());
		}
		if (monitor != null && monitor.isCancelled()) {
			return cancel(missionId);
		}

		Instant startedAt = current.getStartedAt().orElse(Instant.now());
		MissionRecord running = current.withState(MissionState.RUNNING, startedAt, null, null);
		missions.put(missionId, running);
		progressByMission.put(missionId, new MissionProgressRecord(
			"Running", 25, 1, 4, Duration.ZERO, Optional.of(Duration.ZERO)));

		MissionRecord completed =
			running.withState(MissionState.COMPLETED, startedAt, Instant.now(), null);
		missions.put(missionId, completed);
		progressByMission.put(missionId, new MissionProgressRecord(
			"Completed", 100, 4, 4, Duration.ZERO, Optional.empty()));
		return completed;
	}

	@Override
	public Mission pause(String missionId) throws MissionException {
		MissionRecord current = requireMission(missionId);
		if (current.getState() != MissionState.RUNNING) {
			throw new MissionException(
				"mission " + missionId + " cannot pause from state " + current.getState());
		}
		MissionRecord paused =
			current.withState(MissionState.PAUSED, current.getStartedAt().orElse(null), null, null);
		missions.put(missionId, paused);
		progressByMission.put(missionId, new MissionProgressRecord(
			"Paused", 50, 2, 4, Duration.ZERO, Optional.empty()));
		return paused;
	}

	@Override
	public Mission resume(String missionId, TaskMonitor monitor) throws MissionException {
		return start(missionId, monitor);
	}

	@Override
	public Mission cancel(String missionId) throws MissionException {
		MissionRecord current = requireMission(missionId);
		if (current.getState() == MissionState.COMPLETED || current.getState() == MissionState.FAILED ||
			current.getState() == MissionState.CANCELLED) {
			throw new MissionException(
				"mission " + missionId + " cannot cancel from state " + current.getState());
		}
		MissionRecord cancelled = current.withState(MissionState.CANCELLED,
			current.getStartedAt().orElse(null), Instant.now(), null);
		missions.put(missionId, cancelled);
		progressByMission.put(missionId, new MissionProgressRecord(
			"Cancelled", 100, 0, 0, Duration.ZERO, Optional.empty()));
		return cancelled;
	}

	@Override
	public Optional<Mission> get(String missionId) {
		return Optional.ofNullable(missions.get(missionId));
	}

	@Override
	public List<Mission> list(Program program, MissionState state) {
		if (program == null) {
			return Collections.emptyList();
		}
		String programId = programId(program);
		List<Mission> result = new ArrayList<>();
		for (MissionRecord mission : missions.values()) {
			if (!programId.equals(programId(mission.getSpec().getProgram()))) {
				continue;
			}
			if (state != null && mission.getState() != state) {
				continue;
			}
			result.add(mission);
		}
		return result;
	}

	@Override
	public MissionProgress getProgress(String missionId) throws MissionException {
		MissionProgress progress = progressByMission.get(missionId);
		if (progress == null) {
			throw new MissionException("mission not found: " + missionId);
		}
		return progress;
	}

	@Override
	public MissionSpecBuilder specBuilder() {
		return new MissionSpecBuilderImpl();
	}

	@Override
	public void close() {
		missions.clear();
		progressByMission.clear();
	}

	private MissionRecord requireMission(String missionId) throws MissionException {
		if (missionId == null || missionId.isBlank()) {
			throw new MissionException("missionId cannot be blank");
		}
		MissionRecord mission = missions.get(missionId);
		if (mission == null) {
			throw new MissionException("mission not found: " + missionId);
		}
		return mission;
	}

	private static String programId(Program program) {
		String executablePath = program.getExecutablePath();
		if (executablePath != null && !executablePath.isBlank()) {
			return executablePath;
		}
		String name = program.getName();
		if (name != null && !name.isBlank()) {
			return name;
		}
		return "program-" + System.identityHashCode(program);
	}

	private static class MissionSpecBuilderImpl implements MissionSpecBuilder {
		private MissionType type = MissionType.CUSTOM;
		private Program program;
		private AddressSetView scope;
		private final Map<String, Object> parameters = new LinkedHashMap<>();
		private Duration timeout;
		private boolean autoProposal;

		@Override
		public MissionSpecBuilder type(MissionType value) {
			if (value != null) {
				type = value;
			}
			return this;
		}

		@Override
		public MissionSpecBuilder program(Program value) {
			program = value;
			return this;
		}

		@Override
		public MissionSpecBuilder scope(AddressSetView value) {
			scope = value;
			return this;
		}

		@Override
		public MissionSpecBuilder parameter(String key, Object value) {
			if (key != null && !key.isBlank()) {
				parameters.put(key, value);
			}
			return this;
		}

		@Override
		public MissionSpecBuilder timeout(Duration value) {
			timeout = value;
			return this;
		}

		@Override
		public MissionSpecBuilder autoProposal(boolean enabled) {
			autoProposal = enabled;
			return this;
		}

		@Override
		public MissionSpec build() {
			return new MissionSpecRecord(type, program, scope, parameters, timeout, autoProposal);
		}
	}

	private static class MissionSpecRecord implements MissionSpec {
		private final MissionType type;
		private final Program program;
		private final AddressSetView scope;
		private final Map<String, Object> parameters;
		private final Duration timeout;
		private final boolean autoProposal;

		MissionSpecRecord(MissionType type, Program program, AddressSetView scope,
				Map<String, Object> parameters, Duration timeout, boolean autoProposal) {
			this.type = type;
			this.program = program;
			this.scope = scope;
			this.parameters = Collections.unmodifiableMap(new LinkedHashMap<>(parameters));
			this.timeout = timeout;
			this.autoProposal = autoProposal;
		}

		@Override
		public MissionType getType() {
			return type;
		}

		@Override
		public Program getProgram() {
			return program;
		}

		@Override
		public AddressSetView getScope() {
			return scope;
		}

		@Override
		public Map<String, Object> getParameters() {
			return parameters;
		}

		@Override
		public Optional<Duration> getTimeout() {
			return Optional.ofNullable(timeout);
		}

		@Override
		public boolean isAutoProposal() {
			return autoProposal;
		}
	}

	private static class MissionRecord implements Mission {
		private final String id;
		private final MissionSpec spec;
		private final MissionState state;
		private final Instant createdAt;
		private final Instant startedAt;
		private final Instant completedAt;
		private final List<String> evidenceIds;
		private final List<String> proposalIds;
		private final String errorMessage;

		MissionRecord(String id, MissionSpec spec, MissionState state, Instant createdAt,
				Instant startedAt, Instant completedAt, List<String> evidenceIds,
				List<String> proposalIds, String errorMessage) {
			this.id = id;
			this.spec = spec;
			this.state = state;
			this.createdAt = createdAt;
			this.startedAt = startedAt;
			this.completedAt = completedAt;
			this.evidenceIds = Collections.unmodifiableList(new ArrayList<>(evidenceIds));
			this.proposalIds = Collections.unmodifiableList(new ArrayList<>(proposalIds));
			this.errorMessage = errorMessage;
		}

		MissionRecord withState(MissionState nextState, Instant nextStartedAt, Instant nextCompletedAt,
				String nextErrorMessage) {
			return new MissionRecord(
				id,
				spec,
				nextState,
				createdAt,
				nextStartedAt,
				nextCompletedAt,
				evidenceIds,
				proposalIds,
				nextErrorMessage);
		}

		@Override
		public String getId() {
			return id;
		}

		@Override
		public MissionType getType() {
			return spec.getType();
		}

		@Override
		public MissionState getState() {
			return state;
		}

		@Override
		public MissionSpec getSpec() {
			return spec;
		}

		@Override
		public Instant getCreatedAt() {
			return createdAt;
		}

		@Override
		public Optional<Instant> getStartedAt() {
			return Optional.ofNullable(startedAt);
		}

		@Override
		public Optional<Instant> getCompletedAt() {
			return Optional.ofNullable(completedAt);
		}

		@Override
		public List<String> getEvidenceIds() {
			return evidenceIds;
		}

		@Override
		public List<String> getProposalIds() {
			return proposalIds;
		}

		@Override
		public Optional<String> getErrorMessage() {
			return Optional.ofNullable(errorMessage);
		}
	}

	private static class MissionProgressRecord implements MissionProgress {
		private final String currentPhase;
		private final int percentComplete;
		private final long processedCount;
		private final long totalCount;
		private final Duration elapsed;
		private final Optional<Duration> estimatedRemaining;

		MissionProgressRecord(String currentPhase, int percentComplete, long processedCount,
				long totalCount, Duration elapsed, Optional<Duration> estimatedRemaining) {
			this.currentPhase = currentPhase;
			this.percentComplete = percentComplete;
			this.processedCount = processedCount;
			this.totalCount = totalCount;
			this.elapsed = elapsed;
			this.estimatedRemaining = estimatedRemaining;
		}

		@Override
		public String getCurrentPhase() {
			return currentPhase;
		}

		@Override
		public int getPercentComplete() {
			return percentComplete;
		}

		@Override
		public long getProcessedCount() {
			return processedCount;
		}

		@Override
		public long getTotalCount() {
			return totalCount;
		}

		@Override
		public Duration getElapsed() {
			return elapsed;
		}

		@Override
		public Optional<Duration> getEstimatedRemaining() {
			return estimatedRemaining;
		}
	}
}
