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

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.reverend.api.v1.EvidenceService;
import ghidra.reverend.api.v1.MissionService;
import ghidra.reverend.api.v1.ProposalIntegrationService;
import ghidra.reverend.api.v1.ProposalIntegrationService.AnalysisSuggestion;
import ghidra.security.proposal.Proposal;
import ghidra.util.task.TaskMonitor;

/**
 * Executes a single cockpit mission -> evidence -> proposal flow.
 */
public class CockpitMissionProposalFlow {

	private final MissionService missionService;
	private final ProposalIntegrationService proposalService;
	private final EvidenceService evidenceService;

	public CockpitMissionProposalFlow(MissionService missionService,
			ProposalIntegrationService proposalService, EvidenceService evidenceService) {
		this.missionService = Objects.requireNonNull(missionService, "missionService cannot be null");
		this.proposalService =
			Objects.requireNonNull(proposalService, "proposalService cannot be null");
		this.evidenceService =
			Objects.requireNonNull(evidenceService, "evidenceService cannot be null");
	}

	public Result execute(Program program, Address address, String functionName, String executionMode,
			TaskMonitor monitor) throws MissionService.MissionException,
			ProposalIntegrationService.ProposalCreationException, EvidenceService.EvidenceException {
		Objects.requireNonNull(program, "program cannot be null");
		Objects.requireNonNull(address, "address cannot be null");
		Objects.requireNonNull(functionName, "functionName cannot be null");

		MissionService.MissionSpec spec = missionService.specBuilder()
			.type(MissionService.MissionType.FUNCTION_ID)
			.program(program)
			.parameter("address", address.toString())
			.parameter("function", functionName)
			.parameter("mode", executionMode)
			.autoProposal(true)
			.build();
		MissionService.Mission mission = missionService.create(spec);
		MissionService.Mission completed = missionService.start(mission.getId(), monitor);

		Map<String, Object> payload = new LinkedHashMap<>();
		payload.put("action", "create_proposal");
		payload.put("function", functionName);
		payload.put("address", address.toString());
		payload.put("mode", executionMode);

		EvidenceService.Evidence evidence = evidenceService.record(
			evidenceService.builder()
				.type(EvidenceService.EvidenceType.STATIC_ANALYSIS)
				.source("reverend.cockpit.proposal")
				.sourceVersion("1.0")
				.programId(programId(program))
				.addAddress(address)
				.payload(payload)
				.confidence(0.8d)
				.missionId(completed.getId())
				.build());

		AnalysisSuggestion suggestion = new SimpleSuggestion(
			"rename",
			functionName + "@" + address,
			functionName + "_reviewed",
			0.8d,
			"Generated from cockpit mission flow");
		Proposal proposal = proposalService.createFromSuggestion(program, suggestion, evidence.getId());

		return new Result(
			completed.getId(),
			evidence.getId(),
			proposal.getId(),
			completed.getState(),
			suggestion.getType(),
			suggestion.getTarget(),
			suggestion.getValue());
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

	private static class SimpleSuggestion implements AnalysisSuggestion {
		private final String type;
		private final String target;
		private final String value;
		private final double confidence;
		private final String rationale;

		SimpleSuggestion(String type, String target, String value, double confidence, String rationale) {
			this.type = type;
			this.target = target;
			this.value = value;
			this.confidence = confidence;
			this.rationale = rationale;
		}

		@Override
		public String getType() {
			return type;
		}

		@Override
		public String getTarget() {
			return target;
		}

		@Override
		public String getValue() {
			return value;
		}

		@Override
		public double getConfidence() {
			return confidence;
		}

		@Override
		public Optional<String> getRationale() {
			return Optional.ofNullable(rationale);
		}
	}

	public static class Result {
		private final String missionId;
		private final String evidenceId;
		private final String proposalId;
		private final MissionService.MissionState missionState;
		private final String suggestionType;
		private final String target;
		private final String value;

		Result(String missionId, String evidenceId, String proposalId,
				MissionService.MissionState missionState, String suggestionType, String target,
				String value) {
			this.missionId = missionId;
			this.evidenceId = evidenceId;
			this.proposalId = proposalId;
			this.missionState = missionState;
			this.suggestionType = suggestionType;
			this.target = target;
			this.value = value;
		}

		public String getMissionId() {
			return missionId;
		}

		public String getEvidenceId() {
			return evidenceId;
		}

		public String getProposalId() {
			return proposalId;
		}

		public MissionService.MissionState getMissionState() {
			return missionState;
		}

		public String getSuggestionType() {
			return suggestionType;
		}

		public String getTarget() {
			return target;
		}

		public String getValue() {
			return value;
		}
	}
}
