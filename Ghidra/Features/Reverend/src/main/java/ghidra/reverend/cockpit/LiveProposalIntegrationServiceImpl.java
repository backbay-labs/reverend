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

import java.util.*;
import java.util.stream.Collectors;

import ghidra.program.model.listing.Program;
import ghidra.reverend.api.v1.EvidenceService;
import ghidra.reverend.api.v1.EvidenceService.EvidenceException;
import ghidra.reverend.api.v1.ProposalIntegrationService;
import ghidra.security.proposal.*;
import ghidra.util.task.TaskMonitor;

/**
 * Live proposal integration service backed by Ghidra proposal primitives.
 */
public class LiveProposalIntegrationServiceImpl implements ProposalIntegrationService,
		AutoCloseable {

	private final InMemoryProposalStore proposalStore;
	private final ProposalService proposalService;
	private final EvidenceService evidenceService;

	/**
	 * Creates a proposal integration service with an in-memory proposal store.
	 */
	public LiveProposalIntegrationServiceImpl() {
		this(null);
	}

	/**
	 * Creates a proposal integration service with optional evidence linking.
	 *
	 * @param evidenceService optional evidence service for provenance links
	 */
	public LiveProposalIntegrationServiceImpl(EvidenceService evidenceService) {
		this.proposalStore = new InMemoryProposalStore();
		this.proposalService = new ProposalService(proposalStore);
		this.evidenceService = evidenceService;
	}

	@Override
	public ProposalService getProposalService() {
		return proposalService;
	}

	@Override
	public Proposal createFromSuggestion(Program program, AnalysisSuggestion suggestion,
			String evidenceId) throws ProposalCreationException {
		return createFromSuggestion(program, suggestion, evidenceId, null);
	}

	@Override
	public BatchProposalResult createBatch(Program program, List<AnalysisSuggestion> suggestions,
			String missionId, TaskMonitor monitor) {
		List<Proposal> created = new ArrayList<>();
		List<CreationFailure> failures = new ArrayList<>();
		List<AnalysisSuggestion> safeSuggestions =
			suggestions != null ? suggestions : Collections.emptyList();

		if (monitor != null) {
			monitor.initialize(safeSuggestions.size());
		}

		for (int i = 0; i < safeSuggestions.size(); i++) {
			if (monitor != null && monitor.isCancelled()) {
				break;
			}

			AnalysisSuggestion suggestion = safeSuggestions.get(i);
			try {
				created.add(createFromSuggestion(program, suggestion, null, missionId));
			}
			catch (ProposalCreationException e) {
				failures.add(new CreationFailureImpl(suggestion, e.getMessage()));
			}

			if (monitor != null) {
				monitor.setProgress(i + 1);
			}
		}

		return new BatchProposalResultImpl(created, failures, safeSuggestions.size());
	}

	@Override
	public List<Proposal> queryProposals(Program program, ProposalState state, String missionId) {
		if (program == null) {
			return Collections.emptyList();
		}

		String programId = programId(program);
		return proposalStore.findByProgram(programId)
			.stream()
			.filter(proposal -> state == null || proposal.getState() == state)
			.filter(proposal -> missionId == null ||
				missionId.equals(proposal.getMetadata().get("missionId")))
			.collect(Collectors.toList());
	}

	@Override
	public ProposalApplicationResult apply(Program program, Proposal proposal, TaskMonitor monitor)
			throws ProposalApplicationException {
		if (program == null) {
			throw new ProposalApplicationException("program cannot be null");
		}
		if (proposal == null) {
			throw new ProposalApplicationException("proposal cannot be null");
		}

		try {
			Proposal applied = proposalService.apply(proposal.getId());
			String receiptId = "receipt-" + applied.getId();
			return new ProposalApplicationResultImpl(applied, receiptId, true);
		}
		catch (InvalidStateTransitionException | NoSuchElementException e) {
			throw new ProposalApplicationException("Failed to apply proposal: " + e.getMessage(), e);
		}
	}

	@Override
	public int getPendingCount(Program program) {
		if (program == null) {
			return 0;
		}

		String programId = programId(program);
		return (int) proposalStore.findByProgram(programId)
			.stream()
			.filter(proposal -> proposal.getState().isInReview())
			.count();
	}

	@Override
	public void close() {
		proposalStore.clear();
	}

	private Proposal createFromSuggestion(Program program, AnalysisSuggestion suggestion,
			String evidenceId, String missionId) throws ProposalCreationException {
		if (program == null) {
			throw new ProposalCreationException("program cannot be null");
		}
		if (suggestion == null) {
			throw new ProposalCreationException("suggestion cannot be null");
		}

		Proposal proposal = Proposal.builder()
			.title(buildTitle(suggestion))
			.description(buildDescription(suggestion))
			.author("reverend-cockpit")
			.programId(programId(program))
			.metadata("suggestionType", safeValue(suggestion.getType()))
			.metadata("target", safeValue(suggestion.getTarget()))
			.metadata("value", safeValue(suggestion.getValue()))
			.metadata("confidence", String.valueOf(suggestion.getConfidence()))
			.metadata("missionId", missionId)
			.metadata("evidenceId", evidenceId)
			.build();

		Proposal created = proposalService.create(proposal);
		if (!isBlank(evidenceId) && evidenceService != null) {
			try {
				evidenceService.linkToProposal(evidenceId, created.getId());
			}
			catch (EvidenceException e) {
				throw new ProposalCreationException(
					"Created proposal but failed to link evidence: " + e.getMessage(), e);
			}
		}
		return created;
	}

	private static String buildTitle(AnalysisSuggestion suggestion) {
		String type = safeValue(suggestion.getType());
		String target = safeValue(suggestion.getTarget());
		return "Suggestion [" + type + "] " + target;
	}

	private static String buildDescription(AnalysisSuggestion suggestion) {
		StringBuilder builder = new StringBuilder();
		builder.append("Type: ").append(safeValue(suggestion.getType())).append('\n');
		builder.append("Target: ").append(safeValue(suggestion.getTarget())).append('\n');
		builder.append("Value: ").append(safeValue(suggestion.getValue())).append('\n');
		builder.append("Confidence: ").append(suggestion.getConfidence());
		suggestion.getRationale()
			.filter(rationale -> !rationale.isBlank())
			.ifPresent(rationale -> builder.append('\n').append("Rationale: ").append(rationale));
		return builder.toString();
	}

	private static String programId(Program program) {
		String executablePath = program.getExecutablePath();
		if (!isBlank(executablePath)) {
			return executablePath;
		}
		String name = program.getName();
		if (!isBlank(name)) {
			return name;
		}
		return "program-" + System.identityHashCode(program);
	}

	private static String safeValue(String value) {
		return value != null ? value : "";
	}

	private static boolean isBlank(String value) {
		return value == null || value.isBlank();
	}

	private static class BatchProposalResultImpl implements BatchProposalResult {
		private final List<Proposal> created;
		private final List<CreationFailure> failures;
		private final int totalCount;

		BatchProposalResultImpl(List<Proposal> created, List<CreationFailure> failures,
				int totalCount) {
			this.created = Collections.unmodifiableList(new ArrayList<>(created));
			this.failures = Collections.unmodifiableList(new ArrayList<>(failures));
			this.totalCount = totalCount;
		}

		@Override
		public List<Proposal> getCreated() {
			return created;
		}

		@Override
		public List<CreationFailure> getFailures() {
			return failures;
		}

		@Override
		public int getTotalCount() {
			return totalCount;
		}
	}

	private static class CreationFailureImpl implements CreationFailure {
		private final AnalysisSuggestion suggestion;
		private final String reason;

		CreationFailureImpl(AnalysisSuggestion suggestion, String reason) {
			this.suggestion = suggestion;
			this.reason = reason;
		}

		@Override
		public AnalysisSuggestion getSuggestion() {
			return suggestion;
		}

		@Override
		public String getReason() {
			return reason;
		}
	}

	private static class ProposalApplicationResultImpl implements ProposalApplicationResult {
		private final Proposal proposal;
		private final String receiptId;
		private final boolean undoable;

		ProposalApplicationResultImpl(Proposal proposal, String receiptId, boolean undoable) {
			this.proposal = proposal;
			this.receiptId = receiptId;
			this.undoable = undoable;
		}

		@Override
		public Proposal getProposal() {
			return proposal;
		}

		@Override
		public String getReceiptId() {
			return receiptId;
		}

		@Override
		public boolean isUndoable() {
			return undoable;
		}
	}
}
