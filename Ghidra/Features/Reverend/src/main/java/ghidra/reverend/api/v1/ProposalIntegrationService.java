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

import java.util.List;
import java.util.Optional;

import ghidra.program.model.listing.Program;
import ghidra.security.proposal.Proposal;
import ghidra.security.proposal.ProposalService;
import ghidra.security.proposal.ProposalState;
import ghidra.util.task.TaskMonitor;

/**
 * Service for integrating Reverend analysis results with the proposal workflow system.
 *
 * <p>This service bridges the Reverend analysis pipeline with Ghidra's proposal
 * infrastructure, enabling:
 * <ul>
 *   <li>Creation of proposals from analysis suggestions</li>
 *   <li>Batch proposal management for bulk operations</li>
 *   <li>Proposal state queries and filtering</li>
 *   <li>Transaction-safe proposal application</li>
 * </ul>
 *
 * <p>Proposals created through this service are linked to their source evidence
 * for provenance tracking.
 *
 * @since 1.0
 * @see ghidra.security.proposal.ProposalService
 * @see EvidenceService
 */
public interface ProposalIntegrationService {

	/**
	 * Returns the API version of this service implementation.
	 *
	 * @return the service version
	 */
	default ServiceVersion getVersion() {
		return ServiceVersion.CURRENT;
	}

	/**
	 * Returns the underlying proposal service for direct operations.
	 *
	 * @return the proposal service
	 */
	ProposalService getProposalService();

	/**
	 * Creates a proposal from an analysis suggestion.
	 *
	 * @param program the program the proposal applies to
	 * @param suggestion the analysis suggestion to convert
	 * @param evidenceId the evidence ID linking to provenance data
	 * @return the created proposal in DRAFT state
	 * @throws ProposalCreationException if proposal creation fails
	 */
	Proposal createFromSuggestion(Program program, AnalysisSuggestion suggestion,
			String evidenceId) throws ProposalCreationException;

	/**
	 * Creates multiple proposals from a batch of analysis suggestions.
	 *
	 * @param program the program the proposals apply to
	 * @param suggestions the analysis suggestions to convert
	 * @param missionId optional mission ID to link all proposals
	 * @param monitor task monitor for cancellation and progress
	 * @return result containing created proposals and any failures
	 */
	BatchProposalResult createBatch(Program program, List<AnalysisSuggestion> suggestions,
			String missionId, TaskMonitor monitor);

	/**
	 * Queries proposals by state and optional filters.
	 *
	 * @param program the program to query proposals for
	 * @param state optional state filter (null for all states)
	 * @param missionId optional mission ID filter
	 * @return list of matching proposals
	 */
	List<Proposal> queryProposals(Program program, ProposalState state, String missionId);

	/**
	 * Applies an approved proposal within a Ghidra transaction.
	 *
	 * <p>This method ensures the proposal application is atomic and can be
	 * undone through Ghidra's undo mechanism.
	 *
	 * @param program the program to apply the proposal to
	 * @param proposal the approved proposal to apply
	 * @param monitor task monitor for cancellation and progress
	 * @return the application result with receipt information
	 * @throws ProposalApplicationException if application fails
	 */
	ProposalApplicationResult apply(Program program, Proposal proposal,
			TaskMonitor monitor) throws ProposalApplicationException;

	/**
	 * Gets the pending proposal count for a program.
	 *
	 * @param program the program to query
	 * @return count of proposals in reviewable states
	 */
	int getPendingCount(Program program);

	/**
	 * Represents an analysis suggestion that can be converted to a proposal.
	 */
	interface AnalysisSuggestion {

		/**
		 * Returns the suggestion type.
		 * @return the type (e.g., "rename", "retype", "comment", "structure")
		 */
		String getType();

		/**
		 * Returns the target address or identifier.
		 * @return the target
		 */
		String getTarget();

		/**
		 * Returns the suggested change value.
		 * @return the suggestion value
		 */
		String getValue();

		/**
		 * Returns the confidence score (0.0 to 1.0).
		 * @return the confidence
		 */
		double getConfidence();

		/**
		 * Returns the rationale for this suggestion.
		 * @return optional rationale text
		 */
		Optional<String> getRationale();
	}

	/**
	 * Result of a batch proposal creation operation.
	 */
	interface BatchProposalResult {

		/**
		 * Returns successfully created proposals.
		 * @return list of created proposals
		 */
		List<Proposal> getCreated();

		/**
		 * Returns failures that occurred during batch creation.
		 * @return list of creation failures
		 */
		List<CreationFailure> getFailures();

		/**
		 * Returns the total number of suggestions processed.
		 * @return total count
		 */
		int getTotalCount();
	}

	/**
	 * Represents a single failure during batch proposal creation.
	 */
	interface CreationFailure {

		/**
		 * Returns the suggestion that failed.
		 * @return the failed suggestion
		 */
		AnalysisSuggestion getSuggestion();

		/**
		 * Returns the failure reason.
		 * @return the error message
		 */
		String getReason();
	}

	/**
	 * Result of applying a proposal.
	 */
	interface ProposalApplicationResult {

		/**
		 * Returns the applied proposal.
		 * @return the proposal
		 */
		Proposal getProposal();

		/**
		 * Returns the receipt ID for this application.
		 * @return the receipt ID
		 */
		String getReceiptId();

		/**
		 * Returns whether the application can be undone.
		 * @return true if undoable
		 */
		boolean isUndoable();
	}

	/**
	 * Exception thrown when proposal creation fails.
	 */
	class ProposalCreationException extends Exception {
		public ProposalCreationException(String message) {
			super(message);
		}

		public ProposalCreationException(String message, Throwable cause) {
			super(message, cause);
		}
	}

	/**
	 * Exception thrown when proposal application fails.
	 */
	class ProposalApplicationException extends Exception {
		public ProposalApplicationException(String message) {
			super(message);
		}

		public ProposalApplicationException(String message, Throwable cause) {
			super(message, cause);
		}
	}
}
