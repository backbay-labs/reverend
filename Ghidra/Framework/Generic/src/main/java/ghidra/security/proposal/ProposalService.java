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
package ghidra.security.proposal;

import java.util.*;

/**
 * Service that orchestrates proposal lifecycle transitions, reviewer actions,
 * and bulk operations.
 *
 * <p>Key invariants:
 * <ul>
 *   <li>State transitions are validated against {@link ProposalState#canTransitionTo}</li>
 *   <li>Only APPROVED proposals can enter the apply workflow</li>
 *   <li>A rejection from any reviewer transitions the proposal to REJECTED</li>
 *   <li>Approval threshold must be met before transitioning to APPROVED</li>
 * </ul>
 *
 * <p>Based on type-lifecycle-ux.md section 4.4 review workflow states.
 */
public class ProposalService {

	private final ProposalStore store;

	public ProposalService(ProposalStore store) {
		this.store = Objects.requireNonNull(store, "store is required");
	}

	/**
	 * Creates a new proposal in DRAFT state and persists it.
	 * @param proposal the proposal to create (state will be set to DRAFT)
	 * @return the persisted proposal
	 */
	public Proposal create(Proposal proposal) {
		Proposal draft = proposal.getState() == ProposalState.DRAFT
			? proposal
			: proposal.withState(ProposalState.DRAFT);
		store.save(draft);
		return draft;
	}

	/**
	 * Submits a DRAFT proposal for review (transitions to OPEN).
	 * @param proposalId the proposal ID
	 * @return the updated proposal
	 * @throws InvalidStateTransitionException if transition is invalid
	 * @throws NoSuchElementException if proposal not found
	 */
	public Proposal submit(String proposalId) throws InvalidStateTransitionException {
		return transition(proposalId, ProposalState.OPEN);
	}

	/**
	 * Assigns reviewers to an OPEN proposal (transitions to UNDER_REVIEW).
	 * @param proposalId the proposal ID
	 * @return the updated proposal
	 * @throws InvalidStateTransitionException if transition is invalid
	 * @throws NoSuchElementException if proposal not found
	 */
	public Proposal assignReviewers(String proposalId) throws InvalidStateTransitionException {
		return transition(proposalId, ProposalState.UNDER_REVIEW);
	}

	/**
	 * Records a reviewer action on a proposal.
	 *
	 * <p>If the action is REJECT, the proposal transitions to REJECTED.
	 * If the action is APPROVE and the approval threshold is met, the proposal
	 * transitions to APPROVED. Otherwise it remains UNDER_REVIEW.
	 *
	 * @param proposalId the proposal ID
	 * @param review the review to record
	 * @return the updated proposal
	 * @throws InvalidStateTransitionException if the proposal is not in a reviewable state
	 * @throws NoSuchElementException if proposal not found
	 */
	public Proposal review(String proposalId, Review review)
			throws InvalidStateTransitionException {
		Proposal proposal = getOrThrow(proposalId);

		if (!proposal.getState().isInReview()) {
			throw new InvalidStateTransitionException(
				String.format("Proposal %s is not in a reviewable state: %s",
					proposalId, proposal.getState()));
		}

		Proposal updated = proposal.withReview(review);

		if (review.getAction() == ReviewAction.REJECT) {
			updated = updated.withState(ProposalState.REJECTED);
		}
		else if (review.getAction() == ReviewAction.APPROVE &&
				updated.hasMetApprovalThreshold()) {
			updated = updated.withState(ProposalState.APPROVED);
		}

		store.save(updated);
		return updated;
	}

	/**
	 * Applies an approved proposal (transitions to MERGED).
	 * Only APPROVED proposals can be applied.
	 *
	 * @param proposalId the proposal ID
	 * @return the updated proposal
	 * @throws InvalidStateTransitionException if the proposal is not APPROVED
	 * @throws NoSuchElementException if proposal not found
	 */
	public Proposal apply(String proposalId) throws InvalidStateTransitionException {
		Proposal proposal = getOrThrow(proposalId);

		if (!proposal.canApply()) {
			throw new InvalidStateTransitionException(
				String.format("Only APPROVED proposals can be applied. Proposal %s is %s",
					proposalId, proposal.getState()));
		}

		return transition(proposalId, ProposalState.MERGED);
	}

	/**
	 * Withdraws a proposal (transitions to WITHDRAWN).
	 * Can be called from DRAFT, OPEN, or UNDER_REVIEW states.
	 *
	 * @param proposalId the proposal ID
	 * @return the updated proposal
	 * @throws InvalidStateTransitionException if transition is invalid
	 * @throws NoSuchElementException if proposal not found
	 */
	public Proposal withdraw(String proposalId) throws InvalidStateTransitionException {
		return transition(proposalId, ProposalState.WITHDRAWN);
	}

	/**
	 * Revises a rejected proposal (transitions back to DRAFT for re-editing).
	 *
	 * @param proposalId the proposal ID
	 * @return the updated proposal
	 * @throws InvalidStateTransitionException if transition is invalid
	 * @throws NoSuchElementException if proposal not found
	 */
	public Proposal revise(String proposalId) throws InvalidStateTransitionException {
		return transition(proposalId, ProposalState.DRAFT);
	}

	/**
	 * Bulk approve: records an approval review on multiple proposals.
	 * Proposals that are not in a reviewable state are skipped and reported.
	 *
	 * @param proposalIds the IDs of proposals to approve
	 * @param reviewer the reviewer identifier
	 * @param comment optional comment
	 * @return result containing successfully approved and skipped proposals
	 */
	public BulkResult bulkApprove(List<String> proposalIds, String reviewer, String comment) {
		return bulkReview(proposalIds, reviewer, ReviewAction.APPROVE, comment);
	}

	/**
	 * Bulk reject: records a rejection review on multiple proposals.
	 * Proposals that are not in a reviewable state are skipped and reported.
	 *
	 * @param proposalIds the IDs of proposals to reject
	 * @param reviewer the reviewer identifier
	 * @param comment optional comment
	 * @return result containing successfully rejected and skipped proposals
	 */
	public BulkResult bulkReject(List<String> proposalIds, String reviewer, String comment) {
		return bulkReview(proposalIds, reviewer, ReviewAction.REJECT, comment);
	}

	/**
	 * Bulk review: records a review action on multiple proposals.
	 *
	 * @param proposalIds the IDs of proposals
	 * @param reviewer the reviewer identifier
	 * @param action the review action
	 * @param comment optional comment
	 * @return result containing processed and skipped proposals
	 */
	public BulkResult bulkReview(List<String> proposalIds, String reviewer,
			ReviewAction action, String comment) {
		List<Proposal> processed = new ArrayList<>();
		List<BulkSkip> skipped = new ArrayList<>();

		for (String id : proposalIds) {
			try {
				Review rev = Review.builder()
					.reviewer(reviewer)
					.action(action)
					.comment(comment)
					.build();
				Proposal result = review(id, rev);
				processed.add(result);
			}
			catch (InvalidStateTransitionException e) {
				skipped.add(new BulkSkip(id, e.getMessage()));
			}
			catch (NoSuchElementException e) {
				skipped.add(new BulkSkip(id, "Proposal not found"));
			}
		}

		return new BulkResult(processed, skipped);
	}

	private Proposal transition(String proposalId, ProposalState targetState)
			throws InvalidStateTransitionException {
		Proposal proposal = getOrThrow(proposalId);

		if (!proposal.getState().canTransitionTo(targetState)) {
			throw new InvalidStateTransitionException(
				proposalId, proposal.getState(), targetState);
		}

		Proposal updated = proposal.withState(targetState);
		store.save(updated);
		return updated;
	}

	private Proposal getOrThrow(String proposalId) {
		return store.findById(proposalId)
			.orElseThrow(() -> new NoSuchElementException(
				"Proposal not found: " + proposalId));
	}

	/**
	 * Result of a bulk review operation.
	 */
	public static class BulkResult {
		private final List<Proposal> processed;
		private final List<BulkSkip> skipped;

		public BulkResult(List<Proposal> processed, List<BulkSkip> skipped) {
			this.processed = Collections.unmodifiableList(new ArrayList<>(processed));
			this.skipped = Collections.unmodifiableList(new ArrayList<>(skipped));
		}

		public List<Proposal> getProcessed() {
			return processed;
		}

		public List<BulkSkip> getSkipped() {
			return skipped;
		}

		public int processedCount() {
			return processed.size();
		}

		public int skippedCount() {
			return skipped.size();
		}
	}

	/**
	 * A proposal that was skipped during a bulk operation, with the reason.
	 */
	public static class BulkSkip {
		private final String proposalId;
		private final String reason;

		public BulkSkip(String proposalId, String reason) {
			this.proposalId = proposalId;
			this.reason = reason;
		}

		public String getProposalId() {
			return proposalId;
		}

		public String getReason() {
			return reason;
		}
	}
}
