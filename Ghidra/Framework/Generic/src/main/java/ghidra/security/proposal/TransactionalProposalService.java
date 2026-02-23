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
import java.util.stream.Collectors;

/**
 * A transaction-aware proposal service that wraps apply/revert operations
 * in atomic Ghidra transactions with receipt tracking.
 *
 * <p>This service extends {@link ProposalService} with transaction semantics
 * based on type-lifecycle-ux.md section 5.5:
 * <ul>
 *   <li>Apply and revert actions participate in atomic Ghidra transactions</li>
 *   <li>Undo/redo behavior remains consistent for batch and single-item operations</li>
 *   <li>Receipt/audit links survive apply and rollback paths</li>
 * </ul>
 *
 * <p>Key guarantees:
 * <ul>
 *   <li>Apply receipt and transaction are committed atomically with the proposal state change</li>
 *   <li>Apply receipt always links to the applied proposals</li>
 *   <li>Rollback receipt always links to the original apply receipt</li>
 *   <li>Single-change and batch-change rollback both restore the exact pre-apply state</li>
 *   <li>Repeated rollback calls are idempotent</li>
 * </ul>
 */
public class TransactionalProposalService {

	private final ProposalService proposalService;
	private final ProposalStore proposalStore;
	private final TransactionContext transactionContext;
	private final ApplyReceiptStore receiptStore;

	/**
	 * Creates a transactional proposal service.
	 *
	 * @param proposalStore the proposal store
	 * @param transactionContext the transaction context for atomic operations
	 * @param receiptStore the receipt store for audit records
	 */
	public TransactionalProposalService(
			ProposalStore proposalStore,
			TransactionContext transactionContext,
			ApplyReceiptStore receiptStore) {
		this.proposalStore = Objects.requireNonNull(proposalStore, "proposalStore is required");
		this.transactionContext = Objects.requireNonNull(transactionContext,
			"transactionContext is required");
		this.receiptStore = Objects.requireNonNull(receiptStore, "receiptStore is required");
		this.proposalService = new ProposalService(proposalStore);
	}

	/**
	 * Returns the underlying proposal service for non-transactional operations.
	 *
	 * @return the proposal service
	 */
	public ProposalService getProposalService() {
		return proposalService;
	}

	/**
	 * Applies an approved proposal within a transaction.
	 *
	 * <p>The operation:
	 * <ol>
	 *   <li>Starts a Ghidra transaction</li>
	 *   <li>Validates the proposal is APPROVED</li>
	 *   <li>Transitions the proposal to MERGED</li>
	 *   <li>Creates and persists an apply receipt</li>
	 *   <li>Commits the transaction (or rolls back on failure)</li>
	 * </ol>
	 *
	 * @param proposalId the proposal ID
	 * @param actor the actor performing the apply
	 * @return the apply result containing the receipt and updated proposal
	 * @throws InvalidStateTransitionException if the proposal is not APPROVED
	 * @throws NoSuchElementException if proposal not found
	 */
	public ApplyResult apply(String proposalId, String actor) throws InvalidStateTransitionException {
		return applyBatch(Collections.singletonList(proposalId), actor);
	}

	/**
	 * Applies multiple approved proposals atomically within a single transaction.
	 *
	 * <p>All proposals must be in APPROVED state. If any proposal cannot be applied,
	 * the entire batch is rolled back and no changes are made.
	 *
	 * @param proposalIds the proposal IDs to apply
	 * @param actor the actor performing the apply
	 * @return the apply result containing the receipt and updated proposals
	 * @throws InvalidStateTransitionException if any proposal is not APPROVED
	 * @throws NoSuchElementException if any proposal not found
	 */
	public ApplyResult applyBatch(List<String> proposalIds, String actor)
			throws InvalidStateTransitionException {
		Objects.requireNonNull(proposalIds, "proposalIds is required");
		Objects.requireNonNull(actor, "actor is required");

		if (proposalIds.isEmpty()) {
			throw new IllegalArgumentException("proposalIds cannot be empty");
		}

		String description = proposalIds.size() == 1
			? "Apply proposal: " + proposalIds.get(0)
			: "Apply " + proposalIds.size() + " proposals";

		int txId = transactionContext.startTransaction(description);
		try {
			// Validate all proposals are approved first
			List<Proposal> proposals = new ArrayList<>();
			for (String id : proposalIds) {
				Proposal proposal = proposalStore.findById(id)
					.orElseThrow(() -> new NoSuchElementException("Proposal not found: " + id));

				if (!proposal.canApply()) {
					throw new InvalidStateTransitionException(
						String.format("Only APPROVED proposals can be applied. Proposal %s is %s",
							id, proposal.getState()));
				}
				proposals.add(proposal);
			}

			// Apply all proposals
			List<Proposal> appliedProposals = new ArrayList<>();
			List<String> allDeltaIds = new ArrayList<>();
			for (Proposal proposal : proposals) {
				Proposal applied = proposalService.apply(proposal.getId());
				appliedProposals.add(applied);
				allDeltaIds.addAll(
					proposal.getDeltas().stream()
						.map(ProposalDelta::getId)
						.collect(Collectors.toList()));
			}

			// Create and save the apply receipt
			ApplyReceipt receipt = ApplyReceipt.builder()
				.transactionId(txId)
				.actor(actor)
				.proposalIds(proposalIds)
				.deltaIds(allDeltaIds)
				.build();
			receiptStore.saveApplyReceipt(receipt);

			transactionContext.endTransaction(txId, true);
			return new ApplyResult(receipt, appliedProposals);
		}
		catch (Exception e) {
			transactionContext.endTransaction(txId, false);
			throw e;
		}
	}

	/**
	 * Reverts a previously applied proposal, restoring the pre-apply state.
	 *
	 * <p>The operation:
	 * <ol>
	 *   <li>Looks up the apply receipt</li>
	 *   <li>If already rolled back, returns idempotently</li>
	 *   <li>Starts a Ghidra transaction</li>
	 *   <li>Transitions proposals back to APPROVED state</li>
	 *   <li>Creates and persists a rollback receipt</li>
	 *   <li>Links the rollback receipt to the apply receipt</li>
	 *   <li>Commits the transaction</li>
	 * </ol>
	 *
	 * @param applyReceiptId the apply receipt ID to rollback
	 * @param actor the actor performing the rollback
	 * @param reason optional reason for the rollback
	 * @return the rollback result
	 * @throws NoSuchElementException if apply receipt not found
	 */
	public RollbackResult revert(String applyReceiptId, String actor, String reason) {
		Objects.requireNonNull(applyReceiptId, "applyReceiptId is required");
		Objects.requireNonNull(actor, "actor is required");

		ApplyReceipt applyReceipt = receiptStore.findApplyReceiptById(applyReceiptId)
			.orElseThrow(() -> new NoSuchElementException(
				"Apply receipt not found: " + applyReceiptId));

		// Idempotent: if already rolled back, return the existing rollback receipt
		if (applyReceipt.isRolledBack()) {
			RollbackReceipt existingRollback = receiptStore
				.findRollbackReceiptById(applyReceipt.getRollbackReceiptId())
				.orElse(null);
			return RollbackResult.idempotent(applyReceipt, existingRollback);
		}

		String description = applyReceipt.isBatch()
			? "Revert " + applyReceipt.getProposalIds().size() + " proposals"
			: "Revert proposal: " + applyReceipt.getProposalIds().get(0);

		int txId = transactionContext.startTransaction(description);
		try {
			// Transition all proposals back to APPROVED
			List<Proposal> revertedProposals = new ArrayList<>();
			for (String proposalId : applyReceipt.getProposalIds()) {
				Optional<Proposal> optProposal = proposalStore.findById(proposalId);
				if (optProposal.isPresent()) {
					Proposal proposal = optProposal.get();
					if (proposal.getState() == ProposalState.MERGED) {
						Proposal reverted = proposal.withState(ProposalState.APPROVED);
						proposalStore.save(reverted);
						revertedProposals.add(reverted);
					}
				}
			}

			// Create and save the rollback receipt
			RollbackReceipt rollbackReceipt = RollbackReceipt.builder()
				.transactionId(txId)
				.applyReceiptId(applyReceiptId)
				.actor(actor)
				.reason(reason)
				.build();
			receiptStore.saveRollbackReceipt(rollbackReceipt);

			transactionContext.endTransaction(txId, true);
			return RollbackResult.rolledBack(rollbackReceipt, revertedProposals);
		}
		catch (Exception e) {
			transactionContext.endTransaction(txId, false);
			throw e;
		}
	}

	/**
	 * Checks if a proposal can be reverted (i.e., has been applied and not yet rolled back).
	 *
	 * @param proposalId the proposal ID
	 * @return true if the proposal can be reverted
	 */
	public boolean canRevert(String proposalId) {
		List<ApplyReceipt> receipts = receiptStore.findApplyReceiptsByProposalId(proposalId);
		return receipts.stream().anyMatch(r -> !r.isRolledBack());
	}

	/**
	 * Returns the most recent apply receipt for a proposal that has not been rolled back.
	 *
	 * @param proposalId the proposal ID
	 * @return the apply receipt, or empty if not applied or already rolled back
	 */
	public Optional<ApplyReceipt> getActiveApplyReceipt(String proposalId) {
		List<ApplyReceipt> receipts = receiptStore.findApplyReceiptsByProposalId(proposalId);
		return receipts.stream()
			.filter(r -> !r.isRolledBack())
			.max(Comparator.comparing(ApplyReceipt::getAppliedAt));
	}

	/**
	 * Result of an apply operation.
	 */
	public static class ApplyResult {
		private final ApplyReceipt receipt;
		private final List<Proposal> proposals;

		public ApplyResult(ApplyReceipt receipt, List<Proposal> proposals) {
			this.receipt = receipt;
			this.proposals = Collections.unmodifiableList(new ArrayList<>(proposals));
		}

		public ApplyReceipt getReceipt() {
			return receipt;
		}

		public List<Proposal> getProposals() {
			return proposals;
		}

		/**
		 * Returns whether this was a batch apply.
		 *
		 * @return true if more than one proposal was applied
		 */
		public boolean isBatch() {
			return proposals.size() > 1;
		}
	}

	/**
	 * Result of a rollback operation.
	 */
	public static class RollbackResult {
		private final RollbackReceipt receipt;
		private final List<Proposal> proposals;
		private final boolean wasIdempotent;

		private RollbackResult(RollbackReceipt receipt, List<Proposal> proposals,
				boolean wasIdempotent) {
			this.receipt = receipt;
			this.proposals = proposals != null
				? Collections.unmodifiableList(new ArrayList<>(proposals))
				: Collections.emptyList();
			this.wasIdempotent = wasIdempotent;
		}

		public static RollbackResult rolledBack(RollbackReceipt receipt, List<Proposal> proposals) {
			return new RollbackResult(receipt, proposals, false);
		}

		public static RollbackResult idempotent(ApplyReceipt applyReceipt,
				RollbackReceipt existingRollback) {
			return new RollbackResult(existingRollback, null, true);
		}

		public RollbackReceipt getReceipt() {
			return receipt;
		}

		public List<Proposal> getProposals() {
			return proposals;
		}

		/**
		 * Returns whether this rollback was idempotent (already rolled back).
		 *
		 * @return true if the apply was already rolled back
		 */
		public boolean wasIdempotent() {
			return wasIdempotent;
		}
	}
}
