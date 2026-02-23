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

import static org.junit.Assert.*;

import java.util.*;

import org.junit.Before;
import org.junit.Test;

/**
 * Tests for {@link TransactionalProposalService} transaction atomicity,
 * undo/redo consistency, and receipt/audit link survival.
 *
 * <p>Based on type-lifecycle-ux.md section 5.6 representative automated rollback tests:
 * <ul>
 *   <li>applySingle_recordsTxAndReceiptLinks</li>
 *   <li>rollbackSingle_restoresPreApplyState</li>
 *   <li>rollbackBatch_restoresPreApplyStateAtomically</li>
 *   <li>rollbackIsIdempotent</li>
 * </ul>
 */
public class TransactionalProposalServiceTest {

	private TransactableProposalStore proposalStore;
	private InMemoryTransactionContext transactionContext;
	private InMemoryApplyReceiptStore receiptStore;
	private TransactionalProposalService service;

	@Before
	public void setUp() {
		proposalStore = new TransactableProposalStore();
		transactionContext = new InMemoryTransactionContext();
		receiptStore = new InMemoryApplyReceiptStore();

		// Register the proposal store as a state provider for undo/redo
		transactionContext.registerStateProvider(proposalStore);

		service = new TransactionalProposalService(
			proposalStore, transactionContext, receiptStore);
	}

	// --- Single apply/revert tests ---

	@Test
	public void testApplySingle_recordsTxAndReceiptLinks() throws Exception {
		// Create and approve a proposal
		Proposal proposal = createApprovedProposal("Test proposal", "user:alice");
		String proposalId = proposal.getId();

		// Apply it
		TransactionalProposalService.ApplyResult result =
			service.apply(proposalId, "user:alice");

		// Verify the apply receipt
		ApplyReceipt receipt = result.getReceipt();
		assertNotNull(receipt);
		assertNotNull(receipt.getId());
		assertEquals("user:alice", receipt.getActor());
		assertEquals(1, receipt.getProposalIds().size());
		assertEquals(proposalId, receipt.getProposalIds().get(0));
		assertFalse(receipt.isRolledBack());
		assertFalse(receipt.isBatch());

		// Verify the proposal is MERGED
		Proposal merged = result.getProposals().get(0);
		assertEquals(ProposalState.MERGED, merged.getState());

		// Verify receipt is persisted and linked
		Optional<ApplyReceipt> stored = receiptStore.findApplyReceiptById(receipt.getId());
		assertTrue(stored.isPresent());
		assertEquals(receipt.getId(), stored.get().getId());

		// Verify receipt is findable by proposal
		List<ApplyReceipt> byProposal = receiptStore.findApplyReceiptsByProposalId(proposalId);
		assertEquals(1, byProposal.size());
		assertEquals(receipt.getId(), byProposal.get(0).getId());

		// Verify transaction was recorded
		assertEquals(1, transactionContext.getUndoStackSize());
		assertTrue(transactionContext.canUndo());
	}

	@Test
	public void testRollbackSingle_restoresPreApplyState() throws Exception {
		// Create and approve a proposal
		Proposal proposal = createApprovedProposal("Test proposal", "user:alice");
		String proposalId = proposal.getId();

		// Apply it
		TransactionalProposalService.ApplyResult applyResult =
			service.apply(proposalId, "user:alice");

		// Verify it's MERGED
		assertEquals(ProposalState.MERGED,
			proposalStore.findById(proposalId).get().getState());

		// Rollback
		TransactionalProposalService.RollbackResult rollbackResult =
			service.revert(applyResult.getReceipt().getId(), "user:alice", "Testing rollback");

		// Verify rollback receipt
		RollbackReceipt rollbackReceipt = rollbackResult.getReceipt();
		assertNotNull(rollbackReceipt);
		assertEquals(applyResult.getReceipt().getId(), rollbackReceipt.getApplyReceiptId());
		assertEquals("user:alice", rollbackReceipt.getActor());
		assertEquals("Testing rollback", rollbackReceipt.getReason());
		assertFalse(rollbackResult.wasIdempotent());

		// Verify proposal is back to APPROVED
		Proposal reverted = proposalStore.findById(proposalId).get();
		assertEquals(ProposalState.APPROVED, reverted.getState());

		// Verify apply receipt is marked as rolled back
		ApplyReceipt updatedApplyReceipt =
			receiptStore.findApplyReceiptById(applyResult.getReceipt().getId()).get();
		assertTrue(updatedApplyReceipt.isRolledBack());
		assertEquals(rollbackReceipt.getId(), updatedApplyReceipt.getRollbackReceiptId());

		// Verify rollback receipt links to apply receipt
		Optional<RollbackReceipt> byApply =
			receiptStore.findRollbackByApplyReceiptId(applyResult.getReceipt().getId());
		assertTrue(byApply.isPresent());
		assertEquals(rollbackReceipt.getId(), byApply.get().getId());
	}

	// --- Batch apply/revert tests ---

	@Test
	public void testApplyBatch_recordsSingleReceiptForMultipleProposals() throws Exception {
		// Create and approve multiple proposals
		List<String> proposalIds = new ArrayList<>();
		for (int i = 0; i < 3; i++) {
			Proposal p = createApprovedProposal("Batch proposal " + i, "user:alice");
			proposalIds.add(p.getId());
		}

		// Apply as batch
		TransactionalProposalService.ApplyResult result =
			service.applyBatch(proposalIds, "user:bob");

		// Verify single receipt for all proposals
		ApplyReceipt receipt = result.getReceipt();
		assertTrue(receipt.isBatch());
		assertEquals(3, receipt.getProposalIds().size());
		assertTrue(receipt.getProposalIds().containsAll(proposalIds));

		// Verify all proposals are MERGED
		assertEquals(3, result.getProposals().size());
		for (Proposal p : result.getProposals()) {
			assertEquals(ProposalState.MERGED, p.getState());
		}

		// Verify single transaction
		assertEquals(1, transactionContext.getUndoStackSize());
	}

	@Test
	public void testRollbackBatch_restoresPreApplyStateAtomically() throws Exception {
		// Create and approve multiple proposals
		List<String> proposalIds = new ArrayList<>();
		for (int i = 0; i < 3; i++) {
			Proposal p = createApprovedProposal("Batch proposal " + i, "user:alice");
			proposalIds.add(p.getId());
		}

		// Apply as batch
		TransactionalProposalService.ApplyResult applyResult =
			service.applyBatch(proposalIds, "user:alice");

		// Verify all are MERGED
		for (String id : proposalIds) {
			assertEquals(ProposalState.MERGED, proposalStore.findById(id).get().getState());
		}

		// Rollback the batch
		TransactionalProposalService.RollbackResult rollbackResult =
			service.revert(applyResult.getReceipt().getId(), "user:alice", null);

		// Verify all proposals are back to APPROVED
		for (String id : proposalIds) {
			assertEquals(ProposalState.APPROVED, proposalStore.findById(id).get().getState());
		}

		// Verify rollback receipt links to apply receipt
		assertEquals(applyResult.getReceipt().getId(),
			rollbackResult.getReceipt().getApplyReceiptId());
	}

	@Test
	public void testRollbackIsIdempotent() throws Exception {
		// Create, approve, apply
		Proposal proposal = createApprovedProposal("Test proposal", "user:alice");
		TransactionalProposalService.ApplyResult applyResult =
			service.apply(proposal.getId(), "user:alice");
		String applyReceiptId = applyResult.getReceipt().getId();

		// First rollback
		TransactionalProposalService.RollbackResult firstRollback =
			service.revert(applyReceiptId, "user:alice", "First rollback");
		assertFalse(firstRollback.wasIdempotent());
		String firstRollbackReceiptId = firstRollback.getReceipt().getId();

		// Second rollback - should be idempotent
		TransactionalProposalService.RollbackResult secondRollback =
			service.revert(applyReceiptId, "user:bob", "Second rollback");
		assertTrue(secondRollback.wasIdempotent());
		// Should return the same rollback receipt
		assertEquals(firstRollbackReceiptId, secondRollback.getReceipt().getId());

		// Proposal should still be APPROVED (not re-processed)
		assertEquals(ProposalState.APPROVED,
			proposalStore.findById(proposal.getId()).get().getState());

		// Only one rollback receipt should exist
		assertEquals(1, receiptStore.findAllRollbackReceipts().size());
	}

	// --- Undo/redo tests ---

	@Test
	public void testUndoRestoresPreApplyState() throws Exception {
		// Create and approve a proposal
		Proposal proposal = createApprovedProposal("Test proposal", "user:alice");
		String proposalId = proposal.getId();

		// Verify initial state
		assertEquals(ProposalState.APPROVED, proposalStore.findById(proposalId).get().getState());

		// Apply it
		service.apply(proposalId, "user:alice");

		// Verify it's MERGED
		assertEquals(ProposalState.MERGED, proposalStore.findById(proposalId).get().getState());

		// Undo via transaction context
		assertTrue(transactionContext.canUndo());
		assertTrue(transactionContext.undo());

		// Verify state is restored to APPROVED
		assertEquals(ProposalState.APPROVED, proposalStore.findById(proposalId).get().getState());
	}

	@Test
	public void testRedoRestoresAppliedState() throws Exception {
		// Create, approve, and apply
		Proposal proposal = createApprovedProposal("Test proposal", "user:alice");
		String proposalId = proposal.getId();
		service.apply(proposalId, "user:alice");

		// Undo
		transactionContext.undo();
		assertEquals(ProposalState.APPROVED, proposalStore.findById(proposalId).get().getState());

		// Redo
		assertTrue(transactionContext.canRedo());
		assertTrue(transactionContext.redo());
		assertEquals(ProposalState.MERGED, proposalStore.findById(proposalId).get().getState());
	}

	@Test
	public void testUndoRedoConsistencyForBatchOperations() throws Exception {
		// Create and approve multiple proposals
		List<String> proposalIds = new ArrayList<>();
		for (int i = 0; i < 3; i++) {
			Proposal p = createApprovedProposal("Batch proposal " + i, "user:alice");
			proposalIds.add(p.getId());
		}

		// Apply as batch (single transaction)
		service.applyBatch(proposalIds, "user:alice");

		// Verify all are MERGED
		for (String id : proposalIds) {
			assertEquals(ProposalState.MERGED, proposalStore.findById(id).get().getState());
		}

		// Single undo should revert all (atomically)
		assertEquals(1, transactionContext.getUndoStackSize());
		transactionContext.undo();

		// All should be back to APPROVED
		for (String id : proposalIds) {
			assertEquals(ProposalState.APPROVED, proposalStore.findById(id).get().getState());
		}

		// Single redo should restore all
		transactionContext.redo();
		for (String id : proposalIds) {
			assertEquals(ProposalState.MERGED, proposalStore.findById(id).get().getState());
		}
	}

	// --- Transaction atomicity tests ---

	@Test
	public void testApplyFailureRollsBackTransaction() throws Exception {
		// Create one approved and one non-approved proposal
		Proposal approved = createApprovedProposal("Approved", "user:alice");
		Proposal draft = service.getProposalService().create(Proposal.builder()
			.title("Draft")
			.author("user:alice")
			.build());

		List<String> ids = List.of(approved.getId(), draft.getId());

		// Batch apply should fail because draft is not approved
		try {
			service.applyBatch(ids, "user:alice");
			fail("Should have thrown InvalidStateTransitionException");
		}
		catch (InvalidStateTransitionException e) {
			// Expected
		}

		// Verify the approved proposal is still APPROVED (not MERGED)
		assertEquals(ProposalState.APPROVED,
			proposalStore.findById(approved.getId()).get().getState());

		// Verify no apply receipt was created
		assertTrue(receiptStore.findAllApplyReceipts().isEmpty());

		// Verify no transaction was committed
		assertEquals(0, transactionContext.getUndoStackSize());
	}

	@Test(expected = NoSuchElementException.class)
	public void testApplyNonexistentProposalFails() throws Exception {
		service.apply("nonexistent-id", "user:alice");
	}

	@Test(expected = NoSuchElementException.class)
	public void testRevertNonexistentReceiptFails() {
		service.revert("nonexistent-receipt-id", "user:alice", null);
	}

	// --- Receipt audit trail tests ---

	@Test
	public void testReceiptsSurviveApplyAndRollbackPaths() throws Exception {
		// Create and apply
		Proposal proposal = createApprovedProposal("Test", "user:alice");
		TransactionalProposalService.ApplyResult applyResult =
			service.apply(proposal.getId(), "user:alice");

		// Rollback
		TransactionalProposalService.RollbackResult rollbackResult =
			service.revert(applyResult.getReceipt().getId(), "user:bob", "Mistake");

		// Verify complete audit trail
		ApplyReceipt applyReceipt =
			receiptStore.findApplyReceiptById(applyResult.getReceipt().getId()).get();
		RollbackReceipt rollbackReceipt =
			receiptStore.findRollbackReceiptById(rollbackResult.getReceipt().getId()).get();

		// Apply receipt references proposal
		assertTrue(applyReceipt.getProposalIds().contains(proposal.getId()));

		// Apply receipt is marked as rolled back with link
		assertTrue(applyReceipt.isRolledBack());
		assertEquals(rollbackReceipt.getId(), applyReceipt.getRollbackReceiptId());

		// Rollback receipt references apply receipt
		assertEquals(applyReceipt.getId(), rollbackReceipt.getApplyReceiptId());

		// Bidirectional lookup works
		Optional<RollbackReceipt> byApply =
			receiptStore.findRollbackByApplyReceiptId(applyReceipt.getId());
		assertTrue(byApply.isPresent());
		assertEquals(rollbackReceipt.getId(), byApply.get().getId());
	}

	@Test
	public void testCanRevert() throws Exception {
		Proposal proposal = createApprovedProposal("Test", "user:alice");
		String proposalId = proposal.getId();

		// Not applied yet
		assertFalse(service.canRevert(proposalId));

		// Apply
		TransactionalProposalService.ApplyResult applyResult =
			service.apply(proposalId, "user:alice");
		assertTrue(service.canRevert(proposalId));

		// Revert
		service.revert(applyResult.getReceipt().getId(), "user:alice", null);
		assertFalse(service.canRevert(proposalId));
	}

	@Test
	public void testGetActiveApplyReceipt() throws Exception {
		Proposal proposal = createApprovedProposal("Test", "user:alice");
		String proposalId = proposal.getId();

		// Not applied yet
		assertFalse(service.getActiveApplyReceipt(proposalId).isPresent());

		// Apply
		TransactionalProposalService.ApplyResult applyResult =
			service.apply(proposalId, "user:alice");
		Optional<ApplyReceipt> active = service.getActiveApplyReceipt(proposalId);
		assertTrue(active.isPresent());
		assertEquals(applyResult.getReceipt().getId(), active.get().getId());

		// Revert
		service.revert(applyResult.getReceipt().getId(), "user:alice", null);
		assertFalse(service.getActiveApplyReceipt(proposalId).isPresent());
	}

	// --- Helper methods ---

	private Proposal createApprovedProposal(String title, String author) throws Exception {
		ProposalService ps = service.getProposalService();

		Proposal draft = ps.create(Proposal.builder()
			.title(title)
			.author(author)
			.requiredApprovals(1)
			.delta(ProposalDelta.builder()
				.artifactType("function")
				.address("0x401000")
				.newValue("name", "renamed_func")
				.build())
			.build());

		ps.submit(draft.getId());
		ps.assignReviewers(draft.getId());

		return ps.review(draft.getId(), Review.builder()
			.reviewer("user:reviewer")
			.action(ReviewAction.APPROVE)
			.build());
	}

	/**
	 * A proposal store that implements StateProvider for undo/redo testing.
	 */
	private static class TransactableProposalStore
			extends InMemoryProposalStore
			implements InMemoryTransactionContext.StateProvider {

		@Override
		public Object captureState() {
			// Return a copy of all proposals
			return new ArrayList<>(findAll());
		}

		@Override
		@SuppressWarnings("unchecked")
		public void restoreState(Object state) {
			// Clear and restore from snapshot using replaceAll
			List<Proposal> snapshot = (List<Proposal>) state;
			replaceAll(snapshot);
		}
	}
}
