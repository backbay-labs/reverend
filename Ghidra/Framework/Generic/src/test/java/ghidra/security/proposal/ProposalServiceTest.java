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
 * Tests for {@link ProposalService} lifecycle transitions, review actions,
 * and bulk operations.
 */
public class ProposalServiceTest {

	private ProposalStore store;
	private ProposalService service;

	@Before
	public void setUp() {
		store = new InMemoryProposalStore();
		service = new ProposalService(store);
	}

	// --- Full lifecycle tests ---

	@Test
	public void testFullLifecycle_ApproveAndMerge() throws Exception {
		Proposal draft = service.create(Proposal.builder()
			.title("Rename crypto funcs")
			.author("user:alice")
			.programId("prog-1")
			.requiredApprovals(1)
			.build());
		assertEquals(ProposalState.DRAFT, draft.getState());

		Proposal open = service.submit(draft.getId());
		assertEquals(ProposalState.OPEN, open.getState());

		Proposal underReview = service.assignReviewers(open.getId());
		assertEquals(ProposalState.UNDER_REVIEW, underReview.getState());

		Review approval = Review.builder()
			.reviewer("user:bob")
			.action(ReviewAction.APPROVE)
			.comment("Looks good")
			.build();
		Proposal approved = service.review(underReview.getId(), approval);
		assertEquals(ProposalState.APPROVED, approved.getState());
		assertTrue(approved.canApply());

		Proposal merged = service.apply(approved.getId());
		assertEquals(ProposalState.MERGED, merged.getState());
		assertTrue(merged.getState().isTerminal());
	}

	@Test
	public void testFullLifecycle_RejectAndRevise() throws Exception {
		Proposal draft = service.create(Proposal.builder()
			.title("Retype structs")
			.author("user:alice")
			.requiredApprovals(1)
			.build());

		service.submit(draft.getId());
		service.assignReviewers(draft.getId());

		Review rejection = Review.builder()
			.reviewer("user:bob")
			.action(ReviewAction.REJECT)
			.comment("Wrong struct layout")
			.build();
		Proposal rejected = service.review(draft.getId(), rejection);
		assertEquals(ProposalState.REJECTED, rejected.getState());
		assertFalse(rejected.canApply());

		Proposal revised = service.revise(rejected.getId());
		assertEquals(ProposalState.DRAFT, revised.getState());
	}

	@Test
	public void testWithdraw() throws Exception {
		Proposal draft = service.create(Proposal.builder()
			.title("Test")
			.author("user:alice")
			.build());

		Proposal withdrawn = service.withdraw(draft.getId());
		assertEquals(ProposalState.WITHDRAWN, withdrawn.getState());
		assertTrue(withdrawn.getState().isTerminal());
	}

	// --- Only approved can apply ---

	@Test(expected = InvalidStateTransitionException.class)
	public void testApply_DraftFails() throws Exception {
		Proposal draft = service.create(Proposal.builder()
			.title("Test")
			.author("user:alice")
			.build());

		service.apply(draft.getId());
	}

	@Test(expected = InvalidStateTransitionException.class)
	public void testApply_OpenFails() throws Exception {
		Proposal draft = service.create(Proposal.builder()
			.title("Test")
			.author("user:alice")
			.build());
		service.submit(draft.getId());

		service.apply(draft.getId());
	}

	@Test(expected = InvalidStateTransitionException.class)
	public void testApply_UnderReviewFails() throws Exception {
		Proposal draft = service.create(Proposal.builder()
			.title("Test")
			.author("user:alice")
			.build());
		service.submit(draft.getId());
		service.assignReviewers(draft.getId());

		service.apply(draft.getId());
	}

	@Test(expected = InvalidStateTransitionException.class)
	public void testApply_RejectedFails() throws Exception {
		Proposal draft = service.create(Proposal.builder()
			.title("Test")
			.author("user:alice")
			.build());
		service.submit(draft.getId());
		service.assignReviewers(draft.getId());
		service.review(draft.getId(), Review.builder()
			.reviewer("user:bob")
			.action(ReviewAction.REJECT)
			.build());

		service.apply(draft.getId());
	}

	// --- Review threshold tests ---

	@Test
	public void testMultipleApprovalsRequired() throws Exception {
		Proposal draft = service.create(Proposal.builder()
			.title("Test")
			.author("user:alice")
			.requiredApprovals(2)
			.build());
		service.submit(draft.getId());
		service.assignReviewers(draft.getId());

		// First approval -- stays UNDER_REVIEW
		Proposal after1 = service.review(draft.getId(), Review.builder()
			.reviewer("user:bob")
			.action(ReviewAction.APPROVE)
			.build());
		assertEquals(ProposalState.UNDER_REVIEW, after1.getState());

		// Second approval -- transitions to APPROVED
		Proposal after2 = service.review(draft.getId(), Review.builder()
			.reviewer("user:carol")
			.action(ReviewAction.APPROVE)
			.build());
		assertEquals(ProposalState.APPROVED, after2.getState());
	}

	@Test
	public void testReviewFromOpenState() throws Exception {
		Proposal draft = service.create(Proposal.builder()
			.title("Test")
			.author("user:alice")
			.requiredApprovals(1)
			.build());
		service.submit(draft.getId());

		// Reviewing from OPEN state is allowed (isInReview includes OPEN)
		Proposal approved = service.review(draft.getId(), Review.builder()
			.reviewer("user:bob")
			.action(ReviewAction.APPROVE)
			.build());
		assertEquals(ProposalState.APPROVED, approved.getState());
	}

	@Test(expected = InvalidStateTransitionException.class)
	public void testReview_DraftFails() throws Exception {
		Proposal draft = service.create(Proposal.builder()
			.title("Test")
			.author("user:alice")
			.build());

		service.review(draft.getId(), Review.builder()
			.reviewer("user:bob")
			.action(ReviewAction.APPROVE)
			.build());
	}

	// --- Invalid transitions ---

	@Test(expected = InvalidStateTransitionException.class)
	public void testSubmitApproved_Fails() throws Exception {
		Proposal draft = service.create(Proposal.builder()
			.title("Test")
			.author("user:alice")
			.requiredApprovals(1)
			.build());
		service.submit(draft.getId());
		service.review(draft.getId(), Review.builder()
			.reviewer("user:bob")
			.action(ReviewAction.APPROVE)
			.build());

		service.submit(draft.getId()); // Can't re-submit approved
	}

	@Test(expected = NoSuchElementException.class)
	public void testSubmitNonexistent_Fails() throws Exception {
		service.submit("does-not-exist");
	}

	// --- Bulk operations ---

	@Test
	public void testBulkApprove() throws Exception {
		List<String> ids = new ArrayList<>();
		for (int i = 0; i < 3; i++) {
			Proposal p = service.create(Proposal.builder()
				.title("Proposal " + i)
				.author("user:alice")
				.requiredApprovals(1)
				.build());
			service.submit(p.getId());
			service.assignReviewers(p.getId());
			ids.add(p.getId());
		}

		ProposalService.BulkResult result =
			service.bulkApprove(ids, "user:reviewer", "LGTM");

		assertEquals(3, result.processedCount());
		assertEquals(0, result.skippedCount());

		for (Proposal p : result.getProcessed()) {
			assertEquals(ProposalState.APPROVED, p.getState());
		}
	}

	@Test
	public void testBulkReject() throws Exception {
		List<String> ids = new ArrayList<>();
		for (int i = 0; i < 2; i++) {
			Proposal p = service.create(Proposal.builder()
				.title("Proposal " + i)
				.author("user:alice")
				.requiredApprovals(1)
				.build());
			service.submit(p.getId());
			ids.add(p.getId());
		}

		ProposalService.BulkResult result =
			service.bulkReject(ids, "user:reviewer", "Not ready");

		assertEquals(2, result.processedCount());
		assertEquals(0, result.skippedCount());

		for (Proposal p : result.getProcessed()) {
			assertEquals(ProposalState.REJECTED, p.getState());
		}
	}

	@Test
	public void testBulkApprove_SkipsNonReviewable() throws Exception {
		Proposal draft = service.create(Proposal.builder()
			.title("Draft")
			.author("user:alice")
			.build());

		Proposal underReview = service.create(Proposal.builder()
			.title("Ready")
			.author("user:alice")
			.requiredApprovals(1)
			.build());
		service.submit(underReview.getId());

		List<String> ids = List.of(draft.getId(), underReview.getId(), "nonexistent");

		ProposalService.BulkResult result =
			service.bulkApprove(ids, "user:reviewer", "OK");

		assertEquals(1, result.processedCount());
		assertEquals(2, result.skippedCount());
	}

	// --- Querying ---

	@Test
	public void testQueryByState() throws Exception {
		service.create(Proposal.builder().title("P1").author("user:a").build());
		Proposal p2 = service.create(Proposal.builder().title("P2").author("user:b").build());
		service.submit(p2.getId());

		assertEquals(1, store.findByState(ProposalState.DRAFT).size());
		assertEquals(1, store.findByState(ProposalState.OPEN).size());
		assertEquals(0, store.findByState(ProposalState.APPROVED).size());
	}

	@Test
	public void testQueryByAuthor() {
		service.create(Proposal.builder().title("P1").author("user:alice").build());
		service.create(Proposal.builder().title("P2").author("user:bob").build());
		service.create(Proposal.builder().title("P3").author("user:alice").build());

		assertEquals(2, store.findByAuthor("user:alice").size());
		assertEquals(1, store.findByAuthor("user:bob").size());
	}

	@Test
	public void testQueryByProgram() {
		service.create(Proposal.builder().title("P1").author("a").programId("prog-1").build());
		service.create(Proposal.builder().title("P2").author("b").programId("prog-2").build());
		service.create(Proposal.builder().title("P3").author("c").programId("prog-1").build());

		assertEquals(2, store.findByProgram("prog-1").size());
		assertEquals(1, store.findByProgram("prog-2").size());
	}

	@Test
	public void testQueryPendingReview() throws Exception {
		Proposal p1 = service.create(Proposal.builder().title("P1").author("a").build());
		Proposal p2 = service.create(Proposal.builder().title("P2").author("b").build());
		service.submit(p1.getId());
		service.submit(p2.getId());
		service.assignReviewers(p2.getId());

		List<Proposal> pending = store.findPendingReview();
		assertEquals(2, pending.size()); // OPEN + UNDER_REVIEW are both "in review"
	}

	// --- Persistence ---

	@Test
	public void testStateIsPersisted() throws Exception {
		Proposal created = service.create(Proposal.builder()
			.title("Test")
			.author("user:alice")
			.build());

		service.submit(created.getId());

		Optional<Proposal> loaded = store.findById(created.getId());
		assertTrue(loaded.isPresent());
		assertEquals(ProposalState.OPEN, loaded.get().getState());
	}

	@Test
	public void testReviewsArePersisted() throws Exception {
		Proposal p = service.create(Proposal.builder()
			.title("Test")
			.author("user:alice")
			.requiredApprovals(1)
			.build());
		service.submit(p.getId());

		service.review(p.getId(), Review.builder()
			.reviewer("user:bob")
			.action(ReviewAction.APPROVE)
			.comment("LGTM")
			.build());

		Optional<Proposal> loaded = store.findById(p.getId());
		assertTrue(loaded.isPresent());
		assertEquals(1, loaded.get().getReviews().size());
		assertEquals("user:bob", loaded.get().getReviews().get(0).getReviewer());
		assertEquals(ReviewAction.APPROVE, loaded.get().getReviews().get(0).getAction());
	}
}
