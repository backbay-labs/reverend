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

import org.junit.Test;

/**
 * Tests for {@link Proposal} data class.
 */
public class ProposalTest {

	@Test
	public void testBuildMinimal() {
		Proposal p = Proposal.builder()
			.title("Rename crypto funcs")
			.author("user:alice")
			.build();

		assertNotNull(p.getId());
		assertEquals("Rename crypto funcs", p.getTitle());
		assertEquals("user:alice", p.getAuthor());
		assertEquals(ProposalState.DRAFT, p.getState());
		assertEquals("", p.getDescription());
		assertNotNull(p.getCreatedAt());
		assertTrue(p.getDeltas().isEmpty());
		assertTrue(p.getReviews().isEmpty());
		assertEquals(1, p.getRequiredApprovals());
	}

	@Test
	public void testBuildFull() {
		ProposalDelta delta = ProposalDelta.builder()
			.artifactType("SYMBOL")
			.address("0x401000")
			.newValue("name", "ssl_init")
			.build();

		Proposal p = Proposal.builder()
			.id("test-id")
			.title("Rename funcs")
			.description("Rename crypto functions")
			.author("user:bob")
			.programId("prog-1")
			.requiredApprovals(2)
			.delta(delta)
			.metadata("source", "manual")
			.build();

		assertEquals("test-id", p.getId());
		assertEquals("Rename funcs", p.getTitle());
		assertEquals("Rename crypto functions", p.getDescription());
		assertEquals("user:bob", p.getAuthor());
		assertEquals("prog-1", p.getProgramId());
		assertEquals(2, p.getRequiredApprovals());
		assertEquals(1, p.getDeltas().size());
		assertEquals("manual", p.getMetadata().get("source"));
	}

	@Test(expected = NullPointerException.class)
	public void testBuildRequiresTitle() {
		Proposal.builder().author("user:alice").build();
	}

	@Test(expected = NullPointerException.class)
	public void testBuildRequiresAuthor() {
		Proposal.builder().title("Test").build();
	}

	@Test
	public void testWithState() {
		Proposal draft = Proposal.builder()
			.title("Test")
			.author("user:alice")
			.build();

		assertEquals(ProposalState.DRAFT, draft.getState());

		Proposal open = draft.withState(ProposalState.OPEN);
		assertEquals(ProposalState.OPEN, open.getState());
		assertEquals(draft.getId(), open.getId());
		assertEquals(draft.getTitle(), open.getTitle());
		// Original unchanged
		assertEquals(ProposalState.DRAFT, draft.getState());
	}

	@Test
	public void testWithReview() {
		Proposal p = Proposal.builder()
			.title("Test")
			.author("user:alice")
			.build();

		Review review = Review.builder()
			.reviewer("user:bob")
			.action(ReviewAction.APPROVE)
			.build();

		Proposal reviewed = p.withReview(review);
		assertEquals(1, reviewed.getReviews().size());
		assertEquals("user:bob", reviewed.getReviews().get(0).getReviewer());
		// Original unchanged
		assertTrue(p.getReviews().isEmpty());
	}

	@Test
	public void testApprovalCounting() {
		Proposal p = Proposal.builder()
			.title("Test")
			.author("user:alice")
			.requiredApprovals(2)
			.build();

		assertEquals(0, p.getApprovalCount());
		assertFalse(p.hasMetApprovalThreshold());

		Review approve1 = Review.builder()
			.reviewer("user:bob")
			.action(ReviewAction.APPROVE)
			.build();

		Proposal p1 = p.withReview(approve1);
		assertEquals(1, p1.getApprovalCount());
		assertFalse(p1.hasMetApprovalThreshold());

		Review approve2 = Review.builder()
			.reviewer("user:carol")
			.action(ReviewAction.APPROVE)
			.build();

		Proposal p2 = p1.withReview(approve2);
		assertEquals(2, p2.getApprovalCount());
		assertTrue(p2.hasMetApprovalThreshold());
	}

	@Test
	public void testRequestChangesDoesNotCountAsApproval() {
		Proposal p = Proposal.builder()
			.title("Test")
			.author("user:alice")
			.requiredApprovals(1)
			.build();

		Review rc = Review.builder()
			.reviewer("user:bob")
			.action(ReviewAction.REQUEST_CHANGES)
			.build();

		Proposal reviewed = p.withReview(rc);
		assertEquals(0, reviewed.getApprovalCount());
		assertFalse(reviewed.hasMetApprovalThreshold());
	}

	@Test
	public void testCanApply() {
		Proposal draft = Proposal.builder()
			.title("Test")
			.author("user:alice")
			.build();
		assertFalse(draft.canApply());

		Proposal approved = draft.withState(ProposalState.APPROVED);
		assertTrue(approved.canApply());
	}

	@Test
	public void testEquality() {
		Proposal p1 = Proposal.builder().id("abc").title("T").author("a").build();
		Proposal p2 = Proposal.builder().id("abc").title("T2").author("b").build();
		Proposal p3 = Proposal.builder().id("xyz").title("T").author("a").build();

		assertEquals(p1, p2);
		assertNotEquals(p1, p3);
		assertEquals(p1.hashCode(), p2.hashCode());
	}

	@Test
	public void testImmutableCollections() {
		Proposal p = Proposal.builder()
			.title("Test")
			.author("user:alice")
			.metadata("k", "v")
			.build();

		try {
			p.getDeltas().add(ProposalDelta.builder().artifactType("X").build());
			fail("Should not be able to modify deltas");
		}
		catch (UnsupportedOperationException e) {
			// expected
		}

		try {
			p.getMetadata().put("new", "value");
			fail("Should not be able to modify metadata");
		}
		catch (UnsupportedOperationException e) {
			// expected
		}
	}
}
