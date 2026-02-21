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
 * Tests for {@link ProposalState} enum and state machine transitions.
 */
public class ProposalStateTest {

	@Test
	public void testDraftTransitions() {
		assertTrue(ProposalState.DRAFT.canTransitionTo(ProposalState.OPEN));
		assertTrue(ProposalState.DRAFT.canTransitionTo(ProposalState.WITHDRAWN));
		assertFalse(ProposalState.DRAFT.canTransitionTo(ProposalState.APPROVED));
		assertFalse(ProposalState.DRAFT.canTransitionTo(ProposalState.MERGED));
	}

	@Test
	public void testOpenTransitions() {
		assertTrue(ProposalState.OPEN.canTransitionTo(ProposalState.UNDER_REVIEW));
		assertTrue(ProposalState.OPEN.canTransitionTo(ProposalState.WITHDRAWN));
		assertFalse(ProposalState.OPEN.canTransitionTo(ProposalState.APPROVED));
		assertFalse(ProposalState.OPEN.canTransitionTo(ProposalState.DRAFT));
	}

	@Test
	public void testUnderReviewTransitions() {
		assertTrue(ProposalState.UNDER_REVIEW.canTransitionTo(ProposalState.APPROVED));
		assertTrue(ProposalState.UNDER_REVIEW.canTransitionTo(ProposalState.REJECTED));
		assertTrue(ProposalState.UNDER_REVIEW.canTransitionTo(ProposalState.WITHDRAWN));
		assertFalse(ProposalState.UNDER_REVIEW.canTransitionTo(ProposalState.DRAFT));
		assertFalse(ProposalState.UNDER_REVIEW.canTransitionTo(ProposalState.MERGED));
	}

	@Test
	public void testApprovedTransitions() {
		assertTrue(ProposalState.APPROVED.canTransitionTo(ProposalState.MERGED));
		assertFalse(ProposalState.APPROVED.canTransitionTo(ProposalState.DRAFT));
		assertFalse(ProposalState.APPROVED.canTransitionTo(ProposalState.REJECTED));
	}

	@Test
	public void testRejectedTransitions() {
		assertTrue(ProposalState.REJECTED.canTransitionTo(ProposalState.DRAFT));
		assertTrue(ProposalState.REJECTED.canTransitionTo(ProposalState.WITHDRAWN));
		assertFalse(ProposalState.REJECTED.canTransitionTo(ProposalState.APPROVED));
	}

	@Test
	public void testTerminalStates() {
		assertTrue(ProposalState.MERGED.isTerminal());
		assertTrue(ProposalState.WITHDRAWN.isTerminal());
		assertFalse(ProposalState.DRAFT.isTerminal());
		assertFalse(ProposalState.APPROVED.isTerminal());

		assertTrue(ProposalState.MERGED.validTransitions().isEmpty());
		assertTrue(ProposalState.WITHDRAWN.validTransitions().isEmpty());
	}

	@Test
	public void testCanApply() {
		assertTrue(ProposalState.APPROVED.canApply());
		assertFalse(ProposalState.DRAFT.canApply());
		assertFalse(ProposalState.OPEN.canApply());
		assertFalse(ProposalState.UNDER_REVIEW.canApply());
		assertFalse(ProposalState.REJECTED.canApply());
		assertFalse(ProposalState.MERGED.canApply());
	}

	@Test
	public void testIsEditable() {
		assertTrue(ProposalState.DRAFT.isEditable());
		assertTrue(ProposalState.REJECTED.isEditable());
		assertFalse(ProposalState.OPEN.isEditable());
		assertFalse(ProposalState.APPROVED.isEditable());
	}

	@Test
	public void testIsInReview() {
		assertTrue(ProposalState.OPEN.isInReview());
		assertTrue(ProposalState.UNDER_REVIEW.isInReview());
		assertFalse(ProposalState.DRAFT.isInReview());
		assertFalse(ProposalState.APPROVED.isInReview());
	}

	@Test
	public void testFromIdentifier() {
		assertEquals(ProposalState.DRAFT, ProposalState.fromIdentifier("draft"));
		assertEquals(ProposalState.APPROVED, ProposalState.fromIdentifier("approved"));
		assertEquals(ProposalState.UNDER_REVIEW, ProposalState.fromIdentifier("under_review"));
		assertNull(ProposalState.fromIdentifier("nonexistent"));
		assertNull(ProposalState.fromIdentifier(null));
	}

	@Test
	public void testToString() {
		assertEquals("draft", ProposalState.DRAFT.toString());
		assertEquals("approved", ProposalState.APPROVED.toString());
		assertEquals("under_review", ProposalState.UNDER_REVIEW.toString());
	}
}
