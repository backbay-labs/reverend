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

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import org.junit.Before;
import org.junit.Test;

/**
 * Tests for {@link InMemoryProposalStore}.
 */
public class InMemoryProposalStoreTest {

	private InMemoryProposalStore store;

	@Before
	public void setUp() {
		store = new InMemoryProposalStore();
	}

	@Test
	public void testSaveAndFindById() {
		Proposal p = Proposal.builder()
			.id("p-1")
			.title("Test")
			.author("user:alice")
			.build();

		store.save(p);

		Optional<Proposal> found = store.findById("p-1");
		assertTrue(found.isPresent());
		assertEquals("Test", found.get().getTitle());
	}

	@Test
	public void testFindByIdNotFound() {
		assertFalse(store.findById("nonexistent").isPresent());
	}

	@Test(expected = IllegalArgumentException.class)
	public void testSaveNull() {
		store.save(null);
	}

	@Test
	public void testSaveUpdatesExisting() {
		Proposal p1 = Proposal.builder()
			.id("p-1")
			.title("Original")
			.author("user:alice")
			.build();
		store.save(p1);

		Proposal p2 = p1.withState(ProposalState.OPEN);
		store.save(p2);

		assertEquals(1, store.size());
		assertEquals(ProposalState.OPEN, store.findById("p-1").get().getState());
	}

	@Test
	public void testFindByState() {
		store.save(Proposal.builder().id("p-1").title("T1").author("a")
			.state(ProposalState.DRAFT).build());
		store.save(Proposal.builder().id("p-2").title("T2").author("b")
			.state(ProposalState.OPEN).build());
		store.save(Proposal.builder().id("p-3").title("T3").author("c")
			.state(ProposalState.DRAFT).build());

		List<Proposal> drafts = store.findByState(ProposalState.DRAFT);
		assertEquals(2, drafts.size());

		List<Proposal> open = store.findByState(ProposalState.OPEN);
		assertEquals(1, open.size());

		List<Proposal> approved = store.findByState(ProposalState.APPROVED);
		assertEquals(0, approved.size());
	}

	@Test
	public void testFindByAuthor() {
		store.save(Proposal.builder().id("p-1").title("T").author("user:alice").build());
		store.save(Proposal.builder().id("p-2").title("T").author("user:bob").build());
		store.save(Proposal.builder().id("p-3").title("T").author("user:alice").build());

		assertEquals(2, store.findByAuthor("user:alice").size());
		assertEquals(1, store.findByAuthor("user:bob").size());
		assertEquals(0, store.findByAuthor("user:carol").size());
	}

	@Test
	public void testFindByProgram() {
		store.save(Proposal.builder().id("p-1").title("T").author("a")
			.programId("prog-1").build());
		store.save(Proposal.builder().id("p-2").title("T").author("b")
			.programId("prog-2").build());

		assertEquals(1, store.findByProgram("prog-1").size());
		assertEquals(1, store.findByProgram("prog-2").size());
		assertEquals(0, store.findByProgram("prog-3").size());
	}

	@Test
	public void testFindPendingReview() {
		store.save(Proposal.builder().id("p-1").title("T").author("a")
			.state(ProposalState.DRAFT).build());
		store.save(Proposal.builder().id("p-2").title("T").author("b")
			.state(ProposalState.OPEN).build());
		store.save(Proposal.builder().id("p-3").title("T").author("c")
			.state(ProposalState.UNDER_REVIEW).build());
		store.save(Proposal.builder().id("p-4").title("T").author("d")
			.state(ProposalState.APPROVED).build());

		List<Proposal> pending = store.findPendingReview();
		assertEquals(2, pending.size());
	}

	@Test
	public void testFindAll() {
		assertTrue(store.findAll().isEmpty());

		store.save(Proposal.builder().id("p-1").title("T").author("a").build());
		store.save(Proposal.builder().id("p-2").title("T").author("b").build());

		assertEquals(2, store.findAll().size());
	}

	@Test
	public void testSizeAndIsEmpty() {
		assertTrue(store.isEmpty());
		assertEquals(0, store.size());

		store.save(Proposal.builder().id("p-1").title("T").author("a").build());

		assertFalse(store.isEmpty());
		assertEquals(1, store.size());
	}

	@Test
	public void testOrderingByCreatedAt() {
		Instant t1 = Instant.parse("2026-01-01T00:00:00Z");
		Instant t2 = Instant.parse("2026-01-02T00:00:00Z");
		Instant t3 = Instant.parse("2026-01-03T00:00:00Z");

		// Insert out of order
		store.save(Proposal.builder().id("p-3").title("T3").author("a")
			.createdAt(t3).build());
		store.save(Proposal.builder().id("p-1").title("T1").author("a")
			.createdAt(t1).build());
		store.save(Proposal.builder().id("p-2").title("T2").author("a")
			.createdAt(t2).build());

		List<Proposal> all = store.findAll();
		assertEquals("p-1", all.get(0).getId());
		assertEquals("p-2", all.get(1).getId());
		assertEquals("p-3", all.get(2).getId());
	}
}
