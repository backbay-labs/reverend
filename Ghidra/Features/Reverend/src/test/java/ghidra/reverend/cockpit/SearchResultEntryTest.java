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

import static org.junit.Assert.*;

import java.util.Optional;

import org.junit.Test;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.reverend.api.v1.QueryService.QueryResult;

/**
 * Unit tests for {@link SearchResultEntry}.
 */
public class SearchResultEntryTest {

	@Test
	public void testCreateFromQueryResult() {
		Address addr = createTestAddress(0x401000);
		QueryResult result = new TestQueryResult(addr, 0.85, "Match found", "ev-123");

		SearchResultEntry entry = new SearchResultEntry(result, "main");

		assertEquals(addr, entry.getAddress());
		assertEquals(0x401000, entry.getAddressOffset());
		assertEquals(0.85, entry.getScore(), 0.001);
		assertEquals("Match found", entry.getSummary());
		assertEquals("main", entry.getFunctionName());
		assertTrue(entry.hasEvidence());
		assertEquals("ev-123", entry.getEvidenceId().orElse(null));
	}

	@Test
	public void testCreateFromQueryResultNoFunction() {
		Address addr = createTestAddress(0x402000);
		QueryResult result = new TestQueryResult(addr, 0.5, "Some match", null);

		SearchResultEntry entry = new SearchResultEntry(result, null);

		assertEquals(addr, entry.getAddress());
		assertEquals("<unknown>", entry.getFunctionName());
		assertFalse(entry.hasEvidence());
		assertTrue(entry.getEvidenceId().isEmpty());
	}

	@Test
	public void testCreateWithExplicitValues() {
		Address addr = createTestAddress(0x403000);

		SearchResultEntry entry = new SearchResultEntry(
			addr, 0.95, "Exact match", "evidence-abc", "encryptData");

		assertEquals(addr, entry.getAddress());
		assertEquals(0.95, entry.getScore(), 0.001);
		assertEquals("Exact match", entry.getSummary());
		assertEquals("evidence-abc", entry.getEvidenceId().orElse(null));
		assertEquals("encryptData", entry.getFunctionName());
	}

	@Test
	public void testGetScorePercent() {
		Address addr = createTestAddress(0x401000);
		SearchResultEntry entry = new SearchResultEntry(addr, 0.875, "Test", null, "func");

		assertEquals("87.5%", entry.getScorePercent());
	}

	@Test
	public void testGetScorePercentZero() {
		Address addr = createTestAddress(0x401000);
		SearchResultEntry entry = new SearchResultEntry(addr, 0.0, "Test", null, "func");

		assertEquals("0.0%", entry.getScorePercent());
	}

	@Test
	public void testGetScorePercentFull() {
		Address addr = createTestAddress(0x401000);
		SearchResultEntry entry = new SearchResultEntry(addr, 1.0, "Test", null, "func");

		assertEquals("100.0%", entry.getScorePercent());
	}

	@Test
	public void testNullSummary() {
		Address addr = createTestAddress(0x401000);
		SearchResultEntry entry = new SearchResultEntry(addr, 0.5, null, null, "func");

		assertEquals("", entry.getSummary());
	}

	@Test
	public void testEqualsAndHashCode() {
		Address addr = createTestAddress(0x401000);

		SearchResultEntry entry1 = new SearchResultEntry(addr, 0.85, "Test 1", null, "func");
		SearchResultEntry entry2 = new SearchResultEntry(addr, 0.85, "Test 2", "ev-1", "other");

		// Same address and score should be equal
		assertEquals(entry1, entry2);
		assertEquals(entry1.hashCode(), entry2.hashCode());
	}

	@Test
	public void testNotEqualsDifferentAddress() {
		Address addr1 = createTestAddress(0x401000);
		Address addr2 = createTestAddress(0x402000);

		SearchResultEntry entry1 = new SearchResultEntry(addr1, 0.85, "Test", null, "func");
		SearchResultEntry entry2 = new SearchResultEntry(addr2, 0.85, "Test", null, "func");

		assertNotEquals(entry1, entry2);
	}

	@Test
	public void testNotEqualsDifferentScore() {
		Address addr = createTestAddress(0x401000);

		SearchResultEntry entry1 = new SearchResultEntry(addr, 0.85, "Test", null, "func");
		SearchResultEntry entry2 = new SearchResultEntry(addr, 0.90, "Test", null, "func");

		assertNotEquals(entry1, entry2);
	}

	@Test
	public void testEqualsSameObject() {
		Address addr = createTestAddress(0x401000);
		SearchResultEntry entry = new SearchResultEntry(addr, 0.85, "Test", null, "func");

		assertEquals(entry, entry);
	}

	@Test
	public void testEqualsNull() {
		Address addr = createTestAddress(0x401000);
		SearchResultEntry entry = new SearchResultEntry(addr, 0.85, "Test", null, "func");

		assertNotEquals(entry, null);
	}

	@Test
	public void testToString() {
		Address addr = createTestAddress(0x401000);
		SearchResultEntry entry = new SearchResultEntry(addr, 0.85, "Test", null, "myFunc");

		String str = entry.toString();
		assertTrue(str.contains("401000"));
		assertTrue(str.contains("0.85"));
		assertTrue(str.contains("myFunc"));
	}

	@Test(expected = NullPointerException.class)
	public void testConstructorNullResult() {
		new SearchResultEntry(null, "func");
	}

	private Address createTestAddress(long offset) {
		GenericAddressSpace space = new GenericAddressSpace("ram", 32,
			ghidra.program.model.address.AddressSpace.TYPE_RAM, 0);
		return space.getAddress(offset);
	}

	/**
	 * Test implementation of QueryResult.
	 */
	private static class TestQueryResult implements QueryResult {
		private final Address address;
		private final double score;
		private final String summary;
		private final String evidenceId;

		TestQueryResult(Address address, double score, String summary, String evidenceId) {
			this.address = address;
			this.score = score;
			this.summary = summary;
			this.evidenceId = evidenceId;
		}

		@Override
		public Address getAddress() {
			return address;
		}

		@Override
		public double getScore() {
			return score;
		}

		@Override
		public String getSummary() {
			return summary;
		}

		@Override
		public Optional<String> getEvidenceId() {
			return Optional.ofNullable(evidenceId);
		}
	}
}
