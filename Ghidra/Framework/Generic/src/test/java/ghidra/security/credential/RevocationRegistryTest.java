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
package ghidra.security.credential;

import static org.junit.Assert.*;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import org.junit.Before;
import org.junit.Test;

import ghidra.security.credential.RevocationRegistry.*;

/**
 * Tests for {@link RevocationRegistry} implementations.
 */
public class RevocationRegistryTest {

	private InMemoryRevocationRegistry registry;

	@Before
	public void setUp() {
		registry = new InMemoryRevocationRegistry();
	}

	@Test
	public void testRevoke_createsRecord() {
		String tokenId = UUID.randomUUID().toString();

		RevocationRecord record = registry.revoke(
			tokenId, RevocationReason.MANUAL_REVOCATION, "admin:test");

		assertNotNull(record);
		assertEquals(tokenId, record.getTokenId());
		assertEquals(RevocationReason.MANUAL_REVOCATION, record.getReason());
		assertEquals("admin:test", record.getRevokedBy());
		assertNotNull(record.getRevokedAt());
	}

	@Test
	public void testIsRevoked_returnsTrueAfterRevocation() {
		String tokenId = UUID.randomUUID().toString();

		assertFalse(registry.isRevoked(tokenId));

		registry.revoke(tokenId, RevocationReason.SECURITY_INCIDENT, "admin");

		assertTrue(registry.isRevoked(tokenId));
	}

	@Test
	public void testIsRevoked_returnsFalseForUnknownToken() {
		assertFalse(registry.isRevoked("nonexistent-token"));
	}

	@Test
	public void testGetRevocationRecord_returnsRecord() {
		String tokenId = UUID.randomUUID().toString();
		registry.revoke(tokenId, RevocationReason.POLICY_VIOLATION, "system");

		RevocationRecord record = registry.getRevocationRecord(tokenId);

		assertNotNull(record);
		assertEquals(tokenId, record.getTokenId());
		assertEquals(RevocationReason.POLICY_VIOLATION, record.getReason());
	}

	@Test
	public void testGetRevocationRecord_returnsNullForUnrevokedToken() {
		assertNull(registry.getRevocationRecord("not-revoked"));
	}

	@Test
	public void testRevokeByPrincipal_revokesAllTokensForPrincipal() {
		String principal = "agent:bulk-test";

		// Register multiple tokens for the same principal
		String token1 = UUID.randomUUID().toString();
		String token2 = UUID.randomUUID().toString();
		String token3 = UUID.randomUUID().toString();

		registry.registerToken(token1, principal);
		registry.registerToken(token2, principal);
		registry.registerToken(token3, principal);

		// Also register a token for a different principal
		String otherToken = UUID.randomUUID().toString();
		registry.registerToken(otherToken, "agent:other");

		// Revoke all tokens for the target principal
		List<RevocationRecord> records = registry.revokeByPrincipal(
			principal, RevocationReason.PRINCIPAL_DEACTIVATED, "admin");

		assertEquals(3, records.size());
		assertTrue(registry.isRevoked(token1));
		assertTrue(registry.isRevoked(token2));
		assertTrue(registry.isRevoked(token3));
		assertFalse(registry.isRevoked(otherToken));
	}

	@Test
	public void testRevokeByPrincipal_returnsEmptyForUnknownPrincipal() {
		List<RevocationRecord> records = registry.revokeByPrincipal(
			"unknown:principal", RevocationReason.MANUAL_REVOCATION, "admin");

		assertTrue(records.isEmpty());
	}

	@Test
	public void testGetRevocationsBetween_filtersCorrectly() throws InterruptedException {
		Instant before = Instant.now();
		Thread.sleep(10);

		registry.revoke("token1", RevocationReason.MANUAL_REVOCATION, "admin");
		registry.revoke("token2", RevocationReason.SECURITY_INCIDENT, "admin");

		Thread.sleep(10);
		Instant middle = Instant.now();
		Thread.sleep(10);

		registry.revoke("token3", RevocationReason.KEY_ROTATION, "system");

		Thread.sleep(10);
		Instant after = Instant.now();

		// Query all
		List<RevocationRecord> all = registry.getRevocationsBetween(before, after);
		assertEquals(3, all.size());

		// Query first two only
		List<RevocationRecord> first = registry.getRevocationsBetween(before, middle);
		assertEquals(2, first.size());

		// Query last one only
		List<RevocationRecord> last = registry.getRevocationsBetween(middle, after);
		assertEquals(1, last.size());
		assertEquals("token3", last.get(0).getTokenId());
	}

	@Test
	public void testGetRevocationCount_returnsCorrectCount() {
		assertEquals(0, registry.getRevocationCount());

		registry.revoke("token1", RevocationReason.MANUAL_REVOCATION, "admin");
		assertEquals(1, registry.getRevocationCount());

		registry.revoke("token2", RevocationReason.MANUAL_REVOCATION, "admin");
		assertEquals(2, registry.getRevocationCount());

		// Re-revoking same token should update, not add
		registry.revoke("token1", RevocationReason.SECURITY_INCIDENT, "admin");
		assertEquals(2, registry.getRevocationCount());
	}

	@Test
	public void testPruneExpiredRecords_removesOldRecords() throws InterruptedException {
		registry.revoke("old-token", RevocationReason.MANUAL_REVOCATION, "admin");
		Thread.sleep(50);
		Instant cutoff = Instant.now();
		Thread.sleep(10);
		registry.revoke("new-token", RevocationReason.MANUAL_REVOCATION, "admin");

		int removed = registry.pruneExpiredRecords(cutoff);

		assertEquals(1, removed);
		assertFalse(registry.isRevoked("old-token"));
		assertTrue(registry.isRevoked("new-token"));
	}

	@Test
	public void testClear_removesAllRecords() {
		registry.revoke("token1", RevocationReason.MANUAL_REVOCATION, "admin");
		registry.revoke("token2", RevocationReason.MANUAL_REVOCATION, "admin");

		assertEquals(2, registry.getRevocationCount());

		registry.clear();

		assertEquals(0, registry.getRevocationCount());
		assertFalse(registry.isRevoked("token1"));
		assertFalse(registry.isRevoked("token2"));
	}

	@Test
	public void testRevocationReasons_haveDescriptions() {
		for (RevocationReason reason : RevocationReason.values()) {
			assertNotNull(reason.getDescription());
			assertFalse(reason.getDescription().isEmpty());
		}
	}

	@Test
	public void testRevocationRecord_toString_containsKeyInfo() {
		RevocationRecord record = new RevocationRecord(
			"test-token",
			Instant.now(),
			RevocationReason.SECURITY_INCIDENT,
			"admin:security",
			"agent:target"
		);

		String str = record.toString();
		assertTrue(str.contains("test-token"));
		assertTrue(str.contains("SECURITY_INCIDENT"));
		assertTrue(str.contains("admin:security"));
	}
}
