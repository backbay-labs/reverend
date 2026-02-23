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

import java.time.Duration;
import java.time.Instant;

import org.junit.Before;
import org.junit.Test;

import ghidra.security.audit.InMemorySecurityAuditLogger;
import ghidra.security.audit.SecurityAuditEvent;
import ghidra.security.audit.SecurityAuditEventType;
import ghidra.security.capability.*;
import ghidra.security.capability.CapabilityDeniedException.DenialReason;
import ghidra.security.credential.RevocationRegistry.RevocationReason;

/**
 * Tests for {@link RevocationAwareCapabilityGuard} covering revocation and replay detection.
 */
public class RevocationAwareCapabilityGuardTest {

	private InMemoryRevocationRegistry revocationRegistry;
	private InMemorySecurityAuditLogger auditLogger;

	@Before
	public void setUp() {
		revocationRegistry = new InMemoryRevocationRegistry();
		auditLogger = new InMemorySecurityAuditLogger();
	}

	private CapabilityToken createValidToken(String principal, PermissionProfile profile) {
		return CapabilityToken.builder()
			.principal(principal)
			.profile(profile.getName())
			.capabilities(profile.getCapabilities())
			.expiresAt(Instant.now().plus(Duration.ofHours(1)))
			.build();
	}

	// ===== Revocation Tests =====

	@Test
	public void testAssertCapability_validToken_succeeds() throws CapabilityDeniedException {
		CapabilityToken token = createValidToken("agent:test", PermissionProfile.ANNOTATOR);
		RevocationAwareCapabilityGuard guard =
			RevocationAwareCapabilityGuard.forNormalUse(token, revocationRegistry, auditLogger);

		// Should not throw
		guard.assertCapability(Capability.WRITE_RENAME, "rename function");
	}

	@Test
	public void testAssertCapability_revokedToken_throws() {
		CapabilityToken token = createValidToken("agent:test", PermissionProfile.ANNOTATOR);
		revocationRegistry.revoke(token.getTokenId(), RevocationReason.MANUAL_REVOCATION, "admin");

		RevocationAwareCapabilityGuard guard =
			RevocationAwareCapabilityGuard.forNormalUse(token, revocationRegistry, auditLogger);

		try {
			guard.assertCapability(Capability.WRITE_RENAME, "rename function");
			fail("Expected CapabilityDeniedException");
		}
		catch (CapabilityDeniedException e) {
			assertEquals(DenialReason.TOKEN_REVOKED, e.getReason());
			assertEquals(Capability.WRITE_RENAME, e.getDeniedCapability());
		}
	}

	@Test
	public void testAssertCapability_revokedToken_logsAuditEvent() {
		CapabilityToken token = createValidToken("agent:test", PermissionProfile.ANNOTATOR);
		revocationRegistry.revoke(token.getTokenId(), RevocationReason.SECURITY_INCIDENT, "admin");

		RevocationAwareCapabilityGuard guard =
			RevocationAwareCapabilityGuard.forNormalUse(token, revocationRegistry, auditLogger);

		try {
			guard.assertCapability(Capability.WRITE_RENAME, "rename function");
		}
		catch (CapabilityDeniedException e) {
			// Expected
		}

		assertTrue(auditLogger.getAllEvents().stream()
			.anyMatch(e -> e.getEventType() == SecurityAuditEventType.TOKEN_REVOKED_ATTEMPT));
	}

	@Test
	public void testHasCapability_revokedToken_returnsFalse() {
		CapabilityToken token = createValidToken("agent:test", PermissionProfile.ANNOTATOR);
		revocationRegistry.revoke(token.getTokenId(), RevocationReason.MANUAL_REVOCATION, "admin");

		RevocationAwareCapabilityGuard guard =
			RevocationAwareCapabilityGuard.forNormalUse(token, revocationRegistry, auditLogger);

		assertFalse(guard.hasCapability(Capability.WRITE_RENAME));
	}

	@Test
	public void testIsRevoked_returnsCorrectStatus() {
		CapabilityToken token = createValidToken("agent:test", PermissionProfile.ANNOTATOR);
		RevocationAwareCapabilityGuard guard =
			RevocationAwareCapabilityGuard.forNormalUse(token, revocationRegistry, auditLogger);

		assertFalse(guard.isRevoked());

		revocationRegistry.revoke(token.getTokenId(), RevocationReason.MANUAL_REVOCATION, "admin");

		assertTrue(guard.isRevoked());
	}

	// ===== Replay Tests =====

	@Test
	public void testAssertCapability_oneTimeToken_succeedsFirstTime()
			throws CapabilityDeniedException {
		CapabilityToken token = createValidToken("agent:test", PermissionProfile.ANNOTATOR);
		RevocationAwareCapabilityGuard guard =
			RevocationAwareCapabilityGuard.forOneTimeUse(token, revocationRegistry, auditLogger);

		// Should succeed first time
		guard.assertCapability(Capability.WRITE_RENAME, "rename function");
	}

	@Test
	public void testAssertCapability_oneTimeToken_failsOnReplay() throws CapabilityDeniedException {
		CapabilityToken token = createValidToken("agent:test", PermissionProfile.ANNOTATOR);
		RevocationAwareCapabilityGuard guard =
			RevocationAwareCapabilityGuard.forOneTimeUse(token, revocationRegistry, auditLogger);

		// First use succeeds
		guard.assertCapability(Capability.WRITE_RENAME, "rename function");

		// Second use should fail
		try {
			guard.assertCapability(Capability.WRITE_RENAME, "rename again");
			fail("Expected CapabilityDeniedException");
		}
		catch (CapabilityDeniedException e) {
			assertEquals(DenialReason.TOKEN_REPLAYED, e.getReason());
		}
	}

	@Test
	public void testAssertCapability_oneTimeToken_replay_logsCriticalEvent()
			throws CapabilityDeniedException {
		CapabilityToken token = createValidToken("agent:test", PermissionProfile.ANNOTATOR);
		RevocationAwareCapabilityGuard guard =
			RevocationAwareCapabilityGuard.forOneTimeUse(token, revocationRegistry, auditLogger);

		guard.assertCapability(Capability.WRITE_RENAME, "first use");

		try {
			guard.assertCapability(Capability.WRITE_RENAME, "replay attempt");
		}
		catch (CapabilityDeniedException e) {
			// Expected
		}

		assertTrue(auditLogger.getAllEvents().stream()
			.anyMatch(e -> e.getEventType() == SecurityAuditEventType.TOKEN_REPLAYED));
	}

	@Test
	public void testHasCapability_usedOneTimeToken_returnsFalse()
			throws CapabilityDeniedException {
		CapabilityToken token = createValidToken("agent:test", PermissionProfile.ANNOTATOR);
		RevocationAwareCapabilityGuard guard =
			RevocationAwareCapabilityGuard.forOneTimeUse(token, revocationRegistry, auditLogger);

		assertTrue(guard.hasCapability(Capability.WRITE_RENAME));

		guard.assertCapability(Capability.WRITE_RENAME, "use token");

		assertFalse(guard.hasCapability(Capability.WRITE_RENAME));
	}

	@Test
	public void testIsUsed_tracksOneTimeTokenUsage() throws CapabilityDeniedException {
		CapabilityToken token = createValidToken("agent:test", PermissionProfile.ANNOTATOR);
		RevocationAwareCapabilityGuard guard =
			RevocationAwareCapabilityGuard.forOneTimeUse(token, revocationRegistry, auditLogger);

		assertFalse(guard.isUsed());

		guard.assertCapability(Capability.WRITE_RENAME, "use token");

		assertTrue(guard.isUsed());
	}

	@Test
	public void testNormalToken_canBeUsedMultipleTimes() throws CapabilityDeniedException {
		CapabilityToken token = createValidToken("agent:test", PermissionProfile.ANNOTATOR);
		RevocationAwareCapabilityGuard guard =
			RevocationAwareCapabilityGuard.forNormalUse(token, revocationRegistry, auditLogger);

		// Multiple uses should all succeed
		for (int i = 0; i < 5; i++) {
			guard.assertCapability(Capability.WRITE_RENAME, "use " + i);
		}

		assertFalse(guard.isOneTimeUse());
	}

	// ===== Expiration Tests =====

	@Test
	public void testAssertCapability_expiredToken_throws() {
		CapabilityToken token = CapabilityToken.builder()
			.principal("agent:test")
			.profile("annotator")
			.capabilities(PermissionProfile.ANNOTATOR.getCapabilities())
			.expiresAt(Instant.now().minusSeconds(60)) // Already expired
			.build();

		RevocationAwareCapabilityGuard guard =
			RevocationAwareCapabilityGuard.forNormalUse(token, revocationRegistry, auditLogger);

		try {
			guard.assertCapability(Capability.WRITE_RENAME, "test operation");
			fail("Expected CapabilityDeniedException");
		}
		catch (CapabilityDeniedException e) {
			assertEquals(DenialReason.TOKEN_EXPIRED, e.getReason());
		}
	}

	// ===== Capability Tests =====

	@Test
	public void testAssertCapability_insufficientCapability_throws() {
		CapabilityToken token = createValidToken("agent:test", PermissionProfile.OBSERVER);
		RevocationAwareCapabilityGuard guard =
			RevocationAwareCapabilityGuard.forNormalUse(token, revocationRegistry, auditLogger);

		try {
			guard.assertCapability(Capability.WRITE_RENAME, "try to write");
			fail("Expected CapabilityDeniedException");
		}
		catch (CapabilityDeniedException e) {
			assertEquals(DenialReason.CAPABILITY_NOT_GRANTED, e.getReason());
		}
	}

	@Test
	public void testAssertCapability_success_logsGrantedEvent() throws CapabilityDeniedException {
		CapabilityToken token = createValidToken("agent:test", PermissionProfile.ANNOTATOR);
		RevocationAwareCapabilityGuard guard =
			RevocationAwareCapabilityGuard.forNormalUse(token, revocationRegistry, auditLogger);

		guard.assertCapability(Capability.WRITE_RENAME, "rename function");

		assertTrue(auditLogger.getAllEvents().stream()
			.anyMatch(e -> e.getEventType() == SecurityAuditEventType.CAPABILITY_GRANTED));
	}

	// ===== Program Scope Tests =====

	@Test
	public void testAssertCapabilityForProgram_validScope_succeeds()
			throws CapabilityDeniedException {
		CapabilityToken.TokenScope scope = new CapabilityToken.TokenScope(
			java.util.Set.of("allowed.bin"), null, false);

		CapabilityToken token = CapabilityToken.builder()
			.principal("agent:test")
			.profile("annotator")
			.capabilities(PermissionProfile.ANNOTATOR.getCapabilities())
			.expiresAt(Instant.now().plus(Duration.ofHours(1)))
			.scope(scope)
			.build();

		RevocationAwareCapabilityGuard guard =
			RevocationAwareCapabilityGuard.forNormalUse(token, revocationRegistry, auditLogger);

		guard.assertCapabilityForProgram(Capability.WRITE_RENAME, "allowed.bin", "rename in allowed");
	}

	@Test
	public void testAssertCapabilityForProgram_revokedToken_throws() {
		CapabilityToken token = createValidToken("agent:test", PermissionProfile.ANNOTATOR);
		revocationRegistry.revoke(token.getTokenId(), RevocationReason.MANUAL_REVOCATION, "admin");

		RevocationAwareCapabilityGuard guard =
			RevocationAwareCapabilityGuard.forNormalUse(token, revocationRegistry, auditLogger);

		try {
			guard.assertCapabilityForProgram(Capability.WRITE_RENAME, "test.bin", "operation");
			fail("Expected CapabilityDeniedException");
		}
		catch (CapabilityDeniedException e) {
			assertEquals(DenialReason.TOKEN_REVOKED, e.getReason());
		}
	}

	@Test
	public void testHasCapabilityForProgram_revokedToken_returnsFalse() {
		CapabilityToken token = createValidToken("agent:test", PermissionProfile.ANNOTATOR);
		RevocationAwareCapabilityGuard guard =
			RevocationAwareCapabilityGuard.forNormalUse(token, revocationRegistry, auditLogger);

		assertTrue(guard.hasCapabilityForProgram(Capability.WRITE_RENAME, "test.bin"));

		revocationRegistry.revoke(token.getTokenId(), RevocationReason.MANUAL_REVOCATION, "admin");

		assertFalse(guard.hasCapabilityForProgram(Capability.WRITE_RENAME, "test.bin"));
	}

	// ===== Factory Method Tests =====

	@Test
	public void testForOneTimeUse_createsOneTimeGuard() {
		CapabilityToken token = createValidToken("agent:test", PermissionProfile.ANNOTATOR);
		RevocationAwareCapabilityGuard guard =
			RevocationAwareCapabilityGuard.forOneTimeUse(token, revocationRegistry, auditLogger);

		assertTrue(guard.isOneTimeUse());
	}

	@Test
	public void testForNormalUse_createsNormalGuard() {
		CapabilityToken token = createValidToken("agent:test", PermissionProfile.ANNOTATOR);
		RevocationAwareCapabilityGuard guard =
			RevocationAwareCapabilityGuard.forNormalUse(token, revocationRegistry, auditLogger);

		assertFalse(guard.isOneTimeUse());
	}
}
