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
import java.util.List;

import org.junit.Before;
import org.junit.Test;

import ghidra.security.audit.InMemorySecurityAuditLogger;
import ghidra.security.audit.SecurityAuditEvent;
import ghidra.security.audit.SecurityAuditEventType;
import ghidra.security.capability.CapabilityToken;
import ghidra.security.credential.CredentialBroker.TokenValidationResult;
import ghidra.security.credential.CredentialBroker.ValidationStatus;
import ghidra.security.credential.RevocationRegistry.RevocationReason;

/**
 * Tests for {@link CredentialBroker} covering token issuance, validation,
 * and failure scenarios for expired, revoked, and replayed credentials.
 */
public class CredentialBrokerTest {

	private InMemoryRevocationRegistry revocationRegistry;
	private InMemorySecurityAuditLogger auditLogger;
	private CredentialBroker broker;

	@Before
	public void setUp() {
		revocationRegistry = new InMemoryRevocationRegistry();
		auditLogger = new InMemorySecurityAuditLogger();
		broker = new CredentialBroker(revocationRegistry, auditLogger, "test-broker");
	}

	// ===== Token Issuance Tests =====

	@Test
	public void testIssueToken_withDefaultTTL() {
		CapabilityToken token = broker.issueToken("agent:test", PermissionProfile.ANNOTATOR);

		assertNotNull(token);
		assertNotNull(token.getTokenId());
		assertEquals("agent:test", token.getPrincipal());
		assertEquals("annotator", token.getProfile());
		assertFalse(token.isExpired());

		// TTL should be approximately 8 hours
		Duration ttl = Duration.between(token.getIssuedAt(), token.getExpiresAt());
		assertEquals(CredentialBroker.DEFAULT_TTL.toHours(), ttl.toHours());

		// Audit event should be logged
		List<SecurityAuditEvent> events = auditLogger.getAllEvents();
		assertEquals(1, events.size());
		assertEquals(SecurityAuditEventType.TOKEN_CREATED, events.get(0).getEventType());
	}

	@Test
	public void testIssueToken_withCustomTTL() {
		Duration customTTL = Duration.ofHours(2);
		CapabilityToken token = broker.issueToken(
			"agent:custom", PermissionProfile.OBSERVER, customTTL);

		Duration actualTTL = Duration.between(token.getIssuedAt(), token.getExpiresAt());
		assertEquals(customTTL.toMinutes(), actualTTL.toMinutes());
	}

	@Test(expected = IllegalArgumentException.class)
	public void testIssueToken_ttlBelowMinimum_throws() {
		broker.issueToken("agent:test", PermissionProfile.OBSERVER, Duration.ofSeconds(30));
	}

	@Test(expected = IllegalArgumentException.class)
	public void testIssueToken_ttlAboveMaximum_throws() {
		broker.issueToken("agent:test", PermissionProfile.OBSERVER, Duration.ofHours(48));
	}

	@Test
	public void testIssueToken_withScope() {
		CapabilityToken.TokenScope scope = new CapabilityToken.TokenScope(
			java.util.Set.of("firmware.bin"),
			100,
			true
		);

		CapabilityToken token = broker.issueToken(
			"agent:scoped", PermissionProfile.ANALYST, Duration.ofHours(4), scope, false);

		assertEquals(scope, token.getScope());
		assertTrue(token.getScope().isProgramAllowed("firmware.bin"));
		assertFalse(token.getScope().isProgramAllowed("other.bin"));
	}

	// ===== Expired Token Tests =====

	@Test
	public void testValidateToken_expired_returnsExpiredStatus() {
		// Issue a token with minimal TTL, then simulate expiration
		CapabilityToken token = CapabilityToken.builder()
			.principal("agent:expired")
			.profile("annotator")
			.capabilities(PermissionProfile.ANNOTATOR.getCapabilities())
			.expiresAt(Instant.now().minusSeconds(60)) // Already expired
			.build();

		TokenValidationResult result = broker.validateToken(token, false);

		assertEquals(ValidationStatus.EXPIRED, result.getStatus());
		assertFalse(result.isValid());

		// Verify audit event
		List<SecurityAuditEvent> events = auditLogger.getAllEvents();
		assertTrue(events.stream()
			.anyMatch(e -> e.getEventType() == SecurityAuditEventType.TOKEN_EXPIRED));
	}

	// ===== Revoked Token Tests =====

	@Test
	public void testValidateToken_revoked_returnsRevokedStatus() {
		CapabilityToken token = broker.issueToken("agent:revoked", PermissionProfile.ANNOTATOR);

		// Revoke the token
		broker.revokeToken(token.getTokenId(), RevocationReason.MANUAL_REVOCATION, "admin:test");

		// Validate should fail
		TokenValidationResult result = broker.validateToken(token, false);

		assertEquals(ValidationStatus.REVOKED, result.getStatus());
		assertFalse(result.isValid());
		assertNotNull(result.getRevocationRecord());
		assertEquals(RevocationReason.MANUAL_REVOCATION, result.getRevocationRecord().getReason());
	}

	@Test
	public void testRevokeToken_logsAuditEvent() {
		CapabilityToken token = broker.issueToken("agent:test", PermissionProfile.ANNOTATOR);

		int eventsBefore = auditLogger.getAllEvents().size();
		broker.revokeToken(token.getTokenId(), RevocationReason.SECURITY_INCIDENT, "admin:security");

		List<SecurityAuditEvent> events = auditLogger.getAllEvents();
		assertTrue(events.size() > eventsBefore);
		assertTrue(events.stream()
			.anyMatch(e -> e.getEventType() == SecurityAuditEventType.TOKEN_REVOKED));
	}

	@Test
	public void testRevokeAllForPrincipal_revokesMultipleTokens() {
		// Issue multiple tokens to same principal
		broker.issueToken("agent:bulk", PermissionProfile.ANNOTATOR);
		broker.issueToken("agent:bulk", PermissionProfile.OBSERVER);
		broker.issueToken("agent:bulk", PermissionProfile.ANALYST);

		List<RevocationRegistry.RevocationRecord> records =
			broker.revokeAllForPrincipal("agent:bulk", RevocationReason.PRINCIPAL_DEACTIVATED, "admin");

		assertEquals(3, records.size());
	}

	@Test
	public void testIsRevoked_returnsCorrectStatus() {
		CapabilityToken token = broker.issueToken("agent:check", PermissionProfile.ANNOTATOR);

		assertFalse(broker.isRevoked(token.getTokenId()));

		broker.revokeToken(token.getTokenId(), RevocationReason.MANUAL_REVOCATION, "admin");

		assertTrue(broker.isRevoked(token.getTokenId()));
	}

	// ===== Replayed Token Tests =====

	@Test
	public void testValidateToken_oneTimeUse_succeedsFirstTime() {
		CapabilityToken token = broker.issueOneTimeToken(
			"agent:onetime", PermissionProfile.ANNOTATOR, Duration.ofHours(1));

		TokenValidationResult result = broker.validateToken(token, true);

		assertEquals(ValidationStatus.VALID, result.getStatus());
		assertTrue(result.isValid());
	}

	@Test
	public void testValidateToken_oneTimeUse_failsOnReplay() {
		CapabilityToken token = broker.issueOneTimeToken(
			"agent:onetime", PermissionProfile.ANNOTATOR, Duration.ofHours(1));

		// First use succeeds
		TokenValidationResult firstResult = broker.validateToken(token, true);
		assertTrue(firstResult.isValid());

		// Second use fails (replay)
		TokenValidationResult secondResult = broker.validateToken(token, true);
		assertEquals(ValidationStatus.REPLAYED, secondResult.getStatus());
		assertFalse(secondResult.isValid());

		// Verify critical audit event for replay
		assertTrue(auditLogger.getAllEvents().stream()
			.anyMatch(e -> e.getEventType() == SecurityAuditEventType.TOKEN_REPLAYED));
	}

	@Test
	public void testValidateToken_normalToken_canBeUsedMultipleTimes() {
		CapabilityToken token = broker.issueToken("agent:normal", PermissionProfile.ANNOTATOR);

		// Multiple validations should all succeed
		for (int i = 0; i < 5; i++) {
			TokenValidationResult result = broker.validateToken(token, false);
			assertTrue("Validation " + i + " should succeed", result.isValid());
		}
	}

	// ===== Permission Profile Tests =====

	@Test
	public void testIssueToken_observerProfile_hasOnlyReadCapabilities() {
		CapabilityToken token = broker.issueToken("agent:observer", PermissionProfile.OBSERVER);

		assertTrue(token.hasCapability("READ.DECOMPILE"));
		assertTrue(token.hasCapability("READ.NAVIGATE"));
		assertFalse(token.hasCapability("WRITE.RENAME"));
		assertFalse(token.hasCapability("EXECUTE.SCRIPT"));
	}

	@Test
	public void testIssueToken_annotatorProfile_hasReadAndAnnotateCapabilities() {
		CapabilityToken token = broker.issueToken("agent:annotator", PermissionProfile.ANNOTATOR);

		assertTrue(token.hasCapability("READ.DECOMPILE"));
		assertTrue(token.hasCapability("WRITE.RENAME"));
		assertTrue(token.hasCapability("WRITE.ANNOTATE"));
		assertFalse(token.hasCapability("WRITE.PATCH"));
		assertFalse(token.hasCapability("EXECUTE.SCRIPT"));
	}

	@Test
	public void testIssueToken_engineerProfile_hasWriteAndScriptCapabilities() {
		CapabilityToken token = broker.issueToken("agent:engineer", PermissionProfile.ENGINEER);

		assertTrue(token.hasCapability("READ.DECOMPILE"));
		assertTrue(token.hasCapability("WRITE.PATCH"));
		assertTrue(token.hasCapability("EXECUTE.SCRIPT"));
	}

	@Test
	public void testIssueToken_adminProfile_hasAllCapabilities() {
		CapabilityToken token = broker.issueToken("admin:super", PermissionProfile.ADMIN);

		assertTrue(token.hasCapability("ADMIN"));
		assertTrue(token.hasCapability("READ.DECOMPILE"));
		assertTrue(token.hasCapability("WRITE.PATCH"));
		assertTrue(token.hasCapability("EXECUTE.SCRIPT"));
	}

	// ===== Combined Failure Scenarios =====

	@Test
	public void testValidateToken_expiredAndRevoked_returnsExpired() {
		// Create an expired token
		CapabilityToken token = CapabilityToken.builder()
			.principal("agent:test")
			.profile("annotator")
			.capabilities(PermissionProfile.ANNOTATOR.getCapabilities())
			.expiresAt(Instant.now().minusSeconds(60))
			.build();

		// Also revoke it
		revocationRegistry.revoke(token.getTokenId(), RevocationReason.MANUAL_REVOCATION, "admin");

		// Expiration check comes first
		TokenValidationResult result = broker.validateToken(token, false);
		assertEquals(ValidationStatus.EXPIRED, result.getStatus());
	}

	@Test
	public void testValidateToken_revokedAndReplayed_returnsRevoked() {
		CapabilityToken token = broker.issueOneTimeToken(
			"agent:test", PermissionProfile.ANNOTATOR, Duration.ofHours(1));

		// Use it once
		broker.validateToken(token, true);

		// Then revoke it
		broker.revokeToken(token.getTokenId(), RevocationReason.MANUAL_REVOCATION, "admin");

		// Revocation check comes before replay check
		TokenValidationResult result = broker.validateToken(token, true);
		assertEquals(ValidationStatus.REVOKED, result.getStatus());
	}
}
