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
package ghidra.security.audit;

import static org.junit.Assert.*;

import org.junit.Test;

import ghidra.security.capability.*;

/**
 * Tests for {@link ViolationIncident}.
 */
public class ViolationIncidentTest {

	@Test
	public void testBasicIncidentCreation() {
		SecurityAuditEvent event = SecurityAuditEvent.builder()
			.eventType(SecurityAuditEventType.CAPABILITY_DENIED)
			.principal("agent:test")
			.sessionId("session-001")
			.detail("denied_capability", "WRITE.PATCH")
			.build();

		ViolationIncident incident = ViolationIncident.builder()
			.event(event)
			.policyName("capability-token-policy")
			.policyVersion("1.0")
			.violatedConstraint("Capability WRITE.PATCH not granted to profile 'annotator'")
			.remediationAction(ViolationIncident.RemediationAction.BLOCKED)
			.remediationDetails("Operation denied")
			.escalated(false)
			.build();

		assertNotNull(incident.getIncidentId());
		assertEquals(event, incident.getEvent());
		assertEquals("capability-token-policy", incident.getPolicyName());
		assertEquals("1.0", incident.getPolicyVersion());
		assertEquals("Capability WRITE.PATCH not granted to profile 'annotator'",
			incident.getViolatedConstraint());
		assertEquals(ViolationIncident.RemediationAction.BLOCKED, incident.getRemediationAction());
		assertEquals("Operation denied", incident.getRemediationDetails());
		assertFalse(incident.isEscalated());
	}

	@Test
	public void testFromCapabilityDenial_NotGranted() {
		CapabilityDeniedException exception = CapabilityDeniedException.capabilityNotGranted(
			createAnnotatorToken(),
			Capability.WRITE_PATCH,
			"patch bytes at 0x401000");

		ViolationIncident incident = ViolationIncident.fromCapabilityDenial(
			exception, "session-001", "token-001");

		assertEquals(SecurityAuditEventType.CAPABILITY_DENIED, incident.getViolationType());
		assertEquals(Severity.WARNING, incident.getSeverity());
		assertEquals("agent:claude-opus-4-6", incident.getPrincipal());
		assertEquals("session-001", incident.getSessionId());
		assertEquals("capability-token-policy", incident.getPolicyName());
		assertEquals(ViolationIncident.RemediationAction.BLOCKED, incident.getRemediationAction());
		assertFalse(incident.isEscalated());

		// Check details
		assertEquals("WRITE.PATCH", incident.getDetails().get("denied_capability"));
		assertEquals("CAPABILITY_NOT_GRANTED", incident.getDetails().get("denial_reason"));
		assertEquals("annotator", incident.getDetails().get("profile"));
	}

	@Test
	public void testFromCapabilityDenial_TokenExpired() {
		CapabilityDeniedException exception = CapabilityDeniedException.tokenExpired(
			createExpiredToken(),
			Capability.READ,
			"read something");

		ViolationIncident incident = ViolationIncident.fromCapabilityDenial(
			exception, "session-001", "token-001");

		assertEquals(SecurityAuditEventType.TOKEN_EXPIRED, incident.getViolationType());
		assertEquals("TOKEN_EXPIRED", incident.getDetails().get("denial_reason"));
	}

	@Test
	public void testFromCapabilityDenial_ScopeViolation() {
		CapabilityDeniedException exception = CapabilityDeniedException.scopeViolation(
			createAnnotatorToken(),
			Capability.READ_DECOMPILE,
			"access restricted program");

		ViolationIncident incident = ViolationIncident.fromCapabilityDenial(
			exception, "session-001", "token-001");

		assertEquals(SecurityAuditEventType.SCOPE_VIOLATION, incident.getViolationType());
		assertEquals("SCOPE_VIOLATION", incident.getDetails().get("denial_reason"));
	}

	@Test
	public void testFromCapabilityDenial_MutationLimitExceeded() {
		CapabilityDeniedException exception = new CapabilityDeniedException(
			Capability.WRITE_RENAME,
			CapabilityDeniedException.DenialReason.MUTATION_LIMIT_EXCEEDED,
			"annotator",
			"agent:claude-opus-4-6",
			"rename function");

		ViolationIncident incident = ViolationIncident.fromCapabilityDenial(
			exception, "session-001", "token-001");

		assertEquals(SecurityAuditEventType.MUTATION_LIMIT_EXCEEDED, incident.getViolationType());
		assertEquals("MUTATION_LIMIT_EXCEEDED", incident.getDetails().get("denial_reason"));
	}

	@Test
	public void testIncidentDelegation() {
		SecurityAuditEvent event = SecurityAuditEvent.builder()
			.eventType(SecurityAuditEventType.CAPABILITY_DENIED)
			.principal("agent:test")
			.sessionId("session-001")
			.build();

		ViolationIncident incident = ViolationIncident.builder()
			.event(event)
			.policyName("test-policy")
			.violatedConstraint("test constraint")
			.remediationAction(ViolationIncident.RemediationAction.LOGGED_ONLY)
			.build();

		// These should delegate to the event
		assertEquals(event.getTimestamp(), incident.getTimestamp());
		assertEquals(event.getSeverity(), incident.getSeverity());
		assertEquals(event.getPrincipal(), incident.getPrincipal());
		assertEquals(event.getSessionId(), incident.getSessionId());
		assertEquals(event.getEventType(), incident.getViolationType());
	}

	@Test
	public void testRemediationActionDescriptions() {
		assertNotNull(ViolationIncident.RemediationAction.BLOCKED.getDescription());
		assertNotNull(ViolationIncident.RemediationAction.SESSION_TERMINATED.getDescription());
		assertNotNull(ViolationIncident.RemediationAction.TOKEN_REVOKED.getDescription());
		assertNotNull(ViolationIncident.RemediationAction.ALERT_SENT.getDescription());
		assertNotNull(ViolationIncident.RemediationAction.LOGGED_ONLY.getDescription());
		assertNotNull(ViolationIncident.RemediationAction.REQUIRES_REVIEW.getDescription());
	}

	@Test
	public void testEquality() {
		SecurityAuditEvent event = SecurityAuditEvent.builder()
			.eventType(SecurityAuditEventType.CAPABILITY_DENIED)
			.principal("agent:test")
			.build();

		ViolationIncident incident1 = ViolationIncident.builder()
			.incidentId("same-id")
			.event(event)
			.policyName("policy")
			.violatedConstraint("constraint")
			.remediationAction(ViolationIncident.RemediationAction.BLOCKED)
			.build();

		ViolationIncident incident2 = ViolationIncident.builder()
			.incidentId("same-id")
			.event(event)
			.policyName("different-policy")
			.violatedConstraint("different-constraint")
			.remediationAction(ViolationIncident.RemediationAction.ALERT_SENT)
			.build();

		assertEquals(incident1, incident2);  // Same ID = equal
		assertEquals(incident1.hashCode(), incident2.hashCode());
	}

	private CapabilityToken createAnnotatorToken() {
		return CapabilityToken.builder()
			.tokenId("token-001")
			.principal("agent:claude-opus-4-6")
			.profile("annotator")
			.capabilities(java.util.List.of("READ.*", "WRITE.RENAME", "WRITE.ANNOTATE"))
			.expiresAt(java.time.Instant.now().plusSeconds(3600))
			.build();
	}

	private CapabilityToken createExpiredToken() {
		return CapabilityToken.builder()
			.tokenId("expired-001")
			.principal("agent:expired")
			.profile("annotator")
			.capabilities(java.util.List.of("READ.*"))
			.expiresAt(java.time.Instant.now().minusSeconds(3600))
			.build();
	}
}
