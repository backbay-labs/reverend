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

import java.time.Instant;
import java.util.Map;

import org.junit.Test;

/**
 * Tests for {@link SecurityAuditEvent}.
 */
public class SecurityAuditEventTest {

	@Test
	public void testBasicEventCreation() {
		SecurityAuditEvent event = SecurityAuditEvent.builder()
			.eventType(SecurityAuditEventType.CAPABILITY_GRANTED)
			.principal("agent:claude-opus-4-6")
			.sessionId("session-001")
			.detail("capability", "READ.DECOMPILE")
			.detail("operation", "decompile function at 0x401000")
			.context("program", "firmware.gzf")
			.build();

		assertNotNull(event.getEventId());
		assertNotNull(event.getTimestamp());
		assertEquals(SecurityAuditEventType.CAPABILITY_GRANTED, event.getEventType());
		assertEquals(Severity.INFO, event.getSeverity());
		assertEquals("agent:claude-opus-4-6", event.getPrincipal());
		assertEquals("session-001", event.getSessionId());
		assertEquals("READ.DECOMPILE", event.getDetail("capability"));
		assertEquals("firmware.gzf", event.getContextValue("program"));
		assertFalse(event.isViolation());
	}

	@Test
	public void testViolationEvent() {
		SecurityAuditEvent event = SecurityAuditEvent.builder()
			.eventType(SecurityAuditEventType.CAPABILITY_DENIED)
			.principal("agent:test")
			.detail("denied_capability", "WRITE.PATCH")
			.build();

		assertTrue(event.isViolation());
		assertEquals(Severity.WARNING, event.getSeverity());
	}

	@Test
	public void testCriticalEvent() {
		SecurityAuditEvent event = SecurityAuditEvent.builder()
			.eventType(SecurityAuditEventType.SANDBOX_VIOLATION)
			.principal("agent:malicious")
			.build();

		assertTrue(event.isViolation());
		assertEquals(Severity.CRITICAL, event.getSeverity());
		assertTrue(event.getEventType().requiresAlert());
	}

	@Test
	public void testCustomSeverity() {
		SecurityAuditEvent event = SecurityAuditEvent.builder()
			.eventType(SecurityAuditEventType.CAPABILITY_GRANTED)
			.severity(Severity.WARNING)  // Override default
			.principal("agent:test")
			.build();

		assertEquals(Severity.WARNING, event.getSeverity());
	}

	@Test
	public void testCustomTimestamp() {
		Instant customTime = Instant.parse("2026-02-19T10:00:00Z");
		SecurityAuditEvent event = SecurityAuditEvent.builder()
			.eventType(SecurityAuditEventType.SESSION_STARTED)
			.timestamp(customTime)
			.principal("user:analyst")
			.build();

		assertEquals(customTime, event.getTimestamp());
	}

	@Test
	public void testToBuilder() {
		SecurityAuditEvent original = SecurityAuditEvent.builder()
			.eventType(SecurityAuditEventType.CAPABILITY_GRANTED)
			.principal("agent:test")
			.sessionId("session-001")
			.detail("key", "value")
			.build();

		SecurityAuditEvent copy = original.toBuilder()
			.detail("extra", "data")
			.build();

		// Copy should have new event ID
		assertNotEquals(original.getEventId(), copy.getEventId());
		// But same other values
		assertEquals(original.getEventType(), copy.getEventType());
		assertEquals(original.getPrincipal(), copy.getPrincipal());
		assertEquals(original.getSessionId(), copy.getSessionId());
		// Plus the new detail
		assertEquals("data", copy.getDetail("extra"));
	}

	@Test
	public void testDetailsAndContextAreImmutable() {
		SecurityAuditEvent event = SecurityAuditEvent.builder()
			.eventType(SecurityAuditEventType.CAPABILITY_GRANTED)
			.principal("agent:test")
			.detail("key", "value")
			.context("ctx", "val")
			.build();

		Map<String, String> details = event.getDetails();
		try {
			details.put("new", "entry");
			fail("Details map should be immutable");
		}
		catch (UnsupportedOperationException e) {
			// Expected
		}

		Map<String, String> context = event.getContext();
		try {
			context.put("new", "entry");
			fail("Context map should be immutable");
		}
		catch (UnsupportedOperationException e) {
			// Expected
		}
	}

	@Test
	public void testNullDetailValuesIgnored() {
		SecurityAuditEvent event = SecurityAuditEvent.builder()
			.eventType(SecurityAuditEventType.CAPABILITY_GRANTED)
			.principal("agent:test")
			.detail("present", "value")
			.detail("absent", null)
			.build();

		assertEquals("value", event.getDetail("present"));
		assertNull(event.getDetail("absent"));
		assertFalse(event.getDetails().containsKey("absent"));
	}

	@Test
	public void testEquality() {
		SecurityAuditEvent event1 = SecurityAuditEvent.builder()
			.eventId("same-id")
			.eventType(SecurityAuditEventType.CAPABILITY_GRANTED)
			.principal("agent:test")
			.build();

		SecurityAuditEvent event2 = SecurityAuditEvent.builder()
			.eventId("same-id")
			.eventType(SecurityAuditEventType.CAPABILITY_DENIED)
			.principal("agent:different")
			.build();

		assertEquals(event1, event2);  // Same ID = equal
		assertEquals(event1.hashCode(), event2.hashCode());
	}

	@Test(expected = NullPointerException.class)
	public void testRequiresEventType() {
		SecurityAuditEvent.builder()
			.principal("agent:test")
			.build();
	}

	@Test(expected = NullPointerException.class)
	public void testRequiresPrincipal() {
		SecurityAuditEvent.builder()
			.eventType(SecurityAuditEventType.CAPABILITY_GRANTED)
			.build();
	}
}
