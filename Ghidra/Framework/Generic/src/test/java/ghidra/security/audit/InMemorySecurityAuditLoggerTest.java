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
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.Before;
import org.junit.Test;

import ghidra.security.audit.SecurityAuditLogger.AuditQuery;

/**
 * Tests for {@link InMemorySecurityAuditLogger}.
 */
public class InMemorySecurityAuditLoggerTest {

	private InMemorySecurityAuditLogger logger;

	@Before
	public void setUp() {
		logger = new InMemorySecurityAuditLogger();
	}

	// === Basic logging tests ===

	@Test
	public void testLogEvent() {
		SecurityAuditEvent event = createEvent(
			SecurityAuditEventType.CAPABILITY_GRANTED, "agent:test");

		logger.log(event);

		assertEquals(1, logger.getEventCount());
		assertEquals(0, logger.getViolationCount());
	}

	@Test
	public void testRecordViolation() {
		ViolationIncident incident = createViolation("agent:test");

		logger.recordViolation(incident);

		assertEquals(1, logger.getEventCount());  // Event is also logged
		assertEquals(1, logger.getViolationCount());
	}

	// === Query tests ===

	@Test
	public void testQueryByEventType() {
		logger.log(createEvent(SecurityAuditEventType.CAPABILITY_GRANTED, "agent:a"));
		logger.log(createEvent(SecurityAuditEventType.CAPABILITY_DENIED, "agent:b"));
		logger.log(createEvent(SecurityAuditEventType.CAPABILITY_GRANTED, "agent:c"));

		List<SecurityAuditEvent> results = logger.queryEvents(
			AuditQuery.builder()
				.eventType(SecurityAuditEventType.CAPABILITY_GRANTED)
				.build());

		assertEquals(2, results.size());
		assertTrue(results.stream()
			.allMatch(e -> e.getEventType() == SecurityAuditEventType.CAPABILITY_GRANTED));
	}

	@Test
	public void testQueryByPrincipal() {
		logger.log(createEvent(SecurityAuditEventType.CAPABILITY_GRANTED, "agent:alice"));
		logger.log(createEvent(SecurityAuditEventType.CAPABILITY_GRANTED, "agent:bob"));
		logger.log(createEvent(SecurityAuditEventType.CAPABILITY_DENIED, "agent:alice"));

		List<SecurityAuditEvent> results = logger.queryEvents(
			AuditQuery.builder()
				.principal("agent:alice")
				.build());

		assertEquals(2, results.size());
		assertTrue(results.stream().allMatch(e -> "agent:alice".equals(e.getPrincipal())));
	}

	@Test
	public void testQueryBySessionId() {
		logger.log(createEventWithSession(
			SecurityAuditEventType.CAPABILITY_GRANTED, "agent:test", "session-1"));
		logger.log(createEventWithSession(
			SecurityAuditEventType.CAPABILITY_GRANTED, "agent:test", "session-2"));
		logger.log(createEventWithSession(
			SecurityAuditEventType.CAPABILITY_GRANTED, "agent:test", "session-1"));

		List<SecurityAuditEvent> results = logger.queryEvents(
			AuditQuery.builder()
				.sessionId("session-1")
				.build());

		assertEquals(2, results.size());
	}

	@Test
	public void testQueryByMinSeverity() {
		logger.log(createEvent(SecurityAuditEventType.CAPABILITY_GRANTED, "agent:a")); // INFO
		logger.log(createEvent(SecurityAuditEventType.CAPABILITY_DENIED, "agent:b")); // WARNING
		logger.log(createEvent(SecurityAuditEventType.SANDBOX_VIOLATION, "agent:c")); // CRITICAL

		List<SecurityAuditEvent> warningsAndAbove = logger.queryEvents(
			AuditQuery.builder()
				.minSeverity(Severity.WARNING)
				.build());

		assertEquals(2, warningsAndAbove.size());

		List<SecurityAuditEvent> criticalOnly = logger.queryEvents(
			AuditQuery.builder()
				.minSeverity(Severity.CRITICAL)
				.build());

		assertEquals(1, criticalOnly.size());
		assertEquals(SecurityAuditEventType.SANDBOX_VIOLATION, criticalOnly.get(0).getEventType());
	}

	@Test
	public void testQueryByTimeRange() {
		Instant now = Instant.now();

		logger.log(createEventAtTime(SecurityAuditEventType.CAPABILITY_GRANTED, "agent:a",
			now.minus(2, ChronoUnit.HOURS)));
		logger.log(createEventAtTime(SecurityAuditEventType.CAPABILITY_GRANTED, "agent:b",
			now.minus(30, ChronoUnit.MINUTES)));
		logger.log(createEventAtTime(SecurityAuditEventType.CAPABILITY_GRANTED, "agent:c",
			now));

		List<SecurityAuditEvent> lastHour = logger.queryEvents(
			AuditQuery.builder()
				.startTime(now.minus(1, ChronoUnit.HOURS))
				.build());

		assertEquals(2, lastHour.size());
	}

	@Test
	public void testQueryViolationsOnly() {
		logger.log(createEvent(SecurityAuditEventType.CAPABILITY_GRANTED, "agent:a"));
		logger.log(createEvent(SecurityAuditEventType.CAPABILITY_DENIED, "agent:b"));
		logger.log(createEvent(SecurityAuditEventType.SESSION_STARTED, "agent:c"));

		List<SecurityAuditEvent> violations = logger.queryEvents(
			AuditQuery.builder()
				.violationsOnly(true)
				.build());

		assertEquals(1, violations.size());
		assertTrue(violations.get(0).isViolation());
	}

	@Test
	public void testQueryWithPagination() {
		for (int i = 0; i < 20; i++) {
			logger.log(createEvent(SecurityAuditEventType.CAPABILITY_GRANTED, "agent:" + i));
		}

		List<SecurityAuditEvent> page1 = logger.queryEvents(
			AuditQuery.builder()
				.limit(5)
				.offset(0)
				.build());
		assertEquals(5, page1.size());

		List<SecurityAuditEvent> page2 = logger.queryEvents(
			AuditQuery.builder()
				.limit(5)
				.offset(5)
				.build());
		assertEquals(5, page2.size());

		// Pages should not overlap
		Set<String> page1Ids = new HashSet<>();
		for (SecurityAuditEvent e : page1) {
			page1Ids.add(e.getEventId());
		}
		for (SecurityAuditEvent e : page2) {
			assertFalse(page1Ids.contains(e.getEventId()));
		}
	}

	@Test
	public void testQueryViolations() {
		logger.recordViolation(createViolation("agent:alice"));
		logger.recordViolation(createViolation("agent:bob"));
		logger.log(createEvent(SecurityAuditEventType.CAPABILITY_DENIED, "agent:charlie"));

		List<ViolationIncident> allViolations = logger.queryViolations(
			AuditQuery.builder().build());
		assertEquals(2, allViolations.size());

		List<ViolationIncident> aliceViolations = logger.queryViolations(
			AuditQuery.builder()
				.principal("agent:alice")
				.build());
		assertEquals(1, aliceViolations.size());
	}

	@Test
	public void testQueryResultsOrderedByTimestampDescending() {
		Instant now = Instant.now();

		logger.log(createEventAtTime(SecurityAuditEventType.CAPABILITY_GRANTED, "agent:first",
			now.minus(2, ChronoUnit.HOURS)));
		logger.log(createEventAtTime(SecurityAuditEventType.CAPABILITY_GRANTED, "agent:second",
			now.minus(1, ChronoUnit.HOURS)));
		logger.log(createEventAtTime(SecurityAuditEventType.CAPABILITY_GRANTED, "agent:third",
			now));

		List<SecurityAuditEvent> results = logger.queryEvents(AuditQuery.builder().build());

		assertEquals("agent:third", results.get(0).getPrincipal());
		assertEquals("agent:second", results.get(1).getPrincipal());
		assertEquals("agent:first", results.get(2).getPrincipal());
	}

	// === Alert listener tests ===

	@Test
	public void testAlertListenerCalledForCriticalEvents() {
		AtomicInteger alertCount = new AtomicInteger(0);
		List<SecurityAuditEvent> alertedEvents = new ArrayList<>();

		logger.addAlertListener(event -> {
			alertCount.incrementAndGet();
			alertedEvents.add(event);
		});

		// Non-critical event - no alert
		logger.log(createEvent(SecurityAuditEventType.CAPABILITY_DENIED, "agent:a"));
		assertEquals(0, alertCount.get());

		// Critical event - should alert
		SecurityAuditEvent criticalEvent = createEvent(
			SecurityAuditEventType.SANDBOX_VIOLATION, "agent:b");
		logger.log(criticalEvent);

		assertEquals(1, alertCount.get());
		assertEquals(criticalEvent, alertedEvents.get(0));
	}

	@Test
	public void testRemoveAlertListener() {
		AtomicInteger alertCount = new AtomicInteger(0);
		java.util.function.Consumer<SecurityAuditEvent> listener = event -> alertCount.incrementAndGet();

		logger.addAlertListener(listener);
		logger.log(createEvent(SecurityAuditEventType.SANDBOX_VIOLATION, "agent:a"));
		assertEquals(1, alertCount.get());

		logger.removeAlertListener(listener);
		logger.log(createEvent(SecurityAuditEventType.SANDBOX_VIOLATION, "agent:b"));
		assertEquals(1, alertCount.get());  // No increment
	}

	// === Capacity limit tests ===

	@Test
	public void testEvictionWhenCapacityExceeded() {
		InMemorySecurityAuditLogger smallLogger = new InMemorySecurityAuditLogger(5, 3);

		for (int i = 0; i < 10; i++) {
			smallLogger.log(createEvent(SecurityAuditEventType.CAPABILITY_GRANTED, "agent:" + i));
		}

		assertEquals(5, smallLogger.getEventCount());

		// Oldest events should be evicted
		List<SecurityAuditEvent> remaining = smallLogger.getAllEvents();
		assertTrue(remaining.stream().anyMatch(e -> "agent:9".equals(e.getPrincipal())));
		assertFalse(remaining.stream().anyMatch(e -> "agent:0".equals(e.getPrincipal())));
	}

	// === Statistics tests ===

	@Test
	public void testGetEventCountsByType() {
		logger.log(createEvent(SecurityAuditEventType.CAPABILITY_GRANTED, "agent:a"));
		logger.log(createEvent(SecurityAuditEventType.CAPABILITY_GRANTED, "agent:b"));
		logger.log(createEvent(SecurityAuditEventType.CAPABILITY_DENIED, "agent:c"));

		Map<SecurityAuditEventType, Long> counts = logger.getEventCountsByType();

		assertEquals(Long.valueOf(2), counts.get(SecurityAuditEventType.CAPABILITY_GRANTED));
		assertEquals(Long.valueOf(1), counts.get(SecurityAuditEventType.CAPABILITY_DENIED));
	}

	@Test
	public void testGetEventCountsBySeverity() {
		logger.log(createEvent(SecurityAuditEventType.CAPABILITY_GRANTED, "agent:a")); // INFO
		logger.log(createEvent(SecurityAuditEventType.CAPABILITY_DENIED, "agent:b")); // WARNING
		logger.log(createEvent(SecurityAuditEventType.SANDBOX_VIOLATION, "agent:c")); // CRITICAL

		Map<Severity, Long> counts = logger.getEventCountsBySeverity();

		assertEquals(Long.valueOf(1), counts.get(Severity.INFO));
		assertEquals(Long.valueOf(1), counts.get(Severity.WARNING));
		assertEquals(Long.valueOf(1), counts.get(Severity.CRITICAL));
	}

	@Test
	public void testGetEventCountsByPrincipal() {
		logger.log(createEvent(SecurityAuditEventType.CAPABILITY_GRANTED, "agent:alice"));
		logger.log(createEvent(SecurityAuditEventType.CAPABILITY_GRANTED, "agent:alice"));
		logger.log(createEvent(SecurityAuditEventType.CAPABILITY_GRANTED, "agent:bob"));

		Map<String, Long> counts = logger.getEventCountsByPrincipal();

		assertEquals(Long.valueOf(2), counts.get("agent:alice"));
		assertEquals(Long.valueOf(1), counts.get("agent:bob"));
	}

	@Test
	public void testClear() {
		logger.log(createEvent(SecurityAuditEventType.CAPABILITY_GRANTED, "agent:a"));
		logger.recordViolation(createViolation("agent:b"));

		assertEquals(2, logger.getEventCount());
		assertEquals(1, logger.getViolationCount());

		logger.clear();

		assertEquals(0, logger.getEventCount());
		assertEquals(0, logger.getViolationCount());
	}

	// === Helper methods ===

	private SecurityAuditEvent createEvent(SecurityAuditEventType type, String principal) {
		return SecurityAuditEvent.builder()
			.eventType(type)
			.principal(principal)
			.build();
	}

	private SecurityAuditEvent createEventWithSession(
			SecurityAuditEventType type, String principal, String sessionId) {
		return SecurityAuditEvent.builder()
			.eventType(type)
			.principal(principal)
			.sessionId(sessionId)
			.build();
	}

	private SecurityAuditEvent createEventAtTime(
			SecurityAuditEventType type, String principal, Instant timestamp) {
		return SecurityAuditEvent.builder()
			.eventType(type)
			.principal(principal)
			.timestamp(timestamp)
			.build();
	}

	private ViolationIncident createViolation(String principal) {
		SecurityAuditEvent event = SecurityAuditEvent.builder()
			.eventType(SecurityAuditEventType.CAPABILITY_DENIED)
			.principal(principal)
			.detail("denied_capability", "WRITE.PATCH")
			.build();

		return ViolationIncident.builder()
			.event(event)
			.policyName("test-policy")
			.violatedConstraint("test constraint")
			.remediationAction(ViolationIncident.RemediationAction.BLOCKED)
			.build();
	}
}
