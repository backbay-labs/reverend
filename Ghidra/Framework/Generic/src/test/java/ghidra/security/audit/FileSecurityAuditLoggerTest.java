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

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.*;
import org.junit.rules.TemporaryFolder;

import ghidra.security.audit.SecurityAuditLogger.AuditQuery;

/**
 * Tests for {@link FileSecurityAuditLogger}.
 * Verifies file-based persistence, round-trip serialization, and query support.
 */
public class FileSecurityAuditLoggerTest {

	@Rule
	public TemporaryFolder tempFolder = new TemporaryFolder();

	private FileSecurityAuditLogger logger;
	private Path logDir;

	@Before
	public void setUp() throws IOException {
		logDir = tempFolder.newFolder("audit-logs").toPath();
		logger = new FileSecurityAuditLogger(logDir, false);
	}

	@After
	public void tearDown() throws IOException {
		if (logger != null) {
			logger.close();
		}
	}

	// === Basic logging and persistence ===

	@Test
	public void testLogEventCreatesFile() throws IOException {
		logger.log(createEvent(SecurityAuditEventType.CAPABILITY_GRANTED, "agent:test"));

		List<Path> files = logger.listEventFiles();
		assertEquals(1, files.size());
		assertTrue(Files.size(files.get(0)) > 0);
	}

	@Test
	public void testLogEventPersistsToFile() throws IOException {
		SecurityAuditEvent event = SecurityAuditEvent.builder()
			.eventType(SecurityAuditEventType.CAPABILITY_GRANTED)
			.principal("agent:claude-opus-4-6")
			.sessionId("session-001")
			.detail("capability", "READ.DECOMPILE")
			.detail("operation", "decompile function at 0x401000")
			.context("program", "firmware.gzf")
			.build();

		logger.log(event);

		assertEquals(1, logger.getEventCount());
	}

	@Test
	public void testRecordViolationPersistsBothEventAndViolation() throws IOException {
		ViolationIncident incident = createViolation("agent:test");

		logger.recordViolation(incident);

		assertEquals(1, logger.getEventCount());
		assertEquals(1, logger.getViolationCount());

		List<Path> violationFiles = logger.listViolationFiles();
		assertEquals(1, violationFiles.size());
		assertTrue(Files.size(violationFiles.get(0)) > 0);
	}

	// === Round-trip serialization ===

	@Test
	public void testEventRoundTrip() throws IOException {
		Instant fixedTime = Instant.parse("2026-02-19T14:30:00Z");

		SecurityAuditEvent original = SecurityAuditEvent.builder()
			.eventId("test-event-001")
			.eventType(SecurityAuditEventType.CAPABILITY_DENIED)
			.severity(Severity.WARNING)
			.principal("agent:claude-opus-4-6")
			.sessionId("session-abc")
			.timestamp(fixedTime)
			.detail("denied_capability", "WRITE.PATCH")
			.detail("operation", "patch bytes at 0x401000")
			.context("program", "firmware.gzf")
			.context("active_function", "main")
			.build();

		logger.log(original);

		List<SecurityAuditEvent> results = logger.queryEvents(AuditQuery.builder().build());
		assertEquals(1, results.size());

		SecurityAuditEvent restored = results.get(0);
		assertEquals(original.getEventId(), restored.getEventId());
		assertEquals(original.getEventType(), restored.getEventType());
		assertEquals(original.getSeverity(), restored.getSeverity());
		assertEquals(original.getPrincipal(), restored.getPrincipal());
		assertEquals(original.getSessionId(), restored.getSessionId());
		assertEquals(fixedTime, restored.getTimestamp());
		assertEquals("WRITE.PATCH", restored.getDetail("denied_capability"));
		assertEquals("patch bytes at 0x401000", restored.getDetail("operation"));
		assertEquals("firmware.gzf", restored.getContextValue("program"));
		assertEquals("main", restored.getContextValue("active_function"));
	}

	@Test
	public void testViolationRoundTrip() throws IOException {
		SecurityAuditEvent event = SecurityAuditEvent.builder()
			.eventType(SecurityAuditEventType.CAPABILITY_DENIED)
			.principal("agent:test")
			.sessionId("session-001")
			.detail("denied_capability", "WRITE.PATCH")
			.build();

		ViolationIncident original = ViolationIncident.builder()
			.incidentId("incident-001")
			.event(event)
			.policyName("capability-token-policy")
			.policyVersion("1.0")
			.violatedConstraint("Capability WRITE.PATCH not granted to profile 'annotator'")
			.remediationAction(ViolationIncident.RemediationAction.BLOCKED)
			.remediationDetails("Operation denied; CapabilityDeniedException thrown")
			.escalated(true)
			.build();

		logger.recordViolation(original);

		List<ViolationIncident> results = logger.queryViolations(AuditQuery.builder().build());
		assertEquals(1, results.size());

		ViolationIncident restored = results.get(0);
		assertEquals(original.getIncidentId(), restored.getIncidentId());
		assertEquals(original.getViolationType(), restored.getViolationType());
		assertEquals(original.getSeverity(), restored.getSeverity());
		assertEquals(original.getPrincipal(), restored.getPrincipal());
		assertEquals(original.getPolicyName(), restored.getPolicyName());
		assertEquals(original.getPolicyVersion(), restored.getPolicyVersion());
		assertEquals(original.getViolatedConstraint(), restored.getViolatedConstraint());
		assertEquals(original.getRemediationAction(), restored.getRemediationAction());
		assertEquals(original.getRemediationDetails(), restored.getRemediationDetails());
		assertEquals(original.isEscalated(), restored.isEscalated());
	}

	// === Query tests ===

	@Test
	public void testQueryByEventType() throws IOException {
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
	public void testQueryByPrincipal() throws IOException {
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
	public void testQueryByMinSeverity() throws IOException {
		logger.log(createEvent(SecurityAuditEventType.CAPABILITY_GRANTED, "agent:a"));  // INFO
		logger.log(createEvent(SecurityAuditEventType.CAPABILITY_DENIED, "agent:b"));   // WARNING
		logger.log(createEvent(SecurityAuditEventType.SANDBOX_VIOLATION, "agent:c"));   // CRITICAL

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
	public void testQueryByTimeRange() throws IOException {
		Instant now = Instant.now();

		logger.log(createEventAtTime(
			SecurityAuditEventType.CAPABILITY_GRANTED, "agent:old", now.minus(2, ChronoUnit.HOURS)));
		logger.log(createEventAtTime(
			SecurityAuditEventType.CAPABILITY_GRANTED, "agent:mid", now.minus(30, ChronoUnit.MINUTES)));
		logger.log(createEventAtTime(
			SecurityAuditEventType.CAPABILITY_GRANTED, "agent:new", now));

		List<SecurityAuditEvent> lastHour = logger.queryEvents(
			AuditQuery.builder()
				.startTime(now.minus(1, ChronoUnit.HOURS))
				.build());

		assertEquals(2, lastHour.size());
	}

	@Test
	public void testQueryWithPagination() throws IOException {
		for (int i = 0; i < 10; i++) {
			logger.log(createEvent(SecurityAuditEventType.CAPABILITY_GRANTED, "agent:" + i));
		}

		List<SecurityAuditEvent> page1 = logger.queryEvents(
			AuditQuery.builder().limit(3).offset(0).build());
		assertEquals(3, page1.size());

		List<SecurityAuditEvent> page2 = logger.queryEvents(
			AuditQuery.builder().limit(3).offset(3).build());
		assertEquals(3, page2.size());

		// Pages should not overlap
		assertFalse(page1.get(0).getEventId().equals(page2.get(0).getEventId()));
	}

	@Test
	public void testQueryViolations() throws IOException {
		logger.recordViolation(createViolation("agent:alice"));
		logger.recordViolation(createViolation("agent:bob"));
		logger.log(createEvent(SecurityAuditEventType.CAPABILITY_DENIED, "agent:charlie"));

		List<ViolationIncident> allViolations = logger.queryViolations(
			AuditQuery.builder().build());
		assertEquals(2, allViolations.size());

		List<ViolationIncident> aliceViolations = logger.queryViolations(
			AuditQuery.builder().principal("agent:alice").build());
		assertEquals(1, aliceViolations.size());
	}

	@Test
	public void testQueryResultsOrderedByTimestampDescending() throws IOException {
		Instant now = Instant.now();

		logger.log(createEventAtTime(
			SecurityAuditEventType.CAPABILITY_GRANTED, "agent:first", now.minus(2, ChronoUnit.HOURS)));
		logger.log(createEventAtTime(
			SecurityAuditEventType.CAPABILITY_GRANTED, "agent:second", now.minus(1, ChronoUnit.HOURS)));
		logger.log(createEventAtTime(
			SecurityAuditEventType.CAPABILITY_GRANTED, "agent:third", now));

		List<SecurityAuditEvent> results = logger.queryEvents(AuditQuery.builder().build());

		assertEquals("agent:third", results.get(0).getPrincipal());
		assertEquals("agent:second", results.get(1).getPrincipal());
		assertEquals("agent:first", results.get(2).getPrincipal());
	}

	// === Alert listener tests ===

	@Test
	public void testAlertListenerCalledForCriticalEvents() throws IOException {
		AtomicInteger alertCount = new AtomicInteger(0);

		logger.addAlertListener(event -> alertCount.incrementAndGet());

		// Non-critical event - no alert
		logger.log(createEvent(SecurityAuditEventType.CAPABILITY_DENIED, "agent:a"));
		assertEquals(0, alertCount.get());

		// Critical event - should alert
		logger.log(createEvent(SecurityAuditEventType.SANDBOX_VIOLATION, "agent:b"));
		assertEquals(1, alertCount.get());
	}

	// === Special character handling ===

	@Test
	public void testSpecialCharactersInDetails() throws IOException {
		SecurityAuditEvent event = SecurityAuditEvent.builder()
			.eventType(SecurityAuditEventType.CAPABILITY_GRANTED)
			.principal("agent:test")
			.detail("operation", "rename to \"main_func\"")
			.detail("path", "C:\\Users\\test\\file.bin")
			.build();

		logger.log(event);

		List<SecurityAuditEvent> results = logger.queryEvents(AuditQuery.builder().build());
		assertEquals(1, results.size());

		SecurityAuditEvent restored = results.get(0);
		assertEquals("rename to \"main_func\"", restored.getDetail("operation"));
		assertEquals("C:\\Users\\test\\file.bin", restored.getDetail("path"));
	}

	// === Close and reopen ===

	@Test
	public void testDataSurvivesCloseAndReopen() throws IOException {
		logger.log(createEvent(SecurityAuditEventType.CAPABILITY_GRANTED, "agent:a"));
		logger.log(createEvent(SecurityAuditEventType.CAPABILITY_DENIED, "agent:b"));
		logger.recordViolation(createViolation("agent:c"));

		logger.close();

		// Reopen with a new logger instance pointing to the same directory
		FileSecurityAuditLogger newLogger = new FileSecurityAuditLogger(logDir, false);
		try {
			assertEquals(3, newLogger.getEventCount());
			assertEquals(1, newLogger.getViolationCount());

			List<SecurityAuditEvent> events = newLogger.queryEvents(AuditQuery.builder().build());
			assertEquals(3, events.size());
		}
		finally {
			newLogger.close();
		}
	}

	// === File listing ===

	@Test
	public void testListEventFiles() throws IOException {
		logger.log(createEvent(SecurityAuditEventType.CAPABILITY_GRANTED, "agent:test"));

		List<Path> eventFiles = logger.listEventFiles();
		assertEquals(1, eventFiles.size());
		assertTrue(eventFiles.get(0).getFileName().toString().startsWith("audit-events-"));
		assertTrue(eventFiles.get(0).getFileName().toString().endsWith(".jsonl"));
	}

	@Test
	public void testListViolationFiles() throws IOException {
		logger.recordViolation(createViolation("agent:test"));

		List<Path> violationFiles = logger.listViolationFiles();
		assertEquals(1, violationFiles.size());
		assertTrue(violationFiles.get(0).getFileName().toString().startsWith("audit-violations-"));
		assertTrue(violationFiles.get(0).getFileName().toString().endsWith(".jsonl"));
	}

	@Test
	public void testGetLogDirectory() {
		assertEquals(logDir, logger.getLogDirectory());
	}

	// === Null safety ===

	@Test(expected = NullPointerException.class)
	public void testLogRejectsNull() {
		logger.log(null);
	}

	@Test(expected = NullPointerException.class)
	public void testRecordViolationRejectsNull() {
		logger.recordViolation(null);
	}

	@Test(expected = NullPointerException.class)
	public void testQueryEventsRejectsNull() {
		logger.queryEvents(null);
	}

	@Test(expected = NullPointerException.class)
	public void testQueryViolationsRejectsNull() {
		logger.queryViolations(null);
	}

	// === Helper methods ===

	private SecurityAuditEvent createEvent(SecurityAuditEventType type, String principal) {
		return SecurityAuditEvent.builder()
			.eventType(type)
			.principal(principal)
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
