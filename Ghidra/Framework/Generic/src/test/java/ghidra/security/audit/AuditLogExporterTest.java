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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;

import org.junit.Before;
import org.junit.Test;

import ghidra.security.audit.SecurityAuditLogger.AuditQuery;

/**
 * Tests for {@link AuditLogExporter}.
 * Verifies JSON and CSV export for compliance review.
 */
public class AuditLogExporterTest {

	private InMemorySecurityAuditLogger logger;
	private AuditLogExporter exporter;

	@Before
	public void setUp() {
		logger = new InMemorySecurityAuditLogger();
		exporter = new AuditLogExporter(logger);
	}

	// === JSON event export ===

	@Test
	public void testExportEventsJson() throws IOException {
		logger.log(createEvent(SecurityAuditEventType.CAPABILITY_GRANTED, "agent:test",
			"session-001"));
		logger.log(createEvent(SecurityAuditEventType.CAPABILITY_DENIED, "agent:test",
			"session-001"));

		String output = exportEventsToString(AuditQuery.builder().build(),
			AuditLogExporter.Format.JSON);

		// JSON Lines format - one JSON object per line
		String[] lines = output.trim().split("\n");
		assertEquals(2, lines.length);

		// Check that each line is a valid JSON object
		for (String line : lines) {
			assertTrue(line.startsWith("{"));
			assertTrue(line.endsWith("}"));
			assertTrue(line.contains("\"eventId\""));
			assertTrue(line.contains("\"timestamp\""));
			assertTrue(line.contains("\"eventType\""));
			assertTrue(line.contains("\"principal\""));
		}
	}

	@Test
	public void testExportEventsJsonIncludesDetails() throws IOException {
		SecurityAuditEvent event = SecurityAuditEvent.builder()
			.eventType(SecurityAuditEventType.CAPABILITY_GRANTED)
			.principal("agent:claude-opus-4-6")
			.sessionId("session-001")
			.detail("capability", "READ.DECOMPILE")
			.detail("operation", "decompile function")
			.context("program", "firmware.gzf")
			.build();

		logger.log(event);

		String output = exportEventsToString(AuditQuery.builder().build(),
			AuditLogExporter.Format.JSON);

		assertTrue(output.contains("agent:claude-opus-4-6"));
		assertTrue(output.contains("CAPABILITY_GRANTED"));
		assertTrue(output.contains("READ.DECOMPILE"));
		assertTrue(output.contains("firmware.gzf"));
	}

	@Test
	public void testExportEventsJsonWithFilter() throws IOException {
		logger.log(createEvent(SecurityAuditEventType.CAPABILITY_GRANTED, "agent:alice",
			"session-001"));
		logger.log(createEvent(SecurityAuditEventType.CAPABILITY_DENIED, "agent:bob",
			"session-002"));
		logger.log(createEvent(SecurityAuditEventType.CAPABILITY_GRANTED, "agent:alice",
			"session-001"));

		String output = exportEventsToString(
			AuditQuery.builder().principal("agent:alice").build(),
			AuditLogExporter.Format.JSON);

		String[] lines = output.trim().split("\n");
		assertEquals(2, lines.length);

		for (String line : lines) {
			assertTrue(line.contains("agent:alice"));
		}
	}

	// === CSV event export ===

	@Test
	public void testExportEventsCsv() throws IOException {
		logger.log(createEvent(SecurityAuditEventType.CAPABILITY_GRANTED, "agent:test",
			"session-001"));

		String output = exportEventsToString(AuditQuery.builder().build(),
			AuditLogExporter.Format.CSV);

		String[] lines = output.trim().split("\n");
		assertEquals(2, lines.length); // header + 1 data row

		// Check header
		String header = lines[0];
		assertTrue(header.contains("eventId"));
		assertTrue(header.contains("timestamp"));
		assertTrue(header.contains("eventType"));
		assertTrue(header.contains("severity"));
		assertTrue(header.contains("principal"));

		// Check data row
		String data = lines[1];
		assertTrue(data.contains("CAPABILITY_GRANTED"));
		assertTrue(data.contains("agent:test"));
		assertTrue(data.contains("INFO"));
	}

	@Test
	public void testExportEventsCsvMultipleRows() throws IOException {
		logger.log(createEvent(SecurityAuditEventType.CAPABILITY_GRANTED, "agent:a", null));
		logger.log(createEvent(SecurityAuditEventType.CAPABILITY_DENIED, "agent:b", null));
		logger.log(createEvent(SecurityAuditEventType.SANDBOX_VIOLATION, "agent:c", null));

		String output = exportEventsToString(AuditQuery.builder().build(),
			AuditLogExporter.Format.CSV);

		String[] lines = output.trim().split("\n");
		assertEquals(4, lines.length); // header + 3 data rows
	}

	// === JSON violation export ===

	@Test
	public void testExportViolationsJson() throws IOException {
		logger.recordViolation(createViolation("agent:alice"));
		logger.recordViolation(createViolation("agent:bob"));

		String output = exportViolationsToString(AuditQuery.builder().build(),
			AuditLogExporter.Format.JSON);

		String[] lines = output.trim().split("\n");
		assertEquals(2, lines.length);

		for (String line : lines) {
			assertTrue(line.contains("\"incidentId\""));
			assertTrue(line.contains("\"policyName\""));
			assertTrue(line.contains("\"violatedConstraint\""));
			assertTrue(line.contains("\"remediationAction\""));
		}
	}

	@Test
	public void testExportViolationsJsonIncludesPolicyContext() throws IOException {
		SecurityAuditEvent event = SecurityAuditEvent.builder()
			.eventType(SecurityAuditEventType.CAPABILITY_DENIED)
			.principal("agent:test")
			.detail("denied_capability", "WRITE.PATCH")
			.build();

		ViolationIncident incident = ViolationIncident.builder()
			.event(event)
			.policyName("capability-token-policy")
			.policyVersion("1.0")
			.violatedConstraint("Capability WRITE.PATCH not granted to profile 'annotator'")
			.remediationAction(ViolationIncident.RemediationAction.BLOCKED)
			.remediationDetails("Operation denied")
			.escalated(true)
			.build();

		logger.recordViolation(incident);

		String output = exportViolationsToString(AuditQuery.builder().build(),
			AuditLogExporter.Format.JSON);

		assertTrue(output.contains("capability-token-policy"));
		assertTrue(output.contains("1.0"));
		assertTrue(output.contains("WRITE.PATCH not granted"));
		assertTrue(output.contains("BLOCKED"));
		assertTrue(output.contains("Operation denied"));
		assertTrue(output.contains("true")); // escalated
	}

	// === CSV violation export ===

	@Test
	public void testExportViolationsCsv() throws IOException {
		logger.recordViolation(createViolation("agent:test"));

		String output = exportViolationsToString(AuditQuery.builder().build(),
			AuditLogExporter.Format.CSV);

		String[] lines = output.trim().split("\n");
		assertEquals(2, lines.length); // header + 1 data row

		// Check header
		String header = lines[0];
		assertTrue(header.contains("incidentId"));
		assertTrue(header.contains("policyName"));
		assertTrue(header.contains("violatedConstraint"));
		assertTrue(header.contains("remediationAction"));
		assertTrue(header.contains("escalated"));

		// Check data row
		String data = lines[1];
		assertTrue(data.contains("CAPABILITY_DENIED"));
		assertTrue(data.contains("test-policy"));
		assertTrue(data.contains("BLOCKED"));
	}

	// === Summary generation ===

	@Test
	public void testGenerateSummary() {
		logger.log(createEvent(SecurityAuditEventType.CAPABILITY_GRANTED, "agent:alice", null));
		logger.log(createEvent(SecurityAuditEventType.CAPABILITY_GRANTED, "agent:bob", null));
		logger.log(createEvent(SecurityAuditEventType.CAPABILITY_DENIED, "agent:alice", null));
		logger.recordViolation(createViolation("agent:charlie"));

		AuditLogExporter.AuditSummary summary = exporter.generateSummary(
			AuditQuery.builder().build());

		assertEquals(4, summary.getTotalEvents());
		assertEquals(1, summary.getTotalViolations());
		assertNotNull(summary.getEarliestEvent());
		assertNotNull(summary.getLatestEvent());
		assertEquals(Long.valueOf(2),
			summary.getEventsByType().get(SecurityAuditEventType.CAPABILITY_GRANTED));
		assertEquals(Long.valueOf(2),
			summary.getEventsByType().get(SecurityAuditEventType.CAPABILITY_DENIED));
		assertEquals(Long.valueOf(2), summary.getEventsByPrincipal().get("agent:alice"));
	}

	@Test
	public void testGenerateSummaryWithTimeRange() {
		Instant now = Instant.now();

		logger.log(createEventAtTime(SecurityAuditEventType.CAPABILITY_GRANTED, "agent:a",
			now.minusSeconds(7200)));
		logger.log(createEventAtTime(SecurityAuditEventType.CAPABILITY_GRANTED, "agent:b",
			now.minusSeconds(1800)));
		logger.log(createEventAtTime(SecurityAuditEventType.CAPABILITY_GRANTED, "agent:c", now));

		AuditLogExporter.AuditSummary summary = exporter.generateSummary(
			AuditQuery.builder()
				.startTime(now.minusSeconds(3600))
				.build());

		assertEquals(2, summary.getTotalEvents());
	}

	@Test
	public void testGenerateEmptySummary() {
		AuditLogExporter.AuditSummary summary = exporter.generateSummary(
			AuditQuery.builder().build());

		assertEquals(0, summary.getTotalEvents());
		assertEquals(0, summary.getTotalViolations());
		assertNull(summary.getEarliestEvent());
		assertNull(summary.getLatestEvent());
		assertTrue(summary.getEventsByType().isEmpty());
	}

	@Test
	public void testExportSummaryJson() throws IOException {
		logger.log(createEvent(SecurityAuditEventType.CAPABILITY_GRANTED, "agent:test", null));
		logger.log(createEvent(SecurityAuditEventType.CAPABILITY_DENIED, "agent:test", null));
		logger.recordViolation(createViolation("agent:test"));

		AuditLogExporter.AuditSummary summary = exporter.generateSummary(
			AuditQuery.builder().build());

		ByteArrayOutputStream out = new ByteArrayOutputStream();
		exporter.exportSummary(summary, out);
		String output = out.toString(StandardCharsets.UTF_8);

		assertTrue(output.contains("\"totalEvents\": 3"));
		assertTrue(output.contains("\"totalViolations\": 1"));
		assertTrue(output.contains("\"eventsByType\""));
		assertTrue(output.contains("\"eventsBySeverity\""));
		assertTrue(output.contains("\"eventsByPrincipal\""));
	}

	@Test
	public void testSummaryToString() {
		logger.log(createEvent(SecurityAuditEventType.CAPABILITY_GRANTED, "agent:test", null));

		AuditLogExporter.AuditSummary summary = exporter.generateSummary(
			AuditQuery.builder().build());

		String str = summary.toString();
		assertTrue(str.contains("events=1"));
		assertTrue(str.contains("violations=0"));
	}

	// === Null safety ===

	@Test(expected = NullPointerException.class)
	public void testConstructorRejectsNullLogger() {
		new AuditLogExporter(null);
	}

	// === Helper methods ===

	private String exportEventsToString(AuditQuery query, AuditLogExporter.Format format)
			throws IOException {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		exporter.exportEvents(query, out, format);
		return out.toString(StandardCharsets.UTF_8);
	}

	private String exportViolationsToString(AuditQuery query, AuditLogExporter.Format format)
			throws IOException {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		exporter.exportViolations(query, out, format);
		return out.toString(StandardCharsets.UTF_8);
	}

	private SecurityAuditEvent createEvent(SecurityAuditEventType type, String principal,
			String sessionId) {
		return SecurityAuditEvent.builder()
			.eventType(type)
			.principal(principal)
			.sessionId(sessionId)
			.build();
	}

	private SecurityAuditEvent createEventAtTime(SecurityAuditEventType type, String principal,
			Instant timestamp) {
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
