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

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * Exports audit logs and violation incidents for compliance review.
 * Supports JSON and CSV export formats per NIST SP 800-53 AU-6 audit review requirements.
 *
 * <p>Export capabilities:
 * <ul>
 *   <li>Full audit trail export for compliance review</li>
 *   <li>Filtered export by time range, principal, or event type</li>
 *   <li>Violation-only export for security incident review</li>
 *   <li>Summary statistics for audit reporting</li>
 * </ul>
 */
public class AuditLogExporter {

	/**
	 * Export format options.
	 */
	public enum Format {
		/** JSON format with one record per line (JSON Lines) */
		JSON,
		/** Comma-separated values with header row */
		CSV
	}

	private static final DateTimeFormatter TIMESTAMP_FORMAT =
		DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
			.withZone(ZoneOffset.UTC);

	private final SecurityAuditLogger logger;

	/**
	 * Creates an exporter for the specified audit logger.
	 *
	 * @param logger the audit logger to export from
	 */
	public AuditLogExporter(SecurityAuditLogger logger) {
		this.logger = Objects.requireNonNull(logger, "logger must not be null");
	}

	/**
	 * Exports events matching the query to the specified output.
	 *
	 * @param query the query to filter events
	 * @param output the output stream to write to
	 * @param format the export format
	 * @throws IOException if writing fails
	 */
	public void exportEvents(SecurityAuditLogger.AuditQuery query, OutputStream output,
			Format format) throws IOException {
		Objects.requireNonNull(query, "query must not be null");
		Objects.requireNonNull(output, "output must not be null");
		Objects.requireNonNull(format, "format must not be null");

		List<SecurityAuditEvent> events = logger.queryEvents(query);
		try (BufferedWriter writer =
			new BufferedWriter(new OutputStreamWriter(output, StandardCharsets.UTF_8))) {
			if (format == Format.CSV) {
				writeEventsCsv(events, writer);
			}
			else {
				writeEventsJson(events, writer);
			}
		}
	}

	/**
	 * Exports events matching the query to a file.
	 *
	 * @param query the query to filter events
	 * @param outputFile the file to write to
	 * @param format the export format
	 * @throws IOException if writing fails
	 */
	public void exportEvents(SecurityAuditLogger.AuditQuery query, Path outputFile,
			Format format) throws IOException {
		try (OutputStream out = Files.newOutputStream(outputFile)) {
			exportEvents(query, out, format);
		}
	}

	/**
	 * Exports violation incidents matching the query to the specified output.
	 *
	 * @param query the query to filter violations
	 * @param output the output stream to write to
	 * @param format the export format
	 * @throws IOException if writing fails
	 */
	public void exportViolations(SecurityAuditLogger.AuditQuery query, OutputStream output,
			Format format) throws IOException {
		Objects.requireNonNull(query, "query must not be null");
		Objects.requireNonNull(output, "output must not be null");
		Objects.requireNonNull(format, "format must not be null");

		List<ViolationIncident> violations = logger.queryViolations(query);
		try (BufferedWriter writer =
			new BufferedWriter(new OutputStreamWriter(output, StandardCharsets.UTF_8))) {
			if (format == Format.CSV) {
				writeViolationsCsv(violations, writer);
			}
			else {
				writeViolationsJson(violations, writer);
			}
		}
	}

	/**
	 * Exports violation incidents matching the query to a file.
	 *
	 * @param query the query to filter violations
	 * @param outputFile the file to write to
	 * @param format the export format
	 * @throws IOException if writing fails
	 */
	public void exportViolations(SecurityAuditLogger.AuditQuery query, Path outputFile,
			Format format) throws IOException {
		try (OutputStream out = Files.newOutputStream(outputFile)) {
			exportViolations(query, out, format);
		}
	}

	/**
	 * Generates a summary report of audit activity.
	 *
	 * @param query the query to filter events
	 * @return the summary report
	 */
	public AuditSummary generateSummary(SecurityAuditLogger.AuditQuery query) {
		List<SecurityAuditEvent> events = logger.queryEvents(query);
		List<ViolationIncident> violations = logger.queryViolations(query);

		Map<SecurityAuditEventType, Long> eventsByType = new LinkedHashMap<>();
		Map<Severity, Long> eventsBySeverity = new LinkedHashMap<>();
		Map<String, Long> eventsByPrincipal = new LinkedHashMap<>();

		for (SecurityAuditEvent event : events) {
			eventsByType.merge(event.getEventType(), 1L, Long::sum);
			eventsBySeverity.merge(event.getSeverity(), 1L, Long::sum);
			eventsByPrincipal.merge(event.getPrincipal(), 1L, Long::sum);
		}

		Instant earliest = events.stream()
			.map(SecurityAuditEvent::getTimestamp)
			.min(Comparator.naturalOrder())
			.orElse(null);
		Instant latest = events.stream()
			.map(SecurityAuditEvent::getTimestamp)
			.max(Comparator.naturalOrder())
			.orElse(null);

		return new AuditSummary(
			events.size(),
			violations.size(),
			earliest,
			latest,
			eventsByType,
			eventsBySeverity,
			eventsByPrincipal);
	}

	/**
	 * Exports a summary report to JSON format.
	 *
	 * @param summary the summary to export
	 * @param output the output stream
	 * @throws IOException if writing fails
	 */
	public void exportSummary(AuditSummary summary, OutputStream output) throws IOException {
		try (BufferedWriter writer =
			new BufferedWriter(new OutputStreamWriter(output, StandardCharsets.UTF_8))) {
			writeSummaryJson(summary, writer);
		}
	}

	private void writeEventsJson(List<SecurityAuditEvent> events, BufferedWriter writer)
			throws IOException {
		for (SecurityAuditEvent event : events) {
			writer.write(eventToJson(event));
			writer.newLine();
		}
	}

	private void writeEventsCsv(List<SecurityAuditEvent> events, BufferedWriter writer)
			throws IOException {
		// Header
		writer.write("eventId,timestamp,eventType,severity,principal,sessionId,operation,target");
		writer.newLine();

		for (SecurityAuditEvent event : events) {
			StringBuilder line = new StringBuilder();
			line.append(csvEscape(event.getEventId())).append(",");
			line.append(csvEscape(TIMESTAMP_FORMAT.format(event.getTimestamp()))).append(",");
			line.append(csvEscape(event.getEventType().getIdentifier())).append(",");
			line.append(csvEscape(event.getSeverity().getLabel())).append(",");
			line.append(csvEscape(event.getPrincipal())).append(",");
			line.append(csvEscape(event.getSessionId())).append(",");
			line.append(csvEscape(event.getDetail("operation"))).append(",");
			line.append(csvEscape(event.getContextValue("program")));
			writer.write(line.toString());
			writer.newLine();
		}
	}

	private void writeViolationsJson(List<ViolationIncident> violations, BufferedWriter writer)
			throws IOException {
		for (ViolationIncident violation : violations) {
			writer.write(violationToJson(violation));
			writer.newLine();
		}
	}

	private void writeViolationsCsv(List<ViolationIncident> violations, BufferedWriter writer)
			throws IOException {
		// Header
		writer.write("incidentId,timestamp,violationType,severity,principal,sessionId," +
			"policyName,violatedConstraint,remediationAction,escalated");
		writer.newLine();

		for (ViolationIncident violation : violations) {
			StringBuilder line = new StringBuilder();
			line.append(csvEscape(violation.getIncidentId())).append(",");
			line.append(csvEscape(TIMESTAMP_FORMAT.format(violation.getTimestamp()))).append(",");
			line.append(csvEscape(violation.getViolationType().getIdentifier())).append(",");
			line.append(csvEscape(violation.getSeverity().getLabel())).append(",");
			line.append(csvEscape(violation.getPrincipal())).append(",");
			line.append(csvEscape(violation.getSessionId())).append(",");
			line.append(csvEscape(violation.getPolicyName())).append(",");
			line.append(csvEscape(violation.getViolatedConstraint())).append(",");
			line.append(csvEscape(violation.getRemediationAction().name())).append(",");
			line.append(violation.isEscalated());
			writer.write(line.toString());
			writer.newLine();
		}
	}

	private void writeSummaryJson(AuditSummary summary, BufferedWriter writer) throws IOException {
		StringBuilder sb = new StringBuilder();
		sb.append("{\n");
		sb.append("  \"totalEvents\": ").append(summary.getTotalEvents()).append(",\n");
		sb.append("  \"totalViolations\": ").append(summary.getTotalViolations()).append(",\n");

		if (summary.getEarliestEvent() != null) {
			sb.append("  \"earliestEvent\": \"")
				.append(TIMESTAMP_FORMAT.format(summary.getEarliestEvent()))
				.append("\",\n");
		}
		if (summary.getLatestEvent() != null) {
			sb.append("  \"latestEvent\": \"")
				.append(TIMESTAMP_FORMAT.format(summary.getLatestEvent()))
				.append("\",\n");
		}

		sb.append("  \"eventsByType\": {\n");
		writeMapJson(sb, summary.getEventsByType(), "    ");
		sb.append("  },\n");

		sb.append("  \"eventsBySeverity\": {\n");
		writeMapJson(sb, summary.getEventsBySeverity(), "    ");
		sb.append("  },\n");

		sb.append("  \"eventsByPrincipal\": {\n");
		writeMapJson(sb, summary.getEventsByPrincipal(), "    ");
		sb.append("  }\n");

		sb.append("}\n");
		writer.write(sb.toString());
	}

	private <K> void writeMapJson(StringBuilder sb, Map<K, Long> map, String indent) {
		Iterator<Map.Entry<K, Long>> iter = map.entrySet().iterator();
		while (iter.hasNext()) {
			Map.Entry<K, Long> entry = iter.next();
			sb.append(indent).append("\"").append(entry.getKey()).append("\": ")
				.append(entry.getValue());
			if (iter.hasNext()) {
				sb.append(",");
			}
			sb.append("\n");
		}
	}

	private String eventToJson(SecurityAuditEvent event) {
		StringBuilder sb = new StringBuilder();
		sb.append("{");
		appendJsonField(sb, "eventId", event.getEventId(), true);
		appendJsonField(sb, "timestamp", TIMESTAMP_FORMAT.format(event.getTimestamp()), true);
		appendJsonField(sb, "eventType", event.getEventType().getIdentifier(), true);
		appendJsonField(sb, "severity", event.getSeverity().getLabel(), true);
		appendJsonField(sb, "principal", event.getPrincipal(), true);
		if (event.getSessionId() != null) {
			appendJsonField(sb, "sessionId", event.getSessionId(), true);
		}
		appendJsonMap(sb, "details", event.getDetails(), true);
		appendJsonMap(sb, "context", event.getContext(), false);
		sb.append("}");
		return sb.toString();
	}

	private String violationToJson(ViolationIncident incident) {
		StringBuilder sb = new StringBuilder();
		sb.append("{");
		appendJsonField(sb, "incidentId", incident.getIncidentId(), true);
		appendJsonField(sb, "timestamp", TIMESTAMP_FORMAT.format(incident.getTimestamp()), true);
		appendJsonField(sb, "violationType", incident.getViolationType().getIdentifier(), true);
		appendJsonField(sb, "severity", incident.getSeverity().getLabel(), true);
		appendJsonField(sb, "principal", incident.getPrincipal(), true);
		if (incident.getSessionId() != null) {
			appendJsonField(sb, "sessionId", incident.getSessionId(), true);
		}
		appendJsonField(sb, "policyName", incident.getPolicyName(), true);
		if (incident.getPolicyVersion() != null) {
			appendJsonField(sb, "policyVersion", incident.getPolicyVersion(), true);
		}
		appendJsonField(sb, "violatedConstraint", incident.getViolatedConstraint(), true);
		appendJsonField(sb, "remediationAction", incident.getRemediationAction().name(), true);
		if (incident.getRemediationDetails() != null) {
			appendJsonField(sb, "remediationDetails", incident.getRemediationDetails(), true);
		}
		appendJsonField(sb, "escalated", String.valueOf(incident.isEscalated()), true);
		appendJsonMap(sb, "details", incident.getDetails(), true);
		appendJsonMap(sb, "context", incident.getContext(), false);
		sb.append("}");
		return sb.toString();
	}

	private void appendJsonField(StringBuilder sb, String key, String value, boolean hasMore) {
		sb.append("\"").append(escapeJson(key)).append("\":\"")
			.append(escapeJson(value)).append("\"");
		if (hasMore) {
			sb.append(",");
		}
	}

	private void appendJsonMap(StringBuilder sb, String key, Map<String, String> map,
			boolean hasMore) {
		sb.append("\"").append(escapeJson(key)).append("\":{");
		boolean first = true;
		for (Map.Entry<String, String> entry : map.entrySet()) {
			if (!first) {
				sb.append(",");
			}
			sb.append("\"").append(escapeJson(entry.getKey())).append("\":\"")
				.append(escapeJson(entry.getValue())).append("\"");
			first = false;
		}
		sb.append("}");
		if (hasMore) {
			sb.append(",");
		}
	}

	private String escapeJson(String value) {
		if (value == null) {
			return "";
		}
		return value.replace("\\", "\\\\")
			.replace("\"", "\\\"")
			.replace("\n", "\\n")
			.replace("\r", "\\r")
			.replace("\t", "\\t");
	}

	private String csvEscape(String value) {
		if (value == null) {
			return "";
		}
		if (value.contains(",") || value.contains("\"") || value.contains("\n")) {
			return "\"" + value.replace("\"", "\"\"") + "\"";
		}
		return value;
	}

	/**
	 * Summary statistics for audit activity.
	 */
	public static final class AuditSummary {
		private final long totalEvents;
		private final long totalViolations;
		private final Instant earliestEvent;
		private final Instant latestEvent;
		private final Map<SecurityAuditEventType, Long> eventsByType;
		private final Map<Severity, Long> eventsBySeverity;
		private final Map<String, Long> eventsByPrincipal;

		AuditSummary(long totalEvents, long totalViolations, Instant earliestEvent,
				Instant latestEvent, Map<SecurityAuditEventType, Long> eventsByType,
				Map<Severity, Long> eventsBySeverity, Map<String, Long> eventsByPrincipal) {
			this.totalEvents = totalEvents;
			this.totalViolations = totalViolations;
			this.earliestEvent = earliestEvent;
			this.latestEvent = latestEvent;
			this.eventsByType = Collections.unmodifiableMap(new LinkedHashMap<>(eventsByType));
			this.eventsBySeverity = Collections.unmodifiableMap(new LinkedHashMap<>(eventsBySeverity));
			this.eventsByPrincipal = Collections.unmodifiableMap(new LinkedHashMap<>(eventsByPrincipal));
		}

		public long getTotalEvents() {
			return totalEvents;
		}

		public long getTotalViolations() {
			return totalViolations;
		}

		public Instant getEarliestEvent() {
			return earliestEvent;
		}

		public Instant getLatestEvent() {
			return latestEvent;
		}

		public Map<SecurityAuditEventType, Long> getEventsByType() {
			return eventsByType;
		}

		public Map<Severity, Long> getEventsBySeverity() {
			return eventsBySeverity;
		}

		public Map<String, Long> getEventsByPrincipal() {
			return eventsByPrincipal;
		}

		@Override
		public String toString() {
			return String.format(
				"AuditSummary[events=%d, violations=%d, from=%s, to=%s]",
				totalEvents, totalViolations, earliestEvent, latestEvent);
		}
	}
}
