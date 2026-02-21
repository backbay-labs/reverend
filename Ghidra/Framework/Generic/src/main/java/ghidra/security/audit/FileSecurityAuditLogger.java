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
import java.nio.file.*;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * File-based persistent implementation of {@link SecurityAuditLogger}.
 * Provides append-only audit logging suitable for compliance requirements.
 *
 * <p>This implementation:
 * <ul>
 *   <li>Writes events to append-only JSON-Lines (.jsonl) files</li>
 *   <li>Stores violations in a separate file for faster violation queries</li>
 *   <li>Supports file rotation by date</li>
 *   <li>Provides efficient query execution with streaming file reads</li>
 *   <li>Is thread-safe for concurrent logging and querying</li>
 * </ul>
 *
 * <p>File format follows NIST SP 800-53 AU-3 requirements for audit record content.
 */
public class FileSecurityAuditLogger implements SecurityAuditLogger, Closeable {

	private static final String EVENTS_FILE_PREFIX = "audit-events-";
	private static final String VIOLATIONS_FILE_PREFIX = "audit-violations-";
	private static final String FILE_EXTENSION = ".jsonl";
	private static final DateTimeFormatter DATE_FORMAT =
		DateTimeFormatter.ofPattern("yyyy-MM-dd").withZone(java.time.ZoneOffset.UTC);

	private final Path logDirectory;
	private final List<Consumer<SecurityAuditEvent>> alertListeners;
	private final ReadWriteLock lock;
	private final boolean rotateDaily;

	private volatile BufferedWriter eventsWriter;
	private volatile BufferedWriter violationsWriter;
	private volatile String currentDateSuffix;

	/**
	 * Creates a logger that writes to the specified directory.
	 *
	 * @param logDirectory the directory for audit log files
	 * @throws IOException if the directory cannot be created or accessed
	 */
	public FileSecurityAuditLogger(Path logDirectory) throws IOException {
		this(logDirectory, true);
	}

	/**
	 * Creates a logger with optional daily rotation.
	 *
	 * @param logDirectory the directory for audit log files
	 * @param rotateDaily if true, creates new files daily
	 * @throws IOException if the directory cannot be created or accessed
	 */
	public FileSecurityAuditLogger(Path logDirectory, boolean rotateDaily) throws IOException {
		this.logDirectory = Objects.requireNonNull(logDirectory, "logDirectory must not be null");
		this.rotateDaily = rotateDaily;
		this.alertListeners = new CopyOnWriteArrayList<>();
		this.lock = new ReentrantReadWriteLock();

		Files.createDirectories(logDirectory);
		openWriters();
	}

	@Override
	public void log(SecurityAuditEvent event) {
		Objects.requireNonNull(event, "event must not be null");

		lock.writeLock().lock();
		try {
			checkRotation();
			String jsonLine = eventToJson(event);
			eventsWriter.write(jsonLine);
			eventsWriter.newLine();
			eventsWriter.flush();
		}
		catch (IOException e) {
			throw new UncheckedIOException("Failed to write audit event", e);
		}
		finally {
			lock.writeLock().unlock();
		}

		// Dispatch alerts outside the lock
		if (event.getEventType().requiresAlert()) {
			dispatchAlert(event);
		}
	}

	@Override
	public void recordViolation(ViolationIncident incident) {
		Objects.requireNonNull(incident, "incident must not be null");

		// Log the underlying event first
		log(incident.getEvent());

		lock.writeLock().lock();
		try {
			checkRotation();
			String jsonLine = violationToJson(incident);
			violationsWriter.write(jsonLine);
			violationsWriter.newLine();
			violationsWriter.flush();
		}
		catch (IOException e) {
			throw new UncheckedIOException("Failed to write violation incident", e);
		}
		finally {
			lock.writeLock().unlock();
		}
	}

	@Override
	public List<SecurityAuditEvent> queryEvents(AuditQuery query) {
		Objects.requireNonNull(query, "query must not be null");

		lock.readLock().lock();
		try {
			return streamEventFiles()
				.flatMap(this::readEventsFromFile)
				.filter(query::matches)
				.sorted(Comparator.comparing(SecurityAuditEvent::getTimestamp).reversed())
				.skip(query.getOffset())
				.limit(query.getLimit())
				.collect(Collectors.toList());
		}
		finally {
			lock.readLock().unlock();
		}
	}

	@Override
	public List<ViolationIncident> queryViolations(AuditQuery query) {
		Objects.requireNonNull(query, "query must not be null");

		lock.readLock().lock();
		try {
			return streamViolationFiles()
				.flatMap(this::readViolationsFromFile)
				.filter(v -> query.matches(v.getEvent()))
				.sorted(Comparator.comparing(ViolationIncident::getTimestamp).reversed())
				.skip(query.getOffset())
				.limit(query.getLimit())
				.collect(Collectors.toList());
		}
		finally {
			lock.readLock().unlock();
		}
	}

	@Override
	public long getEventCount() {
		lock.readLock().lock();
		try {
			return streamEventFiles()
				.flatMap(this::readEventsFromFile)
				.count();
		}
		finally {
			lock.readLock().unlock();
		}
	}

	@Override
	public long getViolationCount() {
		lock.readLock().lock();
		try {
			return streamViolationFiles()
				.flatMap(this::readViolationsFromFile)
				.count();
		}
		finally {
			lock.readLock().unlock();
		}
	}

	@Override
	public void addAlertListener(Consumer<SecurityAuditEvent> listener) {
		Objects.requireNonNull(listener, "listener must not be null");
		alertListeners.add(listener);
	}

	@Override
	public void removeAlertListener(Consumer<SecurityAuditEvent> listener) {
		alertListeners.remove(listener);
	}

	/**
	 * Returns the log directory path.
	 * @return the log directory
	 */
	public Path getLogDirectory() {
		return logDirectory;
	}

	/**
	 * Lists all audit event files in the log directory.
	 * @return list of event file paths, sorted by date
	 * @throws IOException if the directory cannot be read
	 */
	public List<Path> listEventFiles() throws IOException {
		try (Stream<Path> stream = Files.list(logDirectory)) {
			return stream
				.filter(p -> p.getFileName().toString().startsWith(EVENTS_FILE_PREFIX))
				.filter(p -> p.getFileName().toString().endsWith(FILE_EXTENSION))
				.sorted()
				.collect(Collectors.toList());
		}
	}

	/**
	 * Lists all violation files in the log directory.
	 * @return list of violation file paths, sorted by date
	 * @throws IOException if the directory cannot be read
	 */
	public List<Path> listViolationFiles() throws IOException {
		try (Stream<Path> stream = Files.list(logDirectory)) {
			return stream
				.filter(p -> p.getFileName().toString().startsWith(VIOLATIONS_FILE_PREFIX))
				.filter(p -> p.getFileName().toString().endsWith(FILE_EXTENSION))
				.sorted()
				.collect(Collectors.toList());
		}
	}

	@Override
	public void close() throws IOException {
		lock.writeLock().lock();
		try {
			if (eventsWriter != null) {
				eventsWriter.close();
				eventsWriter = null;
			}
			if (violationsWriter != null) {
				violationsWriter.close();
				violationsWriter = null;
			}
		}
		finally {
			lock.writeLock().unlock();
		}
	}

	private void openWriters() throws IOException {
		currentDateSuffix = rotateDaily ? DATE_FORMAT.format(Instant.now()) : "all";
		Path eventsFile = logDirectory.resolve(EVENTS_FILE_PREFIX + currentDateSuffix + FILE_EXTENSION);
		Path violationsFile =
			logDirectory.resolve(VIOLATIONS_FILE_PREFIX + currentDateSuffix + FILE_EXTENSION);

		eventsWriter = Files.newBufferedWriter(eventsFile, StandardCharsets.UTF_8,
			StandardOpenOption.CREATE, StandardOpenOption.APPEND);
		violationsWriter = Files.newBufferedWriter(violationsFile, StandardCharsets.UTF_8,
			StandardOpenOption.CREATE, StandardOpenOption.APPEND);
	}

	private void checkRotation() throws IOException {
		if (!rotateDaily) {
			return;
		}
		String newDateSuffix = DATE_FORMAT.format(Instant.now());
		if (!newDateSuffix.equals(currentDateSuffix)) {
			if (eventsWriter != null) {
				eventsWriter.close();
			}
			if (violationsWriter != null) {
				violationsWriter.close();
			}
			openWriters();
		}
	}

	private Stream<Path> streamEventFiles() {
		try {
			return Files.list(logDirectory)
				.filter(p -> p.getFileName().toString().startsWith(EVENTS_FILE_PREFIX))
				.filter(p -> p.getFileName().toString().endsWith(FILE_EXTENSION));
		}
		catch (IOException e) {
			return Stream.empty();
		}
	}

	private Stream<Path> streamViolationFiles() {
		try {
			return Files.list(logDirectory)
				.filter(p -> p.getFileName().toString().startsWith(VIOLATIONS_FILE_PREFIX))
				.filter(p -> p.getFileName().toString().endsWith(FILE_EXTENSION));
		}
		catch (IOException e) {
			return Stream.empty();
		}
	}

	private Stream<SecurityAuditEvent> readEventsFromFile(Path file) {
		try {
			return Files.lines(file, StandardCharsets.UTF_8)
				.filter(line -> !line.trim().isEmpty())
				.map(this::parseEvent)
				.filter(Objects::nonNull);
		}
		catch (IOException e) {
			return Stream.empty();
		}
	}

	private Stream<ViolationIncident> readViolationsFromFile(Path file) {
		try {
			return Files.lines(file, StandardCharsets.UTF_8)
				.filter(line -> !line.trim().isEmpty())
				.map(this::parseViolation)
				.filter(Objects::nonNull);
		}
		catch (IOException e) {
			return Stream.empty();
		}
	}

	private void dispatchAlert(SecurityAuditEvent event) {
		for (Consumer<SecurityAuditEvent> listener : alertListeners) {
			try {
				listener.accept(event);
			}
			catch (Exception e) {
				// Log but don't propagate listener exceptions
				System.err.println("Alert listener threw exception: " + e.getMessage());
			}
		}
	}

	// Simple JSON serialization - avoids external dependencies
	private String eventToJson(SecurityAuditEvent event) {
		StringBuilder sb = new StringBuilder();
		sb.append("{");
		appendJsonField(sb, "eventId", event.getEventId(), true);
		appendJsonField(sb, "timestamp", event.getTimestamp().toString(), true);
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
		appendJsonField(sb, "timestamp", incident.getTimestamp().toString(), true);
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
		appendJsonField(sb, "remediationAction",
			incident.getRemediationAction().name(), true);
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

	private SecurityAuditEvent parseEvent(String jsonLine) {
		try {
			Map<String, String> fields = parseSimpleJson(jsonLine);
			if (fields.isEmpty()) {
				return null;
			}

			SecurityAuditEvent.Builder builder = SecurityAuditEvent.builder()
				.eventId(fields.get("eventId"))
				.timestamp(Instant.parse(fields.get("timestamp")))
				.eventType(parseEventType(fields.get("eventType")))
				.severity(parseSeverity(fields.get("severity")))
				.principal(fields.get("principal"))
				.sessionId(fields.get("sessionId"));

			// Add details and context from nested objects
			for (Map.Entry<String, String> entry : fields.entrySet()) {
				String key = entry.getKey();
				if (key.startsWith("details.")) {
					builder.detail(key.substring(8), entry.getValue());
				}
				else if (key.startsWith("context.")) {
					builder.context(key.substring(8), entry.getValue());
				}
			}

			return builder.build();
		}
		catch (Exception e) {
			return null;
		}
	}

	private ViolationIncident parseViolation(String jsonLine) {
		try {
			Map<String, String> fields = parseSimpleJson(jsonLine);
			if (fields.isEmpty()) {
				return null;
			}

			// Build the underlying event
			SecurityAuditEvent.Builder eventBuilder = SecurityAuditEvent.builder()
				.eventId(fields.get("incidentId"))
				.timestamp(Instant.parse(fields.get("timestamp")))
				.eventType(parseEventType(fields.get("violationType")))
				.severity(parseSeverity(fields.get("severity")))
				.principal(fields.get("principal"))
				.sessionId(fields.get("sessionId"));

			for (Map.Entry<String, String> entry : fields.entrySet()) {
				String key = entry.getKey();
				if (key.startsWith("details.")) {
					eventBuilder.detail(key.substring(8), entry.getValue());
				}
				else if (key.startsWith("context.")) {
					eventBuilder.context(key.substring(8), entry.getValue());
				}
			}

			return ViolationIncident.builder()
				.incidentId(fields.get("incidentId"))
				.event(eventBuilder.build())
				.policyName(fields.get("policyName"))
				.policyVersion(fields.get("policyVersion"))
				.violatedConstraint(fields.get("violatedConstraint"))
				.remediationAction(parseRemediationAction(fields.get("remediationAction")))
				.remediationDetails(fields.get("remediationDetails"))
				.escalated(Boolean.parseBoolean(fields.get("escalated")))
				.build();
		}
		catch (Exception e) {
			return null;
		}
	}

	private Map<String, String> parseSimpleJson(String json) {
		Map<String, String> result = new LinkedHashMap<>();
		// Simple parser for our known JSON format
		json = json.trim();
		if (!json.startsWith("{") || !json.endsWith("}")) {
			return result;
		}
		json = json.substring(1, json.length() - 1);

		String currentKey = null;
		String currentNested = null;
		StringBuilder value = new StringBuilder();
		boolean inString = false;
		boolean escaped = false;
		int braceDepth = 0;

		for (int i = 0; i < json.length(); i++) {
			char c = json.charAt(i);

			if (escaped) {
				value.append(c);
				escaped = false;
				continue;
			}

			if (c == '\\') {
				escaped = true;
				value.append(c);
				continue;
			}

			if (c == '"' && braceDepth == 0) {
				inString = !inString;
				continue;
			}

			if (inString) {
				value.append(c);
				continue;
			}

			if (c == '{') {
				braceDepth++;
				if (braceDepth == 1 && currentKey != null) {
					currentNested = currentKey;
					currentKey = null;
					value = new StringBuilder();
				}
				continue;
			}

			if (c == '}') {
				braceDepth--;
				if (braceDepth == 0 && currentNested != null) {
					currentNested = null;
				}
				continue;
			}

			if (braceDepth > 0) {
				// Inside nested object
				if (c == ':' && currentKey == null) {
					currentKey = value.toString().trim();
					value = new StringBuilder();
				}
				else if (c == ',') {
					if (currentKey != null && currentNested != null) {
						result.put(currentNested + "." + currentKey,
							unescapeJson(value.toString().trim()));
					}
					currentKey = null;
					value = new StringBuilder();
				}
				else {
					value.append(c);
				}
				continue;
			}

			if (c == ':' && currentKey == null) {
				currentKey = value.toString().trim();
				value = new StringBuilder();
			}
			else if (c == ',') {
				if (currentKey != null) {
					result.put(currentKey, unescapeJson(value.toString().trim()));
				}
				currentKey = null;
				value = new StringBuilder();
			}
			else {
				value.append(c);
			}
		}

		// Handle last key if inside nested
		if (currentKey != null && currentNested != null) {
			result.put(currentNested + "." + currentKey,
				unescapeJson(value.toString().trim()));
		}
		else if (currentKey != null) {
			result.put(currentKey, unescapeJson(value.toString().trim()));
		}

		return result;
	}

	private String unescapeJson(String value) {
		return value.replace("\\n", "\n")
			.replace("\\r", "\r")
			.replace("\\t", "\t")
			.replace("\\\"", "\"")
			.replace("\\\\", "\\");
	}

	private SecurityAuditEventType parseEventType(String value) {
		if (value == null) {
			return SecurityAuditEventType.CAPABILITY_GRANTED;
		}
		for (SecurityAuditEventType type : SecurityAuditEventType.values()) {
			if (type.getIdentifier().equals(value)) {
				return type;
			}
		}
		return SecurityAuditEventType.CAPABILITY_GRANTED;
	}

	private Severity parseSeverity(String value) {
		if (value == null) {
			return Severity.INFO;
		}
		for (Severity sev : Severity.values()) {
			if (sev.getLabel().equals(value)) {
				return sev;
			}
		}
		return Severity.INFO;
	}

	private ViolationIncident.RemediationAction parseRemediationAction(String value) {
		if (value == null) {
			return ViolationIncident.RemediationAction.LOGGED_ONLY;
		}
		try {
			return ViolationIncident.RemediationAction.valueOf(value);
		}
		catch (IllegalArgumentException e) {
			return ViolationIncident.RemediationAction.LOGGED_ONLY;
		}
	}
}
