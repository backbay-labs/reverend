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

import java.time.Instant;
import java.util.*;

/**
 * An immutable record of a security-relevant event for audit and compliance purposes.
 * Each event includes the actor, time, target, and contextual details.
 *
 * <p>Event schema based on agent-runtime-security-spec section 8.4:
 * <pre>
 * {
 *   "timestamp": "2026-02-19T14:32:01.123Z",
 *   "event_type": "CAPABILITY_DENIED",
 *   "severity": "WARNING",
 *   "principal": "agent:claude-opus-4-6",
 *   "session_id": "uuid",
 *   "details": { ... },
 *   "context": { ... }
 * }
 * </pre>
 */
public final class SecurityAuditEvent {

	private final String eventId;
	private final Instant timestamp;
	private final SecurityAuditEventType eventType;
	private final Severity severity;
	private final String principal;
	private final String sessionId;
	private final Map<String, String> details;
	private final Map<String, String> context;

	private SecurityAuditEvent(Builder builder) {
		this.eventId = builder.eventId != null ? builder.eventId : UUID.randomUUID().toString();
		this.timestamp = builder.timestamp != null ? builder.timestamp : Instant.now();
		this.eventType = Objects.requireNonNull(builder.eventType, "eventType is required");
		this.severity = builder.severity != null ? builder.severity : eventType.getDefaultSeverity();
		this.principal = Objects.requireNonNull(builder.principal, "principal is required");
		this.sessionId = builder.sessionId;
		this.details = Collections.unmodifiableMap(new LinkedHashMap<>(builder.details));
		this.context = Collections.unmodifiableMap(new LinkedHashMap<>(builder.context));
	}

	/**
	 * Returns the unique identifier for this event.
	 * @return the event ID (UUID format)
	 */
	public String getEventId() {
		return eventId;
	}

	/**
	 * Returns when this event occurred.
	 * @return the event timestamp
	 */
	public Instant getTimestamp() {
		return timestamp;
	}

	/**
	 * Returns the type of security event.
	 * @return the event type
	 */
	public SecurityAuditEventType getEventType() {
		return eventType;
	}

	/**
	 * Returns the severity level of this event.
	 * @return the severity
	 */
	public Severity getSeverity() {
		return severity;
	}

	/**
	 * Returns the principal (actor) that triggered this event.
	 * Format: "agent:model-name" or "user:username"
	 * @return the principal identifier
	 */
	public String getPrincipal() {
		return principal;
	}

	/**
	 * Returns the session ID associated with this event, or null if not applicable.
	 * @return the session ID or null
	 */
	public String getSessionId() {
		return sessionId;
	}

	/**
	 * Returns event-specific details as key-value pairs.
	 * Examples: "requested_capability", "tool_call", "target_address"
	 * @return immutable map of details
	 */
	public Map<String, String> getDetails() {
		return details;
	}

	/**
	 * Returns the value of a specific detail, or null if not present.
	 * @param key the detail key
	 * @return the detail value or null
	 */
	public String getDetail(String key) {
		return details.get(key);
	}

	/**
	 * Returns contextual information about the event.
	 * Examples: "program", "active_function"
	 * @return immutable map of context
	 */
	public Map<String, String> getContext() {
		return context;
	}

	/**
	 * Returns the value of a specific context field, or null if not present.
	 * @param key the context key
	 * @return the context value or null
	 */
	public String getContextValue(String key) {
		return context.get(key);
	}

	/**
	 * Checks if this event represents a security violation.
	 * @return true if this is a violation event
	 */
	public boolean isViolation() {
		return eventType.isViolation();
	}

	/**
	 * Creates a new builder for constructing audit events.
	 * @return a new builder
	 */
	public static Builder builder() {
		return new Builder();
	}

	/**
	 * Creates a builder initialized with values from this event.
	 * Useful for creating derived events.
	 * @return a new builder with copied values
	 */
	public Builder toBuilder() {
		return new Builder()
			.eventType(eventType)
			.severity(severity)
			.principal(principal)
			.sessionId(sessionId)
			.details(details)
			.context(context);
	}

	@Override
	public String toString() {
		return String.format(
			"SecurityAuditEvent[%s/%s principal=%s type=%s at %s]",
			eventId.substring(0, 8), severity, principal, eventType, timestamp);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof SecurityAuditEvent)) {
			return false;
		}
		SecurityAuditEvent other = (SecurityAuditEvent) obj;
		return eventId.equals(other.eventId);
	}

	@Override
	public int hashCode() {
		return eventId.hashCode();
	}

	/**
	 * Builder for creating security audit events.
	 */
	public static final class Builder {
		private String eventId;
		private Instant timestamp;
		private SecurityAuditEventType eventType;
		private Severity severity;
		private String principal;
		private String sessionId;
		private Map<String, String> details = new LinkedHashMap<>();
		private Map<String, String> context = new LinkedHashMap<>();

		private Builder() {
		}

		public Builder eventId(String eventId) {
			this.eventId = eventId;
			return this;
		}

		public Builder timestamp(Instant timestamp) {
			this.timestamp = timestamp;
			return this;
		}

		public Builder eventType(SecurityAuditEventType eventType) {
			this.eventType = eventType;
			return this;
		}

		public Builder severity(Severity severity) {
			this.severity = severity;
			return this;
		}

		public Builder principal(String principal) {
			this.principal = principal;
			return this;
		}

		public Builder sessionId(String sessionId) {
			this.sessionId = sessionId;
			return this;
		}

		public Builder detail(String key, String value) {
			if (value != null) {
				this.details.put(key, value);
			}
			return this;
		}

		public Builder details(Map<String, String> details) {
			this.details.putAll(details);
			return this;
		}

		public Builder context(String key, String value) {
			if (value != null) {
				this.context.put(key, value);
			}
			return this;
		}

		public Builder context(Map<String, String> context) {
			this.context.putAll(context);
			return this;
		}

		public SecurityAuditEvent build() {
			return new SecurityAuditEvent(this);
		}
	}
}
