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
import java.util.List;
import java.util.function.Consumer;

/**
 * Interface for logging security audit events and querying the audit trail.
 * Implementations must be thread-safe and provide durable storage for compliance.
 *
 * <p>The audit logger provides:
 * <ul>
 *   <li>Event logging with timestamp and actor attribution</li>
 *   <li>Violation incident recording with policy context</li>
 *   <li>Query interface for compliance review</li>
 *   <li>Real-time alert hooks for critical events</li>
 * </ul>
 */
public interface SecurityAuditLogger {

	/**
	 * Logs a security audit event.
	 * @param event the event to log
	 */
	void log(SecurityAuditEvent event);

	/**
	 * Records a violation incident with full policy context.
	 * This automatically logs the underlying event and stores the incident record.
	 * @param incident the violation incident to record
	 */
	void recordViolation(ViolationIncident incident);

	/**
	 * Queries events matching the specified criteria.
	 * @param query the query parameters
	 * @return list of matching events, ordered by timestamp descending
	 */
	List<SecurityAuditEvent> queryEvents(AuditQuery query);

	/**
	 * Queries violation incidents matching the specified criteria.
	 * @param query the query parameters
	 * @return list of matching incidents, ordered by timestamp descending
	 */
	List<ViolationIncident> queryViolations(AuditQuery query);

	/**
	 * Returns the total number of events logged.
	 * @return the event count
	 */
	long getEventCount();

	/**
	 * Returns the total number of violation incidents recorded.
	 * @return the violation count
	 */
	long getViolationCount();

	/**
	 * Registers a listener for real-time alerts on critical events.
	 * @param listener the alert listener
	 */
	void addAlertListener(Consumer<SecurityAuditEvent> listener);

	/**
	 * Removes a previously registered alert listener.
	 * @param listener the listener to remove
	 */
	void removeAlertListener(Consumer<SecurityAuditEvent> listener);

	/**
	 * Query parameters for searching audit logs.
	 */
	final class AuditQuery {
		private final Instant startTime;
		private final Instant endTime;
		private final String principal;
		private final String sessionId;
		private final SecurityAuditEventType eventType;
		private final Severity minSeverity;
		private final boolean violationsOnly;
		private final int limit;
		private final int offset;

		private AuditQuery(Builder builder) {
			this.startTime = builder.startTime;
			this.endTime = builder.endTime;
			this.principal = builder.principal;
			this.sessionId = builder.sessionId;
			this.eventType = builder.eventType;
			this.minSeverity = builder.minSeverity;
			this.violationsOnly = builder.violationsOnly;
			this.limit = builder.limit > 0 ? builder.limit : 100;
			this.offset = builder.offset >= 0 ? builder.offset : 0;
		}

		public Instant getStartTime() {
			return startTime;
		}

		public Instant getEndTime() {
			return endTime;
		}

		public String getPrincipal() {
			return principal;
		}

		public String getSessionId() {
			return sessionId;
		}

		public SecurityAuditEventType getEventType() {
			return eventType;
		}

		public Severity getMinSeverity() {
			return minSeverity;
		}

		public boolean isViolationsOnly() {
			return violationsOnly;
		}

		public int getLimit() {
			return limit;
		}

		public int getOffset() {
			return offset;
		}

		/**
		 * Tests if an event matches this query's criteria.
		 * @param event the event to test
		 * @return true if the event matches
		 */
		public boolean matches(SecurityAuditEvent event) {
			if (startTime != null && event.getTimestamp().isBefore(startTime)) {
				return false;
			}
			if (endTime != null && event.getTimestamp().isAfter(endTime)) {
				return false;
			}
			if (principal != null && !principal.equals(event.getPrincipal())) {
				return false;
			}
			if (sessionId != null && !sessionId.equals(event.getSessionId())) {
				return false;
			}
			if (eventType != null && eventType != event.getEventType()) {
				return false;
			}
			if (minSeverity != null && !event.getSeverity().isAtLeast(minSeverity)) {
				return false;
			}
			if (violationsOnly && !event.isViolation()) {
				return false;
			}
			return true;
		}

		public static Builder builder() {
			return new Builder();
		}

		public static final class Builder {
			private Instant startTime;
			private Instant endTime;
			private String principal;
			private String sessionId;
			private SecurityAuditEventType eventType;
			private Severity minSeverity;
			private boolean violationsOnly;
			private int limit = 100;
			private int offset = 0;

			private Builder() {
			}

			public Builder startTime(Instant startTime) {
				this.startTime = startTime;
				return this;
			}

			public Builder endTime(Instant endTime) {
				this.endTime = endTime;
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

			public Builder eventType(SecurityAuditEventType eventType) {
				this.eventType = eventType;
				return this;
			}

			public Builder minSeverity(Severity minSeverity) {
				this.minSeverity = minSeverity;
				return this;
			}

			public Builder violationsOnly(boolean violationsOnly) {
				this.violationsOnly = violationsOnly;
				return this;
			}

			public Builder limit(int limit) {
				this.limit = limit;
				return this;
			}

			public Builder offset(int offset) {
				this.offset = offset;
				return this;
			}

			public AuditQuery build() {
				return new AuditQuery(this);
			}
		}
	}
}
