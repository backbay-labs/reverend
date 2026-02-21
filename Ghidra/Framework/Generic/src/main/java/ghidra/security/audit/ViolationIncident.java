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
 * A detailed record of a security policy violation, including policy context
 * and remediation action taken. This extends the base audit event with
 * violation-specific fields for compliance review.
 *
 * <p>Violation incidents are generated when:
 * <ul>
 *   <li>A capability check fails (CAPABILITY_DENIED)</li>
 *   <li>An operation exceeds its allowed scope (SCOPE_VIOLATION)</li>
 *   <li>Session limits are exceeded (MUTATION_LIMIT_EXCEEDED)</li>
 *   <li>Network egress is blocked (EGRESS_BLOCKED)</li>
 *   <li>Sandbox boundaries are breached (SANDBOX_VIOLATION)</li>
 * </ul>
 */
public final class ViolationIncident {

	/**
	 * Actions taken in response to a violation.
	 */
	public enum RemediationAction {
		/** The violating operation was blocked and an exception thrown */
		BLOCKED("Operation blocked and denied"),
		/** The session was terminated after the violation */
		SESSION_TERMINATED("Agent session terminated"),
		/** The token was revoked after the violation */
		TOKEN_REVOKED("Capability token revoked"),
		/** An alert was sent to security monitoring */
		ALERT_SENT("Security alert dispatched"),
		/** The incident was logged but no immediate action taken */
		LOGGED_ONLY("Incident logged for review"),
		/** Manual review is required before proceeding */
		REQUIRES_REVIEW("Manual review required");

		private final String description;

		RemediationAction(String description) {
			this.description = description;
		}

		public String getDescription() {
			return description;
		}
	}

	private final String incidentId;
	private final SecurityAuditEvent event;
	private final String policyName;
	private final String policyVersion;
	private final String violatedConstraint;
	private final RemediationAction remediationAction;
	private final String remediationDetails;
	private final boolean escalated;

	private ViolationIncident(Builder builder) {
		this.incidentId = builder.incidentId != null
			? builder.incidentId : UUID.randomUUID().toString();
		this.event = Objects.requireNonNull(builder.event, "event is required");
		this.policyName = Objects.requireNonNull(builder.policyName, "policyName is required");
		this.policyVersion = builder.policyVersion;
		this.violatedConstraint = Objects.requireNonNull(
			builder.violatedConstraint, "violatedConstraint is required");
		this.remediationAction = Objects.requireNonNull(
			builder.remediationAction, "remediationAction is required");
		this.remediationDetails = builder.remediationDetails;
		this.escalated = builder.escalated;
	}

	/**
	 * Returns the unique identifier for this incident.
	 * @return the incident ID
	 */
	public String getIncidentId() {
		return incidentId;
	}

	/**
	 * Returns the underlying security audit event.
	 * @return the audit event
	 */
	public SecurityAuditEvent getEvent() {
		return event;
	}

	/**
	 * Returns when this incident occurred.
	 * @return the incident timestamp
	 */
	public Instant getTimestamp() {
		return event.getTimestamp();
	}

	/**
	 * Returns the type of violation.
	 * @return the event type
	 */
	public SecurityAuditEventType getViolationType() {
		return event.getEventType();
	}

	/**
	 * Returns the severity of this incident.
	 * @return the severity
	 */
	public Severity getSeverity() {
		return event.getSeverity();
	}

	/**
	 * Returns the principal that caused the violation.
	 * @return the principal identifier
	 */
	public String getPrincipal() {
		return event.getPrincipal();
	}

	/**
	 * Returns the session ID where the violation occurred.
	 * @return the session ID or null
	 */
	public String getSessionId() {
		return event.getSessionId();
	}

	/**
	 * Returns the name of the policy that was violated.
	 * Examples: "capability-token-policy", "egress-allow-list", "sandbox-boundaries"
	 * @return the policy name
	 */
	public String getPolicyName() {
		return policyName;
	}

	/**
	 * Returns the version of the policy that was violated.
	 * @return the policy version or null
	 */
	public String getPolicyVersion() {
		return policyVersion;
	}

	/**
	 * Returns a description of the specific constraint that was violated.
	 * Examples: "Capability WRITE.PATCH not granted to profile 'annotator'"
	 * @return the violated constraint description
	 */
	public String getViolatedConstraint() {
		return violatedConstraint;
	}

	/**
	 * Returns the remediation action taken in response to this violation.
	 * @return the remediation action
	 */
	public RemediationAction getRemediationAction() {
		return remediationAction;
	}

	/**
	 * Returns additional details about the remediation taken.
	 * @return remediation details or null
	 */
	public String getRemediationDetails() {
		return remediationDetails;
	}

	/**
	 * Returns whether this incident was escalated to security monitoring.
	 * @return true if escalated
	 */
	public boolean isEscalated() {
		return escalated;
	}

	/**
	 * Returns the event details map.
	 * @return the details map
	 */
	public Map<String, String> getDetails() {
		return event.getDetails();
	}

	/**
	 * Returns the event context map.
	 * @return the context map
	 */
	public Map<String, String> getContext() {
		return event.getContext();
	}

	/**
	 * Creates a new builder for constructing violation incidents.
	 * @return a new builder
	 */
	public static Builder builder() {
		return new Builder();
	}

	/**
	 * Creates a violation incident from a capability denial exception.
	 *
	 * @param exception the denial exception
	 * @param sessionId the session ID
	 * @param tokenId the capability token ID
	 * @return the violation incident
	 */
	public static ViolationIncident fromCapabilityDenial(
			ghidra.security.capability.CapabilityDeniedException exception,
			String sessionId,
			String tokenId) {

		SecurityAuditEventType eventType = mapDenialReasonToEventType(exception.getReason());

		SecurityAuditEvent event = SecurityAuditEvent.builder()
			.eventType(eventType)
			.principal(exception.getPrincipal())
			.sessionId(sessionId)
			.detail("denied_capability",
				exception.getDeniedCapability() != null
					? exception.getDeniedCapability().getIdentifier()
					: "unknown")
			.detail("denial_reason", exception.getReason().name())
			.detail("profile", exception.getProfile())
			.detail("operation", exception.getOperation())
			.detail("token_id", tokenId)
			.build();

		return builder()
			.event(event)
			.policyName("capability-token-policy")
			.violatedConstraint(buildConstraintDescription(exception))
			.remediationAction(RemediationAction.BLOCKED)
			.remediationDetails("Operation denied; CapabilityDeniedException thrown")
			.escalated(eventType.requiresAlert())
			.build();
	}

	private static SecurityAuditEventType mapDenialReasonToEventType(
			ghidra.security.capability.CapabilityDeniedException.DenialReason reason) {
		switch (reason) {
			case TOKEN_EXPIRED:
				return SecurityAuditEventType.TOKEN_EXPIRED;
			case SCOPE_VIOLATION:
				return SecurityAuditEventType.SCOPE_VIOLATION;
			case MUTATION_LIMIT_EXCEEDED:
				return SecurityAuditEventType.MUTATION_LIMIT_EXCEEDED;
			case CAPABILITY_NOT_GRANTED:
			case NO_TOKEN:
			case RECEIPT_REQUIRED:
			default:
				return SecurityAuditEventType.CAPABILITY_DENIED;
		}
	}

	private static String buildConstraintDescription(
			ghidra.security.capability.CapabilityDeniedException exception) {
		String capability = exception.getDeniedCapability() != null
			? exception.getDeniedCapability().getIdentifier()
			: "unknown";
		return String.format("Capability %s not granted to profile '%s': %s",
			capability, exception.getProfile(), exception.getReason().getDescription());
	}

	@Override
	public String toString() {
		return String.format(
			"ViolationIncident[%s type=%s principal=%s policy=%s remediation=%s]",
			incidentId.substring(0, 8),
			event.getEventType(),
			event.getPrincipal(),
			policyName,
			remediationAction);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof ViolationIncident)) {
			return false;
		}
		ViolationIncident other = (ViolationIncident) obj;
		return incidentId.equals(other.incidentId);
	}

	@Override
	public int hashCode() {
		return incidentId.hashCode();
	}

	/**
	 * Builder for creating violation incidents.
	 */
	public static final class Builder {
		private String incidentId;
		private SecurityAuditEvent event;
		private String policyName;
		private String policyVersion;
		private String violatedConstraint;
		private RemediationAction remediationAction;
		private String remediationDetails;
		private boolean escalated;

		private Builder() {
		}

		public Builder incidentId(String incidentId) {
			this.incidentId = incidentId;
			return this;
		}

		public Builder event(SecurityAuditEvent event) {
			this.event = event;
			return this;
		}

		public Builder policyName(String policyName) {
			this.policyName = policyName;
			return this;
		}

		public Builder policyVersion(String policyVersion) {
			this.policyVersion = policyVersion;
			return this;
		}

		public Builder violatedConstraint(String violatedConstraint) {
			this.violatedConstraint = violatedConstraint;
			return this;
		}

		public Builder remediationAction(RemediationAction remediationAction) {
			this.remediationAction = remediationAction;
			return this;
		}

		public Builder remediationDetails(String remediationDetails) {
			this.remediationDetails = remediationDetails;
			return this;
		}

		public Builder escalated(boolean escalated) {
			this.escalated = escalated;
			return this;
		}

		public ViolationIncident build() {
			return new ViolationIncident(this);
		}
	}
}
