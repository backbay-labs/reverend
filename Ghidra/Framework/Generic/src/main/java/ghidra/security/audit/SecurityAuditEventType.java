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

/**
 * Types of security-relevant events that should be logged for audit and compliance.
 * Based on the audit logging pipeline design from agent-runtime-security-spec.md.
 */
public enum SecurityAuditEventType {

	// === Capability events ===

	/** A capability check succeeded and the operation was permitted */
	CAPABILITY_GRANTED("CAPABILITY_GRANTED", Severity.INFO,
		"Agent permitted to perform operation"),

	/** A capability check failed and the operation was denied */
	CAPABILITY_DENIED("CAPABILITY_DENIED", Severity.WARNING,
		"Agent attempted action beyond its permissions"),

	/** A capability token was created/issued */
	TOKEN_CREATED("TOKEN_CREATED", Severity.INFO,
		"New capability token issued to principal"),

	/** A capability token expired during use */
	TOKEN_EXPIRED("TOKEN_EXPIRED", Severity.WARNING,
		"Agent continued operating with expired token"),

	// === Scope and limit events ===

	/** Operation target is outside the token's allowed scope */
	SCOPE_VIOLATION("SCOPE_VIOLATION", Severity.WARNING,
		"Operation target not in allowed scope"),

	/** Session mutation limit exceeded */
	MUTATION_LIMIT_EXCEEDED("MUTATION_LIMIT_EXCEEDED", Severity.WARNING,
		"Session mutation limit exceeded"),

	// === Egress events ===

	/** Outbound connection blocked by network policy */
	EGRESS_BLOCKED("EGRESS_BLOCKED", Severity.WARNING,
		"Outbound connection to non-allowed destination"),

	/** Raw binary content detected in outbound request */
	BINARY_CONTENT_IN_EGRESS("BINARY_CONTENT_IN_EGRESS", Severity.CRITICAL,
		"Raw binary content detected in outbound request"),

	/** Cumulative data sent to cloud API exceeds threshold */
	CONTENT_BUDGET_EXCEEDED("CONTENT_BUDGET_EXCEEDED", Severity.WARNING,
		"Cumulative data sent to cloud API exceeds threshold"),

	/** Request rate exceeded configured maximum */
	RATE_LIMIT_HIT("RATE_LIMIT_HIT", Severity.INFO,
		"Request rate exceeded configured maximum"),

	// === Sandbox events ===

	/** Process attempted to escape sandbox boundaries */
	SANDBOX_VIOLATION("SANDBOX_VIOLATION", Severity.CRITICAL,
		"Process attempted to escape sandbox boundaries"),

	/** Resource limit (CPU, memory, etc.) was hit */
	RESOURCE_LIMIT_HIT("RESOURCE_LIMIT_HIT", Severity.WARNING,
		"Resource limit reached for sandboxed process"),

	// === Integrity events ===

	/** Receipt chain hash verification failed */
	RECEIPT_CHAIN_BROKEN("RECEIPT_CHAIN_BROKEN", Severity.CRITICAL,
		"Hash chain integrity check failed"),

	// === Analysis mutation events ===

	/** An analysis mutation (rename, retype, etc.) was performed */
	ANALYSIS_MUTATION("ANALYSIS_MUTATION", Severity.INFO,
		"Analysis state was modified"),

	// === Session events ===

	/** A new agent session started */
	SESSION_STARTED("SESSION_STARTED", Severity.INFO,
		"Agent session initiated"),

	/** An agent session ended */
	SESSION_ENDED("SESSION_ENDED", Severity.INFO,
		"Agent session terminated");

	private final String identifier;
	private final Severity defaultSeverity;
	private final String description;

	SecurityAuditEventType(String identifier, Severity defaultSeverity, String description) {
		this.identifier = identifier;
		this.defaultSeverity = defaultSeverity;
		this.description = description;
	}

	/**
	 * Returns the string identifier for this event type.
	 * @return the event type identifier
	 */
	public String getIdentifier() {
		return identifier;
	}

	/**
	 * Returns the default severity level for this event type.
	 * @return the default severity
	 */
	public Severity getDefaultSeverity() {
		return defaultSeverity;
	}

	/**
	 * Returns a human-readable description of this event type.
	 * @return the description
	 */
	public String getDescription() {
		return description;
	}

	/**
	 * Checks if this event type represents a security violation.
	 * Violations are events that indicate a policy breach or attempted unauthorized action.
	 * @return true if this is a violation event
	 */
	public boolean isViolation() {
		return defaultSeverity == Severity.WARNING || defaultSeverity == Severity.CRITICAL;
	}

	/**
	 * Checks if this event type requires immediate alerting.
	 * @return true if this event should trigger an immediate alert
	 */
	public boolean requiresAlert() {
		return defaultSeverity == Severity.CRITICAL;
	}

	@Override
	public String toString() {
		return identifier;
	}
}
