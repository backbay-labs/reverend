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
package ghidra.security.policy;

/**
 * Exception thrown when an egress policy violation is detected.
 * Implements deterministic mitigation behavior: violations fail explicitly
 * with a clear reason and suggested mitigation action.
 *
 * <p>Each violation includes:
 * <ul>
 *   <li>The violation type (what rule was violated)</li>
 *   <li>The blocked destination or operation</li>
 *   <li>The active policy mode</li>
 *   <li>Suggested mitigation action</li>
 * </ul>
 */
public class PolicyViolationException extends SecurityException {

	private static final long serialVersionUID = 1L;

	private final ViolationType type;
	private final String destination;
	private final PolicyMode mode;
	private final MitigationAction suggestedAction;

	/**
	 * Types of policy violations.
	 */
	public enum ViolationType {
		/** Network access attempted in offline mode */
		NETWORK_ACCESS_IN_OFFLINE_MODE("Network access not permitted in offline mode"),

		/** Endpoint not in the allowlist */
		ENDPOINT_NOT_ALLOWED("Endpoint not in allowlist"),

		/** Endpoint matches a blocked pattern */
		ENDPOINT_BLOCKED("Endpoint matches blocked pattern"),

		/** Payload size exceeds threshold */
		PAYLOAD_TOO_LARGE("Request payload exceeds size threshold"),

		/** Request rate exceeded limit */
		RATE_LIMIT_EXCEEDED("Request rate limit exceeded"),

		/** Binary content detected in outbound request */
		BINARY_CONTENT_DETECTED("Binary content detected in outbound request");

		private final String description;

		ViolationType(String description) {
			this.description = description;
		}

		public String getDescription() {
			return description;
		}
	}

	/**
	 * Suggested mitigation actions for policy violations.
	 */
	public enum MitigationAction {
		/** Switch to a different policy mode */
		CHANGE_POLICY_MODE("Change project policy mode to enable network access"),

		/** Add the endpoint to the allowlist */
		ADD_TO_ALLOWLIST("Add endpoint to project allowlist"),

		/** Use a local/offline model instead */
		USE_LOCAL_MODEL("Use a local inference model (Ollama, vLLM)"),

		/** Reduce payload size */
		REDUCE_PAYLOAD("Reduce request payload size or use abstracted representations"),

		/** Wait and retry */
		WAIT_AND_RETRY("Wait before retrying request"),

		/** Strip binary content */
		STRIP_BINARY_CONTENT("Remove binary content from request payload"),

		/** Contact administrator */
		CONTACT_ADMIN("Contact security administrator for policy review");

		private final String description;

		MitigationAction(String description) {
			this.description = description;
		}

		public String getDescription() {
			return description;
		}
	}

	/**
	 * Creates a new policy violation exception.
	 *
	 * @param type the type of violation
	 * @param destination the blocked destination (host:port or description)
	 * @param mode the active policy mode
	 * @param suggestedAction the suggested mitigation action
	 */
	public PolicyViolationException(ViolationType type, String destination,
			PolicyMode mode, MitigationAction suggestedAction) {
		super(formatMessage(type, destination, mode, suggestedAction));
		this.type = type;
		this.destination = destination;
		this.mode = mode;
		this.suggestedAction = suggestedAction;
	}

	/**
	 * Creates a violation for network access attempted in offline mode.
	 *
	 * @param destination the attempted destination
	 * @return the exception
	 */
	public static PolicyViolationException offlineMode(String destination) {
		return new PolicyViolationException(
			ViolationType.NETWORK_ACCESS_IN_OFFLINE_MODE,
			destination,
			PolicyMode.OFFLINE,
			MitigationAction.USE_LOCAL_MODEL);
	}

	/**
	 * Creates a violation for an endpoint not in the allowlist.
	 *
	 * @param host the host
	 * @param port the port
	 * @param mode the active policy mode
	 * @return the exception
	 */
	public static PolicyViolationException endpointNotAllowed(String host, int port,
			PolicyMode mode) {
		return new PolicyViolationException(
			ViolationType.ENDPOINT_NOT_ALLOWED,
			host + ":" + port,
			mode,
			MitigationAction.ADD_TO_ALLOWLIST);
	}

	/**
	 * Creates a violation for an endpoint matching a blocked pattern.
	 *
	 * @param host the host
	 * @param pattern the matching blocked pattern
	 * @param mode the active policy mode
	 * @return the exception
	 */
	public static PolicyViolationException endpointBlocked(String host, String pattern,
			PolicyMode mode) {
		return new PolicyViolationException(
			ViolationType.ENDPOINT_BLOCKED,
			host + " (matches: " + pattern + ")",
			mode,
			MitigationAction.CONTACT_ADMIN);
	}

	/**
	 * Creates a violation for an oversized payload.
	 *
	 * @param actualSize the actual payload size in bytes
	 * @param threshold the threshold in bytes
	 * @param mode the active policy mode
	 * @return the exception
	 */
	public static PolicyViolationException payloadTooLarge(long actualSize, long threshold,
			PolicyMode mode) {
		return new PolicyViolationException(
			ViolationType.PAYLOAD_TOO_LARGE,
			String.format("%d bytes (threshold: %d)", actualSize, threshold),
			mode,
			MitigationAction.REDUCE_PAYLOAD);
	}

	/**
	 * Creates a violation for rate limit exceeded.
	 *
	 * @param destination the destination
	 * @param currentRate the current request rate
	 * @param limit the rate limit
	 * @param mode the active policy mode
	 * @return the exception
	 */
	public static PolicyViolationException rateLimitExceeded(String destination,
			int currentRate, int limit, PolicyMode mode) {
		return new PolicyViolationException(
			ViolationType.RATE_LIMIT_EXCEEDED,
			String.format("%s (%d/min, limit: %d/min)", destination, currentRate, limit),
			mode,
			MitigationAction.WAIT_AND_RETRY);
	}

	/**
	 * Creates a violation for binary content detected.
	 *
	 * @param destination the destination
	 * @param mode the active policy mode
	 * @return the exception
	 */
	public static PolicyViolationException binaryContentDetected(String destination,
			PolicyMode mode) {
		return new PolicyViolationException(
			ViolationType.BINARY_CONTENT_DETECTED,
			destination,
			mode,
			MitigationAction.STRIP_BINARY_CONTENT);
	}

	private static String formatMessage(ViolationType type, String destination,
			PolicyMode mode, MitigationAction action) {
		return String.format(
			"Policy violation: %s. Destination: %s. Mode: %s. Suggested action: %s",
			type.getDescription(),
			destination,
			mode.getIdentifier(),
			action.getDescription());
	}

	/**
	 * Returns the type of violation.
	 * @return the violation type
	 */
	public ViolationType getType() {
		return type;
	}

	/**
	 * Returns the blocked destination.
	 * @return the destination
	 */
	public String getDestination() {
		return destination;
	}

	/**
	 * Returns the active policy mode.
	 * @return the policy mode
	 */
	public PolicyMode getMode() {
		return mode;
	}

	/**
	 * Returns the suggested mitigation action.
	 * @return the mitigation action
	 */
	public MitigationAction getSuggestedAction() {
		return suggestedAction;
	}
}
