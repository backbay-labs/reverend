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
 * Defines the network policy mode for agent operations.
 * Policy modes control outbound network access following the egress control
 * architecture defined in the agent-runtime-security-spec.
 *
 * <p>Three modes are supported:
 * <ul>
 *   <li><b>OFFLINE</b> - No outbound network connectivity. All external requests blocked.
 *       Use for classified or air-gapped deployments.</li>
 *   <li><b>ALLOWLIST</b> - Only allow-listed endpoints permitted. Default deny policy.
 *       Use for controlled environments with specific approved model APIs.</li>
 *   <li><b>CLOUD</b> - Configured endpoints allowed with egress monitoring.
 *       Use for standard cloud deployments with logging and rate limiting.</li>
 * </ul>
 *
 * <p>Policy modes are configured per-project via {@link EgressPolicy}.
 */
public enum PolicyMode {

	/**
	 * No outbound network connectivity allowed.
	 * All external API calls are blocked. Local/offline inference only.
	 * Suitable for classified, restricted (T4), or air-gapped deployments.
	 */
	OFFLINE("offline", "No external network access permitted"),

	/**
	 * Only explicitly allow-listed endpoints permitted.
	 * Default policy is deny-all with explicit allow entries.
	 * Suitable for controlled environments with approved model APIs.
	 */
	ALLOWLIST("allowlist", "Only allow-listed endpoints permitted"),

	/**
	 * Cloud mode with configured endpoints and monitoring.
	 * Allows configured model API endpoints with egress monitoring,
	 * rate limiting, and data exfiltration detection.
	 * Suitable for standard deployments with T1-T3 data classification.
	 */
	CLOUD("cloud", "Cloud endpoints with monitoring");

	private final String identifier;
	private final String description;

	PolicyMode(String identifier, String description) {
		this.identifier = identifier;
		this.description = description;
	}

	/**
	 * Returns the string identifier for this policy mode.
	 * @return the mode identifier (e.g., "offline", "allowlist", "cloud")
	 */
	public String getIdentifier() {
		return identifier;
	}

	/**
	 * Returns a human-readable description of this policy mode.
	 * @return the description
	 */
	public String getDescription() {
		return description;
	}

	/**
	 * Returns whether this mode allows any external network access.
	 * @return true if external network access is permitted
	 */
	public boolean allowsNetworkAccess() {
		return this != OFFLINE;
	}

	/**
	 * Returns whether this mode requires explicit endpoint allowlisting.
	 * @return true if endpoints must be explicitly allowed
	 */
	public boolean requiresAllowlist() {
		return this == ALLOWLIST || this == CLOUD;
	}

	/**
	 * Parses a policy mode from its string identifier.
	 * @param identifier the mode identifier (case-insensitive)
	 * @return the policy mode
	 * @throws IllegalArgumentException if the identifier is not recognized
	 */
	public static PolicyMode fromIdentifier(String identifier) {
		if (identifier == null) {
			throw new IllegalArgumentException("Policy mode identifier cannot be null");
		}
		String normalized = identifier.toLowerCase().trim();
		for (PolicyMode mode : values()) {
			if (mode.identifier.equals(normalized)) {
				return mode;
			}
		}
		throw new IllegalArgumentException("Unknown policy mode: " + identifier);
	}

	@Override
	public String toString() {
		return identifier;
	}
}
