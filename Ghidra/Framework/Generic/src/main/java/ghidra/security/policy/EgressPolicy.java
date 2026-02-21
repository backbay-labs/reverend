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

import java.util.*;
import java.util.regex.Pattern;

/**
 * Defines an egress policy for controlling outbound network access.
 * Policies are configurable per-project and specify which endpoints are allowed,
 * which are blocked, and what monitoring/limits apply.
 *
 * <p>Policy structure follows the agent-runtime-security-spec:
 * <pre>
 * egress_policy:
 *   default: deny
 *   allowed_endpoints:
 *     - host: api.anthropic.com
 *       port: 443
 *       protocol: https
 *       purpose: "Claude API"
 *   blocked_patterns:
 *     - "*.pastebin.com"
 *     - "*.ngrok.io"
 *   monitoring:
 *     log_all_connections: true
 *     large_payload_threshold_bytes: 1048576
 * </pre>
 */
public final class EgressPolicy {

	private final String projectId;
	private final PolicyMode mode;
	private final Set<Endpoint> allowedEndpoints;
	private final Set<Pattern> blockedPatterns;
	private final boolean logAllConnections;
	private final boolean alertOnDenied;
	private final long largePayloadThresholdBytes;
	private final int maxRequestsPerMinute;

	private EgressPolicy(Builder builder) {
		this.projectId = Objects.requireNonNull(builder.projectId, "projectId is required");
		this.mode = Objects.requireNonNull(builder.mode, "mode is required");
		this.allowedEndpoints = Collections.unmodifiableSet(new HashSet<>(builder.allowedEndpoints));
		this.blockedPatterns = Collections.unmodifiableSet(new HashSet<>(builder.blockedPatterns));
		this.logAllConnections = builder.logAllConnections;
		this.alertOnDenied = builder.alertOnDenied;
		this.largePayloadThresholdBytes = builder.largePayloadThresholdBytes;
		this.maxRequestsPerMinute = builder.maxRequestsPerMinute;
	}

	/**
	 * Returns the project ID this policy applies to.
	 * @return the project identifier
	 */
	public String getProjectId() {
		return projectId;
	}

	/**
	 * Returns the policy mode (OFFLINE, ALLOWLIST, or CLOUD).
	 * @return the policy mode
	 */
	public PolicyMode getMode() {
		return mode;
	}

	/**
	 * Returns the set of allowed endpoints.
	 * @return immutable set of allowed endpoints
	 */
	public Set<Endpoint> getAllowedEndpoints() {
		return allowedEndpoints;
	}

	/**
	 * Returns the set of blocked hostname patterns.
	 * @return immutable set of blocked patterns
	 */
	public Set<Pattern> getBlockedPatterns() {
		return blockedPatterns;
	}

	/**
	 * Returns whether all connections should be logged.
	 * @return true if logging is enabled
	 */
	public boolean shouldLogAllConnections() {
		return logAllConnections;
	}

	/**
	 * Returns whether denied connections should trigger an alert.
	 * @return true if alerting is enabled
	 */
	public boolean shouldAlertOnDenied() {
		return alertOnDenied;
	}

	/**
	 * Returns the threshold for large payload detection.
	 * @return the threshold in bytes
	 */
	public long getLargePayloadThresholdBytes() {
		return largePayloadThresholdBytes;
	}

	/**
	 * Returns the maximum requests per minute rate limit.
	 * @return the rate limit
	 */
	public int getMaxRequestsPerMinute() {
		return maxRequestsPerMinute;
	}

	/**
	 * Checks if network access is allowed under this policy.
	 * @return true if any network access is permitted
	 */
	public boolean allowsNetworkAccess() {
		return mode.allowsNetworkAccess();
	}

	/**
	 * Creates a new builder for constructing egress policies.
	 * @return a new builder
	 */
	public static Builder builder() {
		return new Builder();
	}

	/**
	 * Creates a strict offline policy that blocks all network access.
	 *
	 * @param projectId the project identifier
	 * @return an offline policy
	 */
	public static EgressPolicy offline(String projectId) {
		return builder()
			.projectId(projectId)
			.mode(PolicyMode.OFFLINE)
			.alertOnDenied(true)
			.build();
	}

	/**
	 * Creates a default cloud policy with common model API endpoints.
	 *
	 * @param projectId the project identifier
	 * @return a cloud policy with standard endpoints
	 */
	public static EgressPolicy defaultCloud(String projectId) {
		return builder()
			.projectId(projectId)
			.mode(PolicyMode.CLOUD)
			.addEndpoint(Endpoint.https("api.anthropic.com", "Claude API"))
			.addEndpoint(Endpoint.https("api.openai.com", "OpenAI API"))
			.addEndpoint(Endpoint.localhost(11434, "Ollama local inference"))
			.addBlockedPattern("*.pastebin.com")
			.addBlockedPattern("*.ngrok.io")
			.addBlockedPattern("*.requestbin.com")
			.addBlockedPattern("transfer.sh")
			.logAllConnections(true)
			.alertOnDenied(true)
			.build();
	}

	@Override
	public String toString() {
		return String.format("EgressPolicy[project=%s, mode=%s, endpoints=%d, blocked=%d]",
			projectId, mode, allowedEndpoints.size(), blockedPatterns.size());
	}

	/**
	 * Builder for creating egress policies.
	 */
	public static final class Builder {
		private String projectId;
		private PolicyMode mode = PolicyMode.ALLOWLIST;
		private final Set<Endpoint> allowedEndpoints = new HashSet<>();
		private final Set<Pattern> blockedPatterns = new HashSet<>();
		private boolean logAllConnections = true;
		private boolean alertOnDenied = true;
		private long largePayloadThresholdBytes = 1024 * 1024; // 1MB
		private int maxRequestsPerMinute = 60;

		private Builder() {
		}

		public Builder projectId(String projectId) {
			this.projectId = projectId;
			return this;
		}

		public Builder mode(PolicyMode mode) {
			this.mode = mode;
			return this;
		}

		public Builder addEndpoint(Endpoint endpoint) {
			this.allowedEndpoints.add(endpoint);
			return this;
		}

		public Builder endpoints(Collection<Endpoint> endpoints) {
			this.allowedEndpoints.addAll(endpoints);
			return this;
		}

		/**
		 * Adds a blocked hostname pattern using glob-style wildcards.
		 * Examples: "*.pastebin.com", "*.ngrok.io"
		 *
		 * @param glob the glob pattern
		 * @return this builder
		 */
		public Builder addBlockedPattern(String glob) {
			String regex = globToRegex(glob);
			this.blockedPatterns.add(Pattern.compile(regex, Pattern.CASE_INSENSITIVE));
			return this;
		}

		public Builder logAllConnections(boolean log) {
			this.logAllConnections = log;
			return this;
		}

		public Builder alertOnDenied(boolean alert) {
			this.alertOnDenied = alert;
			return this;
		}

		public Builder largePayloadThresholdBytes(long threshold) {
			this.largePayloadThresholdBytes = threshold;
			return this;
		}

		public Builder maxRequestsPerMinute(int limit) {
			this.maxRequestsPerMinute = limit;
			return this;
		}

		public EgressPolicy build() {
			return new EgressPolicy(this);
		}

		/**
		 * Converts a glob pattern (with * wildcards) to a regex.
		 */
		private static String globToRegex(String glob) {
			StringBuilder regex = new StringBuilder("^");
			for (int i = 0; i < glob.length(); i++) {
				char c = glob.charAt(i);
				switch (c) {
					case '*':
						regex.append(".*");
						break;
					case '?':
						regex.append(".");
						break;
					case '.':
					case '(':
					case ')':
					case '[':
					case ']':
					case '{':
					case '}':
					case '^':
					case '$':
					case '|':
					case '\\':
						regex.append("\\").append(c);
						break;
					default:
						regex.append(c);
				}
			}
			regex.append("$");
			return regex.toString();
		}
	}
}
