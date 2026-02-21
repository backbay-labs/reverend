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

import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;

/**
 * Enforces egress policy for outbound network requests.
 * All outbound traffic from agent operations must pass through this enforcer.
 *
 * <p>The enforcer implements:
 * <ul>
 *   <li>Policy mode enforcement (offline blocks all, allowlist/cloud require approval)</li>
 *   <li>Endpoint allowlist validation</li>
 *   <li>Blocked pattern matching</li>
 *   <li>Payload size checking</li>
 *   <li>Rate limiting per destination</li>
 *   <li>Binary content detection</li>
 * </ul>
 *
 * <p>Usage pattern:
 * <pre>
 * EgressPolicy policy = EgressPolicy.defaultCloud("my-project");
 * EgressPolicyEnforcer enforcer = new EgressPolicyEnforcer(policy);
 *
 * // Before any outbound request:
 * enforcer.validateRequest("api.anthropic.com", 443, "https", requestBody);
 * </pre>
 */
public class EgressPolicyEnforcer {

	/** Threshold for detecting binary content (high-byte ratio) */
	private static final double BINARY_CONTENT_THRESHOLD = 0.1;

	private final EgressPolicy policy;
	private final ConcurrentHashMap<String, RateLimitBucket> rateLimitBuckets;

	/**
	 * Creates an enforcer for the specified policy.
	 *
	 * @param policy the egress policy to enforce
	 * @throws IllegalArgumentException if policy is null
	 */
	public EgressPolicyEnforcer(EgressPolicy policy) {
		this.policy = Objects.requireNonNull(policy, "EgressPolicy must not be null");
		this.rateLimitBuckets = new ConcurrentHashMap<>();
	}

	/**
	 * Returns the policy being enforced.
	 * @return the egress policy
	 */
	public EgressPolicy getPolicy() {
		return policy;
	}

	/**
	 * Validates an outbound request against the egress policy.
	 * Throws {@link PolicyViolationException} if the request is denied.
	 *
	 * @param host the destination host
	 * @param port the destination port
	 * @param protocol the protocol ("http" or "https")
	 * @throws PolicyViolationException if the request violates policy
	 */
	public void validateEndpoint(String host, int port, String protocol)
			throws PolicyViolationException {
		Objects.requireNonNull(host, "host must not be null");
		Objects.requireNonNull(protocol, "protocol must not be null");

		// Step 1: Check if network access is allowed at all
		if (!policy.allowsNetworkAccess()) {
			throw PolicyViolationException.offlineMode(host + ":" + port);
		}

		// Step 2: Check blocked patterns first (deny takes precedence)
		for (Pattern blocked : policy.getBlockedPatterns()) {
			if (blocked.matcher(host).matches()) {
				throw PolicyViolationException.endpointBlocked(
					host, blocked.pattern(), policy.getMode());
			}
		}

		// Step 3: Check allowlist
		if (policy.getMode().requiresAllowlist()) {
			boolean allowed = false;
			for (Endpoint endpoint : policy.getAllowedEndpoints()) {
				if (endpoint.matches(host, port, protocol)) {
					allowed = true;
					break;
				}
			}
			if (!allowed) {
				throw PolicyViolationException.endpointNotAllowed(host, port, policy.getMode());
			}
		}

		// Step 4: Enforce per-destination request rate limits
		checkRateLimit(destinationKey(host, port));
	}

	/**
	 * Validates an outbound request including payload inspection.
	 *
	 * @param host the destination host
	 * @param port the destination port
	 * @param protocol the protocol ("http" or "https")
	 * @param payload the request payload (may be null)
	 * @throws PolicyViolationException if the request violates policy
	 */
	public void validateRequest(String host, int port, String protocol, byte[] payload)
			throws PolicyViolationException {
		// Validate endpoint first
		validateEndpoint(host, port, protocol);

		String destination = host + ":" + port;

		// Check payload if present
		if (payload != null && payload.length > 0) {
			// Check payload size
			if (payload.length > policy.getLargePayloadThresholdBytes()) {
				throw PolicyViolationException.payloadTooLarge(
					payload.length, policy.getLargePayloadThresholdBytes(), policy.getMode());
			}

			// Check for binary content
			if (containsBinaryContent(payload)) {
				throw PolicyViolationException.binaryContentDetected(destination, policy.getMode());
			}
		}
	}

	/**
	 * Validates an outbound request with string payload.
	 *
	 * @param host the destination host
	 * @param port the destination port
	 * @param protocol the protocol ("http" or "https")
	 * @param payload the request payload (may be null)
	 * @throws PolicyViolationException if the request violates policy
	 */
	public void validateRequest(String host, int port, String protocol, String payload)
			throws PolicyViolationException {
		byte[] payloadBytes = payload != null ? payload.getBytes(java.nio.charset.StandardCharsets.UTF_8) : null;
		validateRequest(host, port, protocol, payloadBytes);
	}

	/**
	 * Checks if the endpoint is allowed without throwing.
	 * Useful for pre-validation and UI feedback.
	 *
	 * @param host the destination host
	 * @param port the destination port
	 * @param protocol the protocol ("http" or "https")
	 * @return validation result with allowed status and reason
	 */
	public ValidationResult checkEndpoint(String host, int port, String protocol) {
		try {
			validateEndpoint(host, port, protocol);
			return ValidationResult.allowed();
		}
		catch (PolicyViolationException e) {
			return ValidationResult.denied(e.getType(), e.getSuggestedAction());
		}
	}

	/**
	 * Resets rate limiting state. Useful for testing.
	 */
	public void resetRateLimits() {
		rateLimitBuckets.clear();
	}

	private String destinationKey(String host, int port) {
		return host.toLowerCase(Locale.ROOT) + ":" + port;
	}

	private void checkRateLimit(String destination) throws PolicyViolationException {
		RateLimitBucket bucket = rateLimitBuckets.computeIfAbsent(
			destination, k -> new RateLimitBucket());

		int currentRate = bucket.incrementAndGetRate();
		if (currentRate > policy.getMaxRequestsPerMinute()) {
			throw PolicyViolationException.rateLimitExceeded(
				destination, currentRate, policy.getMaxRequestsPerMinute(), policy.getMode());
		}
	}

	/**
	 * Detects binary content in a payload by checking for high-byte characters.
	 * Returns true if the payload appears to contain binary data rather than text.
	 */
	private boolean containsBinaryContent(byte[] payload) {
		if (payload == null || payload.length == 0) {
			return false;
		}

		int highByteCount = 0;
		int nullCount = 0;

		// Sample the payload (check first 4KB or entire payload if smaller)
		int sampleSize = Math.min(payload.length, 4096);

		for (int i = 0; i < sampleSize; i++) {
			byte b = payload[i];
			// Check for null bytes (common in binary data)
			if (b == 0) {
				nullCount++;
			}
			// Check for non-printable, non-whitespace bytes
			// Excluding common control characters like tab, newline, carriage return
			if (b < 0x09 || (b > 0x0D && b < 0x20) || (b & 0x80) != 0) {
				highByteCount++;
			}
		}

		// If null bytes are present, it's likely binary
		if (nullCount > 0) {
			return true;
		}

		// If more than threshold of bytes are high/non-printable, flag as binary
		double ratio = (double) highByteCount / sampleSize;
		return ratio > BINARY_CONTENT_THRESHOLD;
	}

	/**
	 * Rate limiting bucket that tracks requests per minute.
	 */
	private static class RateLimitBucket {
		private final AtomicInteger count = new AtomicInteger(0);
		private volatile long windowStart = System.currentTimeMillis();

		int incrementAndGetRate() {
			long now = System.currentTimeMillis();
			// Reset window if more than a minute has passed
			if (now - windowStart > 60_000) {
				synchronized (this) {
					if (now - windowStart > 60_000) {
						count.set(0);
						windowStart = now;
					}
				}
			}
			return count.incrementAndGet();
		}
	}

	/**
	 * Result of endpoint validation.
	 */
	public static final class ValidationResult {
		private final boolean allowed;
		private final PolicyViolationException.ViolationType violationType;
		private final PolicyViolationException.MitigationAction suggestedAction;

		private ValidationResult(boolean allowed,
				PolicyViolationException.ViolationType violationType,
				PolicyViolationException.MitigationAction suggestedAction) {
			this.allowed = allowed;
			this.violationType = violationType;
			this.suggestedAction = suggestedAction;
		}

		static ValidationResult allowed() {
			return new ValidationResult(true, null, null);
		}

		static ValidationResult denied(PolicyViolationException.ViolationType type,
				PolicyViolationException.MitigationAction action) {
			return new ValidationResult(false, type, action);
		}

		public boolean isAllowed() {
			return allowed;
		}

		public PolicyViolationException.ViolationType getViolationType() {
			return violationType;
		}

		public PolicyViolationException.MitigationAction getSuggestedAction() {
			return suggestedAction;
		}

		@Override
		public String toString() {
			if (allowed) {
				return "ValidationResult[allowed]";
			}
			return String.format("ValidationResult[denied: %s, action: %s]",
				violationType, suggestedAction);
		}
	}
}
