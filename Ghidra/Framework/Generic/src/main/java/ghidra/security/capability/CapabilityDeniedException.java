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
package ghidra.security.capability;

/**
 * Exception thrown when an operation is denied due to insufficient capabilities.
 * This implements fail-closed behavior: operations fail explicitly with a clear reason
 * rather than silently succeeding or failing ambiguously.
 *
 * <p>Each denial includes:
 * <ul>
 *   <li>The denied capability that was required</li>
 *   <li>The denial reason explaining why access was denied</li>
 *   <li>The token's profile for context</li>
 *   <li>The principal that attempted the operation</li>
 * </ul>
 */
public class CapabilityDeniedException extends SecurityException {

	private static final long serialVersionUID = 1L;

	private final Capability deniedCapability;
	private final DenialReason reason;
	private final String profile;
	private final String principal;
	private final String operation;

	/**
	 * Reasons why a capability check may be denied.
	 */
	public enum DenialReason {
		/** The token does not include the required capability */
		CAPABILITY_NOT_GRANTED("Capability not granted in token"),
		/** The token has expired */
		TOKEN_EXPIRED("Token has expired"),
		/** No token was provided */
		NO_TOKEN("No capability token provided"),
		/** The operation target is outside the token's allowed scope */
		SCOPE_VIOLATION("Operation target not in allowed scope"),
		/** The mutation limit for the session has been exceeded */
		MUTATION_LIMIT_EXCEEDED("Session mutation limit exceeded"),
		/** The operation requires a receipt but none was provided */
		RECEIPT_REQUIRED("Operation requires a receipt"),
		/** The token has been revoked */
		TOKEN_REVOKED("Token has been revoked"),
		/** The token has already been used (replay attempt) */
		TOKEN_REPLAYED("Token has already been used (replay attempt)");

		private final String description;

		DenialReason(String description) {
			this.description = description;
		}

		public String getDescription() {
			return description;
		}
	}

	/**
	 * Creates a new capability denied exception.
	 *
	 * @param deniedCapability the capability that was required but not granted
	 * @param reason the reason for denial
	 * @param profile the token's profile (or "none" if no token)
	 * @param principal the principal that attempted the operation (or "unknown")
	 * @param operation description of the attempted operation
	 */
	public CapabilityDeniedException(Capability deniedCapability, DenialReason reason,
			String profile, String principal, String operation) {
		super(formatMessage(deniedCapability, reason, profile, principal, operation));
		this.deniedCapability = deniedCapability;
		this.reason = reason;
		this.profile = profile;
		this.principal = principal;
		this.operation = operation;
	}

	/**
	 * Creates a capability denied exception for a missing capability.
	 *
	 * @param token the token that was checked
	 * @param required the required capability
	 * @param operation description of the attempted operation
	 * @return the exception
	 */
	public static CapabilityDeniedException capabilityNotGranted(CapabilityToken token,
			Capability required, String operation) {
		return new CapabilityDeniedException(
			required,
			DenialReason.CAPABILITY_NOT_GRANTED,
			token.getProfile(),
			token.getPrincipal(),
			operation);
	}

	/**
	 * Creates a capability denied exception for an expired token.
	 *
	 * @param token the expired token
	 * @param required the required capability
	 * @param operation description of the attempted operation
	 * @return the exception
	 */
	public static CapabilityDeniedException tokenExpired(CapabilityToken token,
			Capability required, String operation) {
		return new CapabilityDeniedException(
			required,
			DenialReason.TOKEN_EXPIRED,
			token.getProfile(),
			token.getPrincipal(),
			operation);
	}

	/**
	 * Creates a capability denied exception for a missing token.
	 *
	 * @param required the required capability
	 * @param operation description of the attempted operation
	 * @return the exception
	 */
	public static CapabilityDeniedException noToken(Capability required, String operation) {
		return new CapabilityDeniedException(
			required,
			DenialReason.NO_TOKEN,
			"none",
			"unknown",
			operation);
	}

	/**
	 * Creates a capability denied exception for a scope violation.
	 *
	 * @param token the token
	 * @param required the required capability
	 * @param operation description of the attempted operation
	 * @return the exception
	 */
	public static CapabilityDeniedException scopeViolation(CapabilityToken token,
			Capability required, String operation) {
		return new CapabilityDeniedException(
			required,
			DenialReason.SCOPE_VIOLATION,
			token.getProfile(),
			token.getPrincipal(),
			operation);
	}

	/**
	 * Creates a capability denied exception for a revoked token.
	 *
	 * @param token the revoked token
	 * @param required the required capability
	 * @param operation description of the attempted operation
	 * @return the exception
	 */
	public static CapabilityDeniedException tokenRevoked(CapabilityToken token,
			Capability required, String operation) {
		return new CapabilityDeniedException(
			required,
			DenialReason.TOKEN_REVOKED,
			token.getProfile(),
			token.getPrincipal(),
			operation);
	}

	/**
	 * Creates a capability denied exception for a replayed token.
	 *
	 * @param token the replayed token
	 * @param required the required capability
	 * @param operation description of the attempted operation
	 * @return the exception
	 */
	public static CapabilityDeniedException tokenReplayed(CapabilityToken token,
			Capability required, String operation) {
		return new CapabilityDeniedException(
			required,
			DenialReason.TOKEN_REPLAYED,
			token.getProfile(),
			token.getPrincipal(),
			operation);
	}

	private static String formatMessage(Capability cap, DenialReason reason,
			String profile, String principal, String operation) {
		return String.format(
			"Access denied: %s. Required capability: %s. Principal: %s. Profile: %s. Operation: %s",
			reason.getDescription(),
			cap != null ? cap.getIdentifier() : "unknown",
			principal,
			profile,
			operation);
	}

	/**
	 * Returns the capability that was required but not granted.
	 * @return the denied capability
	 */
	public Capability getDeniedCapability() {
		return deniedCapability;
	}

	/**
	 * Returns the reason for denial.
	 * @return the denial reason
	 */
	public DenialReason getReason() {
		return reason;
	}

	/**
	 * Returns the profile from the token that was checked.
	 * @return the profile name
	 */
	public String getProfile() {
		return profile;
	}

	/**
	 * Returns the principal that attempted the operation.
	 * @return the principal identifier
	 */
	public String getPrincipal() {
		return principal;
	}

	/**
	 * Returns a description of the attempted operation.
	 * @return the operation description
	 */
	public String getOperation() {
		return operation;
	}
}
