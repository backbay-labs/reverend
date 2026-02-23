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
package ghidra.security.credential;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import ghidra.security.audit.*;
import ghidra.security.capability.*;

/**
 * Enhanced capability guard that integrates with the credential control plane
 * to check for revoked and replayed tokens in addition to standard capability checks.
 *
 * <p>This guard extends the basic capability validation with:
 * <ul>
 *   <li>Revocation checking via the {@link RevocationRegistry}</li>
 *   <li>Replay detection for one-time use tokens</li>
 *   <li>Audit logging for all security events</li>
 * </ul>
 */
public class RevocationAwareCapabilityGuard extends CapabilityGuard {

	private final RevocationRegistry revocationRegistry;
	private final SecurityAuditLogger auditLogger;
	private final Set<String> usedOneTimeTokens;
	private final boolean isOneTimeUse;

	/**
	 * Creates a guard with revocation and replay checking.
	 *
	 * @param token the capability token to enforce
	 * @param revocationRegistry the revocation registry to check against
	 * @param auditLogger the audit logger for security events
	 */
	public RevocationAwareCapabilityGuard(CapabilityToken token,
			RevocationRegistry revocationRegistry, SecurityAuditLogger auditLogger) {
		this(token, revocationRegistry, auditLogger, false);
	}

	/**
	 * Creates a guard with revocation and replay checking.
	 *
	 * @param token the capability token to enforce
	 * @param revocationRegistry the revocation registry to check against
	 * @param auditLogger the audit logger for security events
	 * @param isOneTimeUse if true, token can only be used once
	 */
	public RevocationAwareCapabilityGuard(CapabilityToken token,
			RevocationRegistry revocationRegistry, SecurityAuditLogger auditLogger,
			boolean isOneTimeUse) {
		super(token);
		this.revocationRegistry = Objects.requireNonNull(revocationRegistry);
		this.auditLogger = Objects.requireNonNull(auditLogger);
		this.usedOneTimeTokens = ConcurrentHashMap.newKeySet();
		this.isOneTimeUse = isOneTimeUse;
	}

	/**
	 * Shared one-time token registry for use across multiple guards.
	 *
	 * @param token the capability token to enforce
	 * @param revocationRegistry the revocation registry to check against
	 * @param auditLogger the audit logger for security events
	 * @param usedTokens shared set of used one-time tokens
	 * @param isOneTimeUse if true, token can only be used once
	 */
	public RevocationAwareCapabilityGuard(CapabilityToken token,
			RevocationRegistry revocationRegistry, SecurityAuditLogger auditLogger,
			Set<String> usedTokens, boolean isOneTimeUse) {
		super(token);
		this.revocationRegistry = Objects.requireNonNull(revocationRegistry);
		this.auditLogger = Objects.requireNonNull(auditLogger);
		this.usedOneTimeTokens = Objects.requireNonNull(usedTokens);
		this.isOneTimeUse = isOneTimeUse;
	}

	/**
	 * Asserts that the token grants the specified capability.
	 * Additionally checks for revocation and replay.
	 *
	 * @param capability the required capability
	 * @param operation description of the attempted operation
	 * @throws CapabilityDeniedException if access is denied for any reason
	 */
	@Override
	public void assertCapability(Capability capability, String operation)
			throws CapabilityDeniedException {
		CapabilityToken token = getToken();

		// Check revocation first
		if (revocationRegistry.isRevoked(token.getTokenId())) {
			logRevocationAttempt(token, capability, operation);
			throw CapabilityDeniedException.tokenRevoked(token, capability, operation);
		}

		// Check replay for one-time use tokens
		if (isOneTimeUse && usedOneTimeTokens.contains(token.getTokenId())) {
			logReplayAttempt(token, capability, operation);
			throw CapabilityDeniedException.tokenReplayed(token, capability, operation);
		}

		// Delegate to parent for standard capability checks (expiration, capability, limits)
		super.assertCapability(capability, operation);

		// Mark token as used for one-time tokens (only after successful validation)
		if (isOneTimeUse) {
			usedOneTimeTokens.add(token.getTokenId());
		}

		// Log successful capability check
		logCapabilityGranted(token, capability, operation);
	}

	/**
	 * Asserts that the token grants the specified capability for the given program.
	 * Additionally checks for revocation and replay.
	 *
	 * @param capability the required capability
	 * @param programName the target program name
	 * @param operation description of the attempted operation
	 * @throws CapabilityDeniedException if access is denied for any reason
	 */
	@Override
	public void assertCapabilityForProgram(Capability capability, String programName,
			String operation) throws CapabilityDeniedException {
		CapabilityToken token = getToken();

		// Check revocation first
		if (revocationRegistry.isRevoked(token.getTokenId())) {
			logRevocationAttempt(token, capability, operation);
			throw CapabilityDeniedException.tokenRevoked(token, capability, operation);
		}

		// Check replay for one-time use tokens
		if (isOneTimeUse && usedOneTimeTokens.contains(token.getTokenId())) {
			logReplayAttempt(token, capability, operation);
			throw CapabilityDeniedException.tokenReplayed(token, capability, operation);
		}

		// Delegate to parent for standard checks
		super.assertCapabilityForProgram(capability, programName, operation);

		// Mark token as used for one-time tokens
		if (isOneTimeUse) {
			usedOneTimeTokens.add(token.getTokenId());
		}
	}

	/**
	 * Checks if the token grants the specified capability without throwing.
	 * Also checks for revocation.
	 *
	 * @param capability the capability to check
	 * @return true if granted, not expired, and not revoked
	 */
	@Override
	public boolean hasCapability(Capability capability) {
		if (revocationRegistry.isRevoked(getToken().getTokenId())) {
			return false;
		}
		if (isOneTimeUse && usedOneTimeTokens.contains(getToken().getTokenId())) {
			return false;
		}
		return super.hasCapability(capability);
	}

	/**
	 * Checks if the token grants the specified capability for the given program.
	 * Also checks for revocation.
	 *
	 * @param capability the capability to check
	 * @param programName the target program name
	 * @return true if granted, not expired, not revoked, and in scope
	 */
	@Override
	public boolean hasCapabilityForProgram(Capability capability, String programName) {
		if (revocationRegistry.isRevoked(getToken().getTokenId())) {
			return false;
		}
		if (isOneTimeUse && usedOneTimeTokens.contains(getToken().getTokenId())) {
			return false;
		}
		return super.hasCapabilityForProgram(capability, programName);
	}

	/**
	 * Returns whether this guard enforces one-time use.
	 *
	 * @return true if one-time use is enforced
	 */
	public boolean isOneTimeUse() {
		return isOneTimeUse;
	}

	/**
	 * Checks if the token has been revoked.
	 *
	 * @return true if the token has been revoked
	 */
	public boolean isRevoked() {
		return revocationRegistry.isRevoked(getToken().getTokenId());
	}

	/**
	 * Checks if the token has been used (for one-time use tokens).
	 *
	 * @return true if the token has been used
	 */
	public boolean isUsed() {
		return usedOneTimeTokens.contains(getToken().getTokenId());
	}

	private void logRevocationAttempt(CapabilityToken token, Capability capability,
			String operation) {
		RevocationRegistry.RevocationRecord record =
			revocationRegistry.getRevocationRecord(token.getTokenId());

		auditLogger.log(SecurityAuditEvent.builder()
			.eventType(SecurityAuditEventType.TOKEN_REVOKED_ATTEMPT)
			.severity(Severity.WARNING)
			.principal(token.getPrincipal())
			.sessionId(token.getTokenId())
			.detail("token_id", token.getTokenId())
			.detail("requested_capability", capability.getIdentifier())
			.detail("operation", operation)
			.detail("revocation_reason", record != null ? record.getReason().name() : "unknown")
			.detail("revoked_at", record != null ? record.getRevokedAt().toString() : "unknown")
			.build());
	}

	private void logReplayAttempt(CapabilityToken token, Capability capability,
			String operation) {
		auditLogger.log(SecurityAuditEvent.builder()
			.eventType(SecurityAuditEventType.TOKEN_REPLAYED)
			.severity(Severity.CRITICAL)
			.principal(token.getPrincipal())
			.sessionId(token.getTokenId())
			.detail("token_id", token.getTokenId())
			.detail("requested_capability", capability.getIdentifier())
			.detail("operation", operation)
			.build());
	}

	private void logCapabilityGranted(CapabilityToken token, Capability capability,
			String operation) {
		auditLogger.log(SecurityAuditEvent.builder()
			.eventType(SecurityAuditEventType.CAPABILITY_GRANTED)
			.severity(Severity.INFO)
			.principal(token.getPrincipal())
			.sessionId(token.getTokenId())
			.detail("capability", capability.getIdentifier())
			.detail("operation", operation)
			.detail("profile", token.getProfile())
			.build());
	}

	/**
	 * Factory method to create a guard for a one-time use token.
	 *
	 * @param token the capability token
	 * @param revocationRegistry the revocation registry
	 * @param auditLogger the audit logger
	 * @return a one-time use guard
	 */
	public static RevocationAwareCapabilityGuard forOneTimeUse(CapabilityToken token,
			RevocationRegistry revocationRegistry, SecurityAuditLogger auditLogger) {
		return new RevocationAwareCapabilityGuard(token, revocationRegistry, auditLogger, true);
	}

	/**
	 * Factory method to create a guard for normal use.
	 *
	 * @param token the capability token
	 * @param revocationRegistry the revocation registry
	 * @param auditLogger the audit logger
	 * @return a standard guard with revocation checking
	 */
	public static RevocationAwareCapabilityGuard forNormalUse(CapabilityToken token,
			RevocationRegistry revocationRegistry, SecurityAuditLogger auditLogger) {
		return new RevocationAwareCapabilityGuard(token, revocationRegistry, auditLogger, false);
	}
}
