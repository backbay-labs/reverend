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

import java.time.Duration;
import java.time.Instant;
import java.util.*;

import ghidra.security.audit.*;
import ghidra.security.capability.*;
import ghidra.security.credential.RevocationRegistry.RevocationReason;

/**
 * Credential broker for issuing short-lived capability tokens with TTL and scoped permissions.
 * Replaces long-lived static secret assumptions with time-bound, auditable credentials.
 *
 * <p>The broker provides:
 * <ul>
 *   <li>Token issuance with configurable TTL (default: 8 hours)</li>
 *   <li>Scoped permissions based on predefined profiles</li>
 *   <li>Integration with revocation registry for immediate invalidation</li>
 *   <li>Audit logging for all issuance and revocation events</li>
 *   <li>One-time use token support for sensitive operations</li>
 * </ul>
 *
 * <p>Based on the agent-runtime-security-spec credential broker requirements.
 */
public class CredentialBroker {

	/** Default TTL for issued tokens: 8 hours */
	public static final Duration DEFAULT_TTL = Duration.ofHours(8);

	/** Maximum TTL allowed: 24 hours */
	public static final Duration MAX_TTL = Duration.ofHours(24);

	/** Minimum TTL allowed: 1 minute */
	public static final Duration MIN_TTL = Duration.ofMinutes(1);

	private final RevocationRegistry revocationRegistry;
	private final SecurityAuditLogger auditLogger;
	private final String issuerId;

	// Track one-time use tokens
	private final Set<String> usedOneTimeTokens =
		Collections.synchronizedSet(new HashSet<>());

	/**
	 * Creates a new credential broker.
	 *
	 * @param revocationRegistry the revocation registry for token invalidation
	 * @param auditLogger the audit logger for compliance
	 * @param issuerId identifier for this broker instance (for audit attribution)
	 */
	public CredentialBroker(RevocationRegistry revocationRegistry,
			SecurityAuditLogger auditLogger, String issuerId) {
		this.revocationRegistry = Objects.requireNonNull(revocationRegistry);
		this.auditLogger = Objects.requireNonNull(auditLogger);
		this.issuerId = Objects.requireNonNull(issuerId);
	}

	/**
	 * Issues a new capability token with the specified profile and default TTL.
	 *
	 * @param principal the principal to issue the token to
	 * @param profile the permission profile (observer, annotator, analyst, engineer, admin)
	 * @return the issued token
	 */
	public CapabilityToken issueToken(String principal, PermissionProfile profile) {
		return issueToken(principal, profile, DEFAULT_TTL);
	}

	/**
	 * Issues a new capability token with the specified profile and TTL.
	 *
	 * @param principal the principal to issue the token to
	 * @param profile the permission profile
	 * @param ttl the token time-to-live
	 * @return the issued token
	 * @throws IllegalArgumentException if TTL is outside allowed bounds
	 */
	public CapabilityToken issueToken(String principal, PermissionProfile profile, Duration ttl) {
		return issueToken(principal, profile, ttl, null, false);
	}

	/**
	 * Issues a new capability token with full configuration.
	 *
	 * @param principal the principal to issue the token to
	 * @param profile the permission profile
	 * @param ttl the token time-to-live
	 * @param scope optional scope restrictions
	 * @param oneTimeUse if true, token can only be used once
	 * @return the issued token
	 * @throws IllegalArgumentException if TTL is outside allowed bounds
	 */
	public CapabilityToken issueToken(String principal, PermissionProfile profile,
			Duration ttl, CapabilityToken.TokenScope scope, boolean oneTimeUse) {
		Objects.requireNonNull(principal, "principal must not be null");
		Objects.requireNonNull(profile, "profile must not be null");
		Objects.requireNonNull(ttl, "ttl must not be null");

		// Validate TTL bounds
		if (ttl.compareTo(MIN_TTL) < 0) {
			throw new IllegalArgumentException(
				"TTL must be at least " + MIN_TTL.toMinutes() + " minutes");
		}
		if (ttl.compareTo(MAX_TTL) > 0) {
			throw new IllegalArgumentException(
				"TTL must not exceed " + MAX_TTL.toHours() + " hours");
		}

		Instant now = Instant.now();
		String tokenId = UUID.randomUUID().toString();

		CapabilityToken token = CapabilityToken.builder()
			.tokenId(tokenId)
			.issuedAt(now)
			.expiresAt(now.plus(ttl))
			.principal(principal)
			.profile(profile.getName())
			.capabilities(profile.getCapabilities())
			.scope(scope)
			.build();

		// Register with revocation registry for bulk revocation support
		if (revocationRegistry instanceof InMemoryRevocationRegistry) {
			((InMemoryRevocationRegistry) revocationRegistry).registerToken(tokenId, principal);
		}

		// Log token creation
		auditLogger.log(SecurityAuditEvent.builder()
			.eventType(SecurityAuditEventType.TOKEN_CREATED)
			.principal(issuerId)
			.detail("token_id", tokenId)
			.detail("issued_to", principal)
			.detail("profile", profile.getName())
			.detail("ttl_seconds", String.valueOf(ttl.getSeconds()))
			.detail("one_time_use", String.valueOf(oneTimeUse))
			.detail("expires_at", token.getExpiresAt().toString())
			.build());

		return token;
	}

	/**
	 * Issues a one-time use token for sensitive operations.
	 * These tokens can only be validated once and are then immediately invalidated.
	 *
	 * @param principal the principal to issue the token to
	 * @param profile the permission profile
	 * @param ttl the token time-to-live
	 * @return the issued token
	 */
	public CapabilityToken issueOneTimeToken(String principal, PermissionProfile profile,
			Duration ttl) {
		return issueToken(principal, profile, ttl, null, true);
	}

	/**
	 * Validates a token, checking expiration, revocation, and replay status.
	 *
	 * @param token the token to validate
	 * @param isOneTimeUse whether this is a one-time use token
	 * @return validation result with details
	 */
	public TokenValidationResult validateToken(CapabilityToken token, boolean isOneTimeUse) {
		Objects.requireNonNull(token, "token must not be null");

		String tokenId = token.getTokenId();

		// Check expiration
		if (token.isExpired()) {
			logTokenExpired(token);
			return TokenValidationResult.expired(tokenId);
		}

		// Check revocation
		if (revocationRegistry.isRevoked(tokenId)) {
			logTokenRevokedAttempt(token);
			return TokenValidationResult.revoked(tokenId,
				revocationRegistry.getRevocationRecord(tokenId));
		}

		// Check replay for one-time use tokens
		if (isOneTimeUse) {
			if (usedOneTimeTokens.contains(tokenId)) {
				logTokenReplayed(token);
				return TokenValidationResult.replayed(tokenId);
			}
			usedOneTimeTokens.add(tokenId);
		}

		return TokenValidationResult.valid(tokenId);
	}

	/**
	 * Revokes a token immediately.
	 *
	 * @param tokenId the token ID to revoke
	 * @param reason the reason for revocation
	 * @param revokedBy the principal performing the revocation
	 * @return the revocation record
	 */
	public RevocationRegistry.RevocationRecord revokeToken(String tokenId,
			RevocationReason reason, String revokedBy) {
		RevocationRegistry.RevocationRecord record =
			revocationRegistry.revoke(tokenId, reason, revokedBy);

		auditLogger.log(SecurityAuditEvent.builder()
			.eventType(SecurityAuditEventType.TOKEN_REVOKED)
			.principal(revokedBy)
			.detail("token_id", tokenId)
			.detail("reason", reason.name())
			.detail("affected_principal", record.getAffectedPrincipal())
			.build());

		return record;
	}

	/**
	 * Revokes all tokens issued to a principal.
	 *
	 * @param principal the principal whose tokens should be revoked
	 * @param reason the reason for revocation
	 * @param revokedBy the principal performing the revocation
	 * @return list of revocation records
	 */
	public List<RevocationRegistry.RevocationRecord> revokeAllForPrincipal(String principal,
			RevocationReason reason, String revokedBy) {
		List<RevocationRegistry.RevocationRecord> records =
			revocationRegistry.revokeByPrincipal(principal, reason, revokedBy);

		if (!records.isEmpty()) {
			auditLogger.log(SecurityAuditEvent.builder()
				.eventType(SecurityAuditEventType.TOKEN_REVOKED)
				.principal(revokedBy)
				.detail("affected_principal", principal)
				.detail("reason", reason.name())
				.detail("tokens_revoked", String.valueOf(records.size()))
				.build());
		}

		return records;
	}

	/**
	 * Checks if a token has been revoked.
	 *
	 * @param tokenId the token ID to check
	 * @return true if revoked
	 */
	public boolean isRevoked(String tokenId) {
		return revocationRegistry.isRevoked(tokenId);
	}

	private void logTokenExpired(CapabilityToken token) {
		auditLogger.log(SecurityAuditEvent.builder()
			.eventType(SecurityAuditEventType.TOKEN_EXPIRED)
			.principal(token.getPrincipal())
			.detail("token_id", token.getTokenId())
			.detail("expired_at", token.getExpiresAt().toString())
			.build());
	}

	private void logTokenRevokedAttempt(CapabilityToken token) {
		auditLogger.log(SecurityAuditEvent.builder()
			.eventType(SecurityAuditEventType.TOKEN_REVOKED_ATTEMPT)
			.principal(token.getPrincipal())
			.detail("token_id", token.getTokenId())
			.build());
	}

	private void logTokenReplayed(CapabilityToken token) {
		auditLogger.log(SecurityAuditEvent.builder()
			.eventType(SecurityAuditEventType.TOKEN_REPLAYED)
			.severity(Severity.CRITICAL)
			.principal(token.getPrincipal())
			.detail("token_id", token.getTokenId())
			.build());
	}

	/**
	 * Result of token validation.
	 */
	public static final class TokenValidationResult {
		private final String tokenId;
		private final ValidationStatus status;
		private final RevocationRegistry.RevocationRecord revocationRecord;

		private TokenValidationResult(String tokenId, ValidationStatus status,
				RevocationRegistry.RevocationRecord revocationRecord) {
			this.tokenId = tokenId;
			this.status = status;
			this.revocationRecord = revocationRecord;
		}

		public static TokenValidationResult valid(String tokenId) {
			return new TokenValidationResult(tokenId, ValidationStatus.VALID, null);
		}

		public static TokenValidationResult expired(String tokenId) {
			return new TokenValidationResult(tokenId, ValidationStatus.EXPIRED, null);
		}

		public static TokenValidationResult revoked(String tokenId,
				RevocationRegistry.RevocationRecord record) {
			return new TokenValidationResult(tokenId, ValidationStatus.REVOKED, record);
		}

		public static TokenValidationResult replayed(String tokenId) {
			return new TokenValidationResult(tokenId, ValidationStatus.REPLAYED, null);
		}

		public String getTokenId() {
			return tokenId;
		}

		public ValidationStatus getStatus() {
			return status;
		}

		public boolean isValid() {
			return status == ValidationStatus.VALID;
		}

		public RevocationRegistry.RevocationRecord getRevocationRecord() {
			return revocationRecord;
		}

		@Override
		public String toString() {
			return String.format("TokenValidationResult[tokenId=%s, status=%s]", tokenId, status);
		}
	}

	/**
	 * Validation status for tokens.
	 */
	public enum ValidationStatus {
		/** Token is valid and can be used */
		VALID,
		/** Token has expired */
		EXPIRED,
		/** Token has been revoked */
		REVOKED,
		/** Token has already been used (one-time use violation) */
		REPLAYED
	}
}
