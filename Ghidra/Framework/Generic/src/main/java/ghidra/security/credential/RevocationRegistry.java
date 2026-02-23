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

import java.time.Instant;
import java.util.List;

/**
 * Registry for tracking revoked capability tokens.
 * Implementations must be thread-safe and provide efficient lookup for revocation checks.
 *
 * <p>The revocation registry supports:
 * <ul>
 *   <li>Immediate token revocation with reason tracking</li>
 *   <li>Bulk revocation by principal or issuer</li>
 *   <li>Revocation status queries for validation</li>
 *   <li>Audit trail for compliance review</li>
 * </ul>
 */
public interface RevocationRegistry {

	/**
	 * Revokes a token by its ID.
	 *
	 * @param tokenId the token ID to revoke
	 * @param reason the reason for revocation
	 * @param revokedBy the principal performing the revocation
	 * @return the revocation record
	 */
	RevocationRecord revoke(String tokenId, RevocationReason reason, String revokedBy);

	/**
	 * Revokes all tokens issued to a specific principal.
	 *
	 * @param principal the principal whose tokens should be revoked
	 * @param reason the reason for revocation
	 * @param revokedBy the principal performing the revocation
	 * @return list of revocation records created
	 */
	List<RevocationRecord> revokeByPrincipal(String principal, RevocationReason reason,
			String revokedBy);

	/**
	 * Checks if a token has been revoked.
	 *
	 * @param tokenId the token ID to check
	 * @return true if the token has been revoked
	 */
	boolean isRevoked(String tokenId);

	/**
	 * Gets the revocation record for a token, if it exists.
	 *
	 * @param tokenId the token ID
	 * @return the revocation record, or null if not revoked
	 */
	RevocationRecord getRevocationRecord(String tokenId);

	/**
	 * Returns all revocation records within the specified time range.
	 *
	 * @param start the start of the time range (inclusive)
	 * @param end the end of the time range (exclusive)
	 * @return list of revocation records
	 */
	List<RevocationRecord> getRevocationsBetween(Instant start, Instant end);

	/**
	 * Returns the total number of revocations in the registry.
	 *
	 * @return the revocation count
	 */
	long getRevocationCount();

	/**
	 * Removes expired revocation records older than the specified retention period.
	 * This is a maintenance operation to prevent unbounded growth.
	 *
	 * @param olderThan remove records older than this instant
	 * @return the number of records removed
	 */
	int pruneExpiredRecords(Instant olderThan);

	/**
	 * Reasons for token revocation.
	 */
	enum RevocationReason {
		/** Token was manually revoked by an administrator */
		MANUAL_REVOCATION("Manual revocation by administrator"),
		/** Token was compromised or suspected compromised */
		SECURITY_INCIDENT("Security incident - token compromised"),
		/** Associated principal was deactivated */
		PRINCIPAL_DEACTIVATED("Principal account deactivated"),
		/** Token was revoked as part of a key rotation */
		KEY_ROTATION("Key rotation - all tokens invalidated"),
		/** Token was revoked due to policy violation */
		POLICY_VIOLATION("Policy violation detected"),
		/** Token was superseded by a new token */
		TOKEN_SUPERSEDED("Token superseded by new issuance"),
		/** Session was terminated */
		SESSION_TERMINATED("Session terminated");

		private final String description;

		RevocationReason(String description) {
			this.description = description;
		}

		public String getDescription() {
			return description;
		}
	}

	/**
	 * Record of a token revocation for audit purposes.
	 */
	final class RevocationRecord {
		private final String tokenId;
		private final Instant revokedAt;
		private final RevocationReason reason;
		private final String revokedBy;
		private final String affectedPrincipal;

		public RevocationRecord(String tokenId, Instant revokedAt, RevocationReason reason,
				String revokedBy, String affectedPrincipal) {
			this.tokenId = tokenId;
			this.revokedAt = revokedAt;
			this.reason = reason;
			this.revokedBy = revokedBy;
			this.affectedPrincipal = affectedPrincipal;
		}

		public String getTokenId() {
			return tokenId;
		}

		public Instant getRevokedAt() {
			return revokedAt;
		}

		public RevocationReason getReason() {
			return reason;
		}

		public String getRevokedBy() {
			return revokedBy;
		}

		public String getAffectedPrincipal() {
			return affectedPrincipal;
		}

		@Override
		public String toString() {
			return String.format("RevocationRecord[tokenId=%s, reason=%s, revokedBy=%s, at=%s]",
				tokenId, reason, revokedBy, revokedAt);
		}
	}
}
