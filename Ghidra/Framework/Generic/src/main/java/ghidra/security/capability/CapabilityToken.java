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

import java.time.Instant;
import java.util.*;

/**
 * A capability token grants specific, revocable access to Ghidra APIs.
 * Tokens are scoped by time, principal identity, profile, and optional restrictions.
 *
 * <p>This follows the principle of least privilege: an agent performing function
 * renaming does not need the ability to patch bytes or execute scripts.
 *
 * <p>Token structure based on the agent-runtime-security-spec:
 * <pre>
 * {
 *   "token_id": "uuid-v4",
 *   "issued_at": "2026-02-19T10:00:00Z",
 *   "expires_at": "2026-02-19T18:00:00Z",
 *   "principal": "agent:claude-opus-4-6",
 *   "profile": "annotator",
 *   "capabilities": ["READ.*", "WRITE.RENAME", "WRITE.ANNOTATE"],
 *   "scope": {
 *     "programs": ["firmware_v2.3.gzf"],
 *     "max_mutations_per_session": 500,
 *     "require_receipt": true
 *   }
 * }
 * </pre>
 */
public final class CapabilityToken {

	private final String tokenId;
	private final Instant issuedAt;
	private final Instant expiresAt;
	private final String principal;
	private final String profile;
	private final Set<Capability> capabilities;
	private final TokenScope scope;

	private CapabilityToken(Builder builder) {
		this.tokenId = Objects.requireNonNull(builder.tokenId, "tokenId is required");
		this.issuedAt = Objects.requireNonNull(builder.issuedAt, "issuedAt is required");
		this.expiresAt = Objects.requireNonNull(builder.expiresAt, "expiresAt is required");
		this.principal = Objects.requireNonNull(builder.principal, "principal is required");
		this.profile = Objects.requireNonNull(builder.profile, "profile is required");
		this.capabilities = Collections.unmodifiableSet(
			EnumSet.copyOf(Objects.requireNonNull(builder.capabilities, "capabilities is required")));
		this.scope = builder.scope != null ? builder.scope : TokenScope.UNRESTRICTED;
	}

	/**
	 * Returns the unique identifier for this token.
	 * @return the token ID (UUID format)
	 */
	public String getTokenId() {
		return tokenId;
	}

	/**
	 * Returns when this token was issued.
	 * @return the issue timestamp
	 */
	public Instant getIssuedAt() {
		return issuedAt;
	}

	/**
	 * Returns when this token expires.
	 * @return the expiration timestamp
	 */
	public Instant getExpiresAt() {
		return expiresAt;
	}

	/**
	 * Returns the principal (identity) this token was issued to.
	 * Format: "agent:model-name" or "user:username"
	 * @return the principal identifier
	 */
	public String getPrincipal() {
		return principal;
	}

	/**
	 * Returns the permission profile name (e.g., "observer", "annotator", "analyst").
	 * @return the profile name
	 */
	public String getProfile() {
		return profile;
	}

	/**
	 * Returns the set of capabilities granted by this token.
	 * @return immutable set of capabilities
	 */
	public Set<Capability> getCapabilities() {
		return capabilities;
	}

	/**
	 * Returns the scope restrictions for this token.
	 * @return the token scope
	 */
	public TokenScope getScope() {
		return scope;
	}

	/**
	 * Checks if this token has expired.
	 * @return true if the token has expired
	 */
	public boolean isExpired() {
		return Instant.now().isAfter(expiresAt);
	}

	/**
	 * Checks if this token grants the specified capability.
	 * This accounts for capability hierarchy - if the token has WRITE, it implies WRITE_RENAME.
	 *
	 * @param capability the capability to check
	 * @return true if the capability is granted
	 */
	public boolean hasCapability(Capability capability) {
		if (capability == null) {
			return false;
		}
		// Check direct grant
		if (capabilities.contains(capability)) {
			return true;
		}
		// Check if any granted capability implies the requested one
		for (Capability granted : capabilities) {
			if (granted.implies(capability)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Checks if this token grants the capability specified by identifier.
	 *
	 * @param capabilityId the capability identifier (e.g., "WRITE.RENAME")
	 * @return true if the capability is granted
	 */
	public boolean hasCapability(String capabilityId) {
		Capability cap = Capability.fromIdentifier(capabilityId);
		return cap != null && hasCapability(cap);
	}

	/**
	 * Creates a new builder for constructing capability tokens.
	 * @return a new builder
	 */
	public static Builder builder() {
		return new Builder();
	}

	@Override
	public String toString() {
		return String.format("CapabilityToken[id=%s, principal=%s, profile=%s, expires=%s]",
			tokenId, principal, profile, expiresAt);
	}

	/**
	 * Builder for creating capability tokens.
	 */
	public static final class Builder {
		private String tokenId;
		private Instant issuedAt;
		private Instant expiresAt;
		private String principal;
		private String profile;
		private Set<Capability> capabilities;
		private TokenScope scope;

		private Builder() {
		}

		public Builder tokenId(String tokenId) {
			this.tokenId = tokenId;
			return this;
		}

		public Builder issuedAt(Instant issuedAt) {
			this.issuedAt = issuedAt;
			return this;
		}

		public Builder expiresAt(Instant expiresAt) {
			this.expiresAt = expiresAt;
			return this;
		}

		public Builder principal(String principal) {
			this.principal = principal;
			return this;
		}

		public Builder profile(String profile) {
			this.profile = profile;
			return this;
		}

		public Builder capabilities(Set<Capability> capabilities) {
			this.capabilities = capabilities;
			return this;
		}

		public Builder capabilities(Collection<String> capabilityIds) {
			this.capabilities = Capability.fromIdentifiers(capabilityIds);
			return this;
		}

		public Builder scope(TokenScope scope) {
			this.scope = scope;
			return this;
		}

		public CapabilityToken build() {
			if (tokenId == null) {
				tokenId = UUID.randomUUID().toString();
			}
			if (issuedAt == null) {
				issuedAt = Instant.now();
			}
			return new CapabilityToken(this);
		}
	}

	/**
	 * Defines scope restrictions for a capability token.
	 */
	public static final class TokenScope {
		/**
		 * Unrestricted scope - no additional constraints.
		 */
		public static final TokenScope UNRESTRICTED = new TokenScope(null, null, false);

		private final Set<String> allowedPrograms;
		private final Integer maxMutationsPerSession;
		private final boolean requireReceipt;

		public TokenScope(Set<String> allowedPrograms, Integer maxMutationsPerSession,
				boolean requireReceipt) {
			this.allowedPrograms = allowedPrograms != null
				? Collections.unmodifiableSet(new HashSet<>(allowedPrograms))
				: null;
			this.maxMutationsPerSession = maxMutationsPerSession;
			this.requireReceipt = requireReceipt;
		}

		/**
		 * Returns the set of program names this token is allowed to operate on,
		 * or null if unrestricted.
		 * @return allowed programs or null
		 */
		public Set<String> getAllowedPrograms() {
			return allowedPrograms;
		}

		/**
		 * Returns the maximum number of mutations allowed per session, or null if unlimited.
		 * @return max mutations or null
		 */
		public Integer getMaxMutationsPerSession() {
			return maxMutationsPerSession;
		}

		/**
		 * Returns whether mutations require an associated receipt.
		 * @return true if receipts are required
		 */
		public boolean isReceiptRequired() {
			return requireReceipt;
		}

		/**
		 * Checks if operations on the specified program are allowed.
		 * @param programName the program name
		 * @return true if allowed
		 */
		public boolean isProgramAllowed(String programName) {
			return allowedPrograms == null || allowedPrograms.contains(programName);
		}
	}
}
