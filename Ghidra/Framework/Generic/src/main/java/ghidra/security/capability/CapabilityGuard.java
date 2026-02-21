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

import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Guards operations by validating capability tokens before action execution.
 * Every tool entrypoint should validate the capability token using this guard.
 *
 * <p>Usage pattern:
 * <pre>
 * CapabilityGuard guard = new CapabilityGuard(token);
 *
 * // Before any tool operation:
 * guard.assertCapability(Capability.WRITE_RENAME, "rename function to 'main'");
 *
 * // Or for scoped operations:
 * guard.assertCapabilityForProgram(Capability.READ_DECOMPILE, "firmware.bin",
 *     "decompile function at 0x401000");
 * </pre>
 *
 * <p>The guard implements fail-closed behavior: all denied operations throw
 * {@link CapabilityDeniedException} with an explicit reason.
 */
public class CapabilityGuard {

	private final CapabilityToken token;
	private final AtomicInteger mutationCount;

	/**
	 * Creates a guard with the specified capability token.
	 *
	 * @param token the capability token to enforce
	 * @throws IllegalArgumentException if token is null
	 */
	public CapabilityGuard(CapabilityToken token) {
		this.token = Objects.requireNonNull(token, "CapabilityToken must not be null");
		this.mutationCount = new AtomicInteger(0);
	}

	/**
	 * Returns the token being guarded.
	 * @return the capability token
	 */
	public CapabilityToken getToken() {
		return token;
	}

	/**
	 * Asserts that the token grants the specified capability.
	 * Throws {@link CapabilityDeniedException} if the capability is not granted.
	 *
	 * @param capability the required capability
	 * @param operation description of the attempted operation (for audit/logging)
	 * @throws CapabilityDeniedException if the capability is not granted
	 */
	public void assertCapability(Capability capability, String operation)
			throws CapabilityDeniedException {
		Objects.requireNonNull(capability, "capability must not be null");
		Objects.requireNonNull(operation, "operation must not be null");

		// Check token expiration first
		if (token.isExpired()) {
			throw CapabilityDeniedException.tokenExpired(token, capability, operation);
		}

		// Check capability grant
		if (!token.hasCapability(capability)) {
			throw CapabilityDeniedException.capabilityNotGranted(token, capability, operation);
		}

		// Track mutations for write operations
		if (isWriteCapability(capability)) {
			trackMutation(capability, operation);
		}
	}

	/**
	 * Asserts that the token grants the specified capability for the given program.
	 * Validates both capability and program scope.
	 *
	 * @param capability the required capability
	 * @param programName the target program name
	 * @param operation description of the attempted operation
	 * @throws CapabilityDeniedException if access is denied
	 */
	public void assertCapabilityForProgram(Capability capability, String programName,
			String operation) throws CapabilityDeniedException {
		Objects.requireNonNull(programName, "programName must not be null");

		// First check the basic capability
		assertCapability(capability, operation);

		// Then check program scope
		if (!token.getScope().isProgramAllowed(programName)) {
			throw CapabilityDeniedException.scopeViolation(token, capability,
				operation + " (program: " + programName + ")");
		}
	}

	/**
	 * Asserts that the token grants the specified capability identified by string.
	 *
	 * @param capabilityId the capability identifier (e.g., "WRITE.RENAME")
	 * @param operation description of the attempted operation
	 * @throws CapabilityDeniedException if the capability is not granted
	 * @throws IllegalArgumentException if the capability identifier is unknown
	 */
	public void assertCapability(String capabilityId, String operation)
			throws CapabilityDeniedException {
		Capability capability = Capability.fromIdentifier(capabilityId);
		if (capability == null) {
			throw new IllegalArgumentException("Unknown capability: " + capabilityId);
		}
		assertCapability(capability, operation);
	}

	/**
	 * Checks if the token grants the specified capability without throwing.
	 *
	 * @param capability the capability to check
	 * @return true if granted and not expired
	 */
	public boolean hasCapability(Capability capability) {
		return !token.isExpired() && token.hasCapability(capability);
	}

	/**
	 * Checks if the token grants the specified capability for the given program.
	 *
	 * @param capability the capability to check
	 * @param programName the target program name
	 * @return true if granted, not expired, and in scope
	 */
	public boolean hasCapabilityForProgram(Capability capability, String programName) {
		return hasCapability(capability) && token.getScope().isProgramAllowed(programName);
	}

	/**
	 * Returns the current mutation count for this session.
	 * @return the number of write operations performed
	 */
	public int getMutationCount() {
		return mutationCount.get();
	}

	/**
	 * Creates a guard that requires no capabilities (for testing or bypass scenarios).
	 * This guard will deny all operations.
	 *
	 * @return a guard that denies everything
	 */
	public static CapabilityGuard denyAll() {
		// Create an expired token with no capabilities
		return new CapabilityGuard(CapabilityToken.builder()
			.tokenId("deny-all")
			.principal("system:deny-all")
			.profile("none")
			.capabilities(java.util.Collections.<Capability>emptySet())
			.expiresAt(java.time.Instant.EPOCH)
			.build());
	}

	private void trackMutation(Capability capability, String operation)
			throws CapabilityDeniedException {
		int count = mutationCount.incrementAndGet();
		Integer limit = token.getScope().getMaxMutationsPerSession();
		if (limit != null && count > limit) {
			throw new CapabilityDeniedException(
				capability,
				CapabilityDeniedException.DenialReason.MUTATION_LIMIT_EXCEEDED,
				token.getProfile(),
				token.getPrincipal(),
				operation);
		}
	}

	private boolean isWriteCapability(Capability capability) {
		return capability == Capability.WRITE ||
			capability.getIdentifier().startsWith("WRITE.");
	}
}
