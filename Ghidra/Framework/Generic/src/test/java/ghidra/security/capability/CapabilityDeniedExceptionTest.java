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

import static org.junit.Assert.*;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

import org.junit.Test;

/**
 * Tests for the {@link CapabilityDeniedException} class.
 * Ensures fail-closed behavior with explicit denial reasons.
 */
public class CapabilityDeniedExceptionTest {

	@Test
	public void testCapabilityNotGranted() {
		CapabilityToken token = CapabilityToken.builder()
			.tokenId("test-001")
			.principal("agent:test")
			.profile("observer")
			.capabilities(List.of("READ.*"))
			.expiresAt(Instant.now().plus(1, ChronoUnit.HOURS))
			.build();

		CapabilityDeniedException ex = CapabilityDeniedException.capabilityNotGranted(
			token, Capability.WRITE_PATCH, "patch bytes at 0x401000");

		assertEquals(Capability.WRITE_PATCH, ex.getDeniedCapability());
		assertEquals(CapabilityDeniedException.DenialReason.CAPABILITY_NOT_GRANTED, ex.getReason());
		assertEquals("observer", ex.getProfile());
		assertEquals("agent:test", ex.getPrincipal());
		assertEquals("patch bytes at 0x401000", ex.getOperation());

		String msg = ex.getMessage();
		assertTrue(msg.contains("Capability not granted"));
		assertTrue(msg.contains("WRITE.PATCH"));
		assertTrue(msg.contains("agent:test"));
		assertTrue(msg.contains("observer"));
	}

	@Test
	public void testTokenExpired() {
		CapabilityToken token = CapabilityToken.builder()
			.tokenId("expired-001")
			.principal("agent:expired-test")
			.profile("annotator")
			.capabilities(List.of("WRITE.*"))
			.expiresAt(Instant.now().minus(1, ChronoUnit.HOURS))
			.build();

		CapabilityDeniedException ex = CapabilityDeniedException.tokenExpired(
			token, Capability.WRITE_RENAME, "rename function");

		assertEquals(Capability.WRITE_RENAME, ex.getDeniedCapability());
		assertEquals(CapabilityDeniedException.DenialReason.TOKEN_EXPIRED, ex.getReason());
		assertTrue(ex.getMessage().contains("Token has expired"));
	}

	@Test
	public void testNoToken() {
		CapabilityDeniedException ex = CapabilityDeniedException.noToken(
			Capability.READ_DECOMPILE, "decompile function at 0x401000");

		assertEquals(Capability.READ_DECOMPILE, ex.getDeniedCapability());
		assertEquals(CapabilityDeniedException.DenialReason.NO_TOKEN, ex.getReason());
		assertEquals("none", ex.getProfile());
		assertEquals("unknown", ex.getPrincipal());
		assertTrue(ex.getMessage().contains("No capability token provided"));
	}

	@Test
	public void testScopeViolation() {
		CapabilityToken token = CapabilityToken.builder()
			.tokenId("scoped-001")
			.principal("agent:scoped-test")
			.profile("annotator")
			.capabilities(List.of("READ.*"))
			.expiresAt(Instant.now().plus(1, ChronoUnit.HOURS))
			.build();

		CapabilityDeniedException ex = CapabilityDeniedException.scopeViolation(
			token, Capability.READ_DECOMPILE, "decompile forbidden.gzf");

		assertEquals(Capability.READ_DECOMPILE, ex.getDeniedCapability());
		assertEquals(CapabilityDeniedException.DenialReason.SCOPE_VIOLATION, ex.getReason());
		assertTrue(ex.getMessage().contains("not in allowed scope"));
	}

	@Test
	public void testDenialReasonDescriptions() {
		assertEquals("Capability not granted in token",
			CapabilityDeniedException.DenialReason.CAPABILITY_NOT_GRANTED.getDescription());
		assertEquals("Token has expired",
			CapabilityDeniedException.DenialReason.TOKEN_EXPIRED.getDescription());
		assertEquals("No capability token provided",
			CapabilityDeniedException.DenialReason.NO_TOKEN.getDescription());
		assertEquals("Operation target not in allowed scope",
			CapabilityDeniedException.DenialReason.SCOPE_VIOLATION.getDescription());
		assertEquals("Session mutation limit exceeded",
			CapabilityDeniedException.DenialReason.MUTATION_LIMIT_EXCEEDED.getDescription());
		assertEquals("Operation requires a receipt",
			CapabilityDeniedException.DenialReason.RECEIPT_REQUIRED.getDescription());
	}

	@Test
	public void testExceptionIsSecurityException() {
		CapabilityDeniedException ex = CapabilityDeniedException.noToken(
			Capability.READ, "test operation");

		// Verify it's a SecurityException subclass (for Java security compatibility)
		assertTrue(ex instanceof SecurityException);
	}

	@Test
	public void testDirectConstruction() {
		CapabilityDeniedException ex = new CapabilityDeniedException(
			Capability.EXECUTE_SCRIPT,
			CapabilityDeniedException.DenialReason.CAPABILITY_NOT_GRANTED,
			"engineer",
			"agent:custom-agent",
			"execute malicious.py");

		assertEquals(Capability.EXECUTE_SCRIPT, ex.getDeniedCapability());
		assertEquals(CapabilityDeniedException.DenialReason.CAPABILITY_NOT_GRANTED, ex.getReason());
		assertEquals("engineer", ex.getProfile());
		assertEquals("agent:custom-agent", ex.getPrincipal());
		assertEquals("execute malicious.py", ex.getOperation());
	}

	@Test
	public void testMutationLimitExceeded() {
		CapabilityDeniedException ex = new CapabilityDeniedException(
			Capability.WRITE_RENAME,
			CapabilityDeniedException.DenialReason.MUTATION_LIMIT_EXCEEDED,
			"annotator",
			"agent:greedy",
			"rename attempt #501");

		assertEquals(CapabilityDeniedException.DenialReason.MUTATION_LIMIT_EXCEEDED, ex.getReason());
		assertTrue(ex.getMessage().contains("Session mutation limit exceeded"));
	}
}
