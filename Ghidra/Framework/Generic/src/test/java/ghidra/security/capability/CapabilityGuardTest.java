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
import java.util.*;

import org.junit.Before;
import org.junit.Test;

/**
 * Tests for the {@link CapabilityGuard} class.
 * Verifies fail-closed behavior and explicit denial reasons.
 */
public class CapabilityGuardTest {

	private CapabilityGuard annotatorGuard;
	private CapabilityGuard observerGuard;
	private CapabilityGuard scopedGuard;

	@Before
	public void setUp() {
		// Annotator: READ.* + WRITE.RENAME + WRITE.ANNOTATE
		CapabilityToken annotatorToken = CapabilityToken.builder()
			.tokenId("annotator-001")
			.principal("agent:claude-opus-4-6")
			.profile("annotator")
			.capabilities(List.of("READ.*", "WRITE.RENAME", "WRITE.ANNOTATE"))
			.expiresAt(Instant.now().plus(8, ChronoUnit.HOURS))
			.build();
		annotatorGuard = new CapabilityGuard(annotatorToken);

		// Observer: READ.* only
		CapabilityToken observerToken = CapabilityToken.builder()
			.tokenId("observer-001")
			.principal("agent:test-model")
			.profile("observer")
			.capabilities(List.of("READ.*"))
			.expiresAt(Instant.now().plus(8, ChronoUnit.HOURS))
			.build();
		observerGuard = new CapabilityGuard(observerToken);

		// Scoped guard with program and mutation restrictions
		CapabilityToken.TokenScope scope = new CapabilityToken.TokenScope(
			Set.of("allowed.gzf"),
			3,  // max 3 mutations
			true);
		CapabilityToken scopedToken = CapabilityToken.builder()
			.tokenId("scoped-001")
			.principal("agent:scoped")
			.profile("annotator")
			.capabilities(List.of("READ.*", "WRITE.RENAME"))
			.expiresAt(Instant.now().plus(8, ChronoUnit.HOURS))
			.scope(scope)
			.build();
		scopedGuard = new CapabilityGuard(scopedToken);
	}

	// === Happy path tests ===

	@Test
	public void testAssertCapability_GrantedCapabilitySucceeds() {
		// Should not throw for granted capabilities
		annotatorGuard.assertCapability(Capability.READ, "read operation");
		annotatorGuard.assertCapability(Capability.READ_DECOMPILE, "decompile function");
		annotatorGuard.assertCapability(Capability.WRITE_RENAME, "rename function");
		annotatorGuard.assertCapability(Capability.WRITE_ANNOTATE, "add comment");
	}

	@Test
	public void testAssertCapability_ByString() {
		annotatorGuard.assertCapability("READ.DECOMPILE", "decompile function");
		annotatorGuard.assertCapability("WRITE.RENAME", "rename function");
	}

	@Test
	public void testHasCapability_GrantedReturnsTrue() {
		assertTrue(annotatorGuard.hasCapability(Capability.READ));
		assertTrue(annotatorGuard.hasCapability(Capability.READ_DECOMPILE));
		assertTrue(annotatorGuard.hasCapability(Capability.WRITE_RENAME));
	}

	@Test
	public void testHasCapability_NotGrantedReturnsFalse() {
		assertFalse(annotatorGuard.hasCapability(Capability.WRITE_PATCH));
		assertFalse(annotatorGuard.hasCapability(Capability.EXECUTE));
		assertFalse(annotatorGuard.hasCapability(Capability.ADMIN));
	}

	// === Fail-closed tests: denials with explicit reasons ===

	@Test
	public void testAssertCapability_DeniedThrowsWithReason() {
		try {
			annotatorGuard.assertCapability(Capability.WRITE_PATCH, "patch bytes at 0x401000");
			fail("Should throw CapabilityDeniedException");
		}
		catch (CapabilityDeniedException e) {
			assertEquals(Capability.WRITE_PATCH, e.getDeniedCapability());
			assertEquals(CapabilityDeniedException.DenialReason.CAPABILITY_NOT_GRANTED, e.getReason());
			assertEquals("annotator", e.getProfile());
			assertEquals("agent:claude-opus-4-6", e.getPrincipal());
			assertTrue(e.getOperation().contains("patch bytes"));
			assertTrue(e.getMessage().contains("WRITE.PATCH"));
			assertTrue(e.getMessage().contains("Capability not granted"));
		}
	}

	@Test
	public void testAssertCapability_ObserverCannotWrite() {
		try {
			observerGuard.assertCapability(Capability.WRITE_RENAME, "rename function main");
			fail("Should throw CapabilityDeniedException");
		}
		catch (CapabilityDeniedException e) {
			assertEquals(Capability.WRITE_RENAME, e.getDeniedCapability());
			assertEquals(CapabilityDeniedException.DenialReason.CAPABILITY_NOT_GRANTED, e.getReason());
			assertEquals("observer", e.getProfile());
		}
	}

	@Test
	public void testAssertCapability_ExpiredTokenDenied() {
		CapabilityToken expiredToken = CapabilityToken.builder()
			.tokenId("expired-001")
			.principal("agent:expired")
			.profile("admin")
			.capabilities(Set.of(Capability.ADMIN))
			.expiresAt(Instant.now().minus(1, ChronoUnit.HOURS))
			.build();
		CapabilityGuard expiredGuard = new CapabilityGuard(expiredToken);

		try {
			expiredGuard.assertCapability(Capability.READ, "read something");
			fail("Should throw CapabilityDeniedException");
		}
		catch (CapabilityDeniedException e) {
			assertEquals(CapabilityDeniedException.DenialReason.TOKEN_EXPIRED, e.getReason());
			assertTrue(e.getMessage().contains("Token has expired"));
		}
	}

	// === Program scope tests ===

	@Test
	public void testAssertCapabilityForProgram_AllowedProgram() {
		scopedGuard.assertCapabilityForProgram(
			Capability.READ_DECOMPILE, "allowed.gzf", "decompile function");
	}

	@Test
	public void testAssertCapabilityForProgram_DeniedProgram() {
		try {
			scopedGuard.assertCapabilityForProgram(
				Capability.READ_DECOMPILE, "not-allowed.gzf", "decompile function");
			fail("Should throw CapabilityDeniedException");
		}
		catch (CapabilityDeniedException e) {
			assertEquals(CapabilityDeniedException.DenialReason.SCOPE_VIOLATION, e.getReason());
			assertTrue(e.getMessage().contains("not in allowed scope"));
		}
	}

	@Test
	public void testHasCapabilityForProgram() {
		assertTrue(scopedGuard.hasCapabilityForProgram(Capability.READ_DECOMPILE, "allowed.gzf"));
		assertFalse(scopedGuard.hasCapabilityForProgram(Capability.READ_DECOMPILE, "other.gzf"));
		assertFalse(scopedGuard.hasCapabilityForProgram(Capability.WRITE_PATCH, "allowed.gzf"));
	}

	// === Mutation tracking tests ===

	@Test
	public void testMutationTracking() {
		assertEquals(0, scopedGuard.getMutationCount());

		// First write operation
		scopedGuard.assertCapability(Capability.WRITE_RENAME, "rename 1");
		assertEquals(1, scopedGuard.getMutationCount());

		// Second write operation
		scopedGuard.assertCapability(Capability.WRITE_RENAME, "rename 2");
		assertEquals(2, scopedGuard.getMutationCount());

		// Read operations don't count
		scopedGuard.assertCapability(Capability.READ_DECOMPILE, "decompile");
		assertEquals(2, scopedGuard.getMutationCount());

		// Third write operation (at limit)
		scopedGuard.assertCapability(Capability.WRITE_RENAME, "rename 3");
		assertEquals(3, scopedGuard.getMutationCount());
	}

	@Test
	public void testMutationLimitExceeded() {
		// Use up the mutation limit (3)
		scopedGuard.assertCapability(Capability.WRITE_RENAME, "rename 1");
		scopedGuard.assertCapability(Capability.WRITE_RENAME, "rename 2");
		scopedGuard.assertCapability(Capability.WRITE_RENAME, "rename 3");

		try {
			scopedGuard.assertCapability(Capability.WRITE_RENAME, "rename 4");
			fail("Should throw CapabilityDeniedException");
		}
		catch (CapabilityDeniedException e) {
			assertEquals(CapabilityDeniedException.DenialReason.MUTATION_LIMIT_EXCEEDED, e.getReason());
			assertTrue(e.getMessage().contains("mutation limit"));
		}
	}

	// === DenyAll guard tests ===

	@Test
	public void testDenyAllGuard() {
		CapabilityGuard denyAll = CapabilityGuard.denyAll();

		assertFalse(denyAll.hasCapability(Capability.READ));
		assertFalse(denyAll.hasCapability(Capability.WRITE));
		assertFalse(denyAll.hasCapability(Capability.ADMIN));

		try {
			denyAll.assertCapability(Capability.READ, "any operation");
			fail("Should throw CapabilityDeniedException");
		}
		catch (CapabilityDeniedException e) {
			// Expected - token is expired
			assertEquals(CapabilityDeniedException.DenialReason.TOKEN_EXPIRED, e.getReason());
		}
	}

	// === Edge cases ===

	@Test(expected = NullPointerException.class)
	public void testConstructorRejectsNullToken() {
		new CapabilityGuard(null);
	}

	@Test(expected = NullPointerException.class)
	public void testAssertCapabilityRejectsNullCapability() {
		annotatorGuard.assertCapability((Capability) null, "operation");
	}

	@Test(expected = NullPointerException.class)
	public void testAssertCapabilityRejectsNullOperation() {
		annotatorGuard.assertCapability(Capability.READ, null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testAssertCapabilityByStringRejectsUnknown() {
		annotatorGuard.assertCapability("UNKNOWN.CAPABILITY", "operation");
	}

	@Test
	public void testGetToken() {
		CapabilityToken token = annotatorGuard.getToken();
		assertEquals("annotator-001", token.getTokenId());
		assertEquals("agent:claude-opus-4-6", token.getPrincipal());
	}
}
