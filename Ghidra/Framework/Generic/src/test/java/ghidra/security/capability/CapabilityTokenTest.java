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
 * Tests for the {@link CapabilityToken} class.
 */
public class CapabilityTokenTest {

	private CapabilityToken annotatorToken;
	private CapabilityToken observerToken;
	private CapabilityToken expiredToken;

	@Before
	public void setUp() {
		// Create an annotator profile token (READ.* + WRITE.RENAME + WRITE.ANNOTATE)
		annotatorToken = CapabilityToken.builder()
			.tokenId("test-annotator-001")
			.principal("agent:claude-opus-4-6")
			.profile("annotator")
			.capabilities(List.of("READ.*", "WRITE.RENAME", "WRITE.ANNOTATE"))
			.expiresAt(Instant.now().plus(8, ChronoUnit.HOURS))
			.build();

		// Create an observer profile token (READ.* only)
		observerToken = CapabilityToken.builder()
			.tokenId("test-observer-001")
			.principal("agent:test-model")
			.profile("observer")
			.capabilities(List.of("READ.*"))
			.expiresAt(Instant.now().plus(8, ChronoUnit.HOURS))
			.build();

		// Create an expired token
		expiredToken = CapabilityToken.builder()
			.tokenId("test-expired-001")
			.principal("agent:expired")
			.profile("annotator")
			.capabilities(List.of("READ.*", "WRITE.*"))
			.expiresAt(Instant.now().minus(1, ChronoUnit.HOURS))
			.build();
	}

	@Test
	public void testTokenBuilderDefaults() {
		CapabilityToken token = CapabilityToken.builder()
			.principal("test:user")
			.profile("test")
			.capabilities(Set.of(Capability.READ))
			.expiresAt(Instant.now().plus(1, ChronoUnit.HOURS))
			.build();

		assertNotNull(token.getTokenId());
		assertNotNull(token.getIssuedAt());
	}

	@Test
	public void testAnnotatorHasReadCapabilities() {
		assertTrue(annotatorToken.hasCapability(Capability.READ));
		assertTrue(annotatorToken.hasCapability(Capability.READ_DECOMPILE));
		assertTrue(annotatorToken.hasCapability(Capability.READ_DISASM));
		assertTrue(annotatorToken.hasCapability(Capability.READ_XREF));
		assertTrue(annotatorToken.hasCapability(Capability.READ_STRINGS));
	}

	@Test
	public void testAnnotatorHasWriteRenameAndAnnotate() {
		assertTrue(annotatorToken.hasCapability(Capability.WRITE_RENAME));
		assertTrue(annotatorToken.hasCapability(Capability.WRITE_ANNOTATE));
	}

	@Test
	public void testAnnotatorLacksWritePatch() {
		assertFalse(annotatorToken.hasCapability(Capability.WRITE_PATCH));
		assertFalse(annotatorToken.hasCapability(Capability.WRITE_RETYPE));
		assertFalse(annotatorToken.hasCapability(Capability.WRITE)); // Parent not directly granted
	}

	@Test
	public void testAnnotatorLacksExecute() {
		assertFalse(annotatorToken.hasCapability(Capability.EXECUTE));
		assertFalse(annotatorToken.hasCapability(Capability.EXECUTE_SCRIPT));
		assertFalse(annotatorToken.hasCapability(Capability.EXECUTE_EXTERNAL));
	}

	@Test
	public void testAnnotatorLacksAdmin() {
		assertFalse(annotatorToken.hasCapability(Capability.ADMIN));
	}

	@Test
	public void testObserverHasOnlyRead() {
		assertTrue(observerToken.hasCapability(Capability.READ));
		assertTrue(observerToken.hasCapability(Capability.READ_DECOMPILE));
		assertFalse(observerToken.hasCapability(Capability.WRITE));
		assertFalse(observerToken.hasCapability(Capability.WRITE_RENAME));
		assertFalse(observerToken.hasCapability(Capability.EXECUTE));
	}

	@Test
	public void testHasCapabilityByString() {
		assertTrue(annotatorToken.hasCapability("READ.DECOMPILE"));
		assertTrue(annotatorToken.hasCapability("WRITE.RENAME"));
		assertFalse(annotatorToken.hasCapability("WRITE.PATCH"));
		assertFalse(annotatorToken.hasCapability("NONEXISTENT"));
	}

	@Test
	public void testTokenExpiration() {
		assertFalse(annotatorToken.isExpired());
		assertTrue(expiredToken.isExpired());
	}

	@Test
	public void testTokenMetadata() {
		assertEquals("test-annotator-001", annotatorToken.getTokenId());
		assertEquals("agent:claude-opus-4-6", annotatorToken.getPrincipal());
		assertEquals("annotator", annotatorToken.getProfile());
		assertNotNull(annotatorToken.getIssuedAt());
		assertNotNull(annotatorToken.getExpiresAt());
	}

	@Test
	public void testTokenScope_Unrestricted() {
		CapabilityToken.TokenScope scope = annotatorToken.getScope();
		assertTrue(scope.isProgramAllowed("any-program.gzf"));
		assertTrue(scope.isProgramAllowed("another-program.exe"));
		assertNull(scope.getMaxMutationsPerSession());
	}

	@Test
	public void testTokenScope_RestrictedPrograms() {
		CapabilityToken.TokenScope restrictedScope = new CapabilityToken.TokenScope(
			Set.of("allowed.gzf", "also-allowed.exe"),
			100,
			true);

		assertTrue(restrictedScope.isProgramAllowed("allowed.gzf"));
		assertTrue(restrictedScope.isProgramAllowed("also-allowed.exe"));
		assertFalse(restrictedScope.isProgramAllowed("not-allowed.bin"));
		assertEquals(Integer.valueOf(100), restrictedScope.getMaxMutationsPerSession());
		assertTrue(restrictedScope.isReceiptRequired());
	}

	@Test
	public void testTokenWithScope() {
		CapabilityToken.TokenScope scope = new CapabilityToken.TokenScope(
			Set.of("firmware.gzf"),
			500,
			true);

		CapabilityToken scopedToken = CapabilityToken.builder()
			.tokenId("scoped-001")
			.principal("agent:test")
			.profile("annotator")
			.capabilities(List.of("READ.*"))
			.expiresAt(Instant.now().plus(1, ChronoUnit.HOURS))
			.scope(scope)
			.build();

		assertTrue(scopedToken.getScope().isProgramAllowed("firmware.gzf"));
		assertFalse(scopedToken.getScope().isProgramAllowed("other.gzf"));
	}

	@Test
	public void testTokenToString() {
		String str = annotatorToken.toString();
		assertTrue(str.contains("test-annotator-001"));
		assertTrue(str.contains("agent:claude-opus-4-6"));
		assertTrue(str.contains("annotator"));
	}

	@Test
	public void testCapabilitiesAreImmutable() {
		Set<Capability> caps = annotatorToken.getCapabilities();
		try {
			caps.add(Capability.ADMIN);
			fail("Should not be able to modify capabilities set");
		}
		catch (UnsupportedOperationException e) {
			// Expected
		}
	}

	@Test(expected = NullPointerException.class)
	public void testBuilderRequiresPrincipal() {
		CapabilityToken.builder()
			.profile("test")
			.capabilities(Set.of(Capability.READ))
			.expiresAt(Instant.now().plus(1, ChronoUnit.HOURS))
			.build();
	}

	@Test(expected = NullPointerException.class)
	public void testBuilderRequiresProfile() {
		CapabilityToken.builder()
			.principal("test:user")
			.capabilities(Set.of(Capability.READ))
			.expiresAt(Instant.now().plus(1, ChronoUnit.HOURS))
			.build();
	}

	@Test(expected = NullPointerException.class)
	public void testBuilderRequiresCapabilities() {
		CapabilityToken.builder()
			.principal("test:user")
			.profile("test")
			.expiresAt(Instant.now().plus(1, ChronoUnit.HOURS))
			.build();
	}

	@Test(expected = NullPointerException.class)
	public void testBuilderRequiresExpiresAt() {
		CapabilityToken.builder()
			.principal("test:user")
			.profile("test")
			.capabilities(Set.of(Capability.READ))
			.build();
	}
}
