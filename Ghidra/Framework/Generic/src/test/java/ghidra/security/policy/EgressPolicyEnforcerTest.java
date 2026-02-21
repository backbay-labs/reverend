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

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

/**
 * Tests for the {@link EgressPolicyEnforcer} class.
 * Verifies that policy modes and allowlist enforcement work correctly.
 */
public class EgressPolicyEnforcerTest {

	private EgressPolicy offlinePolicy;
	private EgressPolicy allowlistPolicy;
	private EgressPolicy cloudPolicy;

	@Before
	public void setUp() {
		offlinePolicy = EgressPolicy.offline("test-offline");

		allowlistPolicy = EgressPolicy.builder()
			.projectId("test-allowlist")
			.mode(PolicyMode.ALLOWLIST)
			.addEndpoint(Endpoint.https("api.anthropic.com", "Claude API"))
			.addEndpoint(Endpoint.localhost(11434, "Ollama"))
			.addBlockedPattern("*.pastebin.com")
			.addBlockedPattern("*.ngrok.io")
			.build();

		cloudPolicy = EgressPolicy.defaultCloud("test-cloud");
	}

	// ==================== Offline Mode Tests ====================

	@Test(expected = PolicyViolationException.class)
	public void testOfflineModeBlocksAllNetwork() throws PolicyViolationException {
		EgressPolicyEnforcer enforcer = new EgressPolicyEnforcer(offlinePolicy);
		enforcer.validateEndpoint("api.anthropic.com", 443, "https");
	}

	@Test
	public void testOfflineModeViolationType() {
		EgressPolicyEnforcer enforcer = new EgressPolicyEnforcer(offlinePolicy);
		try {
			enforcer.validateEndpoint("localhost", 11434, "http");
			fail("Expected PolicyViolationException");
		}
		catch (PolicyViolationException e) {
			assertEquals(PolicyViolationException.ViolationType.NETWORK_ACCESS_IN_OFFLINE_MODE,
				e.getType());
			assertEquals(PolicyMode.OFFLINE, e.getMode());
			assertEquals(PolicyViolationException.MitigationAction.USE_LOCAL_MODEL,
				e.getSuggestedAction());
		}
	}

	// ==================== Allowlist Mode Tests ====================

	@Test
	public void testAllowlistModeAllowsConfiguredEndpoint() throws PolicyViolationException {
		EgressPolicyEnforcer enforcer = new EgressPolicyEnforcer(allowlistPolicy);
		// Should not throw
		enforcer.validateEndpoint("api.anthropic.com", 443, "https");
	}

	@Test
	public void testAllowlistModeAllowsLocalhost() throws PolicyViolationException {
		EgressPolicyEnforcer enforcer = new EgressPolicyEnforcer(allowlistPolicy);
		// Should not throw
		enforcer.validateEndpoint("localhost", 11434, "http");
	}

	@Test(expected = PolicyViolationException.class)
	public void testAllowlistModeBlocksUnknownEndpoint() throws PolicyViolationException {
		EgressPolicyEnforcer enforcer = new EgressPolicyEnforcer(allowlistPolicy);
		enforcer.validateEndpoint("evil.example.com", 443, "https");
	}

	@Test
	public void testAllowlistModeEndpointNotAllowedViolationType() {
		EgressPolicyEnforcer enforcer = new EgressPolicyEnforcer(allowlistPolicy);
		try {
			enforcer.validateEndpoint("unknown.api.com", 443, "https");
			fail("Expected PolicyViolationException");
		}
		catch (PolicyViolationException e) {
			assertEquals(PolicyViolationException.ViolationType.ENDPOINT_NOT_ALLOWED, e.getType());
			assertEquals(PolicyViolationException.MitigationAction.ADD_TO_ALLOWLIST,
				e.getSuggestedAction());
		}
	}

	@Test(expected = PolicyViolationException.class)
	public void testAllowlistModeBlocksWrongPort() throws PolicyViolationException {
		EgressPolicyEnforcer enforcer = new EgressPolicyEnforcer(allowlistPolicy);
		// Correct host, wrong port
		enforcer.validateEndpoint("api.anthropic.com", 8080, "https");
	}

	@Test(expected = PolicyViolationException.class)
	public void testAllowlistModeBlocksWrongProtocol() throws PolicyViolationException {
		EgressPolicyEnforcer enforcer = new EgressPolicyEnforcer(allowlistPolicy);
		// Correct host and port, wrong protocol
		enforcer.validateEndpoint("api.anthropic.com", 443, "http");
	}

	// ==================== Blocked Pattern Tests ====================

	@Test(expected = PolicyViolationException.class)
	public void testBlockedPatternMatchesPastebin() throws PolicyViolationException {
		EgressPolicyEnforcer enforcer = new EgressPolicyEnforcer(allowlistPolicy);
		enforcer.validateEndpoint("evil.pastebin.com", 443, "https");
	}

	@Test(expected = PolicyViolationException.class)
	public void testBlockedPatternMatchesNgrok() throws PolicyViolationException {
		EgressPolicyEnforcer enforcer = new EgressPolicyEnforcer(allowlistPolicy);
		enforcer.validateEndpoint("abc123.ngrok.io", 443, "https");
	}

	@Test
	public void testBlockedPatternViolationType() {
		EgressPolicyEnforcer enforcer = new EgressPolicyEnforcer(allowlistPolicy);
		try {
			enforcer.validateEndpoint("exfil.pastebin.com", 443, "https");
			fail("Expected PolicyViolationException");
		}
		catch (PolicyViolationException e) {
			assertEquals(PolicyViolationException.ViolationType.ENDPOINT_BLOCKED, e.getType());
			assertEquals(PolicyViolationException.MitigationAction.CONTACT_ADMIN,
				e.getSuggestedAction());
			assertTrue(e.getDestination().contains("pastebin"));
		}
	}

	// ==================== Cloud Mode Tests ====================

	@Test
	public void testCloudModeAllowsStandardEndpoints() throws PolicyViolationException {
		EgressPolicyEnforcer enforcer = new EgressPolicyEnforcer(cloudPolicy);
		enforcer.validateEndpoint("api.anthropic.com", 443, "https");
		enforcer.validateEndpoint("api.openai.com", 443, "https");
		enforcer.validateEndpoint("localhost", 11434, "http");
	}

	// ==================== Payload Validation Tests ====================

	@Test
	public void testPayloadWithinThreshold() throws PolicyViolationException {
		EgressPolicyEnforcer enforcer = new EgressPolicyEnforcer(cloudPolicy);
		String smallPayload = "Hello, world!";
		enforcer.validateRequest("api.anthropic.com", 443, "https", smallPayload);
	}

	@Test
	public void testPayloadExceedsThreshold() {
		EgressPolicy smallThresholdPolicy = EgressPolicy.builder()
			.projectId("test-small")
			.mode(PolicyMode.CLOUD)
			.addEndpoint(Endpoint.https("api.anthropic.com", "Test"))
			.largePayloadThresholdBytes(100)
			.build();

		EgressPolicyEnforcer enforcer = new EgressPolicyEnforcer(smallThresholdPolicy);
		String largePayload = "x".repeat(200);

		try {
			enforcer.validateRequest("api.anthropic.com", 443, "https", largePayload);
			fail("Expected PolicyViolationException");
		}
		catch (PolicyViolationException e) {
			assertEquals(PolicyViolationException.ViolationType.PAYLOAD_TOO_LARGE, e.getType());
			assertEquals(PolicyViolationException.MitigationAction.REDUCE_PAYLOAD,
				e.getSuggestedAction());
		}
	}

	@Test
	public void testBinaryContentDetection() {
		EgressPolicyEnforcer enforcer = new EgressPolicyEnforcer(cloudPolicy);
		// Binary content with null bytes
		byte[] binaryPayload = new byte[] {0x00, 0x01, 0x02, 0x03, 0x04};

		try {
			enforcer.validateRequest("api.anthropic.com", 443, "https", binaryPayload);
			fail("Expected PolicyViolationException");
		}
		catch (PolicyViolationException e) {
			assertEquals(PolicyViolationException.ViolationType.BINARY_CONTENT_DETECTED, e.getType());
			assertEquals(PolicyViolationException.MitigationAction.STRIP_BINARY_CONTENT,
				e.getSuggestedAction());
		}
	}

	@Test
	public void testNullPayloadAllowed() throws PolicyViolationException {
		EgressPolicyEnforcer enforcer = new EgressPolicyEnforcer(cloudPolicy);
		enforcer.validateRequest("api.anthropic.com", 443, "https", (byte[]) null);
	}

	// ==================== Rate Limiting Tests ====================

	@Test
	public void testRateLimitEnforced() {
		EgressPolicy strictRatePolicy = EgressPolicy.builder()
			.projectId("test-ratelimit")
			.mode(PolicyMode.CLOUD)
			.addEndpoint(Endpoint.https("api.anthropic.com", "Test"))
			.maxRequestsPerMinute(3)
			.build();

		EgressPolicyEnforcer enforcer = new EgressPolicyEnforcer(strictRatePolicy);

		try {
			// Should allow first 3 requests
			for (int i = 0; i < 3; i++) {
				enforcer.validateEndpoint("api.anthropic.com", 443, "https");
			}
			// 4th request should fail
			enforcer.validateEndpoint("api.anthropic.com", 443, "https");
			fail("Expected PolicyViolationException");
		}
		catch (PolicyViolationException e) {
			assertEquals(PolicyViolationException.ViolationType.RATE_LIMIT_EXCEEDED, e.getType());
			assertEquals(PolicyViolationException.MitigationAction.WAIT_AND_RETRY,
				e.getSuggestedAction());
		}
	}

	@Test
	public void testResetRateLimits() throws PolicyViolationException {
		EgressPolicy strictRatePolicy = EgressPolicy.builder()
			.projectId("test-ratelimit-reset")
			.mode(PolicyMode.CLOUD)
			.addEndpoint(Endpoint.https("api.anthropic.com", "Test"))
			.maxRequestsPerMinute(2)
			.build();

		EgressPolicyEnforcer enforcer = new EgressPolicyEnforcer(strictRatePolicy);

		// Use up rate limit
		enforcer.validateEndpoint("api.anthropic.com", 443, "https");
		enforcer.validateEndpoint("api.anthropic.com", 443, "https");

		// Reset
		enforcer.resetRateLimits();

		// Should succeed again
		enforcer.validateEndpoint("api.anthropic.com", 443, "https");
	}

	// ==================== Validation Result Tests ====================

	@Test
	public void testCheckEndpointAllowed() {
		EgressPolicyEnforcer enforcer = new EgressPolicyEnforcer(cloudPolicy);
		EgressPolicyEnforcer.ValidationResult result =
			enforcer.checkEndpoint("api.anthropic.com", 443, "https");

		assertTrue(result.isAllowed());
		assertNull(result.getViolationType());
		assertNull(result.getSuggestedAction());
	}

	@Test
	public void testCheckEndpointDenied() {
		EgressPolicyEnforcer enforcer = new EgressPolicyEnforcer(allowlistPolicy);
		EgressPolicyEnforcer.ValidationResult result =
			enforcer.checkEndpoint("evil.example.com", 443, "https");

		assertFalse(result.isAllowed());
		assertEquals(PolicyViolationException.ViolationType.ENDPOINT_NOT_ALLOWED,
			result.getViolationType());
		assertEquals(PolicyViolationException.MitigationAction.ADD_TO_ALLOWLIST,
			result.getSuggestedAction());
	}

	// ==================== Case Insensitivity Tests ====================

	@Test
	public void testHostnameCaseInsensitive() throws PolicyViolationException {
		EgressPolicyEnforcer enforcer = new EgressPolicyEnforcer(cloudPolicy);
		// Should match regardless of case
		enforcer.validateEndpoint("API.ANTHROPIC.COM", 443, "https");
		enforcer.validateEndpoint("Api.Anthropic.Com", 443, "https");
	}

	@Test
	public void testProtocolCaseInsensitive() throws PolicyViolationException {
		EgressPolicyEnforcer enforcer = new EgressPolicyEnforcer(cloudPolicy);
		// Should match regardless of protocol case
		enforcer.validateEndpoint("api.anthropic.com", 443, "HTTPS");
	}
}
