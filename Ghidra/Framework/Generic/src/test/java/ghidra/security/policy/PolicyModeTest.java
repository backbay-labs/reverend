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

import org.junit.Test;

/**
 * Tests for the {@link PolicyMode} enum.
 */
public class PolicyModeTest {

	@Test
	public void testOfflineModeBlocksNetwork() {
		assertFalse(PolicyMode.OFFLINE.allowsNetworkAccess());
	}

	@Test
	public void testAllowlistModeAllowsNetwork() {
		assertTrue(PolicyMode.ALLOWLIST.allowsNetworkAccess());
	}

	@Test
	public void testCloudModeAllowsNetwork() {
		assertTrue(PolicyMode.CLOUD.allowsNetworkAccess());
	}

	@Test
	public void testOfflineModeDoesNotRequireAllowlist() {
		assertFalse(PolicyMode.OFFLINE.requiresAllowlist());
	}

	@Test
	public void testAllowlistModeRequiresAllowlist() {
		assertTrue(PolicyMode.ALLOWLIST.requiresAllowlist());
	}

	@Test
	public void testCloudModeRequiresAllowlist() {
		assertTrue(PolicyMode.CLOUD.requiresAllowlist());
	}

	@Test
	public void testFromIdentifierLowercase() {
		assertEquals(PolicyMode.OFFLINE, PolicyMode.fromIdentifier("offline"));
		assertEquals(PolicyMode.ALLOWLIST, PolicyMode.fromIdentifier("allowlist"));
		assertEquals(PolicyMode.CLOUD, PolicyMode.fromIdentifier("cloud"));
	}

	@Test
	public void testFromIdentifierCaseInsensitive() {
		assertEquals(PolicyMode.OFFLINE, PolicyMode.fromIdentifier("OFFLINE"));
		assertEquals(PolicyMode.ALLOWLIST, PolicyMode.fromIdentifier("AllowList"));
		assertEquals(PolicyMode.CLOUD, PolicyMode.fromIdentifier("CLOUD"));
	}

	@Test
	public void testFromIdentifierWithWhitespace() {
		assertEquals(PolicyMode.OFFLINE, PolicyMode.fromIdentifier("  offline  "));
	}

	@Test(expected = IllegalArgumentException.class)
	public void testFromIdentifierNull() {
		PolicyMode.fromIdentifier(null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testFromIdentifierUnknown() {
		PolicyMode.fromIdentifier("unknown");
	}

	@Test
	public void testIdentifiers() {
		assertEquals("offline", PolicyMode.OFFLINE.getIdentifier());
		assertEquals("allowlist", PolicyMode.ALLOWLIST.getIdentifier());
		assertEquals("cloud", PolicyMode.CLOUD.getIdentifier());
	}

	@Test
	public void testDescriptions() {
		assertEquals("No external network access permitted", PolicyMode.OFFLINE.getDescription());
		assertEquals("Only allow-listed endpoints permitted", PolicyMode.ALLOWLIST.getDescription());
		assertEquals("Cloud endpoints with monitoring", PolicyMode.CLOUD.getDescription());
	}

	@Test
	public void testToString() {
		assertEquals("offline", PolicyMode.OFFLINE.toString());
		assertEquals("allowlist", PolicyMode.ALLOWLIST.toString());
		assertEquals("cloud", PolicyMode.CLOUD.toString());
	}
}
