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
package ghidra.reverend;

import static org.junit.Assert.*;

import org.junit.Test;

import ghidra.reverend.api.v1.ServiceVersion;

/**
 * Unit tests for {@link ServiceVersion}.
 */
public class ServiceVersionTest {

	@Test
	public void testCurrentVersion() {
		ServiceVersion current = ServiceVersion.CURRENT;
		assertNotNull(current);
		assertEquals(1, current.getMajor());
		assertEquals(0, current.getMinor());
		assertEquals(0, current.getPatch());
	}

	@Test
	public void testParse() {
		ServiceVersion version = ServiceVersion.parse("2.3.4");
		assertEquals(2, version.getMajor());
		assertEquals(3, version.getMinor());
		assertEquals(4, version.getPatch());
	}

	@Test(expected = IllegalArgumentException.class)
	public void testParseInvalidFormat() {
		ServiceVersion.parse("1.2");
	}

	@Test(expected = IllegalArgumentException.class)
	public void testParseNull() {
		ServiceVersion.parse(null);
	}

	@Test
	public void testCompatibility() {
		ServiceVersion v1_0_0 = new ServiceVersion(1, 0, 0);
		ServiceVersion v1_1_0 = new ServiceVersion(1, 1, 0);
		ServiceVersion v1_1_5 = new ServiceVersion(1, 1, 5);
		ServiceVersion v2_0_0 = new ServiceVersion(2, 0, 0);

		assertTrue(v1_1_0.isCompatibleWith(v1_0_0));
		assertTrue(v1_1_5.isCompatibleWith(v1_1_0));
		assertFalse(v1_0_0.isCompatibleWith(v1_1_0));
		assertFalse(v2_0_0.isCompatibleWith(v1_0_0));
	}

	@Test
	public void testComparison() {
		ServiceVersion v1 = new ServiceVersion(1, 0, 0);
		ServiceVersion v2 = new ServiceVersion(1, 1, 0);
		ServiceVersion v3 = new ServiceVersion(2, 0, 0);

		assertTrue(v1.compareTo(v2) < 0);
		assertTrue(v2.compareTo(v3) < 0);
		assertTrue(v3.compareTo(v1) > 0);
		assertEquals(0, v1.compareTo(new ServiceVersion(1, 0, 0)));
	}

	@Test
	public void testToString() {
		ServiceVersion version = new ServiceVersion(1, 2, 3);
		assertEquals("1.2.3", version.toString());
	}

	@Test
	public void testEqualsAndHashCode() {
		ServiceVersion v1 = new ServiceVersion(1, 0, 0);
		ServiceVersion v2 = new ServiceVersion(1, 0, 0);
		ServiceVersion v3 = new ServiceVersion(1, 0, 1);

		assertEquals(v1, v2);
		assertEquals(v1.hashCode(), v2.hashCode());
		assertNotEquals(v1, v3);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testNegativeVersion() {
		new ServiceVersion(-1, 0, 0);
	}

	@Test
	public void testModuleConstants() {
		assertEquals("Reverend", ReverendPluginModule.MODULE_NAME);
		assertEquals("1.0.0", ReverendPluginModule.MODULE_VERSION);
		assertEquals(ServiceVersion.CURRENT, ReverendPluginModule.getApiVersion());
	}
}
