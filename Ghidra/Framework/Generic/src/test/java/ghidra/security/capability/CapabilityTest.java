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

import java.util.*;

import org.junit.Test;

/**
 * Tests for the {@link Capability} enum.
 */
public class CapabilityTest {

	@Test
	public void testCapabilityIdentifiers() {
		assertEquals("ADMIN", Capability.ADMIN.getIdentifier());
		assertEquals("WRITE", Capability.WRITE.getIdentifier());
		assertEquals("WRITE.RENAME", Capability.WRITE_RENAME.getIdentifier());
		assertEquals("READ", Capability.READ.getIdentifier());
		assertEquals("READ.DECOMPILE", Capability.READ_DECOMPILE.getIdentifier());
		assertEquals("EXECUTE", Capability.EXECUTE.getIdentifier());
		assertEquals("EXECUTE.SCRIPT", Capability.EXECUTE_SCRIPT.getIdentifier());
	}

	@Test
	public void testCapabilityHierarchy_AdminImpliesAll() {
		// ADMIN should imply all capabilities
		assertTrue(Capability.ADMIN.implies(Capability.ADMIN));
		assertTrue(Capability.ADMIN.implies(Capability.WRITE));
		assertTrue(Capability.ADMIN.implies(Capability.WRITE_RENAME));
		assertTrue(Capability.ADMIN.implies(Capability.READ));
		assertTrue(Capability.ADMIN.implies(Capability.READ_DECOMPILE));
		assertTrue(Capability.ADMIN.implies(Capability.EXECUTE));
		assertTrue(Capability.ADMIN.implies(Capability.EXECUTE_SCRIPT));
	}

	@Test
	public void testCapabilityHierarchy_WriteImpliesWriteChildren() {
		assertTrue(Capability.WRITE.implies(Capability.WRITE));
		assertTrue(Capability.WRITE.implies(Capability.WRITE_RENAME));
		assertTrue(Capability.WRITE.implies(Capability.WRITE_RETYPE));
		assertTrue(Capability.WRITE.implies(Capability.WRITE_ANNOTATE));
		assertTrue(Capability.WRITE.implies(Capability.WRITE_PATCH));
		assertTrue(Capability.WRITE.implies(Capability.WRITE_STRUCTURE));

		// WRITE should not imply READ or EXECUTE
		assertFalse(Capability.WRITE.implies(Capability.READ));
		assertFalse(Capability.WRITE.implies(Capability.EXECUTE));
	}

	@Test
	public void testCapabilityHierarchy_ReadImpliesReadChildren() {
		assertTrue(Capability.READ.implies(Capability.READ));
		assertTrue(Capability.READ.implies(Capability.READ_DECOMPILE));
		assertTrue(Capability.READ.implies(Capability.READ_DISASM));
		assertTrue(Capability.READ.implies(Capability.READ_XREF));
		assertTrue(Capability.READ.implies(Capability.READ_STRINGS));
		assertTrue(Capability.READ.implies(Capability.READ_TYPES));
		assertTrue(Capability.READ.implies(Capability.READ_METADATA));
		assertTrue(Capability.READ.implies(Capability.READ_NAVIGATE));

		// READ should not imply WRITE or EXECUTE
		assertFalse(Capability.READ.implies(Capability.WRITE));
		assertFalse(Capability.READ.implies(Capability.EXECUTE));
	}

	@Test
	public void testCapabilityHierarchy_ChildDoesNotImplyParent() {
		// Children should not imply their parents
		assertFalse(Capability.WRITE_RENAME.implies(Capability.WRITE));
		assertFalse(Capability.WRITE_RENAME.implies(Capability.ADMIN));
		assertFalse(Capability.READ_DECOMPILE.implies(Capability.READ));
		assertFalse(Capability.READ_DECOMPILE.implies(Capability.ADMIN));
		assertFalse(Capability.EXECUTE_SCRIPT.implies(Capability.EXECUTE));
	}

	@Test
	public void testCapabilityHierarchy_SiblingsDontImplyEachOther() {
		assertFalse(Capability.WRITE_RENAME.implies(Capability.WRITE_RETYPE));
		assertFalse(Capability.READ_DECOMPILE.implies(Capability.READ_DISASM));
		assertFalse(Capability.WRITE.implies(Capability.READ));
	}

	@Test
	public void testFromIdentifier() {
		assertEquals(Capability.WRITE_RENAME, Capability.fromIdentifier("WRITE.RENAME"));
		assertEquals(Capability.READ_DECOMPILE, Capability.fromIdentifier("READ.DECOMPILE"));
		assertEquals(Capability.ADMIN, Capability.fromIdentifier("ADMIN"));
		assertNull(Capability.fromIdentifier("NONEXISTENT"));
		assertNull(Capability.fromIdentifier(null));
	}

	@Test
	public void testFromIdentifiers_Simple() {
		Set<Capability> result = Capability.fromIdentifiers(
			List.of("READ.DECOMPILE", "WRITE.RENAME"));
		assertEquals(2, result.size());
		assertTrue(result.contains(Capability.READ_DECOMPILE));
		assertTrue(result.contains(Capability.WRITE_RENAME));
	}

	@Test
	public void testFromIdentifiers_Wildcard() {
		Set<Capability> result = Capability.fromIdentifiers(List.of("READ.*"));
		// Should include READ and all READ children
		assertTrue(result.contains(Capability.READ));
		assertTrue(result.contains(Capability.READ_DECOMPILE));
		assertTrue(result.contains(Capability.READ_DISASM));
		assertTrue(result.contains(Capability.READ_XREF));
		assertTrue(result.contains(Capability.READ_STRINGS));
		assertTrue(result.contains(Capability.READ_TYPES));
		assertTrue(result.contains(Capability.READ_METADATA));
		assertTrue(result.contains(Capability.READ_NAVIGATE));

		// Should not include WRITE or EXECUTE
		assertFalse(result.contains(Capability.WRITE));
		assertFalse(result.contains(Capability.EXECUTE));
	}

	@Test(expected = IllegalArgumentException.class)
	public void testFromIdentifiers_UnknownCapability() {
		Capability.fromIdentifiers(List.of("UNKNOWN.CAPABILITY"));
	}

	@Test(expected = IllegalArgumentException.class)
	public void testFromIdentifiers_UnknownWildcard() {
		Capability.fromIdentifiers(List.of("NONEXISTENT.*"));
	}

	@Test
	public void testGetImpliedCapabilities() {
		Set<Capability> writeImplied = Capability.WRITE.getImpliedCapabilities();
		assertTrue(writeImplied.contains(Capability.WRITE));
		assertTrue(writeImplied.contains(Capability.WRITE_RENAME));
		assertTrue(writeImplied.contains(Capability.WRITE_RETYPE));
		assertTrue(writeImplied.contains(Capability.WRITE_ANNOTATE));
		assertTrue(writeImplied.contains(Capability.WRITE_PATCH));
		assertTrue(writeImplied.contains(Capability.WRITE_STRUCTURE));

		// Should not include READ or EXECUTE
		assertFalse(writeImplied.contains(Capability.READ));
		assertFalse(writeImplied.contains(Capability.EXECUTE));
	}

	@Test
	public void testGetParent() {
		assertNull(Capability.ADMIN.getParent());
		assertEquals(Capability.ADMIN, Capability.WRITE.getParent());
		assertEquals(Capability.WRITE, Capability.WRITE_RENAME.getParent());
		assertEquals(Capability.ADMIN, Capability.READ.getParent());
		assertEquals(Capability.READ, Capability.READ_DECOMPILE.getParent());
	}

	@Test
	public void testToString() {
		assertEquals("WRITE.RENAME", Capability.WRITE_RENAME.toString());
		assertEquals("READ.DECOMPILE", Capability.READ_DECOMPILE.toString());
	}
}
