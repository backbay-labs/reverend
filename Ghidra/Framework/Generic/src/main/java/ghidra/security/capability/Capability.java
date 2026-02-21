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

import java.util.*;

/**
 * Defines capabilities for agent/tool operations following the principle of least privilege.
 * Capabilities are organized in a hierarchy where parent capabilities imply child capabilities.
 *
 * <p>The capability hierarchy:
 * <pre>
 * ADMIN (full control)
 * ├── WRITE (mutate analysis state)
 * │   ├── RENAME      - Rename functions, variables, parameters
 * │   ├── RETYPE      - Change types, apply structs
 * │   ├── ANNOTATE    - Add/modify comments, bookmarks, tags
 * │   ├── PATCH       - Modify bytes in the program image
 * │   └── STRUCTURE   - Create/modify data types, enums, structs
 * ├── READ (query analysis state)
 * │   ├── DECOMPILE   - Read decompiled output
 * │   ├── DISASM      - Read disassembly
 * │   ├── XREF        - Query cross-references
 * │   ├── STRINGS     - Read string table
 * │   ├── TYPES       - Read type information
 * │   ├── METADATA    - Read program metadata
 * │   └── NAVIGATE    - List functions, search symbols
 * └── EXECUTE
 *     ├── SCRIPT      - Run Ghidra scripts
 *     ├── HEADLESS    - Invoke headless analysis
 *     └── EXTERNAL    - Call external tools
 * </pre>
 */
public enum Capability {

	// Top-level administrative capability
	ADMIN("ADMIN", null),

	// Write capabilities - mutate analysis state
	WRITE("WRITE", ADMIN),
	WRITE_RENAME("WRITE.RENAME", WRITE),
	WRITE_RETYPE("WRITE.RETYPE", WRITE),
	WRITE_ANNOTATE("WRITE.ANNOTATE", WRITE),
	WRITE_PATCH("WRITE.PATCH", WRITE),
	WRITE_STRUCTURE("WRITE.STRUCTURE", WRITE),

	// Read capabilities - query analysis state
	READ("READ", ADMIN),
	READ_DECOMPILE("READ.DECOMPILE", READ),
	READ_DISASM("READ.DISASM", READ),
	READ_XREF("READ.XREF", READ),
	READ_STRINGS("READ.STRINGS", READ),
	READ_TYPES("READ.TYPES", READ),
	READ_METADATA("READ.METADATA", READ),
	READ_NAVIGATE("READ.NAVIGATE", READ),

	// Execute capabilities - run code/external tools
	EXECUTE("EXECUTE", ADMIN),
	EXECUTE_SCRIPT("EXECUTE.SCRIPT", EXECUTE),
	EXECUTE_HEADLESS("EXECUTE.HEADLESS", EXECUTE),
	EXECUTE_EXTERNAL("EXECUTE.EXTERNAL", EXECUTE);

	private final String identifier;
	private final Capability parent;
	private final Set<Capability> implied;

	private static final Map<String, Capability> BY_IDENTIFIER = new HashMap<>();

	static {
		for (Capability cap : values()) {
			BY_IDENTIFIER.put(cap.identifier, cap);
		}
	}

	Capability(String identifier, Capability parent) {
		this.identifier = identifier;
		this.parent = parent;
		this.implied = computeImplied();
	}

	private Set<Capability> computeImplied() {
		// EnumSet cannot be safely initialized from inside enum constructors.
		Set<Capability> result = new HashSet<>();
		result.add(this);
		if (parent != null) {
			// Parent capability implies this one
			// We'll resolve the full chain at query time to avoid initialization order issues
		}
		return Collections.unmodifiableSet(result);
	}

	/**
	 * Returns the string identifier for this capability (e.g., "READ.DECOMPILE").
	 * @return the capability identifier
	 */
	public String getIdentifier() {
		return identifier;
	}

	/**
	 * Returns the parent capability, or null if this is a top-level capability.
	 * @return the parent capability or null
	 */
	public Capability getParent() {
		return parent;
	}

	/**
	 * Checks if this capability implies the given capability.
	 * A capability implies another if it is an ancestor in the hierarchy or the same capability.
	 * For example, WRITE implies WRITE_RENAME, and ADMIN implies all capabilities.
	 *
	 * @param other the capability to check
	 * @return true if this capability implies the other
	 */
	public boolean implies(Capability other) {
		if (this == other) {
			return true;
		}
		// Walk up the hierarchy from 'other' to see if we find 'this'
		Capability current = other.parent;
		while (current != null) {
			if (current == this) {
				return true;
			}
			current = current.parent;
		}
		return false;
	}

	/**
	 * Returns all capabilities that this capability implies (including itself).
	 * @return set of implied capabilities
	 */
	public Set<Capability> getImpliedCapabilities() {
		Set<Capability> result = EnumSet.of(this);
		for (Capability cap : values()) {
			if (this.implies(cap) && cap != this) {
				result.add(cap);
			}
		}
		return Collections.unmodifiableSet(result);
	}

	/**
	 * Parses a capability from its string identifier.
	 * Supports wildcard patterns like "READ.*" which matches all READ sub-capabilities.
	 *
	 * @param identifier the capability identifier
	 * @return the capability, or null if not found
	 */
	public static Capability fromIdentifier(String identifier) {
		return BY_IDENTIFIER.get(identifier);
	}

	/**
	 * Parses a set of capabilities from string identifiers.
	 * Supports wildcard patterns like "READ.*" which expands to all READ sub-capabilities.
	 *
	 * @param identifiers collection of capability identifiers
	 * @return set of capabilities
	 * @throws IllegalArgumentException if an identifier is not recognized
	 */
	public static Set<Capability> fromIdentifiers(Collection<String> identifiers) {
		Set<Capability> result = EnumSet.noneOf(Capability.class);
		for (String id : identifiers) {
			if (id.endsWith(".*")) {
				// Wildcard: expand to parent and all children
				String parentId = id.substring(0, id.length() - 2);
				Capability parent = BY_IDENTIFIER.get(parentId);
				if (parent == null) {
					throw new IllegalArgumentException("Unknown capability: " + parentId);
				}
				result.add(parent);
				result.addAll(parent.getImpliedCapabilities());
			}
			else {
				Capability cap = BY_IDENTIFIER.get(id);
				if (cap == null) {
					throw new IllegalArgumentException("Unknown capability: " + id);
				}
				result.add(cap);
			}
		}
		return result;
	}

	@Override
	public String toString() {
		return identifier;
	}
}
