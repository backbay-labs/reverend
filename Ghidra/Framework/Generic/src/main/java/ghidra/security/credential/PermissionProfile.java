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
package ghidra.security.credential;

import java.util.*;

import ghidra.security.capability.Capability;

/**
 * Predefined permission profiles that bundle capabilities for common use cases.
 * Based on the agent-runtime-security-spec permission profiles.
 *
 * <p>Profile hierarchy:
 * <ul>
 *   <li><b>Observer</b>: READ.* - Explain functions, answer questions, no mutations</li>
 *   <li><b>Annotator</b>: READ.* + WRITE.RENAME + WRITE.ANNOTATE - Most common agent mode</li>
 *   <li><b>Analyst</b>: READ.* + WRITE.RENAME/RETYPE/ANNOTATE/STRUCTURE - Full analysis without patches</li>
 *   <li><b>Engineer</b>: READ.* + WRITE.* + EXECUTE.SCRIPT - Development and automation</li>
 *   <li><b>Admin</b>: ADMIN - Unrestricted (human operators only)</li>
 * </ul>
 */
public enum PermissionProfile {

	/**
	 * Observer profile: read-only access.
	 * Use for explaining functions, answering questions, no mutations allowed.
	 */
	OBSERVER("observer", "Read-only access for explanation and queries",
		EnumSet.of(
			Capability.READ,
			Capability.READ_DECOMPILE,
			Capability.READ_DISASM,
			Capability.READ_XREF,
			Capability.READ_STRINGS,
			Capability.READ_TYPES,
			Capability.READ_METADATA,
			Capability.READ_NAVIGATE
		)),

	/**
	 * Annotator profile: read plus rename and comment capabilities.
	 * Most common agent mode for suggesting names and comments.
	 */
	ANNOTATOR("annotator", "Read access plus rename and annotation capabilities",
		EnumSet.of(
			Capability.READ,
			Capability.READ_DECOMPILE,
			Capability.READ_DISASM,
			Capability.READ_XREF,
			Capability.READ_STRINGS,
			Capability.READ_TYPES,
			Capability.READ_METADATA,
			Capability.READ_NAVIGATE,
			Capability.WRITE_RENAME,
			Capability.WRITE_ANNOTATE
		)),

	/**
	 * Analyst profile: full analysis capabilities without byte patching.
	 * For comprehensive analysis assistance.
	 */
	ANALYST("analyst", "Full analysis capabilities without byte patching",
		EnumSet.of(
			Capability.READ,
			Capability.READ_DECOMPILE,
			Capability.READ_DISASM,
			Capability.READ_XREF,
			Capability.READ_STRINGS,
			Capability.READ_TYPES,
			Capability.READ_METADATA,
			Capability.READ_NAVIGATE,
			Capability.WRITE_RENAME,
			Capability.WRITE_RETYPE,
			Capability.WRITE_ANNOTATE,
			Capability.WRITE_STRUCTURE
		)),

	/**
	 * Engineer profile: full read/write plus script execution.
	 * For development and advanced automation workflows.
	 */
	ENGINEER("engineer", "Full read/write access plus script execution",
		EnumSet.of(
			Capability.READ,
			Capability.READ_DECOMPILE,
			Capability.READ_DISASM,
			Capability.READ_XREF,
			Capability.READ_STRINGS,
			Capability.READ_TYPES,
			Capability.READ_METADATA,
			Capability.READ_NAVIGATE,
			Capability.WRITE,
			Capability.WRITE_RENAME,
			Capability.WRITE_RETYPE,
			Capability.WRITE_ANNOTATE,
			Capability.WRITE_PATCH,
			Capability.WRITE_STRUCTURE,
			Capability.EXECUTE_SCRIPT
		)),

	/**
	 * Admin profile: unrestricted access.
	 * Reserved for human operators only.
	 */
	ADMIN("admin", "Unrestricted administrative access",
		EnumSet.of(Capability.ADMIN));

	private final String name;
	private final String description;
	private final Set<Capability> capabilities;

	private static final Map<String, PermissionProfile> BY_NAME = new HashMap<>();

	static {
		for (PermissionProfile profile : values()) {
			BY_NAME.put(profile.name, profile);
		}
	}

	PermissionProfile(String name, String description, EnumSet<Capability> capabilities) {
		this.name = name;
		this.description = description;
		this.capabilities = Collections.unmodifiableSet(capabilities);
	}

	/**
	 * Returns the profile name (lowercase identifier).
	 * @return the profile name
	 */
	public String getName() {
		return name;
	}

	/**
	 * Returns a human-readable description of this profile.
	 * @return the description
	 */
	public String getDescription() {
		return description;
	}

	/**
	 * Returns the set of capabilities granted by this profile.
	 * @return immutable set of capabilities
	 */
	public Set<Capability> getCapabilities() {
		return capabilities;
	}

	/**
	 * Checks if this profile grants the specified capability.
	 *
	 * @param capability the capability to check
	 * @return true if granted
	 */
	public boolean hasCapability(Capability capability) {
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
	 * Checks if this profile is more permissive than another profile.
	 *
	 * @param other the profile to compare
	 * @return true if this profile includes all capabilities of the other
	 */
	public boolean implies(PermissionProfile other) {
		if (this == ADMIN) {
			return true;
		}
		for (Capability cap : other.capabilities) {
			if (!hasCapability(cap)) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Looks up a profile by name.
	 *
	 * @param name the profile name (case-insensitive)
	 * @return the profile, or null if not found
	 */
	public static PermissionProfile fromName(String name) {
		return BY_NAME.get(name.toLowerCase());
	}

	/**
	 * Returns the default profile for agent operations.
	 * @return the annotator profile
	 */
	public static PermissionProfile defaultAgentProfile() {
		return ANNOTATOR;
	}

	@Override
	public String toString() {
		return name;
	}
}
