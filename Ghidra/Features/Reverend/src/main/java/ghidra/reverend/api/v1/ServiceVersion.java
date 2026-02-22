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
package ghidra.reverend.api.v1;

import java.util.Objects;

/**
 * Represents a semantic version for Reverend service API contracts.
 *
 * <p>Versions follow semantic versioning (semver) with major.minor.patch format:
 * <ul>
 *   <li><b>Major</b>: Incremented for breaking API changes</li>
 *   <li><b>Minor</b>: Incremented for backward-compatible additions</li>
 *   <li><b>Patch</b>: Incremented for backward-compatible fixes</li>
 * </ul>
 *
 * @since 1.0
 */
public final class ServiceVersion implements Comparable<ServiceVersion> {

	/**
	 * Current API version for all Reverend v1 services.
	 */
	public static final ServiceVersion CURRENT = new ServiceVersion(1, 0, 0);

	private final int major;
	private final int minor;
	private final int patch;

	/**
	 * Creates a new service version.
	 *
	 * @param major the major version (breaking changes)
	 * @param minor the minor version (additive changes)
	 * @param patch the patch version (fixes)
	 * @throws IllegalArgumentException if any version component is negative
	 */
	public ServiceVersion(int major, int minor, int patch) {
		if (major < 0 || minor < 0 || patch < 0) {
			throw new IllegalArgumentException("Version components must be non-negative");
		}
		this.major = major;
		this.minor = minor;
		this.patch = patch;
	}

	/**
	 * Parses a version string in "major.minor.patch" format.
	 *
	 * @param version the version string to parse
	 * @return the parsed ServiceVersion
	 * @throws IllegalArgumentException if the format is invalid
	 */
	public static ServiceVersion parse(String version) {
		if (version == null || version.isEmpty()) {
			throw new IllegalArgumentException("Version string cannot be null or empty");
		}

		String[] parts = version.split("\\.");
		if (parts.length != 3) {
			throw new IllegalArgumentException(
				"Invalid version format: " + version + " (expected major.minor.patch)");
		}

		try {
			int major = Integer.parseInt(parts[0]);
			int minor = Integer.parseInt(parts[1]);
			int patch = Integer.parseInt(parts[2]);
			return new ServiceVersion(major, minor, patch);
		}
		catch (NumberFormatException e) {
			throw new IllegalArgumentException("Invalid version number in: " + version, e);
		}
	}

	/**
	 * Returns the major version component.
	 * @return the major version
	 */
	public int getMajor() {
		return major;
	}

	/**
	 * Returns the minor version component.
	 * @return the minor version
	 */
	public int getMinor() {
		return minor;
	}

	/**
	 * Returns the patch version component.
	 * @return the patch version
	 */
	public int getPatch() {
		return patch;
	}

	/**
	 * Checks if this version is compatible with another version.
	 * Versions are compatible if they have the same major version and
	 * this version's minor is greater than or equal to the other's.
	 *
	 * @param other the version to check compatibility with
	 * @return true if this version is compatible with the other version
	 */
	public boolean isCompatibleWith(ServiceVersion other) {
		if (other == null) {
			return false;
		}
		return this.major == other.major && this.minor >= other.minor;
	}

	@Override
	public int compareTo(ServiceVersion other) {
		int cmp = Integer.compare(this.major, other.major);
		if (cmp != 0) {
			return cmp;
		}
		cmp = Integer.compare(this.minor, other.minor);
		if (cmp != 0) {
			return cmp;
		}
		return Integer.compare(this.patch, other.patch);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof ServiceVersion)) {
			return false;
		}
		ServiceVersion other = (ServiceVersion) obj;
		return major == other.major && minor == other.minor && patch == other.patch;
	}

	@Override
	public int hashCode() {
		return Objects.hash(major, minor, patch);
	}

	@Override
	public String toString() {
		return major + "." + minor + "." + patch;
	}
}
