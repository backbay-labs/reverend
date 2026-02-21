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
package ghidra.security.audit;

/**
 * Severity levels for security audit events.
 * Used to categorize the importance and urgency of security events.
 */
public enum Severity {

	/**
	 * Informational events - normal operations, successful access grants.
	 * These are logged for audit trail completeness but don't require attention.
	 */
	INFO("INFO", 0),

	/**
	 * Warning events - denied access, policy violations that were blocked.
	 * These should be reviewed periodically for anomalies.
	 */
	WARNING("WARNING", 1),

	/**
	 * Critical events - sandbox escapes, integrity failures, data exfiltration attempts.
	 * These require immediate attention and potential incident response.
	 */
	CRITICAL("CRITICAL", 2);

	private final String label;
	private final int level;

	Severity(String label, int level) {
		this.label = label;
		this.level = level;
	}

	/**
	 * Returns the string label for this severity.
	 * @return the severity label
	 */
	public String getLabel() {
		return label;
	}

	/**
	 * Returns the numeric level for comparison purposes.
	 * Higher values indicate more severe events.
	 * @return the severity level
	 */
	public int getLevel() {
		return level;
	}

	/**
	 * Checks if this severity is at least as severe as the given severity.
	 * @param other the severity to compare against
	 * @return true if this severity is >= the other severity
	 */
	public boolean isAtLeast(Severity other) {
		return this.level >= other.level;
	}

	@Override
	public String toString() {
		return label;
	}
}
