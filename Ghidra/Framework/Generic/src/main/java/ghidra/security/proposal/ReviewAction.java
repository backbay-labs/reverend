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
package ghidra.security.proposal;

/**
 * Actions a reviewer can take on a proposal.
 */
public enum ReviewAction {

	/**
	 * Approve the proposal. Counts toward the approval threshold.
	 */
	APPROVE("approve"),

	/**
	 * Reject the proposal. Transitions it to REJECTED state.
	 */
	REJECT("reject"),

	/**
	 * Request changes without approving or rejecting.
	 * The proposal remains in its current review state.
	 */
	REQUEST_CHANGES("request_changes");

	private final String identifier;

	ReviewAction(String identifier) {
		this.identifier = identifier;
	}

	public String getIdentifier() {
		return identifier;
	}

	public static ReviewAction fromIdentifier(String identifier) {
		if (identifier == null) {
			return null;
		}
		for (ReviewAction action : values()) {
			if (action.identifier.equalsIgnoreCase(identifier)) {
				return action;
			}
		}
		return null;
	}

	@Override
	public String toString() {
		return identifier;
	}
}
