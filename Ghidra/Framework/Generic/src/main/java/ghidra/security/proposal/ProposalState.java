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

import java.util.EnumSet;
import java.util.Set;

/**
 * Lifecycle states for annotation change proposals.
 * Proposals progress through a defined state machine:
 *
 * <pre>
 * DRAFT → OPEN → UNDER_REVIEW → APPROVED → MERGED
 *                             ↘ REJECTED
 *                             ↘ WITHDRAWN
 * </pre>
 *
 * <p>Only APPROVED proposals can enter the apply/merge workflow.
 * This ensures all analysis changes undergo review before becoming canonical.
 *
 * <p>State machine based on type-lifecycle-ux.md section 1.2.
 */
public enum ProposalState {

	/**
	 * Initial draft state. Changes are being accumulated but not yet submitted.
	 * The author can still modify the proposal contents.
	 */
	DRAFT("draft"),

	/**
	 * Submitted for review. The proposal is visible to reviewers but not yet assigned.
	 * Transitions from DRAFT when author submits.
	 */
	OPEN("open"),

	/**
	 * Actively being reviewed. One or more reviewers are assigned.
	 * Transitions from OPEN when reviewers are assigned.
	 */
	UNDER_REVIEW("under_review"),

	/**
	 * All required approvals received. The proposal can now enter the apply workflow.
	 * Transitions from UNDER_REVIEW when approval threshold is met.
	 */
	APPROVED("approved"),

	/**
	 * At least one reviewer rejected the proposal.
	 * The proposal can be revised (returning to DRAFT) or abandoned.
	 */
	REJECTED("rejected"),

	/**
	 * The approved changes have been applied to the canonical program.
	 * This is a terminal state.
	 */
	MERGED("merged"),

	/**
	 * The author withdrew the proposal before completion.
	 * This is a terminal state.
	 */
	WITHDRAWN("withdrawn");

	private final String identifier;

	ProposalState(String identifier) {
		this.identifier = identifier;
	}

	/**
	 * Returns the string identifier for this state.
	 * @return the state identifier
	 */
	public String getIdentifier() {
		return identifier;
	}

	/**
	 * Parses a proposal state from its identifier.
	 * @param identifier the identifier to parse
	 * @return the corresponding ProposalState, or null if not found
	 */
	public static ProposalState fromIdentifier(String identifier) {
		if (identifier == null) {
			return null;
		}
		for (ProposalState state : values()) {
			if (state.identifier.equalsIgnoreCase(identifier)) {
				return state;
			}
		}
		return null;
	}

	/**
	 * Returns whether this state is a terminal state (no further transitions possible).
	 * @return true if terminal
	 */
	public boolean isTerminal() {
		return this == MERGED || this == WITHDRAWN;
	}

	/**
	 * Returns whether this state allows the proposal to be modified.
	 * @return true if modifications are allowed
	 */
	public boolean isEditable() {
		return this == DRAFT || this == REJECTED;
	}

	/**
	 * Returns whether this state allows the proposal to enter the apply workflow.
	 * Only APPROVED proposals can be merged.
	 * @return true if apply is allowed
	 */
	public boolean canApply() {
		return this == APPROVED;
	}

	/**
	 * Returns whether this proposal is in an active review state.
	 * @return true if actively being reviewed
	 */
	public boolean isInReview() {
		return this == OPEN || this == UNDER_REVIEW;
	}

	/**
	 * Returns whether this proposal has completed the review process (either way).
	 * @return true if review is complete
	 */
	public boolean isReviewComplete() {
		return this == APPROVED || this == REJECTED || this == MERGED;
	}

	/**
	 * Returns the set of valid next states from this state.
	 * @return set of valid transition targets
	 */
	public Set<ProposalState> validTransitions() {
		switch (this) {
			case DRAFT:
				return EnumSet.of(OPEN, WITHDRAWN);
			case OPEN:
				return EnumSet.of(UNDER_REVIEW, WITHDRAWN);
			case UNDER_REVIEW:
				return EnumSet.of(APPROVED, REJECTED, WITHDRAWN);
			case APPROVED:
				return EnumSet.of(MERGED);
			case REJECTED:
				return EnumSet.of(DRAFT, WITHDRAWN);  // Can revise and resubmit
			case MERGED:
			case WITHDRAWN:
				return EnumSet.noneOf(ProposalState.class);  // Terminal states
			default:
				return EnumSet.noneOf(ProposalState.class);
		}
	}

	/**
	 * Checks if transitioning to the target state is valid from this state.
	 * @param target the target state
	 * @return true if the transition is valid
	 */
	public boolean canTransitionTo(ProposalState target) {
		return validTransitions().contains(target);
	}

	@Override
	public String toString() {
		return identifier;
	}
}
