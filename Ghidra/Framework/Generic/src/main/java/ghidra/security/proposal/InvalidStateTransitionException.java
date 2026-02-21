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
 * Exception thrown when an invalid state transition is attempted on a proposal.
 */
public class InvalidStateTransitionException extends Exception {

	private final String proposalId;
	private final ProposalState fromState;
	private final ProposalState toState;

	public InvalidStateTransitionException(String proposalId, ProposalState fromState,
			ProposalState toState) {
		super(String.format("Invalid transition for proposal %s: %s -> %s",
			proposalId, fromState, toState));
		this.proposalId = proposalId;
		this.fromState = fromState;
		this.toState = toState;
	}

	public InvalidStateTransitionException(String message) {
		super(message);
		this.proposalId = null;
		this.fromState = null;
		this.toState = null;
	}

	public String getProposalId() {
		return proposalId;
	}

	public ProposalState getFromState() {
		return fromState;
	}

	public ProposalState getToState() {
		return toState;
	}
}
