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

import java.util.List;
import java.util.Optional;
import java.util.Set;

import ghidra.program.model.listing.Program;
import ghidra.security.capability.Capability;
import ghidra.security.capability.CapabilityToken;
import ghidra.security.policy.EgressPolicy;
import ghidra.security.policy.PolicyMode;

/**
 * Service for policy-aware action execution with capability and egress controls.
 *
 * <p>The PolicyService enforces security policies for all Reverend operations:
 * <ul>
 *   <li>Capability-based access control for sensitive operations</li>
 *   <li>Egress policy enforcement for network operations</li>
 *   <li>Action audit logging and compliance tracking</li>
 *   <li>Policy validation before action execution</li>
 * </ul>
 *
 * <p>All service operations that may involve external resources or sensitive
 * data must check policy compliance through this service.
 *
 * @since 1.0
 * @see ghidra.security.policy.PolicyMode
 * @see ghidra.security.policy.EgressPolicy
 * @see ghidra.security.capability.Capability
 */
public interface PolicyService {

	/**
	 * Returns the API version of this service implementation.
	 *
	 * @return the service version
	 */
	default ServiceVersion getVersion() {
		return ServiceVersion.CURRENT;
	}

	/**
	 * Gets the current policy mode for a program.
	 *
	 * @param program the program
	 * @return the policy mode
	 */
	PolicyMode getPolicyMode(Program program);

	/**
	 * Sets the policy mode for a program.
	 *
	 * @param program the program
	 * @param mode the policy mode to set
	 * @throws PolicyException if the mode cannot be changed
	 */
	void setPolicyMode(Program program, PolicyMode mode) throws PolicyException;

	/**
	 * Gets the egress policy for a program.
	 *
	 * @param program the program
	 * @return the egress policy
	 */
	EgressPolicy getEgressPolicy(Program program);

	/**
	 * Checks if an action is permitted under current policy.
	 *
	 * @param program the program context
	 * @param action the action to check
	 * @return check result with details
	 */
	PolicyCheckResult checkAction(Program program, PolicyAction action);

	/**
	 * Requests a capability token for a set of capabilities.
	 *
	 * <p>Capability tokens are short-lived and should be used immediately
	 * for the intended operation.
	 *
	 * @param program the program context
	 * @param capabilities the required capabilities
	 * @param reason the reason for requesting capabilities
	 * @return the capability token if granted
	 * @throws PolicyException if capabilities cannot be granted
	 */
	CapabilityToken requestCapabilities(Program program, Set<Capability> capabilities,
			String reason) throws PolicyException;

	/**
	 * Executes an action with policy enforcement.
	 *
	 * <p>This method:
	 * <ol>
	 *   <li>Validates the action against current policy</li>
	 *   <li>Acquires necessary capability tokens</li>
	 *   <li>Executes the action</li>
	 *   <li>Logs the action for audit</li>
	 * </ol>
	 *
	 * @param <T> the result type
	 * @param program the program context
	 * @param action the action to execute
	 * @return the execution result
	 * @throws PolicyException if policy prevents execution
	 */
	<T> PolicyExecutionResult<T> executeWithPolicy(Program program,
			PolicyAction action) throws PolicyException;

	/**
	 * Gets the audit log for recent policy-controlled actions.
	 *
	 * @param program the program
	 * @param limit maximum number of entries to return
	 * @return list of audit entries
	 */
	List<PolicyAuditEntry> getAuditLog(Program program, int limit);

	/**
	 * Validates a proposed action without executing it.
	 *
	 * @param program the program context
	 * @param action the action to validate
	 * @return validation result with any issues
	 */
	PolicyValidationResult validate(Program program, PolicyAction action);

	/**
	 * Gets the current confidence threshold for automatic actions.
	 *
	 * <p>Actions with confidence below this threshold require explicit approval.
	 *
	 * @param program the program
	 * @return the confidence threshold (0.0 to 1.0)
	 */
	double getConfidenceThreshold(Program program);

	/**
	 * Sets the confidence threshold for automatic actions.
	 *
	 * @param program the program
	 * @param threshold the threshold (0.0 to 1.0)
	 * @throws PolicyException if the threshold is invalid
	 */
	void setConfidenceThreshold(Program program, double threshold) throws PolicyException;

	/**
	 * Represents an action that requires policy enforcement.
	 */
	interface PolicyAction {

		/**
		 * Returns the action type.
		 * @return the type
		 */
		ActionType getType();

		/**
		 * Returns the action description.
		 * @return the description
		 */
		String getDescription();

		/**
		 * Returns required capabilities for this action.
		 * @return set of required capabilities
		 */
		Set<Capability> getRequiredCapabilities();

		/**
		 * Returns whether this action involves network egress.
		 * @return true if network egress is required
		 */
		boolean requiresNetworkEgress();

		/**
		 * Returns the target endpoint for network actions.
		 * @return optional endpoint identifier
		 */
		Optional<String> getTargetEndpoint();

		/**
		 * Returns the confidence score for this action.
		 * @return the confidence (0.0 to 1.0)
		 */
		double getConfidence();
	}

	/**
	 * Result of a policy check.
	 */
	interface PolicyCheckResult {

		/**
		 * Returns whether the action is permitted.
		 * @return true if permitted
		 */
		boolean isPermitted();

		/**
		 * Returns the reason if not permitted.
		 * @return optional denial reason
		 */
		Optional<String> getDenialReason();

		/**
		 * Returns required capabilities that are missing.
		 * @return set of missing capabilities
		 */
		Set<Capability> getMissingCapabilities();

		/**
		 * Returns whether approval is required.
		 * @return true if explicit approval is needed
		 */
		boolean requiresApproval();
	}

	/**
	 * Result of executing an action with policy enforcement.
	 *
	 * @param <T> the result type
	 */
	interface PolicyExecutionResult<T> {

		/**
		 * Returns whether execution succeeded.
		 * @return true if successful
		 */
		boolean isSuccess();

		/**
		 * Returns the execution result.
		 * @return optional result value
		 */
		Optional<T> getResult();

		/**
		 * Returns the audit entry for this execution.
		 * @return the audit entry
		 */
		PolicyAuditEntry getAuditEntry();

		/**
		 * Returns error message if execution failed.
		 * @return optional error message
		 */
		Optional<String> getErrorMessage();
	}

	/**
	 * Result of validating an action.
	 */
	interface PolicyValidationResult {

		/**
		 * Returns whether the action is valid.
		 * @return true if valid
		 */
		boolean isValid();

		/**
		 * Returns validation issues.
		 * @return list of issues
		 */
		List<String> getIssues();

		/**
		 * Returns warnings (action may proceed).
		 * @return list of warnings
		 */
		List<String> getWarnings();
	}

	/**
	 * An entry in the policy audit log.
	 */
	interface PolicyAuditEntry {

		/**
		 * Returns the entry ID.
		 * @return the ID
		 */
		String getId();

		/**
		 * Returns the timestamp.
		 * @return the timestamp in epoch milliseconds
		 */
		long getTimestamp();

		/**
		 * Returns the action type.
		 * @return the action type
		 */
		ActionType getActionType();

		/**
		 * Returns the action description.
		 * @return the description
		 */
		String getDescription();

		/**
		 * Returns whether the action was permitted.
		 * @return true if permitted
		 */
		boolean wasPermitted();

		/**
		 * Returns the user or agent that initiated the action.
		 * @return the initiator identifier
		 */
		String getInitiator();
	}

	/**
	 * Types of policy-controlled actions.
	 */
	enum ActionType {

		/** Query against local data */
		LOCAL_QUERY,

		/** Query involving model inference */
		MODEL_QUERY,

		/** Network egress to external API */
		NETWORK_EGRESS,

		/** Program modification */
		PROGRAM_MODIFY,

		/** Proposal creation */
		PROPOSAL_CREATE,

		/** Proposal application */
		PROPOSAL_APPLY,

		/** Evidence recording */
		EVIDENCE_RECORD,

		/** Mission execution */
		MISSION_EXECUTE,

		/** Configuration change */
		CONFIG_CHANGE
	}

	/**
	 * Exception thrown when policy operations fail.
	 */
	class PolicyException extends Exception {
		public PolicyException(String message) {
			super(message);
		}

		public PolicyException(String message, Throwable cause) {
			super(message, cause);
		}
	}
}
