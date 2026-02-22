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

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * Service for orchestrating multi-step analysis missions.
 *
 * <p>A mission represents a coordinated analysis workflow that may involve:
 * <ul>
 *   <li>Multiple analysis passes over the same or different scopes</li>
 *   <li>Iterative refinement based on intermediate results</li>
 *   <li>Coordination between query, evidence, and proposal services</li>
 *   <li>Progress tracking and cancellation support</li>
 * </ul>
 *
 * <p>Missions provide a higher-level abstraction than individual service calls,
 * enabling complex analysis workflows to be defined, executed, and monitored.
 *
 * @since 1.0
 * @see QueryService
 * @see EvidenceService
 * @see ProposalIntegrationService
 */
public interface MissionService {

	/**
	 * Returns the API version of this service implementation.
	 *
	 * @return the service version
	 */
	default ServiceVersion getVersion() {
		return ServiceVersion.CURRENT;
	}

	/**
	 * Creates a new mission.
	 *
	 * @param spec the mission specification
	 * @return the created mission in PENDING state
	 * @throws MissionException if creation fails
	 */
	Mission create(MissionSpec spec) throws MissionException;

	/**
	 * Starts a pending mission.
	 *
	 * @param missionId the mission ID
	 * @param monitor task monitor for cancellation and progress
	 * @return the updated mission in RUNNING state
	 * @throws MissionException if the mission cannot be started
	 */
	Mission start(String missionId, TaskMonitor monitor) throws MissionException;

	/**
	 * Pauses a running mission.
	 *
	 * @param missionId the mission ID
	 * @return the updated mission in PAUSED state
	 * @throws MissionException if the mission cannot be paused
	 */
	Mission pause(String missionId) throws MissionException;

	/**
	 * Resumes a paused mission.
	 *
	 * @param missionId the mission ID
	 * @param monitor task monitor for cancellation and progress
	 * @return the updated mission in RUNNING state
	 * @throws MissionException if the mission cannot be resumed
	 */
	Mission resume(String missionId, TaskMonitor monitor) throws MissionException;

	/**
	 * Cancels a mission.
	 *
	 * @param missionId the mission ID
	 * @return the updated mission in CANCELLED state
	 * @throws MissionException if the mission cannot be cancelled
	 */
	Mission cancel(String missionId) throws MissionException;

	/**
	 * Gets a mission by ID.
	 *
	 * @param missionId the mission ID
	 * @return the mission if found
	 */
	Optional<Mission> get(String missionId);

	/**
	 * Lists missions for a program with optional state filter.
	 *
	 * @param program the program
	 * @param state optional state filter
	 * @return list of matching missions
	 */
	List<Mission> list(Program program, MissionState state);

	/**
	 * Gets the current progress of a mission.
	 *
	 * @param missionId the mission ID
	 * @return the mission progress
	 * @throws MissionException if the mission is not found
	 */
	MissionProgress getProgress(String missionId) throws MissionException;

	/**
	 * Specification for creating a mission.
	 */
	interface MissionSpec {

		/**
		 * Returns the mission type.
		 * @return the type
		 */
		MissionType getType();

		/**
		 * Returns the target program.
		 * @return the program
		 */
		Program getProgram();

		/**
		 * Returns the analysis scope.
		 * @return optional scope (null for entire program)
		 */
		AddressSetView getScope();

		/**
		 * Returns mission parameters.
		 * @return parameter map
		 */
		Map<String, Object> getParameters();

		/**
		 * Returns the optional timeout.
		 * @return optional timeout duration
		 */
		Optional<Duration> getTimeout();

		/**
		 * Returns whether to create proposals automatically.
		 * @return true if auto-proposal is enabled
		 */
		boolean isAutoProposal();
	}

	/**
	 * Builder for creating mission specifications.
	 */
	interface MissionSpecBuilder {

		/**
		 * Sets the mission type.
		 * @param type the type
		 * @return this builder
		 */
		MissionSpecBuilder type(MissionType type);

		/**
		 * Sets the target program.
		 * @param program the program
		 * @return this builder
		 */
		MissionSpecBuilder program(Program program);

		/**
		 * Sets the analysis scope.
		 * @param scope the scope
		 * @return this builder
		 */
		MissionSpecBuilder scope(AddressSetView scope);

		/**
		 * Sets a mission parameter.
		 * @param key the parameter key
		 * @param value the parameter value
		 * @return this builder
		 */
		MissionSpecBuilder parameter(String key, Object value);

		/**
		 * Sets the timeout.
		 * @param timeout the timeout duration
		 * @return this builder
		 */
		MissionSpecBuilder timeout(Duration timeout);

		/**
		 * Enables automatic proposal creation.
		 * @param enabled whether to enable
		 * @return this builder
		 */
		MissionSpecBuilder autoProposal(boolean enabled);

		/**
		 * Builds the mission specification.
		 * @return the specification
		 */
		MissionSpec build();
	}

	/**
	 * Creates a new mission spec builder.
	 *
	 * @return a new builder instance
	 */
	MissionSpecBuilder specBuilder();

	/**
	 * Represents a mission instance.
	 */
	interface Mission {

		/**
		 * Returns the mission ID.
		 * @return the mission ID
		 */
		String getId();

		/**
		 * Returns the mission type.
		 * @return the type
		 */
		MissionType getType();

		/**
		 * Returns the current state.
		 * @return the state
		 */
		MissionState getState();

		/**
		 * Returns the specification this mission was created from.
		 * @return the specification
		 */
		MissionSpec getSpec();

		/**
		 * Returns the creation timestamp.
		 * @return the creation time
		 */
		Instant getCreatedAt();

		/**
		 * Returns the start timestamp.
		 * @return optional start time
		 */
		Optional<Instant> getStartedAt();

		/**
		 * Returns the completion timestamp.
		 * @return optional completion time
		 */
		Optional<Instant> getCompletedAt();

		/**
		 * Returns evidence IDs produced by this mission.
		 * @return list of evidence IDs
		 */
		List<String> getEvidenceIds();

		/**
		 * Returns proposal IDs created by this mission.
		 * @return list of proposal IDs
		 */
		List<String> getProposalIds();

		/**
		 * Returns error message if the mission failed.
		 * @return optional error message
		 */
		Optional<String> getErrorMessage();
	}

	/**
	 * Represents mission execution progress.
	 */
	interface MissionProgress {

		/**
		 * Returns the current phase name.
		 * @return the phase name
		 */
		String getCurrentPhase();

		/**
		 * Returns the progress percentage (0-100).
		 * @return the progress percentage
		 */
		int getPercentComplete();

		/**
		 * Returns the number of items processed.
		 * @return processed count
		 */
		long getProcessedCount();

		/**
		 * Returns the total number of items to process.
		 * @return total count (0 if unknown)
		 */
		long getTotalCount();

		/**
		 * Returns the elapsed time.
		 * @return elapsed duration
		 */
		Duration getElapsed();

		/**
		 * Returns estimated time remaining.
		 * @return optional estimated remaining time
		 */
		Optional<Duration> getEstimatedRemaining();
	}

	/**
	 * Types of missions that can be executed.
	 */
	enum MissionType {

		/** Full analysis of a scope with all available capabilities */
		FULL_ANALYSIS,

		/** Focused type recovery mission */
		TYPE_RECOVERY,

		/** Function identification and naming mission */
		FUNCTION_ID,

		/** Vulnerability pattern search mission */
		VULN_SEARCH,

		/** Similarity search across corpus */
		SIMILARITY_SEARCH,

		/** Interactive refinement based on user feedback */
		ITERATIVE_REFINEMENT,

		/** Custom mission type defined by parameters */
		CUSTOM
	}

	/**
	 * Mission lifecycle states.
	 */
	enum MissionState {

		/** Mission created but not started */
		PENDING,

		/** Mission is currently executing */
		RUNNING,

		/** Mission is paused */
		PAUSED,

		/** Mission completed successfully */
		COMPLETED,

		/** Mission failed with an error */
		FAILED,

		/** Mission was cancelled */
		CANCELLED
	}

	/**
	 * Exception thrown when mission operations fail.
	 */
	class MissionException extends Exception {
		public MissionException(String message) {
			super(message);
		}

		public MissionException(String message, Throwable cause) {
			super(message, cause);
		}
	}
}
