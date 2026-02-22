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

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

/**
 * Service for evidence collection, retrieval, and linking for analysis provenance.
 *
 * <p>The EvidenceService provides a persistent evidence store that tracks:
 * <ul>
 *   <li>Analysis artifacts and their derivation chains</li>
 *   <li>Model inference results with input/output linkage</li>
 *   <li>Static and dynamic evidence from multiple sources</li>
 *   <li>Confidence scores and uncertainty information</li>
 * </ul>
 *
 * <p>All evidence records are immutable once created. Updates create new
 * records with links to predecessors.
 *
 * @since 1.0
 * @see MissionService
 */
public interface EvidenceService {

	/**
	 * Returns the API version of this service implementation.
	 *
	 * @return the service version
	 */
	default ServiceVersion getVersion() {
		return ServiceVersion.CURRENT;
	}

	/**
	 * Records a new evidence entry.
	 *
	 * @param evidence the evidence to record
	 * @return the persisted evidence with assigned ID
	 * @throws EvidenceException if recording fails
	 */
	Evidence record(Evidence evidence) throws EvidenceException;

	/**
	 * Retrieves evidence by ID.
	 *
	 * @param evidenceId the evidence ID
	 * @return the evidence if found
	 */
	Optional<Evidence> get(String evidenceId);

	/**
	 * Queries evidence by program and optional filters.
	 *
	 * @param program the program to query evidence for
	 * @param type optional evidence type filter
	 * @param source optional source filter
	 * @param since optional timestamp filter (evidence created after this time)
	 * @return list of matching evidence records
	 */
	List<Evidence> query(Program program, EvidenceType type, String source, Instant since);

	/**
	 * Retrieves evidence linked to a specific address.
	 *
	 * @param program the program containing the address
	 * @param address the address to query
	 * @return list of evidence records linked to this address
	 */
	List<Evidence> getForAddress(Program program, Address address);

	/**
	 * Links evidence to a proposal for provenance tracking.
	 *
	 * @param evidenceId the evidence ID
	 * @param proposalId the proposal ID
	 * @throws EvidenceException if linking fails
	 */
	void linkToProposal(String evidenceId, String proposalId) throws EvidenceException;

	/**
	 * Gets the derivation chain for an evidence record.
	 *
	 * @param evidenceId the evidence ID
	 * @return list of predecessor evidence records in derivation order
	 */
	List<Evidence> getDerivationChain(String evidenceId);

	/**
	 * Represents a single evidence record.
	 */
	interface Evidence {

		/**
		 * Returns the unique evidence ID.
		 * @return the evidence ID (null if not yet persisted)
		 */
		String getId();

		/**
		 * Returns the evidence type.
		 * @return the type
		 */
		EvidenceType getType();

		/**
		 * Returns the source identifier (e.g., model name, analyzer name).
		 * @return the source
		 */
		String getSource();

		/**
		 * Returns the source version.
		 * @return the version string
		 */
		String getSourceVersion();

		/**
		 * Returns the program ID this evidence relates to.
		 * @return the program ID
		 */
		String getProgramId();

		/**
		 * Returns addresses this evidence relates to.
		 * @return list of related addresses
		 */
		List<Address> getAddresses();

		/**
		 * Returns the evidence payload.
		 * @return payload map
		 */
		Map<String, Object> getPayload();

		/**
		 * Returns the confidence score (0.0 to 1.0).
		 * @return the confidence
		 */
		double getConfidence();

		/**
		 * Returns the creation timestamp.
		 * @return the creation time
		 */
		Instant getCreatedAt();

		/**
		 * Returns IDs of predecessor evidence records.
		 * @return list of predecessor IDs
		 */
		List<String> getPredecessorIds();

		/**
		 * Returns the mission ID if this evidence is part of a mission.
		 * @return optional mission ID
		 */
		Optional<String> getMissionId();
	}

	/**
	 * Builder for creating evidence records.
	 */
	interface EvidenceBuilder {

		/**
		 * Sets the evidence type.
		 * @param type the type
		 * @return this builder
		 */
		EvidenceBuilder type(EvidenceType type);

		/**
		 * Sets the source identifier.
		 * @param source the source
		 * @return this builder
		 */
		EvidenceBuilder source(String source);

		/**
		 * Sets the source version.
		 * @param version the version
		 * @return this builder
		 */
		EvidenceBuilder sourceVersion(String version);

		/**
		 * Sets the program ID.
		 * @param programId the program ID
		 * @return this builder
		 */
		EvidenceBuilder programId(String programId);

		/**
		 * Adds an address this evidence relates to.
		 * @param address the address
		 * @return this builder
		 */
		EvidenceBuilder addAddress(Address address);

		/**
		 * Sets the evidence payload.
		 * @param payload the payload map
		 * @return this builder
		 */
		EvidenceBuilder payload(Map<String, Object> payload);

		/**
		 * Sets the confidence score.
		 * @param confidence the confidence (0.0 to 1.0)
		 * @return this builder
		 */
		EvidenceBuilder confidence(double confidence);

		/**
		 * Adds a predecessor evidence ID.
		 * @param predecessorId the predecessor ID
		 * @return this builder
		 */
		EvidenceBuilder addPredecessor(String predecessorId);

		/**
		 * Sets the mission ID.
		 * @param missionId the mission ID
		 * @return this builder
		 */
		EvidenceBuilder missionId(String missionId);

		/**
		 * Builds the evidence record.
		 * @return the evidence
		 */
		Evidence build();
	}

	/**
	 * Creates a new evidence builder.
	 *
	 * @return a new builder instance
	 */
	EvidenceBuilder builder();

	/**
	 * Types of evidence that can be recorded.
	 */
	enum EvidenceType {

		/** Static analysis result (e.g., data flow, control flow) */
		STATIC_ANALYSIS,

		/** Dynamic trace or execution evidence */
		DYNAMIC_TRACE,

		/** Model inference result */
		MODEL_INFERENCE,

		/** Symbolic execution result */
		SYMBOLIC,

		/** Taint analysis result */
		TAINT,

		/** Coverage data */
		COVERAGE,

		/** Similarity or matching result */
		SIMILARITY,

		/** User annotation or correction */
		USER_ANNOTATION,

		/** Aggregated or derived evidence */
		AGGREGATED
	}

	/**
	 * Exception thrown when evidence operations fail.
	 */
	class EvidenceException extends Exception {
		public EvidenceException(String message) {
			super(message);
		}

		public EvidenceException(String message, Throwable cause) {
			super(message, cause);
		}
	}
}
