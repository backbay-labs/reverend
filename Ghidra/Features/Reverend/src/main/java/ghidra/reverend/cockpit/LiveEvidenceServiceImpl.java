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
package ghidra.reverend.cockpit;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.reverend.api.v1.EvidenceService;

/**
 * Live in-memory evidence service used by cockpit runtime wiring.
 */
public class LiveEvidenceServiceImpl implements EvidenceService, AutoCloseable {

	private static final String DEFAULT_SOURCE = "reverend.cockpit.live";
	private static final String DEFAULT_SOURCE_VERSION = "1.0";

	private final Map<String, Evidence> evidenceById = new ConcurrentHashMap<>();
	private final Map<String, Set<String>> proposalLinks = new ConcurrentHashMap<>();
	private final Set<String> seededPrograms = ConcurrentHashMap.newKeySet();

	/**
	 * Seeds baseline evidence for an activated program.
	 *
	 * @param program activated program
	 */
	public void bindToProgram(Program program) {
		if (program == null) {
			return;
		}

		String programId = programId(program);
		if (!seededPrograms.add(programId)) {
			return;
		}
		seedProgramEvidence(program, programId);
	}

	/**
	 * Clears evidence associated with a deactivated program.
	 *
	 * @param program deactivated program
	 */
	public void unbindFromProgram(Program program) {
		if (program == null) {
			return;
		}

		String programId = programId(program);
		seededPrograms.remove(programId);
		evidenceById.entrySet().removeIf(entry -> programId.equals(entry.getValue().getProgramId()));
	}

	@Override
	public Evidence record(Evidence evidence) throws EvidenceException {
		if (evidence == null) {
			throw new EvidenceException("evidence cannot be null");
		}

		String source = evidence.getSource();
		if (source == null || source.isBlank()) {
			throw new EvidenceException("evidence source cannot be blank");
		}
		if (evidence.getType() == null) {
			throw new EvidenceException("evidence type cannot be null");
		}

		Instant createdAt = evidence.getCreatedAt() != null ? evidence.getCreatedAt() : Instant.now();
		String id = isBlank(evidence.getId()) ? "ev-" + UUID.randomUUID() : evidence.getId();
		Evidence persisted = new ImmutableEvidence(
			id,
			evidence.getType(),
			source,
			evidence.getSourceVersion(),
			evidence.getProgramId(),
			safeAddresses(evidence.getAddresses()),
			safePayload(evidence.getPayload()),
			evidence.getConfidence(),
			createdAt,
			safePredecessors(evidence.getPredecessorIds()),
			evidence.getMissionId().orElse(null));
		evidenceById.put(id, persisted);
		return persisted;
	}

	@Override
	public Optional<Evidence> get(String evidenceId) {
		if (isBlank(evidenceId)) {
			return Optional.empty();
		}
		return Optional.ofNullable(evidenceById.get(evidenceId));
	}

	@Override
	public List<Evidence> query(Program program, EvidenceType type, String source, Instant since) {
		if (program == null) {
			return Collections.emptyList();
		}
		String expectedProgramId = programId(program);
		return evidenceById.values()
			.stream()
			.filter(evidence -> expectedProgramId.equals(evidence.getProgramId()))
			.filter(evidence -> type == null || evidence.getType() == type)
			.filter(evidence -> source == null || source.equals(evidence.getSource()))
			.filter(evidence -> since == null || !evidence.getCreatedAt().isBefore(since))
			.sorted(Comparator.comparing(Evidence::getCreatedAt))
			.collect(Collectors.toList());
	}

	@Override
	public List<Evidence> getForAddress(Program program, Address address) {
		if (program == null || address == null) {
			return Collections.emptyList();
		}

		String expectedProgramId = programId(program);
		return evidenceById.values()
			.stream()
			.filter(evidence -> expectedProgramId.equals(evidence.getProgramId()))
			.filter(evidence -> evidence.getAddresses().contains(address))
			.sorted(Comparator.comparing(Evidence::getCreatedAt))
			.collect(Collectors.toList());
	}

	@Override
	public void linkToProposal(String evidenceId, String proposalId) throws EvidenceException {
		if (isBlank(evidenceId)) {
			throw new EvidenceException("evidenceId cannot be blank");
		}
		if (isBlank(proposalId)) {
			throw new EvidenceException("proposalId cannot be blank");
		}
		if (!evidenceById.containsKey(evidenceId)) {
			throw new EvidenceException("Unknown evidenceId: " + evidenceId);
		}

		proposalLinks.computeIfAbsent(evidenceId, key -> ConcurrentHashMap.newKeySet()).add(proposalId);
	}

	@Override
	public List<Evidence> getDerivationChain(String evidenceId) {
		if (isBlank(evidenceId)) {
			return Collections.emptyList();
		}

		List<Evidence> chain = new ArrayList<>();
		Set<String> seen = new HashSet<>();
		Deque<String> pending = new ArrayDeque<>();
		pending.add(evidenceId);

		while (!pending.isEmpty()) {
			String currentId = pending.removeFirst();
			Evidence current = evidenceById.get(currentId);
			if (current == null) {
				continue;
			}
			for (String predecessorId : current.getPredecessorIds()) {
				if (seen.add(predecessorId)) {
					Evidence predecessor = evidenceById.get(predecessorId);
					if (predecessor != null) {
						chain.add(predecessor);
						pending.addLast(predecessorId);
					}
				}
			}
		}

		return chain;
	}

	@Override
	public EvidenceBuilder builder() {
		return new LiveEvidenceBuilder();
	}

	@Override
	public void close() {
		evidenceById.clear();
		proposalLinks.clear();
		seededPrograms.clear();
	}

	private void seedProgramEvidence(Program program, String programId) {
		int seededCount = 0;
		FunctionManager functionManager = program.getFunctionManager();
		if (functionManager != null) {
			FunctionIterator functions = functionManager.getFunctions(true);
			while (functions.hasNext()) {
				Function function = functions.next();
				Map<String, Object> payload = new LinkedHashMap<>();
				payload.put("kind", "function");
				payload.put("name", function.getName());
				payload.put("entryPoint", function.getEntryPoint().toString());
				Evidence evidence = builder()
					.type(EvidenceType.STATIC_ANALYSIS)
					.source(DEFAULT_SOURCE)
					.sourceVersion(DEFAULT_SOURCE_VERSION)
					.programId(programId)
					.addAddress(function.getEntryPoint())
					.payload(payload)
					.confidence(0.75d)
					.build();
				try {
					record(evidence);
					seededCount++;
				}
				catch (EvidenceException e) {
					// Ignore individual seed failures and continue.
				}
			}
		}

		if (seededCount == 0) {
			Map<String, Object> payload = new LinkedHashMap<>();
			payload.put("kind", "program");
			payload.put("name", program.getName());
			Evidence evidence = builder()
				.type(EvidenceType.STATIC_ANALYSIS)
				.source(DEFAULT_SOURCE)
				.sourceVersion(DEFAULT_SOURCE_VERSION)
				.programId(programId)
				.payload(payload)
				.confidence(0.5d)
				.build();
			try {
				record(evidence);
			}
			catch (EvidenceException e) {
				// Ignore fallback seed failures.
			}
		}
	}

	private static String programId(Program program) {
		String executablePath = program.getExecutablePath();
		if (!isBlank(executablePath)) {
			return executablePath;
		}
		String name = program.getName();
		if (!isBlank(name)) {
			return name;
		}
		return "program-" + System.identityHashCode(program);
	}

	private static boolean isBlank(String value) {
		return value == null || value.isBlank();
	}

	private static List<Address> safeAddresses(List<Address> addresses) {
		return addresses != null ? addresses : Collections.emptyList();
	}

	private static Map<String, Object> safePayload(Map<String, Object> payload) {
		return payload != null ? payload : Collections.emptyMap();
	}

	private static List<String> safePredecessors(List<String> predecessorIds) {
		return predecessorIds != null ? predecessorIds : Collections.emptyList();
	}

	private static class LiveEvidenceBuilder implements EvidenceBuilder {
		private EvidenceType type = EvidenceType.STATIC_ANALYSIS;
		private String source = DEFAULT_SOURCE;
		private String sourceVersion = DEFAULT_SOURCE_VERSION;
		private String programId = "";
		private final List<Address> addresses = new ArrayList<>();
		private Map<String, Object> payload = new LinkedHashMap<>();
		private double confidence = 0.0d;
		private final List<String> predecessorIds = new ArrayList<>();
		private String missionId;

		@Override
		public EvidenceBuilder type(EvidenceType evidenceType) {
			if (evidenceType != null) {
				this.type = evidenceType;
			}
			return this;
		}

		@Override
		public EvidenceBuilder source(String evidenceSource) {
			if (!isBlank(evidenceSource)) {
				this.source = evidenceSource;
			}
			return this;
		}

		@Override
		public EvidenceBuilder sourceVersion(String version) {
			this.sourceVersion = version != null ? version : "";
			return this;
		}

		@Override
		public EvidenceBuilder programId(String id) {
			this.programId = id != null ? id : "";
			return this;
		}

		@Override
		public EvidenceBuilder addAddress(Address address) {
			if (address != null) {
				addresses.add(address);
			}
			return this;
		}

		@Override
		public EvidenceBuilder payload(Map<String, Object> evidencePayload) {
			this.payload = evidencePayload != null
				? new LinkedHashMap<>(evidencePayload)
				: new LinkedHashMap<>();
			return this;
		}

		@Override
		public EvidenceBuilder confidence(double value) {
			confidence = Math.max(0.0d, Math.min(1.0d, value));
			return this;
		}

		@Override
		public EvidenceBuilder addPredecessor(String predecessorId) {
			if (!isBlank(predecessorId)) {
				predecessorIds.add(predecessorId);
			}
			return this;
		}

		@Override
		public EvidenceBuilder missionId(String id) {
			missionId = id;
			return this;
		}

		@Override
		public Evidence build() {
			return new ImmutableEvidence(
				null,
				type,
				source,
				sourceVersion,
				programId,
				addresses,
				payload,
				confidence,
				Instant.now(),
				predecessorIds,
				missionId);
		}
	}

	private static final class ImmutableEvidence implements Evidence {
		private final String id;
		private final EvidenceType type;
		private final String source;
		private final String sourceVersion;
		private final String programId;
		private final List<Address> addresses;
		private final Map<String, Object> payload;
		private final double confidence;
		private final Instant createdAt;
		private final List<String> predecessorIds;
		private final String missionId;

		ImmutableEvidence(String id, EvidenceType type, String source, String sourceVersion,
				String programId, List<Address> addresses, Map<String, Object> payload,
				double confidence, Instant createdAt, List<String> predecessorIds, String missionId) {
			this.id = id;
			this.type = type;
			this.source = source;
			this.sourceVersion = sourceVersion != null ? sourceVersion : "";
			this.programId = programId != null ? programId : "";
			this.addresses = Collections.unmodifiableList(new ArrayList<>(addresses));
			this.payload = Collections.unmodifiableMap(new LinkedHashMap<>(payload));
			this.confidence = confidence;
			this.createdAt = createdAt;
			this.predecessorIds = Collections.unmodifiableList(new ArrayList<>(predecessorIds));
			this.missionId = missionId;
		}

		@Override
		public String getId() {
			return id;
		}

		@Override
		public EvidenceType getType() {
			return type;
		}

		@Override
		public String getSource() {
			return source;
		}

		@Override
		public String getSourceVersion() {
			return sourceVersion;
		}

		@Override
		public String getProgramId() {
			return programId;
		}

		@Override
		public List<Address> getAddresses() {
			return addresses;
		}

		@Override
		public Map<String, Object> getPayload() {
			return payload;
		}

		@Override
		public double getConfidence() {
			return confidence;
		}

		@Override
		public Instant getCreatedAt() {
			return createdAt;
		}

		@Override
		public List<String> getPredecessorIds() {
			return predecessorIds;
		}

		@Override
		public Optional<String> getMissionId() {
			return Optional.ofNullable(missionId);
		}
	}
}
