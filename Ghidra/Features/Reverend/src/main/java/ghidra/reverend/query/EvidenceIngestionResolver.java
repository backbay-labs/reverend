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
package ghidra.reverend.query;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import ghidra.reverend.api.v1.EvidenceService;
import ghidra.reverend.api.v1.EvidenceService.Evidence;
import ghidra.reverend.api.v1.EvidenceService.EvidenceException;
import ghidra.reverend.api.v1.EvidenceService.EvidenceType;

/**
 * Ingestion adapters and deterministic canonical entity resolution for evidence sources.
 *
 * <p>This resolver accepts source-specific evidence payloads, maps extracted entities
 * to canonical graph identities, persists evidence, and emits reconciliation details
 * for unresolved entities.
 */
public class EvidenceIngestionResolver {

	private final CanonicalEntityResolver entityResolver;
	private final List<IngestionAdapter> adapters;

	public EvidenceIngestionResolver() {
		this(new CanonicalEntityResolver(), List.of(
			new StaticAnalysisAdapter(),
			new TraceAdapter(),
			new ProposalReceiptAdapter()));
	}

	EvidenceIngestionResolver(CanonicalEntityResolver entityResolver, List<IngestionAdapter> adapters) {
		this.entityResolver = Objects.requireNonNull(entityResolver, "entityResolver");
		this.adapters = List.copyOf(Objects.requireNonNull(adapters, "adapters"));
	}

	/**
	 * Ingests an evidence record using the matching adapter and resolves canonical entities.
	 *
	 * @param evidenceService evidence persistence service
	 * @param input source evidence input
	 * @return ingestion outcome with persisted evidence and reconciliation report
	 * @throws EvidenceException when persistence fails
	 */
	public IngestionOutcome ingest(EvidenceService evidenceService, IncomingEvidence input)
			throws EvidenceException {
		Objects.requireNonNull(evidenceService, "evidenceService");
		Objects.requireNonNull(input, "input");

		IngestionAdapter adapter = resolveAdapter(input.getSourceType());
		if (adapter == null) {
			ReconciliationReport unsupportedReport = ReconciliationReport.unsupportedSource(
				input.getSourceType());
			Map<String, Object> payload = new LinkedHashMap<>(input.getPayload());
			payload.put("canonical_entities", List.of());
			payload.put("reconciliation_report", unsupportedReport.toMap());
			Evidence persisted = evidenceService.record(
				evidenceService.builder()
					.type(EvidenceType.AGGREGATED)
					.source(input.getSource())
					.sourceVersion(input.getSourceVersion())
					.programId(input.getProgramId())
					.payload(payload)
					.confidence(input.getConfidence())
					.build());
			return new IngestionOutcome(persisted, unsupportedReport);
		}

		AdaptedEvidence adapted = adapter.adapt(input);
		List<Map<String, Object>> canonicalEntities = new ArrayList<>();
		ReconciliationReport report = new ReconciliationReport();
		for (EntityCandidate candidate : adapted.getEntityCandidates()) {
			Resolution resolution = entityResolver.resolve(candidate);
			report.record(resolution);
			canonicalEntities.add(resolution.toMap());
		}

		Map<String, Object> payload = new LinkedHashMap<>(input.getPayload());
		payload.put("canonical_entities", Collections.unmodifiableList(canonicalEntities));
		payload.put("reconciliation_report", report.toMap());

		EvidenceService.EvidenceBuilder builder = evidenceService.builder()
			.type(adapted.getEvidenceType())
			.source(input.getSource())
			.sourceVersion(input.getSourceVersion())
			.programId(input.getProgramId())
			.payload(payload)
			.confidence(input.getConfidence());
		for (String predecessorId : input.getPredecessorIds()) {
			builder.addPredecessor(predecessorId);
		}
		input.getMissionId().ifPresent(builder::missionId);
		Evidence persisted = evidenceService.record(builder.build());
		return new IngestionOutcome(persisted, report);
	}

	private IngestionAdapter resolveAdapter(String sourceType) {
		for (IngestionAdapter adapter : adapters) {
			if (adapter.supports(sourceType)) {
				return adapter;
			}
		}
		return null;
	}

	public static final class IncomingEvidence {
		private final String sourceType;
		private final String source;
		private final String sourceVersion;
		private final String programId;
		private final Map<String, Object> payload;
		private final double confidence;
		private final List<String> predecessorIds;
		private final String missionId;

		public IncomingEvidence(String sourceType, String source, String sourceVersion,
				String programId, Map<String, Object> payload, double confidence,
				List<String> predecessorIds, String missionId) {
			this.sourceType = normalize(sourceType);
			this.source = normalize(source);
			this.sourceVersion = sourceVersion != null ? sourceVersion : "";
			this.programId = programId != null ? programId : "";
			this.payload = payload != null ? new LinkedHashMap<>(payload) : new LinkedHashMap<>();
			this.confidence = clamp(confidence);
			this.predecessorIds = predecessorIds != null
				? Collections.unmodifiableList(new ArrayList<>(predecessorIds))
				: List.of();
			this.missionId = missionId;
		}

		public String getSourceType() {
			return sourceType;
		}

		public String getSource() {
			return source;
		}

		public String getSourceVersion() {
			return sourceVersion;
		}

		public String getProgramId() {
			return programId;
		}

		public Map<String, Object> getPayload() {
			return Collections.unmodifiableMap(payload);
		}

		public double getConfidence() {
			return confidence;
		}

		public List<String> getPredecessorIds() {
			return predecessorIds;
		}

		public Optional<String> getMissionId() {
			return Optional.ofNullable(missionId).filter(value -> !value.isBlank());
		}

		private static double clamp(double value) {
			return Math.max(0.0d, Math.min(1.0d, value));
		}
	}

	public static final class IngestionOutcome {
		private final Evidence evidence;
		private final ReconciliationReport reconciliationReport;

		IngestionOutcome(Evidence evidence, ReconciliationReport reconciliationReport) {
			this.evidence = Objects.requireNonNull(evidence, "evidence");
			this.reconciliationReport = Objects.requireNonNull(reconciliationReport,
				"reconciliationReport");
		}

		public Evidence getEvidence() {
			return evidence;
		}

		public ReconciliationReport getReconciliationReport() {
			return reconciliationReport;
		}
	}

	public static final class ReconciliationReport {
		private int observed;
		private int mapped;
		private int created;
		private int unresolved;
		private final List<Map<String, String>> unresolvedEntities = new ArrayList<>();

		void record(Resolution resolution) {
			observed++;
			switch (resolution.status) {
				case CREATED:
					created++;
					break;
				case MAPPED:
					mapped++;
					break;
				case UNRESOLVED:
					unresolved++;
					Map<String, String> unresolvedEntry = new LinkedHashMap<>();
					unresolvedEntry.put("entity_type", resolution.entityType);
					unresolvedEntry.put("reason", resolution.reason);
					if (resolution.identity != null) {
						unresolvedEntry.put("identity", resolution.identity);
					}
					unresolvedEntities.add(Collections.unmodifiableMap(unresolvedEntry));
					break;
				default:
					break;
			}
		}

		static ReconciliationReport unsupportedSource(String sourceType) {
			ReconciliationReport report = new ReconciliationReport();
			report.observed = 1;
			report.unresolved = 1;
			Map<String, String> unresolvedEntry = new LinkedHashMap<>();
			unresolvedEntry.put("entity_type", "source");
			unresolvedEntry.put("reason", "unsupported_source_type");
			if (sourceType != null && !sourceType.isBlank()) {
				unresolvedEntry.put("identity", sourceType);
			}
			report.unresolvedEntities.add(Collections.unmodifiableMap(unresolvedEntry));
			return report;
		}

		public int getObserved() {
			return observed;
		}

		public int getMapped() {
			return mapped;
		}

		public int getCreated() {
			return created;
		}

		public int getUnresolved() {
			return unresolved;
		}

		public List<Map<String, String>> getUnresolvedEntities() {
			return Collections.unmodifiableList(unresolvedEntities);
		}

		public Map<String, Object> toMap() {
			Map<String, Object> report = new LinkedHashMap<>();
			report.put("observed_count", observed);
			report.put("mapped_count", mapped);
			report.put("created_count", created);
			report.put("unresolved_count", unresolved);
			report.put("unresolved_entities", Collections.unmodifiableList(unresolvedEntities));
			return Collections.unmodifiableMap(report);
		}
	}

	private interface IngestionAdapter {
		boolean supports(String sourceType);

		AdaptedEvidence adapt(IncomingEvidence input);
	}

	private static final class AdaptedEvidence {
		private final EvidenceType evidenceType;
		private final List<EntityCandidate> entityCandidates;

		AdaptedEvidence(EvidenceType evidenceType, List<EntityCandidate> entityCandidates) {
			this.evidenceType = Objects.requireNonNull(evidenceType, "evidenceType");
			this.entityCandidates = List.copyOf(entityCandidates);
		}

		EvidenceType getEvidenceType() {
			return evidenceType;
		}

		List<EntityCandidate> getEntityCandidates() {
			return entityCandidates;
		}
	}

	private static final class StaticAnalysisAdapter implements IngestionAdapter {
		@Override
		public boolean supports(String sourceType) {
			return "static-analysis".equals(normalize(sourceType)) ||
				"static_analysis".equals(normalize(sourceType));
		}

		@Override
		public AdaptedEvidence adapt(IncomingEvidence input) {
			Map<String, Object> payload = input.getPayload();
			String identity = firstNonBlank(payload.get("functionName"), payload.get("symbol"),
				payload.get("address"));
			return new AdaptedEvidence(EvidenceType.STATIC_ANALYSIS,
				List.of(new EntityCandidate("function", identity, "missing_function_identity")));
		}
	}

	private static final class TraceAdapter implements IngestionAdapter {
		@Override
		public boolean supports(String sourceType) {
			String normalized = normalize(sourceType);
			return "trace".equals(normalized) || "dynamic-trace".equals(normalized) ||
				"dynamic_trace".equals(normalized);
		}

		@Override
		public AdaptedEvidence adapt(IncomingEvidence input) {
			Map<String, Object> payload = input.getPayload();
			String identity = firstNonBlank(payload.get("address"), payload.get("threadId"),
				payload.get("functionName"));
			return new AdaptedEvidence(EvidenceType.DYNAMIC_TRACE,
				List.of(new EntityCandidate("trace-node", identity, "missing_trace_identity")));
		}
	}

	private static final class ProposalReceiptAdapter implements IngestionAdapter {
		@Override
		public boolean supports(String sourceType) {
			String normalized = normalize(sourceType);
			return "proposal-receipt".equals(normalized) || "proposal_receipt".equals(normalized) ||
				"proposal/receipt".equals(normalized) || "receipt".equals(normalized);
		}

		@Override
		public AdaptedEvidence adapt(IncomingEvidence input) {
			Map<String, Object> payload = input.getPayload();
			EntityCandidate proposal = new EntityCandidate("proposal", asString(payload.get("proposalId")),
				"missing_proposal_id");
			EntityCandidate receipt = new EntityCandidate("receipt", asString(payload.get("receiptId")),
				"missing_receipt_id");
			return new AdaptedEvidence(EvidenceType.AGGREGATED, List.of(proposal, receipt));
		}
	}

	private static final class EntityCandidate {
		private final String entityType;
		private final String identity;
		private final String missingReason;

		EntityCandidate(String entityType, String identity, String missingReason) {
			this.entityType = normalize(entityType);
			this.identity = normalize(identity);
			this.missingReason = missingReason;
		}
	}

	private static final class CanonicalEntityResolver {
		private final Map<String, CanonicalEntity> entitiesByKey = new ConcurrentHashMap<>();

		Resolution resolve(EntityCandidate candidate) {
			if (candidate.identity == null || candidate.identity.isBlank()) {
				return Resolution.unresolved(candidate.entityType, null, candidate.missingReason);
			}
			String canonicalKey = candidate.entityType + "|" + candidate.identity;
			CanonicalEntity existing = entitiesByKey.get(canonicalKey);
			if (existing != null) {
				return Resolution.mapped(existing);
			}
			CanonicalEntity created = new CanonicalEntity(
				buildEntityId(canonicalKey, candidate.entityType),
				candidate.entityType,
				candidate.identity,
				canonicalKey);
			CanonicalEntity winner = entitiesByKey.putIfAbsent(canonicalKey, created);
			if (winner != null) {
				return Resolution.mapped(winner);
			}
			return Resolution.created(created);
		}

		private static String buildEntityId(String canonicalKey, String entityType) {
			return "entity:" + entityType + ":" + sha256Hex(canonicalKey).substring(0, 16);
		}
	}

	private static final class CanonicalEntity {
		private final String id;
		private final String type;
		private final String identity;
		private final String canonicalKey;

		CanonicalEntity(String id, String type, String identity, String canonicalKey) {
			this.id = id;
			this.type = type;
			this.identity = identity;
			this.canonicalKey = canonicalKey;
		}
	}

	private enum ResolutionStatus {
		CREATED,
		MAPPED,
		UNRESOLVED
	}

	private static final class Resolution {
		private final ResolutionStatus status;
		private final String entityId;
		private final String entityType;
		private final String identity;
		private final String canonicalKey;
		private final String reason;

		private Resolution(ResolutionStatus status, String entityId, String entityType,
				String identity, String canonicalKey, String reason) {
			this.status = status;
			this.entityId = entityId;
			this.entityType = entityType;
			this.identity = identity;
			this.canonicalKey = canonicalKey;
			this.reason = reason;
		}

		static Resolution created(CanonicalEntity entity) {
			return new Resolution(ResolutionStatus.CREATED, entity.id, entity.type,
				entity.identity, entity.canonicalKey, "");
		}

		static Resolution mapped(CanonicalEntity entity) {
			return new Resolution(ResolutionStatus.MAPPED, entity.id, entity.type,
				entity.identity, entity.canonicalKey, "");
		}

		static Resolution unresolved(String entityType, String identity, String reason) {
			return new Resolution(ResolutionStatus.UNRESOLVED, null,
				normalize(entityType), normalize(identity), null,
				reason != null ? reason : "unresolved");
		}

		Map<String, Object> toMap() {
			Map<String, Object> map = new LinkedHashMap<>();
			map.put("status", status.name().toLowerCase(Locale.ROOT));
			map.put("entity_type", entityType);
			if (identity != null) {
				map.put("identity", identity);
			}
			if (entityId != null) {
				map.put("entity_id", entityId);
			}
			if (canonicalKey != null) {
				map.put("canonical_key", canonicalKey);
			}
			if (status == ResolutionStatus.UNRESOLVED) {
				map.put("reason", reason);
			}
			return Collections.unmodifiableMap(map);
		}
	}

	private static String firstNonBlank(Object... candidates) {
		for (Object candidate : candidates) {
			String value = asString(candidate);
			if (value != null && !value.isBlank()) {
				return value;
			}
		}
		return null;
	}

	private static String asString(Object value) {
		if (value == null) {
			return null;
		}
		String stringValue = value.toString();
		return stringValue != null ? stringValue.trim() : null;
	}

	private static String normalize(String value) {
		if (value == null) {
			return "";
		}
		return value.trim().toLowerCase(Locale.ROOT);
	}

	private static String sha256Hex(String value) {
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] bytes = digest.digest(value.getBytes(StandardCharsets.UTF_8));
			StringBuilder builder = new StringBuilder(bytes.length * 2);
			for (byte b : bytes) {
				builder.append(Character.forDigit((b >>> 4) & 0x0f, 16));
				builder.append(Character.forDigit(b & 0x0f, 16));
			}
			return builder.toString();
		}
		catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("SHA-256 unavailable", e);
		}
	}
}
