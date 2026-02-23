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

import static org.junit.Assert.*;

import java.util.List;
import java.util.Map;

import org.junit.Test;

import ghidra.reverend.api.v1.EvidenceService.EvidenceType;
import ghidra.reverend.cockpit.LiveEvidenceServiceImpl;

public class EvidenceIngestionResolverTest {

	@Test
	public void testAdaptersSupportExpectedSourceTypes() throws Exception {
		EvidenceIngestionResolver resolver = new EvidenceIngestionResolver();
		try (LiveEvidenceServiceImpl evidenceService = new LiveEvidenceServiceImpl()) {
			EvidenceIngestionResolver.IngestionOutcome staticOutcome = resolver.ingest(
				evidenceService,
				new EvidenceIngestionResolver.IncomingEvidence(
					"static-analysis",
					"fixture.static",
					"1",
					"program-a",
					Map.of("functionName", "FUN_main", "address", "00401000"),
					0.8d,
					List.of(),
					null));
			assertEquals(EvidenceType.STATIC_ANALYSIS, staticOutcome.getEvidence().getType());

			EvidenceIngestionResolver.IngestionOutcome traceOutcome = resolver.ingest(
				evidenceService,
				new EvidenceIngestionResolver.IncomingEvidence(
					"trace",
					"fixture.trace",
					"1",
					"program-a",
					Map.of("threadId", "7", "address", "00402000"),
					0.7d,
					List.of(),
					null));
			assertEquals(EvidenceType.DYNAMIC_TRACE, traceOutcome.getEvidence().getType());

				EvidenceIngestionResolver.IngestionOutcome proposalOutcome = resolver.ingest(
					evidenceService,
					new EvidenceIngestionResolver.IncomingEvidence(
						"proposal/receipt",
						"fixture.proposal",
						"1",
						"program-a",
					Map.of("proposalId", "proposal-1", "receiptId", "receipt-1"),
					0.9d,
					List.of(),
					null));
			assertEquals(EvidenceType.AGGREGATED, proposalOutcome.getEvidence().getType());
		}
	}

	@Test
	public void testResolverDeterministicallyMapsExistingCanonicalEntity() throws Exception {
		EvidenceIngestionResolver resolver = new EvidenceIngestionResolver();
		try (LiveEvidenceServiceImpl evidenceService = new LiveEvidenceServiceImpl()) {
			EvidenceIngestionResolver.IngestionOutcome first = resolver.ingest(
				evidenceService,
				new EvidenceIngestionResolver.IncomingEvidence(
					"static-analysis",
					"fixture.static",
					"1",
					"program-a",
					Map.of("functionName", "FUN_dispatch", "address", "00403000"),
					0.75d,
					List.of(),
					null));
			EvidenceIngestionResolver.IngestionOutcome second = resolver.ingest(
				evidenceService,
				new EvidenceIngestionResolver.IncomingEvidence(
					"static-analysis",
					"fixture.static",
					"1",
					"program-a",
					Map.of("functionName", "FUN_dispatch", "address", "00403000"),
					0.75d,
					List.of(),
					null));

			String firstEntityId = canonicalEntityId(first.getEvidence().getPayload());
			String secondEntityId = canonicalEntityId(second.getEvidence().getPayload());

			assertNotNull(firstEntityId);
			assertEquals(firstEntityId, secondEntityId);
			assertEquals(1, first.getReconciliationReport().getCreated());
			assertEquals(0, first.getReconciliationReport().getMapped());
			assertEquals(0, second.getReconciliationReport().getCreated());
			assertEquals(1, second.getReconciliationReport().getMapped());
		}
	}

	@Test
	public void testIngestionEmitsReconciliationReportForUnresolvedEntity() throws Exception {
		EvidenceIngestionResolver resolver = new EvidenceIngestionResolver();
		try (LiveEvidenceServiceImpl evidenceService = new LiveEvidenceServiceImpl()) {
			EvidenceIngestionResolver.IngestionOutcome outcome = resolver.ingest(
				evidenceService,
				new EvidenceIngestionResolver.IncomingEvidence(
					"proposal-receipt",
					"fixture.proposal",
					"1",
					"program-a",
					Map.of("proposalId", "proposal-2"),
					0.6d,
					List.of(),
					null));

			assertEquals(2, outcome.getReconciliationReport().getObserved());
			assertEquals(1, outcome.getReconciliationReport().getUnresolved());
			assertFalse(outcome.getReconciliationReport().getUnresolvedEntities().isEmpty());
			assertEquals("missing_receipt_id",
				outcome.getReconciliationReport().getUnresolvedEntities().get(0).get("reason"));

			@SuppressWarnings("unchecked")
			Map<String, Object> report = (Map<String, Object>) outcome.getEvidence()
				.getPayload()
				.get("reconciliation_report");
			assertEquals(1, report.get("unresolved_count"));
		}
	}

	@SuppressWarnings("unchecked")
	private static String canonicalEntityId(Map<String, Object> payload) {
		List<Map<String, Object>> entities = (List<Map<String, Object>>) payload.get("canonical_entities");
		for (Map<String, Object> entity : entities) {
			Object entityId = entity.get("entity_id");
			if (entityId != null) {
				return entityId.toString();
			}
		}
		return null;
	}
}
