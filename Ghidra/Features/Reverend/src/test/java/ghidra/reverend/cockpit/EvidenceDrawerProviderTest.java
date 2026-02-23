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

import static org.junit.Assert.*;

import java.awt.Component;
import java.time.Instant;
import java.util.*;

import javax.swing.JComponent;
import javax.swing.JLabel;

import org.junit.*;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.reverend.api.v1.EvidenceService;
import ghidra.reverend.api.v1.EvidenceService.EvidenceType;
import ghidra.reverend.api.v1.QueryService.QueryResult;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.test.TestEnv;

/**
 * Tests for {@link EvidenceDrawerProvider} hit-level provenance overlays.
 */
public class EvidenceDrawerProviderTest extends AbstractGhidraHeadlessIntegrationTest {

	private TestEnv env;
	private MockEvidenceService evidenceService;
	private EvidenceDrawerProvider provider;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		evidenceService = new MockEvidenceService();
		provider = new EvidenceDrawerProvider(env.getTool(), evidenceService);
	}

	@After
	public void tearDown() {
		if (env != null) {
			env.dispose();
		}
	}

	@Test
	public void testShowEvidenceForHitRendersStaticAndDynamicProvenanceLinks() {
		Address address = createAddress(0x401000);
		SearchResultEntry entry = new SearchResultEntry(
			new TestQueryResult(
				address,
				0.92,
				"fixture summary",
				null,
				List.of(
					"evidence_ref:static:semantic:00401000",
					"evidence_ref:dynamic:semantic:00401000"),
				Map.of(
					"static_provenance_ref", "provenance_ref:static:semantic:00401000",
					"dynamic_provenance_ref", "provenance_ref:dynamic:semantic:00401000")),
			"fixtureFunc");

		provider.showEvidenceForHit(entry);

		String text = collectText(provider.getComponent());
		assertTrue(text.contains("Hit Provenance Links"));
		assertTrue(text.contains("Static:"));
		assertTrue(text.contains("Dynamic:"));
		assertTrue(text.contains("evidence_ref:static:semantic:00401000"));
		assertTrue(text.contains("evidence_ref:dynamic:semantic:00401000"));
	}

	@Test
	public void testShowEvidenceForHitIncludesEvidenceCardWhenEvidenceExists() throws Exception {
		Address address = createAddress(0x402000);
		MockEvidence evidence = new MockEvidence(
			"ev-hit-1",
			EvidenceType.DYNAMIC_TRACE,
			"trace-fixture",
			List.of(address));
		evidenceService.put(evidence);
		SearchResultEntry entry = new SearchResultEntry(
			new TestQueryResult(
				address,
				0.88,
				"trace hit",
				"ev-hit-1",
				List.of("evidence_ref:static:semantic:00402000", "evidence_ref:dynamic:semantic:00402000"),
				Map.of()),
			"traceFunc");

		provider.showEvidenceForHit(entry);

		String text = collectText(provider.getComponent());
		assertTrue(text.contains("trace-fixture"));
		assertTrue(text.contains("evidence_ref:static:semantic:00402000"));
		assertTrue(text.contains("evidence_ref:dynamic:semantic:00402000"));
	}

	private String collectText(JComponent root) {
		StringBuilder builder = new StringBuilder();
		collectTextRecursive(root, builder);
		return builder.toString();
	}

	private void collectTextRecursive(Component component, StringBuilder builder) {
		if (component instanceof JLabel label && label.getText() != null) {
			builder.append(label.getText()).append('\n');
		}
		if (component instanceof JComponent jComponent) {
			for (Component child : jComponent.getComponents()) {
				collectTextRecursive(child, builder);
			}
		}
	}

	private Address createAddress(long offset) {
		GenericAddressSpace space = new GenericAddressSpace("ram", 32,
			ghidra.program.model.address.AddressSpace.TYPE_RAM, 0);
		return space.getAddress(offset);
	}

	private static class MockEvidenceService implements EvidenceService {
		private final Map<String, Evidence> evidenceById = new LinkedHashMap<>();

		void put(Evidence evidence) {
			evidenceById.put(evidence.getId(), evidence);
		}

		@Override
		public Evidence record(Evidence evidence) {
			evidenceById.put(evidence.getId(), evidence);
			return evidence;
		}

		@Override
		public Optional<Evidence> get(String evidenceId) {
			return Optional.ofNullable(evidenceById.get(evidenceId));
		}

		@Override
		public List<Evidence> query(Program program, EvidenceType type, String source, Instant since) {
			return new ArrayList<>(evidenceById.values());
		}

		@Override
		public List<Evidence> getForAddress(Program program, Address address) {
			return new ArrayList<>();
		}

		@Override
		public void linkToProposal(String evidenceId, String proposalId) {
			// no-op for test
		}

		@Override
		public List<Evidence> getDerivationChain(String evidenceId) {
			return Collections.emptyList();
		}

		@Override
		public EvidenceBuilder builder() {
			throw new UnsupportedOperationException("not used in test");
		}
	}

	private static class MockEvidence implements Evidence {
		private final String id;
		private final EvidenceType type;
		private final String source;
		private final List<Address> addresses;

		MockEvidence(String id, EvidenceType type, String source, List<Address> addresses) {
			this.id = id;
			this.type = type;
			this.source = source;
			this.addresses = addresses;
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
			return "test";
		}

		@Override
		public String getProgramId() {
			return "program-test";
		}

		@Override
		public List<Address> getAddresses() {
			return addresses;
		}

		@Override
		public Map<String, Object> getPayload() {
			return Map.of("kind", "mock");
		}

		@Override
		public double getConfidence() {
			return 0.75;
		}

		@Override
		public Instant getCreatedAt() {
			return Instant.parse("2026-02-01T00:00:00Z");
		}

		@Override
		public List<String> getPredecessorIds() {
			return List.of();
		}

		@Override
		public Optional<String> getMissionId() {
			return Optional.empty();
		}
	}

	private static class TestQueryResult implements QueryResult {
		private final Address address;
		private final double score;
		private final String summary;
		private final String evidenceId;
		private final List<String> evidenceRefs;
		private final Map<String, String> provenance;

		TestQueryResult(Address address, double score, String summary, String evidenceId,
				List<String> evidenceRefs, Map<String, String> provenance) {
			this.address = address;
			this.score = score;
			this.summary = summary;
			this.evidenceId = evidenceId;
			this.evidenceRefs = evidenceRefs;
			this.provenance = provenance;
		}

		@Override
		public Address getAddress() {
			return address;
		}

		@Override
		public double getScore() {
			return score;
		}

		@Override
		public String getSummary() {
			return summary;
		}

		@Override
		public Optional<String> getEvidenceId() {
			return Optional.ofNullable(evidenceId);
		}

		@Override
		public List<String> getEvidenceRefs() {
			return evidenceRefs;
		}

		@Override
		public Map<String, String> getProvenance() {
			return provenance;
		}
	}
}
