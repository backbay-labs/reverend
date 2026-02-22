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

import java.util.*;

import org.junit.*;

import ghidra.framework.options.SaveState;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.reverend.api.v1.QueryService;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.task.TaskMonitor;

/**
 * Integration tests for {@link CockpitSearchProvider}.
 */
public class CockpitSearchProviderTest extends AbstractGhidraHeadlessIntegrationTest {

	private TestEnv env;
	private CockpitSearchProvider provider;
	private MockQueryService queryService;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		queryService = new MockQueryService();
		provider = new CockpitSearchProvider(env.getTool(), queryService);
	}

	@After
	public void tearDown() throws Exception {
		if (env != null) {
			env.dispose();
		}
	}

	@Test
	public void testProviderCreation() {
		assertNotNull(provider);
		assertNotNull(provider.getComponent());
		assertEquals("Reverend Search", CockpitSearchProvider.TITLE);
	}

	@Test
	public void testInitialState() {
		assertTrue(provider.getResults().isEmpty());
		assertTrue(provider.getSelectedEntry().isEmpty());
	}

	@Test
	public void testSetProgram() {
		Program program = createDefaultProgram("test", "x86:LE:64:default", this);
		provider.setProgram(program);
		// No exceptions should be thrown
	}

	@Test
	public void testClearProgram() {
		provider.clearProgram();
		assertTrue(provider.getResults().isEmpty());
	}

	@Test
	public void testStateDefaultValues() {
		CockpitState state = provider.getState();
		assertEquals("", state.getLastQuery());
		assertEquals(50, state.getMaxResults());
		assertEquals(0.0, state.getMinConfidence(), 0.001);
	}

	@Test
	public void testStateSerialization() {
		// Modify state
		CockpitState state = provider.getState();
		state.setLastQuery("test query");
		state.setMaxResults(100);
		state.setMinConfidence(0.7);

		// Save state
		SaveState saveState = new SaveState();
		provider.writeConfigState(saveState);

		// Create new provider and restore
		CockpitSearchProvider restored = new CockpitSearchProvider(env.getTool(), queryService);
		restored.readConfigState(saveState);

		// Verify restoration
		CockpitState restoredState = restored.getState();
		assertEquals("test query", restoredState.getLastQuery());
		assertEquals(100, restoredState.getMaxResults());
		assertEquals(0.7, restoredState.getMinConfidence(), 0.001);
	}

	@Test
	public void testResultsAreUnmodifiable() {
		List<SearchResultEntry> results = provider.getResults();

		try {
			results.add(null);
			fail("Should have thrown UnsupportedOperationException");
		}
		catch (UnsupportedOperationException e) {
			// Expected
		}
	}

	@Test
	public void testGetSelectedEntryWhenNoneSelected() {
		assertTrue(provider.getSelectedEntry().isEmpty());
	}

	/**
	 * Mock query service for testing.
	 */
	private static class MockQueryService implements QueryService {

		private List<QueryResult> resultsToReturn = new ArrayList<>();

		public void setResults(List<QueryResult> results) {
			this.resultsToReturn = results;
		}

		@Override
		public List<QueryResult> findSimilarFunctions(Program program, Function function,
				int maxResults, TaskMonitor monitor) {
			return resultsToReturn;
		}

		@Override
		public List<QueryResult> semanticSearch(Program program, String query,
				AddressSetView scope, int maxResults, TaskMonitor monitor) {
			return resultsToReturn;
		}

		@Override
		public List<Address> patternSearch(Program program, String pattern,
				AddressSetView scope, TaskMonitor monitor) {
			return Collections.emptyList();
		}

		@Override
		public Optional<QueryContext> getContext(Program program, Address address) {
			return Optional.empty();
		}
	}
}
