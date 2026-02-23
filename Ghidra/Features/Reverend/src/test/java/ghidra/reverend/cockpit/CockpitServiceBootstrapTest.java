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

import java.util.List;

import org.junit.*;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.reverend.api.v1.EvidenceService;
import ghidra.reverend.api.v1.QueryService;
import ghidra.reverend.query.LiveQueryServiceImpl;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.task.TaskMonitor;

/**
 * Tests for cockpit service bootstrap initialization and lifecycle.
 */
public class CockpitServiceBootstrapTest extends AbstractGhidraHeadlessIntegrationTest {

	private CockpitServiceBootstrap bootstrap;
	private Program program;

	@Before
	public void setUp() throws Exception {
		bootstrap = new CockpitServiceBootstrap();
		bootstrap.init();
		program = createFixtureProgram();
	}

	@After
	public void tearDown() {
		if (bootstrap != null) {
			bootstrap.dispose();
		}
		if (program != null) {
			program.release(this);
		}
	}

	@Test
	public void testInitBootstrapsLiveImplementations() {
		assertTrue(bootstrap.isInitialized());
		assertTrue(bootstrap.getQueryService() instanceof LiveQueryServiceImpl);
		assertTrue(bootstrap.getEvidenceService() instanceof LiveEvidenceServiceImpl);
		assertTrue(bootstrap.getProposalService() instanceof LiveProposalIntegrationServiceImpl);
	}

	@Test
	public void testBindAndUnbindLifecycle() {
		bootstrap.bindProgram(program);

		LiveQueryServiceImpl liveQueryService =
			(LiveQueryServiceImpl) bootstrap.getQueryService();
		assertEquals(program, liveQueryService.getCurrentProgram());

		bootstrap.unbindProgram(program);
		assertNull(liveQueryService.getCurrentProgram());
	}

	@Test
	public void testRuntimePathReturnsNonEmptyQueryAndEvidenceOnFixtureProgram() throws Exception {
		bootstrap.bindProgram(program);

		QueryService queryService = bootstrap.getQueryService();
		List<QueryService.QueryResult> queryResults =
			queryService.semanticSearch(program, "fixture", null, 10, TaskMonitor.DUMMY);
		assertFalse(queryResults.isEmpty());

		EvidenceService evidenceService = bootstrap.getEvidenceService();
		assertFalse(evidenceService.query(program, null, null, null).isEmpty());
	}

	@Test
	public void testDisposeClosesBoundServices() {
		bootstrap.bindProgram(program);
		LiveQueryServiceImpl liveQueryService =
			(LiveQueryServiceImpl) bootstrap.getQueryService();
		assertEquals(program, liveQueryService.getCurrentProgram());

		bootstrap.dispose();
		assertFalse(bootstrap.isInitialized());
		assertNull(liveQueryService.getCurrentProgram());
	}

	private Program createFixtureProgram() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("CockpitFixture", ProgramBuilder._X86);
		builder.setBytes("0x01000000", "55 89 e5 83 ec 10 31 c0 c9 c3");
		builder.setBytes("0x01001000", "55 89 e5 83 ec 20 b8 01 00 00 00 c9 c3");
		Program fixtureProgram = builder.getProgram();

		int txId = fixtureProgram.startTransaction("Create fixture functions");
		try {
			CreateFunctionCmd first = new CreateFunctionCmd(
				"fixtureEntry",
				fixtureProgram.getAddressFactory().getAddress("0x01000000"),
				null,
				SourceType.USER_DEFINED);
			first.applyTo(fixtureProgram);

			CreateFunctionCmd second = new CreateFunctionCmd(
				"fixtureWorker",
				fixtureProgram.getAddressFactory().getAddress("0x01001000"),
				null,
				SourceType.USER_DEFINED);
			second.applyTo(fixtureProgram);
		}
		finally {
			fixtureProgram.endTransaction(txId, true);
		}
		return fixtureProgram;
	}
}
