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
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.security.proposal.Proposal;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.task.TaskMonitor;

/**
 * Headless parity tests for mission/proposal/evidence cockpit interactions.
 */
public class CockpitMissionProposalFlowTest extends AbstractGhidraHeadlessIntegrationTest {

	private CockpitServiceBootstrap bootstrap;
	private Program program;
	private Address functionAddress;

	@Before
	public void setUp() throws Exception {
		bootstrap = new CockpitServiceBootstrap();
		bootstrap.init();
		program = createFixtureProgram();
		functionAddress = program.getAddressFactory().getAddress("0x01000000");
		bootstrap.bindProgram(program);
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
	public void testHeadlessUiParityForMissionProposalFlow() throws Exception {
		CockpitMissionProposalFlow flow = new CockpitMissionProposalFlow(
			bootstrap.getMissionService(),
			bootstrap.getProposalService(),
			bootstrap.getEvidenceService());

		CockpitMissionProposalFlow.Result headless = flow.execute(
			program,
			functionAddress,
			"fixtureEntry",
			"headless",
			TaskMonitor.DUMMY);

		CockpitMissionProposalFlow.Result ui = flow.execute(
			program,
			functionAddress,
			"fixtureEntry",
			"ui",
			TaskMonitor.DUMMY);

		assertEquals(headless.getMissionState(), ui.getMissionState());
		assertEquals("rename", headless.getSuggestionType());
		assertEquals(headless.getSuggestionType(), ui.getSuggestionType());
		assertEquals(headless.getTarget(), ui.getTarget());
		assertEquals(headless.getValue(), ui.getValue());

		assertTrue(bootstrap.getEvidenceService().get(headless.getEvidenceId()).isPresent());
		assertTrue(bootstrap.getEvidenceService().get(ui.getEvidenceId()).isPresent());

		List<Proposal> headlessMissionProposals =
			bootstrap.getProposalService().queryProposals(program, null, headless.getMissionId());
		List<Proposal> uiMissionProposals =
			bootstrap.getProposalService().queryProposals(program, null, ui.getMissionId());
		assertEquals(1, headlessMissionProposals.size());
		assertEquals(1, uiMissionProposals.size());
		assertEquals(headless.getEvidenceId(),
			headlessMissionProposals.get(0).getMetadata().get("evidenceId"));
		assertEquals(ui.getEvidenceId(), uiMissionProposals.get(0).getMetadata().get("evidenceId"));
	}

	private Program createFixtureProgram() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("CockpitMissionFixture", ProgramBuilder._X86);
		builder.setBytes("0x01000000", "55 89 e5 83 ec 10 31 c0 c9 c3");
		Program fixtureProgram = builder.getProgram();

		int txId = fixtureProgram.startTransaction("Create fixture function");
		try {
			CreateFunctionCmd first = new CreateFunctionCmd(
				"fixtureEntry",
				fixtureProgram.getAddressFactory().getAddress("0x01000000"),
				null,
				SourceType.USER_DEFINED);
			first.applyTo(fixtureProgram);
		}
		finally {
			fixtureProgram.endTransaction(txId, true);
		}
		return fixtureProgram;
	}
}
