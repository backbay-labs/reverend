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

import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.KeyBindingData;
import docking.action.MenuData;
import docking.action.ToolBarData;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.util.ProgramLocation;
import ghidra.reverend.api.v1.EvidenceService;
import ghidra.reverend.api.v1.MissionService;
import ghidra.reverend.api.v1.ProposalIntegrationService;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import resources.Icons;

/**
 * Factory for cockpit navigation actions.
 *
 * <p>Provides reusable actions for:
 * <ul>
 *   <li>Jump to address</li>
 *   <li>Jump to cross-reference (next/previous)</li>
 *   <li>Create proposal from selection</li>
 * </ul>
 */
public class CockpitNavigationActions {

	private static final String OWNER = "ReverendPlugin";
	private static final String MENU_GROUP = "Navigate";

	private final PluginTool tool;
	private final Supplier<Program> programSupplier;
	private final Supplier<Address> addressSupplier;

	/**
	 * Creates navigation actions with the given suppliers.
	 *
	 * @param tool the plugin tool
	 * @param programSupplier supplier for the current program
	 * @param addressSupplier supplier for the current selected address
	 */
	public CockpitNavigationActions(PluginTool tool, Supplier<Program> programSupplier,
			Supplier<Address> addressSupplier) {
		this.tool = Objects.requireNonNull(tool, "tool cannot be null");
		this.programSupplier = Objects.requireNonNull(programSupplier,
			"programSupplier cannot be null");
		this.addressSupplier = Objects.requireNonNull(addressSupplier,
			"addressSupplier cannot be null");
	}

	/**
	 * Creates a jump-to-address action.
	 *
	 * @return the action
	 */
	public DockingAction createGoToAddressAction() {
		DockingAction action = new DockingAction("Go To Address", OWNER) {
			@Override
			public void actionPerformed(ActionContext context) {
				Address address = addressSupplier.get();
				if (address != null) {
					goToAddress(address);
				}
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return addressSupplier.get() != null;
			}
		};

		action.setPopupMenuData(new MenuData(new String[] { MENU_GROUP, "Go To Address" }));
		action.setToolBarData(new ToolBarData(Icons.NAVIGATE_ON_INCOMING_EVENT_ICON));
		action.setKeyBindingData(new KeyBindingData("G"));
		action.setDescription("Navigate to the selected address in the listing");
		action.setHelpLocation(new HelpLocation(OWNER, "GoToAddress"));

		return action;
	}

	/**
	 * Creates a jump-to-next-xref action.
	 *
	 * @return the action
	 */
	public DockingAction createGoToNextXrefAction() {
		DockingAction action = new DockingAction("Go To Next Xref", OWNER) {
			@Override
			public void actionPerformed(ActionContext context) {
				Address address = addressSupplier.get();
				if (address != null) {
					goToNextXref(address);
				}
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				Address address = addressSupplier.get();
				return address != null && hasXrefs(address);
			}
		};

		action.setPopupMenuData(new MenuData(new String[] { MENU_GROUP, "Go To Next Xref" }));
		action.setKeyBindingData(new KeyBindingData("X"));
		action.setDescription("Navigate to the next cross-reference to this address");
		action.setHelpLocation(new HelpLocation(OWNER, "GoToXref"));

		return action;
	}

	/**
	 * Creates a jump-to-function action.
	 *
	 * @return the action
	 */
	public DockingAction createGoToFunctionAction() {
		DockingAction action = new DockingAction("Go To Function", OWNER) {
			@Override
			public void actionPerformed(ActionContext context) {
				Address address = addressSupplier.get();
				if (address != null) {
					goToFunction(address);
				}
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				Address address = addressSupplier.get();
				return address != null && getContainingFunction(address).isPresent();
			}
		};

		action.setPopupMenuData(new MenuData(new String[] { MENU_GROUP, "Go To Function Start" }));
		action.setKeyBindingData(new KeyBindingData("F"));
		action.setDescription("Navigate to the start of the containing function");
		action.setHelpLocation(new HelpLocation(OWNER, "GoToFunction"));

		return action;
	}

	/**
	 * Creates a create-proposal action.
	 *
	 * @param proposalService the proposal service
	 * @return the action
	 */
	public DockingAction createProposalAction(ProposalIntegrationService proposalService,
			MissionService missionService, EvidenceService evidenceService) {
		DockingAction action = new DockingAction("Create Proposal", OWNER) {
			@Override
			public void actionPerformed(ActionContext context) {
				Address address = addressSupplier.get();
				Program program = programSupplier.get();
				if (address != null && program != null) {
					createProposal(program, address, proposalService, missionService, evidenceService);
				}
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return addressSupplier.get() != null && programSupplier.get() != null;
			}
		};

		action.setPopupMenuData(
			new MenuData(new String[] { "Reverend", "Create Proposal from Selection" }));
		action.setDescription("Create a new proposal for the selected address");
		action.setHelpLocation(new HelpLocation(OWNER, "CreateProposal"));

		return action;
	}

	/**
	 * Creates a show-in-decompiler action.
	 *
	 * @return the action
	 */
	public DockingAction createShowInDecompilerAction() {
		DockingAction action = new DockingAction("Show in Decompiler", OWNER) {
			@Override
			public void actionPerformed(ActionContext context) {
				Address address = addressSupplier.get();
				if (address != null) {
					showInDecompiler(address);
				}
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				Address address = addressSupplier.get();
				return address != null && getContainingFunction(address).isPresent();
			}
		};

		action.setPopupMenuData(new MenuData(new String[] { MENU_GROUP, "Show in Decompiler" }));
		action.setKeyBindingData(new KeyBindingData("D"));
		action.setDescription("Show this address in the decompiler view");
		action.setHelpLocation(new HelpLocation(OWNER, "ShowInDecompiler"));

		return action;
	}

	private void goToAddress(Address address) {
		Program program = programSupplier.get();
		if (program == null) {
			Msg.showWarn(this, null, "No Program", "No program is currently open");
			return;
		}

		GoToService goToService = tool.getService(GoToService.class);
		if (goToService != null) {
			goToService.goTo(new ProgramLocation(program, address));
		}
	}

	private void goToNextXref(Address address) {
		Program program = programSupplier.get();
		if (program == null) {
			return;
		}

		ReferenceManager refManager = program.getReferenceManager();
		ReferenceIterator iter = refManager.getReferencesTo(address);
		if (iter.hasNext()) {
			Reference ref = iter.next();
			goToAddress(ref.getFromAddress());
		}
	}

	private void goToFunction(Address address) {
		getContainingFunction(address).ifPresent(func -> {
			goToAddress(func.getEntryPoint());
		});
	}

	private void showInDecompiler(Address address) {
		// Navigate to address - the decompiler view will follow if open
		goToAddress(address);
	}

	private void createProposal(Program program, Address address,
			ProposalIntegrationService proposalService, MissionService missionService,
			EvidenceService evidenceService) {
		Optional<Function> func = getContainingFunction(address);
		if (func.isEmpty()) {
			Msg.showInfo(this, null, "Create Proposal",
				"No function at address " + address + " - proposals require a function context");
			return;
		}

		try {
			CockpitMissionProposalFlow flow =
				new CockpitMissionProposalFlow(missionService, proposalService, evidenceService);
			CockpitMissionProposalFlow.Result result = flow.execute(
				program,
				address,
				func.get().getName(),
				"ui",
				TaskMonitor.DUMMY);

			Msg.showInfo(this, null, "Create Proposal",
				"Created proposal " + result.getProposalId() + " from mission " +
					result.getMissionId() + " with evidence " + result.getEvidenceId());
		}
		catch (MissionService.MissionException | ProposalIntegrationService.ProposalCreationException |
			EvidenceService.EvidenceException e) {
			Msg.showError(this, null, "Create Proposal Failed", e.getMessage());
		}
	}

	private boolean hasXrefs(Address address) {
		Program program = programSupplier.get();
		if (program == null) {
			return false;
		}

		ReferenceManager refManager = program.getReferenceManager();
		return refManager.hasReferencesTo(address);
	}

	private Optional<Function> getContainingFunction(Address address) {
		Program program = programSupplier.get();
		if (program == null) {
			return Optional.empty();
		}

		Function func = program.getFunctionManager().getFunctionContaining(address);
		return Optional.ofNullable(func);
	}
}
