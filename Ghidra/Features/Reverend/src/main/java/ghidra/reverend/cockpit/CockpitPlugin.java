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

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.reverend.api.v1.EvidenceService;
import ghidra.reverend.api.v1.ProposalIntegrationService;
import ghidra.reverend.api.v1.QueryService;

/**
 * Plugin providing cockpit dockable providers for Reverend analysis.
 *
 * <p>This plugin manages:
 * <ul>
 *   <li>Semantic search provider</li>
 *   <li>Evidence drilldown provider</li>
 *   <li>Navigation actions</li>
 *   <li>UI state persistence</li>
 * </ul>
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = "Reverend",
	category = PluginCategoryNames.ANALYSIS,
	shortDescription = "Reverend Cockpit UI",
	description = "Provides dockable UI providers for semantic search, " +
		"evidence exploration, and navigation actions."
)
//@formatter:on
public class CockpitPlugin extends ProgramPlugin {

	private static final String SEARCH_PROVIDER_STATE = "CockpitSearchProvider";
	private static final String EVIDENCE_PROVIDER_STATE = "EvidenceDrawerProvider";

	private QueryService queryService;
	private EvidenceService evidenceService;
	private ProposalIntegrationService proposalService;

	private CockpitSearchProvider searchProvider;
	private EvidenceDrawerProvider evidenceProvider;
	private CockpitNavigationActions navigationActions;

	/**
	 * Creates a new cockpit plugin.
	 *
	 * @param tool the plugin tool
	 */
	public CockpitPlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	protected void init() {
		super.init();
		createProviders();
	}

	/**
	 * Sets the query service for search operations.
	 *
	 * @param queryService the query service
	 */
	public void setQueryService(QueryService queryService) {
		this.queryService = queryService;
		if (searchProvider != null && queryService != null) {
			// Recreate search provider with new service
			tool.removeComponentProvider(searchProvider);
			createSearchProvider();
		}
	}

	/**
	 * Sets the evidence service for evidence operations.
	 *
	 * @param evidenceService the evidence service
	 */
	public void setEvidenceService(EvidenceService evidenceService) {
		this.evidenceService = evidenceService;
		if (evidenceProvider != null && evidenceService != null) {
			// Recreate evidence provider with new service
			tool.removeComponentProvider(evidenceProvider);
			createEvidenceProvider();
		}
	}

	/**
	 * Sets the proposal service for proposal operations.
	 *
	 * @param proposalService the proposal service
	 */
	public void setProposalService(ProposalIntegrationService proposalService) {
		this.proposalService = proposalService;
	}

	private void createProviders() {
		createSearchProvider();
		createEvidenceProvider();
		createNavigationActions();
	}

	private void createSearchProvider() {
		if (queryService == null) {
			// Use a stub service until the real one is set
			queryService = new StubQueryService();
		}
		searchProvider = new CockpitSearchProvider(tool, queryService);
		tool.addComponentProvider(searchProvider, false);
	}

	private void createEvidenceProvider() {
		if (evidenceService == null) {
			// Use a stub service until the real one is set
			evidenceService = new StubEvidenceService();
		}
		evidenceProvider = new EvidenceDrawerProvider(tool, evidenceService);
		tool.addComponentProvider(evidenceProvider, false);
	}

	private void createNavigationActions() {
		navigationActions = new CockpitNavigationActions(
			tool,
			this::getCurrentProgram,
			this::getCurrentAddress);

		// Register global actions
		tool.addAction(navigationActions.createGoToAddressAction());
		tool.addAction(navigationActions.createGoToNextXrefAction());
		tool.addAction(navigationActions.createGoToFunctionAction());
		tool.addAction(navigationActions.createShowInDecompilerAction());

		if (proposalService != null) {
			tool.addAction(navigationActions.createProposalAction(proposalService));
		}
	}

	private ghidra.program.model.address.Address getCurrentAddress() {
		if (searchProvider != null) {
			return searchProvider.getSelectedEntry()
				.map(SearchResultEntry::getAddress)
				.orElse(null);
		}
		return null;
	}

	@Override
	protected void programActivated(Program program) {
		if (searchProvider != null) {
			searchProvider.setProgram(program);
		}
		if (evidenceProvider != null) {
			evidenceProvider.setProgram(program);
		}
	}

	@Override
	protected void programDeactivated(Program program) {
		if (searchProvider != null) {
			searchProvider.clearProgram();
		}
		if (evidenceProvider != null) {
			evidenceProvider.clearProgram();
		}
	}

	@Override
	public void readConfigState(SaveState saveState) {
		SaveState searchState = saveState.getSaveState(SEARCH_PROVIDER_STATE);
		if (searchState != null && searchProvider != null) {
			searchProvider.readConfigState(searchState);
		}

		SaveState evidenceState = saveState.getSaveState(EVIDENCE_PROVIDER_STATE);
		if (evidenceState != null && evidenceProvider != null) {
			evidenceProvider.readConfigState(evidenceState);
		}
	}

	@Override
	public void writeConfigState(SaveState saveState) {
		if (searchProvider != null) {
			SaveState searchState = new SaveState();
			searchProvider.writeConfigState(searchState);
			saveState.putSaveState(SEARCH_PROVIDER_STATE, searchState);
		}

		if (evidenceProvider != null) {
			SaveState evidenceState = new SaveState();
			evidenceProvider.writeConfigState(evidenceState);
			saveState.putSaveState(EVIDENCE_PROVIDER_STATE, evidenceState);
		}
	}

	@Override
	protected void dispose() {
		if (searchProvider != null) {
			tool.removeComponentProvider(searchProvider);
			searchProvider = null;
		}
		if (evidenceProvider != null) {
			tool.removeComponentProvider(evidenceProvider);
			evidenceProvider = null;
		}
		super.dispose();
	}

	/**
	 * Returns the search provider.
	 *
	 * @return the search provider
	 */
	public CockpitSearchProvider getSearchProvider() {
		return searchProvider;
	}

	/**
	 * Returns the evidence provider.
	 *
	 * @return the evidence provider
	 */
	public EvidenceDrawerProvider getEvidenceProvider() {
		return evidenceProvider;
	}

	/**
	 * Shows the search provider.
	 */
	public void showSearchProvider() {
		if (searchProvider != null) {
			tool.showComponentProvider(searchProvider, true);
		}
	}

	/**
	 * Shows the evidence provider.
	 */
	public void showEvidenceProvider() {
		if (evidenceProvider != null) {
			tool.showComponentProvider(evidenceProvider, true);
		}
	}

	/**
	 * Stub query service used before real service is set.
	 */
	private static class StubQueryService implements QueryService {
		@Override
		public java.util.List<QueryResult> findSimilarFunctions(Program program,
				ghidra.program.model.listing.Function function, int maxResults,
				ghidra.util.task.TaskMonitor monitor) {
			return java.util.Collections.emptyList();
		}

		@Override
		public java.util.List<QueryResult> semanticSearch(Program program, String query,
				ghidra.program.model.address.AddressSetView scope, int maxResults,
				ghidra.util.task.TaskMonitor monitor) {
			return java.util.Collections.emptyList();
		}

		@Override
		public java.util.List<ghidra.program.model.address.Address> patternSearch(
				Program program, String pattern,
				ghidra.program.model.address.AddressSetView scope,
				ghidra.util.task.TaskMonitor monitor) {
			return java.util.Collections.emptyList();
		}

		@Override
		public java.util.Optional<QueryContext> getContext(Program program,
				ghidra.program.model.address.Address address) {
			return java.util.Optional.empty();
		}
	}

	/**
	 * Stub evidence service used before real service is set.
	 */
	private static class StubEvidenceService implements EvidenceService {
		@Override
		public Evidence record(Evidence evidence) {
			return evidence;
		}

		@Override
		public java.util.Optional<Evidence> get(String evidenceId) {
			return java.util.Optional.empty();
		}

		@Override
		public java.util.List<Evidence> query(Program program, EvidenceType type,
				String source, java.time.Instant since) {
			return java.util.Collections.emptyList();
		}

		@Override
		public java.util.List<Evidence> getForAddress(Program program,
				ghidra.program.model.address.Address address) {
			return java.util.Collections.emptyList();
		}

		@Override
		public void linkToProposal(String evidenceId, String proposalId) {
			// No-op
		}

		@Override
		public java.util.List<Evidence> getDerivationChain(String evidenceId) {
			return java.util.Collections.emptyList();
		}

		@Override
		public EvidenceBuilder builder() {
			return new StubEvidenceBuilder();
		}

		private static class StubEvidenceBuilder implements EvidenceBuilder {
			@Override
			public EvidenceBuilder type(EvidenceType type) {
				return this;
			}

			@Override
			public EvidenceBuilder source(String source) {
				return this;
			}

			@Override
			public EvidenceBuilder sourceVersion(String version) {
				return this;
			}

			@Override
			public EvidenceBuilder programId(String programId) {
				return this;
			}

			@Override
			public EvidenceBuilder addAddress(ghidra.program.model.address.Address address) {
				return this;
			}

			@Override
			public EvidenceBuilder payload(java.util.Map<String, Object> payload) {
				return this;
			}

			@Override
			public EvidenceBuilder confidence(double confidence) {
				return this;
			}

			@Override
			public EvidenceBuilder addPredecessor(String predecessorId) {
				return this;
			}

			@Override
			public EvidenceBuilder missionId(String missionId) {
				return this;
			}

			@Override
			public Evidence build() {
				return null;
			}
		}
	}
}
