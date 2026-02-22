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

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;

import docking.ActionContext;
import docking.WindowPosition;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.action.ToolBarData;
import docking.widgets.table.GTable;
import generic.theme.GIcon;
import ghidra.app.services.GoToService;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.reverend.api.v1.QueryService;
import ghidra.reverend.api.v1.QueryService.QueryResult;
import ghidra.reverend.query.LiveQueryServiceImpl;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import resources.Icons;

/**
 * Dockable provider for semantic search with result browsing.
 *
 * <p>This provider offers:
 * <ul>
 *   <li>Semantic search input with query history</li>
 *   <li>Results table with score, address, and summary columns</li>
 *   <li>Jump-to-address actions on selection</li>
 *   <li>Evidence linking for result provenance</li>
 *   <li>State persistence across sessions</li>
 * </ul>
 */
public class CockpitSearchProvider extends ComponentProviderAdapter {

	public static final String TITLE = "Reverend Search";
	public static final String OWNER = "ReverendPlugin";

	private static final String[] COLUMN_NAMES = { "Address", "Score", "Function", "Summary" };
	private static final int HYDRATION_BATCH_SIZE = 16;

	private final QueryService queryService;
	private final CockpitState state;

	private Program currentProgram;
	private JPanel mainPanel;
	private JTextField searchField;
	private GTable resultsTable;
	private SearchResultTableModel tableModel;
	private JLabel statusLabel;
	private final AtomicInteger activeSearchGeneration = new AtomicInteger();

	private List<SearchResultEntry> results = new ArrayList<>();

	/**
	 * Creates a new cockpit search provider.
	 *
	 * @param tool the plugin tool
	 * @param queryService the query service for searches
	 */
	public CockpitSearchProvider(PluginTool tool, QueryService queryService) {
		super(tool, TITLE, OWNER);
		this.queryService = Objects.requireNonNull(queryService, "queryService cannot be null");
		this.state = new CockpitState();

		buildComponent();
		createActions();

		setDefaultWindowPosition(WindowPosition.BOTTOM);
		setIcon(new GIcon("icon.search"));
		setHelpLocation(new HelpLocation(OWNER, "CockpitSearch"));
		setWindowMenuGroup(TITLE);
	}

	private void buildComponent() {
		mainPanel = new JPanel(new BorderLayout(5, 5));
		mainPanel.setPreferredSize(new Dimension(800, 300));

		// Search input panel
		JPanel searchPanel = new JPanel(new BorderLayout(5, 0));
		searchPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

		searchField = new JTextField();
		searchField.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (e.getKeyCode() == KeyEvent.VK_ENTER) {
					performSearch();
				}
			}
		});

		JButton searchButton = new JButton("Search");
		searchButton.addActionListener(e -> performSearch());

		searchPanel.add(new JLabel("Query: "), BorderLayout.WEST);
		searchPanel.add(searchField, BorderLayout.CENTER);
		searchPanel.add(searchButton, BorderLayout.EAST);

		// Results table
		tableModel = new SearchResultTableModel();
		resultsTable = new GTable(tableModel);
		resultsTable.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
		resultsTable.getColumnModel().getColumn(0).setPreferredWidth(100);
		resultsTable.getColumnModel().getColumn(1).setPreferredWidth(60);
		resultsTable.getColumnModel().getColumn(2).setPreferredWidth(150);
		resultsTable.getColumnModel().getColumn(3).setPreferredWidth(400);

		resultsTable.getSelectionModel().addListSelectionListener(e -> {
			if (!e.getValueIsAdjusting()) {
				onSelectionChanged();
			}
		});

		resultsTable.addMouseListener(new java.awt.event.MouseAdapter() {
			@Override
			public void mouseClicked(java.awt.event.MouseEvent e) {
				if (e.getClickCount() == 2) {
					goToSelectedResult();
				}
			}
		});

		JScrollPane scrollPane = new JScrollPane(resultsTable);

		// Status panel
		JPanel statusPanel = new JPanel(new BorderLayout());
		statusPanel.setBorder(BorderFactory.createEmptyBorder(2, 5, 2, 5));
		statusLabel = new JLabel("Ready");
		statusPanel.add(statusLabel, BorderLayout.WEST);

		mainPanel.add(searchPanel, BorderLayout.NORTH);
		mainPanel.add(scrollPane, BorderLayout.CENTER);
		mainPanel.add(statusPanel, BorderLayout.SOUTH);
	}

	private void createActions() {
		DockingAction goToAction = new DockingAction("Go To Address", OWNER) {
			@Override
			public void actionPerformed(ActionContext context) {
				goToSelectedResult();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return resultsTable.getSelectedRow() >= 0;
			}
		};
		goToAction.setPopupMenuData(new MenuData(new String[] { "Go To Address" }));
		goToAction.setToolBarData(new ToolBarData(Icons.NAVIGATE_ON_INCOMING_EVENT_ICON));
		goToAction.setDescription("Navigate to the selected result address");
		addLocalAction(goToAction);

		DockingAction showEvidenceAction = new DockingAction("Show Evidence", OWNER) {
			@Override
			public void actionPerformed(ActionContext context) {
				showEvidenceForSelection();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				int row = resultsTable.getSelectedRow();
				return row >= 0 && row < results.size() && results.get(row).hasEvidence();
			}
		};
		showEvidenceAction.setPopupMenuData(new MenuData(new String[] { "Show Evidence" }));
		showEvidenceAction.setDescription("Show evidence for the selected result");
		addLocalAction(showEvidenceAction);

		DockingAction showXrefsAction = new DockingAction("Show Cross-References", OWNER) {
			@Override
			public void actionPerformed(ActionContext context) {
				showXrefsForSelection();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return resultsTable.getSelectedRow() >= 0;
			}
		};
		showXrefsAction.setPopupMenuData(new MenuData(new String[] { "Show Cross-References" }));
		showXrefsAction.setDescription("Show cross-references for the selected result");
		addLocalAction(showXrefsAction);

		DockingAction clearResultsAction = new DockingAction("Clear Results", OWNER) {
			@Override
			public void actionPerformed(ActionContext context) {
				clearResults();
			}
		};
		clearResultsAction.setPopupMenuData(new MenuData(new String[] { "Clear Results" }));
		clearResultsAction.setDescription("Clear all search results");
		addLocalAction(clearResultsAction);
	}

	/**
	 * Sets the current program for searching.
	 *
	 * @param program the program to search
	 */
	public void setProgram(Program program) {
		this.currentProgram = program;
		clearResults();
	}

	/**
	 * Clears the current program reference.
	 */
	public void clearProgram() {
		this.currentProgram = null;
		clearResults();
	}

	private void performSearch() {
		String query = searchField.getText().trim();
		if (query.isEmpty()) {
			return;
		}

		if (currentProgram == null) {
			Msg.showWarn(this, mainPanel, "No Program", "No program is currently open");
			return;
		}

		state.setLastQuery(query);
		int searchGeneration = activeSearchGeneration.incrementAndGet();
		updateStatus("Searching: " + query);

		Task searchTask = new Task("Semantic Search", true, true, true) {
			@Override
			public void run(TaskMonitor monitor) {
				try {
					monitor.setMessage("Searching: " + query);
					List<QueryResult> queryResults = queryService.semanticSearch(
						currentProgram, query, null, state.getMaxResults(), monitor);
					LiveQueryServiceImpl.BudgetStatus budgetStatus = consumeBudgetStatusIfAvailable();
					populateResultsAsync(queryResults, searchGeneration, monitor);
					applyBudgetStatus(searchGeneration, budgetStatus);
				}
				catch (QueryService.QueryException e) {
					updateStatus("Search failed: " + e.getMessage());
					Msg.showError(this, mainPanel, "Search Failed", e.getMessage());
				}
			}
		};

		TaskLauncher.launch(searchTask);
	}

	private void populateResultsAsync(List<QueryResult> queryResults, int searchGeneration,
			TaskMonitor monitor) {
		FunctionManager funcManager =
			currentProgram != null ? currentProgram.getFunctionManager() : null;
		List<QueryResult> filtered = filterByMinConfidence(queryResults);
		List<SearchResultEntry> placeholders = new ArrayList<>(filtered.size());
		for (QueryResult result : filtered) {
			placeholders.add(new SearchResultEntry(result, null));
		}

		SwingUtilities.invokeLater(() -> {
			if (!isSearchGenerationCurrent(searchGeneration)) {
				return;
			}
			results.clear();
			results.addAll(placeholders);
			tableModel.fireTableDataChanged();
			updateStatus(buildResultCountMessage(results.size(), true));
		});

		List<HydrationUpdate> pendingUpdates = new ArrayList<>(HYDRATION_BATCH_SIZE);
		for (int i = 0; i < filtered.size(); i++) {
			if (monitor != null && monitor.isCancelled()) {
				break;
			}
			QueryResult result = filtered.get(i);
			String funcName = resolveFunctionName(funcManager, result);
			if (funcName != null && !"<unknown>".equals(funcName)) {
				pendingUpdates.add(new HydrationUpdate(i, new SearchResultEntry(result, funcName)));
			}
			if (pendingUpdates.size() >= HYDRATION_BATCH_SIZE) {
				flushHydrationBatch(searchGeneration, pendingUpdates);
				pendingUpdates = new ArrayList<>(HYDRATION_BATCH_SIZE);
			}
		}
		if (!pendingUpdates.isEmpty()) {
			flushHydrationBatch(searchGeneration, pendingUpdates);
		}
		updateStatus(buildResultCountMessage(filtered.size(), false));
	}

	private void clearResults() {
		activeSearchGeneration.incrementAndGet();
		results.clear();
		tableModel.fireTableDataChanged();
		updateStatus("Ready");
	}

	private void onSelectionChanged() {
		// Fire context change for action enablement
		contextChanged();
	}

	private void goToSelectedResult() {
		int row = resultsTable.getSelectedRow();
		if (row < 0 || row >= results.size()) {
			return;
		}

		SearchResultEntry entry = results.get(row);
		Address address = entry.getAddress();
		if (address == null || currentProgram == null) {
			return;
		}

		GoToService goToService = tool.getService(GoToService.class);
		if (goToService != null) {
			goToService.goTo(new ProgramLocation(currentProgram, address));
		}
	}

	private void showEvidenceForSelection() {
		int row = resultsTable.getSelectedRow();
		if (row < 0 || row >= results.size()) {
			return;
		}

		SearchResultEntry entry = results.get(row);
		entry.getEvidenceId().ifPresent(evidenceId -> {
			// Find or create evidence drawer provider and show evidence
			EvidenceDrawerProvider drawer = findEvidenceDrawer();
			if (drawer != null) {
				drawer.showEvidence(evidenceId);
				tool.showComponentProvider(drawer, true);
			}
		});
	}

	private void showXrefsForSelection() {
		int row = resultsTable.getSelectedRow();
		if (row < 0 || row >= results.size()) {
			return;
		}

		SearchResultEntry entry = results.get(row);
		Address address = entry.getAddress();
		if (address == null || currentProgram == null) {
			return;
		}

		// Navigate to address which will show xrefs in standard Ghidra views
		GoToService goToService = tool.getService(GoToService.class);
		if (goToService != null) {
			goToService.goTo(new ProgramLocation(currentProgram, address));
		}
	}

	private EvidenceDrawerProvider findEvidenceDrawer() {
		// Look for existing evidence drawer in tool
		for (docking.ComponentProvider provider : tool.getWindowManager()
				.getComponentProviders(EvidenceDrawerProvider.class)) {
			if (provider instanceof EvidenceDrawerProvider) {
				return (EvidenceDrawerProvider) provider;
			}
		}
		return null;
	}

	/**
	 * Returns the current search results.
	 *
	 * @return unmodifiable list of results
	 */
	public List<SearchResultEntry> getResults() {
		return Collections.unmodifiableList(results);
	}

	/**
	 * Returns the currently selected result entry.
	 *
	 * @return optional selected entry
	 */
	public Optional<SearchResultEntry> getSelectedEntry() {
		int row = resultsTable.getSelectedRow();
		if (row >= 0 && row < results.size()) {
			return Optional.of(results.get(row));
		}
		return Optional.empty();
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	/**
	 * Saves the provider state for session restoration.
	 *
	 * @param saveState the state to save to
	 */
	public void writeConfigState(SaveState saveState) {
		state.setLastQuery(searchField.getText());
		state.save(saveState);
	}

	/**
	 * Restores the provider state from a previous session.
	 *
	 * @param saveState the state to restore from
	 */
	public void readConfigState(SaveState saveState) {
		state.restore(saveState);
		searchField.setText(state.getLastQuery());
		if (state.isBudgetExhausted() && !state.getBudgetStatusMessage().isEmpty()) {
			updateStatus("Results truncated: " + state.getBudgetStatusMessage());
		}
		else {
			updateStatus("Ready");
		}
	}

	/**
	 * Returns the cockpit state for external access.
	 *
	 * @return the current state
	 */
	public CockpitState getState() {
		return state;
	}

	private List<QueryResult> filterByMinConfidence(List<QueryResult> queryResults) {
		if (state.getMinConfidence() <= 0.0) {
			return new ArrayList<>(queryResults);
		}
		List<QueryResult> filtered = new ArrayList<>();
		for (QueryResult result : queryResults) {
			if (result.getScore() >= state.getMinConfidence()) {
				filtered.add(result);
			}
		}
		return filtered;
	}

	private String resolveFunctionName(FunctionManager funcManager, QueryResult result) {
		if (funcManager == null || result.getAddress() == null) {
			return null;
		}
		Function func = funcManager.getFunctionContaining(result.getAddress());
		return func != null ? func.getName() : null;
	}

	private void flushHydrationBatch(int searchGeneration, List<HydrationUpdate> updates) {
		List<HydrationUpdate> copiedUpdates = new ArrayList<>(updates);
		SwingUtilities.invokeLater(() -> {
			if (!isSearchGenerationCurrent(searchGeneration)) {
				return;
			}
			for (HydrationUpdate update : copiedUpdates) {
				if (update.row < 0 || update.row >= results.size()) {
					continue;
				}
				results.set(update.row, update.entry);
				tableModel.fireTableRowsUpdated(update.row, update.row);
			}
		});
	}

	private boolean isSearchGenerationCurrent(int searchGeneration) {
		return searchGeneration == activeSearchGeneration.get();
	}

	private void updateStatus(String message) {
		SwingUtilities.invokeLater(() -> statusLabel.setText(message));
	}

	private String buildResultCountMessage(int count, boolean partial) {
		return partial ? String.format("Results: %d (hydrating...)", count) :
			String.format("Results: %d", count);
	}

	private LiveQueryServiceImpl.BudgetStatus consumeBudgetStatusIfAvailable() {
		if (queryService instanceof LiveQueryServiceImpl liveQueryService) {
			return liveQueryService.consumeLastSemanticSearchBudgetStatus();
		}
		return LiveQueryServiceImpl.BudgetStatus.none();
	}

	private void applyBudgetStatus(int searchGeneration, LiveQueryServiceImpl.BudgetStatus budgetStatus) {
		if (!isSearchGenerationCurrent(searchGeneration)) {
			return;
		}
		state.setBudgetExhausted(budgetStatus.isBudgetExhausted());
		state.setBudgetStatusMessage(budgetStatus.getMessage());
		if (budgetStatus.isBudgetExhausted()) {
			updateStatus("Results truncated: " + budgetStatus.getMessage());
		}
	}

	private static class HydrationUpdate {
		private final int row;
		private final SearchResultEntry entry;

		private HydrationUpdate(int row, SearchResultEntry entry) {
			this.row = row;
			this.entry = entry;
		}
	}

	/**
	 * Table model for search results.
	 */
	private class SearchResultTableModel extends AbstractTableModel {

		@Override
		public int getRowCount() {
			return results.size();
		}

		@Override
		public int getColumnCount() {
			return COLUMN_NAMES.length;
		}

		@Override
		public String getColumnName(int column) {
			return COLUMN_NAMES[column];
		}

		@Override
		public Class<?> getColumnClass(int column) {
			return switch (column) {
				case 0 -> String.class;
				case 1 -> String.class;
				case 2 -> String.class;
				case 3 -> String.class;
				default -> Object.class;
			};
		}

		@Override
		public Object getValueAt(int row, int column) {
			if (row < 0 || row >= results.size()) {
				return null;
			}
			SearchResultEntry entry = results.get(row);
			return switch (column) {
				case 0 -> entry.getAddress() != null ? entry.getAddress().toString() : "";
				case 1 -> entry.getScorePercent();
				case 2 -> entry.getFunctionName();
				case 3 -> entry.getSummary();
				default -> null;
			};
		}
	}
}
