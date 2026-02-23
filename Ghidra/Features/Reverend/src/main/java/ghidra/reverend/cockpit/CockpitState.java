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

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import ghidra.framework.options.SaveState;

/**
 * Serializable state for cockpit providers.
 *
 * <p>This class captures all UI state that should persist across sessions,
 * including search queries, filter settings, and column configurations.
 */
public class CockpitState {

	private static final String KEY_LAST_QUERY = "lastQuery";
	private static final String KEY_MAX_RESULTS = "maxResults";
	private static final String KEY_MIN_CONFIDENCE = "minConfidence";
	private static final String KEY_EVIDENCE_FILTER = "evidenceFilter";
	private static final String KEY_SORT_COLUMN = "sortColumn";
	private static final String KEY_SORT_ASCENDING = "sortAscending";
	private static final String KEY_SELECTED_EVIDENCE_IDS = "selectedEvidenceIds";
	private static final String KEY_EVIDENCE_DRAWER_VISIBLE = "evidenceDrawerVisible";
	private static final String KEY_GRAPH_LAYOUT_MODE = "graphLayoutMode";
	private static final String KEY_BUDGET_EXHAUSTED = "budgetExhausted";
	private static final String KEY_BUDGET_STATUS_MESSAGE = "budgetStatusMessage";
	private static final String KEY_SEARCH_OPERATION_STATUS = "searchOperationStatus";
	private static final String KEY_SEARCH_OPERATION_MESSAGE = "searchOperationMessage";
	private static final String KEY_EVIDENCE_OPERATION_STATUS = "evidenceOperationStatus";
	private static final String KEY_EVIDENCE_OPERATION_MESSAGE = "evidenceOperationMessage";
	private static final String KEY_PROPOSAL_OPERATION_STATUS = "proposalOperationStatus";
	private static final String KEY_PROPOSAL_OPERATION_MESSAGE = "proposalOperationMessage";

	private String lastQuery = "";
	private int maxResults = 50;
	private double minConfidence = 0.0;
	private String evidenceFilter = "";
	private int sortColumn = 1;
	private boolean sortAscending = false;
	private List<String> selectedEvidenceIds = new ArrayList<>();
	private boolean evidenceDrawerVisible = true;
	private String graphLayoutMode = "hierarchical";
	private boolean budgetExhausted = false;
	private String budgetStatusMessage = "";
	private OperationStatus searchOperationStatus = OperationStatus.IDLE;
	private String searchOperationMessage = "";
	private OperationStatus evidenceOperationStatus = OperationStatus.IDLE;
	private String evidenceOperationMessage = "";
	private OperationStatus proposalOperationStatus = OperationStatus.IDLE;
	private String proposalOperationMessage = "";

	/**
	 * Creates a new state with default values.
	 */
	public CockpitState() {
	}

	/**
	 * Creates a state by reading from a SaveState.
	 *
	 * @param saveState the saved state to read from
	 */
	public CockpitState(SaveState saveState) {
		Objects.requireNonNull(saveState, "saveState cannot be null");
		restore(saveState);
	}

	/**
	 * Saves this state to a SaveState object.
	 *
	 * @param saveState the state object to save to
	 */
	public void save(SaveState saveState) {
		saveState.putString(KEY_LAST_QUERY, lastQuery);
		saveState.putInt(KEY_MAX_RESULTS, maxResults);
		saveState.putDouble(KEY_MIN_CONFIDENCE, minConfidence);
		saveState.putString(KEY_EVIDENCE_FILTER, evidenceFilter);
		saveState.putInt(KEY_SORT_COLUMN, sortColumn);
		saveState.putBoolean(KEY_SORT_ASCENDING, sortAscending);
		saveState.putStrings(KEY_SELECTED_EVIDENCE_IDS,
			selectedEvidenceIds.toArray(new String[0]));
		saveState.putBoolean(KEY_EVIDENCE_DRAWER_VISIBLE, evidenceDrawerVisible);
		saveState.putString(KEY_GRAPH_LAYOUT_MODE, graphLayoutMode);
		saveState.putBoolean(KEY_BUDGET_EXHAUSTED, budgetExhausted);
		saveState.putString(KEY_BUDGET_STATUS_MESSAGE, budgetStatusMessage);
		saveState.putString(KEY_SEARCH_OPERATION_STATUS, searchOperationStatus.name());
		saveState.putString(KEY_SEARCH_OPERATION_MESSAGE, searchOperationMessage);
		saveState.putString(KEY_EVIDENCE_OPERATION_STATUS, evidenceOperationStatus.name());
		saveState.putString(KEY_EVIDENCE_OPERATION_MESSAGE, evidenceOperationMessage);
		saveState.putString(KEY_PROPOSAL_OPERATION_STATUS, proposalOperationStatus.name());
		saveState.putString(KEY_PROPOSAL_OPERATION_MESSAGE, proposalOperationMessage);
	}

	/**
	 * Restores this state from a SaveState object.
	 *
	 * @param saveState the state object to restore from
	 */
	public void restore(SaveState saveState) {
		lastQuery = saveState.getString(KEY_LAST_QUERY, "");
		maxResults = saveState.getInt(KEY_MAX_RESULTS, 50);
		minConfidence = saveState.getDouble(KEY_MIN_CONFIDENCE, 0.0);
		evidenceFilter = saveState.getString(KEY_EVIDENCE_FILTER, "");
		sortColumn = saveState.getInt(KEY_SORT_COLUMN, 1);
		sortAscending = saveState.getBoolean(KEY_SORT_ASCENDING, false);
		String[] ids = saveState.getStrings(KEY_SELECTED_EVIDENCE_IDS, new String[0]);
		selectedEvidenceIds = new ArrayList<>(List.of(ids));
		evidenceDrawerVisible = saveState.getBoolean(KEY_EVIDENCE_DRAWER_VISIBLE, true);
		graphLayoutMode = saveState.getString(KEY_GRAPH_LAYOUT_MODE, "hierarchical");
		budgetExhausted = saveState.getBoolean(KEY_BUDGET_EXHAUSTED, false);
		budgetStatusMessage = saveState.getString(KEY_BUDGET_STATUS_MESSAGE, "");
		searchOperationStatus = parseStatus(
			saveState.getString(KEY_SEARCH_OPERATION_STATUS, OperationStatus.IDLE.name()));
		searchOperationMessage = saveState.getString(KEY_SEARCH_OPERATION_MESSAGE, "");
		evidenceOperationStatus = parseStatus(
			saveState.getString(KEY_EVIDENCE_OPERATION_STATUS, OperationStatus.IDLE.name()));
		evidenceOperationMessage = saveState.getString(KEY_EVIDENCE_OPERATION_MESSAGE, "");
		proposalOperationStatus = parseStatus(
			saveState.getString(KEY_PROPOSAL_OPERATION_STATUS, OperationStatus.IDLE.name()));
		proposalOperationMessage = saveState.getString(KEY_PROPOSAL_OPERATION_MESSAGE, "");
	}

	public String getLastQuery() {
		return lastQuery;
	}

	public void setLastQuery(String lastQuery) {
		this.lastQuery = lastQuery != null ? lastQuery : "";
	}

	public int getMaxResults() {
		return maxResults;
	}

	public void setMaxResults(int maxResults) {
		this.maxResults = Math.max(1, Math.min(1000, maxResults));
	}

	public double getMinConfidence() {
		return minConfidence;
	}

	public void setMinConfidence(double minConfidence) {
		this.minConfidence = Math.max(0.0, Math.min(1.0, minConfidence));
	}

	public String getEvidenceFilter() {
		return evidenceFilter;
	}

	public void setEvidenceFilter(String evidenceFilter) {
		this.evidenceFilter = evidenceFilter != null ? evidenceFilter : "";
	}

	public int getSortColumn() {
		return sortColumn;
	}

	public void setSortColumn(int sortColumn) {
		this.sortColumn = sortColumn;
	}

	public boolean isSortAscending() {
		return sortAscending;
	}

	public void setSortAscending(boolean sortAscending) {
		this.sortAscending = sortAscending;
	}

	public List<String> getSelectedEvidenceIds() {
		return new ArrayList<>(selectedEvidenceIds);
	}

	public void setSelectedEvidenceIds(List<String> selectedEvidenceIds) {
		this.selectedEvidenceIds =
			selectedEvidenceIds != null ? new ArrayList<>(selectedEvidenceIds) : new ArrayList<>();
	}

	public boolean isEvidenceDrawerVisible() {
		return evidenceDrawerVisible;
	}

	public void setEvidenceDrawerVisible(boolean evidenceDrawerVisible) {
		this.evidenceDrawerVisible = evidenceDrawerVisible;
	}

	public String getGraphLayoutMode() {
		return graphLayoutMode;
	}

	public void setGraphLayoutMode(String graphLayoutMode) {
		this.graphLayoutMode = graphLayoutMode != null ? graphLayoutMode : "hierarchical";
	}

	public boolean isBudgetExhausted() {
		return budgetExhausted;
	}

	public void setBudgetExhausted(boolean budgetExhausted) {
		this.budgetExhausted = budgetExhausted;
	}

	public String getBudgetStatusMessage() {
		return budgetStatusMessage;
	}

	public void setBudgetStatusMessage(String budgetStatusMessage) {
		this.budgetStatusMessage = budgetStatusMessage != null ? budgetStatusMessage : "";
	}

	public OperationStatus getSearchOperationStatus() {
		return searchOperationStatus;
	}

	public void setSearchOperationStatus(OperationStatus searchOperationStatus) {
		this.searchOperationStatus =
			searchOperationStatus != null ? searchOperationStatus : OperationStatus.IDLE;
	}

	public String getSearchOperationMessage() {
		return searchOperationMessage;
	}

	public void setSearchOperationMessage(String searchOperationMessage) {
		this.searchOperationMessage = searchOperationMessage != null ? searchOperationMessage : "";
	}

	public OperationStatus getEvidenceOperationStatus() {
		return evidenceOperationStatus;
	}

	public void setEvidenceOperationStatus(OperationStatus evidenceOperationStatus) {
		this.evidenceOperationStatus =
			evidenceOperationStatus != null ? evidenceOperationStatus : OperationStatus.IDLE;
	}

	public String getEvidenceOperationMessage() {
		return evidenceOperationMessage;
	}

	public void setEvidenceOperationMessage(String evidenceOperationMessage) {
		this.evidenceOperationMessage =
			evidenceOperationMessage != null ? evidenceOperationMessage : "";
	}

	public OperationStatus getProposalOperationStatus() {
		return proposalOperationStatus;
	}

	public void setProposalOperationStatus(OperationStatus proposalOperationStatus) {
		this.proposalOperationStatus =
			proposalOperationStatus != null ? proposalOperationStatus : OperationStatus.IDLE;
	}

	public String getProposalOperationMessage() {
		return proposalOperationMessage;
	}

	public void setProposalOperationMessage(String proposalOperationMessage) {
		this.proposalOperationMessage =
			proposalOperationMessage != null ? proposalOperationMessage : "";
	}

	private static OperationStatus parseStatus(String raw) {
		try {
			return OperationStatus.valueOf(raw);
		}
		catch (IllegalArgumentException e) {
			return OperationStatus.IDLE;
		}
	}

	public enum OperationStatus {
		IDLE,
		LOADING,
		SUCCESS,
		ERROR
	}
}
