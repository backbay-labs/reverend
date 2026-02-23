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

import org.junit.Before;
import org.junit.Test;

import ghidra.framework.options.SaveState;

/**
 * Unit tests for {@link CockpitState}.
 */
public class CockpitStateTest {

	private CockpitState state;

	@Before
	public void setUp() {
		state = new CockpitState();
	}

	@Test
	public void testDefaultValues() {
		assertEquals("", state.getLastQuery());
		assertEquals(50, state.getMaxResults());
		assertEquals(0.0, state.getMinConfidence(), 0.001);
		assertEquals("", state.getEvidenceFilter());
		assertEquals(1, state.getSortColumn());
		assertFalse(state.isSortAscending());
		assertTrue(state.getSelectedEvidenceIds().isEmpty());
		assertTrue(state.isEvidenceDrawerVisible());
		assertEquals("hierarchical", state.getGraphLayoutMode());
		assertFalse(state.isBudgetExhausted());
		assertEquals("", state.getBudgetStatusMessage());
		assertEquals(CockpitState.OperationStatus.IDLE, state.getSearchOperationStatus());
		assertEquals("", state.getSearchOperationMessage());
		assertEquals(CockpitState.OperationStatus.IDLE, state.getEvidenceOperationStatus());
		assertEquals("", state.getEvidenceOperationMessage());
		assertEquals(CockpitState.OperationStatus.IDLE, state.getProposalOperationStatus());
		assertEquals("", state.getProposalOperationMessage());
	}

	@Test
	public void testSetLastQuery() {
		state.setLastQuery("test query");
		assertEquals("test query", state.getLastQuery());

		state.setLastQuery(null);
		assertEquals("", state.getLastQuery());
	}

	@Test
	public void testSetMaxResults() {
		state.setMaxResults(100);
		assertEquals(100, state.getMaxResults());

		// Test clamping
		state.setMaxResults(0);
		assertEquals(1, state.getMaxResults());

		state.setMaxResults(2000);
		assertEquals(1000, state.getMaxResults());
	}

	@Test
	public void testSetMinConfidence() {
		state.setMinConfidence(0.5);
		assertEquals(0.5, state.getMinConfidence(), 0.001);

		// Test clamping
		state.setMinConfidence(-0.5);
		assertEquals(0.0, state.getMinConfidence(), 0.001);

		state.setMinConfidence(1.5);
		assertEquals(1.0, state.getMinConfidence(), 0.001);
	}

	@Test
	public void testSetEvidenceFilter() {
		state.setEvidenceFilter("STATIC");
		assertEquals("STATIC", state.getEvidenceFilter());

		state.setEvidenceFilter(null);
		assertEquals("", state.getEvidenceFilter());
	}

	@Test
	public void testSetSortColumn() {
		state.setSortColumn(3);
		assertEquals(3, state.getSortColumn());
	}

	@Test
	public void testSetSortAscending() {
		state.setSortAscending(true);
		assertTrue(state.isSortAscending());

		state.setSortAscending(false);
		assertFalse(state.isSortAscending());
	}

	@Test
	public void testSetSelectedEvidenceIds() {
		List<String> ids = List.of("ev-1", "ev-2", "ev-3");
		state.setSelectedEvidenceIds(ids);

		List<String> result = state.getSelectedEvidenceIds();
		assertEquals(3, result.size());
		assertTrue(result.contains("ev-1"));
		assertTrue(result.contains("ev-2"));
		assertTrue(result.contains("ev-3"));

		// Verify defensive copy
		assertNotSame(ids, result);
	}

	@Test
	public void testSetSelectedEvidenceIdsNull() {
		state.setSelectedEvidenceIds(null);
		assertTrue(state.getSelectedEvidenceIds().isEmpty());
	}

	@Test
	public void testSetEvidenceDrawerVisible() {
		state.setEvidenceDrawerVisible(false);
		assertFalse(state.isEvidenceDrawerVisible());

		state.setEvidenceDrawerVisible(true);
		assertTrue(state.isEvidenceDrawerVisible());
	}

	@Test
	public void testSetGraphLayoutMode() {
		state.setGraphLayoutMode("force-directed");
		assertEquals("force-directed", state.getGraphLayoutMode());

		state.setGraphLayoutMode(null);
		assertEquals("hierarchical", state.getGraphLayoutMode());
	}

	@Test
	public void testSaveAndRestore() {
		// Set up state with non-default values
		state.setLastQuery("encryption function");
		state.setMaxResults(75);
		state.setMinConfidence(0.8);
		state.setEvidenceFilter("MODEL_INFERENCE");
		state.setSortColumn(2);
		state.setSortAscending(true);
		state.setSelectedEvidenceIds(List.of("id-a", "id-b"));
		state.setEvidenceDrawerVisible(false);
		state.setGraphLayoutMode("circular");
		state.setBudgetExhausted(true);
		state.setBudgetStatusMessage("decompile budget exhausted");
		state.setSearchOperationStatus(CockpitState.OperationStatus.SUCCESS);
		state.setSearchOperationMessage("ok");
		state.setEvidenceOperationStatus(CockpitState.OperationStatus.LOADING);
		state.setEvidenceOperationMessage("loading");
		state.setProposalOperationStatus(CockpitState.OperationStatus.ERROR);
		state.setProposalOperationMessage("failed");

		// Save to SaveState
		SaveState saveState = new SaveState();
		state.save(saveState);

		// Restore to new state object
		CockpitState restored = new CockpitState(saveState);

		// Verify all values match
		assertEquals("encryption function", restored.getLastQuery());
		assertEquals(75, restored.getMaxResults());
		assertEquals(0.8, restored.getMinConfidence(), 0.001);
		assertEquals("MODEL_INFERENCE", restored.getEvidenceFilter());
		assertEquals(2, restored.getSortColumn());
		assertTrue(restored.isSortAscending());
		assertEquals(2, restored.getSelectedEvidenceIds().size());
		assertTrue(restored.getSelectedEvidenceIds().contains("id-a"));
		assertFalse(restored.isEvidenceDrawerVisible());
		assertEquals("circular", restored.getGraphLayoutMode());
		assertTrue(restored.isBudgetExhausted());
		assertEquals("decompile budget exhausted", restored.getBudgetStatusMessage());
		assertEquals(CockpitState.OperationStatus.SUCCESS, restored.getSearchOperationStatus());
		assertEquals("ok", restored.getSearchOperationMessage());
		assertEquals(CockpitState.OperationStatus.LOADING, restored.getEvidenceOperationStatus());
		assertEquals("loading", restored.getEvidenceOperationMessage());
		assertEquals(CockpitState.OperationStatus.ERROR, restored.getProposalOperationStatus());
		assertEquals("failed", restored.getProposalOperationMessage());
	}

	@Test
	public void testRestoreFromEmptySaveState() {
		SaveState emptyState = new SaveState();
		CockpitState restored = new CockpitState(emptyState);

		// Should have default values
		assertEquals("", restored.getLastQuery());
		assertEquals(50, restored.getMaxResults());
		assertEquals(0.0, restored.getMinConfidence(), 0.001);
	}

	@Test(expected = NullPointerException.class)
	public void testConstructorNullSaveState() {
		new CockpitState(null);
	}
}
