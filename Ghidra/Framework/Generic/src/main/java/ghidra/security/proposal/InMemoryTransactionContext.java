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
package ghidra.security.proposal;

import java.util.*;

/**
 * In-memory implementation of {@link TransactionContext} for testing.
 * Tracks transaction history and supports undo/redo operations.
 *
 * <p>This implementation stores snapshots of registered state providers,
 * allowing tests to verify transaction atomicity without a full Program database.
 */
public class InMemoryTransactionContext implements TransactionContext {

	private final List<Transaction> undoStack = new ArrayList<>();
	private final List<Transaction> redoStack = new ArrayList<>();
	private final List<StateProvider> stateProviders = new ArrayList<>();
	private final Map<Integer, PendingTransaction> pendingTransactions = new HashMap<>();
	private int nextTransactionId = 1;

	/**
	 * Registers a state provider whose state will be snapshotted for undo/redo.
	 *
	 * @param provider the state provider to register
	 */
	public void registerStateProvider(StateProvider provider) {
		stateProviders.add(provider);
	}

	@Override
	public int startTransaction(String description) {
		int txId = nextTransactionId++;
		Map<StateProvider, Object> beforeState = captureState();
		pendingTransactions.put(txId, new PendingTransaction(description, beforeState));
		return txId;
	}

	@Override
	public void endTransaction(int transactionId, boolean commit) {
		PendingTransaction pending = pendingTransactions.remove(transactionId);
		if (pending == null) {
			throw new IllegalArgumentException("No pending transaction with id: " + transactionId);
		}

		if (commit) {
			Map<StateProvider, Object> afterState = captureState();
			undoStack.add(new Transaction(pending.description, pending.beforeState, afterState));
			redoStack.clear();
		}
		else {
			restoreState(pending.beforeState);
		}
	}

	@Override
	public boolean undo() {
		if (undoStack.isEmpty()) {
			return false;
		}
		Transaction tx = undoStack.remove(undoStack.size() - 1);
		restoreState(tx.beforeState);
		redoStack.add(tx);
		return true;
	}

	@Override
	public boolean redo() {
		if (redoStack.isEmpty()) {
			return false;
		}
		Transaction tx = redoStack.remove(redoStack.size() - 1);
		restoreState(tx.afterState);
		undoStack.add(tx);
		return true;
	}

	@Override
	public boolean canUndo() {
		return !undoStack.isEmpty();
	}

	@Override
	public boolean canRedo() {
		return !redoStack.isEmpty();
	}

	@Override
	public String getUndoName() {
		return undoStack.isEmpty() ? null : undoStack.get(undoStack.size() - 1).description;
	}

	@Override
	public String getRedoName() {
		return redoStack.isEmpty() ? null : redoStack.get(redoStack.size() - 1).description;
	}

	/**
	 * Returns the number of committed transactions in the undo stack.
	 *
	 * @return the undo stack size
	 */
	public int getUndoStackSize() {
		return undoStack.size();
	}

	/**
	 * Returns the number of undone transactions in the redo stack.
	 *
	 * @return the redo stack size
	 */
	public int getRedoStackSize() {
		return redoStack.size();
	}

	private Map<StateProvider, Object> captureState() {
		Map<StateProvider, Object> state = new HashMap<>();
		for (StateProvider provider : stateProviders) {
			state.put(provider, provider.captureState());
		}
		return state;
	}

	@SuppressWarnings("unchecked")
	private void restoreState(Map<StateProvider, Object> state) {
		for (StateProvider provider : stateProviders) {
			Object snapshot = state.get(provider);
			if (snapshot != null) {
				provider.restoreState(snapshot);
			}
		}
	}

	/**
	 * Interface for components that can have their state captured and restored.
	 */
	public interface StateProvider {
		/**
		 * Captures the current state as a snapshot.
		 *
		 * @return an opaque state snapshot
		 */
		Object captureState();

		/**
		 * Restores state from a snapshot.
		 *
		 * @param state the snapshot to restore from
		 */
		void restoreState(Object state);
	}

	private static class PendingTransaction {
		final String description;
		final Map<StateProvider, Object> beforeState;

		PendingTransaction(String description, Map<StateProvider, Object> beforeState) {
			this.description = description;
			this.beforeState = beforeState;
		}
	}

	private static class Transaction {
		final String description;
		final Map<StateProvider, Object> beforeState;
		final Map<StateProvider, Object> afterState;

		Transaction(String description, Map<StateProvider, Object> beforeState,
				Map<StateProvider, Object> afterState) {
			this.description = description;
			this.beforeState = beforeState;
			this.afterState = afterState;
		}
	}
}
