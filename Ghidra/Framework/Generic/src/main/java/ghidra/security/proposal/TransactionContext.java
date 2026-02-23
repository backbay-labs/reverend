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

/**
 * Abstraction for transaction boundaries that supports atomic apply/revert operations.
 * This interface allows proposal operations to participate in Ghidra's undo/redo stack
 * while remaining testable without a full Program database.
 *
 * <p>Implementations must guarantee:
 * <ul>
 *   <li>All changes between {@code startTransaction} and a successful {@code endTransaction}
 *       are committed atomically</li>
 *   <li>On rollback (commit=false), all changes are discarded</li>
 *   <li>Committed transactions can be undone via the undo stack</li>
 * </ul>
 *
 * <p>Based on type-lifecycle-ux.md section 5.1 and 5.5.
 */
public interface TransactionContext {

	/**
	 * Starts a new transaction with the given description.
	 * The description appears in the undo history.
	 *
	 * @param description human-readable description of the transaction
	 * @return a transaction ID that must be passed to {@code endTransaction}
	 */
	int startTransaction(String description);

	/**
	 * Ends a transaction, either committing or rolling back all changes.
	 *
	 * @param transactionId the ID returned by {@code startTransaction}
	 * @param commit true to commit changes, false to discard them
	 */
	void endTransaction(int transactionId, boolean commit);

	/**
	 * Undoes the last committed transaction.
	 *
	 * @return true if undo was successful, false if nothing to undo
	 */
	boolean undo();

	/**
	 * Redoes the last undone transaction.
	 *
	 * @return true if redo was successful, false if nothing to redo
	 */
	boolean redo();

	/**
	 * Returns whether there is a transaction that can be undone.
	 *
	 * @return true if undo is available
	 */
	boolean canUndo();

	/**
	 * Returns whether there is a transaction that can be redone.
	 *
	 * @return true if redo is available
	 */
	boolean canRedo();

	/**
	 * Returns the name of the transaction that would be undone.
	 *
	 * @return the undo transaction name, or null if nothing to undo
	 */
	String getUndoName();

	/**
	 * Returns the name of the transaction that would be redone.
	 *
	 * @return the redo transaction name, or null if nothing to redo
	 */
	String getRedoName();
}
