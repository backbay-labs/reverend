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

import java.util.List;
import java.util.Optional;

/**
 * Storage interface for apply and rollback receipts.
 * Provides audit trail persistence for transaction-safe proposal operations.
 *
 * <p>Based on type-lifecycle-ux.md section 5.5, receipts must:
 * <ul>
 *   <li>Be committed atomically with the Program mutation</li>
 *   <li>Link apply receipts to proposal receipts</li>
 *   <li>Link rollback receipts to apply receipts</li>
 *   <li>Survive apply and rollback paths</li>
 * </ul>
 */
public interface ApplyReceiptStore {

	/**
	 * Saves an apply receipt.
	 *
	 * @param receipt the receipt to save
	 */
	void saveApplyReceipt(ApplyReceipt receipt);

	/**
	 * Saves a rollback receipt and updates the linked apply receipt.
	 *
	 * @param receipt the rollback receipt to save
	 */
	void saveRollbackReceipt(RollbackReceipt receipt);

	/**
	 * Retrieves an apply receipt by ID.
	 *
	 * @param receiptId the receipt ID
	 * @return the receipt, or empty if not found
	 */
	Optional<ApplyReceipt> findApplyReceiptById(String receiptId);

	/**
	 * Retrieves a rollback receipt by ID.
	 *
	 * @param receiptId the receipt ID
	 * @return the receipt, or empty if not found
	 */
	Optional<RollbackReceipt> findRollbackReceiptById(String receiptId);

	/**
	 * Retrieves the rollback receipt for an apply receipt, if it was rolled back.
	 *
	 * @param applyReceiptId the apply receipt ID
	 * @return the rollback receipt, or empty if not rolled back
	 */
	Optional<RollbackReceipt> findRollbackByApplyReceiptId(String applyReceiptId);

	/**
	 * Retrieves all apply receipts for a proposal.
	 *
	 * @param proposalId the proposal ID
	 * @return list of apply receipts involving this proposal
	 */
	List<ApplyReceipt> findApplyReceiptsByProposalId(String proposalId);

	/**
	 * Retrieves all apply receipts by actor.
	 *
	 * @param actor the actor identifier
	 * @return list of apply receipts by this actor
	 */
	List<ApplyReceipt> findApplyReceiptsByActor(String actor);

	/**
	 * Retrieves all apply receipts.
	 *
	 * @return all apply receipts, ordered by applied time ascending
	 */
	List<ApplyReceipt> findAllApplyReceipts();

	/**
	 * Retrieves all rollback receipts.
	 *
	 * @return all rollback receipts, ordered by rolled back time ascending
	 */
	List<RollbackReceipt> findAllRollbackReceipts();
}
