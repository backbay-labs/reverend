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
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * In-memory implementation of {@link ApplyReceiptStore}.
 * Thread-safe via concurrent data structures.
 */
public class InMemoryApplyReceiptStore implements ApplyReceiptStore {

	private final Map<String, ApplyReceipt> applyReceipts = new ConcurrentHashMap<>();
	private final Map<String, RollbackReceipt> rollbackReceipts = new ConcurrentHashMap<>();
	private final Map<String, String> rollbackByApply = new ConcurrentHashMap<>();

	@Override
	public void saveApplyReceipt(ApplyReceipt receipt) {
		Objects.requireNonNull(receipt, "receipt is required");
		applyReceipts.put(receipt.getId(), receipt);
	}

	@Override
	public void saveRollbackReceipt(RollbackReceipt receipt) {
		Objects.requireNonNull(receipt, "receipt is required");
		rollbackReceipts.put(receipt.getId(), receipt);
		rollbackByApply.put(receipt.getApplyReceiptId(), receipt.getId());

		// Update the apply receipt to mark it as rolled back
		ApplyReceipt applyReceipt = applyReceipts.get(receipt.getApplyReceiptId());
		if (applyReceipt != null) {
			applyReceipts.put(applyReceipt.getId(), applyReceipt.withRolledBack(receipt.getId()));
		}
	}

	@Override
	public Optional<ApplyReceipt> findApplyReceiptById(String receiptId) {
		return Optional.ofNullable(applyReceipts.get(receiptId));
	}

	@Override
	public Optional<RollbackReceipt> findRollbackReceiptById(String receiptId) {
		return Optional.ofNullable(rollbackReceipts.get(receiptId));
	}

	@Override
	public Optional<RollbackReceipt> findRollbackByApplyReceiptId(String applyReceiptId) {
		String rollbackId = rollbackByApply.get(applyReceiptId);
		return rollbackId != null ? Optional.ofNullable(rollbackReceipts.get(rollbackId))
			: Optional.empty();
	}

	@Override
	public List<ApplyReceipt> findApplyReceiptsByProposalId(String proposalId) {
		return applyReceipts.values().stream()
			.filter(r -> r.getProposalIds().contains(proposalId))
			.sorted(Comparator.comparing(ApplyReceipt::getAppliedAt))
			.collect(Collectors.toList());
	}

	@Override
	public List<ApplyReceipt> findApplyReceiptsByActor(String actor) {
		return applyReceipts.values().stream()
			.filter(r -> r.getActor().equals(actor))
			.sorted(Comparator.comparing(ApplyReceipt::getAppliedAt))
			.collect(Collectors.toList());
	}

	@Override
	public List<ApplyReceipt> findAllApplyReceipts() {
		return applyReceipts.values().stream()
			.sorted(Comparator.comparing(ApplyReceipt::getAppliedAt))
			.collect(Collectors.toList());
	}

	@Override
	public List<RollbackReceipt> findAllRollbackReceipts() {
		return rollbackReceipts.values().stream()
			.sorted(Comparator.comparing(RollbackReceipt::getRolledBackAt))
			.collect(Collectors.toList());
	}

	/**
	 * Clears all receipts. For testing only.
	 */
	public void clear() {
		applyReceipts.clear();
		rollbackReceipts.clear();
		rollbackByApply.clear();
	}
}
