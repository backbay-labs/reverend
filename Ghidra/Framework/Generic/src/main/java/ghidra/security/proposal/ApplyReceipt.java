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

import java.time.Instant;
import java.util.*;

/**
 * An immutable audit record for a proposal apply operation.
 * Links the apply action to its source proposals and tracks rollback state.
 *
 * <p>Based on type-lifecycle-ux.md section 5.5:
 * <ul>
 *   <li>Apply receipt and transaction journal row are committed atomically with the Program mutation</li>
 *   <li>Apply receipt always links to one or more approved proposal receipts</li>
 *   <li>Rollback receipt always links to the original apply receipt</li>
 * </ul>
 */
public final class ApplyReceipt {

	private final String id;
	private final int transactionId;
	private final String actor;
	private final List<String> proposalIds;
	private final List<String> deltaIds;
	private final Instant appliedAt;
	private final boolean rolledBack;
	private final String rollbackReceiptId;

	private ApplyReceipt(Builder builder) {
		this.id = builder.id != null ? builder.id : UUID.randomUUID().toString();
		this.transactionId = builder.transactionId;
		this.actor = Objects.requireNonNull(builder.actor, "actor is required");
		this.proposalIds = Collections.unmodifiableList(new ArrayList<>(builder.proposalIds));
		this.deltaIds = Collections.unmodifiableList(new ArrayList<>(builder.deltaIds));
		this.appliedAt = builder.appliedAt != null ? builder.appliedAt : Instant.now();
		this.rolledBack = builder.rolledBack;
		this.rollbackReceiptId = builder.rollbackReceiptId;
	}

	public String getId() {
		return id;
	}

	/**
	 * Returns the Ghidra transaction ID associated with this apply operation.
	 * This links the receipt to the undo stack for redo support.
	 *
	 * @return the transaction ID
	 */
	public int getTransactionId() {
		return transactionId;
	}

	public String getActor() {
		return actor;
	}

	/**
	 * Returns the IDs of the proposals that were applied.
	 * For single-item applies, this contains one ID; for batch applies, multiple.
	 *
	 * @return unmodifiable list of proposal IDs
	 */
	public List<String> getProposalIds() {
		return proposalIds;
	}

	/**
	 * Returns the IDs of the deltas that were applied.
	 *
	 * @return unmodifiable list of delta IDs
	 */
	public List<String> getDeltaIds() {
		return deltaIds;
	}

	public Instant getAppliedAt() {
		return appliedAt;
	}

	/**
	 * Returns whether this apply has been rolled back.
	 *
	 * @return true if rolled back
	 */
	public boolean isRolledBack() {
		return rolledBack;
	}

	/**
	 * Returns the ID of the rollback receipt if this apply was rolled back.
	 *
	 * @return the rollback receipt ID, or null if not rolled back
	 */
	public String getRollbackReceiptId() {
		return rollbackReceiptId;
	}

	/**
	 * Returns whether this was a batch apply (multiple proposals).
	 *
	 * @return true if batch apply
	 */
	public boolean isBatch() {
		return proposalIds.size() > 1;
	}

	/**
	 * Creates a copy with rollback status updated.
	 *
	 * @param rollbackReceiptId the rollback receipt ID
	 * @return new receipt marked as rolled back
	 */
	public ApplyReceipt withRolledBack(String rollbackReceiptId) {
		return toBuilder()
			.rolledBack(true)
			.rollbackReceiptId(rollbackReceiptId)
			.build();
	}

	public static Builder builder() {
		return new Builder();
	}

	public Builder toBuilder() {
		return new Builder()
			.id(id)
			.transactionId(transactionId)
			.actor(actor)
			.proposalIds(proposalIds)
			.deltaIds(deltaIds)
			.appliedAt(appliedAt)
			.rolledBack(rolledBack)
			.rollbackReceiptId(rollbackReceiptId);
	}

	@Override
	public String toString() {
		return String.format("ApplyReceipt[%s actor=%s proposals=%d rolledBack=%s]",
			id.substring(0, Math.min(8, id.length())), actor, proposalIds.size(), rolledBack);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof ApplyReceipt)) {
			return false;
		}
		ApplyReceipt other = (ApplyReceipt) obj;
		return id.equals(other.id);
	}

	@Override
	public int hashCode() {
		return id.hashCode();
	}

	public static final class Builder {
		private String id;
		private int transactionId;
		private String actor;
		private List<String> proposalIds = new ArrayList<>();
		private List<String> deltaIds = new ArrayList<>();
		private Instant appliedAt;
		private boolean rolledBack;
		private String rollbackReceiptId;

		private Builder() {
		}

		public Builder id(String id) {
			this.id = id;
			return this;
		}

		public Builder transactionId(int transactionId) {
			this.transactionId = transactionId;
			return this;
		}

		public Builder actor(String actor) {
			this.actor = actor;
			return this;
		}

		public Builder proposalId(String proposalId) {
			this.proposalIds.add(proposalId);
			return this;
		}

		public Builder proposalIds(List<String> proposalIds) {
			this.proposalIds = new ArrayList<>(proposalIds);
			return this;
		}

		public Builder deltaId(String deltaId) {
			this.deltaIds.add(deltaId);
			return this;
		}

		public Builder deltaIds(List<String> deltaIds) {
			this.deltaIds = new ArrayList<>(deltaIds);
			return this;
		}

		public Builder appliedAt(Instant appliedAt) {
			this.appliedAt = appliedAt;
			return this;
		}

		public Builder rolledBack(boolean rolledBack) {
			this.rolledBack = rolledBack;
			return this;
		}

		public Builder rollbackReceiptId(String rollbackReceiptId) {
			this.rollbackReceiptId = rollbackReceiptId;
			return this;
		}

		public ApplyReceipt build() {
			return new ApplyReceipt(this);
		}
	}
}
