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
import java.util.Objects;
import java.util.UUID;

/**
 * An immutable audit record for a proposal rollback operation.
 * Links the rollback to its original apply receipt for audit trail continuity.
 *
 * <p>Based on type-lifecycle-ux.md section 5.5:
 * <ul>
 *   <li>Rollback receipt always links to the original apply receipt</li>
 *   <li>Repeated rollback calls are idempotent</li>
 * </ul>
 */
public final class RollbackReceipt {

	private final String id;
	private final int transactionId;
	private final String applyReceiptId;
	private final String actor;
	private final String reason;
	private final Instant rolledBackAt;

	private RollbackReceipt(Builder builder) {
		this.id = builder.id != null ? builder.id : UUID.randomUUID().toString();
		this.transactionId = builder.transactionId;
		this.applyReceiptId = Objects.requireNonNull(builder.applyReceiptId,
			"applyReceiptId is required");
		this.actor = Objects.requireNonNull(builder.actor, "actor is required");
		this.reason = builder.reason;
		this.rolledBackAt = builder.rolledBackAt != null ? builder.rolledBackAt : Instant.now();
	}

	public String getId() {
		return id;
	}

	/**
	 * Returns the Ghidra transaction ID for this rollback operation.
	 *
	 * @return the transaction ID
	 */
	public int getTransactionId() {
		return transactionId;
	}

	/**
	 * Returns the ID of the apply receipt that was rolled back.
	 * This creates the bidirectional audit link between apply and rollback.
	 *
	 * @return the apply receipt ID
	 */
	public String getApplyReceiptId() {
		return applyReceiptId;
	}

	public String getActor() {
		return actor;
	}

	/**
	 * Returns the reason for the rollback, if provided.
	 *
	 * @return the rollback reason, or null
	 */
	public String getReason() {
		return reason;
	}

	public Instant getRolledBackAt() {
		return rolledBackAt;
	}

	public static Builder builder() {
		return new Builder();
	}

	@Override
	public String toString() {
		return String.format("RollbackReceipt[%s applyReceipt=%s actor=%s]",
			id.substring(0, Math.min(8, id.length())),
			applyReceiptId.substring(0, Math.min(8, applyReceiptId.length())),
			actor);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof RollbackReceipt)) {
			return false;
		}
		RollbackReceipt other = (RollbackReceipt) obj;
		return id.equals(other.id);
	}

	@Override
	public int hashCode() {
		return id.hashCode();
	}

	public static final class Builder {
		private String id;
		private int transactionId;
		private String applyReceiptId;
		private String actor;
		private String reason;
		private Instant rolledBackAt;

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

		public Builder applyReceiptId(String applyReceiptId) {
			this.applyReceiptId = applyReceiptId;
			return this;
		}

		public Builder actor(String actor) {
			this.actor = actor;
			return this;
		}

		public Builder reason(String reason) {
			this.reason = reason;
			return this;
		}

		public Builder rolledBackAt(Instant rolledBackAt) {
			this.rolledBackAt = rolledBackAt;
			return this;
		}

		public RollbackReceipt build() {
			return new RollbackReceipt(this);
		}
	}
}
