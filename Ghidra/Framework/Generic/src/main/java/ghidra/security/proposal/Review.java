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
 * An immutable review action on a proposal by a reviewer.
 */
public final class Review {

	private final String id;
	private final String reviewer;
	private final ReviewAction action;
	private final String comment;
	private final Instant timestamp;

	private Review(Builder builder) {
		this.id = builder.id != null ? builder.id : UUID.randomUUID().toString();
		this.reviewer = Objects.requireNonNull(builder.reviewer, "reviewer is required");
		this.action = Objects.requireNonNull(builder.action, "action is required");
		this.comment = builder.comment;
		this.timestamp = builder.timestamp != null ? builder.timestamp : Instant.now();
	}

	public String getId() {
		return id;
	}

	public String getReviewer() {
		return reviewer;
	}

	public ReviewAction getAction() {
		return action;
	}

	public String getComment() {
		return comment;
	}

	public Instant getTimestamp() {
		return timestamp;
	}

	public static Builder builder() {
		return new Builder();
	}

	@Override
	public String toString() {
		return String.format("Review[%s reviewer=%s action=%s]",
			id.substring(0, Math.min(8, id.length())), reviewer, action);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof Review)) {
			return false;
		}
		Review other = (Review) obj;
		return id.equals(other.id);
	}

	@Override
	public int hashCode() {
		return id.hashCode();
	}

	public static final class Builder {
		private String id;
		private String reviewer;
		private ReviewAction action;
		private String comment;
		private Instant timestamp;

		private Builder() {
		}

		public Builder id(String id) {
			this.id = id;
			return this;
		}

		public Builder reviewer(String reviewer) {
			this.reviewer = reviewer;
			return this;
		}

		public Builder action(ReviewAction action) {
			this.action = action;
			return this;
		}

		public Builder comment(String comment) {
			this.comment = comment;
			return this;
		}

		public Builder timestamp(Instant timestamp) {
			this.timestamp = timestamp;
			return this;
		}

		public Review build() {
			return new Review(this);
		}
	}
}
