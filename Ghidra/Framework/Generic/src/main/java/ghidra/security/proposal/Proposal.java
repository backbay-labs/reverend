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
 * An immutable proposal representing a set of annotation changes submitted for review.
 * Proposals follow the lifecycle defined in {@link ProposalState}:
 * DRAFT -> OPEN -> UNDER_REVIEW -> APPROVED -> MERGED (or REJECTED/WITHDRAWN).
 *
 * <p>Only APPROVED proposals can enter the apply/merge workflow.
 *
 * <p>Based on the AnnotationChangeset model from collaboration-review-design.md section 1
 * and the Type PR concept from type-lifecycle-ux.md section 4.
 */
public final class Proposal {

	private final String id;
	private final String title;
	private final String description;
	private final String author;
	private final String programId;
	private final ProposalState state;
	private final Instant createdAt;
	private final Instant updatedAt;
	private final List<ProposalDelta> deltas;
	private final List<Review> reviews;
	private final int requiredApprovals;
	private final Map<String, String> metadata;

	private Proposal(Builder builder) {
		this.id = builder.id != null ? builder.id : UUID.randomUUID().toString();
		this.title = Objects.requireNonNull(builder.title, "title is required");
		this.description = builder.description != null ? builder.description : "";
		this.author = Objects.requireNonNull(builder.author, "author is required");
		this.programId = builder.programId;
		this.state = builder.state != null ? builder.state : ProposalState.DRAFT;
		this.createdAt = builder.createdAt != null ? builder.createdAt : Instant.now();
		this.updatedAt = builder.updatedAt != null ? builder.updatedAt : this.createdAt;
		this.deltas = Collections.unmodifiableList(new ArrayList<>(builder.deltas));
		this.reviews = Collections.unmodifiableList(new ArrayList<>(builder.reviews));
		this.requiredApprovals = builder.requiredApprovals;
		this.metadata = Collections.unmodifiableMap(new LinkedHashMap<>(builder.metadata));
	}

	public String getId() {
		return id;
	}

	public String getTitle() {
		return title;
	}

	public String getDescription() {
		return description;
	}

	public String getAuthor() {
		return author;
	}

	public String getProgramId() {
		return programId;
	}

	public ProposalState getState() {
		return state;
	}

	public Instant getCreatedAt() {
		return createdAt;
	}

	public Instant getUpdatedAt() {
		return updatedAt;
	}

	public List<ProposalDelta> getDeltas() {
		return deltas;
	}

	public List<Review> getReviews() {
		return reviews;
	}

	public int getRequiredApprovals() {
		return requiredApprovals;
	}

	public Map<String, String> getMetadata() {
		return metadata;
	}

	/**
	 * Returns the number of approvals received.
	 * @return count of APPROVE reviews
	 */
	public int getApprovalCount() {
		int count = 0;
		for (Review r : reviews) {
			if (r.getAction() == ReviewAction.APPROVE) {
				count++;
			}
		}
		return count;
	}

	/**
	 * Returns whether this proposal has met its approval threshold.
	 * @return true if approval count >= required approvals
	 */
	public boolean hasMetApprovalThreshold() {
		return getApprovalCount() >= requiredApprovals;
	}

	/**
	 * Returns whether this proposal can enter the apply/merge workflow.
	 * Only APPROVED proposals can be applied.
	 * @return true if this proposal is approved
	 */
	public boolean canApply() {
		return state.canApply();
	}

	/**
	 * Creates a copy of this proposal with a new state and updated timestamp.
	 * @param newState the new state
	 * @return a new proposal with the updated state
	 */
	public Proposal withState(ProposalState newState) {
		return toBuilder()
			.state(newState)
			.updatedAt(Instant.now())
			.build();
	}

	/**
	 * Creates a copy of this proposal with an additional review.
	 * @param review the review to add
	 * @return a new proposal with the added review
	 */
	public Proposal withReview(Review review) {
		List<Review> newReviews = new ArrayList<>(this.reviews);
		newReviews.add(review);
		return toBuilder()
			.reviews(newReviews)
			.updatedAt(Instant.now())
			.build();
	}

	public static Builder builder() {
		return new Builder();
	}

	public Builder toBuilder() {
		return new Builder()
			.id(id)
			.title(title)
			.description(description)
			.author(author)
			.programId(programId)
			.state(state)
			.createdAt(createdAt)
			.updatedAt(updatedAt)
			.deltas(deltas)
			.reviews(reviews)
			.requiredApprovals(requiredApprovals)
			.metadata(metadata);
	}

	@Override
	public String toString() {
		return String.format("Proposal[%s title=%s state=%s author=%s deltas=%d]",
			id.substring(0, Math.min(8, id.length())), title, state, author, deltas.size());
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof Proposal)) {
			return false;
		}
		Proposal other = (Proposal) obj;
		return id.equals(other.id);
	}

	@Override
	public int hashCode() {
		return id.hashCode();
	}

	public static final class Builder {
		private String id;
		private String title;
		private String description;
		private String author;
		private String programId;
		private ProposalState state;
		private Instant createdAt;
		private Instant updatedAt;
		private List<ProposalDelta> deltas = new ArrayList<>();
		private List<Review> reviews = new ArrayList<>();
		private int requiredApprovals = 1;
		private Map<String, String> metadata = new LinkedHashMap<>();

		private Builder() {
		}

		public Builder id(String id) {
			this.id = id;
			return this;
		}

		public Builder title(String title) {
			this.title = title;
			return this;
		}

		public Builder description(String description) {
			this.description = description;
			return this;
		}

		public Builder author(String author) {
			this.author = author;
			return this;
		}

		public Builder programId(String programId) {
			this.programId = programId;
			return this;
		}

		public Builder state(ProposalState state) {
			this.state = state;
			return this;
		}

		public Builder createdAt(Instant createdAt) {
			this.createdAt = createdAt;
			return this;
		}

		public Builder updatedAt(Instant updatedAt) {
			this.updatedAt = updatedAt;
			return this;
		}

		public Builder delta(ProposalDelta delta) {
			this.deltas.add(delta);
			return this;
		}

		public Builder deltas(List<ProposalDelta> deltas) {
			this.deltas = new ArrayList<>(deltas);
			return this;
		}

		public Builder review(Review review) {
			this.reviews.add(review);
			return this;
		}

		public Builder reviews(List<Review> reviews) {
			this.reviews = new ArrayList<>(reviews);
			return this;
		}

		public Builder requiredApprovals(int requiredApprovals) {
			if (requiredApprovals < 0) {
				throw new IllegalArgumentException("requiredApprovals must be >= 0");
			}
			this.requiredApprovals = requiredApprovals;
			return this;
		}

		public Builder metadata(String key, String value) {
			if (value != null) {
				this.metadata.put(key, value);
			}
			return this;
		}

		public Builder metadata(Map<String, String> metadata) {
			this.metadata = new LinkedHashMap<>(metadata);
			return this;
		}

		public Proposal build() {
			return new Proposal(this);
		}
	}
}
