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
 * A single annotation change within a proposal.
 * Maps to the AnnotationDelta concept from collaboration-review-design.md.
 *
 * <p>Each delta describes a typed artifact change at an address, with optional
 * confidence scoring and rationale.
 */
public final class ProposalDelta {

	private final String id;
	private final String artifactType;
	private final String address;
	private final Map<String, String> oldValue;
	private final Map<String, String> newValue;
	private final Double confidence;
	private final String rationale;

	private ProposalDelta(Builder builder) {
		this.id = builder.id != null ? builder.id : UUID.randomUUID().toString();
		this.artifactType = Objects.requireNonNull(builder.artifactType, "artifactType is required");
		this.address = builder.address;
		this.oldValue = Collections.unmodifiableMap(new LinkedHashMap<>(builder.oldValue));
		this.newValue = Collections.unmodifiableMap(new LinkedHashMap<>(builder.newValue));
		this.confidence = builder.confidence;
		this.rationale = builder.rationale;
	}

	public String getId() {
		return id;
	}

	public String getArtifactType() {
		return artifactType;
	}

	public String getAddress() {
		return address;
	}

	public Map<String, String> getOldValue() {
		return oldValue;
	}

	public Map<String, String> getNewValue() {
		return newValue;
	}

	public Double getConfidence() {
		return confidence;
	}

	public String getRationale() {
		return rationale;
	}

	public static Builder builder() {
		return new Builder();
	}

	@Override
	public String toString() {
		return String.format("ProposalDelta[%s type=%s addr=%s]",
			id.substring(0, Math.min(8, id.length())), artifactType, address);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof ProposalDelta)) {
			return false;
		}
		ProposalDelta other = (ProposalDelta) obj;
		return id.equals(other.id);
	}

	@Override
	public int hashCode() {
		return id.hashCode();
	}

	public static final class Builder {
		private String id;
		private String artifactType;
		private String address;
		private Map<String, String> oldValue = new LinkedHashMap<>();
		private Map<String, String> newValue = new LinkedHashMap<>();
		private Double confidence;
		private String rationale;

		private Builder() {
		}

		public Builder id(String id) {
			this.id = id;
			return this;
		}

		public Builder artifactType(String artifactType) {
			this.artifactType = artifactType;
			return this;
		}

		public Builder address(String address) {
			this.address = address;
			return this;
		}

		public Builder oldValue(String key, String value) {
			if (value != null) {
				this.oldValue.put(key, value);
			}
			return this;
		}

		public Builder oldValue(Map<String, String> oldValue) {
			this.oldValue.putAll(oldValue);
			return this;
		}

		public Builder newValue(String key, String value) {
			if (value != null) {
				this.newValue.put(key, value);
			}
			return this;
		}

		public Builder newValue(Map<String, String> newValue) {
			this.newValue.putAll(newValue);
			return this;
		}

		public Builder confidence(Double confidence) {
			if (confidence != null && (confidence < 0.0 || confidence > 1.0)) {
				throw new IllegalArgumentException("confidence must be between 0.0 and 1.0");
			}
			this.confidence = confidence;
			return this;
		}

		public Builder rationale(String rationale) {
			this.rationale = rationale;
			return this;
		}

		public ProposalDelta build() {
			return new ProposalDelta(this);
		}
	}
}
