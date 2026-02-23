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

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import ghidra.program.model.address.Address;
import ghidra.reverend.api.v1.QueryService.QueryResult;

/**
 * Represents a single search result entry in the cockpit UI.
 *
 * <p>This class wraps a {@link QueryResult} and provides additional
 * display metadata for the result table.
 */
public class SearchResultEntry {

	private final Address address;
	private final double score;
	private final String summary;
	private final String evidenceId;
	private final List<String> evidenceRefs;
	private final Map<String, String> provenance;
	private final String functionName;
	private final long addressOffset;

	/**
	 * Creates a new search result entry from a query result.
	 *
	 * @param result the query result
	 * @param functionName the name of the containing function (may be null)
	 */
	public SearchResultEntry(QueryResult result, String functionName) {
		Objects.requireNonNull(result, "result cannot be null");
		this.address = result.getAddress();
		this.score = result.getScore();
		this.summary = result.getSummary();
		this.evidenceId = result.getEvidenceId().orElse(null);
		this.evidenceRefs = Collections.unmodifiableList(new ArrayList<>(result.getEvidenceRefs()));
		this.provenance = Collections.unmodifiableMap(new LinkedHashMap<>(result.getProvenance()));
		this.functionName = functionName != null ? functionName : "<unknown>";
		this.addressOffset = address != null ? address.getOffset() : 0;
	}

	/**
	 * Creates a search result entry with explicit values.
	 *
	 * @param address the result address
	 * @param score the relevance score
	 * @param summary the result summary
	 * @param evidenceId optional evidence ID
	 * @param functionName the containing function name
	 */
	public SearchResultEntry(Address address, double score, String summary,
			String evidenceId, String functionName) {
		this.address = address;
		this.score = score;
		this.summary = summary != null ? summary : "";
		this.evidenceId = evidenceId;
		this.evidenceRefs = evidenceId != null
				? Collections.unmodifiableList(List.of(evidenceId))
				: Collections.emptyList();
		this.provenance = Collections.emptyMap();
		this.functionName = functionName != null ? functionName : "<unknown>";
		this.addressOffset = address != null ? address.getOffset() : 0;
	}

	/**
	 * Returns the result address.
	 *
	 * @return the address
	 */
	public Address getAddress() {
		return address;
	}

	/**
	 * Returns the address offset for display.
	 *
	 * @return the offset value
	 */
	public long getAddressOffset() {
		return addressOffset;
	}

	/**
	 * Returns the relevance/similarity score.
	 *
	 * @return the score (0.0 to 1.0)
	 */
	public double getScore() {
		return score;
	}

	/**
	 * Returns the score as a percentage string.
	 *
	 * @return formatted percentage
	 */
	public String getScorePercent() {
		return String.format("%.1f%%", score * 100);
	}

	/**
	 * Returns the result summary text.
	 *
	 * @return the summary
	 */
	public String getSummary() {
		return summary;
	}

	/**
	 * Returns the evidence ID if available.
	 *
	 * @return optional evidence ID
	 */
	public Optional<String> getEvidenceId() {
		return Optional.ofNullable(evidenceId);
	}

	/**
	 * Returns deterministic evidence references for this result.
	 *
	 * @return immutable evidence reference list
	 */
	public List<String> getEvidenceRefs() {
		return evidenceRefs;
	}

	/**
	 * Returns provenance metadata associated with this result.
	 *
	 * @return immutable provenance map
	 */
	public Map<String, String> getProvenance() {
		return provenance;
	}

	/**
	 * Returns the containing function name.
	 *
	 * @return the function name
	 */
	public String getFunctionName() {
		return functionName;
	}

	/**
	 * Returns true if this result has linked evidence.
	 *
	 * @return true if evidence is available
	 */
	public boolean hasEvidence() {
		return evidenceId != null && !evidenceId.isEmpty();
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof SearchResultEntry)) {
			return false;
		}
		SearchResultEntry other = (SearchResultEntry) obj;
		return Objects.equals(address, other.address) &&
			Double.compare(score, other.score) == 0;
	}

	@Override
	public int hashCode() {
		return Objects.hash(address, score);
	}

	@Override
	public String toString() {
		return String.format("SearchResultEntry[%s, score=%.2f, func=%s]",
			address, score, functionName);
	}
}
