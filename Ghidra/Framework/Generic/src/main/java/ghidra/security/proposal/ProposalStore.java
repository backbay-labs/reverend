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
 * Storage interface for proposal lifecycle persistence and querying.
 *
 * <p>Implementations must ensure thread safety for concurrent access.
 * Proposals are stored by ID and queryable by state, author, and program.
 */
public interface ProposalStore {

	/**
	 * Stores a new proposal or updates an existing one.
	 * @param proposal the proposal to save
	 * @throws IllegalArgumentException if proposal is null
	 */
	void save(Proposal proposal);

	/**
	 * Retrieves a proposal by its ID.
	 * @param proposalId the proposal ID
	 * @return the proposal, or empty if not found
	 */
	Optional<Proposal> findById(String proposalId);

	/**
	 * Returns all proposals in the given state.
	 * @param state the state to filter by
	 * @return list of proposals in that state, ordered by creation time ascending
	 */
	List<Proposal> findByState(ProposalState state);

	/**
	 * Returns all proposals by the given author.
	 * @param author the author identifier
	 * @return list of proposals by that author, ordered by creation time ascending
	 */
	List<Proposal> findByAuthor(String author);

	/**
	 * Returns all proposals for the given program.
	 * @param programId the program ID
	 * @return list of proposals for that program, ordered by creation time ascending
	 */
	List<Proposal> findByProgram(String programId);

	/**
	 * Returns all proposals that are in an active review state (OPEN or UNDER_REVIEW).
	 * @return list of proposals pending review
	 */
	List<Proposal> findPendingReview();

	/**
	 * Returns all proposals.
	 * @return all proposals, ordered by creation time ascending
	 */
	List<Proposal> findAll();

	/**
	 * Returns the total number of proposals.
	 * @return the count
	 */
	int size();

	/**
	 * Returns whether the store is empty.
	 * @return true if no proposals stored
	 */
	boolean isEmpty();
}
