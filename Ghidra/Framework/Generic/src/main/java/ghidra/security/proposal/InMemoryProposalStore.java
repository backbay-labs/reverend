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
 * Thread-safe in-memory implementation of {@link ProposalStore}.
 * Suitable for testing and single-session use.
 */
public class InMemoryProposalStore implements ProposalStore {

	private final ConcurrentHashMap<String, Proposal> proposals = new ConcurrentHashMap<>();

	@Override
	public void save(Proposal proposal) {
		if (proposal == null) {
			throw new IllegalArgumentException("proposal must not be null");
		}
		proposals.put(proposal.getId(), proposal);
	}

	@Override
	public Optional<Proposal> findById(String proposalId) {
		return Optional.ofNullable(proposals.get(proposalId));
	}

	@Override
	public List<Proposal> findByState(ProposalState state) {
		return proposals.values().stream()
			.filter(p -> p.getState() == state)
			.sorted(Comparator.comparing(Proposal::getCreatedAt))
			.collect(Collectors.toList());
	}

	@Override
	public List<Proposal> findByAuthor(String author) {
		return proposals.values().stream()
			.filter(p -> p.getAuthor().equals(author))
			.sorted(Comparator.comparing(Proposal::getCreatedAt))
			.collect(Collectors.toList());
	}

	@Override
	public List<Proposal> findByProgram(String programId) {
		return proposals.values().stream()
			.filter(p -> programId.equals(p.getProgramId()))
			.sorted(Comparator.comparing(Proposal::getCreatedAt))
			.collect(Collectors.toList());
	}

	@Override
	public List<Proposal> findPendingReview() {
		return proposals.values().stream()
			.filter(p -> p.getState().isInReview())
			.sorted(Comparator.comparing(Proposal::getCreatedAt))
			.collect(Collectors.toList());
	}

	@Override
	public List<Proposal> findAll() {
		return proposals.values().stream()
			.sorted(Comparator.comparing(Proposal::getCreatedAt))
			.collect(Collectors.toList());
	}

	@Override
	public int size() {
		return proposals.size();
	}

	@Override
	public boolean isEmpty() {
		return proposals.isEmpty();
	}

	/**
	 * Clears all proposals from the store.
	 * For testing and transaction rollback support.
	 */
	public void clear() {
		proposals.clear();
	}

	/**
	 * Replaces all proposals with the given collection.
	 * For transaction rollback support.
	 *
	 * @param newProposals the proposals to set
	 */
	public void replaceAll(Collection<Proposal> newProposals) {
		proposals.clear();
		for (Proposal p : newProposals) {
			proposals.put(p.getId(), p);
		}
	}
}
