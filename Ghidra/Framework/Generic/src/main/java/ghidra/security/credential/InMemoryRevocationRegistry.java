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
package ghidra.security.credential;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * Thread-safe in-memory implementation of {@link RevocationRegistry}.
 * Suitable for single-instance deployments and testing.
 *
 * <p>For distributed deployments, consider a persistent implementation
 * backed by a database or distributed cache.
 */
public class InMemoryRevocationRegistry implements RevocationRegistry {

	private final ConcurrentHashMap<String, RevocationRecord> revocations =
		new ConcurrentHashMap<>();
	private final ConcurrentHashMap<String, Set<String>> tokensByPrincipal =
		new ConcurrentHashMap<>();

	/**
	 * Creates a new in-memory revocation registry.
	 */
	public InMemoryRevocationRegistry() {
	}

	/**
	 * Registers a token-to-principal mapping for bulk revocation support.
	 * Call this when tokens are issued.
	 *
	 * @param tokenId the token ID
	 * @param principal the principal the token was issued to
	 */
	public void registerToken(String tokenId, String principal) {
		tokensByPrincipal.computeIfAbsent(principal, k -> ConcurrentHashMap.newKeySet())
			.add(tokenId);
	}

	@Override
	public RevocationRecord revoke(String tokenId, RevocationReason reason, String revokedBy) {
		Objects.requireNonNull(tokenId, "tokenId must not be null");
		Objects.requireNonNull(reason, "reason must not be null");
		Objects.requireNonNull(revokedBy, "revokedBy must not be null");

		RevocationRecord record = new RevocationRecord(
			tokenId,
			Instant.now(),
			reason,
			revokedBy,
			findPrincipalForToken(tokenId));

		revocations.put(tokenId, record);
		return record;
	}

	@Override
	public List<RevocationRecord> revokeByPrincipal(String principal, RevocationReason reason,
			String revokedBy) {
		Objects.requireNonNull(principal, "principal must not be null");
		Objects.requireNonNull(reason, "reason must not be null");
		Objects.requireNonNull(revokedBy, "revokedBy must not be null");

		Set<String> tokens = tokensByPrincipal.get(principal);
		if (tokens == null || tokens.isEmpty()) {
			return Collections.emptyList();
		}

		List<RevocationRecord> records = new ArrayList<>();
		Instant now = Instant.now();
		for (String tokenId : tokens) {
			RevocationRecord record = new RevocationRecord(
				tokenId, now, reason, revokedBy, principal);
			revocations.put(tokenId, record);
			records.add(record);
		}
		return records;
	}

	@Override
	public boolean isRevoked(String tokenId) {
		return revocations.containsKey(tokenId);
	}

	@Override
	public RevocationRecord getRevocationRecord(String tokenId) {
		return revocations.get(tokenId);
	}

	@Override
	public List<RevocationRecord> getRevocationsBetween(Instant start, Instant end) {
		return revocations.values().stream()
			.filter(r -> !r.getRevokedAt().isBefore(start) && r.getRevokedAt().isBefore(end))
			.sorted(Comparator.comparing(RevocationRecord::getRevokedAt).reversed())
			.collect(Collectors.toList());
	}

	@Override
	public long getRevocationCount() {
		return revocations.size();
	}

	@Override
	public int pruneExpiredRecords(Instant olderThan) {
		int count = 0;
		Iterator<Map.Entry<String, RevocationRecord>> it = revocations.entrySet().iterator();
		while (it.hasNext()) {
			Map.Entry<String, RevocationRecord> entry = it.next();
			if (entry.getValue().getRevokedAt().isBefore(olderThan)) {
				it.remove();
				count++;
			}
		}
		return count;
	}

	private String findPrincipalForToken(String tokenId) {
		for (Map.Entry<String, Set<String>> entry : tokensByPrincipal.entrySet()) {
			if (entry.getValue().contains(tokenId)) {
				return entry.getKey();
			}
		}
		return "unknown";
	}

	/**
	 * Clears all revocations. Primarily for testing.
	 */
	public void clear() {
		revocations.clear();
		tokensByPrincipal.clear();
	}
}
