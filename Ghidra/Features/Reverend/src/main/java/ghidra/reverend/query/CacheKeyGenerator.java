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
package ghidra.reverend.query;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;
import java.util.Objects;

import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSetView;

/**
 * Generates collision-resistant cache keys from canonical query/scope serialization.
 */
final class CacheKeyGenerator {

	private static final String KEY_VERSION = "v1";
	private static final String SIMILAR_PREFIX = "similar";
	private static final String SEMANTIC_PREFIX = "semantic";
	private static final String PATTERN_PREFIX = "pattern";

	private CacheKeyGenerator() {
		// Utility class
	}

	static String forSimilarFunctions(String functionEntryPoint) {
		String canonical = "entrypoint=" + normalizeToken(functionEntryPoint);
		return buildKey(SIMILAR_PREFIX, canonical);
	}

	static String forSemanticSearch(String query, AddressSetView scope) {
		String canonical = "query=" + normalizeText(query) + "|scope=" + serializeScope(scope);
		return buildKey(SEMANTIC_PREFIX, canonical);
	}

	static String forPatternSearch(String pattern, AddressSetView scope) {
		String canonical = "pattern=" + normalizeText(pattern) + "|scope=" + serializeScope(scope);
		return buildKey(PATTERN_PREFIX, canonical);
	}

	private static String buildKey(String prefix, String canonicalPayload) {
		String payload = KEY_VERSION + "|" + prefix + "|" + canonicalPayload;
		return prefix + ":" + KEY_VERSION + ":" + sha256Hex(payload);
	}

	private static String normalizeText(String text) {
		Objects.requireNonNull(text, "text");
		String trimmed = text.trim().toLowerCase(Locale.ROOT);
		return trimmed.replaceAll("\\s+", " ");
	}

	private static String normalizeToken(String token) {
		Objects.requireNonNull(token, "token");
		return token.trim().toLowerCase(Locale.ROOT);
	}

	private static String serializeScope(AddressSetView scope) {
		if (scope == null) {
			return "<all>";
		}

		AddressRangeIterator ranges = scope.getAddressRanges();
		StringBuilder canonical = new StringBuilder();
		while (ranges.hasNext()) {
			AddressRange range = ranges.next();
			if (canonical.length() > 0) {
				canonical.append('|');
			}
			canonical.append(range.getMinAddress()).append("..").append(range.getMaxAddress());
		}
		if (canonical.length() == 0) {
			return "<empty>";
		}
		return canonical.toString();
	}

	private static String sha256Hex(String value) {
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] hash = digest.digest(value.getBytes(StandardCharsets.UTF_8));
			StringBuilder hex = new StringBuilder(hash.length * 2);
			for (byte b : hash) {
				hex.append(Character.forDigit((b >> 4) & 0xf, 16));
				hex.append(Character.forDigit(b & 0xf, 16));
			}
			return hex.toString();
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("SHA-256 digest unavailable", e);
		}
	}
}
