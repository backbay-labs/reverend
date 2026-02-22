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

import static org.junit.Assert.*;

import java.lang.reflect.Method;

import org.junit.Before;
import org.junit.Test;

import ghidra.program.model.address.AddressSetView;

public class LiveQueryServiceImplCacheKeyTest {

	private LiveQueryServiceImpl service;

	@Before
	public void setUp() {
		QueryTelemetry telemetry = new QueryTelemetry();
		service = new LiveQueryServiceImpl(
			new QueryCacheManager(),
			new DecompilerContextProvider(telemetry),
			telemetry
		);
	}

	@Test
	public void testSemanticCacheKeyIsDeterministicForEquivalentQueryText() throws Exception {
		String keyA = buildSemanticCacheKey("  Find   memcpy  ", null);
		String keyB = buildSemanticCacheKey("find memcpy", null);

		assertEquals(keyA, keyB);
	}

	@Test
	public void testPatternCacheKeyIsDeterministicForEquivalentPatternText() throws Exception {
		String keyA = buildPatternCacheKey("MoV eax, ebx", null);
		String keyB = buildPatternCacheKey("mov eax, ebx", null);

		assertEquals(keyA, keyB);
	}

	@Test
	public void testSemanticCacheKeyResistsHashCollisionInputs() throws Exception {
		assertEquals("Aa".hashCode(), "BB".hashCode());

		String keyA = buildSemanticCacheKey("Aa", null);
		String keyB = buildSemanticCacheKey("BB", null);

		assertNotEquals(keyA, keyB);
	}

	@Test
	public void testPatternCacheKeyResistsHashCollisionInputs() throws Exception {
		assertEquals("Aa".hashCode(), "BB".hashCode());

		String keyA = buildPatternCacheKey("Aa", null);
		String keyB = buildPatternCacheKey("BB", null);

		assertNotEquals(keyA, keyB);
	}

	private String buildSemanticCacheKey(String query, AddressSetView scope) throws Exception {
		Method method = LiveQueryServiceImpl.class.getDeclaredMethod(
			"buildSemanticSearchCacheKey", String.class, AddressSetView.class);
		method.setAccessible(true);
		return (String) method.invoke(service, query, scope);
	}

	private String buildPatternCacheKey(String pattern, AddressSetView scope) throws Exception {
		Method method = LiveQueryServiceImpl.class.getDeclaredMethod(
			"buildPatternSearchCacheKey", String.class, AddressSetView.class);
		method.setAccessible(true);
		return (String) method.invoke(service, pattern, scope);
	}
}
