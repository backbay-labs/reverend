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
/**
 * Live query service implementation with Program and Decompiler bindings.
 *
 * <p>This package provides the implementation of the {@link ghidra.reverend.api.v1.QueryService}
 * interface with live bindings to Ghidra's Program model and Decompiler.
 *
 * <h2>Key Components</h2>
 *
 * <ul>
 *   <li>{@link ghidra.reverend.query.LiveQueryServiceImpl} - Main query service implementation
 *       that binds to live Program and Decompiler state</li>
 *   <li>{@link ghidra.reverend.query.DecompilerContextProvider} - Manages decompiler instances
 *       and result caching per program</li>
 *   <li>{@link ghidra.reverend.query.QueryCacheManager} - Handles query result caching with
 *       deterministic invalidation on program changes</li>
 *   <li>{@link ghidra.reverend.query.QueryTelemetry} - Collects latency and error metrics
 *       for monitoring</li>
 * </ul>
 *
 * <h2>Cache Invalidation Strategy</h2>
 *
 * <p>The implementation uses Ghidra's {@link ghidra.framework.model.DomainObjectListener}
 * infrastructure to receive program change notifications. Invalidation is fine-grained:
 *
 * <ul>
 *   <li><b>Function changes</b> (add/remove/modify): Invalidates function similarity
 *       and semantic search caches</li>
 *   <li><b>Symbol changes</b> (add/remove/rename): Invalidates semantic search caches
 *       that depend on symbol names</li>
 *   <li><b>Code changes</b> (add/remove/replace): Invalidates pattern search and
 *       context caches for affected regions</li>
 *   <li><b>Memory changes</b> (block add/remove/modify): Invalidates all caches
 *       for the program</li>
 * </ul>
 *
 * <h2>Telemetry</h2>
 *
 * <p>All query operations emit telemetry through {@link ghidra.reverend.query.QueryTelemetry}:
 *
 * <ul>
 *   <li>Latency percentiles (p50, p90, p99) per operation type</li>
 *   <li>Error counts and types</li>
 *   <li>Cache hit/miss rates</li>
 *   <li>Decompilation performance metrics</li>
 * </ul>
 *
 * <h2>Usage Example</h2>
 *
 * <pre>{@code
 * // Create components
 * QueryTelemetry telemetry = new QueryTelemetry();
 * QueryCacheManager cacheManager = new QueryCacheManager();
 * DecompilerContextProvider decompilerProvider = new DecompilerContextProvider(telemetry);
 *
 * // Create and bind service
 * LiveQueryServiceImpl queryService = new LiveQueryServiceImpl(
 *     cacheManager, decompilerProvider, telemetry);
 * queryService.bindToProgram(currentProgram);
 *
 * // Use the service
 * List<QueryResult> results = queryService.findSimilarFunctions(
 *     currentProgram, currentFunction, 10, monitor);
 *
 * // Access telemetry
 * System.out.println(telemetry.getSummaryReport());
 * }</pre>
 *
 * @since 1.0
 * @see ghidra.reverend.api.v1.QueryService
 */
package ghidra.reverend.query;
