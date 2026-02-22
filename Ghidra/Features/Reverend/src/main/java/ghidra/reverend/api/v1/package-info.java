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
 * Reverend Plugin Service API v1.
 *
 * <p>This package defines the versioned service contracts for the Reverend plugin module.
 * All interfaces in this package are part of the public API and follow semantic versioning:
 *
 * <ul>
 *   <li><b>Major version</b> (v1, v2, ...): Breaking changes to interface signatures</li>
 *   <li><b>Minor version</b>: Additive changes (new methods with default implementations)</li>
 *   <li><b>Patch version</b>: Documentation and implementation-only changes</li>
 * </ul>
 *
 * <h2>Service Contracts</h2>
 *
 * <p>The following service interfaces are provided:
 *
 * <ul>
 *   <li>{@link ghidra.reverend.api.v1.QueryService} - Semantic search and query operations
 *       against the program model and decompiler state</li>
 *   <li>{@link ghidra.reverend.api.v1.ProposalIntegrationService} - Integration with the
 *       proposal workflow system for applying analysis suggestions</li>
 *   <li>{@link ghidra.reverend.api.v1.EvidenceService} - Evidence collection, retrieval,
 *       and linking for analysis provenance</li>
 *   <li>{@link ghidra.reverend.api.v1.MissionService} - Mission orchestration for
 *       multi-step analysis workflows</li>
 *   <li>{@link ghidra.reverend.api.v1.PolicyService} - Policy-aware action execution
 *       with capability and egress controls</li>
 * </ul>
 *
 * <h2>Versioning Contract</h2>
 *
 * <p>Clients should depend on specific API versions. When a new major version is released:
 * <ol>
 *   <li>The previous version remains available for at least one release cycle</li>
 *   <li>Deprecation warnings are added to the old version</li>
 *   <li>Migration guides are provided in the release notes</li>
 * </ol>
 *
 * <p>API version: 1.0.0
 *
 * @since 1.0
 * @see ghidra.reverend.api.v1.ServiceVersion
 */
package ghidra.reverend.api.v1;
