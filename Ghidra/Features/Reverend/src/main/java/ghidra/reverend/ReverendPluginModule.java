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
package ghidra.reverend;

import ghidra.reverend.api.v1.*;

/**
 * Module class for the Reverend plugin.
 *
 * <p>The Reverend plugin provides AI-assisted reverse engineering capabilities
 * within Ghidra, including:
 * <ul>
 *   <li>Semantic code search and similarity analysis</li>
 *   <li>Automated type recovery and function identification</li>
 *   <li>Evidence-based analysis with provenance tracking</li>
 *   <li>Mission-based workflow orchestration</li>
 *   <li>Policy-aware operation execution</li>
 * </ul>
 *
 * <p>All functionality is exposed through versioned service interfaces in
 * the {@link ghidra.reverend.api.v1} package.
 *
 * @since 1.0
 * @see QueryService
 * @see ProposalIntegrationService
 * @see EvidenceService
 * @see MissionService
 * @see PolicyService
 */
public class ReverendPluginModule {

	/**
	 * Module name constant.
	 */
	public static final String MODULE_NAME = "Reverend";

	/**
	 * Current module version.
	 */
	public static final String MODULE_VERSION = "1.0.0";

	/**
	 * Returns the current API version for Reverend services.
	 *
	 * @return the service API version
	 */
	public static ServiceVersion getApiVersion() {
		return ServiceVersion.CURRENT;
	}

	/**
	 * Returns the module name.
	 *
	 * @return the module name
	 */
	public static String getModuleName() {
		return MODULE_NAME;
	}

	/**
	 * Returns the module version.
	 *
	 * @return the module version string
	 */
	public static String getModuleVersion() {
		return MODULE_VERSION;
	}
}
