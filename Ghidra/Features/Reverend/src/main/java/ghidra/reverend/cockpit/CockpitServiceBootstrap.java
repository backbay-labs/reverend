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

import ghidra.program.model.listing.Program;
import ghidra.reverend.api.v1.EvidenceService;
import ghidra.reverend.api.v1.ProposalIntegrationService;
import ghidra.reverend.api.v1.QueryService;
import ghidra.reverend.query.*;

/**
 * Bootstraps live Reverend cockpit services and manages their lifecycle.
 */
public class CockpitServiceBootstrap implements AutoCloseable {

	private LiveQueryServiceImpl queryService;
	private LiveEvidenceServiceImpl evidenceService;
	private LiveProposalIntegrationServiceImpl proposalService;
	private boolean initialized;

	/**
	 * Initializes live service implementations if needed.
	 */
	public synchronized void init() {
		if (initialized) {
			return;
		}

		QueryTelemetry telemetry = new QueryTelemetry();
		queryService = new LiveQueryServiceImpl(
			new QueryCacheManager(),
			new DecompilerContextProvider(telemetry),
			telemetry);
		evidenceService = new LiveEvidenceServiceImpl();
		proposalService = new LiveProposalIntegrationServiceImpl(evidenceService);
		initialized = true;
	}

	/**
	 * Returns true if bootstrap initialization has run.
	 *
	 * @return true if initialized
	 */
	public synchronized boolean isInitialized() {
		return initialized;
	}

	/**
	 * Returns the live query service.
	 *
	 * @return live query service
	 */
	public synchronized QueryService getQueryService() {
		ensureInitialized();
		return queryService;
	}

	/**
	 * Returns the live evidence service.
	 *
	 * @return live evidence service
	 */
	public synchronized EvidenceService getEvidenceService() {
		ensureInitialized();
		return evidenceService;
	}

	/**
	 * Returns the live proposal integration service.
	 *
	 * @return live proposal service
	 */
	public synchronized ProposalIntegrationService getProposalService() {
		ensureInitialized();
		return proposalService;
	}

	/**
	 * Binds live services to an activated program.
	 *
	 * @param program activated program
	 */
	public synchronized void bindProgram(Program program) {
		if (!initialized || program == null) {
			return;
		}
		queryService.bindToProgram(program);
		evidenceService.bindToProgram(program);
	}

	/**
	 * Unbinds live services from a deactivated program.
	 *
	 * @param program deactivated program
	 */
	public synchronized void unbindProgram(Program program) {
		if (!initialized || program == null) {
			return;
		}
		queryService.unbindFromProgram(program);
		evidenceService.unbindFromProgram(program);
	}

	/**
	 * Disposes all bootstrap-managed services.
	 */
	public synchronized void dispose() {
		close();
	}

	@Override
	public synchronized void close() {
		if (!initialized) {
			return;
		}

		queryService.close();
		evidenceService.close();
		proposalService.close();

		queryService = null;
		evidenceService = null;
		proposalService = null;
		initialized = false;
	}

	private void ensureInitialized() {
		if (!initialized) {
			throw new IllegalStateException("Cockpit services are not initialized");
		}
	}
}
