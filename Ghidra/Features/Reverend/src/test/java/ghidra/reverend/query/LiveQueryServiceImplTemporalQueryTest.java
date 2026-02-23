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

import java.time.Instant;
import java.util.*;

import org.junit.*;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.reverend.api.v1.QueryService;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;

public class LiveQueryServiceImplTemporalQueryTest extends AbstractGhidraHeadlessIntegrationTest {

	private static final Instant FIXTURE_EPOCH = Instant.parse("2026-01-01T00:00:00Z");

	private LiveQueryServiceImpl service;
	private Program program;

	@Before
	public void setUp() throws Exception {
		QueryTelemetry telemetry = new QueryTelemetry();
		service = new LiveQueryServiceImpl(
			new QueryCacheManager(),
			new DecompilerContextProvider(telemetry),
			telemetry
		);
		program = createFixtureProgram();
		service.bindToProgram(program);
	}

	@After
	public void tearDown() {
		if (service != null) {
			service.close();
		}
		if (program != null) {
			program.release(this);
		}
	}

	@Test
	public void testTemporalWindowBeforeAfterUsesDeterministicOrdering() throws Exception {
		Address a0 = program.getAddressFactory().getAddress("0x01000000");
		Address a1 = program.getAddressFactory().getAddress("0x01001000");
		Address a2 = program.getAddressFactory().getAddress("0x01002000");
		service.ingestTemporalEventForTesting(fixtureEvent(
			"event-a", a0, FIXTURE_EPOCH.plusMillis(1000), List.of()));
		service.ingestTemporalEventForTesting(fixtureEvent(
			"event-b", a1, FIXTURE_EPOCH.plusMillis(2000), List.of("event-a")));
		service.ingestTemporalEventForTesting(fixtureEvent(
			"event-c", a2, FIXTURE_EPOCH.plusMillis(3000), List.of("event-b")));

		List<QueryService.TemporalEvent> before = service.queryTemporalWindow(program,
			new QueryService.TemporalWindowRequest(
				FIXTURE_EPOCH.plusMillis(3200), 2500,
				QueryService.TemporalDirection.BEFORE, 10));
		assertEquals(List.of("event-c", "event-b"), toEventIds(before));

		List<QueryService.TemporalEvent> after = service.queryTemporalWindow(program,
			new QueryService.TemporalWindowRequest(
				FIXTURE_EPOCH.plusMillis(1500), 2500,
				QueryService.TemporalDirection.AFTER, 10));
		assertEquals(List.of("event-b", "event-c"), toEventIds(after));
	}

	@Test
	public void testTemporalIntervalJoinFollowsDeterministicFixtureSemantics() throws Exception {
		Address a0 = program.getAddressFactory().getAddress("0x01000000");
		Address a1 = program.getAddressFactory().getAddress("0x01001000");
		Address a2 = program.getAddressFactory().getAddress("0x01002000");
		service.ingestTemporalEventForTesting(fixtureEvent(
			"join-left", a0, FIXTURE_EPOCH.plusMillis(1000), List.of()));
		service.ingestTemporalEventForTesting(new FixtureTemporalEvent(
			"join-mid", fixtureProgramId(), a1, "fixture",
			FIXTURE_EPOCH.plusMillis(1500), FIXTURE_EPOCH.plusMillis(2400), List.of("join-left")));
		service.ingestTemporalEventForTesting(new FixtureTemporalEvent(
			"join-far", fixtureProgramId(), a2, "fixture",
			FIXTURE_EPOCH.plusMillis(4000), FIXTURE_EPOCH.plusMillis(4200), List.of("join-mid")));

		List<QueryService.TemporalIntervalJoinResult> joins = service.queryTemporalIntervalJoin(program,
			new QueryService.TemporalIntervalJoinRequest(
				FIXTURE_EPOCH, FIXTURE_EPOCH.plusMillis(5000), 700, 10));

		assertEquals(1, joins.size());
		QueryService.TemporalIntervalJoinResult match = joins.get(0);
		assertEquals("join-left", match.getLeft().getEventId());
		assertEquals("join-mid", match.getRight().getEventId());
		assertEquals(500L, match.getStartGapMillis());
		assertEquals(0L, match.getOverlapMillis());
	}

	@Test
	public void testTemporalLineageReturnsRootAndPredecessorsByDepth() throws Exception {
		Address a0 = program.getAddressFactory().getAddress("0x01000000");
		Address a1 = program.getAddressFactory().getAddress("0x01001000");
		Address a2 = program.getAddressFactory().getAddress("0x01002000");
		service.ingestTemporalEventForTesting(fixtureEvent(
			"lineage-root", a2, FIXTURE_EPOCH.plusMillis(3000), List.of("lineage-mid")));
		service.ingestTemporalEventForTesting(fixtureEvent(
			"lineage-mid", a1, FIXTURE_EPOCH.plusMillis(2000), List.of("lineage-base")));
		service.ingestTemporalEventForTesting(fixtureEvent(
			"lineage-base", a0, FIXTURE_EPOCH.plusMillis(1000), List.of()));

		List<QueryService.TemporalEvent> lineage = service.queryTemporalLineage(program, "lineage-root", 4);
		assertEquals(List.of("lineage-root", "lineage-mid", "lineage-base"), toEventIds(lineage));
	}

	@Test
	public void testTemporalLatencyBudgetsAcrossRepresentativeVolumes() throws Exception {
		Address baseAddress = program.getAddressFactory().getAddress("0x01000000");
		int fixtureSize = 5000;
		for (int i = 0; i < fixtureSize; i++) {
			String id = "latency-" + i;
			List<String> predecessor = i > 0 ? List.of("latency-" + (i - 1)) : List.of();
			service.ingestTemporalEventForTesting(new FixtureTemporalEvent(
				id,
				fixtureProgramId(),
				baseAddress,
				"latency",
				FIXTURE_EPOCH.plusMillis(i * 10L),
				FIXTURE_EPOCH.plusMillis(i * 10L + 1L),
				predecessor));
		}

		long windowP95 = p95Nanos(() -> {
			try {
				service.queryTemporalWindow(program, new QueryService.TemporalWindowRequest(
					FIXTURE_EPOCH.plusMillis(35_000), 20_000, QueryService.TemporalDirection.BEFORE, 256));
			}
			catch (Exception e) {
				throw new RuntimeException(e);
			}
		}, 12);
		long joinP95 = p95Nanos(() -> {
			try {
				service.queryTemporalIntervalJoin(program, new QueryService.TemporalIntervalJoinRequest(
					FIXTURE_EPOCH, FIXTURE_EPOCH.plusMillis(50_000), 5, 2048));
			}
			catch (Exception e) {
				throw new RuntimeException(e);
			}
		}, 12);
		long lineageP95 = p95Nanos(() -> {
			try {
				service.queryTemporalLineage(program, "latency-4999", 128);
			}
			catch (Exception e) {
				throw new RuntimeException(e);
			}
		}, 12);

		assertTrue("window p95 too high: " + millis(windowP95), millis(windowP95) <= 150.0);
		assertTrue("join p95 too high: " + millis(joinP95), millis(joinP95) <= 500.0);
		assertTrue("lineage p95 too high: " + millis(lineageP95), millis(lineageP95) <= 100.0);
	}

	private QueryService.TemporalEvent fixtureEvent(String id, Address address, Instant start,
			List<String> predecessors) {
		return new FixtureTemporalEvent(
			id,
			fixtureProgramId(),
			address,
			"fixture",
			start,
			start,
			predecessors);
	}

	private static List<String> toEventIds(List<QueryService.TemporalEvent> events) {
		List<String> ids = new ArrayList<>(events.size());
		for (QueryService.TemporalEvent event : events) {
			ids.add(event.getEventId());
		}
		return ids;
	}

	private static long p95Nanos(Runnable action, int iterations) {
		long[] samples = new long[iterations];
		for (int i = 0; i < iterations; i++) {
			long start = System.nanoTime();
			action.run();
			samples[i] = System.nanoTime() - start;
		}
		Arrays.sort(samples);
		int index = Math.min(samples.length - 1, (int) Math.ceil(samples.length * 0.95d) - 1);
		return samples[Math.max(0, index)];
	}

	private static double millis(long nanos) {
		return nanos / 1_000_000.0d;
	}

	private String fixtureProgramId() {
		String executablePath = program.getExecutablePath();
		if (executablePath != null && !executablePath.isBlank()) {
			return executablePath;
		}
		String name = program.getName();
		if (name != null && !name.isBlank()) {
			return name;
		}
		return "program-" + System.identityHashCode(program);
	}

	private Program createFixtureProgram() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("TemporalFixture", ProgramBuilder._X86);
		builder.setBytes("0x01000000", "55 89 e5 31 c0 c9 c3");
		builder.setBytes("0x01001000", "55 89 e5 83 ec 10 c9 c3");
		builder.setBytes("0x01002000", "55 89 e5 83 ec 20 c9 c3");
		Program fixtureProgram = builder.getProgram();
		int txId = fixtureProgram.startTransaction("Create temporal fixture functions");
		try {
			CreateFunctionCmd f0 = new CreateFunctionCmd(
				"fixtureA",
				fixtureProgram.getAddressFactory().getAddress("0x01000000"),
				null,
				SourceType.USER_DEFINED);
			f0.applyTo(fixtureProgram);
			CreateFunctionCmd f1 = new CreateFunctionCmd(
				"fixtureB",
				fixtureProgram.getAddressFactory().getAddress("0x01001000"),
				null,
				SourceType.USER_DEFINED);
			f1.applyTo(fixtureProgram);
			CreateFunctionCmd f2 = new CreateFunctionCmd(
				"fixtureC",
				fixtureProgram.getAddressFactory().getAddress("0x01002000"),
				null,
				SourceType.USER_DEFINED);
			f2.applyTo(fixtureProgram);
		}
		finally {
			fixtureProgram.endTransaction(txId, true);
		}
		return fixtureProgram;
	}

	private static final class FixtureTemporalEvent implements QueryService.TemporalEvent {
		private final String eventId;
		private final String programId;
		private final Address address;
		private final String operation;
		private final Instant startTime;
		private final Instant endTime;
		private final List<String> predecessorEventIds;

		FixtureTemporalEvent(String eventId, String programId, Address address, String operation,
				Instant startTime, Instant endTime, List<String> predecessorEventIds) {
			this.eventId = eventId;
			this.programId = programId;
			this.address = address;
			this.operation = operation;
			this.startTime = startTime;
			this.endTime = endTime;
			this.predecessorEventIds = List.copyOf(predecessorEventIds);
		}

		@Override
		public String getEventId() {
			return eventId;
		}

		@Override
		public String getProgramId() {
			return programId;
		}

		@Override
		public Optional<Address> getAddress() {
			return Optional.ofNullable(address);
		}

		@Override
		public String getOperation() {
			return operation;
		}

		@Override
		public Instant getStartTime() {
			return startTime;
		}

		@Override
		public Instant getEndTime() {
			return endTime;
		}

		@Override
		public List<String> getPredecessorEventIds() {
			return predecessorEventIds;
		}

		@Override
		public Map<String, String> getMetadata() {
			return Map.of("fixture", "true");
		}
	}
}
