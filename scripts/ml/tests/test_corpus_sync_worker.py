from __future__ import annotations

import importlib.util
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "corpus_sync_worker.py"
SPEC = importlib.util.spec_from_file_location("e7_corpus_sync_worker", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"failed to load module spec from {MODULE_PATH}")
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

AccessContext = MODULE.AccessContext
AccessDeniedError = MODULE.AccessDeniedError
CorpusSyncWorker = MODULE.CorpusSyncWorker
EndpointPolicyConfig = MODULE.EndpointPolicyConfig
EndpointPolicyRule = MODULE.EndpointPolicyRule
ProposalArtifact = MODULE.ProposalArtifact
SyncStateStore = MODULE.SyncStateStore
run_read_job = MODULE.run_read_job
run_sync_job = MODULE.run_sync_job
query_audit_log_records = MODULE.query_audit_log_records


class CorpusSyncWorkerTest(unittest.TestCase):
    def _write_local_store(self, path: Path, proposals: list[dict[str, object]]) -> None:
        path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "kind": "local_proposal_store",
                    "proposals": proposals,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

    def test_sync_filters_non_approved_proposals(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            local_store = tmp / "local_store.json"
            backend_store = tmp / "backend_store.json"
            state_path = tmp / "state.json"

            self._write_local_store(
                local_store,
                [
                    {"proposal_id": "p-approved", "state": "APPROVED", "receipt_id": "r-1"},
                    {"proposal_id": "p-proposed", "state": "PROPOSED", "receipt_id": "r-2"},
                    {"proposal_id": "p-rejected", "state": "REJECTED", "receipt_id": "r-3"},
                ],
            )

            telemetry = run_sync_job(
                local_store_path=local_store,
                backend_store_path=backend_store,
                state_path=state_path,
                job_id="sync-filter-test",
            )
            backend = json.loads(backend_store.read_text(encoding="utf-8"))

            self.assertEqual(telemetry.scanned_total, 3)
            self.assertEqual(telemetry.approved_total, 1)
            self.assertEqual(telemetry.skipped_non_approved, 2)
            self.assertEqual(telemetry.synced_count, 1)
            self.assertEqual(telemetry.error_count, 0)
            self.assertEqual(sorted(backend["artifacts"].keys()), ["p-approved"])

    def test_sync_preserves_provenance_chain_on_backend_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            local_store = tmp / "local_store.json"
            backend_store = tmp / "backend_store.json"
            state_path = tmp / "state.json"

            self._write_local_store(
                local_store,
                [
                    {
                        "proposal_id": "p-with-chain",
                        "state": "APPROVED",
                        "receipt_id": "r-3",
                        "provenance_chain": [
                            {"receipt_id": "r-1"},
                            {"receipt_id": "r-2", "previous_receipt_id": "r-1"},
                            {"receipt_id": "r-3", "previous_receipt_id": "r-2"},
                        ],
                    }
                ],
            )

            telemetry = run_sync_job(
                local_store_path=local_store,
                backend_store_path=backend_store,
                state_path=state_path,
                job_id="sync-chain-test",
            )

            backend = json.loads(backend_store.read_text(encoding="utf-8"))
            artifact = backend["artifacts"]["p-with-chain"]

            self.assertEqual(telemetry.synced_count, 1)
            self.assertEqual(telemetry.error_count, 0)
            self.assertEqual(
                [entry["receipt_id"] for entry in artifact["provenance_chain"]],
                ["r-1", "r-2", "r-3"],
            )
            self.assertEqual(artifact["provenance_head_receipt_id"], "r-3")

    def test_sync_materializes_complete_provenance_links(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            local_store = tmp / "local_store.json"
            backend_store = tmp / "backend_store.json"
            state_path = tmp / "state.json"

            self._write_local_store(
                local_store,
                [
                    {
                        "proposal_id": "p-chain-materialized",
                        "state": "APPROVED",
                        "receipt_id": "r-3",
                        "provenance_chain": ["r-1", "r-2", "r-3"],
                    }
                ],
            )

            telemetry = run_sync_job(
                local_store_path=local_store,
                backend_store_path=backend_store,
                state_path=state_path,
                job_id="sync-chain-materialized",
            )

            backend = json.loads(backend_store.read_text(encoding="utf-8"))
            chain = backend["artifacts"]["p-chain-materialized"]["provenance_chain"]

            self.assertEqual(telemetry.synced_count, 1)
            self.assertEqual(telemetry.error_count, 0)
            self.assertEqual(chain[0], {"receipt_id": "r-1"})
            self.assertEqual(chain[1], {"receipt_id": "r-2", "previous_receipt_id": "r-1"})
            self.assertEqual(chain[2], {"receipt_id": "r-3", "previous_receipt_id": "r-2"})

    def test_sync_is_idempotent_and_stateful(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            local_store = tmp / "local_store.json"
            backend_store = tmp / "backend_store.json"
            state_path = tmp / "state.json"

            self._write_local_store(
                local_store,
                [
                    {"proposal_id": "p-1", "state": "APPROVED", "receipt_id": "r-1"},
                ],
            )

            first = run_sync_job(
                local_store_path=local_store,
                backend_store_path=backend_store,
                state_path=state_path,
                job_id="sync-idempotent-1",
            )
            second = run_sync_job(
                local_store_path=local_store,
                backend_store_path=backend_store,
                state_path=state_path,
                job_id="sync-idempotent-2",
            )

            backend = json.loads(backend_store.read_text(encoding="utf-8"))
            self.assertEqual(first.synced_count, 1)
            self.assertEqual(second.synced_count, 0)
            self.assertEqual(second.already_synced_count, 1)
            self.assertEqual(len(backend["artifacts"]), 1)

    def test_sync_denies_unauthorized_write_and_audits(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            local_store = tmp / "local_store.json"
            backend_store = tmp / "backend_store.json"
            state_path = tmp / "state.json"
            audit_path = tmp / "audit.jsonl"

            self._write_local_store(
                local_store,
                [
                    {
                        "proposal_id": "p-denied",
                        "state": "APPROVED",
                        "receipt_id": "r-denied",
                        "program_id": "program:alpha",
                    }
                ],
            )

            telemetry = run_sync_job(
                local_store_path=local_store,
                backend_store_path=backend_store,
                state_path=state_path,
                job_id="sync-deny-test",
                access_context=AccessContext.from_values(
                    principal="agent:observer",
                    capabilities={"READ.CORPUS"},
                ),
                audit_path=audit_path,
            )

            events = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines() if line.strip()]

            self.assertEqual(telemetry.synced_count, 0)
            self.assertEqual(telemetry.error_count, 1)
            self.assertEqual(events[0]["event_type"], "CAPABILITY_DENIED")
            self.assertEqual(events[0]["action"], "SYNC")
            self.assertEqual(events[0]["outcome"], "DENY")
            self.assertEqual(events[0]["actor"], "agent:observer")
            self.assertEqual(events[0]["target_type"], "proposal")
            self.assertEqual(events[0]["target"], "p-denied")
            self.assertTrue(events[0]["timestamp_utc"])
            self.assertEqual(events[0]["proposal_id"], "p-denied")

    def test_sync_denies_unauthorized_write_when_no_approved_proposals(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            local_store = tmp / "local_store.json"
            backend_store = tmp / "backend_store.json"
            state_path = tmp / "state.json"
            audit_path = tmp / "audit.jsonl"

            self._write_local_store(
                local_store,
                [
                    {
                        "proposal_id": "p-not-approved",
                        "state": "PROPOSED",
                        "receipt_id": "r-not-approved",
                    }
                ],
            )

            telemetry = run_sync_job(
                local_store_path=local_store,
                backend_store_path=backend_store,
                state_path=state_path,
                job_id="sync-deny-no-approved",
                access_context=AccessContext.from_values(
                    principal="agent:observer",
                    capabilities={"READ.CORPUS"},
                ),
                audit_path=audit_path,
            )

            events = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines() if line.strip()]

            self.assertEqual(telemetry.synced_count, 0)
            self.assertEqual(telemetry.approved_total, 0)
            self.assertEqual(telemetry.error_count, 1)
            self.assertEqual(telemetry.errors[0].proposal_id, "sync-deny-no-approved")
            self.assertFalse(state_path.exists())
            self.assertFalse(backend_store.exists())
            self.assertEqual(events[0]["event_type"], "CAPABILITY_DENIED")
            self.assertEqual(events[0]["action"], "SYNC")
            self.assertEqual(events[0]["outcome"], "DENY")
            self.assertEqual(events[0]["proposal_id"], "sync-deny-no-approved")

    def test_sync_denies_scoped_write_when_program_id_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            local_store = tmp / "local_store.json"
            backend_store = tmp / "backend_store.json"
            state_path = tmp / "state.json"
            audit_path = tmp / "audit.jsonl"

            self._write_local_store(
                local_store,
                [
                    {
                        "proposal_id": "p-scoped-no-program",
                        "state": "APPROVED",
                        "receipt_id": "r-scoped-no-program",
                    }
                ],
            )

            telemetry = run_sync_job(
                local_store_path=local_store,
                backend_store_path=backend_store,
                state_path=state_path,
                job_id="sync-scoped-no-program",
                access_context=AccessContext.from_values(
                    principal="agent:scoped-writer",
                    capabilities={"WRITE.CORPUS_SYNC"},
                    allowed_program_ids={"program:alpha"},
                ),
                audit_path=audit_path,
            )

            events = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines() if line.strip()]

            self.assertEqual(telemetry.synced_count, 0)
            self.assertEqual(telemetry.error_count, 1)
            self.assertEqual(telemetry.errors[0].proposal_id, "p-scoped-no-program")
            self.assertFalse(backend_store.exists())
            self.assertFalse(state_path.exists())
            self.assertEqual(events[0]["event_type"], "ACCESS_DENIED")
            self.assertEqual(events[0]["action"], "SYNC")
            self.assertEqual(events[0]["outcome"], "DENY")
            self.assertEqual(events[0]["proposal_id"], "p-scoped-no-program")
            self.assertIn("requires scoped program_id", events[0]["reason"])

    def test_sync_resumes_after_partial_failure(self) -> None:
        class FlakyBackend:
            def __init__(self) -> None:
                self.artifacts: dict[str, dict[str, object]] = {}
                self.fail_once_for = {"p-2"}

            def has(self, proposal_id: str) -> bool:
                return proposal_id in self.artifacts

            def upsert(self, proposal: ProposalArtifact) -> None:
                if proposal.proposal_id in self.fail_once_for:
                    self.fail_once_for.remove(proposal.proposal_id)
                    raise RuntimeError("temporary backend outage")
                self.artifacts[proposal.proposal_id] = proposal.to_backend_json()

            def get(self, proposal_id: str) -> dict[str, object] | None:
                return self.artifacts.get(proposal_id)

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            state_store = SyncStateStore(tmp / "state.json")
            backend = FlakyBackend()
            worker = CorpusSyncWorker(backend=backend, state_store=state_store)
            proposals = [
                ProposalArtifact.from_json({"proposal_id": "p-1", "state": "APPROVED", "receipt_id": "r-1"}),
                ProposalArtifact.from_json({"proposal_id": "p-2", "state": "APPROVED", "receipt_id": "r-2"}),
            ]

            first = worker.sync(proposals, job_id="resume-1")
            second = worker.sync(proposals, job_id="resume-2")
            checkpoint = state_store.load()

            self.assertEqual(first.synced_count, 1)
            self.assertEqual(first.error_count, 1)
            self.assertEqual(first.errors[0].proposal_id, "p-2")

            self.assertTrue(second.resumed_from_checkpoint)
            self.assertEqual(second.already_synced_count, 1)
            self.assertEqual(second.synced_count, 1)
            self.assertEqual(second.error_count, 0)
            self.assertGreaterEqual(second.latency_ms, 0.0)
            self.assertEqual(sorted(checkpoint.synced_proposal_ids), ["p-1", "p-2"])

    def test_read_denies_unauthorized_request_and_audits(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            local_store = tmp / "local_store.json"
            backend_store = tmp / "backend_store.json"
            state_path = tmp / "state.json"
            audit_path = tmp / "audit.jsonl"

            self._write_local_store(
                local_store,
                [
                    {
                        "proposal_id": "p-read",
                        "state": "APPROVED",
                        "receipt_id": "r-read",
                        "program_id": "program:restricted",
                    }
                ],
            )

            sync_telemetry = run_sync_job(
                local_store_path=local_store,
                backend_store_path=backend_store,
                state_path=state_path,
                job_id="sync-before-read-deny",
            )
            self.assertEqual(sync_telemetry.error_count, 0)

            with self.assertRaises(AccessDeniedError):
                run_read_job(
                    backend_store_path=backend_store,
                    proposal_id="p-read",
                    access_context=AccessContext.from_values(
                        principal="agent:writer",
                        capabilities={"WRITE.CORPUS_SYNC"},
                    ),
                    audit_path=audit_path,
                )

            events = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines() if line.strip()]
            self.assertEqual(events[0]["event_type"], "CAPABILITY_DENIED")
            self.assertEqual(events[0]["action"], "READ")
            self.assertEqual(events[0]["outcome"], "DENY")
            self.assertEqual(events[0]["proposal_id"], "p-read")

    def test_read_enforces_program_scope(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            local_store = tmp / "local_store.json"
            backend_store = tmp / "backend_store.json"
            state_path = tmp / "state.json"
            audit_path = tmp / "audit.jsonl"

            self._write_local_store(
                local_store,
                [
                    {
                        "proposal_id": "p-scope",
                        "state": "APPROVED",
                        "receipt_id": "r-scope",
                        "program_id": "program:scope-a",
                    }
                ],
            )

            sync_telemetry = run_sync_job(
                local_store_path=local_store,
                backend_store_path=backend_store,
                state_path=state_path,
                job_id="sync-before-read-scope",
            )
            self.assertEqual(sync_telemetry.error_count, 0)

            with self.assertRaises(AccessDeniedError):
                run_read_job(
                    backend_store_path=backend_store,
                    proposal_id="p-scope",
                    access_context=AccessContext.from_values(
                        principal="agent:reader",
                        capabilities={"READ.CORPUS"},
                        allowed_program_ids={"program:scope-b"},
                    ),
                    audit_path=audit_path,
                )

            events = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines() if line.strip()]
            self.assertEqual(events[0]["event_type"], "ACCESS_DENIED")
            self.assertEqual(events[0]["action"], "READ")
            self.assertEqual(events[0]["outcome"], "DENY")
            self.assertEqual(events[0]["program_id"], "program:scope-a")

    def test_read_returns_artifact_when_authorized(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            local_store = tmp / "local_store.json"
            backend_store = tmp / "backend_store.json"
            state_path = tmp / "state.json"

            self._write_local_store(
                local_store,
                [
                    {
                        "proposal_id": "p-readable",
                        "state": "APPROVED",
                        "receipt_id": "r-readable",
                        "program_id": "program:alpha",
                    }
                ],
            )

            sync_telemetry = run_sync_job(
                local_store_path=local_store,
                backend_store_path=backend_store,
                state_path=state_path,
                job_id="sync-before-read-allow",
            )
            self.assertEqual(sync_telemetry.error_count, 0)

            artifact = run_read_job(
                backend_store_path=backend_store,
                proposal_id="p-readable",
                access_context=AccessContext.from_values(
                    principal="agent:reader",
                    capabilities={"READ.CORPUS"},
                    allowed_program_ids={"program:alpha"},
                ),
            )

            assert artifact is not None
            self.assertEqual(artifact["proposal_id"], "p-readable")
            self.assertEqual(artifact["receipt_id"], "r-readable")

    def test_read_denies_before_backend_lookup_when_capability_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            backend_store = tmp / "backend_store.json"
            audit_path = tmp / "audit.jsonl"
            backend_store.write_text("{invalid-json", encoding="utf-8")

            with self.assertRaises(AccessDeniedError) as ctx:
                run_read_job(
                    backend_store_path=backend_store,
                    proposal_id="p-precheck",
                    access_context=AccessContext.from_values(
                        principal="agent:writer",
                        capabilities={"WRITE.CORPUS_SYNC"},
                    ),
                    audit_path=audit_path,
                )

            self.assertIn("lacks capability 'READ.CORPUS'", str(ctx.exception))
            events = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines() if line.strip()]
            self.assertEqual(events[0]["event_type"], "CAPABILITY_DENIED")
            self.assertEqual(events[0]["action"], "READ")
            self.assertEqual(events[0]["outcome"], "DENY")
            self.assertEqual(events[0]["proposal_id"], "p-precheck")

    def test_read_denies_scoped_request_when_program_id_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            local_store = tmp / "local_store.json"
            backend_store = tmp / "backend_store.json"
            state_path = tmp / "state.json"
            audit_path = tmp / "audit.jsonl"

            self._write_local_store(
                local_store,
                [
                    {
                        "proposal_id": "p-read-scope-missing-program",
                        "state": "APPROVED",
                        "receipt_id": "r-read-scope-missing-program",
                    }
                ],
            )
            sync_telemetry = run_sync_job(
                local_store_path=local_store,
                backend_store_path=backend_store,
                state_path=state_path,
                job_id="sync-before-read-scope-missing-program",
            )
            self.assertEqual(sync_telemetry.error_count, 0)

            with self.assertRaises(AccessDeniedError) as ctx:
                run_read_job(
                    backend_store_path=backend_store,
                    proposal_id="p-read-scope-missing-program",
                    access_context=AccessContext.from_values(
                        principal="agent:scoped-reader",
                        capabilities={"READ.CORPUS"},
                        allowed_program_ids={"program:alpha"},
                    ),
                    audit_path=audit_path,
                )
            self.assertIn("requires scoped program_id", str(ctx.exception))

            events = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines() if line.strip()]
            self.assertEqual(events[0]["event_type"], "ACCESS_DENIED")
            self.assertEqual(events[0]["action"], "READ")
            self.assertEqual(events[0]["outcome"], "DENY")
            self.assertEqual(events[0]["proposal_id"], "p-read-scope-missing-program")
            self.assertIn("requires scoped program_id", events[0]["reason"])

    def test_read_rejects_incomplete_provenance_chain(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            local_store = tmp / "local_store.json"
            backend_store = tmp / "backend_store.json"
            state_path = tmp / "state.json"
            audit_path = tmp / "audit.jsonl"

            self._write_local_store(
                local_store,
                [
                    {
                        "proposal_id": "p-read-invalid-chain",
                        "state": "APPROVED",
                        "receipt_id": "r-3",
                        "provenance_chain": ["r-1", "r-2", "r-3"],
                    }
                ],
            )
            sync_telemetry = run_sync_job(
                local_store_path=local_store,
                backend_store_path=backend_store,
                state_path=state_path,
                job_id="sync-before-read-invalid-chain",
            )
            self.assertEqual(sync_telemetry.error_count, 0)

            backend_doc = json.loads(backend_store.read_text(encoding="utf-8"))
            backend_doc["artifacts"]["p-read-invalid-chain"]["provenance_chain"] = [
                {"receipt_id": "r-1"},
                {"receipt_id": "r-2"},
                {"receipt_id": "r-3", "previous_receipt_id": "r-2"},
            ]
            backend_store.write_text(json.dumps(backend_doc, indent=2) + "\n", encoding="utf-8")

            with self.assertRaises(ValueError) as ctx:
                run_read_job(
                    backend_store_path=backend_store,
                    proposal_id="p-read-invalid-chain",
                    audit_path=audit_path,
                )
            self.assertIn("missing previous_receipt_id", str(ctx.exception))

            events = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines() if line.strip()]
            self.assertEqual(events[0]["event_type"], "ACCESS_GRANTED")
            self.assertEqual(events[0]["action"], "READ")
            self.assertEqual(events[0]["outcome"], "ALLOW")
            self.assertEqual(events[1]["event_type"], "PROVENANCE_CHAIN_INVALID")
            self.assertEqual(events[1]["action"], "READ")
            self.assertEqual(events[1]["outcome"], "DENY")
            self.assertEqual(events[1]["proposal_id"], "p-read-invalid-chain")

    def test_sync_policy_modes_are_configurable_per_project(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            local_store = tmp / "local_store.json"
            backend_store = tmp / "backend_store.json"
            state_path = tmp / "state.json"
            audit_path = tmp / "audit.jsonl"

            self._write_local_store(
                local_store,
                [
                    {
                        "proposal_id": "p-cloud",
                        "state": "APPROVED",
                        "receipt_id": "r-cloud",
                        "project_id": "project:cloud",
                    },
                    {
                        "proposal_id": "p-offline",
                        "state": "APPROVED",
                        "receipt_id": "r-offline",
                        "project_id": "project:offline",
                    },
                ],
            )

            policy_config = EndpointPolicyConfig(
                default_rule=EndpointPolicyRule(mode="cloud"),
                project_rules={
                    "project:cloud": EndpointPolicyRule(mode="cloud"),
                    "project:offline": EndpointPolicyRule(mode="offline"),
                },
            )

            telemetry = run_sync_job(
                local_store_path=local_store,
                backend_store_path=backend_store,
                state_path=state_path,
                job_id="sync-policy-per-project",
                audit_path=audit_path,
                policy_config=policy_config,
                backend_endpoint="https://api.example.com/v1/corpus",
            )

            backend = json.loads(backend_store.read_text(encoding="utf-8"))
            events = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines() if line.strip()]
            blocked = [event for event in events if event.get("event_type") == "EGRESS_BLOCKED"]

            self.assertEqual(telemetry.synced_count, 1)
            self.assertEqual(telemetry.error_count, 1)
            self.assertEqual(telemetry.errors[0].proposal_id, "p-offline")
            self.assertEqual(sorted(backend["artifacts"].keys()), ["p-cloud"])
            self.assertEqual(len(blocked), 1)
            self.assertEqual(blocked[0]["project_id"], "project:offline")
            self.assertEqual(blocked[0]["policy_mode"], "offline")

    def test_allowlist_mode_blocks_non_approved_destination(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            local_store = tmp / "local_store.json"
            backend_store = tmp / "backend_store.json"
            state_path = tmp / "state.json"
            audit_path = tmp / "audit.jsonl"

            self._write_local_store(
                local_store,
                [
                    {
                        "proposal_id": "p-allowlist",
                        "state": "APPROVED",
                        "receipt_id": "r-allowlist",
                        "project_id": "project:allowlist",
                    }
                ],
            )

            policy_config = EndpointPolicyConfig(
                default_rule=EndpointPolicyRule(
                    mode="allowlist",
                    allowed_endpoints=frozenset({"https://api.allowed.example"}),
                ),
            )

            telemetry = run_sync_job(
                local_store_path=local_store,
                backend_store_path=backend_store,
                state_path=state_path,
                job_id="sync-allowlist-block",
                audit_path=audit_path,
                policy_config=policy_config,
                backend_endpoint="https://api.blocked.example/v1/corpus",
            )

            events = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines() if line.strip()]
            blocked = [event for event in events if event.get("event_type") == "EGRESS_BLOCKED"]

            self.assertEqual(telemetry.synced_count, 0)
            self.assertEqual(telemetry.error_count, 1)
            self.assertEqual(telemetry.errors[0].proposal_id, "p-allowlist")
            self.assertFalse(backend_store.exists())
            self.assertFalse(state_path.exists())
            self.assertEqual(len(blocked), 1)
            self.assertEqual(blocked[0]["action"], "SYNC")
            self.assertEqual(blocked[0]["outcome"], "DENY")
            self.assertEqual(blocked[0]["policy_mode"], "allowlist")
            self.assertEqual(blocked[0]["target_type"], "destination")
            self.assertEqual(blocked[0]["target"], "https://api.blocked.example/v1/corpus")
            self.assertEqual(blocked[0]["destination"], "https://api.blocked.example/v1/corpus")
            incidents = [event for event in events if event.get("kind") == "corpus_violation_incident"]
            self.assertEqual(len(incidents), 1)
            self.assertEqual(incidents[0]["source_event_type"], "EGRESS_BLOCKED")
            self.assertEqual(
                incidents[0]["remediation_action"],
                "DENY_EGRESS_AND_REQUIRE_ALLOWLIST_UPDATE",
            )
            self.assertEqual(incidents[0]["policy_context"]["policy_mode"], "allowlist")

    def test_audit_log_query_filters_records_for_compliance_review(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            local_store = tmp / "local_store.json"
            backend_store = tmp / "backend_store.json"
            state_path = tmp / "state.json"
            audit_path = tmp / "audit.jsonl"

            self._write_local_store(
                local_store,
                [
                    {
                        "proposal_id": "p-query",
                        "state": "APPROVED",
                        "receipt_id": "r-query",
                    }
                ],
            )

            telemetry = run_sync_job(
                local_store_path=local_store,
                backend_store_path=backend_store,
                state_path=state_path,
                job_id="sync-query-audit",
                access_context=AccessContext.from_values(
                    principal="agent:auditor",
                    capabilities={"READ.CORPUS"},
                ),
                audit_path=audit_path,
            )
            self.assertEqual(telemetry.error_count, 1)

            deny_audits = query_audit_log_records(
                audit_path,
                kind="corpus_access_audit",
                event_type="CAPABILITY_DENIED",
                principal="agent:auditor",
                action="SYNC",
                outcome="DENY",
                target="p-query",
            )
            self.assertEqual(len(deny_audits), 1)
            self.assertEqual(deny_audits[0]["target_type"], "proposal")

            deny_incidents = query_audit_log_records(
                audit_path,
                kind="corpus_violation_incident",
                event_type="CAPABILITY_DENIED",
                principal="agent:auditor",
                action="SYNC",
                outcome="DENY",
                limit=1,
            )
            self.assertEqual(len(deny_incidents), 1)
            self.assertEqual(
                deny_incidents[0]["remediation_action"],
                "DENY_ACTION_AND_REQUIRE_CAPABILITY_GRANT",
            )

    def test_policy_violation_mitigation_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            local_store = tmp / "local_store.json"
            backend_store = tmp / "backend_store.json"
            state_path = tmp / "state.json"
            audit_path = tmp / "audit.jsonl"

            self._write_local_store(
                local_store,
                [
                    {
                        "proposal_id": "p-deterministic",
                        "state": "APPROVED",
                        "receipt_id": "r-deterministic",
                        "project_id": "project:deterministic",
                    }
                ],
            )

            policy_config = EndpointPolicyConfig(
                default_rule=EndpointPolicyRule(
                    mode="allowlist",
                    allowed_endpoints=frozenset({"https://api.allowed.example"}),
                ),
            )
            blocked_destination = "https://api.blocked.example/v1/corpus"
            expected_reason = (
                "policy mode 'allowlist' blocks destination "
                "'https://api.blocked.example/v1/corpus' for project "
                "'project:deterministic': destination is not allowlisted"
            )

            first = run_sync_job(
                local_store_path=local_store,
                backend_store_path=backend_store,
                state_path=state_path,
                job_id="sync-deterministic-1",
                audit_path=audit_path,
                policy_config=policy_config,
                backend_endpoint=blocked_destination,
            )
            second = run_sync_job(
                local_store_path=local_store,
                backend_store_path=backend_store,
                state_path=state_path,
                job_id="sync-deterministic-2",
                audit_path=audit_path,
                policy_config=policy_config,
                backend_endpoint=blocked_destination,
            )

            events = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines() if line.strip()]
            blocked_reasons = [event["reason"] for event in events if event.get("event_type") == "EGRESS_BLOCKED"]

            self.assertEqual(first.synced_count, 0)
            self.assertEqual(second.synced_count, 0)
            self.assertEqual(first.error_count, 1)
            self.assertEqual(second.error_count, 1)
            self.assertEqual(first.errors[0].error, expected_reason)
            self.assertEqual(second.errors[0].error, expected_reason)
            self.assertEqual(blocked_reasons, [expected_reason, expected_reason])
            self.assertFalse(backend_store.exists())
            self.assertFalse(state_path.exists())

    def test_read_blocks_non_allowlisted_destination(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            backend_store = tmp / "backend_store.json"
            audit_path = tmp / "audit.jsonl"
            backend_store.write_text("{invalid-json", encoding="utf-8")

            policy_config = EndpointPolicyConfig(
                default_rule=EndpointPolicyRule(
                    mode="allowlist",
                    allowed_endpoints=frozenset({"https://api.allowed.example"}),
                ),
            )

            with self.assertRaises(AccessDeniedError) as ctx:
                run_read_job(
                    backend_store_path=backend_store,
                    proposal_id="p-read-policy",
                    project_id="project:read-policy",
                    audit_path=audit_path,
                    policy_config=policy_config,
                    backend_endpoint="https://api.blocked.example/v1/corpus",
                )

            self.assertEqual(
                str(ctx.exception),
                "policy mode 'allowlist' blocks destination "
                "'https://api.blocked.example/v1/corpus' for project "
                "'project:read-policy': destination is not allowlisted",
            )
            events = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines() if line.strip()]
            self.assertEqual(events[0]["event_type"], "EGRESS_BLOCKED")
            self.assertEqual(events[0]["action"], "READ")
            self.assertEqual(events[0]["outcome"], "DENY")

    def test_cli_run_writes_telemetry_with_counts_errors_and_latency(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            local_store = tmp / "local_store.json"
            backend_store = tmp / "backend_store.json"
            state_path = tmp / "state.json"
            telemetry_path = tmp / "telemetry.jsonl"

            self._write_local_store(
                local_store,
                [
                    {"proposal_id": "p-approved", "state": "APPROVED", "receipt_id": "r-1"},
                    {"proposal_id": "p-proposed", "state": "PROPOSED", "receipt_id": "r-2"},
                ],
            )

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = MODULE.main(
                    [
                        "--local-store",
                        str(local_store),
                        "--backend-store",
                        str(backend_store),
                        "--state-path",
                        str(state_path),
                        "--telemetry-path",
                        str(telemetry_path),
                        "--job-id",
                        "sync-telemetry-test",
                    ]
                )
            events = telemetry_path.read_text(encoding="utf-8").strip().splitlines()
            telemetry_event = json.loads(events[0])

            self.assertEqual(exit_code, 0)
            self.assertEqual(len(events), 1)
            self.assertEqual(telemetry_event["kind"], "corpus_sync_run")
            self.assertEqual(telemetry_event["scanned_total"], 2)
            self.assertEqual(telemetry_event["approved_total"], 1)
            self.assertEqual(telemetry_event["skipped_non_approved"], 1)
            self.assertEqual(telemetry_event["error_count"], 0)
            self.assertGreaterEqual(telemetry_event["latency_ms"], 0.0)


if __name__ == "__main__":
    unittest.main()
