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
ProposalArtifact = MODULE.ProposalArtifact
SyncStateStore = MODULE.SyncStateStore
run_read_job = MODULE.run_read_job
run_sync_job = MODULE.run_sync_job


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
            self.assertEqual(events[0]["proposal_id"], "p-denied")

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
