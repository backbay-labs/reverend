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

CorpusSyncWorker = MODULE.CorpusSyncWorker
ProposalArtifact = MODULE.ProposalArtifact
SyncStateStore = MODULE.SyncStateStore
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
