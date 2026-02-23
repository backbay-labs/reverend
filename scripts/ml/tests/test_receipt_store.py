from __future__ import annotations

import importlib.util
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "receipt_store.py"
SPEC = importlib.util.spec_from_file_location("e2_receipt_store", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"failed to load module spec from {MODULE_PATH}")
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

AppendOnlyViolationError = MODULE.AppendOnlyViolationError
ReceiptStore = MODULE.ReceiptStore
ReceiptStoreIntegrityError = MODULE.ReceiptStoreIntegrityError
main = MODULE.main


class ReceiptStoreTest(unittest.TestCase):
    def _base_receipt(self, *, receipt_id: str, target_id: str, action: str = "rename") -> dict[str, object]:
        return {
            "receipt_id": receipt_id,
            "timestamp": "2026-02-20T07:00:00Z",
            "actor": {
                "actor": "agent:renamer-v2",
                "actor_type": "agent",
            },
            "action": action,
            "target": {
                "target_type": "FUNCTION",
                "target_id": target_id,
                "old_value": "FUN_0010",
                "new_value": "parse_http_header",
            },
            "evidence": [
                {
                    "evidence_type": "string_match",
                    "source_type": "string_index",
                    "source_id": "evidence:http-signature",
                    "metadata": {"token": "HTTP/1.1"},
                }
            ],
            "metadata": {
                "confidence": 0.94,
            },
        }

    def _applied_proposal_receipt(
        self,
        *,
        receipt_id: str,
        proposal_id: str = "evp_http_parser_proposal_1",
        target_id: str = "func-http-1",
        with_raw_signal: bool = True,
    ) -> dict[str, object]:
        evidence: list[dict[str, object]] = []
        if with_raw_signal:
            evidence.append(
                {
                    "evidence_type": "callsite_signal",
                    "source_type": "static_analysis",
                    "source_id": "evidence:callsite:001",
                    "entity_type": "static",
                    "entity_id": "evs_http_signature_1",
                    "entity_schema_version": 1,
                    "edge": {
                        "edge_type": "supports",
                        "target_entity_type": "proposal",
                        "target_entity_id": proposal_id,
                        "target_entity_schema_version": 1,
                    },
                    "metadata": {"confidence": 0.91},
                }
            )
        evidence.append(
            {
                "evidence_type": "receipt_link",
                "source_type": "receipt_store",
                "source_id": "evidence:receipt-link:001",
                "entity_type": "receipt",
                "entity_id": "evr_apply_stage_1",
                "entity_schema_version": 1,
                "edge": {
                    "edge_type": "supports",
                    "target_entity_type": "proposal",
                    "target_entity_id": proposal_id,
                    "target_entity_schema_version": 1,
                },
                "metadata": {"stage": "apply"},
            }
        )
        return {
            "receipt_id": receipt_id,
            "timestamp": "2026-02-20T07:05:00Z",
            "actor": {
                "actor": "agent:apply-worker-v1",
                "actor_type": "agent",
            },
            "action": "APPLY",
            "target": {
                "target_type": "FUNCTION",
                "target_id": target_id,
            },
            "evidence": evidence,
            "metadata": {
                "applied_proposal_id": proposal_id,
            },
        }

    def test_append_builds_chain_and_preserves_linkage_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store_path = Path(tmpdir) / "receipts.json"
            store = ReceiptStore(store_path)

            first = store.append(self._base_receipt(receipt_id="r-1", target_id="func-1"))
            second = store.append(self._base_receipt(receipt_id="r-2", target_id="func-2"))

            self.assertEqual(first["chain"]["sequence_number"], 0)
            self.assertIsNone(first["chain"]["previous_receipt_id"])
            self.assertIsNone(first["chain"]["previous_hash"])

            self.assertEqual(second["chain"]["sequence_number"], 1)
            self.assertEqual(second["chain"]["previous_receipt_id"], "r-1")
            self.assertEqual(second["chain"]["previous_hash"], first["hash"])

            self.assertEqual(second["actor"]["actor"], "agent:renamer-v2")
            self.assertEqual(second["action"], "rename")
            self.assertEqual(second["target"]["target_id"], "func-2")
            self.assertEqual(second["evidence"][0]["source_id"], "evidence:http-signature")

            report = store.verify_integrity()
            self.assertTrue(report.ok)
            self.assertEqual(report.issue_count, 0)

    def test_append_rejects_duplicate_receipt_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = ReceiptStore(Path(tmpdir) / "receipts.json")
            store.append(self._base_receipt(receipt_id="r-1", target_id="func-1"))

            with self.assertRaises(AppendOnlyViolationError):
                store.append(self._base_receipt(receipt_id="r-1", target_id="func-1"))

    def test_append_rejects_conflicting_chain_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = ReceiptStore(Path(tmpdir) / "receipts.json")
            store.append(self._base_receipt(receipt_id="r-1", target_id="func-1"))

            payload = self._base_receipt(receipt_id="r-2", target_id="func-2")
            payload["chain"] = {
                "sequence_number": 9,
                "previous_receipt_id": "wrong-parent",
                "previous_hash": "0" * 64,
            }
            with self.assertRaises(ValueError):
                store.append(payload)

    def test_verify_integrity_detects_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store_path = Path(tmpdir) / "receipts.json"
            store = ReceiptStore(store_path)
            store.append(self._base_receipt(receipt_id="r-1", target_id="func-1"))
            store.append(self._base_receipt(receipt_id="r-2", target_id="func-2"))

            raw = json.loads(store_path.read_text(encoding="utf-8"))
            raw["receipts"][0]["target"]["new_value"] = "tampered_name"
            store_path.write_text(json.dumps(raw, indent=2, sort_keys=True) + "\n", encoding="utf-8")

            tampered = ReceiptStore(store_path)
            report = tampered.verify_integrity()
            self.assertFalse(report.ok)
            self.assertGreater(report.issue_count, 0)
            self.assertIn("hash mismatch", report.issues[0].reason)

            with self.assertRaises(ReceiptStoreIntegrityError):
                tampered.append(self._base_receipt(receipt_id="r-3", target_id="func-3"))

    def test_append_accepts_canonical_evidence_entity_and_edge_contract(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = ReceiptStore(Path(tmpdir) / "receipts.json")
            payload = self._base_receipt(receipt_id="r-1", target_id="func-1")
            payload["evidence"] = [
                {
                    "evidence_type": "type_support",
                    "source_type": "symbolic_solver",
                    "source_id": "evidence:ssa-pass-1",
                    "entity_type": "symbolic",
                    "entity_id": "evy_solver-path-01",
                    "entity_schema_version": 1,
                    "edge": {
                        "edge_type": "supports",
                        "target_entity_type": "proposal",
                        "target_entity_id": "evp_type-proposal-1",
                        "target_entity_schema_version": 1,
                    },
                    "metadata": {"path_constraints": 4},
                }
            ]
            stored = store.append(payload)
            self.assertEqual(stored["evidence"][0]["entity_type"], "symbolic")
            self.assertEqual(stored["evidence"][0]["edge"]["edge_type"], "supports")

    def test_append_rejects_invalid_canonical_cross_source_edge_contract(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = ReceiptStore(Path(tmpdir) / "receipts.json")
            payload = self._base_receipt(receipt_id="r-1", target_id="func-1")
            payload["evidence"] = [
                {
                    "evidence_type": "invalid_contract",
                    "source_type": "symbolic_solver",
                    "source_id": "evidence:ssa-pass-1",
                    "entity_type": "symbolic",
                    "entity_id": "evy_solver-path-01",
                    "entity_schema_version": 1,
                    "edge": {
                        "edge_type": "supports",
                        "target_entity_type": "dynamic",
                        "target_entity_id": "evd_trace-step-9",
                        "target_entity_schema_version": 1,
                    },
                    "metadata": {},
                }
            ]
            with self.assertRaises(ValueError):
                store.append(payload)

    def test_verify_provenance_builds_explainability_packet_for_applied_proposal(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = ReceiptStore(Path(tmpdir) / "receipts.json")
            store.append(self._base_receipt(receipt_id="r-setup", target_id="func-setup"))
            apply_receipt = self._applied_proposal_receipt(receipt_id="r-apply")
            stored_apply = store.append(apply_receipt)

            report = store.verify_provenance()
            self.assertTrue(report.ok)
            self.assertEqual(report.issue_count, 0)

            packet = report.explainability_packet
            self.assertEqual(packet["kind"], "applied_proposal_explainability_packet")
            self.assertEqual(len(packet["applied_proposals"]), 1)
            chain_entry = packet["applied_proposals"][0]
            self.assertEqual(chain_entry["proposal_id"], "evp_http_parser_proposal_1")
            self.assertEqual(chain_entry["applied_receipt_id"], "r-apply")

            canonical_chain = chain_entry["canonical_chain"]
            self.assertEqual(canonical_chain[0]["entity_type"], "static")
            self.assertEqual(canonical_chain[1]["entity_type"], "proposal")
            self.assertEqual(canonical_chain[-2]["kind"], "receipt")
            self.assertEqual(canonical_chain[-2]["receipt_id"], stored_apply["receipt_id"])
            self.assertEqual(canonical_chain[-2]["link_type"], "APPLIED_BY_RECEIPT")
            self.assertEqual(canonical_chain[-1]["kind"], "annotation")
            self.assertEqual(canonical_chain[-1]["target_type"], "FUNCTION")

            generated_packet = store.build_explainability_packet()
            self.assertEqual(generated_packet["applied_proposals"][0]["proposal_id"], "evp_http_parser_proposal_1")

    def test_verify_provenance_detects_missing_raw_signal_link(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = ReceiptStore(Path(tmpdir) / "receipts.json")
            store.append(self._base_receipt(receipt_id="r-setup", target_id="func-setup"))
            store.append(self._applied_proposal_receipt(receipt_id="r-apply", with_raw_signal=False))

            report = store.verify_provenance()
            self.assertFalse(report.ok)
            reasons = [issue.reason for issue in report.issues]
            self.assertTrue(
                any("missing raw-signal evidence chain to proposal" in reason for reason in reasons)
            )
            self.assertEqual(report.explainability_packet["applied_proposals"], [])

    def test_verify_provenance_cli_is_gate_compatible(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            failing_store_path = Path(tmpdir) / "failing-receipts.json"
            failing_store = ReceiptStore(failing_store_path)
            failing_store.append(self._base_receipt(receipt_id="r-setup", target_id="func-setup"))
            failing_store.append(
                self._applied_proposal_receipt(
                    receipt_id="r-apply",
                    with_raw_signal=False,
                )
            )

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                failing_exit = main(["verify-provenance", "--store", str(failing_store_path)])
            self.assertEqual(failing_exit, 1)
            failing_payload = json.loads(stdout.getvalue())
            self.assertEqual(failing_payload["kind"], "provenance_chain_verification_report")
            self.assertFalse(failing_payload["ok"])
            self.assertGreater(failing_payload["issue_count"], 0)
            self.assertEqual(failing_payload["explainability_packet"]["kind"], "applied_proposal_explainability_packet")

            passing_store_path = Path(tmpdir) / "passing-receipts.json"
            passing_store = ReceiptStore(passing_store_path)
            passing_store.append(self._base_receipt(receipt_id="r-setup", target_id="func-setup"))
            passing_store.append(self._applied_proposal_receipt(receipt_id="r-apply-ok"))

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                passing_exit = main(["verify-provenance", "--store", str(passing_store_path)])
            self.assertEqual(passing_exit, 0)
            passing_payload = json.loads(stdout.getvalue())
            self.assertTrue(passing_payload["ok"])
            self.assertEqual(passing_payload["issue_count"], 0)
            self.assertEqual(len(passing_payload["explainability_packet"]["applied_proposals"]), 1)


if __name__ == "__main__":
    unittest.main()
