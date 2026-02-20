from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
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


if __name__ == "__main__":
    unittest.main()

