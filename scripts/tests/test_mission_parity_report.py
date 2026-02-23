from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[2] / "eval" / "scripts" / "mission_parity_report.py"
SPEC = importlib.util.spec_from_file_location("mission_parity_report", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"failed to load module spec from {MODULE_PATH}")
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def _doc(mode: str) -> dict[str, object]:
    return {
        "schema_version": 1,
        "mission_id": "e25.conformance.fixture",
        "execution_mode": mode,
        "flows": {
            "mission_launch": {
                "status": "completed",
                "outcome": "success",
                "stage_order": ["primary_supervised", "classify_failure", "fallback_route"],
                "generated_at_utc": "2026-02-23T01:00:00Z",
            },
            "checkpoint_resume": {
                "resumed": True,
                "resume_checkpoint_id": "checkpoint-1",
                "replayed_stage_ids": ["fallback_route"],
                "execution_order": ["primary_supervised", "classify_failure", "fallback_route"],
                "updated_at": "2026-02-23T01:01:00Z",
            },
            "artifact_export": {
                "export_status": "success",
                "export_path": f"/tmp/{mode}/exports",
                "artifacts": [
                    {
                        "artifact_id": "mission.log",
                        "semantic_type": "log",
                        "sha256": "bbbb",
                        "bytes": 512,
                    },
                    {
                        "artifact_id": "triage.summary.json",
                        "semantic_type": "json_summary",
                        "sha256": "aaaa",
                        "bytes": 1024,
                    },
                ],
            },
        },
    }


class MissionParityReportTest(unittest.TestCase):
    def test_semantic_parity_passes_with_non_semantic_differences(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            headless = tmp / "headless.json"
            cockpit = tmp / "cockpit.json"
            output_json = tmp / "out" / "parity.json"
            output_md = tmp / "out" / "parity.md"

            headless_doc = _doc("headless")
            cockpit_doc = _doc("cockpit")
            # Reorder artifacts to confirm semantic sort behavior.
            cockpit_doc["flows"]["artifact_export"]["artifacts"] = list(
                reversed(cockpit_doc["flows"]["artifact_export"]["artifacts"])
            )
            headless.write_text(json.dumps(headless_doc, indent=2) + "\n", encoding="utf-8")
            cockpit.write_text(json.dumps(cockpit_doc, indent=2) + "\n", encoding="utf-8")

            rc = MODULE.main(
                [
                    "--headless",
                    str(headless),
                    "--cockpit",
                    str(cockpit),
                    "--output-json",
                    str(output_json),
                    "--output-md",
                    str(output_md),
                    "--fail-on-mismatch",
                ]
            )
            self.assertEqual(rc, 0)

            report = json.loads(output_json.read_text(encoding="utf-8"))
            self.assertTrue(report["evaluation"]["passed"])
            self.assertEqual(
                report["evaluation"]["covered_flows"],
                ["mission_launch", "checkpoint_resume", "artifact_export"],
            )
            self.assertEqual(report["evaluation"]["mismatch_count"], 0)

    def test_semantic_mismatch_fails_gate(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            headless = tmp / "headless.json"
            cockpit = tmp / "cockpit.json"
            output_json = tmp / "out" / "parity.json"
            output_md = tmp / "out" / "parity.md"

            headless_doc = _doc("headless")
            cockpit_doc = _doc("cockpit")
            cockpit_doc["flows"]["checkpoint_resume"]["replayed_stage_ids"] = ["classify_failure"]
            headless.write_text(json.dumps(headless_doc, indent=2) + "\n", encoding="utf-8")
            cockpit.write_text(json.dumps(cockpit_doc, indent=2) + "\n", encoding="utf-8")

            rc = MODULE.main(
                [
                    "--headless",
                    str(headless),
                    "--cockpit",
                    str(cockpit),
                    "--output-json",
                    str(output_json),
                    "--output-md",
                    str(output_md),
                    "--fail-on-mismatch",
                ]
            )
            self.assertEqual(rc, 1)

            report = json.loads(output_json.read_text(encoding="utf-8"))
            self.assertFalse(report["evaluation"]["passed"])
            self.assertGreaterEqual(report["evaluation"]["mismatch_count"], 1)
            self.assertEqual(report["mismatches"][0]["flow"], "checkpoint_resume")


if __name__ == "__main__":
    unittest.main()
