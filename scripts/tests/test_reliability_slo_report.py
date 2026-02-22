from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[2] / "eval" / "scripts" / "reliability_slo_report.py"
SPEC = importlib.util.spec_from_file_location("reliability_slo_report", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"failed to load module spec from {MODULE_PATH}")
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class ReliabilitySloReportTest(unittest.TestCase):
    def test_report_builds_and_fails_on_breach(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            soak_path = tmp / "soak.json"
            thresholds_path = tmp / "thresholds.json"
            output_json = tmp / "out" / "reliability.json"
            output_md = tmp / "out" / "reliability.md"

            soak_path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "soak_test": {"iterations": 3},
                        "iterations": [
                            {
                                "iteration": 0,
                                "metrics": {"type": {"accuracy": 1.0}},
                                "reliability": {
                                    "completed": True,
                                    "deadlock": False,
                                    "fallback_applied": False,
                                    "error": False,
                                },
                            },
                            {
                                "iteration": 1,
                                "metrics": {"type": {"accuracy": 1.0}},
                                "reliability": {
                                    "completed": True,
                                    "deadlock": False,
                                    "fallback_applied": True,
                                    "error": False,
                                },
                            },
                            {
                                "iteration": 2,
                                "metrics": {},
                                "reliability": {
                                    "completed": False,
                                    "deadlock": False,
                                    "fallback_applied": False,
                                    "error": True,
                                },
                            },
                        ],
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )

            thresholds_path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "metrics": {
                            "deadlock_rate": {"operator": "<=", "threshold": 0.0},
                            "fallback_rate": {"operator": "<=", "threshold": 0.1},
                            "error_rate": {"operator": "<=", "threshold": 0.0},
                            "successful_completion_slo": {"operator": ">=", "threshold": 0.95},
                        },
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )

            exit_code = MODULE.main(
                [
                    "--soak-report",
                    str(soak_path),
                    "--thresholds",
                    str(thresholds_path),
                    "--output-json",
                    str(output_json),
                    "--output-md",
                    str(output_md),
                    "--fail-on-breach",
                ]
            )
            self.assertEqual(exit_code, 1)

            report = json.loads(output_json.read_text(encoding="utf-8"))
            markdown = output_md.read_text(encoding="utf-8")

            self.assertEqual(report["metrics"]["deadlock_rate"], 0.0)
            self.assertEqual(report["metrics"]["fallback_rate"], 0.333333)
            self.assertEqual(report["metrics"]["error_rate"], 0.333333)
            self.assertEqual(report["metrics"]["successful_completion_slo"], 0.666667)
            self.assertFalse(report["evaluation"]["passed"])
            self.assertGreaterEqual(len(report["evaluation"]["breaches"]), 1)
            self.assertIn("Reliability SLO Report", markdown)
            self.assertIn("Threshold Evaluation", markdown)

    def test_legacy_soak_without_reliability_fields_defaults_clean(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            soak_path = tmp / "legacy-soak.json"
            thresholds_path = tmp / "thresholds.json"
            output_json = tmp / "out" / "reliability.json"
            output_md = tmp / "out" / "reliability.md"

            soak_path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "soak_test": {"iterations": 2},
                        "iterations": [
                            {"iteration": 0, "metrics": {"type": {"accuracy": 1.0}}},
                            {"iteration": 1, "metrics": {"type": {"accuracy": 1.0}}},
                        ],
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )

            thresholds_path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "metrics": {
                            "deadlock_rate": {"operator": "<=", "threshold": 0.0},
                            "fallback_rate": {"operator": "<=", "threshold": 0.0},
                            "error_rate": {"operator": "<=", "threshold": 0.0},
                            "successful_completion_slo": {"operator": ">=", "threshold": 1.0},
                        },
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )

            exit_code = MODULE.main(
                [
                    "--soak-report",
                    str(soak_path),
                    "--thresholds",
                    str(thresholds_path),
                    "--output-json",
                    str(output_json),
                    "--output-md",
                    str(output_md),
                    "--fail-on-breach",
                ]
            )
            self.assertEqual(exit_code, 0)

            report = json.loads(output_json.read_text(encoding="utf-8"))
            self.assertEqual(report["metrics"]["deadlock_rate"], 0.0)
            self.assertEqual(report["metrics"]["fallback_rate"], 0.0)
            self.assertEqual(report["metrics"]["error_rate"], 0.0)
            self.assertEqual(report["metrics"]["successful_completion_slo"], 1.0)
            self.assertTrue(report["evaluation"]["passed"])


if __name__ == "__main__":
    unittest.main()
