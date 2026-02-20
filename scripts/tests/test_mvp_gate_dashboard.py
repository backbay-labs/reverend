from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[2] / "eval" / "scripts" / "mvp_gate_dashboard.py"
SPEC = importlib.util.spec_from_file_location("mvp_gate_dashboard", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"failed to load module spec from {MODULE_PATH}")
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class MvpGateDashboardTest(unittest.TestCase):
    def test_dashboard_and_alerts_are_built_from_run_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            artifacts_dir = tmp / "runs"
            output_dir = tmp / "dashboard"
            artifacts_dir.mkdir(parents=True, exist_ok=True)

            thresholds_path = tmp / "mvp_gate_thresholds.json"
            thresholds_path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "gates": {
                            "recall_at_10_delta_vs_stock": {
                                "operator": ">=",
                                "threshold": 0.1,
                            },
                            "search_latency_p95_ms": {
                                "operator": "<=",
                                "threshold": 300.0,
                            },
                            "receipt_completeness": {
                                "operator": "==",
                                "threshold": 1.0,
                            },
                            "rollback_success_rate": {
                                "operator": "==",
                                "threshold": 1.0,
                            },
                        },
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )

            (artifacts_dir / "run-1.json").write_text(
                json.dumps(
                    {
                        "run_id": "run-1",
                        "timestamp": "2026-02-20T01:00:00Z",
                        "commit_sha": "aaa111",
                        "metrics": {
                            "recall_at_10_delta_vs_stock": 0.25,
                            "search_latency_p95_ms": 145.0,
                            "receipt_completeness": 1.0,
                            "rollback_success_rate": 1.0,
                        },
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
            (artifacts_dir / "run-2.json").write_text(
                json.dumps(
                    {
                        "run_id": "run-2",
                        "timestamp": "2026-02-20T02:00:00Z",
                        "commit_sha": "bbb222",
                        "metrics": {
                            "recall_at_10_delta_vs_stock": 0.05,
                            "search_latency_p95_ms": 210.0,
                            "receipt_completeness": 1.0,
                            "rollback_success_rate": 1.0,
                        },
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )

            exit_code = MODULE.main(
                [
                    "--artifacts-dir",
                    str(artifacts_dir),
                    "--thresholds",
                    str(thresholds_path),
                    "--output-dir",
                    str(output_dir),
                ]
            )
            self.assertEqual(exit_code, 0)

            dashboard = json.loads((output_dir / "dashboard.json").read_text(encoding="utf-8"))
            alerts = json.loads((output_dir / "alerts.json").read_text(encoding="utf-8"))
            markdown = (output_dir / "dashboard.md").read_text(encoding="utf-8")

            self.assertEqual(dashboard["run_count"], 2)
            self.assertEqual(dashboard["current_run"]["run_id"], "run-2")
            self.assertEqual(dashboard["current_run"]["status"], "failed")
            self.assertEqual(
                dashboard["trend"]["recall_at_10_delta_vs_stock"]["delta"],
                -0.2,
            )

            self.assertEqual(len(alerts["alerts"]), 1)
            self.assertEqual(alerts["alerts"][0]["metric_name"], "recall_at_10_delta_vs_stock")
            self.assertIn("Gate Status", markdown)


if __name__ == "__main__":
    unittest.main()
