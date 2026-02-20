from __future__ import annotations

import importlib.util
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parent / "no_direct_agent_write_invariant.py"
SPEC = importlib.util.spec_from_file_location("no_direct_agent_write_invariant", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"failed to load module spec from {MODULE_PATH}")
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class NoDirectAgentWriteInvariantSuiteTest(unittest.TestCase):
    def test_suite_emits_passing_report_with_direct_and_indirect_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir) / "artifacts"
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = MODULE.main(["--output-dir", str(output_dir)])
            self.assertEqual(exit_code, 0)

            json_report = output_dir / MODULE.REPORT_JSON_NAME
            markdown_report = output_dir / MODULE.REPORT_MD_NAME

            self.assertTrue(json_report.exists())
            self.assertTrue(markdown_report.exists())

            report = json.loads(json_report.read_text(encoding="utf-8"))
            self.assertEqual(report["kind"], "no_direct_agent_write_invariant_report")
            self.assertEqual(report["summary"]["status"], "PASS")
            self.assertEqual(report["summary"]["failed_checks"], 0)

            check_ids = {check["check_id"] for check in report["checks"]}
            self.assertIn("direct_sync_write_capability_denied", check_ids)
            self.assertIn("indirect_sync_scope_denied", check_ids)
            self.assertIn("indirect_sync_preflight_bypass_denied", check_ids)

            path_types = {check["path_type"] for check in report["checks"]}
            self.assertEqual(path_types, {"direct", "indirect"})


if __name__ == "__main__":
    unittest.main()
