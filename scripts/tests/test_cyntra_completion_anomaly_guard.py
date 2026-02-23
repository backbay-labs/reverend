from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CYNTRA_WRAPPER = ROOT / "scripts" / "cyntra" / "cyntra.sh"


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows), encoding="utf-8")


class CyntraCompletionAnomalyGuardTest(unittest.TestCase):
    def test_auto_reopens_done_issue_with_zero_diff_noop_violation(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            issues_path = tmp / "issues.jsonl"
            events_path = tmp / "events.jsonl"
            report_path = tmp / "completion-anomaly-report.json"

            _write_jsonl(
                issues_path,
                [
                    {
                        "id": "3111",
                        "title": "E20-S11",
                        "status": "done",
                        "tags": ["roadmap12w", "type:story"],
                    }
                ],
            )
            _write_jsonl(
                events_path,
                [
                    {
                        "event": "completion_policy_gate_summary",
                        "issue_id": "3111",
                        "workcell_id": "wc-3111",
                        "proof_path": ".workcells/wc-3111/proof.json",
                        "gate_summary": {
                            "completion_classification": "noop",
                            "explicit_noop_justification_present": False,
                            "policy_result": "blocked",
                            "policy_block_reason": "missing_manifest_noop_justification",
                        },
                    }
                ],
            )

            result = subprocess.run(
                [
                    "bash",
                    str(CYNTRA_WRAPPER),
                    "completion-anomaly-guard",
                    "--events",
                    str(events_path),
                    "--issues",
                    str(issues_path),
                    "--report",
                    str(report_path),
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, msg=result.stderr)

            updated_issues = [
                json.loads(line)
                for line in issues_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            self.assertEqual(updated_issues[0]["status"], "open")

            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(report["actions"]["auto_reopened"], 1)
            self.assertEqual(report["actions"]["flagged_human_review"], 0)
            self.assertEqual(report["anomalies_detected"], 1)

            events = [json.loads(line) for line in events_path.read_text(encoding="utf-8").splitlines() if line.strip()]
            decision_events = [event for event in events if event.get("event") == "completion_anomaly_guard_decision"]
            self.assertEqual(len(decision_events), 1)
            self.assertEqual(decision_events[0].get("applied_action"), "auto_reopen")

    def test_flags_human_review_for_non_allowlisted_skip_pattern(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            issues_path = tmp / "issues.jsonl"
            events_path = tmp / "events.jsonl"
            report_path = tmp / "completion-anomaly-report.json"

            _write_jsonl(
                issues_path,
                [
                    {
                        "id": "3112",
                        "title": "E20-S12",
                        "status": "done",
                        "tags": ["roadmap12w", "type:story"],
                    }
                ],
            )
            _write_jsonl(
                events_path,
                [
                    {
                        "event": "completion_policy_gate_summary",
                        "issue_id": "3112",
                        "workcell_id": "wc-3112",
                        "proof_path": ".workcells/wc-3112/proof.json",
                        "gate_summary": {
                            "completion_classification": "code_change",
                            "policy_result": "blocked",
                            "policy_block_reason": "blocking_gate_skip_reason_not_allowlisted",
                        },
                    }
                ],
            )

            result = subprocess.run(
                [
                    "bash",
                    str(CYNTRA_WRAPPER),
                    "completion-anomaly-guard",
                    "--events",
                    str(events_path),
                    "--issues",
                    str(issues_path),
                    "--report",
                    str(report_path),
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, msg=result.stderr)

            updated_issues = [
                json.loads(line)
                for line in issues_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            self.assertEqual(updated_issues[0]["status"], "done")
            self.assertIn("needs-human-review", updated_issues[0]["tags"])

            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(report["actions"]["auto_reopened"], 0)
            self.assertEqual(report["actions"]["flagged_human_review"], 1)
            self.assertEqual(report["anomalies_detected"], 1)


if __name__ == "__main__":
    unittest.main()
