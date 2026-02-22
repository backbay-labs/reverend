from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUN_ONCE_SRC = ROOT / "scripts" / "cyntra" / "run-once.sh"
RUN_WATCH_SRC = ROOT / "scripts" / "cyntra" / "run-watch.sh"


def _run(cmd: list[str], *, cwd: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=cwd,
        env=env,
        text=True,
        capture_output=True,
        check=True,
    )


def _write_exec(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)


def _prepare_fake_repo(tmp: Path, runner_source: Path) -> tuple[Path, Path, Path]:
    scripts_dir = tmp / "scripts" / "cyntra"
    scripts_dir.mkdir(parents=True, exist_ok=True)
    (tmp / ".cyntra" / "state").mkdir(parents=True, exist_ok=True)
    (tmp / ".cyntra" / "logs").mkdir(parents=True, exist_ok=True)

    runner_dest = scripts_dir / runner_source.name
    runner_dest.write_text(runner_source.read_text(encoding="utf-8"), encoding="utf-8")
    runner_dest.chmod(0o755)

    _write_exec(
        scripts_dir / "preflight.sh",
        "#!/usr/bin/env bash\nset -euo pipefail\necho '[preflight] ok' >> .cyntra/logs/invocations.log\n",
    )
    _write_exec(
        scripts_dir / "cyntra.sh",
        "#!/usr/bin/env bash\nset -euo pipefail\nprintf 'ARGS=%s\\n' \"$*\" >> .cyntra/logs/invocations.log\n",
    )

    state_path = tmp / ".cyntra" / "state" / "watchdog-running.json"
    events_path = tmp / ".cyntra" / "logs" / "events.jsonl"
    return runner_dest, state_path, events_path


class CyntraWatchdogReconciliationTest(unittest.TestCase):
    def test_interrupted_run_once_reconciles_stale_pid_entry(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            runner, state_path, events_path = _prepare_fake_repo(tmp, RUN_ONCE_SRC)
            orphan_path = tmp / ".workcells" / "wc-3304-20260222T000000Z"
            orphan_path.mkdir(parents=True, exist_ok=True)
            state_path.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "entries": [
                            {
                                "runner": "run-once",
                                "pid": 999_999_999,
                                "workcell_id": "wc-3304-20260222T000000Z",
                                "workcell_path": str(orphan_path),
                            }
                        ],
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )

            env = os.environ.copy()
            env["CYNTRA_ENABLE_FAILURE_FALLBACK"] = "0"
            result = _run(["bash", str(runner)], cwd=tmp, env=env)

            self.assertIn("watchdog remediation: reason_code=stale_running_pid_missing", result.stdout)
            state = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertEqual(state["entries"], [])

            events = [
                json.loads(line)
                for line in events_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            self.assertTrue(events)
            self.assertEqual(events[0]["event"], "watchdog_remediation")
            self.assertEqual(events[0]["reason_code"], "stale_running_pid_missing")
            self.assertEqual(events[0]["action"], "archive_orphaned_workcell")
            self.assertIn("archived_workcell_path", events[0])
            self.assertFalse(orphan_path.exists())

    def test_interrupted_run_watch_reconciles_missing_workcell_entry(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            runner, state_path, events_path = _prepare_fake_repo(tmp, RUN_WATCH_SRC)
            state_path.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "entries": [
                            {
                                "runner": "run-watch",
                                "pid": os.getpid(),
                                "workcell_id": "wc-3304-20260222T000001Z",
                                "workcell_path": str(tmp / ".workcells" / "wc-missing"),
                            }
                        ],
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )

            result = _run(["bash", str(runner)], cwd=tmp, env=os.environ.copy())

            self.assertIn("watchdog remediation: reason_code=stale_running_workcell_missing", result.stdout)
            state = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertEqual(state["entries"], [])

            events = [
                json.loads(line)
                for line in events_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            self.assertTrue(events)
            self.assertEqual(events[0]["event"], "watchdog_remediation")
            self.assertEqual(events[0]["reason_code"], "stale_running_workcell_missing")
            self.assertEqual(events[0]["action"], "drop_stale_running_entry")


if __name__ == "__main__":
    unittest.main()
