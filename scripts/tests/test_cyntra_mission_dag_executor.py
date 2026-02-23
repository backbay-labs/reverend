from __future__ import annotations

import json
import os
import signal
import subprocess
import tempfile
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUN_ONCE_SRC = ROOT / "scripts" / "cyntra" / "run-once.sh"


def _write_exec(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)


def _prepare_fake_repo(tmp: Path) -> Path:
    scripts_dir = tmp / "scripts" / "cyntra"
    scripts_dir.mkdir(parents=True, exist_ok=True)
    (tmp / ".cyntra" / "state").mkdir(parents=True, exist_ok=True)
    (tmp / ".cyntra" / "logs").mkdir(parents=True, exist_ok=True)

    runner_dest = scripts_dir / "run-once.sh"
    runner_dest.write_text(RUN_ONCE_SRC.read_text(encoding="utf-8"), encoding="utf-8")
    runner_dest.chmod(0o755)

    _write_exec(
        scripts_dir / "preflight.sh",
        "#!/usr/bin/env bash\nset -euo pipefail\necho '[preflight] ok' >> .cyntra/logs/invocations.log\n",
    )

    _write_exec(
        scripts_dir / "cyntra.sh",
        (
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            "mkdir -p .cyntra/logs .cyntra/state .workcells/wc-mission\n"
            "if [[ -n \"${CYNTRA_FAILURE_CODE:-}\" ]]; then\n"
            "  count=0\n"
            "  if [[ -f .cyntra/state/fallback-count ]]; then\n"
            "    count=\"$(cat .cyntra/state/fallback-count)\"\n"
            "  fi\n"
            "  count=$((count + 1))\n"
            "  printf '%s\\n' \"$count\" > .cyntra/state/fallback-count\n"
            "  printf 'fallback:%s:%s\\n' \"$count\" \"$CYNTRA_FAILURE_CODE\" >> .cyntra/logs/invocations.log\n"
            "  sleep \"${CYNTRA_TEST_FALLBACK_SLEEP:-0}\"\n"
            "  mode=\"${CYNTRA_TEST_FALLBACK_MODE:-success}\"\n"
            "  if [[ \"$mode\" == \"always_17\" ]]; then\n"
            "    exit 17\n"
            "  fi\n"
            "  if [[ \"$mode\" == \"first_17_then_success\" && \"$count\" -eq 1 ]]; then\n"
            "    exit 17\n"
            "  fi\n"
            "  exit 0\n"
            "fi\n"
            "count=0\n"
            "if [[ -f .cyntra/state/primary-count ]]; then\n"
            "  count=\"$(cat .cyntra/state/primary-count)\"\n"
            "fi\n"
            "count=$((count + 1))\n"
            "printf '%s\\n' \"$count\" > .cyntra/state/primary-count\n"
            "printf 'primary:%s\\n' \"$count\" >> .cyntra/logs/invocations.log\n"
            "python3 - <<'PY'\n"
            "import json\n"
            "from pathlib import Path\n"
            "proof = {\n"
            "    'status': 'failed',\n"
            "    'failure_code': 'gate.quality_gate_failed',\n"
            "    'issue_id': '3602',\n"
            "    'workcell_id': 'wc-mission',\n"
            "    'metadata': {},\n"
            "    'verification': {'gate_summary': {}},\n"
            "}\n"
            "path = Path('.workcells/wc-mission/proof.json')\n"
            "path.parent.mkdir(parents=True, exist_ok=True)\n"
            "path.write_text(json.dumps(proof, indent=2) + '\\n', encoding='utf-8')\n"
            "PY\n"
            "exit 1\n"
        ),
    )

    return runner_dest


def _read_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


class CyntraMissionDagExecutorTest(unittest.TestCase):
    def test_checkpoint_resume_replays_only_interrupted_stage(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            runner = _prepare_fake_repo(tmp)
            checkpoint_path = tmp / ".cyntra" / "state" / "mission-checkpoint.json"

            env = os.environ.copy()
            env["CYNTRA_MISSION_CHECKPOINT_PATH"] = str(checkpoint_path)
            env["CYNTRA_TEST_FALLBACK_SLEEP"] = "20"
            env["CYNTRA_TEST_FALLBACK_MODE"] = "success"
            env["CYNTRA_DETERMINISTIC_FAILURE_CODES"] = "runtime.prompt_stall_no_output,gate.quality_gate_failed"

            proc = subprocess.Popen(
                ["bash", str(runner)],
                cwd=tmp,
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )

            deadline = time.time() + 15.0
            checkpoint_doc = {}
            while time.time() < deadline:
                if checkpoint_path.exists():
                    checkpoint_doc = _read_json(checkpoint_path)
                    stages = checkpoint_doc.get("stages", {})
                    def _stage_status(name: str) -> str:
                        stage = stages.get(name) if isinstance(stages, dict) else None
                        return str(stage.get("status")) if isinstance(stage, dict) else ""
                    if (
                        _stage_status("primary_supervised") == "succeeded"
                        and _stage_status("classify_failure") == "succeeded"
                        and _stage_status("fallback_route") == "running"
                    ):
                        break
                time.sleep(0.05)
            else:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.communicate(timeout=5)
                self.fail("checkpoint did not reach expected interrupted stage state")

            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.communicate(timeout=5)

            self.assertTrue(checkpoint_path.exists(), "checkpoint should survive interruption")
            checkpoint_doc = _read_json(checkpoint_path)
            self.assertEqual(
                checkpoint_doc.get("execution_order"),
                ["primary_supervised", "classify_failure", "fallback_route"],
            )

            env["CYNTRA_TEST_FALLBACK_SLEEP"] = "0"
            resumed = subprocess.run(
                ["bash", str(runner)],
                cwd=tmp,
                env=env,
                text=True,
                capture_output=True,
                check=True,
            )
            self.assertIn(
                "mission DAG order=primary_supervised,classify_failure,fallback_route",
                resumed.stdout,
            )
            self.assertIn("mission DAG resume from checkpoint", resumed.stdout)
            self.assertIn("stage 'primary_supervised' already succeeded", resumed.stdout)
            self.assertIn("stage 'classify_failure' already succeeded", resumed.stdout)
            self.assertIn("stage 'fallback_route' was interrupted while running; replaying attempt", resumed.stdout)

            log_lines = (tmp / ".cyntra" / "logs" / "invocations.log").read_text(encoding="utf-8").splitlines()
            self.assertEqual(len([line for line in log_lines if line.startswith("primary:")]), 1)
            self.assertGreaterEqual(len([line for line in log_lines if line.startswith("fallback:")]), 1)
            self.assertFalse(checkpoint_path.exists(), "completed mission should clean checkpoint")

    def test_retry_policy_is_explicit_and_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            runner = _prepare_fake_repo(tmp)

            env = os.environ.copy()
            env["CYNTRA_TEST_FALLBACK_MODE"] = "always_17"
            env["CYNTRA_TEST_FALLBACK_SLEEP"] = "0"
            env["CYNTRA_MISSION_FALLBACK_MAX_ATTEMPTS"] = "2"
            env["CYNTRA_MISSION_FALLBACK_RETRYABLE_EXIT_CODES"] = "17"
            env["CYNTRA_DETERMINISTIC_FAILURE_CODES"] = "runtime.prompt_stall_no_output,gate.quality_gate_failed"

            result = subprocess.run(
                ["bash", str(runner)],
                cwd=tmp,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 17, msg=f"stdout={result.stdout!r} stderr={result.stderr!r}")
            self.assertIn("fallback(max=2,codes=17)", result.stdout)
            self.assertIn("stage 'fallback_route' attempt 1/2 failed with exit=17; retrying", result.stdout)
            self.assertIn("stage 'fallback_route' failed with exit=17 (attempt 2/2)", result.stdout)

            log_lines = (tmp / ".cyntra" / "logs" / "invocations.log").read_text(encoding="utf-8").splitlines()
            self.assertEqual(len([line for line in log_lines if line.startswith("primary:")]), 1)
            self.assertEqual(len([line for line in log_lines if line.startswith("fallback:")]), 2)


if __name__ == "__main__":
    unittest.main()
