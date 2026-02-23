from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUN_ONCE_SRC = ROOT / "scripts" / "cyntra" / "run-once.sh"
FIXTURE_DIR = ROOT / "scripts" / "tests" / "fixtures" / "cyntra_completion_policy"


def _write_exec(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)


def _read_jsonl(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _prepare_fake_repo(tmp: Path, fixture: dict[str, object]) -> Path:
    scripts_dir = tmp / "scripts" / "cyntra"
    scripts_dir.mkdir(parents=True, exist_ok=True)
    (tmp / ".cyntra" / "state").mkdir(parents=True, exist_ok=True)
    (tmp / ".cyntra" / "logs").mkdir(parents=True, exist_ok=True)
    manifest = fixture.get("manifest")
    if isinstance(manifest, dict):
        (tmp / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

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
            "printf 'ARGS=%s\\n' \"$*\" >> .cyntra/logs/cyntra-calls.log\n"
            "python3 - <<'PY'\n"
            "import json\n"
            "import os\n"
            "from pathlib import Path\n"
            "fixture_path = Path(os.environ['CYNTRA_TEST_COMPLETION_FIXTURE'])\n"
            "fixture = json.loads(fixture_path.read_text(encoding='utf-8'))\n"
            "proof = fixture['proof']\n"
            "workcell_id = str(proof.get('workcell_id') or 'wc-completion-fixture')\n"
            "workcell_dir = Path('.workcells') / workcell_id\n"
            "workcell_dir.mkdir(parents=True, exist_ok=True)\n"
            "proof_path = workcell_dir / 'proof.json'\n"
            "proof_path.write_text(json.dumps(proof, ensure_ascii=False, indent=2) + '\\n', encoding='utf-8')\n"
            "PY\n"
        ),
    )
    return runner_dest


class CyntraCompletionIntegrityPolicyTest(unittest.TestCase):
    def test_completion_policy_regression_fixtures(self) -> None:
        fixtures = sorted(FIXTURE_DIR.glob("*.json"))
        self.assertTrue(fixtures, "expected completion policy fixtures")

        for fixture_path in fixtures:
            with self.subTest(fixture=fixture_path.name):
                fixture = json.loads(fixture_path.read_text(encoding="utf-8"))

                with tempfile.TemporaryDirectory() as tmpdir:
                    tmp = Path(tmpdir)
                    runner = _prepare_fake_repo(tmp, fixture)

                    env = os.environ.copy()
                    env["CYNTRA_TEST_COMPLETION_FIXTURE"] = str(fixture_path)
                    env["CYNTRA_COMPLETION_BLOCKING_SKIP_BUDGET"] = "0"
                    env["CYNTRA_COMPLETION_BLOCKING_SKIP_REASON_ALLOWLIST"] = "no scope changes"
                    result = subprocess.run(
                        ["bash", str(runner)],
                        cwd=tmp,
                        env=env,
                        text=True,
                        capture_output=True,
                        check=False,
                    )

                    expected_exit = int(fixture["expect_exit_code"])
                    self.assertEqual(
                        result.returncode,
                        expected_exit,
                        msg=f"{fixture_path.name} stdout={result.stdout!r} stderr={result.stderr!r}",
                    )

                    workcell_id = str(fixture["proof"].get("workcell_id") or "wc-completion-fixture")
                    proof_path = tmp / ".workcells" / workcell_id / "proof.json"
                    self.assertTrue(proof_path.exists(), f"missing proof artifact for {fixture_path.name}")
                    proof_doc = json.loads(proof_path.read_text(encoding="utf-8"))

                    expected_failure_code = str(fixture.get("expected_failure_code") or "")
                    actual_failure_code = str(proof_doc.get("failure_code") or "")
                    self.assertEqual(actual_failure_code, expected_failure_code)

                    expected_gate_summary = fixture["expected_gate_summary"]
                    gate_summary = (
                        proof_doc.get("verification", {}).get("gate_summary", {})
                        if isinstance(proof_doc.get("verification"), dict)
                        else {}
                    )
                    self.assertIsInstance(gate_summary, dict)
                    for key, value in expected_gate_summary.items():
                        self.assertEqual(gate_summary.get(key), value, f"{fixture_path.name} gate_summary.{key}")

                    telemetry_events = _read_jsonl(tmp / ".workcells" / workcell_id / "telemetry.jsonl")
                    completion_events = [e for e in telemetry_events if e.get("event") == "completion_policy_gate_summary"]
                    self.assertTrue(completion_events, f"{fixture_path.name} missing completion telemetry")
                    latest_completion_event = completion_events[-1]
                    event_gate_summary = latest_completion_event.get("gate_summary", {})
                    self.assertIsInstance(event_gate_summary, dict)
                    for key, value in expected_gate_summary.items():
                        self.assertEqual(event_gate_summary.get(key), value, f"{fixture_path.name} telemetry gate_summary.{key}")

                    global_events = _read_jsonl(tmp / ".cyntra" / "logs" / "events.jsonl")
                    completion_global_events = [e for e in global_events if e.get("event") == "completion_policy_gate_summary"]
                    self.assertTrue(completion_global_events, f"{fixture_path.name} missing global completion event")

                    expected_event = fixture["expected_event"]
                    latest_global_event = completion_global_events[-1]
                    for key, value in expected_event.items():
                        if key != "gate_summary":
                            self.assertEqual(latest_global_event.get(key), value, f"{fixture_path.name} global_event.{key}")
                    expected_event_gate_summary = expected_event.get("gate_summary", {})
                    self.assertIsInstance(expected_event_gate_summary, dict)
                    latest_global_gate_summary = latest_global_event.get("gate_summary", {})
                    self.assertIsInstance(latest_global_gate_summary, dict)
                    for key, value in expected_event_gate_summary.items():
                        self.assertEqual(
                            latest_global_gate_summary.get(key),
                            value,
                            f"{fixture_path.name} global_event.gate_summary.{key}",
                        )

                    if expected_failure_code:
                        failure_events = [
                            e
                            for e in telemetry_events
                            if e.get("event") == "failure_code_classified"
                            and str(e.get("failure_code") or "") == expected_failure_code
                        ]
                        self.assertTrue(failure_events, f"{fixture_path.name} missing failure classification telemetry")

                    call_log = tmp / ".cyntra" / "logs" / "cyntra-calls.log"
                    call_count = len(call_log.read_text(encoding="utf-8").splitlines()) if call_log.exists() else 0
                    self.assertEqual(call_count, int(fixture["expect_cyntra_calls"]), f"{fixture_path.name} call count")


if __name__ == "__main__":
    unittest.main()
