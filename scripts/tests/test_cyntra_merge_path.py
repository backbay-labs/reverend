from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CYNTRA_WRAPPER = ROOT / "scripts" / "cyntra" / "cyntra.sh"
ORIGINAL_RE = re.compile(r"-\s*Original issue:\s*#(\d+)")


def _run(cmd: list[str], *, cwd: Path, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=cwd,
        env=env,
        check=True,
        text=True,
        capture_output=True,
    )


def _is_merge_conflict(issue: dict[str, object]) -> bool:
    title = str(issue.get("title") or "")
    description = str(issue.get("description") or "")
    tags = issue.get("tags") or []
    return (
        title.startswith("[MERGE CONFLICT]")
        or "MERGE_CONFLICT_AUTOGEN" in description
        or "merge-conflict" in tags
    )


def _original_issue(issue: dict[str, object]) -> str | None:
    match = ORIGINAL_RE.search(str(issue.get("description") or ""))
    if not match:
        return None
    return match.group(1)


def _recursive_schedulable_ids(issues: list[dict[str, object]]) -> list[str]:
    by_id = {str(issue.get("id")): issue for issue in issues}
    schedulable = {"open", "ready", "in_progress"}
    results: list[str] = []
    for issue in issues:
        if not _is_merge_conflict(issue):
            continue
        issue_id = str(issue.get("id"))
        status = str(issue.get("status") or "").lower()
        if status not in schedulable:
            continue

        depth = 0
        seen: set[str] = set()
        current = issue_id
        recursive = False
        while True:
            current_issue = by_id.get(current)
            if not current_issue or not _is_merge_conflict(current_issue):
                break
            if current in seen:
                recursive = True
                break
            seen.add(current)
            next_issue = _original_issue(current_issue)
            if not next_issue:
                break
            depth += 1
            current = next_issue
        if depth > 1 or recursive:
            results.append(issue_id)
    return sorted(results)


class CyntraMergePathTest(unittest.TestCase):
    def test_run_canonicalizes_shadow_issue_before_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            issues_path = tmp / "issues.jsonl"
            config_path = tmp / "config.yaml"
            kernel_path = tmp / "kernel"
            uv_log = tmp / "uv.log"
            bin_dir = tmp / "bin"
            kernel_path.mkdir(parents=True, exist_ok=True)
            bin_dir.mkdir(parents=True, exist_ok=True)

            issues = [
                {"id": "1201", "title": "E3-S1", "status": "open", "description": "canonical"},
                {
                    "id": "1",
                    "title": "[MERGE CONFLICT] E3-S1",
                    "status": "open",
                    "description": "<!-- MERGE_CONFLICT_AUTOGEN -->\n- Original issue: #1201",
                    "tags": ["merge-conflict"],
                },
                {
                    "id": "4",
                    "title": "[MERGE CONFLICT] [MERGE CONFLICT] E3-S1",
                    "status": "open",
                    "description": "<!-- MERGE_CONFLICT_AUTOGEN -->\n- Original issue: #1",
                    "tags": ["merge-conflict"],
                },
                {
                    "id": "7",
                    "title": "[MERGE CONFLICT] [MERGE CONFLICT] [MERGE CONFLICT] E3-S1",
                    "status": "open",
                    "description": "<!-- MERGE_CONFLICT_AUTOGEN -->\n- Original issue: #4",
                    "tags": ["merge-conflict"],
                },
            ]
            issues_path.write_text(
                "".join(json.dumps(issue, ensure_ascii=False) + "\n" for issue in issues),
                encoding="utf-8",
            )
            config_path.write_text("runtime:\n  noop: true\n", encoding="utf-8")

            uv_stub = bin_dir / "uv"
            uv_stub.write_text(
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                "printf '%s\\n' \"$*\" >> \"$CYNTRA_UV_LOG\"\n",
                encoding="utf-8",
            )
            uv_stub.chmod(0o755)

            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}{os.pathsep}{env.get('PATH', '')}"
            env["CYNTRA_KERNEL_PATH"] = str(kernel_path)
            env["CYNTRA_CONFIG_PATH"] = str(config_path)
            env["CYNTRA_ISSUES_PATH"] = str(issues_path)
            env["CYNTRA_UV_LOG"] = str(uv_log)

            result = _run(
                ["bash", str(CYNTRA_WRAPPER), "run", "--once", "--issue", "7"],
                cwd=ROOT,
                env=env,
            )

            self.assertIn("remapped --issue 7 -> 1201", result.stdout)
            uv_args = uv_log.read_text(encoding="utf-8")
            self.assertIn("--issue 1201", uv_args)

            updated = [
                json.loads(line)
                for line in issues_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            self.assertEqual(_recursive_schedulable_ids(updated), [])

    def test_clean_patch_apply_and_merge_cycle_succeeds(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = Path(tmpdir) / "merge-cycle"
            repo.mkdir(parents=True, exist_ok=True)
            _run(["git", "init", "-b", "main"], cwd=repo)
            _run(["git", "config", "user.name", "Cyntra Test"], cwd=repo)
            _run(["git", "config", "user.email", "cyntra-test@example.com"], cwd=repo)

            target = repo / "sample.txt"
            target.write_text("base\n", encoding="utf-8")
            _run(["git", "add", "sample.txt"], cwd=repo)
            _run(["git", "commit", "-m", "base"], cwd=repo)

            workcell_branch = "wc/1201/20260221T000000Z"
            _run(["git", "checkout", "-b", workcell_branch], cwd=repo)
            target.write_text("base\nfeature\n", encoding="utf-8")
            _run(["git", "add", "sample.txt"], cwd=repo)
            _run(["git", "commit", "-m", "workcell change"], cwd=repo)

            _run(["git", "checkout", "main"], cwd=repo)
            patch = _run(["git", "format-patch", "--stdout", f"main..{workcell_branch}"], cwd=repo).stdout
            patch_path = repo / "workcell.patch"
            patch_path.write_text(patch, encoding="utf-8")

            _run(["git", "apply", "--check", str(patch_path)], cwd=repo)
            _run(["git", "apply", str(patch_path)], cwd=repo)
            _run(["git", "add", "sample.txt"], cwd=repo)
            _run(["git", "commit", "-m", "apply workcell patch"], cwd=repo)

            _run(["git", "merge", "--no-ff", "--no-edit", workcell_branch], cwd=repo)
            parents = _run(["git", "show", "-s", "--format=%P", "HEAD"], cwd=repo).stdout.strip().split()
            self.assertEqual(len(parents), 2)
            self.assertEqual(target.read_text(encoding="utf-8"), "base\nfeature\n")

    def test_failure_class_policy_routes_to_fallback_toolchain(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            issues_path = tmp / "issues.jsonl"
            config_path = tmp / "config.yaml"
            kernel_path = tmp / "kernel"
            uv_log = tmp / "uv.log"
            fallback_record = tmp / "fallback-routing.json"
            bin_dir = tmp / "bin"
            kernel_path.mkdir(parents=True, exist_ok=True)
            bin_dir.mkdir(parents=True, exist_ok=True)

            issues = [
                {"id": "3302", "title": "E22-S2", "status": "open", "dk_tool_hint": "codex"},
                {"id": "9999", "title": "Other", "status": "ready", "dk_tool_hint": "codex"},
            ]
            issues_path.write_text(
                "".join(json.dumps(issue, ensure_ascii=False) + "\n" for issue in issues),
                encoding="utf-8",
            )
            config_path.write_text("runtime:\n  noop: true\n", encoding="utf-8")

            uv_stub = bin_dir / "uv"
            uv_stub.write_text(
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                "{\n"
                "  printf 'ARGS=%s\\n' \"$*\"\n"
                "  printf 'FALLBACK_APPLIED=%s\\n' \"${CYNTRA_FALLBACK_APPLIED:-}\"\n"
                "  printf 'FALLBACK_CLASS=%s\\n' \"${CYNTRA_FALLBACK_CLASS:-}\"\n"
                "  printf 'FALLBACK_SOURCE=%s\\n' \"${CYNTRA_FALLBACK_SOURCE_TOOLCHAIN:-}\"\n"
                "  printf 'FALLBACK_TARGET=%s\\n' \"${CYNTRA_FALLBACK_TARGET_TOOLCHAIN:-}\"\n"
                "  printf 'FALLBACK_ISSUE=%s\\n' \"${CYNTRA_FALLBACK_ISSUE_ID:-}\"\n"
                "  printf 'FALLBACK_WORKCELL=%s\\n' \"${CYNTRA_FALLBACK_WORKCELL_ID:-}\"\n"
                "  printf 'FALLBACK_PROOF=%s\\n' \"${CYNTRA_FALLBACK_PROOF_PATH:-}\"\n"
                "  printf 'BEADS_PATH=%s\\n' \"${CYNTRA_BEADS_PATH:-}\"\n"
                "} >> \"$CYNTRA_UV_LOG\"\n"
                "if [[ -n \"${CYNTRA_BEADS_PATH:-}\" && -f \"${CYNTRA_BEADS_PATH}\" ]]; then\n"
                "  python3 - \"$CYNTRA_BEADS_PATH\" <<'PY' >> \"$CYNTRA_UV_LOG\"\n"
                "import json\n"
                "import sys\n"
                "from pathlib import Path\n"
                "path = Path(sys.argv[1])\n"
                "for line in path.read_text(encoding='utf-8').splitlines():\n"
                "    if not line.strip():\n"
                "        continue\n"
                "    issue = json.loads(line)\n"
                "    if str(issue.get('id')) == '3302':\n"
                "        print(f\"ISSUE_3302_HINT={issue.get('dk_tool_hint')}\")\n"
                "PY\n"
                "fi\n",
                encoding="utf-8",
            )
            uv_stub.chmod(0o755)

            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}{os.pathsep}{env.get('PATH', '')}"
            env["CYNTRA_KERNEL_PATH"] = str(kernel_path)
            env["CYNTRA_CONFIG_PATH"] = str(config_path)
            env["CYNTRA_ISSUES_PATH"] = str(issues_path)
            env["CYNTRA_UV_LOG"] = str(uv_log)
            env["CYNTRA_FAILURE_CLASS"] = "prompt_stall_no_output"
            env["CYNTRA_FALLBACK_POLICY"] = "prompt_stall_no_output=claude"
            env["CYNTRA_PRIMARY_TOOLCHAIN"] = "codex"
            env["CYNTRA_FALLBACK_PROOF_PATH"] = "/tmp/proofs/stall-proof.json"
            env["CYNTRA_FALLBACK_RECORD_PATH"] = str(fallback_record)

            result = _run(
                ["bash", str(CYNTRA_WRAPPER), "run", "--once", "--issue", "3302"],
                cwd=ROOT,
                env=env,
            )

            self.assertIn("fallback routing: class='prompt_stall_no_output'", result.stdout)
            uv_env_log = uv_log.read_text(encoding="utf-8")
            self.assertIn("FALLBACK_APPLIED=1", uv_env_log)
            self.assertIn("FALLBACK_CLASS=prompt_stall_no_output", uv_env_log)
            self.assertIn("FALLBACK_SOURCE=codex", uv_env_log)
            self.assertIn("FALLBACK_TARGET=claude", uv_env_log)
            self.assertIn("FALLBACK_ISSUE=3302", uv_env_log)
            self.assertIn("FALLBACK_WORKCELL=wc-3302-20260222T215925Z", uv_env_log)
            self.assertIn("FALLBACK_PROOF=/tmp/proofs/stall-proof.json", uv_env_log)
            self.assertIn("ISSUE_3302_HINT=claude", uv_env_log)

            fallback_doc = json.loads(fallback_record.read_text(encoding="utf-8"))
            self.assertEqual(fallback_doc["issue_id"], "3302")
            self.assertEqual(fallback_doc["failure_class"], "prompt_stall_no_output")
            self.assertEqual(fallback_doc["source_toolchain"], "codex")
            self.assertEqual(fallback_doc["target_toolchain"], "claude")

    def test_fallback_loop_guard_blocks_repeated_toolchain(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            issues_path = tmp / "issues.jsonl"
            config_path = tmp / "config.yaml"
            kernel_path = tmp / "kernel"
            uv_log = tmp / "uv.log"
            bin_dir = tmp / "bin"
            kernel_path.mkdir(parents=True, exist_ok=True)
            bin_dir.mkdir(parents=True, exist_ok=True)

            issues_path.write_text(
                json.dumps({"id": "3302", "title": "E22-S2", "status": "open", "dk_tool_hint": "codex"})
                + "\n",
                encoding="utf-8",
            )
            config_path.write_text("runtime:\n  noop: true\n", encoding="utf-8")

            uv_stub = bin_dir / "uv"
            uv_stub.write_text(
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                "{\n"
                "  printf 'FALLBACK_APPLIED=%s\\n' \"${CYNTRA_FALLBACK_APPLIED:-}\"\n"
                "  printf 'BEADS_PATH=%s\\n' \"${CYNTRA_BEADS_PATH:-}\"\n"
                "} >> \"$CYNTRA_UV_LOG\"\n",
                encoding="utf-8",
            )
            uv_stub.chmod(0o755)

            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}{os.pathsep}{env.get('PATH', '')}"
            env["CYNTRA_KERNEL_PATH"] = str(kernel_path)
            env["CYNTRA_CONFIG_PATH"] = str(config_path)
            env["CYNTRA_ISSUES_PATH"] = str(issues_path)
            env["CYNTRA_UV_LOG"] = str(uv_log)
            env["CYNTRA_FAILURE_CLASS"] = "prompt_stall_no_output"
            env["CYNTRA_FALLBACK_POLICY"] = "prompt_stall_no_output=claude"
            env["CYNTRA_FALLBACK_CHAIN"] = "codex,claude"
            env["CYNTRA_PRIMARY_TOOLCHAIN"] = "codex"

            result = _run(
                ["bash", str(CYNTRA_WRAPPER), "run", "--once", "--issue", "3302"],
                cwd=ROOT,
                env=env,
            )

            self.assertIn("fallback loop guard", result.stdout)
            uv_env_log = uv_log.read_text(encoding="utf-8")
            self.assertIn("FALLBACK_APPLIED=", uv_env_log)
            self.assertIn("BEADS_PATH=", uv_env_log)


if __name__ == "__main__":
    unittest.main()
