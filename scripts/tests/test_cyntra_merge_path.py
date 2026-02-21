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


if __name__ == "__main__":
    unittest.main()
