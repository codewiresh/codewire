#!/usr/bin/env python3
"""Decide whether an explicit preflight base is a verified tree (#2892).

  verified-base.py SHA

Local merge qualification normally selects from the merge-base with main.
PREFLIGHT_VERIFIED_BASE names another base, for example the old main a
rewritten branch reproduces with one changed line. It is trusted only when
that commit's own main CI verified it, by the same predicate Dev delivery uses
(main-ci-verdict.py), read through the supported fj CLI. On success this
prints verified_base=<sha> and evidence=main-ci:<run> and exits 0; anything
else prints the reason and exits 1, and the caller falls back to the
merge-base.
"""

from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, Callable

HERE = Path(__file__).resolve().parent
HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
RUNS_RE = re.compile(r"^/actions/runs\?head_sha=([0-9a-f]{40})&workflow_id=([A-Za-z0-9._-]+)&page=1&limit=\d+$")
JOBS_RE = re.compile(r"^/actions/runs/(\d+)/jobs\?page=1&limit=\d+$")
LOGS_RE = re.compile(r"^/actions/jobs/(\d+)/logs$")


def load_verdicts() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "codewire_ci_verified_base_verdict", HERE / "main-ci-verdict.py"
    )
    if spec is None or spec.loader is None:
        raise ImportError("cannot load main-ci-verdict.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


verdicts = load_verdicts()
Runner = Callable[[list[str]], str]


def run_fj(arguments: list[str]) -> str:
    try:
        completed = subprocess.run(
            ["fj", *arguments], stdin=subprocess.DEVNULL, capture_output=True,
            text=True, check=False, timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise verdicts.Unproven("fj-unavailable") from exc
    if completed.returncode != 0:
        raise verdicts.Unproven("fj-failed")
    return completed.stdout


class FjForgejo:
    """main-ci-verdict's repository API, answered by the fj CLI."""

    def __init__(self, repository: str, run: Runner = run_fj):
        self.repository = repository
        self._run = run
        self._job_runs: dict[int, int] = {}

    def _json(self, arguments: list[str]) -> Any:
        try:
            return json.loads(self._run(arguments))
        except json.JSONDecodeError as exc:
            raise verdicts.Unproven("forgejo-api-malformed") from exc

    def get_json(self, path: str) -> Any:
        match = RUNS_RE.fullmatch(path)
        if match:
            document = self._json(["actions", "runs", "list", "--head", match.group(1),
                                   "--workflow", match.group(2), "-L", "100", "--output", "json"])
            if not isinstance(document, dict) or not isinstance(document.get("runs"), list):
                raise verdicts.Unproven("forgejo-api-malformed")
            runs = [
                {
                    "id": run.get("id"),
                    "commit_sha": run.get("head_sha"),
                    "workflow_id": run.get("workflow"),
                    "prettyref": run.get("ref"),
                    "event": run.get("event"),
                    "status": run.get("status"),
                }
                for run in document["runs"] if isinstance(run, dict)
            ]
            return {"total_count": len(runs), "workflow_runs": runs}
        match = JOBS_RE.fullmatch(path)
        if match:
            run_id = int(match.group(1))
            document = self._json(["actions", "runs", "view", str(run_id), "--output", "json"])
            if not isinstance(document, dict) or not isinstance(document.get("jobs"), list):
                raise verdicts.Unproven("forgejo-api-malformed")
            for job in document["jobs"]:
                if isinstance(job, dict) and isinstance(job.get("id"), int):
                    self._job_runs[job["id"]] = run_id
            return document["jobs"]
        raise verdicts.Unproven("forgejo-api-unsupported")

    def get_text(self, path: str) -> str:
        match = LOGS_RE.fullmatch(path)
        if not match or int(match.group(1)) not in self._job_runs:
            raise verdicts.Unproven("verdict-log-unavailable")
        job_id = int(match.group(1))
        return self._run(["actions", "runs", "logs", str(self._job_runs[job_id]),
                          "--job", str(job_id)])


def git(*arguments: str) -> str:
    completed = subprocess.run(["git", *arguments], stdin=subprocess.DEVNULL,
                               capture_output=True, text=True, check=False, timeout=60)
    if completed.returncode != 0:
        raise verdicts.Unproven("commit-unavailable")
    return completed.stdout.strip()


def verify(sha: str, api, tree_of: Callable[[str], str]) -> tuple[bool, str]:
    if not HEX40_RE.fullmatch(sha):
        return False, "the base is not an exact commit"
    try:
        result = verdicts.verdict(api, sha, tree_of(sha))
    except verdicts.Unproven as exc:
        return False, f"main CI's verdict for {sha} is unreadable ({exc})"
    if not result.verified:
        return False, result.describe(sha)
    return True, f"main-ci:{result.run_id}"


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: verified-base.py SHA", file=sys.stderr)
        return 2
    try:
        sha = git("rev-parse", "--verify", f"{argv[0]}^{{commit}}")
    except verdicts.Unproven:
        print(f"verified base: {argv[0]} is not a commit here", file=sys.stderr)
        return 1
    api = FjForgejo("codewire/codewire")
    verified, detail = verify(sha, api, lambda commit: git("rev-parse", f"{commit}^{{tree}}"))
    if not verified:
        print(f"verified base: {detail}", file=sys.stderr)
        return 1
    print(f"verified_base={sha}\nevidence={detail}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
