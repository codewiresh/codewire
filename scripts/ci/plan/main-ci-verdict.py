#!/usr/bin/env python3
"""Main CI's verdict for one main commit (#2892).

A main commit is verified only by ci.yaml's own push run for it on
refs/heads/main. That run's Required verification job prints one verdict
marker, after every selected capability group succeeded or an exact
tested-tree receipt was accepted, and only when the run was not superseded:
a superseded run dispatches no capability group, so it verified nothing.

One predicate decides, for every consumer: plan-main-push.py (is the previous
main commit a planning baseline?), Deploy Dev's publish job (may it sign and
dispatch this commit?) and CI's final job (may it start that publish job?).
A pull-request, dispatched or scheduled run of the same commit never counts.
The run's own overall status does not decide: its final delivery job runs
after Required verification and may still be running when the verdict is read.

  main-ci-verdict.py emit                      (Required verification, push to main)
  main-ci-verdict.py check --sha SHA --tree TREE [--github-output]
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
POSITIVE_RE = re.compile(r"^[1-9][0-9]*$")
SERVER_URL_RE = re.compile(r"^https?://[^/]+$")
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SCHEMA = "codewire.main-ci-verdict/v1"
PREFIX = "CODEWIRE_MAIN_CI_VERDICT="
MARKER_RE = re.compile(re.escape(PREFIX) + r"([A-Za-z0-9+/=]+)")
SUPERSEDED_PREFIX = "main CI verdict: not verified; superseded by "
SUPERSEDED_RE = re.compile(re.escape(SUPERSEDED_PREFIX) + r"([0-9a-f]{40})")
WORKFLOW = "ci.yaml"
MAIN_REF = "refs/heads/main"
REQUIRED_JOB = "Required verification"
API_LIMIT = 100
MAX_LOG_BYTES = 32 * 1024 * 1024

VERIFIED = "verified"
PENDING = "pending"
FAILED = "failed"
SUPERSEDED = "superseded"
MISSING = "missing"
UNVERIFIED = "unverified"

# Forgejo job and run states, and the GitHub-style status/conclusion pairs
# some API versions report.
DONE_FAILED = {"failure", "cancelled", "skipped"}
NOT_STARTED = {"waiting", "blocked", "queued", "pending"}
RUNNING = {"running", "in_progress", "unknown"}


# What Deploy Dev's publish job does with each verdict (check).
DECISIONS = {
    VERIFIED: "delivering it",
    PENDING: "signing nothing now; that run's final job reruns this job when it passes",
    FAILED: "signing nothing",
    SUPERSEDED: "signing nothing",
    UNVERIFIED: "signing nothing",
    MISSING: "signing nothing",
}


class Unproven(Exception):
    """The verdict cannot be read; nothing may rely on it."""


class VerdictError(RuntimeError):
    """The verdict marker cannot be emitted from these inputs."""


@dataclass(frozen=True)
class Verdict:
    state: str
    reason: str
    run_id: int | None = None
    basis: str | None = None

    @property
    def verified(self) -> bool:
        return self.state == VERIFIED

    def describe(self, sha: str) -> str:
        run = f"ci.yaml run {self.run_id}"
        if self.state == VERIFIED:
            return f"main CI verdict: {sha} verified by {run} ({self.basis})"
        if self.state == PENDING:
            return f"main CI verdict: waiting for {run}'s verdict on {sha}"
        if self.state == FAILED:
            return f"main CI verdict: {run} did not pass for {sha}; fix forward, the next push delivers"
        if self.state == SUPERSEDED:
            return f"main CI verdict: {run} was superseded and verified nothing for {sha}"
        if self.state == UNVERIFIED:
            return f"main CI verdict: {run} printed no verdict for {sha}"
        return f"main CI verdict: no ci.yaml push run on {MAIN_REF} for {sha}"


class ForgejoAPI:
    """The repository API with the job token, as the receipt check uses it."""

    def __init__(self, server_url: str, repository: str, token: str):
        if not SERVER_URL_RE.fullmatch(server_url):
            raise Unproven("invalid-server-url")
        if not REPOSITORY_RE.fullmatch(repository):
            raise Unproven("invalid-repository")
        if not token or any(character in token for character in "\r\n\""):
            raise Unproven("gitea-token-unavailable")
        self.repository = repository
        self._base = f"{server_url.rstrip('/')}/api/v1/repos/{repository}"
        self._token = token

    @classmethod
    def from_environ(cls, environ: Mapping[str, str]) -> "ForgejoAPI":
        return cls(
            environ.get("GITHUB_SERVER_URL", ""),
            environ.get("GITHUB_REPOSITORY", ""),
            environ.get("GITEA_TOKEN", ""),
        )

    def _request(self, method: str, path: str) -> tuple[int, bytes]:
        with tempfile.TemporaryDirectory(prefix="codewire-main-ci-verdict-") as temporary:
            config = Path(temporary) / "curl-auth"
            descriptor = os.open(config, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w") as handle:
                handle.write(f'header = "Authorization: token {self._token}"\n')
            body = Path(temporary) / "body"
            try:
                completed = subprocess.run(
                    [
                        "curl", "--silent", "--show-error", "--max-time", "30",
                        "--max-filesize", str(MAX_LOG_BYTES), "--request", method,
                        "--config", str(config), "--output", str(body),
                        "--write-out", "%{http_code}", f"{self._base}{path}",
                    ],
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=60,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise Unproven("forgejo-api-unavailable") from exc
            status = completed.stdout.strip()
            if completed.returncode != 0 or not re.fullmatch(r"[1-5][0-9]{2}", status):
                raise Unproven("forgejo-api-unavailable")
            try:
                content = body.read_bytes() if body.exists() else b""
            except OSError as exc:
                raise Unproven("forgejo-api-unavailable") from exc
            return int(status), content

    def get_json(self, path: str) -> Any:
        status, content = self._request("GET", path)
        if status != 200:
            raise Unproven("forgejo-api-unavailable")
        try:
            return json.loads(content)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise Unproven("forgejo-api-malformed") from exc

    def get_text(self, path: str) -> str:
        status, content = self._request("GET", path)
        if status != 200:
            raise Unproven("verdict-log-unavailable")
        return content.decode("utf-8", errors="replace")

    def post(self, path: str) -> int:
        status, _ = self._request("POST", path)
        return status


def positive_id(record: Mapping[str, Any], key: str = "id") -> int | None:
    value = record.get(key)
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value
    return None


def bounded(document: Any, key: str) -> list[dict[str, Any]]:
    if isinstance(document, list):
        items = document
    elif (
        isinstance(document, dict)
        and isinstance(document.get(key), list)
        and isinstance(document.get("total_count"), int)
        and not isinstance(document.get("total_count"), bool)
        and document["total_count"] == len(document[key])
    ):
        items = document[key]
    else:
        raise Unproven("forgejo-api-malformed")
    if len(items) > API_LIMIT:
        raise Unproven("forgejo-api-ambiguous")
    return [item for item in items if isinstance(item, dict)]


def state_of(record: Mapping[str, Any]) -> str:
    """success, failure, cancelled, skipped, not-started or running."""
    status = record.get("status")
    conclusion = record.get("conclusion")
    if status == "completed":
        if conclusion == "success":
            return "success"
        return conclusion if conclusion in DONE_FAILED else "failure"
    if status == "success" and conclusion in (None, "success"):
        return "success"
    if status in DONE_FAILED:
        return status
    if status in NOT_STARTED:
        return "not-started"
    if status in RUNNING:
        return "running"
    raise Unproven("forgejo-api-malformed")


def main_push_runs(api: ForgejoAPI, workflow: str, sha: str) -> list[dict[str, Any]]:
    """The workflow's push runs on refs/heads/main for exactly this commit.

    A scheduled run that a push to main registered reports event push and
    trigger_event schedule; a dispatch and a pull request report their own
    events. Only the push run on main counts.
    """
    runs = bounded(
        api.get_json(
            f"/actions/runs?head_sha={sha}&workflow_id={workflow}&page=1&limit={API_LIMIT}"
        ),
        "workflow_runs",
    )
    return [
        run
        for run in runs
        if (run.get("head_sha") or run.get("commit_sha")) == sha
        and (run.get("trigger_event") or run.get("event")) == "push"
        and (
            run.get("path") == f"{workflow}@{MAIN_REF}"
            or (run.get("workflow_id") == workflow and run.get("prettyref") == "main")
        )
        and positive_id(run) is not None
    ]


def jobs_of(api: ForgejoAPI, run_id: int) -> list[dict[str, Any]]:
    return bounded(api.get_json(f"/actions/runs/{run_id}/jobs?page=1&limit={API_LIMIT}"), "jobs")


def named_job(jobs: list[dict[str, Any]], name: str, run_id: int) -> dict[str, Any]:
    matches = [
        job for job in jobs
        if job.get("name") == name and job.get("run_id", run_id) == run_id
    ]
    if len(matches) != 1 or positive_id(matches[0]) is None:
        raise Unproven("jobs-ambiguous")
    return matches[0]


def job_attempt(job: Mapping[str, Any]) -> int:
    attempt = job.get("run_attempt", job.get("attempt"))
    if isinstance(attempt, int) and not isinstance(attempt, bool) and attempt > 0:
        return attempt
    raise Unproven("forgejo-api-malformed")


def decode_marker(encoded: str) -> Any:
    try:
        return json.loads(base64.b64decode(encoded, validate=True))
    except (binascii.Error, UnicodeError, json.JSONDecodeError) as exc:
        raise Unproven("verdict-marker-mismatch") from exc


def marker_matches(
    document: Any, repository: str, run_id: int, attempt: int, sha: str, tree: str
) -> str | None:
    """The marker's basis when it names exactly this run, attempt and tree."""
    if not isinstance(document, dict):
        return None
    common = {
        "schema": SCHEMA,
        "repository": repository,
        "event": "push",
        "workflow_path": f"{WORKFLOW}@{MAIN_REF}",
        "run": {"id": run_id, "attempt": attempt, "job": REQUIRED_JOB},
        "source": {"commit": sha, "tree": tree},
    }
    if any(document.get(key) != value for key, value in common.items()):
        return None
    basis = document.get("basis")
    if basis == "verification" and set(document) == set(common) | {"basis"}:
        return "every selected capability group succeeded"
    tested = document.get("tested_tree")
    if (
        basis == "tested-tree"
        and set(document) == set(common) | {"basis", "tested_tree"}
        and isinstance(tested, dict)
        and set(tested) == {"pull_request", "run"}
        and all(positive_id(tested, key) is not None for key in ("pull_request", "run"))
    ):
        return f"exact tested tree of PR #{tested['pull_request']} run {tested['run']}"
    return None


def verdict(api: ForgejoAPI, sha: str, tree: str) -> Verdict:
    """The one predicate: is this main commit verified by its own push run?"""
    if not HEX40_RE.fullmatch(sha) or not HEX40_RE.fullmatch(tree):
        raise Unproven("invalid-commit")
    candidates = main_push_runs(api, WORKFLOW, sha)
    if not candidates:
        return Verdict(MISSING, "run-not-found")
    run = max(candidates, key=lambda candidate: candidate["id"])
    run_id = run["id"]
    required = named_job(jobs_of(api, run_id), REQUIRED_JOB, run_id)
    state = state_of(required)
    if state in ("not-started", "running"):
        return Verdict(PENDING, "run-pending", run_id)
    if state != "success":
        return Verdict(FAILED, "run-not-successful", run_id)
    log = api.get_text(f"/actions/jobs/{required['id']}/logs")
    markers = MARKER_RE.findall(log)
    if not markers:
        if SUPERSEDED_RE.search(log):
            return Verdict(SUPERSEDED, "run-superseded", run_id)
        # A run that predates the marker, or one that verified nothing.
        return Verdict(UNVERIFIED, "run-has-no-verdict", run_id)
    if len(markers) != 1:
        raise Unproven("verdict-marker-count-invalid")
    basis = marker_matches(
        decode_marker(markers[0]), api.repository, run_id, job_attempt(required), sha, tree
    )
    if basis is None:
        raise Unproven("verdict-marker-mismatch")
    return Verdict(VERIFIED, "verified", run_id, basis)


def require(env: Mapping[str, str], key: str, pattern: re.Pattern[str] | None = None) -> str:
    value = env.get(key, "")
    if not value or (pattern and not pattern.fullmatch(value)):
        raise VerdictError(f"verdict input {key} is invalid")
    return value


def run_attempt(env: Mapping[str, str]) -> int:
    # github.run_attempt is the job's attempt, which the API reports.
    value = env.get("CODEWIRE_RUN_ATTEMPT") or env.get("GITHUB_RUN_ATTEMPT") or "1"
    if not POSITIVE_RE.fullmatch(value):
        raise VerdictError("verdict input run attempt is invalid")
    return int(value)


def checkout_tree(sha: str) -> str:
    completed = subprocess.run(
        ["git", "rev-parse", "--verify", f"{sha}^{{tree}}"],
        stdin=subprocess.DEVNULL, capture_output=True, text=True, check=False, timeout=60,
    )
    tree = completed.stdout.strip()
    if completed.returncode != 0 or not HEX40_RE.fullmatch(tree):
        raise VerdictError("the verified commit's tree is unavailable")
    return tree


def build_marker(env: Mapping[str, str], tree_of=checkout_tree) -> tuple[str, str | None]:
    """The human verdict line and, for a verified commit, its marker line."""
    if env.get("GITHUB_EVENT_NAME") != "push" or env.get("GITHUB_REF") != MAIN_REF:
        raise VerdictError("a verdict is recorded only for a push to main")
    sha = require(env, "GITHUB_SHA", HEX40_RE)
    superseded = env.get("VERIFICATION_SUPERSEDED", "")
    if superseded == "true":
        newer = require(env, "VERIFICATION_SUPERSEDED_BY", HEX40_RE)
        return (
            f"{SUPERSEDED_PREFIX}{newer}, whose run verifies this commit's changes; "
            f"Dev never delivers {sha} from this run",
            None,
        )
    if superseded != "false":
        raise VerdictError("verdict input VERIFICATION_SUPERSEDED is invalid")
    if require(env, "CODEWIRE_HEAD_COMMIT", HEX40_RE) != sha:
        raise VerdictError("the verified commit is not the workflow commit")
    tree = require(env, "CODEWIRE_HEAD_TREE", HEX40_RE)
    if tree_of(sha) != tree:
        raise VerdictError("the verified tree is not the workflow commit's tree")
    document: dict[str, Any] = {
        "schema": SCHEMA,
        "repository": require(env, "GITHUB_REPOSITORY", REPOSITORY_RE),
        "event": "push",
        "workflow_path": f"{WORKFLOW}@{MAIN_REF}",
        "run": {
            "id": int(require(env, "GITHUB_RUN_ID", POSITIVE_RE)),
            "attempt": run_attempt(env),
            "job": REQUIRED_JOB,
        },
        "source": {"commit": sha, "tree": tree},
    }
    receipt = env.get("VERIFICATION_TESTED_TREE_RECEIPT", "")
    if receipt == "fallback":
        document["basis"] = "verification"
        line = f"main CI verdict: {sha} verified; every selected capability group succeeded"
    elif receipt == "accepted":
        document["basis"] = "tested-tree"
        document["tested_tree"] = {
            "pull_request": int(require(env, "VERIFICATION_TESTED_TREE_PR", POSITIVE_RE)),
            "run": int(require(env, "VERIFICATION_TESTED_TREE_RUN", POSITIVE_RE)),
        }
        line = (
            f"main CI verdict: {sha} verified; exact tested tree of PR "
            f"#{document['tested_tree']['pull_request']} run {document['tested_tree']['run']}"
        )
    else:
        raise VerdictError("verdict input VERIFICATION_TESTED_TREE_RECEIPT is invalid")
    encoded = base64.b64encode(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    ).decode()
    return line, f"{PREFIX}{encoded}"


def write_outputs(path: str | None, outputs: dict[str, str]) -> None:
    rendered = "".join(f"{key}={value}\n" for key, value in outputs.items())
    if path:
        with Path(path).open("a", encoding="utf-8") as handle:
            handle.write(rendered)


def command_emit(_: argparse.Namespace) -> int:
    try:
        line, marker = build_marker(os.environ)
    except VerdictError as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 1
    print(line)
    if marker:
        print(marker)
    return 0


def command_check(args: argparse.Namespace) -> int:
    output = os.environ.get("GITHUB_OUTPUT") if args.github_output else None
    try:
        result = verdict(ForgejoAPI.from_environ(os.environ), args.sha, args.tree)
    except Unproven as exc:
        print(f"::error::cannot read main CI's verdict for {args.sha} ({exc}); signing nothing",
              file=sys.stderr)
        return 1
    print(f"{result.describe(args.sha)}; {DECISIONS[result.state]}")
    write_outputs(output, {
        "verified": "true" if result.verified else "false",
        "state": result.state,
        "ci_run": str(result.run_id or ""),
    })
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("emit").set_defaults(handler=command_emit)
    check = commands.add_parser("check")
    check.add_argument("--sha", required=True)
    check.add_argument("--tree", required=True)
    check.add_argument("--github-output", action="store_true")
    check.set_defaults(handler=command_check)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
