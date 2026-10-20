#!/usr/bin/env python3
"""Name the commit the last successful scheduled run of a workflow checked.

A scheduled run of ci.yaml (Kind) or cw-release-dry-run.yaml (the release dry
run) does its work only when its inputs changed since that commit. This reads
the repository's runs with the job token, as plan-main-push.py does, and
prints schedule_baseline=<commit>, or schedule_baseline= when there is no such
run or the answer is uncertain; the caller then runs everything.

Forgejo records a scheduled run with event "push" when the push to main that
registered the schedule created it, so a scheduled run is told apart by its
trigger_event, never by its event.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable

HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
SERVER_URL_RE = re.compile(r"^https?://[^/]+$")
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
WORKFLOW_RE = re.compile(r"^[A-Za-z0-9_.-]+\.ya?ml$")
MAIN_REF = "refs/heads/main"
PAGE_LIMIT = 50
# Successful runs of every event, newest first; the newest scheduled one is
# normally on the first page. Past this many the baseline is unknown.
MAX_PAGES = 4


class Unknown(Exception):
    """No trustworthy baseline: the scheduled run checks everything."""


Fetch = Callable[[str], Any]


def forgejo_fetch(environ: dict[str, str]) -> Fetch:
    """GET a repository API path with the job token, as plan-main-push.py does."""
    server_url = environ.get("GITHUB_SERVER_URL", "")
    repository = environ.get("GITHUB_REPOSITORY", "")
    token = environ.get("GITEA_TOKEN", "")
    if not SERVER_URL_RE.fullmatch(server_url):
        raise Unknown("invalid-server-url")
    if not REPOSITORY_RE.fullmatch(repository):
        raise Unknown("invalid-repository")
    if not token or any(character in token for character in "\r\n\""):
        raise Unknown("gitea-token-unavailable")
    api_base = f"{server_url.rstrip('/')}/api/v1/repos/{repository}"

    def fetch(path: str) -> Any:
        with tempfile.TemporaryDirectory(prefix="codewire-schedule-baseline-") as temporary:
            config = Path(temporary) / "curl-auth"
            descriptor = os.open(config, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w") as handle:
                handle.write(f'header = "Authorization: token {token}"\n')
            body = Path(temporary) / "body.json"
            try:
                completed = subprocess.run(
                    [
                        "curl", "--silent", "--show-error", "--max-time", "30",
                        "--config", str(config), "--output", str(body),
                        "--write-out", "%{http_code}", f"{api_base}{path}",
                    ],
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=60,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise Unknown("forgejo-api-unavailable") from exc
            if completed.returncode != 0 or completed.stdout.strip() != "200":
                raise Unknown("forgejo-api-unavailable")
            try:
                return json.loads(body.read_text())
            except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                raise Unknown("forgejo-api-malformed") from exc

    return fetch


def succeeded(record: dict[str, Any]) -> bool:
    status = record.get("status")
    conclusion = record.get("conclusion")
    return (status == "completed" and conclusion == "success") or (
        status == "success" and conclusion in (None, "success")
    )


def run_id(record: dict[str, Any]) -> int | None:
    value = record.get("id")
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value
    return None


def on_main(record: dict[str, Any], workflow: str) -> bool:
    return record.get("path") == f"{workflow}@{MAIN_REF}" or (
        record.get("workflow_id") == workflow and record.get("prettyref") == "main"
    )


def page_runs(document: Any) -> list[dict[str, Any]]:
    if not (
        isinstance(document, dict)
        and isinstance(document.get("workflow_runs"), list)
        and isinstance(document.get("total_count"), int)
        and not isinstance(document.get("total_count"), bool)
    ):
        raise Unknown("forgejo-api-malformed")
    runs = document["workflow_runs"]
    if len(runs) > PAGE_LIMIT:
        raise Unknown("forgejo-api-ambiguous")
    return [run for run in runs if isinstance(run, dict)]


def last_scheduled_run(fetch: Fetch, workflow: str, own_run: int | None) -> tuple[str, int]:
    """The commit and id of the newest successful scheduled run on main."""
    for page in range(1, MAX_PAGES + 1):
        runs = page_runs(fetch(
            f"/actions/runs?workflow_id={workflow}&status=success"
            f"&page={page}&limit={PAGE_LIMIT}"
        ))
        if runs and not any("trigger_event" in run for run in runs):
            # This Forgejo does not say which runs a schedule started.
            raise Unknown("trigger-event-unavailable")
        candidates = [
            run for run in runs
            if run.get("trigger_event") == "schedule"
            and on_main(run, workflow)
            and succeeded(run)
            and run_id(run) is not None
            and run_id(run) != own_run
        ]
        if candidates:
            newest = max(candidates, key=lambda run: run_id(run) or 0)
            commit = newest.get("commit_sha") or newest.get("head_sha")
            if not isinstance(commit, str) or not HEX40_RE.fullmatch(commit):
                raise Unknown("scheduled-run-commit-invalid")
            return commit, run_id(newest) or 0
        if len(runs) < PAGE_LIMIT:
            raise Unknown("no-successful-scheduled-run")
    raise Unknown("no-successful-scheduled-run-in-recent-runs")


def choose(environ: dict[str, str], workflow: str,
           fetch_factory: Callable[[dict[str, str]], Fetch] = forgejo_fetch) -> str:
    try:
        if environ.get("GITHUB_EVENT_NAME") != "schedule":
            raise Unknown("not-a-scheduled-run")
        own = environ.get("GITHUB_RUN_ID", "")
        own_run = int(own) if own.isdigit() else None
        commit, found = last_scheduled_run(fetch_factory(environ), workflow, own_run)
    except Unknown as exc:
        print(f"schedule: no baseline for {workflow} ({exc}); this run checks everything")
        return ""
    print(f"schedule: the last successful scheduled {workflow} run {found} checked {commit}")
    return commit


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workflow", required=True, help="workflow file name, such as ci.yaml")
    parser.add_argument("--github-output", action="store_true",
                        help="also append schedule_baseline= to $GITHUB_OUTPUT")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    if not WORKFLOW_RE.fullmatch(args.workflow):
        print(f"schedule: invalid workflow name {args.workflow!r}", file=sys.stderr)
        return 2
    rendered = f"schedule_baseline={choose(dict(os.environ), args.workflow)}\n"
    if args.github_output:
        with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as handle:
            handle.write(rendered)
    sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
