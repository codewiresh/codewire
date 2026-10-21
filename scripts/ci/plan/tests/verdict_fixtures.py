"""Recorded Forgejo API responses for main CI's verdict (#2892).

Runs, jobs and logs take the shapes Forgejo v17 returns: a run carries
commit_sha, workflow_id, prettyref, event, trigger_event and status; a job
list is a plain array; a job log is plain text with a timestamp per line.
"""

from __future__ import annotations

import base64
import json
import re
from typing import Any, Callable

REPOSITORY = "codewire/codewire"
PREFIX = "CODEWIRE_MAIN_CI_VERDICT="


def marker(
    sha: str,
    tree: str,
    *,
    run_id: int = 41,
    attempt: int = 1,
    basis: str = "verification",
    tested: dict[str, int] | None = None,
    repository: str = REPOSITORY,
    **overrides: Any,
) -> str:
    document: dict[str, Any] = {
        "schema": "codewire.main-ci-verdict/v1",
        "repository": repository,
        "event": "push",
        "workflow_path": "ci.yaml@refs/heads/main",
        "run": {"id": run_id, "attempt": attempt, "job": "Required verification"},
        "source": {"commit": sha, "tree": tree},
        "basis": basis,
    }
    if tested is not None:
        document["tested_tree"] = tested
    document.update(overrides)
    encoded = base64.b64encode(json.dumps(document, sort_keys=True).encode()).decode()
    return PREFIX + encoded


def log_lines(*lines: str) -> str:
    """Job log text, each line prefixed by its timestamp as Forgejo stores it."""
    return "".join(f"2026-10-20T12:00:{index:02d}.0000000Z {line}\n" for index, line in enumerate(lines))


def run(
    sha: str,
    *,
    run_id: int = 41,
    workflow: str = "ci.yaml",
    event: str = "push",
    trigger_event: str | None = "push",
    prettyref: str = "main",
    status: str = "success",
    **fields: Any,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "id": run_id,
        "commit_sha": sha,
        "workflow_id": workflow,
        "prettyref": prettyref,
        "event": event,
        "status": status,
    }
    if trigger_event is not None:
        record["trigger_event"] = trigger_event
    record.update(fields)
    return record


def ci_jobs(run_id: int = 41, *, required: str = "success", attempt: int = 1,
            policy: str = "success", required_id: int | None = None) -> list[dict[str, Any]]:
    base = run_id * 10
    return [
        {"id": base + 1, "run_id": run_id, "attempt": 1, "name": "Verification selection", "status": "success"},
        {"id": base + 2, "run_id": run_id, "attempt": 1, "name": "Policy verification", "status": policy},
        {"id": required_id or base + 3, "run_id": run_id, "attempt": attempt,
         "name": "Required verification", "status": required},
        {"id": base + 4, "run_id": run_id, "attempt": 1,
         "name": "Start Dev delivery of the verified commit", "status": "running"},
    ]


def required_job_id(run_id: int = 41) -> int:
    return run_id * 10 + 3


class FakeForgejo:
    """The repository API, answered from recorded responses.

    runs maps a workflow file to its run records. jobs maps a run ID to a job
    list, or to a list of successive job lists (a job that changes state while
    it is polled); the last one repeats. logs maps a job ID to its log text.
    reruns maps a job ID to the successive HTTP statuses its rerun returns.
    """

    def __init__(
        self,
        runs: dict[str, list[dict[str, Any]] | Exception] | None = None,
        jobs: dict[int, Any] | None = None,
        logs: dict[int, str | Exception] | None = None,
        reruns: dict[int, list[int]] | None = None,
        repository: str = REPOSITORY,
    ):
        self.runs = runs or {}
        self.jobs = jobs or {}
        self.logs = logs or {}
        self.reruns = reruns or {}
        self.repository = repository
        self.paths: list[str] = []
        self.posts: list[str] = []
        self._served: dict[int, int] = {}
        self.on_get: Callable[[str], None] | None = None

    def factory(self, environ: dict[str, str]) -> "FakeForgejo":
        return self

    def get_json(self, path: str) -> Any:
        self.paths.append(path)
        if self.on_get:
            self.on_get(path)
        match = re.fullmatch(
            r"/actions/runs\?head_sha=([0-9a-f]{40}|[^&]*)&workflow_id=([^&]+)&page=1&limit=100", path
        )
        if match:
            runs = self.runs.get(match.group(2), [])
            if isinstance(runs, Exception):
                raise runs
            return {"total_count": len(runs), "workflow_runs": runs}
        match = re.fullmatch(r"/actions/runs/(\d+)/jobs\?page=1&limit=100", path)
        assert match, path
        run_id = int(match.group(1))
        jobs = self.jobs[run_id]
        if isinstance(jobs, Exception):
            raise jobs
        if isinstance(jobs, list) and jobs and isinstance(jobs[0], list):
            served = self._served.get(run_id, 0)
            self._served[run_id] = served + 1
            return jobs[min(served, len(jobs) - 1)]
        return jobs

    def get_text(self, path: str) -> str:
        self.paths.append(path)
        match = re.fullmatch(r"/actions/jobs/(\d+)/logs", path)
        assert match, path
        log = self.logs[int(match.group(1))]
        if isinstance(log, Exception):
            raise log
        return log

    def post(self, path: str) -> int:
        self.posts.append(path)
        match = re.fullmatch(r"/actions/jobs/(\d+)/rerun", path)
        assert match, path
        statuses = self.reruns.get(int(match.group(1)), [204])
        return statuses.pop(0) if len(statuses) > 1 else statuses[0]
