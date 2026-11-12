#!/usr/bin/env python3
from __future__ import annotations

import pathlib
import re

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[3]
WORKFLOW = ROOT / ".github/workflows/codeql.yml"
ALLOWED_ACTIONS = {
    "actions/checkout",
    "actions/setup-go",
    "github/codeql-action/analyze",
    "github/codeql-action/init",
}
LANGUAGES = {
    "actions": "none",
    "go": "autobuild",
    "javascript-typescript": "none",
    "python": "none",
    "rust": "none",
}


def fail(message: str) -> None:
    raise SystemExit(f"test-codeql-workflow: {message}")


def main() -> None:
    text = WORKFLOW.read_text()
    workflow = yaml.safe_load(text)
    triggers = workflow.get("on", workflow.get(True))
    if set(triggers) != {"schedule", "workflow_dispatch"}:
        fail("CodeQL must run on its daily schedule and manual dispatch only")
    if workflow.get("permissions") != "read-all":
        fail("the workflow must be read-only by default")

    jobs = workflow["jobs"]
    if set(jobs) != {"analyze"}:
        fail(f"unexpected jobs: {sorted(jobs)}")
    job = jobs["analyze"]
    if job.get("if") != "github.event.repository.private == false":
        fail("the private mirror must skip CodeQL")
    if job.get("runs-on") != "ubuntu-24.04":
        fail("CodeQL must run on a GitHub-hosted Ubuntu runner")
    if job.get("permissions") != {"contents": "read", "security-events": "write"}:
        fail("the job permissions must be exactly the code-scanning minimum")
    if set(job) & {"env", "container", "services"}:
        fail("the CodeQL job must not add an environment, container or services")
    matrix = {
        entry["language"]: entry["build-mode"]
        for entry in job["strategy"]["matrix"]["include"]
    }
    if matrix != LANGUAGES:
        fail(f"unexpected languages or build modes: {matrix}")

    analyze = None
    setup_go = None
    for step in job["steps"]:
        if "run" in step:
            fail("the CodeQL job may contain only approved actions")
        action = step["uses"]
        name, separator, digest = action.partition("@")
        if name not in ALLOWED_ACTIONS:
            fail(f"unapproved action: {name}")
        if not separator or not re.fullmatch(r"[0-9a-f]{40}", digest):
            fail(f"{name} must be pinned to a full commit")
        if name == "actions/checkout" and step.get("with", {}).get("persist-credentials") is not False:
            fail("the checkout must not persist the workflow token")
        if name == "github/codeql-action/analyze":
            analyze = step
        if name == "actions/setup-go":
            setup_go = step
    if analyze is None:
        fail("the CodeQL analyze action is missing; OpenSSF Scorecard's SAST check looks for it")
    # go.work requires a newer Go than the runner ships, and the Go
    # autobuild uses the Go on PATH.
    if setup_go is None or setup_go.get("if") != "matrix.language == 'go'":
        fail("the Go analysis must install go.work's Go first, and only for Go")
    if setup_go.get("with") != {"go-version-file": "go.work", "cache": False}:
        fail("setup-go must read go.work's version and keep no cache")
    if "secrets." in text:
        fail("CodeQL must use the workflow token, not a PAT or another secret")

    print("codeql workflow contract passed")


if __name__ == "__main__":
    main()
