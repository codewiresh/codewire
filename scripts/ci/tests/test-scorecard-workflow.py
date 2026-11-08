#!/usr/bin/env python3
from __future__ import annotations

import pathlib
import re

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[3]
WORKFLOW = ROOT / ".github/workflows/scorecard.yml"
ALLOWED_ACTIONS = {
    "actions/checkout",
    "actions/upload-artifact",
    "github/codeql-action/upload-sarif",
    "ossf/scorecard-action",
}


def fail(message: str) -> None:
    raise SystemExit(f"test-scorecard-workflow: {message}")


def main() -> None:
    text = WORKFLOW.read_text()
    workflow = yaml.safe_load(text)
    triggers = workflow.get("on", workflow.get(True))
    if set(triggers) != {"push", "schedule", "workflow_dispatch"}:
        fail("Scorecard must allow pushes, its weekly schedule and manual retries")
    if triggers["push"] != {"branches": ["main"]}:
        fail("Scorecard push runs must be limited to main")
    if workflow.get("permissions") != "read-all":
        fail("the workflow must be read-only by default")
    if set(workflow) & {"env", "defaults"}:
        fail("the publishing API forbids workflow-level env and defaults")

    jobs = workflow["jobs"]
    if set(jobs) != {"analysis"}:
        fail(f"unexpected jobs: {sorted(jobs)}")
    job = jobs["analysis"]
    if job.get("if") != "github.event.repository.private == false":
        fail("the private mirror must skip Scorecard publication")
    if job.get("runs-on") != "ubuntu-24.04":
        fail("publication requires a GitHub-hosted Ubuntu runner")
    if job.get("permissions") != {
        "contents": "read",
        "security-events": "write",
        "id-token": "write",
    }:
        fail("the job permissions must be exactly the publication minimum")
    if set(job) & {"env", "defaults", "container", "services"}:
        fail("the Scorecard job violates the publishing restrictions")

    scorecard = None
    for step in job["steps"]:
        if "run" in step:
            fail("the publishing job may contain only approved actions")
        action = step["uses"]
        name, separator, digest = action.partition("@")
        if name not in ALLOWED_ACTIONS:
            fail(f"unapproved action: {name}")
        if not separator or not re.fullmatch(r"[0-9a-f]{40}", digest):
            fail(f"{name} must be pinned to a full commit")
        if name == "ossf/scorecard-action":
            scorecard = step
    if scorecard is None:
        fail("the Scorecard action is missing")
    inputs = scorecard["with"]
    if inputs.get("publish_results") is not True:
        fail("Scorecard must publish its signed result")
    if inputs.get("results_format") != "sarif" or inputs.get("results_file") != "results.sarif":
        fail("Scorecard must produce results.sarif")
    if "repo_token" in inputs or "secrets." in text:
        fail("Scorecard must use the workflow token, not a PAT or another secret")

    print("scorecard workflow contract passed")


if __name__ == "__main__":
    main()
