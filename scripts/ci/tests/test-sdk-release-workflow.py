#!/usr/bin/env python3
"""Static proof for the GitHub SDK release workflow (codewire#3512).

npm and PyPI trust .github/workflows/sdk-release.yml by its file name and its
environment, so these properties are the release's whole authorization:

- it runs only when dispatched, on GitHub-hosted runners;
- it holds no permission by default and reads no secret;
- the build job refuses any dispatch but the owner's, of main;
- only the npm and pypi jobs may mint an OIDC token, each in the environment
  of the same name, which admits only main, and only after the build job and
  only when publish is true;
- every action is pinned to a full commit;
- each Node.js it installs is one setup-node.sh pins;
- npm only stages a version, for the owner to approve with 2FA;
- package.json names the repository npm checks the token against.
"""

from __future__ import annotations

import json
import pathlib
import re

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[3]
WORKFLOW = ROOT / ".github/workflows/sdk-release.yml"
PUBLISHERS = {"npm": "typescript", "pypi": "python"}


def fail(message: str) -> None:
    raise SystemExit(f"test-sdk-release-workflow: {message}")


def main() -> None:
    text = WORKFLOW.read_text()
    workflow = yaml.safe_load(text)
    # PyYAML reads the bare key `on` as True.
    triggers = workflow.get("on", workflow.get(True))
    if set(triggers) != {"workflow_dispatch"}:
        fail(f"the release must only be dispatched, not triggered by {sorted(triggers)}")
    inputs = triggers["workflow_dispatch"]["inputs"]
    if inputs["sdk"]["options"] != list(PUBLISHERS.values()) or inputs["publish"]["default"] is not False:
        fail("the inputs must choose typescript or python and default publish to false")
    if workflow.get("permissions") != {}:
        fail("the workflow must hold no permission by default")
    if "'workflow_dispatch|refs/heads/main|noeljackson|codewiresh/codewire'" not in text:
        fail("the build job must refuse any dispatch but the owner's, of main")
    if "secrets." in text or "GITHUB_TOKEN" in text:
        fail("the release must read no secret; the registries trust its OIDC identity")

    jobs = workflow["jobs"]
    if set(jobs) != {"build", *PUBLISHERS}:
        fail(f"unexpected jobs: {sorted(jobs)}")
    for name, job in jobs.items():
        if job.get("runs-on") != "ubuntu-24.04":
            fail(f"{name} must run on a GitHub-hosted runner; trusted publishing refuses self-hosted ones")
        permissions = job.get("permissions", {})
        if name == "build":
            if permissions != {"contents": "read"} or "environment" in job:
                fail("the build job reads the repository only")
            continue
        if (permissions.get("id-token") != "write" or set(permissions) - {"id-token", "contents"}
                or permissions.get("contents", "read") != "read"):
            fail(f"{name} may hold only id-token: write and contents: read")
        if job.get("environment") != name:
            fail(f"{name} must publish from the environment {name}, the one its registry trusts")
        if job.get("needs") != "build":
            fail(f"{name} must publish only what the build job checked")
        expected = f"${{{{ inputs.sdk == '{PUBLISHERS[name]}' && inputs.publish }}}}"
        if job.get("if") != expected:
            fail(f"{name} must run only for {PUBLISHERS[name]} with publish true")

    uses = re.findall(r"^\s*-?\s*uses:\s*(\S+)(.*)$", text, re.MULTILINE)
    if not uses:
        fail("no actions found")
    for action, comment in uses:
        if not re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", action) or not re.match(r"\s*# v\d", comment):
            fail(f"{action} must be pinned to a full commit with its version in a comment")

    pinned = set(re.findall(r"^  ([0-9.]+)-linux-x64\)", (ROOT / "scripts/ci/setup/setup-node.sh").read_text(), re.MULTILINE))
    for version in re.findall(r"setup-node\.sh (\S+)", text):
        if version not in pinned:
            fail(f"setup-node.sh does not pin Node.js {version}")

    # npm's trusted publisher allows only staged publishing, which refuses a
    # direct publish, and staging needs npm 11.15.0 (Node.js 24.22.1 has 11.19.1).
    npm_steps = "\n".join(step.get("run", "") for step in jobs["npm"]["steps"])
    if "npm stage publish" not in npm_steps or re.search(r"(?<!stage )npm publish", npm_steps):
        fail("the npm job must stage the version with npm stage publish, never publish it directly")

    package = json.loads((ROOT / "libs/sdk-ts/package.json").read_text())
    if package["repository"]["url"] != "git+https://github.com/codewiresh/codewire.git":
        fail("npm's trusted publishing requires package.json's repository to be codewiresh/codewire")
    print("sdk-release workflow contract passed")


if __name__ == "__main__":
    main()
