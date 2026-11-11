#!/usr/bin/env python3
from __future__ import annotations

import pathlib
import re
import tomllib

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[3]
WORKFLOW = ROOT / ".github/workflows/fuzz.yml"
FUZZ_MANIFEST = ROOT / "fuzz/Cargo.toml"
ALLOWED_ACTIONS = {
    "actions/cache",
    "actions/checkout",
    "actions/upload-artifact",
}


def fail(message: str) -> None:
    raise SystemExit(f"test-fuzz-workflow: {message}")


def main() -> None:
    text = WORKFLOW.read_text()
    workflow = yaml.safe_load(text)
    triggers = workflow.get("on", workflow.get(True))
    if set(triggers) != {"schedule", "workflow_dispatch"}:
        fail("fuzzing must run on its daily schedule and manual dispatch only")
    if workflow.get("permissions") != "read-all":
        fail("the workflow must be read-only by default")

    jobs = workflow["jobs"]
    if set(jobs) != {"fuzz"}:
        fail(f"unexpected jobs: {sorted(jobs)}")
    job = jobs["fuzz"]
    if job.get("if") != "github.event.repository.private == false":
        fail("the private mirror must skip fuzzing")
    if job.get("runs-on") != "ubuntu-24.04":
        fail("fuzzing must run on a GitHub-hosted Ubuntu runner")
    if job.get("permissions") != {"contents": "read"}:
        fail("the fuzz job may only read the repository")
    if set(job) & {"container", "services"}:
        fail("the fuzz job must not add a container or services")

    manifest = tomllib.loads(FUZZ_MANIFEST.read_text())
    if "workspace" not in manifest:
        fail("fuzz/Cargo.toml must be its own workspace, outside the root workspace's builds")
    targets = sorted(binary["name"] for binary in manifest["bin"])
    for binary in manifest["bin"]:
        if not (ROOT / "fuzz" / binary["path"]).is_file():
            fail(f"{binary['name']}: missing {binary['path']}")
    if sorted(job["strategy"]["matrix"]["target"]) != targets:
        fail(f"the matrix must fuzz exactly the targets in fuzz/Cargo.toml: {targets}")

    toolchain = job["env"]["FUZZ_TOOLCHAIN"]
    if not re.fullmatch(r"nightly-\d{4}-\d{2}-\d{2}", toolchain):
        fail("the nightly toolchain must be pinned to a date")
    if not re.fullmatch(r"\d+\.\d+\.\d+", job["env"]["CARGO_FUZZ_VERSION"]):
        fail("cargo-fuzz must be pinned to an exact version")

    for step in job["steps"]:
        if "uses" not in step:
            continue
        name, separator, digest = step["uses"].partition("@")
        if name not in ALLOWED_ACTIONS:
            fail(f"unapproved action: {name}")
        if not separator or not re.fullmatch(r"[0-9a-f]{40}", digest):
            fail(f"{name} must be pinned to a full commit")
        if name == "actions/checkout" and step.get("with", {}).get("persist-credentials") is not False:
            fail("the checkout must not persist the workflow token")
    if "cp Cargo.lock fuzz/Cargo.lock" not in text:
        fail("the fuzz lock must be seeded from the root lock")
    if "--locked" not in text:
        fail("cargo-fuzz must be installed from its own lock")
    if "secrets." in text:
        fail("fuzzing must not use a secret")

    print("fuzz workflow contract passed")


if __name__ == "__main__":
    main()
