#!/usr/bin/env python3
"""Build inputs of each service `make kind-deploy` can update.

`make kind-test` deploys only the services a change feeds, and skips one whose
current inputs the cluster already runs:

  service-sources.py changes --base REF   changed crates and migrations, and
                                          the services they feed, between the
                                          merge base and the working tree
  service-sources.py digest SERVICE       digest of SERVICE's current inputs

A service's inputs are its crate's workspace dependency closure plus what
deployments/docker/kind-dev-binary.Dockerfile copies from outside crates/.
Uncommitted and untracked (not ignored) files count, as the build sees them.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[3]
DIGEST_SCHEMA = "codewire.kind-dev-source/v1"

# deploy-service.sh builds each service from this crate.
SERVICES = {
    "idp": "codewire-idp",
    "orchestration": "codewire-orchestration",
    "credential-service": "codewire-credential-service",
    "billing": "codewire-billing",
    "coordinator": "codewire-coordinator",
    "mesh": "codewire-mesh",
    "dashboard": "codewire-dashboard-web",
    "daemon": "codewire-cli-bin",
}
# The build recipe: the toolchain image, the compiler wrapper it installs, and
# the kind-dev build step.
RECIPE_INPUTS = (
    "deployments/docker/rust-base.Dockerfile",
    "scripts/ci/images/run-rust-build.sh",
    "deployments/docker/kind-dev-binary.Dockerfile",
)
# Copied for every build: the workspace manifest and lock, the kind-dev Cargo
# profile and the protobuf sources every service compiles through
# codewire-daemon-proto; plus the recipe.
SHARED_INPUTS = (
    "Cargo.toml",
    "Cargo.lock",
    "scripts/dev/kind/cargo-profile.toml",
    "proto",
    "libs/daemon-proto",
) + RECIPE_INPUTS
# Copied files that only these crates embed.
CRATE_INPUTS = {
    "codewire-dashboard-web": ("packages/codewire-design", "apps/cli/install.sh"),
    "codewire-cli": ("apps/cli/GPG_PUBLIC_KEY.asc",),
    # Embedded by the cw runtime smoke example, which build-smokes.sh compiles.
    "codewire-client": ("scripts/ci/verify/kind/cw_runtime_probe.py",),
}
# Every service compiles the published workspace image pin, but a retained
# cluster keeps the workspace image it was prepared with, so a pin change is
# observed on Dev and never redeploys a service here.
IGNORED_CRATES = frozenset({"codewire-workspace-image"})


class Failure(Exception):
    pass


def git(*args: str, env: dict[str, str] | None = None) -> str:
    result = subprocess.run(["git", "-C", str(ROOT), *args], env=env, text=True,
                            capture_output=True, stdin=subprocess.DEVNULL, check=False)
    if result.returncode != 0:
        raise Failure(f"git {args[0]} failed: {result.stderr.strip()}")
    return result.stdout


def workspace_crates() -> dict[str, tuple[str, list[tuple[str, str | None]]]]:
    """name -> (directory relative to ROOT, [(path dependency, kind)])."""
    result = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--offline", "--format-version", "1",
         "--manifest-path", str(ROOT / "Cargo.toml")],
        text=True, capture_output=True, stdin=subprocess.DEVNULL, check=False)
    if result.returncode != 0:
        raise Failure(f"cargo metadata failed: {result.stderr.strip()}")
    crates = {}
    for package in json.loads(result.stdout)["packages"]:
        directory = Path(package["manifest_path"]).resolve().parent.relative_to(ROOT).as_posix()
        dependencies = [(dependency["name"], dependency["kind"])
                        for dependency in package["dependencies"] if dependency.get("path")]
        crates[package["name"]] = (directory, dependencies)
    return crates


def closure(crates: dict[str, tuple[str, list[tuple[str, str | None]]]], root: str) -> set[str]:
    # The root's dev-dependencies count: the credential fixture is its test binary.
    found = {root}
    pending = [name for name, _ in crates[root][1]]
    while pending:
        name = pending.pop()
        if name in found or name not in crates:
            continue
        found.add(name)
        pending.extend(dependency for dependency, kind in crates[name][1] if kind != "dev")
    return found


def service_inputs(crates, service: str) -> list[str]:
    if service not in SERVICES:
        raise Failure(f"unknown service: {service}")
    members = closure(crates, SERVICES[service]) - IGNORED_CRATES
    inputs = set(SHARED_INPUTS)
    for name in members:
        inputs.add(crates[name][0])
        inputs.update(CRATE_INPUTS.get(name, ()))
    return sorted(inputs)


def working_tree(paths: list[str]) -> str:
    """A tree object of HEAD's index with PATHS replaced by the working tree."""
    index = Path(git("rev-parse", "--git-path", "index").strip())
    if not index.is_absolute():
        index = ROOT / index
    tracked = git("ls-files", "-z", "--", *paths).split("\0")
    known = [path for path in paths if (ROOT / path).exists()
             or any(name == path or name.startswith(path + "/") for name in tracked)]
    with tempfile.TemporaryDirectory(prefix="kind-service-sources.") as directory:
        scratch = Path(directory) / "index"
        if index.exists():
            shutil.copyfile(index, scratch)
        env = os.environ | {"GIT_INDEX_FILE": str(scratch)}
        if not index.exists():
            git("read-tree", "HEAD", env=env)
        if known:
            git("add", "--all", "--", *known, env=env)
        return git("write-tree", env=env).strip()


def object_ids(tree: str, paths: list[str]) -> dict[str, str]:
    ids = {}
    for line in git("ls-tree", "-z", tree, "--", *paths).split("\0"):
        if line:
            meta, path = line.split("\t", 1)
            ids[path] = meta.split()[2]
    return ids


def under(path: str, inputs: list[str]) -> bool:
    return any(path == item or path.startswith(item + "/") for item in inputs)


def command_digest(service: str) -> None:
    crates = workspace_crates()
    inputs = service_inputs(crates, service)
    ids = object_ids(working_tree(inputs), inputs)
    record = [DIGEST_SCHEMA, service] + [f"{path} {ids.get(path, 'absent')}" for path in inputs]
    print(hashlib.sha256("\n".join(record).encode()).hexdigest())


def command_changes(base: str) -> None:
    crates = workspace_crates()
    inputs = {service: service_inputs(crates, service) for service in SERVICES}
    paths = sorted({"crates"} | {path for items in inputs.values() for path in items})
    try:
        merge_base = git("merge-base", base, "HEAD").strip()
    except Failure:
        merge_base = git("rev-parse", "--verify", f"{base}^{{commit}}").strip()
    changed = [path for path in git("diff-tree", "-r", "-z", "--name-only", "--no-renames",
                                    merge_base, working_tree(paths)).split("\0") if path]
    names = {directory: name for name, (directory, _) in crates.items()}
    for name in sorted({names[directory] for path in changed
                        for directory in names if under(path, [directory])}):
        print("crate", name)
    for path in changed:
        parts = path.split("/")
        if len(parts) > 3 and parts[0] == "crates" and parts[2] == "migrations":
            print("migration", path)
    for service in SERVICES:
        if any(under(path, inputs[service]) for path in changed):
            print("service", service)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    changes = commands.add_parser("changes")
    changes.add_argument("--base", required=True)
    digest = commands.add_parser("digest")
    digest.add_argument("service", choices=sorted(SERVICES))
    arguments = parser.parse_args()
    try:
        if arguments.command == "changes":
            command_changes(arguments.base)
        else:
            command_digest(arguments.service)
    except Failure as error:
        print(f"service-sources: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
