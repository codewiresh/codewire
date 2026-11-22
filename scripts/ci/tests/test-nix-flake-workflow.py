#!/usr/bin/env python3
"""Contract for the public mirror's Nix flake check (docs/dev/CLI-NIX-INSTALL.md,
"The check"; #5399): GitHub-hosted, read-only, run only when the flake or its
pin changes, Nix configured so a flake can't widen what it trusts, and both a
build of the released cw and the pin's recomputation from the signed release."""
from __future__ import annotations

import pathlib
import re
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[3]
WORKFLOW = ROOT / ".github/workflows/nix-flake.yml"
ALLOWED_ACTIONS = {"actions/checkout"}
INSTALLER_URL = re.compile(r"https://releases\.nixos\.org/nix/nix-[0-9]+\.[0-9]+\.[0-9]+/install")
PATHS = ["flake.nix", "flake.lock", "nix/**", ".github/workflows/nix-flake.yml"]
NIX_CONFIG = {
    "experimental-features": "nix-command flakes",
    "accept-flake-config": "false",
    "sandbox": "true",
    "require-sigs": "true",
    "substituters": "https://cache.nixos.org/",
    "trusted-public-keys": "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=",
}


def errors(text: str) -> list[str]:
    found = []

    def need(condition: bool, message: str) -> None:
        if not condition:
            found.append(message)

    workflow = yaml.safe_load(text)
    triggers = workflow.get("on", workflow.get(True))
    need(set(triggers) == {"push", "workflow_dispatch"}, "the check runs on main's pushes and dispatch only")
    need(triggers.get("push") == {"branches": ["main"], "paths": PATHS},
         "the check runs only when the flake, its pin or this workflow changes on main")
    need(workflow.get("permissions") == {}, "the workflow grants nothing by default")
    need("secrets." not in text, "the check uses no secret")

    jobs = workflow.get("jobs", {})
    need(set(jobs) == {"flake", "pin"}, f"unexpected jobs: {sorted(jobs)}")
    for name, job in jobs.items():
        need(job.get("if") == "github.event.repository.private == false", f"{name}: the private mirror must skip it")
        need(job.get("permissions") == {"contents": "read"}, f"{name}: may only read the repository")
        need(not set(job) & {"container", "services"}, f"{name}: adds a container or services")
        for step in job.get("steps", []):
            if "uses" not in step:
                continue
            action, separator, digest = step["uses"].partition("@")
            need(action in ALLOWED_ACTIONS, f"{name}: unapproved action {action}")
            need(bool(separator) and re.fullmatch(r"[0-9a-f]{40}", digest.split()[0]) is not None,
                 f"{name}: {action} is not pinned to a full commit")
            if action == "actions/checkout":
                need(step.get("with", {}).get("persist-credentials") is False,
                     f"{name}: the checkout persists the workflow token")

    flake = jobs.get("flake", {})
    need(flake.get("runs-on") == "${{ matrix.os }}"
         and flake.get("strategy", {}).get("matrix", {}).get("os") == ["ubuntu-24.04", "macos-15"],
         "the flake is installed on GitHub-hosted Linux and macOS")
    install = next((step for step in flake.get("steps", []) if step.get("name") == "Install Nix"), {})
    env = install.get("env", {})
    script = install.get("run", "")
    need(INSTALLER_URL.fullmatch(str(env.get("NIX_INSTALLER_URL", ""))) is not None,
         "Nix is not installed by its official installer at one release")
    need(re.fullmatch(r"[0-9a-f]{64}", str(env.get("NIX_INSTALLER_SHA256", ""))) is not None,
         "the Nix installer has no pinned SHA-256")
    need('[[ "$got" == "$NIX_INSTALLER_SHA256" ]]' in script
         and script.index('[[ "$got" == "$NIX_INSTALLER_SHA256" ]]') < script.find('sh "$work/install"'),
         "the installer runs before its SHA-256 is checked")
    need('sh "$work/install" --daemon ' in script, "Nix is not a daemon install, so the runner's user is trusted")
    body = script.split("<<'EOF'\n", 1)[1].split("\nEOF\n", 1)[0] if "<<'EOF'\n" in script else ""
    config = dict(line.split(" = ", 1) for line in body.splitlines() if " = " in line)
    need(config == NIX_CONFIG, f"Nix is not configured exactly as reviewed: {config}")
    run = "\n".join(step.get("run", "") for step in flake.get("steps", []))
    need("nix flake check --all-systems --no-build" in run, "every system's package is not evaluated")
    need('version="$(nix run .#cw -- version)"' in run and '[[ "$version" == "cw $release" ]]' in run,
         "the installed cw is not run and compared with the pinned release")
    need('[[ "$got" == "$want" ]]' in run, "the installed bytes are not compared with the release")
    need('codesign --verify --strict --verbose=2 "$out/bin/cw"' in run, "the macOS signature is not verified")

    pin = jobs.get("pin", {})
    need(pin.get("runs-on") == "ubuntu-24.04", "the pin is checked on a GitHub-hosted Ubuntu runner")
    need(any(step.get("run") == "python3 -I -B scripts/ci/release/nix_release_pin.py check --pin nix/release.json --blobs"
             for step in pin.get("steps", [])),
         "the pin is not recomputed from the signed release with its blobs")
    return found


MUTATIONS = {
    "pull requests": lambda t: t.replace("  workflow_dispatch:\n", "  workflow_dispatch:\n  pull_request_target:\n", 1),
    "any path": lambda t: t.replace('      - "nix/**"\n', "", 1),
    "write token": lambda t: t.replace("    permissions:\n      contents: read\n",
                                       "    permissions:\n      contents: write\n", 1),
    "flake config accepted": lambda t: t.replace("accept-flake-config = false", "accept-flake-config = true", 1),
    "no sandbox": lambda t: t.replace("sandbox = true", "sandbox = false", 1),
    "extra cache": lambda t: t.replace("substituters = https://cache.nixos.org/",
                                       "substituters = https://cache.nixos.org/ https://example.invalid", 1),
    "trusted user": lambda t: t.replace("          require-sigs = true\n",
                                        "          require-sigs = true\n          trusted-users = root runner\n", 1),
    "single-user install": lambda t: t.replace('sh "$work/install" --daemon ', 'sh "$work/install" --no-daemon ', 1),
    "unchecked installer": lambda t: t.replace('[[ "$got" == "$NIX_INSTALLER_SHA256" ]]', "true", 1),
    "unpinned installer": lambda t: t.replace("https://releases.nixos.org/nix/nix-2.28.3/install",
                                              "https://nixos.org/nix/install", 1),
    "third-party action": lambda t: t.replace("      - name: Install Nix\n",
                                              "      - name: Set up\n        uses: example/setup@v1\n\n"
                                              "      - name: Install Nix\n", 1),
    "no version check": lambda t: t.replace('[[ "$version" == "cw $release" ]]', "true", 1),
    "no byte check": lambda t: t.replace('[[ "$got" == "$want" ]]', "true", 1),
    "no blob check": lambda t: t.replace(" --pin nix/release.json --blobs", " --pin nix/release.json", 1),
    "persisted token": lambda t: t.replace("persist-credentials: false", "persist-credentials: true", 1),
}


def main() -> int:
    text = WORKFLOW.read_text()
    found = errors(text)
    for name, mutate in MUTATIONS.items():
        mutated = mutate(text)
        if mutated == text or not errors(mutated):
            found.append(f"mutation {name!r} was not rejected")
    if found:
        print("test-nix-flake-workflow: FAIL\n  " + "\n  ".join(found), file=sys.stderr)
        return 1
    print(f"test-nix-flake-workflow: PASS mutations_rejected={len(MUTATIONS)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
