#!/usr/bin/env python3
"""The cw-egress image pin: the one digest the egress component runs.

The pin is a digest-only `images:` entry in deployments/k8s/egress's
Component. Each overlay that opts in maps the placeholder name to its own
registry and never sets a digest or tag, so the component decides what runs
and no registry host is written here (private-docs designs/hosted-egress.md,
"The image and its deployment"). Only a merged "bump cw-egress" pull request
changes the pin.

  egress-image-pin.py fingerprint --commit SHA   the egress_image fingerprint at SHA
  egress-image-pin.py show --commit SHA          the pinned digest at SHA, or nothing
  egress-image-pin.py render --digest DIGEST     write DIGEST as the pin
  egress-image-pin.py check                      the pin's form in the working tree
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
COMPONENT = "deployments/k8s/egress/kustomization.yaml"
PLACEHOLDER = "git.example.com/codewire/egress"
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
COMMIT = re.compile(r"[0-9a-f]{40}")
HEADER = "images:\n"
ENTRY = f"  - name: {PLACEHOLDER}\n    digest: {{digest}}\n"
PIN_BLOCK = re.compile(
    r"^images:\n  - name: " + re.escape(PLACEHOLDER) + r"\n    digest: (\S+)\n", re.MULTILINE
)


class PinError(RuntimeError):
    pass


def git(*args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(ROOT), *args], capture_output=True, text=True, check=False, timeout=120
    )
    if completed.returncode != 0:
        raise PinError(f"git {' '.join(args)} failed: {completed.stderr.strip()}")
    return completed.stdout


def commit(value: str) -> str:
    if not COMMIT.fullmatch(value):
        raise PinError(f"not an exact commit: {value!r}")
    return value


def pinned(text: str) -> str:
    """The pinned digest in a component's text, or "" when it pins none yet."""
    if "images:" not in text:
        return ""
    matches = PIN_BLOCK.findall(text)
    if len(matches) != 1 or text.count("images:") != 1:
        raise PinError(f"{COMPONENT} must hold exactly one images entry, the digest of {PLACEHOLDER}")
    if not DIGEST.fullmatch(matches[0]):
        raise PinError(f"{COMPONENT} pins {matches[0]!r}, not a sha256 digest")
    after = text[text.index("images:"):]
    entry = after.split("\n\n", 1)[0]
    if re.search(r"^\s+(newName|newTag):", entry, re.MULTILINE):
        raise PinError(f"{COMPONENT} must pin only a digest: overlays name the registry, and no tag is used")
    return matches[0]


def show(sha: str) -> str:
    return pinned(git("show", f"{commit(sha)}:{COMPONENT}"))


def fingerprint(sha: str) -> str:
    """The planner's egress_image fingerprint at `sha`, with `sha` as its own policy."""
    sha = commit(sha)
    with tempfile.TemporaryDirectory(prefix="codewire-egress-pin-") as temporary:
        plan = Path(temporary) / "plan.json"
        completed = subprocess.run(
            [sys.executable, str(ROOT / "scripts/ci/plan/planner.py"), "--repository", str(ROOT),
             "--target-base", sha, "--head", sha, "--trusted-policy", sha, "--output", str(plan)],
            capture_output=True, text=True, check=False, timeout=600,
        )
        if completed.returncode != 0:
            raise PinError(f"the planner failed at {sha}: {completed.stderr.strip()[-400:]}")
        value = json.loads(plan.read_text())["artifacts"].get("egress_image", {}).get("head_fingerprint")
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise PinError(f"the planner gave no egress_image fingerprint at {sha}")
    return value


def render(digest: str) -> None:
    if not DIGEST.fullmatch(digest):
        raise PinError(f"not a sha256 digest: {digest!r}")
    path = ROOT / COMPONENT
    text = path.read_text()
    pinned(text)
    block = HEADER + ENTRY.format(digest=digest)
    if "images:" in text:
        text = PIN_BLOCK.sub(block, text)
    else:
        text = text.rstrip("\n") + "\n\n" + block
    path.write_text(text)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("fingerprint", "show"):
        commands.add_parser(name).add_argument("--commit", required=True)
    commands.add_parser("render").add_argument("--digest", required=True)
    commands.add_parser("check")
    args = parser.parse_args(argv)
    try:
        if args.command == "fingerprint":
            print(fingerprint(args.commit))
        elif args.command == "show":
            print(show(args.commit))
        elif args.command == "render":
            render(args.digest)
        else:
            pinned((ROOT / COMPONENT).read_text())
    except PinError as error:
        print(f"egress image pin: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
