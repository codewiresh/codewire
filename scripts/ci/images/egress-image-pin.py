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
  egress-image-pin.py verify --commit SHA --digest DIGEST
                                                 the trusted pin check before a delivery uses SHA's tree

verify is the design's trusted check ("The pin check, in two parts"): it fails
closed unless DIGEST is the pin at SHA, exists in the registry
($CODEWIRE_IMAGE_REGISTRY) with the pipeline identity's main-CI-verified
signature, and that signature names a source commit SHA contains. A pin whose
egress inputs have moved on is stale, which a main-only job warns about; it
does not stop a delivery.
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

ROOT = Path(__file__).resolve().parents[3]
COMPONENT = "deployments/k8s/egress/kustomization.yaml"
PLACEHOLDER = "git.example.com/codewire/egress"
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
COMMIT = re.compile(r"[0-9a-f]{40}")
REGISTRY = re.compile(r"[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]+)?")
VERIFIER = ROOT / "scripts/ci/images/verify-runtime-image-signatures.sh"
PUBLIC_KEY = ROOT / "scripts/ci/trust/codewire-runtime-signing.pub"
HEADER = "images:\n"
ENTRY = f"  - name: {PLACEHOLDER}\n    digest: {{digest}}\n"
# The front-door hosts orchestration binds and cw-egress serves, which both
# compile in from codewire-access: the checked-in derived list, and for a
# pinned image older than that list, the declarations it is derived from.
FRONT_DOOR_HOSTS = "crates/codewire-access/front-door-hosts.txt"
FRONT_DOOR_SOURCE = "crates/codewire-access/src/front_door.rs"
FRONT_DOOR_DECLARATIONS = re.compile(
    r"^pub const (?:GITHUB_INTERCEPTED|[A-Z_]*_HOSTS?|[A-Z_]*_WILDCARD)\b.*?;$", re.M | re.S)
PIN_BLOCK = re.compile(
    r"^images:\n  - name: " + re.escape(PLACEHOLDER) + r"\n    digest: (\S+)\n", re.MULTILINE
)


class PinError(RuntimeError):
    pass


def run(command: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    """Run `command`; one that outlives `timeout` seconds is a refusal, never a traceback."""
    try:
        return subprocess.run(command, capture_output=True, text=True, check=False, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise PinError(f"{Path(command[0]).name} {' '.join(command[1:])} took over {timeout} s") from None


def git(*args: str) -> str:
    completed = run(["git", "-C", str(ROOT), *args], 120)
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
        completed = run(
            [sys.executable, str(ROOT / "scripts/ci/plan/planner.py"), "--repository", str(ROOT),
             "--target-base", sha, "--head", sha, "--trusted-policy", sha, "--output", str(plan)],
            600,
        )
        if completed.returncode != 0:
            raise PinError(f"the planner failed at {sha}: {completed.stderr.strip()[-400:]}")
        value = json.loads(plan.read_text())["artifacts"].get("egress_image", {}).get("head_fingerprint")
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise PinError(f"the planner gave no egress_image fingerprint at {sha}")
    return value


def contains(sha: str, source: str) -> bool:
    """Whether `sha` contains `source`; an unknown commit is not contained."""
    return run(["git", "-C", str(ROOT), "merge-base", "--is-ancestor", source, sha], 120).returncode == 0


def verify(sha: str, digest: str, registry: str) -> str:
    """The trusted pin check for a delivery of `sha`'s tree; the signed source it accepted."""
    sha = commit(sha)
    if not DIGEST.fullmatch(digest):
        raise PinError(f"not a sha256 digest: {digest!r}")
    if not REGISTRY.fullmatch(registry):
        raise PinError(f"not a registry host: {registry!r}")
    pin = show(sha)
    if not pin:
        raise PinError(f"{sha} pins no cw-egress image, but {digest} is delivered")
    if pin != digest:
        raise PinError(f"{digest} is delivered, but {sha} pins {pin}")
    reference = f"{registry}/codewire/egress@{digest}"
    completed = run([str(VERIFIER), "--egress", reference, str(PUBLIC_KEY)], 600)
    if completed.returncode != 0:
        raise PinError(f"{reference} is missing or has no valid main-CI-verified signature: "
                       f"{completed.stderr.strip()[-400:]}")
    for source in completed.stdout.split():
        if COMMIT.fullmatch(source) and contains(sha, source):
            return source
    raise PinError(f"no main-CI-verified signature of {reference} names a source that {sha} contains")


def front_door(sha: str) -> str | None:
    """What decides `sha`'s front-door hosts: its derived list, or before that
    list existed, the host declarations in front_door.rs; None when neither
    is readable."""
    listed = run(["git", "-C", str(ROOT), "show", f"{commit(sha)}:{FRONT_DOOR_HOSTS}"], 120)
    if listed.returncode == 0:
        return "list:" + listed.stdout
    source = run(["git", "-C", str(ROOT), "show", f"{commit(sha)}:{FRONT_DOOR_SOURCE}"], 120)
    if source.returncode != 0:
        return None
    return "declarations:" + "\n".join(FRONT_DOOR_DECLARATIONS.findall(source.stdout))


def same_front_door(sha: str, source: str) -> None:
    """Refuse a delivery of `sha` whose front-door hosts differ from those of
    the pinned cw-egress image's `source` (infra#1534): orchestration would
    bind hosts cw-egress doesn't serve, as on 2026-11-24 when 576f428938's
    GitHub routes met cw-egress from d9abce139c."""
    delivered, pinned_image = front_door(sha), front_door(source)
    if delivered is None or pinned_image is None:
        raise PinError(f"the front-door hosts of {sha} or {source} cannot be read")
    if delivered.split(":", 1)[0] != pinned_image.split(":", 1)[0]:
        # One side predates the list: compare the declarations both have.
        delivered = "declarations:" + "\n".join(FRONT_DOOR_DECLARATIONS.findall(
            git("show", f"{commit(sha)}:{FRONT_DOOR_SOURCE}")))
        pinned_image = "declarations:" + "\n".join(FRONT_DOOR_DECLARATIONS.findall(
            git("show", f"{commit(source)}:{FRONT_DOOR_SOURCE}")))
    if delivered != pinned_image:
        raise PinError(
            f"{sha} changes the front-door hosts past the pinned cw-egress image (built from {source}); "
            "merge the cw-egress bump first")


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
    verifying = commands.add_parser("verify")
    verifying.add_argument("--commit", required=True)
    verifying.add_argument("--digest", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "fingerprint":
            print(fingerprint(args.commit))
        elif args.command == "show":
            print(show(args.commit))
        elif args.command == "render":
            render(args.digest)
        elif args.command == "verify":
            registry = os.environ.get("CODEWIRE_IMAGE_REGISTRY", "")
            source = verify(args.commit, args.digest, registry)
            same_front_door(args.commit, source)
            print(f"egress image pin: {args.digest} is the pin at {args.commit}, signed by main CI from {source}, "
                  "with the same front-door hosts")
        else:
            pinned((ROOT / COMPONENT).read_text())
    except PinError as error:
        print(f"egress image pin: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
