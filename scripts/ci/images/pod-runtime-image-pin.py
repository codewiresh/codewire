#!/usr/bin/env python3
"""The standard pod-runtime image pin: the one digest a deployment runs (#5602).

The pin is deployments/k8s/orchestration/pod-runtime-image.digest, one line:
`unpinned`, or the image's `sha256:` digest. Dev delivery builds and signs the
image but never delivers it, exactly as it does cw-egress
(egress-image-pin.py); a deployment that turns `standard` on sets
SANDBOX_STANDARD_RUNTIME_IMAGE to its own registry's copy of this digest, and
its delivery verifies it with `verify` before it runs. Only a merged pull
request changes the pin.

  pod-runtime-image-pin.py fingerprint --commit SHA   the pod_runtime_image fingerprint at SHA
  pod-runtime-image-pin.py show --commit SHA          the pinned digest at SHA, or nothing
  pod-runtime-image-pin.py render --digest DIGEST     write DIGEST as the pin
  pod-runtime-image-pin.py check                      the pin's form in the working tree
  pod-runtime-image-pin.py verify --commit SHA --digest DIGEST
                                                      the trusted pin check before a delivery uses SHA's tree

verify fails closed unless DIGEST is the pin at SHA, exists in the registry
($CODEWIRE_IMAGE_REGISTRY) with the pipeline identity's main-CI-verified
signature of the pod-runtime family, and that signature names a source commit
SHA contains.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PIN = "deployments/k8s/orchestration/pod-runtime-image.digest"
UNPINNED = "unpinned"
ARTIFACT = "pod_runtime_image"

# The egress pin's checked helpers: one implementation of running, git, exact
# commits, containment and the signature verifier's location.
_spec = importlib.util.spec_from_file_location("egress_image_pin", ROOT / "scripts/ci/images/egress-image-pin.py")
egress = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(egress)
PinError = egress.PinError


def pinned(text: str) -> str:
    """The pinned digest in the pin file's text, or "" when it pins none yet."""
    lines = text.split("\n")
    if len(lines) != 2 or lines[1] != "":
        raise PinError(f"{PIN} must be exactly one line")
    if lines[0] == UNPINNED:
        return ""
    if not egress.DIGEST.fullmatch(lines[0]):
        raise PinError(f"{PIN} pins {lines[0]!r}, not {UNPINNED} or a sha256 digest")
    return lines[0]


def show(sha: str) -> str:
    return pinned(egress.git("show", f"{egress.commit(sha)}:{PIN}"))


def fingerprint(sha: str) -> str:
    """The planner's pod_runtime_image fingerprint at `sha`, with `sha` as its own policy."""
    sha = egress.commit(sha)
    with tempfile.TemporaryDirectory(prefix="codewire-pod-runtime-pin-") as temporary:
        plan = Path(temporary) / "plan.json"
        completed = egress.run(
            [sys.executable, str(ROOT / "scripts/ci/plan/planner.py"), "--repository", str(ROOT),
             "--target-base", sha, "--head", sha, "--trusted-policy", sha, "--output", str(plan)],
            600,
        )
        if completed.returncode != 0:
            raise PinError(f"the planner failed at {sha}: {completed.stderr.strip()[-400:]}")
        value = json.loads(plan.read_text())["artifacts"].get(ARTIFACT, {}).get("head_fingerprint")
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise PinError(f"the planner gave no {ARTIFACT} fingerprint at {sha}")
    return value


def verify(sha: str, digest: str, registry: str) -> str:
    """The trusted pin check for a delivery of `sha`'s tree; the signed source it accepted."""
    sha = egress.commit(sha)
    if not egress.DIGEST.fullmatch(digest):
        raise PinError(f"not a sha256 digest: {digest!r}")
    if not egress.REGISTRY.fullmatch(registry):
        raise PinError(f"not a registry host: {registry!r}")
    pin = show(sha)
    if not pin:
        raise PinError(f"{sha} pins no pod-runtime image, but {digest} is delivered")
    if pin != digest:
        raise PinError(f"{digest} is delivered, but {sha} pins {pin}")
    reference = f"{registry}/codewire/pod-runtime@{digest}"
    completed = egress.run([str(egress.VERIFIER), "--pod-runtime", reference, str(egress.PUBLIC_KEY)], 600)
    if completed.returncode != 0:
        raise PinError(f"{reference} is missing or has no valid main-CI-verified signature: "
                       f"{completed.stderr.strip()[-400:]}")
    for source in completed.stdout.split():
        if egress.COMMIT.fullmatch(source) and egress.contains(sha, source):
            return source
    raise PinError(f"no main-CI-verified signature of {reference} names a source that {sha} contains")


def render(digest: str) -> None:
    if not egress.DIGEST.fullmatch(digest):
        raise PinError(f"not a sha256 digest: {digest!r}")
    path = ROOT / PIN
    pinned(path.read_text())
    path.write_text(digest + "\n")


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
            print(f"pod-runtime image pin: {args.digest} is the pin at {args.commit}, signed by main CI from {source}")
        else:
            pinned((ROOT / PIN).read_text())
    except PinError as error:
        print(f"pod-runtime image pin: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
