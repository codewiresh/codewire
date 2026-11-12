#!/usr/bin/env python3
"""Build the Pods a pull request's sandbox goldens render, for `kyverno apply` (#3821).

Usage: kyverno-pods-from-goldens.py GOLDENS POLICY REGISTRY OUT

GOLDENS is crates/codewire-orchestration/tests/fixtures/sandbox of the tree
under test, and POLICY one cluster's sandbox-runtime-security.yaml. REGISTRY is
the hosted image registry's host (CODEWIRE_IMAGE_REGISTRY). OUT is a new
directory; one Pod is written per case, and the case names are printed.

Cases named pass-* are the hosted sandbox templates as a real render would
carry them: the placeholder registry becomes the hosted one, a `:golden` tag
an exact digest, and each DinD image the policy's own approved image of the
same version. They must be admitted. deny-* cases are single mutations of
the warm-pool template the policy must refuse; they prove the CLI evaluates the
policy's foreach, regex and hash rules rather than passing everything.
"""

from __future__ import annotations

import copy
import json
import os
import pathlib
import re
import stat
import sys

import yaml

# The templates rendered into the hosted shared sandbox namespaces. A new
# SandboxTemplate golden must be named here or in LOCAL_ONLY, so none is
# silently left unchecked.
HOSTED = (
    "warm-pool-sandboxtemplate",
    "warm-pool-subfolder-sandboxtemplate",
    "identity-free-sandboxtemplate",
    "confidential-sandboxtemplate",
)
# Rendered for local Kind only (runc), which the shared policy refuses.
LOCAL_ONLY = ("identity-free-sandboxtemplate-runc",)
PLACEHOLDER_REGISTRY = "registry.example.invalid/"
# A host, with an optional port and no scheme or path.
REGISTRY = re.compile(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]+)?$")
PLACEHOLDER_DIGEST = "@sha256:" + "a" * 64
# A golden is a few kilobytes; the bound only stops an absurd file.
MAX_GOLDEN_BYTES = 1024 * 1024
DIND = re.compile(r"^docker\.io/library/docker:([0-9.]+)-dind@sha256:[0-9a-f]{64}$")


class Refused(Exception):
    pass


def approved_dind(policy_text: str) -> dict[str, str]:
    """The policy's approved DinD images, by Docker version."""
    approved: dict[str, str] = {}
    for document in yaml.safe_load_all(policy_text):
        if not isinstance(document, dict) or document.get("kind") != "ClusterPolicy":
            continue
        for rule in document["spec"]["rules"]:
            for exclusion in ((rule.get("validate") or {}).get("podSecurity") or {}).get("exclude", []):
                for image in exclusion.get("images", []):
                    match = DIND.match(image)
                    if match:
                        approved[match.group(1)] = image
    if not approved:
        raise Refused("the policy approves no DinD image")
    return approved


def real_image(image: str, dind: dict[str, str], registry: str) -> str:
    match = re.match(r"^docker\.io/library/docker:([0-9.]+)-dind@", image)
    if match:
        # An unapproved version stays as rendered, so the policy refuses it.
        return dind.get(match.group(1), image)
    if image.startswith(PLACEHOLDER_REGISTRY):
        image = f"{registry}/{image[len(PLACEHOLDER_REGISTRY):]}"
    if image.endswith(":golden"):
        image = image[: -len(":golden")] + PLACEHOLDER_DIGEST
    return image


def pod(golden: dict, name: str, dind: dict[str, str], registry: str) -> dict:
    template = golden["spec"]["podTemplate"]
    spec = copy.deepcopy(template["spec"])
    for key in ("initContainers", "containers"):
        for container in spec.get(key, []):
            container["image"] = real_image(container["image"], dind, registry)
    metadata = copy.deepcopy(template.get("metadata") or {})
    metadata.update(name=name, namespace="dev-sandboxes")
    # The agent-sandbox controller adds this label to every member Pod.
    metadata.setdefault("labels", {})["agents.x-k8s.io/sandbox-name-hash"] = "0123456789abcdef"
    return {"apiVersion": "v1", "kind": "Pod", "metadata": metadata, "spec": spec}


def container(case: dict, name: str) -> dict:
    for key in ("initContainers", "containers"):
        for item in case["spec"].get(key, []):
            if item["name"] == name:
                return item
    raise Refused(f"the warm-pool template has no {name} container")


def read_golden(path: pathlib.Path) -> str:
    """A golden as a regular file of the tree, never through a link.

    The tree under test is a pull request's: a golden committed as a symlink
    could otherwise name a file on the runner and have it parsed and logged.
    """
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as error:
        raise Refused(f"{path.name} is not a regular file of the tree") from error
    try:
        held = os.fstat(descriptor)
        if not stat.S_ISREG(held.st_mode) or held.st_size > MAX_GOLDEN_BYTES:
            raise Refused(f"{path.name} is not a regular file of at most {MAX_GOLDEN_BYTES} bytes")
        with os.fdopen(descriptor, "r", encoding="utf-8", closefd=False) as stream:
            return stream.read()
    finally:
        os.close(descriptor)


def cases(goldens: pathlib.Path, policy_text: str, registry: str) -> dict[str, dict]:
    if not REGISTRY.match(registry):
        raise Refused("REGISTRY must be a registry host, such as registry.example.com")
    dind = approved_dind(policy_text)
    if goldens.is_symlink() or not goldens.is_dir():
        raise Refused("the goldens directory is not a directory of the tree")
    templates = sorted(path.name.removesuffix(".golden.json")
                       for path in goldens.glob("*sandboxtemplate*.golden.json"))
    unknown = sorted(set(templates) - set(HOSTED) - set(LOCAL_ONLY))
    if unknown:
        raise Refused(f"unclassified SandboxTemplate goldens: {', '.join(unknown)}")
    missing = sorted(set(HOSTED) - set(templates))
    if missing:
        raise Refused(f"missing hosted SandboxTemplate goldens: {', '.join(missing)}")

    def load(stem: str) -> dict:
        return json.loads(read_golden(goldens / f"{stem}.golden.json"))

    built = {f"pass-{stem}": pod(load(stem), f"pass-{stem}", dind, registry) for stem in HOSTED}

    def mutated(name: str, change) -> None:
        case = pod(load("warm-pool-sandboxtemplate"), name, dind, registry)
        change(case)
        built[name] = case

    mutated("deny-mount-registry",
            lambda case: container(case, "mount-workspace").update(
                image="registry.evil.invalid/codewire/daemon" + PLACEHOLDER_DIGEST))
    mutated("deny-mount-renamed",
            lambda case: container(case, "mount-workspace").update(name="mount-other"))
    mutated("deny-mount-script",
            lambda case: container(case, "mount-workspace")["command"].__setitem__(-1, "true"))
    mutated("deny-runc", lambda case: case["spec"].update(runtimeClassName="runc"))
    mutated("deny-dind-digest",
            lambda case: container(case, "dind").update(
                image="docker.io/library/docker:29.9.2-dind" + PLACEHOLDER_DIGEST))
    mutated("deny-privileged-workspace",
            lambda case: container(case, "workspace").setdefault("securityContext", {}).update(
                privileged=True))
    return built


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print(__doc__.split("\n\n")[1], file=sys.stderr)
        return 2
    goldens, policy, out = (pathlib.Path(value) for value in (argv[0], argv[1], argv[3]))
    try:
        built = cases(goldens, policy.read_text(encoding="utf-8"), argv[2])
    except Refused as error:
        print(f"[kyverno-pods-from-goldens] ERROR: {error}", file=sys.stderr)
        return 1
    out.mkdir()
    for name, case in built.items():
        (out / f"{name}.json").write_text(json.dumps(case, indent=1) + "\n", encoding="utf-8")
    print(" ".join(sorted(built)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
