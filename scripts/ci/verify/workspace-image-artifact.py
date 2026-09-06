#!/usr/bin/env python3
"""Local, non-publishing workspace-image identity; never accept a caller image override."""

import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile


INPUTS = (
    "images/base/Dockerfile", "images/workspace/Dockerfile", ".dockerignore",
    "scripts/ci/verify/workspace-agent-contract.sh",
    "scripts/ci/verify/verify-workspace-image.sh",
    "scripts/ci/verify/workspace-image-artifact.py",
)


def command(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout.strip()


def source_identity(root):
    if command("git", "-C", str(root), "status", "--porcelain", "--untracked-files=normal"):
        raise ValueError("workspace image requires a clean committed source tree")
    source = command("git", "-C", str(root), "rev-parse", "HEAD")
    tree = command("git", "-C", str(root), "rev-parse", "HEAD^{tree}")
    if not all(re.fullmatch(r"[0-9a-f]{40}", value) for value in (source, tree)):
        raise ValueError("invalid source identity")
    architecture = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine())
    if platform.system() != "Linux" or architecture is None:
        raise ValueError("workspace verification requires a supported native Linux host")
    return {
        "schema_version": 1, "source_sha": source, "source_tree": tree,
        "inputs": {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in INPUTS},
        "os": "linux", "architecture": architecture,
    }


def inspect(image):
    raw = command(os.environ.get("CODEWIRE_DOCKER_BIN", "docker"), "image", "inspect", image)
    if len(raw) > 512 * 1024:
        raise ValueError("image inspection exceeds its bound")
    values = json.loads(raw)
    if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], dict):
        raise ValueError("expected one image")
    return values[0]


def digest(value):
    if not isinstance(value, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
        raise ValueError("invalid image digest")
    return value


def alias_for(image_id):
    return "localhost/codewire-ci/workspace:source-" + digest(image_id)[7:]


def validate_image(identity, image_id):
    image = inspect(digest(image_id))
    config = image.get("Config", {})
    if not isinstance(config, dict):
        raise ValueError("invalid image configuration")
    labels = config.get("Labels", {}) or {}
    if not isinstance(labels, dict):
        raise ValueError("invalid image labels")
    expected_labels = {
        "org.opencontainers.image.revision": identity["source_sha"],
        "dev.codewire.source-tree": identity["source_tree"],
        "dev.codewire.workspace-contract": identity["inputs"][INPUTS[3]],
        "dev.codewire.promotable": "false",
        "dev.codewire.build.profile": "workspace-verify",
    }
    if image.get("Id") != image_id or any(labels.get(key) != value for key, value in expected_labels.items()):
        raise ValueError("image source identity mismatch")
    if image.get("Os") != identity["os"] or image.get("Architecture") != identity["architecture"]:
        raise ValueError("image architecture mismatch")


def reuse(root, receipt):
    current = source_identity(root)
    if receipt.is_symlink() or not receipt.is_file():
        raise ValueError("invalid receipt file")
    with receipt.open("rb") as source:
        raw = source.read(64 * 1024 + 1)
    if len(raw) > 64 * 1024:
        raise ValueError("receipt exceeds its bound")
    value = json.loads(raw)
    if set(value) != set(current) | {"base_manifest_digest", "workspace_image_id", "workspace_alias"}:
        raise ValueError("invalid receipt fields")
    if not isinstance(value["source_sha"], str) or not re.fullmatch(r"[0-9a-f]{40}", value["source_sha"]):
        raise ValueError("invalid receipt source")
    # Identical committed content can retain proof across a merge commit.
    original_tree = command("git", "-C", str(root), "rev-parse", value["source_sha"] + "^{tree}")
    for key in current:
        if key != "source_sha" and value[key] != current[key]:
            raise ValueError("receipt source/input mismatch")
    if original_tree != current["source_tree"]:
        raise ValueError("receipt source commit mismatch")
    digest(value["base_manifest_digest"])
    image_id = digest(value["workspace_image_id"])
    alias = alias_for(image_id)
    if value["workspace_alias"] != alias:
        raise ValueError("receipt alias mismatch")
    validate_image(value, image_id)
    if inspect(alias).get("Id") != image_id:
        raise ValueError("image alias no longer resolves to verified bytes")
    return alias


def seal(root, receipt, image_id, base_digest):
    value = source_identity(root)
    validate_image(value, image_id)
    alias = alias_for(image_id)
    command(os.environ.get("CODEWIRE_DOCKER_BIN", "docker"), "image", "tag", image_id, alias)
    if inspect(alias).get("Id") != image_id:
        raise ValueError("image alias mismatch")
    value.update(base_manifest_digest=digest(base_digest), workspace_image_id=image_id, workspace_alias=alias)
    if receipt.is_symlink() or receipt.parent.is_symlink() or not receipt.parent.is_dir():
        raise ValueError("invalid receipt destination")
    descriptor, temporary = tempfile.mkstemp(prefix=".workspace-image-", dir=receipt.parent)
    try:
        with os.fdopen(descriptor, "w") as output:
            json.dump(value, output, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, receipt)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return alias


def main(argv):
    if len(argv) < 2:
        raise ValueError("arguments")
    mode, root_arg, *args = argv
    root = Path(root_arg).resolve(strict=True)
    if mode == "identity" and not args:
        print(json.dumps(source_identity(root), sort_keys=True))
    elif mode == "reuse" and len(args) == 1:
        print(reuse(root, Path(args[0])))
    elif mode == "seal" and len(args) == 3:
        print(seal(root, Path(args[0]), args[1], args[2]))
    else:
        raise ValueError("arguments")


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (ValueError, OSError, KeyError, TypeError, subprocess.CalledProcessError):
        print("workspace image artifact: no matching verified image", file=sys.stderr)
        sys.exit(1)
