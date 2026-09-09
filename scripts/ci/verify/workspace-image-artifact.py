#!/usr/bin/env python3
"""Local, non-publishing workspace-image identity; never accept a caller image override."""

import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import sys
import tarfile
import tempfile


INPUTS = (
    "images/base/Dockerfile", "images/workspace/Dockerfile", ".dockerignore",
    "scripts/ci/verify/workspace-agent-contract.sh",
    "scripts/ci/verify/verify-workspace-image.sh",
    "scripts/ci/verify/workspace-image-artifact.py",
    "scripts/ci/images/workspace-cache.sh",
    "scripts/ci/images/run-rust-build.sh",
    "scripts/ci/setup/select-untrusted-workspace-cache.sh",
)
MAXIMUM_ARCHIVE_BYTES = 80 * 1024 * 1024 * 1024
MAXIMUM_DOCUMENT_BYTES = 4 * 1024 * 1024
MANIFEST_TYPES = {
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
}
INDEX_TYPES = {
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
}


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
        "schema_version": 2, "source_sha": source, "source_tree": tree,
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


def archive_identity(path, image_id, architecture):
    """Bind the exported runtime image to the Docker image that passed contracts.

    No extraction or network access occurs here. The native importer additionally
    verifies every layer and all production OCI descriptor constraints.
    """
    if path != path.resolve(strict=True):
        raise ValueError("noncanonical OCI archive")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        info = os.fstat(source.fileno())
        if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o400
                or info.st_uid != os.getuid() or info.st_nlink != 1
                or not 0 < info.st_size <= MAXIMUM_ARCHIVE_BYTES):
            raise ValueError("invalid OCI archive file")
        archive_sha = hashlib.file_digest(source, "sha256").hexdigest()
        source.seek(0)
        with tarfile.open(fileobj=source, mode="r:") as archive:
            members = {}
            for member in archive:
                if len(members) >= 65536 or member.name in members:
                    raise ValueError("duplicate or excessive OCI archive entries")
                if member.isdir():
                    if member.name not in {"blobs", "blobs/sha256"}:
                        raise ValueError("invalid OCI archive directory")
                elif (not member.isfile() or member.size < 0
                      or member.name not in {"oci-layout", "index.json"}
                      and not re.fullmatch(r"blobs/sha256/[0-9a-f]{64}", member.name)):
                    raise ValueError("invalid OCI archive entry")
                members[member.name] = member

            def document(name, expected_digest=None, expected_size=None):
                member = members.get(name)
                if (member is None or not member.isfile()
                        or not 0 < member.size <= MAXIMUM_DOCUMENT_BYTES
                        or expected_size is not None and member.size != expected_size):
                    raise ValueError("invalid OCI document")
                with archive.extractfile(member) as contents:
                    raw = contents.read(MAXIMUM_DOCUMENT_BYTES + 1)
                if len(raw) != member.size or (expected_digest is not None
                        and "sha256:" + hashlib.sha256(raw).hexdigest() != expected_digest):
                    raise ValueError("OCI document digest mismatch")
                value = json.loads(raw)
                if not isinstance(value, dict):
                    raise ValueError("invalid OCI document object")
                return value

            def descriptor_document(value):
                if not isinstance(value, dict) or any(key in value for key in ("urls", "data", "artifactType")):
                    raise ValueError("invalid OCI descriptor")
                target = digest(value["digest"])
                size = value["size"]
                if type(size) is not int or size <= 0:
                    raise ValueError("invalid OCI descriptor size")
                return document("blobs/sha256/" + target[7:], target, size)

            if document("oci-layout") != {"imageLayoutVersion": "1.0.0"}:
                raise ValueError("invalid OCI layout version")
            index = document("index.json")
            if index.get("schemaVersion") != 2 or len(index.get("manifests", [])) != 1:
                raise ValueError("expected one OCI runtime image")
            selected = index["manifests"][0]
            source_digest = digest(selected["digest"])
            image = descriptor_document(selected)
            if selected.get("mediaType") in INDEX_TYPES:
                candidates = [entry for entry in image.get("manifests", [])
                              if entry.get("platform", {}).get("os") == "linux"
                              and entry.get("platform", {}).get("architecture") == architecture
                              and entry.get("platform", {}).get("variant") in
                              ((None, "v8") if architecture == "arm64" else (None,))]
                if image.get("schemaVersion") != 2 or len(candidates) != 1:
                    raise ValueError("expected one native OCI manifest")
                selected = candidates[0]
                image = descriptor_document(selected)
            if selected.get("mediaType") not in MANIFEST_TYPES or image.get("schemaVersion") != 2:
                raise ValueError("invalid OCI image manifest")
            config = image.get("config", {})
            # Docker's content store can identify an image by its manifest
            # (the containerd store) or its config. Both must be exact verified
            # objects in this one archive, never a tag or caller substitution.
            if image_id not in {source_digest, selected["digest"], config.get("digest")}:
                raise ValueError("OCI archive differs from verified Docker image")
            configuration = descriptor_document(config)
            if configuration.get("os") != "linux" or configuration.get("architecture") != architecture:
                raise ValueError("OCI archive architecture mismatch")
        after = os.fstat(source.fileno())
        if (info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (
                after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError("OCI archive changed during validation")
    return {"file": "workspace-image-" + archive_sha + ".oci.tar",
            "sha256": archive_sha, "size": info.st_size, "source_digest": source_digest}


def cache_modes():
    values = {"compiler": os.environ.get("CODEWIRE_SCCACHE_MODE", "local"),
              "layers": os.environ.get("CODEWIRE_BUILDKIT_CACHE_MODE", "local")}
    if any(mode not in ("disabled", "local", "r2") for mode in values.values()):
        raise ValueError("invalid workspace cache mode")
    return values


def reuse(root, receipt, *, native=False, for_build=False):
    current = source_identity(root)
    if receipt.is_symlink() or not receipt.is_file():
        raise ValueError("invalid receipt file")
    with receipt.open("rb") as source:
        raw = source.read(64 * 1024 + 1)
    if len(raw) > 64 * 1024:
        raise ValueError("receipt exceeds its bound")
    value = json.loads(raw)
    if set(value) != set(current) | {
            "base_manifest_digest", "workspace_image_id", "workspace_alias",
            "workspace_oci", "cache_modes", "layer_cache_fallback"}:
        raise ValueError("invalid receipt fields")
    modes = value["cache_modes"]
    if not isinstance(modes, dict) or set(modes) != {"compiler", "layers"} \
            or any(mode not in ("disabled", "local", "r2") for mode in modes.values()) \
            or type(value["layer_cache_fallback"]) is not bool \
            or (value["layer_cache_fallback"] and modes["layers"] != "r2"):
        raise ValueError("invalid receipt cache modes")
    if for_build and modes != cache_modes():
        raise ValueError("receipt cache mode mismatch")
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
    oci = value["workspace_oci"]
    if (not isinstance(oci, dict) or set(oci) != {"file", "sha256", "size", "source_digest"}
            or not isinstance(oci["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", oci["sha256"])
            or oci["file"] != "workspace-image-" + oci["sha256"] + ".oci.tar"):
        raise ValueError("invalid OCI receipt fields")
    archive_path = receipt.parent / oci["file"]
    if archive_identity(archive_path, image_id, value["architecture"]) != oci:
        raise ValueError("OCI receipt identity mismatch")
    if native:
        return {**oci, "path": str(archive_path)}
    return alias


def previous_archive(receipt, destination):
    """Select only the prior receipt's verified, distinct artifact for cleanup."""
    try:
        descriptor = os.open(receipt, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as source:
            info = os.fstat(source.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_nlink != 1 or info.st_size > 64 * 1024):
                return None
            value = json.loads(source.read(64 * 1024 + 1))
        oci = value["workspace_oci"]
        name = oci["file"]
        if not isinstance(name, str) or not re.fullmatch(r"workspace-image-[0-9a-f]{64}\.oci\.tar", name):
            return None
        # The stale acceptance marker may have been atomically moved aside
        # before a fresh attempt. Artifacts always live beside the canonical
        # destination, not beside that private temporary receipt.
        path = destination.parent / name
        if path == destination:
            return None
        before = path.lstat()
        if archive_identity(path, digest(value["workspace_image_id"]), value["architecture"]) != oci:
            return None
        return path, before
    except (OSError, ValueError, KeyError, TypeError, AttributeError, tarfile.TarError):
        # An untrusted or incomplete old receipt is never deletion authority.
        return None


def seal(root, receipt, image_id, base_digest, archive_path, previous_receipt=None):
    value = source_identity(root)
    modes = cache_modes()
    fallback = os.environ.get("CODEWIRE_BUILDKIT_CACHE_FALLBACK", "false")
    if fallback not in ("true", "false"):
        raise ValueError("invalid layer cache fallback")
    if fallback == "true" and modes["layers"] != "r2":
        raise ValueError("local layer cache cannot report remote fallback")
    validate_image(value, image_id)
    alias = alias_for(image_id)
    command(os.environ.get("CODEWIRE_DOCKER_BIN", "docker"), "image", "tag", image_id, alias)
    if inspect(alias).get("Id") != image_id:
        raise ValueError("image alias mismatch")
    value.update(base_manifest_digest=digest(base_digest), workspace_image_id=image_id, workspace_alias=alias)
    value.update(cache_modes=modes, layer_cache_fallback=fallback == "true")
    if receipt.is_symlink() or receipt.parent.is_symlink() or not receipt.parent.is_dir():
        raise ValueError("invalid receipt destination")
    oci = archive_identity(archive_path, image_id, value["architecture"])
    destination = receipt.parent / oci["file"]
    previous = previous_archive(previous_receipt or receipt, destination)
    created_archive = False
    published_receipt = False
    temporary = None
    try:
        if archive_path != destination:
            try:
                # Export and receipt are staged on the same filesystem.
                # Never replace an existing immutable image artifact.
                os.link(archive_path, destination, follow_symlinks=False)
            except FileExistsError:
                if archive_identity(destination, image_id, value["architecture"]) != oci:
                    raise ValueError("existing OCI artifact differs")
            else:
                created_archive = True
                os.unlink(archive_path)
        value["workspace_oci"] = oci
        descriptor, temporary = tempfile.mkstemp(prefix=".workspace-image-", dir=receipt.parent)
        with os.fdopen(descriptor, "w") as output:
            json.dump(value, output, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, receipt)
        published_receipt = True
        directory = os.open(receipt.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        if previous is not None:
            old_path, before = previous
            try:
                after = old_path.lstat()
                if (before.st_dev, before.st_ino, before.st_ctime_ns) == (
                        after.st_dev, after.st_ino, after.st_ctime_ns):
                    old_path.unlink()
            except OSError:
                # Qualification is already published; retention failure is not
                # a failed image contract or permission to delete another file.
                print("workspace image artifact: prior archive cleanup deferred", file=sys.stderr)
    finally:
        if temporary is not None and os.path.exists(temporary):
            os.unlink(temporary)
        if created_archive and not published_receipt:
            os.unlink(destination)
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
    elif mode == "native-input" and len(args) == 1:
        print(json.dumps(reuse(root, Path(args[0]), native=True), sort_keys=True))
    elif mode == "reuse-for-build" and len(args) == 1:
        print(reuse(root, Path(args[0]), for_build=True))
    elif mode == "seal" and len(args) in (4, 5):
        prior = Path(args[4]) if len(args) == 5 else None
        print(seal(root, Path(args[0]), args[1], args[2], Path(args[3]), prior))
    else:
        raise ValueError("arguments")


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (ValueError, OSError, KeyError, TypeError, AttributeError, tarfile.TarError,
            subprocess.CalledProcessError):
        print("workspace image artifact: no matching verified image", file=sys.stderr)
        sys.exit(1)
