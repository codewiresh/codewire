#!/usr/bin/env python3
"""Seal or reuse an admitted local Kind base without inventing CI receipts."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import resource
import selectors
import stat
import subprocess
import sys
import tarfile
import tempfile
import time


FILE_BOUND = 16 * 1024**3
TOTAL_BOUND = 64 * 1024**3
FILE_COUNT_BOUND = 128
JSON_BOUND = 64 * 1024
INPUT_BOUND = 4 * 1024**2
LOG_BOUND = 64 * 1024**2
ARCHIVE_MEMBER_BOUND = 4096
ARCHIVE_METADATA_BOUND = 16 * 1024
PROVENANCE = "provenance.json"
SOURCE_INPUTS = (
    "scripts/ci/verify/verify-workspace-image.sh",
    "scripts/ci/images/build-kind-images.sh",
    "scripts/ci/images/build-kind-smokes.sh",
    "scripts/ci/verify/kind-build-artifacts.py",
    "scripts/ci/verify/kind/profile-artifacts.py",
    "scripts/dev/kind/cluster-profile.py",
    "scripts/ci/verify/run-host-rust-build.sh",
    "scripts/ci/images/run-rust-build.sh",
    "scripts/ci/verify/resolve-cargo-target-dir.sh",
    "rust-toolchain.toml", "Cargo.toml", "Cargo.lock", "docker-bake.hcl",
    "deployments/docker/rust-base.Dockerfile",
)


class SealError(RuntimeError):
    """The selected immutable base cannot be safely admitted or reused."""


class NoAdmission(SealError):
    """The validated profile has no artifacts yet; a producer may run."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SealError(message)


def run(*argv: str, cwd: Path | None = None, timeout: int = 30,
        file_limit: int | None = None) -> str:
    """Bound metadata output and the lifetime of the exact child we launch."""
    def limit_file_size():
        resource.setrlimit(resource.RLIMIT_FSIZE, (file_limit, file_limit))

    child = subprocess.Popen(argv, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             preexec_fn=limit_file_size if file_limit is not None else None)
    output = bytearray()
    size = 0
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ, True)
            selector.register(child.stderr, selectors.EVENT_READ, False)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                require(remaining > 0, "artifact metadata command exceeded its deadline")
                for key, _ in selector.select(min(remaining, 1)):
                    chunk = os.read(key.fileobj.fileno(), 8192)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    size += len(chunk)
                    require(size <= JSON_BOUND, "artifact metadata output exceeds its bound")
                    if key.data:
                        output.extend(chunk)
            require(child.wait(timeout=max(0.01, deadline - time.monotonic())) == 0,
                    "artifact metadata command failed")
        return bytes(output).decode().strip()
    finally:
        if child.poll() is None:
            child.kill()
            child.wait()
        child.stdout.close()
        child.stderr.close()


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    require(spec is not None and spec.loader is not None, "missing artifact admission module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module  # Dataclasses resolve their declaring module here.
    previous = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    return module


def load_core(root: Path):
    return load_module("codewire_kind_profile_admission", root / "scripts/dev/kind/cluster-profile.py")


def load_inventory(root: Path):
    return load_module("codewire_kind_build_inventory", root / "scripts/ci/verify/kind-build-artifacts.py")


def relative_path(value: str) -> str:
    path = PurePosixPath(value)
    require(isinstance(value, str) and 0 < len(value) <= 180 and not path.is_absolute()
            and value == path.as_posix() and all(part not in ("", ".", "..") for part in path.parts)
            and re.fullmatch(r"[A-Za-z0-9_./-]+", value) is not None,
            "unsafe artifact member path")
    return value


def parent_fd(path: Path, *, create: bool = False, private: bool = False) -> int:
    require(path.is_absolute() and ".." not in path.parts, "artifact path must be absolute")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parent.parts[1:]:
            try:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                dir_fd=descriptor)
            except FileNotFoundError:
                require(create, "artifact parent does not exist")
                info = os.fstat(descriptor)
                require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
                        "artifact directory creation escaped private staging")
                os.mkdir(part, 0o700, dir_fd=descriptor)
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        if private:
            info = os.fstat(descriptor)
            require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
                    "artifact destination is not owner-private")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def fingerprint(info) -> tuple:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
            info.st_uid, info.st_mode, info.st_nlink)


@contextmanager
def regular_reader(path: Path, *, bound: int = FILE_BOUND):
    parent = descriptor = -1
    try:
        parent = parent_fd(path)
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                             dir_fd=parent)
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid(),
                "artifact input is not an owned regular file")
        require(0 <= before.st_size <= bound, "artifact input exceeds its byte bound")
        yield descriptor, before
        require(fingerprint(before) == fingerprint(os.fstat(descriptor)),
                "artifact input changed while reading")
    except OSError as error:
        raise SealError("artifact input cannot be read without following links") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if parent >= 0:
            os.close(parent)


def chunks(descriptor: int, size: int):
    consumed = 0
    deadline = time.monotonic() + 120
    while chunk := os.read(descriptor, min(1024**2, size + 1 - consumed)):
        consumed += len(chunk)
        require(consumed <= size, "artifact input grew while reading")
        require(time.monotonic() < deadline, "artifact read exceeded its deadline")
        yield chunk
    require(consumed == size, "artifact input shrank while reading")


def read_bytes(path: Path, *, bound: int = JSON_BOUND) -> bytes:
    with regular_reader(path, bound=bound) as (descriptor, before):
        return b"".join(chunks(descriptor, before.st_size))


def digest(path: Path, *, bound: int = FILE_BOUND) -> str:
    value = hashlib.sha256()
    with regular_reader(path, bound=bound) as (descriptor, before):
        for chunk in chunks(descriptor, before.st_size):
            value.update(chunk)
    return value.hexdigest()


def seal_archive_mode(path: Path, budget) -> int:
    parent = parent_fd(path, private=True)
    descriptor = -1
    try:
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                             dir_fd=parent)
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1,
                "saved image archive is not an owned unlinked regular file")
        budget.reserve(info.st_size)
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
        return info.st_size
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent)


class Budget:
    def __init__(self):
        self.count = self.size = 0

    def reserve(self, size: int) -> None:
        require(0 <= size <= FILE_BOUND and self.count < FILE_COUNT_BOUND
                and self.size + size <= TOTAL_BOUND, "artifact inventory exceeds its bound")
        self.count += 1
        self.size += size


def write_bytes(destination: Path, data: bytes, mode: int, budget: Budget | None = None) -> dict:
    require(len(data) <= JSON_BOUND, "artifact metadata exceeds its byte bound")
    if budget is not None:
        budget.reserve(len(data))
    parent = parent_fd(destination, create=True, private=True)
    try:
        descriptor = os.open(destination.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                             | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fchmod(stream.fileno(), mode)
            os.fsync(stream.fileno())
    finally:
        os.close(parent)
    return {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data), "mode": mode}


def copy_file(source: Path, destination: Path, mode: int,
              budget: Budget | None = None, *, bound: int = FILE_BOUND) -> dict:
    with regular_reader(source, bound=bound) as (incoming, before):
        require(mode != 0o500 or bool(before.st_mode & 0o111), "build member is not executable")
        if budget is not None:
            budget.reserve(before.st_size)
        parent = parent_fd(destination, create=True, private=True)
        try:
            descriptor = os.open(destination.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                 | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
            value = hashlib.sha256()
            with os.fdopen(descriptor, "wb") as outgoing:
                for chunk in chunks(incoming, before.st_size):
                    outgoing.write(chunk)
                    value.update(chunk)
                outgoing.flush()
                os.fchmod(outgoing.fileno(), mode)
                os.fsync(outgoing.fileno())
        finally:
            os.close(parent)
    return {"sha256": value.hexdigest(), "bytes": before.st_size, "mode": mode}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate artifact JSON field")
        result[key] = value
    return result


def decode(data: bytes):
    return json.loads(data, object_pairs_hook=unique_object)


def encode(value) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def select_test(jsonl: Path, target: str, kinds: list[str], cargo_ci: Path) -> Path:
    matches = []
    for line in read_bytes(jsonl, bound=LOG_BOUND).splitlines():
        require(len(line) <= INPUT_BOUND, "Cargo artifact record exceeds its byte bound")
        value = decode(line)
        if not isinstance(value, dict):
            continue
        profile, selected = value.get("profile"), value.get("target")
        if (value.get("reason") == "compiler-artifact" and isinstance(profile, dict)
                and profile.get("test") is True and isinstance(selected, dict)
                and selected.get("name") == target and selected.get("kind") == kinds
                and isinstance(value.get("executable"), str)):
            matches.append(Path(value["executable"]))
    require(len(matches) == 1, "expected exactly one selected test executable")
    source = matches[0]
    require(source.is_absolute() and source.is_relative_to(cargo_ci) and source != cargo_ci
            and ".." not in source.parts, "test executable escaped the selected Cargo profile")
    with regular_reader(source):
        pass
    return source


def copy_smokes(inventory, cargo_ci: Path, run_dir: Path, stage: Path,
                destination: Path, budget: Budget, files: dict) -> None:
    for relative in inventory.SMOKE_FILES.values():
        relative_path(relative)
        name = "smokes/" + relative
        files[name] = copy_file(cargo_ci / relative, stage / name, 0o500, budget)
    for key, (jsonl, target, kinds) in inventory.TEST_FILES.items():
        name = "smokes/tests/" + relative_path(key)
        files[name] = copy_file(select_test(run_dir / jsonl, target, kinds, cargo_ci),
                                stage / name, 0o500, budget)
        value = {"reason": "compiler-artifact", "profile": {"test": True},
                 "target": {"name": target, "kind": kinds}, "executable": str(destination / name)}
        files[relative_path(jsonl)] = write_bytes(stage / jsonl, encode(value), 0o400, budget)


def preflight_archive(stream, size: int) -> None:
    """Bound raw headers before tarfile can allocate extended-header payloads."""
    offset, count = 0, 0
    names = set()
    while offset + 512 <= size:
        stream.seek(offset)
        header = stream.read(512)
        if header == b"\0" * 512:
            require(size - offset <= 1024**2, "Docker archive has excessive trailing padding")
            require(not stream.read(size - offset - 512).strip(b"\0"),
                    "Docker archive has data after its terminator")
            return
        count += 1
        require(count <= ARCHIVE_MEMBER_BOUND, "Docker archive member count exceeds its bound")
        info = tarfile.TarInfo.frombuf(header, "utf-8", "strict")
        name = info.name.rstrip("/") if info.isdir() else info.name
        relative_path(name)
        require(name not in names, "duplicate Docker archive member")
        names.add(name)
        require(info.isfile() or info.isdir() or info.type == tarfile.XHDTYPE,
                "Docker archive contains a link or special member")
        require(0 <= info.size <= FILE_BOUND and (not info.isdir() or info.size == 0),
                "Docker archive member size is invalid")
        if info.type == tarfile.XHDTYPE:
            require(info.size <= ARCHIVE_METADATA_BOUND, "Docker archive extended header exceeds its bound")
            payload = stream.read(info.size)
            while payload:
                length, separator, rest = payload.partition(b" ")
                require(separator == b" " and length.isdigit(), "invalid Docker archive extended header")
                length = int(length)
                require(0 < length <= len(payload), "invalid Docker archive extended record size")
                record = payload[len(str(length)) + 1:length]
                key, separator, _ = record.rstrip(b"\n").partition(b"=")
                require(separator == b"=" and key in (b"mtime", b"atime", b"ctime"),
                        "Docker archive extended header changes member identity")
                payload = payload[length:]
        offset += 512 + ((info.size + 511) // 512) * 512
        require(offset <= size, "truncated Docker archive member")
    raise SealError("Docker archive lacks a complete terminator")


def verify_archive(path: Path, expected: dict[str, str]) -> None:
    try:
        verify_archive_contents(path, expected)
    except (tarfile.TarError, UnicodeError, ValueError) as error:
        raise SealError("Docker archive metadata is invalid") from error


def archive_bytes(archive, members: dict, name: str, bound: int) -> bytes:
    member = members.get(name)
    require(member is not None and member.isfile() and 0 <= member.size <= bound,
            "Docker archive metadata member is absent or oversized")
    with archive.extractfile(member) as incoming:
        data = incoming.read()
    require(len(data) == member.size, "Docker archive metadata member is truncated")
    return data


def verify_oci_blob(archive, members: dict, descriptor: dict, media: set[str],
                    hashes: dict[str, str], deadline: float, *, bound: int = FILE_BOUND,
                    annotations: bool = False) -> str:
    keys = {"digest", "mediaType", "size"} | ({"annotations"} if annotations else set())
    require(isinstance(descriptor, dict) and set(descriptor) == keys
            and isinstance(descriptor["mediaType"], str) and descriptor["mediaType"] in media
            and isinstance(descriptor["digest"], str)
            and re.fullmatch(r"sha256:[0-9a-f]{64}", descriptor["digest"]) is not None
            and type(descriptor["size"]) is int and 0 <= descriptor["size"] <= bound,
            "unsupported OCI archive descriptor")
    name = "blobs/sha256/" + descriptor["digest"].removeprefix("sha256:")
    member = members.get(name)
    require(member is not None and member.isfile() and member.size == descriptor["size"],
            "OCI archive descriptor does not match its member size")
    require(time.monotonic() < deadline, "OCI archive hashing exceeded its deadline")
    if name not in hashes:
        value, consumed = hashlib.sha256(), 0
        with archive.extractfile(member) as incoming:
            while chunk := incoming.read(1024**2):
                consumed += len(chunk)
                require(consumed <= member.size and time.monotonic() < deadline,
                        "OCI archive hashing exceeded its size or deadline")
                value.update(chunk)
        require(consumed == member.size, "OCI archive blob is truncated")
        hashes[name] = "sha256:" + value.hexdigest()
    require(hashes[name] == descriptor["digest"], "OCI archive blob digest differs")
    return name


def verify_oci_index(archive, members: dict, expected: dict[str, str], compatibility: dict,
                     deadline: float) -> dict[str, str]:
    """Admit only Docker-save's observed single-platform OCI manifest chain."""
    require(decode(archive_bytes(archive, members, "oci-layout", JSON_BOUND))
            == {"imageLayoutVersion": "1.0.0"}, "unsupported OCI archive layout")
    index = decode(archive_bytes(archive, members, "index.json", 1024**2))
    require(isinstance(index, dict) and set(index) == {"schemaVersion", "mediaType", "manifests"}
            and type(index["schemaVersion"]) is int and index["schemaVersion"] == 2
            and index["mediaType"] == "application/vnd.oci.image.index.v1+json"
            and isinstance(index["manifests"], list) and len(index["manifests"]) == len(expected),
            "unsupported OCI archive index")
    found, hashes, digests = {}, {}, set()
    for descriptor in index["manifests"]:
        require(isinstance(descriptor, dict), "invalid OCI archive index descriptor")
        annotations = descriptor.get("annotations")
        require(isinstance(annotations, dict)
                and {"io.containerd.image.name", "org.opencontainers.image.ref.name"} <= set(annotations)
                and set(annotations) <= {"io.containerd.image.name", "org.opencontainers.image.ref.name",
                                         "org.opencontainers.image.created"}
                and all(isinstance(value, str) and len(value) <= 512 for value in annotations.values()),
                "unsupported OCI archive tag annotations")
        reference = annotations["io.containerd.image.name"]
        tag = reference.removeprefix("docker.io/library/")
        require(reference == "docker.io/library/" + tag and tag in expected and tag not in found
                and annotations["org.opencontainers.image.ref.name"] == tag.rsplit(":", 1)[-1]
                and descriptor.get("digest") == expected[tag] and descriptor["digest"] not in digests,
                "OCI archive tag or manifest identity differs")
        name = verify_oci_blob(archive, members, descriptor,
                               {"application/vnd.oci.image.manifest.v1+json"}, hashes, deadline,
                               bound=1024**2, annotations=True)
        manifest = decode(archive_bytes(archive, members, name, 1024**2))
        require(isinstance(manifest, dict) and set(manifest) == {"schemaVersion", "mediaType", "config", "layers"}
                and type(manifest["schemaVersion"]) is int and manifest["schemaVersion"] == 2
                and manifest["mediaType"] == "application/vnd.oci.image.manifest.v1+json"
                and isinstance(manifest["layers"], list) and len(manifest["layers"]) <= 256,
                "unsupported OCI archive image manifest")
        config = verify_oci_blob(archive, members, manifest["config"],
                                 {"application/vnd.oci.image.config.v1+json"}, hashes, deadline,
                                 bound=INPUT_BOUND)
        selected = compatibility[tag]
        require(config == selected["config"] and manifest["config"]["digest"] == selected["config_id"],
                "OCI image config differs from the Docker compatibility manifest")
        layer_names = [verify_oci_blob(archive, members, layer,
                                      {"application/vnd.oci.image.layer.v1.tar+gzip",
                                       "application/vnd.oci.image.layer.v1.tar"}, hashes, deadline)
                       for layer in manifest["layers"]]
        require(layer_names == selected["layers"] and len(set(layer_names)) == len(layer_names),
                "OCI ordered layers differ from the Docker compatibility manifest")
        found[tag] = descriptor["digest"]
        digests.add(descriptor["digest"])
    return found


def verify_archive_contents(path: Path, expected: dict[str, str]) -> None:
    deadline = time.monotonic() + 120
    with regular_reader(path) as (descriptor, before):
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            preflight_archive(stream, before.st_size)
            stream.seek(0)
            with tarfile.open(fileobj=stream, mode="r:") as archive:
                members = {}
                for member in archive:
                    require(len(members) < ARCHIVE_MEMBER_BOUND and member.name not in members,
                            "duplicate or excessive Docker archive members")
                    members[member.name] = member
                manifest = members.get("manifest.json")
                require(manifest is not None and manifest.isfile() and manifest.size <= 1024**2,
                        "Docker archive manifest is missing or oversized")
                entries = decode(archive.extractfile(manifest).read())
                require(isinstance(entries, list) and len(entries) == len(expected),
                        "Docker archive product inventory differs")
                found, compatibility = {}, {}
                for entry in entries:
                    require(isinstance(entry, dict) and isinstance(entry.get("RepoTags"), list),
                            "invalid Docker archive entry")
                    config_name = entry.get("Config")
                    config = members.get(config_name) if isinstance(config_name, str) else None
                    require(config is not None and config.isfile() and config.size <= INPUT_BOUND,
                            "Docker archive image config is invalid")
                    image_id = "sha256:" + hashlib.sha256(archive.extractfile(config).read()).hexdigest()
                    layers = entry.get("Layers")
                    require(isinstance(layers, list) and len(layers) <= 256,
                            "Docker archive layer inventory is invalid")
                    for layer in layers:
                        require(isinstance(layer, str) and layer in members and members[layer].isfile(),
                                "Docker archive layer is absent or unsafe")
                    for tag in entry["RepoTags"]:
                        require(isinstance(tag, str) and tag not in found and tag in expected,
                                "unexpected or duplicate Docker archive tag")
                        found[tag] = image_id
                        compatibility[tag] = {"config": config_name, "config_id": image_id, "layers": layers}
                require(set(found) == set(expected), "Docker archive tag inventory differs")
                if "index.json" in members:
                    found = verify_oci_index(archive, members, expected, compatibility, deadline)
                require(found == expected, "Docker archive tags do not match admitted image IDs")


def source_identity(root: Path) -> tuple[str, str]:
    values = run("git", "-C", str(root), "rev-parse", "HEAD", "HEAD^{tree}").splitlines()
    require(len(values) == 2 and all(re.fullmatch(r"[0-9a-f]{40}", value) for value in values)
            and not run("git", "-C", str(root), "status", "--porcelain", "--untracked-files=normal"),
            "Kind base requires a clean committed source tree")
    return tuple(values)


def provenance(root: Path) -> dict:
    head, tree = source_identity(root)
    mode = os.environ.get("CODEWIRE_KIND_PRODUCT_IMAGE_MODE", "build-ci")
    require(mode in ("build-ci", "prebuilt-ci"), "named Kind artifacts require CI product images")
    require(platform.system() == "Linux" and platform.machine() == "x86_64",
            "named Kind artifacts require Linux amd64")
    flags = ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTUP_TOOLCHAIN", "RUSTC",
             "RUSTC_WORKSPACE_WRAPPER", "CARGO_BUILD_TARGET", "PROTOC", "CODEWIRE_SCCACHE_MODE")
    # These are the admitting host's observed tools and inputs. Prebuilt CI
    # outputs keep their original producer proof; do not relabel these local
    # observations as the remote compiler or manufacture a workflow identity.
    return {"schema": "codewire.kind-profile-provenance/v1", "source_head": head, "source_tree": tree,
            "platform": "linux/amd64", "profile": "ci", "producer_mode": mode,
            "admission_toolchain": {
                "rustc": run(os.environ.get("RUSTC") or "rustc", "--version", "--verbose", cwd=root),
                "cargo": run("cargo", "--version", cwd=root),
                "protoc": run(os.environ.get("PROTOC") or "protoc", "--version", cwd=root)},
            "admission_compiler_inputs": {key: hashlib.sha256(os.environ.get(key, "").encode()).hexdigest()
                                          for key in flags},
            "inputs": {name: digest(root / name, bound=INPUT_BOUND) for name in SOURCE_INPUTS}}


@contextmanager
def transaction(root: Path, *, publication: bool):
    core = load_core(root)
    keys = ["KIND_PROFILE_LOCK_FD"]
    if publication:
        keys.append("KIND_BUILD_PUBLICATION_LOCK_FD")
    require(all(re.fullmatch(r"[0-9]{1,10}", os.environ.get(key, "")) for key in keys),
            "missing inherited artifact transaction descriptor")
    try:
        cluster = core.cluster_name(os.environ.get("CLUSTER", ""))
        profiles = core.Profiles(core.default_root())
        with profiles.operation(cluster, publication=publication):
            fields = profiles.env(cluster)
            require(all(os.environ.get(key) == value for key, value in fields.items()),
                    "inherited profile projection differs from the selected private profile")
            with profiles.registry():
                value = profiles.load(cluster)
                profiles.node(value, allow_unbound=True)
            descriptor = core.directory_fd(Path(fields["KIND_PROFILE_ARTIFACT_ROOT"]))
            os.close(descriptor)
            yield profiles, value, fields
    except core.ProfileError as error:
        raise SealError("selected profile, daemon, lock or artifact identity is invalid") from error


def required_inventory(inventory) -> set[str]:
    return {"images.tar", PROVENANCE, *("inputs/" + name for name in SOURCE_INPUTS),
            *("smokes/" + relative_path(name) for name in inventory.SMOKE_FILES.values()),
            *("smokes/tests/" + relative_path(key) for key in inventory.TEST_FILES),
            *(relative_path(value[0]) for value in inventory.TEST_FILES.values())}


def admitted_reuse(root: Path, profiles, value: dict, binding: dict, inventory) -> Path:
    if value["artifacts"] is None:
        artifact_root = profiles.path(value["cluster_name"]) / "artifacts"
        descriptor = parent_fd(artifact_root / "entry", private=True)
        try:
            with os.scandir(descriptor) as entries:
                require(next(entries, None) is None,
                        f"unadmitted artifact state requires reconciliation; retained: {artifact_root}")
        finally:
            os.close(descriptor)
        raise NoAdmission("selected profile has no admitted artifacts")
    require(value["artifacts"]["source_head"] == binding["source_head"]
            and value["artifacts"]["source_tree"] == binding["source_tree"],
            "saved Kind base uses another source; use a fresh profile")
    manifest, _ = profiles.artifact_manifest(value)
    require(set(manifest["files"]) == required_inventory(inventory), "saved artifact inventory differs")
    destination = profiles.manifest_path(value).parent
    require(decode(read_bytes(destination / PROVENANCE)) == binding,
            "saved producer inputs or toolchain differ; use a fresh profile")
    for name, checksum in binding["inputs"].items():
        require(manifest["files"]["inputs/" + name]["sha256"] == checksum,
                "saved source input differs from provenance")
    profiles.verify_artifacts(value["cluster_name"])
    require(provenance(root) == binding, "source or producer inputs changed during artifact reuse")
    return destination


def reuse(root: Path, cargo_ci: Path, run_dir: Path) -> Path:
    with transaction(root, publication=False) as (profiles, value, fields):
        require(run_dir == Path(fields["RUN_DIR"]), "artifact run directory differs from its profile")
        return admitted_reuse(root, profiles, value, provenance(root), load_inventory(root))


def inspect_products(inventory, head: str) -> dict[str, str]:
    result = {}
    template = ('{"id":{{json .Id}},"os":{{json .Os}},"arch":{{json .Architecture}},'
                '"profile":{{json (index .Config.Labels "dev.codewire.build.profile")}},'
                '"promotable":{{json (index .Config.Labels "dev.codewire.promotable")}},'
                '"source":{{json (index .Config.Labels "org.opencontainers.image.revision")}}}')
    for reference in inventory.PRODUCT_IMAGES:
        value = decode(run("docker", "image", "inspect", "--format", template, reference))
        require(isinstance(value, dict) and re.fullmatch(r"sha256:[0-9a-f]{64}", value.get("id", ""))
                and value.get("os") == "linux" and value.get("arch") == "amd64"
                and value.get("profile") == "ci" and value.get("promotable") == "false"
                and value.get("source") == head, "product image identity or CI profile differs")
        result[reference] = value["id"]
    return result


def publish(stage: Path, destination: Path) -> None:
    """Publish atomically without replacing even an unexpected empty directory."""
    parent = parent_fd(destination, private=True)
    source_parent = parent_fd(stage, private=True)
    published = False
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        rename = getattr(libc, "renameat2", None)
        require(rename is not None, "atomic artifact publication requires Linux renameat2")
        rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
        rename.restype = ctypes.c_int
        if rename(source_parent, os.fsencode(stage.name), parent, os.fsencode(destination.name), 1) != 0:
            raise SealError(f"artifact publication refused without overwrite: {destination}")
        published = True
        os.fsync(parent)
    except OSError as error:
        if published:
            raise SealError(f"artifact publication durability requires reconciliation; retained: {destination}") from error
        raise
    finally:
        os.close(source_parent)
        os.close(parent)


def seal(root: Path, cargo_ci: Path, run_dir: Path) -> Path:
    with transaction(root, publication=True) as (profiles, value, fields):
        require(run_dir == Path(fields["RUN_DIR"]), "artifact run directory differs from its profile")
        expected_cargo = Path(os.environ.get("CARGO_TARGET_DIR", str(root / "target"))) / "ci"
        require(cargo_ci == expected_cargo, "artifact Cargo directory differs from the selected producer")
        binding, inventory = provenance(root), load_inventory(root)
        if value["artifacts"] is not None:
            return admitted_reuse(root, profiles, value, binding, inventory)
        profile = Path(fields["KIND_PROFILE_ARTIFACT_ROOT"])
        destination = profile / f"{binding['source_head']}-{binding['source_tree']}"
        require(not destination.exists() and not destination.is_symlink(),
                f"unadmitted artifact directory retained without overwrite: {destination}")
        expected = inspect_products(inventory, binding["source_head"])
        budget, files = Budget(), {}
        with tempfile.TemporaryDirectory(prefix=".sealing-", dir=profile) as temporary:
            stage = Path(temporary)
            archive = stage / "images.tar"
            run("docker", "image", "save", "--output", str(archive), *inventory.PRODUCT_IMAGES,
                timeout=900, file_limit=FILE_BOUND)
            archive_size = seal_archive_mode(archive, budget)
            verify_archive(archive, expected)
            require(inspect_products(inventory, binding["source_head"]) == expected,
                    "product tags changed during archive publication")
            files["images.tar"] = {"sha256": digest(archive), "bytes": archive_size, "mode": 0o400}
            copy_smokes(inventory, cargo_ci, run_dir, stage, destination, budget, files)
            for name, checksum in binding["inputs"].items():
                copied = copy_file(root / name, stage / "inputs" / name, 0o400, budget, bound=INPUT_BOUND)
                require(copied["sha256"] == checksum, "source input changed during artifact copying")
                files["inputs/" + name] = copied
            files[PROVENANCE] = write_bytes(stage / PROVENANCE, encode(binding), 0o400, budget)
            require(set(files) == required_inventory(inventory), "artifact inventory differs from its producer")
            descriptor = {"schema": "codewire.kind-profile-artifacts/v1",
                          "cluster_name": value["cluster_name"], "docker_id": value["docker_id"],
                          "ownership_nonce": value["ownership_nonce"],
                          "source_head": binding["source_head"], "source_tree": binding["source_tree"],
                          "product_images": {key.removeprefix("codewire-").removesuffix(":e2e"): image
                                             for key, image in expected.items()}, "files": files}
            write_bytes(stage / "manifest.json", encode(descriptor), 0o400)
            require(provenance(root) == binding, "source or producer inputs changed before publication")
            for directory in (*sorted((path for path in stage.rglob("*") if path.is_dir()),
                                      key=lambda path: len(path.parts), reverse=True), stage):
                directory_descriptor = parent_fd(directory / "entry", private=True)
                try:
                    os.fsync(directory_descriptor)
                finally:
                    os.close(directory_descriptor)
            publish(stage, destination)
        # Publication is irreversible until the actual registry outcome is known.
        # Admission can fsync successfully and still raise; never erase this path.
        try:
            require(provenance(root) == binding, "source or producer inputs changed before admission")
            profiles.record_artifacts(value["cluster_name"], value["ownership_nonce"], destination / "manifest.json")
        except Exception as error:
            raise SealError(f"artifact admission outcome requires reconciliation; retained: {destination}") from error
        return destination


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["seal", "reuse"])
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--cargo-ci-dir", type=Path, required=True)
    parser.add_argument("--run-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        function = seal if args.command == "seal" else reuse
        function(args.root.absolute(), args.cargo_ci_dir.absolute(), args.run_dir.absolute())
    except NoAdmission as error:
        parser.exit(3, f"kind artifact reuse unavailable: {error}\n")
    except (SealError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        parser.exit(1, f"kind artifact sealing failed: {error}\n")


if __name__ == "__main__":
    main()
