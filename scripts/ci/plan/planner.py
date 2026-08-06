#!/usr/bin/env python3
"""Trusted, no-network artifact impact planner for Codewire CI.

The planner resolves Rust package closures plus migrated file-set and composite
artifacts. Nodes without a trusted resolver remain unclassified and fail closed.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import posixpath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from collections import deque
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

try:
    import tomllib
except ModuleNotFoundError as exc:  # pragma: no cover - Codewire uses Python 3.11+
    raise SystemExit("Python 3.11 or newer is required") from exc


BASELINE_SCHEMA = "codewire.ci-baseline/v1"
PLAN_SCHEMA = "codewire.ci-plan/v1"
SUPPORT_CANDIDATE_SCHEMA = "codewire.ci-published-support-candidate/v1"
DEPLOYED_SOURCE_CANDIDATE_SCHEMA = "codewire.ci-deployed-source-candidate/v1"
MAX_ARCHIVE_MEMBERS = 30_000
MAX_ARCHIVE_FILE_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_TOTAL_BYTES = 512 * 1024 * 1024
MAX_BASELINE_CANDIDATE_BYTES = 1024 * 1024
MAX_CARGO_PACKAGES = 512
METADATA_TIMEOUT_SECONDS = 90
HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
LOCK_REF_RE = re.compile(r"^(?P<name>\S+?)(?:\s+(?P<version>\S+))?(?:\s+\((?P<source>.+)\))?$")
SUPPORT_REPOSITORIES = {
    "base": "ghcr.io/codewiresh/base",
    "workspace": "ghcr.io/codewiresh/workspace",
}


class PlannerError(RuntimeError):
    """A classification input could not be trusted."""


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _run(
    argv: list[str],
    *,
    cwd: Path,
    env: dict[str, str] | None = None,
    timeout: int = METADATA_TIMEOUT_SECONDS,
) -> bytes:
    try:
        completed = subprocess.run(
            argv,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PlannerError(f"command could not run: {argv[0]}: {exc}") from exc
    if completed.returncode != 0:
        message = completed.stderr.decode("utf-8", "replace").strip()
        raise PlannerError(f"command failed: {' '.join(argv)}: {message[:2000]}")
    return completed.stdout


def git(repository: Path, *args: str) -> str:
    return _run(["git", *args], cwd=repository).decode("utf-8", "strict").strip()


def resolve_commit(repository: Path, revision: str) -> str:
    commit = git(repository, "rev-parse", "--verify", f"{revision}^{{commit}}")
    if not HEX40_RE.fullmatch(commit):
        raise PlannerError(f"Git returned an invalid commit for {revision!r}")
    return commit


def _safe_member_path(name: str) -> str:
    if not name or "\x00" in name or name.startswith("/"):
        raise PlannerError(f"unsafe archive path: {name!r}")
    if "\\" in name:
        raise PlannerError(f"archive path uses a backslash: {name!r}")
    normalized = posixpath.normpath(name)
    if normalized in ("", ".") or normalized == ".." or normalized.startswith("../"):
        raise PlannerError(f"archive path escapes the tree: {name!r}")
    if normalized != name.rstrip("/"):
        raise PlannerError(f"archive path is not normalized: {name!r}")
    return normalized


def _safe_symlink_target(member_name: str, target: str) -> None:
    if not target or "\x00" in target or target.startswith("/") or "\\" in target:
        raise PlannerError(f"unsafe symlink target at {member_name!r}: {target!r}")
    resolved = posixpath.normpath(posixpath.join(posixpath.dirname(member_name), target))
    if resolved == ".." or resolved.startswith("../"):
        raise PlannerError(f"symlink escapes the tree at {member_name!r}: {target!r}")


def safe_extract_tar(stream: Any, destination: Path) -> None:
    """Extract a streamed Git archive without trusting archive paths or types."""

    destination.mkdir(parents=True, exist_ok=True)
    seen: set[str] = set()
    member_count = 0
    total_bytes = 0
    with tarfile.open(fileobj=stream, mode="r|*") as archive:
        for member in archive:
            member_count += 1
            if member_count > MAX_ARCHIVE_MEMBERS:
                raise PlannerError("archive contains too many members")
            name = _safe_member_path(member.name)
            if name in seen:
                raise PlannerError(f"archive contains duplicate path: {name}")
            seen.add(name)
            target = destination.joinpath(*PurePosixPath(name).parts)
            target.parent.mkdir(parents=True, exist_ok=True)

            if member.isdir():
                target.mkdir(exist_ok=True)
                continue
            if member.issym():
                _safe_symlink_target(name, member.linkname)
                os.symlink(member.linkname, target)
                continue
            if member.islnk() or member.isdev() or member.isfifo():
                raise PlannerError(f"unsupported archive member type: {name}")
            if not member.isfile():
                raise PlannerError(f"unknown archive member type: {name}")
            if member.size < 0 or member.size > MAX_ARCHIVE_FILE_BYTES:
                raise PlannerError(f"archive file exceeds size limit: {name}")
            total_bytes += member.size
            if total_bytes > MAX_ARCHIVE_TOTAL_BYTES:
                raise PlannerError("archive exceeds total size limit")
            source = archive.extractfile(member)
            if source is None:
                raise PlannerError(f"archive file has no content: {name}")
            with target.open("xb") as output:
                remaining = member.size
                while remaining:
                    chunk = source.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise PlannerError(f"archive file ended early: {name}")
                    output.write(chunk)
                    remaining -= len(chunk)
            target.chmod(member.mode & 0o777)


def export_git_tree(repository: Path, commit: str, destination: Path) -> None:
    try:
        process = subprocess.Popen(
            ["git", "archive", "--format=tar", commit],
            cwd=repository,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as exc:
        raise PlannerError(f"git archive could not start: {exc}") from exc
    assert process.stdout is not None
    try:
        safe_extract_tar(process.stdout, destination)
    except BaseException:
        process.kill()
        process.wait()
        raise
    finally:
        process.stdout.close()
    stderr = process.stderr.read() if process.stderr is not None else b""
    if process.stderr is not None:
        process.stderr.close()
    returncode = process.wait()
    if returncode != 0:
        raise PlannerError(f"git archive failed: {stderr.decode('utf-8', 'replace')[:2000]}")
    validate_exported_tree(destination)


def validate_exported_tree(root: Path) -> None:
    root_resolved = root.resolve()
    count = 0
    total = 0
    for directory, dirs, files in os.walk(root, followlinks=False):
        dirs.sort()
        files.sort()
        for name in [*dirs, *files]:
            count += 1
            if count > MAX_ARCHIVE_MEMBERS:
                raise PlannerError("exported tree contains too many paths")
            path = Path(directory, name)
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                _safe_symlink_target(relative, os.readlink(path))
                resolved = path.resolve(strict=False)
                if root_resolved != resolved and root_resolved not in resolved.parents:
                    raise PlannerError(f"symlink escapes exported tree: {relative}")
            elif path.is_file():
                size = path.stat().st_size
                if size > MAX_ARCHIVE_FILE_BYTES:
                    raise PlannerError(f"exported file exceeds size limit: {relative}")
                total += size
                if total > MAX_ARCHIVE_TOTAL_BYTES:
                    raise PlannerError("exported tree exceeds total size limit")
    cargo_configs = [
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file()
        and path.parent.name == ".cargo"
        and path.name in {"config", "config.toml", "credentials", "credentials.toml"}
    ]
    if cargo_configs:
        raise PlannerError(f"candidate tree supplies Cargo configuration: {cargo_configs[0]}")


@dataclass(frozen=True)
class IndexedPath:
    path: str
    kind: str
    mode: int
    sha256: str


class TreeIndex:
    def __init__(self, root: Path):
        self.root = root
        self.entries: dict[str, IndexedPath] = {}
        for directory, dirs, files in os.walk(root, followlinks=False):
            dirs.sort()
            files.sort()
            for name in [*dirs, *files]:
                full = Path(directory, name)
                relative = full.relative_to(root).as_posix()
                info = full.lstat()
                if stat.S_ISLNK(info.st_mode):
                    self.entries[relative] = IndexedPath(
                        relative, "symlink", info.st_mode & 0o777, sha256_bytes(os.readlink(full).encode())
                    )
                elif stat.S_ISREG(info.st_mode):
                    digest = hashlib.sha256()
                    with full.open("rb") as source:
                        for chunk in iter(lambda: source.read(1024 * 1024), b""):
                            digest.update(chunk)
                    self.entries[relative] = IndexedPath(relative, "file", info.st_mode & 0o777, digest.hexdigest())
                elif not stat.S_ISDIR(info.st_mode):
                    raise PlannerError(f"tree contains an unsupported path type: {relative}")

    def matching(self, pattern: str) -> list[IndexedPath]:
        if pattern.endswith("/**"):
            prefix = pattern[:-3].rstrip("/")
            return [entry for path, entry in self.entries.items() if path == prefix or path.startswith(prefix + "/")]
        return [entry for path, entry in self.entries.items() if fnmatch.fnmatchcase(path, pattern)]


def isolated_cargo_environment(temp_root: Path, trusted_toolchain: str | None = None) -> dict[str, str]:
    environment = {
        name: os.environ[name]
        for name in ("PATH", "RUSTUP_HOME", "LANG", "LC_ALL", "TMPDIR")
        if name in os.environ
    }
    home = temp_root / "home"
    cargo_home = temp_root / "cargo-home"
    home.mkdir()
    cargo_home.mkdir()
    environment.update(
        {
            "HOME": str(home),
            "CARGO_HOME": str(cargo_home),
            "CARGO_NET_OFFLINE": "true",
            "CARGO_TERM_COLOR": "never",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
        }
    )
    if trusted_toolchain:
        environment["RUSTUP_TOOLCHAIN"] = trusted_toolchain
    return environment


def trusted_rust_toolchain(policy_tree: Path) -> str | None:
    declaration = policy_tree / "rust-toolchain.toml"
    if declaration.is_file():
        document = tomllib.loads(declaration.read_text())
        channel = document.get("toolchain", {}).get("channel")
        if not isinstance(channel, str) or not channel:
            raise PlannerError("trusted rust-toolchain.toml has no channel")
        return channel
    environment = {
        name: os.environ[name]
        for name in ("PATH", "RUSTUP_HOME", "HOME", "LANG", "LC_ALL")
        if name in os.environ
    }
    try:
        active = _run(["rustup", "show", "active-toolchain"], cwd=policy_tree, env=environment).decode().split()
    except PlannerError:
        return os.environ.get("RUSTUP_TOOLCHAIN")
    return active[0] if active else None


def cargo_metadata(tree: Path, manifest: Path, cargo_env: dict[str, str]) -> dict[str, Any]:
    output = _run(
        [
            "cargo",
            "metadata",
            "--format-version=1",
            "--locked",
            "--offline",
            "--no-deps",
            "--manifest-path",
            str(manifest),
        ],
        cwd=tree,
        env=cargo_env,
    )
    try:
        result = json.loads(output)
    except json.JSONDecodeError as exc:
        raise PlannerError(f"cargo metadata returned invalid JSON: {exc}") from exc
    if not isinstance(result.get("packages"), list):
        raise PlannerError("cargo metadata omitted packages")
    return result


def relative_to_tree(path: str | Path, tree: Path) -> str:
    try:
        return Path(path).resolve().relative_to(tree.resolve()).as_posix()
    except ValueError as exc:
        raise PlannerError(f"Cargo path escapes exported tree: {path}") from exc


@dataclass
class CargoUniverse:
    packages: dict[str, dict[str, Any]]
    manifests: dict[str, dict[str, Any]]
    package_dirs: set[str]


def discover_cargo_universe(tree: Path, artifact_manifest: str, cargo_env: dict[str, str]) -> CargoUniverse:
    queue = deque(["Cargo.toml", artifact_manifest])
    visited: set[str] = set()
    packages: dict[str, dict[str, Any]] = {}
    manifests: dict[str, dict[str, Any]] = {}
    while queue:
        manifest_relative = posixpath.normpath(queue.popleft())
        if manifest_relative in visited:
            continue
        visited.add(manifest_relative)
        manifest = tree / manifest_relative
        if not manifest.is_file():
            raise PlannerError(f"Cargo manifest is missing: {manifest_relative}")
        metadata = cargo_metadata(tree, manifest, cargo_env)
        for package in metadata["packages"]:
            package_manifest = relative_to_tree(package["manifest_path"], tree)
            package_copy = dict(package)
            package_copy["_manifest_relative"] = package_manifest
            package_copy["_directory_relative"] = posixpath.dirname(package_manifest)
            packages[package_manifest] = package_copy
            manifests[package_manifest] = metadata
            if len(packages) > MAX_CARGO_PACKAGES:
                raise PlannerError("Cargo package graph exceeds package limit")
        for package in list(packages.values()):
            for dependency in package.get("dependencies", []):
                dependency_path = dependency.get("path")
                if not dependency_path:
                    continue
                relative_directory = relative_to_tree(dependency_path, tree)
                dependency_manifest = posixpath.join(relative_directory, "Cargo.toml")
                if dependency_manifest not in packages and dependency_manifest not in visited:
                    queue.append(dependency_manifest)
    return CargoUniverse(packages, manifests, {package["_directory_relative"] for package in packages.values()})


def dependency_kind_is_artifact(dependency: dict[str, Any]) -> bool:
    return dependency.get("kind") in (None, "normal", "build")


def resolve_local_dependency(
    dependency: dict[str, Any], universe: CargoUniverse, tree: Path
) -> dict[str, Any] | None:
    dependency_path = dependency.get("path")
    if not dependency_path:
        return None
    manifest = posixpath.join(relative_to_tree(dependency_path, tree), "Cargo.toml")
    return universe.packages.get(manifest)


def cargo_local_closure(
    tree: Path, universe: CargoUniverse, package_name: str, artifact_manifest: str
) -> list[dict[str, Any]]:
    candidates = [
        package
        for package in universe.packages.values()
        if package.get("name") == package_name
        and (
            package["_manifest_relative"] == artifact_manifest
            or artifact_manifest == "Cargo.toml"
        )
    ]
    if len(candidates) != 1:
        raise PlannerError(f"expected one Cargo package named {package_name}, found {len(candidates)}")
    closure: dict[str, dict[str, Any]] = {}
    queue = deque([candidates[0]])
    while queue:
        package = queue.popleft()
        manifest = package["_manifest_relative"]
        if manifest in closure:
            continue
        closure[manifest] = package
        if len(closure) > MAX_CARGO_PACKAGES:
            raise PlannerError("Cargo dependency closure exceeds package limit")
        for dependency in package.get("dependencies", []):
            if not dependency_kind_is_artifact(dependency):
                continue
            local = resolve_local_dependency(dependency, universe, tree)
            if local is not None:
                queue.append(local)
    return [closure[key] for key in sorted(closure)]


def normalized_dependency(dependency: dict[str, Any], tree: Path) -> dict[str, Any]:
    path = dependency.get("path")
    return {
        "name": dependency.get("name"),
        "source": dependency.get("source"),
        "req": dependency.get("req"),
        "kind": dependency.get("kind") or "normal",
        "rename": dependency.get("rename"),
        "optional": bool(dependency.get("optional")),
        "uses_default_features": bool(dependency.get("uses_default_features")),
        "features": sorted(dependency.get("features") or []),
        "target": dependency.get("target"),
        "path": relative_to_tree(path, tree) if path else None,
    }


def normalized_package(package: dict[str, Any], tree: Path) -> dict[str, Any]:
    targets = []
    for target in package.get("targets", []):
        kinds = sorted(target.get("kind") or [])
        if any(kind in {"test", "example", "bench"} for kind in kinds):
            continue
        targets.append(
            {
                "name": target.get("name"),
                "kind": kinds,
                "crate_types": sorted(target.get("crate_types") or []),
                "src_path": relative_to_tree(target["src_path"], tree),
                "edition": target.get("edition"),
                "required_features": sorted(target.get("required-features") or []),
            }
        )
    dependencies = [
        normalized_dependency(dependency, tree)
        for dependency in package.get("dependencies", [])
        if dependency_kind_is_artifact(dependency)
    ]
    license_file = package.get("license_file")
    readme = package.get("readme")
    return {
        "name": package.get("name"),
        "version": package.get("version"),
        "edition": package.get("edition"),
        "rust_version": package.get("rust_version"),
        "links": package.get("links"),
        "authors": package.get("authors") or [],
        "license": package.get("license"),
        "license_file": relative_to_tree(license_file, tree) if license_file else None,
        "description": package.get("description"),
        "homepage": package.get("homepage"),
        "documentation": package.get("documentation"),
        "repository": package.get("repository"),
        "readme": relative_to_tree(readme, tree) if readme else None,
        "keywords": package.get("keywords") or [],
        "categories": package.get("categories") or [],
        "default_run": package.get("default_run"),
        "metadata": package.get("metadata"),
        "features": {key: sorted(value) for key, value in sorted((package.get("features") or {}).items())},
        "dependencies": sorted(dependencies, key=lambda value: canonical_json(value)),
        "targets": sorted(targets, key=lambda value: canonical_json(value)),
        "manifest": package["_manifest_relative"],
    }


def selected_profiles(tree: Path, names: Iterable[str], artifact_manifest: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    manifests = ["Cargo.toml"]
    if artifact_manifest != "Cargo.toml":
        manifests.append(artifact_manifest)
    for relative in manifests:
        manifest = tree / relative
        if not manifest.is_file():
            continue
        document = tomllib.loads(manifest.read_text())
        profiles = document.get("profile", {})
        for name in names:
            if name in profiles:
                result[f"{relative}:{name}"] = profiles[name]
    return result


def parse_lock_reference(reference: str) -> tuple[str, str | None, str | None]:
    match = LOCK_REF_RE.fullmatch(reference)
    if not match:
        raise PlannerError(f"unsupported Cargo.lock dependency reference: {reference!r}")
    return match.group("name"), match.group("version"), match.group("source")


def lock_record_key(record: dict[str, Any]) -> tuple[str, str, str | None]:
    return str(record["name"]), str(record["version"]), record.get("source")


def resolve_lock_reference(reference: str, records: list[dict[str, Any]]) -> dict[str, Any]:
    name, version, source = parse_lock_reference(reference)
    candidates = [record for record in records if record.get("name") == name]
    if version is not None:
        candidates = [record for record in candidates if str(record.get("version")) == version]
    if source is not None:
        candidates = [record for record in candidates if record.get("source") == source]
    if len(candidates) != 1:
        raise PlannerError(f"Cargo.lock reference is ambiguous or missing: {reference!r}")
    return candidates[0]


def reachable_lock_records(
    tree: Path, lockfile_relative: str, closure: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    lockfile = tree / lockfile_relative
    if not lockfile.is_file():
        raise PlannerError(f"Cargo lockfile is missing: {lockfile_relative}")
    document = tomllib.loads(lockfile.read_text())
    records = document.get("package")
    if not isinstance(records, list):
        raise PlannerError(f"Cargo lockfile has no package records: {lockfile_relative}")
    local_keys = {(str(package["name"]), str(package["version"]), None) for package in closure}
    local_records: dict[tuple[str, str, str | None], dict[str, Any]] = {}
    for record in records:
        key = lock_record_key(record)
        if key in local_keys:
            if key in local_records:
                raise PlannerError(f"duplicate local Cargo.lock record: {key[0]} {key[1]}")
            local_records[key] = record
    missing = local_keys - set(local_records)
    if missing:
        package = sorted(missing)[0]
        raise PlannerError(f"local package is missing from Cargo.lock: {package[0]} {package[1]}")

    queue: deque[dict[str, Any]] = deque()
    for package in closure:
        local_record = local_records[(str(package["name"]), str(package["version"]), None)]
        external_names = {
            str(dependency["name"])
            for dependency in package.get("dependencies", [])
            if dependency_kind_is_artifact(dependency) and not dependency.get("path")
        }
        for reference in local_record.get("dependencies", []):
            if parse_lock_reference(str(reference))[0] not in external_names:
                continue
            resolved = resolve_lock_reference(str(reference), records)
            if lock_record_key(resolved) not in local_keys:
                queue.append(resolved)

    reachable: dict[tuple[str, str, str | None], dict[str, Any]] = {}
    while queue:
        record = queue.popleft()
        key = lock_record_key(record)
        if key in reachable or key in local_keys:
            continue
        reachable[key] = record
        if len(reachable) > MAX_CARGO_PACKAGES * 20:
            raise PlannerError("Cargo.lock traversal exceeds record limit")
        for reference in record.get("dependencies", []):
            dependency = resolve_lock_reference(str(reference), records)
            if lock_record_key(dependency) not in local_keys:
                queue.append(dependency)
    return [
        {
            "name": record["name"],
            "version": str(record["version"]),
            "source": record.get("source"),
            "checksum": record.get("checksum"),
            "dependencies": sorted(str(value) for value in record.get("dependencies", [])),
        }
        for _, record in sorted(reachable.items())
    ]


def indexed_file_record(entry: IndexedPath) -> dict[str, Any]:
    return {"path": entry.path, "kind": entry.kind, "mode": entry.mode, "sha256": entry.sha256}


def add_pattern_entries(index: TreeIndex, pattern: str, destination: dict[str, dict[str, Any]]) -> None:
    for entry in index.matching(pattern):
        destination[entry.path] = indexed_file_record(entry)


def normalized_input_patterns(spec: dict[str, Any], artifact_kind: str) -> list[str]:
    raw_patterns = spec.get("inputs")
    if not isinstance(raw_patterns, list) or not raw_patterns:
        raise PlannerError(f"{artifact_kind} inputs must be a non-empty list")
    patterns: list[str] = []
    for raw_pattern in raw_patterns:
        if not isinstance(raw_pattern, str) or not raw_pattern:
            raise PlannerError(f"{artifact_kind} input pattern must be a non-empty string")
        if "\x00" in raw_pattern or "\\" in raw_pattern or raw_pattern.startswith("/"):
            raise PlannerError(f"unsafe {artifact_kind} input pattern: {raw_pattern!r}")
        normalized = posixpath.normpath(raw_pattern)
        if (
            normalized in ("", ".", "..")
            or normalized.startswith("../")
            or normalized != raw_pattern
        ):
            raise PlannerError(f"non-normalized {artifact_kind} input pattern: {raw_pattern!r}")
        patterns.append(normalized)
    if len(patterns) != len(set(patterns)):
        raise PlannerError(f"{artifact_kind} input patterns contain a duplicate")
    return patterns


@dataclass
class ArtifactFingerprint:
    fingerprint: str
    document: dict[str, Any]


def file_set_fingerprint(
    tree: Path,
    spec: dict[str, Any],
    index: TreeIndex | None = None,
    *,
    artifact_kind: str = "file-set",
) -> ArtifactFingerprint:
    allowed_fields = {"kind", "inputs"}
    unexpected = sorted(set(spec) - allowed_fields)
    if unexpected:
        raise PlannerError(f"{artifact_kind} has unsupported fields: {unexpected}")
    patterns = normalized_input_patterns(spec, artifact_kind)
    tree_index = index or TreeIndex(tree)
    files: dict[str, dict[str, Any]] = {}
    for pattern in patterns:
        matches = tree_index.matching(pattern)
        if not matches:
            raise PlannerError(f"{artifact_kind} input pattern matched no files: {pattern}")
        for entry in matches:
            if entry.kind != "file":
                raise PlannerError(f"{artifact_kind} input is not a regular file: {entry.path}")
            files[entry.path] = indexed_file_record(entry)
    document = {
        "patterns": patterns,
        "files": [files[path] for path in sorted(files)],
    }
    return ArtifactFingerprint(sha256_bytes(canonical_json(document)), document)


@dataclass
class RustFingerprint:
    fingerprint: str
    document: dict[str, Any]
    closure_manifests: set[str]
    closure_directories: set[str]
    all_package_directories: set[str]


def rust_fingerprint(
    tree: Path,
    spec: dict[str, Any],
    trusted_toolchain: str | None = None,
    index: TreeIndex | None = None,
) -> RustFingerprint:
    with tempfile.TemporaryDirectory(prefix="codewire-ci-cargo-") as cargo_temp:
        cargo_env = isolated_cargo_environment(Path(cargo_temp), trusted_toolchain)
        universe = discover_cargo_universe(tree, spec["manifest"], cargo_env)
    closure = cargo_local_closure(tree, universe, spec["package"], spec["manifest"])
    tree_index = index or TreeIndex(tree)
    files: dict[str, dict[str, Any]] = {}
    for package in closure:
        directory = package["_directory_relative"]
        source_prefix = posixpath.join(directory, "src") if directory else "src"
        add_pattern_entries(tree_index, source_prefix + "/**", files)
        for target in package.get("targets", []):
            kinds = set(target.get("kind") or [])
            if kinds & {"test", "example", "bench"}:
                continue
            target_path = relative_to_tree(target["src_path"], tree)
            if target_path in tree_index.entries:
                files[target_path] = indexed_file_record(tree_index.entries[target_path])
        build_rs = posixpath.join(directory, "build.rs") if directory else "build.rs"
        if build_rs in tree_index.entries:
            files[build_rs] = indexed_file_record(tree_index.entries[build_rs])
        for pattern in spec.get("package_inputs", {}).get(package["name"], []):
            add_pattern_entries(tree_index, pattern, files)
    for pattern in spec.get("explicit_inputs", []):
        add_pattern_entries(tree_index, pattern, files)

    document = {
        "package": spec["package"],
        "manifest": spec["manifest"],
        "release_targets": list(spec.get("release_targets", [])),
        "profiles": selected_profiles(tree, spec.get("profiles", []), spec["manifest"]),
        "packages": [normalized_package(package, tree) for package in closure],
        "lock_records": reachable_lock_records(tree, spec["lockfile"], closure),
        "files": [files[key] for key in sorted(files)],
    }
    return RustFingerprint(
        sha256_bytes(canonical_json(document)),
        document,
        {package["_manifest_relative"] for package in closure},
        {package["_directory_relative"] for package in closure},
        universe.package_dirs,
    )


def composite_dependencies(spec: dict[str, Any]) -> list[str]:
    allowed_fields = {"kind", "dependencies", "inputs"}
    unexpected = sorted(set(spec) - allowed_fields)
    if unexpected:
        raise PlannerError(f"composite has unsupported fields: {unexpected}")
    raw_dependencies = spec.get("dependencies")
    if not isinstance(raw_dependencies, list) or not raw_dependencies:
        raise PlannerError("composite dependencies must be a non-empty list")
    if not all(isinstance(value, str) and value for value in raw_dependencies):
        raise PlannerError("composite dependency names must be non-empty strings")
    if len(raw_dependencies) != len(set(raw_dependencies)):
        raise PlannerError("composite dependencies contain a duplicate")
    return list(raw_dependencies)


def artifact_fingerprint(
    name: str,
    tree: Path,
    graph: dict[str, Any],
    trusted_toolchain: str | None,
    tree_index: TreeIndex,
    cache: dict[str, ArtifactFingerprint | RustFingerprint],
    resolving: list[str] | None = None,
) -> ArtifactFingerprint | RustFingerprint:
    if name in cache:
        return cache[name]
    path = list(resolving or [])
    if name in path:
        raise PlannerError(f"artifact dependency cycle: {' -> '.join([*path, name])}")
    spec = graph.get("artifacts", {}).get(name)
    if not isinstance(spec, dict):
        raise PlannerError(f"artifact dependency is missing: {name}")
    kind = spec.get("kind")
    if kind == "rust-package":
        result: ArtifactFingerprint | RustFingerprint = rust_fingerprint(
            tree, spec, trusted_toolchain, tree_index
        )
    elif kind == "file-set":
        result = file_set_fingerprint(tree, spec, tree_index)
    elif kind == "composite":
        dependencies = composite_dependencies(spec)
        own = file_set_fingerprint(
            tree,
            {"kind": "file-set", "inputs": spec.get("inputs")},
            tree_index,
            artifact_kind="composite",
        )
        dependency_records = []
        for dependency in dependencies:
            resolved = artifact_fingerprint(
                dependency,
                tree,
                graph,
                trusted_toolchain,
                tree_index,
                cache,
                [*path, name],
            )
            dependency_records.append(
                {"artifact": dependency, "fingerprint": resolved.fingerprint}
            )
        document = {
            "dependencies": dependency_records,
            "inputs": own.document,
        }
        result = ArtifactFingerprint(sha256_bytes(canonical_json(document)), document)
    elif kind == "unmigrated":
        raise PlannerError("artifact resolver has not migrated to the canonical graph")
    else:
        raise PlannerError(f"unsupported artifact kind: {kind}")
    cache[name] = result
    return result


def changed_paths(repository: Path, baseline: str, head: str) -> list[str]:
    output = _run(
        ["git", "diff", "--name-status", "-z", "--find-renames", baseline, head, "--"],
        cwd=repository,
    )
    fields = output.decode("utf-8", "surrogateescape").split("\x00")
    paths: set[str] = set()
    index = 0
    while index < len(fields) and fields[index]:
        status_code = fields[index]
        index += 1
        path_count = 2 if status_code.startswith(("R", "C")) else 1
        if index + path_count > len(fields):
            raise PlannerError("git diff returned malformed name-status output")
        for path in fields[index : index + path_count]:
            paths.add(_safe_member_path(path))
        index += path_count
    return sorted(paths)


def component_changes(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    explanations: list[str] = []
    for component in sorted(set(before) | set(after)):
        if before.get(component) != after.get(component):
            explanations.append(f"{component} fingerprint changed")
    return explanations or ["artifact fingerprint changed"]


def path_under(path: str, directory: str) -> bool:
    if not directory:
        return "/" not in path
    return path == directory or path.startswith(directory.rstrip("/") + "/")


def has_unknown_reachable_path(
    paths: Iterable[str],
    before: RustFingerprint,
    after: RustFingerprint,
    known_artifact_directories: set[str],
) -> str | None:
    closure_dirs = before.closure_directories | after.closure_directories
    all_package_dirs = before.all_package_directories | after.all_package_directories
    analyzed = {
        record["path"] for record in before.document["files"] + after.document["files"]
    }
    analyzed |= before.closure_manifests | after.closure_manifests
    known_root_inputs = {"Cargo.toml", "Cargo.lock", "rust-toolchain.toml"}
    unrelated_roots = {
        "apps",
        "deployments",
        "docs",
        "images",
        "packages",
        "proto",
        "libs",
        ".github",
    }
    for path in paths:
        if path in analyzed or path in known_root_inputs or path.endswith("/Cargo.lock"):
            continue
        matching_closure = [directory for directory in closure_dirs if path_under(path, directory)]
        if matching_closure:
            relative = path[len(matching_closure[0]) :].lstrip("/")
            if relative.startswith(("tests/", "test/", "benches/", "examples/")) or relative in {
                "README",
                "README.md",
                "LICENSE",
                "LICENSE.md",
            }:
                continue
            return path
        if any(path_under(path, directory) for directory in all_package_dirs):
            continue
        if any(directory and path_under(path, directory) for directory in known_artifact_directories):
            continue
        first = path.split("/", 1)[0]
        if first in unrelated_roots:
            continue
        if path.startswith("scripts/ci/release/"):
            continue
        return path
    return None


def policy_changed(paths: Iterable[str]) -> str | None:
    sensitive_prefixes = (
        "scripts/ci/plan/",
        ".gitea/workflows/",
        "scripts/ci/receipts/",
        "scripts/ci/receipt/",
    )
    sensitive_files = {
        "scripts/ci/select/require-verification-results.sh",
        "scripts/ci/select/select-verification.sh",
        "scripts/ci/select/verify-tested-tree-receipt.sh",
    }
    for path in paths:
        if path in sensitive_files or path.startswith(sensitive_prefixes):
            return path
    return None


def policy_hash(policy_tree: Path, graph: dict[str, Any]) -> tuple[str, str]:
    graph_path = policy_tree / "scripts/ci/plan/artifact-graph.json"
    graph_digest = sha256_bytes(graph_path.read_bytes())
    records = []
    for relative in graph.get("policy_files", []):
        path = policy_tree / relative
        if not path.is_file() or path.is_symlink():
            raise PlannerError(f"trusted policy file is missing or not regular: {relative}")
        records.append({"path": relative, "sha256": sha256_bytes(path.read_bytes())})
    return sha256_bytes(canonical_json(records)), graph_digest


def make_pull_request_baseline(repository: Path, target_base: str, head: str) -> dict[str, Any]:
    merge_base = git(repository, "merge-base", target_base, head)
    valid = bool(HEX40_RE.fullmatch(merge_base))
    reasons = [] if valid else ["git merge-base did not return one commit"]
    return {
        "schema": BASELINE_SCHEMA,
        "mode": "pull_request_merge_base",
        "target_base_commit": target_base,
        "baseline_commit": merge_base,
        "head_commit": head,
        "head_tree": git(repository, "rev-parse", f"{head}^{{tree}}"),
        "provenance": {"provider": "git", "comparison": "target-base merge-base to exact head"},
        "validation": {"valid": valid, "reasons": reasons},
    }


def _bounded_candidate(
    path: Path, label: str = "published support"
) -> tuple[dict[str, Any] | None, str, list[str]]:
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_BASELINE_CANDIDATE_BYTES + 1)
    except OSError:
        return None, "0" * 64, [f"{label} candidate is unavailable"]
    if len(raw) > MAX_BASELINE_CANDIDATE_BYTES:
        return None, "0" * 64, [f"{label} candidate exceeds the size limit"]
    digest = sha256_bytes(raw)

    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate JSON key")
            value[key] = item
        return value

    try:
        candidate = json.loads(raw, object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, ValueError):
        return None, digest, [f"{label} candidate is malformed"]
    if not isinstance(candidate, dict):
        return None, digest, [f"{label} candidate is not an object"]
    return candidate, digest, []


def _git_is_ancestor(
    repository: Path, ancestor: str, head: str, label: str = "published support"
) -> bool:
    completed = subprocess.run(
        ["git", "merge-base", "--is-ancestor", ancestor, head],
        cwd=repository,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if completed.returncode not in (0, 1):
        raise PlannerError(f"Git could not validate the {label} ancestor")
    return completed.returncode == 0


def make_published_support_baseline(
    repository: Path,
    target_base: str,
    head: str,
    candidate_path: Path,
) -> dict[str, Any]:
    candidate, candidate_digest, reasons = _bounded_candidate(candidate_path)
    provenance: dict[str, Any] = {
        "provider": "ghcr",
        "candidate_sha256": candidate_digest,
        "images": {},
    }
    baseline_commit = head
    revisions: dict[str, str] = {}

    if target_base != head:
        reasons.append("published support planning target is not the exact canonical head")
    if candidate is not None:
        if candidate.get("schema") != SUPPORT_CANDIDATE_SCHEMA:
            reasons.append("published support candidate schema is unsupported")
        retrieval = candidate.get("retrieval")
        if not isinstance(retrieval, dict):
            reasons.append("published support candidate omits retrieval status")
        elif retrieval.get("valid") is not True or retrieval.get("reasons") != []:
            reasons.append("published support candidate retrieval did not succeed")

        images = candidate.get("images")
        if not isinstance(images, dict):
            reasons.append("published support candidate omits image metadata")
        else:
            for name, expected_repository in SUPPORT_REPOSITORIES.items():
                image = images.get(name)
                if not isinstance(image, dict):
                    reasons.append(f"published support candidate omits {name} metadata")
                    continue
                repository_value = image.get("repository")
                tag = image.get("tag")
                digest = image.get("digest")
                revision = image.get("revision")
                provenance["images"][name] = {
                    "repository": repository_value if isinstance(repository_value, str) else None,
                    "tag": tag if isinstance(tag, str) else None,
                    "digest": digest if isinstance(digest, str) else None,
                    "revision": revision if isinstance(revision, str) else None,
                }
                if repository_value != expected_repository:
                    reasons.append(f"published support {name} repository is invalid")
                if tag != "latest":
                    reasons.append(f"published support {name} tag is not latest")
                if not isinstance(digest, str) or not SHA256_DIGEST_RE.fullmatch(digest):
                    reasons.append(f"published support {name} digest is invalid")
                if not isinstance(revision, str) or not HEX40_RE.fullmatch(revision):
                    reasons.append(f"published support {name} revision is invalid")
                else:
                    revisions[name] = revision

    if len(revisions) == 2:
        source = revisions["base"]
        if source != revisions["workspace"]:
            reasons.append("published support image revisions do not match")
        else:
            try:
                resolved_source = resolve_commit(repository, source)
            except PlannerError:
                reasons.append("published support source is absent from canonical Git history")
            else:
                if not _git_is_ancestor(repository, resolved_source, head):
                    reasons.append("published support source is not an ancestor of the exact head")
                else:
                    baseline_commit = resolved_source

    normalized_reasons = sorted(set(reasons))
    return {
        "schema": BASELINE_SCHEMA,
        "mode": "published_support_pair",
        "target_base_commit": target_base,
        "baseline_commit": baseline_commit,
        "head_commit": head,
        "head_tree": git(repository, "rev-parse", f"{head}^{{tree}}"),
        "provenance": provenance,
        "validation": {"valid": not normalized_reasons, "reasons": normalized_reasons},
    }


def make_deployed_source_baseline(
    repository: Path,
    target_base: str,
    head: str,
    candidate_path: Path,
) -> dict[str, Any]:
    candidate, candidate_digest, reasons = _bounded_candidate(
        candidate_path, "deployed source"
    )
    provenance: dict[str, Any] = {
        "provider": "codewire/deploy release",
        "candidate_sha256": candidate_digest,
        "release": {},
        "source": {},
    }
    baseline_commit = head
    source_sha: str | None = None

    if target_base != head:
        reasons.append("deployed-source planning target is not the exact canonical head")
    if candidate is not None:
        if candidate.get("schema") != DEPLOYED_SOURCE_CANDIDATE_SCHEMA:
            reasons.append("deployed source candidate schema is unsupported")

        retrieval = candidate.get("retrieval")
        if not isinstance(retrieval, dict):
            reasons.append("deployed source candidate omits retrieval status")
        elif retrieval.get("valid") is not True or retrieval.get("reasons") != []:
            reasons.append("deployed source candidate retrieval did not succeed")

        target = candidate.get("target")
        if not isinstance(target, dict):
            reasons.append("deployed source candidate omits target binding")
        else:
            target_repository = target.get("repository")
            target_head = target.get("head_sha")
            if set(target) != {"repository", "head_sha"}:
                reasons.append("deployed source target binding is ambiguous")
            if target_repository != "codewire/codewire":
                reasons.append("deployed source target repository is invalid")
            if target_head != head:
                reasons.append("deployed source candidate is stale for the exact head")

        release = candidate.get("release")
        if not isinstance(release, dict):
            reasons.append("deployed source candidate omits release identity")
        else:
            provenance["release"] = {
                "repository": release.get("repository"),
                "path": release.get("path"),
                "ref": release.get("ref"),
            }
            if set(release) != {"repository", "path", "ref"}:
                reasons.append("deployed source release identity is ambiguous")
            if release.get("repository") != "codewire/deploy":
                reasons.append("deployed source release repository is invalid")
            if release.get("path") != "environments/dev/release.json":
                reasons.append("deployed source release path is invalid")
            if release.get("ref") != "main":
                reasons.append("deployed source release ref is invalid")

        source = candidate.get("source")
        if not isinstance(source, dict):
            reasons.append("deployed source candidate omits source identity")
        else:
            repository_value = source.get("repository")
            sha_value = source.get("sha")
            provenance["source"] = {
                "repository": repository_value if isinstance(repository_value, str) else None,
                "sha": sha_value if isinstance(sha_value, str) else None,
            }
            if set(source) != {"repository", "sha"}:
                reasons.append("deployed source identity is ambiguous")
            if repository_value != "codewire/codewire":
                reasons.append("deployed source repository is invalid")
            if not isinstance(sha_value, str) or not HEX40_RE.fullmatch(sha_value):
                reasons.append("deployed source SHA is invalid")
            elif sha_value == "0" * 40:
                reasons.append("deployed source SHA is invalid")
            else:
                source_sha = sha_value

    if source_sha is not None:
        try:
            resolved_source = resolve_commit(repository, source_sha)
        except PlannerError:
            reasons.append("deployed source is absent from canonical Git history")
        else:
            if not _git_is_ancestor(repository, resolved_source, head, "deployed source"):
                reasons.append("deployed source is not an ancestor of the exact head")
            else:
                baseline_commit = resolved_source

    normalized_reasons = sorted(set(reasons))
    return {
        "schema": BASELINE_SCHEMA,
        "mode": "deployed_source",
        "target_base_commit": target_base,
        "baseline_commit": baseline_commit,
        "head_commit": head,
        "head_tree": git(repository, "rev-parse", f"{head}^{{tree}}"),
        "provenance": provenance,
        "validation": {"valid": not normalized_reasons, "reasons": normalized_reasons},
    }


def unclassified_result(reason: str) -> dict[str, Any]:
    return {
        "state": "unclassified",
        "baseline_fingerprint": None,
        "head_fingerprint": None,
        "explanations": [reason],
    }


def plan(
    repository: Path,
    target_base_revision: str,
    head_revision: str,
    trusted_policy_revision: str | None = None,
    baseline_candidate: Path | None = None,
    deployed_source_candidate: Path | None = None,
) -> dict[str, Any]:
    repository = repository.resolve()
    target_base = resolve_commit(repository, target_base_revision)
    head = resolve_commit(repository, head_revision)
    trusted_policy = resolve_commit(repository, trusted_policy_revision or target_base_revision)
    if baseline_candidate is not None and deployed_source_candidate is not None:
        raise PlannerError("baseline candidate modes are mutually exclusive")
    if deployed_source_candidate is not None:
        baseline = make_deployed_source_baseline(
            repository,
            target_base,
            head,
            deployed_source_candidate,
        )
    elif baseline_candidate is None:
        baseline = make_pull_request_baseline(repository, target_base, head)
    else:
        baseline = make_published_support_baseline(
            repository,
            target_base,
            head,
            baseline_candidate,
        )
    degraded: list[str] = []
    artifacts: dict[str, Any] = {}

    with tempfile.TemporaryDirectory(prefix="codewire-ci-plan-") as temporary:
        temp = Path(temporary)
        policy_tree = temp / "policy"
        baseline_tree = temp / "baseline"
        head_tree = temp / "head"
        try:
            export_git_tree(repository, trusted_policy, policy_tree)
            graph_path = policy_tree / "scripts/ci/plan/artifact-graph.json"
            graph = json.loads(graph_path.read_text())
            if graph.get("schema") != "codewire.ci-artifact-graph/v1":
                raise PlannerError("trusted artifact graph has an unsupported schema")
            policy_digest, graph_digest = policy_hash(policy_tree, graph)
            rust_toolchain = trusted_rust_toolchain(policy_tree)
        except (OSError, json.JSONDecodeError, PlannerError) as exc:
            raise PlannerError(f"trusted policy could not be loaded: {exc}") from exc

        baseline_validation = baseline.get("validation")
        if (
            not isinstance(baseline_validation, dict)
            or baseline_validation.get("valid") is not True
            or baseline_validation.get("reasons") != []
        ):
            baseline_reasons = (
                baseline_validation.get("reasons")
                if isinstance(baseline_validation, dict)
                and isinstance(baseline_validation.get("reasons"), list)
                else ["baseline validation result is malformed"]
            )
            reason = "baseline validation failed: " + "; ".join(
                value for value in baseline_reasons if isinstance(value, str)
            )
            degraded.append(reason)
            for name in graph["artifacts"]:
                artifacts[name] = unclassified_result(reason)
        else:
            paths = changed_paths(repository, baseline["baseline_commit"], head)
            changed_policy_path = policy_changed(paths)
            try:
                export_git_tree(repository, baseline["baseline_commit"], baseline_tree)
                export_git_tree(repository, head, head_tree)
            except PlannerError as exc:
                degraded.append(str(exc))
                for name in graph["artifacts"]:
                    artifacts[name] = unclassified_result(str(exc))
            else:
                known_artifact_directories = {
                    posixpath.dirname(candidate.get("manifest", ""))
                    for candidate in graph["artifacts"].values()
                    if candidate.get("kind") == "rust-package"
                }
                baseline_index = TreeIndex(baseline_tree)
                head_index = TreeIndex(head_tree)
                baseline_fingerprints: dict[str, ArtifactFingerprint | RustFingerprint] = {}
                head_fingerprints: dict[str, ArtifactFingerprint | RustFingerprint] = {}
                classifying: set[str] = set()

                def classify(name: str) -> dict[str, Any]:
                    if name in artifacts:
                        return artifacts[name]
                    spec = graph["artifacts"].get(name)
                    if not isinstance(spec, dict):
                        return unclassified_result(f"artifact definition is missing: {name}")
                    if changed_policy_path:
                        result = unclassified_result(
                            f"trusted policy surface changed: {changed_policy_path}"
                        )
                        artifacts[name] = result
                        return result
                    if spec.get("kind") == "unmigrated":
                        result = unclassified_result(
                            "artifact resolver has not migrated to the canonical graph"
                        )
                        artifacts[name] = result
                        return result
                    if name in classifying:
                        result = unclassified_result(f"artifact dependency cycle includes: {name}")
                        artifacts[name] = result
                        return result
                    classifying.add(name)
                    try:
                        before = artifact_fingerprint(
                            name,
                            baseline_tree,
                            graph,
                            rust_toolchain,
                            baseline_index,
                            baseline_fingerprints,
                        )
                        after = artifact_fingerprint(
                            name,
                            head_tree,
                            graph,
                            rust_toolchain,
                            head_index,
                            head_fingerprints,
                        )
                        dependency_failure = None
                        if spec.get("kind") == "composite":
                            for dependency in composite_dependencies(spec):
                                dependency_result = classify(dependency)
                                if dependency_result["state"] == "unclassified":
                                    dependency_failure = (
                                        f"dependency {dependency} is unclassified: "
                                        f"{dependency_result['explanations'][0]}"
                                    )
                                    break
                        if dependency_failure:
                            result = {
                                "state": "unclassified",
                                "baseline_fingerprint": before.fingerprint,
                                "head_fingerprint": after.fingerprint,
                                "explanations": [dependency_failure],
                            }
                        elif before.fingerprint != after.fingerprint:
                            result = {
                                "state": "affected",
                                "baseline_fingerprint": before.fingerprint,
                                "head_fingerprint": after.fingerprint,
                                "explanations": component_changes(before.document, after.document),
                            }
                        elif isinstance(before, RustFingerprint) and isinstance(after, RustFingerprint):
                            unknown = has_unknown_reachable_path(
                                paths, before, after, known_artifact_directories
                            )
                            if unknown:
                                result = {
                                    "state": "unclassified",
                                    "baseline_fingerprint": before.fingerprint,
                                    "head_fingerprint": after.fingerprint,
                                    "explanations": [
                                        f"changed path has no trusted ownership rule: {unknown}"
                                    ],
                                }
                            else:
                                result = {
                                    "state": "unaffected",
                                    "baseline_fingerprint": before.fingerprint,
                                    "head_fingerprint": after.fingerprint,
                                    "explanations": [
                                        "artifact fingerprint and owned inputs are unchanged"
                                    ],
                                }
                        else:
                            result = {
                                "state": "unaffected",
                                "baseline_fingerprint": before.fingerprint,
                                "head_fingerprint": after.fingerprint,
                                "explanations": [
                                    "artifact fingerprint and owned inputs are unchanged"
                                ],
                            }
                    except (OSError, UnicodeError, tomllib.TOMLDecodeError, PlannerError) as exc:
                        reason = f"{name} classification failed: {exc}"
                        degraded.append(reason)
                        result = unclassified_result(reason)
                    finally:
                        classifying.discard(name)
                    artifacts[name] = result
                    return result

                for name in graph["artifacts"]:
                    classify(name)

    return {
        "schema": PLAN_SCHEMA,
        "trusted_policy": {
            "commit": trusted_policy,
            "policy_sha256": policy_digest,
            "graph_sha256": graph_digest,
        },
        "baseline": baseline,
        "artifacts": artifacts,
        "degraded_reasons": sorted(set(degraded)),
    }


def cargo_oracle(repository: Path, plan_document: dict[str, Any]) -> None:
    graph = json.loads((repository / "scripts/ci/plan/artifact-graph.json").read_text())
    for artifact, spec in graph["artifacts"].items():
        if spec.get("kind") != "rust-package":
            continue
        with tempfile.TemporaryDirectory(prefix="codewire-ci-oracle-") as temporary:
            cargo_env = isolated_cargo_environment(Path(temporary))
            universe = discover_cargo_universe(repository, spec["manifest"], cargo_env)
            closure = cargo_local_closure(repository, universe, spec["package"], spec["manifest"])
        local_names = {package["name"] for package in universe.packages.values()}
        argv = [
            "cargo",
            "tree",
            "--locked",
            "--offline",
            "--edges",
            "normal,build",
            "--prefix",
            "none",
            "--format",
            "{p}",
            "-p",
            spec["package"],
        ]
        if spec["manifest"] != "Cargo.toml":
            argv.extend(["--manifest-path", spec["manifest"]])
        output = _run(argv, cwd=repository, env={**os.environ, "CARGO_NET_OFFLINE": "true"})
        oracle_names = {
            line.split(" ", 1)[0]
            for line in output.decode().splitlines()
            if line.split(" ", 1)[0] in local_names
        }
        planner_names = {package["name"] for package in closure}
        missing = oracle_names - planner_names
        if missing:
            raise PlannerError(f"{artifact} Cargo oracle found missing local packages: {sorted(missing)}")
        if spec["package"] not in planner_names:
            raise PlannerError(f"{artifact} planner closure omitted its root package")
        if plan_document["artifacts"][artifact]["state"] == "unclassified":
            explanations = plan_document["artifacts"][artifact]["explanations"]
            if any("classification failed" in explanation for explanation in explanations):
                raise PlannerError(f"{artifact} is unclassified because its current-tree Cargo resolution failed")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", default=".", help="Git repository to inspect")
    parser.add_argument("--target-base", required=True, help="trusted pull-request target base revision")
    parser.add_argument("--head", required=True, help="exact proposed head revision")
    parser.add_argument(
        "--trusted-policy",
        help="revision containing the executing policy (defaults to --target-base)",
    )
    parser.add_argument(
        "--baseline-candidate",
        help="untrusted published-support registry candidate to validate before planning",
    )
    parser.add_argument(
        "--deployed-source-candidate",
        help="untrusted deployed-source release candidate to validate before planning",
    )
    parser.add_argument("--output", help="write the canonical JSON plan to this path instead of stdout")
    parser.add_argument("--check-cargo-oracle", action="store_true", help="compare local closure with cargo tree")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        document = plan(
            Path(args.repository),
            args.target_base,
            args.head,
            trusted_policy_revision=args.trusted_policy,
            baseline_candidate=(
                Path(args.baseline_candidate) if args.baseline_candidate else None
            ),
            deployed_source_candidate=(
                Path(args.deployed_source_candidate)
                if args.deployed_source_candidate
                else None
            ),
        )
        if args.check_cargo_oracle:
            cargo_oracle(Path(args.repository).resolve(), document)
    except PlannerError as exc:
        print(f"planner: {exc}", file=sys.stderr)
        return 2
    output = json.dumps(document, sort_keys=True, indent=2) + "\n"
    if args.output:
        Path(args.output).write_text(output)
    else:
        sys.stdout.write(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
