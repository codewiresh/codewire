#!/usr/bin/env python3
"""Owned, persistent local Kind topology; this tool never creates a cluster.

Profiles lease loopback ports on one workstation and bind a cluster to the
actual Docker daemon and node container. Bash consumers use fixed NUL records,
not shell expressions. Build provenance remains the producer's responsibility;
record-artifacts admits its sealed, source-qualified local file inventory.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import socket
import stat
import subprocess
import sys
import time
from typing import Iterator
from urllib.parse import urlsplit


SCHEMA = "codewire.kind-profile/v1"
ARTIFACT_SCHEMA = "codewire.kind-profile-artifacts/v1"
JSON_BOUND = 64 * 1024
NAME = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,47}[a-z0-9])?")
HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")
NONCE = re.compile(r"[0-9a-f]{32}")
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")
DAEMON_ID = re.compile(r"[A-Za-z0-9_.:-]{1,128}")
PORT_NAMES = ("http", "tls", "orchestration", "coordinator", "temporal", "postgres", "watch")
NODE_PORTS = {"http": 80, "tls": 443, "orchestration": 30084,
              "coordinator": 30090, "temporal": 30733, "postgres": 30432}
DEFAULT_PORTS = {"http": 8090, "tls": 10443, "orchestration": 8084,
                 "coordinator": 18092, "temporal": 7233, "postgres": 25432}
IMAGE_NAMES = ("dashboard", "services", "mesh", "daemon")
PROFILE_KEYS = {"schema", "cluster_name", "docker_id", "ownership_nonce", "created_at",
                "lifecycle", "ports", "origins", "node", "artifacts"}
ARTIFACT_KEYS = {"schema", "cluster_name", "docker_id", "ownership_nonce",
                 "source_head", "source_tree", "product_images", "files"}
ENV_CONFLICT_KEYS = {"KIND_CLUSTER_NAME", "KUBE_CONTEXT", "KUBECONFIG", "KIND_CONFIG", "RUN_DIR",
                     "KIND_INGRESS_HOST_PORT", "KIND_COORDINATOR_DIRECT_HOST_PORT",
                     "KIND_INGRESS_HTTP_HOST_PORT", "KIND_INGRESS_TLS_HOST_PORT",
                     "KIND_ORCHESTRATION_HOST_PORT", "KIND_COORDINATOR_HOST_PORT",
                     "KIND_TEMPORAL_HOST_PORT", "KIND_POSTGRES_HOST_PORT", "KIND_WATCH_HOST_PORT",
                     "KIND_INGRESS_URL", "KIND_INGRESS_TLS_URL", "KIND_ORCHESTRATION_URL",
                     "KIND_COORDINATOR_DIRECT_URL", "KIND_TEMPORAL_ADDRESS", "KIND_DATABASE_URL",
                     "KIND_ORCHESTRATION_HTTP_URL", "KIND_TEMPORAL_FRONTEND_URL",
                     "KIND_WATCH_ADDR", "KIND_PUBLIC_ORIGIN", "KIND_BROWSER_API_ORIGIN"}


class ProfileError(RuntimeError):
    """A selected topology cannot be safely used."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ProfileError(message)


def render_host_ports(text: str, replacements: dict[int, int], *, bind_loopback: bool = False) -> str:
    """Render the checked-in six mappings once, including swapped assignments."""
    require(set(replacements) == set(DEFAULT_PORTS.values()),
            "Kind renderer requires exactly the six checked-in host mappings")
    require(all(type(port) is int and 1024 <= port <= 65535 for port in replacements.values())
            and len(set(replacements.values())) == len(replacements),
            "Kind requested host ports must be distinct unprivileged TCP ports")
    mappings = [int(match.group(1)) for match in re.finditer(r"(?m)^[ \t]*hostPort: ([0-9]+)[ \t]*$", text)]
    require(len(mappings) == len(DEFAULT_PORTS) and set(mappings) == set(DEFAULT_PORTS.values()),
            "Kind template must contain exactly the six checked-in host mappings")
    if bind_loopback:
        require(re.search(r"(?m)^[ \t]*listenAddress:", text) is None,
                "Kind template has unexpected host listen-address mappings")

    def render(match):
        line = f"{match.group(1)}hostPort: {replacements[int(match.group(2))]}{match.group(3)}"
        if bind_loopback:
            line += f'\n{match.group(1)}listenAddress: "127.0.0.1"'
        return line

    return re.sub(r"(?m)^([ \t]*)hostPort: ([0-9]+)([ \t]*)$", render, text)


def acquire_lock(descriptor: int) -> None:
    timeout = os.environ.get("KIND_PROFILE_LOCK_TIMEOUT_SECONDS", "1200")
    require(re.fullmatch(r"[1-9][0-9]{0,4}", timeout) is not None and int(timeout) <= 86400,
            "profile lock timeout must be a bounded positive integer")
    deadline = time.monotonic() + int(timeout)
    while True:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except BlockingIOError as error:
            if time.monotonic() >= deadline:
                raise ProfileError("timed out waiting for the owned profile or publication lock") from error
            time.sleep(0.05)


def cluster_name(value: str) -> str:
    require(isinstance(value, str) and NAME.fullmatch(value) is not None,
            "cluster name must be a lowercase DNS label of at most 49 characters")
    return value


def origin(value: str) -> str:
    require(isinstance(value, str) and len(value) <= 512
            and not re.search(r"[\x00-\x20\x7f\\]", value), "invalid profile origin")
    try:
        parsed = urlsplit(value)
        port = parsed.port
        valid = (parsed.scheme in ("http", "https") and parsed.hostname is not None
                 and re.fullmatch(r"[A-Za-z0-9.-]+", parsed.hostname) is not None
                 and parsed.username is None and parsed.password is None
                 and parsed.path in ("", "/") and not parsed.query and not parsed.fragment
                 and (port is None or 1 <= port <= 65535))
    except ValueError:
        valid = False
    require(valid, "profile origin must be an HTTP(S) origin without credentials or a path")
    return value.rstrip("/")


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def decode_json(data: bytes) -> dict:
    require(len(data) <= JSON_BOUND, "profile JSON exceeds its bound")
    try:
        value = json.loads(data, object_pairs_hook=unique_object)
    except (ValueError, UnicodeError) as error:
        raise ProfileError("invalid profile JSON") from error
    require(isinstance(value, dict), "profile JSON must be an object")
    return value


def directory_fd(path: Path, *, create: bool = False) -> int:
    require(path.is_absolute() and ".." not in path.parts, "profile path must be absolute")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            try:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                dir_fd=descriptor)
            except FileNotFoundError:
                require(create, "profile directory does not exist")
                try:
                    os.mkdir(part, 0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        info = os.fstat(descriptor)
        require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
                "profile directory must be owned and mode 0700")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


@contextmanager
def owned_file(path: Path, *, modes: tuple[int, ...] = (0o600,),
               create: bool = False, writable: bool = False) -> Iterator[int]:
    parent = directory_fd(path.parent)
    descriptor = -1
    try:
        flags = ((os.O_RDWR if writable else os.O_RDONLY)
                 | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        if create:
            flags |= os.O_CREAT
        descriptor = os.open(path.name, flags, 0o600, dir_fd=parent)
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) in modes,
                "profile file must be owned, regular, private and unlinked elsewhere")
        yield descriptor
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent)


def read_json(path: Path, *, modes: tuple[int, ...] = (0o600,)) -> tuple[dict, bytes]:
    with owned_file(path, modes=modes) as descriptor:
        before = os.fstat(descriptor)
        require(before.st_size <= JSON_BOUND, "profile JSON exceeds its bound")
        data = bytearray()
        while chunk := os.read(descriptor, min(8192, JSON_BOUND + 1 - len(data))):
            data.extend(chunk)
            require(len(data) <= JSON_BOUND, "profile JSON exceeds its bound")
        after = os.fstat(descriptor)
        require((before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                == (after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                "profile file changed while reading")
    return decode_json(bytes(data)), bytes(data)


def atomic_write(path: Path, data: bytes) -> None:
    parent = directory_fd(path.parent)
    temporary = f".profile-{secrets.token_hex(12)}"
    descriptor = -1
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                             | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
        with os.fdopen(descriptor, "wb") as output:
            descriptor = -1
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path.name, src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=parent)
        except FileNotFoundError:
            pass
        os.close(parent)


def write_json(path: Path, value: dict) -> None:
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode() + b"\n"
    require(len(data) <= JSON_BOUND, "profile JSON exceeds its bound")
    atomic_write(path, data)


def member_state(info: os.stat_result) -> tuple:
    return (info.st_dev, info.st_ino, info.st_uid, info.st_mode, info.st_size, info.st_mtime_ns)


def inspect_private_tree(descriptor: int, *, deadline: float, budget: list[int], links: dict,
                         directories: set, depth: int = 0) -> dict:
    require(depth <= 64 and time.monotonic() < deadline, "profile purge inventory exceeded its bound")
    result = {}
    with os.scandir(descriptor) as entries:
        for entry in entries:
            budget[0] -= 1
            require(budget[0] >= 0 and time.monotonic() < deadline,
                    "profile purge inventory exceeded its bound")
            info = os.stat(entry.name, dir_fd=descriptor, follow_symlinks=False)
            require(info.st_uid == os.getuid() and not stat.S_IMODE(info.st_mode) & 0o022,
                    "profile purge found a foreign or writable shared member")
            identity = (info.st_dev, info.st_ino)
            children = None
            if stat.S_ISDIR(info.st_mode):
                require(identity not in directories, "profile purge found a repeated directory")
                directories.add(identity)
                child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                dir_fd=descriptor)
                try:
                    require((os.fstat(child).st_dev, os.fstat(child).st_ino) == identity,
                            "profile purge directory changed during inspection")
                    children = inspect_private_tree(child, deadline=deadline, budget=budget, links=links,
                                                    directories=directories, depth=depth + 1)
                finally:
                    os.close(child)
            else:
                require(stat.S_ISREG(info.st_mode), "profile purge refuses links and special files")
                # Cargo hard-links build outputs inside its target directory. Count every
                # name so purge can prove that each link of a file is a member of this tree.
                first, seen = links.get(identity, (info, 0))
                require((*member_state(first), first.st_nlink, first.st_ctime_ns)
                        == (*member_state(info), info.st_nlink, info.st_ctime_ns),
                        "profile purge member changed during inspection")
                links[identity] = (first, seen + 1)
            result[entry.name] = (info, children)
    return result


def remove_private_tree(descriptor: int, inventory: dict, *, deadline: float, links: dict) -> None:
    # Leave admission metadata and its operation lock until the other members
    # have been removed, keeping an ordinary partial cache purge identifiable.
    for name in sorted(inventory, key=lambda name: (name in ("profile.json", "operation.lock"), name)):
        require(time.monotonic() < deadline, "profile purge removal exceeded its bound")
        before, children = inventory[name]
        current = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        require((current.st_dev, current.st_ino, current.st_uid, current.st_mode)
                == (before.st_dev, before.st_ino, before.st_uid, before.st_mode),
                "profile purge member changed after inspection")
        if children is not None:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=descriptor)
            try:
                require((os.fstat(child).st_dev, os.fstat(child).st_ino) == (before.st_dev, before.st_ino),
                        "profile purge directory changed before removal")
                remove_private_tree(child, children, deadline=deadline, links=links)
            finally:
                os.close(child)
            os.rmdir(name, dir_fd=descriptor)
        else:
            identity = (before.st_dev, before.st_ino)
            remaining, changed = links[identity]
            member = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=descriptor)
            try:
                held = os.fstat(member)
                require(member_state(held) == member_state(before)
                        and (held.st_nlink, held.st_ctime_ns) == (remaining, changed),
                        "profile purge file changed before removal")
                os.unlink(name, dir_fd=descriptor)
                held = os.fstat(member)
                require(member_state(held) == member_state(before) and held.st_nlink == remaining - 1,
                        "profile purge file changed during removal")
            finally:
                os.close(member)
            # Our own unlink changes the link count and change time of the remaining aliases.
            links[identity] = (remaining - 1, held.st_ctime_ns)


@dataclass(frozen=True)
class Node:
    id: str
    name: str
    cluster: str
    role: str
    created: str
    running: bool = True


class Docker:
    """Read only the daemon identity and bounded, nonsecret node/image metadata."""

    @staticmethod
    def run(*arguments: str) -> str:
        try:
            result = subprocess.run(["docker", *arguments], check=True, capture_output=True,
                                    text=True, timeout=15)
        except (OSError, subprocess.SubprocessError) as error:
            raise ProfileError("cannot read Docker identity or selected node metadata") from error
        require(len(result.stdout.encode()) <= JSON_BOUND, "Docker metadata exceeds its bound")
        return result.stdout.strip()

    def identity(self) -> str:
        value = json.loads(self.run("info", "--format", "{{json .ID}}"))
        require(isinstance(value, str) and DAEMON_ID.fullmatch(value) is not None,
                "Docker daemon has no valid stable identity")
        return value

    def nodes(self, cluster: str) -> list[Node]:
        cluster = cluster_name(cluster)
        labelled = self.run("ps", "-a", "--quiet", "--no-trunc", "--filter",
                            f"label=io.x-k8s.kind.cluster={cluster}").splitlines()
        named = self.run("ps", "-a", "--quiet", "--no-trunc", "--filter",
                         f"name=^/{cluster}-control-plane$").splitlines()
        ids = sorted(set(labelled) | set(named))
        require(len(ids) <= 4, "selected Kind cluster has an unsupported node count")
        result = []
        template = ('{"id":{{json .Id}},"name":{{json .Name}},'
                    '"cluster":{{json (index .Config.Labels "io.x-k8s.kind.cluster")}},'
                    '"role":{{json (index .Config.Labels "io.x-k8s.kind.role")}},'
                    '"created":{{json .Created}},"running":{{json .State.Running}}}')
        for identifier in ids:
            require(HEX64.fullmatch(identifier) is not None, "invalid Docker node identity")
            value = json.loads(self.run("inspect", "--format", template, identifier))
            result.append(Node(value["id"], value["name"].removeprefix("/"), value["cluster"],
                               value["role"], value["created"], value["running"]))
        return result

    def image_ids(self) -> dict[str, str]:
        return {name: self.run("image", "inspect", "--format", "{{.Id}}", f"codewire-{name}:e2e")
                for name in IMAGE_NAMES}

    def cluster_names(self) -> list[str]:
        values = self.run("ps", "-a", "--format", '{{.Label "io.x-k8s.kind.cluster"}}',
                          "--filter", "label=io.x-k8s.kind.cluster").splitlines()
        require(len(values) <= 256, "Kind cluster inventory exceeds its bound")
        require(all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", value) for value in values),
                "Kind cluster inventory has unsupported names")
        return sorted(set(values))


class Profiles:
    def __init__(self, root: Path, docker: Docker | None = None):
        self.root = root.absolute()
        self.docker = docker or Docker()
        self.daemon = self.docker.identity()
        require(isinstance(self.daemon, str) and DAEMON_ID.fullmatch(self.daemon) is not None,
                "invalid Docker daemon identity")
        self.namespace = self.root / hashlib.sha256(self.daemon.encode()).hexdigest()

    def path(self, cluster: str) -> Path:
        return self.namespace / cluster_name(cluster)

    @contextmanager
    def registry(self, *, create: bool = False) -> Iterator[None]:
        descriptor = directory_fd(self.root, create=create)
        os.close(descriptor)
        with owned_file(self.root / "registry.lock", create=create, writable=True) as lock:
            acquire_lock(lock)
            require(self.docker.identity() == self.daemon, "Docker daemon identity changed")
            yield

    def build_lock_path(self) -> Path:
        """Legacy and named producers share one publication lock on this host."""
        with self.registry(create=True):
            path = self.root / "publication.lock"
            with owned_file(path, create=True, writable=True):
                pass
            return path

    def validate(self, value: dict, cluster: str, daemon: str) -> None:
        require(set(value) == PROFILE_KEYS and value["schema"] == SCHEMA,
                "invalid profile fields or schema")
        require(value["cluster_name"] == cluster and value["docker_id"] == daemon,
                "profile cluster or Docker daemon identity mismatch")
        require(isinstance(daemon, str) and DAEMON_ID.fullmatch(daemon) is not None,
                "invalid recorded Docker daemon identity")
        require(isinstance(value["ownership_nonce"], str)
                and NONCE.fullmatch(value["ownership_nonce"]) is not None,
                "invalid profile ownership nonce")
        require(type(value["created_at"]) is int and value["created_at"] > 0,
                "invalid profile creation time")
        require(value["lifecycle"] in ("allocated", "bound", "deleted"), "invalid profile lifecycle")
        ports = value["ports"]
        require(isinstance(ports, dict) and set(ports) == set(PORT_NAMES), "invalid profile port keys")
        require(all(type(port) is int and 1024 <= port <= 65535 for port in ports.values())
                and len(set(ports.values())) == len(PORT_NAMES), "invalid or overlapping profile ports")
        origins = value["origins"]
        require(isinstance(origins, dict) and set(origins) == {"public", "browser_api"},
                "invalid profile origin fields")
        public, browser = origin(origins["public"]), origin(origins["browser_api"])
        require(public == origins["public"] and browser == origins["browser_api"]
                and urlsplit(public).hostname == urlsplit(browser).hostname,
                "profile browser API must use the public origin's host")
        node = value["node"]
        require((value["lifecycle"] == "allocated") == (node is None), "profile lifecycle lacks its node identity")
        if node is not None:
            require(isinstance(node, dict) and set(node) == {"id", "name", "created"}
                    and isinstance(node["id"], str) and HEX64.fullmatch(node["id"]) is not None
                    and node["name"] == f"{cluster}-control-plane"
                    and isinstance(node["created"], str) and 0 < len(node["created"]) <= 64,
                    "invalid recorded node identity")
        if value["artifacts"] is not None:
            artifacts = value["artifacts"]
            require(isinstance(artifacts, dict)
                    and set(artifacts) == {"source_head", "source_tree", "manifest_sha256", "product_images"},
                    "invalid recorded artifact fields")
            require(isinstance(artifacts["source_head"], str) and HEX40.fullmatch(artifacts["source_head"])
                    and isinstance(artifacts["source_tree"], str) and HEX40.fullmatch(artifacts["source_tree"])
                    and isinstance(artifacts["manifest_sha256"], str) and HEX64.fullmatch(artifacts["manifest_sha256"]),
                    "invalid recorded artifact identity")
            self.validate_images(artifacts["product_images"])

    @staticmethod
    def validate_images(images: object) -> None:
        require(isinstance(images, dict) and set(images) == set(IMAGE_NAMES), "invalid product image set")
        require(all(isinstance(value, str) and IMAGE_ID.fullmatch(value) is not None
                    for value in images.values()), "invalid product image ID")

    def load(self, cluster: str) -> dict:
        value, _ = read_json(self.path(cluster) / "profile.json")
        self.validate(value, cluster, self.daemon)
        self.validate_mutable_paths(cluster)
        return value

    def save(self, value: dict) -> None:
        self.validate(value, value["cluster_name"], self.daemon)
        self.validate_mutable_paths(value["cluster_name"])
        write_json(self.path(value["cluster_name"]) / "profile.json", value)

    def validate_mutable_paths(self, cluster: str, *, allow_absent_run: bool = False) -> None:
        """Check paths handed to writers without opening any kubeconfig data."""
        descriptor = directory_fd(self.path(cluster))
        try:
            try:
                os.stat("run", dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError:
                require(allow_absent_run,
                        "profile run directory must be owned, private and without symlinks")
            else:
                try:
                    runtime = directory_fd(self.path(cluster) / "run")
                except (OSError, ProfileError) as error:
                    raise ProfileError("profile run directory must be owned, private and without symlinks") from error
                os.close(runtime)
            try:
                info = os.stat("kubeconfig", dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError:
                return
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                    and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1,
                    "existing profile kubeconfig must be owned, regular, mode 0600 and without links")
        finally:
            os.close(descriptor)

    def inherited_lock(self, path: Path, variable: str) -> int | None:
        value = os.environ.get(variable)
        if value is None:
            return None
        require(re.fullmatch(r"[0-9]{1,10}", value) is not None, "invalid inherited profile lock descriptor")
        descriptor = int(value)
        try:
            info = os.fstat(descriptor)
            with owned_file(path, writable=True) as expected:
                expected_info = os.fstat(expected)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                    and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
                    and (info.st_dev, info.st_ino) == (expected_info.st_dev, expected_info.st_ino),
                    "inherited lock belongs to another profile or publication registry")
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            raise ProfileError("inherited profile lock is unavailable") from error
        return descriptor

    @contextmanager
    def operation(self, cluster: str, *, publication: bool = False) -> Iterator[None]:
        paths = [(self.path(cluster) / "operation.lock", "KIND_PROFILE_LOCK_FD")]
        if publication:
            paths.append((self.root / "publication.lock", "KIND_BUILD_PUBLICATION_LOCK_FD"))
        from contextlib import ExitStack
        with ExitStack() as stack:
            for path, variable in paths:
                if self.inherited_lock(path, variable) is None:
                    descriptor = stack.enter_context(owned_file(path, writable=True))
                    acquire_lock(descriptor)
                    # A waiter may still hold the old inode after an explicit
                    # purge/reallocation. It must not control the new profile.
                    with owned_file(path, writable=True) as current:
                        require((os.fstat(current).st_dev, os.fstat(current).st_ino)
                                == (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino),
                                "owned operation lock was replaced while waiting")
            yield

    def list_profiles(self) -> dict:
        result = {"docker_id": self.daemon, "saved_profiles": [], "unmanaged_clusters": []}
        if self.root.exists() or self.root.is_symlink():
            with self.registry():
                if self.namespace.exists() or self.namespace.is_symlink():
                    descriptor = directory_fd(self.namespace)
                    os.close(descriptor)
                    entries = sorted(self.namespace.iterdir())
                    require(len(entries) <= 256, "saved profile inventory exceeds its bound")
                    for entry in entries:
                        cluster = cluster_name(entry.name)
                        value = self.load(cluster)
                        fields = self.environment(value)
                        reason = ""
                        if value["lifecycle"] == "bound":
                            try:
                                self.node(value)
                                runtime = "running"
                            except ProfileError as error:
                                runtime, reason = "attention", str(error)
                        elif self.docker.nodes(cluster):
                            runtime, reason = "attention", "saved profile has an unbound named node"
                        else:
                            runtime = "absent"
                        artifacts = value["artifacts"] or {}
                        result["saved_profiles"].append({
                            "cluster_name": cluster, "lifecycle": value["lifecycle"],
                            "runtime_state": runtime, "reason": reason,
                            "context": fields["KUBE_CONTEXT"], "kubeconfig": fields["KUBECONFIG"],
                            "profile_path": fields["KIND_PROFILE_PATH"],
                            "source_head": artifacts.get("source_head", ""),
                            "source_tree": artifacts.get("source_tree", ""),
                            "endpoints": {"http": fields["KIND_INGRESS_URL"],
                                          "tls": fields["KIND_INGRESS_TLS_URL"],
                                          "orchestration": fields["KIND_ORCHESTRATION_URL"],
                                          "coordinator": fields["KIND_COORDINATOR_DIRECT_URL"],
                                          "temporal": fields["KIND_TEMPORAL_ADDRESS"],
                                          "postgres": fields["KIND_DATABASE_URL"],
                                          "watch": fields["KIND_WATCH_ADDR"]}})
        managed = {value["cluster_name"] for value in result["saved_profiles"]}
        result["unmanaged_clusters"] = [name for name in self.docker.cluster_names() if name not in managed]
        require(self.docker.identity() == self.daemon, "Docker daemon identity changed while listing")
        return result

    def node(self, value: dict, *, allow_unbound: bool = False) -> Node | None:
        nodes = self.docker.nodes(value["cluster_name"])
        if value["lifecycle"] == "allocated" and allow_unbound:
            require(not nodes, "unbound profile cannot adopt an existing Kind node")
            return None
        require(value["lifecycle"] == "bound", "profile has no live recorded node")
        require(len(nodes) == 1, "recorded Kind node is missing or cluster topology changed")
        node = nodes[0]
        require(node.id == value["node"]["id"] and node.name == value["node"]["name"]
                and node.created == value["node"]["created"]
                and node.cluster == value["cluster_name"] and node.role == "control-plane"
                and node.running is True, "Kind node was replaced or has the wrong identity/state")
        return node

    def leased_ports(self) -> set[int]:
        ports: set[int] = set()
        for namespace in self.root.iterdir():
            if namespace.name in ("registry.lock", "publication.lock"):
                continue
            require(HEX64.fullmatch(namespace.name) is not None, "unknown profile registry entry")
            descriptor = directory_fd(namespace)
            os.close(descriptor)
            for entry in namespace.iterdir():
                cluster_name(entry.name)
                value, _ = read_json(entry / "profile.json")
                require(isinstance(value.get("docker_id"), str)
                        and hashlib.sha256(value["docker_id"].encode()).hexdigest() == namespace.name,
                        "profile is stored below the wrong Docker identity")
                self.validate(value, entry.name, value["docker_id"])
                require(not ports.intersection(value["ports"].values()), "saved profile port leases overlap")
                ports.update(value["ports"].values())
        return ports

    @staticmethod
    @contextmanager
    def free_ports(ports: dict[str, int] | None = None, *, excluded: set[int] | None = None) -> Iterator[dict]:
        sockets = []
        result = {}
        try:
            for name in PORT_NAMES:
                for _ in range(256):
                    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    try:
                        listener.bind(("127.0.0.1", ports[name] if ports else 0))
                    except OSError as error:
                        listener.close()
                        message = (f"saved {name} loopback port {ports[name]} is occupied; "
                                   "free that port or select another profile" if ports else
                                   "cannot allocate a free unprivileged profile port")
                        raise ProfileError(message) from error
                    port = listener.getsockname()[1]
                    if port < 1024 or (excluded and port in excluded):
                        listener.close()
                        continue
                    sockets.append(listener)
                    result[name] = port
                    break
                else:
                    raise ProfileError("cannot allocate a free unprivileged profile port")
            yield result
        finally:
            for listener in sockets:
                listener.close()

    def ensure(self, cluster: str, public: str | None = None, browser: str | None = None) -> dict:
        cluster = cluster_name(cluster)
        for key in ("CLUSTER", "KIND_CLUSTER_NAME"):
            require(not os.environ.get(key) or os.environ[key] == cluster,
                    "inherited cluster selector conflicts with selected profile")
        public = origin(public) if public is not None else None
        browser = origin(browser) if browser is not None else None
        with self.registry(create=True):
            profile = self.path(cluster)
            if profile.exists() or profile.is_symlink():
                value = self.load(cluster)
                self.inherited_lock(profile / "operation.lock", "KIND_PROFILE_LOCK_FD")
                require(public is None or value["origins"]["public"] == public,
                        "saved profile public origin cannot be overridden")
                require(browser is None or value["origins"]["browser_api"] == browser,
                        "saved profile browser API origin cannot be overridden")
                self.check_environment(value)
                # Deleted profiles keep their leases. Validate the complete
                # registry too, so a corrupted or manually overlapping saved
                # lease cannot be admitted just because no process binds it.
                self.leased_ports()
                if value["lifecycle"] == "deleted":
                    require(not self.docker.nodes(cluster),
                            "deleted profile cannot replace an existing named node")
                    with self.free_ports(value["ports"]):
                        if value["artifacts"] is not None:
                            self.artifact_manifest(value)
                        value["node"] = None
                        value["lifecycle"] = "allocated"
                        self.save(value)
                    return value
                self.node(value, allow_unbound=True)
                if value["lifecycle"] == "allocated":
                    with self.free_ports(value["ports"]):
                        pass
                return value
            require(os.environ.get("KIND_PROFILE_LOCK_FD") is None,
                    "cannot allocate another profile while inheriting a profile lock")
            require(not self.docker.nodes(cluster), "named cluster exists without an owned profile")
            leased = self.leased_ports()
            with self.free_ports(excluded=leased) as ports:
                value = {"schema": SCHEMA, "cluster_name": cluster, "docker_id": self.daemon,
                         "ownership_nonce": secrets.token_hex(16), "created_at": time.time_ns(),
                         "lifecycle": "allocated", "ports": ports,
                         "origins": {"public": public or f"http://127.0.0.1:{ports['watch']}",
                                     "browser_api": browser or f"http://127.0.0.1:{ports['http']}"},
                         "node": None, "artifacts": None}
                self.validate(value, cluster, self.daemon)
                self.check_environment(value)
                for path in (self.namespace, profile, profile / "run", profile / "artifacts"):
                    descriptor = directory_fd(path, create=True)
                    os.close(descriptor)
                for path in (profile / "operation.lock", self.root / "publication.lock"):
                    with owned_file(path, create=True, writable=True):
                        pass
                self.save(value)
                return value

    def manifest_path(self, value: dict) -> Path:
        artifacts = value["artifacts"]
        qualified = (f"{artifacts['source_head']}-{artifacts['source_tree']}"
                     if artifacts is not None else "unsealed")
        return self.path(value["cluster_name"]) / "artifacts" / qualified / "manifest.json"

    def artifact_manifest(self, value: dict, path: Path | None = None) -> tuple[dict, bytes]:
        path = path or self.manifest_path(value)
        manifest, raw = read_json(path, modes=(0o400,))
        require(set(manifest) == ARTIFACT_KEYS and manifest["schema"] == ARTIFACT_SCHEMA,
                "invalid artifact descriptor fields")
        for key in ("cluster_name", "docker_id", "ownership_nonce"):
            require(manifest[key] == value[key], "artifact ownership identity mismatch")
        require(isinstance(manifest["source_head"], str) and HEX40.fullmatch(manifest["source_head"])
                and isinstance(manifest["source_tree"], str) and HEX40.fullmatch(manifest["source_tree"]),
                "invalid artifact source identity")
        self.validate_images(manifest["product_images"])
        expected = self.path(value["cluster_name"]) / "artifacts" / (
            f"{manifest['source_head']}-{manifest['source_tree']}") / "manifest.json"
        require(path == expected, "artifact descriptor is outside its source-qualified profile directory")
        files = manifest["files"]
        require(isinstance(files, dict) and 1 <= len(files) <= 128, "invalid artifact file inventory")
        total = 0
        for name, contract in files.items():
            relative = PurePosixPath(name)
            require(isinstance(name, str) and 0 < len(name) <= 180 and not relative.is_absolute()
                    and name == relative.as_posix() and all(part not in ("", ".", "..") for part in relative.parts)
                    and re.fullmatch(r"[A-Za-z0-9_./-]+", name) is not None and name != "manifest.json",
                    "invalid artifact member path")
            require(isinstance(contract, dict) and set(contract) == {"sha256", "bytes", "mode"}
                    and isinstance(contract["sha256"], str) and HEX64.fullmatch(contract["sha256"])
                    and type(contract["bytes"]) is int and 0 <= contract["bytes"] <= 16 * 1024**3
                    and type(contract["mode"]) is int and contract["mode"] in (0o400, 0o500),
                    "invalid artifact member contract")
            total += contract["bytes"]
            with owned_file(path.parent / name, modes=(contract["mode"],)) as descriptor:
                require(os.fstat(descriptor).st_size == contract["bytes"], "sealed artifact file size differs")
        require(total <= 64 * 1024**3, "artifact inventory exceeds its byte bound")
        if value["artifacts"] is not None and path == self.manifest_path(value):
            saved = value["artifacts"]
            require(hashlib.sha256(raw).hexdigest() == saved["manifest_sha256"]
                    and manifest["source_head"] == saved["source_head"]
                    and manifest["source_tree"] == saved["source_tree"]
                    and manifest["product_images"] == saved["product_images"],
                    "sealed artifact descriptor differs from its admission")
        return manifest, raw

    def env(self, cluster: str) -> dict[str, str]:
        with self.registry():
            value = self.load(cluster)
            self.inherited_lock(self.path(cluster) / "operation.lock", "KIND_PROFILE_LOCK_FD")
            require(value["lifecycle"] != "deleted", "selected profile was explicitly deleted")
            if value["artifacts"] is not None:
                self.artifact_manifest(value)
            return self.environment(value)

    def check_environment(self, value: dict) -> None:
        fields = self.environment(value)
        for key in ENV_CONFLICT_KEYS:
            require(not os.environ.get(key) or os.environ[key] == fields[key],
                    "inherited endpoint or path conflicts with saved profile")

    def environment(self, value: dict) -> dict[str, str]:
        cluster = value["cluster_name"]
        profile = self.path(cluster)
        ports = value["ports"]
        artifacts = value["artifacts"] or {}
        manifest = self.manifest_path(value)
        result = {
                "KIND_PROFILE": "1", "KIND_PROFILE_PATH": str(profile / "profile.json"),
                "KIND_PROFILE_NONCE": value["ownership_nonce"], "KIND_PROFILE_DOCKER_ID": self.daemon,
                "KIND_PROFILE_STATE": value["lifecycle"], "KIND_PROFILE_LOCK_FILE": str(profile / "operation.lock"),
                "KIND_BUILD_PUBLICATION_LOCK_FILE": str(self.root / "publication.lock"),
                "KIND_CLUSTER_NAME": cluster, "KUBE_CONTEXT": f"kind-{cluster}",
                "KUBECONFIG": str(profile / "kubeconfig"), "KIND_CONFIG": str(profile / "kind-config.yaml"),
                "RUN_DIR": str(profile / "run"), "KIND_PROFILE_ARTIFACT_ROOT": str(profile / "artifacts"),
                "KIND_PROFILE_ARTIFACT_DIR": str(manifest.parent),
                "KIND_PROFILE_SMOKE_DIR": str(manifest.parent / "smokes"),
                "KIND_PROFILE_IMAGE_MANIFEST": str(manifest),
                "KIND_PROFILE_SOURCE_HEAD": artifacts.get("source_head", ""),
                "KIND_PROFILE_SOURCE_TREE": artifacts.get("source_tree", ""),
                "KIND_PROFILE_IMAGE_PREFIX": f"codewire-kind-{cluster}-{value['ownership_nonce'][:12]}",
                "KIND_INGRESS_URL": f"http://127.0.0.1:{ports['http']}",
                "KIND_INGRESS_TLS_URL": f"https://localhost:{ports['tls']}",
                "KIND_ORCHESTRATION_URL": f"http://127.0.0.1:{ports['orchestration']}",
                "KIND_COORDINATOR_DIRECT_URL": f"http://127.0.0.1:{ports['coordinator']}",
                "KIND_TEMPORAL_ADDRESS": f"http://127.0.0.1:{ports['temporal']}",
                "KIND_DATABASE_URL": f"postgres://codewire:codewire@127.0.0.1:{ports['postgres']}/codewire",
                "KIND_WATCH_ADDR": f"127.0.0.1:{ports['watch']}",
                "KIND_PUBLIC_ORIGIN": value["origins"]["public"],
                "KIND_BROWSER_API_ORIGIN": value["origins"]["browser_api"],
        }
        for name, key in (("http", "INGRESS_HTTP"), ("tls", "INGRESS_TLS"),
                          ("orchestration", "ORCHESTRATION"), ("coordinator", "COORDINATOR"),
                          ("temporal", "TEMPORAL"), ("postgres", "POSTGRES"), ("watch", "WATCH")):
            result[f"KIND_{key}_HOST_PORT"] = str(ports[name])
        result["KIND_INGRESS_HOST_PORT"] = result["KIND_INGRESS_HTTP_HOST_PORT"]
        result["KIND_COORDINATOR_DIRECT_HOST_PORT"] = result["KIND_COORDINATOR_HOST_PORT"]
        result["KIND_ORCHESTRATION_HTTP_URL"] = result["KIND_ORCHESTRATION_URL"]
        result["KIND_TEMPORAL_FRONTEND_URL"] = result["KIND_TEMPORAL_ADDRESS"]
        for image in IMAGE_NAMES:
            result[f"KIND_PROFILE_{image.upper()}_IMAGE_ID"] = artifacts.get("product_images", {}).get(image, "")
        return result

    def verify_node(self, cluster: str) -> dict:
        with self.operation(cluster), self.registry():
            value = self.load(cluster)
            self.node(value)
            return value

    def record_node(self, cluster: str, nonce: str, identifier: str) -> dict:
        require(HEX64.fullmatch(identifier) is not None, "invalid requested node ID")
        with self.operation(cluster), self.registry():
            value = self.load(cluster)
            require(nonce == value["ownership_nonce"], "profile ownership nonce mismatch")
            if value["lifecycle"] == "bound":
                self.node(value)
                require(value["node"]["id"] == identifier, "recorded node ID cannot be replaced")
                return value
            require(value["lifecycle"] == "allocated", "deleted profile cannot adopt a node")
            nodes = self.docker.nodes(cluster)
            require(len(nodes) == 1, "selected cluster must have exactly one created node")
            node = nodes[0]
            require(node.id == identifier and node.name == f"{cluster}-control-plane"
                    and node.cluster == cluster and node.role == "control-plane" and node.running is True
                    and isinstance(node.created, str) and 0 < len(node.created) <= 64,
                    "created Kind node identity mismatch")
            value["node"] = {"id": node.id, "name": node.name, "created": node.created}
            value["lifecycle"] = "bound"
            self.save(value)
            return value

    def mark_deleted(self, cluster: str, nonce: str) -> dict:
        with self.operation(cluster), self.registry():
            value = self.load(cluster)
            require(value["ownership_nonce"] == nonce, "profile ownership nonce mismatch")
            require(value["lifecycle"] in ("bound", "deleted"), "unbound profile has no node to retire")
            require(not self.docker.nodes(cluster), "refusing to mark a live or replacement node deleted")
            value["lifecycle"] = "deleted"
            self.save(value)
            return value

    def purge(self, cluster: str, nonce: str) -> dict:
        with self.operation(cluster), self.registry():
            # A guarded partial purge may already have removed run/. Read the
            # strict controls first; only this nonce-bound retirement may resume.
            value, _ = read_json(self.path(cluster) / "profile.json")
            self.validate(value, cluster, self.daemon)
            require(value["ownership_nonce"] == nonce, "profile ownership nonce mismatch")
            require(value["lifecycle"] in ("allocated", "deleted"),
                    "bound profile must be explicitly stopped before purge")
            self.validate_mutable_paths(cluster, allow_absent_run=True)
            require(not self.docker.nodes(cluster), "profile purge refuses a live or replacement named node")
            with self.free_ports(value["ports"]):
                directory = directory_fd(self.path(cluster))
                parent = directory_fd(self.namespace)
                try:
                    deadline = time.monotonic() + 30
                    root = os.fstat(directory)
                    links: dict = {}
                    inventory = inspect_private_tree(directory, deadline=deadline, budget=[8192], links=links,
                                                     directories={(root.st_dev, root.st_ino)})
                    require(all(seen == first.st_nlink for first, seen in links.values()),
                            "profile purge refuses links outside the private profile")
                    info = os.stat(cluster, dir_fd=parent, follow_symlinks=False)
                    require((info.st_dev, info.st_ino) == (os.fstat(directory).st_dev, os.fstat(directory).st_ino),
                            "profile directory changed before purge")
                    remove_private_tree(directory, inventory, deadline=deadline,
                                        links={identity: (first.st_nlink, first.st_ctime_ns)
                                               for identity, (first, _) in links.items()})
                    os.rmdir(cluster, dir_fd=parent)
                    os.fsync(parent)
                finally:
                    os.close(directory)
                    os.close(parent)
            return {"cluster_name": cluster, "purged": True}

    def record_artifacts(self, cluster: str, nonce: str, manifest_path: Path) -> dict:
        with self.operation(cluster, publication=True), self.registry():
            value = self.load(cluster)
            require(nonce == value["ownership_nonce"] and value["lifecycle"] != "deleted",
                    "artifact profile ownership/lifecycle mismatch")
            manifest, raw = self.artifact_manifest(value, manifest_path.absolute())
            require(self.docker.image_ids() == manifest["product_images"],
                    "sealed artifact image IDs differ from the admitted :e2e producer outputs")
            value["artifacts"] = {key: manifest[key] for key in ("source_head", "source_tree", "product_images")}
            value["artifacts"]["manifest_sha256"] = hashlib.sha256(raw).hexdigest()
            self.save(value)
            return value

    def verify_artifacts(self, cluster: str) -> dict:
        with self.operation(cluster):
            with self.registry():
                value = self.load(cluster)
                require(value["artifacts"] is not None, "profile has no admitted immutable artifacts")
                manifest, _ = self.artifact_manifest(value)
                root = self.manifest_path(value).parent
            deadline = time.monotonic() + 120
            for name, contract in manifest["files"].items():
                digest = hashlib.sha256()
                count = 0
                with owned_file(root / name, modes=(contract["mode"],)) as descriptor:
                    while chunk := os.read(descriptor, 1024 * 1024):
                        require(time.monotonic() < deadline, "artifact verification exceeded its deadline")
                        count += len(chunk)
                        require(count <= contract["bytes"], "sealed artifact grew during verification")
                        digest.update(chunk)
                require(count == contract["bytes"] and digest.hexdigest() == contract["sha256"],
                        "sealed artifact bytes differ from their admission")
            return value

    def render_config(self, cluster: str, template: Path) -> Path:
        with template.open("rb") as stream:
            data = stream.read(JSON_BOUND + 1)
        require(len(data) <= JSON_BOUND, "Kind config template exceeds its bound")
        text = data.decode()
        with self.operation(cluster), self.registry():
            value = self.load(cluster)
            self.node(value, allow_unbound=True)
            if value["lifecycle"] == "allocated":
                with self.free_ports(value["ports"]):
                    pass
            # Named host mappings bind only loopback. Node ports, Host/SNI and
            # the complete suite topology remain unchanged.
            replacements = {original: value["ports"][name] for name, original in DEFAULT_PORTS.items()}
            text = render_host_ports(text, replacements, bind_loopback=True)
            path = self.path(cluster) / "kind-config.yaml"
            if path.exists() or path.is_symlink():
                with owned_file(path):
                    pass
            atomic_write(path, text.encode())
            return path


def default_root() -> Path:
    if override := os.environ.get("CODEWIRE_KIND_PROFILE_ROOT"):
        return Path(override).absolute()
    state = Path(os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local/state")))
    return state / "codewire/kind-profiles"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=default_root())
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("build-lock-path")
    listing = commands.add_parser("list")
    listing.add_argument("--format", choices=("table", "json"), default="table")
    for command in ("ensure", "env", "render-config", "record-node", "verify-node",
                    "record-artifacts", "verify-artifacts", "mark-deleted", "purge"):
        sub = commands.add_parser(command)
        sub.add_argument("--cluster", required=True)
        if command in ("record-node", "record-artifacts", "mark-deleted", "purge"):
            sub.add_argument("--nonce", required=True)
        if command == "ensure":
            sub.add_argument("--public-origin")
            sub.add_argument("--browser-api-origin")
        if command == "env":
            sub.add_argument("--format", choices=("json", "nul"), default="json")
        if command == "record-node":
            sub.add_argument("--node-id", required=True)
        if command == "record-artifacts":
            sub.add_argument("--manifest", required=True, type=Path)
        if command == "render-config":
            sub.add_argument("--template", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        cluster = cluster_name(arguments.cluster) if arguments.command not in ("build-lock-path", "list") else None
        profiles = Profiles(arguments.root)
        if arguments.command == "build-lock-path":
            print(profiles.build_lock_path())
            return 0
        if arguments.command == "list":
            result = profiles.list_profiles()
            if arguments.format == "table":
                print("CLUSTER  LIFECYCLE  RUNTIME  CONTEXT  SOURCE")
                for value in result["saved_profiles"]:
                    source = value["source_head"][:12] or "unsealed"
                    print(f"{value['cluster_name']}  {value['lifecycle']}  {value['runtime_state']}  "
                          f"{value['context']}  {source}")
                    print("  " + "  ".join(f"{key}={endpoint}" for key, endpoint in value["endpoints"].items()))
                    if value["reason"]:
                        print(f"  {value['reason']}")
                if result["unmanaged_clusters"]:
                    print("Unmanaged Kind clusters: " + ", ".join(result["unmanaged_clusters"]))
                return 0
            print(json.dumps(result, sort_keys=True, separators=(",", ":")))
            return 0
        match arguments.command:
            case "ensure":
                result = profiles.ensure(cluster, arguments.public_origin, arguments.browser_api_origin)
            case "env":
                result = profiles.env(cluster)
                if arguments.format == "nul":
                    for key, value in result.items():
                        sys.stdout.buffer.write(key.encode() + b"\0" + value.encode() + b"\0")
                    return 0
            case "render-config":
                result = {"KIND_CONFIG": str(profiles.render_config(cluster, arguments.template))}
            case "record-node":
                result = profiles.record_node(cluster, arguments.nonce, arguments.node_id)
            case "verify-node":
                result = profiles.verify_node(cluster)
            case "record-artifacts":
                result = profiles.record_artifacts(cluster, arguments.nonce, arguments.manifest)
            case "verify-artifacts":
                result = profiles.verify_artifacts(cluster)
            case "mark-deleted":
                result = profiles.mark_deleted(cluster, arguments.nonce)
            case "purge":
                result = profiles.purge(cluster, arguments.nonce)
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except ProfileError as error:
        # ProfileError messages are fixed checked-in reasons. The sole dynamic
        # fields are validated endpoint names and numeric loopback ports.
        print(f"cluster-profile: {error}", file=sys.stderr)
        return 2
    except (OSError, ValueError, KeyError, TypeError):
        # Never reflect arbitrary metadata, filesystem errors or Docker stderr.
        print("cluster-profile: selected profile, identity or artifact admission is invalid", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
