#!/usr/bin/env python3
"""Local, non-publishing workspace-image identity; never accept a caller image override."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import selectors
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid
from contextlib import closing


INPUTS = (
    "images/base/Dockerfile", "images/workspace/Dockerfile", ".dockerignore",
    "scripts/ci/verify/workspace-agent-contract.sh",
    "scripts/ci/verify/verify-workspace-image.sh",
    "scripts/ci/verify/workspace-image-artifact.py",
    "scripts/ci/images/workspace-cache.sh",
    "scripts/ci/images/run-rust-build.sh",
    "scripts/ci/setup/select-untrusted-workspace-cache.sh",
    "scripts/ci/setup/select-workspace-cache-experiment.py",
    "scripts/ci/setup/prepare-workspace-cache-measurement.sh",
    "scripts/ci/verify/workspace-cache-report.py",
    "images/cw-runtime/Dockerfile",
    "rust-toolchain.toml",
    "scripts/ci/release/cw_release.py",
    "scripts/dev/cw-runtime-image.py",
    "scripts/ci/images/prepare-cw-source-context.py",
    "scripts/ci/images/build-cw-runtime-source.py",
    "scripts/ci/images/finalize-cw-runtime-source.py",
    "scripts/ci/images/prepare-cw-image-context.py",
    "scripts/ci/images/cw-image-consumer.py",
    "scripts/ci/images/cw-image-consumer.sh",
    "scripts/ci/images/cw-image-source.py",
    "scripts/ci/images/build-product-images.sh",
    "scripts/ci/verify/build-linux-vmm-kernel.py",
    "images/base/apt-transport.conf",
    "images/base/apt-get-with-retry",
    "images/workspace/debian.sources",
    ".gitignore",
)
MAXIMUM_ARCHIVE_BYTES = 80 * 1024 * 1024 * 1024
MAXIMUM_DOCUMENT_BYTES = 4 * 1024 * 1024
# A Docker command that neither writes output nor exits for this long is hung.
# Output restarts the bound, so a slow but progressing copy is never cut short,
# and the producer's local admission before the copy never spends it.
CW_STALL_SECONDS = 120
CW_CLEANUP_SECONDS = 30
CW_STDERR_BYTES = 64 * 1024
CW_COPY_LABEL = "dev.codewire.workspace-cw-verification"
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
    validate_image_value(identity, image_id, image)


def validate_image_value(identity, image_id, image):
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


def cw_consumer(root):
    # Loading is confined to this operation. Receipt/OCI-only callers do not
    # import a producer or execute any incoming payload.
    path = root / "scripts/ci/images/cw-image-consumer.py"
    spec = importlib.util.spec_from_file_location("workspace_cw_consumer", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def cw_docker_environment(directory):
    environment = {"PATH": "/usr/bin:/bin", "HOME": str(directory / "home"),
                   "DOCKER_CONFIG": str(directory / "docker"), "TMPDIR": str(directory / "tmp"),
                   "LC_ALL": "C", "TZ": "UTC"}
    # This uses the caller's existing daemon transport, never its registry
    # login, cache credentials, proxy, provider environment or Docker context.
    if os.environ.get("DOCKER_CONTEXT", "default") not in ("", "default"):
        raise ValueError("workspace CW copy requires an explicit Docker transport")
    for key in ("DOCKER_HOST", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "DOCKER_API_VERSION"):
        if key in os.environ:
            value = os.environ[key]
            if not value or len(value.encode()) > 4096 or any(ord(c) < 32 or ord(c) == 127 for c in value):
                raise ValueError("workspace CW Docker transport is invalid")
            environment[key] = value
    return environment


class CwCopyOwner:
    """One fixed image read; separate bounded pipes and kernel family custody.

    Docker's container is owned separately from its CLI process. Failure does
    not grant name-prefix cleanup authority or imply that the container died.
    """

    def __init__(self, consumer, directory, image_id):
        self.consumer, self.owner, self.asset = consumer, consumer.owner, consumer.asset
        self.directory, self.image_id = directory, image_id
        self.token = uuid.uuid4().hex
        self.name = "codewire-workspace-cw-" + self.token
        self.cidfile = directory / "cid"
        self.docker = os.environ.get("CODEWIRE_DOCKER_BIN", "docker")
        if (not self.docker or len(self.docker.encode()) > 4096
                or any(ord(c) < 32 or ord(c) == 127 for c in self.docker)):
            raise ValueError("workspace CW Docker executable is invalid")
        self.environment = cw_docker_environment(directory)
        self.outcomes = []
        self.started = False
        self.container_clean = False
        self.cleanup_deadline = None
        self.private_directories = {}
        self.parent = self.asset.Parent(directory)
        try:
            info = os.fstat(self.parent.fd)
            if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise ValueError("workspace CW copy directory is not private")
            for name in ("home", "docker", "tmp"):
                os.mkdir(name, mode=0o700, dir_fd=self.parent.fd)
                self.private_directories[name] = self.asset.Parent(directory / name)
        except BaseException:
            self.close()
            raise

    def revalidate(self):
        self.parent.revalidate()
        info = os.fstat(self.parent.fd)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("workspace CW copy directory changed")
        for name, held in self.private_directories.items():
            held.revalidate()
            info = os.fstat(held.fd)
            if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise ValueError("workspace CW private environment directory changed")
            if name == "docker" and os.listdir(held.fd):
                raise ValueError("workspace CW Docker configuration is not empty")

    def check(self, deadline, cleanup, action):
        if not cleanup and self.owner.STOP is not None:
            raise ValueError("workspace CW copy was cancelled")
        if time.monotonic() >= deadline:
            raise ValueError(f"workspace CW container cleanup exceeded its {CW_CLEANUP_SECONDS} s bound"
                             if cleanup else f"workspace CW {action} made no progress for {CW_STALL_SECONDS} s")

    def run(self, arguments, maximum, consume=None, *, cleanup_deadline=None):
        self.revalidate()
        cleanup = cleanup_deadline is not None
        action = "docker " + arguments[0]
        deadline = cleanup_deadline if cleanup else time.monotonic() + CW_STALL_SECONDS
        self.check(deadline, cleanup, action)
        command = [self.docker, *arguments]
        output, count, error_count = bytearray(), 0, 0
        output_sha, error_sha = hashlib.sha256(), hashlib.sha256()
        adopted, leader, process = {}, None, None
        selector = selectors.DefaultSelector()
        try:
            process = subprocess.Popen(command, cwd=self.directory, env=self.environment,
                                       stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, start_new_session=True, umask=0o077)
            leader = self.owner.bind_child(process.pid)
            for stream, kind in ((process.stdout, "out"), (process.stderr, "err")):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, kind)
            while True:
                terminal = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                if terminal and not selector.get_map():
                    break
                self.check(deadline, cleanup, action)
                for event, _ in selector.select(min(0.05, max(0, deadline - time.monotonic()))):
                    if not cleanup:
                        deadline = time.monotonic() + CW_STALL_SECONDS
                    block = os.read(event.fileobj.fileno(), 64 * 1024)
                    if not block:
                        selector.unregister(event.fileobj)
                    elif event.data == "out":
                        count += len(block)
                        if count > maximum:
                            raise ValueError("workspace CW command stdout exceeded its bound")
                        output_sha.update(block)
                        if consume is None:
                            output.extend(block)
                        else:
                            consume(block)
                    else:
                        error_count += len(block)
                        if error_count > CW_STDERR_BYTES:
                            raise ValueError("workspace CW command stderr exceeded its bound")
                        error_sha.update(block)
            # Keep the unreaped leader until every possible group signal is
            # finished. Normal completion with an adopted child is a failure.
            if self.owner.children() != {process.pid}:
                raise ValueError("workspace CW command left an unexpected family")
            status = process.wait()
            try:
                os.waitpid(-1, os.WNOHANG | self.owner.WALL)
            except ChildProcessError:
                pass
            else:
                raise ValueError("workspace CW command did not prove ECHILD")
            self.outcomes.append({"action": arguments[0], "exit": status, "stdout_size": count,
                                  "stdout_sha256": output_sha.hexdigest(), "stderr_size": error_count,
                                  "stderr_sha256": error_sha.hexdigest(), "family_cleanup_known": True})
            if status != 0:
                raise ValueError("workspace CW command failed")
            return bytes(output), count, output_sha.hexdigest()
        except BaseException:
            if self.cleanup_deadline is None:
                self.cleanup_deadline = time.monotonic() + CW_CLEANUP_SECONDS
            raise
        finally:
            try:
                if process is not None:
                    remaining = (CW_CLEANUP_SECONDS if self.cleanup_deadline is None
                                 else max(0.001, self.cleanup_deadline - time.monotonic()))
                    self.owner.abort_family(process, adopted, remaining)
            finally:
                if leader is not None:
                    os.close(leader)
                for fd in adopted.values():
                    os.close(fd)
                selector.close()
                if process is not None:
                    process.stdout.close()
                    process.stderr.close()
                self.revalidate()

    def image(self):
        raw, _, _ = self.run(["image", "inspect", self.image_id], 512 * 1024)
        images = json.loads(raw)
        if type(images) is not list or len(images) != 1 or type(images[0]) is not dict:
            raise ValueError("workspace CW requires one image")
        return images[0]

    def cid(self):
        with closing(self.asset.HeldFile(self.cidfile, 65)) as held:
            if held.metadata["uid"] != os.geteuid() or stat.S_IMODE(held.metadata["mode"]) != 0o600:
                raise ValueError("workspace CW CID file is not private")
            value = held.data.decode("ascii")
            if not re.fullmatch(r"[0-9a-f]{64}\n?", value):
                raise ValueError("workspace CW CID is invalid")
            held.revalidate(content=True)
            return value.rstrip("\n")

    def copy(self, expected_size):
        self.started = True
        _, size, sha256 = self.run([
            "run", "--rm", "--pull=never", "--network=none", "--read-only", "--user", "1000:1000",
            "--name", self.name, "--cidfile", str(self.cidfile),
            "--label", CW_COPY_LABEL + "=" + self.token,
            "--entrypoint", "/usr/bin/cat", self.image_id, "/usr/local/bin/cw",
        ], expected_size + 1, lambda _: None)
        self.cid()
        if size != expected_size:
            raise ValueError("workspace image CW length differs from its producer")
        return sha256

    def cleanup_container(self):
        if not self.started:
            self.container_clean = True
            return
        if self.cleanup_deadline is None:
            self.cleanup_deadline = time.monotonic() + CW_CLEANUP_SECONDS
        deadline = self.cleanup_deadline
        arguments = ["container", "ls", "--all", "--no-trunc", "--filter",
                     "name=^/" + self.name + "$", "--format", "{{.ID}}"]
        raw, _, _ = self.run(arguments, 65, cleanup_deadline=deadline)
        if not raw:
            self.container_clean = True
            return
        if not re.fullmatch(rb"[0-9a-f]{64}\n", raw):
            raise ValueError("workspace CW container cleanup is unknown")
        cid = raw.decode().rstrip("\n")
        if os.path.lexists(self.cidfile) and self.cid() != cid:
            raise ValueError("workspace CW container CID changed")
        raw, _, _ = self.run(["container", "inspect", cid], 512 * 1024, cleanup_deadline=deadline)
        values = json.loads(raw)
        if type(values) is not list or len(values) != 1 or type(values[0]) is not dict:
            raise ValueError("workspace CW container identity is unknown")
        value = values[0]
        config = value.get("Config", {})
        if (value.get("Id") != cid or value.get("Image") != self.image_id
                or value.get("Name") != "/" + self.name or type(config) is not dict
                or config.get("Image") != self.image_id or type(config.get("Labels")) is not dict
                or config["Labels"].get(CW_COPY_LABEL) != self.token):
            raise ValueError("workspace CW container identity changed")
        raw, _, _ = self.run(["rm", "--force", cid], 65, cleanup_deadline=deadline)
        if raw != (cid + "\n").encode():
            raise ValueError("workspace CW container removal is unknown")
        raw, _, _ = self.run(arguments, 65, cleanup_deadline=deadline)
        if raw:
            raise ValueError("workspace CW container remained after cleanup")
        self.container_clean = True

    def evidence(self, accepted):
        self.revalidate()
        data = json.dumps({"accepted": accepted, "container_cleanup_known": self.container_clean,
                           "image_id": self.image_id, "container_name": self.name,
                           "operation_id": self.token, "commands": self.outcomes}, sort_keys=True).encode() + b"\n"
        fd = os.open("outcome.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o400, dir_fd=self.parent.fd)
        with os.fdopen(fd, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.fsync(self.parent.fd)

    def close(self):
        for held in self.private_directories.values():
            held.close()
        self.parent.close()


# The Cargo profile of the verified amd64 cw producer. It is fixed here, not
# taken from the producer pointer, and equals WORKSPACE_CW_PROFILE in
# scripts/ci/images/workspace-cache.sh. Publication builds the same profile.
WORKSPACE_CW_PROFILE = "runtime"


def verify_cw(root, image_id, result_path):
    """Reopen the original compiler proof, then compare actual image bytes.

    This makes no cache claim, executes no incoming CW, and does not rewrite
    the original source identity or create a reusable independent acceptance.
    """
    previous_bytecode = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        consumer = cw_consumer(root)
        try:
            return verify_cw_admitted(consumer, root, image_id, result_path)
        except consumer.release.ReleaseError as error:
            raise ValueError(f"workspace CW producer admission failed: {error}") from None
    finally:
        sys.dont_write_bytecode = previous_bytecode


def verify_cw_admitted(consumer, root, image_id, result_path):
    producer, asset = consumer.producer, consumer.asset
    result_path = asset.path_arg(str(result_path))
    if result_path.name != "cw-producer-result.json" or result_path.parent.name != "cw-image-work":
        raise ValueError("workspace CW producer reference path is invalid")
    with closing(asset.HeldFile(result_path, producer.release.MAX_JSON)) as held:
        if held.metadata["uid"] != os.geteuid() or stat.S_IMODE(held.metadata["mode"]) != 0o400:
            raise ValueError("workspace CW producer reference is not private")
        parent_info = os.fstat(held.parent.fd)
        if parent_info.st_uid != os.geteuid() or stat.S_IMODE(parent_info.st_mode) != 0o700:
            raise ValueError("workspace CW producer reference directory is not private")
        value = producer.release.parse_canonical(held.data)
        fields = {"status", "receipt", "producer_receipt", "image", "index_sha256", "payload", "source",
                  "profile", "version", "build_ref", "cache_qualified", "image_qualified"}
        if type(value) is not dict or set(value) != fields or value["status"] != "producer-admitted":
            raise ValueError("workspace CW producer reference is invalid")
        version = consumer.effective_version(root, os.environ.get("CODEWIRE_VERSION"))
        with producer.source.git_scope():
            identity = source_identity(root)
        if identity["architecture"] != "amd64":
            raise ValueError("workspace static CW verification requires AMD64")
        selected_image = digest(image_id)
        saved_handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
        old_stop = consumer.owner.STOP
        for sig in saved_handlers:
            signal.signal(sig, consumer.owner.on_signal)
        owner = None
        accepted = False
        try:
            # Admission reads only local files and bounded Git calls, as every
            # reopen does. Only the Docker commands below have a stall bound.
            with producer.reopen(value["receipt"]["path"], value["receipt"]["sha256"], root,
                                 identity["source_sha"], WORKSPACE_CW_PROFILE, version) as admitted:
                summary = admitted.summary
                if any(producer.release.canonical(value[key]) != producer.release.canonical(summary[key])
                       for key in fields):
                    raise ValueError("workspace CW reference differs from its original producer")
                held.revalidate(content=True)
                admitted.revalidate()
                consumer.owner.arm_custody()
                directory = Path(tempfile.mkdtemp(prefix=".workspace-cw-copy-", dir=result_path.parent))
                owner = CwCopyOwner(consumer, directory, selected_image)
                try:
                    validate_image_value(identity, selected_image, owner.image())
                    actual_sha = owner.copy(summary["payload"]["size"])
                    if actual_sha != summary["payload"]["sha256"]:
                        raise ValueError("workspace image CW differs from its producer")
                    admitted.revalidate()
                    held.revalidate(content=True)
                    with producer.source.git_scope():
                        if source_identity(root) != identity:
                            raise ValueError("workspace source changed during CW verification")
                    if consumer.owner.STOP is not None:
                        raise ValueError("workspace CW copy was cancelled")
                finally:
                    owner.cleanup_container()
                admitted.revalidate()
                held.revalidate(content=True)
                if consumer.owner.STOP is not None:
                    raise ValueError("workspace CW copy was cancelled")
                accepted = True
                return {"status": "workspace-cw-verified", "workspace_image_id": selected_image,
                        "payload": summary["payload"], "source": summary["source"],
                        "current_source": summary["current_source"], "profile": summary["profile"], "version": version,
                        "producer_receipt_sha256": summary["receipt"]["sha256"],
                        "family_cleanup_known": True, "container_cleanup_known": True}
        finally:
            try:
                if owner is not None:
                    try:
                        owner.evidence(accepted and owner.container_clean)
                    finally:
                        owner.close()
            finally:
                consumer.owner.STOP = old_stop
                for sig, handler in saved_handlers.items():
                    signal.signal(sig, handler)


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


PLANNER = "scripts/ci/plan/planner.py"
PLANNED_ARTIFACT = "workspace_image_verification"
UNAFFECTED_SCHEMA = "codewire.workspace-image-unaffected/v1"


def unaffected_record_path(receipt):
    return receipt.with_name(receipt.name + ".unaffected")


# A build can read these, so a change here always rebuilds the image locally,
# even when the planner's fingerprint of the image is unchanged.
BUILD_READABLE_ROOTS = ("crates/", "apps/", "packages/", "proto/", "libs/", "images/", ".cargo/")
BUILD_READABLE_FILES = {"Cargo.toml", "Cargo.lock", "rust-toolchain.toml", ".dockerignore", ".gitignore"}


def build_readable(path):
    return path in BUILD_READABLE_FILES or path.startswith(BUILD_READABLE_ROOTS) or "/" not in path


def load_planner(root):
    name = "workspace_receipt_planner"
    spec = importlib.util.spec_from_file_location(name, root / PLANNER)
    planner = importlib.util.module_from_spec(spec)
    # The planner's dataclasses resolve their module through sys.modules.
    sys.modules[name] = planner
    try:
        spec.loader.exec_module(planner)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return planner


def planner_unaffected(root, receipt_source, head):
    """Whether the canonical artifact planner proves the workspace image unchanged.

    `workspace_image_verification` covers the image definition, its verifier,
    contract and build tooling, and the Rust closure of the `cw` it carries. It
    is unchanged when the planner classifies it unaffected, or when its
    fingerprint is unchanged and every changed path lies outside anything a
    build can read: the planner leaves a path it has no ownership rule for
    (a new test, say) unclassified, which selects CI work but says nothing about
    this image. A policy change, an unclassifiable fingerprint, or a receipt
    commit that is not the merge base of the head is treated as changed.
    """
    planner = load_planner(root)
    try:
        document = planner.plan(root, receipt_source, head)
        baseline = document.get("baseline") if isinstance(document, dict) else None
        artifacts = document.get("artifacts") if isinstance(document, dict) else None
        if not isinstance(baseline, dict) or not isinstance(artifacts, dict):
            return False
        if baseline.get("baseline_commit") != receipt_source or baseline.get("head_commit") != head:
            return False
        planned = artifacts.get(PLANNED_ARTIFACT)
        if not isinstance(planned, dict):
            return False
        if planned.get("state") == "unaffected":
            return True
        before, after = planned.get("baseline_fingerprint"), planned.get("head_fingerprint")
        if not isinstance(before, str) or not re.fullmatch(r"[0-9a-f]{64}", before) or before != after:
            return False
        return not any(build_readable(path) for path in planner.changed_paths(root, receipt_source, head))
    except planner.PlannerError:
        return False


def read_unaffected_record(path):
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    with os.fdopen(descriptor, "rb") as source:
        info = os.fstat(source.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or info.st_size > 4096):
            return None
        raw = source.read(4097)
    try:
        value = json.loads(raw)
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


def write_unaffected_record(path, value):
    descriptor, temporary = tempfile.mkstemp(prefix=".workspace-image-unaffected-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w") as output:
            json.dump(value, output, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None and os.path.exists(temporary):
            os.unlink(temporary)


def unaffected_since_receipt(root, receipt, raw, receipt_source, current):
    """Accept a verified image for a different tree only when nothing it is built from changed.

    The planner's answer is recorded next to the receipt for this exact receipt
    and tree, so repeated consumers of one checkout pay for it once.
    """
    record_path = unaffected_record_path(receipt)
    expected = {
        "schema": UNAFFECTED_SCHEMA,
        "receipt_sha256": hashlib.sha256(raw).hexdigest(),
        "receipt_source_sha": receipt_source,
        "source_tree": current["source_tree"],
        "artifact": PLANNED_ARTIFACT,
    }
    if read_unaffected_record(record_path) == expected:
        return True
    if not planner_unaffected(root, receipt_source, current["source_sha"]):
        return False
    try:
        write_unaffected_record(record_path, expected)
    except OSError:
        print("workspace image artifact: unaffected decision not recorded", file=sys.stderr)
    return True


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
    # Identical committed content can retain proof across a merge commit. A
    # different tree retains it only while the planner proves every input of
    # the verified image unchanged; the verifier's own inputs must match.
    original_tree = command("git", "-C", str(root), "rev-parse", value["source_sha"] + "^{tree}")
    for key in current:
        if key not in ("source_sha", "source_tree") and value[key] != current[key]:
            raise ValueError("receipt source/input mismatch")
    if original_tree != value["source_tree"]:
        raise ValueError("receipt source commit mismatch")
    if value["source_tree"] != current["source_tree"] \
            and not unaffected_since_receipt(root, receipt, raw, value["source_sha"], current):
        raise ValueError("receipt source/input mismatch")
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
    elif mode == "verify-cw" and len(args) == 2:
        print(json.dumps(verify_cw(root, args[0], Path(args[1])), sort_keys=True))
    elif mode == "seal" and len(args) in (4, 5):
        prior = Path(args[4]) if len(args) == 5 else None
        print(seal(root, Path(args[0]), args[1], args[2], Path(args[3]), prior))
    else:
        raise ValueError("arguments")


REUSE_MODES = ("reuse", "native-input", "reuse-for-build")


def failure(mode, error):
    """Name the step's own cause: a hung copy must not read as a mismatch."""
    reason = str(error) if isinstance(error, ValueError) else f"{type(error).__name__}: {error}"
    reason = " ".join(reason.split())[:400]
    if mode in REUSE_MODES:
        return "no matching verified image: " + reason
    return (mode if mode in ("identity", "verify-cw", "seal") else "command") + " failed: " + reason


def cli(argv):
    try:
        main(argv)
    except (ValueError, OSError, KeyError, TypeError, AttributeError, tarfile.TarError,
            subprocess.CalledProcessError) as error:
        print("workspace image artifact: " + failure(argv[0] if argv else "", error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(cli(sys.argv[1:]))
