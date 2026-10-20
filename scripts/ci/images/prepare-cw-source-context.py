#!/usr/bin/env python3
"""Capture a selected checkout as a bounded, nonsecret CW build context.

The Git capsule contains real SHA-1 commit/tree/blob objects and a normalized
stage-zero index. It contains no copied Git configuration, hooks, remotes,
alternates, reflogs or credentials. Worktree edits retain their own source
digest; the selected HEAD is never relabelled as the edited tree.

prepare() returns a held SourceContext. Revalidate it immediately before the
compiler solve and afterwards. A receipt is source admission, not build proof.
"""

import argparse
import contextlib
import hashlib
import importlib.util
import os
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import sys
import time
import zlib


ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location("cw_source_asset_context", ROOT / "scripts/ci/images/prepare-cw-image-context.py")
asset = importlib.util.module_from_spec(spec)
previous_bytecode = sys.dont_write_bytecode
sys.dont_write_bytecode = True
try:
    spec.loader.exec_module(asset)
finally:
    sys.dont_write_bytecode = previous_bytecode
del previous_bytecode
release = asset.release
Refused = asset.Refused
require = asset.require

SCHEMA = "codewire.cw.source-context/v1"
TARGET = "x86_64-unknown-linux-musl"
MAX_FILE = 64 * 1024 * 1024
MAX_TOTAL = 512 * 1024 * 1024
MAX_FILES = 16384
MAX_OBJECTS = 65536
MAX_DOCUMENT = 16 * 1024 * 1024
MAX_GIT_REPLY = 16 * 1024 * 1024
# A Git call that neither reads its input nor writes output for this long is
# hung. Progress restarts the bound, so a large bounded read is never cut short.
GIT_STALL_SECONDS = 60
PREREQUISITES = (
    ".gitignore", "Cargo.toml", "Cargo.lock", "rust-toolchain.toml",
    "images/cw-runtime/Dockerfile", "images/workspace/debian.sources",
    "images/base/apt-transport.conf", "images/base/apt-get-with-retry",
    "scripts/ci/images/run-rust-build.sh", "scripts/ci/images/prepare-cw-image-context.py",
    "scripts/ci/images/prepare-cw-source-context.py", "scripts/ci/images/build-cw-runtime-source.py",
    "scripts/ci/images/finalize-cw-runtime-source.py", "scripts/ci/release/cw_release.py",
    "scripts/dev/cw-runtime-image.py", "scripts/ci/verify/build-linux-vmm-kernel.py",
)
# These owning producer inputs must be added to the shared source pathspec by
# its owner before this route can compile. A prerequisite-only hash is not a
# substitute for the compiled source identity.
DIGEST_PREREQUISITES = (
    "scripts/ci/images/prepare-cw-source-context.py", "scripts/ci/images/build-cw-runtime-source.py",
    "scripts/ci/images/finalize-cw-runtime-source.py", "scripts/ci/images/prepare-cw-image-context.py",
    "scripts/ci/images/run-rust-build.sh", "scripts/ci/verify/build-linux-vmm-kernel.py",
    "images/cw-runtime/Dockerfile",
)
DEADLINE = None


def active():
    asset.active()
    require(DEADLINE is None or time.monotonic() < DEADLINE, "source capture exceeded its operation bound")


def relative(value):
    require(type(value) is str and 0 < len(value.encode("utf-8")) <= 4096
            and not value.startswith("/") and len(value.split("/")) <= 64
            and all(part not in ("", ".", "..", ".git") for part in value.split("/"))
            and not any(ord(c) <= 32 or ord(c) == 127 for c in value), "source path refused")
    return value


def git_environment(git_dir=None, work_tree=None):
    environment = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TZ": "UTC",
                   "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
                   "GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0", "GIT_NO_REPLACE_OBJECTS": "1",
                   "GIT_NO_LAZY_FETCH": "1", "GIT_ALLOW_PROTOCOL": "", "GIT_PROTOCOL_FROM_USER": "0",
                   "GIT_CONFIG_COUNT": "5", "GIT_CONFIG_KEY_0": "core.fsmonitor",
                   "GIT_CONFIG_VALUE_0": "false", "GIT_CONFIG_KEY_1": "core.hooksPath",
                   "GIT_CONFIG_VALUE_1": "/dev/null", "GIT_CONFIG_KEY_2": "core.excludesFile",
                   "GIT_CONFIG_VALUE_2": "/dev/null", "GIT_CONFIG_KEY_3": "maintenance.auto",
                   "GIT_CONFIG_VALUE_3": "false", "GIT_CONFIG_KEY_4": "gc.auto", "GIT_CONFIG_VALUE_4": "0"}
    if git_dir is not None:
        environment.update(GIT_DIR=str(git_dir), GIT_WORK_TREE=str(work_tree))
    return environment


@contextlib.contextmanager
def git_scope(git_dir=None, work_tree=None):
    # The shared producer's Git calls inherit only this explicit, short-lived
    # projection. It is never inherited by the actual Cargo child.
    saved = {key: value for key, value in os.environ.items() if key.startswith("GIT_")}
    for key in saved:
        del os.environ[key]
    os.environ.update({key: value for key, value in git_environment(git_dir, work_tree).items()
                       if key.startswith("GIT_")})
    try:
        yield
    finally:
        for key in list(os.environ):
            if key.startswith("GIT_"):
                del os.environ[key]
        os.environ.update(saved)


def git(root, arguments, input_bytes=None, maximum=MAX_GIT_REPLY, git_dir=None):
    """Fixed Git binary, bounded pipes/deadline, no filters/hooks/network calls."""
    active()
    command = ["/usr/bin/git", "--no-optional-locks", *arguments]
    environment = git_environment(git_dir, root)
    process = subprocess.Popen(command, cwd=root, env=environment, stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    output, error = bytearray(), bytearray()
    pending = memoryview(input_bytes or b"")
    end = time.monotonic() + GIT_STALL_SECONDS
    selector = selectors.DefaultSelector()
    try:
        for pipe, kind in ((process.stdout, "out"), (process.stderr, "err")):
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ, kind)
        if pending:
            os.set_blocking(process.stdin.fileno(), False)
            selector.register(process.stdin, selectors.EVENT_WRITE, "in")
        else:
            process.stdin.close()
        while selector.get_map():
            active()
            require(time.monotonic() < end, f"Git {arguments[0]} made no progress for {GIT_STALL_SECONDS} s")
            for key, _ in selector.select(0.1):
                end = time.monotonic() + GIT_STALL_SECONDS
                if key.data == "in":
                    count = os.write(key.fd, pending[:65536])
                    pending = pending[count:]
                    if not pending:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                    continue
                block = os.read(key.fd, 65536)
                if not block:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                destination = output if key.data == "out" else error
                destination.extend(block)
                require(len(destination) <= (maximum if key.data == "out" else 16384), "Git capture exceeds its bound")
        require(process.wait(timeout=max(0.01, end - time.monotonic())) == 0, "selected Git metadata refused")
        return bytes(output)
    finally:
        if process.returncode is None:
            # This owner has not reaped the fresh session leader; its group is
            # still reserved. None of the allowed Git commands runs hooks.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
        selector.close()
        for pipe in (process.stdin, process.stdout, process.stderr):
            if not pipe.closed:
                pipe.close()


def index_entries(raw):
    require(len(raw) <= MAX_GIT_REPLY and raw.endswith(b"\0"), "index inventory refused")
    entries, seen = [], set()
    for line in raw[:-1].split(b"\0"):
        fields, path = line.split(b"\t", 1)
        mode, oid, stage = fields.decode("ascii").split(" ")
        name = relative(path.decode("utf-8", "strict"))
        require(mode in ("100644", "100755", "120000") and stage == "0" and release.is_hex(oid, 40)
                and name not in seen and len(entries) < MAX_FILES, "index must be unique stage zero without submodules")
        seen.add(name)
        entries.append((name, mode, oid))
    require(entries, "selected index is empty")
    return sorted(entries)


def normalized_index(entries):
    return b"".join(f"{mode} {oid} 0\t{name}".encode() + b"\0" for name, mode, oid in entries)


def head_objects(root, revision, entries, git_dir=None):
    commit = git(root, ["cat-file", "commit", revision], maximum=1024 * 1024, git_dir=git_dir)
    require(hashlib.sha1(b"commit " + str(len(commit)).encode() + b"\0" + commit).hexdigest() == revision,
            "HEAD commit object differs")
    headers = commit.split(b"\n\n", 1)[0].splitlines()
    trees = [line[5:].decode("ascii") for line in headers if line.startswith(b"tree ")]
    require(len(trees) == 1 and release.is_hex(trees[0], 40), "HEAD tree refused")
    tree = trees[0]
    objects = {revision: "commit", tree: "tree"}
    listing = git(root, ["ls-tree", "-r", "-t", "-z", revision], git_dir=git_dir)
    require(not listing or listing.endswith(b"\0"), "HEAD tree inventory refused")
    for line in listing.rstrip(b"\0").split(b"\0") if listing else ():
        header, path = line.split(b"\t", 1)
        mode, kind, oid = header.decode("ascii").split(" ")
        relative(path.decode("utf-8", "strict"))
        require(mode in ("040000", "100644", "100755", "120000") and kind in ("tree", "blob")
                and release.is_hex(oid, 40) and objects.get(oid, kind) == kind,
                "HEAD object inventory refused")
        objects[oid] = kind
    for _, _, oid in entries:
        require(objects.get(oid, "blob") == "blob", "index object type refused")
        objects[oid] = "blob"
    require(len(objects) <= MAX_OBJECTS, "Git closure exceeds its object bound")
    return tree, objects


def object_closure(root, objects):
    """Yield (oid, kind, compressed object, size) for each object, in oid order.

    One bounded `git cat-file --batch` reads the whole closure. Each object must
    have its expected type, fit MAX_FILE and hash to its identity, as a separate
    `cat-file <kind> <oid>` read requires; one process per object made a large
    tree spend most of its time starting Git.
    """
    names = sorted(objects)
    if not names:
        return
    raw = git(root, ["cat-file", "--batch"], "".join(oid + "\n" for oid in names).encode(),
              maximum=MAX_TOTAL + 128 * len(names))
    offset = 0
    for oid in names:
        active()
        kind = objects[oid]
        end = raw.find(b"\n", offset, offset + 128)
        require(end >= 0, "Git object batch header refused")
        header = raw[offset:end].split(b" ")
        require(len(header) == 3 and header[0] == oid.encode() and header[1] == kind.encode()
                and header[2].isdigit() and len(header[2]) <= 12, "Git object batch header refused")
        size = int(header[2])
        start = end + 1
        require(size <= MAX_FILE and len(raw) >= start + size + 1 and raw[start + size] == 0x0A,
                "Git object batch framing refused")
        framed = kind.encode() + b" " + str(size).encode() + b"\0" + raw[start:start + size]
        require(hashlib.sha1(framed).hexdigest() == oid, "Git object differs from its identity")
        offset = start + size + 1
        yield oid, kind, zlib.compress(framed, 9), size
    require(offset == len(raw), "Git object batch has unrequested output")


def write_relative(root_fd, name, data, mode):
    name = relative(name)
    descriptor = os.dup(root_fd)
    try:
        for part in name.split("/")[:-1]:
            try:
                os.mkdir(part, 0o700, dir_fd=descriptor)
            except FileExistsError:
                pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=descriptor)
            info = os.fstat(child)
            require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700,
                    "created directory identity refused")
            os.close(descriptor)
            descriptor = child
        asset.write_new(descriptor, name.split("/")[-1], data, mode)
    finally:
        os.close(descriptor)


def file_binding(raw, mode):
    return {"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw), "mode": mode}


class HeldSourceFile(asset.HeldFile):
    """Source and Git blobs may legitimately have zero bytes."""

    def __init__(self, path, maximum):
        self.path, self.maximum, self.parent, self.fd = asset.path_arg(str(path)), maximum, None, None
        try:
            self.parent = asset.Parent(self.path.parent)
            before = os.stat(self.path.name, dir_fd=self.parent.fd, follow_symlinks=False)
            self.fd = os.open(self.path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                              dir_fd=self.parent.fd)
            info = os.fstat(self.fd)
            require(asset.stamp(before) == asset.stamp(info) and stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                    and info.st_uid in (0, os.geteuid()) and not info.st_mode & 0o022
                    and 0 <= info.st_size <= maximum, "source member is not a bounded owned regular file")
            self.metadata = asset.stamp(info)
            self.data = self.read()
            self.sha256 = hashlib.sha256(self.data).hexdigest()
            self.revalidate()
        except BaseException:
            self.close()
            raise


def load_release(source):
    spec = importlib.util.spec_from_file_location("cw_selected_source_release", source / "scripts/ci/release/cw_release.py")
    module = importlib.util.module_from_spec(spec)
    previous_bytecode = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous_bytecode
    class SelectedRelease:
        # Loading the selected checkout creates its own Python exception class.
        # Normalize that private class at our owning boundary without changing
        # any shared producer bytes or admission semantics.
        def __getattr__(self, name):
            value = getattr(module, name)
            if not callable(value) or name == "ReleaseError":
                return value
            def admitted_call(*args, **kwargs):
                try:
                    return value(*args, **kwargs)
                except module.ReleaseError:
                    raise release.ReleaseError("selected shared producer refused") from None
            return admitted_call
    return SelectedRelease()


class SourceContext:
    def __init__(self):
        self.inputs, self.outputs, self.source_parent, self.output_parent = {}, {}, None, None
        self.root_fd = None

    def revalidate(self):
        active()
        revalidate_original(self)
        self.output_parent.revalidate()
        require(asset.stamp(os.fstat(self.root_fd), asset.DIR_FIELDS) == self.output_stamp
                == asset.stamp(os.stat(self.path.name, dir_fd=self.output_parent.fd, follow_symlinks=False), asset.DIR_FIELDS),
                "source context root changed")
        for held in self.outputs.values():
            held.revalidate(content=True)
        validate_inventory(self.path, set(self.outputs))
        self.output_parent.revalidate()

    def close(self):
        for held in (*self.inputs.values(), *self.outputs.values()):
            held.close()
        if self.root_fd is not None:
            os.close(self.root_fd)
            self.root_fd = None
        for parent in (self.source_parent, self.output_parent):
            if parent is not None:
                parent.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def revalidate_original(context):
    active()
    context.source_parent.revalidate()
    for held in context.inputs.values():
        held.revalidate(content=True)
    require(git(context.source, ["rev-parse", "HEAD"]).strip().decode() == context.model["source"]["revision"]
            and normalized_index(index_entries(git(context.source, ["ls-files", "--stage", "-z"]))) == context.index,
            "selected HEAD or index changed")
    tree, _ = head_objects(context.source, context.model["source"]["revision"], index_entries(context.index))
    require(tree == context.model["source"]["git_tree"], "selected real Git tree differs")
    with git_scope():
        require([os.fsdecode(path) for path in context.selected.source_inputs(context.source)] == context.model["digest_inputs"]
                and context.selected.source_tree_sha256(context.source) == context.model["source"]["source_tree_sha256"],
                "selected source changed")


class CurrentSource:
    """Admit current Git identity with unchanged retained compiler inputs."""

    def __init__(self, path, model_value, revision):
        self.source, self.inputs, self.source_parent = asset.path_arg(str(path)), {}, None
        try:
            require(release.is_hex(revision, 40), "current source revision refused")
            self.source_parent = asset.Parent(self.source)
            require(git(self.source, ["rev-parse", "HEAD"]).strip().decode() == revision,
                    "current checkout is not the selected revision")
            self.index = normalized_index(index_entries(git(self.source, ["ls-files", "--stage", "-z"])))
            tree, objects = head_objects(self.source, revision, index_entries(self.index))
            total = sum(binding["size"] for binding in model_value["files"].values())
            for _, _, raw, size in object_closure(self.source, objects):
                total += len(raw) + size
                require(total <= MAX_TOTAL, "current Git closure exceeds its byte bound")
            current = {"revision": revision, "git_tree": tree,
                       "source_tree_sha256": model_value["source"]["source_tree_sha256"],
                       "index_sha256": hashlib.sha256(self.index).hexdigest(), "object_count": len(objects)}
            self.model = model_value | {"source": current}
            for name, binding in model_value["files"].items():
                held = HeldSourceFile(self.source / name, MAX_FILE)
                self.inputs[name] = held
                require(file_binding(held.data, 0o555 if held.metadata["mode"] & 0o111 else 0o444) == binding,
                        "current source prerequisite differs from retained compilation")
            self.selected = load_release(self.source)
            self.revalidate()
        except BaseException:
            self.close()
            raise

    def revalidate(self):
        revalidate_original(self)

    def close(self):
        for held in self.inputs.values():
            held.close()
        if self.source_parent is not None:
            self.source_parent.close()


def validate_inventory(root, expected, empty_directories=("git/refs",)):
    actual = set()
    # Every member is subsequently reopened through held nofollow ancestry.
    # Enumeration itself uses fresh directory descriptors and before/after
    # identity, and refuses links or unknown leaves rather than ignoring them.
    def anchored(fd, prefix, depth):
        require(depth <= 64, "capsule directory depth refused")
        before = asset.stamp(os.fstat(fd))
        fresh = os.open(".", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
        try:
            for name in sorted(os.listdir(fresh)):
                active()
                item = prefix + name
                info = os.stat(name, dir_fd=fresh, follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    require(any(path.startswith(item + "/") for path in expected) or item in empty_directories,
                            "capsule contains an unknown directory")
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fresh)
                    try:
                        require(asset.stamp(os.fstat(child)) == asset.stamp(info), "capsule directory changed")
                        anchored(child, item + "/", depth + 1)
                        require(asset.stamp(os.stat(name, dir_fd=fresh, follow_symlinks=False)) == asset.stamp(info),
                                "capsule directory changed")
                    finally:
                        os.close(child)
                else:
                    require(item in expected and stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                            "capsule contains an unknown or linked member")
                    actual.add(item)
            require(asset.stamp(os.fstat(fresh)) == before == asset.stamp(os.fstat(fd)), "capsule enumeration changed")
        finally:
            os.close(fresh)
    parent = asset.Parent(root)
    try:
        anchored(parent.fd, "", 0)
        require(actual == expected, "capsule inventory is incomplete")
    finally:
        parent.close()


def prepare(source_root, revision, profile, version, output):
    global DEADLINE
    DEADLINE = time.monotonic() + 600
    require(release.is_hex(revision, 40) and profile in ("ci", "release", "runtime") and release.valid_version(version),
            "producer selection refused")
    context = SourceContext()
    try:
        context.source, context.path = asset.path_arg(str(source_root)), asset.path_arg(str(output))
        require(not os.path.lexists(context.path), "source output already exists")
        context.source_parent = asset.Parent(context.source)
        require(git(context.source, ["rev-parse", "HEAD"]).strip().decode() == revision, "checkout is not selected HEAD")
        context.index = normalized_index(index_entries(git(context.source, ["ls-files", "--stage", "-z"])))
        entries = index_entries(context.index)
        git_tree, objects = head_objects(context.source, revision, entries)
        context.selected = load_release(context.source)
        with git_scope():
            inputs = [relative(os.fsdecode(raw)) for raw in context.selected.source_inputs(context.source)]
        require(len(inputs) <= MAX_FILES and all(name in inputs for name in DIGEST_PREREQUISITES),
                "owning producer prerequisites are absent from the shared source digest")
        names = sorted(set(inputs) | set(PREREQUISITES))
        total, files = 0, {}
        for name in names:
            active()
            held = HeldSourceFile(context.source / name, MAX_FILE)
            context.inputs[name] = held
            total += len(held.data)
            require(total <= MAX_TOTAL, "source closure exceeds its byte bound")
            files[name] = file_binding(held.data, 0o555 if held.metadata["mode"] & 0o111 else 0o444)
        with git_scope():
            tree_digest = context.selected.source_tree_sha256(context.source)
        context.model = {"schema": SCHEMA, "target": TARGET, "profile": profile, "version": version,
                         "source": {"revision": revision, "git_tree": git_tree, "source_tree_sha256": tree_digest,
                                    "index_sha256": hashlib.sha256(context.index).hexdigest()},
                         "digest_inputs": inputs, "files": files, "objects": {},
                         "prerequisites": list(PREREQUISITES)}
        # Finish capture and object admission before creating the output.
        copied_objects = {}
        for oid, kind, raw, size in object_closure(context.source, objects):
            total += size + len(raw)
            require(total <= MAX_TOTAL, "source and Git closure exceed their byte bound")
            copied_objects[oid] = raw
            context.model["objects"][oid] = {"type": kind, "object_size": size, **file_binding(raw, 0o400)}
        context.model["source"]["object_count"] = len(objects)
        request = release.canonical(context.model)
        require(len(request) <= MAX_DOCUMENT, "capsule request exceeds its bound")
        for held in context.inputs.values():
            held.revalidate(content=True)
        require(normalized_index(index_entries(git(context.source, ["ls-files", "--stage", "-z"]))) == context.index
                and git(context.source, ["rev-parse", "HEAD"]).strip().decode() == revision, "capture source changed")
        context.output_parent = asset.Parent(context.path.parent)
        require(os.fstat(context.output_parent.fd).st_uid == os.geteuid(), "output parent is not owned")
        os.mkdir(context.path.name, 0o700, dir_fd=context.output_parent.fd)
        context.root_fd = os.open(context.path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                  dir_fd=context.output_parent.fd)
        context.output_stamp = asset.stamp(os.fstat(context.root_fd), asset.DIR_FIELDS)
        for name, held in context.inputs.items():
            write_relative(context.root_fd, "source/" + name, held.data, files[name]["mode"])
        write_relative(context.root_fd, "git/HEAD", (revision + "\n").encode(), 0o400)
        # A shallow boundary records the intentionally retained commit closure;
        # it never claims or copies unrelated historical objects.
        write_relative(context.root_fd, "git/shallow", (revision + "\n").encode(), 0o400)
        git_fd = os.open("git", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=context.root_fd)
        try:
            os.mkdir("refs", 0o700, dir_fd=git_fd)
        finally:
            os.close(git_fd)
        for oid, raw in copied_objects.items():
            write_relative(context.root_fd, f"git/objects/{oid[:2]}/{oid[2:]}", raw, 0o400)
        git(context.path / "source", ["update-index", "-z", "--index-info"], context.index,
            git_dir=context.path / "git")
        (context.path / "git/index").chmod(0o400)
        index_file = HeldSourceFile(context.path / "git/index", MAX_GIT_REPLY)
        try:
            context.model["git_index"] = file_binding(index_file.data, 0o400)
        finally:
            index_file.close()
        request = release.canonical(context.model)
        require(len(request) <= MAX_DOCUMENT, "capsule request exceeds its bound")
        write_relative(context.root_fd, "request.json", request, 0o400)
        output_names = {"source/" + name for name in files} | {"git/HEAD", "git/shallow", "git/index", "request.json"}
        output_names |= {f"git/objects/{oid[:2]}/{oid[2:]}" for oid in copied_objects}
        for name in sorted(output_names):
            context.outputs[name] = HeldSourceFile(context.path / name, MAX_FILE + 1024 * 1024 if name.startswith("git/objects/") else MAX_FILE)
        with git_scope(context.path / "git", context.path / "source"):
            require(context.selected.head_revision(context.path / "source") == revision
                    and context.selected.source_inputs(context.path / "source") == [name.encode() for name in inputs]
                    and context.selected.source_tree_sha256(context.path / "source") == tree_digest,
                    "sanitized source does not reproduce the selected source inventory")
        context.revalidate()
        return context
    except BaseException:
        context.close()  # Unknown/partial output is retained; never overwritten.
        raise
    finally:
        DEADLINE = None


def model(raw):
    value = release.parse_canonical(raw, MAX_DOCUMENT)
    require(type(value) is dict and set(value) == {"schema", "target", "profile", "version", "source",
                                                  "digest_inputs", "files", "objects", "prerequisites", "git_index"}
            and value["schema"] == SCHEMA and value["target"] == TARGET and value["profile"] in ("ci", "release", "runtime")
            and release.valid_version(value["version"]), "capsule model refused")
    source = value["source"]
    require(type(source) is dict and set(source) == {"revision", "git_tree", "source_tree_sha256", "index_sha256", "object_count"}
            and release.is_hex(source["revision"], 40) and release.is_hex(source["git_tree"], 40)
            and all(release.is_hex(source[key], 64) for key in ("source_tree_sha256", "index_sha256"))
            and type(source["object_count"]) is int and 1 <= source["object_count"] <= MAX_OBJECTS,
            "capsule source identity refused")
    require(type(value["digest_inputs"]) is list and 0 < len(value["digest_inputs"]) <= MAX_FILES
            and value["digest_inputs"] == sorted(set(value["digest_inputs"]))
            and all(relative(name) in value["files"] for name in value["digest_inputs"]), "digest input inventory refused")
    require(value["prerequisites"] == list(PREREQUISITES) and type(value["files"]) is dict
            and 0 < len(value["files"]) <= MAX_FILES
            and set(value["files"]) == set(value["digest_inputs"]) | set(PREREQUISITES)
            and all(name in value["digest_inputs"] for name in DIGEST_PREREQUISITES), "prerequisite inventory refused")
    def bound(binding, maximum, modes):
        require(type(binding) is dict and set(binding) == {"sha256", "size", "mode"}
                and release.is_hex(binding["sha256"], 64) and type(binding["size"]) is int
                and 0 <= binding["size"] <= maximum and type(binding["mode"]) is int and binding["mode"] in modes,
                "capsule byte binding refused")
    total = 0
    for name, binding in value["files"].items():
        relative(name)
        bound(binding, MAX_FILE, (0o444, 0o555))
        total += binding["size"]
    bound(value["git_index"], MAX_GIT_REPLY, (0o400,))
    require(value["git_index"]["size"] > 0 and type(value["objects"]) is dict
            and len(value["objects"]) == source["object_count"], "Git closure inventory refused")
    for oid, binding in value["objects"].items():
        require(release.is_hex(oid, 40) and type(binding) is dict
                and set(binding) == {"sha256", "size", "mode", "type", "object_size"}
                and binding["type"] in ("blob", "tree", "commit") and type(binding["object_size"]) is int
                and 0 <= binding["object_size"] <= MAX_FILE, "Git object model refused")
        bound({key: binding[key] for key in ("sha256", "size", "mode")}, MAX_FILE + 1024 * 1024, (0o400,))
        total += binding["size"] + binding["object_size"]
    require(total <= MAX_TOTAL, "capsule model exceeds its total bound")
    return value


class AdmittedSource:
    def __init__(self):
        self.files = {}

    def revalidate(self):
        for held in self.files.values():
            held.revalidate(content=True)
        validate_inventory(self.source, set(self.model["files"]), ())
        validate_inventory(self.git_dir, self.git_members, ("refs",))
        with git_scope(self.git_dir, self.source):
            require(self.selected.head_revision(self.source) == self.model["source"]["revision"]
                    and self.selected.source_tree_sha256(self.source) == self.model["source"]["source_tree_sha256"]
                    and [os.fsdecode(name) for name in self.selected.source_inputs(self.source)] == self.model["digest_inputs"],
                    "admitted capsule source changed")

    def close(self):
        for held in self.files.values():
            held.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def admit(source_root, git_dir, request_path, request_sha256):
    """Reopen the exact capsule inside the compiler; no candidate execution."""
    require(release.is_hex(request_sha256, 64), "capsule request pin refused")
    admitted = AdmittedSource()
    try:
        admitted.source, admitted.git_dir = asset.path_arg(str(source_root)), asset.path_arg(str(git_dir))
        request = HeldSourceFile(request_path, MAX_DOCUMENT)
        admitted.files["request"] = request
        require(request.sha256 == request_sha256, "capsule request differs from its external pin")
        admitted.model = model(request.data)
        for name, binding in admitted.model["files"].items():
            held = HeldSourceFile(admitted.source / name, MAX_FILE)
            admitted.files["source/" + name] = held
            require(file_binding(held.data, stat.S_IMODE(held.metadata["mode"])) == binding,
                    "capsule source member differs")
        admitted.git_members = {"HEAD", "index", "shallow"}
        for oid, binding in admitted.model["objects"].items():
            name = f"objects/{oid[:2]}/{oid[2:]}"
            admitted.git_members.add(name)
            held = HeldSourceFile(admitted.git_dir / name, MAX_FILE + 1024 * 1024)
            admitted.files["git/" + name] = held
            require(file_binding(held.data, stat.S_IMODE(held.metadata["mode"])) ==
                    {key: binding[key] for key in ("sha256", "size", "mode")}, "capsule Git member differs")
            decoder = zlib.decompressobj()
            try:
                framed = decoder.decompress(held.data, MAX_FILE + 128)
            except zlib.error:
                raise Refused("capsule Git object compression refused") from None
            require(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
                    and len(framed) <= MAX_FILE + 128 and hashlib.sha1(framed).hexdigest() == oid,
                    "capsule Git object framing refused")
            header, content = framed.split(b"\0", 1)
            require(header == f"{binding['type']} {binding['object_size']}".encode()
                    and len(content) == binding["object_size"], "capsule Git object type or size differs")
        for name in ("HEAD", "index", "shallow"):
            held = HeldSourceFile(admitted.git_dir / name, MAX_GIT_REPLY)
            admitted.files["git/" + name] = held
            require(stat.S_IMODE(held.metadata["mode"]) == 0o400, "capsule Git metadata mode refused")
        revision = admitted.model["source"]["revision"]
        require(admitted.files["git/HEAD"].data == admitted.files["git/shallow"].data == (revision + "\n").encode()
                and file_binding(admitted.files["git/index"].data, 0o400) == admitted.model["git_index"],
                "capsule HEAD/index boundary differs")
        entries = index_entries(git(admitted.source, ["ls-files", "--stage", "-z"], git_dir=admitted.git_dir))
        require(hashlib.sha256(normalized_index(entries)).hexdigest() == admitted.model["source"]["index_sha256"],
                "capsule normalized index differs")
        tree, objects = head_objects(admitted.source, revision, entries, admitted.git_dir)
        require(tree == admitted.model["source"]["git_tree"] and objects ==
                {oid: binding["type"] for oid, binding in admitted.model["objects"].items()},
                "capsule does not contain exactly the selected Git closure")
        git(admitted.source, ["fsck", "--full", "--no-reflogs", "--strict", "--no-dangling"], git_dir=admitted.git_dir)
        admitted.selected = load_release(admitted.source)
        admitted.revalidate()
        return admitted
    except BaseException:
        admitted.close()
        raise


def main(argv=None):
    def cancel(sig, _frame):
        asset.STOP = sig
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, cancel)
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in ("source-root", "source-sha", "profile", "version", "output"):
        parser.add_argument("--" + name, required=True, action=asset.SingleUse)
    args = parser.parse_args(argv)
    with prepare(args.source_root, args.source_sha, args.profile, args.version, args.output) as context:
        print(release.canonical({"status": "source-admitted", "claim": "source-only-no-compiler-proof",
                                 "source": context.model["source"], "request_sha256": context.outputs["request.json"].sha256,
                                 "path": str(context.path)}).decode(), end="")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, release.ReleaseError):
        print("prepare-cw-source-context: selected source refused", file=sys.stderr)
        sys.exit(1)
