#!/usr/bin/env python3
"""Admit a pinned CW OCI asset into a private, nonpublishing Buildx context.

This validates the OCI closure and the executable's complete compiled identity.
The producer receipt is only a caller-pinned external evidence binding. Its
build success, dep-info and current-source semantics require the owning wrapper's
independent admission; this helper never supplies that qualification.

prepare --request ABS --request-sha256 SHA --output FRESH_ABS writes only cw and
provenance.json in the context and a canonical sibling OUTPUT.context.json.
verify --receipt ABS --receipt-sha256 SHA reopens and revalidates every original
input/context binding before Docker or after a build. Python callers can retain
the returned Context and its held descriptors across both boundaries instead.
No executable, compiler, Docker, network, credential or publication is invoked.
"""

import argparse
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import signal
import stat
import sys
import tarfile


ROOT = Path(__file__).resolve().parents[3]
IMAGE_PATH = ROOT / "scripts/dev/cw-runtime-image.py"
spec = importlib.util.spec_from_file_location("cw_context_image", IMAGE_PATH)
image = importlib.util.module_from_spec(spec)
spec.loader.exec_module(image)
release = image.release

CONTEXT_NAME = "codewire-verified-cw"
SCHEMA = "codewire.cw.image-context/v1"
CLAIM = "asset-admission-and-external-evidence-binding-only"
MAX_DOCUMENT = 64 * 1024
MAX_PATH = 4096
MAX_DEPTH = 64
FILES = {"cw": 0o500, "provenance.json": 0o400}
STAMP_FIELDS = ("dev", "ino", "mode", "uid", "gid", "nlink", "size", "mtime_ns", "ctime_ns")
DIR_FIELDS = STAMP_FIELDS[:5]
STOP = None


class Refused(ValueError):
    pass


def require(value, message):
    if not value:
        raise Refused(message)


def active():
    require(STOP is None, "context operation cancelled")


def path_arg(value):
    require(type(value) is str and value.startswith("/") and value != "/"
            and not any(ord(c) < 32 or ord(c) == 127 for c in value), "invalid absolute path")
    try:
        raw = value.encode("utf-8", "strict")
    except UnicodeError:
        raise Refused("invalid path encoding") from None
    require(len(raw) <= MAX_PATH and all(part not in ("", ".", "..") for part in value.split("/")[1:])
            and len(value.split("/")) <= MAX_DEPTH, "path is not bounded canonical spelling")
    return Path(value)


def stamp(info, fields=STAMP_FIELDS):
    values = dict(zip(STAMP_FIELDS, (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                                   info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)))
    return {key: values[key] for key in fields}


def trusted_directory(info):
    require(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, os.geteuid()), "directory ownership refused")
    writable = bool(info.st_mode & 0o022)
    require(not writable or (info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o1777),
            "directory permits foreign replacement")


class Parent:
    """An anchored nofollow ancestry, excluding mutable directory timestamps."""

    def __init__(self, path):
        self.path, self.fds, self.names, self.stamps = path, [], [], []
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        try:
            for name in ("/", *path.parts[1:]):
                before = os.stat(name, dir_fd=self.fds[-1] if self.fds else None, follow_symlinks=False)
                fd = os.open(name, flags, dir_fd=self.fds[-1] if self.fds else None)
                self.fds.append(fd)
                info = os.fstat(fd)
                trusted_directory(info)
                require(stamp(before, DIR_FIELDS) == stamp(info, DIR_FIELDS), "directory changed during admission")
                self.names.append(name)
                self.stamps.append(stamp(info, DIR_FIELDS))
            self.revalidate()
        except BaseException:
            self.close()
            raise

    @property
    def fd(self):
        return self.fds[-1]

    def revalidate(self):
        active()
        for i, (name, fd, expected) in enumerate(zip(self.names, self.fds, self.stamps)):
            current = os.stat(name, dir_fd=self.fds[i - 1] if i else None, follow_symlinks=False)
            require(stamp(current, DIR_FIELDS) == expected == stamp(os.fstat(fd), DIR_FIELDS),
                    "held ancestry changed")
            trusted_directory(current)

    def close(self):
        while self.fds:
            os.close(self.fds.pop())


class HeldFile:
    def __init__(self, path, maximum, expected=None):
        self.path, self.maximum, self.parent, self.fd = path_arg(str(path)), maximum, None, None
        try:
            self.parent = Parent(self.path.parent)
            before = os.stat(self.path.name, dir_fd=self.parent.fd, follow_symlinks=False)
            self.fd = os.open(self.path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                              dir_fd=self.parent.fd)
            info = os.fstat(self.fd)
            require(stamp(before) == stamp(info) and stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                    and info.st_uid in (0, os.geteuid()) and not info.st_mode & 0o022
                    and 0 < info.st_size <= maximum, "input is not a bounded owned regular file")
            self.metadata = stamp(info)
            self.data = self.read()
            self.sha256 = hashlib.sha256(self.data).hexdigest()
            if expected is not None:
                require(len(self.data) == expected["size"] and self.sha256 == expected["sha256"],
                        "input differs from its external pin")
            self.revalidate()
        except BaseException:
            self.close()
            raise

    def read(self):
        active()
        os.lseek(self.fd, 0, os.SEEK_SET)
        data = bytearray()
        while True:
            active()
            block = os.read(self.fd, min(1024 * 1024, self.maximum + 1 - len(data)))
            if not block:
                break
            data.extend(block)
            require(len(data) <= self.maximum, "input exceeded its bound")
        require(len(data) == self.metadata["size"], "held input size changed")
        return bytes(data)

    def revalidate(self, content=False):
        self.parent.revalidate()
        current = os.stat(self.path.name, dir_fd=self.parent.fd, follow_symlinks=False)
        require(stamp(current) == self.metadata == stamp(os.fstat(self.fd)), "held input changed")
        if content:
            require(hashlib.sha256(self.read()).hexdigest() == self.sha256, "held input bytes changed")
            require(stamp(os.fstat(self.fd)) == self.metadata
                    == stamp(os.stat(self.path.name, dir_fd=self.parent.fd, follow_symlinks=False)),
                    "held input changed during revalidation")
        self.parent.revalidate()

    def evidence(self):
        return {"path": str(self.path), "sha256": self.sha256, "size": len(self.data), "metadata": self.metadata}

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        if self.parent is not None:
            self.parent.close()


def binding(value, maximum):
    require(type(value) is dict and set(value) == {"path", "sha256", "size"}, "input binding fields refused")
    path_arg(value["path"])
    require(release.is_hex(value["sha256"], 64) and type(value["size"]) is int
            and 0 < value["size"] <= maximum, "input binding pin refused")
    return value


def request_model(raw):
    value = release.parse_canonical(raw, MAX_DOCUMENT)
    require(type(value) is dict and set(value) == {"schema_version", "image", "index_sha256", "payload", "producer_receipt"}
            and type(value["schema_version"]) is int and value["schema_version"] == 1, "request fields refused")
    binding(value["image"], image.MAX_ARCHIVE)
    binding(value["producer_receipt"], MAX_DOCUMENT)
    require(release.is_hex(value["index_sha256"], 64), "index pin refused")
    release.validate_identity(value["payload"], image.TARGET)
    return value


def inventory(fd):
    # dup shares enumeration offset; a fresh anchored '.' FD does not.
    fresh = os.open(".", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
    try:
        require(stamp(os.fstat(fresh), DIR_FIELDS) == stamp(os.fstat(fd), DIR_FIELDS), "enumeration root changed")
        result = set()
        with os.scandir(fresh) as entries:
            for entry in entries:
                active()
                require(entry.name in FILES and entry.name not in result, "context inventory refused")
                result.add(entry.name)
        require(result == set(FILES), "context inventory is incomplete")
        require(stamp(os.fstat(fresh), DIR_FIELDS) == stamp(os.fstat(fd), DIR_FIELDS), "enumeration root changed")
    finally:
        os.close(fresh)


def write_new(parent, name, data, mode):
    active()
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode, dir_fd=parent)
    try:
        view = memoryview(data)
        while view:
            active()
            written = os.write(fd, view)
            require(written > 0, "context write made no progress")
            view = view[written:]
        os.fchmod(fd, mode)
        os.fsync(fd)
    finally:
        os.close(fd)


class Context:
    """Keep the input, ancestry, output-root and payload FDs through a build."""

    def __init__(self):
        self.inputs, self.files, self.parent, self.root_fd = {}, {}, None, None
        self.receipt_file = None

    def revalidate(self):
        active()
        if self.receipt_file is not None:
            self.receipt_file.revalidate(content=True)
            require(self.receipt_file.metadata["uid"] == os.geteuid()
                    and stat.S_IMODE(self.receipt_file.metadata["mode"]) == 0o400, "receipt private policy refused")
        for held in self.inputs.values():
            held.revalidate(content=True)
        self.parent.revalidate()
        named = os.stat(self.path.name, dir_fd=self.parent.fd, follow_symlinks=False)
        require(stamp(named, DIR_FIELDS) == self.root_metadata == stamp(os.fstat(self.root_fd), DIR_FIELDS),
                "context root changed")
        require(named.st_uid == os.geteuid() and stat.S_IMODE(named.st_mode) == 0o700,
                "context root policy changed")
        inventory(self.root_fd)
        for name, held in self.files.items():
            held.revalidate(content=True)
            require(stat.S_IMODE(os.fstat(held.fd).st_mode) == FILES[name]
                    and os.fstat(held.fd).st_uid == os.geteuid(), "context file policy changed")
        inventory(self.root_fd)
        self.parent.revalidate()
        require(stamp(os.stat(self.path.name, dir_fd=self.parent.fd, follow_symlinks=False), DIR_FIELDS)
                == self.root_metadata == stamp(os.fstat(self.root_fd), DIR_FIELDS), "context root changed")
        if self.receipt_file is not None:
            self.receipt_file.revalidate(content=True)
            require(self.receipt_file.data == release.canonical(self.receipt()), "receipt is not the exact admitted model")

    def receipt(self):
        return {"schema": SCHEMA, "claim": CLAIM, "producer_semantics_verified": False,
                "context_name": CONTEXT_NAME, "payload": self.payload, "provenance": self.provenance,
                "inputs": {name: held.evidence() for name, held in self.inputs.items()},
                "context": {"path": str(self.path), "metadata": self.root_metadata},
                "files": {name: held.evidence() for name, held in self.files.items()}}

    def close(self):
        if self.receipt_file is not None:
            self.receipt_file.close()
        for held in (*self.files.values(), *self.inputs.values()):
            held.close()
        if self.root_fd is not None:
            os.close(self.root_fd)
            self.root_fd = None
        if self.parent is not None:
            self.parent.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def asset_admission(context, request):
    # The externally admitted receipt must be structurally bounded JSON only.
    # Deliberately do not derive success, source, compiler or dep-info from it.
    producer = release.parse_json(context.inputs["producer_receipt"].data, MAX_DOCUMENT)
    require(type(producer) is dict and producer, "producer evidence is not a nonempty JSON object")
    # Python's JSON decoder also accepts NaN/Infinity, which are not JSON.
    # This is structural validation only; no receipt field grants authority.
    pending = [producer]
    while pending:
        item = pending.pop()
        if type(item) is float:
            require(math.isfinite(item), "producer evidence contains a non-JSON number")
        elif type(item) is dict:
            pending.extend(item.values())
        elif type(item) is list:
            pending.extend(item)
    cw, provenance = image.admit(context.inputs["image"].data, request["index_sha256"])
    context.payload = request["payload"]
    context.provenance = release.parse_canonical(provenance, image.MAX_JSON)
    require(context.provenance["payload"] == context.payload, "OCI payload differs from expected identity")
    require(release.make_identity(cw, image.TARGET, context.payload["package_version"],
                                  context.payload["source_revision"], context.payload["source_tree_sha256"],
                                  context.payload["rustc"]) == context.payload, "compiled identity differs")
    return cw, provenance


def prepare(request_path, request_sha256, output):
    """All incoming admission precedes output allocation; failures retain it."""
    require(release.is_hex(request_sha256, 64), "request pin refused")
    context = Context()
    try:
        context.inputs["request"] = HeldFile(request_path, MAX_DOCUMENT)
        require(context.inputs["request"].sha256 == request_sha256, "request differs from its external pin")
        request = request_model(context.inputs["request"].data)
        for name in ("image", "producer_receipt"):
            maximum = image.MAX_ARCHIVE if name == "image" else MAX_DOCUMENT
            context.inputs[name] = HeldFile(request[name]["path"], maximum, request[name])
        cw, provenance = asset_admission(context, request)
        for held in context.inputs.values():
            held.revalidate(content=True)
        context.path = path_arg(str(output))
        context.parent = Parent(context.path.parent)
        require(os.fstat(context.parent.fd).st_uid == os.geteuid()
                and not os.fstat(context.parent.fd).st_mode & 0o022, "output parent policy refused")
        receipt_name = context.path.name + ".context.json"
        for name in (context.path.name, receipt_name):
            try:
                os.stat(name, dir_fd=context.parent.fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise Refused("output or receipt already exists")
        active()
        os.mkdir(context.path.name, 0o700, dir_fd=context.parent.fd)
        context.root_fd = os.open(context.path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                  dir_fd=context.parent.fd)
        os.fchmod(context.root_fd, 0o700)
        info = os.fstat(context.root_fd)
        require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700, "output private policy refused")
        context.root_metadata = stamp(info, DIR_FIELDS)
        for name, data in (("cw", cw), ("provenance.json", provenance)):
            write_new(context.root_fd, name, data, FILES[name])
            context.files[name] = HeldFile(context.path / name, image.MAX_CW if name == "cw" else image.MAX_JSON)
        os.fsync(context.root_fd)
        context.revalidate()
        context.receipt_path = context.path.with_name(receipt_name)
        raw = release.canonical(context.receipt())
        require(len(raw) <= MAX_DOCUMENT, "context receipt exceeds bound")
        write_new(context.parent.fd, receipt_name, raw, 0o400)
        os.fsync(context.parent.fd)
        context.receipt_sha256 = hashlib.sha256(raw).hexdigest()
        context.receipt_file = HeldFile(context.receipt_path, MAX_DOCUMENT,
                                        {"sha256": context.receipt_sha256, "size": len(raw)})
        context.revalidate()
        return context
    except BaseException:
        context.close()
        raise


def metadata_model(value, directory=False):
    fields = set(DIR_FIELDS if directory else STAMP_FIELDS)
    require(type(value) is dict and set(value) == fields
            and all(type(v) is int and -(1 << 63) <= v < (1 << 64) for v in value.values()),
            "receipt metadata fields refused")


def verify(receipt_path, receipt_sha256):
    """Reopen a SHA-bound context receipt, re-prove its original admission."""
    require(release.is_hex(receipt_sha256, 64), "receipt pin refused")
    context = Context()
    try:
        context.receipt_file = receipt_file = HeldFile(receipt_path, MAX_DOCUMENT)
        require(receipt_file.sha256 == receipt_sha256, "receipt differs from its external pin")
        require(receipt_file.metadata["uid"] == os.geteuid()
                and stat.S_IMODE(receipt_file.metadata["mode"]) == 0o400, "receipt private policy refused")
        value = release.parse_canonical(receipt_file.data, MAX_DOCUMENT)
        require(type(value) is dict and set(value) == {"schema", "claim", "producer_semantics_verified", "context_name",
                                                     "payload", "provenance", "inputs", "context", "files"}
                and value["schema"] == SCHEMA and value["claim"] == CLAIM
                and value["producer_semantics_verified"] is False and value["context_name"] == CONTEXT_NAME,
                "context receipt contract refused")
        require(type(value["inputs"]) is dict and set(value["inputs"]) == {"request", "image", "producer_receipt"}
                and type(value["files"]) is dict and set(value["files"]) == set(FILES), "receipt inventory refused")
        require(type(value["context"]) is dict and set(value["context"]) == {"path", "metadata"}, "context fields refused")
        metadata_model(value["context"]["metadata"], directory=True)
        context.path = path_arg(value["context"]["path"])
        require(receipt_file.path == context.path.with_name(context.path.name + ".context.json"), "receipt placement refused")
        context.parent = Parent(context.path.parent)
        require(os.fstat(context.parent.fd).st_uid == os.geteuid()
                and not os.fstat(context.parent.fd).st_mode & 0o022, "output parent policy refused")
        context.root_fd = os.open(context.path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                  dir_fd=context.parent.fd)
        context.root_metadata = value["context"]["metadata"]
        require(context.root_metadata["uid"] == os.geteuid()
                and stat.S_IMODE(context.root_metadata["mode"]) == 0o700, "receipt private root policy refused")
        for group, maximums in (("inputs", {"request": MAX_DOCUMENT, "image": image.MAX_ARCHIVE, "producer_receipt": MAX_DOCUMENT}),
                               ("files", {"cw": image.MAX_CW, "provenance.json": image.MAX_JSON})):
            target = context.inputs if group == "inputs" else context.files
            for name, maximum in maximums.items():
                expected = value[group][name]
                require(type(expected) is dict and set(expected) == {"path", "sha256", "size", "metadata"},
                        "receipt file evidence fields refused")
                binding({k: expected[k] for k in ("path", "sha256", "size")}, maximum)
                metadata_model(expected["metadata"])
                if group == "files":
                    require(expected["path"] == str(context.path / name), "context file path refused")
                target[name] = HeldFile(expected["path"], maximum, expected)
                require(target[name].evidence() == expected, "original file identity changed")
        request = request_model(context.inputs["request"].data)
        for name in ("image", "producer_receipt"):
            require(request[name] == {k: value["inputs"][name][k] for k in ("path", "sha256", "size")},
                    "receipt differs from original request")
        cw, provenance = asset_admission(context, request)
        require(value["payload"] == context.payload and value["provenance"] == context.provenance
                and context.files["cw"].data == cw and context.files["provenance.json"].data == provenance,
                "context differs from original admitted asset")
        # Compare canonical bytes too: Python equality alone equates true/1.
        require(release.canonical(context.receipt()) == receipt_file.data, "receipt is not the exact admitted model")
        context.receipt_path, context.receipt_sha256 = receipt_file.path, receipt_sha256
        context.revalidate()
        return context
    except BaseException:
        context.close()
        raise


class SingleUse(argparse.Action):
    def __call__(self, parser, namespace, value, option_string=None):
        if getattr(namespace, self.dest, None) is not None or not value:
            parser.error("option must occur exactly once with a nonempty value")
        setattr(namespace, self.dest, value)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare_args = commands.add_parser("prepare", allow_abbrev=False)
    prepare_args.add_argument("--request", required=True, action=SingleUse)
    prepare_args.add_argument("--request-sha256", required=True, action=SingleUse)
    prepare_args.add_argument("--output", required=True, action=SingleUse)
    verify_args = commands.add_parser("verify", allow_abbrev=False)
    verify_args.add_argument("--receipt", required=True, action=SingleUse)
    verify_args.add_argument("--receipt-sha256", required=True, action=SingleUse)
    args = parser.parse_args(argv)
    try:
        operation = (prepare(args.request, args.request_sha256, args.output) if args.command == "prepare"
                     else verify(args.receipt, args.receipt_sha256))
        with operation as context:
            context.revalidate()
            active()
            print(json.dumps({"status": "asset-admitted", "claim": CLAIM, "producer_semantics_verified": False,
                              "context_name": CONTEXT_NAME, "context": str(context.path),
                              "receipt": str(context.receipt_path) if args.command == "prepare" else args.receipt,
                              "receipt_sha256": context.receipt_sha256 if args.command == "prepare" else args.receipt_sha256,
                              "cw_sha256": context.payload["sha256"]}, sort_keys=True))
        return 0
    except (release.ReleaseError, OSError, ValueError, KeyError, TypeError, tarfile.TarError) as error:
        # Errors from untrusted inputs can contain names or values. Keep only
        # the fixed error class, with no receipt/body/path material on stderr.
        print("cw image context: REJECT " + type(error).__name__, file=sys.stderr)
        return 1


if __name__ == "__main__":
    def stop(signum, _frame):
        global STOP
        STOP = signum

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    raise SystemExit(main())
