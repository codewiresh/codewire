#!/usr/bin/env python3
"""Shared cw release identity, delivery manifest and OpenPGP verification.

One identity producer describes each final executable: its effective compiled
version, size, SHA-256, target, source revision, source digest and toolchain.
The version, target, compiler and source come from the one closed build record
crates/codewire-cli/build.rs embeds in the executable, and must equal what the
producer admitted; the digest and size are computed from the bytes. The same
bytes back the raw release asset, the OCI image layer and the native runtime
pack. A closed canonical release manifest binds every target identity and
transport object, and the existing release OpenPGP key signs it.

Subcommands:
  prepare        build identities, OCI/pack transports and the unsigned manifest
  verify         re-derive and check a prepared or signed delivery directory
  manifest       bind the signed SHA256SUMS into the canonical release manifest
  pointer        write the stable channel pointer for the signed manifest
  channel        assemble the signed channel object from that pointer's signature
  digest         print one content digest of a delivery tree (artifact integrity)
  source-digest  print the source revision and digest a build must embed
  admit          admit one built executable: unchanged source, every compiled
                 input digested and its build record

Nothing here uses the network or a provider credential.
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
RUNTIME_IMAGE_TOOL = ROOT / "scripts/dev/cw-runtime-image.py"

# Identity contract shared with crates/codewire-cw-release (schema 2).
PAYLOAD_SCHEMA_VERSION = 2
PROTOCOL_VERSION = 1
RECORD_VERSION = 1
MIN_EXECUTABLE = 64
MAX_EXECUTABLE = 256 * 1024 * 1024
MAX_JSON = 64 * 1024
MAX_SIGNATURE = 16 * 1024
RELEASE_TARGETS = (
    "aarch64-apple-darwin",
    "aarch64-unknown-linux-gnu",
    "x86_64-apple-darwin",
    "x86_64-unknown-linux-musl",
)
# Native runtime transports exist only for this target.
RUNTIME_TARGET = "x86_64-unknown-linux-musl"
OBJECT_PREFIX = "cw/v1"
RELEASE_SCHEMA = "codewire.cw.release/v1"
CHANNEL_SCHEMA = "codewire.cw.channel/v1"
CHANNELS = ("stable",)
# Production trust: the checked-in release key and its exact fingerprint, the
# same pair cw compiles in (crates/codewire-cli/src/public_fetch.rs). Tests
# pass their own Trust explicitly.
PRODUCTION_KEY = ROOT / "apps/cli/GPG_PUBLIC_KEY.asc"
PRODUCTION_FINGERPRINT = "A38FF6BC6623FCA611A7A32B5EFBF0F4A5870815"
# Source-digest inputs: the Rust/protocol patterns, every other file Cargo
# compiles into cw, and the producers that turn those bytes into identities.
# A build whose dep-info names any other repository file is refused.
SOURCE_PATHSPEC = ("*.rs", "*.toml", "*.lock", "*.proto",
                   "apps/cli/GPG_PUBLIC_KEY.asc",
                   "crates/codewire-credential-broker/src/ssh_agent/askpass.sh",
                   "crates/codewire-egress-policy/policies", "crates/codewire-mesh/migrations",
                   "crates/codewire-proto/codewire_descriptor.bin",
                   "crates/codewire-server-core/migrations", "scripts/ci/release/cw_release.py",
                   "scripts/dev/build-cw.py", "scripts/dev/build-native-managed-agent.py",
                   "scripts/dev/cw-runtime-image.py", "images/cw-runtime/Dockerfile",
                   "scripts/ci/images/prepare-cw-source-context.py",
                   "scripts/ci/images/build-cw-runtime-source.py",
                   "scripts/ci/images/finalize-cw-runtime-source.py",
                   "scripts/ci/images/prepare-cw-image-context.py",
                   "scripts/ci/images/run-rust-build.sh",
                   "scripts/ci/verify/kind/cw_runtime_probe.py",
                   "scripts/ci/verify/build-linux-vmm-kernel.py")
# Cargo's server-core rerun-if-changed rule names this directory. Its leaves,
# rather than the directory name, are source-digest inputs. No other directory
# dependency is admitted by this exception.
SOURCE_DIRECTORY_INPUTS = ("crates/codewire-server-core/migrations",)
MAX_SOURCE_DIRECTORY_ENTRIES = 4096
MAX_SOURCE_DIRECTORY_DEPTH = 16
# The closed record crates/codewire-cli/build.rs embeds once in every cw.
BUILD_RECORD_MAGIC = b"\0codewire-cw-build-record-v1\0"
BUILD_RECORD_FIELDS = {"package_version", "rustc", "source_revision", "source_tree_sha256", "target"}
MAX_BUILD_RECORD = 1024
# Host development builds may also target these; releases never do.
DEVELOPMENT_TARGETS = RELEASE_TARGETS + ("aarch64-unknown-linux-musl", "x86_64-unknown-linux-gnu")
RECOVERY_SCHEMA = "codewire.cw.release-recovery/v1"
MAX_RECOVERY = 2 * MAX_JSON + 2 * MAX_SIGNATURE + 4096


class ReleaseError(Exception):
    pass


def require(condition, reason):
    if not condition:
        raise ReleaseError(reason)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def is_hex(value, size):
    return isinstance(value, str) and len(value) == size and all(c in "0123456789abcdef" for c in value)


def exact(value, expected):
    return type(value) is type(expected) and value == expected


def canonical(value):
    """Sorted keys, compact separators, ASCII only, one trailing newline."""
    text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    require(text.isascii(), "canonical JSON must be ASCII")
    return (text + "\n").encode()


def _unique(pairs):
    keys = [key for key, _ in pairs]
    require(len(keys) == len(set(keys)), "JSON has duplicate object keys")
    return dict(pairs)


def parse_json(data, limit=MAX_JSON):
    require(0 < len(data) <= limit, "JSON document exceeds its bound")
    try:
        return json.loads(data, object_pairs_hook=_unique)
    except ReleaseError:
        raise
    except (ValueError, RecursionError):
        raise ReleaseError("JSON document is malformed") from None


def parse_canonical(data, limit=MAX_JSON):
    value = parse_json(data, limit)
    require(canonical(value) == data, "JSON document is not canonical")
    return value


def read_regular(path, limit):
    """Read a bounded regular file without following links or blocking."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        raise ReleaseError(f"{Path(path).name} is not a readable regular file") from None
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= limit,
                f"{Path(path).name} is not a bounded regular file")
        data = handle.read(limit + 1)
    require(len(data) <= limit, f"{Path(path).name} exceeds its bound")
    return data


def write_new(path, data, mode=0o644):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(path, mode)


def blob_key(digest):
    return f"{OBJECT_PREFIX}/blobs/sha256/{digest}"


def release_key(version, name):
    return f"{OBJECT_PREFIX}/releases/{version}/{name}"


def channel_key(channel):
    return f"{OBJECT_PREFIX}/channels/{channel}.json"


def valid_version(value):
    return (isinstance(value, str) and 0 < len(value) <= 64
            and all(c.isascii() and (c.isalnum() or c in ".-+") for c in value))


def release_version(value):
    return isinstance(value, str) and re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?", value) is not None


def version_key(value):
    """Ordering for channel promotion: numeric core, then prerelease below release."""
    match = re.fullmatch(r"v([0-9]+)\.([0-9]+)\.([0-9]+)(?:-([0-9A-Za-z.]+))?", value)
    require(match is not None, "release version is not vMAJOR.MINOR.PATCH")
    core = tuple(int(part) for part in match.group(1, 2, 3))
    return core + ((1, "") if match.group(4) is None else (0, match.group(4)),)


# --- Executable identity -----------------------------------------------------

def check_header(target, data):
    """Admit only a single-architecture executable for the target."""
    require(len(data) >= MIN_EXECUTABLE, "executable is too small")
    if "linux" in target:
        machine = 62 if target.startswith("x86_64") else 183
        require(data[:7] == b"\x7fELF\x02\x01\x01" and data[7] in (0, 3)
                and struct.unpack_from("<H", data, 16)[0] in (2, 3)
                and struct.unpack_from("<H", data, 18)[0] == machine,
                f"executable is not a {target} ELF")
    else:
        cpu = 0x01000007 if target.startswith("x86_64") else 0x0100000C
        magic, cputype, _, filetype = struct.unpack_from("<IIII", data, 0)
        require(magic == 0xFEEDFACF and cputype == cpu and filetype == 2,
                f"executable is not a {target} Mach-O")


def check_static_elf(data):
    """The runtime target must be static: no interpreter, no needed library."""
    offset, = struct.unpack_from("<Q", data, 32)
    size, count = struct.unpack_from("<HH", data, 54)
    require(offset >= 64 and size == 56 and 0 < count <= 128 and offset + size * count <= len(data),
            "runtime executable has invalid ELF program headers")
    for position in range(offset, offset + size * count, size):
        kind, = struct.unpack_from("<I", data, position)
        require(kind != 3, "runtime executable has a dynamic interpreter")
        if kind == 2:
            start, = struct.unpack_from("<Q", data, position + 8)
            length, = struct.unpack_from("<Q", data, position + 32)
            require(length % 16 == 0 and start + length <= len(data), "runtime executable has an invalid dynamic table")
            for entry in range(start, start + length, 16):
                tag, = struct.unpack_from("<q", data, entry)
                if tag == 0:
                    break
                require(tag != 1, "runtime executable names a shared library")


def valid_rustc(value):
    return (isinstance(value, str) and value.startswith("rustc ") and len(value) <= 128
            and value.isascii() and value.isprintable())


def build_record(data):
    """The one closed compile-time record in a cw executable's bytes.

    Its marker must occur exactly once. A version string elsewhere in the bytes
    is never evidence. The source fields are null only for a build that was not
    given explicit provenance.
    """
    start = data.find(BUILD_RECORD_MAGIC)
    require(start >= 0, "executable has no cw build record")
    require(data.find(BUILD_RECORD_MAGIC, start + 1) < 0, "executable has more than one cw build record")
    offset = start + len(BUILD_RECORD_MAGIC)
    require(offset + 4 <= len(data), "cw build record is truncated")
    length, = struct.unpack_from("<I", data, offset)
    body = data[offset + 4:offset + 4 + length]
    require(0 < length <= MAX_BUILD_RECORD and len(body) == length, "cw build record length is invalid")
    record = parse_canonical(body, MAX_BUILD_RECORD)
    require(isinstance(record, dict) and set(record) == BUILD_RECORD_FIELDS,
            "cw build record fields are not the closed set")
    require(valid_version(record["package_version"]), "cw build record version is invalid")
    require(isinstance(record["target"], str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", record["target"]),
            "cw build record target is invalid")
    require(valid_rustc(record["rustc"]), "cw build record compiler is invalid")
    source = (record["source_revision"], record["source_tree_sha256"])
    require(source == (None, None) or (is_hex(source[0], 40) and is_hex(source[1], 64)),
            "cw build record source provenance is invalid")
    return record


def validate_identity(identity, target=None, targets=RELEASE_TARGETS):
    """Closed schema-2 identity, refusing unknown fields and contradictions."""
    fields = {"schema_version", "protocol_version", "record_version", "package_version", "target",
              "source_revision", "source_tree_sha256", "rustc", "sha256", "size"}
    require(isinstance(identity, dict) and set(identity) == fields, "identity fields are not the schema-2 set")
    require(exact(identity["schema_version"], PAYLOAD_SCHEMA_VERSION)
            and exact(identity["protocol_version"], PROTOCOL_VERSION)
            and exact(identity["record_version"], RECORD_VERSION), "identity schema, protocol or record is unsupported")
    require(valid_version(identity["package_version"]), "identity package_version is invalid")
    require(identity["target"] in targets and (target is None or identity["target"] == target),
            "identity target is not the expected release target")
    require(is_hex(identity["source_revision"], 40) and is_hex(identity["source_tree_sha256"], 64)
            and is_hex(identity["sha256"], 64), "identity revision or digest is invalid")
    require(valid_rustc(identity["rustc"]), "identity rustc is invalid")
    require(type(identity["size"]) is int and MIN_EXECUTABLE <= identity["size"] <= MAX_EXECUTABLE,
            "identity size is out of bounds")
    return identity


def source_inputs(root):
    """Sorted repository paths (bytes) of the tracked and untracked digest inputs."""
    names = subprocess.check_output(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard",
                                     "--", *SOURCE_PATHSPEC], cwd=root).split(b"\0")
    return sorted(set(name for name in names if name))


def source_directory_inventory(root, inputs):
    """Validate the complete, bounded inventory of known directory inputs.

    Ignored entries are inspected too. Every real leaf must be regular and in
    the digest, every covered leaf must exist, and every subdirectory must lead
    to a covered leaf. Held directory descriptors and before/after stats refuse
    links, replacement and mutation during enumeration. The returned stamps
    also bind the inventory across source hashing and dep-info admission.
    """
    root = Path(root).absolute()
    covered = {os.fsdecode(name) for name in inputs}
    inventory = {}

    def stamp(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
                info.st_mtime_ns, info.st_ctime_ns)

    def open_directory(name, parent=None):
        info = os.stat(name, dir_fd=parent, follow_symlinks=False)
        require(stat.S_ISDIR(info.st_mode), "source directory input contains a link or non-directory")
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        try:
            require(stamp(os.fstat(fd)) == stamp(info), "source directory input changed while opening")
        except BaseException:
            os.close(fd)
            raise
        return fd

    def walk(fd, relative, expected, depth):
        require(depth <= MAX_SOURCE_DIRECTORY_DEPTH, "source directory input exceeds its depth bound")
        before = stamp(os.fstat(fd))
        inventory[relative] = before
        with os.scandir(fd) as entries:
            for entry in entries:
                name = relative + "/" + entry.name
                require(len(inventory) < MAX_SOURCE_DIRECTORY_ENTRIES,
                        "source directory input exceeds its entry bound")
                info = os.stat(entry.name, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    require(any(leaf.startswith(name + "/") for leaf in expected),
                            "source directory input contains an empty or uncovered directory")
                    child = open_directory(entry.name, fd)
                    try:
                        walk(child, name, expected, depth + 1)
                        require(stamp(os.stat(entry.name, dir_fd=fd, follow_symlinks=False)) ==
                                stamp(os.fstat(child)), "source directory input was replaced")
                    finally:
                        os.close(child)
                else:
                    require(stat.S_ISREG(info.st_mode), "source directory input leaf is not a regular file")
                    require(name in expected, "source directory input contains an undigested leaf")
                    inventory[name] = stamp(info)
        require(stamp(os.fstat(fd)) == before, "source directory input changed during enumeration")

    try:
        for relative in SOURCE_DIRECTORY_INPUTS:
            expected = {name for name in covered if name.startswith(relative + "/")}
            if not expected and not os.path.lexists(root / relative):
                continue  # Small synthetic source repositories need not contain it.
            require(root.resolve(strict=True) == root, "source directory input root is not canonical")
            require(expected, "source directory input is empty or uncovered")
            fds = [open_directory(root)]
            bindings = []
            try:
                for part in relative.split("/"):
                    parent = fds[-1]
                    before = stamp(os.fstat(parent))
                    child = open_directory(part, parent)
                    fds.append(child)
                    bindings.append((parent, part, child, before))
                start = set(inventory)
                walk(fds[-1], relative, expected, 0)
                actual = {name for name in set(inventory) - start
                          if stat.S_ISREG(inventory[name][2])}
                require(actual == expected, "source directory input has missing digest leaves")
                for parent, part, child, before in reversed(bindings):
                    require(stamp(os.fstat(parent)) == before and
                            stamp(os.stat(part, dir_fd=parent, follow_symlinks=False)) ==
                            stamp(os.fstat(child)), "source directory input path changed")
            finally:
                for fd in reversed(fds):
                    os.close(fd)
    except OSError as error:
        raise ReleaseError("source directory input cannot be safely enumerated") from error
    return inventory


def source_tree_sha256(root):
    """Digest of every source input the cw build compiles and its producers."""
    root = Path(root)
    digest = hashlib.sha256()
    inputs = source_inputs(root)
    inventory = source_directory_inventory(root, inputs)
    for raw in inputs:
        path = root / os.fsdecode(raw)
        require(not path.is_symlink() and path.is_file(), "source digest input must be a regular file")
        data = path.read_bytes()
        digest.update(raw + b"\0" + str(len(data)).encode() + b"\0" + hashlib.sha256(data).digest())
    require(source_inputs(root) == inputs and source_directory_inventory(root, inputs) == inventory,
            "source directory inputs changed during hashing")
    return digest.hexdigest()


def head_revision(root):
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    require(is_hex(revision, 40), "source checkout has no 40-hex HEAD revision")
    return revision


def build_environment(version, revision, tree):
    """The explicit inputs build.rs embeds; a build never discovers them itself."""
    require(valid_version(version) and is_hex(revision, 40) and is_hex(tree, 64),
            "build provenance inputs are invalid")
    return {"CODEWIRE_VERSION": version, "CODEWIRE_SOURCE_REVISION": revision,
            "CODEWIRE_SOURCE_TREE_SHA256": tree}


def toolchain_rustc(root, rustc_output):
    import tomllib  # Only release and native producers pin the channel.
    channel = tomllib.loads((Path(root) / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    rustc = rustc_output.strip()
    require(rustc.startswith(f"rustc {channel} "), "actual rustc does not match rust-toolchain.toml")
    return rustc


def make_identity(data, target, version, source_revision, source_tree, rustc, targets=RELEASE_TARGETS):
    """The single identity producer for one final executable's bytes.

    The executable's own build record must name exactly this effective
    version, target, compiler and source. The digest and size are computed
    here from the bytes, never read from them.
    """
    require(target in targets, "target is not an admitted cw target")
    require(MIN_EXECUTABLE <= len(data) <= MAX_EXECUTABLE, "executable is out of bounds")
    check_header(target, data)
    if target == RUNTIME_TARGET:
        check_static_elf(data)
    record = build_record(data)
    require(record["source_revision"] is not None, "executable was compiled without source provenance")
    admitted = {"package_version": version, "target": target, "rustc": rustc,
                "source_revision": source_revision, "source_tree_sha256": source_tree}
    for field, value in admitted.items():
        require(record[field] == value,
                f"executable's compiled {field} {record[field]} differs from the admitted {value}")
    return validate_identity({
        "schema_version": PAYLOAD_SCHEMA_VERSION, "protocol_version": PROTOCOL_VERSION,
        "record_version": RECORD_VERSION, "package_version": version, "target": target,
        "source_revision": source_revision, "source_tree_sha256": source_tree, "rustc": rustc,
        "sha256": sha256(data), "size": len(data),
    }, target, targets)


def depinfo_inputs(path):
    """Dependency paths of a Cargo dep-info file's first rule."""
    text = read_regular(path, 8 * 1024 * 1024).decode()
    line = next((line for line in text.splitlines() if line.strip()), "")
    rule = line.replace("\\ ", "\0").split(" ")
    require(len(rule) > 1 and rule[0].endswith(":"), "dep-info is not a Cargo rule")
    return [Path(token.replace("\0", " ")) for token in rule[1:] if token]


def check_build_inputs(root, depinfo, allowed_outside):
    """Every repository file Cargo compiled must be a source-digest input.

    Paths under `allowed_outside` (the Cargo target directory for build-script
    output, and the Cargo home for lockfile-checksummed dependency sources) are
    not repository inputs. Anything else is refused.
    """
    names = source_inputs(root)
    inventory = source_directory_inventory(root, names)
    root = Path(root).resolve()
    allowed = [Path(path).resolve() for path in allowed_outside]
    inputs = {os.fsdecode(name) for name in names}
    missing, foreign, repository = [], [], 0
    for path in depinfo_inputs(depinfo):
        require(path.is_absolute(), "dep-info path is not absolute")
        resolved = path.resolve()
        if any(resolved.is_relative_to(base) for base in allowed):
            continue
        if not resolved.is_relative_to(root):
            foreign.append(str(path))
            continue
        repository += 1
        relative = resolved.relative_to(root).as_posix()
        if relative in SOURCE_DIRECTORY_INPUTS:
            require(path == resolved and relative in inventory,
                    "compiled directory input is not canonical and covered")
        elif relative not in inputs:
            missing.append(relative)
    require(not foreign, f"compiled inputs outside the repository and Cargo home: {sorted(foreign)[:5]}")
    require(not missing, f"compiled inputs missing from the source digest: {sorted(missing)[:8]}")
    require(repository > 0, "dep-info names no repository input")
    require(source_inputs(root) == names and source_directory_inventory(root, names) == inventory,
            "source directory inputs changed during dep-info admission")
    return repository


def admit_build(root, executable, depinfo, target, version, revision, tree_before, rustc, allowed_outside,
                targets=RELEASE_TARGETS):
    """Admit one freshly built cw: unchanged source, digested inputs and its record."""
    require(head_revision(root) == revision and source_tree_sha256(root) == tree_before,
            "source changed during the build; no identity is emitted")
    inputs = check_build_inputs(root, depinfo, allowed_outside)
    data = read_regular(executable, MAX_EXECUTABLE)
    return data, make_identity(data, target, version, revision, tree_before, rustc, targets), inputs


# --- Runtime transports -------------------------------------------------------

def runtime_transports(executable, identity, work, tool=RUNTIME_IMAGE_TOOL):
    """Build the OCI image and native runtime pack from exactly these bytes."""
    work = Path(work)
    work.mkdir(mode=0o700)
    descriptor = dict(identity)
    descriptor.pop("size")
    descriptor["path"] = str(Path(executable).resolve())
    artifact = work / "artifact.json"
    write_new(artifact, json.dumps(descriptor).encode(), 0o600)
    image_dir, pack_dir = work / "oci", work / "pack"
    # The tool imports this module from its own tree; -B keeps bytecode out of
    # a strict source capsule.
    receipt = json.loads(subprocess.check_output(
        [sys.executable, "-B", str(tool), "build", "--artifact", str(artifact), "--output", str(image_dir)], text=True))
    lock = json.loads(subprocess.check_output(
        [sys.executable, "-B", str(tool), "pack", "--image", str(image_dir / "cw.oci.tar"),
         "--index-sha256", receipt["index_sha256"], "--output", str(pack_dir)], text=True))
    return image_dir, pack_dir, receipt, lock


def decode_pack(data):
    require(len(data) >= 24 and data[:8] == b"CWRPACK1", "runtime pack framing is invalid")
    provenance_len, payload_len = struct.unpack_from("<QQ", data, 8)
    require(24 + provenance_len + payload_len == len(data), "runtime pack has truncated or trailing bytes")
    provenance = parse_json(data[24:24 + provenance_len], 16 * 1024)
    return provenance, data[24 + provenance_len:]


def check_transports(executable_bytes, identity, oci_archive, image_receipt, pack_bytes, lock_bytes,
                     tool=RUNTIME_IMAGE_TOOL):
    """Prove the OCI layer and runtime pack carry exactly the raw executable."""
    require(image_receipt["cw_sha256"] == identity["sha256"]
            and image_receipt["archive_sha256"] == sha256(oci_archive)
            and image_receipt["index_sha256"] != image_receipt["archive_sha256"],
            "OCI receipt does not bind the raw executable and its archive")
    with tempfile.TemporaryDirectory(prefix="cw-release-unpack.") as scratch:
        image = Path(scratch) / "cw.oci.tar"
        write_new(image, oci_archive, 0o600)
        out = Path(scratch) / "out"
        subprocess.run([sys.executable, "-B", str(tool), "unpack", "--image", str(image),
                        "--index-sha256", image_receipt["index_sha256"], "--output", str(out)],
                       check=True, stdout=subprocess.DEVNULL)
        require((out / "cw").read_bytes() == executable_bytes, "OCI layer bytes differ from the raw executable")
    provenance, payload = decode_pack(pack_bytes)
    require(payload == executable_bytes, "runtime pack bytes differ from the raw executable")
    require(provenance.get("payload") == identity and provenance.get("image_index_sha256") == image_receipt["index_sha256"],
            "runtime pack provenance differs from the release identity")
    lock = parse_canonical(lock_bytes)
    require(lock == {"schema_version": 1, "image_index_sha256": image_receipt["index_sha256"],
                     "pack": {"path": "runtime.pack", "size": len(pack_bytes), "sha256": sha256(pack_bytes)}},
            "runtime lock does not bind the pack and image index")


# --- Local VM runtime (#2539) ---------------------------------------------------
# The document a release's cw embeds (crates/codewire-cli/build.rs) and the
# blobs it pins. Shared contract with crates/codewire-cw-release/src/
# local_runtime.rs, whose decoder this mirrors. release.json never lists it:
# older cw decode release.json strictly, and the runtime is trusted through the
# embedding cw's own verified bytes.

LOCAL_RUNTIME_SCHEMA = "codewire.cw.local-runtime/v1"
LOCAL_RUNTIME_NAME = "local-runtime.json"
LOCAL_RUNTIME_DIR = "local-runtime"
# The canonical document's first bytes: its keys sort schema first.
LOCAL_RUNTIME_PREFIX = b'{"schema":"codewire.cw.local-runtime/v1",'
MAX_OBJECT = MAX_EXECUTABLE + 8 * 1024 * 1024
MAX_RUNTIME_COMPONENTS = 32
MAX_RUNTIME_TEXT = 128
RUNTIME_PLATFORMS = ("linux-x86_64", "linux-aarch64", "macos-x86_64", "macos-aarch64")
# The release target whose cw must embed a delivery's runtime.
LOCAL_RUNTIME_TARGET = "aarch64-apple-darwin"
SPEC_FIELDS = {"path", "size", "sha256", "architecture"}


def _blob_size(value):
    return type(value) is int and 1 <= value <= MAX_OBJECT


def _runtime_text(value, extra):
    return (isinstance(value, str) and 0 < len(value) <= MAX_RUNTIME_TEXT
            and all(c.isascii() and (c.isalnum() or c in extra) for c in value))


def _blob_ref(value, label):
    require(isinstance(value, dict) and set(value) == {"sha256", "size"}
            and is_hex(value["sha256"], 64) and _blob_size(value["size"]), f"local runtime {label} is invalid")
    return value["sha256"], value["size"]


def _runtime_lock_files(platform, lock):
    """The lock's files, checked exactly as the Rust decoder checks them."""
    require(isinstance(lock, dict), "local runtime lock is invalid")
    architecture = platform.rsplit("-", 1)[1]
    specs = []

    def spec(value, versioned=False):
        fields = SPEC_FIELDS | ({"version"} if versioned else set())
        require(isinstance(value, dict) and set(value) == fields, "local runtime lock is invalid")
        if versioned:
            require(isinstance(value["version"], str) and 0 < len(value["version"]) <= MAX_RUNTIME_TEXT,
                    "local runtime lock is invalid")
        specs.append(value)

    if platform.startswith("macos-"):
        require(set(lock) == {"schema_version", "vz_runner", "e2fsprogs", "git", "kernel", "initramfs"}
                and platform == "macos-aarch64", "local runtime lock is invalid")
        e2fsprogs, git = lock["e2fsprogs"], lock["git"]
        require(isinstance(e2fsprogs, dict) and set(e2fsprogs) == {"mkfs_ext4", "e2fsck", "resize2fs", "debugfs",
                                                                  "mke2fs_conf"}
                and isinstance(git, dict) and set(git) == {"git", "git_remote_https"},
                "local runtime lock is invalid")
        for value in (lock["vz_runner"], lock["kernel"], lock["initramfs"], e2fsprogs["mkfs_ext4"],
                      e2fsprogs["e2fsck"], e2fsprogs["resize2fs"], e2fsprogs["debugfs"],
                      e2fsprogs["mke2fs_conf"], git["git"], git["git_remote_https"]):
            spec(value)
    else:
        require({"schema_version", "cloud_hypervisor", "kernel", "initramfs"} <= set(lock)
                <= {"schema_version", "cloud_hypervisor", "virtiofsd", "kernel", "initramfs"},
                "local runtime lock is invalid")
        spec(lock["cloud_hypervisor"], versioned=True)
        spec(lock["kernel"])
        spec(lock["initramfs"])
        if lock.get("virtiofsd") is not None:
            spec(lock["virtiofsd"], versioned=True)
    require(type(lock["schema_version"]) is int and lock["schema_version"] == 1, "local runtime lock is invalid")
    paths = set()
    for value in specs:
        path = value["path"]
        require(_runtime_text(path, "-_.") and path not in (".", "..") and path not in paths
                and is_hex(value["sha256"], 64) and _blob_size(value["size"])
                and value["architecture"] == architecture, "local runtime lock file is invalid")
        paths.add(path)
    return [(value["sha256"], value["size"]) for value in specs]


def local_runtime_blobs(document):
    """Validate a canonical local runtime document; return every blob it pins.

    The result is each (sha256, size) once, sorted by digest: the lock files,
    the cw runtime and the component sources of every target.
    """
    value = parse_canonical(document)
    require(isinstance(value, dict) and set(value) == {"schema", "source_revision", "targets"}
            and value["schema"] == LOCAL_RUNTIME_SCHEMA and is_hex(value["source_revision"], 40),
            "local runtime identity is invalid")
    targets = value["targets"]
    require(isinstance(targets, dict) and targets, "local runtime targets are invalid")
    references = []
    for platform, target in targets.items():
        require(platform in RUNTIME_PLATFORMS, "local runtime target is invalid")
        require(isinstance(target, dict) and "lock" in target
                and set(target) <= {"lock", "cw_runtime", "components"}, "local runtime target is invalid")
        references += _runtime_lock_files(platform, target["lock"])
        if "cw_runtime" in target:
            cw_runtime = target["cw_runtime"]
            require(isinstance(cw_runtime, dict) and set(cw_runtime) == {"lock", "pack"},
                    "local runtime cw runtime is invalid")
            references += [_blob_ref(cw_runtime["lock"], "cw runtime"), _blob_ref(cw_runtime["pack"], "cw runtime")]
        if "components" in target:
            components = target["components"]
            require(isinstance(components, list) and 0 < len(components) <= MAX_RUNTIME_COMPONENTS,
                    "local runtime components are invalid")
            for component in components:
                require(isinstance(component, dict) and set(component) == {"name", "version", "license", "source"}
                        and _runtime_text(component["name"], "-_.")
                        and _runtime_text(component["version"], "-_.+")
                        and _runtime_text(component["license"], "-_.+ ()"),
                        "local runtime component is invalid")
                references.append(_blob_ref(component["source"], "component source"))
    sizes = {}
    for digest, size in references:
        require(sizes.setdefault(digest, size) == size, "local runtime blob sizes disagree")
    return sorted(sizes.items())


def embedded_local_runtime(data):
    """The local runtime document a cw executable embeds, or None.

    build.rs includes the canonical document's exact bytes, which begin with
    LOCAL_RUNTIME_PREFIX and end at their single newline. It must occur at most
    once and must validate.
    """
    start = data.find(LOCAL_RUNTIME_PREFIX)
    if start < 0:
        return None
    require(data.find(LOCAL_RUNTIME_PREFIX, start + 1) < 0, "executable embeds more than one local runtime")
    end = data.find(b"\n", start, start + MAX_JSON)
    require(end > start, "embedded local runtime is truncated or exceeds its bound")
    document = data[start:end + 1]
    local_runtime_blobs(document)
    return document


def local_runtime_paths(dist):
    root = Path(dist) / DELIVERY / LOCAL_RUNTIME_DIR
    return root, root / LOCAL_RUNTIME_NAME, root / "blobs/sha256"


def _verify_blob_file(path, digest, size):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        raise ReleaseError(f"local runtime blob {digest} is not a readable regular file") from None
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size == size, f"local runtime blob {digest} has the wrong size")
        hasher, total = hashlib.sha256(), 0
        while chunk := handle.read(1024 * 1024):
            total += len(chunk)
            require(total <= size, f"local runtime blob {digest} grew while it was read")
            hasher.update(chunk)
    require(total == size and hasher.hexdigest() == digest, f"local runtime blob {digest} differs from its digest")


def load_local_runtime(dist):
    """A delivery's local runtime directory, or None when it has none."""
    return load_local_runtime_dir(local_runtime_paths(dist)[0])


def load_local_runtime_dir(root):
    """A local runtime directory, or None when there is none.

    It holds exactly the canonical document and the blobs it pins, each with
    its exact size and digest: nothing more. The release packer stages one
    as <dist>/local-runtime and prepare moves it into the delivery.
    """
    root = Path(root)
    document_path, blobs = root / LOCAL_RUNTIME_NAME, root / "blobs/sha256"
    try:
        info = os.lstat(root)
    except FileNotFoundError:
        return None
    require(stat.S_ISDIR(info.st_mode) and sorted(os.listdir(root)) == ["blobs", LOCAL_RUNTIME_NAME]
            and not os.path.islink(root / "blobs") and sorted(os.listdir(root / "blobs")) == ["sha256"]
            and not os.path.islink(blobs), "local runtime directory holds other entries")
    document = read_regular(document_path, MAX_JSON)
    pinned = local_runtime_blobs(document)
    require(sorted(os.listdir(blobs)) == [digest for digest, _ in pinned],
            "local runtime blobs are not exactly the pinned files")
    for digest, size in pinned:
        _verify_blob_file(blobs / digest, digest, size)
    return document, pinned


def check_local_runtime(dist, executables, identities):
    """A delivery publishes its runtime exactly when its macOS arm64 cw embeds one.

    Every executable that embeds a document embeds this one, made from the same
    source revision, so no released cw names a runtime this release lacks.
    """
    local = load_local_runtime(dist)
    embedded = {target: embedded_local_runtime(data) for target, data in executables.items()}
    if local is None:
        require(all(document is None for document in embedded.values()),
                "a cw embeds a local runtime the delivery does not carry")
        return None
    document, pinned = local
    require(embedded.get(LOCAL_RUNTIME_TARGET) == document,
            f"the {LOCAL_RUNTIME_TARGET} cw does not embed the delivery's local runtime")
    require(all(found in (None, document) for found in embedded.values()),
            "a cw embeds a different local runtime")
    require(json.loads(document)["source_revision"] == identities[LOCAL_RUNTIME_TARGET]["source_revision"],
            "local runtime source revision differs from the cw that embeds it")
    return document, pinned


# --- Manifest -----------------------------------------------------------------

def object_ref(key, data):
    return {"key": key, "sha256": sha256(data), "size": len(data)}


def asset_name(version, target):
    return f"cw-{version}-{target}"


def checksums_text(version, executables):
    # Same order as `sha256sum cw-* | sort -k2`: by asset name.
    lines = [f"{sha256(executables[target])}  {asset_name(version, target)}"
             for target in sorted(executables, key=lambda target: asset_name(version, target))]
    return ("\n".join(lines) + "\n").encode()


def validate_ref(ref, key=None):
    require(isinstance(ref, dict) and set(ref) == {"key", "sha256", "size"}
            and isinstance(ref["key"], str) and ref["key"].startswith(f"{OBJECT_PREFIX}/")
            and (key is None or ref["key"] == key) and is_hex(ref["sha256"], 64)
            and type(ref["size"]) is int and 0 < ref["size"] <= MAX_EXECUTABLE + 8 * 1024 * 1024,
            "object reference is invalid")
    return ref


def validate_manifest(manifest):
    """Closed release manifest: four targets, consistent identities and objects."""
    fields = {"schema", "release_tag", "package_version", "tag_object_sha", "source_revision",
              "source_tree_sha256", "rustc", "signing_fingerprint", "checksums", "targets"}
    require(isinstance(manifest, dict) and set(manifest) == fields, "manifest fields are not the closed set")
    require(exact(manifest["schema"], RELEASE_SCHEMA), "manifest schema is unsupported")
    version = manifest["release_tag"]
    require(release_version(version) and exact(manifest["package_version"], version),
            "manifest version is not the release tag")
    require(is_hex(manifest["tag_object_sha"], 40) and is_hex(manifest["source_revision"], 40)
            and is_hex(manifest["source_tree_sha256"], 64), "manifest source identity is invalid")
    require(isinstance(manifest["signing_fingerprint"], str)
            and re.fullmatch(r"[0-9A-F]{40}", manifest["signing_fingerprint"]) is not None,
            "manifest signing fingerprint is invalid")
    checksums = manifest["checksums"]
    require(isinstance(checksums, dict) and set(checksums) == {"file", "signature"},
            "manifest checksums are not the closed set")
    validate_ref(checksums["file"], release_key(version, "SHA256SUMS"))
    validate_ref(checksums["signature"], release_key(version, "SHA256SUMS.asc"))
    targets = manifest["targets"]
    require(isinstance(targets, list) and [entry.get("target") if isinstance(entry, dict) else None
                                           for entry in targets] == list(RELEASE_TARGETS),
            "manifest must list exactly the four release targets in order")
    for entry in targets:
        target = entry["target"]
        runtime = target == RUNTIME_TARGET
        keys = {"target", "asset_name", "identity", "executable"}
        if runtime:
            keys |= {"oci", "runtime_pack", "runtime_lock"}
        require(set(entry) == keys, f"{target} entry fields are not the closed set")
        require(exact(entry["asset_name"], asset_name(version, target)), f"{target} asset name is wrong")
        identity = validate_identity(entry["identity"], target)
        require(identity["package_version"] == version and identity["source_revision"] == manifest["source_revision"]
                and identity["source_tree_sha256"] == manifest["source_tree_sha256"]
                and identity["rustc"] == manifest["rustc"], f"{target} identity contradicts the release")
        executable = validate_ref(entry["executable"], blob_key(identity["sha256"]))
        require(executable["sha256"] == identity["sha256"] and executable["size"] == identity["size"],
                f"{target} executable contradicts its identity")
        if runtime:
            oci = entry["oci"]
            require(isinstance(oci, dict) and set(oci) == {"index_sha256", "manifest_sha256", "archive"}
                    and is_hex(oci["index_sha256"], 64) and is_hex(oci["manifest_sha256"], 64),
                    "OCI reference is invalid")
            archive = validate_ref(oci["archive"])
            require(archive["key"] == blob_key(archive["sha256"]) and archive["sha256"] != oci["index_sha256"],
                    "OCI archive and index hashes are not distinct objects")
            for name in ("runtime_pack", "runtime_lock"):
                ref = validate_ref(entry[name])
                require(ref["key"] == blob_key(ref["sha256"]), f"{name} key is not content-addressed")
    return manifest


def build_manifest(version, tag_object_sha, source_revision, source_tree, rustc, entries, sums, sums_signature_ref,
                   fingerprint=PRODUCTION_FINGERPRINT):
    manifest = {
        "schema": RELEASE_SCHEMA, "release_tag": version, "package_version": version,
        "tag_object_sha": tag_object_sha, "source_revision": source_revision,
        "source_tree_sha256": source_tree, "rustc": rustc,
        "signing_fingerprint": fingerprint,
        "checksums": {"file": object_ref(release_key(version, "SHA256SUMS"), sums),
                      "signature": sums_signature_ref},
        "targets": [entries[target] for target in RELEASE_TARGETS],
    }
    return validate_manifest(manifest)


# --- OpenPGP trust ------------------------------------------------------------

class Trust:
    """A public key file and the exact primary fingerprint that must sign."""

    def __init__(self, key_file, fingerprint):
        require(re.fullmatch(r"[0-9A-F]{40}", fingerprint) is not None, "trust fingerprint is invalid")
        self.key_file = Path(key_file)
        self.fingerprint = fingerprint


PRODUCTION_TRUST = Trust(PRODUCTION_KEY, PRODUCTION_FINGERPRINT)


def verify_detached(data, signature, trust):
    """Verify one detached signature by exactly the trusted primary key."""
    require(0 < len(signature) <= MAX_SIGNATURE, "signature exceeds its bound")
    with tempfile.TemporaryDirectory(prefix="cw-release-gpg.") as home:
        os.chmod(home, 0o700)
        env = {"GNUPGHOME": home, "PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C"}
        listed = subprocess.run(["gpg", "--no-options", "--no-autostart", "--batch", "--with-colons", "--import-options", "show-only",
                                 "--import", str(trust.key_file)], env=env, capture_output=True, text=True, timeout=15)
        primaries = [line.split(":") for line in listed.stdout.splitlines() if line.startswith("pub:")]
        fingerprints = []
        lines = listed.stdout.splitlines()
        for index, line in enumerate(lines):
            if line.startswith("pub:") and index + 1 < len(lines) and lines[index + 1].startswith("fpr:"):
                fingerprints.append(lines[index + 1].split(":")[9])
        require(listed.returncode == 0 and len(primaries) == 1 and fingerprints == [trust.fingerprint],
                "trusted key file does not contain exactly the trusted primary key")
        subprocess.run(["gpg", "--no-options", "--no-autostart", "--batch", "--import", str(trust.key_file)], env=env,
                       capture_output=True, check=True, timeout=15)
        data_path, sig_path = Path(home) / "data", Path(home) / "data.asc"
        data_path.write_bytes(data)
        sig_path.write_bytes(signature)
        result = subprocess.run(["gpg", "--no-options", "--no-autostart", "--batch", "--status-fd", "1", "--verify", str(sig_path), str(data_path)],
                                env=env, capture_output=True, text=True, timeout=15)
    status = [line.split() for line in result.stdout.splitlines() if line.startswith("[GNUPG:] ")]
    valid = [fields for fields in status if fields[1] == "VALIDSIG"]
    bad = [fields for fields in status if fields[1] in ("BADSIG", "ERRSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG")]
    require(result.returncode == 0 and not bad and len(valid) == 1
            and valid[0][-1] == trust.fingerprint, "signature is not a valid signature by the trusted key")


# --- Channel objects ------------------------------------------------------------

def channel_pointer(channel, manifest_bytes, signature_bytes, version):
    require(channel in CHANNELS, "channel is not admitted")
    return {"channel": channel, "release_tag": version,
            "release": object_ref(release_key(version, "release.json"), manifest_bytes),
            "release_signature": object_ref(release_key(version, "release.json.asc"), signature_bytes)}


def validate_pointer(pointer):
    require(isinstance(pointer, dict) and set(pointer) == {"channel", "release_tag", "release", "release_signature"}
            and pointer["channel"] in CHANNELS and release_version(pointer["release_tag"]),
            "channel pointer fields are not the closed set")
    validate_ref(pointer["release"], release_key(pointer["release_tag"], "release.json"))
    validate_ref(pointer["release_signature"], release_key(pointer["release_tag"], "release.json.asc"))
    return pointer


def channel_object(pointer, signature):
    validate_pointer(pointer)
    text = signature.decode("ascii")
    require(text.startswith("-----BEGIN PGP SIGNATURE-----"), "channel signature is not armored")
    return canonical({"schema": CHANNEL_SCHEMA, "pointer": pointer, "signature": text})


def verify_channel(data, trust):
    """A channel object is one canonical document carrying its own signature."""
    value = parse_canonical(data)
    require(isinstance(value, dict) and set(value) == {"schema", "pointer", "signature"}
            and exact(value["schema"], CHANNEL_SCHEMA) and isinstance(value["signature"], str),
            "channel object fields are not the closed set")
    pointer = validate_pointer(value["pointer"])
    verify_detached(canonical(pointer), value["signature"].encode("ascii"), trust)
    return pointer


# --- Delivery directory -----------------------------------------------------------

DELIVERY = "delivery"


def delivery_paths(dist):
    dist = Path(dist)
    delivery = dist / DELIVERY
    return {
        "sums": dist / "SHA256SUMS", "sums_sig": dist / "SHA256SUMS.asc",
        "manifest": delivery / "release.json", "manifest_sig": delivery / "release.json.asc",
        "pointer": delivery / "channels/stable.pointer.json", "channel": delivery / "channels/stable.json",
        "oci": delivery / "runtime/cw.oci.tar", "image": delivery / "runtime/image.json",
        "pack": delivery / "runtime/runtime.pack", "lock": delivery / "runtime/cw-runtime.lock.json",
        "identities": delivery / "identities",
    }


def prepare(dist, version, source_root, source_sha, tag_object_sha, rustc_output, tool=RUNTIME_IMAGE_TOOL,
            source_digest_before=None):
    """Derive identities, transports and the unsigned manifest for a package."""
    dist, source_root = Path(dist), Path(source_root)
    require(release_version(version), "release version is not vMAJOR.MINOR.PATCH")
    require(is_hex(source_sha, 40) and is_hex(tag_object_sha, 40), "source and tag object must be 40-hex")
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source_root, text=True).strip()
    require(head == source_sha, "packaged checkout is not the selected source revision")
    source_tree = source_tree_sha256(source_root)
    require(source_digest_before is None or source_digest_before == source_tree,
            "source changed while the release was built")
    rustc = toolchain_rustc(source_root, rustc_output)
    paths = delivery_paths(dist)
    require(not (dist / DELIVERY).exists(), "delivery directory already exists")
    (dist / DELIVERY).mkdir(mode=0o755)
    # The runtime the macOS cw was built to embed, staged by the packer.
    staged = dist / LOCAL_RUNTIME_DIR
    if load_local_runtime_dir(staged) is not None:
        os.rename(staged, local_runtime_paths(dist)[0])
    paths["identities"].mkdir()
    executables, entries = {}, {}
    for target in RELEASE_TARGETS:
        data = read_regular(dist / asset_name(version, target), MAX_EXECUTABLE)
        identity = make_identity(data, target, version, source_sha, source_tree, rustc)
        write_new(paths["identities"] / f"{target}.json", canonical(identity))
        executables[target] = data
        entries[target] = {"target": target, "asset_name": asset_name(version, target), "identity": identity,
                           "executable": object_ref(blob_key(identity["sha256"]), data)}
    with tempfile.TemporaryDirectory(prefix="cw-release-runtime.") as scratch:
        image_dir, pack_dir, receipt, _ = runtime_transports(
            dist / asset_name(version, RUNTIME_TARGET), entries[RUNTIME_TARGET]["identity"],
            Path(scratch) / "work", tool)
        (dist / DELIVERY / "runtime").mkdir()
        for source, target in ((image_dir / "cw.oci.tar", paths["oci"]), (image_dir / "image.json", paths["image"]),
                               (pack_dir / "runtime.pack", paths["pack"]),
                               (pack_dir / "cw-runtime.lock.json", paths["lock"])):
            write_new(target, source.read_bytes())
    oci, pack, lock = paths["oci"].read_bytes(), paths["pack"].read_bytes(), paths["lock"].read_bytes()
    check_transports(executables[RUNTIME_TARGET], entries[RUNTIME_TARGET]["identity"], oci, receipt, pack, lock, tool)
    entries[RUNTIME_TARGET].update({
        "oci": {"index_sha256": receipt["index_sha256"], "manifest_sha256": receipt["manifest_sha256"],
                "archive": object_ref(blob_key(sha256(oci)), oci)},
        "runtime_pack": object_ref(blob_key(sha256(pack)), pack),
        "runtime_lock": object_ref(blob_key(sha256(lock)), lock),
    })
    sums = read_regular(paths["sums"], MAX_JSON)
    require(sums == checksums_text(version, executables), "SHA256SUMS does not list exactly the four raw assets")
    return entries, sums, source_tree, rustc


def finish_manifest(dist, version, tag_object_sha, source_sha, source_tree, rustc, entries,
                    fingerprint=PRODUCTION_FINGERPRINT):
    """Bind the signed SHA256SUMS into the manifest once its signature exists."""
    paths = delivery_paths(dist)
    sums = read_regular(paths["sums"], MAX_JSON)
    sums_sig = read_regular(paths["sums_sig"], MAX_SIGNATURE)
    manifest = build_manifest(version, tag_object_sha, source_sha, source_tree, rustc, entries, sums,
                              object_ref(release_key(version, "SHA256SUMS.asc"), sums_sig), fingerprint)
    return canonical(manifest)


def verify_delivery(dist, trust=None, tool=RUNTIME_IMAGE_TOOL):
    """Re-derive every hash and cross-check a delivery directory.

    Without trust, only the unsigned structure is checked (CI dry-run). With
    trust, the SHA256SUMS, release manifest and channel signatures must verify.
    """
    paths = delivery_paths(dist)
    sums = read_regular(paths["sums"], MAX_JSON)
    identities = {}
    for target in RELEASE_TARGETS:
        identities[target] = validate_identity(
            parse_canonical(read_regular(paths["identities"] / f"{target}.json", MAX_JSON)), target)
    versions = {identity["package_version"] for identity in identities.values()}
    require(len(versions) == 1, "target identities disagree on the effective version")
    version = versions.pop()
    executables = {}
    for target, identity in identities.items():
        data = read_regular(Path(dist) / asset_name(version, target), MAX_EXECUTABLE)
        # Re-derive from the bytes and their build record, never trust the file.
        require(make_identity(data, target, version, identity["source_revision"], identity["source_tree_sha256"],
                              identity["rustc"]) == identity, f"{target} raw asset contradicts its identity")
        executables[target] = data
    require(sums == checksums_text(version, executables), "SHA256SUMS does not list exactly the four raw assets")
    oci, pack, lock = (read_regular(paths[name], MAX_EXECUTABLE + 8 * 1024 * 1024) for name in ("oci", "pack", "lock"))
    receipt = parse_json(read_regular(paths["image"], MAX_JSON))
    check_transports(executables[RUNTIME_TARGET], identities[RUNTIME_TARGET], oci, receipt, pack, lock, tool)
    local_runtime = check_local_runtime(dist, executables, identities)
    result = {"targets": len(identities), "version": version, "runtime_equal": True, "signed": False}
    if local_runtime is not None:
        result["local_runtime"] = {"document_sha256": sha256(local_runtime[0]), "blobs": len(local_runtime[1])}
    if trust is None:
        return result
    verify_detached(sums, read_regular(paths["sums_sig"], MAX_SIGNATURE), trust)
    manifest_bytes = read_regular(paths["manifest"], MAX_JSON)
    manifest_sig = read_regular(paths["manifest_sig"], MAX_SIGNATURE)
    verify_detached(manifest_bytes, manifest_sig, trust)
    manifest = validate_manifest(parse_canonical(manifest_bytes))
    require(manifest["release_tag"] == version and manifest["signing_fingerprint"] == trust.fingerprint,
            "manifest version or signer contradicts the delivery")
    require(manifest["checksums"]["file"] == object_ref(release_key(version, "SHA256SUMS"), sums)
            and manifest["checksums"]["signature"]["sha256"] == sha256(read_regular(paths["sums_sig"], MAX_SIGNATURE)),
            "manifest does not bind the signed SHA256SUMS")
    for entry in manifest["targets"]:
        target = entry["target"]
        require(entry["identity"] == identities[target], f"{target} manifest identity differs from the delivery")
        require(entry["executable"] == object_ref(blob_key(identities[target]["sha256"]), executables[target]),
                f"{target} manifest executable differs from the delivery")
    runtime = manifest["targets"][RELEASE_TARGETS.index(RUNTIME_TARGET)]
    require(runtime["oci"]["archive"] == object_ref(blob_key(sha256(oci)), oci)
            and runtime["oci"]["index_sha256"] == receipt["index_sha256"]
            and runtime["runtime_pack"] == object_ref(blob_key(sha256(pack)), pack)
            and runtime["runtime_lock"] == object_ref(blob_key(sha256(lock)), lock),
            "manifest runtime transports differ from the delivery")
    pointer = verify_channel(read_regular(paths["channel"], MAX_JSON), trust)
    require(pointer == channel_pointer("stable", manifest_bytes, manifest_sig, version),
            "channel object does not point at this signed release")
    result["signed"] = True
    return result


# --- Retry recovery ------------------------------------------------------------------

def check_signed_release(version, manifest_bytes, manifest_sig, sums, sums_sig, trust):
    """A signed manifest and signed SHA256SUMS that bind each other for one version."""
    verify_detached(manifest_bytes, manifest_sig, trust)
    manifest = validate_manifest(parse_canonical(manifest_bytes))
    require(manifest["release_tag"] == version and manifest["signing_fingerprint"] == trust.fingerprint,
            "signed release version or signer differs")
    verify_detached(sums, sums_sig, trust)
    require(manifest["checksums"]["file"] == object_ref(release_key(version, "SHA256SUMS"), sums)
            and manifest["checksums"]["signature"] == object_ref(release_key(version, "SHA256SUMS.asc"), sums_sig),
            "signed manifest does not bind the signed SHA256SUMS")
    return manifest


def recovery_receipt(version, manifest_bytes, manifest_sig, sums, sums_sig):
    """One bounded envelope carrying the exact signed bytes of a release.

    It is created once, after every content-addressed blob and before any named
    signed object, so an interrupted publication recovers its original signed
    delivery rather than signing a rebuild.
    """
    try:
        texts = [value.decode("ascii") for value in (manifest_bytes, manifest_sig, sums, sums_sig)]
    except UnicodeDecodeError:
        raise ReleaseError("signed release objects must be ASCII") from None
    data = canonical({"schema": RECOVERY_SCHEMA, "release_tag": version, "release": texts[0],
                      "release_signature": texts[1], "checksums": texts[2], "checksums_signature": texts[3]})
    require(len(data) <= MAX_RECOVERY, "recovery receipt exceeds its bound")
    return data


def open_recovery_receipt(data, version, trust):
    """Verify a receipt and return its exact signed bytes and manifest."""
    value = parse_canonical(data, MAX_RECOVERY)
    fields = {"schema", "release_tag", "release", "release_signature", "checksums", "checksums_signature"}
    require(isinstance(value, dict) and set(value) == fields and exact(value["schema"], RECOVERY_SCHEMA)
            and exact(value["release_tag"], version)
            and all(isinstance(value[name], str) and value[name].isascii() for name in fields - {"schema"}),
            "recovery receipt fields are not the closed set")
    signed = tuple(value[name].encode("ascii")
                   for name in ("release", "release_signature", "checksums", "checksums_signature"))
    return signed, check_signed_release(version, *signed, trust)


def prepared_candidate(dist):
    """The freshly admitted build this run prepared."""
    state = parse_canonical(read_regular(Path(dist) / DELIVERY / "prepared.json", MAX_JSON))
    require(isinstance(state, dict)
            and set(state) == {"version", "tag_object_sha", "source_sha", "source_tree", "rustc", "entries"},
            "prepared delivery state is not the closed set")
    return state


def require_same_source(manifest, candidate):
    """Reuse a published release only for this run's exact tag, source and toolchain."""
    admitted = {"release_tag": candidate["version"], "tag_object_sha": candidate["tag_object_sha"],
                "source_revision": candidate["source_sha"], "source_tree_sha256": candidate["source_tree"],
                "rustc": candidate["rustc"]}
    for field, value in admitted.items():
        require(manifest[field] == value,
                f"published release {field} differs from this admitted build; refusing to reuse it")


def tree_digest(directory):
    """One digest over every regular file's relative path and bytes.

    Modes are excluded: artifact transfer between jobs does not preserve them.
    """
    directory = Path(directory)
    digest = hashlib.sha256()
    for path in sorted(directory.rglob("*")):
        relative = path.relative_to(directory).as_posix()
        require(not path.is_symlink(), f"{relative} is a link")
        if path.is_dir():
            continue
        require(path.is_file(), f"{relative} is not a regular file")
        digest.update(f"{relative}\0".encode())
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


# --- Command line -------------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    prep = sub.add_parser("prepare")
    prep.add_argument("--dist", type=Path, required=True)
    prep.add_argument("--version", required=True)
    prep.add_argument("--source-root", type=Path, required=True)
    prep.add_argument("--source-sha", required=True)
    prep.add_argument("--tag-object-sha", required=True)
    prep.add_argument("--source-digest-before", required=True)
    stage = sub.add_parser("manifest")
    stage.add_argument("--dist", type=Path, required=True)
    verify = sub.add_parser("verify")
    verify.add_argument("--dist", type=Path, required=True)
    verify.add_argument("--unsigned", action="store_true")
    pointer = sub.add_parser("pointer")
    pointer.add_argument("--dist", type=Path, required=True)
    channel = sub.add_parser("channel")
    channel.add_argument("--dist", type=Path, required=True)
    channel.add_argument("--signature", type=Path, required=True)
    digest = sub.add_parser("digest")
    digest.add_argument("--dist", type=Path, required=True)
    source = sub.add_parser("source-digest")
    source.add_argument("--source-root", type=Path, required=True)
    runtime = sub.add_parser("local-runtime", help="check a local runtime directory before a cw embeds it")
    runtime.add_argument("--dir", type=Path, required=True)
    runtime.add_argument("--source-sha", required=True)
    admit = sub.add_parser("admit")
    admit.add_argument("--source-root", type=Path, required=True)
    admit.add_argument("--executable", type=Path, required=True)
    admit.add_argument("--depinfo", type=Path, required=True)
    admit.add_argument("--target", required=True)
    admit.add_argument("--version", required=True)
    admit.add_argument("--source-sha", required=True)
    admit.add_argument("--source-digest-before", required=True)
    admit.add_argument("--target-dir", type=Path, required=True)
    admit.add_argument("--cargo-home", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "source-digest":
            print(source_tree_sha256(args.source_root))
        elif args.command == "prepare":
            rustc = subprocess.check_output(["rustc", "--version"], cwd=args.source_root, text=True)
            entries, _, source_tree, rustc = prepare(args.dist, args.version, args.source_root, args.source_sha,
                                                     args.tag_object_sha, rustc,
                                                     source_digest_before=args.source_digest_before)
            state = {"version": args.version, "tag_object_sha": args.tag_object_sha, "source_sha": args.source_sha,
                     "source_tree": source_tree, "rustc": rustc, "entries": entries}
            write_new(Path(args.dist) / DELIVERY / "prepared.json", canonical(state))
            print(f"cw-release: prepared targets={len(entries)} version={args.version} runtime_equal=true")
        elif args.command == "manifest":
            state = parse_canonical(read_regular(Path(args.dist) / DELIVERY / "prepared.json", MAX_JSON))
            data = finish_manifest(args.dist, state["version"], state["tag_object_sha"], state["source_sha"],
                                   state["source_tree"], state["rustc"], state["entries"])
            write_new(delivery_paths(args.dist)["manifest"], data)
            print(f"cw-release: manifest sha256={sha256(data)}")
        elif args.command in ("pointer", "channel"):
            paths = delivery_paths(args.dist)
            manifest_bytes = read_regular(paths["manifest"], MAX_JSON)
            manifest = validate_manifest(parse_canonical(manifest_bytes))
            pointer = channel_pointer("stable", manifest_bytes, read_regular(paths["manifest_sig"], MAX_SIGNATURE),
                                      manifest["release_tag"])
            if args.command == "pointer":
                paths["pointer"].parent.mkdir(exist_ok=True)
                write_new(paths["pointer"], canonical(pointer))
            else:
                require(read_regular(paths["pointer"], MAX_JSON) == canonical(pointer),
                        "signed channel pointer differs from the release")
                write_new(paths["channel"], channel_object(pointer, read_regular(args.signature, MAX_SIGNATURE)))
        elif args.command == "verify":
            result = verify_delivery(args.dist, None if args.unsigned else PRODUCTION_TRUST)
            print("cw-release: verified targets={targets} version={version} runtime_equal=true signed={signed}"
                  .format(targets=result["targets"], version=result["version"], signed=str(result["signed"]).lower()))
            if "local_runtime" in result:
                print("cw-release: local runtime document_sha256={document_sha256} blobs={blobs}"
                      .format(**result["local_runtime"]))
        elif args.command == "digest":
            print(tree_digest(args.dist))
        elif args.command == "local-runtime":
            loaded = load_local_runtime_dir(args.dir)
            require(loaded is not None, "local runtime directory is missing")
            document, pinned = loaded
            require(json.loads(document)["source_revision"] == args.source_sha,
                    "local runtime was built from another source revision")
            print(f"cw-release: local runtime document_sha256={sha256(document)} blobs={len(pinned)}")
        elif args.command == "admit":
            rustc = toolchain_rustc(args.source_root, subprocess.check_output(
                ["rustc", "--version"], cwd=args.source_root, text=True))
            # Preparation later restricts the delivery to the release targets.
            _, identity, inputs = admit_build(args.source_root, args.executable, args.depinfo, args.target,
                                              args.version, args.source_sha, args.source_digest_before, rustc,
                                              (args.target_dir, args.cargo_home / "registry",
                                               args.cargo_home / "git"), DEVELOPMENT_TARGETS)
            print(f"cw-release: admitted target={identity['target']} version={identity['package_version']} "
                  f"inputs={inputs} sha256={identity['sha256']}")
    except (ReleaseError, subprocess.CalledProcessError, OSError, KeyError, TypeError) as error:
        reason = error if isinstance(error, ReleaseError) else type(error).__name__
        print(f"cw-release: REJECT {reason}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
