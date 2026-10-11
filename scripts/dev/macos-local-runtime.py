#!/usr/bin/env python3
"""Pack the macOS local VM runtime and install it with `cw setup --local`.

Developer tooling for an Apple Silicon Mac; it runs on the system Python 3.9.
It builds the Virtualization.framework helper in release mode, signs it ad hoc
with exactly developer-entitlements.plist, checks the supplied arm64 kernel
Image, Codewire guest root and pinned e2fsprogs bundle (from
macos-ext4-tool.py) the way artifact admission does, and writes a
release directory (blobs/sha256/<digest> and local-runtime.json, the format a
release publishes). With --cw-runtime it adds a sealed aarch64 cw runtime
(cw-runtime.lock.json and runtime.pack from `cw-runtime-image.py pack`). Then
`cw setup --local --from DIR` installs it; cw refuses a different installed
runtime unless --replace is given. With --pack DIR it only writes DIR.
Nothing is downloaded.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import stat
import subprocess
import sys
import tempfile

PACKAGE = Path(__file__).resolve().parents[2] / "crates/codewire-local-vmm/macos-vz-runner"
ENTITLEMENTS = PACKAGE / "developer-entitlements.plist"
PRODUCT = "codewire-vz-runner"
SWIFT = "swift"
CODESIGN = "/usr/bin/codesign"
OTOOL = "/usr/bin/otool"
# A stock Mac has no e2fsprogs, so the runtime ships the pinned build that
# scripts/dev/macos-ext4-tool.py makes on this Mac: (lock key, bundle file,
# installed name). mke2fs installed as mkfs.ext4 formats ext4 by its name.
E2FSPROGS_TOOLS = (("mkfs_ext4", "mke2fs", "mkfs.ext4"), ("e2fsck", "e2fsck", "e2fsck"),
                   ("resize2fs", "resize2fs", "resize2fs"), ("debugfs", "debugfs", "debugfs"))
E2FSPROGS_CONFIG = ("mke2fs_conf", "mke2fs.conf", "mke2fs.conf")
# macos-ext4-tool.py CONFIG_SHA256: every format uses exactly this mke2fs.conf.
MKE2FS_CONFIG_SHA256 = "539290aab306f0bd03a6b49c90ec2852044150c35538c04e4e9bee016bd3d973"
E2FSPROGS_HINT = ("build it on this Mac with scripts/dev/macos-ext4-tool.py --source-archive "
                  "e2fsprogs-1.47.4.tar.gz --output DIR and pass DIR/bundle")
# A stock Mac's /usr/bin/git only asks for the Xcode Command Line Tools, so the
# runtime ships the pinned git that scripts/dev/macos-git-tool.py makes on this
# Mac, with its HTTPS remote helper: (lock key, bundle file and installed name).
GIT_TOOLS = (("git", "git"), ("git_remote_https", "git-remote-https"))
GIT_VERSION = b"git version 2.56.0\n"
# Stock macOS system libraries only (the dyld shared cache).
GIT_LIBRARIES = {
    "/usr/lib/libSystem.B.dylib", "/usr/lib/libcurl.4.dylib", "/usr/lib/libz.1.dylib",
    "/usr/lib/libiconv.2.dylib",
    "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation",
    "/System/Library/Frameworks/CoreServices.framework/Versions/A/CoreServices",
}
GIT_HINT = ("build it on this Mac with scripts/dev/macos-git-tool.py --source-archive "
            "git-2.56.0.tar.xz --output DIR and pass DIR/bundle")
LOCAL_RUNTIME_SCHEMA = "codewire.cw.local-runtime/v1"
LOCAL_RUNTIME_DOCUMENT = "local-runtime.json"
# cw's host target key (runtime_install::host_target) on Apple Silicon.
TARGET = "macos-aarch64"
REPOSITORY = Path(__file__).resolve().parents[2]
# Lock key, installed file name inside the artifact root, and the mode cw sets.
ARTIFACTS = (("vz_runner", PRODUCT, 0o500), ("kernel", "kernel", 0o400),
             ("initramfs", "initramfs", 0o400))
INITRAMFS_LIMIT = 512 * 1024 * 1024
CHUNK = 1024 * 1024

# The canonical guest root written by codewire-vmm-guest-probe's newc.rs
# (canonical_guest_root_newc). The tests compare these with that source.
NEWC_MAGIC = b"070701"
DIRECTORY_MODE = 0o040755
INIT_MODE = 0o100755
SYMLINK_MODE = 0o120777
NULL_DEVICE_MODE = 0o020666
ARCHIVE_BLOCK = 512
TRAILER = b"TRAILER!!!\0"
CW_RUNTIME_PROVENANCE_ENTRY = b"codewire-cw/provenance.json"
BASIC_BUSYBOX_APPLETS = (
    "[", "awk", "basename", "cat", "chmod", "cp", "cut", "date", "dd", "dirname", "echo", "env",
    "expr", "false", "find", "grep", "head", "hostname", "id", "kill", "ln", "ls", "mkdir",
    "mktemp", "mv", "nproc", "printf", "ps", "pwd", "readlink", "rm", "rmdir", "sed",
    "sha256sum", "sh", "sleep", "sort", "stat", "stty", "sync", "tail", "tee", "test", "touch",
    "tr", "true", "tty", "uname", "wc", "which", "xargs",
)
ELF_MACHINE_AARCH64 = 183
GUEST_ROOT_HINT = ("build it on an x86_64 Linux host with scripts/ci/verify/build-local-vmm-initramfs.sh "
                   "--verify-root --target aarch64-unknown-linux-musl")
# The sealed cw runtime cw installs beside the artifact lock, as written by
# scripts/dev/cw-runtime-image.py pack (crates/codewire-local-vmm cw_runtime.rs).
CW_RUNTIME_LOCK = "cw-runtime.lock.json"
CW_RUNTIME_PACK = "runtime.pack"
CW_RUNTIME_TARGET = "aarch64-unknown-linux-musl"
CW_RUNTIME_PACK_MAGIC = b"CWRPACK1"
CW_RUNTIME_MAX_PROVENANCE = 16 * 1024
CW_RUNTIME_MAX_BYTES = 256 * 1024 * 1024
CW_RUNTIME_MAX_PACK = 24 + CW_RUNTIME_MAX_PROVENANCE + CW_RUNTIME_MAX_BYTES
# A guest root without its trusted live publisher cannot boot with a cw runtime.
LIVE_RUNTIME_CAPABILITY_MARKER = b"CODEWIRE_NATIVE_CW_LIVE_PUBLISHER_V1\0"
CW_RUNTIME_HINT = ("build it on an arm64 Linux host with scripts/dev/build-native-managed-agent.py "
                   "--target aarch64-unknown-linux-musl, then cw-runtime-image.py build and pack")


class InstallError(Exception):
    pass


def log(message: str) -> None:
    print("macos-local-runtime: " + message, flush=True)


def require_host() -> None:
    system, machine = platform.system(), platform.machine()
    if system != "Darwin" or machine != "arm64":
        raise InstallError("macOS local VMs need an Apple Silicon Mac (this host is %s %s)"
                           % (system, machine))


def check_e2fsprogs(bundle: Path) -> dict:
    """The pinned e2fsprogs bundle: lock key -> (bundle file, installed name)."""
    if not bundle.is_absolute() or not bundle.is_dir():
        raise InstallError("E2FSPROGS must be an absolute directory: %s; %s" % (bundle, E2FSPROGS_HINT))
    found = {}
    for key, name, installed in E2FSPROGS_TOOLS:
        path = bundle / name
        if not path.is_file() or path.is_symlink():
            raise InstallError("%s is missing; %s" % (path, E2FSPROGS_HINT))
        try:
            thin_arm64_macho(path)
            report = run([OTOOL, "-L", str(path)], capture=True).decode().splitlines()[1:]
            dependencies = [line.split(" (", 1)[0].strip() for line in report]
            if dependencies != ["/usr/lib/libSystem.B.dylib"]:
                raise InstallError("%s links more than libSystem" % path)
            run([CODESIGN, "--verify", "--strict", str(path)])
        except InstallError as error:
            raise InstallError("%s; %s" % (error, E2FSPROGS_HINT)) from None
        found[key] = (path, installed)
    key, name, installed = E2FSPROGS_CONFIG
    config = bundle / name
    if not config.is_file() or config.is_symlink() or identity(config)[0] != MKE2FS_CONFIG_SHA256:
        raise InstallError("%s is not the pinned mke2fs configuration; %s" % (config, E2FSPROGS_HINT))
    found[key] = (config, installed)
    return found


def check_git(bundle: Path) -> dict:
    """The pinned git bundle: lock key -> (bundle file, installed name)."""
    if not bundle.is_absolute() or not bundle.is_dir():
        raise InstallError("GIT must be an absolute directory: %s; %s" % (bundle, GIT_HINT))
    found = {}
    for key, name in GIT_TOOLS:
        path = bundle / name
        if not path.is_file() or path.is_symlink():
            raise InstallError("%s is missing; %s" % (path, GIT_HINT))
        try:
            thin_arm64_macho(path)
            report = run([OTOOL, "-L", str(path)], capture=True).decode().splitlines()[1:]
            dependencies = {line.split(" (", 1)[0].strip() for line in report}
            if not dependencies <= GIT_LIBRARIES:
                raise InstallError("%s links beyond the stock system libraries" % path)
            run([CODESIGN, "--verify", "--strict", str(path)])
        except InstallError as error:
            raise InstallError("%s; %s" % (error, GIT_HINT)) from None
        found[key] = (path, name)
    version = run(["/usr/bin/env", "-i", str(bundle / "git"), "--version"], capture=True)
    if version != GIT_VERSION:
        raise InstallError("%s is not git 2.56.0; %s" % (bundle / "git", GIT_HINT))
    return found


def input_file(value: str, flag: str) -> Path:
    if not value:
        raise InstallError("%s is required: make macos-local-runtime KERNEL=/abs/Image "
                           "INITRAMFS=/abs/initramfs.cpio" % flag)
    path = Path(value)
    if not path.is_absolute():
        raise InstallError("%s must be an absolute path: %s" % (flag, value))
    try:
        status = os.stat(path)
    except FileNotFoundError:
        raise InstallError("%s does not exist: %s" % (flag, value)) from None
    if not stat.S_ISREG(status.st_mode) or status.st_size == 0:
        raise InstallError("%s must be a non-empty regular file: %s" % (flag, value))
    return path


def elf_header(data: bytes) -> bool:
    return (len(data) >= 20 and data[:4] == b"\x7fELF" and data[4] == 2 and data[5] == 1
            and int.from_bytes(data[16:18], "little") in (2, 3)
            and int.from_bytes(data[18:20], "little") == ELF_MACHINE_AARCH64)


def static_elf(data: bytes) -> bool:
    """An aarch64 ELF without a program interpreter (PT_INTERP)."""
    if not elf_header(data) or len(data) < 64:
        return False
    offset = int.from_bytes(data[32:40], "little")
    entry_size = int.from_bytes(data[54:56], "little")
    count = int.from_bytes(data[56:58], "little")
    if count > 1024 or (count and entry_size < 56):
        return False
    for index in range(count):
        start = offset + index * entry_size
        kind = data[start:start + 4]
        if len(kind) != 4 or int.from_bytes(kind, "little") == 3:
            return False
    return True


def align4(value: int) -> int:
    return (value + 3) & ~3


def newc_entry(archive: bytes, expected: bytes):
    offset = 0
    while True:
        header = archive[offset:offset + 110]
        if len(header) != 110 or header[:6] != NEWC_MAGIC:
            return None
        try:
            file_size, name_size = int(header[54:62], 16), int(header[94:102], 16)
        except ValueError:
            return None
        name_end = offset + 110 + name_size
        data_start = align4(name_end)
        data_end = data_start + file_size
        if name_size == 0 or data_end > len(archive):
            return None
        name = archive[offset + 110:name_end]
        if name[-1:] == b"\0" and name[:-1] == expected:
            return archive[data_start:data_end]
        if name == TRAILER:
            return None
        offset = align4(data_end)


def newc_append(archive: bytearray, inode: int, mode: int, name: bytes, contents: bytes = b"",
                rdev: tuple = (0, 0)) -> None:
    archive += NEWC_MAGIC
    for value in (inode, mode, 0, 0, 1, 0, len(contents), 0, 0, rdev[0], rdev[1], len(name), 0):
        archive += b"%08x" % value
    archive += name
    archive += bytes(-len(archive) % 4)
    archive += contents
    archive += bytes(-len(archive) % 4)


def canonical_guest_root(init: bytes, busybox: bytes, runc: bytes) -> bytes:
    archive = bytearray()
    newc_append(archive, 1, DIRECTORY_MODE, b"dev\0")
    newc_append(archive, 2, NULL_DEVICE_MODE, b"dev/null\0", rdev=(1, 3))
    entries = [(DIRECTORY_MODE, "bin", b""), (DIRECTORY_MODE, "sbin", b""),
               (DIRECTORY_MODE, "run", b""), (INIT_MODE, "init", init),
               (INIT_MODE, "bin/busybox", busybox), (INIT_MODE, "sbin/runc", runc)]
    entries += [(SYMLINK_MODE, "bin/" + applet, b"busybox") for applet in BASIC_BUSYBOX_APPLETS]
    for inode, (mode, name, contents) in enumerate(entries, start=3):
        newc_append(archive, inode, mode, name.encode() + b"\0", contents)
    newc_append(archive, 0, 0, TRAILER)
    archive += bytes(-len(archive) % ARCHIVE_BLOCK)
    return bytes(archive)


def check_kernel(path: Path) -> None:
    with path.open("rb") as stream:
        header = stream.read(0x40)
    if header[0x38:0x3C] != b"ARM\x64":
        raise InstallError("%s is not an uncompressed arm64 Linux kernel Image (no ARM\\x64 "
                           "header magic); build it with scripts/ci/verify/build-linux-vmm-kernel.py "
                           "--arch arm64" % path)


def check_initramfs(path: Path) -> None:
    """Mirror artifact admission for an aarch64 guest root."""
    if os.stat(path).st_size > INITRAMFS_LIMIT:
        raise InstallError("%s exceeds the 512 MiB guest root limit" % path)
    data = path.read_bytes()
    init = newc_entry(data, b"init")
    busybox, runc = newc_entry(data, b"bin/busybox"), newc_entry(data, b"sbin/runc")
    if newc_entry(data, CW_RUNTIME_PROVENANCE_ENTRY) is not None:
        reason = "it embeds a cw runtime, which only x86_64 guest roots may carry"
    elif init is None or not elf_header(init):
        reason = "it has no arm64 /init"
    elif busybox is None or runc is None or not (static_elf(busybox) and static_elf(runc)):
        reason = "it lacks static arm64 /bin/busybox and /sbin/runc"
    elif canonical_guest_root(init, busybox, runc) != data:
        reason = "it is not the exact canonical archive"
    else:
        return
    raise InstallError("%s is not an arm64 Codewire guest root: %s; %s" % (path, reason, GUEST_ROOT_HINT))


def hex_digest(value) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def check_cw_runtime(directory: Path) -> dict:
    """Mirror cw's admission of a sealed cw runtime source; return its lock."""

    def refuse(reason: str) -> None:
        raise InstallError("%s is not a sealed aarch64 cw runtime: %s; %s" % (directory, reason, CW_RUNTIME_HINT))

    lock_path, pack_path = directory / CW_RUNTIME_LOCK, directory / CW_RUNTIME_PACK
    for path in (lock_path, pack_path):
        try:
            status = os.lstat(path)
        except FileNotFoundError:
            refuse("%s is missing" % path.name)
        if not stat.S_ISREG(status.st_mode):
            refuse("%s is not a regular file" % path.name)
    try:
        lock = json.loads(lock_path.read_bytes())
    except ValueError:
        lock = None
    pack_entry = lock.get("pack") if isinstance(lock, dict) else None
    if (not isinstance(lock, dict) or set(lock) != {"schema_version", "image_index_sha256", "pack"}
            or lock["schema_version"] != 1 or not hex_digest(lock["image_index_sha256"])
            or not isinstance(pack_entry, dict) or set(pack_entry) != {"path", "size", "sha256"}
            or pack_entry["path"] != CW_RUNTIME_PACK or type(pack_entry["size"]) is not int
            or not hex_digest(pack_entry["sha256"])):
        refuse("%s is not a schema 1 cw runtime lock" % CW_RUNTIME_LOCK)
    pack = pack_path.read_bytes()
    if (len(pack) != pack_entry["size"] or not 24 <= len(pack) <= CW_RUNTIME_MAX_PACK
            or hashlib.sha256(pack).hexdigest() != pack_entry["sha256"]):
        refuse("%s does not match its lock's size and SHA-256" % CW_RUNTIME_PACK)
    provenance_size = int.from_bytes(pack[8:16], "little")
    payload_size = int.from_bytes(pack[16:24], "little")
    if (pack[:8] != CW_RUNTIME_PACK_MAGIC or not 1 <= provenance_size <= CW_RUNTIME_MAX_PROVENANCE
            or not 64 <= payload_size <= CW_RUNTIME_MAX_BYTES
            or 24 + provenance_size + payload_size != len(pack)):
        refuse("%s has invalid framing" % CW_RUNTIME_PACK)
    payload = pack[24 + provenance_size:]
    try:
        provenance = json.loads(pack[24:24 + provenance_size])
        identity = provenance["payload"]
        valid = (provenance["image_index_sha256"] == lock["image_index_sha256"]
                 and identity["target"] == CW_RUNTIME_TARGET
                 and identity["sha256"] == hashlib.sha256(payload).hexdigest()
                 and identity["size"] == len(payload))
    except (ValueError, KeyError, TypeError):
        valid = False
    if not valid:
        refuse("its provenance does not bind this image and a %s payload" % CW_RUNTIME_TARGET)
    if not static_elf(payload):
        refuse("its payload is not a static aarch64 ELF")
    return lock


def check_live_publisher(initramfs: Path) -> None:
    init = newc_entry(initramfs.read_bytes(), b"init") or b""
    if init.count(LIVE_RUNTIME_CAPABILITY_MARKER) != 1:
        raise InstallError("%s has no trusted live cw publisher, so it cannot boot with a cw runtime; "
                           "rebuild the guest root from current source; %s" % (initramfs, GUEST_ROOT_HINT))


def thin_arm64_macho(path: Path) -> None:
    with path.open("rb") as stream:
        header = stream.read(16)
    words = [int.from_bytes(header[index:index + 4], "little") for index in range(0, 16, 4)]
    if len(header) != 16 or words[0] != 0xFEEDFACF or words[1] != 0x0100000C or words[3] != 2:
        raise InstallError("%s is not a thin arm64 Mach-O executable" % path)


def check_helper(path: Path) -> None:
    """A thin arm64 Mach-O executable signed with exactly the developer entitlements."""
    thin_arm64_macho(path)
    shown = run([CODESIGN, "-d", "--entitlements", "-", "--xml", str(path)], capture=True)
    start = shown.find(b"<?xml")
    try:
        signed = plistlib.loads(shown[start:]) if start >= 0 else None
    except Exception:
        signed = None
    if signed != plistlib.loads(ENTITLEMENTS.read_bytes()):
        raise InstallError("the signed helper does not carry exactly %s" % ENTITLEMENTS.name)


def run(argv: list, capture: bool = False) -> bytes:
    """Run a tool; a captured query also keeps its stderr chatter quiet."""
    try:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE if capture else None,
                                stderr=subprocess.DEVNULL if capture else None, check=False)
    except FileNotFoundError:
        raise InstallError("%s is unavailable; install the Xcode Command Line Tools "
                           "(xcode-select --install)" % argv[0]) from None
    if result.returncode != 0:
        raise InstallError("command exited %d: %s" % (result.returncode, " ".join(argv)))
    return result.stdout or b""


def build_helper() -> Path:
    command = [SWIFT, "build", "-c", "release", "--package-path", str(PACKAGE)]
    log("building the VZ helper: " + " ".join(command))
    run(command)
    binary = Path(run([*command, "--show-bin-path"], capture=True).decode().strip()) / PRODUCT
    if not binary.is_file():
        raise InstallError("swift build produced no %s" % binary)
    return binary


def private_directory(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True)
    os.chmod(path, 0o700)


def stage_copy(source: Path, staged: Path) -> None:
    with source.open("rb") as reader:
        descriptor = os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as writer:
            for chunk in iter(lambda: reader.read(CHUNK), b""):
                writer.write(chunk)
            writer.flush()
            os.fsync(writer.fileno())


def identity(path: Path) -> tuple:
    checksum, size = hashlib.sha256(), 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(CHUNK), b""):
            checksum.update(chunk)
            size += len(chunk)
    return checksum.hexdigest(), size


def put_blob(release: Path, source: Path) -> dict:
    """Store `source` under its digest; return its blob reference."""
    sha256, size = identity(source)
    blobs = release / "blobs" / "sha256"
    blobs.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not (blobs / sha256).exists():
        stage_copy(source, blobs / sha256)
    return {"sha256": sha256, "size": size}


def source_revision(given: str = "") -> str:
    """The checkout's commit: cw installs only a runtime from its own source.

    A tree without Git metadata (a synced copy) names its commit explicitly;
    cw still refuses a runtime whose commit differs from its own.
    """
    revision = given or run(["git", "-C", str(REPOSITORY), "rev-parse", "HEAD"],
                            capture=True).decode().strip()
    if len(revision) != 40 or not all(c in "0123456789abcdef" for c in revision):
        raise InstallError("the source revision must be a 40-character commit, not %r" % revision)
    return revision


def pack(kernel: Path, initramfs: Path, e2fsprogs: Path, git: Path, release: Path, cw_runtime=None,
         revision: str = "") -> Path:
    """Write the release directory for this Mac's runtime into `release`."""
    require_host()
    check_kernel(kernel)
    check_initramfs(initramfs)
    if cw_runtime is not None:
        check_cw_runtime(cw_runtime)
        check_live_publisher(initramfs)
    tools = check_e2fsprogs(e2fsprogs)
    git_tools = check_git(git)
    if release.exists():
        raise InstallError("%s already exists; pack into a new directory" % release)
    revision = source_revision(revision)
    helper = build_helper()
    private_directory(release)
    signed = release / ("." + PRODUCT)
    stage_copy(helper, signed)
    # A fixed identifier keeps the signed bytes independent of the staging
    # name, so an unchanged rebuild pins the same digest.
    run([CODESIGN, "--force", "--sign", "-", "--identifier", PRODUCT,
         "--entitlements", str(ENTITLEMENTS), str(signed)])
    check_helper(signed)
    sources = {"vz_runner": signed, "kernel": kernel, "initramfs": initramfs}
    lock = {"schema_version": 1}

    def spec(source: Path, name: str) -> dict:
        blob = put_blob(release, source)
        return {"path": name, "size": blob["size"], "sha256": blob["sha256"],
                "architecture": "aarch64"}

    for key, name, _mode in ARTIFACTS:
        lock[key] = spec(sources[key], name)
        if key == "vz_runner":
            lock["e2fsprogs"] = {tool: spec(path, installed)
                                 for tool, (path, installed) in tools.items()}
            lock["git"] = {tool: spec(path, installed)
                           for tool, (path, installed) in git_tools.items()}
    signed.unlink()
    target = {"lock": lock}
    if cw_runtime is not None:
        target["cw_runtime"] = {"lock": put_blob(release, cw_runtime / CW_RUNTIME_LOCK),
                                "pack": put_blob(release, cw_runtime / CW_RUNTIME_PACK)}
    document = {"schema": LOCAL_RUNTIME_SCHEMA, "source_revision": revision,
                "targets": {TARGET: target}}
    # cw decodes the document strictly: canonical JSON (sorted keys, compact,
    # ASCII, one trailing newline), exactly as a release's cw embeds it.
    (release / LOCAL_RUNTIME_DOCUMENT).write_text(
        json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n")
    for key, name, _mode in ARTIFACTS:
        log("%-9s %s sha256=%s size=%d" % (key, name, lock[key]["sha256"], lock[key]["size"]))
    for group in ("e2fsprogs", "git"):
        for entry in lock[group].values():
            log("%-9s %s sha256=%s size=%d" % (group, entry["path"], entry["sha256"], entry["size"]))
    log("packed %s (source %s)" % (release, revision))
    return release


def install(kernel: Path, initramfs: Path, e2fsprogs: Path, git: Path, replace: bool, cw: str,
            cw_runtime=None, revision: str = "") -> int:
    with tempfile.TemporaryDirectory(prefix="cw-local-runtime-") as scratch:
        release = pack(kernel, initramfs, e2fsprogs, git, Path(scratch) / "release", cw_runtime, revision)
        run([cw, "setup", "--local", "--from", str(release)] + (["--replace"] if replace else []))
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--kernel", default="", help="absolute path to the arm64 Linux kernel Image")
    parser.add_argument("--initramfs", default="", help="absolute path to the arm64 guest root")
    parser.add_argument("--e2fsprogs", default="",
                        help="absolute directory holding the pinned e2fsprogs bundle from macos-ext4-tool.py")
    parser.add_argument("--git", default="",
                        help="absolute directory holding the pinned git bundle from macos-git-tool.py")
    parser.add_argument("--replace", action="store_true", help="replace a different installed runtime")
    parser.add_argument("--cw-runtime", default="",
                        help="absolute directory holding a sealed aarch64 cw-runtime.lock.json and runtime.pack")
    parser.add_argument("--pack", default="", help="only write the release directory to this new path")
    parser.add_argument("--cw", default="cw", help="the cw that installs the runtime (default: cw on PATH)")
    parser.add_argument("--source-revision", default="",
                        help="the source commit, for a tree without Git metadata (default: git rev-parse HEAD)")
    args = parser.parse_args(argv)
    try:
        kernel = input_file(args.kernel, "KERNEL")
        initramfs = input_file(args.initramfs, "INITRAMFS")
        if not args.e2fsprogs:
            raise InstallError("E2FSPROGS is required; " + E2FSPROGS_HINT)
        e2fsprogs = Path(args.e2fsprogs)
        if not args.git:
            raise InstallError("GIT is required; " + GIT_HINT)
        git = Path(args.git)
        cw_runtime = None
        if args.cw_runtime:
            cw_runtime = Path(args.cw_runtime)
            if not cw_runtime.is_absolute() or not cw_runtime.is_dir():
                raise InstallError("CW_RUNTIME must be an absolute directory: %s" % args.cw_runtime)
        if args.pack:
            release = Path(args.pack)
            if not release.is_absolute():
                raise InstallError("--pack must be an absolute path: %s" % args.pack)
            pack(kernel, initramfs, e2fsprogs, git, release, cw_runtime, args.source_revision)
            return 0
        return install(kernel, initramfs, e2fsprogs, git, args.replace, args.cw, cw_runtime,
                       args.source_revision)
    except (InstallError, OSError) as error:
        print("macos-local-runtime: ERROR: %s" % error, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
