#!/usr/bin/env python3
"""Pack the Linux x86_64 local VM runtime and check sealed cw runtimes (#2733).

`pack` writes the local runtime's linux-x86_64 target: the release's linux
fragment, and a runtime directory `cw setup --local --from DIR` installs with
a cw built from the same source. It checks the pinned Cloud Hypervisor and
virtiofsd (scripts/ci/release/local-runtime-sources.json; virtiofsd is the
one pinned member of its pinned release zip), the x86_64 kernel bzImage, the
canonical x86_64 guest root and a sealed x86_64 cw runtime the way artifact
admission does, then writes blobs/sha256/<digest> and local-runtime.json, the
format a release publishes, with that one target. Nothing is built or
downloaded.

`check-cw-runtime` checks one sealed cw runtime (cw-runtime.lock.json and
runtime.pack from `cw-runtime-image.py pack`) as a release requires: its cw
is a static ELF for the target whose build record names that target and the
source revision, and it embeds no local runtime document, since a blob the
document pins must never hold the cw that embeds the document.
"""

from __future__ import annotations

import argparse
import importlib.util
import io
import os
from pathlib import Path
import stat
import subprocess
import sys
import zipfile

REPOSITORY = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY / "scripts/ci/release"))
import cw_release as release  # noqa: E402
import local_runtime_sources as sources  # noqa: E402


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# The guest root layout, its live publisher marker and the component reader
# are the macOS packer's; only the architecture differs.
macos = _load("macos_local_runtime", Path(__file__).resolve().with_name("macos-local-runtime.py"))

PLATFORM = "linux-x86_64"
ARCHITECTURE = "x86_64"
CW_TARGET = "x86_64-unknown-linux-musl"
CW_TARGETS = ("x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl")
KERNEL_RELEASE = "6.18.48-codewire3"
KERNEL_LIMIT = 64 * 1024 * 1024
ZIP_LIMIT = 64 * 1024 * 1024
# Lock key and installed file name; cw installs executables 0500 and data 0400
# (crates/codewire-local-vmm/src/artifact.rs).
EXECUTABLES = (("cloud_hypervisor", "cloud-hypervisor"), ("virtiofsd", "virtiofsd"))
DATA = (("kernel", "kernel"), ("initramfs", "initramfs"))
GUEST_ROOT_HINT = ("build it with scripts/ci/release/build-runtime-guest-root.sh --target "
                   "x86_64-unknown-linux-musl")
KERNEL_HINT = "build it with scripts/ci/release/build-runtime-kernel.sh --arch x86_64"
CW_RUNTIME_HINT = "build it with scripts/ci/release/build-runtime-cw.sh"


class PackError(Exception):
    pass


def require(condition, reason: str) -> None:
    if not condition:
        raise PackError(reason)


def log(message: str) -> None:
    print("linux-local-runtime: " + message, flush=True)


def read_input(path: Path, limit: int, label: str) -> bytes:
    require(path.is_absolute(), "%s must be an absolute path: %s" % (label, path))
    try:
        return release.read_regular(path, limit)
    except release.ReleaseError as error:
        raise PackError("%s %s: %s" % (label, path, error)) from None


def static_elf(data: bytes, target: str, label: str) -> None:
    """A single-architecture ELF executable with no interpreter or needed library."""
    try:
        release.check_header(target, data)
        release.check_static_elf(data)
    except (release.ReleaseError, IndexError, ValueError) as error:
        raise PackError("%s is not a static %s ELF: %s" % (label, target, error)) from None


def elf_header(data: bytes) -> bool:
    try:
        release.check_header(CW_TARGET, data)
    except (release.ReleaseError, ValueError):
        return False
    return True


def cloud_hypervisor(path: Path, pin: dict) -> bytes:
    """The pinned upstream static Cloud Hypervisor."""
    data = read_input(path, release.MAX_OBJECT, "Cloud Hypervisor")
    require(len(data) == pin["size"] and release.sha256(data) == pin["sha256"],
            "%s is not the pinned Cloud Hypervisor %s (%s)" % (path, pin["version"], pin["url"]))
    static_elf(data, CW_TARGET, "Cloud Hypervisor")
    return data


def virtiofsd(path: Path, pin: dict) -> bytes:
    """Exactly the pinned member of the pinned upstream virtiofsd zip."""
    archive = read_input(path, ZIP_LIMIT, "the virtiofsd archive")
    require(release.sha256(archive) == pin["sha256"],
            "%s is not the pinned virtiofsd %s archive (%s)" % (path, pin["version"], pin["url"]))
    try:
        with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
            entries = [entry for entry in bundle.infolist() if entry.filename == pin["member"]]
            require(len(entries) == 1, "the virtiofsd archive holds no single %s" % pin["member"])
            entry = entries[0]
            mode = entry.external_attr >> 16
            require(not entry.flag_bits & 1 and entry.file_size == pin["member_size"]
                    and (mode == 0 or stat.S_ISREG(mode)),
                    "the virtiofsd archive's %s is not the pinned regular file" % pin["member"])
            data = bundle.read(entry)
    except (zipfile.BadZipFile, zipfile.LargeZipFile, OSError, EOFError) as error:
        raise PackError("the virtiofsd archive is unreadable: %s" % error) from None
    require(len(data) == pin["member_size"] and release.sha256(data) == pin["member_sha256"],
            "the virtiofsd archive's %s differs from its pin" % pin["member"])
    static_elf(data, CW_TARGET, "virtiofsd")
    return data


def check_kernel(path: Path) -> bytes:
    data = read_input(path, KERNEL_LIMIT, "the kernel")
    require(len(data) >= 0x206 and data[510:512] == b"\x55\xaa" and data[0x202:0x206] == b"HdrS",
            "%s is not an x86 bzImage (no boot sector signature or HdrS header); %s" % (path, KERNEL_HINT))
    require(KERNEL_RELEASE.encode() in data[:65536],
            "%s is not the %s kernel; %s" % (path, KERNEL_RELEASE, KERNEL_HINT))
    return data


def check_initramfs(path: Path) -> bytes:
    """The exact canonical x86_64 guest root, with its live cw publisher."""
    data = read_input(path, macos.INITRAMFS_LIMIT, "the guest root")
    init = macos.newc_entry(data, b"init")
    busybox, runc = macos.newc_entry(data, b"bin/busybox"), macos.newc_entry(data, b"sbin/runc")

    def static(binary) -> bool:
        try:
            static_elf(binary, CW_TARGET, "binary")
        except PackError:
            return False
        return True

    if macos.newc_entry(data, macos.CW_RUNTIME_PROVENANCE_ENTRY) is not None:
        reason = "it embeds a cw; a release's cw runtime is its own sealed pack"
    elif init is None or not elf_header(init):
        reason = "it has no x86_64 /init"
    elif busybox is None or runc is None or not (static(busybox) and static(runc)):
        reason = "it lacks static x86_64 /bin/busybox and /sbin/runc"
    elif macos.canonical_guest_root(init, busybox, runc) != data:
        reason = "it is not the exact canonical archive"
    elif init.count(macos.LIVE_RUNTIME_CAPABILITY_MARKER) != 1:
        reason = "it has no trusted live cw publisher, so it cannot boot with a cw runtime"
    else:
        return data
    raise PackError("%s is not an x86_64 Codewire guest root: %s; %s" % (path, reason, GUEST_ROOT_HINT))


def check_cw_runtime(directory: Path, target: str, revision: str) -> tuple:
    """A sealed cw runtime for `target` built from `revision`: (lock, pack) bytes."""
    require(target in CW_TARGETS, "cw runtime target must be one of %s" % ", ".join(CW_TARGETS))

    def refuse(reason: str) -> None:
        raise PackError("%s is not a sealed %s cw runtime of %s: %s; %s"
                        % (directory, target, revision, reason, CW_RUNTIME_HINT))

    require(directory.is_absolute() and directory.is_dir(), "CW_RUNTIME must be an absolute directory: %s" % directory)
    files = {}
    for name, limit in ((macos.CW_RUNTIME_LOCK, release.MAX_JSON), (macos.CW_RUNTIME_PACK, macos.CW_RUNTIME_MAX_PACK)):
        try:
            files[name] = release.read_regular(directory / name, limit)
        except release.ReleaseError as error:
            refuse("%s: %s" % (name, error))
    lock_bytes, pack_bytes = files[macos.CW_RUNTIME_LOCK], files[macos.CW_RUNTIME_PACK]
    try:
        lock = release.parse_json(lock_bytes)
    except release.ReleaseError:
        lock = None
    entry = lock.get("pack") if isinstance(lock, dict) else None
    if (not isinstance(lock, dict) or set(lock) != {"schema_version", "image_index_sha256", "pack"}
            or not release.exact(lock["schema_version"], 1) or not release.is_hex(lock["image_index_sha256"], 64)
            or not isinstance(entry, dict) or set(entry) != {"path", "size", "sha256"}
            or entry["path"] != macos.CW_RUNTIME_PACK or type(entry["size"]) is not int
            or not release.is_hex(entry["sha256"], 64)):
        refuse("%s is not a schema 1 cw runtime lock" % macos.CW_RUNTIME_LOCK)
    if len(pack_bytes) != entry["size"] or release.sha256(pack_bytes) != entry["sha256"]:
        refuse("%s does not match its lock's size and SHA-256" % macos.CW_RUNTIME_PACK)
    provenance_size = int.from_bytes(pack_bytes[8:16], "little")
    payload_size = int.from_bytes(pack_bytes[16:24], "little")
    if (pack_bytes[:8] != macos.CW_RUNTIME_PACK_MAGIC or not 1 <= provenance_size <= macos.CW_RUNTIME_MAX_PROVENANCE
            or not 64 <= payload_size <= macos.CW_RUNTIME_MAX_BYTES
            or 24 + provenance_size + payload_size != len(pack_bytes)):
        refuse("%s has invalid framing" % macos.CW_RUNTIME_PACK)
    payload = pack_bytes[24 + provenance_size:]
    try:
        provenance = release.parse_json(pack_bytes[24:24 + provenance_size])
        identity = provenance["payload"]
        bound = (provenance["image_index_sha256"] == lock["image_index_sha256"]
                 and identity["target"] == target and identity["source_revision"] == revision
                 and identity["sha256"] == release.sha256(payload) and identity["size"] == len(payload))
    except (release.ReleaseError, KeyError, TypeError):
        bound = False
    if not bound:
        refuse("its provenance does not bind this image and a %s payload from that revision" % target)
    try:
        static_elf(payload, target, "its cw")
    except PackError as error:
        refuse(str(error))
    try:
        record = release.build_record(payload)
    except release.ReleaseError as error:
        refuse("its cw build record is invalid: %s" % error)
    if record["target"] != target or record["source_revision"] != revision:
        refuse("its cw build record names %s from %s" % (record["target"], record["source_revision"]))
    try:
        embedded = release.embedded_local_runtime(payload)
    except release.ReleaseError as error:
        refuse("its cw embeds a malformed local runtime document: %s" % error)
    if embedded is not None:
        refuse("its cw embeds a local runtime document; build it without CODEWIRE_LOCAL_RUNTIME")
    return lock_bytes, pack_bytes


def source_revision(given: str = "") -> str:
    revision = given or subprocess.run(["git", "-C", str(REPOSITORY), "rev-parse", "HEAD"], check=True,
                                       stdin=subprocess.DEVNULL, capture_output=True, text=True).stdout.strip()
    require(release.is_hex(revision, 40), "the source revision must be a 40-character commit, not %r" % revision)
    return revision


def put(output: Path, data: bytes) -> dict:
    """Store `data` under its digest; return its blob reference."""
    blobs = output / "blobs" / "sha256"
    blobs.mkdir(mode=0o700, parents=True, exist_ok=True)
    digest = release.sha256(data)
    if not (blobs / digest).exists():
        release.write_new(blobs / digest, data, 0o600)
    return {"sha256": digest, "size": len(data)}


def pack(kernel: Path, initramfs: Path, cloud_hypervisor_path: Path, virtiofsd_zip: Path, cw_runtime: Path,
         output: Path, revision: str = "", components=(), pins=None) -> bytes:
    """Write the linux-x86_64 runtime directory into a new `output`."""
    pins = pins or sources.load_pins()
    host = pins["linux_runtime"]
    try:
        listed = macos.read_components(components)
    except macos.InstallError as error:
        raise PackError(str(error)) from None
    executables = {"cloud_hypervisor": cloud_hypervisor(cloud_hypervisor_path, host["cloud_hypervisor"]),
                   "virtiofsd": virtiofsd(virtiofsd_zip, host["virtiofsd"])}
    data = {"kernel": check_kernel(kernel), "initramfs": check_initramfs(initramfs)}
    revision = source_revision(revision)
    cw_lock, cw_pack = check_cw_runtime(cw_runtime, CW_TARGET, revision)
    require(output.is_absolute(), "--output must be an absolute path: %s" % output)
    require(not os.path.lexists(output), "%s already exists; pack into a new directory" % output)
    output.mkdir(mode=0o700)
    lock = {"schema_version": 1}
    for key, name in EXECUTABLES:
        lock[key] = {"path": name, "architecture": ARCHITECTURE, "version": host[key]["version"],
                     **put(output, executables[key])}
    for key, name in DATA:
        lock[key] = {"path": name, "architecture": ARCHITECTURE, **put(output, data[key])}
    target = {"lock": lock, "cw_runtime": {"lock": put(output, cw_lock), "pack": put(output, cw_pack)}}
    if listed:
        target["components"] = [{"name": entry["name"], "version": entry["version"], "license": entry["license"],
                                 "source": macos.put_blob(output, source)} for entry, source in listed]
    document = release.canonical({"schema": release.LOCAL_RUNTIME_SCHEMA, "source_revision": revision,
                                  "targets": {PLATFORM: target}})
    release.write_new(output / release.LOCAL_RUNTIME_NAME, document, 0o600)
    try:
        loaded = release.load_local_runtime_dir(output)
    except release.ReleaseError as error:
        raise PackError("the packed runtime does not verify: %s" % error) from None
    require(loaded is not None and loaded[0] == document, "the packed runtime does not verify")
    for key, _name in EXECUTABLES + DATA:
        log("%-16s sha256=%s size=%d" % (key, lock[key]["sha256"], lock[key]["size"]))
    log("%-16s sha256=%s size=%d" % ("cw_runtime.pack", target["cw_runtime"]["pack"]["sha256"],
                                     target["cw_runtime"]["pack"]["size"]))
    log("packed %s (%s, source %s, document sha256=%s)" % (output, PLATFORM, revision, release.sha256(document)))
    return document


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    packer = sub.add_parser("pack", help="write the linux-x86_64 local runtime directory")
    packer.add_argument("--kernel", type=Path, required=True, help="the x86_64 bzImage (vmlinuz-%s)" % KERNEL_RELEASE)
    packer.add_argument("--initramfs", type=Path, required=True, help="the canonical x86_64 guest root")
    packer.add_argument("--cloud-hypervisor", type=Path, required=True, help="the pinned cloud-hypervisor-static")
    packer.add_argument("--virtiofsd-zip", type=Path, required=True, help="the pinned virtiofsd release zip")
    packer.add_argument("--cw-runtime", type=Path, required=True,
                        help="directory with a sealed x86_64 cw-runtime.lock.json and runtime.pack")
    packer.add_argument("--components", type=Path, action="append", default=[],
                        help="directory from local_runtime_sources.py fetch; repeatable")
    packer.add_argument("--source-revision", default="", help="the source commit (default: git rev-parse HEAD)")
    packer.add_argument("--output", type=Path, required=True, help="the new runtime directory")
    checker = sub.add_parser("check-cw-runtime", help="check a sealed cw runtime for a release")
    checker.add_argument("--dir", type=Path, required=True)
    checker.add_argument("--target", required=True, choices=CW_TARGETS)
    checker.add_argument("--source-revision", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "pack":
            pack(args.kernel, args.initramfs, args.cloud_hypervisor, args.virtiofsd_zip, args.cw_runtime,
                 args.output, args.source_revision, args.components)
        else:
            revision = source_revision(args.source_revision)
            _lock, data = check_cw_runtime(args.dir, args.target, revision)
            log("cw runtime %s pack sha256=%s size=%d source %s" % (args.target, release.sha256(data), len(data),
                                                                     revision))
    except (PackError, sources.SourcesError, release.ReleaseError, OSError, subprocess.SubprocessError) as error:
        print("linux-local-runtime: ERROR: %s" % error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
