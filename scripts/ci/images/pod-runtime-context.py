#!/usr/bin/env python3
"""Assemble the build context of the `standard` pod-runtime image (#5602).

The image (images/pod-runtime/Dockerfile) holds one `cw` and the local VM
runtime it boots a sandbox's VM with: Cloud Hypervisor, virtiofsd, the guest
kernel, the guest root and the sealed cw runtime, at the paths
`cw __pod-runtime` reads (crates/codewire-local-vmm/src/pod_runtime.rs).

Nothing here builds or downloads. The runtime comes from a local runtime
directory, the format a release publishes: the linux job's linux-x86_64
fragment (scripts/ci/release/build-local-runtime.sh linux) or a release's
merged runtime. Its linux-x86_64 target supplies every part, each checked
against its digest. The `cw` must be a static x86_64 musl cw built from the
same source revision as that runtime, read from its build record, so the
host side and the guest's sealed cw are one source. Without --cw it is the
sealed cw runtime's own cw, which is exactly that: Dev delivery's build has
no other (.gitea/workflows/deploy-dev.yaml, build-pod-runtime-image).

The output is a new directory holding the Dockerfile's context:

    cw                                    0755
    runtime/                              0700
    runtime/artifacts/                    0700
    runtime/artifacts/<lock path>         0500 executables, 0400 data
    runtime/artifacts.lock                0400, the target's lock, canonical
    runtime/cw-runtime.lock.json          0400
    runtime/runtime.pack                  0400
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import sys

REPOSITORY = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPOSITORY / "scripts/ci/release"))
import cw_release as release  # noqa: E402

PLATFORM = "linux-x86_64"
CW_TARGET = "x86_64-unknown-linux-musl"
# The lock keys the pod runtime admits, and the mode cw installs each with
# (crates/codewire-local-vmm/src/artifact.rs).
EXECUTABLES = ("cloud_hypervisor", "virtiofsd")
DATA = ("kernel", "initramfs")
MAX_CW = 512 * 1024 * 1024


class ContextError(Exception):
    pass


def require(condition, reason: str) -> None:
    if not condition:
        raise ContextError(reason)


def runtime_target(runtime: Path) -> tuple[dict, str]:
    """The checked linux-x86_64 target of a local runtime directory, and its source revision."""
    require(runtime.is_absolute(), "--runtime must be an absolute path: %s" % runtime)
    loaded = release.load_local_runtime_dir(runtime)
    require(loaded is not None, "%s is not a local runtime directory" % runtime)
    document = release.parse_canonical(loaded[0])
    target = document["targets"].get(PLATFORM)
    require(target is not None, "the local runtime has no %s target" % PLATFORM)
    require("cw_runtime" in target, "the %s target has no sealed cw runtime" % PLATFORM)
    lock = target["lock"]
    require(set(lock) == {"schema_version", *EXECUTABLES, *DATA},
            "the %s lock is not exactly Cloud Hypervisor, virtiofsd, the kernel and the guest root" % PLATFORM)
    return target, document["source_revision"]


def check_cw(cw: Path, revision: str) -> None:
    """A static x86_64 musl cw whose build record names `revision`."""
    data = release.read_regular(cw, MAX_CW)
    require(data[:4] == b"\x7fELF", "%s is not an ELF executable" % cw)
    record = release.build_record(data)
    require(record["target"] == CW_TARGET, "%s is a %s cw, not %s" % (cw, record["target"], CW_TARGET))
    require(record["source_revision"] == revision,
            "%s is built from %s, but the runtime from %s" % (cw, record["source_revision"], revision))


def sealed_cw(runtime: Path, target: dict, revision: str) -> bytes:
    """The cw of the target's sealed cw runtime, checked as a release checks it."""
    sealed = target["cw_runtime"]
    blobs = runtime / "blobs" / "sha256"
    lock = release.read_regular(blobs / sealed["lock"]["sha256"], 64 * 1024)
    pack = release.read_regular(blobs / sealed["pack"]["sha256"], release.CW_RUNTIME_MAX_BYTES + 64 * 1024)
    return release.check_cw_runtime_pack(lock, pack, CW_TARGET, revision)


def copy_blob(runtime: Path, reference: dict, destination: Path, mode: int) -> None:
    """Copy one pinned blob, which load_local_runtime_dir has checked, to a new file."""
    source = runtime / "blobs" / "sha256" / reference["sha256"]
    with open(source, "rb") as reader:
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(descriptor, "wb") as writer:
            shutil.copyfileobj(reader, writer, 1024 * 1024)
            writer.flush()
            os.fsync(writer.fileno())
    os.chmod(destination, mode)
    release._verify_blob_file(destination, reference["sha256"], reference["size"])


def assemble(runtime: Path, cw: Path | None, output: Path) -> str:
    """Write the context into the new directory `output`; return the source revision.

    `cw` None takes the sealed cw runtime's own cw."""
    target, revision = runtime_target(runtime)
    if cw is None:
        cw_bytes = sealed_cw(runtime, target, revision)
    else:
        check_cw(cw, revision)
        cw_bytes = release.read_regular(cw, MAX_CW)
    require(output.is_absolute(), "--output must be an absolute path: %s" % output)
    require(not os.path.lexists(output), "%s already exists; assemble into a new directory" % output)
    output.mkdir(mode=0o755)
    release.write_new(output / "cw", cw_bytes, 0o755)
    root = output / "runtime"
    artifacts = root / "artifacts"
    root.mkdir(mode=0o700)
    artifacts.mkdir(mode=0o700)
    lock = target["lock"]
    for key in EXECUTABLES + DATA:
        entry = lock[key]
        name = entry["path"]
        require(isinstance(name, str) and name and "/" not in name and name not in (".", ".."),
                "the lock's %s path is not one file name" % key)
        copy_blob(runtime, entry, artifacts / name, 0o500 if key in EXECUTABLES else 0o400)
    release.write_new(root / "artifacts.lock", release.canonical(lock), 0o400)
    copy_blob(runtime, target["cw_runtime"]["lock"], root / "cw-runtime.lock.json", 0o400)
    copy_blob(runtime, target["cw_runtime"]["pack"], root / "runtime.pack", 0o400)
    return revision


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--runtime", type=Path, required=True,
                        help="a local runtime directory with a linux-x86_64 target (local-runtime.json, blobs/)")
    parser.add_argument("--cw", type=Path,
                        help="a static x86_64 musl cw built from the runtime's source revision "
                             "(default: the sealed cw runtime's own cw)")
    parser.add_argument("--output", type=Path, required=True, help="the new context directory")
    args = parser.parse_args(argv)
    try:
        revision = assemble(args.runtime, args.cw, args.output)
    except (ContextError, release.ReleaseError, OSError) as error:
        print("pod-runtime-context: ERROR: %s" % error, file=sys.stderr)
        return 1
    print("pod-runtime-context: assembled %s from source %s" % (args.output, revision))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
