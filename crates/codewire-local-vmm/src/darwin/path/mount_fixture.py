#!/usr/bin/env python3
"""Owned APFS mount discriminator. Failures retain artifacts, never guess cleanup."""

import json
import os
from pathlib import Path
import plistlib
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time


CHILD = "darwin::path::tests::mounted_volume_child"
LIMIT = 1024 * 1024
CANCELLED = None


def check_cancelled():
    if CANCELLED is not None:
        raise InterruptedError(f"fixture cancelled by signal {CANCELLED}")


def mounted_entity(document, mountpoint):
    entities = document["system-entities"]
    mounted = [entry for entry in entities if "mount-point" in entry]
    if len(mounted) != 1 or mounted[0]["mount-point"] != str(mountpoint):
        raise RuntimeError("attachment did not identify exactly the owned mounted volume")
    device = mounted[0]["dev-entry"]
    if not isinstance(device, str) or not re.fullmatch(r"/dev/disk[0-9]+(?:s[0-9]+)*", device):
        raise RuntimeError("invalid attached device identity")
    return device


def image_record(document, image, mountpoint, device):
    records = [entry for entry in document["images"] if entry.get("image-path") == str(image)]
    if len(records) != 1 or mounted_entity(records[0], mountpoint) != device:
        raise RuntimeError("live image/mount/device ownership does not match attachment")


def detached(document, image, mountpoint):
    for entry in document["images"]:
        if entry.get("image-path") == str(image) or any(
            entity.get("mount-point") == str(mountpoint)
            for entity in entry.get("system-entities", [])
        ):
            raise RuntimeError("owned image or mount remains attached")


def identity(metadata):
    return metadata.st_dev, metadata.st_ino, metadata.st_uid, stat.S_IFMT(metadata.st_mode)


class Fixture:
    def __init__(self, root):
        self.root = root
        self.image = root / "volume.dmg"
        self.mountpoint = root / "mounted"
        self.allowed = {"status.json", "volume.dmg", "mounted", "tmp"}
        self.sequence = 0
        self.details = {}
        self.env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C",
                    "TMPDIR": str(root / "tmp") + "/"}

    def stage(self, name):
        (self.root / "status.json").write_text(json.dumps({"stage": name, "root": str(self.root), **self.details}) + "\n")
        print(f"APFS fixture {name}: {self.root}", flush=True)

    def command(self, argv, timeout):
        print(f"APFS command {json.dumps(argv)} (deadline {timeout}s)", flush=True)
        self.sequence += 1
        names = [f"command-{self.sequence:02d}.{suffix}" for suffix in ("out", "err")]
        self.allowed.update(names)
        deadline = time.monotonic() + timeout
        ownership_known = True
        child = None
        with (self.root / names[0]).open("xb") as output, (self.root / names[1]).open("xb") as errors:
            try:
                check_cancelled()
                # Signal handlers only record cancellation. They cannot raise
                # between successful spawn and retaining the Child reference.
                child = subprocess.Popen(argv, cwd=self.root, env=self.env, stdin=subprocess.DEVNULL,
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                check_cancelled()
                with selectors.DefaultSelector() as reader:
                    for pipe, stream in [(child.stdout, output), (child.stderr, errors)]:
                        reader.register(pipe, selectors.EVENT_READ, [stream, 0])
                    while True:
                        check_cancelled()
                        if time.monotonic() >= deadline:
                            raise RuntimeError("owned command exceeded time bound; effect unknown")
                        try:
                            result = child.poll()
                        except OSError:
                            ownership_known = False
                            raise
                        if result is not None and not reader.get_map():
                            break
                        for key, _events in reader.select(max(0, min(0.05, deadline - time.monotonic()))):
                            data = os.read(key.fd, 16384)
                            if not data:
                                reader.unregister(key.fileobj)
                                continue
                            stream, length = key.data
                            if length + len(data) > LIMIT:
                                raise RuntimeError("owned command exceeded output bound; effect unknown")
                            stream.write(data)
                            key.data[1] += len(data)
            finally:
                try:
                    # Only a fresh, still-unreaped direct child. A reaped process
                    # or uncertain ownership never authorizes numeric PID reuse.
                    if child is not None and ownership_known and child.poll() is None:
                        child.kill()
                        child.wait(timeout=5)
                except BaseException as error:
                    raise RuntimeError("owned command cleanup unknown; retain artifacts") from error
                finally:
                    if child is not None:
                        child.stdout.close()
                        child.stderr.close()
        check_cancelled()
        if time.monotonic() >= deadline:
            raise RuntimeError("owned command exceeded time bound; effect unknown")
        if result != 0:
            raise RuntimeError(f"owned command failed ({result}); inspect {names}")
        print(f"APFS command exit {result}", flush=True)
        with (self.root / names[0]).open("rb") as stream:
            data = stream.read(LIMIT + 1)
        if len(data) > LIMIT:
            raise RuntimeError("retained output exceeded bound")
        return data

    def info(self):
        return plistlib.loads(self.command(["/usr/bin/hdiutil", "info", "-plist"], 10))

    def execute(self, executable):
        self.stage("create")
        self.mountpoint.mkdir(mode=0o700)
        (self.root / "tmp").mkdir(mode=0o700)
        covered = os.open(self.mountpoint, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        mounted = None
        try:
            original = identity(os.fstat(covered))
            self.details["covered_identity"] = original
            self.command(["/usr/bin/hdiutil", "create", "-size", "64m", "-fs", "APFS",
                          "-type", "UDIF", "-volname", "cw-path-proof",
                          "-uid", str(os.getuid()), "-gid", str(os.getgid()), "-mode", "0700",
                          str(self.image)], 60)
            self.stage("attach")
            attached = plistlib.loads(self.command([
                "/usr/bin/hdiutil", "attach", str(self.image), "-nobrowse", "-noautoopen",
                "-owners", "on", "-mountpoint", str(self.mountpoint), "-plist"], 60))
            device = mounted_entity(attached, self.mountpoint)
            mounted = os.open(self.mountpoint, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            current = os.fstat(mounted)
            if identity(current) == original or current.st_dev == os.fstat(covered).st_dev:
                raise RuntimeError("fixture did not mount a distinct filesystem")
            if current.st_uid != os.getuid():
                raise RuntimeError("mounted root is not owned by this user")
            image_record(self.info(), self.image, self.mountpoint, device)
            self.details.update(mounted_identity=identity(current), device=device)
            self.stage("prepare-private-root")
            # APFS may ignore create's requested root mode (observed0755).
            # Establish the fixture prerequisite on the verified owned FD;
            # never weaken admission, strip ACLs, or change an object's owner.
            os.fchmod(mounted, 0o700)
            prepared = os.fstat(mounted)
            if identity(prepared) != identity(current) or stat.S_IMODE(prepared.st_mode) != 0o700:
                raise RuntimeError("private fixture mode preparation changed identity or failed")
            self.stage("test")
            self.env["CW_DARWIN_PATH_MOUNT_CHILD"] = str(self.root)
            output = self.command([executable, "--exact", CHILD, "--ignored", "--nocapture"], 20)
            if not re.search(rb"test result: ok\. 1 passed; 0 failed; 0 ignored;", output):
                raise RuntimeError("required mount child did not execute exactly one passing test")
            print("APFS mount child: 1 passed; 0 failed; 0 ignored", flush=True)
            self.stage("detach")
            # Reconcile the current image association and retained mounted node
            # immediately before detaching the private path, never bare diskN.
            image_record(self.info(), self.image, self.mountpoint, device)
            if identity(os.stat(self.mountpoint, follow_symlinks=False)) != identity(os.fstat(mounted)):
                raise RuntimeError("mounted path was replaced; refuse detach")
            os.close(mounted)
            mounted = None
            self.command(["/usr/bin/hdiutil", "detach", str(self.mountpoint)], 30)
            detached(self.info(), self.image, self.mountpoint)
            if identity(os.stat(self.mountpoint, follow_symlinks=False)) != original:
                raise RuntimeError("covered mountpoint identity was not restored")
            if list(self.mountpoint.iterdir()) or list((self.root / "tmp").iterdir()):
                raise RuntimeError("unexpected entries prevent fixture cleanup")
            if {entry.name for entry in self.root.iterdir()} != self.allowed:
                raise RuntimeError("unexpected fixture paths prevent cleanup")
        finally:
            if mounted is not None:
                os.close(mounted)
            os.close(covered)
        self.stage("passed-and-detached")
        # Only this freshly owned tree, after exact mount detachment and identity
        # restoration. Every failure above retains it for explicit diagnosis.
        shutil.rmtree(self.root)


def main():
    os.umask(0o077)
    # This standalone fixture owns/waits its children. Deferred cancellation
    # protects the spawn/assignment boundary without changing child signal masks.
    signal.signal(signal.SIGCHLD, signal.SIG_DFL)
    def cancelled(signum, _frame):
        global CANCELLED
        CANCELLED = signum
    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, cancelled)
    # Outside the build helper's auto-cleaned TMPDIR/source tree. A failed
    # attachment must survive helper cleanup and subsequent source transfers.
    root = Path(tempfile.mkdtemp(prefix="cw-path-mount-", dir="/private/var/tmp")).resolve()
    try:
        Fixture(root).execute(sys.argv[1])
    except Exception as error:
        print(f"APFS fixture FAILED; retained {root}: {error}", file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
