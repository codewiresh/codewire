#!/usr/bin/env python3
"""The command owner and archive helpers the macOS developer loop
(macos-cli.py) and the runtime's e2fsprogs build (macos-ext4-tool.py) share.

It is its own file so that the e2fsprogs part's cache recipe
(scripts/ci/release/local_runtime_parts.py) names this code and not the whole
developer loop: a change to the loop alone no longer rebuilds e2fsprogs. The
loop uploads it beside its worker.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path, PurePosixPath
import shutil
import signal
import subprocess
import tarfile
import time


STOP_SECONDS = 3


class CleanupUnknown(RuntimeError):
    """A command's process group is not proven quiescent; retain its state."""


def digest(path):
    checksum = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            checksum.update(chunk)
    return checksum.hexdigest()


def safe_name(name):
    path = PurePosixPath(name)
    if not name or path.is_absolute() or ".." in path.parts or ".git" in path.parts:
        raise ValueError(f"unsafe archive path: {name!r}")
    return path


def extract(archive_path, destination, links=False):
    """Extract into an empty owned directory; links last, no hardlinks/devices."""
    with tarfile.open(archive_path) as archive:
        entries = archive.getmembers()
        names = set()
        symlinks = {entry.name for entry in entries if entry.issym()}
        for entry in entries:
            path = safe_name(entry.name)
            if entry.name in names or any(str(parent) in symlinks for parent in path.parents):
                raise ValueError(f"duplicate path or symlink parent: {entry.name}")
            names.add(entry.name)
            if not entry.isfile() and not (links and entry.issym()):
                raise ValueError(f"unsupported archive entry: {entry.name}")
            if entry.issym():
                target = destination / entry.name
                if Path(entry.linkname).is_absolute() or not (target.parent / entry.linkname).resolve().is_relative_to(destination.resolve()):
                    raise ValueError(f"escaping archive link: {entry.name}")
        for entry in sorted(entries, key=lambda member: member.issym()):
            target = destination / entry.name
            target.parent.mkdir(parents=True, exist_ok=True)
            if entry.issym():
                target.symlink_to(entry.linkname)
            else:
                with archive.extractfile(entry) as source, target.open("xb") as sink:
                    shutil.copyfileobj(source, sink)
                target.chmod(entry.mode & 0o777)


def group_absent(process):
    try:
        reaped = process.poll() is not None
    except OSError as error:
        raise CleanupUnknown("command child ownership is unknown") from error
    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        return reaped
    except OSError as error:
        raise CleanupUnknown("command group absence is unknown") from error
    return False


def stop_group(process):
    for signum in (signal.SIGTERM, signal.SIGKILL):
        try:
            # Only this command owner reaps its child. With default SIGCHLD,
            # exit after this poll leaves a zombie pinning the PID until our
            # next poll. A reaped or unknown leader never authorizes a signal.
            live = process.poll() is None
        except OSError as error:
            raise CleanupUnknown("command child ownership is unknown") from error
        try:
            if live:
                os.killpg(process.pid, signum)
        except ProcessLookupError:
            pass
        except OSError as error:
            raise CleanupUnknown("command group signal ownership is unknown") from error
        stop = time.monotonic() + STOP_SECONDS
        while True:
            if group_absent(process):
                return
            if time.monotonic() >= stop:
                break
            time.sleep(0.02)
    raise CleanupUnknown("command group remains; runtime and cache retained")


def run_command(argv, cwd, env, log, cancel, deadline):
    if cancel.is_set() or time.monotonic() >= deadline:
        return 130 if cancel.is_set() else 124
    # Heartbeat/watchdog threads only set cancellation; this standalone worker
    # is the sole child reaper. Reset SIG_IGN/SA_NOCLDWAIT before every spawn.
    signal.signal(signal.SIGCHLD, signal.SIG_DFL)
    with log.open("wb") as stream:
        process = subprocess.Popen(argv, cwd=cwd, env=env, stdout=stream,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        ownership_known = True
        try:
            while True:
                try:
                    status = process.poll()
                except OSError as error:
                    ownership_known = False
                    raise CleanupUnknown("command child ownership is unknown") from error
                if status is not None:
                    return status
                if cancel.is_set() or time.monotonic() >= deadline:
                    return 130 if cancel.is_set() else 124
                time.sleep(0.1)
        finally:
            if ownership_known:
                try:
                    stop_group(process)
                except BaseException as error:
                    raise CleanupUnknown("command cleanup is unknown; state retained") from error
