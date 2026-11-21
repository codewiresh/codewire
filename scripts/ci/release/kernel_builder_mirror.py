#!/usr/bin/env python3
"""The kernel builder's pacman packages, mirrored by content hash (#5619).

build-runtime-kernel.sh installs the kernel's toolchain with pacman from the
pinned archive.archlinux.org snapshot. A release must not depend on that
archive: it stalled v0.4.25's build (cli-release 65835) and was down for
v0.4.27's dry run (68539). So every file pacman reads for the pinned snapshot
-- the sync databases and each package, with their signatures -- is listed in
kernel-builder-packages.json by repository path, sha256 and size, and stored
once in the release R2 bucket the runtime parts cache already uses, under its
own prefix (KEY_PREFIX), content-addressed and written only if absent.

fetch     writes the locked files into DIR as a pacman repository tree
          (DIR/<repo>/os/x86_64/<file>), each read by its digest from the public
          origin and checked against the lock before it is written. A missing
          or different object fails; there is no other source.
record    reads a directory of files the refresh collected (already checked by
          pacman's own signature verification), stores each by digest with an
          immutable write, and writes the lock. Only a dispatched run on main
          does this; the lock changes only through a reviewed pull request.

The lock's snapshot must be the pins' kernel_builder.snapshot, so a pin change
without a refreshed lock fails before any download.
"""

import argparse
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import cw_release as release  # noqa: E402
import cw_release_r2 as r2  # noqa: E402

LOCK = HERE / "kernel-builder-packages.json"
PINS = HERE / "local-runtime-sources.json"
# The builder container is x86_64; the arm64 kernel is cross-compiled there.
ARCH = "x86_64"
REPOSITORIES = ("core", "extra")
FILE_NAME = re.compile(r"[A-Za-z0-9@._+-]+")
DIGEST = re.compile(r"[0-9a-f]{64}")
MAX_FILES = 2000
# Its own prefix in the release bucket, apart from the release's blobs.
KEY_PREFIX = f"{release.OBJECT_PREFIX}/kernel-builder/sha256"


class MirrorError(Exception):
    pass


def require(condition, reason):
    if not condition:
        raise MirrorError(reason)


def key(digest):
    require(DIGEST.fullmatch(digest) is not None, f"bad digest {digest!r}")
    return f"{KEY_PREFIX}/{digest}"


def relative_path(repository, name):
    require(repository in REPOSITORIES, f"unknown repository {repository!r}")
    require(FILE_NAME.fullmatch(name) is not None and name not in (".", ".."), f"bad file name {name!r}")
    return f"{repository}/os/{ARCH}/{name}"


def pinned_snapshot(pins_path=PINS):
    return json.loads(Path(pins_path).read_text())["kernel_builder"]["snapshot"]


def parse_lock(data, snapshot):
    """The lock's files, after every field is checked."""
    try:
        lock = json.loads(data)
    except ValueError as error:
        raise MirrorError(f"the lock is not JSON: {error}") from None
    require(isinstance(lock, dict) and set(lock) == {"snapshot", "files"}, "the lock must hold snapshot and files")
    require(lock["snapshot"] == snapshot,
            f"the lock is for snapshot {lock['snapshot']!r}, the pins name {snapshot!r}: refresh the mirror")
    files = lock["files"]
    require(isinstance(files, list) and 0 < len(files) <= MAX_FILES, "the lock lists no files, or too many")
    seen = set()
    for entry in files:
        require(isinstance(entry, dict) and set(entry) == {"repository", "name", "sha256", "size"},
                "a lock entry must hold repository, name, sha256 and size")
        path = relative_path(entry["repository"], entry["name"])
        require(path not in seen, f"{path} is listed twice")
        seen.add(path)
        require(isinstance(entry["sha256"], str) and DIGEST.fullmatch(entry["sha256"]) is not None,
                f"{path}: bad sha256")
        require(type(entry["size"]) is int and 0 < entry["size"] <= r2.MAX_OBJECT, f"{path}: bad size")
    for repository in REPOSITORIES:
        require(relative_path(repository, f"{repository}.db") in seen, f"the lock has no {repository}.db")
    return files


def fetch(origin, lock_bytes, snapshot, directory):
    """Write every locked file into `directory`, each checked before it is written."""
    files = parse_lock(lock_bytes, snapshot)
    directory = Path(directory)
    require(not directory.exists(), f"{directory} already exists")
    blobs = []
    for entry in files:
        path = relative_path(entry["repository"], entry["name"])
        response = origin.get(key(entry["sha256"]), r2.MAX_OBJECT)
        require(response.status == 200, f"{path}: the mirror returned status {response.status}")
        require(len(response.body) == entry["size"] and release.sha256(response.body) == entry["sha256"],
                f"{path}: the mirrored bytes differ from the lock")
        blobs.append((path, response.body))
    directory.mkdir(mode=0o755)
    for repository in REPOSITORIES:
        (directory / repository / "os" / ARCH).mkdir(parents=True, mode=0o755)
    for path, data in blobs:
        release.write_new(directory / path, data, 0o644)
    return len(blobs)


def record(s3, collected, snapshot):
    """Store each collected file by digest; return the lock's bytes."""
    collected = Path(collected)
    files = []
    for repository in REPOSITORIES:
        folder = collected / repository / "os" / ARCH
        # The collected tree is data from the archive's container: no link.
        for part in (collected, collected / repository, collected / repository / "os", folder):
            require(not part.is_symlink(), f"{part} is a link")
        require(folder.is_dir(), f"{folder} is missing")
        for item in sorted(folder.iterdir()):
            relative_path(repository, item.name)
            data = release.read_regular(item, r2.MAX_OBJECT)
            digest = release.sha256(data)
            outcome = r2.put_immutable(s3, key(digest), data, "application/octet-stream")
            r2.log(f"kernel builder {repository}/{item.name} {outcome}")
            files.append({"repository": repository, "name": item.name, "sha256": digest, "size": len(data)})
    lock = json.dumps({"snapshot": snapshot, "files": files}, indent=1) + "\n"
    parse_lock(lock, snapshot)
    return lock


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    fetch_command = commands.add_parser("fetch")
    fetch_command.add_argument("--dir", required=True, type=Path)
    record_command = commands.add_parser("record")
    record_command.add_argument("--collected", required=True, type=Path)
    record_command.add_argument("--credentials", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        snapshot = pinned_snapshot()
        if args.command == "fetch":
            count = fetch(r2.PublicOrigin(r2.HttpsTransport()), release.read_regular(LOCK, release.MAX_JSON * 16),
                          snapshot, args.dir)
            print(f"kernel builder mirror: {count} files for snapshot {snapshot} in {args.dir}")
        else:
            s3 = r2.S3(r2.HttpsTransport(), r2.load_credentials(args.credentials))
            lock = record(s3, args.collected, snapshot)
            release.write_new(LOCK.with_suffix(".json.new"), lock.encode())
            LOCK.with_suffix(".json.new").replace(LOCK)
            print(f"kernel builder mirror: recorded {len(json.loads(lock)['files'])} files for snapshot {snapshot}")
    except (MirrorError, release.ReleaseError, r2.PublishError, r2.TransportError, OSError, KeyError) as error:
        print(f"kernel builder mirror: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
