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
record    reads the tar archive of files the refresh collected (already checked
          by pacman's own signature verification), stores each by digest with
          an immutable write, and writes the lock. Only a dispatched run on main
          does this; the lock changes only through a reviewed pull request.

The lock's snapshot must be the pins' kernel_builder.snapshot, so a pin change
without a refreshed lock fails before any download.
"""

import argparse
import json
import re
import sys
import tarfile
from pathlib import Path, PurePosixPath

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import cw_release as release  # noqa: E402
import cw_release_r2 as r2  # noqa: E402

LOCK = HERE / "kernel-builder-packages.json"
PINS = HERE / "local-runtime-sources.json"
# The builder container is x86_64; the arm64 kernel is cross-compiled there.
ARCH = "x86_64"
REPOSITORIES = ("core", "extra")
# The folders a collected archive may hold, as path parts.
FOLDERS = {(), *(folder for r in REPOSITORIES for folder in ((r,), (r, "os"), (r, "os", ARCH)))}
# A package with an epoch is named NAME-EPOCH:VERSION-REL-ARCH (fakeroot-1:1.37.2-3-x86_64.pkg.tar.zst).
FILE_NAME = re.compile(r"[A-Za-z0-9@._+:-]+")
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
    # pacman fetches each package's detached signature from the mirror too, so
    # a package without one would fail the offline build.
    for entry in files:
        if ".pkg.tar." in entry["name"] and not entry["name"].endswith(".sig"):
            require(relative_path(entry["repository"], entry["name"] + ".sig") in seen,
                    f"{relative_path(entry['repository'], entry['name'])} has no signature in the lock")
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


def record(s3, archive, snapshot):
    """Store each collected file by digest; return the lock's bytes.

    The archive is data from the archive's container, handed on as one tar
    file because an artifact path may not hold a package's epoch colon. It is
    read in memory and never extracted: only regular files at
    <repo>/os/x86_64/<file> and the folders above them, nothing else.
    """
    files, seen = [], set()
    with tarfile.open(archive, "r:") as tar:
        for member in tar:
            parts = PurePosixPath(member.name).parts
            if member.isdir():
                require(parts in FOLDERS, f"{member.name} is not a repository folder")
                continue
            require(member.isreg(), f"{member.name} is not a regular file")
            require(len(parts) == 4 and parts[1:3] == ("os", ARCH), f"{member.name} is not in a repository folder")
            repository, name = parts[0], parts[3]
            path = relative_path(repository, name)
            require(path not in seen, f"{path} is listed twice")
            require(len(seen) < MAX_FILES, "the archive holds too many files")
            seen.add(path)
            require(0 < member.size <= r2.MAX_OBJECT, f"{path} is empty or exceeds its bound")
            data = tar.extractfile(member).read(member.size + 1)
            require(len(data) == member.size, f"{path} is not the size the archive names")
            digest = release.sha256(data)
            outcome = r2.put_immutable(s3, key(digest), data, "application/octet-stream")
            r2.log(f"kernel builder {repository}/{name} {outcome}")
            files.append({"repository": repository, "name": name, "sha256": digest, "size": len(data)})
    files.sort(key=lambda f: (REPOSITORIES.index(f["repository"]), f["name"]))
    lock = json.dumps({"snapshot": snapshot, "files": files}, indent=1) + "\n"
    parse_lock(lock, snapshot)
    return lock


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    fetch_command = commands.add_parser("fetch")
    fetch_command.add_argument("--dir", required=True, type=Path)
    record_command = commands.add_parser("record")
    record_command.add_argument("--collected-tar", required=True, type=Path)
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
            lock = record(s3, args.collected_tar, snapshot)
            release.write_new(LOCK.with_suffix(".json.new"), lock.encode())
            LOCK.with_suffix(".json.new").replace(LOCK)
            print(f"kernel builder mirror: recorded {len(json.loads(lock)['files'])} files for snapshot {snapshot}")
    except (MirrorError, release.ReleaseError, r2.PublishError, r2.TransportError, OSError, KeyError,
            tarfile.TarError) as error:
        print(f"kernel builder mirror: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
