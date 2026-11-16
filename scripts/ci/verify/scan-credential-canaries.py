#!/usr/bin/env python3
"""Find synthetic credential values in files, and in every file under directories.

The values arrive on stdin as `NAME<TAB>VALUE` lines, so they never appear in
argv. Each value is searched for as it is and in the forms a program might
store it in: base64 at each of its three alignments, hex in either case, and
UTF-16LE. A value is made of letters, digits, `.`, `_` and `-`, which URL
encoding leaves as they are, so its URL-encoded form is the value itself.

A raw disk image or a memory image keeps a file in blocks and pages that need
not be adjacent. A form shorter than a 4 KiB block crosses at most one
boundary, so each form is searched for as two adjacent 16-byte windows of its
last 32 bytes, one of which a single boundary always leaves whole; a whole
form contains its windows, so nothing else is needed. Each window must be the
value's own randomness, or it could match another value: a value's last 32
characters must be random, as they are in the synthetic provider's values (a
prefix and 32 hex characters) and in a `cwp1_` placeholder.

With --debugfs, every ext4 image found is also read through its filesystem,
read-only: its files are dumped into --spill, searched the same way, and
removed. An image is refused when its used blocks would not fit in the spill
filesystem's free space. --scanned FILE lists every file read, with its size,
so a caller can require that the files it expects were searched.

Only allocated ranges are read, so a sparse disk image costs what it holds.
Each finding is printed as `NAME<TAB>FORM<TAB>PATH<TAB>OFFSET`, a file inside
an ext4 image as `IMAGE:/PATH`; a value's bytes are never printed. The exit
status is 0 whether or not anything is found; the caller decides which names
must and must not be found. Status 2 means the scan itself failed.
"""

import argparse
import base64
import errno
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile

WINDOW = 16
WINDOWS = 2
ALLOWED = re.compile(rb"[A-Za-z0-9._-]+")
CHUNK = 4 * 1024 * 1024
EXT4_MAGIC_OFFSET = 1080
EXT4_MAGIC = b"\x53\xef"
SPILL_MARGIN = 64 * 1024 * 1024


class ScanError(Exception):
    pass


def base64_cores(value):
    """The base64 characters that depend only on the value, at each alignment."""
    cores = []
    for shift in range(3):
        encoded = base64.b64encode(b"\0" * shift + value)
        start = -(-shift * 4 // 3)
        end = (shift + len(value)) * 4 // 3
        cores.append((f"base64-{shift}", encoded[start:end]))
    return cores


def windows(encoded):
    """Two adjacent windows of the last 32 bytes of one encoded form."""
    tail = len(encoded) - WINDOWS * WINDOW
    return [encoded[tail + index * WINDOW:tail + (index + 1) * WINDOW] for index in range(WINDOWS)]


def forms(value):
    """Every byte string to search for one value, each named ENCODING/WINDOW."""
    encodings = [
        ("raw", value),
        *base64_cores(value),
        ("hex", value.hex().encode()),
        ("hex-upper", value.hex().upper().encode()),
        ("utf16le", value.decode("ascii").encode("utf-16-le")),
    ]
    unique = []
    seen = set()
    for encoding, encoded in encodings:
        for index, needle in enumerate(windows(encoded)):
            if needle not in seen:
                seen.add(needle)
                unique.append((f"{encoding}/{index}", needle))
    return unique


def read_values(stream):
    values = []
    names = set()
    for line in stream.read().splitlines():
        name, separator, value = line.partition(b"\t")
        name = name.decode("ascii", "strict")
        if not separator or not name or name in names:
            raise ScanError("each value needs one unique name")
        if len(value) < WINDOWS * WINDOW or not ALLOWED.fullmatch(value):
            raise ScanError(f"{name}: a value must be at least {WINDOWS * WINDOW} of A-Z a-z 0-9 . _ -")
        names.add(name)
        values.append((name, value))
    if not values:
        raise ScanError("no values on stdin")
    return values


def needles_for(values):
    return [(name, form, needle) for name, value in values for form, needle in forms(value)]


def allocated_ranges(descriptor, size):
    if not hasattr(os, "SEEK_DATA"):
        yield 0, size
        return
    offset = 0
    while offset < size:
        try:
            data = os.lseek(descriptor, offset, os.SEEK_DATA)
        except OSError as error:
            if error.errno == errno.ENXIO:
                return
            if error.errno in (errno.EINVAL, errno.ENOTSUP):
                yield 0, size
                return
            raise
        hole = os.lseek(descriptor, data, os.SEEK_HOLE)
        yield data, min(hole, size)
        offset = max(hole, data + 1)


def scan_file(path, needles):
    """Each (name, form, offset) whose needle is in the file, first offset only."""
    found = {}
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        size = os.fstat(descriptor).st_size
        for start, end in allocated_ranges(descriptor, size):
            carry = b""
            offset = start
            while offset < end:
                chunk = os.pread(descriptor, min(CHUNK, end - offset), offset)
                if not chunk:
                    break
                combined = carry + chunk
                base = offset - len(carry)
                # A dense memory image is mostly zero pages; none holds a value.
                if combined != bytes(len(combined)):
                    for name, form, needle in needles:
                        if (name, form) in found:
                            continue
                        at = combined.find(needle)
                        if at >= 0:
                            found[(name, form)] = base + at
                carry = combined[-(WINDOW - 1):]
                offset += len(chunk)
    finally:
        os.close(descriptor)
    return size, [(name, form, at) for (name, form), at in found.items()]


def is_ext4(path):
    try:
        with open(path, "rb") as handle:
            handle.seek(EXT4_MAGIC_OFFSET)
            return handle.read(2) == EXT4_MAGIC
    except OSError:
        return False


def unreadable(error):
    # A directory the walk cannot list would hide its files from the scan.
    raise ScanError(f"cannot read {error.filename}: {error.strerror}")


def regular_files(path):
    """The regular files at PATH: itself, or every one below it, links not followed.

    A directory that cannot be listed fails the scan rather than be skipped.
    """
    if stat.S_ISREG(os.stat(path, follow_symlinks=False).st_mode):
        yield path
        return
    for directory, directories, files in os.walk(path, followlinks=False, onerror=unreadable):
        directories[:] = sorted(
            name for name in directories if not os.path.islink(os.path.join(directory, name))
        )
        for name in sorted(files):
            found = os.path.join(directory, name)
            if stat.S_ISREG(os.stat(found, follow_symlinks=False).st_mode):
                yield found


def scan_paths(paths, needles, scanned, label=lambda path: path):
    findings = []
    for top in paths:
        for path in regular_files(top):
            size, found = scan_file(path, needles)
            scanned.append((label(path), size))
            findings += [(name, form, label(path), at) for name, form, at in found]
    return findings


def debugfs_run(debugfs, image, request, target=None):
    result = subprocess.run(
        [debugfs, "-c", "-R", request, image],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE if target is None else subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if result.returncode != 0:
        raise ScanError(f"{image}: debugfs exited {result.returncode}")
    return result.stdout


def used_bytes(debugfs, image):
    """The bytes an ext4 image's allocated blocks hold, from its superblock."""
    fields = {}
    for line in debugfs_run(debugfs, image, "stats").decode("ascii", "replace").splitlines()[:60]:
        key, separator, value = line.partition(":")
        if separator:
            fields[key.strip()] = value.strip()
    try:
        return (int(fields["Block count"]) - int(fields["Free blocks"])) * int(fields["Block size"])
    except (KeyError, ValueError):
        raise ScanError(f"{image}: debugfs printed no block counts") from None


def open_up(target):
    """Make an image's dumped files ours to read and remove.

    They keep the image's modes, so a directory the image holds as mode 000,
    such as an overlay's work directory, cannot be listed here either. Each
    directory is opened up before it is listed, and each file made readable.
    """
    os.chmod(target, stat.S_IRWXU)
    with os.scandir(target) as entries:
        for entry in entries:
            if entry.is_dir(follow_symlinks=False):
                open_up(entry.path)
            elif entry.is_file(follow_symlinks=False):
                os.chmod(entry.path, stat.S_IRUSR | stat.S_IWUSR)


def remove_spill(target):
    """Remove an image's dumped files. A spill that cannot be removed fails
    the scan rather than fill the disk one image at a time."""
    open_up(target)
    shutil.rmtree(target)


def scan_ext4(image, needles, debugfs, spill, scanned):
    """Read an ext4 image's files through the filesystem, read-only."""
    needed = used_bytes(debugfs, image) + SPILL_MARGIN
    free = shutil.disk_usage(spill).free
    if needed > free:
        raise ScanError(f"{image}: its files need {needed} bytes in the spill, which has {free}")
    target = tempfile.mkdtemp(prefix="ext4-", dir=spill)
    try:
        debugfs_run(debugfs, image, f"rdump / {target}", target)
        open_up(target)
        inside = lambda path: f"{image}:/{os.path.relpath(path, target)}"  # noqa: E731
        return scan_paths([target], needles, scanned, inside)
    finally:
        remove_spill(target)


def within(path, parent):
    return path == parent or path.startswith(parent + os.sep)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("paths", nargs="+", metavar="PATH", help="absolute files or directories to scan")
    parser.add_argument("--debugfs", help="also read each ext4 image through this debugfs")
    parser.add_argument(
        "--spill",
        help="an absolute private directory, outside every PATH, for ext4 files while they are read",
    )
    parser.add_argument("--scanned", help="write each file read, with its size, to this file")
    args = parser.parse_args(argv)
    scanned = []
    try:
        paths = []
        for path in args.paths:
            if not os.path.isabs(path) or not os.path.lexists(path):
                raise ScanError(f"{path}: not an absolute path that exists")
            paths.append(os.path.realpath(path))
        if args.debugfs:
            if not args.spill or not os.path.isabs(args.spill) or not os.path.isdir(args.spill):
                raise ScanError("--debugfs needs --spill, an absolute directory")
            spill = os.path.realpath(args.spill)
            if any(within(spill, path) for path in paths):
                raise ScanError("--spill must be outside every PATH")
        needles = needles_for(read_values(sys.stdin.buffer))
        findings = scan_paths(paths, needles, scanned)
        if args.debugfs:
            for top in paths:
                for path in regular_files(top):
                    if is_ext4(path):
                        findings += scan_ext4(path, needles, args.debugfs, spill, scanned)
        if args.scanned:
            with open(args.scanned, "w", encoding="utf-8") as handle:
                handle.writelines(f"{path}\t{size}\n" for path, size in scanned)
    except (ScanError, OSError, UnicodeError) as error:
        print(f"scan-credential-canaries: {error}", file=sys.stderr)
        return 2
    for name, form, path, at in sorted(set(findings)):
        print(f"{name}\t{form}\t{path}\t{at}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
