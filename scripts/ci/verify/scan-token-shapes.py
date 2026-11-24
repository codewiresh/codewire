#!/usr/bin/env python3
"""Find any value in a real provider credential's shape in files, without printing it.

`no-token-at-rest`'s shape scan (docs/journeys/network-and-egress.md, #6194).
The canary scan beside it finds synthetic values it is given; this finds any
value in a provider's shape, so a walk with real credentials can prove none is
at rest. The journey section is the spec; this is its implementation.

A match is classified and dropped at once. A whole `cwp1_` placeholder, alone
or after its provider prefix, is counted by shape. A match equal to a control,
a random value the walk passes on stdin as `NAME<TAB>VALUE` and plants where
the scan must find it, is reported by name. Anything else in a shape is a
finding. Output is one line per finding or control found,
`SHAPE<TAB>FORM<TAB>PATH<TAB>OFFSET<TAB>LENGTH`, then
`placeholder<TAB>SHAPE<TAB>COUNT` for each shape counted and
`missing<TAB>control:NAME` for a control not found. No byte of a match is
printed, hashed or kept, and an error names only a path, an offset and the
error's class.

Exit 0: nothing but placeholders and controls, and every control found.
Exit 1: a finding or a missing control. Exit 2: the scan itself failed.
"""

import argparse
import base64
import binascii
import gzip
import hashlib
import importlib.util
import json
import lzma
import os
import re
import resource
import signal
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "scan_credential_canaries", Path(__file__).with_name("scan-credential-canaries.py")
)
canaries = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(canaries)
ScanError = canaries.ScanError

CHUNK = 4 * 1024 * 1024
MAX_CARRY = 1024 * 1024
MIN_CARRY = 4096
PAGE = 4096
CUT_MIN = 16
BASE64_MIN = 40

TOKEN_CHARS = rb"A-Za-z0-9_\-"
WEAK = rb"(?<![A-Za-z0-9_\-])"

# Each shape: a name, its fixed prefix, the characters that follow it, how
# many, and whether the prefix is common enough in other text to need a
# boundary before it. A cut value is judged by the same characters.
SHAPES = [
    ("anthropic", rb"sk-ant-(?:api03|oat01|ort01|admin01)-", rb"[A-Za-z0-9_\-]", rb"{40,}", False),
    ("openai", rb"sk-(?:proj|svcacct|admin)-", rb"[A-Za-z0-9_\-]", rb"{40,}", False),
    ("openai-legacy", rb"sk-", rb"[A-Za-z0-9]", rb"{20}T3BlbkFJ[A-Za-z0-9]{20}", True),
    ("github", rb"gh[pousr]_", rb"[A-Za-z0-9]", rb"{36,251}", False),
    ("github-pat", rb"github_pat_", rb"[A-Za-z0-9_]", rb"{82}", False),
    ("google-api-key", rb"AIza", rb"[A-Za-z0-9_\-]", rb"{35}", True),
    ("google-oauth", rb"ya29\.", rb"[A-Za-z0-9_\-]", rb"{20,}", False),
    ("gitlab", rb"glpat-", rb"[A-Za-z0-9_\-]", rb"{20,}", False),
    ("slack", rb"xox[abposr]-", rb"[A-Za-z0-9\-]", rb"{10,}", False),
    ("aws-access-key-id", rb"(?:AKIA|ASIA)", rb"[A-Z0-9]", rb"{16}", True),
    ("stripe", rb"(?:sk|rk)_live_", rb"[A-Za-z0-9]", rb"{24,}", False),
    ("huggingface", rb"hf_", rb"[A-Za-z]", rb"{34}", True),
]
SHAPE_NAMES = [shape[0] for shape in SHAPES]
SHAPE_RUNS = [re.compile(chars + rb"*") for _name, _prefix, chars, _count, _weak in SHAPES]

# Exact issuers whose signed JWTs are provider credentials, and the shape each
# is reported as.
PROVIDER_ISSUERS = {
    "https://auth.openai.com": "jwt-openai",
    "https://accounts.google.com": "jwt-google",
    "accounts.google.com": "jwt-google",
}
# Shapes a walk binds: a baseline never excuses one, cut or whole.
BOUND_SHAPES = frozenset(
    {"anthropic", "openai", "openai-legacy", "github", "github-pat", "refresh-token-field", "jwt-openai"}
)
# Where in an image a baseline never applies: what a user or a run writes.
UNEXCUSED_DIRECTORIES = ("/home", "/workspace", "/root", "/tmp", "/var/tmp", "/run")
BASELINE_HEADER = "# scan-token-shapes baseline"
PLACEHOLDER_JWT_SIGNATURES = frozenset({b"", b"codewire-placeholder"})

PLACEHOLDER = re.compile(rb"cwp1_[A-Za-z0-9_\-]{43}")
PLACEHOLDER_REFRESH = re.compile(rb"codewire-managed-no-refresh-token(?:-[A-Za-z0-9_\-]+)?")
# A refresh token's value, as opposed to code that names one: 20 or more of a
# token's characters, with a letter and a digit.
REFRESH_VALUE = re.compile(rb"(?=[^0-9]*[0-9])(?=[^A-Za-z]*[A-Za-z])[A-Za-z0-9._~+/=\-]{20,}")


def _shape_alternatives():
    parts = []
    for index, (_name, prefix, chars, count, weak) in enumerate(SHAPES):
        parts.append(
            (WEAK if weak else b"")
            + rb"(?P<p%d>" % index
            + prefix
            + rb")(?P<b%d>" % index
            + chars
            + count
            + rb")(?![A-Za-z0-9_\-])"
        )
    return parts


MATCH = re.compile(
    b"|".join(
        _shape_alternatives()
        + [
            WEAK + rb"(?P<cwp1>cwp1_[A-Za-z0-9_\-]{43})(?![A-Za-z0-9_\-])",
            WEAK + rb"(?P<jwt>eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*)",
            rb"(?P<refresh>(?:\"refresh_token\"\s*:\s*"
            rb"|(?<![A-Za-z0-9])(?:refresh_token|REFRESH_TOKEN)[ \t]*[=:][ \t]*)"
            rb"(?:\"(?P<rq>[^\"\\\r\n]*)\"|'(?P<rs>[^'\\\r\n]*)'|(?P<rb>[^\s\"'#,;}]+)))",
        ]
    )
)
PREFIX = re.compile(
    b"|".join(
        (WEAK if weak else b"") + rb"(?P<p%d>" % index + prefix + b")"
        for index, (_name, prefix, _chars, _count, weak) in enumerate(SHAPES)
    )
)
# Every match starts with one of these, so a match is looked for only where
# one is: bytes.find runs at memory speed, a regex tried at every byte does
# not.
LITERALS = (
    b"sk-", b"sk_live_", b"rk_live_", b"ghp_", b"gho_", b"ghu_", b"ghs_", b"ghr_", b"github_pat_", b"AIza", b"ya29.",
    b"glpat-", b"xox", b"AKIA", b"ASIA", b"hf_", b"cwp1_", b"eyJ", b'"refresh_token"', b"refresh_token",
    b"REFRESH_TOKEN",
)


def _table(classes, default=b"."):
    """A bytes.translate table mapping each byte to the class it belongs to."""
    table = bytearray(default * 256)
    for members, label in classes:
        for byte in members:
            table[byte] = label[0]
    return bytes(table)


ALNUM_BYTES = bytes(range(48, 58)) + bytes(range(65, 91)) + bytes(range(97, 123))
_BASE64_CHARS = ALNUM_BYTES + b"+/_-"
BASE64_CLASSES = _table([(_BASE64_CHARS, b"A"), (b"\n", b"N"), (b"\r", b"R"), (b"=", b"E")])
UTF16_CLASSES = _table([(bytes(range(0x20, 0x7F)), b"P"), (b"\0", b"Z")])
JSON_RUN_CLASSES = _table([(ALNUM_BYTES + b"_.-=\"': \\", b"J")])
CARRY_CLASSES = _table([(_BASE64_CHARS + b"=.\r\n\"': \\", b"C")])
A_RUN = re.compile(rb"A*")
PZ_RUN = re.compile(rb"(?:PZ)*")
JSON_ESCAPE = re.compile(rb"\\u00([0-9A-Fa-f]{2})|\\([\"/\\])")

GZIP_MAGIC = b"\x1f\x8b"
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
XZ_MAGIC = b"\xfd7zXZ\x00"
JOURNAL_MAGIC = b"LPKSHHRH"


class Where:
    """What is being read, so an error can name it without any bytes."""

    path = None
    offset = None


WHERE = Where()


class Results:
    def __init__(self, controls, baseline=frozenset(), image_disks=frozenset()):
        self.controls = controls
        self.baseline = baseline
        self.image_disks = image_disks
        self.found_controls = set()
        self.findings = set()
        self.placeholders = {}

    def excused(self, finding):
        """Whether the baseline excuses FINDING: the same finding, of a shape
        no walk binds, in a declared image disk, read raw or through its
        filesystem outside what a user or a run writes
        (docs/journeys/network-and-egress.md, "A baseline for what an image
        ships"). A state disk is never declared: mounted as a home, its own
        root holds the user's files."""
        shape, _form, path, _offset, _length = finding
        if finding not in self.baseline or shape.removeprefix("cut:") in BOUND_SHAPES:
            return False
        if "!decompressed" in path:
            return False
        image, inside, inner = path.partition(":/")
        if image not in self.image_disks:
            return False
        return not inside or not any(canaries.within("/" + inner, directory) for directory in UNEXCUSED_DIRECTORIES)

    def placeholder(self, shape, key):
        self.placeholders.setdefault(shape, set()).add(key)

    def report(self, shape, form, path, offset, length, matched):
        name = self.controls.get(matched)
        if name is not None:
            self.found_controls.add(name)
            shape = f"control:{name}"
        self.findings.add((shape, form, path, offset, length))


def b64url_json(segment):
    try:
        decoded = base64.urlsafe_b64decode(segment + b"=" * (-len(segment) % 4))
        value = json.loads(decoded)
    except (binascii.Error, ValueError):
        return None
    return value if isinstance(value, dict) else None


def jwt_shape(token):
    """`None` when the JWT is no credential here, else the shape it is."""
    header_segment, payload_segment, signature = token.split(b".")
    header = b64url_json(header_segment)
    if header is None:
        return "jwt-unreadable"
    if header.get("alg") == "none":
        return None if signature in PLACEHOLDER_JWT_SIGNATURES else "jwt-unsigned-signature"
    payload = b64url_json(payload_segment)
    if payload is None or not isinstance(payload.get("iss"), str):
        return "jwt-unreadable"
    return PROVIDER_ISSUERS.get(payload["iss"])


def classify(match):
    """(kind, shape, matched bytes) for one match; kind is placeholder,
    finding or None."""
    group = match.lastgroup
    if group == "cwp1":
        return "placeholder", "cwp1", None
    if group == "jwt":
        token = match.group("jwt")
        shape = jwt_shape(token)
        return ("finding", shape, token) if shape else (None, None, None)
    if group in ("refresh", "rq", "rs", "rb"):
        value = match.group("rq")
        if value is None:
            value = match.group("rs")
        if value is None:
            value = match.group("rb")
        if not REFRESH_VALUE.fullmatch(value) or PLACEHOLDER_REFRESH.fullmatch(value) or PLACEHOLDER.fullmatch(value):
            return None, None, None
        return "finding", "refresh-token-field", value
    index = int(group[1:])
    shape = SHAPE_NAMES[index]
    if PLACEHOLDER.fullmatch(match.group(f"b{index}")):
        return "placeholder", shape, None
    return "finding", shape, match.group(0)


def hits(data):
    """Every index in DATA where one of LITERALS starts, in order."""
    found = set()
    for literal in LITERALS:
        at = data.find(literal)
        while at >= 0:
            found.add(at)
            at = data.find(literal, at + 1)
    return sorted(found)


def scan_text(data, final, form, path, position, results, cut_unit=None):
    """Find every shape in DATA, a byte string in one form.

    POSITION maps an index in DATA to the offset reported. A match that runs
    to DATA's end is left for the next chunk unless FINAL. CUT_UNIT, the
    bytes one character takes in the file, turns on the page-end rule.
    """
    covered = 0
    for at in hits(data):
        if at < covered:
            continue
        match = MATCH.match(data, at)
        if match is not None:
            if not final and match.end() == len(data):
                continue
            covered = match.end()
            kind, shape, matched = classify(match)
            if kind == "placeholder":
                results.placeholder(shape, (form, path, position(at)))
            elif kind == "finding":
                results.report(shape, form, path, position(at), len(match.group(0)), matched)
            continue
        prefix = PREFIX.match(data, at) if cut_unit is not None else None
        if prefix is None:
            continue
        index = int(prefix.lastgroup[1:])
        run_end = SHAPE_RUNS[index].match(data, prefix.end()).end()
        if run_end == len(data) and not final:
            continue
        # The first page boundary with at least CUT_MIN characters before it.
        boundary = -(-(position(prefix.end()) + CUT_MIN * cut_unit) // PAGE) * PAGE
        if position(run_end) < boundary:
            continue
        shape = SHAPE_NAMES[index]
        if data.startswith(b"cwp1_", prefix.end()):
            results.placeholder(shape, (form, path, position(at)))
        else:
            results.report("cut:" + shape, form, path, position(at), run_end - at, None)


def utf16_runs(data, final):
    """(start, end) of each run of 16 or more UTF-16LE printable characters."""
    classes = data.translate(UTF16_CLASSES)
    at = classes.find(b"PZ" * 16)
    while at >= 0:
        end = PZ_RUN.match(classes, at).end()
        if final or end < len(data):
            yield at, end
        at = classes.find(b"PZ" * 16, end)


def json_escaped_runs(data, final):
    """(start, end) of each run of value characters holding a `\\u00XX` or a
    `\\"` escape: JSON text inside a JSON string, as in a log line."""
    classes = data.translate(JSON_RUN_CLASSES)
    starts = sorted(set(escape_starts(data, b"\\u00")) | set(escape_starts(data, b'\\"')))
    end = 0
    for at in starts:
        if at < end:
            continue
        start = classes.rfind(b".", 0, at) + 1
        end = classes.find(b".", at)
        end = len(data) if end < 0 else end
        if end - start >= 16 and (final or end < len(data)):
            yield start, end


def escape_starts(data, escape):
    at = data.find(escape)
    while at >= 0:
        yield at
        at = data.find(escape, at + 1)


def unescape(escape):
    return bytes([int(escape.group(1), 16)]) if escape.group(1) else escape.group(2)


def scan_forms(data, base, final, path, results, prefix="", cut=False):
    """Scan DATA, which starts at file offset BASE, in its raw, UTF-16LE and
    JSON-escaped forms."""
    scan_text(data, final, f"{prefix}raw", path, lambda index: base + index, results, 1 if cut else None)
    for start, end in utf16_runs(data, final):
        scan_text(
            data[start:end:2],
            True,
            f"{prefix}utf16le",
            path,
            lambda index, start=start: base + start + 2 * index,
            results,
            2 if cut else None,
        )
    for start, end in json_escaped_runs(data, final):
        unescaped = JSON_ESCAPE.sub(unescape, data[start:end])
        scan_text(unescaped, True, f"{prefix}json-escaped", path, lambda _index, start=start: base + start, results)


def base64_runs(data, final):
    """(start, end) of each run of 40 or more base64 characters, with lines
    broken only by a newline joined, and up to two `=` after it."""
    classes = data.translate(BASE64_CLASSES)
    at = classes.find(b"A" * BASE64_MIN)
    while at >= 0:
        end = A_RUN.match(classes, at).end()
        while True:
            if classes.startswith(b"NA", end):
                end = A_RUN.match(classes, end + 1).end()
            elif classes.startswith(b"RNA", end):
                end = A_RUN.match(classes, end + 2).end()
            else:
                break
        for _ in range(2):
            if classes.startswith(b"E", end):
                end += 1
        if final or end < len(data):
            yield at, end
        at = classes.find(b"A" * BASE64_MIN, end)


def base64_decodings(run):
    """RUN decoded at each character alignment, in each alphabet it fits."""
    joined = run.replace(b"\r", b"").replace(b"\n", b"").rstrip(b"=")
    alphabets = []
    if b"_" not in joined and b"-" not in joined:
        alphabets.append(base64.b64decode)
    if b"+" not in joined and b"/" not in joined:
        alphabets.append(base64.urlsafe_b64decode)
    for decode in alphabets:
        for shift in range(4):
            usable = joined[shift:]
            usable = usable[: len(usable) - len(usable) % 4]
            if len(usable) >= BASE64_MIN - 3:
                yield decode(usable)


def scan_base64(data, base, final, path, results):
    for start, end in base64_runs(data, final):
        for decoded in base64_decodings(data[start:end]):
            scan_forms(decoded, base + start, True, path, _AtRunStart(results, base + start), "base64/")


class _AtRunStart:
    """Results for a decoded run: every offset is the run's own start."""

    def __init__(self, results, start):
        self._results = results
        self._start = start

    def placeholder(self, shape, key):
        form, path, _offset = key
        self._results.placeholder(shape, (form, path, self._start))

    def report(self, shape, form, path, _offset, length, matched):
        self._results.report(shape, form, path, self._start, length, matched)


def carry_start(combined):
    """Where the bytes worth seeing again with the next chunk begin: the
    trailing run of characters a value or its encodings are made of, or of
    UTF-16LE text, at least MIN_CARRY and at most MAX_CARRY bytes."""
    window = max(0, len(combined) - MAX_CARRY)
    tail = combined[window:]
    run = window + tail.translate(CARRY_CLASSES).rfind(b".") + 1
    classes = tail.translate(UTF16_CLASSES)
    pairs = len(tail)
    while pairs >= 2 and classes[pairs - 2:pairs] == b"PZ":
        pairs -= 2
    return max(0, min(run, window + pairs, len(combined) - MIN_CARRY))


def scan_chunks(chunks, path, results, cut):
    """Scan a file read as (offset, bytes) chunks, each followed directly by
    the next unless a hole lies between them."""
    carry = b""
    carry_base = 0
    pending = None
    for offset, chunk in chunks:
        if pending is not None:
            scan_block(*pending, final=offset != pending[1] + len(pending[0]), path=path, results=results, cut=cut)
        if carry and carry_base + len(carry) == offset:
            combined, base = carry + chunk, carry_base
        else:
            combined, base = chunk, offset
        pending = (combined, base)
        keep = carry_start(combined)
        carry, carry_base = combined[keep:], base + keep
    if pending is not None:
        scan_block(*pending, final=True, path=path, results=results, cut=cut)


def scan_block(combined, base, final, path, results, cut):
    WHERE.offset = base
    # A dense memory image is mostly zero pages; none holds a value.
    if combined.count(0) == len(combined):
        return
    scan_forms(combined, base, final, path, results, cut=cut)
    scan_base64(combined, base, final, path, results)
    for start, end in utf16_runs(combined, final):
        scan_base64(combined[start:end:2], base + start, True, path, results)


def file_chunks(descriptor):
    size = os.fstat(descriptor).st_size
    if stat.S_ISREG(os.fstat(descriptor).st_mode) and size > 0:
        for start, end in canaries.allocated_ranges(descriptor, size):
            offset = start
            while offset < end:
                chunk = os.pread(descriptor, min(CHUNK, end - offset), offset)
                if not chunk:
                    break
                yield offset, chunk
                offset += len(chunk)
        return
    # A pipe, or a file the kernel sizes as 0 such as /proc/PID/environ.
    yield from stream_chunks(lambda: os.read(descriptor, CHUNK))


def stream_chunks(read):
    offset = 0
    while True:
        chunk = read()
        if not chunk:
            return
        yield offset, chunk
        offset += len(chunk)


def decompressed(path, magic):
    """The decompressed bytes of a compressed file, as chunks."""
    if magic.startswith(GZIP_MAGIC):
        with gzip.open(path, "rb") as handle:
            yield from stream_chunks(lambda: handle.read(CHUNK))
    elif magic.startswith(XZ_MAGIC):
        with lzma.open(path, "rb") as handle:
            yield from stream_chunks(lambda: handle.read(CHUNK))
    elif magic.startswith(ZSTD_MAGIC):
        yield from command_chunks(["zstd", "-dc", "--", path])
    elif magic.startswith(JOURNAL_MAGIC):
        yield from command_chunks(["journalctl", "--file", path, "-o", "export", "--no-pager"])


def command_chunks(argv):
    try:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        raise ScanError(f"{WHERE.path}: {argv[0]} is needed to read it and is not installed") from None
    try:
        yield from stream_chunks(lambda: process.stdout.read(CHUNK))
    finally:
        process.stdout.close()
        status = process.wait()
    if status != 0:
        raise ScanError(f"{WHERE.path}: {argv[0]} exited {status}")


def scan_file(path, label, results, scanned, cut):
    WHERE.path, WHERE.offset = label, None
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        size = os.fstat(descriptor).st_size
        magic = os.pread(descriptor, 8, 0) if stat.S_ISREG(os.fstat(descriptor).st_mode) else b""
        scan_chunks(file_chunks(descriptor), label, results, cut)
    finally:
        os.close(descriptor)
    scanned.append((label, size))
    if magic.startswith((GZIP_MAGIC, XZ_MAGIC, ZSTD_MAGIC, JOURNAL_MAGIC)):
        inside = f"{label}!decompressed"
        WHERE.path = inside
        try:
            scan_chunks(decompressed(path, magic), inside, results, False)
        except (EOFError, lzma.LZMAError, gzip.BadGzipFile, OSError) as error:
            raise ScanError(f"{label}: cannot decompress it ({type(error).__name__})") from None
        scanned.append((inside, -1))


def regular_files(top, excluded):
    """The regular files at TOP, links not followed, skipping EXCLUDED paths.
    A directory that cannot be listed fails the scan."""
    if stat.S_ISREG(os.stat(top, follow_symlinks=False).st_mode):
        yield top
        return
    for directory, directories, files in os.walk(top, followlinks=False, onerror=canaries.unreadable):
        directories[:] = sorted(
            name
            for name in directories
            if not os.path.islink(os.path.join(directory, name))
            and os.path.join(directory, name) not in excluded
        )
        for name in sorted(files):
            found = os.path.join(directory, name)
            if found not in excluded and stat.S_ISREG(os.stat(found, follow_symlinks=False).st_mode):
                yield found


def scan_tree(top, excluded, results, scanned, label=lambda path: path, cut=True):
    for path in regular_files(top, excluded):
        scan_file(path, label(path), results, scanned, cut)


def scan_processes(results, scanned):
    """Every other process's environment and command line. One that cannot be
    read fails the scan; one that exited meanwhile is gone and is skipped."""
    for entry in sorted(os.listdir("/proc")):
        if not entry.isdigit():
            continue
        for part in ("environ", "cmdline"):
            path = f"/proc/{entry}/{part}"
            try:
                scan_file(path, path, results, scanned, False)
            except (FileNotFoundError, ProcessLookupError):
                continue
            except PermissionError:
                raise ScanError(f"{path}: cannot read it; run the scan as root") from None


def on_tmpfs(path):
    """Whether PATH lies on a memory-backed filesystem, from the mount table."""
    best, kind = "", None
    with open("/proc/self/mounts", encoding="utf-8") as mounts:
        for line in mounts:
            fields = line.split()
            mount = fields[1].replace("\\040", " ")
            if canaries.within(path, mount) and len(mount) >= len(best):
                best, kind = mount, fields[2]
    return kind in ("tmpfs", "ramfs")


def make_spill(parent):
    if not parent or not os.path.isabs(parent) or not os.path.isdir(parent):
        raise ScanError("the spill parent must be an absolute directory (--spill-parent, or XDG_RUNTIME_DIR)")
    parent = os.path.realpath(parent)
    if not on_tmpfs(parent):
        raise ScanError(f"{parent}: the spill must be on tmpfs, never a persistent disk")
    return tempfile.mkdtemp(prefix="scan-token-shapes-", dir=parent)


def scan_ext4(image, debugfs, spill, results, scanned):
    """Read an ext4 image's files through the filesystem, read-only."""
    needed = canaries.used_bytes(debugfs, image) + canaries.SPILL_MARGIN
    free = os.statvfs(spill).f_bavail * os.statvfs(spill).f_frsize
    if needed > free:
        raise ScanError(f"{image}: its files need {needed} bytes in the spill, which has {free}")
    target = tempfile.mkdtemp(prefix="ext4-", dir=spill)
    try:
        canaries.debugfs_run(debugfs, image, f"rdump / {target}", target)
        canaries.open_up(target)
        inside = lambda path: f"{image}:/{os.path.relpath(path, target)}"  # noqa: E731
        scan_tree(target, set(), results, scanned, inside, cut=False)
    finally:
        canaries.remove_spill(target)


def read_controls(stream):
    controls = {}
    for line in stream.read().splitlines():
        name, separator, value = line.partition(b"\t")
        try:
            name = name.decode("ascii")
        except UnicodeDecodeError:
            raise ScanError("a control's name must be ASCII") from None
        if not separator or not name or name in controls.values():
            raise ScanError("each control needs one unique name")
        if len(value) < 20 or not all(0x21 <= byte <= 0x7E for byte in value) or PLACEHOLDER.fullmatch(value):
            raise ScanError(f"{name}: a control must be 20 or more printable characters, and not a placeholder")
        controls[value] = name
    return controls


def scanner_digest():
    """SHA-256 of the scanner's code: this file and the canary scanner it loads."""
    digest = hashlib.sha256()
    for path in (Path(__file__), Path(__file__).with_name("scan-credential-canaries.py")):
        digest.update(path.read_bytes())
    return digest.hexdigest()


def baseline_header(image):
    return f"{BASELINE_HEADER}\timage={image}\tscanner={scanner_digest()}"


def read_baseline(path, image):
    """The findings of a scan of the same image, by this same scanner, before
    any credential was bound. A file for another image or scanner, or one
    listing a bound shape or a control, is refused."""
    with open(path, encoding="utf-8") as handle:
        lines = handle.read().splitlines()
    if not lines or lines[0] != baseline_header(image):
        raise ScanError(f"{path}: not a baseline of this image by this scanner")
    baseline = set()
    for line in lines[1:]:
        fields = line.split("\t")
        if len(fields) != 5:
            raise ScanError(f"{path}: not a findings list")
        shape = fields[0]
        if shape.startswith("control:") or shape.removeprefix("cut:") in BOUND_SHAPES:
            raise ScanError(f"{path}: lists {shape.partition(':')[0] if shape.startswith('control:') else shape}, which a baseline never excuses")
        try:
            baseline.add((shape, fields[1], fields[2], int(fields[3]), int(fields[4])))
        except ValueError:
            raise ScanError(f"{path}: not a findings list") from None
    return frozenset(baseline)


def write_baseline(path, image, results):
    with open(path, "x", encoding="utf-8") as handle:
        handle.write(baseline_header(image) + "\n")
        handle.writelines("\t".join(map(str, finding)) + "\n" for finding in sorted(results.findings))


def stop(_signum, _frame):
    raise SystemExit(2)


def main(argv=None):
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGHUP, stop)
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "paths", nargs="*", metavar="PATH", help="absolute files, directories or pipes (such as <(command)) to scan"
    )
    parser.add_argument("--exclude", action="append", default=[], metavar="PATH", help="an absolute path not to walk into")
    parser.add_argument("--processes", action="store_true", help="also scan every process's environment and command line")
    parser.add_argument("--debugfs", help="also read each ext4 image through this debugfs")
    parser.add_argument(
        "--spill-parent",
        default=os.environ.get("XDG_RUNTIME_DIR"),
        help="a tmpfs directory for ext4 files while they are read (default XDG_RUNTIME_DIR)",
    )
    parser.add_argument("--scanned", help="write each file read, with its size, to this file")
    parser.add_argument("--baseline", help="a baseline this scanner wrote for --image before any credential was bound")
    parser.add_argument("--write-baseline", metavar="FILE", help="write this run's findings as the baseline for --image")
    parser.add_argument("--image", metavar="DIGEST", help="the digest of the image the baseline belongs to")
    parser.add_argument(
        "--image-disk",
        action="append",
        default=[],
        metavar="PATH",
        help="a disk image that holds only the image, never a state disk; its raw findings may be excused",
    )
    args = parser.parse_args(argv)
    if (args.baseline or args.write_baseline) and not args.image:
        parser.error("--baseline and --write-baseline need --image")
    if not args.paths and not args.processes:
        parser.error("name a PATH or --processes")
    scanned = []
    spill = None
    try:
        baseline = read_baseline(args.baseline, args.image) if args.baseline else frozenset()
        image_disks = frozenset(os.path.realpath(path) for path in args.image_disk)
        results = Results(read_controls(sys.stdin.buffer), baseline, image_disks)
        # Kernel views, not storage; --processes reads what matters in /proc.
        excluded = {"/proc", "/sys", "/dev"}
        for path in args.exclude:
            if not os.path.isabs(path):
                raise ScanError(f"{path}: --exclude takes an absolute path")
            excluded.add(os.path.realpath(path))
        streams, trees = [], []
        for path in args.paths:
            if not os.path.isabs(path) or not os.path.lexists(path):
                raise ScanError(f"{path}: not an absolute path that exists")
            mode = os.stat(path).st_mode
            if stat.S_ISFIFO(mode) or stat.S_ISCHR(mode):
                streams.append(path)
            else:
                trees.append(os.path.realpath(path))
        if args.debugfs:
            spill = make_spill(args.spill_parent)
            if any(canaries.within(spill, path) for path in trees):
                raise ScanError("the spill must be outside every PATH")
        for path in streams:
            WHERE.path, WHERE.offset = path, None
            descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
            try:
                scan_chunks(file_chunks(descriptor), path, results, False)
            finally:
                os.close(descriptor)
            scanned.append((path, -1))
        for top in trees:
            scan_tree(top, excluded, results, scanned)
        if args.processes:
            scan_processes(results, scanned)
        if args.debugfs:
            for top in trees:
                for path in regular_files(top, excluded):
                    if canaries.is_ext4(path):
                        scan_ext4(path, args.debugfs, spill, results, scanned)
        if args.scanned:
            with open(args.scanned, "w", encoding="utf-8") as handle:
                handle.writelines(f"{path}\t{size}\n" for path, size in scanned)
        if args.write_baseline:
            write_baseline(args.write_baseline, args.image, results)
        return report(results)
    except ScanError as error:
        print(f"scan-token-shapes: {error}", file=sys.stderr)
        return 2
    except BaseException as error:  # noqa: BLE001 - no traceback may carry a value
        where = f"{WHERE.path or '-'} at offset {WHERE.offset if WHERE.offset is not None else '-'}"
        print(f"scan-token-shapes: {where}: {type(error).__name__}", file=sys.stderr)
        return 2
    finally:
        if spill is not None:
            canaries.remove_spill(spill)


def report(results):
    findings = sorted(finding for finding in results.findings if not results.excused(finding))
    for shape, form, path, offset, length in findings:
        print(f"{shape}\t{form}\t{path}\t{offset}\t{length}")
    baseline = {}
    for shape, *_rest in results.findings - set(findings):
        baseline[shape] = baseline.get(shape, 0) + 1
    for shape in sorted(baseline):
        print(f"baseline\t{shape}\t{baseline[shape]}")
    for shape in sorted(results.placeholders):
        print(f"placeholder\t{shape}\t{len(results.placeholders[shape])}")
    missing = sorted(set(results.controls.values()) - results.found_controls)
    for name in missing:
        print(f"missing\tcontrol:{name}")
    sys.stdout.flush()
    failed = missing or any(not shape.startswith("control:") for shape, *_rest in findings)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
