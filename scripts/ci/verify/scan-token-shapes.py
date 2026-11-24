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
BASELINE_HEADER = "# scan-token-shapes baseline"
BLOB_NAME = re.compile(r"[0-9a-f]{64}")
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
DECOMPRESSED = "!decompressed"
ICHECK_BATCH = 512
CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def printable(path):
    """PATH with control characters escaped: a name an image or a guest chose
    must not break a line of the output or the baseline."""
    return CONTROL.sub(lambda character: f"\\x{ord(character.group()):02x}", path)
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


def sha256_file(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


class ImageContent:
    """The bytes a walk declares as the image's own, and nothing else
    (docs/journeys/network-and-egress.md, "A baseline for what an image
    ships"): files under an image directory of a declared disk, read through
    its filesystem or raw where debugfs maps a block to one, and blobs whose
    name is their SHA-256."""

    def __init__(self, disks=None, blob_dirs=frozenset()):
        self.disks = disks or {}
        self.blob_dirs = blob_dirs
        # A raw finding in a declared disk -> the image file every block of it
        # is in, or None when they aren't all one image file's, or can't be
        # mapped.
        self.raw_files = {}
        # File label -> SHA-256, for image files holding a finding.
        self.file_digests = {}
        # Declared disk -> the name a baseline knows it by: its ext4
        # filesystem UUID, which a copy of the disk at another path (a
        # checkpoint's root) shares, or its path when that can't be read.
        self.names = {disk: disk for disk in self.disks}

    def name_disks(self, debugfs):
        for disk in self.disks:
            uuid = filesystem_uuid(debugfs, disk)
            if uuid is not None:
                self.names[disk] = f"ext4-uuid:{uuid}"

    def key(self, path):
        """PATH as a baseline lists it: a declared disk by its name."""
        for disk, name in self.names.items():
            if path == disk or path.startswith(disk + ":/") or path.startswith(disk + DECOMPRESSED):
                return name + path[len(disk):]
        return path

    def key_finding(self, finding):
        return (finding[0], finding[1], self.key(finding[2]), finding[3], finding[4])

    def is_blob(self, path):
        return os.path.dirname(path) in self.blob_dirs and BLOB_NAME.fullmatch(os.path.basename(path)) is not None

    def declared(self, path):
        """Whether PATH, as a baseline lists it, can be image content."""
        if CONTROL.search(path):
            return False
        path = path.removesuffix(DECOMPRESSED)
        if self.is_blob(path):
            return True
        named = {}
        for disk, name in self.names.items():
            named.setdefault(name, set()).add(self.disks[disk])
        if path.startswith("ext4-uuid:"):
            image, inside, inner = path[len("ext4-uuid:"):].partition(":/")
            image = "ext4-uuid:" + image
        else:
            image, inside, inner = path.partition(":/")
        if inside:
            return any(canaries.within("/" + inner, directory) for directory in named.get(image, ()))
        return path in named

    def file_of(self, finding):
        """The image file FINDING is in, or None."""
        path = finding[2]
        if CONTROL.search(path):
            return None
        label = path.removesuffix(DECOMPRESSED)
        if self.is_blob(label):
            return label if self.digest(label) is not None else None
        image, inside, inner = label.partition(":/")
        if inside:
            directory = self.disks.get(image)
            return label if directory is not None and canaries.within("/" + inner, directory) else None
        if path in self.disks:
            return self.raw_files.get(finding)
        return None

    def digest(self, label):
        """The SHA-256 of an image file as it is now, or None. A blob is
        image content only when its name is its SHA-256."""
        if self.is_blob(label):
            if label not in self.file_digests:
                self.file_digests[label] = sha256_file(label)
            return self.file_digests[label] if self.file_digests[label] == os.path.basename(label) else None
        return self.file_digests.get(label)


class Baseline:
    def __init__(self, findings=frozenset(), digests=None):
        self.findings = findings
        self.digests = digests or {}


class Results:
    def __init__(self, controls, baseline=None, image=None):
        self.controls = controls
        self.baseline = baseline or Baseline()
        self.image = image or ImageContent()
        self.found_controls = set()
        self.findings = set()
        # Finding -> the file bytes [start, end) it was read from.
        self.spans = {}
        self.placeholders = {}

    def excusal(self, finding):
        """None when the baseline doesn't excuse FINDING; else the image file
        it is in, and whether its shape is one a walk binds, which is excused
        only while that file's SHA-256 is the baseline's."""
        if self.image.key_finding(finding) not in self.baseline.findings:
            return None
        shape = finding[0]
        label = self.image.file_of(finding)
        if label is None:
            return None
        bound = shape.removeprefix("cut:") in BOUND_SHAPES
        if bound:
            now = self.image.digest(label)
            if now is None or now != self.baseline.digests.get(self.image.key(label)):
                return None
        return label, bound

    def placeholder(self, shape, key):
        self.placeholders.setdefault(shape, set()).add(key)

    def report(self, shape, form, path, offset, length, matched, span):
        name = self.controls.get(matched)
        if name is not None:
            self.found_controls.add(name)
            shape = f"control:{name}"
        finding = (shape, form, path, offset, length)
        self.findings.add(finding)
        start, end = self.spans.get(finding, span)
        self.spans[finding] = (min(start, span[0]), max(end, span[1]))


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


def scan_text(data, final, form, path, position, results, cut_unit=None, extent=None):
    """Find every shape in DATA, a byte string in one form.

    POSITION maps an index in DATA to the offset reported. A match that runs
    to DATA's end is left for the next chunk unless FINAL. CUT_UNIT, the
    bytes one character takes in the file, turns on the page-end rule.
    EXTENT, when POSITION can't map a match's end, is the file bytes DATA
    came from.
    """
    span = (lambda start, end: extent) if extent else (lambda start, end: (position(start), position(end)))
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
                results.report(shape, form, path, position(at), len(match.group(0)), matched, span(at, match.end()))
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
            results.report("cut:" + shape, form, path, position(at), run_end - at, None, span(at, run_end))


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
        scan_text(
            unescaped,
            True,
            f"{prefix}json-escaped",
            path,
            lambda _index, start=start: base + start,
            results,
            extent=(base + start, base + end),
        )


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


def scan_base64(data, base, final, path, results, unit=1):
    """Each base64 run in DATA decoded and scanned; UNIT is the file bytes one
    character of DATA takes (2 for text narrowed from UTF-16LE)."""
    for start, end in base64_runs(data, final):
        run = _AtRunStart(results, base + unit * start, base + unit * end)
        for decoded in base64_decodings(data[start:end]):
            scan_forms(decoded, base + unit * start, True, path, run, "base64/")


class _AtRunStart:
    """Results for a decoded run: every offset is the run's own start."""

    def __init__(self, results, start, end):
        self._results = results
        self._start = start
        self._end = end

    def placeholder(self, shape, key):
        form, path, _offset = key
        self._results.placeholder(shape, (form, path, self._start))

    def report(self, shape, form, path, _offset, length, matched, _span):
        self._results.report(shape, form, path, self._start, length, matched, (self._start, self._end))


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
        scan_base64(combined[start:end:2], base + start, True, path, results, unit=2)


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
        directory = results.image.disks.get(image)
        if directory is not None:
            map_image_files(image, directory, debugfs, target, results)
    finally:
        canaries.remove_spill(target)


def map_image_files(image, directory, debugfs, target, results):
    """While IMAGE's files are dumped at TARGET: hash each file under
    DIRECTORY that holds a finding, and map each raw finding in IMAGE to the
    one file under DIRECTORY that owns every block of it.

    Names come from the guest's own filesystem, so a raw finding's file is
    hashed by its inode, and a name with a control character, one not in the
    dump, or a hash that disagrees with the file's under that name maps the
    finding to None."""
    content = results.image
    for _shape, _form, path, _offset, _length in results.findings:
        label = path.removesuffix(DECOMPRESSED)
        inner = label.removeprefix(f"{image}:")
        if inner != label and canaries.within(inner, directory) and label not in content.file_digests:
            content.file_digests[label] = sha256_file(os.path.join(target, inner.lstrip("/")))
    raw = [finding for finding in results.findings if finding[2] == image]
    if not raw:
        return
    block_size = block_size_of(debugfs, image)
    spans = {}
    for finding in raw:
        start, end = results.spans.get(finding, (0, 0))
        spans[finding] = range(start // block_size, (end - 1) // block_size + 1) if end > start else None
    owners = icheck(debugfs, image, sorted({block for blocks in spans.values() if blocks for block in blocks}))
    names = ncheck(debugfs, image, sorted({inode for inode in owners.values() if inode is not None}))
    digests = {}
    for finding, blocks in spans.items():
        label = None
        found = {owners.get(block) for block in blocks} if blocks else {None}
        if len(found) == 1 and None not in found:
            inode = found.pop()
            label = image_file(image, directory, target, names.get(inode, []))
            if label is not None:
                if inode not in digests:
                    digests[inode] = inode_digest(debugfs, image, inode, os.path.dirname(target))
                if content.file_digests.setdefault(label, digests[inode]) != digests[inode]:
                    label = None
        content.raw_files[finding] = label


def image_file(image, directory, target, names):
    """The label of the image file every one of NAMES calls, or None."""
    if not names:
        return None
    for name in names:
        # A guest chose the name: no `.` or `..` part may lead the lookup
        # out of DIR or out of the dump.
        if CONTROL.search(name) or {".", ".."} & set(name.split("/")) or not canaries.within(name, directory):
            return None
        if not regular_file_in(target, name):
            return None
    return f"{image}:{min(names)}"


def regular_file_in(target, name):
    """Whether NAME is a regular file in the dump at TARGET with every part
    before it a real directory there: the dump keeps the image's symlinks,
    and one in a directory part would lead the lookup out of the dump."""
    current = target
    parts = [part for part in name.split("/") if part]
    try:
        for index, part in enumerate(parts):
            current = os.path.join(current, part)
            mode = os.lstat(current).st_mode
            if not (stat.S_ISREG(mode) if index == len(parts) - 1 else stat.S_ISDIR(mode)):
                return False
    except FileNotFoundError:
        return False
    return bool(parts)


def inode_digest(debugfs, image, inode, spill):
    """The SHA-256 of an inode's own bytes, dumped by number, not by name."""
    out = os.path.join(tempfile.mkdtemp(prefix="inode-", dir=spill), "file")
    try:
        canaries.debugfs_run(debugfs, image, f"dump <{inode}> {out}", out)
        return sha256_file(out)
    finally:
        canaries.remove_spill(os.path.dirname(out))


def filesystem_uuid(debugfs, image):
    """An ext4 image's filesystem UUID, or None when it isn't one or debugfs
    can't read it."""
    if not canaries.is_ext4(image):
        return None
    try:
        output = canaries.debugfs_run(debugfs, image, "stats")
    except ScanError:
        return None
    for line in output.decode("ascii", "replace").splitlines()[:60]:
        key, separator, value = line.partition(":")
        if separator and key.strip() == "Filesystem UUID" and UUID.fullmatch(value.strip()):
            return value.strip()
    return None


def block_size_of(debugfs, image):
    for line in canaries.debugfs_run(debugfs, image, "stats").decode("ascii", "replace").splitlines()[:60]:
        key, separator, value = line.partition(":")
        if separator and key.strip() == "Block size":
            return int(value.strip())
    raise ScanError(f"{image}: debugfs printed no block size")


def icheck(debugfs, image, blocks):
    """Block -> the inode that owns it, or None."""
    owners = {}
    for start in range(0, len(blocks), ICHECK_BATCH):
        batch = blocks[start:start + ICHECK_BATCH]
        output = canaries.debugfs_run(debugfs, image, "icheck " + " ".join(map(str, batch)))
        for line in output.decode("ascii", "replace").splitlines()[1:]:
            block, _separator, inode = line.partition("\t")
            if block.strip().isdigit():
                owners[int(block)] = int(inode) if inode.strip().isdigit() else None
    return owners


def ncheck(debugfs, image, inodes):
    """Inode -> every path that names it."""
    names = {}
    for start in range(0, len(inodes), ICHECK_BATCH):
        batch = inodes[start:start + ICHECK_BATCH]
        output = canaries.debugfs_run(debugfs, image, "ncheck " + " ".join(map(str, batch)))
        for line in output.decode("utf-8", "replace").splitlines()[1:]:
            inode, _separator, name = line.partition("\t")
            if inode.strip().isdigit() and name.startswith("/"):
                names.setdefault(int(inode), []).append(name)
    return names


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


def read_baseline(path, image, content):
    """The findings in image content of a scan of the same image, by this
    same scanner, before any credential was bound, and the SHA-256 of each
    image file holding one. A file for another image or scanner, or one
    listing a control or a finding outside image content, is refused."""
    with open(path, encoding="utf-8") as handle:
        lines = handle.read().splitlines()
    if not lines or lines[0] != baseline_header(image):
        raise ScanError(f"{path}: not a baseline of this image by this scanner")
    findings, digests = set(), {}
    for line in lines[1:]:
        fields = line.split("\t")
        if len(fields) == 3 and fields[0] == "sha256":
            digests[fields[1]] = fields[2]
            continue
        if len(fields) != 5:
            raise ScanError(f"{path}: not a baseline")
        if fields[0].startswith("control:"):
            raise ScanError(f"{path}: lists a control, which a baseline never excuses")
        if not content.declared(fields[2]):
            raise ScanError(f"{path}: lists a finding outside image content, which a baseline never excuses")
        try:
            findings.add((fields[0], fields[1], fields[2], int(fields[3]), int(fields[4])))
        except ValueError:
            raise ScanError(f"{path}: not a baseline") from None
    return Baseline(frozenset(findings), digests)


def write_baseline(path, image, results):
    """This run's findings in image content, and the SHA-256 of each image
    file holding one."""
    findings, labels = [], set()
    for finding in sorted(results.findings):
        label = results.image.file_of(finding)
        if label is not None and not finding[0].startswith("control:"):
            findings.append(finding)
            labels.add(label)
    content = results.image
    with open(path, "x", encoding="utf-8") as handle:
        handle.write(baseline_header(image) + "\n")
        handle.writelines("\t".join(map(str, content.key_finding(finding))) + "\n" for finding in findings)
        for label in sorted(labels):
            digest = content.digest(label)
            if digest is not None:
                handle.write(f"sha256\t{content.key(label)}\t{digest}\n")


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
        metavar="PATH:DIR",
        help="a disk whose files under DIR are the image alone, such as a local VM's root disk and /lower",
    )
    parser.add_argument(
        "--image-blobs",
        action="append",
        default=[],
        metavar="DIR",
        help="a directory of image blobs, each named by its SHA-256",
    )
    args = parser.parse_args(argv)
    if (args.baseline or args.write_baseline) and not args.image:
        parser.error("--baseline and --write-baseline need --image")
    if not args.paths and not args.processes:
        parser.error("name a PATH or --processes")
    scanned = []
    spill = None
    try:
        disks = {}
        for value in args.image_disk:
            disk, separator, directory = value.rpartition(":/")
            if not separator or not os.path.isabs(disk):
                raise ScanError(f"{value}: --image-disk takes an absolute PATH, a colon and the image's DIR")
            disks[os.path.realpath(disk)] = "/" + directory.rstrip("/")
        blob_dirs = frozenset(os.path.realpath(directory) for directory in args.image_blobs)
        content = ImageContent(disks, blob_dirs)
        if args.debugfs:
            content.name_disks(args.debugfs)
        baseline = read_baseline(args.baseline, args.image, content) if args.baseline else Baseline()
        results = Results(read_controls(sys.stdin.buffer), baseline, content)
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
    findings, counted, image_files = [], {}, {}
    for finding in sorted(results.findings):
        excusal = results.excusal(finding)
        if excusal is None:
            findings.append(finding)
        elif excusal[1]:
            key = (finding[0], excusal[0])
            image_files[key] = image_files.get(key, 0) + 1
        else:
            counted[finding[0]] = counted.get(finding[0], 0) + 1
    for shape, form, path, offset, length in findings:
        print(f"{shape}\t{form}\t{printable(path)}\t{offset}\t{length}")
    for (shape, label), count in sorted(image_files.items()):
        print(f"baseline-image\t{shape}\t{printable(label)}\t{count}")
    for shape in sorted(counted):
        print(f"baseline\t{shape}\t{counted[shape]}")
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
