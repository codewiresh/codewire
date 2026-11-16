#!/usr/bin/env python3
"""The credential canary scanner finds each value in every form it searches
for, says where without printing it, and refuses input it cannot search
soundly. Values are synthetic; ext4 cases need mkfs.ext4 and debugfs."""

import base64
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import importlib.util

ROOT = Path(__file__).resolve().parents[3]
SCANNER = ROOT / "scripts/ci/verify/scan-credential-canaries.py"


def value(prefix="cwtest"):
    # The synthetic provider's shape: a prefix and 32 hex characters.
    return prefix + secrets.token_hex(16)


def load_scanner():
    spec = importlib.util.spec_from_file_location("scan_credential_canaries", SCANNER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def tool(name):
    for directory in ("/usr/sbin", "/usr/bin"):
        path = Path(directory) / name
        if path.is_file():
            return str(path)
    return None


class Scanner(unittest.TestCase):
    def setUp(self):
        self.temporary = Path(tempfile.mkdtemp(prefix="scan-canaries-"))
        self.root = self.temporary / "root"
        self.root.mkdir()

    def tearDown(self):
        shutil.rmtree(self.temporary)

    def scan(self, values, *paths, extra=()):
        stdin = "".join(f"{name}\t{data}\n" for name, data in values).encode()
        result = subprocess.run(
            [sys.executable, "-I", str(SCANNER), *extra, *[str(path) for path in (paths or [self.root])]],
            input=stdin,
            capture_output=True,
            check=False,
        )
        for _, data in values:
            self.assertNotIn(data.encode(), result.stdout + result.stderr)
        return result

    def findings(self, values, *paths, extra=()):
        result = self.scan(values, *paths, extra=extra)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        rows = [line.split("\t") for line in result.stdout.decode().splitlines()]
        return {(name, form): (path, int(offset)) for name, form, path, offset in rows}

    def test_finds_the_raw_value_with_its_offset_and_never_prints_it(self):
        secret = value()
        (self.root / "log").write_bytes(b"x" * 100 + secret.encode() + b"\n")
        found = self.findings([("token", secret)])
        tail = 100 + len(secret) - 32
        for index in range(2):
            self.assertEqual(found[("token", f"raw/{index}")], (str(self.root / "log"), tail + 16 * index))

    def test_a_clean_tree_reports_nothing(self):
        (self.root / "log").write_bytes(b"nothing here\n")
        self.assertEqual(self.findings([("token", value())]), {})

    def test_another_value_with_the_same_prefix_is_not_reported(self):
        (self.root / "log").write_bytes(value().encode())
        self.assertEqual(self.findings([("token", value())]), {})

    def test_a_value_split_across_blocks_is_found_by_a_window(self):
        secret = value().encode()
        for cut in range(1, len(secret)):
            path = self.root / "image"
            path.write_bytes(secret[:cut] + os.urandom(4096) + secret[cut:])
            found = self.findings([("token", secret.decode())])
            self.assertTrue(any(form.startswith("raw/") for _, form in found), cut)

    def test_every_base64_alignment_is_found(self):
        secret = value().encode()
        for shift in range(3):
            stored = base64.b64encode(os.urandom(shift) + secret + os.urandom(2))
            (self.root / "blob").write_bytes(stored)
            found = self.findings([("token", secret.decode())])
            self.assertIn(("token", f"base64-{shift}/0"), found, shift)

    def test_a_base64_form_split_across_blocks_is_found_by_a_window(self):
        secret = value().encode()
        stored = base64.b64encode(secret)
        for cut in range(1, len(stored)):
            (self.root / "image").write_bytes(stored[:cut] + os.urandom(4096) + stored[cut:])
            found = self.findings([("token", secret.decode())])
            self.assertTrue(any(form.startswith("base64-0/") for _, form in found), cut)

    def test_hex_and_utf16_forms_are_found(self):
        # "j" to "o" are 0x6a-0x6f and "z" is 0x7a: each one's hex has a
        # letter, so the upper-case windows differ from the lower-case.
        secret = "cwhex" + "".join(secrets.choice("jklmnoz") for _ in range(64))
        (self.root / "hex").write_bytes(secret.encode().hex().upper().encode())
        (self.root / "wide").write_bytes(secret.encode("utf-16-le"))
        found = self.findings([("token", secret)])
        self.assertIn(("token", "hex-upper/0"), found)
        self.assertEqual(found[("token", "utf16le/0")][0], str(self.root / "wide"))

    def test_a_value_after_a_hole_in_a_sparse_file(self):
        secret = value()
        path = self.root / "sparse.raw"
        with open(path, "wb") as handle:
            handle.seek(64 * 1024 * 1024)
            handle.write(secret.encode())
        found = self.findings([("token", secret)])
        self.assertEqual(found[("token", "raw/0")], (str(path), 64 * 1024 * 1024 + len(secret) - 32))

    def test_a_value_across_a_read_chunk(self):
        secret = value()
        path = self.root / "big"
        with open(path, "wb") as handle:
            handle.write(b"z" * (4 * 1024 * 1024 - 10))
            handle.write(secret.encode())
        self.assertIn(("token", "raw/1"), self.findings([("token", secret)]))

    def test_files_and_directories_are_both_paths(self):
        secret = value()
        (self.root / "a").write_bytes(secret.encode())
        other = self.temporary / "single.log"
        other.write_bytes(secret.encode())
        found = self.scan([("token", secret)], self.root, other)
        self.assertEqual(found.returncode, 0)
        self.assertIn(str(other).encode(), found.stdout)
        self.assertIn(str(self.root / "a").encode(), found.stdout)

    def test_links_are_not_followed(self):
        secret = value()
        outside = self.temporary / "outside"
        outside.mkdir()
        (outside / "held").write_bytes(secret.encode())
        (self.root / "link").symlink_to(outside)
        self.assertEqual(self.findings([("token", secret)]), {})

    def test_refuses_values_it_cannot_search_soundly(self):
        for bad in ("short", "cw" + "a" * 60 + " space", "cw/" + secrets.token_hex(32)):
            result = self.scan([("token", bad)])
            self.assertEqual(result.returncode, 2, bad)
        secret = value()
        self.assertEqual(self.scan([("a", secret), ("a", value())]).returncode, 2)
        self.assertEqual(self.scan([]).returncode, 2)

    def test_refuses_a_relative_path_and_a_spill_inside_a_path(self):
        self.assertEqual(self.scan([("token", value())], "relative").returncode, 2)
        spill = self.root / "spill"
        spill.mkdir()
        result = self.scan([("token", value())], extra=("--debugfs", "/bin/false", "--spill", str(spill)))
        self.assertEqual(result.returncode, 2)

    @unittest.skipUnless(tool("mkfs.ext4") and tool("debugfs"), "needs mkfs.ext4 and debugfs")
    def test_a_file_inside_an_ext4_image_is_read_through_the_filesystem(self):
        secret = value()
        staging = self.temporary / "staging"
        (staging / "user").mkdir(parents=True)
        # Fill a block, so the value starts in one block and ends in the next.
        (staging / "user/credentials.json").write_bytes(b"{" + b" " * 4090 + secret.encode() + b"}")
        image = self.root / "state.raw"
        with open(image, "wb") as handle:
            handle.truncate(32 * 1024 * 1024)
        subprocess.run(
            [tool("mkfs.ext4"), "-q", "-F", "-d", str(staging), str(image)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        spill = self.temporary / "spill"
        spill.mkdir()
        found = self.findings([("token", secret)], extra=("--debugfs", tool("debugfs"), "--spill", str(spill)))
        self.assertEqual(found[("token", "raw/0")][0], f"{image}:/user/credentials.json")
        self.assertEqual(list(spill.iterdir()), [])

    @unittest.skipUnless(tool("mkfs.ext4") and tool("debugfs"), "needs mkfs.ext4 and debugfs")
    def test_a_read_only_directory_in_an_image_leaves_no_spill(self):
        secret = value()
        staging = self.temporary / "staging"
        (staging / "locked/inner").mkdir(parents=True)
        (staging / "locked/inner/file").write_bytes(secret.encode())
        (staging / "locked/inner").chmod(0o555)
        (staging / "locked").chmod(0o555)
        self.make_image(staging)
        # The image keeps the modes; the staging copy can be removed again.
        (staging / "locked").chmod(0o755)
        (staging / "locked/inner").chmod(0o755)
        spill = self.temporary / "spill"
        spill.mkdir()
        found = self.findings([("token", secret)], extra=("--debugfs", tool("debugfs"), "--spill", str(spill)))
        self.assertIn(("token", "raw/0"), found)
        self.assertEqual(list(spill.iterdir()), [])

    @unittest.skipUnless(tool("mkfs.ext4") and tool("debugfs"), "needs mkfs.ext4 and debugfs")
    def test_a_mode_000_directory_in_an_image_is_read_and_removed(self):
        # As an overlay's work directory is: the dump keeps the mode.
        secret = value()
        staging = self.temporary / "staging"
        (staging / "overlay/work").mkdir(parents=True)
        (staging / "overlay/work/held").write_bytes(secret.encode())
        image = self.make_image(staging)
        # mkfs.ext4 -d cannot read a mode-000 directory, so the modes are set
        # in the image afterwards.
        for path, mode in (("/overlay/work/held", "0100000"), ("/overlay/work", "040000")):
            subprocess.run([tool("debugfs"), "-w", "-R", f"set_inode_field {path} mode {mode}", str(image)],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        spill = self.temporary / "spill"
        spill.mkdir()
        found = self.findings([("token", secret)], extra=("--debugfs", tool("debugfs"), "--spill", str(spill)))
        self.assertEqual(found[("token", "raw/0")][0], f"{image}:/overlay/work/held")
        self.assertEqual(list(spill.iterdir()), [])

    def test_an_unreadable_directory_in_a_scanned_tree_fails_the_scan(self):
        # File modes cannot make a directory unreadable to root, and CI runs
        # as root, so the listing itself is made to fail: the real os.walk
        # meets the error the kernel gives a user without read permission.
        locked = self.root / "locked"
        locked.mkdir()
        (locked / "file").write_bytes(b"inside")
        module = load_scanner()
        real_scandir = os.scandir

        def scandir(path="."):
            if os.fspath(path) == str(locked):
                raise PermissionError(13, "Permission denied", str(locked))
            return real_scandir(path)

        with mock.patch.object(os, "scandir", scandir):
            with self.assertRaises(module.ScanError) as raised:
                list(module.regular_files(str(self.root)))
        self.assertIn(f"cannot read {locked}", str(raised.exception))

    @unittest.skipUnless(tool("mkfs.ext4") and tool("debugfs"), "needs mkfs.ext4 and debugfs")
    def test_a_link_inside_an_image_is_never_followed(self):
        secret = value()
        held = self.temporary / "held"
        held.mkdir()
        (held / "value").write_bytes(secret.encode())
        staging = self.temporary / "staging"
        staging.mkdir()
        (staging / "to-file").symlink_to(held / "value")
        (staging / "to-directory").symlink_to(held)
        image = self.make_image(staging)
        spill = self.temporary / "spill"
        spill.mkdir()
        scanned = self.temporary / "scanned"
        found = self.findings(
            [("token", secret)],
            image,
            extra=("--debugfs", tool("debugfs"), "--spill", str(spill), "--scanned", str(scanned)),
        )
        self.assertEqual(found, {})
        self.assertNotIn("value", scanned.read_text())

    @unittest.skipUnless(tool("mkfs.ext4") and tool("debugfs"), "needs mkfs.ext4 and debugfs")
    def test_the_scanned_list_names_every_file_read_with_its_size(self):
        staging = self.temporary / "staging"
        staging.mkdir()
        (staging / "inner.log").write_bytes(b"inner\n")
        image = self.make_image(staging)
        (self.root / "outer.log").write_bytes(b"outer line\n")
        (self.root / "empty.log").write_bytes(b"")
        spill = self.temporary / "spill"
        spill.mkdir()
        scanned = self.temporary / "scanned"
        self.findings(
            [("token", value())],
            extra=("--debugfs", tool("debugfs"), "--spill", str(spill), "--scanned", str(scanned)),
        )
        rows = dict(line.split("\t") for line in scanned.read_text().splitlines())
        self.assertEqual(rows[str(self.root / "outer.log")], "11")
        self.assertEqual(rows[str(self.root / "empty.log")], "0")
        self.assertEqual(rows[f"{image}:/inner.log"], "6")

    @unittest.skipUnless(tool("mkfs.ext4") and tool("debugfs"), "needs mkfs.ext4 and debugfs")
    def test_an_image_too_big_for_the_spill_is_refused_before_anything_is_dumped(self):
        staging = self.temporary / "staging"
        staging.mkdir()
        (staging / "file").write_bytes(b"x" * 4096)
        image = self.make_image(staging)
        spill = self.temporary / "spill"
        spill.mkdir()
        module = load_scanner()
        usage = shutil.disk_usage(spill)._replace(free=1024)
        with mock.patch.object(module.shutil, "disk_usage", return_value=usage):
            with self.assertRaises(module.ScanError):
                module.scan_ext4(str(image), [("token", "raw/0", b"x" * 16)], tool("debugfs"), str(spill), [])
        self.assertEqual(list(spill.iterdir()), [])

    def make_image(self, staging):
        image = self.root / "state.raw"
        with open(image, "wb") as handle:
            handle.truncate(32 * 1024 * 1024)
        subprocess.run(
            [tool("mkfs.ext4"), "-q", "-F", "-d", str(staging), str(image)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return image


SMOKE = ROOT / "scripts/ci/verify/smoke-native-local-environment.sh"
HARNESS = r"""
set -euo pipefail
SOURCE_ROOT="$1"; SMOKE_ROOT="$2"; CANARY_SPILL="$3"; CASE="$4"
log() { printf 'LOG %s\n' "$*" >&2; }
die() { printf 'DIE %s\n' "$*" >&2; exit 1; }
declare -A CANARY_VALUES=()
eval "$(sed -n '/^mint_canary() {/,/^}/p;/^scan_for_credential_canaries() {/,/^}/p;/^assert_boundary_control_split() {/,/^}/p' \
  "$SOURCE_ROOT/scripts/ci/verify/smoke-native-local-environment.sh")"
while IFS=$'\t' read -r name value; do CANARY_VALUES[$name]="$value"; done <"$SMOKE_ROOT/../values"
[[ "$CASE" != scanner-fails ]] || CANARY_SPILL="$SMOKE_ROOT/inside"
scan_for_credential_canaries before-delete openai-key \
  --raw control-home '/vms/[^/]+/disks/state[.]raw$' \
  --fs control-home '/vms/[^/]+/disks/state[.]raw' \
  --fs control-base64 '/vms/[^/]+/disks/state[.]raw' \
  --fs control-boundary '/vms/[^/]+/disks/state[.]raw' \
  --log '/logs/supervisor[.]log$'
echo SCANNED
assert_boundary_control_split
echo SPLIT
"""


@unittest.skipUnless(tool("mkfs.ext4") and tool("debugfs"), "needs mkfs.ext4 and debugfs")
class SmokeScan(unittest.TestCase):
    """The managed native smoke's scan function, run on a real ext4 state disk."""

    def run_case(self, case):
        temporary = Path(tempfile.mkdtemp(prefix="smoke-scan-"))
        self.addCleanup(shutil.rmtree, temporary)
        root = temporary / "root"
        spill = temporary / "spill"
        spill.mkdir()
        values = {name: value(prefix) for name, prefix in (
            ("openai-key", "cwlocalopenai"), ("control-home", "cwleakhome"),
            ("control-boundary", "cwleakboundary"), ("control-base64", "cwleakbase64"))}
        (temporary / "values").write_text("".join(f"{k}\t{v}\n" for k, v in values.items()))
        staging = temporary / "staging/user/.leak-scan"
        staging.mkdir(parents=True)
        if case != "missing-control":
            (staging / "home").write_text(values["control-home"])
        (staging / "boundary").write_text("x" * 4090 + values["control-boundary"])
        (staging / "encoded").write_bytes(base64.b64encode(values["control-base64"].encode()))
        if case == "leak":
            (staging / "stray").write_text(values["openai-key"])
        disks = root / "s/engine/vms/abc/disks"
        disks.mkdir(parents=True)
        with open(disks / "state.raw", "wb") as handle:
            handle.truncate(32 * 1024 * 1024)
        subprocess.run([tool("mkfs.ext4"), "-q", "-F", "-d", str(temporary / "staging"), str(disks / "state.raw")],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        logs = root / "s/logs"
        logs.mkdir(parents=True)
        if case != "missing-log":
            (logs / "supervisor.log").write_text("" if case == "empty-log" else "time_unix_ms=1 event=start\n")
        (root / "inside").mkdir()
        result = subprocess.run(["bash", "-c", HARNESS, "harness", str(ROOT), str(root), str(spill), case],
                                capture_output=True, text=True, check=False)
        for secret in values.values():
            self.assertNotIn(secret, result.stdout + result.stderr)
        return result

    def test_controls_found_and_logs_read_pass_the_scan(self):
        result = self.run_case("ok")
        self.assertIn("SCANNED", result.stdout, result.stderr)
        # mkfs.ext4 -d lays a file out in adjacent blocks, so the split
        # check must refuse it rather than claim the window path was proven.
        self.assertIn("DIE the boundary control was stored in adjacent blocks", result.stderr)

    def test_a_missing_control_fails(self):
        result = self.run_case("missing-control")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("DIE before-delete: control control-home was not found", result.stderr)

    def test_a_leaked_value_fails_and_names_where(self):
        result = self.run_case("leak")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("LOG before-delete: synthetic openai-key found as raw/0 in s/engine/vms/abc/disks/state.raw",
                      result.stderr)
        self.assertIn("DIE before-delete: a synthetic credential value entered durable smoke state", result.stderr)

    def test_a_missing_or_empty_log_fails(self):
        for case in ("missing-log", "empty-log"):
            result = self.run_case(case)
            self.assertNotEqual(result.returncode, 0, case)
            self.assertIn("no non-empty log matching", result.stderr, case)

    def test_a_scanner_failure_fails(self):
        result = self.run_case("scanner-fails")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("DIE before-delete: the canary scan failed", result.stderr)

if __name__ == "__main__":
    unittest.main()
