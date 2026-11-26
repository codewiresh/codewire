#!/usr/bin/env python3
"""The shape scanner finds a value in each provider's shape in every form it
reads, passes placeholders, reports controls by name, and never prints a
value (docs/journeys/network-and-egress.md, `no-token-at-rest`; #6194).

Every value is random and made at run time; the prefixes are built from
parts, so no committed literal reads as a credential."""

import base64
import gzip
import hashlib
import importlib.util
import json
import lzma
import os
from pathlib import Path
import secrets
import select
import shutil
import string
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
SCANNER = ROOT / "scripts/ci/verify/scan-token-shapes.py"
ALNUM = string.ascii_letters + string.digits
PAGE = 4096


def random(count, alphabet=ALNUM + "_-"):
    return "".join(secrets.choice(alphabet) for _ in range(count))


def anthropic(kind="api03", body=None):
    return "-".join(["sk", "ant", kind, body or random(93)])


def github(kind="p"):
    return "gh" + kind + "_" + random(36, ALNUM)


def placeholder():
    return "cwp1_" + random(43)


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def jwt(header, payload, signature=None):
    third = b64url(os.urandom(64)) if signature is None else signature
    return ".".join([b64url(json.dumps(header).encode()), b64url(json.dumps(payload).encode()), third])


def load_scanner():
    spec = importlib.util.spec_from_file_location("scan_token_shapes", SCANNER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def tool(name):
    return shutil.which(name, path="/usr/sbin:/usr/bin:/sbin:/bin")


class Scanner(unittest.TestCase):
    def setUp(self):
        self.temporary = Path(tempfile.mkdtemp(prefix="scan-token-shapes-"))
        self.root = self.temporary / "root"
        self.root.mkdir()
        self.secrets = []

    def tearDown(self):
        shutil.rmtree(self.temporary)

    def write(self, name, data):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data if isinstance(data, bytes) else data.encode())
        return path

    def secret(self, value):
        self.secrets.append(value)
        return value

    def scan(self, *paths, controls=(), extra=()):
        stdin = "".join(f"{name}\t{value}\n" for name, value in controls).encode()
        result = subprocess.run(
            [sys.executable, "-I", str(SCANNER), *extra, *[str(path) for path in (paths or [self.root])]],
            input=stdin,
            capture_output=True,
            check=False,
            timeout=300,
        )
        output = result.stdout + result.stderr
        for value in self.secrets + [value for _, value in controls]:
            self.assertNotIn(value.encode(), output)
            # Not even the part a prefix leaves.
            self.assertNotIn(value[-24:].encode(), output)
        lines = [line.split("\t") for line in result.stdout.decode().splitlines()]
        return result.returncode, lines, result.stderr.decode()

    def findings(self, lines):
        return [line for line in lines if line[0] not in ("placeholder", "missing", "baseline", "baseline-image")]

    def test_every_shape_is_a_finding_and_no_value_is_printed(self):
        values = {
            "anthropic": anthropic(),
            "openai": "-".join(["sk", "proj", random(120)]),
            "openai-legacy": "sk-" + random(20, ALNUM) + "T3Blbk" + "FJ" + random(20, ALNUM),
            "github": github("o"),
            "github-pat": "github" + "_pat_" + random(82, ALNUM + "_"),
            "google-api-key": "AI" + "za" + random(35),
            "google-oauth": "ya" + "29." + random(60),
            "gitlab": "gl" + "pat-" + random(20),
            "slack": "xo" + "xb-" + random(40, ALNUM + "-"),
            "aws-access-key-id": "AK" + "IA" + random(16, string.ascii_uppercase + string.digits),
            "stripe": "sk" + "_live_" + random(30, ALNUM),
            "huggingface": "hf" + "_" + random(34, string.ascii_letters),
        }
        for shape, value in values.items():
            self.write(f"{shape}.txt", f"value: {self.secret(value)}\n")
        status, lines, _ = self.scan()
        self.assertEqual(status, 1)
        found = {(line[0], Path(line[2]).name, line[3], line[4]) for line in self.findings(lines)}
        self.assertEqual(found, {(shape, f"{shape}.txt", "7", str(len(value))) for shape, value in values.items()})

    def test_placeholders_pass_and_are_counted(self):
        self.write("env", f"ANTHROPIC_API_KEY={anthropic('api03', placeholder())}\nTOKEN={placeholder()}\n")
        self.write("login.json", json.dumps({"accessToken": anthropic("oat01", placeholder())}))
        status, lines, _ = self.scan()
        self.assertEqual(status, 0)
        self.assertEqual(sorted(lines), [["placeholder", "anthropic", "2"], ["placeholder", "cwp1", "1"]])

    def test_a_placeholder_with_more_after_it_is_not_one(self):
        self.write("env", anthropic("api03", placeholder() + "extra"))
        status, lines, _ = self.scan()
        self.assertEqual((status, [line[0] for line in lines]), (1, ["anthropic"]))

    def test_a_control_is_reported_by_name_and_a_missing_one_fails(self):
        control = github()
        self.write("home/notes", f"x {control} y")
        status, lines, _ = self.scan(controls=[("planted", control)])
        self.assertEqual(status, 0)
        self.assertEqual([line[0] for line in lines], ["control:planted"])
        status, lines, _ = self.scan(controls=[("planted", control), ("elsewhere", github())])
        self.assertEqual(status, 1)
        self.assertIn(["missing", "control:elsewhere"], lines)

    def test_utf16_and_json_escaped_forms(self):
        self.write("wide", ("token=" + self.secret(anthropic())).encode("utf-16-le"))
        escaped = self.secret(anthropic()).replace("-", "\\u002d")
        self.write("escaped.json", '{"k": "' + escaped + '"}')
        status, lines, _ = self.scan()
        self.assertEqual(status, 1)
        self.assertEqual(sorted(line[1] for line in self.findings(lines)), ["json-escaped", "utf16le"])

    def test_base64_at_every_alignment_in_both_alphabets_and_wrapped(self):
        for shift in range(3):
            leaked = self.secret(anthropic())
            blob = os.urandom(shift) + leaked.encode() + os.urandom(5)
            self.write(f"std-{shift}", base64.b64encode(blob))
            self.write(f"url-{shift}", base64.urlsafe_b64encode(blob))
        wrapped = base64.encodebytes(b"header:" + self.secret(anthropic()).encode())
        self.write("mime", wrapped)
        status, lines, _ = self.scan()
        self.assertEqual(status, 1)
        found = {Path(line[2]).name for line in self.findings(lines) if line[1].startswith("base64/")}
        self.assertEqual(found, {"std-0", "std-1", "std-2", "url-0", "url-1", "url-2", "mime"})

    def test_a_value_inside_base64_inside_utf16(self):
        encoded = base64.b64encode(self.secret(anthropic()).encode()).decode()
        self.write("wide64", encoded.encode("utf-16-le"))
        status, lines, _ = self.scan()
        self.assertEqual(status, 1)
        self.assertTrue(any(line[0] == "anthropic" for line in self.findings(lines)))

    def test_compressed_logs_are_read_decompressed(self):
        line = f"token {self.secret(anthropic())}\n".encode()
        self.write("app.log.1.gz", gzip.compress(line))
        self.write("app.log.2.xz", lzma.compress(line))
        if tool("zstd"):
            self.write("app.log.3.zst", subprocess.run(["zstd", "-q", "-c"], input=line, capture_output=True, check=True, timeout=60).stdout)
        status, lines, _ = self.scan()
        self.assertEqual(status, 1)
        # A short log can keep the value as a literal in the compressed
        # bytes too, which the raw read reports as well.
        found = {Path(line[2]).name for line in self.findings(lines)}
        expected = {"app.log.1.gz!decompressed", "app.log.2.xz!decompressed"}
        if tool("zstd"):
            expected.add("app.log.3.zst!decompressed")
        self.assertLessEqual(expected, found)

    def test_a_compressed_file_it_cannot_read_fails_the_scan_without_bytes(self):
        leaked = self.secret(anthropic())
        self.write("broken.gz", b"\x1f\x8b\x08\x00" + leaked.encode())
        status, _, error = self.scan()
        self.assertEqual(status, 2)
        self.assertIn("broken.gz", error)
        self.assertNotIn("Traceback", error)

    def test_jwts(self):
        provider = jwt({"alg": "RS256"}, {"iss": "https://auth.openai.com", "sub": "a"})
        google = jwt({"alg": "RS256"}, {"iss": "https://accounts.google.com", "sub": "g"})
        other = jwt({"alg": "ES256"}, {"iss": "https://issuer.example", "sub": "b"})
        no_issuer = jwt({"alg": "RS256"}, {"sub": "c"})
        unsigned = jwt({"alg": "none", "typ": "JWT"}, {"email": "a@example.com"}, "codewire-placeholder")
        empty = jwt({"alg": "none"}, {"email": "a@example.com"}, "")
        none_signed = jwt({"alg": "none"}, {"email": "a@example.com"}, b64url(os.urandom(32)))
        for name, token in [("provider", provider), ("google", google), ("other", other), ("no-issuer", no_issuer),
                            ("unsigned", unsigned), ("empty", empty), ("none-signed", none_signed)]:
            self.write(name, f"jwt={self.secret(token)}\n")
        self.write("garbled", "jwt=eyJ" + random(30) + "." + random(30) + "." + random(40) + "\n")
        status, lines, _ = self.scan()
        self.assertEqual(status, 1)
        found = {(Path(line[2]).name, line[0]) for line in self.findings(lines) if line[1] == "raw"}
        self.assertEqual(
            found,
            {
                ("provider", "jwt-openai"),
                ("google", "jwt-google"),
                ("no-issuer", "jwt-unreadable"),
                ("none-signed", "jwt-unsigned-signature"),
                ("garbled", "jwt-unreadable"),
            },
        )

    def test_refresh_token_fields_of_no_fixed_shape(self):
        value = self.secret("rt_" + random(40))
        self.write("auth.json", json.dumps({"tokens": {"refresh_token": value}}))
        self.write("config.toml", f'refresh_token = "{self.secret("rt_" + random(40))}"\n')
        self.write("env", f"OPENAI_REFRESH_TOKEN={self.secret(random(48))}\n")
        self.write("hosts.yml", f"github.com:\n  refresh_token: {self.secret(random(48))}\n")
        inner = json.dumps({"refresh_token": self.secret("rt_" + random(40))})
        self.write("app.log", json.dumps({"msg": inner}) + "\n")
        self.write("placeholders.json", json.dumps({"a": {"refresh_token": "codewire-managed-no-refresh-token"},
                                                    "b": {"refresh_token": "codewire-managed-no-refresh-token-" + random(16)},
                                                    "c": {"refresh_token": ""}, "d": {"refresh_token": None}}))
        self.write("client.py", "refresh_token = self._token_data.get('refresh_token')\n"
                                "refresh_token = credentials.refresh_token_value\n")
        status, lines, _ = self.scan()
        self.assertEqual(status, 1)
        found = {(Path(line[2]).name, line[1]) for line in self.findings(lines)}
        self.assertLessEqual(
            {("auth.json", "raw"), ("config.toml", "raw"), ("env", "raw"), ("hosts.yml", "raw"),
             ("app.log", "json-escaped")},
            found,
        )
        self.assertNotIn("placeholders.json", {name for name, _form in found})
        self.assertNotIn("client.py", {name for name, _form in found})
        self.assertTrue(all(line[0] == "refresh-token-field" for line in self.findings(lines)))

    IMAGE = "sha256:" + "ab" * 32

    def baseline_file(self, *lines, image=None):
        path = self.temporary / f"baseline-{secrets.token_hex(4)}"
        header = load_scanner().baseline_header(image or self.IMAGE)
        path.write_text("".join(f"{line}\n" for line in (header, *lines)))
        return path

    def blob(self, directory, data):
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / hashlib.sha256(data).hexdigest()
        path.write_bytes(data)
        return path

    def test_a_blob_named_by_its_sha256_is_image_content_and_a_renamed_one_is_not(self):
        blobs = self.root / "blobs"
        shipped = self.secret(github())
        blob = self.blob(blobs, gzip.compress(f"testdata {shipped}\n".encode()))
        baseline = self.temporary / "baseline"
        image = ["--image", self.IMAGE, "--image-blobs", str(blobs)]
        status, lines, _ = self.scan(extra=["--write-baseline", str(baseline), *image])
        self.assertEqual(status, 1)
        status, lines, _ = self.scan(extra=["--baseline", str(baseline), *image])
        self.assertEqual(status, 0, lines)
        self.assertIn(["baseline-image", "github", str(blob), "1"], lines)
        leaked = self.secret(anthropic())
        self.write("state/home/notes", leaked)
        status, lines, _ = self.scan(extra=["--baseline", str(baseline), *image])
        self.assertEqual([line[0] for line in self.findings(lines)], ["anthropic"])
        # A blob whose bytes no longer match its name is not image content.
        blob.write_bytes(gzip.compress(f"testdata {shipped}\nmore\n".encode()))
        status, lines, _ = self.scan(extra=["--baseline", str(baseline), *image])
        self.assertEqual(status, 1)
        self.assertIn("github", [line[0] for line in self.findings(lines)])

    @unittest.skipUnless(tool("mkfs.ext4") and tool("debugfs") and os.path.isdir("/dev/shm"), "needs mkfs.ext4, debugfs and /dev/shm")
    def test_a_root_disk_excuses_its_lower_layer_raw_and_through_the_filesystem_never_its_upper(self):
        source = self.temporary / "source"
        for directory in ("lower/usr/bin", "upper/etc", "work", "merged"):
            (source / directory).mkdir(parents=True)
        shipped_key = "glpat-" + random(24)
        shipped_token = github()
        (source / "lower/usr/bin/tool").write_bytes(
            os.urandom(9000) + f" {self.secret(shipped_key)} {self.secret(shipped_token)} ".encode() + os.urandom(9000)
        )
        (source / "upper/etc/config").write_text(f"key {self.secret('glpat-' + random(24))}\n")
        disk = self.root / "root.raw"
        subprocess.run([tool("mkfs.ext4"), "-q", "-F", "-d", str(source), str(disk), "16M"], check=True, timeout=120)
        spill_parent = Path(tempfile.mkdtemp(prefix="scan-token-shapes-test-", dir="/dev/shm"))
        baseline = self.temporary / "baseline"
        image = ["--image", self.IMAGE, "--image-disk", f"{disk}:/lower", "--debugfs", tool("debugfs"),
                 "--spill-parent", str(spill_parent)]
        try:
            status, before, _ = self.scan(extra=["--write-baseline", str(baseline), *image])
            status, lines, _ = self.scan(extra=["--baseline", str(baseline), *image])
        finally:
            shutil.rmtree(spill_parent)
        self.assertEqual(status, 1)
        left = {(line[0], line[2]) for line in self.findings(lines)}
        self.assertEqual(left, {("gitlab", f"{disk}:/upper/etc/config"), ("gitlab", str(disk))})
        self.assertIn(["baseline-image", "github", f"{disk}:/lower/usr/bin/tool", "2"], lines)
        self.assertIn(["baseline", "gitlab", "2"], lines)
        recorded = baseline.read_text()
        self.assertRegex(recorded, r"sha256\text4-uuid:[0-9a-f-]{36}:/lower/usr/bin/tool\t[0-9a-f]{64}")
        self.assertNotIn("/upper/", recorded)

    @unittest.skipUnless(tool("mkfs.ext4") and tool("debugfs") and os.path.isdir("/dev/shm"), "needs mkfs.ext4, debugfs and /dev/shm")
    def test_a_declared_copy_of_the_root_disk_matches_its_baseline_and_an_undeclared_one_does_not(self):
        source = self.temporary / "source"
        (source / "lower/usr/bin").mkdir(parents=True)
        (source / "upper").mkdir()
        (source / "lower/usr/bin/tool").write_bytes(
            os.urandom(9000) + f" {self.secret(github())} {self.secret('glpat-' + random(24))} ".encode()
        )
        disk = self.root / "vm/root.raw"
        disk.parent.mkdir()
        subprocess.run([tool("mkfs.ext4"), "-q", "-F", "-d", str(source), str(disk), "16M"], check=True, timeout=120)
        copy = self.root / "checkpoint/root.raw"
        copy.parent.mkdir()
        shutil.copyfile(disk, copy)
        spill_parent = Path(tempfile.mkdtemp(prefix="scan-token-shapes-test-", dir="/dev/shm"))
        baseline = self.temporary / "baseline"
        common = ["--image", self.IMAGE, "--debugfs", tool("debugfs"), "--spill-parent", str(spill_parent)]
        try:
            status, _, _ = self.scan(disk, extra=["--write-baseline", str(baseline), "--image-disk", f"{disk}:/lower", *common])
            self.assertEqual(status, 1)
            self.assertNotIn(str(disk), baseline.read_text(), "the baseline names the disk by its UUID")
            self.assertIn("ext4-uuid:", baseline.read_text())
            declared = ["--baseline", str(baseline), "--image-disk", f"{disk}:/lower", "--image-disk", f"{copy}:/lower", *common]
            status, lines, _ = self.scan(disk, copy, extra=declared)
            self.assertEqual((status, self.findings(lines)), (0, []))
            self.assertIn(["baseline-image", "github", f"{copy}:/lower/usr/bin/tool", "2"], lines)
            undeclared = ["--baseline", str(baseline), "--image-disk", f"{disk}:/lower", *common]
            status, lines, _ = self.scan(disk, copy, extra=undeclared)
            self.assertEqual(status, 1)
            self.assertEqual({line[2].split(":/")[0] for line in self.findings(lines)}, {str(copy)})
        finally:
            shutil.rmtree(spill_parent)

    def test_excusal_follows_image_content_and_a_bound_shape_its_files_sha256(self):
        scanner = load_scanner()
        disk, blobs = "/vm/root.raw", "/engine/content/blobs"
        name = "ab" * 32
        content = scanner.ImageContent({disk: "/lower"}, frozenset({blobs}))
        content.raw_files[("gitlab", "raw", disk, 4096, 30)] = f"{disk}:/lower/usr/bin/gh"
        content.raw_files[("gitlab", "raw", disk, 8192, 30)] = None
        content.file_digests.update({f"{disk}:/lower/usr/bin/gh": "11" * 32, f"{blobs}/{name}": name})
        places = {
            (f"{disk}:/lower/usr/bin/gh", 10): True,
            (f"{disk}:/lower/usr/share/doc/x.gz!decompressed", 10): True,
            (disk, 4096): True,
            (disk, 8192): False,
            (disk, 12288): False,
            (f"{disk}:/upper/etc/config", 10): False,
            (f"{disk}:/work/x", 10): False,
            (f"{blobs}/{name}", 10): True,
            (f"{blobs}/{name}!decompressed", 10): True,
            (f"{blobs}/not-a-digest", 10): False,
            ("/vm/state.raw", 10): False,
            ("/vm/state.raw:/codewire/notes", 10): False,
            ("/vm/checkpoint/memory-ranges", 10): False,
            ("/proc/1/environ", 0): False,
            ("/dev/fd/63", 0): False,
            ("/vm/supervisor.log.1.gz!decompressed", 0): False,
        }
        findings = {("gitlab", "raw", path, offset, 30) for path, offset in places}
        results = scanner.Results({}, scanner.Baseline(frozenset(findings)), content)
        for (path, offset), excused in places.items():
            self.assertEqual(results.excusal(("gitlab", "raw", path, offset, 30)) is not None, excused, path)
        self.assertIsNone(results.excusal(("gitlab", "raw", disk, 4097, 30)), "another offset")
        for bound in (
            ("github", "raw", f"{disk}:/lower/usr/bin/gh", 10, 40),
            ("google-api-key", "raw", f"{disk}:/lower/usr/bin/gh", 10, 39),
        ):
            pinned = scanner.Results({}, scanner.Baseline(frozenset({bound}), {f"{disk}:/lower/usr/bin/gh": "11" * 32}), content)
            self.assertEqual(pinned.excusal(bound), (f"{disk}:/lower/usr/bin/gh", True))
            changed = scanner.Results({}, scanner.Baseline(frozenset({bound}), {f"{disk}:/lower/usr/bin/gh": "22" * 32}), content)
            self.assertIsNone(changed.excusal(bound), "a rewritten image file")
            unpinned = scanner.Results({}, scanner.Baseline(frozenset({bound})), content)
            self.assertIsNone(unpinned.excusal(bound), "no recorded SHA-256")

    def test_a_raw_finding_maps_only_when_every_block_is_one_image_file_named_plainly(self):
        scanner = load_scanner()
        disk = "/vm/root.raw"
        target = self.temporary / "dump"
        for name in ("lower/usr/bin/gh", "lower/usr/bin/other", "upper/etc/x"):
            (target / name).parent.mkdir(parents=True, exist_ok=True)
            (target / name).write_bytes(name.encode())
        (target / "lower/linked").symlink_to(target / "upper/etc")
        owners = {1: 11, 2: 11, 3: 22, 4: 33, 5: 44, 6: 55, 7: None, 8: 66, 9: 77}
        names = {
            11: ["/lower/usr/bin/gh"],
            22: ["/lower/usr/bin/other"],
            33: ["/upper/etc/x"],
            44: ["/lower/usr/bin/gh\n12\t/lower/usr/bin/other"],
            55: ["/lower/usr/bin/missing"],
            66: ["/lower/../upper/etc/x"],
            77: ["/lower/linked/x"],
        }
        digests = {11: scanner.sha256_file(target / "lower/usr/bin/gh"), 22: "ff" * 32, 33: "00" * 32,
                   44: "01" * 32, 55: "02" * 32, 66: "03" * 32, 77: "04" * 32}
        cases = {
            ("github", "raw", disk, 4096, 40): ((4096, 8192 + 40), f"{disk}:/lower/usr/bin/gh"),
            ("github", "raw", disk, 8192 + 100, 40): ((8192 + 100, 8192 + 140), f"{disk}:/lower/usr/bin/gh"),
            # UTF-16LE takes two bytes a character, so this one runs into block 3.
            ("github", "utf16le", disk, 8192 + 4050, 40): ((8192 + 4050, 8192 + 4130), None),
            ("github", "raw", disk, 16384, 40): ((16384, 16424), None),
            ("github", "raw", disk, 20480, 40): ((20480, 20520), None),
            ("github", "raw", disk, 24576, 40): ((24576, 24616), None),
            ("github", "raw", disk, 28672, 40): ((28672, 28712), None),
            ("github", "raw", disk, 32768, 40): ((32768, 32808), None),
            ("github", "raw", disk, 36864, 40): ((36864, 36904), None),
        }
        results = scanner.Results({}, None, scanner.ImageContent({disk: "/lower"}))
        results.image.file_digests[f"{disk}:/lower/usr/bin/other"] = "aa" * 32
        for finding, (span, _label) in cases.items():
            results.findings.add(finding)
            results.spans[finding] = span
        with mock.patch.object(scanner, "block_size_of", return_value=4096), \
                mock.patch.object(scanner, "icheck", side_effect=lambda _d, _i, blocks: {b: owners.get(b) for b in blocks}), \
                mock.patch.object(scanner, "ncheck", side_effect=lambda _d, _i, inodes: {i: names[i] for i in inodes if i in names}), \
                mock.patch.object(scanner, "inode_digest", side_effect=lambda _d, _i, inode, _s: digests[inode]):
            scanner.map_image_files(disk, "/lower", "debugfs", str(target), results)
        for finding, (_span, label) in cases.items():
            self.assertEqual(results.image.raw_files[finding], label, finding)

    @unittest.skipUnless(tool("mkfs.ext4") and tool("debugfs") and os.path.isdir("/dev/shm"), "needs mkfs.ext4, debugfs and /dev/shm")
    def test_a_file_named_with_a_newline_is_never_image_content(self):
        source = self.temporary / "source"
        (source / "lower/usr/bin").mkdir(parents=True)
        (source / "lower/usr/bin/gh").write_bytes(os.urandom(5000))
        forged = source / "lower/usr/bin" / "x\n12\tgh"
        forged.write_bytes(os.urandom(5000) + f" {self.secret(github())} ".encode())
        disk = self.root / "root.raw"
        subprocess.run([tool("mkfs.ext4"), "-q", "-F", "-d", str(source), str(disk), "16M"], check=True, timeout=120)
        spill_parent = Path(tempfile.mkdtemp(prefix="scan-token-shapes-test-", dir="/dev/shm"))
        baseline = self.temporary / "baseline"
        image = ["--image", self.IMAGE, "--image-disk", f"{disk}:/lower", "--debugfs", tool("debugfs"),
                 "--spill-parent", str(spill_parent)]
        try:
            self.scan(extra=["--write-baseline", str(baseline), *image])
            status, lines, _ = self.scan(extra=["--baseline", str(baseline), *image])
        finally:
            shutil.rmtree(spill_parent)
        self.assertEqual(status, 1)
        self.assertEqual({line[0] for line in self.findings(lines)}, {"github"})
        self.assertTrue(any(line[2] == str(disk) for line in self.findings(lines)), "raw")
        self.assertTrue(any("\\x0a" in line[2] for line in self.findings(lines)), "the name is escaped")
        self.assertTrue(all(len(line) == 5 for line in self.findings(lines)))
        self.assertNotIn("github", baseline.read_text())

    def test_a_baseline_listing_a_control_or_a_finding_outside_image_content_is_refused(self):
        disk = self.write("root.raw", "nothing")
        image = ["--image", self.IMAGE, "--image-disk", f"{disk}:/lower"]
        for line in (f"control:planted\traw\t{disk}:/lower/x\t0\t40",
                     f"google-api-key\traw\t{disk}:/upper/x\t0\t39",
                     f"google-api-key\traw\t{self.root}/state.raw\t0\t39",
                     f"google-api-key\traw\t/proc/1/environ\t0\t39"):
            status, _, error = self.scan(extra=["--baseline", str(self.baseline_file(line)), *image])
            self.assertEqual(status, 2, line)
            self.assertIn("never excuses", error)
        fine = self.baseline_file(f"github\traw\t{disk}:/lower/x\t0\t40", f"sha256\t{disk}:/lower/x\t{'0' * 64}")
        status, _, _ = self.scan(extra=["--baseline", str(fine), *image])
        self.assertEqual(status, 0)

    def test_a_baseline_of_another_image_or_scanner_is_refused(self):
        self.write("root.raw", "nothing")
        other_image = self.baseline_file(image="sha256:" + "cd" * 32)
        status, _, error = self.scan(extra=["--baseline", str(other_image), "--image", self.IMAGE])
        self.assertEqual(status, 2)
        self.assertIn("not a baseline of this image by this scanner", error)
        other_scanner = self.temporary / "other-scanner"
        other_scanner.write_text(f"# scan-token-shapes baseline\timage={self.IMAGE}\tscanner={'0' * 64}\n")
        status, _, _ = self.scan(extra=["--baseline", str(other_scanner), "--image", self.IMAGE])
        self.assertEqual(status, 2)
        status, _, _ = self.scan(extra=["--baseline", str(self.baseline_file())])
        self.assertEqual(status, 2, "--baseline needs --image")

    def test_a_value_cut_at_a_page_end(self):
        leaked = self.secret(anthropic())
        cut = leaked[: len("sk-ant-api03-") + 20].encode()
        image = bytearray(os.urandom(3 * PAGE).replace(b"-", b"!"))
        image[PAGE - len(cut):PAGE] = cut
        image[PAGE] = 0
        cut_placeholder = anthropic("oat01", placeholder())[:len("sk-ant-oat01-") + 20].encode()
        image[2 * PAGE - len(cut_placeholder):2 * PAGE] = cut_placeholder
        image[2 * PAGE] = 0
        self.write("memory-ranges", bytes(image))
        wide = bytearray(2 * PAGE)
        wide_cut = cut.decode().encode("utf-16-le")
        wide[PAGE - len(wide_cut):PAGE] = wide_cut
        self.write("wide-ranges", bytes(wide))
        status, lines, _ = self.scan()
        self.assertEqual(status, 1)
        found = {(Path(line[2]).name, line[0], line[1]) for line in self.findings(lines)}
        self.assertIn(("memory-ranges", "cut:anthropic", "raw"), found)
        self.assertIn(("wide-ranges", "cut:anthropic", "utf16le"), found)
        self.assertIn(["placeholder", "anthropic", "1"], lines)

    def test_a_value_across_a_read_chunk(self):
        chunk = load_scanner().CHUNK
        leaked = self.secret(anthropic())
        self.write("big", b"a " * ((chunk - 30) // 2) + b" " + leaked.encode() + b" tail")
        status, lines, _ = self.scan()
        self.assertEqual(status, 1)
        self.assertEqual([line[0] for line in self.findings(lines)], ["anthropic"])

    def test_a_value_after_a_hole_in_a_sparse_file(self):
        path = self.root / "sparse"
        with open(path, "wb") as handle:
            handle.seek(64 * 1024 * 1024)
            handle.write(b" " + self.secret(anthropic()).encode() + b"\n")
        status, lines, _ = self.scan()
        self.assertEqual(status, 1)
        self.assertEqual(self.findings(lines)[0][3], str(64 * 1024 * 1024 + 1))

    def test_a_stream_is_read(self):
        leaked = self.secret(anthropic())
        read, write = os.pipe()
        os.write(write, f"log {leaked}\n".encode())
        os.close(write)
        try:
            result = subprocess.run(
                [sys.executable, "-I", str(SCANNER), f"/dev/fd/{read}"],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                pass_fds=(read,),
                check=False,
                timeout=120,
            )
        finally:
            os.close(read)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(leaked[-24:].encode(), result.stdout + result.stderr)
        self.assertEqual(result.stdout.decode().split("\t")[0], "anthropic")

    def test_links_are_not_followed(self):
        outside = self.temporary / "outside"
        outside.write_text(self.secret(anthropic()))
        (self.root / "link").symlink_to(outside)
        status, lines, _ = self.scan()
        self.assertEqual((status, lines), (0, []))

    def test_refusals(self):
        status, _, error = self.scan(Path("relative"))
        self.assertEqual(status, 2)
        self.assertIn("not an absolute path", error)
        status, _, error = self.scan(controls=[("short", "abc")])
        self.assertEqual(status, 2)
        status, _, error = self.scan(controls=[("placeholder", placeholder())])
        self.assertEqual(status, 2)
        persistent = self.temporary / "spill"
        persistent.mkdir()
        if not load_scanner().on_tmpfs(str(persistent)):
            status, _, error = self.scan(extra=["--debugfs", "/bin/true", "--spill-parent", str(persistent)])
            self.assertEqual(status, 2)
            self.assertIn("tmpfs", error)

    def test_an_unreadable_directory_fails_the_scan(self):
        scanner = load_scanner()
        hidden = self.root / "hidden"
        hidden.mkdir()
        real_scandir = os.scandir

        def scandir(path="."):
            if os.fspath(path) == str(hidden):
                raise PermissionError(13, "Permission denied", str(hidden))
            return real_scandir(path)

        with mock.patch("os.scandir", scandir):
            with self.assertRaisesRegex(scanner.ScanError, "cannot read"):
                list(scanner.regular_files(str(self.root), set()))

    def test_processes_environments_are_read_and_an_unreadable_one_fails(self):
        scanner = load_scanner()
        control = github()
        # The child says it is running before it is scanned: until its exec
        # completes, /proc/PID/environ still holds this process's environment.
        child = subprocess.Popen(
            [sys.executable, "-c", "import sys; print(flush=True); sys.stdin.read()"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            env={"PLANTED": control},
        )
        try:
            ready, _, _ = select.select([child.stdout], [], [], 30)
            self.assertEqual(ready, [child.stdout], "the child never said it was running")
            self.assertEqual(child.stdout.readline(), b"\n")
            results = scanner.Results({control.encode(): "environment"})
            with mock.patch.object(scanner.os, "listdir", return_value=[str(child.pid)]):
                scanner.scan_processes(results, [])
            self.assertEqual(results.found_controls, {"environment"})
            with mock.patch.object(scanner.os, "listdir", return_value=[str(child.pid)]), \
                    mock.patch.object(scanner.os, "open", side_effect=PermissionError(13, "denied")):
                with self.assertRaisesRegex(scanner.ScanError, "run the scan as root"):
                    scanner.scan_processes(scanner.Results({}), [])
        finally:
            child.stdin.close()
            child.stdout.close()
            child.wait(timeout=30)

    def test_the_scanned_list_names_every_file_read(self):
        self.write("a", "nothing")
        self.write("b.gz", gzip.compress(b"nothing"))
        listing = self.temporary / "scanned"
        status, _, _ = self.scan(extra=["--scanned", str(listing)])
        self.assertEqual(status, 0)
        names = [Path(line.split("\t")[0]).name for line in listing.read_text().splitlines()]
        self.assertEqual(names, ["a", "b.gz", "b.gz!decompressed"])

    @unittest.skipUnless(tool("mkfs.ext4") and tool("debugfs") and os.path.isdir("/dev/shm"), "needs mkfs.ext4, debugfs and /dev/shm")
    def test_a_file_inside_an_ext4_image_is_read_through_the_filesystem_and_the_spill_removed(self):
        source = self.temporary / "source"
        source.mkdir()
        (source / "home" / "codewire").mkdir(parents=True)
        (source / "home" / "codewire" / "login.json").write_text(json.dumps({"accessToken": self.secret(anthropic("oat01"))}))
        image = self.root / "state.raw"
        subprocess.run([tool("mkfs.ext4"), "-q", "-F", "-d", str(source), str(image), "8M"], check=True, timeout=120)
        spill_parent = Path(tempfile.mkdtemp(prefix="scan-token-shapes-test-", dir="/dev/shm"))
        try:
            status, lines, _ = self.scan(extra=["--debugfs", tool("debugfs"), "--spill-parent", str(spill_parent)])
            self.assertEqual(list(spill_parent.iterdir()), [])
        finally:
            shutil.rmtree(spill_parent)
        self.assertEqual(status, 1)
        self.assertIn(f"{image}:/home/codewire/login.json", {line[2] for line in self.findings(lines)})


if __name__ == "__main__":
    unittest.main()
