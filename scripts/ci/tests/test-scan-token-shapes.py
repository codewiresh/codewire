#!/usr/bin/env python3
"""The shape scanner finds a value in each provider's shape in every form it
reads, passes placeholders, reports controls by name, and never prints a
value (docs/journeys/network-and-egress.md, `no-token-at-rest`; #6194).

Every value is random and made at run time; the prefixes are built from
parts, so no committed literal reads as a credential."""

import base64
import gzip
import importlib.util
import json
import lzma
import os
from pathlib import Path
import secrets
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
        return [line for line in lines if line[0] not in ("placeholder", "missing", "baseline")]

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

    def test_a_baseline_excuses_the_same_finding_in_a_declared_image_disk_only(self):
        disk = self.write("rootfs.raw", f"KEY = '{self.secret('AI' + 'za' + random(35))}'\n")
        baseline = self.temporary / "baseline"
        image = ["--image", self.IMAGE, "--image-disk", str(disk)]
        status, lines, _ = self.scan(extra=["--write-baseline", str(baseline), *image])
        self.assertEqual(status, 1)
        self.assertEqual(baseline.read_text().splitlines()[0], load_scanner().baseline_header(self.IMAGE))
        status, lines, _ = self.scan(extra=["--baseline", str(baseline), *image])
        self.assertEqual((status, lines), (0, [["baseline", "google-api-key", "1"]]))
        status, lines, _ = self.scan(extra=["--baseline", str(baseline), "--image", self.IMAGE])
        self.assertEqual(status, 1, "a disk not declared as the image's is never excused")
        leaked = self.secret(anthropic())
        disk.write_text(disk.read_text() + f"LEAK = '{leaked}'\n")
        status, lines, _ = self.scan(extra=["--baseline", str(baseline), *image])
        self.assertEqual(status, 1)
        self.assertEqual([line[0] for line in self.findings(lines)], ["anthropic"])
        self.assertIn(["baseline", "google-api-key", "1"], lines)

    def test_a_baseline_never_excuses_what_is_not_image_content(self):
        scanner = load_scanner()
        disk = "/vm/disks/rootfs.raw"
        places = {
            f"{disk}:/usr/lib/python3/app.py": True,
            disk: True,
            "/vm/disks/state.raw": False,
            "/vm/disks/state.raw:/codewire/notes": False,
            f"{disk}:/home/codewire/notes": False,
            f"{disk}:/workspace/app/config": False,
            f"{disk}:/root/.bash_history": False,
            f"{disk}:/tmp/x": False,
            f"{disk}:/var/tmp/x": False,
            f"{disk}:/run/codewire/x": False,
            f"{disk}:/var/log/app.log.1.gz!decompressed": False,
            "/vm/checkpoint/memory-ranges": False,
            "/proc/1/environ": False,
            "/dev/fd/63": False,
            "/home/user/.codewire/config.toml": False,
        }
        findings = {("google-api-key", "raw", path, 10, 39) for path in places}
        results = scanner.Results({}, frozenset(findings), frozenset({disk}))
        for path, excused in places.items():
            self.assertEqual(results.excused(("google-api-key", "raw", path, 10, 39)), excused, path)
        self.assertFalse(results.excused(("google-api-key", "raw", disk, 11, 39)), "another offset")
        bound = scanner.Results({}, frozenset({("anthropic", "raw", disk, 10, 106)}), frozenset({disk}))
        self.assertFalse(bound.excused(("anthropic", "raw", disk, 10, 106)))

    def test_a_baseline_listing_a_bound_shape_or_a_control_is_refused(self):
        self.write("rootfs.raw", "nothing")
        for shape in ("anthropic", "openai", "openai-legacy", "github", "github-pat", "refresh-token-field",
                      "jwt-openai", "cut:anthropic", "cut:github", "control:planted"):
            baseline = self.baseline_file(f"{shape}\traw\t{self.root}/rootfs.raw\t0\t40")
            status, _, error = self.scan(extra=["--baseline", str(baseline), "--image", self.IMAGE])
            self.assertEqual(status, 2, shape)
            self.assertIn("never excuses", error)
        baseline = self.baseline_file(f"jwt-google\traw\t{self.root}/rootfs.raw\t0\t40")
        status, _, _ = self.scan(extra=["--baseline", str(baseline), "--image", self.IMAGE])
        self.assertEqual(status, 0)

    def test_a_baseline_of_another_image_or_scanner_is_refused(self):
        self.write("rootfs.raw", "nothing")
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
        child = subprocess.Popen(
            [sys.executable, "-c", "import sys; sys.stdin.read()"],
            stdin=subprocess.PIPE,
            env={"PLANTED": control},
        )
        try:
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
            child.wait()

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
