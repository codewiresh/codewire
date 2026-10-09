#!/usr/bin/env python3
"""The public POSIX sh installer, run offline against a fake curl.

Every case runs under each available POSIX shell (the system sh, plus dash,
busybox sh and bash --posix when installed). The fake curl serves fixture
objects for https://releases.codewire.sh/, records its arguments and applies
the same size cap and status semantics as curl.
"""

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
INSTALLER = ROOT / "apps/cli/install.sh"
ORIGIN = "https://releases.codewire.sh/"
VERSION = "v1.2.3"
TARGETS = (
    "aarch64-apple-darwin",
    "aarch64-unknown-linux-gnu",
    "x86_64-apple-darwin",
    "x86_64-unknown-linux-musl",
)
TOOLS = ("awk", "cat", "chmod", "find", "grep", "head", "id", "mkdir", "mktemp", "mv", "rm",
         "sed", "tr", "uname", "wc")

FAKE_CURL = r'''#!PYTHON -I
import json, os, sys
args = sys.argv[1:]
log = os.environ["FAKE_CURL_LOG"]
with open(log, "a") as handle:
    handle.write(json.dumps(args) + "\n")
assert args[0] == "-q", "curl must read no configuration file"
values = {}
flags = set()
url = None
takes = {"--proto", "--proxy", "--noproxy", "--connect-timeout", "--max-time", "--max-filesize",
         "--header", "--output", "--write-out"}
i = 1
while i < len(args):
    if args[i] in takes:
        values[args[i]] = args[i + 1]
        i += 2
    elif args[i].startswith("-"):
        flags.add(args[i])
        i += 1
    else:
        assert url is None
        url = args[i]
        i += 1
assert values["--proto"] == "=https" and values["--proxy"] == "" and values["--noproxy"] == "*"
assert {"--fail", "--tlsv1.2", "--silent", "--show-error"} <= flags and "--location" not in flags
assert values["--header"] == "Accept-Encoding: identity"
assert url.startswith(ORIGIN), url
key = url[len(ORIGIN):]
rules = json.loads(open(os.environ["FAKE_CURL_RULES"]).read())
status = rules.get("status", {}).get(key, 200)
path = os.path.join(os.environ["FAKE_CURL_ROOT"], key)
code = "404"
body = b""
if status != 200:
    code = str(status)
elif os.path.isfile(path):
    code = "200"
    body = open(path, "rb").read()
sys.stdout.write(code)
if int(code) >= 400:
    sys.stderr.write("curl: (22) The requested URL returned error: %s\n" % code)
    sys.exit(22)
if len(body) > int(values["--max-filesize"]):
    sys.stderr.write("curl: (63) Maximum file size exceeded\n")
    sys.exit(63)
with open(values["--output"], "wb") as handle:
    handle.write(body)
'''


def available_shells():
    shells = [["/bin/sh"]]
    for name, argv in (("dash", ["dash"]), ("busybox", ["busybox", "sh"]),
                       ("bash", ["bash", "--posix"])):
        found = shutil.which(name)
        if found:
            shells.append([found] + argv[1:])
    return shells


def executable(target):
    return b"\x7fELF" + hashlib.sha512(target.encode()).digest() * 2


class Fixture:
    def __init__(self, base):
        self.base = base
        self.objects = base / "objects"
        self.bin = base / "bin"
        self.bin.mkdir()
        self.log = base / "curl.log"
        self.rules = base / "rules.json"
        self.rules.write_text("{}")
        self.prefix = base / "prefix"
        self.publish(VERSION)
        self.write("cw/v1/channels/stable.json", self.channel(VERSION))
        curl = self.bin / "curl"
        curl.write_text(FAKE_CURL.replace("PYTHON", sys.executable).replace(
            "ORIGIN", repr(ORIGIN)))
        curl.chmod(0o755)

    def write(self, key, data):
        path = self.objects / key
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def channel(self, tag):
        pointer = {"release": {"key": f"cw/v1/releases/{tag}/release.json", "sha256": "a" * 64,
                               "size": 1},
                   "release_signature": {"key": f"cw/v1/releases/{tag}/release.json.asc",
                                         "sha256": "b" * 64, "size": 1},
                   "release_tag": tag}
        value = {"pointer": pointer, "schema": "codewire.cw.channel/v1",
                 "signature": "-----BEGIN PGP SIGNATURE-----\n\nAAAA\n=AAAA\n-----END PGP SIGNATURE-----\n"}
        return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()

    def publish(self, tag, override=None):
        lines = []
        for target in TARGETS:
            data = executable(target + tag)
            digest = hashlib.sha256(data).hexdigest()
            self.write(f"cw/v1/blobs/sha256/{digest}", data if override is None else override)
            lines.append(f"{digest}  cw-{tag}-{target}\n")
        self.write(f"cw/v1/releases/{tag}/SHA256SUMS", "".join(lines).encode())

    def expected(self, target, tag=VERSION):
        return executable(target + tag)

    def rule(self, **values):
        self.rules.write_text(json.dumps(values))

    def tools(self, omit=(), extra=None):
        """A PATH directory holding only the named stock tools."""
        directory = Path(tempfile.mkdtemp(dir=self.base, prefix="tools."))
        extra = extra or {}
        for name in TOOLS + ("sha256sum",):
            if name in omit or name in extra:
                continue
            found = shutil.which(name)
            if found:
                (directory / name).symlink_to(found)
        if "curl" not in omit:
            (directory / "curl").symlink_to(self.bin / "curl")
        for name, script in extra.items():
            path = directory / name
            assert not path.exists() and not path.is_symlink()
            path.write_text(script)
            path.chmod(0o755)
        return directory

    def run(self, shell, *args, path=None, stdin_script=False, env=None, script=None):
        environment = {
            "PATH": str(path or self.tools()),
            "HOME": str(self.base / "home"),
            "TMPDIR": str(self.base),
            "FAKE_CURL_ROOT": str(self.objects),
            "FAKE_CURL_LOG": str(self.log),
            "FAKE_CURL_RULES": str(self.rules),
        }
        environment.update(env or {})
        source = script if script is not None else INSTALLER.read_bytes()
        if stdin_script:
            command = shell + ["-s", "--"] + list(args)
            return subprocess.run(command, input=source, env=environment, capture_output=True,
                                  timeout=60, cwd=self.base)
        installer = self.base / "install.sh"
        installer.write_bytes(source)
        return subprocess.run(shell + [str(installer)] + list(args), env=environment,
                              capture_output=True, timeout=60, stdin=subprocess.DEVNULL,
                              cwd=self.base)

    def requests(self):
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def leftovers(self, directory):
        return sorted(p.name for p in Path(directory).iterdir() if p.name.startswith(".cw-install"))


def host_target():
    system, machine = os.uname().sysname, os.uname().machine
    if system == "Darwin":
        return "aarch64-apple-darwin" if machine == "arm64" else "x86_64-apple-darwin"
    return "aarch64-unknown-linux-gnu" if machine in ("aarch64", "arm64") else "x86_64-unknown-linux-musl"


class InstallerTest(unittest.TestCase):
    def setUp(self):
        # The installer refuses any world-writable ancestor such as /tmp, so
        # fixtures live under the checkout's ignored .tmp.
        scratch = ROOT / ".tmp"
        scratch.mkdir(mode=0o755, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix="cw-install-test.", dir=scratch)
        base = Path(self.temp.name)
        base.chmod(0o755)
        (base / "home").mkdir()
        self.base = base

    def tearDown(self):
        for path in self.base.rglob("*"):
            if path.is_dir() and not path.is_symlink():
                path.chmod(0o755)
        self.temp.cleanup()

    def each_shell(self):
        """Each available shell with its own fresh fixture."""
        return [(shell, Fixture(Path(tempfile.mkdtemp(dir=self.base, prefix="case."))))
                for shell in available_shells()]

    def assert_rejected(self, result, reason):
        stderr = result.stderr.decode()
        self.assertEqual(result.returncode, 1, stderr)
        self.assertIn("cw install: REJECT ", stderr)
        self.assertIn(reason, stderr)

    def test_stable_and_exact_version_install_the_listed_bytes(self):
        target = host_target()
        for shell, fx in self.each_shell():
            result = fx.run(shell, "--prefix", str(fx.prefix))
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            installed = fx.prefix / "bin/cw"
            self.assertEqual(installed.read_bytes(), fx.expected(target))
            self.assertEqual(stat.S_IMODE(installed.stat().st_mode), 0o755)
            self.assertEqual(result.stdout.decode().splitlines(), [
                f"==> Installed cw {VERSION} to {installed}",
                f"NOTE: add {fx.prefix / 'bin'} to your PATH",
            ])
            self.assertEqual(fx.leftovers(fx.prefix / "bin"), [])
            keys = [request[-1][len(ORIGIN):] for request in fx.requests()]
            digest = hashlib.sha256(fx.expected(target)).hexdigest()
            self.assertEqual(keys, ["cw/v1/channels/stable.json", f"cw/v1/releases/{VERSION}/SHA256SUMS",
                                    f"cw/v1/blobs/sha256/{digest}"])

            # An exact version replaces the installed bytes; --verbose names them.
            fx.publish("v1.2.4")
            result = fx.run(shell, "--version", "v1.2.4", "--prefix", str(fx.prefix), "--verbose",
                            env={"PATH": f"{fx.tools()}:{fx.prefix / 'bin'}"})
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            data = fx.expected(target, "v1.2.4")
            self.assertEqual(installed.read_bytes(), data)
            self.assertEqual(result.stdout.decode().splitlines(), [
                f"==> Installed cw v1.2.4 to {installed}",
                f"    target={target} sha256={hashlib.sha256(data).hexdigest()} size={len(data)}",
            ])

    def test_piped_script_and_relative_prefix(self):
        for shell, fx in self.each_shell():
            result = fx.run(shell, "--prefix", "relative", stdin_script=True)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertTrue((fx.base / "relative/bin/cw").is_file())
            self.assertIn(f"to {fx.base.resolve() / 'relative/bin/cw'}", result.stdout.decode())

    def test_default_directory_is_the_users_local_bin(self):
        for shell, fx in self.each_shell():
            if os.access("/usr/local/bin", os.W_OK):
                self.skipTest("/usr/local/bin is writable here")
            result = fx.run(shell, env={"HOME": str(fx.base / "home")})
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertTrue((fx.base / "home/.local/bin/cw").is_file())

    def test_changed_or_unlisted_bytes_never_replace_the_installed_cw(self):
        for shell, fx in self.each_shell():
            bin_dir = fx.prefix / "bin"
            for directory in (fx.prefix, bin_dir):
                directory.mkdir(mode=0o755)
                directory.chmod(0o755)
            (bin_dir / "cw").write_bytes(b"old cw")
            (bin_dir / "cw").chmod(0o755)
            fx.publish(VERSION, override=b"\x7fELF" + b"tampered" * 16)
            self.assert_rejected(fx.run(shell, "--prefix", str(fx.prefix)),
                                 "does not match SHA256SUMS")
            self.assertEqual((bin_dir / "cw").read_bytes(), b"old cw")
            self.assertEqual(fx.leftovers(bin_dir), [])

            sums = f"cw/v1/releases/{VERSION}/SHA256SUMS"
            original = (fx.objects / sums).read_bytes()
            lines = original.decode().splitlines(keepends=True)
            mine = f"cw-{VERSION}-{host_target()}"
            fx.write(sums, "".join(line for line in lines if not line.endswith(f"  {mine}\n")).encode())
            self.assert_rejected(fx.run(shell, "--prefix", str(fx.prefix)), f"exactly one {mine}")
            fx.write(sums, original + next(line for line in lines if line.endswith(f"  {mine}\n")).encode())
            self.assert_rejected(fx.run(shell, "--prefix", str(fx.prefix)), f"exactly one {mine}")
            self.assertEqual((bin_dir / "cw").read_bytes(), b"old cw")

    def test_channel_must_name_exactly_one_valid_tag(self):
        for shell, fx in self.each_shell():
            for channel in (fx.channel("1.2.3"), fx.channel("v1.2.3;rm"), b"{}\n",
                            fx.channel(VERSION).replace(b'"schema"', b'"release_tag":"v9.9.9","schema"')):
                fx.write("cw/v1/channels/stable.json", channel)
                self.assert_rejected(fx.run(shell, "--prefix", str(fx.prefix)), "one release tag")
            self.assert_rejected(fx.run(shell, "--version", "latest", "--prefix", str(fx.prefix)),
                                 "exact release tag")
            self.assertFalse((fx.prefix / "bin/cw").exists())

    def test_redirect_error_and_oversize_responses_are_refused(self):
        for shell, fx in self.each_shell():
            sums = f"cw/v1/releases/{VERSION}/SHA256SUMS"
            fx.rule(status={sums: 302})
            self.assert_rejected(fx.run(shell, "--prefix", str(fx.prefix)), "answered HTTP 302")
            fx.rule(status={sums: 404})
            self.assert_rejected(fx.run(shell, "--prefix", str(fx.prefix)), "could not download")
            fx.rule()
            fx.write(sums, b"0" * 65537)
            self.assert_rejected(fx.run(shell, "--prefix", str(fx.prefix)), "could not download")
            fx.write(sums, b"")
            self.assert_rejected(fx.run(shell, "--prefix", str(fx.prefix)), "empty or exceeds")
            self.assertFalse((fx.prefix / "bin/cw").exists())

    def test_unsafe_destinations_are_refused_without_following_them(self):
        for shell, fx in self.each_shell():
            bin_dir = fx.prefix / "bin"
            for directory in (fx.prefix, bin_dir):
                directory.mkdir(mode=0o755)
                directory.chmod(0o755)
            victim = fx.base / "victim"
            victim.write_bytes(b"not cw")
            (bin_dir / "cw").symlink_to(victim)
            self.assert_rejected(fx.run(shell, "--prefix", str(fx.prefix)), "symbolic link")
            self.assertEqual(victim.read_bytes(), b"not cw")
            (bin_dir / "cw").unlink()

            (bin_dir / "cw").mkdir()
            self.assert_rejected(fx.run(shell, "--prefix", str(fx.prefix)), "owner-controlled regular file")
            (bin_dir / "cw").rmdir()

            (bin_dir / "cw").write_bytes(b"old cw")
            (bin_dir / "cw").chmod(0o755)
            os.link(bin_dir / "cw", fx.base / "second-link")
            self.assert_rejected(fx.run(shell, "--prefix", str(fx.prefix)), "owner-controlled regular file")
            (fx.base / "second-link").unlink()

            for mode in (0o775, 0o757):
                bin_dir.chmod(mode)
                self.assert_rejected(fx.run(shell, "--prefix", str(fx.prefix)), "not a directory controlled")
            bin_dir.chmod(0o755)
            self.assertEqual((bin_dir / "cw").read_bytes(), b"old cw")
            self.assertEqual(fx.leftovers(bin_dir), [])

            linked = fx.base / "linked-prefix"
            linked.symlink_to(fx.prefix)
            self.assert_rejected(fx.run(shell, "--prefix", str(linked)), "not a directory controlled")

    def test_missing_curl_or_hasher_fails_before_any_download(self):
        for shell, fx in self.each_shell():
            self.assert_rejected(fx.run(shell, "--prefix", str(fx.prefix), path=fx.tools(omit=("curl",))),
                                 "curl is required")
            self.assert_rejected(fx.run(shell, "--prefix", str(fx.prefix), path=fx.tools(omit=("sha256sum",))),
                                 "no SHA-256 tool")
            self.assertEqual(fx.requests(), [])

    def test_each_stock_hasher_is_used_when_it_is_the_only_one(self):
        for name in ("shasum", "openssl"):
            found = shutil.which(name)
            if not found:
                continue
            for shell, fx in self.each_shell():
                with self.subTest(hasher=name):
                    tools = fx.tools(omit=("sha256sum",))
                    (tools / name).symlink_to(found)
                    for helper in ("perl",):
                        if name == "shasum" and shutil.which(helper):
                            (tools / helper).symlink_to(shutil.which(helper))
                    result = fx.run(shell, "--prefix", str(fx.prefix), path=tools)
                    self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_targets_follow_the_platform_and_rosetta(self):
        cases = (
            ("Darwin", "arm64", "", "aarch64-apple-darwin"),
            ("Darwin", "x86_64", "0", "x86_64-apple-darwin"),
            ("Darwin", "x86_64", "1", "aarch64-apple-darwin"),
            ("Linux", "x86_64", "", "x86_64-unknown-linux-musl"),
            ("Linux", "aarch64", "", "aarch64-unknown-linux-gnu"),
        )
        for shell, fx in self.each_shell():
            for system, machine, translated, target in cases:
                with self.subTest(system=system, machine=machine, translated=translated):
                    uname = f"#!/bin/sh\ncase \"$1\" in -s) echo {system} ;; -m) echo {machine} ;; esac\n"
                    sysctl = (f"#!/bin/sh\necho {translated}\n" if translated
                              else "#!/bin/sh\nexit 1\n")
                    tools = fx.tools(extra={"uname": uname, "sysctl": sysctl})
                    prefix = fx.base / f"prefix-{system}-{machine}-{translated}"
                    result = fx.run(shell, "--prefix", str(prefix), "--verbose", path=tools)
                    self.assertEqual(result.returncode, 0, result.stderr.decode())
                    self.assertEqual((prefix / "bin/cw").read_bytes(), fx.expected(target))
                    self.assertIn(f"target={target} ", result.stdout.decode())
            uname = "#!/bin/sh\ncase \"$1\" in -s) echo FreeBSD ;; -m) echo amd64 ;; esac\n"
            self.assert_rejected(fx.run(shell, "--prefix", str(fx.prefix),
                                        path=fx.tools(extra={"uname": uname})), "no cw release for FreeBSD")

    def test_a_truncated_script_does_nothing(self):
        source = INSTALLER.read_bytes()
        last = source.rstrip(b"\n").rfind(b"\n") + 1
        self.assertEqual(source[last:], b'main "$@"\n')
        for shell, fx in self.each_shell():
            for end in range(0, last, 97):
                result = fx.run(shell, "--prefix", str(fx.prefix), stdin_script=True, script=source[:end])
                self.assertNotIn(b"Installed", result.stdout)
            self.assertEqual(fx.requests(), [])
            self.assertFalse(fx.prefix.exists())

    def test_arguments_are_closed(self):
        for shell, fx in self.each_shell():
            self.assert_rejected(fx.run(shell, "--prefix"), "--prefix needs a directory")
            self.assert_rejected(fx.run(shell, "--channel", "beta"), "unknown argument --channel")
            result = fx.run(shell, "--help")
            self.assertEqual(result.returncode, 0)
            self.assertIn(b"Usage: install.sh", result.stdout)
            self.assertEqual(fx.requests(), [])

    def test_only_stock_tools_and_the_release_origin_are_used(self):
        text = INSTALLER.read_text()
        self.assertTrue(text.startswith("#!/bin/sh\n"))
        self.assertIn(f"ORIGIN='{ORIGIN}'", text)
        for forbidden in ("python", "gpg", "jq", "perl", "bash", "github.com", "githubusercontent",
                          "--location", "local "):
            self.assertNotIn(forbidden, text.replace("Python", ""), forbidden)


if __name__ == "__main__":
    unittest.main(verbosity=1)
