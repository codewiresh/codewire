#!/usr/bin/env python3
"""Focused public bootstrap proof using the existing private release fixtures."""

import copy
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cw_release_fixtures as fx
import cw_bootstrap as bootstrap

release = fx.release
TARGET = "x86_64-unknown-linux-musl"


class Objects:
    def __init__(self, values):
        self.values, self.requests = values, []

    def read(self, key, cap, expected=None):
        self.requests.append(key)
        return self.values[key]


def delivery(signer, override=None):
    executable = {target: fx.executable(target) for target in release.RELEASE_TARGETS}
    if override is not None:
        executable[TARGET] = override
    entries = {}
    objects = {}
    for target in release.RELEASE_TARGETS:
        data = executable[target]
        # For contradiction cases, the signed claims stay at the original
        # compiled fields while all size/hash/object references match the bytes.
        identity = release.make_identity(fx.executable(target), target, fx.VERSION,
                                         fx.REVISION, fx.TREE, fx.RUSTC)
        identity.update(sha256=release.sha256(data), size=len(data))
        entry = {"target": target, "asset_name": release.asset_name(fx.VERSION, target),
                 "identity": identity, "executable": release.object_ref(release.blob_key(identity["sha256"]), data)}
        objects[entry["executable"]["key"]] = data
        if target == release.RUNTIME_TARGET:
            archive = release.object_ref(release.blob_key(release.sha256(b"synthetic archive")), b"synthetic archive")
            entry.update(oci={"index_sha256": "c" * 64, "manifest_sha256": "d" * 64, "archive": archive},
                         runtime_pack=release.object_ref(release.blob_key(release.sha256(b"pack")), b"pack"),
                         runtime_lock=release.object_ref(release.blob_key(release.sha256(b"lock")), b"lock"))
        entries[target] = entry
    sums = release.checksums_text(fx.VERSION, executable)
    sums_sig = signer.sign(sums)
    manifest = release.build_manifest(fx.VERSION, "c" * 40, fx.REVISION, fx.TREE, fx.RUSTC, entries,
                                      sums, release.object_ref(release.release_key(fx.VERSION, "SHA256SUMS.asc"), sums_sig),
                                      signer.fingerprint)
    body = release.canonical(manifest)
    signature = signer.sign(body)
    pointer = release.channel_pointer("stable", body, signature, fx.VERSION)
    objects.update({release.release_key(fx.VERSION, "release.json"): body,
                    release.release_key(fx.VERSION, "release.json.asc"): signature,
                    release.release_key(fx.VERSION, "SHA256SUMS"): sums,
                    release.release_key(fx.VERSION, "SHA256SUMS.asc"): sums_sig,
                    release.channel_key("stable"): release.channel_object(pointer, signer.sign(release.canonical(pointer)))})
    return objects, executable


class BootstrapTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = fx.scratch("cw-bootstrap.")
        cls.signer = fx.Signer(cls.base)
        cls.other = fx.Signer(cls.base, "Synthetic other signer")
        cls.objects, cls.executables = delivery(cls.signer)

    @classmethod
    def tearDownClass(cls):
        cls.signer.close()
        cls.other.close()
        shutil.rmtree(cls.base)

    def prefix(self):
        root = Path(tempfile.mkdtemp(dir=self.base))
        (root / "bin").mkdir(mode=0o755)
        old = root / "bin/cw"
        old.write_bytes(b"previous owner binary\n")
        old.chmod(0o755)
        return root, old

    def refuse(self, objects, trust=None, version=fx.VERSION):
        root, old = self.prefix()
        before = old.read_bytes(), old.stat().st_ino
        with self.assertRaises((release.ReleaseError, OSError)):
            bootstrap.install(Objects(objects), trust or self.signer.trust, TARGET, root / "bin", version)
        self.assertEqual((old.read_bytes(), old.stat().st_ino), before)
        self.assertEqual(list((root / "bin").iterdir()), [old])

    def test_exact_version_and_signed_stable_install_only_the_selected_blob(self):
        platforms = {
            "x86_64-unknown-linux-musl": ("Linux", "x86_64"),
            "aarch64-unknown-linux-gnu": ("Linux", "aarch64"),
            "x86_64-apple-darwin": ("Darwin", "x86_64"),
            "aarch64-apple-darwin": ("Darwin", "arm64"),
        }
        for target in release.RELEASE_TARGETS:
            self.assertEqual(bootstrap.target_for(*platforms[target]), target)
            for version in (fx.VERSION, None):
                with self.subTest(target=target, version=version):
                    root, old = self.prefix()
                    inode = old.stat().st_ino
                    reader = Objects(self.objects)
                    with old.open("rb") as previous:
                        old_bytes = previous.read()
                        identity = bootstrap.install(reader, self.signer.trust, target, root / "bin", version)
                        previous.seek(0)
                        self.assertEqual(previous.read(), old_bytes)
                    self.assertEqual(old.read_bytes(), self.executables[target])
                    self.assertNotEqual(old.stat().st_ino, inode)
                    self.assertEqual(old.stat().st_mode & 0o7777, 0o755)
                    self.assertEqual(identity["sha256"], release.sha256(old.read_bytes()))
                    blobs = [key for key in reader.requests if "/blobs/" in key]
                    self.assertEqual(blobs, [release.blob_key(identity["sha256"])])
                    self.assertEqual(release.channel_key("stable") in reader.requests, version is None)

    def test_second_primary_and_ambient_key_do_not_participate(self):
        two = self.base / "two-public-keys.asc"
        two.write_bytes(self.signer.public.read_bytes() + self.other.public.read_bytes())
        self.refuse(self.objects, release.Trust(two, self.signer.fingerprint))
        # Every object is validly signed by the ambient other key, so this
        # refusal must come from the fixed trust root rather than a hash mismatch.
        values, _ = delivery(self.other)
        with mock.patch.dict(os.environ, {"GNUPGHOME": str(self.other.home)}):
            self.refuse(values)

    def test_public_gpg_calls_are_private_noninteractive_and_bounded(self):
        data = b"synthetic public message"
        signature = self.signer.sign(data)
        original = release.subprocess.run
        calls = []

        def bounded(command, **kwargs):
            self.assertEqual(command[0], "gpg")
            self.assertIn("--no-options", command)
            self.assertIn("--no-autostart", command)
            self.assertEqual(kwargs["timeout"], 15)
            self.assertEqual(set(kwargs["env"]), {"GNUPGHOME", "PATH", "LC_ALL"})
            home = Path(kwargs["env"]["GNUPGHOME"])
            self.assertEqual(home.stat().st_mode & 0o7777, 0o700)
            self.assertNotIn(home, (self.signer.home, self.other.home))
            calls.append(command)
            return original(command, **kwargs)

        with mock.patch.object(release.subprocess, "run", side_effect=bounded):
            release.verify_detached(data, signature, self.signer.trust)
        self.assertEqual(len(calls), 3)

    def test_each_unsigned_or_changed_metadata_stream_preserves_old_binary(self):
        for name in ("release.json", "release.json.asc", "SHA256SUMS", "SHA256SUMS.asc"):
            with self.subTest(name=name):
                values = copy.deepcopy(self.objects)
                key = release.release_key(fx.VERSION, name)
                if name.endswith(".asc"):
                    # Text after an armored signature can be ignored by GPG.
                    # Use a genuinely wrong signature over the original bytes.
                    values[key] = self.other.sign(values[release.release_key(fx.VERSION, name[:-4])])
                else:
                    values[key] += b"tampered"
                self.refuse(values)

    def test_unsigned_stable_channel_preserves_old_binary(self):
        values = copy.deepcopy(self.objects)
        envelope = release.parse_canonical(values[release.channel_key("stable")])
        envelope["signature"] = self.other.sign(release.canonical(envelope["pointer"])).decode("ascii")
        values[release.channel_key("stable")] = release.canonical(envelope)
        self.refuse(values, version=None)

    def test_hash_size_header_and_exact_compiled_record_all_precede_install(self):
        record = fx.build_record()
        cases = [
            fx.executable(TARGET, version="v9.9.9"),
            fx.executable(TARGET, revision="c" * 40),
            fx.executable(TARGET, tree="d" * 64),
            fx.executable(TARGET, rustc="rustc 1.94.0 (synthetic)"),
            fx.executable("aarch64-unknown-linux-gnu"),
            fx.executable(TARGET, static=False),
            fx.executable(TARGET, tag=record),
            fx.executable(TARGET, record=b"no compiled identity"),
        ]
        for data in cases:
            with self.subTest(record=release.sha256(data)):
                values, _ = delivery(self.signer, data)
                self.refuse(values)
        values = copy.deepcopy(self.objects)
        digest = release.sha256(self.executables[TARGET])
        values[release.blob_key(digest)] = self.executables[TARGET] + b"unexpected byte"
        self.refuse(values)

    def test_signature_valid_checksums_cannot_omit_the_selected_asset(self):
        values = copy.deepcopy(self.objects)
        original = values[release.release_key(fx.VERSION, "SHA256SUMS")]
        selected_name = release.asset_name(fx.VERSION, TARGET).encode("ascii")
        sums = b"".join(line + b"\n" for line in original.splitlines() if selected_name not in line)
        sums_sig = self.signer.sign(sums)
        manifest = release.parse_canonical(values[release.release_key(fx.VERSION, "release.json")])
        manifest["checksums"] = {"file": release.object_ref(release.release_key(fx.VERSION, "SHA256SUMS"), sums),
                                  "signature": release.object_ref(release.release_key(fx.VERSION, "SHA256SUMS.asc"), sums_sig)}
        body = release.canonical(manifest)
        values.update({release.release_key(fx.VERSION, "release.json"): body,
                       release.release_key(fx.VERSION, "release.json.asc"): self.signer.sign(body),
                       release.release_key(fx.VERSION, "SHA256SUMS"): sums,
                       release.release_key(fx.VERSION, "SHA256SUMS.asc"): sums_sig})
        self.refuse(values)

    def test_response_refuses_redirect_encoding_duplicate_length_and_oversize(self):
        for raw in (b"HTTP/2 302", b"HTTP/2 200\r\ncontent-encoding: gzip",
                    b"HTTP/2 200\r\ncontent-length: 1\r\ncontent-length: 1",
                    b"HTTP/2 200\r\ncontent-length: 65"):
            with self.subTest(raw=raw), self.assertRaises(release.ReleaseError):
                bootstrap.response_header(raw, 64, None)
        with self.assertRaises(release.ReleaseError):
            bootstrap.fetch(Objects({release.channel_key("stable"): b"x" * (release.MAX_JSON + 1)}),
                            release.channel_key("stable"), release.MAX_JSON)

    def test_atomic_rename_failure_and_exclusive_stage_collision_preserve_old_bytes(self):
        root, old = self.prefix()
        original = old.read_bytes()
        with mock.patch.object(bootstrap.os, "replace", side_effect=OSError("synthetic refusal")):
            with self.assertRaises(OSError):
                bootstrap.atomic_install(self.executables[TARGET], root / "bin")
        self.assertEqual(old.read_bytes(), original)
        self.assertEqual(list((root / "bin").iterdir()), [old])
        collision = root / f"bin/.cw-install-{'e' * 32}"
        collision.write_bytes(b"preserve another existing stage")
        with mock.patch.object(bootstrap.uuid, "uuid4", return_value=types.SimpleNamespace(hex="e" * 32)):
            with self.assertRaises(FileExistsError):
                bootstrap.atomic_install(self.executables[TARGET], root / "bin")
        self.assertEqual(collision.read_bytes(), b"preserve another existing stage")
        self.assertEqual(old.read_bytes(), original)

    def test_existing_destination_symlink_is_refused_without_following_it(self):
        root, old = self.prefix()
        sentinel = root / "sentinel"
        sentinel.write_bytes(b"unrelated target")
        old.unlink()
        old.symlink_to(sentinel)
        with self.assertRaises(release.ReleaseError):
            bootstrap.install(Objects(self.objects), self.signer.trust, TARGET, root / "bin", fx.VERSION)
        self.assertTrue(old.is_symlink())
        self.assertEqual(sentinel.read_bytes(), b"unrelated target")

    def test_missing_gpg_fails_before_transport_or_install(self):
        root, old = self.prefix()
        real = shutil.which
        with mock.patch.object(bootstrap.shutil, "which", side_effect=lambda name: None if name == "gpg" else real(name)), \
             mock.patch.object(bootstrap, "FixedReader") as reader:
            self.assertEqual(bootstrap.main(["--version", fx.VERSION, "--prefix", str(root)]), 1)
            reader.assert_not_called()
        self.assertEqual(old.read_bytes(), b"previous owner binary\n")

    def test_missing_python_fails_before_the_generated_installer_runs(self):
        empty = Path(tempfile.mkdtemp(dir=self.base))
        result = subprocess.run([shutil.which("bash"), str(fx.ROOT / "apps/cli/install.sh")],
                                env={"PATH": str(empty)}, capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 1)
        self.assertIn("Python3 is required", result.stderr)

    def test_generated_standalone_runs_without_a_checkout_or_network(self):
        spec = importlib.util.spec_from_file_location("generator", fx.ROOT / "scripts/ci/release/generate-cw-bootstrap.py")
        generator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(generator)
        shared = (fx.ROOT / "scripts/ci/release/cw_release.py").read_text().replace(
            f'PRODUCTION_FINGERPRINT = "{release.PRODUCTION_FINGERPRINT}"',
            f'PRODUCTION_FINGERPRINT = "{self.signer.fingerprint}"')
        consumer = (fx.ROOT / "scripts/ci/release/cw_bootstrap.py").read_text()
        wrapper = self.base / "standalone-install.sh"
        wrapper.write_text(generator.render(shared, consumer, self.signer.public.read_bytes()))
        assets = self.base / "objects"
        assets.mkdir()
        for key, data in self.objects.items():
            path = assets / key
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        tools = self.base / "fake-tools"
        tools.mkdir()
        curl = tools / "curl"
        curl.write_text(f"#!/usr/bin/env python3\nimport pathlib,sys\nurl=sys.argv[-1]\n"
                        f"origin={bootstrap.ORIGIN!r}\nassert url.startswith(origin)\n"
                        f"data=(pathlib.Path({str(assets)!r})/url[len(origin):]).read_bytes()\n"
                        "sys.stdout.buffer.write(b'HTTP/2 200\\r\\nContent-Length: '+str(len(data)).encode()+b'\\r\\n\\r\\n'+data)\n")
        curl.chmod(0o755)
        root, old = self.prefix()
        env = {"PATH": str(tools) + os.pathsep + os.environ.get("PATH", "/usr/bin:/bin"),
               "HOME": str(self.base), "TMPDIR": str(self.base)}
        result = subprocess.run(["bash", str(wrapper), "--prefix", str(root)], cwd=self.base,
                                env=env, capture_output=True, text=True, timeout=45)
        self.assertEqual(result.returncode, 0, result.stderr)
        target = bootstrap.target_for(bootstrap.platform.system(), bootstrap.platform.machine())
        self.assertEqual(old.read_bytes(), self.executables[target])


if __name__ == "__main__":
    if sys.platform != "linux":
        raise SystemExit("public bootstrap process fixtures require Linux custody")
    spec = importlib.util.spec_from_file_location(
        "bootstrap_fixture_custody", fx.ROOT / "scripts/ci/verify/build-linux-vmm-kernel.py")
    owner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(owner)
    owner.arm_custody()

    class FixtureResult(unittest.TextTestResult):
        def stopTestRun(self):
            # Every original body/direct wait and Signer.close has finished.
            # Own only this isolated fixture process's adopted helpers; final
            # ECHILD must precede unittest's success summary.
            deadline = time.monotonic() + 5
            while True:
                if time.monotonic() >= deadline:
                    raise RuntimeError("public bootstrap fixture cleanup did not reach ECHILD")
                try:
                    reaped, _ = os.waitpid(-1, os.WNOHANG | owner.WALL)
                except ChildProcessError:
                    break
                except InterruptedError:
                    continue
                if not reaped:
                    time.sleep(0.01)
            super().stopTestRun()

    class FixtureRunner(unittest.TextTestRunner):
        resultclass = FixtureResult

    unittest.main(testRunner=FixtureRunner)
