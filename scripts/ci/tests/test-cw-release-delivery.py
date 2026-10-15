#!/usr/bin/env python3
"""Synthetic proof for cw release identities, transports, manifest and trust."""

import copy
import hashlib
import importlib.util
import json
import os
import shutil
import struct
import subprocess
import sys
import time
import unittest
from unittest import mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cw_release_fixtures as fx  # noqa: E402

release = fx.release
ROOT = fx.ROOT


class DeliveryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = fx.scratch("cw-release-delivery.")
        cls.signer = fx.Signer(cls.base)
        cls.other = fx.Signer(cls.base, "Synthetic other signer")
        (cls.base / "signed").mkdir()
        cls.dist, cls.executables, cls.source_sha = fx.signed_delivery(cls.base / "signed", cls.signer)

    @classmethod
    def tearDownClass(cls):
        cls.signer.close()
        cls.other.close()
        shutil.rmtree(cls.base)

    def copy_dist(self, name):
        target = self.base / name
        shutil.copytree(self.dist, target)
        return target

    # --- identities -----------------------------------------------------------

    def test_four_target_identities_carry_the_effective_compiled_version(self):
        paths = release.delivery_paths(self.dist)
        identities = [release.parse_canonical((paths["identities"] / f"{target}.json").read_bytes())
                      for target in release.RELEASE_TARGETS]
        self.assertEqual(len(identities), 4)
        for target, identity in zip(release.RELEASE_TARGETS, identities):
            data = self.executables[target]
            self.assertEqual(identity["target"], target)
            self.assertEqual(identity["package_version"], fx.VERSION)
            self.assertEqual((identity["sha256"], identity["size"]), (fx.digest(data), len(data)))
            self.assertEqual(identity["source_revision"], self.source_sha)
            self.assertEqual(identity["rustc"], fx.RUSTC)
            self.assertEqual((identity["schema_version"], identity["protocol_version"],
                              identity["record_version"]), (2, 1, 1))

    def test_identity_producer_refuses_inconsistent_executables(self):
        good = fx.executable("x86_64-unknown-linux-musl")
        args = ("x86_64-unknown-linux-musl", fx.VERSION, "a" * 40, "b" * 64, fx.RUSTC)
        release.make_identity(good, *args)
        cases = {
            "version not compiled in": fx.executable("x86_64-unknown-linux-musl", "v9.9.9"),
            "wrong architecture": fx.executable("aarch64-unknown-linux-gnu"),
            "mach-o for linux": fx.executable("x86_64-apple-darwin"),
            "dynamic runtime target": fx.executable("x86_64-unknown-linux-musl", static=False),
            "truncated": good[:32],
        }
        for name, data in cases.items():
            with self.subTest(name), self.assertRaises(release.ReleaseError):
                release.make_identity(data, *args)
        with self.assertRaises(release.ReleaseError):
            release.make_identity(good, "x86_64-unknown-linux-gnu", *args[1:])
        darwin = fx.executable("aarch64-apple-darwin")
        with self.assertRaises(release.ReleaseError):
            release.make_identity(darwin, "x86_64-apple-darwin", *args[1:])

    def test_identity_schema_is_closed_and_typed(self):
        identity = release.make_identity(fx.executable("aarch64-apple-darwin"), "aarch64-apple-darwin",
                                         fx.VERSION, "a" * 40, "b" * 64, fx.RUSTC)
        mutations = {
            "extra field": lambda v: v.update(extra=1),
            "missing size": lambda v: v.pop("size"),
            "boolean protocol": lambda v: v.update(protocol_version=True),
            "protocol 2": lambda v: v.update(protocol_version=2),
            "record 0": lambda v: v.update(record_version=0),
            "schema 3": lambda v: v.update(schema_version=3),
            "unsupported target": lambda v: v.update(target="x86_64-unknown-linux-gnu"),
            "uppercase digest": lambda v: v.update(sha256=v["sha256"].upper()),
            "oversized": lambda v: v.update(size=release.MAX_EXECUTABLE + 1),
            "bad version": lambda v: v.update(package_version="v 1"),
            "not rustc": lambda v: v.update(rustc="cargo 1.93.0"),
        }
        for name, mutate in mutations.items():
            value = copy.deepcopy(identity)
            mutate(value)
            with self.subTest(name), self.assertRaises(release.ReleaseError):
                release.validate_identity(value, "aarch64-apple-darwin")

    def test_identity_requires_the_exact_embedded_build_record(self):
        target = "x86_64-unknown-linux-musl"
        args = (target, "v1.2.3", fx.REVISION, fx.TREE, fx.RUSTC)
        # The requested version occurs incidentally, but the record compiled v1.2.30.
        actual = fx.executable(target, "v1.2.30", tag=b"cw v1.2.3 compatibility v1.2.3\0")
        self.assertIn(b"v1.2.3", actual.replace(b"v1.2.30", b""))
        with self.assertRaisesRegex(release.ReleaseError, "package_version v1.2.30 differs from the admitted v1.2.3"):
            release.make_identity(actual, *args)
        self.assertEqual(release.make_identity(actual, target, "v1.2.30", *args[2:])["package_version"], "v1.2.30")
        record = fx.build_record("v1.2.3", target)
        good = fx.executable(target, record=record)
        self.assertEqual(release.make_identity(good, *args)["package_version"], "v1.2.3")
        body = record[len(release.BUILD_RECORD_MAGIC) + 4:]

        def framed(json_bytes):
            return release.BUILD_RECORD_MAGIC + struct.pack("<I", len(json_bytes)) + json_bytes

        value = json.loads(body)
        refused = {
            "no record": fx.executable(target, record=b"cw v1.2.3"),
            "two records": fx.executable(target, record=record, tag=record),
            "no source provenance": fx.executable(target, record=fx.build_record(
                "v1.2.3", target, revision=None, tree=None)),
            "wrong revision": fx.executable(target, "v1.2.3", revision="c" * 40),
            "wrong source digest": fx.executable(target, "v1.2.3", tree="d" * 64),
            "wrong compiler": fx.executable(target, "v1.2.3", rustc="rustc 1.94.0 (other 2026-03-01)"),
            "wrong target": fx.executable(target, record=fx.build_record("v1.2.3", "aarch64-unknown-linux-gnu")),
            "partial provenance": fx.executable(target, record=framed(release.canonical({**value,
                                                                                          "source_tree_sha256": None}))),
            "unknown field": fx.executable(target, record=framed(release.canonical({**value, "extra": 1}))),
            "missing field": fx.executable(target, record=framed(release.canonical(
                {key: item for key, item in value.items() if key != "rustc"}))),
            "not canonical": fx.executable(target, record=framed(json.dumps(value, indent=1).encode())),
            "duplicate key": fx.executable(target, record=framed(body.replace(b'{"package_version"',
                                                                              b'{"target":"x","package_version"'))),
            "length overruns": fx.executable(target, record=record)[:1024 + len(record) - 1],
            "oversized length": fx.executable(target, record=release.BUILD_RECORD_MAGIC + struct.pack("<I", 4096)),
        }
        for name, data in refused.items():
            with self.subTest(name), self.assertRaises(release.ReleaseError):
                release.make_identity(data, *args)

    def test_build_record_format_matches_the_rust_producer(self):
        build = (ROOT / "crates/codewire-cli/build.rs").read_text()
        self.assertIn('const MAGIC: &[u8] = b"\\0codewire-cw-build-record-v1\\0";', build)
        self.assertEqual(release.BUILD_RECORD_MAGIC, b"\0codewire-cw-build-record-v1\0")
        keys = [key for key in sorted(release.BUILD_RECORD_FIELDS)]
        positions = [build.index(f'\\"{key}\\":') for key in keys]
        self.assertEqual(positions, sorted(positions), "build.rs must emit the record's keys in canonical order")
        self.assertIn("to_le_bytes", build)
        for name in ("CODEWIRE_VERSION", "CODEWIRE_SOURCE_REVISION", "CODEWIRE_SOURCE_TREE_SHA256"):
            self.assertIn(f'"{name}"', build)
            self.assertIn(name, release.build_environment(fx.VERSION, fx.REVISION, fx.TREE))
        self.assertNotIn('Command::new("git")', build)

    def depinfo(self, base, paths):
        rule = base / "cw.d"
        escaped = " ".join(str(path).replace(" ", "\\ ") for path in paths)
        rule.write_text(f"{base}/target/release/cw: {escaped}\n\n")
        return rule

    def directory_source(self, name):
        base = self.base / name
        base.mkdir()
        source, _ = fx.source_repo(base)
        directory = source / "crates/codewire-server-core/migrations"
        directory.mkdir(parents=True)
        (directory / "0001.sql").write_text("create table core(id int);\n")
        return base, source, directory

    def test_complete_known_directory_is_admitted_without_changing_the_digest(self):
        base, source, directory = self.directory_source("directory-covered")
        (directory / "nested").mkdir()
        (directory / "nested/0002.sql").write_text("select 2;\n")
        (directory / ".hidden.sql").write_text("select 3;\n")
        subprocess.run(["git", "add", "crates/codewire-server-core/migrations"], cwd=source, check=True)
        (directory / "0003.sql").write_text("select 4;\n")  # covered untracked leaf
        inputs = release.source_inputs(source)
        self.assertNotIn(os.fsencode(directory.relative_to(source)), inputs)
        expected = hashlib.sha256()
        for raw in inputs:
            data = (source / os.fsdecode(raw)).read_bytes()
            expected.update(raw + b"\0" + str(len(data)).encode() + b"\0" + hashlib.sha256(data).digest())
        self.assertEqual(release.source_tree_sha256(source), expected.hexdigest())
        self.assertEqual(release.check_build_inputs(source, self.depinfo(base, [directory]), (base / "target",)), 1)
        for path in (source / "crates/codewire-server-core", source / "crates/demo/src",
                     directory / "nested", directory / "../migrations"):
            with self.subTest(path=path), self.assertRaises(release.ReleaseError):
                release.check_build_inputs(source, self.depinfo(base, [path]), (base / "target",))
        alias = source / "migration-alias"; alias.symlink_to(directory)
        with self.assertRaises(release.ReleaseError):
            release.check_build_inputs(source, self.depinfo(base, [alias]), (base / "target",))

    def test_hostile_directory_inventory_refuses_before_build_and_admission(self):
        def ignored(source, directory):
            (source / ".gitignore").write_text("ignored.sql\n")
            (directory / "ignored.sql").write_text("not digested\n")

        def missing(source, directory):
            subprocess.run(["git", "add", "crates/codewire-server-core/migrations"], cwd=source, check=True)
            (directory / "0001.sql").unlink()

        def linked_parent(source, directory):
            saved = source / "saved-core"
            directory.parent.rename(saved)
            directory.parent.symlink_to(saved)

        changes = {
            "ignored leaf": ignored,
            "missing tracked leaf": missing,
            "empty root": lambda s, d: (d / "0001.sql").unlink(),
            "empty subdirectory": lambda s, d: (d / "empty").mkdir(),
            "leaf symlink": lambda s, d: (d / "linked.sql").symlink_to(d / "0001.sql"),
            "directory symlink": lambda s, d: (d / "linked").symlink_to(d),
            "parent symlink": linked_parent,
            "fifo": lambda s, d: os.mkfifo(d / "pipe"),
        }
        for index, (name, change) in enumerate(changes.items()):
            base, source, directory = self.directory_source(f"directory-hostile-{index}")
            change(source, directory)
            with self.subTest(name=name):
                with self.assertRaises(release.ReleaseError):
                    release.source_tree_sha256(source)
                with self.assertRaises(release.ReleaseError):
                    release.check_build_inputs(source, self.depinfo(base, [directory]), (base / "target",))

    def test_directory_bounds_and_replacement_refuse(self):
        base, source, directory = self.directory_source("directory-bounds")
        (directory / "nested").mkdir()
        (directory / "nested/0002.sql").write_text("select 2;\n")
        for limit, value in (("MAX_SOURCE_DIRECTORY_ENTRIES", 1), ("MAX_SOURCE_DIRECTORY_DEPTH", 0)):
            with self.subTest(limit=limit), mock.patch.object(release, limit, value), self.assertRaises(release.ReleaseError):
                release.source_tree_sha256(source)
        original = release.depinfo_inputs

        def replaced(path):
            paths = original(path)
            saved = source / "saved-migrations"
            directory.rename(saved)
            shutil.copytree(saved, directory)
            return paths

        with mock.patch.object(release, "depinfo_inputs", side_effect=replaced), self.assertRaisesRegex(
                release.ReleaseError, "changed during dep-info admission"):
            release.check_build_inputs(source, self.depinfo(base, [directory]), (base / "target",))

    def test_admission_refuses_a_source_change_during_the_build(self):
        base = self.base / "admit"
        base.mkdir()
        source, revision = fx.source_repo(base)
        tree = release.source_tree_sha256(source)
        target = "x86_64-unknown-linux-musl"
        executable = base / "cw"
        executable.write_bytes(fx.executable(target, revision=revision, tree=tree))
        depinfo = self.depinfo(base, [source / "crates/demo/src/lib.rs"])
        data, identity, inputs = release.admit_build(source, executable, depinfo, target, fx.VERSION, revision, tree,
                                                     fx.RUSTC, (base / "target",))
        self.assertEqual((identity["sha256"], identity["source_tree_sha256"], inputs), (fx.digest(data), tree, 1))
        # Any release cw may embed the one local runtime document (#2733), and
        # only as a verified input that was compiled in.
        with self.assertRaisesRegex(release.ReleaseError, "was not compiled into the executable"):
            release.admit_build(source, executable, depinfo, target, fx.VERSION, revision, tree, fx.RUSTC,
                                (base / "target",), embedded={(base / "local-runtime.json").resolve(): "0" * 64})
        with self.assertRaisesRegex(release.ReleaseError, "at most one local runtime document"):
            release.admit_build(source, executable, depinfo, target, fx.VERSION, revision, tree, fx.RUSTC,
                                (base / "target",), embedded={(base / "a/local-runtime.json").resolve(): "0" * 64,
                                                              (base / "b/local-runtime.json").resolve(): "1" * 64})
        (source / "crates/demo/src/lib.rs").write_text("pub fn mutated() {}\n")
        with self.assertRaisesRegex(release.ReleaseError, "source changed during the build"):
            release.admit_build(source, executable, depinfo, target, fx.VERSION, revision, tree, fx.RUSTC,
                                (base / "target",))

    def test_preparation_refuses_changed_source_and_unpinned_toolchain(self):
        base = self.base / "refuse"
        base.mkdir()
        source, sha = fx.source_repo(base)
        dist, _ = fx.package(base, source, sha)
        with self.assertRaises(release.ReleaseError):
            release.prepare(dist, fx.VERSION, source, sha, sha, fx.RUSTC, source_digest_before="0" * 64)
        shutil.rmtree(dist / release.DELIVERY, ignore_errors=True)
        with self.assertRaises(release.ReleaseError):
            release.prepare(dist, fx.VERSION, source, sha, sha, "rustc 1.94.0 (other)")
        shutil.rmtree(dist / release.DELIVERY, ignore_errors=True)
        with self.assertRaises(release.ReleaseError):
            release.prepare(dist, fx.VERSION, source, "c" * 40, sha, fx.RUSTC)
        shutil.rmtree(dist / release.DELIVERY, ignore_errors=True)
        (dist / "SHA256SUMS").write_text("0" * 64 + "  cw-v0.4.2-x86_64-apple-darwin\n")
        with self.assertRaises(release.ReleaseError):
            release.prepare(dist, fx.VERSION, source, sha, sha, fx.RUSTC)

    # --- transports -----------------------------------------------------------

    def test_raw_oci_and_pack_carry_identical_executable_bytes(self):
        paths = release.delivery_paths(self.dist)
        raw = self.executables[release.RUNTIME_TARGET]
        provenance, payload = release.decode_pack(paths["pack"].read_bytes())
        self.assertEqual(payload, raw)
        receipt = json.loads(paths["image"].read_bytes())
        self.assertEqual(receipt["cw_sha256"], fx.digest(raw))
        self.assertNotEqual(receipt["index_sha256"], receipt["archive_sha256"])
        out = self.base / "unpacked"
        image = self.base / "image.tar"
        image.write_bytes(paths["oci"].read_bytes())
        image.chmod(0o600)
        subprocess.run([sys.executable, str(release.RUNTIME_IMAGE_TOOL), "unpack", "--image", str(image),
                        "--index-sha256", receipt["index_sha256"], "--output", str(out)],
                       check=True, stdout=subprocess.DEVNULL)
        self.assertEqual((out / "cw").read_bytes(), raw)
        self.assertEqual(provenance["payload"]["sha256"], fx.digest(raw))
        result = release.verify_delivery(self.dist, self.signer.trust)
        self.assertEqual(result, {"targets": 4, "version": fx.VERSION, "runtime_equal": True, "signed": True})

    def test_contradictory_transports_and_hashes_are_refused(self):
        def tamper(name, mutate):
            dist = self.copy_dist(name)
            mutate(dist, release.delivery_paths(dist))
            with self.assertRaises((release.ReleaseError, subprocess.CalledProcessError)):
                release.verify_delivery(dist, self.signer.trust)
            shutil.rmtree(dist)

        def flip(path, offset=-1):
            data = bytearray(path.read_bytes())
            data[offset] ^= 1
            path.write_bytes(bytes(data))

        cases = {
            "raw executable": lambda d, p: flip(d / release.asset_name(fx.VERSION, "aarch64-apple-darwin")),
            "runtime pack payload": lambda d, p: flip(p["pack"]),
            "OCI archive": lambda d, p: flip(p["oci"], 600),
            "runtime lock": lambda d, p: p["lock"].write_text(p["lock"].read_text().replace("1", "2", 1)),
            "identity digest": lambda d, p: (p["identities"] / "x86_64-apple-darwin.json").write_bytes(
                (p["identities"] / "x86_64-apple-darwin.json").read_bytes().replace(b'"size":4096', b'"size":4097')),
            "SHA256SUMS": lambda d, p: p["sums"].write_text(p["sums"].read_text()[::-1]),
        }
        for name, mutate in cases.items():
            with self.subTest(name):
                tamper(name.replace(" ", "-"), mutate)

    # --- manifest -----------------------------------------------------------------

    def manifest(self):
        return release.parse_canonical(release.delivery_paths(self.dist)["manifest"].read_bytes())

    def test_manifest_is_closed_and_binds_consistent_objects(self):
        manifest = self.manifest()
        release.validate_manifest(manifest)
        runtime = manifest["targets"][release.RELEASE_TARGETS.index(release.RUNTIME_TARGET)]
        mutations = {
            "extra field": lambda m: m.update(extra=True),
            "missing target": lambda m: m["targets"].pop(0),
            "reordered targets": lambda m: m["targets"].reverse(),
            "identity version": lambda m: m["targets"][0]["identity"].update(package_version="v0.4.3"),
            "executable digest": lambda m: m["targets"][1]["executable"].update(sha256="0" * 64),
            "executable key": lambda m: m["targets"][1]["executable"].update(key="cw/v1/blobs/sha256/" + "1" * 64),
            "oci index equals archive": lambda m: m["targets"][3]["oci"].update(
                index_sha256=m["targets"][3]["oci"]["archive"]["sha256"]),
            "darwin with pack": lambda m: m["targets"][0].update(runtime_pack=runtime["runtime_pack"]),
            "musl without pack": lambda m: m["targets"][3].pop("runtime_pack"),
            "boolean size": lambda m: m["targets"][2]["executable"].update(size=True),
            "lowercase fingerprint": lambda m: m.update(signing_fingerprint=m["signing_fingerprint"].lower()),
            "foreign key prefix": lambda m: m["checksums"]["file"].update(key="other/SHA256SUMS"),
            "package version mismatch": lambda m: m.update(package_version="v0.4.3"),
        }
        for name, mutate in mutations.items():
            value = copy.deepcopy(manifest)
            mutate(value)
            with self.subTest(name), self.assertRaises((release.ReleaseError, KeyError)):
                release.validate_manifest(value)

    def test_manifest_encoding_is_canonical_and_bounded(self):
        data = release.delivery_paths(self.dist)["manifest"].read_bytes()
        for name, bad in {
            "pretty printed": json.dumps(json.loads(data), indent=2).encode(),
            "duplicate key": data.replace(b'{"checksums"', b'{"schema":"x","checksums"', 1),
            "trailing garbage": data + b"{}",
            "oversized": b" " * (release.MAX_JSON + 1),
        }.items():
            with self.subTest(name), self.assertRaises(release.ReleaseError):
                release.parse_canonical(bad)

    # --- signatures and trust -----------------------------------------------------------

    def test_signature_tampering_and_wrong_keys_are_refused(self):
        paths = release.delivery_paths(self.dist)
        manifest = paths["manifest"].read_bytes()
        signature = paths["manifest_sig"].read_bytes()
        release.verify_detached(manifest, signature, self.signer.trust)
        tampered = manifest.replace(b'"release_tag":"v0.4.2"', b'"release_tag":"v0.4.3"')
        with self.assertRaises(release.ReleaseError):
            release.verify_detached(tampered, signature, self.signer.trust)
        with self.assertRaises(release.ReleaseError):
            release.verify_detached(manifest, self.other.sign(manifest), self.signer.trust)
        with self.assertRaises(release.ReleaseError):
            release.verify_detached(manifest, signature, self.other.trust)
        mixed = self.base / "mixed.asc"
        mixed.write_bytes(self.signer.public.read_bytes() + self.other.public.read_bytes())
        with self.assertRaises(release.ReleaseError):
            release.verify_detached(manifest, signature, release.Trust(mixed, self.signer.fingerprint))
        with self.assertRaises(release.ReleaseError):
            release.verify_detached(manifest, b"-----BEGIN PGP SIGNATURE-----\nbad\n", self.signer.trust)

    def test_synthetic_keys_never_satisfy_production_trust(self):
        compiled = (ROOT / "crates/codewire-cli/src/public_fetch.rs").read_text()
        self.assertIn(f'const TRUST_FINGERPRINT: &str = "{release.PRODUCTION_FINGERPRINT}";', compiled)
        self.assertNotEqual(self.signer.fingerprint, release.PRODUCTION_FINGERPRINT)
        with self.assertRaises(release.ReleaseError):
            release.verify_delivery(self.dist, release.PRODUCTION_TRUST)
        with self.assertRaises(release.ReleaseError):
            release.verify_detached(b"x", self.signer.sign(b"x"), release.PRODUCTION_TRUST)
        # The production key file carries exactly the pinned primary key.
        listing = subprocess.check_output(["gpg", "--batch", "--show-keys", "--with-colons",
                                           str(release.PRODUCTION_KEY)], text=True)
        fingerprints = [line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:")]
        self.assertEqual(fingerprints[0], release.PRODUCTION_FINGERPRINT)

    def test_channel_object_is_self_signed_and_closed(self):
        paths = release.delivery_paths(self.dist)
        data = paths["channel"].read_bytes()
        pointer = release.verify_channel(data, self.signer.trust)
        self.assertEqual(pointer["release_tag"], fx.VERSION)
        value = json.loads(data)
        value["pointer"]["release_tag"] = "v0.4.3"
        for name, bad in {
            "retargeted pointer": release.canonical(value),
            "other signer": release.channel_object(pointer, self.other.sign(release.canonical(pointer))),
        }.items():
            with self.subTest(name), self.assertRaises(release.ReleaseError):
                release.verify_channel(bad, self.signer.trust)
        with self.assertRaises(release.ReleaseError):
            release.channel_pointer("beta", b"{}", b"sig", fx.VERSION)

    # --- signing step -------------------------------------------------------------------

    def signing_repo(self, name):
        """A copied script tree whose trust root is the synthetic key, never production."""
        repo = self.base / name
        for relative in ("scripts/ci/release/cw_release.py", "scripts/ci/release/sign-cw-release.sh",
                         "scripts/dev/cw-runtime-image.py"):
            (repo / relative).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, repo / relative)
        module = repo / "scripts/ci/release/cw_release.py"
        text = module.read_text()
        self.assertEqual(text.count(f'PRODUCTION_FINGERPRINT = "{release.PRODUCTION_FINGERPRINT}"'), 1)
        module.write_text(text.replace(release.PRODUCTION_FINGERPRINT, self.signer.fingerprint))
        (repo / "apps/cli").mkdir(parents=True)
        shutil.copy2(self.signer.public, repo / "apps/cli/GPG_PUBLIC_KEY.asc")
        return repo / "scripts/ci/release/sign-cw-release.sh"

    def run_signer(self, script, dist, key_id=None):
        env = {"PATH": os.environ["PATH"], "HOME": str(self.base), "LC_ALL": "C",
               "CW_RELEASE_GPG_PRIVATE_KEY": self.signer.secret_key(),
               "CW_RELEASE_GPG_KEY_ID": key_id or self.signer.fingerprint}
        return subprocess.run(["bash", str(script), str(dist)], env=env, capture_output=True, text=True, timeout=120)

    def test_real_signer_refuses_a_synthetic_key_before_signing(self):
        base = self.base / "real-signer"
        base.mkdir()
        dist, _, _ = fx.unsigned_delivery(base)
        result = self.run_signer(ROOT / "scripts/ci/release/sign-cw-release.sh", dist)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("signing key is not the admitted release key", result.stderr)
        self.assertFalse((dist / "SHA256SUMS.asc").exists())
        self.assertNotIn(self.signer.secret_key().splitlines()[2], result.stdout + result.stderr)

    def test_signer_signs_fresh_and_retains_published_signatures(self):
        script = self.signing_repo("signing-repo")
        base = self.base / "fresh-signer"
        base.mkdir()
        dist, _, _ = fx.unsigned_delivery(base)
        result = self.run_signer(script, dist)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("signed mode=fresh", result.stdout)
        self.assertTrue(release.verify_delivery(dist, self.signer.trust)["signed"])
        again = self.run_signer(script, dist)
        self.assertNotEqual(again.returncode, 0)
        self.assertIn("a channel pointer is already signed", again.stderr)
        # Retained: an already-signed release gets only a new channel signature.
        paths = release.delivery_paths(dist)
        kept = {name: paths[name].read_bytes() for name in ("sums_sig", "manifest", "manifest_sig")}
        paths["pointer"].unlink()
        paths["channel"].unlink()
        retained = self.run_signer(script, dist)
        self.assertEqual(retained.returncode, 0, retained.stderr)
        self.assertIn("signed mode=retained", retained.stdout)
        self.assertEqual({name: paths[name].read_bytes() for name in kept}, kept)
        # A partially signed delivery is never completed by re-signing.
        partial_base = self.base / "partial-signer"
        partial_base.mkdir()
        partial, _, _ = fx.unsigned_delivery(partial_base)
        (partial / "SHA256SUMS.asc").write_bytes(self.signer.sign((partial / "SHA256SUMS").read_bytes()))
        result = self.run_signer(script, partial)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("partially signed", result.stderr)

    def test_tree_digest_binds_every_file(self):
        before = release.tree_digest(self.dist)
        dist = self.copy_dist("digest-copy")
        self.assertEqual(release.tree_digest(dist), before)
        # Artifact transfer drops modes; content and paths stay bound.
        executable = dist / release.asset_name(fx.VERSION, "x86_64-apple-darwin")
        executable.chmod(0o644)
        self.assertEqual(release.tree_digest(dist), before)
        executable.write_bytes(executable.read_bytes() + b"x")
        self.assertNotEqual(release.tree_digest(dist), before)
        executable.write_bytes(executable.read_bytes()[:-1])
        (dist / "extra").write_text("x")
        self.assertNotEqual(release.tree_digest(dist), before)
        shutil.rmtree(dist)


class SourceDigestTest(unittest.TestCase):
    """Compiled input policy uses only a disposable source tree."""

    @classmethod
    def setUpClass(cls):
        cls.base = fx.scratch("cw-source-digest.")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.base)

    depinfo = DeliveryTest.depinfo

    def test_source_digest_covers_every_compiled_input_kind(self):
        source, _ = fx.source_repo(self.base / "digest")
        spec = importlib.util.spec_from_file_location(
            "build_native_managed_agent", ROOT / "scripts/dev/build-native-managed-agent.py")
        native = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(native)
        self.assertIs(native.release, release, "the native producer must use the shared identity producer")
        inputs = {
            "crates/codewire-mesh/migrations/001_initial_schema.sql": "create table mesh(id int);\n",
            "crates/codewire-server-core/migrations/0001_init.sql": "create table core(id int);\n",
            "crates/codewire-proto/codewire_descriptor.bin": "descriptor\n",
            "crates/codewire-credential-broker/src/ssh_agent/askpass.sh": "#!/bin/sh\n",
            "scripts/ci/verify/kind/cw_runtime_probe.py": "print('embedded observer')\n",
        }
        for name, text in inputs.items():
            (source / name).parent.mkdir(parents=True, exist_ok=True)
            (source / name).write_text(text)
        before = release.source_tree_sha256(source)
        for name in [*inputs, "crates/demo/src/lib.rs", "Cargo.lock", "crates/demo/demo.proto"]:
            with self.subTest(name):
                path = source / name
                original = path.read_bytes()
                path.write_bytes(original + b"-- changed\n")
                self.assertNotEqual(release.source_tree_sha256(source), before)
                path.write_bytes(original)
                self.assertEqual(release.source_tree_sha256(source), before)
        (source / "README.md").write_text("still not an input\n")
        self.assertEqual(release.source_tree_sha256(source), before)


    def test_native_managed_build_falls_back_to_zigbuild_without_a_musl_gcc(self):
        spec = importlib.util.spec_from_file_location(
            "build_native_managed_agent", ROOT / "scripts/dev/build-native-managed-agent.py")
        native = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(native)
        tools = self.base / "compiler-route"
        tools.mkdir()
        home = self.base / "compiler-route-home"

        def provide(*names):
            for entry in tools.iterdir():
                entry.unlink()
            for name in names:
                (tools / name).write_text("#!/bin/sh\nexit 0\n")
                (tools / name).chmod(0o700)

        path = str(tools)
        for target, gcc in ((release.RUNTIME_TARGET, "x86_64-linux-musl-gcc"),
                            ("aarch64-unknown-linux-musl", "aarch64-linux-musl-gcc")):
            with self.subTest(target=target, route="musl gcc"):
                provide(gcc, "cargo-zigbuild", "zig")
                self.assertEqual(native.compiler_route(target, path, home), (
                    ["build"], {"RUSTFLAGS": "-C linker=rust-lld -C target-feature=+crt-static"}))
            with self.subTest(target=target, route="zigbuild"):
                provide("cargo-zigbuild", "zig")
                self.assertEqual(native.compiler_route(target, path, home),
                                 (["zigbuild"], {"HOME": str(home)}))
            for present in (("zig",), ("cargo-zigbuild",), ()):
                with self.subTest(target=target, present=present):
                    provide(*present)
                    with self.assertRaisesRegex(RuntimeError, f"needs {gcc}, or cargo-zigbuild and zig"):
                        native.compiler_route(target, path, home)

    def test_native_managed_build_reuses_one_public_cargo_home_per_target(self):
        spec = importlib.util.spec_from_file_location(
            "build_native_managed_agent", ROOT / "scripts/dev/build-native-managed-agent.py")
        native = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(native)
        cache = self.base / "public-cargo-cache"
        (cache / "registry").mkdir(parents=True)
        (cache / "git").mkdir()
        target = self.base / "public-cargo-target"
        home = native.public_cargo_home(target, cache)
        self.assertEqual(home, target / "native-managed-agent-cargo-home")
        self.assertEqual({entry.name: os.readlink(entry) for entry in home.iterdir()},
                         {"registry": str(cache / "registry"), "git": str(cache / "git")})
        # Cargo's own lock and cache-tracking files are kept; the path is reused.
        for name in native.CARGO_BOOKKEEPING:
            (home / name).write_bytes(b"")
        self.assertEqual(native.public_cargo_home(target, cache), home)
        for name, make in (("config.toml", lambda path: path.write_text("[build]\n")),
                           ("credentials.toml", lambda path: path.write_text("")),
                           ("bin", lambda path: path.mkdir())):
            with self.subTest(name):
                make(home / name)
                with self.assertRaisesRegex(RuntimeError, "not this build's public Cargo home"):
                    native.public_cargo_home(target, cache)
                (shutil.rmtree if (home / name).is_dir() else os.unlink)(home / name)
        other = self.base / "other-cargo-cache"
        (other / "registry").mkdir(parents=True)
        (other / "git").mkdir()
        with self.assertRaisesRegex(RuntimeError, "not this build's public Cargo home"):
            native.public_cargo_home(target, other)
        os.unlink(home / ".global-cache")
        os.symlink(cache, home / ".global-cache")
        with self.assertRaisesRegex(RuntimeError, "not this build's public Cargo home"):
            native.public_cargo_home(target, cache)

    def test_compiled_inputs_must_all_be_in_the_source_digest(self):
        base = self.base / "depinfo"
        base.mkdir()
        source, _ = fx.source_repo(base)
        target, cargo = base / "target", base / "cargo home"
        (cargo / "registry/src").mkdir(parents=True)
        (target / "out").mkdir(parents=True)
        (source / "crates/demo/odd name.sql").write_text("select 1;\n")
        (source / "crates/demo/schema.sql").write_text("select 2;\n")
        covered = [source / "crates/demo/src/lib.rs", source / "Cargo.lock", target / "out/generated.rs",
                   cargo / "registry/src/dependency.rs"]
        self.assertEqual(release.check_build_inputs(source, self.depinfo(base, covered), (target, cargo)), 2)
        for name, extra in {
            "undigested repository file": source / "crates/demo/schema.sql",
            "undigested path with a space": source / "crates/demo/odd name.sql",
            "file outside the repository": Path("/etc/hostname"),
        }.items():
            with self.subTest(name), self.assertRaises(release.ReleaseError):
                release.check_build_inputs(source, self.depinfo(base, [*covered, extra]), (target, cargo))
        with self.assertRaises(release.ReleaseError):
            release.check_build_inputs(source, self.depinfo(base, [target / "out/generated.rs"]), (target, cargo))


    def test_only_the_verified_runtime_document_is_admitted_outside_the_repository(self):
        base = self.base / "embedded-runtime-document"
        base.mkdir()
        source, _ = fx.source_repo(base)
        target, cargo = base / "target", base / "cargo home"
        (target / "out").mkdir(parents=True)
        (cargo / "registry/src").mkdir(parents=True)
        runtime = (base / "runtime").resolve()
        (runtime / "blobs/sha256").mkdir(parents=True)
        document = runtime / release.LOCAL_RUNTIME_NAME
        document.write_bytes(b'{"schema":"codewire.cw.local-runtime/v1"}')
        sibling = runtime / "blobs/sha256" / ("a" * 64)
        sibling.write_bytes(b"blob")
        digest = hashlib.sha256(document.read_bytes()).hexdigest()
        lib = source / "crates/demo/src/lib.rs"
        verified = {document: digest}
        # Before this change admission refused the document. It still does
        # without the verified digest.
        with self.assertRaisesRegex(release.ReleaseError, "outside the repository"):
            release.check_build_inputs(source, self.depinfo(base, [lib, document]), (target, cargo))
        self.assertEqual(release.check_build_inputs(source, self.depinfo(base, [lib, document]), (target, cargo),
                                                    verified), 1)
        alias = base / "runtime-alias"
        alias.symlink_to(runtime)
        for name, paths, embedded, reason in (
                ("sibling file in the runtime directory", [lib, document, sibling], verified, "outside the repository"),
                ("other outside path", [lib, document, Path("/etc/hostname")], verified, "outside the repository"),
                ("verified document not compiled in", [lib], verified, "was not compiled"),
                ("document reached through a symlink", [lib, alias / release.LOCAL_RUNTIME_NAME],
                 {alias / release.LOCAL_RUNTIME_NAME: digest}, "canonical"),
                ("document with another digest", [lib, document], {document: "0" * 64}, "changed after it was verified")):
            with self.subTest(name), self.assertRaisesRegex(release.ReleaseError, reason):
                release.check_build_inputs(source, self.depinfo(base, paths), (target, cargo), embedded)
        document.write_bytes(b'{"schema":"codewire.cw.local-runtime/v1","changed":true}')
        with self.assertRaisesRegex(release.ReleaseError, "changed after it was verified"):
            release.check_build_inputs(source, self.depinfo(base, [lib, document]), (target, cargo), verified)

    def test_embedded_runtime_probe_is_digested_and_admitted_without_other_python(self):
        base = self.base / "embedded-runtime-probe"
        base.mkdir()
        source, _ = fx.source_repo(base)
        relative = "scripts/ci/verify/kind/cw_runtime_probe.py"
        probe = source / relative
        probe.parent.mkdir(parents=True)
        probe.write_text("print('embedded observer')\n")
        other = probe.with_name("unrelated_probe.py")
        other.write_text("print('not compiled')\n")
        depinfo = self.depinfo(base, [source / "crates/demo/src/lib.rs", probe])
        before = release.source_tree_sha256(source)
        self.assertEqual(release.check_build_inputs(source, depinfo, (base / "target",)), 2)
        original = probe.read_bytes()
        probe.write_bytes(original + b"# changed compiled input\n")
        self.assertNotEqual(release.source_tree_sha256(source), before)
        probe.write_bytes(original)
        self.assertEqual(release.source_tree_sha256(source), before)

        # The previous policy could not admit this embedded non-Rust input.
        legacy = tuple(name for name in release.SOURCE_PATHSPEC if name != relative)
        with mock.patch.object(release, "SOURCE_PATHSPEC", legacy):
            legacy_digest = release.source_tree_sha256(source)
            probe.write_bytes(original + b"# invisible to the previous policy\n")
            self.assertEqual(release.source_tree_sha256(source), legacy_digest)
            with self.assertRaisesRegex(release.ReleaseError, "compiled inputs missing from the source digest"):
                release.check_build_inputs(source, depinfo, (base / "target",))
        probe.write_bytes(original)
        self.assertEqual(release.source_tree_sha256(source), before)

        # Admission is limited to the one embedded probe, not every Python file.
        other.write_text("print('still not compiled')\n")
        self.assertEqual(release.source_tree_sha256(source), before)
        with self.assertRaisesRegex(release.ReleaseError, "compiled inputs missing from the source digest"):
            release.check_build_inputs(source, self.depinfo(base, [probe, other]), (base / "target",))




class LocalRuntimeTest(unittest.TestCase):
    """The local VM runtime every release cw embeds (#2539, #2733)."""

    FIXTURES = ROOT / "crates/codewire-cw-release/src/local_runtime/fixtures"

    @classmethod
    def setUpClass(cls):
        cls.base = fx.scratch("cw-release-runtime.")
        cls.signer = fx.Signer(cls.base)
        (cls.base / "signed").mkdir()
        cls.dist = fx.signed_delivery(cls.base / "signed", cls.signer, runtime=True)[0]
        (cls.base / "plain").mkdir()
        cls.plain = fx.unsigned_delivery(cls.base / "plain")[0]

    @classmethod
    def tearDownClass(cls):
        cls.signer.close()
        shutil.rmtree(cls.base)

    def copy(self, dist, label=""):
        target = self.base / f"{self.id().rsplit('.', 1)[-1]}{label}"
        shutil.copytree(dist, target, symlinks=True)
        return target

    def test_shared_fixtures_agree_with_the_rust_decoder(self):
        # crates/codewire-cw-release/src/local_runtime/tests.rs decodes the same files.
        valid = (self.FIXTURES / "valid-macos-aarch64.json").read_bytes()
        self.assertEqual(len(release.local_runtime_blobs(valid)), 14)
        invalid = sorted(self.FIXTURES.glob("invalid-*.json"))
        self.assertEqual(len(invalid), 21)
        for path in invalid:
            with self.subTest(fixture=path.name), self.assertRaises(release.ReleaseError):
                release.local_runtime_blobs(path.read_bytes())

    def test_a_delivery_carries_exactly_the_runtime_every_cw_embeds(self):
        result = release.verify_delivery(self.dist, self.signer.trust)
        document = release.local_runtime_paths(self.dist)[1].read_bytes()
        self.assertTrue(result["signed"])
        self.assertEqual(result["local_runtime"], {"document_sha256": fx.digest(document), "blobs": 21})
        self.assertEqual(sorted(json.loads(document)["targets"]), ["linux-x86_64", "macos-aarch64"])
        for target in release.RELEASE_TARGETS:
            with self.subTest(target=target):
                data = (self.dist / release.asset_name(fx.VERSION, target)).read_bytes()
                self.assertEqual(release.embedded_local_runtime(data), document)
        self.assertNotIn("local_runtime", release.verify_delivery(self.plain))

    def check(self, dist, embedded=None):
        """check_local_runtime over this delivery's identities, with every cw
        rebuilt to embed `embedded` (by default the delivery's document)."""
        document = release.local_runtime_paths(dist)[1].read_bytes()
        identities = {target: json.loads((release.delivery_paths(dist)["identities"] / f"{target}.json").read_bytes())
                      for target in release.RELEASE_TARGETS}
        executables = {target: fx.executable(target, revision=identity["source_revision"],
                                             tree=identity["source_tree_sha256"],
                                             embedded=(embedded or {}).get(target, document))
                       for target, identity in identities.items()}
        return release.check_local_runtime(dist, executables, identities)

    def test_every_release_cw_embeds_the_document(self):
        self.assertIsNotNone(self.check(self.dist))
        revision = json.loads(release.local_runtime_paths(self.dist)[1].read_bytes())["source_revision"]
        for name, other in (("none", b""), ("another", fx.local_runtime(revision, version="v0.4.3")[0])):
            with self.subTest(embedded=name), self.assertRaisesRegex(
                    release.ReleaseError, r"every release cw must embed .*'aarch64-unknown-linux-gnu'"):
                self.check(self.dist, {"aarch64-unknown-linux-gnu": other})

    def runtime_with(self, dist, platform, change):
        """Rewrite one target of the delivery's runtime; `change` edits it and returns new blobs."""
        document_path, blobs = release.local_runtime_paths(dist)[1:]
        document = json.loads(document_path.read_bytes())
        before = {digest for digest, _ in release.local_runtime_blobs(document_path.read_bytes())}
        added = change(document["targets"][platform])
        for data in added:
            (blobs / fx.digest(data)).write_bytes(data)
        data = release.canonical(document)
        after = {digest for digest, _ in release.local_runtime_blobs(data)}
        for digest in before - after:
            (blobs / digest).unlink()
        document_path.write_bytes(data)
        return data

    def test_the_linux_target_runs_only_static_executables_and_a_bzimage(self):
        def swap(key, data):
            def change(target):
                target["lock"][key].update(sha256=fx.digest(data), size=len(data))
                return [data]
            return change

        for name, key, data, reason in (
            ("dynamic Cloud Hypervisor", "cloud_hypervisor",
             fx.executable("x86_64-unknown-linux-musl", static=False, tag=b"ch"), "cloud_hypervisor is not a static"),
            ("arm64 virtiofsd", "virtiofsd", fx.executable("aarch64-unknown-linux-musl", tag=b"fs"),
             "virtiofsd is not a static x86_64"),
            ("not a bzImage", "kernel", b"\0" * 4096, "not an x86 bzImage"),
        ):
            with self.subTest(case=name):
                dist = self.copy(self.dist, "-" + name.replace(" ", "-"))
                self.runtime_with(dist, "linux-x86_64", swap(key, data))
                with self.assertRaisesRegex(release.ReleaseError, reason):
                    self.check(dist)

    def test_each_cw_runtime_holds_a_guest_cw_of_this_release(self):
        revision = json.loads(release.local_runtime_paths(self.dist)[1].read_bytes())["source_revision"]
        x86 = "x86_64-unknown-linux-musl"
        # A released cw is never a guest cw: every released cw embeds the
        # document, and a guest cw that embeds one is refused below.
        cases = (
            ("another target", fx.cw_runtime(x86, revision, payload=fx.executable(
                "aarch64-unknown-linux-musl", revision=revision)), "provenance does not bind|is not a x86_64"),
            ("another revision", fx.cw_runtime(x86, "e" * 40), "provenance does not bind"),
            ("another version", fx.cw_runtime(x86, revision, version="v0.4.3"), "is version v0.4.3"),
            ("dynamic", fx.cw_runtime(x86, revision, payload=fx.executable(x86, static=False, revision=revision)),
             "dynamic interpreter"),
            ("embeds a runtime", fx.cw_runtime(x86, revision, payload=fx.executable(
                x86, revision=revision, embedded=fx.local_runtime(revision)[0])), "embeds a local runtime"),
        )
        for name, (lock, pack), reason in cases:
            def change(target, lock=lock, pack=pack):
                target["cw_runtime"] = {"lock": {"sha256": fx.digest(lock), "size": len(lock)},
                                        "pack": {"sha256": fx.digest(pack), "size": len(pack)}}
                return [lock, pack]

            with self.subTest(case=name):
                dist = self.copy(self.dist, "-" + name.replace(" ", "-"))
                self.runtime_with(dist, "linux-x86_64", change)
                with self.assertRaisesRegex(release.ReleaseError, reason):
                    self.check(dist)

    def test_runtimes_merge_into_one_document_of_disjoint_targets(self):
        revision = "a" * 40
        document, files = fx.local_runtime(revision)
        value = json.loads(document)
        parts = []
        for platform in ("macos-aarch64", "linux-x86_64"):
            part = release.canonical({"schema": release.LOCAL_RUNTIME_SCHEMA, "source_revision": revision,
                                      "targets": {platform: value["targets"][platform]}})
            directory = self.base / f"merge-{self.id().rsplit('.', 1)[-1]}-{platform}"
            (directory / "blobs/sha256").mkdir(parents=True)
            (directory / "local-runtime.json").write_bytes(part)
            for digest, _size in release.local_runtime_blobs(part):
                (directory / "blobs/sha256" / digest).write_bytes(files[digest])
            parts.append(directory)
        output = self.base / "merged-runtime"
        merged, pinned = release.merge_local_runtimes(output, parts)
        self.assertEqual(merged, document)
        self.assertEqual(len(pinned), 21)
        self.assertEqual(release.load_local_runtime_dir(output)[0], document)
        with self.assertRaisesRegex(release.ReleaseError, "in more than one input"):
            release.merge_local_runtimes(self.base / "merged-twice", [parts[0], parts[0]])
        other = self.base / "merge-other-revision"
        shutil.copytree(parts[1], other)
        changed = json.loads((other / "local-runtime.json").read_bytes())
        changed["source_revision"] = "d" * 40
        (other / "local-runtime.json").write_bytes(release.canonical(changed))
        with self.assertRaisesRegex(release.ReleaseError, "different source revisions"):
            release.merge_local_runtimes(self.base / "merged-revisions", [parts[0], other])

    def test_a_cw_that_embeds_a_runtime_is_never_released_without_it(self):
        dist = self.copy(self.dist)
        shutil.rmtree(release.local_runtime_paths(dist)[0])
        with self.assertRaisesRegex(release.ReleaseError, "does not carry"):
            release.verify_delivery(dist)

    def test_a_runtime_no_cw_embeds_is_refused(self):
        dist = self.copy(self.plain)
        identity = json.loads((release.delivery_paths(dist)["identities"] / "aarch64-apple-darwin.json").read_bytes())
        fx.write_local_runtime(dist, *fx.local_runtime(identity["source_revision"]))
        with self.assertRaisesRegex(release.ReleaseError, "must embed"):
            release.verify_delivery(dist)

    def test_runtime_files_are_exactly_the_pinned_blobs(self):
        def extra(blobs):
            (blobs / ("f" * 64)).write_bytes(b"unpinned\n")

        def missing(blobs):
            next(blobs.iterdir()).unlink()

        def changed(blobs):
            path = next(blobs.iterdir())
            path.write_bytes(path.read_bytes() + b"\n")

        def linked(blobs):
            path = next(blobs.iterdir())
            data = path.read_bytes()
            path.unlink()
            (blobs.parent / "held").write_bytes(data)
            path.symlink_to(blobs.parent / "held")

        def stray(blobs):
            (blobs.parents[1] / "notes.txt").write_bytes(b"stray\n")

        for mutate in (extra, missing, changed, linked, stray):
            with self.subTest(case=mutate.__name__):
                dist = self.copy(self.dist, f"-{mutate.__name__}")
                mutate(release.local_runtime_paths(dist)[2])
                with self.assertRaises(release.ReleaseError):
                    release.verify_delivery(dist)

    def test_the_embedded_document_occurs_once_and_whole(self):
        document = release.local_runtime_paths(self.dist)[1].read_bytes()
        self.assertIsNone(release.embedded_local_runtime(b"\0" * 64))
        self.assertEqual(release.embedded_local_runtime(b"head" + document + b"tail"), document)
        for name, data in (("twice", document + document), ("truncated", document[:-1]),
                           ("invalid", document.replace(b'"schema_version":1', b'"schema_version":2'))):
            with self.subTest(case=name), self.assertRaises(release.ReleaseError):
                release.embedded_local_runtime(data)

    def test_the_helper_is_rechecked_without_macos(self):
        release.check_macos_helper(fx.macos_helper())
        networking = release.HELPER_ENTITLEMENTS.read_bytes().replace(
            b"</dict>", b"<key>com.apple.vm.networking</key><true/></dict>")
        cases = {
            "x86_64": fx.macos_helper(cpu=0x01000007),
            "no hardened runtime": fx.macos_helper(runtime=False),
            "another entitlement": fx.macos_helper(entitlements=networking),
            "homebrew library": fx.macos_helper(libraries=fx.HELPER_LIBRARIES + ("/opt/homebrew/lib/libz.dylib",)),
            "rpath library": fx.macos_helper(libraries=("@rpath/libswiftCore.dylib",)),
            "homebrew search path": fx.macos_helper(rpaths=("@loader_path", "/opt/homebrew/lib")),
            "escaping path": fx.macos_helper(libraries=("/usr/lib/../../tmp/x.dylib",)),
            "unsigned": fx.macos_helper(signed=False),
            "fat": b"\xca\xfe\xba\xbe" + fx.macos_helper()[4:],
        }
        for label, data in cases.items():
            with self.subTest(case=label), self.assertRaises(release.ReleaseError):
                release.check_macos_helper(data)

    def test_a_delivery_whose_helper_fails_its_recheck_is_refused(self):
        dist = self.copy(self.dist)
        document_path, blobs = release.local_runtime_paths(dist)[1:]
        document = json.loads(document_path.read_bytes())
        lock = document["targets"]["macos-aarch64"]["lock"]
        bad = fx.macos_helper(runtime=False)
        (blobs / lock["vz_runner"]["sha256"]).unlink()
        (blobs / fx.digest(bad)).write_bytes(bad)
        lock["vz_runner"].update(sha256=fx.digest(bad), size=len(bad))
        document_path.write_bytes(release.canonical(document))
        with self.assertRaisesRegex(release.ReleaseError, "hardened runtime"):
            release.load_local_runtime(dist)
            release.check_macos_helper(bad)
        with self.assertRaises(release.ReleaseError):
            release.verify_delivery(dist)

    def test_the_runtime_comes_from_the_cw_source_revision(self):
        original = fx.local_runtime
        with mock.patch.object(fx, "local_runtime", lambda revision: original("d" * 40)):
            (self.base / "other-revision").mkdir()
            dist = fx.unsigned_delivery(self.base / "other-revision", runtime=True)[0]
        with self.assertRaisesRegex(release.ReleaseError, "source revision"):
            release.verify_delivery(dist)

if __name__ == "__main__":
    if sys.platform != "linux":
        raise SystemExit("release delivery process fixtures require Linux custody")
    spec = importlib.util.spec_from_file_location(
        "delivery_fixture_custody", ROOT / "scripts/ci/verify/build-linux-vmm-kernel.py")
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
                    raise RuntimeError("release delivery fixture cleanup did not reach ECHILD")
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

    result = unittest.main(argv=[sys.argv[0], "-v"], exit=False, testRunner=FixtureRunner).result
    print(f"test-cw-release-delivery: tests={result.testsRun} failures={len(result.failures)} "
          f"errors={len(result.errors)}")
    sys.exit(0 if result.wasSuccessful() and result.testsRun > 0 else 1)
