#!/usr/bin/env python3
"""Synthetic proof for the Nix flake's release pin (docs/dev/CLI-NIX-INSTALL.md).

A signed delivery is published to FakeR2 (cw_release_fixtures) and read back
through its public origin, as the release step reads releases.codewire.sh.
Nothing here opens a network connection.
"""

import contextlib
import io
import json
import shutil
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cw_release_fixtures as fx  # noqa: E402

release = fx.release
sys.path.insert(0, str(fx.ROOT / "scripts/ci/release"))
import cw_release_r2 as r2  # noqa: E402
import nix_release_pin as nix  # noqa: E402


class NixReleasePinTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = fx.scratch("nix-release-pin.")
        cls.signer = fx.Signer(cls.base)
        cls.deliveries = {}
        for name, version in (("old", "v0.4.1"), ("new", fx.VERSION)):
            (cls.base / name).mkdir()
            cls.deliveries[name] = fx.signed_delivery(cls.base / name, cls.signer, version)[0]

    @classmethod
    def tearDownClass(cls):
        cls.signer.close()
        shutil.rmtree(cls.base)

    def setUp(self):
        self.fake = fx.FakeR2()
        self.s3 = r2.S3(self.fake, r2.Credentials(fx.ACCESS_KEY, fx.SECRET_KEY))
        self.origin = r2.PublicOrigin(self.fake)
        self.trust = self.signer.trust
        self.work = self.base / f"work-{self.id().rsplit('.', 1)[-1]}"
        self.work.mkdir()
        self.pin = self.work / "release.json"
        self.report = self.work / "report.md"
        self.sums = self.work / "SHA256SUMS"
        self.sums_sig = self.work / "SHA256SUMS.asc"

    def publish(self, name, promote="stable"):
        with _Quiet():
            r2.publish(self.s3, self.origin, self.deliveries[name], self.trust, promote)

    def render(self, version=fx.VERSION):
        with _Quiet():
            return nix.render(self.origin, version, self.trust, self.pin, self.report, self.sums, self.sums_sig,
                              sleep=lambda _: None)

    def check(self, blobs=False):
        with _Quiet():
            nix.check(self.origin, self.pin, self.trust, blobs)

    def manifest(self, name="new"):
        return json.loads(release.delivery_paths(self.deliveries[name])["manifest"].read_bytes())

    def test_render_writes_each_systems_signed_executable(self):
        self.publish("new")
        self.assertTrue(self.render())
        pin = json.loads(self.pin.read_bytes())
        self.assertEqual((pin["schema"], pin["release_tag"]), (nix.PIN_SCHEMA, fx.VERSION))
        executables = {entry["target"]: entry["executable"] for entry in self.manifest()["targets"]}
        self.assertEqual(pin["targets"], {
            system: {"target": target, "sha256": executables[target]["sha256"],
                     "size": executables[target]["size"]}
            for system, target in sorted(nix.SYSTEMS.items())})
        self.assertEqual(list(pin["targets"]), sorted(nix.SYSTEMS))
        self.assertTrue(self.pin.read_bytes().endswith(b"}\n"))

    def test_the_report_is_the_recomputation_with_an_exact_match_per_system(self):
        self.publish("new")
        self.render()
        text = self.report.read_text()
        self.assertEqual(text.count("| exact match |"), 4)
        for system, entry in json.loads(self.pin.read_bytes())["targets"].items():
            self.assertIn(f"| `{system}` | `{release.asset_name(fx.VERSION, entry['target'])}` | "
                          f"`{entry['sha256']}` | `{entry['sha256']}` | exact match |", text)
        self.assertIn("changes only `nix/release.json`", text)

    def test_a_rendered_pin_checks_and_its_blobs_are_served(self):
        self.publish("new")
        self.render()
        paths = release.delivery_paths(self.deliveries["new"])
        self.assertEqual(self.sums.read_bytes(), paths["sums"].read_bytes())
        self.assertEqual(self.sums_sig.read_bytes(), paths["sums_sig"].read_bytes())
        self.check(blobs=True)

    def test_checksums_that_are_not_the_signed_releases_fail_the_check(self):
        self.publish("new")
        self.render()
        self.sums_sig.write_bytes(self.sums_sig.read_bytes() + b"\n")
        with self.assertRaisesRegex(nix.PinError, "SHA256SUMS and its signature are not"):
            self.check()

    def test_a_pin_that_differs_from_the_signed_release_fails_the_check(self):
        self.publish("new")
        self.render()
        pin = json.loads(self.pin.read_bytes())
        entry = pin["targets"]["x86_64-linux"]
        entry["sha256"] = ("0" if entry["sha256"][0] != "0" else "1") + entry["sha256"][1:]
        self.pin.write_bytes(nix.pin_bytes(pin))
        with self.assertRaisesRegex(nix.PinError, "is not the pin of the signed release"):
            self.check()

    def test_a_pin_in_another_layout_fails_the_check(self):
        self.publish("new")
        self.render()
        self.pin.write_text(json.dumps(json.loads(self.pin.read_bytes())) + "\n")
        with self.assertRaisesRegex(nix.PinError, "is not the pin of the signed release"):
            self.check()

    def test_a_served_executable_with_other_bytes_fails_the_blob_check(self):
        self.publish("new")
        self.render()
        entry = json.loads(self.pin.read_bytes())["targets"]["aarch64-darwin"]
        self.fake.store(release.blob_key(entry["sha256"]), b"not the release")
        with self.assertRaisesRegex(nix.PinError, "aarch64-darwin: the served executable"):
            self.check(blobs=True)

    def test_a_channel_already_on_a_newer_release_writes_nothing(self):
        self.publish("old", promote=None)
        self.publish("new")
        self.assertFalse(self.render("v0.4.1"))
        self.assertFalse(self.pin.exists())
        self.assertFalse(self.report.exists())
        self.assertFalse(self.sums.exists())

    def test_a_release_the_channel_does_not_name_yet_is_refused(self):
        self.publish("old")
        self.publish("new", promote=None)
        with self.assertRaises(r2.PublishError):
            self.render()
        self.assertFalse(self.pin.exists())

    def test_an_executable_sha256sums_does_not_list_is_refused(self):
        manifest = self.manifest()
        sums = release.delivery_paths(self.deliveries["new"])["sums"].read_bytes()
        nix.pin_from(manifest, sums)
        other = manifest["targets"][0]
        other["executable"] = dict(other["executable"], sha256="f" * 64)
        with self.assertRaisesRegex(nix.PinError, "not the one SHA256SUMS lists"):
            nix.pin_from(manifest, sums)

    def test_sha256sums_must_list_exactly_the_four_assets(self):
        manifest = self.manifest()
        sums = release.delivery_paths(self.deliveries["new"])["sums"].read_bytes()
        with self.assertRaisesRegex(nix.PinError, "exactly the four release assets"):
            nix.pin_from(manifest, b"".join(sums.splitlines(keepends=True)[:3]))
        with self.assertRaisesRegex(nix.PinError, "twice"):
            nix.pin_from(manifest, sums + sums.splitlines(keepends=True)[0])
        with self.assertRaisesRegex(nix.PinError, "malformed"):
            nix.pin_from(manifest, sums + b"not a line\n")

    # --- the offline proof the Supply-chain scan runs from protected base ---------------

    def tree(self, name, delivery="new", key=b"release key\n", fingerprint=None, pin=None, sums=True):
        """A tree holding a release key, the fingerprint line cw_release.py
        carries, and (unless delivery is None) that delivery's pin and signed
        checksums."""
        root = self.work / name
        (root / "nix").mkdir(parents=True)
        (root / "apps/cli").mkdir(parents=True)
        (root / "scripts/ci/release").mkdir(parents=True)
        (root / nix.KEY_FILE).write_bytes(key)
        (root / nix.FINGERPRINT_FILE).write_text(
            f'PRODUCTION_FINGERPRINT = "{fingerprint or self.trust.fingerprint}"\n')
        if delivery is not None:
            paths = release.delivery_paths(self.deliveries[delivery])
            manifest = json.loads(paths["manifest"].read_bytes())
            sums_bytes = paths["sums"].read_bytes()
            (root / "nix/release.json").write_bytes(pin or nix.pin_bytes(nix.pin_from(manifest, sums_bytes)))
            if sums:
                (root / "nix/SHA256SUMS").write_bytes(sums_bytes)
                (root / "nix/SHA256SUMS.asc").write_bytes(paths["sums_sig"].read_bytes())
        return root

    def verify(self, base, candidate):
        with _Quiet():
            return nix.verify(base, candidate, self.trust)

    def test_a_signed_pin_is_proved_offline(self):
        self.assertTrue(self.verify(self.tree("base", delivery=None), self.tree("candidate")))
        self.assertTrue(self.verify(self.tree("older", delivery="old"), self.tree("newer")))

    def test_a_pin_and_key_the_base_already_has_are_not_checked(self):
        self.assertFalse(self.verify(self.tree("base"), self.tree("candidate")))

    def test_a_pinned_hash_that_is_not_the_signed_one_is_refused(self):
        pin = json.loads(nix.pin_bytes(nix.pin_from(self.manifest(), release.delivery_paths(
            self.deliveries["new"])["sums"].read_bytes())))
        pin["targets"]["aarch64-linux"]["sha256"] = "e" * 64
        with self.assertRaisesRegex(nix.PinError, "aarch64-linux: e{64} is not the signed hash"):
            self.verify(self.tree("base", delivery=None), self.tree("candidate", pin=nix.pin_bytes(pin)))

    def test_checksums_another_key_signed_are_refused(self):
        candidate = self.tree("candidate")
        # A short home, like the class's signer: gpg-agent's socket lives in
        # it where no /run/user directory exists, and a long path is refused.
        home = fx.scratch("nix-other.")
        other = fx.Signer(home, name="Not the release key")
        try:
            (candidate / "nix/SHA256SUMS.asc").write_bytes(other.sign((candidate / "nix/SHA256SUMS").read_bytes()))
        finally:
            other.close()
            shutil.rmtree(home)
        with self.assertRaises(release.ReleaseError):
            self.verify(self.tree("base", delivery=None), candidate)

    def test_a_pull_request_may_not_change_the_key_with_the_pin(self):
        base = self.tree("base", delivery=None)
        with self.assertRaisesRegex(nix.PinError, "may not change apps/cli/GPG_PUBLIC_KEY.asc"):
            self.verify(base, self.tree("new-key", key=b"another key\n"))
        with self.assertRaisesRegex(nix.PinError, "may not change the release fingerprint"):
            self.verify(base, self.tree("new-fingerprint", fingerprint="0" * 40))

    def test_the_trust_is_the_base_trees(self):
        # A base whose fingerprint line is not the running trust's is refused too.
        with self.assertRaisesRegex(nix.PinError, "may not change the release fingerprint"):
            self.verify(self.tree("base", delivery=None, fingerprint="1" * 40),
                        self.tree("candidate", fingerprint="1" * 40))

    def test_an_older_signed_release_than_the_bases_is_refused(self):
        with self.assertRaisesRegex(nix.PinError, f"may not move back from {fx.VERSION} to v0.4.1"):
            self.verify(self.tree("base"), self.tree("candidate", delivery="old"))

    def test_a_pin_without_its_signed_checksums_is_refused(self):
        with self.assertRaisesRegex(nix.PinError, "must hold release.json, SHA256SUMS and SHA256SUMS.asc"):
            self.verify(self.tree("base", delivery=None), self.tree("candidate", sums=False))

    def test_a_pin_in_another_layout_is_refused(self):
        pin = nix.pin_from(self.manifest(), release.delivery_paths(self.deliveries["new"])["sums"].read_bytes())
        with self.assertRaisesRegex(nix.PinError, "not in the rendered layout"):
            self.verify(self.tree("base", delivery=None),
                        self.tree("candidate", pin=(json.dumps(pin) + "\n").encode()))

    def test_the_committed_pin_is_proved_by_the_committed_checksums(self):
        with _Quiet():
            self.assertTrue(nix.verify(self.tree("empty", delivery=None, key=(fx.ROOT / nix.KEY_FILE).read_bytes(),
                                                 fingerprint=release.PRODUCTION_FINGERPRINT),
                                       fx.ROOT, release.PRODUCTION_TRUST))

    def test_the_flake_installs_the_same_target_for_each_system(self):
        flake = (fx.ROOT / "flake.nix").read_text()
        for system, target in nix.SYSTEMS.items():
            self.assertIn(f'{system} = "{target}";', flake)
        self.assertEqual(set(nix.SYSTEMS.values()), set(release.RELEASE_TARGETS))

    def test_the_committed_pin_is_in_the_rendered_layout(self):
        committed = (fx.ROOT / "nix/release.json").read_bytes()
        pin = json.loads(committed)
        self.assertEqual(nix.pin_bytes(pin), committed)
        self.assertEqual(pin["schema"], nix.PIN_SCHEMA)
        self.assertEqual({system: entry["target"] for system, entry in pin["targets"].items()}, nix.SYSTEMS)


class _Quiet(contextlib.ExitStack):
    """Keep diagnostics out of the test output, and prove nothing reaches stdout."""

    def __enter__(self):
        super().__enter__()
        self.out = self.enter_context(contextlib.redirect_stdout(io.StringIO()))
        self.enter_context(contextlib.redirect_stderr(io.StringIO()))
        return self

    def __exit__(self, *exc):
        result = super().__exit__(*exc)
        assert self.out.getvalue() == "", "diagnostics must not use stdout"
        return result


if __name__ == "__main__":
    unittest.main()
