#!/usr/bin/env python3
"""Synthetic proof for the immutable R2 release publisher.

FakeR2 (cw_release_fixtures) is an in-process S3 double with R2's
conditional-write semantics and injectable faults. Nothing here opens a
network connection.
"""

import contextlib
import datetime
import io
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cw_release_fixtures as fx  # noqa: E402

release = fx.release
sys.path.insert(0, str(fx.ROOT / "scripts/ci/release"))
import cw_release_r2 as r2  # noqa: E402

ACCESS_KEY = fx.ACCESS_KEY
SECRET_KEY = fx.SECRET_KEY
FakeR2 = fx.FakeR2
SIGNED_SEQUENCE = ("recovery.json", "SHA256SUMS", "SHA256SUMS.asc", "release.json.asc", "release.json")


class PublisherTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = fx.scratch("cw-release-r2.")
        cls.signer = fx.Signer(cls.base)
        cls.deliveries = {}
        for name, version, tag, lib in (("old", "v0.4.1", b"", None), ("new", fx.VERSION, b"", None),
                                        ("rebuilt", fx.VERSION, b"rebuilt", None),
                                        ("other-source", fx.VERSION, b"", "pub fn other() {}\n")):
            (cls.base / name).mkdir()
            extra = {"lib": lib} if lib else {}
            cls.deliveries[name] = fx.signed_delivery(cls.base / name, cls.signer, version, tag, **extra)[0]
        # This run's freshly built, not yet signed delivery of the same source.
        (cls.base / "fresh").mkdir()
        cls.fresh = fx.unsigned_delivery(cls.base / "fresh", tag=b"rebuilt")[0]
        # The same, with the local VM runtime the macOS cw embeds (#2539).
        (cls.base / "runtime").mkdir()
        cls.deliveries["runtime"] = fx.signed_delivery(cls.base / "runtime", cls.signer, runtime=True)[0]
        (cls.base / "fresh-runtime").mkdir()
        cls.fresh_runtime = fx.unsigned_delivery(cls.base / "fresh-runtime", tag=b"rebuilt", runtime=True)[0]

    @classmethod
    def tearDownClass(cls):
        cls.signer.close()
        shutil.rmtree(cls.base)

    def setUp(self):
        self.fake = FakeR2()
        self.s3 = r2.S3(self.fake, r2.Credentials(ACCESS_KEY, SECRET_KEY))
        self.origin = r2.PublicOrigin(self.fake)
        self.trust = self.signer.trust

    def quiet(self):
        """Capture both streams and prove neither carries credential material."""
        test = self

        class Quiet(contextlib.ExitStack):
            def __enter__(self):
                super().__enter__()
                self.out = self.enter_context(contextlib.redirect_stdout(io.StringIO()))
                self.err = self.enter_context(contextlib.redirect_stderr(io.StringIO()))
                return self

            def __exit__(self, *exc):
                result = super().__exit__(*exc)
                for text in (self.out.getvalue(), self.err.getvalue()):
                    test.assertNotIn(SECRET_KEY, text)
                    test.assertNotIn(ACCESS_KEY, text)
                return result

        return Quiet()

    def publish(self, name="new", promote=None, dist=None):
        with self.quiet() as streams:
            result = r2.publish(self.s3, self.origin, dist or self.deliveries[name], self.trust, promote)
        self.assertEqual(streams.out.getvalue(), "", "publication diagnostics must not use stdout")
        return result

    def probe(self, dist, retain_into):
        with self.quiet() as streams:
            state = r2.probe(self.s3, dist, fx.VERSION, retain_into, self.trust)
        self.assertEqual(streams.out.getvalue(), "")
        return state

    def objects(self, name="new"):
        return r2.immutable_objects(self.deliveries[name])[2]

    def channel(self):
        return self.fake.objects.get(release.channel_key("stable"))

    def retain_dir(self, label=""):
        return self.base / f"retained-{self.id().rsplit('.', 1)[-1]}{label}"

    # --- immutable objects -----------------------------------------------------------

    def test_fresh_publication_orders_blobs_receipt_then_signed_objects(self):
        counts, promotion = self.publish()
        version, _, objects, blobs = r2.immutable_objects(self.deliveries["new"])
        self.assertEqual(counts, {"created": len(objects), "identical": 0})
        self.assertEqual(len(objects), blobs + len(SIGNED_SEQUENCE))
        self.assertGreaterEqual(blobs, 7)
        self.assertEqual(promotion, "none")
        self.assertIsNone(self.channel())
        puts = self.fake.puts()
        self.assertEqual(len(puts), len(objects))
        self.assertTrue(all(request[3].get("if-none-match") == "*" for request in puts))
        self.assertTrue(all("/blobs/sha256/" in request[2] for request in puts[:blobs]))
        self.assertEqual([request[2].rsplit("/", 1)[1] for request in puts[blobs:]], list(SIGNED_SEQUENCE))
        # Every blob is read back before the receipt is written.
        receipt_put = self.fake.requests.index(puts[blobs])
        blob_reads = {request[2] for request in self.fake.requests[:receipt_put] if request[0] == "GET"}
        self.assertTrue(all(request[2] in blob_reads for request in puts[:blobs]))
        receipt = self.fake.objects[release.release_key(version, "recovery.json")][0]
        signed, _ = release.open_recovery_receipt(receipt, version, self.trust)
        self.assertEqual(signed[0], self.fake.objects[release.release_key(version, "release.json")][0])
        self.assertFalse([request for request in self.fake.requests if request[0] not in ("GET", "PUT")])

    def test_identical_existing_objects_are_accepted_without_overwrite(self):
        self.publish()
        before = dict(self.fake.objects)
        counts, _ = self.publish()
        self.assertEqual(counts, {"created": 0, "identical": len(self.objects())})
        self.assertEqual(self.fake.objects, before)

    def test_conflicting_existing_object_stops_before_the_manifest(self):
        key = release.release_key(fx.VERSION, "SHA256SUMS")
        self.fake.store(key, b"different bytes\n")
        with self.assertRaises(r2.Conflict):
            self.publish()
        self.assertEqual(self.fake.objects[key][0], b"different bytes\n")
        self.assertNotIn(release.release_key(fx.VERSION, "release.json"), self.fake.objects)

    def test_concurrent_conditional_writes(self):
        key, data, _ = self.objects()[0]
        self.fake.before_put = lambda fake, put_key: (
            fake.objects.setdefault(put_key, (data, fake._etag())) if put_key == key else None)
        counts, _ = self.publish()
        self.assertEqual(counts["identical"], 1)
        self.setUp()
        self.fake.before_put = lambda fake, put_key: (
            fake.objects.setdefault(put_key, (b"racing writer", fake._etag())) if put_key == key else None)
        with self.assertRaises(r2.Conflict):
            self.publish()
        self.assertEqual(self.fake.objects[key][0], b"racing writer")

    def test_interrupted_blob_publication_resumes_without_duplicate_effects(self):
        key = self.objects()[4][0]
        self.fake.faults = [("PUT", key, "lost"), ("GET", key, "lost")]
        with self.assertRaises(r2.Uncertain):
            self.publish()
        self.assertNotIn(release.release_key(fx.VERSION, "recovery.json"), self.fake.objects)
        self.assertEqual(len(self.fake.objects), 4)
        # No signed object exists yet, so a retry is fresh.
        self.assertEqual(self.probe(self.fresh, self.retain_dir()), "fresh")
        counts, _ = self.publish()
        self.assertEqual(counts, {"created": len(self.objects()) - 4, "identical": 4})

    def test_uncertain_writes_are_resolved_by_readback(self):
        objects = self.objects()
        self.fake.faults = [("PUT", objects[1][0], "applied-then-lost"), ("PUT", objects[2][0], "500")]
        counts, _ = self.publish()
        self.assertEqual(counts, {"created": len(objects), "identical": 0})
        self.assertEqual(len(self.fake.puts(objects[1][0])), 1)
        self.assertEqual(len(self.fake.puts(objects[2][0])), 2)

    def test_failed_authenticated_readback_prevents_promotion(self):
        key = self.objects()[0][0]
        self.fake.faults = [("GET", key, "corrupt")]
        with self.assertRaises(r2.PublishError):
            self.publish(promote="stable")
        self.assertIsNone(self.channel())
        self.assertNotIn(release.release_key(fx.VERSION, "recovery.json"), self.fake.objects)

    def test_failed_public_readback_prevents_promotion(self):
        self.fake.public_missing = {self.objects()[3][0]}
        with self.assertRaises(r2.PublishError):
            self.publish(promote="stable")
        self.assertIsNone(self.channel())
        self.assertIn(release.release_key(fx.VERSION, "release.json"), self.fake.objects)

    # --- interruption recovery and retained source binding ------------------------------

    def complete_reference(self):
        reference = FakeR2()
        saved, self.fake = self.fake, reference
        self.s3 = r2.S3(reference, r2.Credentials(ACCESS_KEY, SECRET_KEY))
        self.publish("new")
        self.fake = saved
        self.s3 = r2.S3(saved, r2.Credentials(ACCESS_KEY, SECRET_KEY))
        return dict(reference.objects)

    def test_interruption_after_each_signed_object_recovers_the_original_bundle(self):
        reference = self.complete_reference()
        objects = self.objects()
        blobs = len(objects) - len(SIGNED_SEQUENCE)
        for written in range(1, len(SIGNED_SEQUENCE) + 1):
            with self.subTest(after=SIGNED_SEQUENCE[written - 1]):
                self.setUp()
                if written < len(SIGNED_SEQUENCE):
                    stop = objects[blobs + written][0]
                    self.fake.faults = [("PUT", stop, "lost"), ("GET", stop, "lost")]
                    with self.assertRaises(r2.Uncertain):
                        self.publish("new")
                else:
                    self.publish("new")
                published = {key for key in self.fake.objects if "/releases/" in key}
                self.assertEqual(len(published), written)
                # The rebuild has different executable bytes and would sign anew.
                retained = self.retain_dir(f"-{written}")
                self.assertEqual(self.probe(self.fresh, retained), "retained")
                original = release.delivery_paths(self.deliveries["new"])
                kept = release.delivery_paths(retained)
                for name in ("manifest", "manifest_sig", "sums", "sums_sig"):
                    self.assertEqual(kept[name].read_bytes(), original[name].read_bytes(), name)
                for target in release.RELEASE_TARGETS:
                    asset = release.asset_name(fx.VERSION, target)
                    self.assertEqual((retained / asset).read_bytes(), (self.deliveries["new"] / asset).read_bytes())
                self.assertNotEqual((self.fresh / release.asset_name(fx.VERSION, "x86_64-apple-darwin")).read_bytes(),
                                    (retained / release.asset_name(fx.VERSION, "x86_64-apple-darwin")).read_bytes())
                fx.sign_channel(retained, self.signer, fx.VERSION)
                counts, _ = self.publish(dist=retained)
                self.assertEqual(counts["created"], len(SIGNED_SEQUENCE) - written)
                self.assertEqual({key: value[0] for key, value in self.fake.objects.items()},
                                 {key: value[0] for key, value in reference.items()})
                shutil.rmtree(retained)

    def test_local_runtime_blobs_publish_and_read_back_before_the_receipt(self):
        dist = self.deliveries["runtime"]
        counts, _ = self.publish("runtime")
        version, _, objects, blobs = r2.immutable_objects(dist)
        _, pinned = release.load_local_runtime(dist)
        self.assertEqual(len(pinned), 12)
        self.assertEqual(counts, {"created": len(objects), "identical": 0})
        self.assertEqual(blobs, len(r2.immutable_objects(self.deliveries["new"])[2]) - len(SIGNED_SEQUENCE)
                         + len(pinned))
        runtime_keys = {release.blob_key(digest) for digest, _ in pinned}
        self.assertTrue(runtime_keys <= {key for key, _, _ in objects[:blobs]})
        for digest, size in pinned:
            data = self.fake.objects[release.blob_key(digest)][0]
            self.assertEqual((fx.digest(data), len(data)), (digest, size))
        # Nothing names the runtime outside the content-addressed blobs.
        self.assertFalse([key for key in self.fake.objects if "local-runtime" in key])
        puts = [request[2] for request in self.fake.puts()]
        receipt = puts.index(r2.object_path(release.release_key(version, r2.RECEIPT)))
        self.assertTrue(all(r2.object_path(key) in puts[:receipt] for key in runtime_keys))
        reads = {request[2] for request in self.fake.requests[:self.fake.requests.index(self.fake.puts()[receipt])]
                 if request[0] == "GET"}
        self.assertTrue(all(r2.object_path(key) in reads for key in runtime_keys))

    def test_a_retained_retry_restores_the_local_runtime_from_its_blobs(self):
        dist = self.deliveries["runtime"]
        objects = r2.immutable_objects(dist)[2]
        blobs = len(objects) - len(SIGNED_SEQUENCE)
        # Interrupted after the recovery receipt, before SHA256SUMS.
        stop = objects[blobs + 1][0]
        self.fake.faults = [("PUT", stop, "lost"), ("GET", stop, "lost")]
        with self.assertRaises(r2.Uncertain):
            self.publish("runtime")
        retained = self.retain_dir()
        self.assertEqual(self.probe(self.fresh_runtime, retained), "retained")
        original, kept = release.local_runtime_paths(dist), release.local_runtime_paths(retained)
        self.assertEqual(kept[1].read_bytes(), original[1].read_bytes())
        self.assertEqual({path.name: path.read_bytes() for path in kept[2].iterdir()},
                         {path.name: path.read_bytes() for path in original[2].iterdir()})
        fx.sign_channel(retained, self.signer, fx.VERSION)
        counts, _ = self.publish(dist=retained)
        self.assertEqual(counts["created"], len(SIGNED_SEQUENCE) - 1)
        self.assertEqual(counts["identical"], len(objects) - counts["created"])
        shutil.rmtree(retained)

    def test_orphan_signed_objects_without_receipt_or_manifest_are_refused(self):
        for name in ("SHA256SUMS", "SHA256SUMS.asc", "release.json.asc"):
            with self.subTest(name):
                self.setUp()
                self.fake.store(release.release_key(fx.VERSION, name), b"orphan\n")
                retained = self.retain_dir(f"-{name}")
                with self.assertRaises(r2.Conflict) as caught:
                    self.probe(self.fresh, retained)
                self.assertIn("incomplete", str(caught.exception))
                self.assertFalse(retained.exists())

    def test_competing_recovery_receipt_winner_is_retained_never_overwritten(self):
        version, _, rival, _ = r2.immutable_objects(self.deliveries["rebuilt"])
        receipt_key = release.release_key(version, "recovery.json")
        rival_receipt = next(data for key, data, _ in rival if key == receipt_key)
        self.fake.before_put = lambda fake, key: (
            fake.objects.setdefault(key, (rival_receipt, fake._etag())) if key == receipt_key else None)
        with self.assertRaises(r2.Conflict) as caught:
            self.publish("new")
        self.assertIn("another publication", str(caught.exception))
        self.assertEqual(self.fake.objects[receipt_key][0], rival_receipt)
        for name in ("SHA256SUMS", "SHA256SUMS.asc", "release.json.asc", "release.json"):
            self.assertNotIn(release.release_key(version, name), self.fake.objects)
        # The rival's blobs were never written; recovery refuses until they are.
        self.fake.before_put = None
        with self.assertRaises(r2.Conflict):
            self.probe(self.fresh, self.retain_dir("-missing"))
        self.assertFalse(self.retain_dir("-missing").exists())
        for key, data, _ in rival:
            if "/blobs/" in key:
                self.fake.objects.setdefault(key, (data, self.fake._etag()))
        retained = self.retain_dir()
        self.assertEqual(self.probe(self.fresh, retained), "retained")
        self.assertEqual(release.delivery_paths(retained)["manifest"].read_bytes(),
                         release.delivery_paths(self.deliveries["rebuilt"])["manifest"].read_bytes())
        shutil.rmtree(retained)

    def test_retained_release_must_match_the_admitted_tag_source_and_toolchain(self):
        self.publish("new")
        state = release.prepared_candidate(self.fresh)
        conflicts = {
            "source revision": {"source_sha": "c" * 40},
            "tag object": {"tag_object_sha": "d" * 40},
            "source digest": {"source_tree": "e" * 64},
            "toolchain": {"rustc": "rustc 1.93.0 (other 2026-01-19)"},
        }
        for name, change in conflicts.items():
            with self.subTest(name):
                candidate = self.base / f"candidate-{name.replace(' ', '-')}"
                shutil.copytree(self.fresh, candidate)
                prepared = candidate / release.DELIVERY / "prepared.json"
                prepared.write_bytes(release.canonical({**state, **change}))
                retained = self.retain_dir(f"-{name.replace(' ', '-')}")
                with self.assertRaises(r2.Conflict) as caught:
                    self.probe(candidate, retained)
                self.assertIn("refusing to reuse", str(caught.exception))
                self.assertFalse(retained.exists())
                shutil.rmtree(candidate)
        # A different source published under the same tag is never retained.
        self.setUp()
        self.publish("other-source")
        with self.assertRaises(r2.Conflict):
            self.probe(self.fresh, self.retain_dir("-other"))

    def test_retry_retains_the_published_signed_release(self):
        self.assertEqual(self.probe(self.fresh, self.base / "unused"), "fresh")
        self.publish("new")
        published = dict(self.fake.objects)
        retained = self.retain_dir()
        self.assertEqual(self.probe(self.fresh, retained), "retained")
        paths = release.delivery_paths(retained)
        self.assertEqual(paths["manifest"].read_bytes(),
                         published[release.release_key(fx.VERSION, "release.json")][0])
        rebuilt = release.read_regular(self.fresh / release.asset_name(fx.VERSION, "x86_64-apple-darwin"),
                                       release.MAX_EXECUTABLE)
        self.assertNotIn(release.blob_key(fx.digest(rebuilt)), published)
        fx.sign_channel(retained, self.signer, fx.VERSION)
        self.assertTrue(release.verify_delivery(retained, self.trust)["signed"])
        counts, _ = self.publish(dist=retained)
        self.assertEqual(counts["created"], 0)
        self.assertEqual(self.fake.objects, published)
        shutil.rmtree(retained)

    def test_probe_refuses_an_invalid_published_release(self):
        self.publish("new")
        signature_key = release.release_key(fx.VERSION, "release.json.asc")
        (self.base / "probe-other").mkdir()
        other = fx.Signer(self.base / "probe-other", "Synthetic intruder")
        try:
            self.fake.objects[signature_key] = (other.sign(b"forged"), '"forged"')
            with self.assertRaises(r2.Conflict):
                self.probe(self.fresh, self.base / "never")
            self.assertFalse((self.base / "never").exists())
            receipt_key = release.release_key(fx.VERSION, "recovery.json")
            del self.fake.objects[receipt_key]
            with self.assertRaises(r2.Conflict):
                self.probe(self.fresh, self.base / "never")
            self.assertFalse((self.base / "never").exists())
        finally:
            other.close()

    def test_workflow_probe_capture_yields_only_the_state(self):
        """Run the job's exact step shell against the real probe CLI."""
        workflow = yaml.safe_load((fx.ROOT / ".gitea/workflows/cli-release.yaml").read_text())
        step = next(step for step in workflow["jobs"]["package-release"]["steps"]
                    if step.get("name") == "Reuse an already-published signed R2 release")
        self.assertIn('state="$(python3 ../scripts/ci/release/cw_release_r2.py probe', step["run"])
        for published in (False, True):
            with self.subTest(published=published):
                self.setUp()
                if published:
                    self.publish("new")
                sandbox = self.base / f"workflow-{published}"
                (sandbox / "scripts/ci/setup").mkdir(parents=True)
                (sandbox / "scripts/ci/release").mkdir(parents=True)
                source = sandbox / ".release-source"
                (source / "dist").mkdir(parents=True)
                shutil.copytree(self.fresh, source / "dist/cw-release")
                reader = sandbox / "scripts/ci/setup/fetch-openbao-releases-r2-credentials.sh"
                reader.write_text("#!/usr/bin/env bash\nset -euo pipefail\numask 077\n"
                                  "printf '[default]\\naws_access_key_id = %s\\naws_secret_access_key = %s\\n' "
                                  "\"$SYNTHETIC_ACCESS\" \"$SYNTHETIC_SECRET\" >\"$1\"\n"
                                  "echo 'synthetic credential reader' >&2\n")
                reader.chmod(0o755)
                wrapper = sandbox / "scripts/ci/release/cw_release_r2.py"
                wrapper.write_text(
                    "import os, sys\n"
                    "sys.path[:0] = [os.environ['CW_TEST_TESTS'], os.environ['CW_TEST_RELEASE']]\n"
                    "import cw_release_fixtures as fx\nimport cw_release_r2 as r2\n"
                    "fake = fx.FakeR2.load(os.environ['CW_TEST_FAKE_R2'])\n"
                    "r2.HttpsTransport = lambda: fake\n"
                    "r2.release.PRODUCTION_TRUST = r2.release.Trust(os.environ['CW_TEST_KEY'], "
                    "os.environ['CW_TEST_FINGERPRINT'])\n"
                    "sys.exit(r2.main(sys.argv[1:]))\n")
                state = sandbox / "fake-r2.json"
                self.fake.dump(state)
                runner = sandbox / "runner"
                runner.mkdir()
                env = {"PATH": os.environ["PATH"], "HOME": str(sandbox), "LC_ALL": "C",
                       "RUNNER_TEMP": str(runner), "RELEASE_TAG": fx.VERSION,
                       "CW_RELEASE_R2_ROUTE_ADMITTED": "true",
                       "SYNTHETIC_ACCESS": ACCESS_KEY, "SYNTHETIC_SECRET": SECRET_KEY,
                       "CW_TEST_TESTS": str(fx.ROOT / "scripts/ci/tests"),
                       "CW_TEST_RELEASE": str(fx.ROOT / "scripts/ci/release"),
                       "CW_TEST_FAKE_R2": str(state), "CW_TEST_KEY": str(self.signer.public),
                       "CW_TEST_FINGERPRINT": self.signer.fingerprint}
                result = subprocess.run(["bash", "-c", step["run"]], cwd=source, env=env, capture_output=True,
                                        text=True, timeout=120)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("cw-release-r2: probe", result.stderr)
                self.assertNotIn(SECRET_KEY, result.stdout + result.stderr)
                dist = source / "dist/cw-release"
                manifest = release.delivery_paths(dist)["manifest"]
                if published:
                    self.assertTrue((source / "dist/cw-release-rebuilt").is_dir())
                    self.assertEqual(manifest.read_bytes(),
                                     release.delivery_paths(self.deliveries["new"])["manifest"].read_bytes())
                else:
                    self.assertFalse((source / "dist/cw-release-rebuilt").exists())
                    self.assertFalse((source / "dist/cw-release-retained").exists())
                    self.assertFalse(manifest.exists())
                shutil.rmtree(sandbox)

    # --- channel compare-and-swap ---------------------------------------------------------

    def local_channel(self, name):
        return release.delivery_paths(self.deliveries[name])["channel"].read_bytes()

    def test_explicit_promotion_creates_then_swaps_with_observed_etag(self):
        _, first = self.publish("old", promote="stable")
        self.assertEqual(first, "promoted")
        self.assertEqual(self.fake.puts(release.channel_key("stable"))[0][3].get("if-none-match"), "*")
        etag = self.channel()[1]
        _, second = self.publish("new", promote="stable")
        self.assertEqual(second, "promoted")
        self.assertEqual(self.fake.puts(release.channel_key("stable"))[-1][3].get("if-match"), etag)
        self.assertEqual(self.channel()[0], self.local_channel("new"))
        _, again = self.publish("new", promote="stable")
        self.assertEqual(again, "unchanged")

    def resigned(self, name, notation):
        copy = self.base / f"resigned-{self.id().rsplit('.', 1)[-1]}-{notation}"
        shutil.copytree(self.deliveries[name], copy)
        release.delivery_paths(copy)["pointer"].unlink()
        fx.sign_channel(copy, self.signer, fx.VERSION, notation)
        return copy

    def test_resigned_identical_channel_pointer_is_unchanged_without_put(self):
        self.publish("new", promote="stable")
        channel_key = release.channel_key("stable")
        before, puts = self.channel(), len(self.fake.puts(channel_key))
        resigned = self.resigned("new", "first")
        self.assertNotEqual(release.delivery_paths(resigned)["channel"].read_bytes(), before[0])
        _, state = self.publish(dist=resigned, promote="stable")
        self.assertEqual(state, "unchanged")
        self.assertEqual(len(self.fake.puts(channel_key)), puts)
        self.assertEqual(self.channel(), before)
        # A racing writer of the identical pointer with other signature bytes.
        self.setUp()
        self.publish("old", promote="stable")
        racing = release.delivery_paths(self.resigned("new", "second"))["channel"].read_bytes()
        self.fake.before_put = lambda fake, key: fake.store(key, racing) if key == channel_key else None
        _, state = self.publish("new", promote="stable")
        self.assertEqual(state, "unchanged")
        self.assertEqual(self.channel()[0], racing)
        shutil.rmtree(resigned)

    def test_same_version_different_pointer_is_refused(self):
        self.publish("new")
        rival = release.delivery_paths(self.deliveries["rebuilt"])["channel"].read_bytes()
        self.assertNotEqual(release.verify_channel(rival, self.trust),
                            release.verify_channel(self.local_channel("new"), self.trust))
        self.fake.store(release.channel_key("stable"), rival)
        with self.assertRaises(r2.Conflict):
            self.publish("new", promote="stable")
        self.assertEqual(self.channel()[0], rival)

    def test_stale_etag_is_refused(self):
        self.publish("old", promote="stable")
        channel_key = release.channel_key("stable")
        self.fake.before_put = lambda fake, key: fake.store(key, b"concurrent promotion") \
            if key == channel_key else None
        with self.assertRaises(r2.Conflict):
            self.publish("new", promote="stable")
        self.assertEqual(self.channel()[0], b"concurrent promotion")

    def test_uncertain_promotion_is_resolved_by_readback(self):
        self.publish("old", promote="stable")
        channel_key = release.channel_key("stable")
        self.fake.faults = [("PUT", channel_key, "applied-then-lost")]
        _, applied = self.publish("new", promote="stable")
        self.assertEqual(applied, "promoted")
        self.setUp()
        self.publish("old", promote="stable")
        previous_etag = self.channel()[1]
        self.fake.faults = [("PUT", channel_key, "lost")]
        _, retried = self.publish("new", promote="stable")
        self.assertEqual(retried, "promoted")
        attempts = self.fake.puts(channel_key)[-2:]
        self.assertEqual([request[3].get("if-match") for request in attempts], [previous_etag, previous_etag])

    def test_downgrade_and_unsigned_channels_are_refused(self):
        self.publish("new", promote="stable")
        with self.assertRaises(r2.Conflict):
            self.publish("old", promote="stable")
        self.assertEqual(self.channel()[0], self.local_channel("new"))
        self.setUp()
        self.fake.store(release.channel_key("stable"), b'{"unsigned":true}\n')
        with self.assertRaises(release.ReleaseError):
            self.publish("new", promote="stable")

    # --- credentials and requests ----------------------------------------------------------------

    def credential_file(self, name, text, mode=0o600):
        path = self.base / name
        path.write_text(text)
        path.chmod(mode)
        return path

    def test_credentials_are_strict_private_and_never_ambient(self):
        good = f"[default]\naws_access_key_id = {ACCESS_KEY}\naws_secret_access_key = {SECRET_KEY}\n"
        loaded = r2.load_credentials(self.credential_file("good", good), environ={})
        self.assertEqual((loaded.access_key_id, loaded.secret_access_key), (ACCESS_KEY, SECRET_KEY))
        self.assertNotIn(SECRET_KEY, repr(loaded))
        refused = {
            "group readable": self.credential_file("loose", good, 0o640),
            "extra line": self.credential_file("extra", good + "region = auto\n"),
            "wrong profile": self.credential_file("profile", good.replace("[default]", "[other]")),
        }
        link = self.base / "link"
        link.symlink_to(self.base / "good")
        refused["symlink"] = link
        for name, path in refused.items():
            with self.subTest(name), self.assertRaises(r2.PublishError):
                r2.load_credentials(path, environ={})
        with self.assertRaises(r2.PublishError):
            r2.load_credentials(self.base / "good", environ={"AWS_SECRET_ACCESS_KEY": "ambient"})

    def test_requests_never_carry_the_secret(self):
        self.publish("new", promote="stable")
        for _, _, _, headers in self.fake.requests:
            self.assertNotIn(SECRET_KEY, " ".join(headers.values()))

    def test_sigv4_matches_the_published_aws_example(self):
        # AWS S3 SigV4 documentation, "Example: GET Object".
        credentials = r2.Credentials("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
        headers = r2.sigv4_headers(credentials, "GET", "examplebucket.s3.amazonaws.com", "/test.txt",
                                   {"range": "bytes=0-9"}, fx.digest(b""),
                                   datetime.datetime(2013, 5, 24, tzinfo=datetime.timezone.utc), "us-east-1")
        self.assertTrue(headers["authorization"].endswith(
            "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"))
        self.assertIn("SignedHeaders=host;range;x-amz-content-sha256;x-amz-date", headers["authorization"])

    def test_public_readback_names_its_user_agent(self):
        # The public origin answers Python's default User-Agent with 403.
        seen = []

        class Recording:
            def request(self, method, host, path, headers, body=None, limit=None):
                seen.append((method, host, dict(headers)))
                return r2.Response(200, {}, b"x")

        r2.PublicOrigin(Recording()).get("cw/v1/releases/v9.9.9/SHA256SUMS")
        self.assertEqual(seen, [("GET", r2.PUBLIC_HOST, {"user-agent": r2.PUBLIC_USER_AGENT})])
        self.assertNotIn("python", r2.PUBLIC_USER_AGENT.lower())

    def test_object_keys_and_hosts_are_confined(self):
        for key in ("other/x", "cw/v1/../x", "cw/v1//x", "cw/v2/x"):
            with self.subTest(key), self.assertRaises(r2.PublishError):
                r2.object_path(key)
        with self.assertRaises(r2.PublishError):
            r2.HttpsTransport().request("GET", "example.com", "/", {})

    def test_cli_refuses_before_any_request_without_private_credentials(self):
        loose = self.credential_file("cli-loose",
                                     f"[default]\naws_access_key_id = {ACCESS_KEY}\naws_secret_access_key = {SECRET_KEY}\n",
                                     0o644)
        result = subprocess.run([sys.executable, str(fx.ROOT / "scripts/ci/release/cw_release_r2.py"), "publish",
                                 "--dist", str(self.deliveries["new"]), "--credentials", str(loose)],
                                capture_output=True, text=True, env={"PATH": os.environ["PATH"]}, timeout=60)
        self.assertEqual(result.returncode, 1)
        self.assertIn("REJECT", result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertNotIn(SECRET_KEY, result.stdout + result.stderr)


if __name__ == "__main__":
    result = unittest.main(argv=[sys.argv[0], "-v"], exit=False).result
    print(f"test-cw-release-r2: tests={result.testsRun} failures={len(result.failures)} errors={len(result.errors)}")
    sys.exit(0 if result.wasSuccessful() and result.testsRun > 0 else 1)
