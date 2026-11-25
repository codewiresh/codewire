#!/usr/bin/env python3
"""Synthetic proof for the kernel builder's package mirror (#5619).

Nothing here downloads or publishes: the store is the release tests'
in-process FakeR2. A build reads only locked bytes, and a missing or
different object fails with no other source to fall back to.
"""

import io
import json
import shutil
import sys
import tarfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cw_release_fixtures as fx  # noqa: E402

release = fx.release
sys.path.insert(0, str(fx.ROOT / "scripts/ci/release"))
import cw_release_r2 as r2  # noqa: E402
import kernel_builder_mirror as mirror  # noqa: E402

SNAPSHOT = "2026/08/11"
FILES = {
    ("core", "core.db"): b"synthetic core database\n",
    ("extra", "extra.db"): b"synthetic extra database\n",
    ("core", "gcc-16.1.1-1-x86_64.pkg.tar.zst"): b"synthetic gcc package\n",
    ("core", "gcc-16.1.1-1-x86_64.pkg.tar.zst.sig"): b"synthetic gcc signature\n",
    ("core", "archlinux-keyring-20260801-1-any.pkg.tar.zst"): b"synthetic keyring package\n",
    # A package with an epoch: the colon an artifact path refuses.
    ("extra", "fakeroot-1:1.37.2-3-x86_64.pkg.tar.zst"): b"synthetic fakeroot package\n",
}


class MirrorTest(unittest.TestCase):
    def setUp(self):
        self.base = fx.scratch("kernel-builder-mirror.")
        self.addCleanup(shutil.rmtree, self.base)
        self.fake = fx.FakeR2()
        self.s3 = r2.S3(self.fake, r2.Credentials(fx.ACCESS_KEY, fx.SECRET_KEY))
        self.origin = r2.PublicOrigin(self.fake)
        self.collected = self.base / "collected"
        for (repository, name), data in FILES.items():
            folder = self.collected / repository / "os" / "x86_64"
            folder.mkdir(parents=True, exist_ok=True)
            (folder / name).write_bytes(data)
        # As the collect job hands it on: `tar -C collected -cf collected.tar .`
        self.archive = self.base / "collected.tar"
        with tarfile.open(self.archive, "w") as tar:
            tar.add(self.collected, arcname=".")

    def recorded(self):
        return mirror.record(self.s3, self.archive, SNAPSHOT)

    def append(self, member, data=b""):
        """Add one more member to the collected archive."""
        with tarfile.open(self.archive, "a") as tar:
            member.size = len(data) if member.isreg() else 0
            tar.addfile(member, io.BytesIO(data) if member.isreg() else None)

    def test_record_then_fetch_writes_exactly_the_collected_tree(self):
        lock = self.recorded()
        self.assertEqual(len(json.loads(lock)["files"]), len(FILES))
        out = self.base / "out"
        self.assertEqual(mirror.fetch(self.origin, lock, SNAPSHOT, out), len(FILES))
        for (repository, name), data in FILES.items():
            self.assertEqual((out / repository / "os" / "x86_64" / name).read_bytes(), data)

    def test_record_stores_every_file_by_its_digest_under_its_own_prefix(self):
        self.recorded()
        for data in FILES.values():
            self.assertIn(mirror.key(fx.digest(data)), self.fake.objects)
        written = [k for k in self.fake.objects if not k.startswith(mirror.KEY_PREFIX + "/")]
        self.assertEqual(written, [], "the refresh wrote outside the kernel-builder prefix")

    def test_an_existing_object_with_other_bytes_is_never_overwritten(self):
        gcc = FILES[("core", "gcc-16.1.1-1-x86_64.pkg.tar.zst")]
        self.fake.store(mirror.key(fx.digest(gcc)), b"other bytes under that digest\n")
        with self.assertRaises(r2.Conflict):
            self.recorded()
        self.assertEqual(self.fake.objects[mirror.key(fx.digest(gcc))][0], b"other bytes under that digest\n")

    def test_a_mirrored_file_that_differs_from_the_lock_is_refused(self):
        lock = self.recorded()
        gcc = FILES[("core", "gcc-16.1.1-1-x86_64.pkg.tar.zst")]
        # The bucket holds other bytes under the locked digest: whoever can
        # write the bucket can make the build fail, never change it.
        self.fake.store(mirror.key(fx.digest(gcc)), b"tampered gcc package\n")
        out = self.base / "out"
        with self.assertRaisesRegex(mirror.MirrorError, "differ from the lock"):
            mirror.fetch(self.origin, lock, SNAPSHOT, out)
        self.assertFalse(out.exists(), "a refused fetch left files behind")

    def test_a_missing_object_fails_with_no_other_source(self):
        lock = self.recorded()
        keyring = FILES[("core", "archlinux-keyring-20260801-1-any.pkg.tar.zst")]
        del self.fake.objects[mirror.key(fx.digest(keyring))]
        calls = []
        real_request = self.fake.request

        def recording(method, host, path, headers, body=None, limit=r2.MAX_OBJECT):
            calls.append(host)
            return real_request(method, host, path, headers, body, limit)

        self.fake.request = recording
        with self.assertRaisesRegex(mirror.MirrorError, "status 404"):
            mirror.fetch(self.origin, lock, SNAPSHOT, self.base / "out")
        self.assertEqual(set(calls), {r2.PUBLIC_HOST}, "the fetch asked a host other than the release store")

    def test_a_lock_for_another_snapshot_is_refused_before_any_download(self):
        lock = self.recorded()
        before = len(self.fake.requests) if hasattr(self.fake, "requests") else None
        with self.assertRaisesRegex(mirror.MirrorError, "refresh the mirror"):
            mirror.fetch(self.origin, lock, "2026/09/01", self.base / "out")
        if before is not None:
            self.assertEqual(len(self.fake.requests), before)

    def test_an_archive_member_that_is_not_a_regular_file_is_refused(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE):
            with self.subTest(kind=kind):
                self.setUp()
                member = tarfile.TarInfo("./extra/os/x86_64/linked.pkg.tar.zst")
                member.type, member.linkname = kind, "/etc/passwd"
                self.append(member)
                with self.assertRaisesRegex(mirror.MirrorError, "is not a regular file"):
                    self.recorded()

    def test_an_archive_member_outside_the_repository_tree_is_refused(self):
        for name, reason in (("./core/os/x86_64/../../../etc/x", "bad file name|not in a repository folder"),
                             ("/core/os/x86_64/x.pkg.tar.zst", "not in a repository folder"),
                             ("./community/os/x86_64/x.pkg.tar.zst", "unknown repository"),
                             ("./core/x.pkg.tar.zst", "not in a repository folder"),
                             ("./core/os/aarch64/x.pkg.tar.zst", "not in a repository folder")):
            with self.subTest(name=name):
                self.setUp()
                self.append(tarfile.TarInfo(name), b"synthetic stray file\n")
                with self.assertRaisesRegex(mirror.MirrorError, reason):
                    self.recorded()
        self.setUp()
        folder = tarfile.TarInfo("./core/other")
        folder.type = tarfile.DIRTYPE
        self.append(folder)
        with self.assertRaisesRegex(mirror.MirrorError, "is not a repository folder"):
            self.recorded()

    def test_a_file_listed_twice_in_the_archive_is_refused(self):
        self.append(tarfile.TarInfo("./core/os/x86_64/core.db"), b"a second core database\n")
        with self.assertRaisesRegex(mirror.MirrorError, "listed twice"):
            self.recorded()

    def test_a_lock_without_both_sync_databases_is_refused(self):
        lock = json.loads(self.recorded())
        lock["files"] = [entry for entry in lock["files"] if entry["name"] != "extra.db"]
        with self.assertRaisesRegex(mirror.MirrorError, "no extra.db"):
            mirror.parse_lock(json.dumps(lock), SNAPSHOT)

    def test_a_lock_path_cannot_leave_the_repository_tree(self):
        lock = json.loads(self.recorded())
        for bad in ("../etc/passwd", "core.db/../../x", ".."):
            lock["files"][0]["name"] = bad
            with self.assertRaisesRegex(mirror.MirrorError, "bad file name"):
                mirror.parse_lock(json.dumps(lock), SNAPSHOT)
        lock["files"][0]["name"] = "core.db"
        lock["files"][0]["repository"] = "community"
        with self.assertRaisesRegex(mirror.MirrorError, "unknown repository"):
            mirror.parse_lock(json.dumps(lock), SNAPSHOT)

    def test_the_collector_outlasts_an_archive_stall_with_bounded_retries(self):
        collect = (fx.ROOT / "scripts/ci/release/collect-kernel-builder-packages.sh").read_text()
        self.assertTrue("DisableDownloadTimeout" in collect, "pacman's own 10 s stall abort is still on")
        self.assertTrue('for try in 1 2 3; do' in collect and "timeout -s INT -k 30 900 pacman " in collect,
                        "a collector pacman call is not bounded and retried")
        self.assertTrue('--cachedir "$cache"' in collect, "a retry would fetch again what it already has")

    def test_the_lock_matches_the_pinned_snapshot_once_it_exists(self):
        # Until the first refresh there is no lock; once there is, it must
        # be the pinned snapshot's.
        if mirror.LOCK.exists():
            mirror.parse_lock(mirror.LOCK.read_bytes(), mirror.pinned_snapshot())


if __name__ == "__main__":
    unittest.main()
