#!/usr/bin/env python3
"""package-cw-release.sh carries the local VM runtime the macOS cw embeds (#2539).

The real packaging script runs twice, as the release workflow runs it: once as
the Mac job (the darwin pair, embedding the runtime) and once as the Linux job
(the Linux pair, importing the Mac assets and preparing the delivery). A
stand-in `cargo` writes header-correct synthetic executables with the build
record build.rs embeds, plus the runtime document when CODEWIRE_LOCAL_RUNTIME
is set, and a stand-in `rustc` reports the pinned toolchain. Nothing is
compiled, signed or published.
"""

import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cw_release_fixtures as fx  # noqa: E402

release = fx.release
ROOT = fx.ROOT
SCRIPT = ROOT / "scripts/ci/release/package-cw-release.sh"

FAKE_CARGO = '''#!/usr/bin/env python3
import os, sys
from pathlib import Path
sys.path.insert(0, {fixtures!r})
import cw_release_fixtures as fx
args = sys.argv[1:]
target = args[args.index("--target") + 1]
out = Path(os.environ["CARGO_TARGET_DIR"]) / target / "release"
out.mkdir(parents=True, exist_ok=True)
runtime = os.environ.get("CODEWIRE_LOCAL_RUNTIME")
embedded = Path(runtime).read_bytes() if runtime else b""
data = fx.executable(target, os.environ["CODEWIRE_VERSION"], revision=os.environ["CODEWIRE_SOURCE_REVISION"],
                     tree=os.environ["CODEWIRE_SOURCE_TREE_SHA256"], embedded=embedded)
(out / "cw").write_bytes(data)
(out / "cw").chmod(0o755)
(out / "cw.d").write_text(f"{{out / 'cw'}}: {{Path.cwd() / 'crates/demo/src/lib.rs'}}\\n")
'''

FAKE_RUSTC = f'''#!/bin/sh
case "$1" in
  --version) echo "{fx.RUSTC}" ;;
  -vV) printf 'rustc {fx.RUSTC.split()[1]}\\nhost: x86_64-unknown-linux-gnu\\n' ;;
  *) exit 2 ;;
esac
'''


class PackageTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = fx.scratch("cw-package.")
        cls.source, cls.source_sha = fx.source_repo(cls.base)
        tools = cls.base / "bin"
        tools.mkdir()
        (tools / "cargo").write_text(FAKE_CARGO.format(fixtures=str(Path(__file__).resolve().parent)))
        (tools / "rustc").write_text(FAKE_RUSTC)
        for tool in ("cargo", "rustc"):
            (tools / tool).chmod(0o755)
        cls.path = f"{tools}:{os.environ['PATH']}"
        document, files = fx.local_runtime(cls.source_sha)
        cls.runtime = cls.base / "runtime"
        (cls.runtime / "blobs/sha256").mkdir(parents=True)
        (cls.runtime / release.LOCAL_RUNTIME_NAME).write_bytes(document)
        for name, data in files.items():
            (cls.runtime / "blobs/sha256" / name).write_bytes(data)
        cls.document = document

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.base)

    def package(self, name, targets, **extra):
        env = {key: value for key, value in os.environ.items()
               if not key.startswith(("CW_RELEASE_", "CODEWIRE_", "CARGO_"))}
        env.update(PATH=self.path, CW_RELEASE_TARGETS=targets, CW_RELEASE_BUILD_CMD="cargo build",
                   CW_RELEASE_DIST_DIR=str(self.base / name), CARGO_TARGET_DIR=str(self.base / f"target-{name}"),
                   CARGO_HOME=str(self.base / "cargo-home"), **extra)
        return subprocess.run(["bash", str(SCRIPT), fx.VERSION], cwd=self.source, env=env,
                              capture_output=True, text=True)

    def asset(self, dist, target):
        return (self.base / dist / release.asset_name(fx.VERSION, target)).read_bytes()

    def test_the_macos_cw_embeds_the_runtime_and_the_delivery_carries_it(self):
        mac = self.package("mac", "aarch64-apple-darwin x86_64-apple-darwin",
                           CW_RELEASE_LOCAL_RUNTIME_DIR=str(self.runtime),
                           CODEWIRE_LOCAL_RUNTIME="/ambient/must/not/reach/other/targets.json")
        self.assertEqual(mac.returncode, 0, mac.stderr)
        self.assertEqual(release.embedded_local_runtime(self.asset("mac", "aarch64-apple-darwin")), self.document)
        self.assertIsNone(release.embedded_local_runtime(self.asset("mac", "x86_64-apple-darwin")))
        staged = self.base / "mac/local-runtime"
        self.assertEqual((staged / release.LOCAL_RUNTIME_NAME).read_bytes(), self.document)
        self.assertEqual(sorted(path.name for path in (staged / "blobs/sha256").iterdir()),
                         sorted(path.name for path in (self.runtime / "blobs/sha256").iterdir()))

        linux = self.package("full", "x86_64-unknown-linux-musl aarch64-unknown-linux-gnu",
                             CW_RELEASE_IMPORT_DIR=str(self.base / "mac"))
        self.assertEqual(linux.returncode, 0, linux.stderr)
        self.assertFalse((self.base / "full/local-runtime").exists())
        verified = subprocess.run([sys.executable, str(ROOT / "scripts/ci/release/cw_release.py"), "verify",
                                   "--dist", str(self.base / "full"), "--unsigned"],
                                  capture_output=True, text=True)
        self.assertEqual(verified.returncode, 0, verified.stderr)
        self.assertIn(f"cw-release: local runtime document_sha256={fx.digest(self.document)} blobs=12",
                      verified.stdout.splitlines())
        self.assertIn(f"cw-release: verified targets=4 version={fx.VERSION} runtime_equal=true signed=false",
                      verified.stdout.splitlines())

    def test_a_release_without_a_runtime_is_unchanged(self):
        mac = self.package("plain-mac", "aarch64-apple-darwin x86_64-apple-darwin",
                           CODEWIRE_LOCAL_RUNTIME=str(self.runtime / release.LOCAL_RUNTIME_NAME))
        self.assertEqual(mac.returncode, 0, mac.stderr)
        self.assertIsNone(release.embedded_local_runtime(self.asset("plain-mac", "aarch64-apple-darwin")))
        self.assertFalse((self.base / "plain-mac/local-runtime").exists())

    def test_a_runtime_that_cannot_be_embedded_is_refused_before_any_build(self):
        other = self.base / "other-revision"
        document, files = fx.local_runtime("d" * 40)
        (other / "blobs/sha256").mkdir(parents=True)
        (other / release.LOCAL_RUNTIME_NAME).write_bytes(document)
        for name, data in files.items():
            (other / "blobs/sha256" / name).write_bytes(data)
        for label, targets, extra in (
                ("relative", "aarch64-apple-darwin", {"CW_RELEASE_LOCAL_RUNTIME_DIR": "runtime"}),
                ("no-macos-arm64", "x86_64-apple-darwin", {"CW_RELEASE_LOCAL_RUNTIME_DIR": str(self.runtime)}),
                ("other-revision", "aarch64-apple-darwin", {"CW_RELEASE_LOCAL_RUNTIME_DIR": str(other)})):
            with self.subTest(case=label):
                result = self.package(f"refused-{label}", targets, **extra)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("package-cw-release:", result.stderr)
                self.assertFalse((self.base / f"target-refused-{label}").exists(), "a build ran")

    def test_a_runtime_both_imported_and_given_is_refused(self):
        mac = self.package("mac-twice", "aarch64-apple-darwin x86_64-apple-darwin",
                           CW_RELEASE_LOCAL_RUNTIME_DIR=str(self.runtime))
        self.assertEqual(mac.returncode, 0, mac.stderr)
        # This job builds the macOS arm64 cw itself and imports the rest,
        # whose directory also carries a staged runtime.
        twice = self.package("full-twice", "aarch64-apple-darwin x86_64-unknown-linux-musl aarch64-unknown-linux-gnu",
                             CW_RELEASE_IMPORT_DIR=str(self.base / "mac-twice"),
                             CW_RELEASE_LOCAL_RUNTIME_DIR=str(self.runtime))
        self.assertNotEqual(twice.returncode, 0)
        self.assertIn("both imported and given", twice.stderr)

if __name__ == "__main__":
    result = unittest.main(argv=[sys.argv[0], "-v"], exit=False).result
    print(f"test-package-cw-release: tests={result.testsRun} failures={len(result.failures)} "
          f"errors={len(result.errors)}")
    sys.exit(0 if result.wasSuccessful() and result.testsRun > 0 else 1)
