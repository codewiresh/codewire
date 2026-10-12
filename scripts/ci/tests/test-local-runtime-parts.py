#!/usr/bin/env python3
"""Synthetic proof for the local VM runtime's parts cache and source pins (#2539).

Nothing here downloads, builds or publishes: the public origin is the release
tests' in-process FakeR2, and source downloads are served from memory.
"""

import hashlib
import importlib.util
import io
import json
import shutil
import subprocess
import sys
import tarfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cw_release_fixtures as fx  # noqa: E402

release = fx.release
ROOT = fx.ROOT
sys.path.insert(0, str(ROOT / "scripts/ci/release"))
import cw_release_r2 as r2  # noqa: E402
import local_runtime_parts as parts  # noqa: E402
import local_runtime_sources as sources  # noqa: E402

HOST = {"macos": "26.0", "sdk": "26.0", "clang": "Apple clang version 17.0.0"}


def load_tool(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), ROOT / "scripts/dev" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RecipeTest(unittest.TestCase):
    def setUp(self):
        self.root = fx.scratch("runtime-parts.")
        self.addCleanup(shutil.rmtree, self.root)
        for shape in parts.PARTS.values():
            for relative in shape["files"]:
                (self.root / relative).parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / relative, self.root / relative)
        self.pins = self.root / "scripts/ci/release/local-runtime-sources.json"
        self.pins.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(parts.PINS, self.pins)

    def recipe(self, name, host=None):
        return parts.recipe(name, self.root, host=host)

    def test_a_recipe_is_its_exact_inputs(self):
        kernel = self.recipe("kernel-arm64")
        self.assertEqual(kernel, parts.recipe("kernel-arm64", host=None))
        self.assertTrue(release.is_hex(kernel, 64))
        config = self.root / "scripts/ci/verify/linux-vmm-kernel/arm64.config"
        config.write_bytes(config.read_bytes() + b"# changed\n")
        self.assertNotEqual(self.recipe("kernel-arm64"), kernel)

    def test_a_recipe_ignores_other_parts_inputs(self):
        before = {name: self.recipe(name, HOST if shape["host"] else None) for name, shape in parts.PARTS.items()}
        pins = json.loads(self.pins.read_bytes())
        pins["sources"]["git"]["sha256"] = "0" * 64
        self.pins.write_text(json.dumps(pins))
        after = {name: self.recipe(name, HOST if shape["host"] else None) for name, shape in parts.PARTS.items()}
        self.assertNotEqual(after["git-macos"], before["git-macos"])
        self.assertEqual(after["kernel-arm64"], before["kernel-arm64"])
        self.assertEqual(after["e2fsprogs-macos"], before["e2fsprogs-macos"])

    def test_mac_native_parts_are_keyed_by_their_host(self):
        with self.assertRaises(parts.PartsError):
            self.recipe("git-macos")
        with self.assertRaises(parts.PartsError):
            self.recipe("kernel-arm64", HOST)
        with self.assertRaises(parts.PartsError):
            self.recipe("git-macos", {**HOST, "xcode": "x"})
        self.assertNotEqual(self.recipe("git-macos", HOST), self.recipe("git-macos", {**HOST, "sdk": "26.1"}))


class CacheTest(unittest.TestCase):
    def setUp(self):
        self.base = fx.scratch("runtime-cache.")
        self.addCleanup(shutil.rmtree, self.base)
        self.fake = fx.FakeR2()
        self.origin = r2.PublicOrigin(self.fake)
        self.built = self.base / "built"
        self.built.mkdir()
        for name in parts.PARTS["git-macos"]["outputs"]:
            (self.built / name).write_bytes(f"synthetic {name}\n".encode())
        self.recipe = "a" * 64

    def publish(self, record=None):
        record = record or parts.record("git-macos", self.recipe, self.built)
        self.fake.store(parts.record_key(self.recipe), record)
        for name in parts.PARTS["git-macos"]["outputs"]:
            data = (self.built / name).read_bytes()
            self.fake.store(release.blob_key(fx.digest(data)), data)
        return record

    def test_a_hit_writes_exactly_the_recorded_bytes(self):
        record = self.publish()
        self.assertEqual(release.parse_canonical(record)["part"], "git-macos")
        out = self.base / "out"
        self.assertTrue(parts.fetch(self.origin, "git-macos", self.recipe, out))
        for name in parts.PARTS["git-macos"]["outputs"]:
            self.assertEqual((out / name).read_bytes(), (self.built / name).read_bytes())
            self.assertEqual((out / name).stat().st_mode & 0o777, 0o755)

    def test_a_miss_writes_nothing(self):
        out = self.base / "out"
        self.assertFalse(parts.fetch(self.origin, "git-macos", self.recipe, out))
        self.assertFalse(out.exists())

    def test_cached_bytes_must_match_their_record(self):
        self.publish()
        git = (self.built / "git").read_bytes()
        self.fake.store(release.blob_key(fx.digest(git)), git + b"tampered")
        with self.assertRaisesRegex(parts.PartsError, "differs from its record"):
            parts.fetch(self.origin, "git-macos", self.recipe, self.base / "out")
        self.assertFalse((self.base / "out").exists())

    def test_a_record_names_one_part_and_recipe(self):
        record = parts.record("git-macos", self.recipe, self.built)
        for name, recipe in (("e2fsprogs-macos", self.recipe), ("git-macos", "b" * 64)):
            with self.subTest(part=name, recipe=recipe), self.assertRaises(parts.PartsError):
                parts.parse_record(record, name, recipe)
        value = json.loads(record)
        value["files"]["extra"] = value["files"]["git"]
        with self.assertRaises(parts.PartsError):
            parts.parse_record(release.canonical(value), "git-macos", self.recipe)


class PublishTest(unittest.TestCase):
    """Records are written by the publishing job only, after the blobs."""

    @classmethod
    def setUpClass(cls):
        cls.base = fx.scratch("runtime-records.")
        cls.signer = fx.Signer(cls.base)
        (cls.base / "signed").mkdir()
        cls.dist = fx.signed_delivery(cls.base / "signed", cls.signer, runtime=True)[0]

    @classmethod
    def tearDownClass(cls):
        cls.signer.close()
        shutil.rmtree(cls.base)

    def setUp(self):
        self.fake = fx.FakeR2()
        self.s3 = r2.S3(self.fake, r2.Credentials(fx.ACCESS_KEY, fx.SECRET_KEY))
        self.records = fx.scratch("runtime-records-dir.")
        self.addCleanup(shutil.rmtree, self.records)
        # The git part's two files, as the runtime document pins them.
        _, document, blobs = release.local_runtime_paths(self.dist)
        document = json.loads(document.read_bytes())
        git = document["targets"]["macos-aarch64"]["lock"]["git"]
        self.built = fx.scratch("runtime-built.")
        self.addCleanup(shutil.rmtree, self.built)
        for key, name in (("git", "git"), ("git_remote_https", "git-remote-https")):
            shutil.copyfile(blobs / git[key]["sha256"], self.built / name)
        self.recipe = "c" * 64

    def write(self, recipe=None, directory=None):
        recipe = recipe or self.recipe
        data = parts.record("git-macos", recipe, directory or self.built)
        (self.records / f"{recipe}.json").write_bytes(data)
        return data

    def test_records_are_written_once_and_read_back(self):
        data = self.write()
        self.assertEqual(parts.publish(self.s3, self.dist, self.records), 1)
        self.assertEqual(self.fake.objects[parts.record_key(self.recipe)][0], data)
        self.assertTrue(all(request[3].get("if-none-match") == "*" for request in self.fake.puts()))
        self.assertEqual(parts.publish(self.s3, self.dist, self.records), 1)

    def test_a_record_names_only_published_blobs(self):
        (self.built / "git").write_bytes(b"not a published blob\n")
        self.write()
        with self.assertRaisesRegex(parts.PartsError, "does not publish"):
            parts.publish(self.s3, self.dist, self.records)
        self.assertEqual(self.fake.puts(), [])

    def test_an_existing_record_with_other_bytes_is_kept(self):
        value = json.loads(self.write())
        value["files"]["git"] = value["files"]["git-remote-https"]
        existing = release.canonical(value)
        self.fake.store(parts.record_key(self.recipe), existing)
        self.assertEqual(parts.publish(self.s3, self.dist, self.records), 0)
        self.assertEqual(self.fake.objects[parts.record_key(self.recipe)][0], existing)

    def test_a_record_is_named_by_its_recipe(self):
        self.write()
        (self.records / f"{self.recipe}.json").rename(self.records / f"{'d' * 64}.json")
        with self.assertRaisesRegex(parts.PartsError, "named by its recipe"):
            parts.publish(self.s3, self.dist, self.records)
        self.assertEqual(self.fake.puts(), [])


class BuildScriptTest(unittest.TestCase):
    """The orchestrator refuses a bad invocation before it writes anything."""

    def run_script(self, *args):
        return subprocess.run(["bash", str(ROOT / "scripts/ci/release/build-local-runtime.sh"), *args],
                              capture_output=True, text=True, check=False)

    def test_bad_invocations_write_nothing(self):
        base = fx.scratch("runtime-build-script.")
        self.addCleanup(shutil.rmtree, base)
        output = base / "out"
        self.assertEqual(self.run_script().returncode, 2)
        for args, message in (
            (("windows", "--output", str(output)), "mode must be linux or macos"),
            (("macos", "--linux", str(base), "--source-sha", "a" * 40, "--output", str(output)),
             "Apple silicon Mac"),
            (("linux", "--output", "relative"), "absolute path"),
            (("linux", "--output", str(base)), "already exists"),
            (("linux", "--bogus"), "unknown argument"),
        ):
            result = self.run_script(*args)
            self.assertEqual(result.returncode, 1, args)
            self.assertIn(message, result.stderr)
        self.assertFalse(output.exists())


class SourcesTest(unittest.TestCase):
    def setUp(self):
        self.base = fx.scratch("runtime-sources.")
        self.addCleanup(shutil.rmtree, self.base)

    def test_pins_are_exact_and_agree_with_the_mac_tools(self):
        pins = sources.load_pins()
        self.assertEqual(set(pins["sources"]), {name for names in sources.SIDES.values() for name in names})
        for tool, name in (("macos-ext4-tool", "e2fsprogs"), ("macos-git-tool", "git")):
            module = load_tool(tool)
            self.assertEqual((pins["sources"][name]["url"], pins["sources"][name]["sha256"],
                              pins["sources"][name]["version"]),
                             (module.SOURCE_URL, module.SOURCE_SHA256, module.VERSION))
        provenance = json.loads((ROOT / "scripts/ci/verify/linux-vmm-kernel/provenance.json").read_bytes())
        self.assertEqual(pins["kernel_bc"]["sha256"], provenance["bc_sha256"])
        self.assertTrue(pins["kernel_builder"]["image"].startswith("docker.io/library/archlinux@sha256:"))

    def test_initramfs_inputs_are_the_guest_root_pins(self):
        pins = sources.load_pins()["initramfs_inputs"]
        script = (ROOT / "scripts/ci/verify/build-local-vmm-initramfs.sh").read_text()
        self.assertIn(f"readonly ARM64_RUNC_SHA256='{pins['runc']['sha256']}'", script)
        self.assertIn(f"readonly ARM64_BUSYBOX_SHA256='{pins['busybox']['member_sha256']}'", script)
        self.assertIn(pins["busybox"]["sha256"], script)
        self.assertIn(pins["busybox"]["url"], script)
        self.assertIn(pins["runc"]["url"], script)

    def synthetic(self):
        """Pins whose sources are served from memory."""
        served, pins = {}, json.loads(sources.PINS.read_bytes())
        for name, source in pins["sources"].items():
            if "url" in source:
                data = f"synthetic {name}\n".encode()
                source["url"] = f"https://example.invalid/{name}.tar.gz"
                source["sha256"] = hashlib.sha256(data).hexdigest()
                served[source["url"]] = data
            elif "aports" in source:
                files = {}
                for file in ("APKBUILD", "busyboxconfig", "0001-a.patch"):
                    data = f"{file}\n".encode()
                    files[file] = hashlib.sha256(data).hexdigest()
                    aports = source["aports"]
                    served[f"{aports['base']}/{aports['commit']}/{aports['path']}/{file}"] = data
                source["aports"]["files"] = files

        def fetch(url, digest):
            data = served[url]
            if hashlib.sha256(data).hexdigest() != digest:
                raise sources.SourcesError(f"{url} differs from its pinned SHA-256")
            return data
        return pins, served, fetch

    def test_alpine_build_files_assemble_deterministically(self):
        pins, _served, fetch = self.synthetic()
        entry = pins["sources"]["busybox-alpine-build"]
        first = sources.aports_tar("busybox-alpine-build", entry, fetch)
        self.assertEqual(first, sources.aports_tar("busybox-alpine-build", entry, fetch))
        with tarfile.open(fileobj=io.BytesIO(first)) as tar:
            members = tar.getmembers()
        self.assertEqual([member.name for member in members],
                         [f"busybox-alpine-build-1.37.0-r30/{file}" for file in ("0001-a.patch", "APKBUILD",
                                                                                 "busyboxconfig")])
        self.assertTrue(all(member.mode == 0o644 and member.mtime == 0 and member.uid == 0 for member in members))

    def test_each_side_writes_its_sources_and_components(self):
        pins, _served, fetch = self.synthetic()
        kernel = self.base / "kernel"
        kernel.mkdir()
        (kernel / "linux-source.tar.xz").write_bytes(b"synthetic linux source\n")
        linux = sources.fetch_side("linux", self.base / "linux", kernel, pins, fetch)
        mac = sources.fetch_side("macos", self.base / "macos", None, pins, fetch)
        self.assertEqual([component["name"] for component in linux], list(sources.SIDES["linux"]))
        self.assertEqual([component["name"] for component in mac], ["e2fsprogs", "git"])
        listed = json.loads((self.base / "linux/components.json").read_bytes())
        self.assertEqual(listed, linux)
        self.assertEqual((self.base / "linux/linux-source.tar.xz").read_bytes(), b"synthetic linux source\n")
        self.assertEqual(listed[0]["license"], "GPL-2.0-only")
        with self.assertRaisesRegex(sources.SourcesError, "needs --kernel"):
            sources.fetch_side("linux", self.base / "no-kernel", None, pins, fetch)

    def test_a_source_that_differs_from_its_pin_is_refused(self):
        pins, served, fetch = self.synthetic()
        served[pins["sources"]["runc"]["url"]] = b"tampered\n"
        kernel = self.base / "kernel"
        kernel.mkdir()
        (kernel / "linux-source.tar.xz").write_bytes(b"x\n")
        with self.assertRaisesRegex(sources.SourcesError, "differs from its pinned"):
            sources.fetch_side("linux", self.base / "linux", kernel, pins, fetch)


if __name__ == "__main__":
    result = unittest.main(argv=[sys.argv[0], "-v"], exit=False).result
    print(f"test-local-runtime-parts: tests={result.testsRun} failures={len(result.failures)} "
          f"errors={len(result.errors)}")
    sys.exit(0 if result.wasSuccessful() and result.testsRun > 0 else 1)
