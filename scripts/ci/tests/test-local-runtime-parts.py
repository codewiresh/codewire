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
