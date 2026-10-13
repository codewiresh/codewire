#!/usr/bin/env python3
"""Synthetic proof for the local VM runtime's parts cache and source pins (#2539).

Nothing here downloads, builds or publishes: the public origin is the release
tests' in-process FakeR2, and source downloads are served from memory.
"""

import hashlib
import importlib.util
import io
import json
import re
import shutil
import subprocess
import sys
import tarfile
import unittest
import unittest.mock
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
        x86_64 = self.recipe("kernel-x86_64")
        config = self.root / "scripts/ci/verify/linux-vmm-kernel/arm64.config"
        config.write_bytes(config.read_bytes() + b"# changed\n")
        self.assertNotEqual(self.recipe("kernel-arm64"), kernel)
        self.assertEqual(self.recipe("kernel-x86_64"), x86_64)
        config = self.root / "scripts/ci/verify/linux-vmm-kernel/x86_64.config"
        config.write_bytes(config.read_bytes() + b"# changed\n")
        self.assertNotEqual(self.recipe("kernel-x86_64"), x86_64)

    def test_a_kernel_recipe_names_its_architecture(self):
        # The x86_64 kernel is its own part: its recipe takes the x86_64
        # configuration and the architecture build-runtime-kernel.sh is given.
        shape = parts.PARTS["kernel-x86_64"]
        self.assertEqual(shape["arch"], "x86_64")
        self.assertIn("scripts/ci/verify/linux-vmm-kernel/x86_64.config", shape["files"])
        self.assertNotIn("scripts/ci/verify/linux-vmm-kernel/arm64.config", shape["files"])
        self.assertEqual(parts.PARTS["kernel-arm64"]["arch"], "arm64")
        before = self.recipe("kernel-x86_64")
        with unittest.mock.patch.dict(parts.PARTS, {"kernel-x86_64": {**shape, "arch": "arm64"}}):
            self.assertNotEqual(self.recipe("kernel-x86_64"), before)
        # The Mac-native parts have no architecture, so their recipes keep
        # the inputs they had before the Linux kernel joined the cache.
        for name in ("e2fsprogs-macos", "git-macos"):
            self.assertNotIn("arch", parts.PARTS[name])

    def test_a_recipe_ignores_other_parts_inputs(self):
        before = {name: self.recipe(name, HOST if shape["host"] else None) for name, shape in parts.PARTS.items()}
        pins = json.loads(self.pins.read_bytes())
        pins["sources"]["git"]["sha256"] = "0" * 64
        self.pins.write_text(json.dumps(pins))
        after = {name: self.recipe(name, HOST if shape["host"] else None) for name, shape in parts.PARTS.items()}
        self.assertNotEqual(after["git-macos"], before["git-macos"])
        self.assertEqual(after["kernel-arm64"], before["kernel-arm64"])
        self.assertEqual(after["kernel-x86_64"], before["kernel-x86_64"])
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

    def test_only_a_part_s_executables_are_executable(self):
        recipe = "e" * 64
        built = self.base / "kernel"
        built.mkdir()
        (built / "vmlinuz-6.18.48-codewire2").write_bytes(b"synthetic bzImage\n")
        self.fake.store(parts.record_key(recipe), parts.record("kernel-x86_64", recipe, built))
        data = (built / "vmlinuz-6.18.48-codewire2").read_bytes()
        self.fake.store(release.blob_key(fx.digest(data)), data)
        out = self.base / "out"
        self.assertTrue(parts.fetch(self.origin, "kernel-x86_64", recipe, out))
        self.assertEqual(sorted(path.name for path in out.iterdir()), ["vmlinuz-6.18.48-codewire2"])
        self.assertEqual((out / "vmlinuz-6.18.48-codewire2").stat().st_mode & 0o777, 0o644)
        for name, shape in parts.PARTS.items():
            with self.subTest(part=name):
                self.assertLessEqual(set(shape["executables"]), set(shape["outputs"]))

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

    def test_presence_reads_only_the_record(self):
        self.assertFalse(parts.present(self.origin, "git-macos", self.recipe))
        record = self.publish()
        self.assertTrue(parts.present(self.origin, "git-macos", self.recipe))
        self.assertEqual([request for request in self.fake.requests if "/blobs/" in request[2]], [])
        self.fake.store(parts.record_key(self.recipe), record.replace(b"git-macos", b"e2fsprogs-macos"))
        with self.assertRaises(parts.PartsError):
            parts.present(self.origin, "git-macos", self.recipe)

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


class RuntimeModeTest(unittest.TestCase):
    """The dry run builds the runtime exactly when one of its inputs changes."""

    def test_a_runtime_input_selects_the_full_build(self):
        for paths, mode in (
            ([], "parts"),
            (["docs/dev/README.md", "crates/codewire-cli/src/main.rs"], "parts"),
            (["crates/codewire-local-vmm/src/lib.rs"], "parts"),
            (["crates/codewire-local-vmm/macos-vz-runner/Sources/Runner/main.swift"], "full"),
            (["crates/codewire-vmm-guest-probe/src/main.rs"], "full"),
            (["Cargo.lock"], "full"),
            (["scripts/ci/release/local-runtime-sources.json"], "full"),
            (["scripts/ci/verify/linux-vmm-kernel/arm64.config"], "full"),
            (["scripts/ci/select/select-verification.sh"], "full"),
            (["scripts/ci/release"], "parts"),
            (["Cargo.lock.orig"], "parts"),
        ):
            with self.subTest(paths=paths):
                self.assertEqual(parts.runtime_mode(paths), mode)

    def test_runtime_inputs_cover_every_part_and_trigger_the_dry_run(self):
        for name, shape in parts.PARTS.items():
            for path in shape["files"]:
                with self.subTest(part=name, path=path):
                    self.assertEqual(parts.runtime_mode([path]), "full")
        workflow = (ROOT / ".gitea/workflows/cw-release-dry-run.yaml").read_text()
        triggers = workflow.split("    paths:\n", 1)[1].split("\n  workflow_dispatch:", 1)[0]
        patterns = [line.strip()[3:-1] for line in triggers.splitlines()]
        for entry in parts.RUNTIME_INPUTS:
            with self.subTest(entry=entry):
                self.assertTrue((ROOT / entry).exists())
                self.assertTrue(any(entry == pattern or (pattern.endswith("/**") and entry.startswith(pattern[:-2]))
                                    for pattern in patterns), f"{entry} does not trigger the dry run")

    def test_the_mode_reads_changed_paths_on_stdin(self):
        result = subprocess.run([sys.executable, str(ROOT / "scripts/ci/release/local_runtime_parts.py"),
                                 "runtime-mode"], input="README.md\nCargo.lock\n", capture_output=True,
                                text=True, check=True)
        self.assertEqual(result.stdout, "full\n")


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
            (("linux", "--check", "--output", str(output)), "--check takes no other argument"),
        ):
            result = self.run_script(*args)
            self.assertEqual(result.returncode, 1, args)
            self.assertIn(message, result.stderr)
        self.assertFalse(output.exists())


class GuestRootBuilderTest(unittest.TestCase):
    """The guest root builds in its pinned container, never on the runner's toolchain."""

    RUNNER_SCRIPTS = ("build-local-runtime.sh", "build-runtime-kernel.sh", "build-runtime-guest-root.sh",
                      "build-runtime-cw.sh", "runtime-container.sh")

    def test_the_runner_toolchain_is_never_changed(self):
        # The CI runner's Rust toolchain is sealed; a rustup change fails only
        # in CI (main dry run 12507). Nothing on the release's Linux side may
        # depend on one.
        for name in self.RUNNER_SCRIPTS:
            code = [line for line in (ROOT / "scripts/ci/release" / name).read_text().splitlines()
                    if not line.lstrip().startswith("#")]
            with self.subTest(script=name):
                self.assertFalse([line for line in code if re.search(r"\brustup\b", line)])

    def test_the_builder_is_the_sealed_release(self):
        pins = sources.load_pins()["guest_root_builder"]
        script = (ROOT / "scripts/ci/verify/build-local-vmm-initramfs.sh").read_text()
        rust = re.search(r"^readonly REQUIRED_RUST='([0-9.]+)'$", script, re.M).group(1)
        protoc = re.search(r"^readonly REQUIRED_PROTOC='libprotoc ([0-9.]+)'$", script, re.M).group(1)
        sealed = (ROOT / "scripts/ci/setup/assert-ci-runner-image.sh").read_text()
        self.assertIn(f"readonly rust_version='{rust}'", sealed)
        self.assertRegex(pins["image"], r"^docker\.io/library/rust@sha256:[0-9a-f]{64}$")
        self.assertIn(f"rust:{rust}-", pins["origin"])
        # The arm64 guest and the x86_64 archive packer the recipe also builds.
        self.assertEqual(sorted(pins["rust_std"]), ["aarch64-unknown-linux-musl", "x86_64-unknown-linux-musl"])
        for target, tarball in pins["rust_std"].items():
            self.assertRegex(tarball["url"], rf"^https://static\.rust-lang\.org/dist/[0-9-]+/rust-std-{rust}-{target}\.tar\.xz$")
            self.assertRegex(tarball["sha256"], r"^[0-9a-f]{64}$")
        self.assertIn(f"/download/v{protoc}/protoc-{protoc}-linux-x86_64.zip", pins["protoc"]["url"])
        # The same protoc zip the release workflows install on the runner.
        workflow = (ROOT / ".gitea/workflows/cli-release.yaml").read_text()
        self.assertIn(pins["protoc"]["url"], workflow)
        self.assertIn(f'{pins["protoc"]["sha256"]} /tmp/protoc.zip', workflow)

    def run_with_fake_docker(self, job_mounts, *paths):
        fake = fx.scratch("runtime-docker.")
        self.addCleanup(shutil.rmtree, fake)
        (fake / "docker").write_text("#!/bin/sh\n[ \"$1\" = inspect ] || exit 9\nprintf '%b' \"$FAKE_MOUNTS\"\n")
        (fake / "docker").chmod(0o755)
        shell = ('. "$1"; shift; runtime_container_mounts "$@" || exit $?; '
                 'printf "%s\\n" "${RUNTIME_MOUNTS[@]}"')
        return subprocess.run(["bash", "-c", shell, "bash", str(ROOT / "scripts/ci/release/runtime-container.sh"),
                               *paths], capture_output=True, text=True, check=False,
                              env={"PATH": f"{fake}:/usr/bin:/bin", "FAKE_MOUNTS": job_mounts})

    def test_a_job_container_shares_only_the_mounts_that_hold_the_paths(self):
        mounts = ("volume\tjob-workspace\t/workspace\n"
                  "bind\t/var/run/docker.sock\t/var/run/docker.sock\n"
                  "volume\tjob-env\t/var/run/act\n"
                  "bind\t/srv/tools\t/workspace/tools\n")
        result = self.run_with_fake_docker(mounts, "job1", "/workspace/repo", "/workspace/tools/protoc.zip",
                                           "--", "/workspace/out")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(sorted(result.stdout.split()), sorted([
            "--mount", "type=volume,source=job-workspace,target=/workspace",
            "--mount", "type=bind,source=/srv/tools,target=/workspace/tools"]))
        refused = self.run_with_fake_docker(mounts, "job1", "/workspace/repo", "--", "/tmp/out")
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("/tmp/out is not on a mount of job1", refused.stderr)
        self.assertNotEqual(self.run_with_fake_docker(mounts, "job 1", "/workspace/repo").returncode, 0)

    def test_without_a_job_container_paths_are_bound_read_only_unless_writable(self):
        result = self.run_with_fake_docker("", "", "/src", "/in/a", "--", "/out")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.split(), [
            "--mount", "type=bind,source=/src,target=/src,readonly",
            "--mount", "type=bind,source=/in/a,target=/in/a,readonly",
            "--mount", "type=bind,source=/out,target=/out"])

    def test_bad_invocations_are_refused_before_docker(self):
        base = fx.scratch("runtime-guest-root.")
        self.addCleanup(shutil.rmtree, base)
        files = {name: base / name for name in ("busybox", "runc", "rust-std", "rust-std-2", "protoc.zip")}
        for path in files.values():
            path.write_bytes(b"not the pinned bytes\n")
        script = str(ROOT / "scripts/ci/release/build-runtime-guest-root.sh")
        args = ["--busybox", str(files["busybox"]), "--runc", str(files["runc"]),
                "--rust-std", str(files["rust-std"]), "--rust-std", str(files["rust-std-2"]),
                "--protoc-zip", str(files["protoc.zip"])]
        for extra, message in (
            (["--output", str(base / "initramfs.cpio")], "--target must be"),
            (["--target", "riscv64gc-unknown-linux-musl", "--output", str(base / "initramfs.cpio")],
             "--target must be"),
        ):
            result = subprocess.run(["bash", script, *args, *extra], capture_output=True, text=True,
                                    check=False, env={"PATH": "/usr/bin:/bin"})
            with self.subTest(extra=extra):
                self.assertEqual(result.returncode, 1)
                self.assertIn(message, result.stderr)
        args += ["--target", "x86_64-unknown-linux-musl"]
        # The x86_64 recipe runs runc for its version; the read-only input
        # reaches it as an executable copy of the checked bytes.
        text = Path(script).read_text()
        self.assertIn('install -m 0500 "$runc" "$scratch/runc"', text)
        self.assertIn('-e RUNC="$scratch/runc"', text)
        for extra, message in (
            (["--output", "relative.cpio"], "--output must be an absolute path"),
            (["--output", str(base / "missing/initramfs.cpio")], "output parent does not exist"),
            (["--output", str(files["runc"])], "output already exists"),
            (["--output", str(base / "initramfs.cpio")], "no --rust-std is the pinned aarch64-unknown-linux-musl tarball"),
        ):
            result = subprocess.run(["bash", script, *args, *extra], capture_output=True, text=True,
                                    check=False, env={"PATH": "/usr/bin:/bin"})
            with self.subTest(extra=extra):
                self.assertEqual(result.returncode, 1)
                self.assertIn(message, result.stderr)
        self.assertEqual(sorted(path.name for path in base.iterdir()), sorted(files))


class CwRuntimeBuilderTest(unittest.TestCase):
    """The cw runtimes build in the pinned container with the release's own cross tools."""

    def test_the_cross_tools_are_the_release_delivery_s(self):
        builder = sources.load_pins()["cw_runtime_builder"]
        for name in ("cli-release.yaml", "cw-release-dry-run.yaml"):
            workflow = (ROOT / ".gitea/workflows" / name).read_text()
            with self.subTest(workflow=name):
                self.assertIn(f"  ZIG_VERSION: {builder['zig']['version']}\n", workflow)
                self.assertIn(f"  ZIG_X86_64_LINUX_SHA256: {builder['zig']['sha256']}\n", workflow)
                self.assertIn(f"  CARGO_ZIGBUILD_VERSION: {builder['cargo_zigbuild']}\n", workflow)
        self.assertEqual(builder["zig"]["url"], f"https://ziglang.org/download/{builder['zig']['version']}/"
                                                f"zig-x86_64-linux-{builder['zig']['version']}.tar.xz")
        script = (ROOT / "scripts/ci/release/build-runtime-cw.sh").read_text()
        # Exactly the pinned cargo-zigbuild, from its own lockfile, and the
        # producer that never passes CODEWIRE_LOCAL_RUNTIME to the build.
        self.assertIn('cargo-zigbuild --version \\"\\$ZIGBUILD\\"', script)
        self.assertIn("cargo install --locked ", script)
        self.assertIn("scripts/dev/build-native-managed-agent.py", script)
        self.assertIn("check-cw-runtime", script)
        self.assertNotIn("CODEWIRE_LOCAL_RUNTIME=", script)
        producer = (ROOT / "scripts/dev/build-native-managed-agent.py").read_text()
        self.assertNotIn("os.environ.copy()", producer)
        self.assertIn('"PATH": path,', producer)

    def test_bad_invocations_are_refused_before_docker(self):
        base = fx.scratch("runtime-cw.")
        self.addCleanup(shutil.rmtree, base)
        files = {name: base / name for name in ("rust-std", "rust-std-2", "protoc.zip", "zig.tar.xz")}
        for path in files.values():
            path.write_bytes(b"not the pinned bytes\n")
        script = str(ROOT / "scripts/ci/release/build-runtime-cw.sh")
        inputs = ["--rust-std", str(files["rust-std"]), "--rust-std", str(files["rust-std-2"]),
                  "--protoc-zip", str(files["protoc.zip"]), "--zig", str(files["zig.tar.xz"])]
        good = ["--target", "x86_64-unknown-linux-musl", "--version", "v1.2.3", *inputs]
        inside = ROOT / "scripts"
        for args, message in (
            (["--version", "v1.2.3", *inputs, "--output", str(base / "cw")], "--target must be"),
            (["--target", "aarch64-unknown-linux-gnu", "--version", "v1.2.3", *inputs, "--output", str(base / "cw")],
             "--target must be"),
            (["--target", "x86_64-unknown-linux-musl", "--version", "1.2.3", *inputs, "--output", str(base / "cw")],
             "--version must be vMAJOR.MINOR.PATCH"),
            ([*good, "--output", "relative"], "--output must be an absolute path"),
            ([*good, "--output", str(files["zig.tar.xz"])], "output already exists"),
            ([*good, "--output", str(base / "missing/cw")], "output parent does not exist"),
            ([*good, "--output", str(inside / "cw-runtime-test-output")], "inside the checkout and not git-ignored"),
            ([*good, "--jobs", "16", "--output", str(base / "cw")], "--jobs must be 1 to 8"),
            ([*good, "--output", str(base / "cw")], "no --rust-std is the pinned aarch64-unknown-linux-musl tarball"),
        ):
            result = subprocess.run(["bash", script, *args], capture_output=True, text=True, check=False,
                                    env={"PATH": "/usr/bin:/bin"})
            with self.subTest(args=args[-1]):
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn(message, result.stderr)
        self.assertEqual(sorted(path.name for path in base.iterdir()), sorted(files))
        self.assertFalse((inside / "cw-runtime-test-output").exists())

    def test_the_ci_work_directory_is_never_cw_source(self):
        # The dry run builds inside its checkout, under .local-runtime/; the
        # cw build's Cargo sources and target directory there must not enter
        # the source digest its build record binds.
        ignored = subprocess.run(["git", "-C", str(ROOT), "check-ignore", "-q", ".local-runtime/tmp/x.rs"],
                                 check=False)
        self.assertEqual(ignored.returncode, 0)
        workflow = (ROOT / ".gitea/workflows/cw-release-dry-run.yaml").read_text()
        self.assertIn('work="$GITHUB_WORKSPACE/.local-runtime"', workflow)


class SourcesTest(unittest.TestCase):
    def setUp(self):
        self.base = fx.scratch("runtime-sources.")
        self.addCleanup(shutil.rmtree, self.base)

    def test_pins_are_exact_and_agree_with_the_mac_tools(self):
        pins = sources.load_pins()
        self.assertEqual(set(pins["sources"]), {name for names in sources.SIDES.values() for name in names})
        self.assertEqual(sources.SIDES["linux-host"], ("cloud-hypervisor", "virtiofsd"))
        for tool, name in (("macos-ext4-tool", "e2fsprogs"), ("macos-git-tool", "git")):
            module = load_tool(tool)
            self.assertEqual((pins["sources"][name]["url"], pins["sources"][name]["sha256"],
                              pins["sources"][name]["version"]),
                             (module.SOURCE_URL, module.SOURCE_SHA256, module.VERSION))
        provenance = json.loads((ROOT / "scripts/ci/verify/linux-vmm-kernel/provenance.json").read_bytes())
        self.assertEqual(pins["kernel_bc"]["sha256"], provenance["bc_sha256"])
        self.assertTrue(pins["kernel_builder"]["image"].startswith("docker.io/library/archlinux@sha256:"))

    def test_initramfs_inputs_are_the_guest_root_pins(self):
        inputs = sources.load_pins()["initramfs_inputs"]
        script = (ROOT / "scripts/ci/verify/build-local-vmm-initramfs.sh").read_text()
        for target, prefix, arch, runc in (("aarch64-unknown-linux-musl", "ARM64", "aarch64", "arm64"),
                                           ("x86_64-unknown-linux-musl", "X86_64", "x86_64", "amd64")):
            pins = inputs[target]
            with self.subTest(target=target):
                self.assertIn(f"readonly {prefix}_RUNC_SHA256='{pins['runc']['sha256']}'", script)
                self.assertIn(f"readonly {prefix}_BUSYBOX_SHA256='{pins['busybox']['member_sha256']}'", script)
                self.assertIn(pins["busybox"]["sha256"], script)
                self.assertIn(pins["busybox"]["url"], script)
                self.assertEqual(pins["busybox"]["url"], "https://dl-cdn.alpinelinux.org/alpine/v3.23/main/"
                                                         f"{arch}/busybox-static-1.37.0-r30.apk")
                self.assertEqual(pins["busybox"]["member"], "bin/busybox.static")
                self.assertEqual(pins["runc"]["url"],
                                 f"https://github.com/opencontainers/runc/releases/download/v1.5.1/runc.{runc}")
        self.assertIn(inputs["aarch64-unknown-linux-musl"]["runc"]["url"], script)

    def test_linux_runtime_pins_are_what_admission_and_qualification_require(self):
        pins = sources.load_pins()
        host = pins["linux_runtime"]
        artifact = (ROOT / "crates/codewire-local-vmm/src/artifact.rs").read_text()
        self.assertIn(f'pub const CLOUD_HYPERVISOR_RELEASE: &str = "{host["cloud_hypervisor"]["version"]}";',
                      artifact)
        self.assertIn(f'pub const VIRTIOFSD_RELEASE: &str = "{host["virtiofsd"]["version"]}";', artifact)
        # The exact Cloud Hypervisor every Linux qualification ran.
        smoke = (ROOT / "scripts/ci/verify/smoke-local-vmm-cloud-hypervisor.sh").read_text()
        self.assertIn(f"readonly REQUIRED_CH_SHA256='{host['cloud_hypervisor']['sha256']}'", smoke)
        self.assertIn(f"readonly REQUIRED_CH_SIZE='{host['cloud_hypervisor']['size']}'", smoke)
        self.assertEqual(host["cloud_hypervisor"]["url"], "https://github.com/cloud-hypervisor/cloud-hypervisor/"
                                                          "releases/download/v53.0/cloud-hypervisor-static")
        self.assertEqual(host["virtiofsd"]["member"], "target/x86_64-unknown-linux-musl/release/virtiofsd")
        self.assertTrue(host["virtiofsd"]["url"].startswith("https://gitlab.com/-/project/21523468/uploads/"))
        self.assertEqual(host["virtiofsd"]["release"], "https://gitlab.com/virtio-fs/virtiofsd/-/releases/v1.14.0")
        # Each host program's source is a component of the Linux target.
        for name, source in (("cloud_hypervisor", "cloud-hypervisor"), ("virtiofsd", "virtiofsd")):
            self.assertEqual("v" + pins["sources"][source]["version"], host[name]["version"])

    def test_the_kernel_builder_installs_the_recorded_toolchains(self):
        # The builder installs exactly the toolchains the kernels' provenance
        # records: for x86_64 Arch gcc 16.1.1 built 2026-07-28 and binutils
        # 2.47, which the 2026/08/11 snapshot is the last to carry.
        pins = sources.load_pins()
        provenance = json.loads((ROOT / "scripts/ci/verify/linux-vmm-kernel/provenance.json").read_bytes())
        x86_64 = provenance["architectures"]["x86_64"]
        packages = pins["kernel_builder"]["packages"]
        self.assertEqual(x86_64["gcc_version"], "gcc (GCC) 16.1.1 20260728")
        self.assertTrue(packages["gcc"].startswith("16.1.1+"))
        self.assertEqual(x86_64["ld_version"], f"GNU ld (GNU Binutils) {packages['binutils'].split('-')[0]}")
        self.assertEqual(provenance["architectures"]["arm64"]["gcc_version"],
                         f"aarch64-linux-gnu-gcc (GCC) {packages['aarch64-linux-gnu-gcc'].split('-')[0]}")

    def test_pins_of_the_wrong_shape_are_refused(self):
        original = json.loads(sources.PINS.read_bytes())
        for name, change in (
            ("a guest root target is missing", lambda pins: pins["initramfs_inputs"].pop("x86_64-unknown-linux-musl")),
            ("an unpinned BusyBox member", lambda pins: pins["initramfs_inputs"]["x86_64-unknown-linux-musl"]
             ["busybox"].pop("member_sha256")),
            ("another Cloud Hypervisor release", lambda pins: pins["linux_runtime"]["cloud_hypervisor"]
             .__setitem__("version", "v52.0")),
            ("an unpinned virtiofsd member", lambda pins: pins["linux_runtime"]["virtiofsd"].pop("member_sha256")),
            ("an unsized Cloud Hypervisor", lambda pins: pins["linux_runtime"]["cloud_hypervisor"].pop("size")),
            ("plain HTTP", lambda pins: pins["linux_runtime"]["virtiofsd"].__setitem__("url", "http://gitlab.com/x")),
            ("an unpinned zig", lambda pins: pins["cw_runtime_builder"]["zig"].pop("sha256")),
            ("a host source on no side", lambda pins: pins["sources"].__setitem__("qemu", pins["sources"]["runc"])),
        ):
            pins = json.loads(json.dumps(original))
            change(pins)
            path = self.base / f"{len(name)}-{abs(hash(name))}.json"
            path.write_text(json.dumps(pins))
            with self.subTest(name), self.assertRaises(sources.SourcesError):
                sources.load_pins(path)

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
        host = sources.fetch_side("linux-host", self.base / "linux-host", None, pins, fetch)
        mac = sources.fetch_side("macos", self.base / "macos", None, pins, fetch)
        self.assertEqual([component["name"] for component in linux], list(sources.SIDES["linux"]))
        self.assertEqual([component["name"] for component in host], ["cloud-hypervisor", "virtiofsd"])
        self.assertEqual([component["file"] for component in host],
                         ["cloud-hypervisor.tar.gz", "virtiofsd.tar.gz"])
        self.assertEqual(host[1]["license"], "Apache-2.0 AND BSD-3-Clause")
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
