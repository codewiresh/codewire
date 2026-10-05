#!/usr/bin/env python3
"""Credential-free source/producer component fixtures; no Cargo or Docker.

Git repositories and ELF bytes are synthetic. Transport producer/unpacker
actually run their checked-in Python paths; the synthetic executable never
runs. A successful component fixture is not an observed compiler/image solve.
"""

import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

source = load("cw_source_test", ROOT / "scripts/ci/images/prepare-cw-source-context.py")
finalizer = load("cw_source_finalizer_test", ROOT / "scripts/ci/images/finalize-cw-runtime-source.py")
driver = load("cw_source_driver_test", ROOT / "scripts/ci/images/build-cw-runtime-source.py")
sys.path.insert(0, str(Path(__file__).parent))
import cw_release_fixtures as fixture  # noqa: E402

FAILURES = (source.Refused, source.release.ReleaseError, OSError, ValueError, KeyError, TypeError)
LEGACY_HEAD_WITNESS = False


def write(path, raw, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    if os.path.lexists(path):
        path.chmod(0o600)
    path.write_bytes(raw)
    path.chmod(mode)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class Source(unittest.TestCase):
    def setUp(self):
        self.bytecode = mock.patch.dict(os.environ, {"PYTHONDONTWRITEBYTECODE": "1"})
        self.bytecode.start()
        self.addCleanup(self.bytecode.stop)
        self.temporary = tempfile.TemporaryDirectory(prefix="cw-source-test-", dir=ROOT / ".tmp")
        self.base = Path(self.temporary.name)
        self.repo = self.base / "selected"
        self.repo.mkdir()
        for name in source.PREREQUISITES:
            write(self.repo / name, (ROOT / name).read_bytes(), 0o755 if os.access(ROOT / name, os.X_OK) else 0o644)
        # Exercise the actual shared source contract; this fixture adds no
        # producer inputs that production omitted.
        write(self.repo / "crates/demo/src/lib.rs", b"pub fn demo() {}\n")
        write(self.repo / "crates/demo/src/empty.rs", b"")
        write(self.repo / "Cargo.toml", b'[workspace]\nmembers = ["crates/demo"]\n')
        write(self.repo / "Cargo.lock", b"version = 4\n")
        write(self.repo / "rust-toolchain.toml", b'[toolchain]\nchannel = "1.93.0"\n')
        write(self.repo / ".gitignore", b"target/\n.tmp/\n")
        write(self.repo / "README.md", b"retained Git object, not a compiler input\n")
        self.git("init", "-q")
        self.git("add", "-A")
        self.git("-c", "user.name=Synthetic", "-c", "user.email=synthetic@example.invalid", "commit", "-q", "-m", "fixture")
        self.revision = self.git("rev-parse", "HEAD").strip().decode()
        self.output = self.base / "capsule"

    def tearDown(self):
        for module in (source, finalizer.source, driver.source, driver.finalizer.source):
            module.asset.STOP = None
            module.DEADLINE = None
        self.temporary.cleanup()

    def git(self, *args, input_bytes=None):
        return source.git(self.repo, list(args), input_bytes)

    def prepare(self, output=None, profile="ci", version=fixture.VERSION):
        return source.prepare(self.repo, self.revision, profile, version, output or self.output)

    def admits(self, capsule, request_sha=None):
        return source.admit(capsule.path / "source", capsule.path / "git", capsule.path / "request.json",
                            request_sha or capsule.outputs["request.json"].sha256)

    def test_real_git_closure_exact_digest_and_deterministic_context(self):
        with self.prepare() as first, self.prepare(self.base / "again") as second:
            self.assertEqual(first.outputs["request.json"].data, second.outputs["request.json"].data)
            self.assertEqual(first.outputs["git/index"].data, second.outputs["git/index"].data)
            self.assertEqual(first.model["source"]["revision"], self.revision)
            self.assertFalse((first.path / "source/README.md").exists())
            for _ in range(2):
                first.revalidate()
            with self.admits(first) as admitted:
                admitted.revalidate()
                self.assertEqual(admitted.model["source"], first.model["source"])
                self.assertEqual(admitted.files["source/crates/demo/src/empty.rs"].data, b"")
            self.assertNotIn(str(self.base).encode(), first.outputs["request.json"].data)

    def test_normal_python_imports_preserve_sealed_source_and_caller_flag(self):
        environment = {key: value for key, value in os.environ.items() if key != "PYTHONDONTWRITEBYTECODE"}
        with self.prepare() as capsule:
            selected = capsule.path / "source"
            script = selected / "scripts/ci/images/finalize-cw-runtime-source.py"
            result = subprocess.run([sys.executable, str(script), "--help"], cwd=selected,
                                    env=environment, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(list(selected.rglob("__pycache__")), [])
            capsule.revalidate()
            program = r"""
import importlib.util, sys
from pathlib import Path
assert sys.dont_write_bytecode is False
root, capsule = (Path(value) for value in sys.argv[1:3])
spec = importlib.util.spec_from_file_location('normal_host_driver', root / 'scripts/ci/images/build-cw-runtime-source.py')
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)
assert sys.dont_write_bytecode is False
module = driver.load('normal_selected_finalizer', capsule / 'source/scripts/ci/images/finalize-cw-runtime-source.py')
assert sys.dont_write_bytecode is False
with module.source.admit(capsule / 'source', capsule / 'git', capsule / 'request.json', sys.argv[3]) as held:
    held.revalidate()
assert sys.dont_write_bytecode is False
assert not list((capsule / 'source').rglob('__pycache__'))
print('normal-default-cli-and-library-source-unchanged/flag-restored')
"""
            result = subprocess.run([sys.executable, "-c", program, str(ROOT), str(capsule.path),
                                     capsule.outputs["request.json"].sha256], cwd=selected,
                                    env=environment, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(result.stdout, b"normal-default-cli-and-library-source-unchanged/flag-restored\n")
            capsule.revalidate()

    def test_edited_worktree_and_stage_zero_index_are_not_head_relabels(self):
        with self.prepare() as first:
            before = first.model["source"]["source_tree_sha256"]
        write(self.repo / "crates/demo/src/lib.rs", b"pub fn edited() {}\n")
        self.git("add", "crates/demo/src/lib.rs")
        write(self.repo / "crates/demo/src/added.rs", b"pub fn untracked() {}\n")
        with self.prepare(self.base / "edited") as second:
            self.assertEqual(second.model["source"]["revision"], self.revision)
            self.assertNotEqual(second.model["source"]["source_tree_sha256"], before)
            self.assertIn("crates/demo/src/added.rs", second.model["digest_inputs"])
            self.assertEqual(second.index, source.normalized_index(source.index_entries(self.git("ls-files", "--stage", "-z"))))
            with self.admits(second) as admitted:
                admitted.revalidate()

    def test_legacy_head_stub_never_becomes_real_git_provenance(self):
        with self.prepare() as capsule:
            # Remove one actual HEAD tree object, preserving HEAD/index/source
            # strings. Existing digest/HEAD helpers do not validate that object.
            oid = capsule.model["source"]["git_tree"]
            missing = capsule.path / f"git/objects/{oid[:2]}/{oid[2:]}"
            missing.unlink()
            with self.assertRaises(FAILURES):
                if LEGACY_HEAD_WITNESS:
                    with source.git_scope(capsule.path / "git", capsule.path / "source"):
                        capsule.selected.head_revision(capsule.path / "source")
                        capsule.selected.source_tree_sha256(capsule.path / "source")
                else:
                    with self.admits(capsule):
                        pass

    def test_source_git_local_configuration_hooks_and_credentials_are_not_copied(self):
        canary = b"SYNTHETIC_GIT_PRIVATE_NEVER_COPY"
        config = self.repo / ".git/config"
        write(config, config.read_bytes() + b"\n[credential]\n\thelper = " + canary + b"\n")
        write(self.repo / ".git/hooks/synthetic", canary)
        write(self.repo / ".git/info/exclude", canary + b"\n")
        with self.prepare() as capsule:
            self.assertEqual(set(os.listdir(capsule.path / "git")), {"HEAD", "index", "shallow", "objects", "refs"})
            self.assertFalse(any(canary in held.data for held in capsule.outputs.values()))
            with self.admits(capsule) as admitted:
                admitted.revalidate()

    def test_unresolved_or_foreign_index_refuses_before_capsule(self):
        blob = self.git("rev-parse", "HEAD:crates/demo/src/lib.rs").strip().decode()
        entries = f"0 {'0' * 40}\tcrates/demo/src/lib.rs\0".encode()
        entries += f"100644 {blob} 1\tcrates/demo/src/lib.rs\0".encode()
        self.git("update-index", "-z", "--index-info", input_bytes=entries)
        with self.assertRaises(FAILURES):
            self.prepare()
        self.assertFalse(self.output.exists())

    def test_missing_or_undigested_producer_prerequisite_refuses(self):
        path = self.repo / "scripts/ci/release/cw_release.py"
        original = (ROOT / "scripts/ci/release/cw_release.py").read_bytes()
        omitted = b'"scripts/ci/images/build-cw-runtime-source.py",'
        self.assertEqual(original.count(omitted), 1)
        write(path, original.replace(omitted, b"", 1))
        with self.assertRaises(FAILURES):
            self.prepare()
        self.assertFalse(self.output.exists())

    def test_symlink_hardlink_writable_and_missing_source_refusals(self):
        path = self.repo / "crates/demo/src/lib.rs"
        raw = path.read_bytes()
        for kind in ("symlink", "hardlink", "writable", "missing"):
            with self.subTest(kind=kind):
                if os.path.lexists(path):
                    path.unlink()
                external = self.base / ("external-" + kind)
                write(external, raw)
                if kind == "symlink":
                    path.symlink_to(external)
                elif kind == "hardlink":
                    os.link(external, path)
                elif kind == "writable":
                    write(path, raw, 0o666)
                with self.assertRaises(FAILURES):
                    self.prepare()
                self.assertFalse(self.output.exists())
        write(path, raw)

    def test_original_and_capsule_replacement_or_extra_leaf_refuse(self):
        with self.prepare() as capsule:
            write(self.repo / "crates/demo/src/lib.rs", b"pub fn replacement() {}\n")
            with self.assertRaises(FAILURES):
                capsule.revalidate()
        with self.prepare(self.base / "second") as capsule:
            write(capsule.path / "source/extra", b"not admitted\n")
            with self.assertRaises(FAILURES):
                capsule.revalidate()
            with self.assertRaises(FAILURES):
                self.admits(capsule)

    def test_request_pin_canonical_type_target_profile_and_full_inventory(self):
        with self.prepare() as capsule:
            original = capsule.outputs["request.json"].data
            with self.assertRaises(FAILURES):
                self.admits(capsule, "0" * 64)
            for changes in ({"target": "aarch64-unknown-linux-gnu"}, {"profile": "dev"},
                            {"version": True}, {"extra": 1}, {"prerequisites": []},
                            {"source": capsule.model["source"] | {"object_count": True}},
                            {"source": capsule.model["source"] | {"index_sha256": "0" * 64}}):
                with self.subTest(changes=changes):
                    raw = source.release.canonical(capsule.model | changes)
                    write(capsule.path / "request.json", raw, 0o400)
                    with self.assertRaises(FAILURES):
                        self.admits(capsule, sha(raw))
            for raw in (b" " + original, original.replace(b'"target":', b'"target":"x","target":', 1), b"[]\n"):
                write(capsule.path / "request.json", raw, 0o400)
                with self.assertRaises(FAILURES):
                    self.admits(capsule, sha(raw))

    def test_wrong_selected_revision_profile_version_and_existing_output(self):
        for revision, profile, version in (("0" * 40, "ci", fixture.VERSION), (self.revision, "dev", fixture.VERSION),
                                         (self.revision, "ci", ""), (self.revision, "ci", "bad/version")):
            with self.subTest(profile=profile, version=version):
                with self.assertRaises(FAILURES):
                    source.prepare(self.repo, revision, profile, version, self.output)
                self.assertFalse(self.output.exists())
        self.output.mkdir()
        write(self.output / "sentinel", b"preserve\n")
        with self.assertRaises(FAILURES):
            self.prepare()
        self.assertEqual((self.output / "sentinel").read_bytes(), b"preserve\n")

    def test_git_object_byte_and_type_admission(self):
        with self.prepare() as capsule:
            oid = capsule.model["source"]["git_tree"]
            path = capsule.path / f"git/objects/{oid[:2]}/{oid[2:]}"
            write(path, b"not a loose Git object", 0o400)
            with self.assertRaises(FAILURES):
                self.admits(capsule)

    def test_git_overrides_and_ambient_credentials_do_not_reach_cargo(self):
        projection = source.git_environment()
        self.assertEqual((projection["GIT_CONFIG_KEY_3"], projection["GIT_CONFIG_VALUE_3"]), ("maintenance.auto", "false"))
        self.assertEqual((projection["GIT_CONFIG_KEY_4"], projection["GIT_CONFIG_VALUE_4"]), ("gc.auto", "0"))
        with self.prepare() as capsule:
            ambient = {"GIT_DIR": "/wrong", "GIT_CONFIG_COUNT": "99", "HTTP_PROXY": "http://invalid",
                       "SYNTHETIC_PROVIDER_SECRET": "CANARY", "RUSTC_WRAPPER": "/usr/local/bin/sccache",
                       "SCCACHE_DIRECT": "false", "CODEWIRE_VERSION": "unselected"}
            with mock.patch.dict(os.environ, ambient):
                environment = finalizer.cargo_environment(capsule.model, self.base)
            self.assertFalse(any(key.startswith("GIT_") for key in environment))
            self.assertNotIn("HTTP_PROXY", environment)
            self.assertNotIn("SYNTHETIC_PROVIDER_SECRET", environment)
            self.assertEqual(environment["CODEWIRE_VERSION"], fixture.VERSION)
            self.assertEqual(environment["RUSTC_WRAPPER"], "/usr/local/bin/sccache")
            self.assertEqual(environment["SCCACHE_DIRECT"], "false")
            self.assertIn("--profile", finalizer.command("ci"))
            self.assertIn("--release", finalizer.command("release"))
            self.assertNotIn("--profile", finalizer.command("release"))

    def build_bytes(self, capsule, record_changes=None):
        model = capsule.model
        values = {"version": model["version"], "revision": self.revision,
                  "tree": model["source"]["source_tree_sha256"], "rustc": fixture.RUSTC}
        values.update(record_changes or {})
        raw = fixture.executable(source.TARGET, **values)
        target = self.base / "target"
        cargo = self.base / "cargo"
        binary, depinfo = target / "cw", target / "cw.d"
        write(binary, raw, 0o500)
        write(depinfo, (str(binary) + ": " + str(capsule.path / "source/crates/demo/src/lib.rs") + "\n").encode(), 0o400)
        log = self.base / "compile.log"
        write(log, b"synthetic admission only: no compiler or executable ran\n", 0o400)
        result = {"command": finalizer.command(model["profile"]), "exit": 0, "elapsed_seconds": 0,
                  "log": str(log), "log_sha256": sha(log.read_bytes()), "timed_out": False, "interrupted": False,
                  "unexpected_family": False, "cleanup_unknown": False}
        return binary, depinfo, target, cargo, result

    def test_actual_shared_admission_transport_export_and_no_execution(self):
        with self.prepare() as capsule:
            binary, depinfo, target, cargo, result = self.build_bytes(capsule)
            with self.admits(capsule) as admitted:
                receipt = finalizer.finalize(admitted, binary, depinfo, fixture.RUSTC, result,
                                             self.base / "export", target, cargo)
                self.assertEqual(receipt["repository_input_count"], 1)
                self.assertEqual(receipt["source"]["revision"], self.revision)
                self.assertIs(receipt["cache_qualified"], False)
            checked = finalizer.verify_export(self.base / "export", capsule.model, capsule.outputs["request.json"].sha256)
            self.assertEqual(checked["payload"]["sha256"], sha(binary.read_bytes()))
            self.assertEqual((self.base / "export/cw.d").read_bytes(), depinfo.read_bytes())
            self.assertEqual((self.base / "export/cw").read_bytes(), binary.read_bytes())
            self.assertEqual(set(os.listdir(self.base / "export")), finalizer.FILES)

    def test_explicit_owned_docker_route_keeps_the_fixed_producer_suffix(self):
        with driver.prepare_plan(self.repo, self.revision, "ci", fixture.VERSION, self.base / "owned-route") as prepared:
            fixed = driver.producer_arguments(prepared.capsule, prepared.path)
            driver.admit_solve_command(["/owned/fixture/bin/docker", "buildx", "build", *fixed], fixed)
            for binary in ("/owned/../bin/docker", "./docker", "/owned/bin/other"):
                with self.subTest(binary=binary), self.assertRaises(FAILURES):
                    driver.admit_solve_command([binary, "buildx", "build", *fixed], fixed)
            with self.assertRaises(FAILURES):
                driver.admit_solve_command(["/owned/bin/docker", "buildx", "bake", *fixed], fixed)

    def test_failed_cancelled_unknown_and_wrong_record_no_producer_receipt(self):
        with self.prepare() as capsule:
            binary, depinfo, target, cargo, result = self.build_bytes(capsule)
            with self.admits(capsule) as admitted:
                for changes in ({"exit": 1}, {"exit": False}, {"interrupted": True}, {"cleanup_unknown": True},
                                {"timed_out": True}, {"unexpected_family": True}, {"command": ["cargo", "build"]},
                                {"elapsed_seconds": float("nan")}, {"elapsed_seconds": True},
                                {"elapsed_seconds": 10801}, {"extra": None}):
                    with self.subTest(changes=changes), self.assertRaises(FAILURES):
                        finalizer.finalize(admitted, binary, depinfo, fixture.RUSTC, result | changes,
                                           self.base / "export", target, cargo)
                    self.assertFalse((self.base / "export").exists())
                raw = fixture.executable(source.TARGET, revision=self.revision,
                                         tree=capsule.model["source"]["source_tree_sha256"], version="v9.9.9")
                write(binary, raw, 0o500)
                with self.assertRaises(FAILURES):
                    finalizer.finalize(admitted, binary, depinfo, fixture.RUSTC, result,
                                       self.base / "export", target, cargo)
                self.assertFalse((self.base / "export").exists())

    def test_depinfo_undigested_or_foreign_input_and_compiler_pin_refuse(self):
        with self.prepare() as capsule:
            binary, depinfo, target, cargo, result = self.build_bytes(capsule)
            with self.admits(capsule) as admitted:
                for path in (self.base / "foreign.rs", capsule.path / "source/README.md"):
                    write(depinfo, (str(binary) + ": " + str(path) + "\n").encode(), 0o400)
                    with self.assertRaises(FAILURES):
                        finalizer.finalize(admitted, binary, depinfo, fixture.RUSTC, result,
                                           self.base / "export", target, cargo)
                    self.assertFalse((self.base / "export").exists())
                with self.assertRaises(FAILURES):
                    finalizer.finalize(admitted, binary, depinfo, "rustc 1.92.0 (wrong)", result,
                                       self.base / "export", target, cargo)

    def test_canonical_host_finish_binds_metadata_log_assets_and_refusals(self):
        with driver.prepare_plan(self.repo, self.revision, "ci", fixture.VERSION, self.base / "task") as prepared:
            capsule = prepared.capsule
            binary, depinfo, target, cargo, result = self.build_bytes(capsule)
            with self.admits(capsule) as admitted:
                finalizer.finalize(admitted, binary, depinfo, fixture.RUSTC, result, prepared.path / "assets", target, cargo)
            build_log = prepared.path / "build.log"
            write(build_log, b"synthetic solve metadata, no Docker ran\n", 0o400)
            arguments = driver.producer_arguments(capsule, prepared.path)
            result = result | {"command": ["/usr/bin/docker", "buildx", "build", "--builder", "owned", *arguments],
                               "log": str(build_log), "log_sha256": sha(build_log.read_bytes())}
            metadata = prepared.path / "metadata.json"
            write(metadata, source.release.canonical({"buildx.build.ref": "owned/owned-node/" + "a" * 24}), 0o400)
            for changes in ({"exit": 1}, {"exit": False}, {"interrupted": True}, {"cleanup_unknown": True}):
                with self.assertRaises(FAILURES):
                    driver.finish(prepared, result | changes, "owned")
                self.assertFalse((prepared.path / "build.json").exists())
            with self.assertRaises(FAILURES):
                driver.finish(prepared, result, "another")
            self.assertFalse((prepared.path / "build.json").exists())
            receipt = driver.finish(prepared, result, "owned")
            self.assertEqual(receipt["build_ref"], "owned/owned-node/" + "a" * 24)
            self.assertIs(receipt["cache_qualified"], False)
            self.assertIs(receipt["image_qualified"], False)

    def test_metadata_binds_builder_without_inventing_its_node_name(self):
        for node in ("owned-node", "owned0"):
            raw = source.release.canonical({"buildx.build.ref": "owned/" + node + "/" + "a" * 24})
            self.assertEqual(driver.metadata_reference(raw, "owned"), "owned/" + node + "/" + "a" * 24)
            with self.assertRaises(FAILURES):
                driver.metadata_reference(raw, "another")

    def completed_task(self, name="task"):
        """Actual admission of synthetic bytes, never a claimed Docker solve."""
        with driver.prepare_plan(self.repo, self.revision, "ci", fixture.VERSION, self.base / name) as prepared:
            capsule = prepared.capsule
            binary, depinfo, target, cargo, result = self.build_bytes(capsule)
            with self.admits(capsule) as admitted:
                finalizer.finalize(admitted, binary, depinfo, fixture.RUSTC, result,
                                   prepared.path / "assets", target, cargo)
            log = prepared.path / "build.log"
            write(log, b"synthetic solve evidence, no compiler or Docker ran\n", 0o400)
            command = ["/usr/bin/docker", "buildx", "build", "--builder", "owned",
                       *driver.producer_arguments(capsule, prepared.path)]
            write(prepared.path / "metadata.json", source.release.canonical(
                {"buildx.build.ref": "owned/owned-node/" + "a" * 24}), 0o400)
            completed = driver.finish(prepared, result | {"command": command, "log": str(log),
                                      "log_sha256": sha(log.read_bytes())}, "owned")
        return completed

    def reopen(self, completed, revision=None, profile="ci", version=fixture.VERSION, pin=None):
        return driver.reopen(completed["receipt"]["path"], pin or completed["receipt"]["sha256"],
                             self.repo, revision or self.revision, profile, version)

    def test_completed_reopen_holds_original_bytes_and_never_builds_or_rewrites(self):
        completed = self.completed_task()
        task = self.base / "task"
        before = {name: (sha((task / name).read_bytes()), (task / name).stat().st_mtime_ns)
                  for name in ("build.json", "metadata.json", "build.log", "assets/producer.json", "assets/cw.d")}
        with mock.patch.object(driver.owner, "run_owned", side_effect=AssertionError("no replay")), \
             mock.patch.object(driver, "finish", side_effect=AssertionError("no new build evidence")), \
             self.reopen(completed) as retained:
            self.assertIs(retained.reused, True)
            summary = retained.summary
            for name, binding in completed.items():
                self.assertEqual(summary[name], binding)
            self.assertEqual(summary["current_source"], summary["source"])
            summary["source"]["revision"] = "0" * 40
            self.assertEqual(retained.summary["source"]["revision"], self.revision)
            self.assertEqual(set(finalizer.FILES), {name.removeprefix("asset/") for name in retained.files
                                                   if name.startswith("asset/")})
            retained.revalidate()
            retained.revalidate()
        self.assertEqual(before, {name: (sha((task / name).read_bytes()), (task / name).stat().st_mtime_ns)
                                  for name in before})

    def test_docs_only_revision_reuse_preserves_original_compilation_identity(self):
        completed = self.completed_task()
        write(self.repo / "README.md", b"docs-only consumer revision\n")
        self.git("add", "README.md")
        self.git("-c", "user.name=Synthetic", "-c", "user.email=synthetic@example.invalid", "commit", "-q", "-m", "docs only")
        current = self.git("rev-parse", "HEAD").strip().decode()
        with self.reopen(completed, revision=current) as retained:
            summary = retained.summary
            self.assertEqual(summary["source"], completed["source"])
            self.assertEqual(summary["payload"]["source_revision"], self.revision)
            self.assertEqual(summary["current_source"]["revision"], current)
            self.assertNotEqual(summary["current_source"]["git_tree"], summary["source"]["git_tree"])
            self.assertEqual(summary["current_source"]["source_tree_sha256"], summary["source"]["source_tree_sha256"])
            self.assertEqual(summary["build_ref"], completed["build_ref"])
            retained.revalidate()

    def test_reopen_wrong_pin_revision_profile_version_and_relevant_input_refuse(self):
        completed = self.completed_task()
        for changes in ({"pin": "0" * 64}, {"revision": "0" * 40}, {"profile": "release"}, {"version": "v9.9.9"}):
            with self.subTest(changes=changes), self.assertRaises(FAILURES):
                self.reopen(completed, **changes)
        for name in ("crates/demo/src/lib.rs", "scripts/ci/images/finalize-cw-runtime-source.py",
                     "images/base/apt-transport.conf"):
            path = self.repo / name
            raw, mode = path.read_bytes(), stat.S_IMODE(path.stat().st_mode)
            write(path, raw + b"\nchanged source or prerequisite\n", mode)
            with self.subTest(name=name), self.assertRaises(FAILURES):
                self.reopen(completed)
            write(path, raw, mode)
        with self.reopen(completed) as retained:
            write(self.repo / "crates/demo/src/extra.rs", b"pub fn added() {}\n")
            with self.assertRaises(FAILURES):
                retained.revalidate()

    def test_reopen_changed_retained_assets_log_metadata_and_foreign_path_refuse(self):
        for index, name in enumerate(("assets/cw", "assets/cw.d", "assets/runtime.pack", "build.log", "metadata.json")):
            completed = self.completed_task("task-" + str(index))
            task = Path(completed["receipt"]["path"]).parent
            path = task / name
            raw, mode = path.read_bytes(), stat.S_IMODE(path.stat().st_mode)
            with self.reopen(completed) as retained:
                write(path, raw + b"changed", mode)
                with self.subTest(name=name), self.assertRaises(FAILURES):
                    retained.revalidate()
            with self.assertRaises(FAILURES):
                self.reopen(completed)
        completed = self.completed_task("foreign-task")
        task = Path(completed["receipt"]["path"]).parent
        receipt_path = task / "build.json"
        original = source.release.parse_canonical(receipt_path.read_bytes())
        foreign = str(self.base / "foreign")
        changed = original | {"metadata": original["metadata"] | {"path": foreign}}
        raw = source.release.canonical(changed)
        write(receipt_path, raw, 0o400)
        original_held, opened = driver.source.HeldSourceFile, []
        def tracked_open(path, *args, **kwargs):
            opened.append(str(path))
            return original_held(path, *args, **kwargs)
        with mock.patch.object(driver.source, "HeldSourceFile", side_effect=tracked_open):
            with self.assertRaises(FAILURES):
                self.reopen(completed, pin=sha(raw))
        self.assertNotIn(foreign, opened)
        self.assertIn(str(task / "metadata.json"), opened)

    def test_prepared_dispatch_requires_fresh_outputs_and_success_route_is_closed(self):
        with driver.prepare_plan(self.repo, self.revision, "ci", fixture.VERSION, self.base / "task") as prepared:
            prepared.before_dispatch()
            write(prepared.path / "build.log", b"stale log\n", 0o400)
            with self.assertRaises(FAILURES):
                prepared.before_dispatch()
        for value in ("0" * 40, True, ""):
            with self.assertRaises(FAILURES):
                driver.prepare_plan(self.repo, value, "dev", fixture.VERSION, self.base / "unallocated")
            self.assertFalse((self.base / "unallocated").exists())

    def test_fixed_plan_no_recipe_command_context_or_target_overrides(self):
        with driver.prepare_plan(self.repo, self.revision, "release", "0.1.0", self.base / "task") as prepared:
            arguments = driver.producer_arguments(prepared.capsule, prepared.path)
            self.assertEqual(arguments[:4], ["--platform", "linux/amd64", "--target", "cw-runtime-export"])
            self.assertIn("CODEWIRE_RUST_PROFILE=release", arguments)
            self.assertIn("cw-source=" + str(prepared.capsule.path), arguments)
            with self.assertRaises(FAILURES):
                driver.producer_arguments(prepared.capsule, prepared.path, "other")
        flags = ["--source-dir", str(self.repo), "--source-sha", self.revision, "--profile", "ci",
                 "--version", fixture.VERSION, "--output", str(self.base / "unused")]
        for extra in (["--profile", "release"], ["--version", ""], ["--source-di", str(self.repo)],
                      ["--build-command", "true"], ["--tag", "unreviewed"]):
            with self.subTest(extra=extra), mock.patch.object(driver, "prepare_plan") as prepare:
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    driver.main(flags + extra)
                prepare.assert_not_called()

    def test_docker_recipe_one_real_compiler_run_and_closed_pins(self):
        text = (ROOT / "images/cw-runtime/Dockerfile").read_text()
        stage = text.split(" AS cw-builder\n", 1)[1].split("\nFROM ", 1)[0]
        self.assertEqual(sum(line.startswith("RUN ") for line in stage.splitlines()), 1)
        self.assertIn("codewire-rust-build python3 /src/scripts/ci/images/finalize-cw-runtime-source.py", stage)
        self.assertIn("from=cw-source,source=git,target=/source-git,readonly", stage)
        self.assertIn("from=cw-source,source=source,target=/src,readonly", stage)
        self.assertIn("FROM scratch AS cw-source", text)
        self.assertIn("--version 0.23.0", text)
        self.assertIn("zig-x86_64-linux-0.15.2", text)
        self.assertNotIn("ARG RUST_IMAGE", text)
        self.assertNotIn("COPY .git", text)


class FinalizerDiagnostic(unittest.TestCase):
    def test_closed_refusal_diagnostic_never_renders_secret_exception_fields(self):
        canary = "DIAGNOSTIC_SECRET_CANARY"
        cases = (
            (OSError(24, canary, "/" + canary), "os", "process_fd_limit"),
            (OSError(30, canary, "/" + canary), "os", "readonly"),
            (OSError(987654, canary, "/" + canary), "os", "other"),
            (finalizer.release.ReleaseError(canary), "release", "none"),
            (ValueError(canary), "value", "none"),
            (KeyError(canary), "key", "none"),
            (TypeError(canary), "type", "none"),
            (subprocess.CalledProcessError(53, [canary], output=canary, stderr=canary), "subprocess", "none"),
            (subprocess.TimeoutExpired([canary], 1, output=canary, stderr=canary), "subprocess", "none"),
        )
        for error, category, code in cases:
            error.__cause__ = RuntimeError(canary)
            error.__context__ = RuntimeError(canary)
            with self.subTest(category=category, code=code), \
                    mock.patch.dict(finalizer._DIAGNOSTIC, {"phase": canary,
                                    "source_held_files_at_admit": True, "source_held_fds_at_admit": canary}), \
                    mock.patch.object(finalizer.resource, "getrlimit", return_value=(2048, finalizer.resource.RLIM_INFINITY)):
                text = finalizer.failure_diagnostic(error)
            self.assertNotIn(canary, text)
            self.assertLess(len(text.encode("ascii")), 1024)
            self.assertTrue(text.startswith(finalizer.DIAGNOSTIC_PREFIX))
            value = json.loads(text[len(finalizer.DIAGNOSTIC_PREFIX):])
            self.assertEqual(value, {"schema": "codewire.cw.runtime-source-refusal/v1", "phase": "unknown",
                                    "exception": category, "errno": code,
                                    "nofile": {"soft": 2048, "hard": "unlimited"},
                                    "source_held_files_at_admit": None, "source_held_fds_at_admit": None})
        with mock.patch.dict(finalizer._DIAGNOSTIC, {"phase": "readonly", "source_held_files_at_admit": 12,
                                                    "source_held_fds_at_admit": 84}), \
                mock.patch.object(finalizer.resource, "getrlimit", side_effect=OSError(24, canary)):
            value = json.loads(finalizer.failure_diagnostic(ValueError(canary))[len(finalizer.DIAGNOSTIC_PREFIX):])
        self.assertEqual(value["phase"], "readonly")
        self.assertEqual((value["source_held_files_at_admit"], value["source_held_fds_at_admit"]), (12, 84))
        self.assertIsNone(value["nofile"])
        self.assertNotIn(canary, json.dumps(value))

    def test_capsule_refusal_reports_fixed_phase_before_compiler_or_export(self):
        error = OSError(24, "DIAGNOSTIC_SECRET_CANARY", "/DIAGNOSTIC_SECRET_CANARY")
        with mock.patch.object(finalizer.signal, "signal"), \
                mock.patch.object(finalizer.owner, "arm_custody"), \
                mock.patch.object(finalizer.source, "admit", side_effect=error), \
                mock.patch.object(finalizer.owner, "admit_output") as output, \
                mock.patch.object(finalizer.subprocess, "check_output") as rustc, \
                mock.patch.object(finalizer.owner, "run_owned") as compile_command, \
                mock.patch.object(finalizer, "finalize") as export, \
                contextlib.redirect_stdout(io.StringIO()) as stdout, \
                self.assertRaises(OSError) as refused:
            finalizer.main(["--request-sha256", "a" * 64])
        self.assertIs(refused.exception, error)
        self.assertEqual(stdout.getvalue(), "")
        for effect in (output, rustc, compile_command, export):
            effect.assert_not_called()
        value = json.loads(finalizer.failure_diagnostic(error)[len(finalizer.DIAGNOSTIC_PREFIX):])
        self.assertEqual((value["phase"], value["exception"], value["errno"]), ("capsule", "os", "process_fd_limit"))
        self.assertIsNone(value["source_held_files_at_admit"])
        self.assertIsNone(value["source_held_fds_at_admit"])
        self.assertNotIn("DIAGNOSTIC_SECRET_CANARY", json.dumps(value))


if __name__ == "__main__":
    if "--legacy-head-witness" in sys.argv:
        LEGACY_HEAD_WITNESS = True
        sys.argv.remove("--legacy-head-witness")
    ROOT.joinpath(".tmp").mkdir(exist_ok=True)
    unittest.main()
