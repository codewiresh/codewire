#!/usr/bin/env python3
"""Retained Kind intake/routing components; never run Kind, Cargo or CW.

The three producers use the real source capsule, finalizer, eight exports and
finish/reopen boundary over explicitly synthetic, never-executed ELF inputs.
The lock cases use actual isolated kernel descriptors and the unchanged c0
owner, not a fabricated Pod/update acceptance result.
"""

from contextlib import closing, redirect_stderr
import copy
import fcntl
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


assets = load("kind_cw_runtime_intake_test", ROOT / "scripts/ci/verify/kind/cw_runtime_assets.py")
fixture = load("kind_cw_runtime_synthetic_producers", ROOT / "scripts/ci/tests/cw_image_fixtures.py")
source, release = assets.source, assets.release


class AssetIntake(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="kind-cw-intake-", dir=ROOT / ".tmp")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        cls.checkout = cls.root / "source"
        cls.selected = fixture.create_source(cls.checkout)["source_sha"]
        cls.originals = {}
        cls.selections = {}
        for name, profile, version in (
            ("release_a", "release", "0.1.0"),
            ("release_b", "release", "0.1.1-cw-update"),
            ("support_cw", "runtime", "0.0.0-ci"),
        ):
            result = fixture.make_producer(cls.checkout, cls.root / name, profile, version)
            cls.originals[name] = result
            selected = {"build_json": result["receipt"]["path"],
                        "build_sha256": result["receipt"]["sha256"]}
            if name != "support_cw":
                selected["sha256"] = result["payload"]["sha256"]
            cls.selections[name] = selected

    def admitted(self, selections=None, selected=None):
        return assets.admitted_inputs(self.checkout, selected or self.selected,
                                      selections or self.selections)

    def test_full_original_three_producers_and_closed_witness(self):
        with self.admitted() as (witness, recheck):
            self.assertEqual(set(witness), {"schema_version", "source_sha", "current_source",
                                           "release_a", "release_b", "support_cw"})
            self.assertEqual(witness["source_sha"], self.selected)
            for name in self.selections:
                entry = witness[name]
                self.assertEqual(set(entry), {"release_dir", "identity", "build_receipt", "producer_receipt",
                    "image", "index_sha256", "compilation_source", "profile", "version", "build_ref"})
                self.assertEqual(entry["identity"], self.originals[name]["payload"])
                self.assertEqual(entry["compilation_source"]["revision"], self.selected)
                self.assertEqual(entry["profile"], "runtime" if name == "support_cw" else "release")
                self.assertEqual(entry["build_ref"], self.originals[name]["build_ref"])
                self.assertEqual(entry["build_receipt"]["sha256"], self.selections[name]["build_sha256"])
            self.assertNotEqual(witness["release_a"]["identity"]["sha256"],
                                witness["release_b"]["identity"]["sha256"])
            recheck()

    def test_missing_support_refuses_instead_of_falling_back_to_release_a(self):
        selected = {key: value for key, value in self.selections.items() if key != "support_cw"}
        with self.assertRaisesRegex(ValueError, "CI support producers"), self.admitted(selected):
            self.fail("incomplete evidence admitted")

    def test_wrong_external_build_or_payload_pin_refuses(self):
        for name, field in (("release_a", "build_sha256"), ("release_b", "sha256"),
                            ("support_cw", "build_sha256")):
            with self.subTest(name=name, field=field):
                selected = copy.deepcopy(self.selections)
                selected[name][field] = "0" * 64
                with self.assertRaises(ValueError), self.admitted(selected):
                    self.fail("wrong external pin admitted")

    def test_ci_release_profile_substitution_refuses(self):
        selected = copy.deepcopy(self.selections)
        selected["release_a"] = {**selected["support_cw"],
            "sha256": self.originals["support_cw"]["payload"]["sha256"]}
        with self.assertRaises(ValueError), self.admitted(selected):
            self.fail("CI assets relabeled as release")
        selected = copy.deepcopy(self.selections)
        selected["support_cw"] = {key: value for key, value in selected["release_a"].items() if key != "sha256"}
        with self.assertRaises(ValueError), self.admitted(selected):
            self.fail("release assets relabeled as support")

    def test_same_a_and_b_refuses(self):
        selected = copy.deepcopy(self.selections)
        selected["release_b"] = selected["release_a"].copy()
        with self.assertRaisesRegex(ValueError, "distinct A/B"), self.admitted(selected):
            self.fail("same release admitted twice")

    def test_wrong_head_and_changed_compiled_source_refuse(self):
        with self.assertRaises(ValueError), self.admitted(selected="0" * 40):
            self.fail("wrong selected HEAD admitted")
        path = self.checkout / "crates/demo/src/lib.rs"
        original = path.read_bytes()
        try:
            path.write_bytes(original + b"// changed after original compilation\n")
            with self.assertRaises(ValueError), self.admitted():
                self.fail("changed source admitted as original producer")
        finally:
            path.write_bytes(original)

    def test_linked_original_receipt_refuses(self):
        path = Path(self.selections["release_a"]["build_json"])
        link = self.root / "extra-receipt-link"
        os.link(path, link)
        try:
            with self.assertRaises(ValueError), self.admitted():
                self.fail("multiply linked receipt admitted")
        finally:
            link.unlink()

    def test_payload_change_while_held_prevents_success(self):
        path = self.root / "release_b/assets/cw"
        original = path.read_bytes()
        try:
            with self.assertRaises(ValueError):
                with self.admitted() as (_, recheck):
                    path.chmod(0o600)
                    path.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
                    path.chmod(0o500)
                    recheck()
        finally:
            path.chmod(0o600)
            path.write_bytes(original)
            path.chmod(0o500)

    def test_invalid_asset_fails_before_scratch_or_child_dispatch(self):
        arguments = ["--source-sha", self.selected]
        for short, name in (("a", "release_a"), ("b", "release_b"), ("support", "support_cw")):
            selected = self.selections[name]
            arguments += ["--" + short + "-build-json", selected["build_json"],
                          "--" + short + "-build-sha256", "0" * 64 if short == "a" else selected["build_sha256"]]
            if short != "support":
                arguments += ["--" + short + "-sha256", selected["sha256"]]
        with mock.patch.object(assets, "ROOT", self.checkout), \
                mock.patch.object(assets.tempfile, "mkdtemp") as allocation, \
                mock.patch.object(assets, "ProfileLock") as lock, \
                mock.patch.object(assets, "run_journey") as dispatch:
            with self.assertRaises(ValueError):
                assets.main(arguments)
            allocation.assert_not_called()
            lock.assert_not_called()
            dispatch.assert_not_called()


class InputGrammar(unittest.TestCase):
    def arguments(self):
        result = ["--source-sha", "a" * 40]
        for name in ("a", "b", "support"):
            result += ["--" + name + "-build-json", "/owned/" + name + "/build.json",
                       "--" + name + "-build-sha256", "b" * 64]
            if name != "support":
                result += ["--" + name + "-sha256", "c" * 64]
        return result

    def test_duplicate_empty_unknown_and_abbreviated_arguments_refuse(self):
        for arguments in (self.arguments() + ["--source-sha", "d" * 40],
                          self.arguments() + ["--a-sha256", ""],
                          self.arguments() + ["--callback", "/bin/true"],
                          ["--source", "a" * 40]):
            with self.subTest(arguments=arguments), redirect_stderr(io.StringIO()), \
                    self.assertRaises(SystemExit) as result:
                assets.arguments(arguments)
            self.assertEqual(result.exception.code, 2)


class OriginalLock(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="kind-cw-lock-", dir=ROOT / ".tmp")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.daemon, self.cluster = "synthetic-private-daemon", "owned-cw-proof"
        self.profile = self.root / "profiles" / hashlib.sha256(self.daemon.encode()).hexdigest() / self.cluster
        self.profile.mkdir(mode=0o700, parents=True)
        self.path = self.profile / "operation.lock"
        self.fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
        self.addCleanup(os.close, self.fd)
        fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.environment = {"CLUSTER": self.cluster, "KIND_CLUSTER_NAME": self.cluster,
            "KIND_PROFILE_DOCKER_ID": self.daemon, "KIND_PROFILE_PATH": str(self.profile / "profile.json"),
            "KIND_PROFILE_LOCK_FILE": str(self.path), "KIND_PROFILE_LOCK_FD": str(self.fd)}

    def test_original_lock_description_reused_and_unrelated_pipe_not_inherited(self):
        read_fd, write_fd = os.pipe()
        try:
            with closing(assets.ProfileLock(self.environment)) as profile:
                # Fixed isolated child, not the Kind journey or a CW process.
                program = ("import fcntl,os,sys; fd=int(sys.argv[1]); "
                    "fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB); "
                    "assert os.readlink('/proc/self/fd/'+str(fd)) == sys.argv[3]; "
                    "\ntry: os.fstat(int(sys.argv[2]))\nexcept OSError: pass\n"
                    "else: raise AssertionError('unrelated pipe inherited')\n")
                command = [sys.executable, "-I", "-B", "-c", program,
                           str(profile.fd), str(read_fd), str(self.path)]
                original = assets.owner.subprocess
                assets.owner.arm_custody()
                result = assets.run_journey(profile, command,
                    {"PATH": "/usr/bin:/bin", "HOME": str(self.root)}, self.root)
                self.assertEqual(result["exit"], 0)
                self.assertFalse(result["cleanup_unknown"] or result["unexpected_family"])
                self.assertIs(assets.owner.subprocess, original)
                self.assertIs(subprocess.Popen, original.Popen)
                profile.revalidate()
        finally:
            os.close(read_fd)
            os.close(write_fd)

    def test_wrong_descriptor_and_path_refuse_before_popen(self):
        read_fd, write_fd = os.pipe()
        try:
            for patch in ({"KIND_PROFILE_LOCK_FD": str(read_fd)},
                          {"KIND_PROFILE_LOCK_FILE": str(self.root / "foreign.lock")},
                          {"KIND_PROFILE_PATH": str(self.profile.with_name("other") / "profile.json")}):
                with self.subTest(patch=patch), mock.patch.object(subprocess, "Popen") as spawn:
                    with self.assertRaises((ValueError, OSError)), closing(assets.ProfileLock(self.environment | patch)):
                        self.fail("foreign lock admitted")
                    spawn.assert_not_called()
        finally:
            os.close(read_fd)
            os.close(write_fd)

    def test_separately_opened_locked_description_refuses_without_wait(self):
        other = os.open(self.path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            with self.assertRaises(BlockingIOError), closing(assets.ProfileLock(
                    self.environment | {"KIND_PROFILE_LOCK_FD": str(other)})):
                self.fail("separate description waited behind the original lock")
        finally:
            os.close(other)

    def test_replaced_name_refuses_before_child(self):
        with closing(assets.ProfileLock(self.environment)) as profile:
            original = self.profile / "owned-original.lock"
            self.path.rename(original)
            self.path.write_bytes(b"")
            self.path.chmod(0o600)
            with mock.patch.object(subprocess, "Popen") as spawn:
                with self.assertRaises(ValueError):
                    assets.run_journey(profile, ["/usr/bin/true"], {}, self.root)
                spawn.assert_not_called()

    def test_child_failure_remains_failed_and_has_original_completion(self):
        with closing(assets.ProfileLock(self.environment)) as profile:
            command = [sys.executable, "-I", "-B", "-c", "raise SystemExit(42)"]
            assets.owner.arm_custody()
            with self.assertRaises(ValueError) as caught:
                assets.run_journey(profile, command, {"PATH": "/usr/bin:/bin"}, self.root)
            failure = assets.failed_completion(caught.exception, command, self.root)
            self.assertEqual(failure.status, 42)
            result = release.parse_canonical((self.root / "process-failed.json").read_bytes())
            self.assertEqual(result["exit"], 42)
            self.assertFalse(result["cleanup_unknown"] or result["unexpected_family"])

    def test_closed_environment_preserves_topology_and_removes_ambient_credentials(self):
        with closing(assets.ProfileLock(self.environment)) as profile:
            witness = {"release_a": {"release_dir": "/original/a", "identity": {"sha256": "a" * 64}},
                       "release_b": {"release_dir": "/original/b", "identity": {"sha256": "b" * 64}}}
            with mock.patch.dict(os.environ, {"KIND_INGRESS_HOST_PORT": "31100", "KIND_INGRESS_HTTP_HOST_PORT": "31100",
                    "KIND_TEMPORAL_FRONTEND_URL": "http://127.0.0.1:31104", "KIND_RETAINED_USE_CLUSTER_WORKSPACE": "1",
                    "ANTHROPIC_API_KEY": "synthetic-must-not-flow", "AWS_SECRET_ACCESS_KEY": "synthetic-must-not-flow",
                    "KUBECONFIG": "/unrelated/owner-config"}, clear=True):
                environment = assets.child_environment(self.root, witness, self.root / "inputs.json", "c" * 64, profile)
            self.assertEqual(environment["KIND_INGRESS_HTTP_HOST_PORT"], "31100")
            self.assertEqual(environment["KIND_TEMPORAL_FRONTEND_URL"], "http://127.0.0.1:31104")
            self.assertEqual(environment["KIND_RETAINED_USE_CLUSTER_WORKSPACE"], "1")
            self.assertEqual(environment["KIND_PROFILE_LOCK_FD"], str(profile.fd))
            self.assertEqual(environment["KUBECONFIG"], str(self.profile / "kubeconfig"))
            self.assertNotIn("ANTHROPIC_API_KEY", environment)
            self.assertNotIn("AWS_SECRET_ACCESS_KEY", environment)


class Registration(unittest.TestCase):
    def test_embedded_probe_is_part_of_immutable_source_byte_evidence(self):
        artifact = load("kind_cw_profile_inputs_test", ROOT / "scripts/ci/verify/kind/profile-artifacts.py")
        probe = "scripts/ci/verify/kind/cw_runtime_probe.py"
        self.assertIn(probe, artifact.SOURCE_INPUTS)
        with tempfile.TemporaryDirectory(prefix="kind-cw-probe-input-", dir=ROOT / ".tmp") as temporary:
            root = Path(temporary)
            for name in artifact.SOURCE_INPUTS:
                path = root / name
                path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                path.write_bytes((name + "\n").encode())
            # Tool/commit observations are explicitly synthetic; the input
            # digest path itself is production. No artifact is sealed here.
            with mock.patch.object(artifact, "source_identity", return_value=("a" * 40, "b" * 40)), \
                    mock.patch.object(artifact, "run", return_value="synthetic-tool"), \
                    mock.patch.dict(os.environ, {"CODEWIRE_KIND_PRODUCT_IMAGE_MODE": "build-ci"}):
                before = artifact.provenance(root)
                (root / probe).write_bytes(b"changed embedded observer source\n")
                after = artifact.provenance(root)
            self.assertNotEqual(before["inputs"][probe], after["inputs"][probe])
            self.assertEqual({key: value for key, value in before["inputs"].items() if key != probe},
                             {key: value for key, value in after["inputs"].items() if key != probe})


class ReleaseStaging(unittest.TestCase):
    def test_staged_release_is_the_admitted_executable_and_its_canonical_identity(self):
        with tempfile.TemporaryDirectory(prefix="kind-cw-stage-", dir=ROOT / ".tmp") as temporary:
            root = Path(temporary)
            os.chmod(root, 0o700)
            original = root / "assets"
            original.mkdir(mode=0o700)
            payload = b"synthetic admitted executable"
            (original / "cw").write_bytes(payload)
            os.chmod(original / "cw", 0o500)
            identity = {"sha256": hashlib.sha256(payload).hexdigest(), "size": len(payload),
                        "target": "x86_64-unknown-linux-musl"}
            task = root / "task"
            task.mkdir(mode=0o700)
            staged = assets.stage_release(task, "release_a", {"release_dir": str(original), "identity": identity})
            self.assertEqual(staged, task / "release-a")
            self.assertEqual(sorted(path.name for path in staged.iterdir()), ["cw", "cw-runtime.json"])
            self.assertEqual((staged / "cw").read_bytes(), payload)
            self.assertEqual(os.stat(staged / "cw").st_mode & 0o7777, 0o500)
            self.assertEqual((staged / "cw-runtime.json").read_bytes(), assets.release.canonical(identity))
            self.assertEqual(os.stat(staged / "cw-runtime.json").st_mode & 0o7777, 0o400)
            changed = dict(identity, sha256="0" * 64)
            with self.assertRaisesRegex((ValueError, assets.release.ReleaseError), "admitted identity"):
                assets.stage_release(task, "release_b", {"release_dir": str(original), "identity": changed})
            self.assertFalse((task / "release-b").exists())


class SuiteRoute(unittest.TestCase):
    def test_journey_calls_only_probe_modes_the_helpers_accept(self):
        # A refused mode fails the journey under errexit without a message.
        suite = (ROOT / "scripts/ci/verify/kind/suites/cw-runtime.sh").read_text()
        helpers = (ROOT / "scripts/ci/verify/kind/credentials.sh").read_text()
        for helper in ("kind_credential_probe", "kind_credential_daemon_probe"):
            body = helpers.split(helper + "() {", 1)[1]
            accepted = set(re.search(r'\[\[ "\$mode" =~ \^\(([a-z|-]+)\)\$ \]\]', body).group(1).split("|"))
            used = set(re.findall(helper + r' "\$environment" ([a-z-]+)', suite))
            self.assertTrue(used, helper)
            self.assertEqual(used - accepted, set(), helper)

    def test_journey_calls_only_defined_kind_helpers(self):
        # The explicit suite runs only when named, so a helper removed from
        # the shared Kind library fails it only at run time (#2255).
        suite = (ROOT / "scripts/ci/verify/kind/suites/cw-runtime.sh").read_text()
        library = "".join(path.read_text() for path in sorted((ROOT / "scripts/ci/verify/kind").glob("**/*.sh")))
        defined = set(re.findall(r"^([a-z][a-z0-9_]*)\(\) [({]", library, re.M))
        called = set(re.findall(r"(?:^|[;&|(]\s*|\$\()\s*((?:wait|assert|kind|cw|retained|build|validate)_[a-z0-9_]+)\b",
                                suite, re.M))
        self.assertTrue(called)
        self.assertEqual(called - defined, set())

    def run_suite(self, directory, managed=False, **overrides):
        captured = directory / "intake-arguments"
        script = '''source "$1"
require_kind_errexit() { :; }
require_tool() { :; }
python3() { printf '%s\\0' "$@" >"$CAPTURED"; printf '%s' "${CW_RUNTIME_MANAGED_AGENTS-}" >"$CAPTURED.mode"; return 46; }
run_retained_managed_agents_journey() { printf 'managed-only' >"$CAPTURED.route"; return 47; }
if [ "$SELECT_MANAGED" = 1 ]; then run_retained_cw_managed_agents_suite; else run_retained_cw_runtime_suite; fi
'''
        environment = {"PATH": "/usr/bin:/bin", "HOME": str(directory), "KIND_E2E_COMMON_LOADED": "1",
            "ROOT": str(ROOT), "KIND_PROFILE": "1", "CLUSTER": "owned-cw-proof", "CAPTURED": str(captured),
            "CODEWIRE_KIND_PRODUCT_IMAGE_MODE": "build-ci", "CW_RUNTIME_SOURCE_SHA": "a" * 40,
            "CW_RUNTIME_A_BUILD_JSON": "/owned/a/build.json", "CW_RUNTIME_A_BUILD_SHA256": "b" * 64,
            "CW_RUNTIME_A_SHA256": "c" * 64, "CW_RUNTIME_B_BUILD_JSON": "/owned/b/build.json",
            "CW_RUNTIME_B_BUILD_SHA256": "d" * 64, "CW_RUNTIME_B_SHA256": "e" * 64,
            "CW_RUNTIME_SUPPORT_BUILD_JSON": "/owned/ci/build.json", "CW_RUNTIME_SUPPORT_BUILD_SHA256": "f" * 64,
            "SELECT_MANAGED": "1" if managed else "0",
            **overrides}
        result = subprocess.run(["/usr/bin/bash", "-ceu", script, "--",
            str(ROOT / "scripts/ci/verify/kind/suites/cw-runtime.sh")], env=environment,
            capture_output=True, text=True, timeout=10)
        return result, captured

    def test_managed_mode_preserves_original_three_producer_intake_and_named_profile_guard(self):
        with tempfile.TemporaryDirectory(prefix="kind-cw-managed-route-", dir=ROOT / ".tmp") as temporary:
            ordinary = Path(temporary) / "ordinary"; ordinary.mkdir()
            managed = Path(temporary) / "managed"; managed.mkdir()
            original, original_capture = self.run_suite(ordinary)
            selected, selected_capture = self.run_suite(managed, managed=True)
            self.assertEqual((original.returncode, selected.returncode), (46, 46))
            self.assertEqual(original_capture.read_bytes(), selected_capture.read_bytes())
            self.assertEqual(Path(str(original_capture) + ".mode").read_bytes(), b"")
            self.assertEqual(Path(str(selected_capture) + ".mode").read_bytes(), b"1")
            self.assertFalse(Path(str(selected_capture) + ".route").exists())
            # Without a named profile (a retained `make kind-test` cluster) the
            # managed journey runs alone and admits no release producers (#2672).
            retained = Path(temporary) / "retained"; retained.mkdir()
            routed, no_intake = self.run_suite(retained, managed=True, KIND_PROFILE="0", CLUSTER="")
            self.assertEqual(routed.returncode, 47)
            self.assertFalse(no_intake.exists())
            self.assertEqual(Path(str(no_intake) + ".route").read_bytes(), b"managed-only")

    def test_fixed_intake_route_forwards_three_pinned_producers_once(self):
        with tempfile.TemporaryDirectory(prefix="kind-cw-route-", dir=ROOT / ".tmp") as temporary:
            result, captured = self.run_suite(Path(temporary))
            self.assertEqual(result.returncode, 46)
            arguments = captured.read_bytes().split(b"\0")[:-1]
            self.assertEqual(arguments, [b"-B", str(ROOT / "scripts/ci/verify/kind/cw_runtime_assets.py").encode(),
                b"--source-sha", b"a" * 40, b"--a-build-json", b"/owned/a/build.json",
                b"--a-build-sha256", b"b" * 64, b"--a-sha256", b"c" * 64,
                b"--b-build-json", b"/owned/b/build.json", b"--b-build-sha256", b"d" * 64,
                b"--b-sha256", b"e" * 64, b"--support-build-json", b"/owned/ci/build.json",
                b"--support-build-sha256", b"f" * 64])
            self.assertNotIn("green", result.stdout + result.stderr)

    def test_missing_profile_and_wrong_image_mode_refuse_before_intake(self):
        for overrides in ({"KIND_PROFILE": "0", "CLUSTER": ""},
                          {"CODEWIRE_KIND_PRODUCT_IMAGE_MODE": "prebuilt-release"},
                          {"CODEWIRE_KIND_PRODUCT_IMAGE_MODE": "unknown"}):
            with self.subTest(overrides=overrides), tempfile.TemporaryDirectory(
                    prefix="kind-cw-route-refusal-", dir=ROOT / ".tmp") as temporary:
                result, captured = self.run_suite(Path(temporary), **overrides)
                self.assertEqual(result.returncode, 2)
                self.assertFalse(captured.exists())
                self.assertNotIn("green", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
