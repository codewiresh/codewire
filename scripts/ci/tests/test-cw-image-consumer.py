#!/usr/bin/env python3
"""Consumer ordering and held-context fixtures; no Docker or CW execution."""

import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[3]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


consumer = load("cw_consumer_test", ROOT / "scripts/ci/images/cw-image-consumer.py")
fixture = load("cw_consumer_fixture", ROOT / "scripts/ci/tests/cw_release_fixtures.py")


class Consumer(unittest.TestCase):
    def setUp(self):
        (ROOT / ".tmp").mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="cw-consumer-test-", dir=ROOT / ".tmp")
        self.base = Path(self.temporary.name)
        self.source = self.base / "source"
        self.source.mkdir()
        (self.source / "deployments/docker").mkdir(parents=True)
        (self.source / ".dockerignore").write_text(".git\n.env*\ntarget\nnode_modules\n**/.tmp\n**/__pycache__\n")
        (self.source / "deployments/docker/daemon.Dockerfile").write_text("FROM scratch\nCOPY cw /cw\n")
        self.command = ["docker", "buildx", "build", "--file",
                        str(self.source / "deployments/docker/daemon.Dockerfile"), str(self.source)]
        self.args = SimpleNamespace(source_dir=str(self.source), source_sha=fixture.REVISION,
                                    profile="ci", version=fixture.VERSION, output=str(self.base / "consume"),
                                    producer_receipt=str(self.base / "build.json"), producer_sha256="1" * 64,
                                    docker_bin="docker")

    def tearDown(self):
        consumer.asset.STOP = None
        consumer.image_source.STOP = None
        self.temporary.cleanup()

    def validate(self, arguments=None, command=None):
        return consumer.canonical_command(command or self.command[:3] + (arguments or self.command[3:]),
                                          self.source, Path.cwd(), "ci")

    def test_closed_cli_options_and_explicit_delimiter(self):
        options = ["consume", "--source-dir", str(self.source), "--source-sha", fixture.REVISION,
                   "--profile", "ci", "--output", str(self.base / "output"), "--docker-bin", "docker",
                   "--", *self.command]
        args, command = consumer.arguments(options)
        self.assertEqual(command, self.command)
        self.assertEqual(args.docker_bin, "docker")
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            consumer.arguments(options[:options.index("--")] + ["--docker-bin", "other", "--", *self.command])
        with self.assertRaises(consumer.asset.Refused):
            consumer.arguments(options[:options.index("--")])

    def test_reserved_direct_context_override_before_dispatch(self):
        for extra in (["--build-context", "codewire-verified-cw=/tmp/untrusted"],
                      ["--build-context=codewire-verified-cw=docker-image://untrusted"],
                      ["--build-context", "codewire-verified-cw=oci-layout:///tmp/untrusted"],
                      ["--build-context", "cw-builder=/tmp/untrusted"],
                      ["--build-context=cw-builder-amd64=/tmp/untrusted"],
                      ["--target", "cw-builder"], ["--target=cw-builder-amd64"],
                      ["--build-arg", "TARGETARCH=arm64"], ["--build-arg=TARGETPLATFORM=linux/arm64"],
                      ["--call=check"], ["--unknown", "daemon"]):
            with self.subTest(extra=extra), self.assertRaises(consumer.asset.Refused):
                self.validate(extra + self.command[3:])

    def test_reserved_bake_context_and_profile_overrides(self):
        for key in ("daemon.contexts.codewire-verified-cw", "*.contexts.codewire-verified-cw",
                    "daemon.contexts.*", "*.contexts", "daemon.args.CODEWIRE_RUST_PROFILE"):
            command = ["docker", "buildx", "bake", "--file", str(self.source / "docker-bake.hcl"),
                       "--set", key + "=untrusted", "daemon-ci"]
            with self.subTest(key=key), self.assertRaises(consumer.asset.Refused):
                self.validate(command=command)

    def test_bake_recipe_context_and_stage_overrides_refuse_both_spellings(self):
        for key in ("daemon-ci.dockerfile", "*.dockerfile", "daemon-ci.context", "*.context",
                    "daemon-ci.target", "*.target", "daemon-ci.contexts.cw-builder-amd64",
                    "*.contexts.*", "*.args.TARGETARCH"):
            for spelling in (["--set", key + "=/tmp/foreign"], ["--set=" + key + "=/tmp/foreign"]):
                command = ["docker", "buildx", "bake", "-f", str(self.source / "docker-bake.hcl"),
                           *spelling, "daemon-ci"]
                with self.subTest(key=key, spelling=spelling), self.assertRaises(consumer.asset.Refused):
                    self.validate(command=command)

    def test_effective_bake_platforms_are_bound_for_remote_builders(self):
        prefix = ["docker", "buildx", "bake", "-f", str(self.source / "docker-bake.hcl"), "--builder", "remote"]
        for selection, expected in (("*.platform=linux/amd64", True), ("daemon-ci.platform=linux/arm64", False),
                                    ("*.platform=linux/amd64,linux/arm64", True)):
            plan = consumer.canonical_plan(prefix + ["--set", selection, "daemon-ci"], self.source, Path.cwd(), "ci")
            self.assertIs(plan["needs_cw_asset"], expected)
            self.assertIn("daemon-ci.platform=" + selection.split("=", 1)[1], plan["command"])
        with self.assertRaises(consumer.asset.Refused):
            consumer.canonical_plan(prefix + ["--set", "*.platform=linux/arm64", "--set",
                                               "daemon-ci.platform=linux/amd64", "daemon-ci"], self.source, Path.cwd(), "ci")
        with patch.object(consumer.os, "uname", return_value=SimpleNamespace(machine="arm64")):
            plan = consumer.canonical_plan(prefix + ["daemon-ci"], self.source, Path.cwd(), "ci")
            self.assertEqual(plan["platforms"]["daemon-ci"], ["linux/arm64"])
            self.assertIn("daemon-ci.platform=linux/arm64", plan["command"])

    def test_bake_from_foreign_cwd_binds_selected_and_dependency_contexts(self):
        foreign = self.base / "foreign"
        foreign.mkdir()
        prefix = ["docker", "buildx", "bake", "-f", str(self.source / "docker-bake.hcl")]
        plan = consumer.canonical_plan(prefix + ["kind"], self.source, foreign, "ci")
        settings = [plan["command"][index + 1] for index, value in enumerate(plan["command"])
                    if value == "--set"]
        for target in ("dashboard-ci", "services-ci", "mesh-ci", "daemon-ci", "rust-base"):
            self.assertIn(target + ".context=" + str(self.source), settings)
        with self.assertRaises(consumer.asset.Refused):
            consumer.canonical_plan(prefix + ["--set", "*.context=.", "kind"], self.source, foreign, "ci")

    def test_selected_frontend_directives_precede_ordinary_comments(self):
        for recipe, directive in (("deployments/docker/daemon.Dockerfile", "# syntax=docker/dockerfile:1.20"),
                                  ("images/workspace/Dockerfile", "# syntax=docker/dockerfile:1.7")):
            with self.subTest(recipe=recipe):
                self.assertEqual((ROOT / recipe).read_text().splitlines()[0], directive)

    def test_effective_profiles_refuse_conflicts_and_keep_unrelated_ci_targets(self):
        for extra in (["--build-arg", "CODEWIRE_RUST_PROFILE=release"],
                      ["--build-arg=CODEWIRE_RUST_PROFILE=release"]):
            with self.assertRaises(consumer.asset.Refused):
                self.validate(extra + self.command[3:])
        prefix = ["docker", "buildx", "bake", "-f", str(self.source / "docker-bake.hcl")]
        with patch.dict(os.environ, {"CODEWIRE_RUST_PROFILE": "release"}):
            with self.assertRaises(consumer.asset.Refused):
                consumer.canonical_plan(prefix + ["daemon", "daemon-ci"], self.source, Path.cwd(), "release")
            plan = consumer.canonical_plan(prefix + ["daemon", "dashboard-ci"], self.source, Path.cwd(), "release")
            self.assertEqual(plan["targets"], ["daemon"])
            self.assertIn("daemon.args.CODEWIRE_RUST_PROFILE=release", plan["command"])
        plan = consumer.canonical_plan(self.command, self.source, Path.cwd(), "ci")
        self.assertIn("CODEWIRE_RUST_PROFILE=ci", plan["command"])

    def test_bake_groups_bind_only_the_selected_daemon(self):
        for group, profile, expected in (("default", "release", "daemon"), ("kind", "ci", "daemon-ci")):
            command = ["docker", "buildx", "bake", "--file", str(self.source / "docker-bake.hcl"), group]
            targets, required = consumer.canonical_command(command, self.source, Path.cwd(), profile)
            self.assertEqual(targets, [expected])
            self.assertTrue(required)
            bound = consumer.bind_context(command, targets, self.base / "verified")
            self.assertEqual(bound.count(expected + ".contexts.codewire-verified-cw=" + str(self.base / "verified")), 1)
            self.assertEqual(bound.count("--allow=fs.read=" + str(self.base / "verified")), 1)
            self.assertEqual([item for item in bound if item.startswith("--allow")],
                             ["--allow=fs.read=" + str(self.base / "verified")])
        with self.assertRaises(consumer.asset.Refused):
            consumer.canonical_command(command, self.source, Path.cwd(), "release")

    def test_architecture_split_and_unknown_architecture_refusal(self):
        for platforms, expected in (("linux/amd64", True), ("linux/arm64", False),
                                    ("linux/amd64,linux/arm64", True)):
            with self.subTest(platforms=platforms):
                _, needs_asset = self.validate(["--platform", platforms, *self.command[3:]])
                self.assertEqual(needs_asset, expected)
        for platforms in ("linux/386", "linux/amd64,linux/amd64", "linux/amd64,darwin/arm64"):
            with self.subTest(platforms=platforms), self.assertRaises(consumer.asset.Refused):
                self.validate(["--platform", platforms, *self.command[3:]])

    def test_foreign_recipe_context_and_non_docker_command_refuse(self):
        candidates = [self.command[:3] + ["--file", "/tmp/daemon.Dockerfile", str(self.source)],
                      self.command[:-1] + [str(self.base)], ["echo", *self.command[1:]],
                      self.command[:3] + ["--file", self.command[4], "--file", self.command[4], str(self.source)]]
        for command in candidates:
            with self.subTest(command=command), self.assertRaises(consumer.asset.Refused):
                self.validate(command=command)

    def test_missing_producer_and_failed_semantics_never_reach_docker(self):
        self.args.producer_receipt = None
        with patch.object(consumer.owner, "run_owned") as docker, self.assertRaises(consumer.asset.Refused):
            consumer.consume(self.args, self.command)
        docker.assert_not_called()
        self.assertFalse((Path(self.args.output) / "consumer.json").exists())
        self.args.output = str(self.base / "failed")
        self.args.producer_receipt = str(self.base / "failed-build.json")
        with patch.object(consumer.producer, "reopen", side_effect=ValueError("failed producer")) as reopen:
            with patch.object(consumer.owner, "run_owned") as docker, self.assertRaises(ValueError):
                consumer.consume(self.args, self.command)
        reopen.assert_called_once()
        docker.assert_not_called()
        self.assertFalse((Path(self.args.output) / "verified-cw").exists())

    def test_owned_failures_keep_timeout_cancel_and_family_failure_status(self):
        log = self.base / "failed.log"
        base = {"command": self.command, "log": str(log), "exit": 1,
                "timed_out": False, "interrupted": False, "unexpected_family": False, "cleanup_unknown": False}
        for changes, expected in (({}, 1), ({"timed_out": True}, 124), ({"interrupted": True}, 143),
                                  ({"unexpected_family": True}, 70), ({"cleanup_unknown": True}, 70),
                                  ({"exit": 126}, 126), ({"exit": 127}, 127), ({"exit": 137}, 137),
                                  ({"exit": 143}, 143), ({"exit": 255}, 255),
                                  ({"exit": -signal.SIGKILL}, 137), ({"exit": -signal.SIGTERM}, 143)):
            error = ValueError("kernel command failed after owned-family cleanup: " + json.dumps(base | changes))
            with self.subTest(changes=changes), patch.object(consumer.owner, "run_owned", side_effect=error):
                with self.assertRaises(consumer.SolveFailure) as failed:
                    consumer.run_solve(self.command, self.source, log, 1)
                self.assertEqual(failed.exception.code, expected)
        error = ValueError("kernel command failed after owned-family cleanup: " + json.dumps(base | {"command": ["foreign"]}))
        with patch.object(consumer.owner, "run_owned", side_effect=error), self.assertRaises(consumer.asset.Refused):
            consumer.run_solve(self.command, self.source, log, 1)

    def completed(self):
        cw = fixture.executable(consumer.asset.image.TARGET)
        payload = consumer.release.make_identity(cw, consumer.asset.image.TARGET, fixture.VERSION,
                                                fixture.REVISION, fixture.TREE, fixture.RUSTC)
        binary, descriptor = self.base / "synthetic-cw", self.base / "artifact.json"
        binary.write_bytes(cw)
        binary.chmod(0o500)
        descriptor.write_bytes(consumer.release.canonical({key: value for key, value in payload.items() if key != "size"}
                                                         | {"path": str(binary)}))
        with contextlib.redirect_stdout(io.StringIO()):
            consumer.asset.image.build(descriptor, self.base / "asset")
        producer = self.base / "synthetic-producer.json"
        producer.write_bytes(b'{"fixture":"producer semantics are independently tested"}\n')
        producer.chmod(0o400)
        def pin(path):
            raw = path.read_bytes()
            return {"path": str(path), "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}
        summary = {"image": pin(self.base / "asset/cw.oci.tar"),
                   "index_sha256": json.loads((self.base / "asset/image.json").read_bytes())["index_sha256"],
                   "payload": payload, "producer_receipt": pin(producer), "receipt": pin(producer),
                   "source": {"revision": fixture.REVISION, "source_tree_sha256": fixture.TREE},
                   "current_source": {"revision": fixture.REVISION, "source_tree_sha256": fixture.TREE},
                   "build_ref": "synthetic/synthetic-node/12345678901234567890"}
        class Admitted:
            def __init__(self):
                self.summary, self.opened, self.validations = summary, False, 0
            def __enter__(self):
                self.opened = True
                return self
            def revalidate(self):
                assert self.opened
                self.validations += 1
            def __exit__(self, *_):
                self.opened = False
        return Admitted(), cw

    def solve(self, admitted, mutate=False):
        def docker(command, cwd, environment, log, deadline):
            self.assertTrue(admitted.opened)
            self.assertGreaterEqual(admitted.validations, 1)
            binding = command[command.index("--build-context") + 1]
            context = Path(binding.split("=", 1)[1])
            self.assertEqual(set(os.listdir(context)), {"cw", "provenance.json"})
            self.assertEqual(json.loads((context / "provenance.json").read_bytes())["payload"], admitted.summary["payload"])
            Path(log).write_bytes(b"synthetic consumer callback; no Docker execution\n")
            if mutate == "recipe":
                recipe = self.source / "deployments/docker/daemon.Dockerfile"
                recipe.write_bytes(recipe.read_bytes() + b"# changed during solve\n")
            elif mutate == "namespace":
                transient = self.source / "transient"
                transient.write_bytes(b"brief input")
                transient.unlink()
            elif mutate:
                replacement = context / "replacement"
                replacement.write_bytes((context / "cw").read_bytes())
                replacement.chmod(0o500)
                os.replace(replacement, context / "cw")
            return {"command": command, "exit": 0, "timed_out": False, "interrupted": False,
                    "unexpected_family": False, "cleanup_unknown": False, "log": str(log)}
        with patch.object(consumer.producer, "reopen", return_value=admitted):
            with patch.object(consumer.owner, "run_owned", side_effect=docker), patch.object(consumer, "stream_log"):
                return consumer.consume(self.args, self.command)

    def test_actual_oci_intake_is_held_across_consumer_callback(self):
        admitted, cw = self.completed()
        result = self.solve(admitted)
        self.assertFalse(admitted.opened)
        self.assertGreaterEqual(admitted.validations, 2)
        self.assertEqual((Path(self.args.output) / "verified-cw/cw").read_bytes(), cw)
        self.assertIs(result["image_qualified"], False)
        self.assertIs(result["cache_qualified"], False)
        self.assertEqual(result["compilation"], "reused")
        self.assertEqual(result["original_build_ref"], admitted.summary["build_ref"])
        image_pin = result["current_image_source"]
        self.assertEqual(hashlib.sha256(Path(image_pin["path"]).read_bytes()).hexdigest(), image_pin["sha256"])
        self.assertEqual(image_pin["source_dir"], str(self.source))

    def test_recipe_and_transient_namespace_changes_cannot_emit_success(self):
        admitted, _ = self.completed()
        for mutate in ("recipe", "namespace"):
            self.args.output = str(self.base / mutate)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                self.solve(admitted, mutate=mutate)
            self.assertFalse((Path(self.args.output) / "consumer.json").exists())

    def test_symlinked_recipe_refuses_before_docker(self):
        recipe = self.source / "deployments/docker/daemon.Dockerfile"
        recipe.unlink()
        recipe.symlink_to(self.base / "foreign")
        with patch.object(consumer.owner, "run_owned") as docker, self.assertRaises(ValueError):
            consumer.consume(self.args, self.command)
        docker.assert_not_called()

    def test_image_context_has_a_distinct_identity_from_compiled_cw(self):
        image_dir = self.base / "image-source"
        shutil.copytree(self.source, image_dir)
        self.args.image_source_dir = str(image_dir)
        command = ["docker", "buildx", "build", "--file", str(image_dir / "deployments/docker/daemon.Dockerfile"), str(image_dir)]
        admitted, _ = self.completed()
        with patch.object(consumer.producer, "reopen", return_value=admitted) as reopen:
            with patch.object(consumer.owner, "run_owned", return_value={"fixture": "no Docker"}), patch.object(consumer, "stream_log"):
                result = consumer.consume(self.args, command)
        self.assertEqual(reopen.call_args.args[2], self.source)
        self.assertEqual(result["current_image_source"]["source_dir"], str(image_dir))
        self.assertEqual(result["source"], admitted.summary["source"])

    def test_context_replacement_after_callback_cannot_emit_success(self):
        admitted, _ = self.completed()
        with self.assertRaises(consumer.asset.Refused):
            self.solve(admitted, mutate=True)
        self.assertFalse((Path(self.args.output) / "consumer.json").exists())
        self.assertFalse(admitted.opened)

    def test_bad_oci_pin_cannot_reach_consumer_callback(self):
        admitted, _ = self.completed()
        admitted.summary["index_sha256"] = "f" * 64
        with patch.object(consumer.producer, "reopen", return_value=admitted):
            with patch.object(consumer.owner, "run_owned") as docker, self.assertRaises(ValueError):
                consumer.consume(self.args, self.command)
        docker.assert_not_called()
        self.assertFalse((Path(self.args.output) / "consumer.json").exists())


class OwnedFailureDiagnostics(unittest.TestCase):
    """Real c0 children with genuine source/producer intake; no Docker/CW."""

    @classmethod
    def setUpClass(cls):
        (ROOT / ".tmp").mkdir(exist_ok=True)
        cls.temporary = tempfile.TemporaryDirectory(prefix="cw-owned-diagnostic-", dir=ROOT / ".tmp")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.base = Path(cls.temporary.name)
        cls.source = cls.base / "source"
        cls.helper = load("cw_diagnostic_source_fixture", ROOT / "scripts/ci/tests/cw_image_fixtures.py")
        cls.identity = cls.helper.create_source(cls.source)
        with contextlib.redirect_stdout(io.StringIO()):
            cls.original = cls.helper.make_producer(cls.source, cls.base / "original", profile="ci")
        cls.receipt = Path(cls.original["receipt"]["path"])
        cls.receipt_bytes = cls.receipt.read_bytes()
        cls.receipt_sha256 = hashlib.sha256(cls.receipt_bytes).hexdigest()
        cls.home, cls.tmp = cls.base / "home", cls.base / "tmp"
        cls.home.mkdir(mode=0o700)
        cls.tmp.mkdir(mode=0o700)
        cls.environment = {"PATH": "/usr/bin:/bin", "HOME": str(cls.home), "TMPDIR": str(cls.tmp),
                           "USER": "noel", "LOGNAME": "noel", "PYTHONDONTWRITEBYTECODE": "1",
                           "LC_ALL": "C", "TZ": "UTC"}

    def solve(self, operation, status, diagnostic=b""):
        case = Path(tempfile.mkdtemp(prefix=operation + "-", dir=self.base))
        docker = case / "docker"
        # The actual child has no Docker/API/ELF dispatch. Its only effects are
        # a closed synthetic stderr string and the selected process status.
        docker.write_text("#!/usr/bin/python3\nimport os, sys\n"
                          "if sys.argv[1:3] != ['buildx', 'build']: sys.exit(98)\n"
                          "os.write(2, " + repr(diagnostic) + ")\n"
                          "sys.exit(" + str(status) + ")\n")
        docker.chmod(0o700)
        output = case / "output"
        command = [sys.executable, "-B", str(ROOT / "scripts/ci/images/cw-image-consumer.py"),
                   "produce" if operation == "produce" else "consume", "--source-dir", str(self.source),
                   "--source-sha", self.identity["source_sha"], "--profile", "ci", "--output", str(output),
                   "--docker-bin", str(docker)]
        if operation == "produce":
            command.extend(("--builder", "synthetic-owned", "--sccache-mode", "disabled"))
        else:
            if operation == "amd64":
                command.extend(("--producer-receipt", str(self.receipt),
                                "--producer-sha256", self.receipt_sha256))
            command.extend(("--", str(docker), "buildx", "build", "--platform",
                            "linux/arm64" if operation == "native" else "linux/amd64", "--file",
                            str(self.source / "deployments/docker/daemon.Dockerfile"), str(self.source)))
        process = subprocess.Popen(command, cwd=ROOT, env=self.environment, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            stdout, stderr = process.communicate(timeout=120)
        except subprocess.TimeoutExpired:
            # Cancel the identified CLI owner so its c0 handler drains children.
            process.terminate()
            stdout, stderr = process.communicate(timeout=20)
            self.fail("owned diagnostic fixture timed out")
        self.assertEqual(self.receipt.read_bytes(), self.receipt_bytes)
        with self.helper.driver.reopen(str(self.receipt), self.receipt_sha256, self.source,
                                       self.identity["source_sha"], "ci", "0.0.0-ci") as admitted:
            admitted.revalidate()
        self.assertEqual((output / "build.log").read_bytes(), diagnostic)
        self.assertFalse((output / "build.json").exists())
        self.assertFalse((output / "consumer.json").exists())
        self.assertEqual(stdout, b"")
        return process.returncode, stderr

    def assert_empty_failure(self, operation):
        status, stderr = self.solve(operation, 53)
        self.assertEqual(status, 53, stderr.decode())
        self.assertIn(b"solve failed; owned outputs retained", stderr)
        self.assertNotIn(b"Traceback", stderr)

    def test_empty_producer_failure_preserves_owned_exit_53(self):
        self.assert_empty_failure("produce")

    def test_empty_amd64_consumer_failure_preserves_owned_exit_53(self):
        self.assert_empty_failure("amd64")

    def test_empty_native_consumer_failure_preserves_owned_exit_53(self):
        self.assert_empty_failure("native")

    def test_empty_owned_exit_one_does_not_fail_terminal_diagnostics(self):
        for operation in ("produce", "amd64", "native"):
            with self.subTest(operation=operation):
                status, stderr = self.solve(operation, 1)
                self.assertEqual(status, 1)
                self.assertIn(b"solve failed; owned outputs retained", stderr)
                self.assertNotIn(b"Traceback", stderr)

    def test_nonempty_terminal_cache_diagnostic_is_preserved(self):
        diagnostic = (b"synthetic earlier solve vertex\n"
                      b"ERROR: failed to build: failed to solve: failed to load cache: S3 GetObject NoSuchKey\n")
        for operation in ("produce", "amd64", "native"):
            with self.subTest(operation=operation):
                status, stderr = self.solve(operation, 1, diagnostic)
                self.assertEqual(status, 1)
                self.assertIn(diagnostic, stderr)
                self.assertTrue(stderr.endswith(diagnostic.splitlines()[-1] + b"\n"), stderr)
                self.assertNotIn(b"Traceback", stderr)

    def test_silent_success_still_requires_log_and_provenance_admission(self):
        for operation in ("produce", "amd64", "native"):
            with self.subTest(operation=operation):
                status, stderr = self.solve(operation, 0)
                self.assertEqual(status, 1)
                self.assertIn(b"build refused; owned outputs retained", stderr)
                self.assertNotIn(b"solve failed", stderr)


if __name__ == "__main__":
    unittest.main()
