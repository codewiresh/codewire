#!/usr/bin/env python3
"""Synthetic, entitlement-free tests for the App Sandbox canary harness."""

import argparse
import errno
import importlib.util
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


spec = importlib.util.spec_from_file_location(
    "macos_app_sandbox_canary",
    Path(__file__).with_name("macos-app-sandbox-canary.py"),
)
canary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(canary)
QUARANTINE_QUERY = canary.quarantine_attribute_size


def complete_result(property_value: str = "not-falsified") -> dict[str, object]:
    return {
        "schemaVersion": 1,
        "experiment": canary.EXPERIMENT,
        "property": property_value,
        "completion": "complete",
        "artifacts": "retained",
        "controlDirectRead": "succeeded",
        "controlDeputyRead": "succeeded",
        "candidateDirectRead": "denied",
        "candidateDeputyRead": "succeeded" if property_value == "falsified" else "denied",
    }


class SandboxCanaryHarnessTests(unittest.TestCase):
    def setUp(self):
        # These tests model Darwin's known absent quarantine attribute. Linux
        # rejects the Apple xattr namespace as unsupported, which production
        # correctly treats as inconclusive rather than quarantine absence.
        missing = getattr(errno, "ENOATTR", getattr(errno, "ENODATA", None))
        quarantine = mock.patch.object(canary, "quarantine_attribute_size", side_effect=OSError(missing, "missing"))
        quarantine.start()
        self.addCleanup(quarantine.stop)
        self.temporary = tempfile.TemporaryDirectory(prefix="cw-sandbox-canary-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)
        self.build = self.root / "build"
        self.build.mkdir(mode=0o700)
        for product in canary.PRODUCTS:
            path = self.build / product
            path.write_bytes(b"fixed-" + product.encode())
            path.chmod(0o700)

    def arguments(self, artifact: Path) -> argparse.Namespace:
        return argparse.Namespace(build_root=str(self.build), artifact_root=str(artifact))

    def test_cli_has_only_two_fixed_roots(self):
        parsed = canary.parse_arguments(
            ["--build-root", str(self.build), "--artifact-root", str(self.root / "run")]
        )
        self.assertEqual(
            vars(parsed),
            {"build_root": str(self.build), "artifact_root": str(self.root / "run")},
        )
        with self.assertRaises(SystemExit):
            canary.parse_arguments(
                [
                    "--build-root",
                    str(self.build),
                    "--artifact-root",
                    str(self.root / "run"),
                    "--command",
                    "sh",
                ]
            )

    def test_roots_require_private_canonical_non_tcc_parent(self):
        artifact = self.root / "run"
        with mock.patch.object(canary, "forbidden_run_roots", return_value=[]):
            build, actual, separate_canary = canary.validate_run_roots(
                str(self.build), str(artifact)
            )
        self.assertEqual(build, self.build)
        self.assertEqual(actual, artifact)
        self.assertEqual(separate_canary.parent, artifact.parent)
        self.assertFalse(canary.is_within(separate_canary, artifact))

        alias = self.root / "alias"
        alias.symlink_to(self.build)
        with (
            mock.patch.object(canary, "forbidden_run_roots", return_value=[]),
            self.assertRaisesRegex(canary.ExperimentFailure, "canonical"),
        ):
            canary.validate_run_roots(str(alias), str(artifact))

        self.root.chmod(0o755)
        with (
            mock.patch.object(canary, "forbidden_run_roots", return_value=[]),
            self.assertRaisesRegex(canary.ExperimentFailure, "0700"),
        ):
            canary.validate_run_roots(str(self.build), str(artifact))

    def test_broad_and_tcc_locations_are_rejected(self):
        with mock.patch.object(Path, "home", return_value=self.root):
            for name in ("Desktop", "Documents", "Downloads"):
                parent = self.root / name
                parent.mkdir(mode=0o700)
                with self.assertRaisesRegex(canary.ExperimentFailure, "broad or TCC"):
                    canary.validate_run_roots(str(self.build), str(parent / "run"))

    def test_canary_cannot_be_placed_under_build_or_bundle(self):
        nested = self.build / "private"
        nested.mkdir(mode=0o700)
        with (
            mock.patch.object(canary, "forbidden_run_roots", return_value=[]),
            self.assertRaisesRegex(canary.ExperimentFailure, "canary root"),
        ):
            canary.validate_run_roots(str(self.build), str(nested / "run"))

        bundle = self.root / "Fixture.app"
        bundle.mkdir(mode=0o700)
        with (
            mock.patch.object(canary, "forbidden_run_roots", return_value=[]),
            self.assertRaisesRegex(canary.ExperimentFailure, "canary root"),
        ):
            canary.validate_run_roots(str(self.build), str(bundle / "run"))

    def test_product_must_be_owned_unaliased_single_link_executable(self):
        product = canary.exact_product(self.build, canary.PRODUCTS[0])
        self.addCleanup(product.close)
        path = product.path
        self.assertEqual(path, self.build / canary.PRODUCTS[0])
        path.chmod(0o755 | stat.S_IWGRP)
        with self.assertRaisesRegex(canary.ExperimentFailure, "identity"):
            canary.exact_product(self.build, canary.PRODUCTS[0])

    def test_fifo_product_is_rejected_without_blocking(self):
        os.mkfifo(self.build / "fifo", 0o700)
        command = (
            "import importlib.util,pathlib,sys;"
            "s=importlib.util.spec_from_file_location('canary',sys.argv[1]);"
            "m=importlib.util.module_from_spec(s);s.loader.exec_module(m);"
            "m.exact_product(pathlib.Path(sys.argv[2]),'fifo')"
        )
        result = subprocess.run(
            [sys.executable, "-c", command, str(Path(canary.__file__)), str(self.build)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3, check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"build product identity is invalid", result.stderr)

    def test_copy_retains_admitted_descriptor_and_rejects_replacement(self):
        product = canary.exact_product(self.build, canary.PRODUCTS[0])
        self.addCleanup(product.close)
        original = product.path.read_bytes()
        first, second = self.root / "copy1", self.root / "copy2"
        self.assertEqual(canary.copy_executable(product, first), product.sha256)
        self.assertEqual(canary.copy_executable(product, second), product.sha256)
        self.assertEqual(first.read_bytes(), original)
        self.assertEqual(second.read_bytes(), original)
        replacement = self.build / "replacement"
        replacement.write_bytes(b"different-executable")
        replacement.chmod(0o700)
        os.replace(replacement, product.path)
        with self.assertRaisesRegex(canary.ExperimentFailure, "changed"):
            canary.copy_executable(product, self.root / "substituted")
        self.assertFalse((self.root / "substituted").exists())

    def test_admitted_product_rejects_changed_bytes_or_unbounded_size(self):
        product = canary.exact_product(self.build, canary.PRODUCTS[0])
        self.addCleanup(product.close)
        product.path.write_bytes(b"changed")
        with self.assertRaisesRegex(canary.ExperimentFailure, "changed"):
            canary.copy_executable(product, self.root / "copy")
        with (
            mock.patch.object(canary, "MAX_PRODUCT_BYTES", 2),
            self.assertRaisesRegex(canary.ExperimentFailure, "identity"),
        ):
            canary.exact_product(self.build, canary.PRODUCTS[1])

    def test_quarantine_only_known_absence_is_accepted(self):
        absent = getattr(errno, "ENOATTR", getattr(errno, "ENODATA", None))
        with mock.patch.object(canary, "quarantine_attribute_size", side_effect=OSError(absent, "missing")):
            canary.require_no_quarantine(self.build)
        for code in {errno.EACCES, errno.EPERM, errno.EIO, errno.ENOTSUP}:
            with (
                self.subTest(errno=code),
                mock.patch.object(canary, "quarantine_attribute_size", side_effect=OSError(code, "unsupported")),
                self.assertRaises(OSError),
            ):
                canary.require_no_quarantine(self.build)
        for value in (10, 0):
            with (
                self.subTest(value=value),
                mock.patch.object(canary, "quarantine_attribute_size", return_value=value),
                self.assertRaisesRegex(canary.ExperimentFailure, "quarantined"),
            ):
                canary.require_no_quarantine(self.build)

    def test_darwin_quarantine_bridge_queries_only_size_and_keeps_fd_binding(self):
        library = mock.Mock()
        library.fgetxattr.return_value = 0
        library.getxattr.return_value = 12
        with (
            mock.patch.object(canary.sys, "platform", "darwin"),
            mock.patch.object(canary.ctypes, "CDLL", return_value=library) as load,
        ):
            self.assertEqual(QUARANTINE_QUERY(123), 0)
            self.assertEqual(QUARANTINE_QUERY(self.build), 12)
        library.fgetxattr.assert_called_once_with(123, b"com.apple.quarantine", None, 0, 0, 0)
        library.getxattr.assert_called_once_with(os.fsencode(self.build), b"com.apple.quarantine", None, 0, 0, 1)
        load.assert_called_with("/usr/lib/libSystem.B.dylib", use_errno=True)
        library.fgetxattr.return_value = -1
        with (
            mock.patch.object(canary.sys, "platform", "darwin"),
            mock.patch.object(canary.ctypes, "CDLL", return_value=library),
            mock.patch.object(canary.ctypes, "get_errno", return_value=errno.EIO),
            self.assertRaises(OSError) as caught,
        ):
            QUARANTINE_QUERY(123)
        self.assertEqual(caught.exception.errno, errno.EIO)

    @unittest.skipUnless(sys.platform == "darwin", "Darwin public xattr ABI")
    def test_native_darwin_quarantine_absence_on_owned_file_and_descriptor(self):
        path = self.build / canary.PRODUCTS[0]
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            for target in (path, descriptor):
                with self.subTest(target=type(target).__name__), self.assertRaises(OSError) as caught:
                    QUARANTINE_QUERY(target)
                self.assertEqual(caught.exception.errno, errno.ENOATTR)
        finally:
            os.close(descriptor)

    def test_result_contract_keeps_falsification_independent_of_completion(self):
        value = complete_result("falsified")
        value["completion"] = "unknown"
        self.assertEqual(canary.validate_result(value)["property"], "falsified")
        invalid = dict(value)
        invalid["property"] = "not-falsified"
        with self.assertRaisesRegex(canary.ExperimentFailure, "incomplete"):
            canary.validate_result(invalid)

    def test_result_rejects_extra_fields_and_unsupported_falsification(self):
        extra = complete_result()
        extra["detail"] = "/private/path"
        with self.assertRaisesRegex(canary.ExperimentFailure, "schema"):
            canary.validate_result(extra)
        unsupported = complete_result()
        unsupported["property"] = "falsified"
        with self.assertRaisesRegex(canary.ExperimentFailure, "forbidden read"):
            canary.validate_result(unsupported)

    def test_not_falsified_requires_both_controls_and_both_denials(self):
        for field in (
            "controlDirectRead", "controlDeputyRead", "candidateDirectRead", "candidateDeputyRead"
        ):
            for observation in ("failed", "unknown", "not-run"):
                value = complete_result()
                value[field] = observation
                with self.subTest(field=field, value=observation), self.assertRaises(canary.ExperimentFailure):
                    canary.validate_result(value)
        value = complete_result()
        value["schemaVersion"] = True
        with self.assertRaises(canary.ExperimentFailure):
            canary.validate_result(value)

    def test_owner_log_read_is_bounded(self):
        log = self.root / "owner.log"
        log.write_bytes(b"x" * canary.MAX_OUTPUT_BYTES)
        log.chmod(0o600)
        self.assertEqual(len(canary.read_bounded(log)), canary.MAX_OUTPUT_BYTES)
        log.write_bytes(b"x" * (canary.MAX_OUTPUT_BYTES + 1))
        with self.assertRaisesRegex(canary.ExperimentFailure, "exceeded"):
            canary.read_bounded(log)

    def test_fixed_bundle_shape_and_started_receipt_precede_owner(self):
        artifact = self.root / "artifacts"
        observed: dict[str, object] = {}

        def fake_owner(executable: Path, configuration: Path, logs: Path, **binding):
            receipt = json.loads((artifact / "receipt.json").read_text())
            observed["receipt"] = receipt
            config = json.loads(configuration.read_text())
            observed["config"] = config
            self.assertEqual(config["checkpointPath"], str(binding["checkpoint"]))
            self.assertEqual(config["nonce"], binding["nonce"])
            for name in ("controlCDHash", "candidateCDHash", "deputyCDHash"):
                self.assertEqual(config[name], "a" * 40)
            deputy_config = json.loads(
                (
                    artifact
                    / "bundles"
                    / "Candidate.app"
                    / "Contents"
                    / "Helpers"
                    / "Deputy.app"
                    / "Contents"
                    / "Resources"
                    / "run-config.json"
                ).read_text()
            )
            observed["deputy"] = deputy_config
            self.assertEqual(executable.name, "sandbox-experiment-owner")
            self.assertEqual(logs, artifact / "logs")
            return complete_result()

        with (
            mock.patch.object(canary.platform, "system", return_value="Darwin"),
            mock.patch.object(canary.platform, "machine", return_value="arm64"),
            mock.patch.object(canary, "forbidden_run_roots", return_value=[]),
            mock.patch.object(canary, "sign_bundle"),
            mock.patch.object(canary, "verify_bundle", return_value="a" * 40),
            mock.patch.object(
                canary,
                "run_checked",
                return_value=mock.Mock(stdout=b"26.0\n", returncode=0),
            ),
            mock.patch.object(canary, "execute_owner", side_effect=fake_owner),
        ):
            result, status = canary.run(self.arguments(artifact))

        self.assertEqual(status, 0)
        self.assertEqual(result["property"], "not-falsified")
        self.assertEqual(observed["receipt"]["status"], "started")
        config = observed["config"]
        deputy = observed["deputy"]
        self.assertEqual(
            config["deputyBundlePath"],
            str(
                artifact
                / "bundles"
                / "Candidate.app"
                / "Contents"
                / "Helpers"
                / "Deputy.app"
            ),
        )
        self.assertEqual(deputy["canaryPath"], config["canaryPath"])
        self.assertFalse(canary.is_within(Path(config["canaryPath"]), artifact))
        self.assertEqual(
            (
                artifact
                / "bundles"
                / "Control.app"
                / "Contents"
                / "MacOS"
                / "sandbox-candidate"
            ).read_bytes(),
            (
                artifact
                / "bundles"
                / "Candidate.app"
                / "Contents"
                / "MacOS"
                / "sandbox-candidate"
            ).read_bytes(),
        )

    def test_falsified_complete_has_distinct_nonzero_acceptance_status(self):
        artifact = self.root / "artifacts"
        with (
            mock.patch.object(canary.platform, "system", return_value="Darwin"),
            mock.patch.object(canary.platform, "machine", return_value="arm64"),
            mock.patch.object(canary, "forbidden_run_roots", return_value=[]),
            mock.patch.object(canary, "sign_bundle"),
            mock.patch.object(canary, "verify_bundle", return_value="a" * 40),
            mock.patch.object(
                canary,
                "run_checked",
                return_value=mock.Mock(stdout=b"26.0\n", returncode=0),
            ),
            mock.patch.object(canary, "execute_owner", return_value=complete_result("falsified")),
        ):
            result, status = canary.run(self.arguments(artifact))
        self.assertEqual(result["property"], "falsified")
        self.assertEqual(result["completion"], "complete")
        self.assertEqual(status, 2)

    def checkpoint(self, result=None, nonce="a" * 32):
        checkpoint = self.root / "checkpoint.json"
        wrapper = {
            "schemaVersion": 1, "experiment": canary.EXPERIMENT,
            "nonce": nonce, "result": result or complete_result("falsified"),
        }
        checkpoint.write_bytes(canary.canonical_json(wrapper) + b"\n")
        checkpoint.chmod(0o600)
        return checkpoint

    def synthetic_interpreter(self):
        # Keep the same real subprocess/FD/session/wait path on noexec /tmp;
        # the synthetic owner is Python source, not a native bundle executable.
        popen = subprocess.Popen

        def interpret(argv, **kwargs):
            return popen([sys.executable, *argv], **kwargs)

        return mock.patch.object(canary.subprocess, "Popen", side_effect=interpret)

    def test_counterexample_checkpoint_requires_exact_nonce_schema_and_private_file(self):
        checkpoint = self.checkpoint()
        value = canary.read_counterexample(checkpoint, "a" * 32)
        self.assertEqual(value["property"], "falsified")
        self.assertEqual(value["completion"], "unknown")
        self.assertIsNone(canary.read_counterexample(checkpoint, "b" * 32))
        wrapper = json.loads(checkpoint.read_bytes())
        wrapper["extra"] = True
        checkpoint.write_bytes(canary.canonical_json(wrapper) + b"\n")
        self.assertIsNone(canary.read_counterexample(checkpoint, "a" * 32))
        checkpoint = self.checkpoint()
        checkpoint.chmod(0o644)
        self.assertIsNone(canary.read_counterexample(checkpoint, "a" * 32))

    def test_owned_cleanup_never_signals_after_reap_or_unknown_child(self):
        process = mock.Mock(pid=12345)
        for outcome in (0, ChildProcessError(errno.ECHILD, "unknown")):
            process.poll.side_effect = outcome if isinstance(outcome, Exception) else None
            process.poll.return_value = outcome
            with mock.patch.object(canary.os, "killpg") as kill:
                if isinstance(outcome, Exception):
                    with self.assertRaises(ChildProcessError):
                        canary.terminate_owned_group(process)
                else:
                    canary.terminate_owned_group(process)
                kill.assert_not_called()
        process.poll.side_effect = [None, 0]
        process.wait.side_effect = subprocess.TimeoutExpired("synthetic", 2)
        with mock.patch.object(canary.os, "killpg") as kill:
            canary.terminate_owned_group(process)
        kill.assert_called_once_with(process.pid, signal.SIGTERM)

    def test_owner_failure_and_timeout_preserve_persisted_counterexample(self):
        checkpoint = self.checkpoint()
        for suffix, script, timeout in (
            ("failure", "raise SystemExit(70)", 3),
            ("timeout", "import time;time.sleep(10)", 0.1),
        ):
            executable = self.root / f"synthetic-owner-{suffix}"
            executable.write_text(f"#!{sys.executable}\n{script}\n")
            executable.chmod(0o700)
            logs = self.root / f"logs-{suffix}"
            logs.mkdir(mode=0o700)
            with (
                self.subTest(path=suffix),
                mock.patch.object(canary, "OWNER_TIMEOUT_SECONDS", timeout),
                self.synthetic_interpreter(),
            ):
                result = canary.execute_owner(
                    executable, self.root / "config", logs,
                    checkpoint=checkpoint, nonce="a" * 32,
                )
                self.assertEqual(result["property"], "falsified")
                self.assertEqual(result["completion"], "unknown")

    def test_owner_normalizes_inherited_auto_reaping(self):
        executable = self.root / "synthetic-owner"
        output = canary.canonical_json(complete_result()).decode()
        executable.write_text(f"#!{sys.executable}\nprint({output!r})\n")
        executable.chmod(0o700)
        logs = self.root / "logs"
        logs.mkdir(mode=0o700)
        prior = signal.signal(signal.SIGCHLD, signal.SIG_IGN)
        try:
            with self.synthetic_interpreter():
                result = canary.execute_owner(
                    executable, self.root / "config", logs,
                    checkpoint=self.root / "absent", nonce="a" * 32,
                )
            self.assertEqual(signal.getsignal(signal.SIGCHLD), signal.SIG_DFL)
            self.assertEqual(result, complete_result())
        finally:
            signal.signal(signal.SIGCHLD, prior)

    def test_valid_stdout_counterexample_survives_later_log_error(self):
        executable = self.root / "synthetic-owner"
        output = canary.canonical_json(complete_result("falsified")).decode()
        executable.write_text(f"#!{sys.executable}\nprint({output!r})\n")
        executable.chmod(0o700)
        logs = self.root / "logs"
        logs.mkdir(mode=0o700)
        read = canary.read_bounded

        def fail_stderr(path):
            if path.name == "owner.stderr":
                raise OSError(errno.EIO, "synthetic log failure")
            return read(path)

        with self.synthetic_interpreter(), mock.patch.object(canary, "read_bounded", side_effect=fail_stderr):
            result = canary.execute_owner(
                executable, self.root / "config", logs,
                checkpoint=self.root / "absent", nonce="a" * 32,
            )
        self.assertEqual(result["property"], "falsified")
        self.assertEqual(result["completion"], "unknown")

    def test_canary_mutation_without_read_is_inconclusive(self):
        artifact = self.root / "artifacts"

        def mutate_canary(_executable, configuration, _logs, **_binding):
            config = json.loads(configuration.read_bytes())
            Path(config["canaryPath"]).write_bytes(b"changed")
            return complete_result()

        with (
            mock.patch.object(canary.platform, "system", return_value="Darwin"),
            mock.patch.object(canary.platform, "machine", return_value="arm64"),
            mock.patch.object(canary, "forbidden_run_roots", return_value=[]),
            mock.patch.object(canary, "sign_bundle"),
            mock.patch.object(canary, "verify_bundle", return_value="a" * 40),
            mock.patch.object(canary, "run_checked", return_value=mock.Mock(stdout=b"26.0\n")),
            mock.patch.object(canary, "execute_owner", side_effect=mutate_canary),
        ):
            result, status = canary.run(self.arguments(artifact))
        self.assertEqual(status, 1)
        self.assertEqual(result["property"], "inconclusive")
        self.assertEqual(result["completion"], "unknown")
        self.assertEqual(result["candidateDirectRead"], "denied")
        self.assertEqual(result["candidateDeputyRead"], "denied")

    def test_final_digest_failure_preserves_established_counterexample(self):
        artifact = self.root / "artifacts"
        digest = canary.digest_fd
        owner_returned = False

        def fake_owner(*_arguments, **_binding):
            nonlocal owner_returned
            owner_returned = True
            return complete_result("falsified")

        def final_digest(*arguments):
            if owner_returned:
                raise canary.ExperimentFailure("synthetic changed-size observation")
            return digest(*arguments)

        with (
            mock.patch.object(canary.platform, "system", return_value="Darwin"),
            mock.patch.object(canary.platform, "machine", return_value="arm64"),
            mock.patch.object(canary, "forbidden_run_roots", return_value=[]),
            mock.patch.object(canary, "sign_bundle"),
            mock.patch.object(canary, "verify_bundle", return_value="a" * 40),
            mock.patch.object(canary, "run_checked", return_value=mock.Mock(stdout=b"26.0\n")),
            mock.patch.object(canary, "execute_owner", side_effect=fake_owner),
            mock.patch.object(canary, "digest_fd", side_effect=final_digest),
        ):
            result, status = canary.run(self.arguments(artifact))
        self.assertEqual(status, 2)
        self.assertEqual(result["property"], "falsified")
        self.assertEqual(result["completion"], "unknown")
        self.assertIsNone(json.loads((artifact / "receipt.json").read_bytes())["canaryUnchanged"])


if __name__ == "__main__":
    unittest.main()
