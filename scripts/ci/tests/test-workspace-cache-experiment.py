#!/usr/bin/env python3
"""Synthetic source/event/report contracts. No host Docker, provider, or build."""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import stat
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]


def module(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


selector = module("experiment_selector", "scripts/ci/setup/select-workspace-cache-experiment.py")
report = module("experiment_report", "scripts/ci/verify/workspace-cache-report.py")
SOURCE, TREE = "1" * 40, "2" * 40
SEED = "run-2047/tree-" + TREE + "/seed-" + "3" * 64
# A private old/new controller may supply only the historical report function.
# Fixture setup always uses the current actual source/producer admission.
LEGACY_REPORT_FINALIZER = None


class EventTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="workspace-experiment-event-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.path = self.root / "event.json"
        self.event = {"repository": {"full_name": "codewire/codewire"}, "pull_request": {
            "number": 2047, "base": {"ref": "main", "repo": {"full_name": "codewire/codewire"}},
            "head": {"ref": "experiment/workspace-r2-cache/2047", "sha": SOURCE}, "labels": []}}
        self.env = {"GITHUB_EVENT_NAME": "pull_request", "GITHUB_EVENT_PATH": str(self.path),
                    "GITHUB_REF": "refs/pull/2047/head", "GITHUB_SHA": SOURCE,
                    "GITHUB_REPOSITORY": "codewire/codewire", "CODEWIRE_EXPECTED_SOURCE_SHA": SOURCE,
                    "CODEWIRE_EXPECTED_SOURCE_TREE": TREE}
        self.git = mock.patch.object(selector.subprocess, "check_output", return_value=SOURCE + "\n" + TREE + "\n")
        self.command = self.git.start()
        self.addCleanup(self.git.stop)

    def select(self):
        self.path.write_text(json.dumps(self.event))
        return selector.selection(self.root, self.env)

    def test_first_open_branch_and_exact_label_select_four_cases(self):
        self.assertEqual(self.select()["matrix"]["include"], list(selector.CASES))
        self.event["pull_request"]["head"]["ref"] = "ordinary"
        self.event["pull_request"]["labels"] = [{"name": "ci/r2-cache-canary"}]
        self.assertTrue(self.select()["selected"])

    def test_ordinary_events_emit_one_inert_dependency_sentinel(self):
        unselected = {"selected": False, "matrix": {"include": [selector.UNSELECTED]}}
        for event in ("push", "workflow_dispatch", "pull_request_target"):
            with self.subTest(event=event):
                self.env["GITHUB_EVENT_NAME"] = event
                self.assertEqual(self.select(), unselected)
        self.env["GITHUB_EVENT_NAME"] = "pull_request"
        self.event["pull_request"]["head"]["ref"] = "ordinary"
        self.assertEqual(self.select(), unselected)

    def test_branch_pattern_is_full_ascii_and_bounded(self):
        for branch in ("experiment/workspace-r2-cache/", "experiment/workspace-r2-cache/" + "x" * 65,
                       "experiment/workspace-r2-cache/a\n", "experiment/workspace-r2-cache/é",
                       "experiment/workspace-r2-cache/a/extra", "prefix/experiment/workspace-r2-cache/a",
                       "experiment/workspace-r2-cache/A", "experiment/workspace-r2-cache/-a"):
            with self.subTest(branch=branch):
                self.event["pull_request"]["head"]["ref"] = branch
                self.assertFalse(self.select()["selected"])

    def test_explicit_local_and_disabled_win(self):
        for request in ("local", "disabled"):
            self.env["CODEWIRE_BUILDKIT_CACHE_REQUEST"] = request
            self.assertFalse(self.select()["selected"])

    def test_wrong_source_repository_or_ref_fails(self):
        baseline = copy.deepcopy(self.event)
        for mutate in (
            lambda e: e["repository"].update(full_name="other/codewire"),
            lambda e: e["pull_request"]["base"]["repo"].update(full_name="other/codewire"),
            lambda e: e["pull_request"]["base"].update(ref="other"),
            lambda e: e["pull_request"]["head"].update(sha="4" * 40),
            lambda e: e["pull_request"]["head"].update(sha=False),
            lambda e: e["pull_request"].update(number=True),
        ):
            self.event = copy.deepcopy(baseline)
            mutate(self.event)
            with self.assertRaises(ValueError):
                self.select()
        self.event = baseline
        for key in ("GITHUB_REF", "GITHUB_SHA", "GITHUB_REPOSITORY", "CODEWIRE_EXPECTED_SOURCE_TREE"):
            original = self.env[key]
            self.env[key] = "wrong"
            with self.assertRaises(ValueError):
                self.select()
            self.env[key] = original
        self.command.return_value = SOURCE + "\n" + "5" * 40 + "\n"
        with self.assertRaises(ValueError):
            self.select()

    def test_typed_events_and_null_labels(self):
        for field in ("head", "base", "labels"):
            for value in (False, True, "bad", 5):
                event = copy.deepcopy(self.event)
                event["pull_request"][field] = value
                with self.assertRaises(ValueError):
                    selector.requested(event)
        self.event["pull_request"]["labels"] = None
        self.assertTrue(self.select()["selected"])
        for value in ([], None, False):
            with self.assertRaises(ValueError):
                selector.requested(value)


class VersionTests(unittest.TestCase):
    def test_pnpm_inventory_matches_shell_supported_no_shebang_launcher(self):
        temporary_parent = ROOT / ".tmp"
        temporary_parent.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="workspace-pnpm-launcher-", dir=temporary_parent) as temporary:
            binary = Path(temporary) / "pnpm"
            binary.write_text("printf '12.3.4\\n'\n")
            binary.chmod(0o755)
            self.assertNotEqual(binary.read_bytes()[:2], b"#!")
            path = temporary + os.pathsep + os.environ["PATH"]
            output = io.StringIO()
            with mock.patch.dict(os.environ, {"PATH": path}), \
                    mock.patch.object(report, "VERSION_COMMANDS", {"pnpm": report.VERSION_COMMANDS["pnpm"]}), \
                    contextlib.redirect_stdout(output):
                report.versions()
            self.assertEqual(json.loads(output.getvalue()), {"pnpm": "12.3.4"})


class ReportTests(unittest.TestCase):
    # Retain every original native-compiler report/refusal on the ARM route.
    # The separate AMD class uses actual shared producer admission below.
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="workspace-experiment-report-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.env = {"RUNNER_TEMP": str(self.root), "GITHUB_OUTPUT": str(self.root / "output"),
                    "CODEWIRE_EXPECTED_SOURCE_SHA": SOURCE, "CODEWIRE_EXPECTED_SOURCE_TREE": TREE,
                    "CODEWIRE_SCCACHE_MODE": "r2", "CODEWIRE_BUILDKIT_CACHE_MODE": "r2"}
        patch = mock.patch.dict(os.environ, self.env)
        patch.start()
        self.addCleanup(patch.stop)
        patch = mock.patch.object(report.subprocess, "check_output", side_effect=AssertionError("host subprocess forbidden"))
        patch.start()
        self.addCleanup(patch.stop)
        self.seed_directory = self.fixture("seed", "3")
        self.seed = self.finish(self.seed_directory)
        os.environ["CODEWIRE_WORKSPACE_CACHE_SEED_REPORT"] = json.dumps(self.seed)

    def fixture(self, case, identity):
        directory = self.root / case
        directory.mkdir()
        compiler, layers = report.MODES[case]
        header = {"case": case, "source_sha": SOURCE, "source_tree": TREE, "architecture": "arm64",
                  "docker_daemon_id": "daemon-" + identity, "builder_container_id": identity * 64,
                  "builder_name": "codewire-workspace-fixture-" + identity,
                  "pins": {"buildkit_image": "pinned", "job_image_id": "pinned"}, "seed_cache_id": SEED}
        (directory / "identity.json").write_text(json.dumps(header))
        receipt = {"source_sha": SOURCE, "source_tree": TREE, "architecture": "arm64",
                   "cache_modes": {"compiler": compiler, "layers": layers}, "layer_cache_fallback": False,
                   "workspace_image_id": "sha256:" + "4" * 64}
        (directory / "receipt.json").write_text(json.dumps(receipt))
        (directory / "versions.json").write_text(json.dumps({key: "version1" for key in report.VERSION_COMMANDS}))
        (directory / "elapsed-seconds").write_text("15")
        (directory / "sampler-stop-request").write_text("")
        (directory / "sampler-complete.json").write_text('{"status":"stopped","sample_count":1}')
        (directory / "resources.jsonl").write_text("\n".join(json.dumps({"time_ns": i + 1,
            "memory_bytes": 1000 + i, "backing_filesystem_total_bytes": 10000,
            "backing_filesystem_used_bytes": 2000 + i, "backing_filesystem_available_bytes": 8000 - i,
            "network_rx_bytes": 3000 + i, "network_tx_bytes": 4000 + i}) for i in range(3)) + "\n")
        export = "#9 exporting cache to Amazon S3\n#9 DONE 1.0s\n" if layers == "r2" else ""
        (directory / "base-build.log").write_text(export)
        compile_result = "CACHED" if case.startswith("warm-") else "DONE 3.0s"
        (directory / "workspace-build.log").write_text(
            "#1 [workspace-floating-tools 1/2] RUN npm install\n#1 DONE 1.0s\n"
            "#2 [workspace-floating-tools 2/2] RUN go install\n#2 DONE 2.0s\n"
            "#3 [cw-builder 1/1] RUN codewire-rust-build cargo build\n#3 " + compile_result + "\n"
            "#3 1.0 Cache hits 4\n#3 1.0 Cache hits (Rust) 4\n#3 1.0 Cache misses 2\n#3 1.0 Cache write errors 0\n" + export)
        builder = header["builder_name"]
        (directory / "workspace-metadata.json").write_text(json.dumps({
            "buildx.build.ref": f"{builder}/{builder}-node/" + "a" * 25,
            "containerimage.config.digest": receipt["workspace_image_id"]}))
        self.history(directory, [{"digest": "sha256:" + "6" * 64, "inputs": ["sha256:" + "7" * 64],
                                 "name": "[cw-builder 1/1] RUN codewire-rust-build cargo build",
                                 "started": "2026-09-10T10:00:00Z", "completed": "2026-09-10T10:00:03Z",
                                 "cached": case.startswith("warm-")}])
        return directory

    def history(self, directory, events):
        raw = b"".join((json.dumps({"vertexes": [event]}) + "\n").encode() for event in events)
        (directory / "workspace-progress.jsonl").write_bytes(raw)
        metadata = json.loads((directory / "workspace-metadata.json").read_text())
        (directory / "workspace-history.json").write_text(json.dumps({
            "build_ref": metadata["buildx.build.ref"], "workspace_image_id": metadata["containerimage.config.digest"],
            "sha256": hashlib.sha256(raw).hexdigest()}))

    def finish(self, directory):
        case = json.loads((directory / "identity.json").read_text())["case"]
        os.environ["CODEWIRE_SCCACHE_MODE"], os.environ["CODEWIRE_BUILDKIT_CACHE_MODE"] = report.MODES[case]
        with contextlib.redirect_stdout(io.StringIO()):
            report.finalize(directory, directory / "receipt.json")
        return json.loads((directory / "result.json").read_text())

    def test_all_four_cases_and_fresh_worker_comparison(self):
        self.assertEqual(self.seed["metrics"]["backing_filesystem_initial_used_bytes"], 2000)
        self.assertEqual(self.seed["metrics"]["backing_filesystem_final_used_bytes"], 2002)
        self.assertEqual(self.seed["metrics"]["observed_backing_filesystem_max_used_bytes"], 2002)
        self.assertEqual(self.seed["metrics"]["observed_backing_filesystem_min_available_bytes"], 7998)
        values = [self.seed]
        for index, case in enumerate(("cold", "compiler", "warm-1", "warm-2"), 5):
            values.append(self.finish(self.fixture(case, str(index))))
        paths = []
        for index, value in enumerate(values):
            path = self.root / f"job-{index}.log"
            path.write_text("CODEWIRE_WORKSPACE_CACHE_REPORT=" + json.dumps(value) + "\n")
            paths.append(path)
        with contextlib.redirect_stdout(io.StringIO()):
            report.compare(paths)
        values[-1]["docker_daemon_id"] = values[-2]["docker_daemon_id"]
        paths[-1].write_text("CODEWIRE_WORKSPACE_CACHE_REPORT=" + json.dumps(values[-1]) + "\n")
        with self.assertRaises(ValueError):
            report.compare(paths)

    def test_missing_metrics_export_hits_and_drift_are_inconclusive(self):
        directory = self.fixture("warm-1", "5")
        files = ("metrics-error", "resources.jsonl", "versions.json", "workspace-progress.jsonl", "base-build.log", "receipt.json")
        baseline = {name: (directory / name).read_text() for name in files if (directory / name).exists()}
        mutations = {
            "metrics-error": "sampling failed",
            "resources.jsonl": "",
            "versions.json": json.dumps({key: "drift" for key in report.VERSION_COMMANDS}),
            "base-build.log": "#9 exporting cache to Amazon S3\n#9 ERROR: upload failed\n",
            "workspace-progress.jsonl": baseline["workspace-progress.jsonl"].replace('"cached": true', '"cached": false'),
            "receipt.json": baseline["receipt.json"].replace('"layer_cache_fallback": false', '"layer_cache_fallback": true'),
        }
        for name, value in mutations.items():
            with self.subTest(name=name):
                (directory / name).write_text(value)
                with self.assertRaises(ValueError):
                    self.finish(directory)
                self.assertFalse((directory / "result.json").exists())
                if name in baseline:
                    (directory / name).write_text(baseline[name])
                else:
                    (directory / name).unlink()

    def test_cached_completion_survives_lazy_extraction_and_plain_done(self):
        directory = self.fixture("warm-1", "5")
        cached = json.loads((directory / "workspace-progress.jsonl").read_text())["vertexes"][0]
        extraction = {key: value for key, value in cached.items() if key not in ("cached", "inputs")}
        self.history(directory, [cached, extraction])
        path = directory / "workspace-build.log"
        path.write_text(path.read_text().replace("#3 CACHED", "#3 DONE 16.2s"))
        result = self.finish(directory)
        self.assertTrue(result["phases"]["workspace"]["compiler_layer_cached"])
        self.assertFalse(result["phases"]["workspace"]["compiler_executed"])
        initial = {key: value for key, value in cached.items() if key not in ("cached", "started", "completed")}
        self.history(directory, [initial, cached, extraction, initial])
        self.assertTrue(self.finish(directory)["phases"]["workspace"]["compiler_layer_cached"])

    def test_compiler_execution_missing_or_malformed_native_proof_never_passes(self):
        directory = self.fixture("warm-1", "5")
        cached = json.loads((directory / "workspace-progress.jsonl").read_text())["vertexes"][0]
        execution = dict(cached, cached=False)
        extraction = {key: value for key, value in execution.items() if key != "inputs"}
        for events in (
            [], [extraction], [execution, extraction], [cached, execution],
            [dict(cached, cached="true")], [dict(cached, cached=1)],
            [dict(cached, completed=None)], [dict(cached, completed=True)],
            [dict(cached, error="failed")], [cached, dict(cached, completed=None)],
            [dict(cached, name="[other 1/1] RUN unrelated")],
            [cached, dict(cached, digest="sha256:" + "8" * 64)],
            [dict(cached, inputs="invalid")], [dict(cached, digest="invalid")],
        ):
            with self.subTest(events=events):
                self.history(directory, events)
                output = io.StringIO()
                with self.assertRaises(ValueError), contextlib.redirect_stdout(output):
                    self.finish(directory)
                self.assertFalse((directory / "result.json").exists())
                self.assertEqual(output.getvalue(), "")

    def test_history_requires_exact_owned_build_output_and_complete_capture(self):
        directory = self.fixture("warm-1", "5")
        metadata_path = directory / "workspace-metadata.json"
        original = json.loads(metadata_path.read_text())
        for metadata in (dict(original, **{"buildx.build.ref": "^0"}),
                         dict(original, **{"buildx.build.ref": original["buildx.build.ref"].replace("fixture-5/", "fixture-6/")}),
                         dict(original, **{"buildx.build.ref": original["buildx.build.ref"].replace("-node/", "-other/")}),
                         dict(original, **{"containerimage.config.digest": "sha256:" + "8" * 64})):
            metadata_path.write_text(json.dumps(metadata))
            with self.assertRaises(ValueError):
                self.finish(directory)
            self.assertFalse((directory / "result.json").exists())
        metadata_path.write_text(json.dumps(original))
        for name in ("workspace-progress.jsonl", "workspace-history.json"):
            path = directory / name
            raw = path.read_bytes()
            path.write_bytes(raw[:-2])
            with self.assertRaises(ValueError):
                self.finish(directory)
            self.assertFalse((directory / "result.json").exists())
            path.unlink()
            with self.assertRaises(OSError):
                self.finish(directory)
            path.write_bytes(raw)

    def test_capture_queries_only_owned_solve_and_failed_command_never_seals(self):
        directory = self.fixture("warm-1", "5")
        builder = "codewire-workspace-fixture-5"
        raw = (directory / "workspace-progress.jsonl").read_bytes()
        def capture(command, **kwargs):
            self.assertEqual(command, ["fixture-docker", "buildx", "history", "logs", "--builder", builder,
                                       "--progress", "rawjson", "a" * 25])
            self.assertNotIn("timeout", kwargs)  # The caller's process-group supervisor owns the deadline.
            self.assertTrue(kwargs["check"])
            kwargs["stderr"].write(raw)
        with mock.patch.object(report.subprocess, "run", side_effect=capture):
            report.capture_history("fixture-docker", builder, directory)
        self.finish(directory)
        for error in (subprocess.CalledProcessError(1, "fixture"), subprocess.TimeoutExpired("fixture", 60)):
            with mock.patch.object(report.subprocess, "run", side_effect=error), self.assertRaises(type(error)):
                report.capture_history("fixture-docker", builder, directory)
            self.assertFalse((directory / "workspace-history.json").exists())
            with self.assertRaises(OSError):
                self.finish(directory)
            self.assertFalse((directory / "result.json").exists())

    def test_history_capture_timeout_kills_plugin_descendants_without_acceptance(self):
        import signal
        import sys
        import time

        custody = module("workspace_history_fixture_custody", "scripts/ci/verify/build-linux-vmm-kernel.py")
        custody.arm_custody()
        directory = self.fixture("warm-1", "5")
        builder = "codewire-workspace-fixture-5"
        temporary_parent = ROOT / ".tmp"
        temporary_parent.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="workspace-history-timeout-", dir=temporary_parent) as temporary:
            private = Path(temporary)
            binary = private / "docker"
            (private / "expected.jsonl").write_bytes((directory / "workspace-progress.jsonl").read_bytes())
            binary.write_text("""#!/usr/bin/env python3
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

private = Path(__file__).parent
plugin = sys.argv[1:] == ["--plugin"]
if not plugin:
    assert sys.argv[1:] == ["buildx", "history", "logs", "--builder",
                           "codewire-workspace-fixture-5", "--progress", "rawjson", "a" * 25]
pid = os.getpid()
start = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]
(private / ("plugin.pid" if plugin else "docker.pid")).write_text(json.dumps([pid, start]))
if plugin:
    time.sleep(30)
else:
    sys.stderr.buffer.write((private / "expected.jsonl").read_bytes())
    sys.stderr.buffer.flush()
    child = subprocess.Popen([sys.executable, __file__, "--plugin"])
    def terminate(signum, frame):
        raise SystemExit(128 + signum)
    signal.signal(signal.SIGTERM, terminate)
    try:
        child.wait()
    finally:
        child.wait(timeout=2)
""")
            binary.chmod(0o700)

            def live_pid(path):
                if not path.exists():
                    return None
                pid, start = json.loads(path.read_text())
                try:
                    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
                except (FileNotFoundError, ProcessLookupError):
                    # The process can exit between opening and reading its
                    # stat file; the read then fails with ESRCH.
                    return None
                return pid if fields[19] == start and fields[0] != "Z" else None

            pid_paths = [private / "plugin.pid", private / "docker.pid"]
            try:
                completed = subprocess.run([
                    "bash", "-euo", "pipefail", "-c",
                    'source "$1"; workspace_cache_timed_command 1s "$2" "$3" capture-history "$4" "$5" "$6"',
                    "history-timeout-fixture", str(ROOT / "scripts/ci/images/workspace-cache.sh"),
                    sys.executable, str(ROOT / "scripts/ci/verify/workspace-cache-report.py"),
                    str(binary), builder, str(directory),
                ], cwd=ROOT, capture_output=True, text=True, timeout=10)
                self.assertEqual(completed.returncode, 124, completed.stderr)
                self.assertTrue(all(path.exists() for path in pid_paths), "Docker and plugin must both have started")
                deadline = time.monotonic() + 2
                while any(live_pid(path) for path in pid_paths) and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertEqual([live_pid(path) for path in pid_paths], [None, None])
                self.assertEqual((directory / "workspace-progress.jsonl").read_bytes(),
                                 (private / "expected.jsonl").read_bytes())
                self.assertFalse((directory / "workspace-history.json").exists())
                self.assertFalse((directory / "result.json").exists())
                self.assertNotIn("CODEWIRE_WORKSPACE_CACHE_REPORT=", completed.stdout + completed.stderr)
                with self.assertRaises(OSError):
                    self.finish(directory)
                self.assertFalse((directory / "result.json").exists())
            finally:
                for path in pid_paths:
                    pid = live_pid(path)
                    if pid is not None:
                        try:
                            os.kill(pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                # The intentional timeout can orphan the plugin after its
                # parent is killed. This fixture owns that adopted child;
                # snapshot death alone does not prove complete family cleanup.
                deadline = time.monotonic() + 3
                while True:
                    try:
                        reaped, _ = os.waitpid(-1, os.WNOHANG | custody.WALL)
                    except ChildProcessError:
                        break
                    if time.monotonic() >= deadline:
                        self.fail("owned history timeout fixture did not reach __WALL ECHILD")
                    if not reaped:
                        time.sleep(0.01)

    def test_floating_cache_hit_and_sccache_errors_fail(self):
        directory = self.fixture("warm-1", "5")
        path = directory / "workspace-build.log"
        original = path.read_text()
        for text in (original.replace("#1 DONE 1.0s", "#1 CACHED"), original.replace("Cache write errors 0", "Cache write errors 1")):
            path.write_text(text)
            with self.assertRaises(ValueError):
                self.finish(directory)

    def test_original_credential_and_post_build_modes_must_be_closed(self):
        directory = self.fixture("warm-1", "5")
        credential = self.root / "codewire-sccache-r2.aws"
        credential.write_text("synthetic")
        with self.assertRaises(ValueError):
            self.finish(directory)
        credential.unlink()
        os.environ["CODEWIRE_SCCACHE_MODE"] = "disabled"
        with self.assertRaises(ValueError):
            report.finalize(directory, directory / "receipt.json")

    def test_crashed_sampler_cannot_pass_with_initial_and_final_samples(self):
        directory = self.fixture("warm-1", "5")
        (directory / "sampler-complete.json").unlink()
        with self.assertRaises(OSError):
            self.finish(directory)
        self.assertFalse((directory / "result.json").exists())

    def test_wrong_seed_source_or_worker_reuse_fails(self):
        with self.assertRaises(ValueError):
            report.seed_report(json.dumps(self.seed), "6" * 40, TREE)
        directory = self.fixture("warm-1", "3")
        with self.assertRaises(ValueError):
            self.finish(directory)

    def test_compiler_only_requires_positive_hits(self):
        directory = self.fixture("compiler", "5")
        path = directory / "workspace-build.log"
        original = path.read_text()
        for hit_lines in ("Cache hits 0", "Cache hits 4", "Cache hits 4\n#3 1.0 Cache hits (Rust) 0"):
            path.write_text(original.replace("Cache hits 4\n#3 1.0 Cache hits (Rust) 4", hit_lines))
            with self.assertRaises(ValueError):
                self.finish(directory)

    def test_late_output_failure_removes_success_file_and_marker(self):
        os.environ["GITHUB_OUTPUT"] = str(self.root / "missing" / "output")
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(OSError):
            report.finalize(self.seed_directory, self.seed_directory / "receipt.json")
        self.assertFalse((self.seed_directory / "result.json").exists())
        self.assertEqual(output.getvalue(), "")

    def test_seed_report_rejects_malformed_values(self):
        for value in (None, [], False, dict(self.seed, seed_cache_id=False)):
            with self.assertRaises(ValueError):
                report.seed_report(json.dumps(value), SOURCE, TREE)

    def test_actual_workflow_seed_binding_rejects_failed_or_wrong_producers(self):
        body = workflow_job("workspace-cache-measurement")
        block = body.split("      - name: Bind successful exact-source producer\n", 1)[1].split("\n      - name:", 1)[0]
        script = "\n".join(line[10:] for line in block.split("        run: |\n", 1)[1].splitlines())
        output_path = self.root / "bound-env"
        env = {"PATH": "/usr/bin:/bin", "GITHUB_ENV": str(output_path), "GITHUB_RUN_ID": "2047",
               "CODEWIRE_EXPECTED_SOURCE_SHA": SOURCE, "CODEWIRE_EXPECTED_SOURCE_TREE": TREE,
               "KIND_SELECTED": "true", "KIND_RESULT": "success", "WORKSPACE_RESULT": "skipped",
               "KIND_SEED": json.dumps(self.seed), "WORKSPACE_SEED": ""}
        for kind in ("true", "false"):
            good = dict(env, KIND_SELECTED=kind)
            if kind == "false":
                good.update(KIND_RESULT="skipped", WORKSPACE_RESULT="success", KIND_SEED="", WORKSPACE_SEED=json.dumps(self.seed))
            for change, accepted in (({}, True), ({"GITHUB_RUN_ID": "2048"}, False),
                                     ({"CODEWIRE_EXPECTED_SOURCE_TREE": "6" * 40}, False),
                                     ({"KIND_RESULT": "failure", "WORKSPACE_RESULT": "failure"}, False),
                                     ({"KIND_SEED": json.dumps(self.seed), "WORKSPACE_SEED": json.dumps(self.seed)}, False)):
                with self.subTest(kind=kind, change=change):
                    output_path.unlink(missing_ok=True)
                    completed = subprocess.run(["bash", "-eu", "-c", script], cwd=ROOT,
                                               env=dict(good, **change), text=True, capture_output=True, timeout=5)
                    self.assertEqual(completed.returncode == 0, accepted, completed.stderr)
                    self.assertEqual(output_path.exists(), accepted)


class ProducerReportTests(unittest.TestCase):
    """Actual held/source/ELF admission of synthetic bytes and solve events.

    No compiler, Docker, cache server or incoming executable runs. The shared
    producer fixture creates isolated synthetic Git objects, not a delivery
    checkout mutation. Only history transport is mocked in capture tests.
    """

    def setUp(self):
        self.consumer = report.consumer_library()
        self.components = module("workspace_cache_source_fixture", "scripts/ci/tests/test-cw-runtime-source.py")
        self.source_fixture = self.components.Source()
        self.source_fixture.setUp()
        self.addCleanup(self.source_fixture.doCleanups)
        self.addCleanup(self.source_fixture.tearDown)
        self.repo = self.source_fixture.repo
        self.components.write(self.repo / "Cargo.toml",
            ('[workspace]\nmembers = ["crates/demo"]\n[workspace.package]\nversion = "'
             + self.components.fixture.VERSION + '"\n').encode())
        self.source_fixture.git("add", "Cargo.toml")
        self.source_fixture.git("-c", "user.name=Synthetic", "-c", "user.email=synthetic@example.invalid",
                                "commit", "-q", "-m", "workspace version fixture")
        self.source_fixture.revision = self.revision = self.source_fixture.git("rev-parse", "HEAD").strip().decode()
        self.tree = self.source_fixture.git("rev-parse", "HEAD^{tree}").strip().decode()
        self.root = self.source_fixture.base / "reports"
        self.root.mkdir(mode=0o700)
        environment = {"RUNNER_TEMP": str(self.root), "GITHUB_OUTPUT": str(self.root / "output"),
                       "CODEWIRE_EXPECTED_SOURCE_SHA": self.revision, "CODEWIRE_EXPECTED_SOURCE_TREE": self.tree,
                       "CODEWIRE_SCCACHE_MODE": "r2", "CODEWIRE_BUILDKIT_CACHE_MODE": "r2"}
        patch = mock.patch.dict(os.environ, environment)
        patch.start()
        self.addCleanup(patch.stop)
        patch = mock.patch.object(report, "ROOT", self.repo)
        patch.start()
        self.addCleanup(patch.stop)
        self.seed_directory = self.fixture("seed", "3")
        self.seed = self.finish(self.seed_directory)
        os.environ["CODEWIRE_WORKSPACE_CACHE_SEED_REPORT"] = json.dumps(self.seed)

    def fixture(self, case, identity, name=None, build_text=None, plain_done=False):
        directory = ReportTests.fixture(self, case, identity)
        if name is not None:
            renamed = self.root / name
            directory.rename(renamed)
            directory = renamed
        header = json.loads((directory / "identity.json").read_text())
        header.update(source_sha=self.revision, source_tree=self.tree, architecture="amd64",
                      seed_cache_id="run-2047/tree-" + self.tree + "/seed-" + "3" * 64)
        (directory / "identity.json").write_text(json.dumps(header))
        receipt = json.loads((directory / "receipt.json").read_text())
        receipt.update(source_sha=self.revision, source_tree=self.tree, architecture="amd64")
        (directory / "receipt.json").write_text(json.dumps(receipt))
        mode, layers = report.MODES[case]
        export = "#9 exporting cache to Amazon S3\n#9 DONE 1.0s\n" if layers == "r2" else ""
        (directory / "workspace-build.log").write_text(
            "#1 [workspace-floating-tools 1/2] RUN npm install\n#1 DONE 1.0s\n"
            "#2 [workspace-floating-tools 2/2] RUN go install\n#2 DONE 2.0s\n"
            "#3 [cw-builder 1/1] COPY --from=codewire-verified-cw /cw /cw\n#3 DONE 0.1s\n" + export)
        ReportTests.history(self, directory, [{"digest": "sha256:" + "8" * 64,
            "name": "[cw-builder 1/1] COPY --from=codewire-verified-cw /cw /cw",
            "inputs": ["sha256:" + "9" * 64], "cached": False,
            "started": "2026-09-10T10:00:04Z", "completed": "2026-09-10T10:00:05Z"}])
        work = directory / "cw-image-work"
        work.mkdir(mode=0o700)
        (work / "cw-producer-owned").mkdir(mode=0o700)
        producer = self.consumer.producer
        with producer.prepare_plan(self.repo, self.revision, "release", self.components.fixture.VERSION,
                                   work / "cw-producer-owned" / "build") as prepared:
            capsule = prepared.capsule
            binary, depinfo, target, cargo, result = self.source_fixture.build_bytes(capsule)
            with producer.source.admit(capsule.path / "source", capsule.path / "git", capsule.path / "request.json",
                                       capsule.outputs["request.json"].sha256) as admitted:
                producer.finalizer.finalize(admitted, binary, depinfo, self.components.fixture.RUSTC, result,
                                            prepared.path / "assets", target, cargo)
            cached = case.startswith("warm-")
            done = "CACHED" if cached and not plain_done else "DONE 3.0s"
            text = build_text if build_text is not None else (
                "#4 [cw-builder 1/1] RUN codewire-rust-build cargo build --release\n#4 " + done + "\n"
                "#4 1.0 Cache hits 4\n#4 1.0 Cache hits (Rust) 4\n#4 1.0 Cache misses 2\n"
                "#4 1.0 Cache write errors 0\n" + export)
            log = prepared.path / "build.log"
            self.components.write(log, text.encode(), 0o400)
            arguments = producer.producer_arguments(capsule, prepared.path, mode)
            command = ["/usr/bin/docker", "buildx", "build", "--builder", header["builder_name"], *arguments]
            self.components.write(prepared.path / "metadata.json", producer.release.canonical({
                "buildx.build.ref": f'{header["builder_name"]}/{header["builder_name"]}-node/' + "b" * 25}), 0o400)
            completed = producer.finish(prepared, result | {"command": command, "log": str(log),
                                        "log_sha256": hashlib.sha256(log.read_bytes()).hexdigest()}, header["builder_name"])
        self.components.write(work / "cw-producer-result.json", producer.release.canonical(completed), 0o400)
        self.producer_events(directory, [{"digest": "sha256:" + "6" * 64, "inputs": ["sha256:" + "7" * 64],
            "name": "[cw-builder 1/1] RUN codewire-rust-build cargo build --release", "cached": cached,
            "started": "2026-09-10T10:00:00Z", "completed": "2026-09-10T10:00:03Z"}])
        return directory

    def history(self, directory, events):
        ReportTests.history(self, directory, events)

    def evidence(self, directory):
        return report.ProducerEvidence(directory, json.loads((directory / "identity.json").read_text()))

    def producer_events(self, directory, events):
        raw = b"".join((json.dumps({"vertexes": [event]}) + "\n").encode() for event in events)
        (directory / "cw-producer-progress.jsonl").write_bytes(raw)
        with self.evidence(directory) as evidence:
            (directory / "cw-producer-history.json").write_text(json.dumps(
                dict(evidence.identity, sha256=hashlib.sha256(raw).hexdigest())))

    def finish(self, directory, finalizer=None):
        case = json.loads((directory / "identity.json").read_text())["case"]
        os.environ["CODEWIRE_SCCACHE_MODE"], os.environ["CODEWIRE_BUILDKIT_CACHE_MODE"] = report.MODES[case]
        with contextlib.redirect_stdout(io.StringIO()):
            (finalizer or report.finalize)(directory, directory / "receipt.json")
        return json.loads((directory / "result.json").read_text())

    def refused(self, directory):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(
                (ValueError, OSError, KeyError, TypeError, self.consumer.release.ReleaseError)):
            self.finish(directory)
        self.assertFalse((directory / "result.json").exists())
        self.assertEqual(output.getvalue(), "")

    def test_workspace_copy_joins_actual_admission_and_separate_solve(self):
        directory = self.fixture("warm-1", "5")
        result = self.finish(directory, LEGACY_REPORT_FINALIZER)
        workspace, compiled = result["phases"]["workspace"], result["phases"]["cw_producer"]
        self.assertEqual(workspace["floating_runs_executed"], 2)
        self.assertNotEqual(workspace["build_ref"], compiled["build_ref"])
        self.assertTrue(compiled["compiler_layer_cached"])
        self.assertFalse(compiled["compiler_executed"])
        self.assertEqual(compiled["profile"], "release")
        self.assertEqual(compiled["source"]["revision"], self.revision)
        self.assertEqual(compiled["payload"]["source_revision"], self.revision)
        self.assertEqual(compiled["current_source"]["git_tree"], self.tree)
        self.assertEqual(compiled["compiler_cache_statistics"]["Cache hits (Rust)"], 4)

    def test_all_cases_separate_compiler_and_workspace_metrics(self):
        for index, case in enumerate(("cold", "compiler", "warm-1", "warm-2"), 5):
            result = self.finish(self.fixture(case, str(index)))
            compiled = result["phases"]["cw_producer"]
            self.assertEqual(compiled["compiler_executed"], not case.startswith("warm-"))
            self.assertEqual(compiled["compiler_layer_cached"], case.startswith("warm-"))
            self.assertEqual(result["workspace_image_id"], "sha256:" + "4" * 64)
            self.assertNotIn("compiler_executed", result["phases"]["workspace"])

    def test_capture_queries_two_exact_refs_and_never_latest(self):
        directory = self.fixture("warm-1", "5")
        builder = json.loads((directory / "identity.json").read_text())["builder_name"]
        raw = {"a" * 25: (directory / "workspace-progress.jsonl").read_bytes(),
               "b" * 25: (directory / "cw-producer-progress.jsonl").read_bytes()}
        calls, run = [], subprocess.run
        def capture(command, **kwargs):
            if command[0] != "fixture-docker":
                if command[0] != "git":
                    self.assertEqual(command[:4], [sys.executable, "-B", str(ROOT / "scripts/dev/cw-runtime-image.py"), "unpack"])
                return run(command, **kwargs)
            self.assertEqual(command[:-1], ["fixture-docker", "buildx", "history", "logs", "--builder", builder,
                                          "--progress", "rawjson"])
            self.assertIn(command[-1], raw)
            self.assertNotIn("timeout", kwargs)
            calls.append(command[-1])
            kwargs["stderr"].write(raw[command[-1]])
        with mock.patch.object(report.subprocess, "run", side_effect=capture):
            report.capture_history("fixture-docker", builder, directory)
        self.assertEqual(calls, ["a" * 25, "b" * 25])
        self.finish(directory)
        calls.clear()
        def fail_second(command, **kwargs):
            if command[0] == "fixture-docker" and command[-1] == "b" * 25:
                raise subprocess.CalledProcessError(23, command)
            return capture(command, **kwargs)
        with mock.patch.object(report.subprocess, "run", side_effect=fail_second), self.assertRaises(subprocess.CalledProcessError):
            report.capture_history("fixture-docker", builder, directory)
        self.assertFalse((directory / "workspace-history.json").exists())
        self.assertFalse((directory / "cw-producer-history.json").exists())
        self.refused(directory)

    def test_pointer_is_closed_canonical_and_exactly_matches_original(self):
        directory = self.fixture("warm-1", "5")
        path = directory / "cw-image-work/cw-producer-result.json"
        original = path.read_bytes()
        pointer = json.loads(original)
        invalid = [b"", b" " + original, b"[]\n", original[:-1],
                   original.replace(b'"status":', b'"status":"x","status":', 1)]
        for changes in ({"extra": True}, {"reused": True}, {"cache_qualified": 0},
                        {"image_qualified": True}, {"profile": "ci"}, {"version": "v9.9.9"},
                        {"receipt": pointer["receipt"] | {"sha256": "0" * 64}},
                        {"payload": pointer["payload"] | {"sha256": "0" * 64}},
                        {"source": pointer["source"] | {"revision": "0" * 40}}):
            invalid.append(self.consumer.release.canonical(pointer | changes))
        for raw in invalid:
            with self.subTest(raw=raw[:40]):
                self.components.write(path, raw, 0o400)
                self.refused(directory)
        self.components.write(path, original, 0o400)
        self.finish(directory)

    def test_pointer_modes_links_and_foreign_builders_refuse(self):
        directory = self.fixture("warm-1", "5")
        path = directory / "cw-image-work/cw-producer-result.json"
        raw = path.read_bytes()
        path.chmod(0o600)
        self.refused(directory)
        path.chmod(0o400)
        external = self.root / "pointer-copy"
        self.components.write(external, raw, 0o400)
        path.unlink()
        path.symlink_to(external)
        self.refused(directory)
        path.unlink()
        os.link(external, path)
        self.refused(directory)
        path.unlink()
        self.components.write(path, raw, 0o400)
        header_path = directory / "identity.json"
        header = json.loads(header_path.read_text())
        header_path.write_text(json.dumps(header | {"builder_name": "codewire-workspace-another"}))
        self.refused(directory)
        header_path.write_text(json.dumps(header | {"source_tree": "0" * 40}))
        self.refused(directory)

    def test_retained_asset_log_metadata_and_depinfo_replacement_refuse(self):
        for index, name in enumerate(("assets/cw", "assets/cw.d", "assets/cw.oci.tar", "assets/producer.json",
                                      "metadata.json", "build.log")):
            directory = self.fixture("warm-1", "5", name="replacement-" + str(index))
            path = directory / "cw-image-work/cw-producer-owned/build" / name
            mode = stat.S_IMODE(path.stat().st_mode)
            self.components.write(path, path.read_bytes() + b"changed", mode)
            self.refused(directory)

    def test_current_source_and_cache_mode_must_match_but_docs_keep_original(self):
        directory = self.fixture("warm-1", "5")
        header = json.loads((directory / "identity.json").read_text())
        with self.assertRaises(ValueError):
            report.ProducerEvidence(directory, header, compiler_mode="disabled")
        path = self.repo / "crates/demo/src/lib.rs"
        original = path.read_bytes()
        self.components.write(path, original + b"pub fn edited() {}\n")
        self.refused(directory)
        self.components.write(path, original)
        self.components.write(self.repo / "README.md", b"docs-only consumer commit\n")
        self.source_fixture.git("add", "README.md")
        self.source_fixture.git("-c", "user.name=Synthetic", "-c", "user.email=synthetic@example.invalid",
                                "commit", "-q", "-m", "docs only")
        current = self.source_fixture.git("rev-parse", "HEAD").strip().decode()
        tree = self.source_fixture.git("rev-parse", "HEAD^{tree}").strip().decode()
        with report.ProducerEvidence(directory, header | {"source_sha": current, "source_tree": tree}) as evidence:
            summary = evidence.retained.summary
            self.assertEqual(summary["source"]["revision"], self.revision)
            self.assertEqual(summary["current_source"]["revision"], current)
            self.assertNotEqual(summary["source"]["git_tree"], summary["current_source"]["git_tree"])
            self.assertEqual(summary["build_ref"], evidence.identity["build_ref"])
            # Observation through reopen never claims that another solve ran.
            self.assertIs(summary["reused"], True)

    def test_cached_history_retains_lazy_extraction_and_completed_dwell(self):
        directory = self.fixture("warm-1", "5", plain_done=True)
        cached = json.loads((directory / "cw-producer-progress.jsonl").read_text())["vertexes"][0]
        extraction = {key: value for key, value in cached.items() if key not in ("cached", "inputs")}
        initial = {key: value for key, value in cached.items() if key not in ("cached", "started", "completed")}
        self.producer_events(directory, [initial, cached, extraction, initial])
        result = self.finish(directory)["phases"]["cw_producer"]
        self.assertTrue(result["compiler_layer_cached"])
        self.assertFalse(result["compiler_executed"])

    def test_wrong_producer_history_identity_hash_and_incomplete_vertices_refuse(self):
        directory = self.fixture("warm-1", "5")
        marker = directory / "cw-producer-history.json"
        original = json.loads(marker.read_text())
        for key in ("build_ref", "pointer_sha256", "build_receipt_sha256", "build_log_sha256", "sha256"):
            marker.write_text(json.dumps(original | {key: "0" * 64}))
            self.refused(directory)
        event = json.loads((directory / "cw-producer-progress.jsonl").read_text())["vertexes"][0]
        for events in ([], [dict(event, cached=False)], [dict(event, cached=1)], [dict(event, completed=None)],
                       [dict(event, inputs="invalid")], [dict(event, error="failed")],
                       [event, dict(event, digest="sha256:" + "8" * 64)],
                       [dict(event, name="[cw-builder 1/1] COPY /cw /cw")]):
            self.producer_events(directory, events)
            self.refused(directory)

    def test_cold_and_compiler_require_executed_producer_and_rust_hits(self):
        for case in ("cold", "compiler"):
            directory = self.fixture(case, "5", name="cached-" + case)
            event = json.loads((directory / "cw-producer-progress.jsonl").read_text())["vertexes"][0]
            for changed in (dict(event, cached=True), {key: value for key, value in event.items() if key != "inputs"}):
                self.producer_events(directory, [changed])
                self.refused(directory)
        text = "#4 [cw-builder 1/1] RUN codewire-rust-build cargo build --release\n#4 DONE 1.0s\n#4 1.0 Cache hits 100\n"
        for index, suffix in enumerate(("", "#4 1.0 Cache hits (Rust) 0\n")):
            directory = self.fixture("compiler", "5", name="generic-hits-" + str(index), build_text=text + suffix)
            self.refused(directory)

    def test_copy_or_old_workspace_compile_cannot_supply_producer_evidence(self):
        directory = self.fixture("warm-1", "5")
        (directory / "cw-image-work/cw-producer-result.json").unlink()
        self.refused(directory)
        # A valid old compiler observation cannot replace a missing producer.
        log = directory / "workspace-build.log"
        log.write_text(log.read_text() + "#10 [cw-builder 1/1] RUN cargo build\n#10 CACHED\n")
        self.refused(directory)

    def test_late_retained_pointer_mutation_removes_success_and_output(self):
        directory = self.fixture("warm-1", "5")
        pointer = directory / "cw-image-work/cw-producer-result.json"
        raw, original = pointer.read_bytes(), Path.write_text
        def replace_after_emit(path, data, *args, **kwargs):
            result = original(path, data, *args, **kwargs)
            if path == directory / "result.json":
                self.components.write(pointer, raw, 0o400)
            return result
        with mock.patch.object(Path, "write_text", replace_after_emit):
            self.refused(directory)


def workflow_job(name):
    workflow = (ROOT / ".gitea/workflows/ci.yaml").read_text()
    match = re.search(r"^  " + re.escape(name) + r":\n(.*?)(?=^  [a-z0-9-]+:|\Z)", workflow, re.M | re.S)
    if not match:
        raise ValueError("missing workflow job " + name)
    return match[1]


class WorkflowTests(unittest.TestCase):
    def test_sampler_uses_constant_time_backing_filesystem_counters(self):
        self.assertIn("df -Pk /var/lib/buildkit", report.SAMPLE_COMMAND)
        self.assertNotIn("du ", report.SAMPLE_COMMAND)
        self.assertNotIn("aws-credentials", report.SAMPLE_COMMAND)

    def test_measurement_allocation_and_failures_keep_ordinary_gates(self):
        body = workflow_job("workspace-cache-measurement")
        self.assertIn("    name: Workspace cache experiment (${{ matrix.case }})\n", body)
        self.assertIn("    runs-on: " + chr(36) + "{{ github.event_name == 'push' && github.ref == "
                      "'refs/heads/main' && 'ci-heavy-main' || 'ci-heavy' }}\n", body)
        self.assertIn("    enable-openid-connect: true\n", body)
        self.assertNotIn("continue-on-error", body)
        self.assertIn("workspace_cache_experiment == 'true'", body)
        for owner in ("kind-workspace", "workspace-image"):
            self.assertIn(f"needs.{owner}.result == 'success' && needs.{owner}.outputs.workspace_cache_seed != ''", body)
        self.assertLess(body.index("Bind successful exact-source producer"), body.index("Select independent measurement caches"))
        self.assertLess(body.index("Clean measurement cache credential"), body.index("Finalize workspace measurement"))
        self.assertIn("ref: ${{ needs.verification-selection.outputs.ci_head_commit }}", body)
        ordinary = workflow_job("required-verification")
        needs = ordinary.split("    needs:\n", 1)[1].split("    steps:\n", 1)[0]
        self.assertEqual(re.findall(r"^      - (.*)$", needs, re.M), [
            "verification-selection", "cw-release-assets", "workspace-image", "policy", "standard", "tooling",
            "rust-compile", "rust-packages", "rust-features", "rust-transport", "database", "services-control", "services-runtime", "edge-kind"])
        for owner in ("workspace-image", "kind-workspace"):
            self.assertIn("prepare-workspace-cache-measurement.sh seed", workflow_job(owner))
            self.assertIn("success() &&", workflow_job(owner))
            self.assertIn("needs.verification-selection.outputs.workspace_cache_experiment == 'true'", workflow_job(owner))
            self.assertIn("$GITHUB_WORKSPACE/.tmp/codewire-workspace-image-verification.json", workflow_job(owner))
        self.assertNotIn("prepare-workspace-cache-measurement.sh seed", workflow_job("edge-kind"))

    def test_unselected_sentinel_cannot_allocate_a_measurement_task(self):
        body = workflow_job("workspace-cache-measurement")
        self.assertEqual(selector.UNSELECTED,
                         {"case": "not-selected", "compiler": "disabled", "layers": "disabled"})
        self.assertIn("needs.verification-selection.outputs.workspace_cache_experiment == 'true'", body)
        self.assertIn("matrix: ${{ fromJSON(needs.verification-selection.outputs.workspace_cache_measurement_matrix) }}", body)


if __name__ == "__main__":
    unittest.main()
