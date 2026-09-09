#!/usr/bin/env python3
"""Synthetic source/event/report contracts. No host Docker, provider, or build."""
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
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

    def test_ordinary_events_create_zero_tasks(self):
        for event in ("push", "workflow_dispatch", "pull_request_target"):
            with self.subTest(event=event):
                self.env["GITHUB_EVENT_NAME"] = event
                self.assertEqual(self.select(), {"selected": False, "matrix": {"include": []}})
        self.env["GITHUB_EVENT_NAME"] = "pull_request"
        self.event["pull_request"]["head"]["ref"] = "ordinary"
        self.assertFalse(self.select()["selected"])

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
        header = {"case": case, "source_sha": SOURCE, "source_tree": TREE, "architecture": "amd64",
                  "docker_daemon_id": "daemon-" + identity, "builder_container_id": identity * 64,
                  "pins": {"buildkit_image": "pinned", "job_image_id": "pinned"}, "seed_cache_id": SEED}
        (directory / "identity.json").write_text(json.dumps(header))
        receipt = {"source_sha": SOURCE, "source_tree": TREE, "architecture": "amd64",
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
            "#3 1.0 Cache hits 4\n#3 1.0 Cache misses 2\n#3 1.0 Cache write errors 0\n" + export)
        return directory

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
        files = ("metrics-error", "resources.jsonl", "versions.json", "workspace-build.log", "base-build.log", "receipt.json")
        baseline = {name: (directory / name).read_text() for name in files if (directory / name).exists()}
        mutations = {
            "metrics-error": "sampling failed",
            "resources.jsonl": "",
            "versions.json": json.dumps({key: "drift" for key in report.VERSION_COMMANDS}),
            "base-build.log": "#9 exporting cache to Amazon S3\n#9 ERROR: upload failed\n",
            "workspace-build.log": baseline["workspace-build.log"].replace("#3 CACHED", "#3 DONE 3.0s"),
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
        for hit_lines in ("Cache hits 0", "Cache hits 4\n#3 1.0 Cache hits (Rust) 0"):
            path.write_text(original.replace("Cache hits 4", hit_lines))
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
        self.assertIn("    runs-on: ci-heavy\n", body)
        self.assertIn("    enable-openid-connect: true\n", body)
        self.assertNotIn("continue-on-error", body)
        self.assertIn("workspace_cache_experiment == 'true'", body)
        for owner in ("edge-kind", "workspace-image"):
            self.assertIn(f"needs.{owner}.result == 'success' && needs.{owner}.outputs.workspace_cache_seed != ''", body)
        self.assertLess(body.index("Bind successful exact-source producer"), body.index("Select independent measurement caches"))
        self.assertLess(body.index("Clean measurement cache credential"), body.index("Finalize workspace measurement"))
        self.assertIn("ref: ${{ needs.verification-selection.outputs.ci_head_commit }}", body)
        ordinary = workflow_job("required-verification")
        needs = ordinary.split("    needs:\n", 1)[1].split("    steps:\n", 1)[0]
        self.assertEqual(re.findall(r"^      - (.*)$", needs, re.M), [
            "verification-selection", "cw-release-assets", "workspace-image", "policy", "standard", "tooling",
            "rust-transport", "database", "services-control", "services-runtime", "edge-kind"])
        for owner in ("workspace-image", "edge-kind"):
            self.assertIn("prepare-workspace-cache-measurement.sh seed", workflow_job(owner))
            self.assertIn("success() && needs.verification-selection.outputs.tested_tree_receipt != 'accepted' && needs.verification-selection.outputs.workspace_cache_experiment", workflow_job(owner))


if __name__ == "__main__":
    unittest.main()
