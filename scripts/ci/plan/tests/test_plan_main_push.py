"""CI's artifact facts for a push to main (plan-main-push.py, #2897).

Before #2897 every main push ran apply-verification-plan.py --unclassified, so
the CW release assets, Container contract, Compile every Rust target and Rust /
transport jobs ran on every push. A main push now plans the facts with the
previous main's policy, against that commit when its own run verified it, and
keeps every artifact selected otherwise.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent))
import test_planner as fixtures  # noqa: E402

PLAN_ROOT = Path(__file__).parents[1]
REPOSITORY_ROOT = PLAN_ROOT.parents[2]
SPEC = importlib.util.spec_from_file_location(
    "codewire_ci_plan_main_push", PLAN_ROOT / "plan-main-push.py"
)
assert SPEC and SPEC.loader
main_push = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = main_push
SPEC.loader.exec_module(main_push)

MAIN_PUSH = {"GITHUB_EVENT_NAME": "push", "GITHUB_REF": "refs/heads/main"}
EVERYTHING = ("true", "true", "true")
NOTHING = ("false", "false", "false")
HEAVY_ARTIFACT_GROUPS = ("cw_release_assets", "rust_compile", "rust_transport")


def run_record(sha: str, *, run_id: int = 41, status: str = "success", **fields: Any) -> dict:
    record = {
        "id": run_id,
        "head_sha": sha,
        "event": "push",
        "workflow_id": "ci.yaml",
        "prettyref": "main",
        "status": status,
    }
    record.update(fields)
    return record


def job_records(run_id: int, *, policy: str = "success", required: str = "success") -> list[dict]:
    return [
        {"id": 1, "run_id": run_id, "name": "Verification selection", "status": "success"},
        {"id": 2, "run_id": run_id, "name": "Policy verification", "status": policy},
        {"id": 3, "run_id": run_id, "name": "Required verification", "status": required},
    ]


class FakeForgejo:
    """The two repository API reads, answered from fixed records."""

    def __init__(self, runs: list[dict] | Exception, jobs: dict[int, Any] | None = None):
        self.runs = runs
        self.jobs = jobs or {}
        self.paths: list[str] = []

    def factory(self, environ: dict[str, str]):
        return self.fetch

    def fetch(self, path: str) -> Any:
        self.paths.append(path)
        if path.startswith("/actions/runs?"):
            if isinstance(self.runs, Exception):
                raise self.runs
            return {"total_count": len(self.runs), "workflow_runs": self.runs}
        match = re.fullmatch(r"/actions/runs/(\d+)/jobs\?page=1&limit=100", path)
        assert match, path
        jobs = self.jobs[int(match.group(1))]
        if isinstance(jobs, Exception):
            raise jobs
        return jobs if isinstance(jobs, list) else {"total_count": len(jobs["jobs"]), **jobs}


def verified(sha: str) -> FakeForgejo:
    return FakeForgejo([run_record(sha)], {41: job_records(41)})


def capability_selection(paths: list[str]) -> str:
    """The real selector's choice for these paths on a push to main."""
    with tempfile.TemporaryDirectory(prefix="codewire-main-push-paths-") as temporary:
        path_file = Path(temporary) / "paths"
        path_file.write_text("\n".join(paths) + "\n")
        env = {key: value for key, value in os.environ.items()
               if key not in {"GITHUB_OUTPUT", "GITHUB_EVENT_PATH"}}
        env.update(MAIN_PUSH)
        completed = subprocess.run(
            [str(REPOSITORY_ROOT / "scripts/ci/select/select-verification.sh"), str(path_file)],
            cwd=REPOSITORY_ROOT, env=env, text=True, capture_output=True, check=True,
        )
    outputs = dict(line.split("=", 1) for line in completed.stdout.splitlines() if "=" in line)
    return outputs["selection"]


def dispatched(selection: str, outputs: dict[str, str]) -> dict[str, bool]:
    """Which capability groups the real dispatch emitter starts for these facts on a
    push to main, which leaves the workspace image to support-images (#2892)."""
    env = {key: value for key, value in os.environ.items() if key != "GITHUB_OUTPUT"}
    env.update({
        "VERIFICATION_SELECTION": selection,
        "VERIFICATION_TESTED_TREE_RECEIPT": "fallback",
        "VERIFICATION_SUPERSEDED": "false",
        "CW_PACKAGE_SELECTED": outputs["cw_package_selected"],
        "DESKTOP_PACKAGE_SELECTED": outputs["desktop_package_selected"],
        "WORKSPACE_IMAGE_SELECTED": outputs["workspace_image_selected"],
        "KIND_WORKSPACE_SOURCE": "pinned",
        "WORKSPACE_IMAGE_OWNER": "support-images",
    })
    completed = subprocess.run(
        [str(REPOSITORY_ROOT / "scripts/ci/select/emit-verification-matrices.sh")],
        cwd=REPOSITORY_ROOT, env=env, text=True, capture_output=True, check=True,
    )
    return {
        key.removesuffix("_expected"): value == "true"
        for key, value in (line.split("=", 1) for line in completed.stdout.splitlines())
    }


class MainPushPlanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="codewire-main-push-test-")
        self.repo = fixtures.FixtureRepository(Path(self.temporary.name))
        metadata = mock.patch.object(
            main_push.planner, "cargo_metadata", side_effect=fixtures.fixture_cargo_metadata
        )
        metadata.start()
        self.addCleanup(metadata.stop)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def choose(
        self, head: str, before: str, forgejo: FakeForgejo, environ: dict[str, str] | None = None
    ) -> tuple[dict[str, str], str]:
        log = io.StringIO()
        with contextlib.redirect_stdout(log):
            outputs = main_push.choose_outputs(
                self.repo.root, head, before, environ or dict(MAIN_PUSH), forgejo.factory
            )
        return outputs, log.getvalue()

    def selected(self, outputs: dict[str, str]) -> tuple[str, str, str]:
        return (
            outputs["cw_package_selected"],
            outputs["desktop_package_selected"],
            outputs["workspace_image_selected"],
        )

    def previous_outputs(self, head: str) -> dict[str, str]:
        """What CI computed for every main push before #2897."""
        tree = fixtures.run(["git", "rev-parse", f"{head}^{{tree}}"], self.repo.root)
        completed = subprocess.run(
            [sys.executable, str(PLAN_ROOT / "apply-verification-plan.py"),
             "--unclassified", "--head", head, "--head-tree", tree],
            env={key: value for key, value in os.environ.items() if key != "GITHUB_OUTPUT"},
            text=True, capture_output=True, check=True,
        )
        return dict(line.split("=", 1) for line in completed.stdout.splitlines())

    def test_hook_only_push_after_a_verified_main_starts_no_artifact_job(self) -> None:
        before = self.repo.base
        head = self.repo.change(".githooks/pre-push", "#!/bin/sh\necho changed\n")
        selection = capability_selection([".githooks/pre-push"])

        previous = dispatched(selection, self.previous_outputs(head))
        self.assertTrue(all(previous[group] for group in HEAVY_ARTIFACT_GROUPS), previous)
        # Even every artifact selected starts no Container contract job on main.
        self.assertFalse(previous["workspace_image"], previous)

        outputs, log = self.choose(head, before, verified(before))
        self.assertEqual(self.selected(outputs), NOTHING)
        self.assertEqual(outputs["cw_package_state"], "unaffected")
        self.assertEqual(outputs["ci_head_commit"], head)
        self.assertIn(f"{before} was verified by CI run 41", log)
        self.assertIn("cw_cli_release_assets=unaffected", log)
        groups = dispatched(selection, outputs)
        self.assertFalse(any(groups[group] for group in HEAVY_ARTIFACT_GROUPS), groups)
        self.assertTrue(groups["policy"])

    def test_cw_change_after_a_verified_main_still_starts_the_cw_jobs(self) -> None:
        before = self.repo.base
        head = self.repo.change("cli/src/main.rs", "fn main() { /* changed */ }\n")
        outputs, _ = self.choose(head, before, verified(before))
        self.assertEqual(self.selected(outputs), ("true", "false", "true"))
        self.assertEqual(outputs["cw_package_state"], "affected")
        groups = dispatched(capability_selection(["crates/codewire-cli/src/main.rs"]), outputs)
        self.assertTrue(all(groups[group] for group in HEAVY_ARTIFACT_GROUPS), groups)
        # The selected workspace image is support-images' to build and verify.
        self.assertFalse(groups["workspace_image"], groups)

    def test_pin_only_push_selects_what_compiles_the_pin(self) -> None:
        before = self.repo.add_workspace_pin_crate()
        head = self.repo.change(
            fixtures.WORKSPACE_PIN, 'pub const WORKSPACE_IMAGE: &str = "workspace@sha256:two";\n'
        )
        outputs, _ = self.choose(head, before, verified(before))
        # cw compiles the pin; the desktop does not.
        self.assertEqual(self.selected(outputs), ("true", "false", "true"))
        self.assertEqual(outputs["cw_package_state"], "affected")
        self.assertEqual(outputs["desktop_package_state"], "unaffected")
        self.assertEqual(outputs["workspace_image_state"], "affected")
        self.assertEqual(self.selected(self.previous_outputs(head)), EVERYTHING)

    def test_superseded_or_failed_predecessor_keeps_every_artifact_selected(self) -> None:
        # The next run must cover what an unverified predecessor carried.
        before = self.repo.base
        head = self.repo.change(".githooks/pre-push", "#!/bin/sh\necho changed\n")
        cases = (
            ("superseded", "predecessor-run-dispatched-nothing", FakeForgejo(
                [run_record(before)], {41: job_records(41, policy="skipped")}
            )),
            ("failed run", "predecessor-run-not-successful",
             FakeForgejo([run_record(before, status="failure")])),
            ("failed gate", "predecessor-run-not-successful", FakeForgejo(
                [run_record(before)], {41: job_records(41, required="failure")}
            )),
            ("no run", "predecessor-run-not-found", FakeForgejo([])),
            ("API down", "forgejo-api-unavailable",
             FakeForgejo(main_push.Unproven("forgejo-api-unavailable"))),
            ("API shape", "forgejo-api-malformed",
             FakeForgejo([run_record(before)], {41: {"jobs": "x"}})),
        )
        for label, reason, forgejo in cases:
            with self.subTest(case=label):
                outputs, log = self.choose(head, before, forgejo)
                self.assertEqual(self.selected(outputs), EVERYTHING)
                self.assertEqual(outputs["cw_package_state"], "unclassified")
                self.assertIn(f"every artifact stays selected ({reason})", log)

    def test_newest_predecessor_run_decides(self) -> None:
        before = self.repo.base
        head = self.repo.change(".githooks/pre-push", "#!/bin/sh\necho changed\n")
        rerun_failed = FakeForgejo(
            [run_record(before, run_id=41), run_record(before, run_id=42, status="failure")],
            {41: job_records(41)},
        )
        outputs, log = self.choose(head, before, rerun_failed)
        self.assertEqual(self.selected(outputs), EVERYTHING)
        self.assertIn("predecessor-run-not-successful", log)

        # A pull-request run of the same commit proves nothing about main.
        pull_request_only = FakeForgejo(
            [run_record(before, event="pull_request", prettyref="#7")], {41: job_records(41)}
        )
        outputs, log = self.choose(head, before, pull_request_only)
        self.assertEqual(self.selected(outputs), EVERYTHING)
        self.assertIn("predecessor-run-not-found", log)

        # Forgejo's other run and job shapes are accepted.
        other_shapes = FakeForgejo(
            [{"id": 43, "commit_sha": before, "trigger_event": "push",
              "path": "ci.yaml@refs/heads/main", "status": "completed", "conclusion": "success"}],
            {43: [dict(job, status="completed", conclusion="success") for job in job_records(43)]},
        )
        outputs, _ = self.choose(head, before, other_shapes)
        self.assertEqual(self.selected(outputs), NOTHING)

    def test_unavailable_push_baseline_keeps_every_artifact_selected(self) -> None:
        # Includes the force push: the selector reports "push baseline is
        # unavailable", and the artifact facts must select everything rather
        # than fail.
        head = self.repo.change(".githooks/pre-push", "#!/bin/sh\necho changed\n")
        tree = fixtures.run(["git", "rev-parse", "HEAD^{tree}"], self.repo.root)
        rewritten = fixtures.run(["git", "commit-tree", tree, "-m", "rewritten main"], self.repo.root)
        for before in ("", "0" * 40, "f" * 40, "not-a-sha", rewritten, head):
            with self.subTest(before=before):
                forgejo = verified(before)
                outputs, log = self.choose(head, before, forgejo)
                self.assertEqual(self.selected(outputs), EVERYTHING)
                self.assertIn("(push-baseline-unavailable)", log)
                self.assertEqual(forgejo.paths, [])

    def test_policy_change_in_the_push_fails_every_artifact_closed(self) -> None:
        before = self.repo.base
        self.repo.write(".githooks/pre-push", "#!/bin/sh\necho changed\n")
        head = self.repo.change("scripts/ci/plan/artifact-graph-notes.txt", "a policy edit\n")
        outputs, log = self.choose(head, before, verified(before))
        self.assertEqual(self.selected(outputs), EVERYTHING)
        self.assertIn("trusted policy surface changed", log)

    def test_only_a_main_push_is_planned(self) -> None:
        before = self.repo.base
        head = self.repo.change(".githooks/pre-push", "#!/bin/sh\necho changed\n")
        for environ in (
            {"GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": "refs/heads/main"},
            {"GITHUB_EVENT_NAME": "push", "GITHUB_REF": "refs/heads/feature"},
        ):
            with self.subTest(environ=environ):
                forgejo = verified(before)
                outputs, log = self.choose(head, before, forgejo, environ)
                self.assertEqual(self.selected(outputs), EVERYTHING)
                self.assertIn("(not-main-push)", log)
                self.assertEqual(forgejo.paths, [])

    def test_planner_failure_keeps_every_artifact_selected(self) -> None:
        before = self.repo.base
        head = self.repo.change(".githooks/pre-push", "#!/bin/sh\necho changed\n")
        with mock.patch.object(
            main_push.planner, "plan", side_effect=main_push.planner.PlannerError("boom")
        ):
            outputs, log = self.choose(head, before, verified(before))
        self.assertEqual(self.selected(outputs), EVERYTHING)
        self.assertIn("(planner-failed: boom)", log)

    def test_main_writes_the_outputs_once_and_needs_the_job_token(self) -> None:
        before = self.repo.base
        head = self.repo.change(".githooks/pre-push", "#!/bin/sh\necho changed\n")
        output = Path(self.temporary.name) / "github-output"
        environ = {
            **MAIN_PUSH,
            "GITHUB_SERVER_URL": "https://forge.example.invalid",
            "GITHUB_REPOSITORY": "codewire/codewire",
            "GITEA_TOKEN": "",
        }
        with mock.patch.dict(os.environ, environ), \
                contextlib.redirect_stdout(io.StringIO()) as log:
            status = main_push.main([
                "--repository", str(self.repo.root), "--head", head,
                "--before", before, "--output", str(output),
            ])
        self.assertEqual(status, 0)
        self.assertIn("(gitea-token-unavailable)", log.getvalue())
        lines = output.read_text().splitlines()
        self.assertEqual(len(lines), len({line.split("=", 1)[0] for line in lines}))
        self.assertIn("cw_package_selected=true", lines)
        self.assertIn(f"ci_head_commit={head}", lines)

        missing = Path(self.temporary.name) / "missing-head-output"
        with contextlib.redirect_stderr(io.StringIO()):
            status = main_push.main([
                "--repository", str(self.repo.root), "--head", "f" * 40,
                "--before", before, "--output", str(missing),
            ])
        self.assertEqual(status, 2)
        self.assertFalse(missing.exists())

    def test_forgejo_settings_are_validated_before_any_request(self) -> None:
        good = {
            "GITHUB_SERVER_URL": "https://forge.example.invalid",
            "GITHUB_REPOSITORY": "codewire/codewire",
            "GITEA_TOKEN": "token",
        }
        self.assertTrue(callable(main_push.forgejo_fetch(good)))
        for key, value, reason in (
            ("GITHUB_SERVER_URL", "https://forge.example.invalid/path", "invalid-server-url"),
            ("GITHUB_REPOSITORY", "codewire/codewire/extra", "invalid-repository"),
            ("GITEA_TOKEN", "", "gitea-token-unavailable"),
            ("GITEA_TOKEN", 'to"ken', "gitea-token-unavailable"),
            ("GITEA_TOKEN", "to\nken", "gitea-token-unavailable"),
        ):
            with self.subTest(key=key, value=value):
                with self.assertRaisesRegex(main_push.Unproven, reason):
                    main_push.forgejo_fetch({**good, key: value})


if __name__ == "__main__":
    unittest.main()
