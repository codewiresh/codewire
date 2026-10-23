"""CI's artifact facts for a push to main (plan-main-push.py, #2897).

Before #2897 every main push ran apply-verification-plan.py --unclassified, so
the CW release assets, Container contract (since removed, #3119 A12), Compile
every Rust target and Rust / transport jobs ran on every push. A main push now plans the facts with the
previous main's policy, against that commit when main CI's verdict verified it
(main-ci-verdict.py, the predicate Dev delivery uses, #2892), and keeps every
artifact selected otherwise.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent))
import test_planner as fixtures  # noqa: E402
import verdict_fixtures as fx  # noqa: E402

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
HEAVY_ARTIFACT_GROUPS = ("rust_compile", "rust_transport")


def tree_of(repository: Path, sha: str) -> str:
    completed = subprocess.run(
        ["git", "rev-parse", "--verify", f"{sha}^{{tree}}"],
        cwd=repository, text=True, capture_output=True, check=False,
    )
    return completed.stdout.strip() if completed.returncode == 0 else "0" * 40


def recorded(sha: str, tree: str, *, runs: list[dict] | None = None, jobs=None,
             log: str | None = None) -> fx.FakeForgejo:
    """main CI's records for the previous main commit; by default a verified run."""
    return fx.FakeForgejo(
        {"ci.yaml": runs if runs is not None else [fx.run(sha)]},
        {41: jobs if jobs is not None else fx.ci_jobs(41)},
        {fx.required_job_id(41): log if log is not None else fx.log_lines(
            "required verification: every selected capability group succeeded",
            fx.marker(sha, tree),
        )},
    )


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
    push to main."""
    env = {key: value for key, value in os.environ.items() if key != "GITHUB_OUTPUT"}
    env.update({
        "VERIFICATION_SELECTION": selection,
        "VERIFICATION_TESTED_TREE_RECEIPT": "fallback",
        "VERIFICATION_SUPERSEDED": "false",
        "CW_PACKAGE_SELECTED": outputs["cw_package_selected"],
        "DESKTOP_PACKAGE_SELECTED": outputs["desktop_package_selected"],
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

    def verified(self, sha: str) -> fx.FakeForgejo:
        return recorded(sha, tree_of(self.repo.root, sha))

    def choose(
        self, head: str, before: str, forgejo: fx.FakeForgejo, environ: dict[str, str] | None = None
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

        outputs, log = self.choose(head, before, self.verified(before))
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
        outputs, _ = self.choose(head, before, self.verified(before))
        self.assertEqual(self.selected(outputs), ("true", "false", "true"))
        self.assertEqual(outputs["cw_package_state"], "affected")
        groups = dispatched(capability_selection(["crates/codewire-cli/src/main.rs"]), outputs)
        self.assertTrue(all(groups[group] for group in HEAVY_ARTIFACT_GROUPS), groups)
        # No CI group verifies the workspace image: support-images does (#3119 A12).
        self.assertNotIn("workspace_image", groups)

    def test_pin_only_push_selects_what_compiles_the_pin(self) -> None:
        before = self.repo.add_workspace_pin_crate()
        head = self.repo.change(
            fixtures.WORKSPACE_PIN, 'pub const WORKSPACE_IMAGE: &str = "workspace@sha256:two";\n'
        )
        outputs, _ = self.choose(head, before, self.verified(before))
        # cw compiles the pin; the desktop does not.
        self.assertEqual(self.selected(outputs), ("true", "false", "true"))
        self.assertEqual(outputs["cw_package_state"], "affected")
        self.assertEqual(outputs["desktop_package_state"], "unaffected")
        self.assertEqual(outputs["workspace_image_state"], "affected")
        self.assertEqual(self.selected(self.previous_outputs(head)), EVERYTHING)

    def test_unverified_predecessor_keeps_every_artifact_selected(self) -> None:
        # The next run must cover what an unverified predecessor carried.
        before = self.repo.base
        tree = tree_of(self.repo.root, before)
        head = self.repo.change(".githooks/pre-push", "#!/bin/sh\necho changed\n")
        superseded_log = fx.log_lines(
            "required verification: every selected capability group succeeded",
            f"main CI verdict: not verified; superseded by {'4' * 40}, whose run verifies this commit's changes",
        )
        cases = (
            ("superseded", "predecessor-run-superseded", recorded(
                before, tree, jobs=fx.ci_jobs(41, policy="skipped"), log=superseded_log)),
            ("failed run", "predecessor-run-not-successful", recorded(
                before, tree, runs=[fx.run(before, status="failure")], jobs=fx.ci_jobs(41, required="failure"))),
            ("failed gate", "predecessor-run-not-successful", recorded(
                before, tree, jobs=fx.ci_jobs(41, required="failure"))),
            ("still running", "predecessor-run-pending", recorded(
                before, tree, runs=[fx.run(before, status="running")], jobs=fx.ci_jobs(41, required="running"))),
            ("no run", "predecessor-run-not-found", recorded(before, tree, runs=[])),
            ("API down", "forgejo-api-unavailable",
             recorded(before, tree, jobs=main_push.Unproven("forgejo-api-unavailable"))),
            ("API shape", "forgejo-api-malformed", recorded(before, tree, jobs={"jobs": "x"})),
            ("marker for another tree", "verdict-marker-mismatch", recorded(
                before, tree, log=fx.log_lines(fx.marker(before, "5" * 40)))),
        )
        for label, reason, forgejo in cases:
            with self.subTest(case=label):
                outputs, log = self.choose(head, before, forgejo)
                self.assertEqual(self.selected(outputs), EVERYTHING)
                self.assertEqual(outputs["cw_package_state"], "unclassified")
                self.assertIn(f"every artifact stays selected ({reason})", log)

    def test_old_and_new_predecessor_records(self) -> None:
        before = self.repo.base
        tree = tree_of(self.repo.root, before)
        head = self.repo.change(".githooks/pre-push", "#!/bin/sh\necho changed\n")
        # Old: before #2892 a green run with a successful Policy verification
        # job verified its commit. It prints no verdict marker, so the shared
        # predicate no longer counts it, and every artifact stays selected.
        old = recorded(before, tree, log=fx.log_lines(
            "required verification: every selected capability group succeeded"))
        outputs, log = self.choose(head, before, old)
        self.assertEqual(self.selected(outputs), EVERYTHING)
        self.assertIn("(predecessor-run-has-no-verdict)", log)

        # New: a run that reused an exact tested-tree receipt dispatched no
        # group (its Policy verification was skipped), yet it is verified the
        # same way Dev delivery counts it.
        receipt = recorded(before, tree, jobs=fx.ci_jobs(41, policy="skipped"), log=fx.log_lines(
            "required verification: exact tested tree from PR #7 run 99 accepted",
            fx.marker(before, tree, basis="tested-tree", tested={"pull_request": 7, "run": 99}),
        ))
        outputs, log = self.choose(head, before, receipt)
        self.assertEqual(self.selected(outputs), NOTHING)
        self.assertIn(f"{before} was verified by CI run 41", log)

    def test_newest_predecessor_run_decides(self) -> None:
        before = self.repo.base
        tree = tree_of(self.repo.root, before)
        head = self.repo.change(".githooks/pre-push", "#!/bin/sh\necho changed\n")
        rerun_failed = fx.FakeForgejo(
            {"ci.yaml": [fx.run(before, run_id=41), fx.run(before, run_id=42, status="failure")]},
            {41: fx.ci_jobs(41), 42: fx.ci_jobs(42, required="failure")},
            {fx.required_job_id(41): fx.log_lines(fx.marker(before, tree))},
        )
        outputs, log = self.choose(head, before, rerun_failed)
        self.assertEqual(self.selected(outputs), EVERYTHING)
        self.assertIn("predecessor-run-not-successful", log)

        # A newer scheduled run of the same commit, which Forgejo reports with
        # event push, checked Kind alone; the push run still decides.
        scheduled_after_push = fx.FakeForgejo(
            {"ci.yaml": [fx.run(before, run_id=41), fx.run(before, run_id=44, trigger_event="schedule")]},
            {41: fx.ci_jobs(41), 44: fx.ci_jobs(44, policy="skipped")},
            {fx.required_job_id(41): fx.log_lines(fx.marker(before, tree))},
        )
        outputs, log = self.choose(head, before, scheduled_after_push)
        self.assertEqual(self.selected(outputs), NOTHING)
        self.assertIn(f"{before} was verified by CI run 41", log)

        # A green pull-request run of the same commit proves nothing about main.
        pull_request_only = fx.FakeForgejo(
            {"ci.yaml": [fx.run(before, event="pull_request", trigger_event="pull_request", prettyref="#7")]},
            {41: fx.ci_jobs(41)},
            {fx.required_job_id(41): fx.log_lines(fx.marker(before, tree))},
        )
        outputs, log = self.choose(head, before, pull_request_only)
        self.assertEqual(self.selected(outputs), EVERYTHING)
        self.assertIn("predecessor-run-not-found", log)

        # Forgejo's other run and job shapes are accepted.
        other_shapes = fx.FakeForgejo(
            {"ci.yaml": [{"id": 43, "head_sha": before, "trigger_event": "push",
                          "path": "ci.yaml@refs/heads/main", "status": "completed", "conclusion": "success"}]},
            {43: [dict(job, status="completed", conclusion="success") for job in fx.ci_jobs(43)]},
            {fx.required_job_id(43): fx.log_lines(fx.marker(before, tree, run_id=43))},
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
                forgejo = self.verified(before)
                outputs, log = self.choose(head, before, forgejo)
                self.assertEqual(self.selected(outputs), EVERYTHING)
                self.assertIn("(push-baseline-unavailable)", log)
                self.assertEqual(forgejo.paths, [])

    def test_policy_change_in_the_push_fails_every_artifact_closed(self) -> None:
        before = self.repo.base
        self.repo.write(".githooks/pre-push", "#!/bin/sh\necho changed\n")
        head = self.repo.change("scripts/ci/plan/artifact-graph-notes.txt", "a policy edit\n")
        outputs, log = self.choose(head, before, self.verified(before))
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
                forgejo = self.verified(before)
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
            outputs, log = self.choose(head, before, self.verified(before))
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
        self.assertEqual(main_push.forgejo_api(good).repository, "codewire/codewire")
        for key, value, reason in (
            ("GITHUB_SERVER_URL", "https://forge.example.invalid/path", "invalid-server-url"),
            ("GITHUB_REPOSITORY", "codewire/codewire/extra", "invalid-repository"),
            ("GITEA_TOKEN", "", "gitea-token-unavailable"),
            ("GITEA_TOKEN", 'to"ken', "gitea-token-unavailable"),
            ("GITEA_TOKEN", "to\nken", "gitea-token-unavailable"),
        ):
            with self.subTest(key=key, value=value):
                with self.assertRaisesRegex(main_push.Unproven, reason):
                    main_push.forgejo_api({**good, key: value})


if __name__ == "__main__":
    unittest.main()
