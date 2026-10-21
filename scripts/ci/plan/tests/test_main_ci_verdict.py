"""Main CI's verdict for one main commit (main-ci-verdict.py, #2892).

Dev delivers, and plan-main-push.py plans against, only a commit whose own
ci.yaml push run on main printed the verdict marker. These recorded-response
tests cover a green, red, superseded, missing, queued and tested-tree-receipt
run, and pull-request, dispatched and scheduled runs of the same commit, which
never count.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent))
import verdict_fixtures as fx  # noqa: E402

PLAN_ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location("codewire_ci_main_ci_verdict", PLAN_ROOT / "main-ci-verdict.py")
assert SPEC and SPEC.loader
verdicts = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = verdicts
SPEC.loader.exec_module(verdicts)

SHA = "1" * 40
TREE = "2" * 40
OTHER = "3" * 40
REQUIRED = fx.required_job_id(41)


def green(*runs, log: str | None = None, jobs=None) -> fx.FakeForgejo:
    return fx.FakeForgejo(
        {"ci.yaml": list(runs) or [fx.run(SHA)]},
        {41: jobs or fx.ci_jobs(41)},
        {REQUIRED: log if log is not None else fx.log_lines(
            "required verification: every selected capability group succeeded",
            f"main CI verdict: {SHA} verified; every selected capability group succeeded",
            fx.marker(SHA, TREE),
        )},
    )


class VerdictTests(unittest.TestCase):
    def judge(self, forgejo: fx.FakeForgejo, sha: str = SHA, tree: str = TREE):
        return verdicts.verdict(forgejo, sha, tree)

    def test_green_push_run_verifies_its_commit(self) -> None:
        result = self.judge(green())
        self.assertTrue(result.verified)
        self.assertEqual((result.state, result.run_id), (verdicts.VERIFIED, 41))
        self.assertEqual(
            result.describe(SHA),
            f"main CI verdict: {SHA} verified by ci.yaml run 41 (every selected capability group succeeded)",
        )

    def test_a_tested_tree_receipt_counts_as_the_same_verdict(self) -> None:
        receipt_log = fx.log_lines(
            "required verification: exact tested tree from PR #7 run 99 accepted",
            fx.marker(SHA, TREE, basis="tested-tree", tested={"pull_request": 7, "run": 99}),
        )
        result = self.judge(green(log=receipt_log))
        self.assertTrue(result.verified)
        self.assertEqual(result.basis, "exact tested tree of PR #7 run 99")

    def test_red_run_is_not_verified(self) -> None:
        for status in ("failure", "cancelled", "skipped"):
            with self.subTest(status=status):
                forgejo = fx.FakeForgejo(
                    {"ci.yaml": [fx.run(SHA, status="failure")]}, {41: fx.ci_jobs(41, required=status)}
                )
                result = self.judge(forgejo)
                self.assertEqual((result.state, result.run_id), (verdicts.FAILED, 41))
                self.assertIn("did not pass", result.describe(SHA))
                # A red verdict never needs the log.
                self.assertFalse(any(path.endswith("/logs") for path in forgejo.paths))

    def test_superseded_run_verified_nothing(self) -> None:
        log = fx.log_lines(
            "required verification: every selected capability group succeeded",
            f"main CI verdict: not verified; superseded by {OTHER}, whose run verifies this commit's changes",
        )
        result = self.judge(green(log=log))
        self.assertEqual(result.state, verdicts.SUPERSEDED)
        self.assertIn("superseded and verified nothing", result.describe(SHA))

    def test_missing_run(self) -> None:
        result = self.judge(fx.FakeForgejo({"ci.yaml": []}))
        self.assertEqual((result.state, result.run_id), (verdicts.MISSING, None))

    def test_queued_or_running_verification_is_pending(self) -> None:
        for status in ("waiting", "blocked", "running", "unknown"):
            with self.subTest(status=status):
                forgejo = fx.FakeForgejo(
                    {"ci.yaml": [fx.run(SHA, status="running")]}, {41: fx.ci_jobs(41, required=status)}
                )
                result = self.judge(forgejo)
                self.assertEqual((result.state, result.run_id), (verdicts.PENDING, 41))
                self.assertEqual(result.describe(SHA), f"main CI verdict: waiting for ci.yaml run 41's verdict on {SHA}")

    def test_the_run_still_running_its_final_job_is_verified(self) -> None:
        # CI's final job reads the verdict while its own run is still running.
        result = self.judge(green(fx.run(SHA, status="running")))
        self.assertTrue(result.verified)

    def test_other_runs_of_the_same_commit_never_count(self) -> None:
        # A green pull-request, dispatched or scheduled run for the same head
        # SHA, even with a well-formed marker, is not main CI's verdict.
        others = {
            "pull request": fx.run(SHA, event="pull_request", trigger_event="pull_request", prettyref="#7"),
            "pull request sync": fx.run(SHA, event="pull_request", trigger_event="pull_request_sync",
                                        prettyref="#7"),
            "dispatch": fx.run(SHA, event="workflow_dispatch", trigger_event="workflow_dispatch"),
            "schedule registered by a push": fx.run(SHA, event="push", trigger_event="schedule"),
            "another workflow": fx.run(SHA, workflow="deploy-dev.yaml"),
            "another branch": fx.run(SHA, prettyref="feature"),
            "another commit": fx.run(OTHER),
        }
        for label, other in others.items():
            with self.subTest(case=label):
                result = self.judge(green(other))
                self.assertEqual(result.state, verdicts.MISSING)
        # Beside a pending push run, a green pull-request run changes nothing.
        forgejo = fx.FakeForgejo(
            {"ci.yaml": [fx.run(SHA, run_id=41, status="running"),
                         fx.run(SHA, run_id=50, event="pull_request", trigger_event="pull_request",
                                prettyref="#7")]},
            {41: fx.ci_jobs(41, required="running"), 50: fx.ci_jobs(50)},
            {fx.required_job_id(50): fx.log_lines(fx.marker(SHA, TREE, run_id=50))},
        )
        result = self.judge(forgejo)
        self.assertEqual((result.state, result.run_id), (verdicts.PENDING, 41))

    def test_newest_push_run_decides(self) -> None:
        forgejo = fx.FakeForgejo(
            {"ci.yaml": [fx.run(SHA, run_id=41), fx.run(SHA, run_id=42, status="failure")]},
            {41: fx.ci_jobs(41), 42: fx.ci_jobs(42, required="failure")},
            {REQUIRED: fx.log_lines(fx.marker(SHA, TREE))},
        )
        self.assertEqual(self.judge(forgejo).state, verdicts.FAILED)

    def test_a_run_without_a_marker_is_not_verified(self) -> None:
        # Old fixture: a green run before #2892 proved itself only by its
        # Policy verification job; it prints no verdict, so it counts as none.
        old = green(log=fx.log_lines("required verification: every selected capability group succeeded"))
        result = self.judge(old)
        self.assertEqual((result.state, result.reason), (verdicts.UNVERIFIED, "run-has-no-verdict"))

    def test_a_marker_for_anything_else_is_refused(self) -> None:
        mismatches = {
            "another run": fx.marker(SHA, TREE, run_id=40),
            "another attempt": fx.marker(SHA, TREE, attempt=2),
            "another commit": fx.marker(OTHER, TREE),
            "another tree": fx.marker(SHA, OTHER),
            "another repository": fx.marker(SHA, TREE, repository="someone/else"),
            "a pull-request event": fx.marker(SHA, TREE, event="pull_request"),
            "another workflow path": fx.marker(SHA, TREE, workflow_path="ci.yaml@refs/pull/7/head"),
            "an unknown basis": fx.marker(SHA, TREE, basis="trust-me"),
            "a receipt without its run": fx.marker(SHA, TREE, basis="tested-tree", tested={"pull_request": 7}),
            "an extra key": fx.marker(SHA, TREE, extra=True),
            "not base64": fx.PREFIX + "abc",
            "not JSON": fx.PREFIX + "bm90IGpzb24=",
        }
        for label, line in mismatches.items():
            with self.subTest(case=label):
                with self.assertRaises(verdicts.Unproven):
                    self.judge(green(log=fx.log_lines(line)))
        with self.assertRaisesRegex(verdicts.Unproven, "verdict-marker-count-invalid"):
            self.judge(green(log=fx.log_lines(fx.marker(SHA, TREE), fx.marker(SHA, TREE))))

    def test_a_later_attempt_needs_its_own_marker(self) -> None:
        jobs = fx.ci_jobs(41, attempt=2)
        self.assertTrue(self.judge(green(log=fx.log_lines(fx.marker(SHA, TREE, attempt=2)), jobs=jobs)).verified)
        with self.assertRaisesRegex(verdicts.Unproven, "verdict-marker-mismatch"):
            self.judge(green(log=fx.log_lines(fx.marker(SHA, TREE, attempt=1)), jobs=jobs))

    def test_other_api_shapes_are_accepted(self) -> None:
        forgejo = fx.FakeForgejo(
            {"ci.yaml": [{"id": 41, "head_sha": SHA, "trigger_event": "push",
                          "path": "ci.yaml@refs/heads/main", "status": "completed", "conclusion": "success"}]},
            {41: [dict(job, status="completed", conclusion="success", run_attempt=job["attempt"])
                  for job in fx.ci_jobs(41)]},
            {REQUIRED: fx.log_lines(fx.marker(SHA, TREE))},
        )
        self.assertTrue(self.judge(forgejo).verified)

    def test_unreadable_api_is_unproven(self) -> None:
        cases = {
            "runs unavailable": (fx.FakeForgejo({"ci.yaml": verdicts.Unproven("forgejo-api-unavailable")}),
                                 "forgejo-api-unavailable"),
            "jobs malformed": (fx.FakeForgejo({"ci.yaml": [fx.run(SHA)]}, {41: {"jobs": "x"}}),
                               "forgejo-api-malformed"),
            "two Required jobs": (fx.FakeForgejo({"ci.yaml": [fx.run(SHA)]},
                                                 {41: fx.ci_jobs(41) + fx.ci_jobs(41)[2:3]}),
                                  "jobs-ambiguous"),
            "unknown status": (fx.FakeForgejo({"ci.yaml": [fx.run(SHA)]}, {41: fx.ci_jobs(41, required="odd")}),
                               "forgejo-api-malformed"),
            "log unavailable": (fx.FakeForgejo({"ci.yaml": [fx.run(SHA)]}, {41: fx.ci_jobs(41)},
                                               {REQUIRED: verdicts.Unproven("verdict-log-unavailable")}),
                                "verdict-log-unavailable"),
        }
        for label, (forgejo, reason) in cases.items():
            with self.subTest(case=label):
                with self.assertRaisesRegex(verdicts.Unproven, reason):
                    self.judge(forgejo)
        with self.assertRaisesRegex(verdicts.Unproven, "invalid-commit"):
            self.judge(green(), sha="not-a-sha")


class MarkerTests(unittest.TestCase):
    def env(self, **overrides: str) -> dict[str, str]:
        env = {
            "GITHUB_EVENT_NAME": "push", "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": SHA,
            "GITHUB_REPOSITORY": fx.REPOSITORY, "GITHUB_RUN_ID": "41", "CODEWIRE_RUN_ATTEMPT": "1",
            "VERIFICATION_SUPERSEDED": "false", "VERIFICATION_SUPERSEDED_BY": "",
            "VERIFICATION_TESTED_TREE_RECEIPT": "fallback",
            "CODEWIRE_HEAD_COMMIT": SHA, "CODEWIRE_HEAD_TREE": TREE,
        }
        env.update(overrides)
        return env

    def build(self, env: dict[str, str]):
        return verdicts.build_marker(env, tree_of=lambda sha: TREE if sha == SHA else OTHER)

    def round_trip(self, line: str, marker: str) -> "verdicts.Verdict":
        log = fx.log_lines("required verification: every selected capability group succeeded", line, marker)
        return verdicts.verdict(green(log=log), SHA, TREE)

    def test_emitted_marker_is_the_verdict_the_predicate_accepts(self) -> None:
        line, marker = self.build(self.env())
        self.assertEqual(line, f"main CI verdict: {SHA} verified; every selected capability group succeeded")
        self.assertTrue(marker.startswith(fx.PREFIX))
        self.assertTrue(self.round_trip(line, marker).verified)

        line, marker = self.build(self.env(VERIFICATION_TESTED_TREE_RECEIPT="accepted",
                                           VERIFICATION_TESTED_TREE_PR="7", VERIFICATION_TESTED_TREE_RUN="99"))
        self.assertIn("exact tested tree of PR #7 run 99", line)
        self.assertEqual(self.round_trip(line, marker).basis, "exact tested tree of PR #7 run 99")

    def test_superseded_run_prints_no_marker(self) -> None:
        line, marker = self.build(self.env(VERIFICATION_SUPERSEDED="true", VERIFICATION_SUPERSEDED_BY=OTHER))
        self.assertIsNone(marker)
        self.assertTrue(line.startswith(f"main CI verdict: not verified; superseded by {OTHER}"))
        log = fx.log_lines(line)
        self.assertEqual(verdicts.verdict(green(log=log), SHA, TREE).state, verdicts.SUPERSEDED)

    def test_marker_inputs_are_checked(self) -> None:
        bad = {
            "a pull request": {"GITHUB_EVENT_NAME": "pull_request"},
            "a dispatch": {"GITHUB_EVENT_NAME": "workflow_dispatch"},
            "another branch": {"GITHUB_REF": "refs/heads/feature"},
            "another commit": {"CODEWIRE_HEAD_COMMIT": OTHER},
            "another tree": {"CODEWIRE_HEAD_TREE": OTHER},
            "unknown supersession": {"VERIFICATION_SUPERSEDED": ""},
            "superseded by nothing": {"VERIFICATION_SUPERSEDED": "true"},
            "unknown receipt": {"VERIFICATION_TESTED_TREE_RECEIPT": "maybe"},
            "receipt without a PR": {"VERIFICATION_TESTED_TREE_RECEIPT": "accepted"},
            "bad run": {"GITHUB_RUN_ID": "0"},
            "bad attempt": {"CODEWIRE_RUN_ATTEMPT": "x"},
        }
        for label, overrides in bad.items():
            with self.subTest(case=label):
                with self.assertRaises(verdicts.VerdictError):
                    self.build(self.env(**overrides))

    def test_attempt_defaults_to_the_first(self) -> None:
        env = self.env()
        del env["CODEWIRE_RUN_ATTEMPT"]
        _, marker = self.build(env)
        self.assertTrue(self.round_trip("", marker).verified)


class CommandTests(unittest.TestCase):
    def test_check_writes_the_verdict_outputs(self) -> None:
        cases = {
            "verified": (green(), "verified=true\nstate=verified\nci_run=41\n",
                         f"main CI verdict: {SHA} verified by ci.yaml run 41 "
                         "(every selected capability group succeeded); delivering it"),
            "pending": (fx.FakeForgejo({"ci.yaml": [fx.run(SHA, status="running")]},
                                       {41: fx.ci_jobs(41, required="running")}),
                        "verified=false\nstate=pending\nci_run=41\n",
                        f"main CI verdict: waiting for ci.yaml run 41's verdict on {SHA}; signing nothing now; "
                        "that run's final job reruns this job when it passes"),
            "red": (fx.FakeForgejo({"ci.yaml": [fx.run(SHA, status="failure")]},
                                   {41: fx.ci_jobs(41, required="failure")}),
                    "verified=false\nstate=failed\nci_run=41\n",
                    "ci.yaml run 41 did not pass for " + SHA + "; fix forward, the next push delivers; "
                    "signing nothing"),
            "missing": (fx.FakeForgejo({"ci.yaml": []}), "verified=false\nstate=missing\nci_run=\n",
                        "no ci.yaml push run on refs/heads/main for " + SHA + "; signing nothing"),
        }
        for label, (forgejo, outputs, line) in cases.items():
            with self.subTest(case=label), tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary) / "out"
                with mock.patch.object(verdicts.ForgejoAPI, "from_environ", return_value=forgejo), \
                        mock.patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}), \
                        contextlib.redirect_stdout(io.StringIO()) as log:
                    status = verdicts.main(["check", "--sha", SHA, "--tree", TREE, "--github-output"])
                self.assertEqual(status, 0)
                self.assertEqual(output.read_text(), outputs)
                self.assertIn(line, log.getvalue())

    def test_check_fails_closed_when_the_verdict_is_unreadable(self) -> None:
        forgejo = fx.FakeForgejo({"ci.yaml": verdicts.Unproven("forgejo-api-unavailable")})
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "out"
            with mock.patch.object(verdicts.ForgejoAPI, "from_environ", return_value=forgejo), \
                    mock.patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}), \
                    contextlib.redirect_stderr(io.StringIO()) as errors:
                status = verdicts.main(["check", "--sha", SHA, "--tree", TREE, "--github-output"])
            self.assertEqual(status, 1)
            self.assertFalse(output.exists())
            self.assertIn("signing nothing", errors.getvalue())

    def test_forgejo_settings_are_validated_before_any_request(self) -> None:
        good = {"GITHUB_SERVER_URL": "https://forge.example.invalid",
                "GITHUB_REPOSITORY": fx.REPOSITORY, "GITEA_TOKEN": "token"}
        self.assertEqual(verdicts.ForgejoAPI.from_environ(good).repository, fx.REPOSITORY)
        for key, value, reason in (
            ("GITHUB_SERVER_URL", "https://forge.example.invalid/path", "invalid-server-url"),
            ("GITHUB_REPOSITORY", "codewire/codewire/extra", "invalid-repository"),
            ("GITEA_TOKEN", "", "gitea-token-unavailable"),
            ("GITEA_TOKEN", 'to"ken', "gitea-token-unavailable"),
            ("GITEA_TOKEN", "to\nken", "gitea-token-unavailable"),
        ):
            with self.subTest(key=key, value=value):
                with self.assertRaisesRegex(verdicts.Unproven, reason):
                    verdicts.ForgejoAPI.from_environ({**good, key: value})


if __name__ == "__main__":
    unittest.main()
