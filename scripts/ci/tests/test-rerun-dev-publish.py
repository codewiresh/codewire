#!/usr/bin/env python3
"""CI's final job starts Dev delivery of the commit it verified (#2892).

Recorded-response tests of scripts/ci/deploy/rerun-dev-publish.py: both orders
(main CI first, builds first), a publish job running at that moment, the
bounded wait giving up loudly, a missing, superseded or failed Deploy Dev run,
and a verdict that is not this run's or not green. The job names it looks for
are Deploy Dev's own, and the delivered line is dispatch-deploy-dev.sh's.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import re
import sys
import unittest
from pathlib import Path
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts/ci/plan/tests"))
import verdict_fixtures as fx  # noqa: E402
sys.path.insert(0, str(ROOT / "scripts/ci/tests"))
import ci_runner_fixtures as runners  # noqa: E402

SPEC = importlib.util.spec_from_file_location(
    "codewire_ci_rerun_dev_publish", ROOT / "scripts/ci/deploy/rerun-dev-publish.py"
)
assert SPEC and SPEC.loader
publish = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = publish
SPEC.loader.exec_module(publish)

SHA = "1" * 40
TREE = "2" * 40
OTHER = "3" * 40
CI_RUN = 41
DEV_RUN = 60
PUBLISH_JOB = 603


def dev_jobs(publish_state: str, *, builds: str = "success", selection: str = "success") -> list[dict]:
    return [
        {"id": 601, "run_id": DEV_RUN, "attempt": 1, "name": "Deploy selection", "status": selection},
        {"id": 602, "run_id": DEV_RUN, "attempt": 1, "name": "Build and push the service runtime images",
         "status": builds},
        {"id": 604, "run_id": DEV_RUN, "attempt": 1, "name": "Build and push the daemon runtime image",
         "status": builds},
        {"id": PUBLISH_JOB, "run_id": DEV_RUN, "attempt": 1, "name": "Publish the exact runtime image set",
         "status": publish_state},
    ]


WAITED_LOG = fx.log_lines(f"main CI verdict: waiting for ci.yaml run {CI_RUN}'s verdict on {SHA}")
DELIVERED_LOG = fx.log_lines(
    f"main CI verdict: {SHA} verified by ci.yaml run {CI_RUN} (every selected capability group succeeded)",
    f"[dispatch-deploy-dev] accepted canonical source {SHA} as deploy run 7001 / #812",
)


def forgejo(dev_job_states, *, dev_runs=None, publish_log: str = WAITED_LOG, reruns=None,
            ci_required: str = "success", ci_log: str | None = None) -> fx.FakeForgejo:
    return fx.FakeForgejo(
        {
            "ci.yaml": [fx.run(SHA, run_id=CI_RUN, status="running")],
            "deploy-dev.yaml": dev_runs if dev_runs is not None else [
                fx.run(SHA, run_id=DEV_RUN, workflow="deploy-dev.yaml"),
            ],
        },
        {CI_RUN: fx.ci_jobs(CI_RUN, required=ci_required), DEV_RUN: dev_job_states},
        {
            fx.required_job_id(CI_RUN): ci_log if ci_log is not None else fx.log_lines(
                fx.marker(SHA, TREE, run_id=CI_RUN)),
            PUBLISH_JOB: publish_log,
        },
        {PUBLISH_JOB: reruns or [204]},
    )


class Clock:
    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds

    def __call__(self) -> float:
        return self.now


class TriggerTests(unittest.TestCase):
    def trigger(self, api: fx.FakeForgejo, own_run: int = CI_RUN, wait: float = 60):
        clock = Clock()
        lines: list[str] = []
        status = publish.trigger(api, SHA, TREE, own_run, wait_seconds=wait, poll_seconds=10,
                                 sleep=clock.sleep, clock=clock, log=lines.append)
        return status, "\n".join(lines), clock

    def test_builds_first_reruns_the_publish_job_that_waited(self) -> None:
        api = forgejo(dev_jobs("success"))
        status, log, clock = self.trigger(api)
        self.assertEqual(status, 0)
        self.assertEqual(api.posts, [f"/actions/jobs/{PUBLISH_JOB}/rerun"])
        self.assertIn(f"verified by ci.yaml run {CI_RUN}", log)
        self.assertIn(f"reran Deploy Dev run {DEV_RUN}'s publish job {PUBLISH_JOB} for {SHA}", log)
        self.assertEqual(clock.sleeps, [])

    def test_a_failed_publish_job_is_rerun(self) -> None:
        api = forgejo(dev_jobs("failure"), publish_log=fx.log_lines("::error::cannot read main CI's verdict"))
        status, _, _ = self.trigger(api)
        self.assertEqual((status, len(api.posts)), (0, 1))

    def test_ci_first_leaves_the_publish_job_to_read_the_verdict_itself(self) -> None:
        for state, builds in (("blocked", "running"), ("waiting", "success"), ("blocked", "waiting")):
            with self.subTest(publish=state, builds=builds):
                api = forgejo(dev_jobs(state, builds=builds))
                status, log, _ = self.trigger(api)
                self.assertEqual(status, 0)
                self.assertEqual(api.posts, [])
                self.assertIn("has not started; it reads this verdict itself", log)

    def test_already_delivered_is_not_delivered_again(self) -> None:
        api = forgejo(dev_jobs("success"), publish_log=DELIVERED_LOG)
        status, log, _ = self.trigger(api)
        self.assertEqual((status, api.posts), (0, []))
        self.assertIn(f"already delivered {SHA}", log)

    def test_running_publish_job_is_waited_for_then_rerun(self) -> None:
        api = forgejo([dev_jobs("running"), dev_jobs("running"), dev_jobs("success")])
        status, log, clock = self.trigger(api)
        self.assertEqual(status, 0)
        self.assertEqual(clock.sleeps, [10, 10])
        self.assertEqual(len(api.posts), 1)
        self.assertIn("is running; waiting up to 60 s", log)

    def test_running_publish_job_that_delivered_is_left_alone(self) -> None:
        api = forgejo([dev_jobs("running"), dev_jobs("success")], publish_log=DELIVERED_LOG)
        status, _, _ = self.trigger(api)
        self.assertEqual((status, api.posts), (0, []))

    def test_bounded_wait_gives_up_loudly(self) -> None:
        api = forgejo(dev_jobs("running"))
        status, log, clock = self.trigger(api, wait=60)
        self.assertEqual(status, 1)
        self.assertEqual(api.posts, [])
        self.assertLessEqual(sum(clock.sleeps), 60)
        missed = [line for line in log.splitlines() if "missed trigger" in line]
        self.assertEqual(len(missed), 1, log)
        self.assertTrue(missed[0].startswith("::error::missed trigger: Deploy Dev run 60's publish job 603 "
                                             "was still running after 60 s"))
        self.assertIn(f"{SHA} is not delivered", missed[0])

    def test_a_rerun_refused_while_the_job_restarted_is_retried(self) -> None:
        api = forgejo([dev_jobs("success"), dev_jobs("running"), dev_jobs("success")], reruns=[400, 204])
        status, _, clock = self.trigger(api)
        self.assertEqual(status, 0)
        self.assertEqual(len(api.posts), 2)
        self.assertEqual(len(clock.sleeps), 2)

    def test_a_refused_rerun_of_a_finished_job_fails_loudly(self) -> None:
        api = forgejo(dev_jobs("success"), reruns=[400])
        status, log, _ = self.trigger(api)
        self.assertEqual(status, 1)
        self.assertEqual(len(api.posts), 1)
        self.assertIn("missed trigger: Forgejo refused to rerun", log)
        api = forgejo(dev_jobs("success"), reruns=[403])
        status, log, _ = self.trigger(api)
        self.assertEqual(status, 1)
        self.assertIn("(HTTP 403)", log)

    def test_nothing_to_deliver_is_no_error(self) -> None:
        cases = {
            "no Deploy Dev run": (forgejo(dev_jobs("success"), dev_runs=[]), "no Deploy Dev push run"),
            "builds failed": (forgejo(dev_jobs("skipped", builds="failure")), "builds failed"),
            "nothing selected": (forgejo(dev_jobs("skipped", builds="skipped")), "selected nothing to deliver"),
        }
        for label, (api, expected) in cases.items():
            with self.subTest(case=label):
                status, log, _ = self.trigger(api)
                self.assertEqual((status, api.posts), (0, []))
                self.assertIn(expected, log)

    def test_a_cancelled_delivery_of_a_green_commit_is_restarted(self) -> None:
        # A newer push cancelled this commit's delivery while its main CI was
        # still running; now it is green, so the whole delivery runs again.
        for label, jobs in {
            "cancelled while waiting": dev_jobs("cancelled", builds="cancelled"),
            "cancelled while building": dev_jobs("skipped", builds="cancelled"),
            "cancelled before selection": dev_jobs("skipped", builds="skipped", selection="cancelled"),
        }.items():
            with self.subTest(case=label):
                api = forgejo(jobs)
                status, log, _ = self.trigger(api)
                self.assertEqual((status, api.posts), (0, ["/actions/jobs/601/rerun"]))
                self.assertIn(f"Deploy Dev run {DEV_RUN} for {SHA} was cancelled before it published; "
                              f"restarted it from its selection job", log)

    def test_a_refused_restart_fails_loudly(self) -> None:
        api = forgejo(dev_jobs("skipped", builds="cancelled"))
        api.reruns[601] = [403]
        status, log, _ = self.trigger(api)
        self.assertEqual((status, api.posts), (1, ["/actions/jobs/601/rerun"]))
        self.assertIn("missed trigger: Forgejo refused to restart cancelled Deploy Dev run", log)

    def test_only_the_deploy_dev_push_run_for_this_commit_is_rerun(self) -> None:
        # Never "the latest run": a newer run for another commit, a dispatch
        # and a pull-request run of this commit are all ignored.
        dev_runs = [
            fx.run(OTHER, run_id=99, workflow="deploy-dev.yaml"),
            fx.run(SHA, run_id=98, workflow="deploy-dev.yaml", event="workflow_dispatch",
                   trigger_event="workflow_dispatch"),
            fx.run(SHA, run_id=97, workflow="deploy-dev.yaml", event="pull_request",
                   trigger_event="pull_request", prettyref="#7"),
            fx.run(SHA, run_id=DEV_RUN, workflow="deploy-dev.yaml"),
        ]
        api = forgejo(dev_jobs("success"), dev_runs=dev_runs)
        status, _, _ = self.trigger(api)
        self.assertEqual(status, 0)
        self.assertEqual(api.posts, [f"/actions/jobs/{PUBLISH_JOB}/rerun"])
        self.assertIn(f"/actions/runs/{DEV_RUN}/jobs?page=1&limit=100", api.paths)
        self.assertFalse(any(re.search(r"/actions/runs/9[789]/", path) for path in api.paths))

    def test_no_green_verdict_starts_nothing(self) -> None:
        superseded = fx.log_lines(
            f"main CI verdict: not verified; superseded by {OTHER}, whose run verifies this commit's changes")
        cases = {
            "red": forgejo(dev_jobs("success"), ci_required="failure"),
            "pending": forgejo(dev_jobs("success"), ci_required="running"),
            "superseded": forgejo(dev_jobs("success"), ci_log=superseded),
            "no marker": forgejo(dev_jobs("success"), ci_log=fx.log_lines("required verification: ok")),
        }
        for label, api in cases.items():
            with self.subTest(case=label):
                status, log, _ = self.trigger(api)
                self.assertEqual((status, api.posts), (0, []))
                self.assertIn("starting no Dev delivery", log)
                self.assertFalse(any("deploy-dev.yaml" in path for path in api.paths))

    def test_a_pull_request_run_for_the_same_commit_is_no_verdict(self) -> None:
        api = forgejo(dev_jobs("success"))
        api.runs["ci.yaml"] = [fx.run(SHA, run_id=CI_RUN, event="pull_request", trigger_event="pull_request",
                                      prettyref="#7")]
        status, log, _ = self.trigger(api)
        self.assertEqual((status, api.posts), (0, []))
        self.assertIn("no ci.yaml push run", log)

    def test_only_this_runs_verdict_starts_delivery(self) -> None:
        api = forgejo(dev_jobs("success"))
        status, log, _ = self.trigger(api, own_run=40)
        self.assertEqual((status, api.posts), (0, []))
        self.assertIn("comes from ci.yaml run 41, not this run 40", log)

    def test_unreadable_records_fail_loudly(self) -> None:
        api = forgejo(dev_jobs("success"))
        api.runs["deploy-dev.yaml"] = publish.verdicts.Unproven("forgejo-api-unavailable")
        status, log, _ = self.trigger(api)
        self.assertEqual((status, api.posts), (1, []))
        self.assertIn("::error::missed trigger: cannot read the records", log)


def actions_if(expression: str, context: dict[str, str]) -> bool:
    """A job or step condition as Actions evaluates it, for the forms used here:
    github and needs context values, quoted strings, ==, &&, || and !."""
    whole = re.fullmatch(r"\$\{\{(.*)\}\}", expression.strip())
    assert whole, expression
    python = re.sub(r"(?:github|needs)\.[A-Za-z0-9_.-]+", lambda match: repr(context[match.group(0)]),
                    whole.group(1))
    python = python.replace("&&", " and ").replace("||", " or ")
    assert re.fullmatch(r"(?:\s|'[^']*'|==|!=|and|or|\(|\))*", python), python
    return bool(eval(python, {"__builtins__": {}}, {}))  # noqa: S307 - checked above


class CiWorkflowTests(unittest.TestCase):
    """Only CI's final job, on a push to main after a green verdict, reruns."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.jobs = yaml.safe_load((ROOT / ".gitea/workflows/ci.yaml").read_text())["jobs"]

    def context(self, event: str, ref: str, *, required: str = "success", superseded: str = "false"):
        return {
            "github.event_name": event,
            "github.ref": ref,
            "needs.required-verification.result": required,
            "needs.verification-selection.outputs.superseded": superseded,
        }

    def test_only_the_final_job_starts_dev_delivery(self) -> None:
        users = {job_id for job_id, job in self.jobs.items()
                 if "rerun-dev-publish.py" in yaml.safe_dump(job) or "/rerun" in yaml.safe_dump(job)}
        self.assertEqual(users, {"deliver-to-dev"})
        job = self.jobs["deliver-to-dev"]
        self.assertEqual(job["needs"], ["verification-selection", "required-verification"])
        self.assertEqual(job["runs-on"], runners.UNTRUSTED_LIGHT)
        self.assertLessEqual(job["timeout-minutes"], 15)
        self.assertNotIn("enable-openid-connect", job)
        steps = [step for step in job["steps"] if "run" in step]
        self.assertEqual(len(steps), 1)
        self.assertEqual(steps[0]["run"], "python3 -I -B scripts/ci/deploy/rerun-dev-publish.py")
        self.assertEqual(steps[0]["env"], {"GITEA_TOKEN": "${{ github.token }}"})
        # No other job depends on it: nothing waits for Dev delivery.
        self.assertFalse([job_id for job_id, other in self.jobs.items()
                          if "deliver-to-dev" in (other.get("needs") or [])])

    def test_it_runs_on_a_push_to_main_after_a_green_unsuperseded_verdict_only(self) -> None:
        condition = self.jobs["deliver-to-dev"]["if"]
        self.assertTrue(actions_if(condition, self.context("push", "refs/heads/main")))
        for label, context in {
            "pull request": self.context("pull_request", "refs/pull/7/head"),
            "dispatch": self.context("workflow_dispatch", "refs/heads/main"),
            "schedule": self.context("schedule", "refs/heads/main"),
            "another branch": self.context("push", "refs/heads/feature"),
            "red verification": self.context("push", "refs/heads/main", required="failure"),
            "cancelled verification": self.context("push", "refs/heads/main", required="cancelled"),
            "superseded run": self.context("push", "refs/heads/main", superseded="true"),
        }.items():
            with self.subTest(case=label):
                self.assertFalse(actions_if(condition, context))

    def test_required_verification_records_the_verdict_after_its_check(self) -> None:
        steps = self.jobs["required-verification"]["steps"]
        names = [step.get("name") for step in steps]
        check = names.index("Require capability groups")
        record = names.index("Record main CI's verdict for this commit")
        self.assertEqual(record, check + 1)
        step = steps[record]
        self.assertEqual(step["run"], "python3 -I -B scripts/ci/plan/main-ci-verdict.py emit")
        self.assertTrue(actions_if(step["if"], self.context("push", "refs/heads/main")))
        for event, ref in (("pull_request", "refs/pull/7/head"), ("workflow_dispatch", "refs/heads/main"),
                           ("schedule", "refs/heads/main")):
            with self.subTest(event=event):
                self.assertFalse(actions_if(step["if"], self.context(event, ref)))
        self.assertEqual(step["env"], {
            "CODEWIRE_RUN_ATTEMPT": "${{ github.run_attempt }}",
            "CODEWIRE_HEAD_COMMIT": "${{ needs.verification-selection.outputs.ci_head_commit }}",
            "CODEWIRE_HEAD_TREE": "${{ needs.verification-selection.outputs.ci_head_tree }}",
            "VERIFICATION_SUPERSEDED": "${{ needs.verification-selection.outputs.superseded }}",
            "VERIFICATION_SUPERSEDED_BY": "${{ needs.verification-selection.outputs.superseded_by }}",
            "VERIFICATION_TESTED_TREE_RECEIPT": "${{ needs.verification-selection.outputs.tested_tree_receipt }}",
            "VERIFICATION_TESTED_TREE_PR": "${{ needs.verification-selection.outputs.tested_tree_pr }}",
            "VERIFICATION_TESTED_TREE_RUN": "${{ needs.verification-selection.outputs.tested_tree_run }}",
        })
        # Only Required verification prints the verdict.
        printers = {job_id for job_id, job in self.jobs.items() if "main-ci-verdict.py emit" in yaml.safe_dump(job)}
        self.assertEqual(printers, {"required-verification"})


class ContractTests(unittest.TestCase):
    def test_job_names_are_deploy_devs_own(self) -> None:
        workflow = yaml.safe_load((ROOT / ".gitea/workflows/deploy-dev.yaml").read_text())
        names = {job["name"] for job in workflow["jobs"].values()}
        for name in (publish.SELECTION_JOB, *publish.BUILD_JOBS, publish.PUBLISH_JOB):
            self.assertIn(name, names)
        publish_job = next(job for job in workflow["jobs"].values() if job["name"] == publish.PUBLISH_JOB)
        self.assertEqual(
            set(publish_job["needs"]),
            {"deploy-selection", "build-service-images", "build-daemon-image"},
        )

    def test_delivered_line_is_dispatch_deploy_devs_own(self) -> None:
        dispatcher = (ROOT / "scripts/ci/deploy/dispatch-deploy-dev.sh").read_text()
        self.assertIn(
            "printf '[dispatch-deploy-dev] accepted canonical source %s as deploy run %s / #%s\\n'",
            dispatcher,
        )
        self.assertEqual(
            publish.DELIVERED.format(sha=SHA) + " 7001 / #812",
            f"[dispatch-deploy-dev] accepted canonical source {SHA} as deploy run 7001 / #812",
        )

    def test_only_main_ci_push_runs_it(self) -> None:
        for environ in (
            {"GITHUB_EVENT_NAME": "pull_request", "GITHUB_REF": "refs/pull/7/head"},
            {"GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": "refs/heads/main"},
            {"GITHUB_EVENT_NAME": "schedule", "GITHUB_REF": "refs/heads/main"},
            {"GITHUB_EVENT_NAME": "push", "GITHUB_REF": "refs/heads/feature"},
        ):
            with self.subTest(environ=environ), mock.patch.dict(os.environ, environ, clear=True), \
                    contextlib.redirect_stderr(io.StringIO()) as errors:
                self.assertEqual(publish.main(), 2)
                self.assertIn("only main CI's push run starts Dev delivery", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
