#!/usr/bin/env python3
"""The scheduled read of the GitHub App's permissions (scripts/ci/verify/check-github-app-permissions.py).

A read that matches passes, a read that differs fails and names the
difference, and a day GitHub could not be read is a warning, never a failure
by itself. The workflow that runs it holds no credential.
"""

from __future__ import annotations

import importlib.util
import io
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
HELPER = ROOT / "scripts/ci/verify/check-github-app-permissions.py"
WORKFLOW = ROOT / ".gitea/workflows/github-app-permissions.yaml"
BROKER = ROOT / "crates/codewire-credential-broker/src/github_app.rs"
SPEC = importlib.util.spec_from_file_location("codewire_check_github_app_permissions", HELPER)
assert SPEC and SPEC.loader
check = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = check
sys.dont_write_bytecode = True
SPEC.loader.exec_module(check)

# GitHub's answer to GET /apps/codewire-sh on 2026-11-16, without the fields
# the check does not read (ids, owner, description, URLs, dates), and with the
# `actions: read` the App requests from #5737.
RECORDED_HEADERS = {
    "content-type": "application/json; charset=utf-8",
    "x-ratelimit-limit": "60",
    "x-ratelimit-remaining": "59",
    "x-ratelimit-used": "1",
    "x-ratelimit-resource": "core",
}
RECORDED_RECORD = {
    "slug": "codewire-sh",
    "permissions": {
        "actions": "read",
        "contents": "write",
        "metadata": "read",
        "pull_requests": "write",
    },
    "events": [],
}
# GitHub's answer to an unauthenticated request past the hourly limit.
RATE_LIMITED = check.Response(
    403,
    {"x-ratelimit-limit": "60", "x-ratelimit-remaining": "0", "x-ratelimit-resource": "core"},
    b'{"message":"API rate limit exceeded"}',
)


def recorded(**permissions: str | None) -> "check.Response":
    """The recorded answer, with permissions replaced, added or (None) removed."""
    record = json.loads(json.dumps(RECORDED_RECORD))
    for name, level in permissions.items():
        if level is None:
            del record["permissions"][name]
        else:
            record["permissions"][name] = level
    return check.Response(200, dict(RECORDED_HEADERS), json.dumps(record).encode())


class Run:
    """One run of the check against a list of answers, one per attempt."""

    def __init__(self, answers: list, *arguments: str) -> None:
        self.answers = list(answers)
        self.fetches = 0
        self.waits: list[float] = []
        out = io.StringIO()
        with tempfile.TemporaryDirectory() as temporary:
            summary = Path(temporary) / "summary"
            self.code = check.main(
                list(arguments),
                fetch=self.fetch,
                sleep=self.waits.append,
                environ={"GITHUB_STEP_SUMMARY": str(summary)},
                out=out,
            )
            self.summary = summary.read_text() if summary.exists() else ""
        self.output = out.getvalue()

    def fetch(self) -> "check.Response":
        answer = self.answers[min(self.fetches, len(self.answers) - 1)]
        self.fetches += 1
        if isinstance(answer, Exception):
            raise answer
        return answer


class ReadTests(unittest.TestCase):
    def test_the_recorded_answer_passes(self) -> None:
        run = Run([recorded()])
        self.assertEqual(run.code, 0, run.output)
        self.assertEqual(run.fetches, 1)
        self.assertIn("rate limit: 59 of 60 requests remain", run.output)
        self.assertIn(
            "codewire-sh holds actions: read, contents: write, metadata: read, pull_requests: write",
            run.output,
        )
        self.assertIn("app-permissions: read\n", run.output)
        self.assertIn("`app-permissions: read`", run.summary)
        self.assertNotIn("::error::", run.output)
        self.assertNotIn("::warning::", run.output)

    def test_an_added_permission_fails_and_is_named(self) -> None:
        run = Run([recorded(administration="write")])
        self.assertEqual(run.code, 1, run.output)
        self.assertEqual(run.fetches, 1)
        self.assertIn(
            "::error::GitHub App codewire-sh: wider: the App holds administration: write, "
            "which the GitHub route does not expect",
            run.output,
        )
        self.assertIn("app-permissions: changed\n", run.output)
        self.assertIn("administration: write", run.summary)

    def test_a_read_only_addition_still_fails(self) -> None:
        run = Run([recorded(issues="read")])
        self.assertEqual(run.code, 1, run.output)
        self.assertIn("wider: the App holds issues: read", run.output)

    def test_a_raised_level_fails(self) -> None:
        for level in ("admin", "a-level-this-check-does-not-know"):
            with self.subTest(level=level):
                run = Run([recorded(contents=level)])
                self.assertEqual(run.code, 1, run.output)
                self.assertIn(f"wider: the App holds contents: {level}, expected contents: write", run.output)

    def test_a_narrower_set_fails(self) -> None:
        run = Run([recorded(pull_requests=None, contents="read")])
        self.assertEqual(run.code, 1, run.output)
        self.assertIn("narrower: the App holds contents: read, expected contents: write", run.output)
        self.assertIn("narrower: the App no longer holds pull_requests: write", run.output)

    def test_the_app_before_actions_read_fails_as_narrower(self) -> None:
        run = Run([recorded(actions=None)])
        self.assertEqual(run.code, 1, run.output)
        self.assertIn("narrower: the App no longer holds actions: read", run.output)

    def test_actions_write_fails_as_wider(self) -> None:
        run = Run([recorded(actions="write")])
        self.assertEqual(run.code, 1, run.output)
        self.assertIn("wider: the App holds actions: write, expected actions: read", run.output)

    def test_an_answer_the_check_cannot_interpret_fails(self) -> None:
        answers = {
            "404": check.Response(404, {}, b'{"message":"Not Found"}'),
            "403 without a rate limit": check.Response(403, {"x-ratelimit-remaining": "41"}, b"{}"),
            "redirect": check.Response(301, {"location": "https://example.com/"}, b""),
            "not JSON": check.Response(200, {}, b"<html>"),
            "another App": check.Response(200, {}, json.dumps({**RECORDED_RECORD, "slug": "other"}).encode()),
            "no permissions": check.Response(200, {}, b'{"slug":"codewire-sh"}'),
            "permissions of another shape": check.Response(
                200, {}, b'{"slug":"codewire-sh","permissions":{"contents":["write"]}}'
            ),
        }
        for name, answer in answers.items():
            with self.subTest(name=name):
                run = Run([answer])
                self.assertEqual(run.code, 1, run.output)
                self.assertEqual(run.fetches, 1, "only a could-not-read answer is tried again")
                self.assertIn("::error::GitHub App codewire-sh: ", run.output)
                self.assertIn("app-permissions: changed\n", run.output)


class UnreadTests(unittest.TestCase):
    def test_a_day_without_a_read_warns_and_passes(self) -> None:
        answers = {
            "rate limit": RATE_LIMITED,
            "429": check.Response(429, {"retry-after": "60"}, b""),
            "403 with retry-after": check.Response(403, {"retry-after": "60"}, b""),
            "503": check.Response(503, {}, b""),
            "timeout": check.Unread("the request did not complete"),
        }
        for name, answer in answers.items():
            with self.subTest(name=name):
                run = Run([answer])
                self.assertEqual(run.code, 0, run.output)
                self.assertEqual(run.fetches, check.ATTEMPTS)
                self.assertEqual(run.waits, [check.RETRY_WAIT_SECONDS] * (check.ATTEMPTS - 1))
                self.assertIn("::warning::the GitHub App's permissions were not read today", run.output)
                self.assertIn("app-permissions: unread\n", run.output)
                self.assertIn("`app-permissions: unread`", run.summary)
                self.assertNotIn("::error::", run.output)

    def test_a_rate_limited_answer_prints_the_quota(self) -> None:
        self.assertIn("rate limit: 0 of 60 requests remain", Run([RATE_LIMITED]).output)

    def test_a_later_attempt_that_reads_decides(self) -> None:
        run = Run([RATE_LIMITED, recorded()])
        self.assertEqual(run.code, 0, run.output)
        self.assertEqual(run.fetches, 2)
        self.assertIn("app-permissions: read\n", run.output)
        self.assertNotIn("::warning::", run.output)

        run = Run([check.Response(502, {}, b""), recorded(administration="read")])
        self.assertEqual(run.code, 1, run.output)
        self.assertIn("app-permissions: changed\n", run.output)

    def test_the_third_unread_day_fails(self) -> None:
        for earlier, code in ((0, 0), (1, 0), (2, 1), (5, 1)):
            with self.subTest(earlier=earlier):
                run = Run([RATE_LIMITED], "--earlier-unread-days", str(earlier))
                self.assertEqual(run.code, code, run.output)
                self.assertIn("app-permissions: unread\n", run.output)
                if code:
                    self.assertIn(f"have not been read for {earlier + 1} days", run.output)

    def test_earlier_unread_days_do_not_change_a_read(self) -> None:
        self.assertEqual(Run([recorded()], "--earlier-unread-days", "9").code, 0)
        self.assertEqual(Run([recorded(administration="write")], "--earlier-unread-days", "0").code, 1)

    def test_the_tries_fit_the_job_timeout(self) -> None:
        minutes = int(re.search(r"^    timeout-minutes: ([0-9]+)$", WORKFLOW.read_text(), re.M).group(1))
        # Each try is bounded at 60 seconds by its subprocess timeout.
        worst = check.ATTEMPTS * 60 + (check.ATTEMPTS - 1) * check.RETRY_WAIT_SECONDS
        self.assertLess(worst, (minutes - 2) * 60)


class ContractTests(unittest.TestCase):
    def test_the_expected_set_is_the_brokers(self) -> None:
        block = re.search(
            r"const REQUIRED_PERMISSIONS: \[[^\]]*\] = \[(.*?)\];", BROKER.read_text(), re.S
        )
        self.assertIsNotNone(block, "REQUIRED_PERMISSIONS not found in the credential broker")
        pairs = re.findall(r'\("([a-z_]+)", PermissionLevel::([A-Za-z]+)\)', block.group(1))
        self.assertEqual({name: level.lower() for name, level in pairs}, check.REQUIRED)
        self.assertEqual(check.EXPECTED, {**check.REQUIRED, "actions": "read"})

    def test_the_request_names_one_fixed_url(self) -> None:
        self.assertEqual(check.APP_URL, "https://api.github.com/apps/codewire-sh")
        source = HELPER.read_text()
        self.assertNotIn("Authorization", source)
        self.assertNotIn("--location", source)
        self.assertNotIn("TOKEN", source)

    def test_the_workflow_is_scheduled_and_holds_no_credential(self) -> None:
        workflow = WORKFLOW.read_text()
        self.assertRegex(workflow, r"(?m)^on:\n  schedule:\n    - cron: '[0-9]+ [0-9]+ \* \* \*'\n\n")
        self.assertNotRegex(workflow, r"(?m)^  (push|pull_request|pull_request_target|workflow_run|workflow_dispatch):")
        self.assertNotRegex(workflow, r"(?m)^permissions:|enable-openid-connect|secrets\.|inputs\.|github\.token")
        self.assertEqual(workflow.count("runs-on:"), 1, "one job")
        self.assertIn(
            "runs-on: ${{ vars.CODEWIRE_CI_RUNNER_TRUSTED_LIGHT || 'unset-CODEWIRE_CI_RUNNER_TRUSTED_LIGHT' }}",
            workflow,
        )
        self.assertIn("          ref: ${{ github.sha }}\n          persist-credentials: false\n", workflow)
        self.assertIn(
            "run: python3 -I -B scripts/ci/verify/check-github-app-permissions.py\n", workflow
        )


if __name__ == "__main__":
    unittest.main()
