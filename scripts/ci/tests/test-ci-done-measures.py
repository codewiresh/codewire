#!/usr/bin/env python3
"""The #3144 Done-when measures from synthetic Forgejo records and a real Git history."""

import base64
import importlib.machinery
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "scripts/ci/measure/ci-done-measures"
loader = importlib.machinery.SourceFileLoader("ci_done_measures", str(SOURCE))
spec = importlib.util.spec_from_loader("ci_done_measures", loader)
measures = importlib.util.module_from_spec(spec)
sys.dont_write_bytecode = True
loader.exec_module(measures)

TOKEN = "synthetic-token-0123456789abcdef"
SECRET_BODY = "synthetic pull-request body that must never be printed"


def sha(character: str) -> str:
    return character * 40


def at(minutes: float) -> str:
    """Minutes after 2026-10-31T00:00:00Z."""
    total = round(minutes * 60)
    day, rest = divmod(total, 86400)
    hours, rest = divmod(rest, 3600)
    return f"2026-{10 if day == 0 else 11}-{31 if day == 0 else day:02d}T{hours:02d}:{rest // 60:02d}:{rest % 60:02d}Z"


def verdict_marker(run_id, commit):
    """The marker main-ci-verdict.py emits for a verified main run."""
    document = {
        "schema": "codewire.main-ci-verdict/v1", "repository": "codewire/codewire", "event": "push",
        "workflow_path": "ci.yaml@refs/heads/main",
        "run": {"id": run_id, "attempt": 1, "job": "Required verification"},
        "source": {"commit": commit, "tree": sha("e")}, "basis": "verification",
    }
    return "CODEWIRE_MAIN_CI_VERDICT=" + base64.b64encode(json.dumps(document).encode()).decode()


class Fake:
    """Serves allowlisted paths from in-memory runs, jobs and job details."""

    def __init__(self):
        self.runs = {"push": [], "pull_request": [], "pull_request_target": [], "workflow_dispatch": []}
        self.jobs = {}
        self.details = {}
        self.logs = {}
        self.next_job = 1000
        self.paths = []

    def run(self, event, run_id, workflow, commit, created, stopped, status, payload=None, prettyref="main"):
        # Forgejo reports a pull_request_target run's webhook event as
        # pull_request and the workflow's trigger as trigger_event.
        webhook = "pull_request" if event == "pull_request_target" else event
        self.runs[event].append({
            "id": run_id, "event": webhook, "trigger_event": event, "workflow_id": workflow, "commit_sha": commit,
            "created": at(created), "stopped": at(stopped) if stopped is not None else None,
            "status": status, "prettyref": prettyref,
            "event_payload": json.dumps(payload or {}),
        })
        self.jobs[run_id] = []

    def job(self, run_id, name, status, stopped=None, attempt=1, log=""):
        self.next_job += 1
        job_id = self.next_job
        self.logs[job_id] = log
        self.jobs[run_id].append({"id": job_id, "run_id": run_id, "name": name, "status": status,
                                  "attempt": attempt})
        steps = [] if stopped is None else [{"number": 0, "stopped": at(stopped - 1)},
                                            {"number": 1, "stopped": at(stopped)}]
        self.details[job_id] = {"id": job_id, "steps": steps}

    def transport(self, token):
        assert token == TOKEN

        def serve(kind, path):
            self.paths.append(path)
            if kind == "runs":
                event = path.split("event=")[1].split("&")[0]
                page = int(path.split("page=")[1].split("&")[0])
                items = sorted(self.runs[event], key=lambda run: -run["id"])
                chunk = items[(page - 1) * 50: page * 50]
                return 200, json.dumps({"workflow_runs": chunk}).encode()
            if kind == "jobs":
                run_id = int(path.split("/runs/")[1].split("/")[0])
                return 200, json.dumps({"jobs": self.jobs[run_id]}).encode()
            if kind == "log":
                return 200, self.logs[int(path.split("/jobs/")[1].split("/")[0])].encode()
            job_id = int(path.rsplit("/", 1)[1])
            return 200, json.dumps(self.details[job_id]).encode()

        return serve


def pull_payload(number, labels=(), action="synchronize"):
    return {"action": action, "number": number,
            "pull_request": {"number": number, "body": SECRET_BODY,
                             "labels": [{"name": name} for name in labels]}}


class Repository:
    """A real history: main is A, B, C, D; E is a side commit."""

    def __init__(self, base: Path):
        self.git_dir = str(base / "repo.git")
        work = base / "work"
        work.mkdir()
        env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid",
                   GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid",
                   GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1")

        def git(*args):
            return subprocess.run(["git", "-C", str(work), *args], env=env, check=True,
                                  capture_output=True, text=True).stdout.strip()

        git("init", "-q", "-b", "main")
        self.commits = {}
        for name in "ABCD":
            git("commit", "-q", "--allow-empty", "-m", name)
            self.commits[name] = git("rev-parse", "HEAD")
        git("checkout", "-q", "-b", "side", self.commits["B"])
        git("commit", "-q", "--allow-empty", "-m", "E")
        self.commits["E"] = git("rev-parse", "HEAD")
        subprocess.run(["git", "clone", "-q", "--bare", str(work), self.git_dir], env=env, check=True)


class MeasuresTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.base = Path(directory.name)
        self.repo = Repository(self.base)
        self.fake = Fake()

    def collect(self, *extra):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = measures.main(
                ["collect", "--since", "2026-10-31T00:00:00Z", "--until", "2026-11-07T00:00:00Z",
                 "--git-dir", self.repo.git_dir, *extra],
                environ={"CI": "true", "GITEA_TOKEN": TOKEN}, transport_factory=self.fake.transport)
        return code, stdout.getvalue(), stderr.getvalue()

    def rows(self):
        code, stdout, stderr = self.collect()
        self.assertEqual(code, 0, stderr)
        self.assertNotIn(TOKEN, stdout + stderr)
        self.assertNotIn(SECRET_BODY, stdout + stderr)
        return [json.loads(line) for line in stdout.splitlines()]

    def summary(self, rows):
        stdin = io.StringIO("".join(json.dumps(row) + "\n" for row in rows))
        stdout = io.StringIO()
        old = sys.stdin
        try:
            sys.stdin = stdin
            with redirect_stdout(stdout):
                self.assertEqual(measures.main(["summary"]), 0)
        finally:
            sys.stdin = old
        return json.loads(stdout.getvalue())

    def pull_head(self, number, head, pushed, required_stop, approval_stop, labels=(), ci_status="success",
                  run_base=100):
        self.fake.run("pull_request", run_base, "ci.yaml", head, pushed, required_stop, ci_status,
                      pull_payload(number, labels), prettyref=f"#{number}")
        self.fake.job(run_base, "Verification selection", "success", pushed + 1)
        self.fake.job(run_base, "Required verification", ci_status,
                      required_stop if ci_status in measures.TERMINAL else None)
        self.fake.run("pull_request_target", run_base + 1, "source-approval.yml", head, pushed + 0.1,
                      approval_stop, "success", pull_payload(number, labels), prettyref=f"#{number}")
        self.fake.job(run_base + 1, "Supply-chain scan", "success", approval_stop)

    def test_pull_request_speed_is_push_to_last_required_check(self):
        head = sha("1")
        self.pull_head(7, head, pushed=10, required_stop=14, approval_stop=11)
        # A later labeled run on the same head never moves the push or the checks.
        self.fake.run("pull_request", 150, "ci.yaml", head, 40, 60, "success",
                      pull_payload(7, ["merge-check"], action="labeled"), prettyref="#7")
        self.fake.job(150, "Required verification", "success", 60)
        rows = self.rows()
        [row] = [row for row in rows if row["kind"] == "pull_request_head"]
        self.assertEqual((row["pull_request"], row["outcome"], row["seconds"], row["ci_full"]),
                         (7, "finished", 240.0, False))
        self.assertEqual(row["pushed_at"], at(10))

    def test_ci_full_heads_are_reported_apart(self):
        self.pull_head(7, sha("1"), pushed=10, required_stop=14, approval_stop=11, run_base=100)
        self.pull_head(8, sha("2"), pushed=20, required_stop=60, approval_stop=21, labels=["ci-full"],
                       run_base=200)
        summary = self.summary(self.rows())
        ordinary, full = summary["speed"]["pull_requests_ordinary"], summary["speed"]["pull_requests_ci_full"]
        self.assertEqual((ordinary["n"], ordinary["p50_s"], ordinary["holds"]), (1, 240.0, True))
        self.assertEqual((full["n"], full["p50_s"]), (1, 2400.0))
        self.assertNotIn("holds", full)

    def test_superseded_and_unfinished_heads_are_excluded_and_counted(self):
        self.pull_head(7, sha("1"), pushed=10, required_stop=12, approval_stop=11, ci_status="cancelled",
                       run_base=100)
        self.pull_head(7, sha("2"), pushed=12, required_stop=20, approval_stop=13, run_base=200)
        self.pull_head(9, sha("3"), pushed=30, required_stop=None, approval_stop=31, ci_status="running",
                       run_base=300)
        ordinary = self.summary(self.rows())["speed"]["pull_requests_ordinary"]
        self.assertEqual((ordinary["n"], ordinary["p50_s"], ordinary["superseded"], ordinary["unfinished"]),
                         (1, 480.0, 1, 1))

    def test_pull_request_thresholds_are_p50_five_and_p95_ten_minutes(self):
        # Twenty heads: nineteen take 4 min, one takes 11 min, so p95 is 4 min.
        for index in range(20):
            minutes = 11 if index == 19 else 4
            self.pull_head(100 + index, f"{index:040x}", pushed=index * 20, required_stop=index * 20 + minutes,
                           approval_stop=index * 20 + 1, run_base=1000 + index * 10)
        ordinary = self.summary(self.rows())["speed"]["pull_requests_ordinary"]
        self.assertEqual((ordinary["p50_s"], ordinary["p95_s"], ordinary["holds"]), (240.0, 240.0, True))
        # One more slow head moves p95 past ten minutes.
        self.pull_head(200, sha("f"), pushed=900, required_stop=912, approval_stop=901, run_base=5000)
        ordinary = self.summary(self.rows())["speed"]["pull_requests_ordinary"]
        self.assertEqual((ordinary["p95_s"], ordinary["holds"]), (660.0, False))

    def main_run(self, run_id, commit, created, stopped, status, attempts=(1,), verdict="verified"):
        """A main push run whose Required verification prints its verdict.

        verdict: "verified" (the marker for this run and commit), "superseded",
        "none" (no verdict line) or "other-run" (a marker naming another run).
        """
        self.fake.run("push", run_id, "ci.yaml", commit, created, stopped, status)
        for index, attempt in enumerate(attempts):
            self.fake.job(run_id, f"job {index}", "success" if status != "skipped" else "skipped",
                          stopped, attempt=attempt)
        if status == "skipped":
            return
        log = {
            "verified": verdict_marker(run_id, commit),
            "other-run": verdict_marker(run_id + 1000, commit),
            "superseded": (f"main CI verdict: not verified; superseded by {sha('f')}, "
                           "whose run verifies this commit's changes"),
            "none": "required verification: every selected capability group succeeded",
        }[verdict]
        self.fake.job(run_id, "Required verification", "failure" if status == "failure" else "success",
                      stopped, attempt=attempts[-1], log=f"2026-10-31T00:00:00.0000000Z {log}\n")

    def test_main_first_attempt_excludes_skipped_and_superseded_and_rejects_rerun_passes(self):
        commits = self.repo.commits
        self.main_run(1, commits["A"], 0, 8, "success")
        self.main_run(2, commits["B"], 10, 19, "success", attempts=(1, 2))  # passed only after a rerun
        self.main_run(3, commits["C"], 20, 32, "failure")
        self.main_run(4, commits["D"], 40, 40, "skipped")
        self.main_run(5, commits["D"], 50, 51, "cancelled")
        # Another workflow's main push is not main CI.
        self.fake.run("push", 6, "support-images.yaml", commits["D"], 60, 90, "failure")
        summary = self.summary(self.rows())
        green = summary["green"]["main_ci_first_attempt"]
        self.assertEqual((green["runs"], green["verified"], green["failed"], green["first_attempt_passes"],
                          green["rate"], green["holds"]), (3, 2, 1, 1, 0.3333, False))
        self.assertEqual((green["excluded_skipped"], green["excluded_superseded"]), (1, 1))
        main = summary["speed"]["main_ci"]
        self.assertEqual((main["n"], main["p50_s"], main["holds"]), (3, 540.0, True))

    def test_a_main_run_verified_only_by_its_own_verdict(self):
        """A superseded run dispatched nothing, so it never counts (#3176).

        Runs 18429, 18464, 18473 and 18485 ended "success" with every family
        skipped; counted as verified, they pulled main CI's p50 down.
        """
        commits = self.repo.commits
        self.main_run(1, commits["A"], 0, 12, "success")
        for run_id, minutes in ((2, 7), (3, 8), (4, 20)):
            self.main_run(run_id, commits["B"], 20 * run_id, 20 * run_id + minutes, "success",
                          verdict="superseded")
        self.main_run(5, commits["C"], 100, 110, "success", verdict="none")
        self.main_run(6, commits["D"], 120, 121, "success", verdict="other-run")
        rows = self.rows()
        main_rows = {row["run_id"]: row for row in rows if row["kind"] == "main_ci"}
        self.assertEqual({run_id: row["category"] for run_id, row in main_rows.items()},
                         {1: "verified", 2: "superseded", 3: "superseded", 4: "superseded",
                          5: "unverified", 6: "unverified"})
        self.assertEqual([main_rows[run_id]["seconds"] for run_id in (2, 3, 4, 5, 6)], [None] * 5)
        summary = self.summary(rows)
        main = summary["speed"]["main_ci"]
        self.assertEqual((main["n"], main["p50_s"]), (1, 720.0))
        green = summary["green"]["main_ci_first_attempt"]
        self.assertEqual((green["runs"], green["verified"], green["first_attempt_passes"], green["rate"],
                          green["excluded_superseded"], green["excluded_unverified"]),
                         (1, 1, 1, 1.0, 3, 2))
        # Every log read is the Required verification job's, through the allowlist.
        logs = [path for path in self.fake.paths if path.endswith("/logs")]
        self.assertEqual(len(logs), 6)
        self.assertTrue(all(measures.PATHS["log"].fullmatch(path) for path in logs))

    def receipt(self, run_id, source, created, stopped, smoke):
        self.fake.run("workflow_dispatch", run_id, "dev-deployment-smoke-receipt.yaml", sha("9"), created,
                      stopped, "success" if smoke == "success" else "failure",
                      {"inputs": {"source_sha": source, "smoke_status": smoke, "deploy_run_id": "5",
                                  "deploy_commit": sha("8")}})

    def test_merge_to_dev_takes_the_first_passing_receipt_that_contains_the_merge(self):
        commits = self.repo.commits
        self.main_run(1, commits["A"], 0, 8, "success")
        self.main_run(2, commits["B"], 5, 14, "success")
        self.main_run(3, commits["D"], 30, 40, "success")
        # A failed smoke never delivers; a passing smoke of a side commit does
        # not contain D; the passing smoke of C delivers A and B.
        self.receipt(10, commits["B"], 15, 16, "failure")
        self.receipt(11, commits["C"], 18, 20, "success")
        self.receipt(12, commits["E"], 41, 42, "success")
        rows = self.rows()
        deliveries = {row["sha"]: row for row in rows if row["kind"] == "merge_to_dev"}
        self.assertEqual((deliveries[commits["A"]]["seconds"], deliveries[commits["A"]]["receipt_run_id"]),
                         (1200.0, 11))
        self.assertEqual(deliveries[commits["B"]]["seconds"], 900.0)
        self.assertEqual(deliveries[commits["D"]]["outcome"], "undelivered")
        summary = self.summary(rows)
        dev = summary["speed"]["merge_to_dev"]
        self.assertEqual((dev["n"], dev["p50_s"], dev["holds"], dev["undelivered"]), (2, 900.0, True, 1))
        smoke = summary["green"]["dev_smoke"]
        self.assertEqual((smoke["results"], smoke["passes"], smoke["rate"], smoke["holds"]),
                         (3, 2, 0.6667, False))

    def test_a_failed_promotion_never_delivers_and_is_not_a_smoke_result(self):
        commits = self.repo.commits
        self.main_run(1, commits["A"], 0, 8, "success")
        # #3820: the deploy run failed before committing a release.
        self.receipt(10, commits["A"], 12, 13, "promotion_failure")
        self.receipt(11, commits["C"], 18, 20, "success")
        rows = self.rows()
        deliveries = {row["sha"]: row for row in rows if row["kind"] == "merge_to_dev"}
        self.assertEqual(deliveries[commits["A"]]["receipt_run_id"], 11)
        smoke = self.summary(rows)["green"]["dev_smoke"]
        self.assertEqual((smoke["results"], smoke["passes"], smoke["promotion_failures"], smoke["unknown"]),
                         (1, 1, 1, 0))

    def test_receipts_after_the_window_settle_deliveries_but_are_not_counted(self):
        commits = self.repo.commits
        self.main_run(1, commits["D"], 7 * 1440 - 5, 7 * 1440 - 1, "success")
        self.receipt(10, commits["D"], 7 * 1440 + 5, 7 * 1440 + 6, "success")
        summary = self.summary(self.rows())
        self.assertEqual(summary["speed"]["merge_to_dev"]["p50_s"], 660.0)
        self.assertEqual(summary["green"]["dev_smoke"]["results"], 0)

    def test_only_allowlisted_get_paths_are_read(self):
        self.pull_head(7, sha("1"), pushed=10, required_stop=14, approval_stop=11)
        self.rows()
        self.assertTrue(self.fake.paths)
        for path in self.fake.paths:
            self.assertTrue(any(pattern.fullmatch(path) for pattern in measures.PATHS.values()), path)
        forgejo = measures.Forgejo(self.fake.transport(TOKEN))
        with self.assertRaises(measures.CollectorFailure):
            forgejo.get_json("runs", "/repos/codewire/codewire/actions/runs?event=push&page=1&limit=50&x=1")
        with self.assertRaises(measures.CollectorFailure):
            forgejo.get_json("job", "/repos/codewire/other/actions/jobs/1")

    def test_failures_are_value_blind(self):
        code, stdout, stderr = self.collect("--required-check", "not a check")
        self.assertEqual((code, stdout), (1, ""))
        self.assertEqual(stderr.strip(), "ci-done-measures: ERROR a required check must be WORKFLOW_FILE:JOB_NAME")
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = measures.main(["collect", "--since", "2026-10-31T00:00:00Z", "--until", "2026-11-07T00:00:00Z",
                                  "--git-dir", self.repo.git_dir], environ={})
        self.assertEqual(code, 1)
        self.assertIn("pass --token-file", stderr.getvalue())

    def test_forgejo_api_comes_from_the_job_server_url(self):
        self.assertEqual(measures.api_base({"GITHUB_SERVER_URL": "https://git.example.invalid/"}),
                         "https://git.example.invalid/api/v1")
        for environ in ({}, {"GITHUB_SERVER_URL": "http://git.example.invalid"},
                        {"GITHUB_SERVER_URL": "https://git.example.invalid/path"}):
            with self.subTest(environ), self.assertRaisesRegex(measures.CollectorFailure, "GITHUB_SERVER_URL"):
                measures.api_base(environ)

    def test_window_is_bounded(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = measures.main(["collect", "--since", "2026-10-01T00:00:00Z", "--until", "2026-11-07T00:00:00Z",
                                  "--git-dir", self.repo.git_dir],
                                 environ={"CI": "true", "GITEA_TOKEN": TOKEN},
                                 transport_factory=self.fake.transport)
        self.assertEqual(code, 1)
        self.assertIn("at most 31 days", stderr.getvalue())

    def test_empty_window_reports_unknown_not_holding(self):
        summary = self.summary(self.rows())
        self.assertIsNone(summary["speed"]["pull_requests_ordinary"]["holds"])
        self.assertIsNone(summary["green"]["main_ci_first_attempt"]["holds"])
        self.assertIsNone(summary["green"]["dev_smoke"]["holds"])
        self.assertEqual(summary["required_checks"],
                         ["ci.yaml:Required verification", "source-approval.yml:Supply-chain scan"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
