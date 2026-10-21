#!/usr/bin/env python3
"""The CI-worker merge check's binding (scripts/ci/receipts/ci-merge-check.py).

Each case builds a hermetic canonical remote with a pull-request head and a
main. It runs the first job's merge and the receipt job's attestation, then
verifies the receipt job's log against the remote through a fake fj. A pass
needs all of these:

- the newest successful run for the current head;
- its receipt job's single binding line;
- the current main;
- a tested tree equal to merging the current head and main;
- no change to the merge check's own machinery.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TOOL = ROOT / "scripts/ci/receipts/ci-merge-check.py"
FAKE_FJ = """#!/usr/bin/env python3
import os, pathlib, sys
state = pathlib.Path(os.environ["FAKE_FJ_STATE"])
with open(state / "calls", "a", encoding="utf-8") as handle:
    handle.write(" ".join(sys.argv[1:]) + "\\n")
name = {"list": "runs.json", "view": "view.json", "logs": "log.txt"}[sys.argv[3]]
sys.stdout.write((state / name).read_text(encoding="utf-8"))
"""


class MergeCheckCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = Path(tempfile.mkdtemp(prefix="ci-merge-check."))
        self.addCleanup(shutil.rmtree, self.temporary)
        (self.temporary / "home").mkdir()
        fake_bin = self.temporary / "bin"
        fake_bin.mkdir()
        (fake_bin / "fj").write_text(FAKE_FJ, encoding="utf-8")
        (fake_bin / "fj").chmod(0o755)
        self.state = self.temporary / "fj"
        self.state.mkdir()
        self.env = {
            "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
            "HOME": os.fspath(self.temporary / "home"),
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_AUTHOR_NAME": "Fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
            "GIT_COMMITTER_NAME": "Fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
            "FAKE_FJ_STATE": os.fspath(self.state),
            "TMPDIR": os.fspath(self.temporary),
        }
        self.origin = self.temporary / "origin.git"
        self.git(self.temporary, "init", "--quiet", "--bare", "-b", "main", os.fspath(self.origin))
        self.author = self.temporary / "author"
        self.git(self.temporary, "init", "--quiet", "-b", "main", os.fspath(self.author))
        self.git(self.author, "remote", "add", "origin", os.fspath(self.origin))
        self.commit(self.author, "scripts/dev/preflight.sh", "#!/bin/sh\n")
        self.commit(self.author, "shared.txt", "base\n")
        self.git(self.author, "push", "--quiet", "origin", "main")

    # -- helpers ---------------------------------------------------------------

    def git(self, cwd: Path, *args: str) -> str:
        return subprocess.run(["git", *args], cwd=cwd, env=self.env, check=True, text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.strip()

    def commit(self, cwd: Path, path: str, content: str) -> str:
        target = cwd / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        self.git(cwd, "add", "--all")
        self.git(cwd, "commit", "--quiet", "-m", f"change {path}")
        return self.git(cwd, "rev-parse", "HEAD")

    def tool(self, cwd: Path, *args: str, extra: dict[str, str] | None = None
             ) -> subprocess.CompletedProcess[str]:
        return subprocess.run([sys.executable, "-I", "-B", os.fspath(TOOL), *args], cwd=cwd,
                              env={**self.env, **(extra or {})}, text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def open_pull_request(self, path: str = "feature.txt", content: str = "feature\n") -> str:
        """Branch from main, push the head as pull request 1, then move main."""
        self.git(self.author, "checkout", "--quiet", "-b", "feature")
        head = self.commit(self.author, path, content)
        self.git(self.author, "push", "--quiet", "origin", "HEAD:refs/pull/1/head")
        self.git(self.author, "checkout", "--quiet", "main")
        self.commit(self.author, "main-only.txt", "main moved\n")
        self.git(self.author, "push", "--quiet", "origin", "main")
        return head

    def ci_checkout(self, head: str, name: str = "ci") -> Path:
        """What the workflow's checkout leaves: the exact head and origin/main."""
        checkout = self.temporary / name
        self.git(self.temporary, "clone", "--quiet", os.fspath(self.origin), os.fspath(checkout))
        self.git(checkout, "fetch", "--quiet", "origin", "refs/pull/1/head")
        self.git(checkout, "checkout", "--quiet", "--detach", head)
        return checkout

    def merge(self, head: str) -> dict[str, str]:
        checkout = self.ci_checkout(head)
        output = self.temporary / "github-output"
        result = self.tool(checkout, "merge", "--pr", "1", "--head", head, "--github-output",
                           extra={"GITHUB_OUTPUT": os.fspath(output)})
        self.assertEqual(result.returncode, 0, result.stderr)
        return dict(line.split("=", 1) for line in output.read_text().splitlines())

    def attest(self, head: str, facts: dict[str, str], result: str = "success",
               name: str = "receipt") -> subprocess.CompletedProcess[str]:
        candidate = self.ci_checkout(head, name)
        return self.tool(candidate, "attest", "--repo", os.fspath(candidate), "--pr", "1",
                         "--head", head, "--main", facts["main"], "--tree", facts["tree"],
                         "--result", result, "--attested-by", facts["main"],
                         "--output-dir", os.fspath(self.temporary / f"{name}-artifact"),
                         extra={"GITHUB_RUN_ID": "77", "GITHUB_RUN_NUMBER": "12"})

    def run_ci(self, head: str) -> tuple[dict[str, str], str]:
        facts = self.merge(head)
        attested = self.attest(head, facts)
        self.assertEqual(attested.returncode, 0, attested.stderr)
        return facts, attested.stdout

    def serve_run(self, head: str, log: str, status: str = "success",
                  receipt_status: str | None = None, extra_runs: list[dict] | None = None) -> None:
        runs = [{"id": 77, "number": 12, "head_sha": head, "workflow": "merge-check.yaml",
                 "status": status, "event": "pull_request", "ref": "#1",
                 "url": "https://forge.invalid/runs/12"}, *(extra_runs or [])]
        (self.state / "runs.json").write_text(json.dumps({"runs": runs}), encoding="utf-8")
        (self.state / "view.json").write_text(json.dumps({"run": runs[0], "jobs": [
            {"id": 900, "run_id": 77, "name": "Merge check", "status": status},
            {"id": 901, "run_id": 77, "name": "Merge-check receipt",
             "status": receipt_status or status}]}), encoding="utf-8")
        # The runner prefixes every line with a timestamp.
        stamped = "".join(f"2026-10-21T00:00:00.0000000Z {line}\n" for line in log.splitlines())
        (self.state / "log.txt").write_text(stamped, encoding="utf-8")

    def verify(self) -> tuple[int, dict[str, str]]:
        result = self.tool(self.author, "verify", "--pr", "1")
        self.assertEqual(result.stderr, "")
        fields = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
        return result.returncode, fields

    @staticmethod
    def binding(log: str) -> dict:
        marker = "CODEWIRE_MERGE_CHECK_BINDING "
        return json.loads(next(line.split(marker, 1)[1] for line in log.splitlines()
                               if marker in line))

    @staticmethod
    def rewrite(binding: dict, **changes: object) -> str:
        return f"CODEWIRE_MERGE_CHECK_BINDING {json.dumps({**binding, **changes})}\n"

    # -- CI side ---------------------------------------------------------------

    def test_the_receipt_job_binds_head_main_tree_and_the_first_jobs_result(self) -> None:
        head = self.open_pull_request()
        facts, log = self.run_ci(head)
        main = self.git(self.author, "rev-parse", "main")
        self.assertEqual((facts["head"], facts["main"]), (head, main))
        checkout = self.temporary / "ci"
        self.assertEqual(self.git(checkout, "rev-parse", "HEAD^1", "HEAD^2").split(), [head, main])
        self.assertEqual(facts["tree"], self.git(checkout, "merge-tree", "--write-tree", head, main))
        binding = self.binding(log)
        self.assertEqual(binding, {
            "schema": "codewire.ci-merge-check/v2", "pr": 1, "head": head, "main": main,
            "tree": facts["tree"], "run_id": "77", "run_number": "12",
            "merge_check_result": "success", "attested_by": main})
        self.assertIn("::group::Codewire merge-check receipt", log)
        artifact = self.temporary / "receipt-artifact/binding.json"
        self.assertEqual(json.loads(artifact.read_text()), binding)

    def test_a_head_that_already_contains_main_is_qualified_as_is(self) -> None:
        self.git(self.author, "checkout", "--quiet", "-b", "feature")
        head = self.commit(self.author, "feature.txt", "feature\n")
        self.git(self.author, "push", "--quiet", "origin", "HEAD:refs/pull/1/head")
        facts = self.merge(head)
        self.assertEqual(facts["tree"], self.git(self.author, "rev-parse", f"{head}^{{tree}}"))

    def test_a_conflict_fails_and_leaves_the_checkout_clean(self) -> None:
        head = self.open_pull_request("main-only.txt", "pull request side\n")
        checkout = self.ci_checkout(head)
        result = self.tool(checkout, "merge", "--pr", "1", "--head", head)
        self.assertEqual(result.returncode, 1)
        self.assertIn("does not merge cleanly", result.stderr)
        self.assertIn("conflict: main-only.txt", result.stderr)
        self.assertEqual(self.git(checkout, "status", "--porcelain"), "")
        self.assertEqual(self.git(checkout, "rev-parse", "HEAD"), head)

    def test_merge_refuses_a_checkout_that_is_not_the_head(self) -> None:
        head = self.open_pull_request()
        checkout = self.ci_checkout(head)
        self.git(checkout, "checkout", "--quiet", "--detach", "origin/main")
        result = self.tool(checkout, "merge", "--pr", "1", "--head", head)
        self.assertEqual(result.returncode, 1)
        self.assertIn("checkout-is-not-the-pull-request-head", result.stderr)

    def test_a_change_to_the_merge_checks_machinery_gets_no_receipt(self) -> None:
        head = self.open_pull_request("scripts/dev/preflight.sh", "#!/bin/sh\nexit 0\n")
        checkout = self.ci_checkout(head)
        # The run still qualifies it, saying early that no receipt follows.
        merged = self.tool(checkout, "merge", "--pr", "1", "--head", head)
        self.assertEqual(merged.returncode, 0, merged.stderr)
        self.assertIn("(scripts/dev/preflight.sh); the run qualifies it, but no receipt",
                      merged.stderr)
        main = self.git(self.author, "rev-parse", "main")
        tree = self.git(checkout, "merge-tree", "--write-tree", head, main)
        attested = self.attest(head, {"main": main, "tree": tree})
        self.assertEqual(attested.returncode, 1)
        self.assertIn("trust-path-changed", attested.stderr)
        self.assertIn("changed: scripts/dev/preflight.sh", attested.stderr)
        self.assertNotIn("CODEWIRE_MERGE_CHECK_BINDING", attested.stdout)

    def test_the_receipt_job_refuses_what_it_cannot_confirm(self) -> None:
        head = self.open_pull_request()
        facts = self.merge(head)
        other_tree = self.git(self.author, "rev-parse", f"{head}^{{tree}}")
        off_main = self.commit(self.author, "elsewhere.txt", "never pushed\n")
        self.git(self.author, "push", "--quiet", "origin", f"{off_main}:refs/heads/side")
        cases = [
            ("merge-check-failure", facts, "failure"),
            ("merge-check-cancelled", facts, "cancelled"),
            ("tree-mismatch", {**facts, "tree": other_tree}, "success"),
            ("main-not-canonical", {**facts, "main": off_main}, "success"),
        ]
        for index, (reason, inputs, result) in enumerate(cases):
            attested = self.attest(head, inputs, result, name=f"receipt-{index}")
            self.assertEqual(attested.returncode, 1, reason)
            self.assertIn(reason, attested.stderr)
            self.assertNotIn("CODEWIRE_MERGE_CHECK_BINDING", attested.stdout)

    # -- merger side -----------------------------------------------------------

    def test_verify_passes_for_the_current_head_and_main(self) -> None:
        head = self.open_pull_request()
        facts, log = self.run_ci(head)
        self.serve_run(head, log)
        status, fields = self.verify()
        self.assertEqual(status, 0, fields)
        self.assertEqual(fields["ci_merge_check"], "pass")
        self.assertEqual((fields["head"], fields["main"], fields["tree"]),
                         (head, facts["main"], facts["tree"]))
        calls = (self.state / "calls").read_text().splitlines()
        self.assertIn(f"--head {head}", calls[0])
        self.assertIn("--workflow merge-check.yaml", calls[0])
        self.assertEqual(calls[2], "actions runs logs 77 --job 901")

    def test_verify_fails_when_main_moved_and_says_whether_it_overlaps(self) -> None:
        head = self.open_pull_request()
        _, log = self.run_ci(head)
        self.serve_run(head, log)
        self.commit(self.author, "elsewhere.txt", "unrelated\n")
        self.git(self.author, "push", "--quiet", "origin", "main")
        status, fields = self.verify()
        self.assertEqual((status, fields["reason"]), (1, "main-moved"))
        self.assertEqual(fields["main_moved_overlaps_change"], "false")
        self.commit(self.author, "feature.txt", "main also edits it\n")
        self.git(self.author, "push", "--quiet", "origin", "main")
        status, fields = self.verify()
        self.assertEqual((status, fields["reason"]), (1, "main-moved"))
        self.assertEqual(fields["main_moved_overlaps_change"], "true")

    def test_verify_fails_when_the_head_moved(self) -> None:
        head = self.open_pull_request()
        _, log = self.run_ci(head)
        self.serve_run(head, log)
        self.git(self.author, "checkout", "--quiet", "feature")
        self.commit(self.author, "feature.txt", "a later push\n")
        self.git(self.author, "push", "--quiet", "--force", "origin", "HEAD:refs/pull/1/head")
        status, fields = self.verify()
        self.assertEqual((status, fields["reason"]), (1, "no-run-for-head"))

    def test_verify_reports_pending_and_failed_runs_and_a_failed_receipt_job(self) -> None:
        head = self.open_pull_request()
        _, log = self.run_ci(head)
        for status, reason in (("running", "run-pending"), ("waiting", "run-pending"),
                               ("failure", "run-failure"), ("cancelled", "run-cancelled")):
            self.serve_run(head, log, status=status)
            code, fields = self.verify()
            self.assertEqual((code, fields["reason"]), (1, reason), status)
        self.serve_run(head, log, receipt_status="failure")
        code, fields = self.verify()
        self.assertEqual((code, fields["reason"]), (1, "receipt-job-not-success"))

    def test_verify_takes_the_newest_success_and_names_a_newer_pending_run(self) -> None:
        head = self.open_pull_request()
        _, log = self.run_ci(head)
        newer = {"id": 78, "number": 13, "head_sha": head, "status": "running",
                 "event": "pull_request", "ref": "#1", "url": "https://forge.invalid/runs/13"}
        other_pull = {"id": 79, "number": 14, "head_sha": head, "status": "success",
                      "event": "pull_request", "ref": "#2", "url": "https://forge.invalid/runs/14"}
        self.serve_run(head, log, extra_runs=[newer, other_pull])
        code, fields = self.verify()
        self.assertEqual(code, 0, fields)
        self.assertEqual(fields["newer_run_pending"], "https://forge.invalid/runs/13")

    def test_verify_rejects_an_injected_missing_or_altered_binding(self) -> None:
        head = self.open_pull_request()
        facts, log = self.run_ci(head)
        binding = self.binding(log)
        main = binding["main"]
        other_tree = self.git(self.author, "rev-parse", f"{head}^{{tree}}")
        # A commit subject in the receipt job's checkout log is candidate text.
        injected = "HEAD is now at 1234567 " + self.rewrite(binding, tree=other_tree)
        off_main = self.side_commit_not_on_main()
        cases = [
            ("log-binding-ambiguous", injected + log),
            ("log-binding-missing", "no binding here\n"),
            ("binding-malformed", self.rewrite(binding, pr=2)),
            ("binding-malformed", self.rewrite(binding, merge_check_result="failure")),
            ("binding-malformed", self.rewrite(binding, receipt_sha256="x")),
            ("tree-mismatch", self.rewrite(binding, tree=other_tree)),
            ("main-not-canonical", self.rewrite(binding, main=off_main)),
        ]
        for reason, changed in cases:
            self.serve_run(head, changed)
            code, fields = self.verify()
            self.assertEqual((code, fields["reason"]), (1, reason), reason)
        self.assertEqual(facts["main"], main)

    def test_verify_refuses_a_head_that_changes_the_machinery(self) -> None:
        head = self.open_pull_request("scripts/ci/select/select-verification.sh", "#!/bin/sh\n")
        main = self.git(self.author, "rev-parse", "main")
        tree = self.git(self.author, "merge-tree", "--write-tree", head, main)
        binding = {"schema": "codewire.ci-merge-check/v2", "pr": 1, "head": head, "main": main,
                   "tree": tree, "run_id": "77", "run_number": "12",
                   "merge_check_result": "success", "attested_by": main}
        self.serve_run(head, self.rewrite(binding))
        code, fields = self.verify()
        self.assertEqual((code, fields["reason"]), (1, "trust-path-changed"))

    def side_commit_not_on_main(self) -> str:
        """A commit that exists on the remote but is not on main."""
        self.git(self.author, "checkout", "--quiet", "-b", "side", "main")
        side = self.commit(self.author, "side.txt", "side\n")
        self.git(self.author, "push", "--quiet", "origin", "side")
        self.git(self.author, "checkout", "--quiet", "main")
        return side


if __name__ == "__main__":
    unittest.main(verbosity=1)
