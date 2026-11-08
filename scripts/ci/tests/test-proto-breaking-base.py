#!/usr/bin/env python3
"""Exact protobuf preimages: ResolverTests in Policy; BufPreimageTests in Contracts."""
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location("proto_breaking", ROOT / "scripts/checks/proto_breaking.py")
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


class GitFixture(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="proto-base-")
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        environment = {"PATH": os.environ["PATH"], "GIT_CONFIG_GLOBAL": os.devnull,
                       "GIT_CONFIG_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0",
                       "GIT_AUTHOR_NAME": "Synthetic", "GIT_COMMITTER_NAME": "Synthetic",
                       "GIT_AUTHOR_EMAIL": "synthetic@example.invalid",
                       "GIT_COMMITTER_EMAIL": "synthetic@example.invalid"}
        if os.environ.get("BUF"):
            environment["BUF"] = os.environ["BUF"]
        patch = mock.patch.dict(os.environ, environment, clear=True)
        patch.start()
        self.addCleanup(patch.stop)

    def git(self, directory, *arguments, check=True):
        return subprocess.run(["git", *arguments], cwd=directory, capture_output=True,
                              text=True, check=check, timeout=10)

    def graph(self, *, breaking=False):
        source = self.work / "source"
        source.mkdir()
        self.git(source, "init", "-q", "-b", "main")
        proto = source / "proto"
        proto.mkdir()
        (proto / "buf.yaml").write_text("version: v1\nbreaking:\n  use:\n    - FILE\n")
        schema = proto / "codewire/v1/fixture.proto"
        schema.parent.mkdir(parents=True)
        ledger = source / "scripts/checks/contracts/proto-breaking-preimages.sha256"
        ledger.parent.mkdir(parents=True)
        ledger.write_text("# synthetic immutable preimage ledger\n")

        def commit(message, field):
            schema.write_text('syntax = "proto3";\npackage codewire.v1;\nmessage Value { '
                              + ("string kept = 1;" if field else "") + " }\n")
            self.git(source, "add", "proto", "scripts")
            self.git(source, "commit", "--allow-empty", "-qm", message)
            return self.git(source, "rev-parse", "HEAD").stdout.strip()

        self.anchor = commit("synthetic anchor", not breaking)
        self.before = commit("synthetic previous main", True)
        self.git(source, "checkout", "-q", "-B", "rewritten", self.anchor)
        self.head = commit("synthetic replacement main", not breaking)
        remote = self.work / "remote.git"
        self.git(self.work, "clone", "-q", "--bare", str(source), str(remote))
        self.git(self.work, "--git-dir", str(remote), "update-ref", "refs/heads/main", self.head)
        self.git(self.work, "--git-dir", str(remote), "update-ref", "-d", "refs/heads/rewritten")
        self.target = self.work / "target"
        self.git(self.work, "clone", "-q", "--no-local", "--single-branch", "--branch", "main",
                 str(remote), str(self.target))
        self.assertNotEqual(self.git(self.target, "cat-file", "-e", self.before + "^{commit}",
                                    check=False).returncode, 0)
        for name, value in (("ROOT", self.target), ("PREIMAGES", self.target / ledger.relative_to(source))):
            patch = mock.patch.object(policy, name, value)
            patch.start()
            self.addCleanup(patch.stop)


class ResolverTests(GitFixture):
    def test_present_base_needs_no_fetch_or_timeout_tool(self):
        self.graph()
        self.git(self.target, "remote", "remove", "origin")
        with mock.patch.object(policy.shutil, "which", side_effect=AssertionError("unexpected fetch")):
            self.assertEqual(policy.resolve_base("HEAD"), self.head)

    def test_missing_nonancestor_is_fetched_without_ref_or_fetch_head_changes(self):
        self.graph()
        refs = self.git(self.target, "for-each-ref").stdout
        fetch_head = self.target / ".git/FETCH_HEAD"
        previous = fetch_head.read_bytes() if fetch_head.exists() else None
        self.assertEqual(policy.resolve_base(self.before), self.before)
        self.assertEqual(self.git(self.target, "for-each-ref").stdout, refs)
        self.assertEqual(fetch_head.read_bytes() if fetch_head.exists() else None, previous)
        self.assertEqual(self.git(self.target, "merge-base", "--is-ancestor", self.before, "HEAD",
                                  check=False).returncode, 1)

    def test_unavailable_exact_object_fails_closed(self):
        self.graph()
        with self.assertRaisesRegex(policy.PolicyError, "unavailable from origin"):
            policy.resolve_base("f" * 40)

    def test_missing_remote_fails_closed(self):
        self.graph()
        self.git(self.target, "remote", "remove", "origin")
        with self.assertRaisesRegex(policy.PolicyError, "unavailable from origin"):
            policy.resolve_base(self.before)

    def test_unavailable_non_sha_never_fetches(self):
        self.graph()
        with mock.patch.object(policy.shutil, "which", side_effect=AssertionError("unexpected fetch")):
            with self.assertRaisesRegex(policy.PolicyError, "exact commit SHA"):
                policy.resolve_base("missing-branch")

    def test_timeout_is_bounded_and_does_not_choose_another_base(self):
        self.graph()
        with mock.patch.object(policy.subprocess, "run", side_effect=[
            subprocess.CompletedProcess([], 1, stdout=""), subprocess.CompletedProcess([], 124),
        ]) as calls, mock.patch.object(policy.shutil, "which", return_value="/synthetic/timeout"):
            with self.assertRaisesRegex(policy.PolicyError, "unavailable from origin"):
                policy.resolve_base(self.before)
        self.assertEqual(calls.call_count, 2)
        command = calls.call_args_list[1].args[0]
        self.assertEqual(command[:4], ["/synthetic/timeout", "--signal=TERM", "--kill-after=5s", "60s"])
        self.assertEqual(command[-2:], ["origin", self.before])


class BufPreimageTests(GitFixture):
    def test_identical_tree_rewrite_uses_exact_fetched_preimage(self):
        self.graph()
        policy.run_breaking(self.before)
        self.assertEqual(self.git(self.target, "rev-parse", self.before + "^{tree}").stdout,
                         self.git(self.target, "rev-parse", "HEAD^{tree}").stdout)

    def test_rewritten_field_removal_is_still_breaking(self):
        self.graph(breaking=True)
        with self.assertRaises(subprocess.CalledProcessError) as error:
            policy.run_breaking(self.before)
        self.assertEqual(error.exception.returncode, 100)
        # Comparing to HEAD's parent would wrongly accept this rewritten deletion.
        policy.run_breaking(self.anchor)


if __name__ == "__main__":
    unittest.main(verbosity=2)
