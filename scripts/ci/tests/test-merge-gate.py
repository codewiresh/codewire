#!/usr/bin/env python3
"""What the merge gate requires comes from one table (owner, 2026-10-21).

Tests of scripts/ci/select/merge-gate.tsv and its reader, of
scripts/dev/preflight.sh honouring it, and of the verified-base override.

Old behaviour: the gate's requirements were spread over the selector's local
mode, preflight's family list and AGENTS.md prose; a Kind-relevant change set
the local mode to kind, and a plain preflight run exited 3 asking for --kind.
Selection always came from the merge-base with main, so a rewritten branch
that reproduces a verified main with one changed line ran every family.

New behaviour: preflight runs a selected family only when the table marks it
required before merge, reports the others with the table's reason, and fails
closed on a family without a row. Kind is marked not required. An explicit
PREFLIGHT_VERIFIED_BASE that its own main CI verified is compared tree to
tree; anything unverified falls back to the merge-base.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts/ci/plan/tests"))
import verdict_fixtures as fx  # noqa: E402


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


gate = load("codewire_merge_gate", ROOT / "scripts/ci/select/merge-gate.py")
verified_base = load("codewire_verified_base", ROOT / "scripts/ci/plan/verified-base.py")

PREFLIGHT = ROOT / "scripts/dev/preflight.sh"
GIT_ENV = {"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}


def preflight_families() -> set[str]:
    """Every family preflight asks the table about."""
    text = PREFLIGHT.read_text()
    families = set(re.findall(r"^run_selected_family ([a-z_]+) ", text, re.M))
    families |= set(re.findall(r"gate_runs ([a-z_]+)", text))
    families.discard("family")
    return families


class GateTable(unittest.TestCase):
    def test_every_preflight_family_has_exactly_one_row_and_no_row_is_stale(self) -> None:
        rows = gate.load()
        self.assertEqual(set(rows), preflight_families())

    def test_kind_is_never_required_before_merge(self) -> None:
        kind = gate.load()["kind"]
        self.assertFalse(kind.before_merge)
        self.assertIn("Remove the pre-flight gate that says to run a kind cluster", kind.reason)

    def test_malformed_tables_fail_closed(self) -> None:
        cases = {
            "two fields": "policy\tyes\n",
            "not yes or no": "policy\tmaybe\twhy\n",
            "no reason": "policy\tyes\t \n",
            "duplicate": "policy\tyes\ta\npolicy\tno\tb\n",
            "bad family": "Policy\tyes\ta\n",
            "empty": "# only a comment\n",
        }
        for name, body in cases.items():
            with self.subTest(name), tempfile.TemporaryDirectory() as temporary:
                table = Path(temporary) / "merge-gate.tsv"
                table.write_text(body)
                with self.assertRaises(gate.GateError):
                    gate.load(table)

    def test_a_family_without_a_row_fails_closed(self) -> None:
        with self.assertRaisesRegex(gate.GateError, "has no row"):
            gate.decide(gate.load(), "not_a_family")
        completed = subprocess.run(
            [sys.executable, str(ROOT / "scripts/ci/select/merge-gate.py"), "decide", "not_a_family"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(completed.returncode, 2)

    def test_decide_prints_the_reason_of_a_family_that_is_not_required(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(ROOT / "scripts/ci/select/merge-gate.py"), "decide", "kind"],
            capture_output=True, text=True, check=True,
        )
        self.assertTrue(completed.stdout.startswith("no\tPost-merge CI"))


class PreflightSandbox(unittest.TestCase):
    """scripts/dev/preflight.sh in a scratch repository with stub families."""

    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory(prefix="codewire-merge-gate-test-")
        self.root = Path(self.directory.name)
        self.calls = self.root / "calls.log"
        for relative in ("scripts/dev/preflight.sh", "scripts/ci/select/merge-gate.py",
                         "scripts/ci/select/merge-gate.tsv"):
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, target)
        self.stub("scripts/dev/preflight-environment.sh", 'exit 0')
        self.stub("scripts/ci/verify/run-product-verification.sh",
                  'printf "product %s\\n" "$1" >> "$CALLS"')
        self.stub("scripts/ci/verify/run-integration-verification.sh",
                  'printf "integration %s\\n" "$1" >> "$CALLS"')
        self.stub("scripts/ci/verify/kind-e2e.sh", 'printf "kind-e2e\\n" >> "$CALLS"')
        # The selector echoes a fixed selection and records the paths it got.
        self.stub("scripts/ci/select/select-verification.sh", textwrap.dedent('''\
            if [ -n "${1:-}" ]; then sed 's/^/path /' "$1" >> "$CALLS"; fi
            printf 'selector KIND_E2E_OPT_IN=%s\\n' "${KIND_E2E_OPT_IN:-}" >> "$CALLS"
            printf 'selector_version=v3\\nclassification=changed\\nrequired_local_mode=default\\n'
            printf 'selection=%s\\n' "$STUB_SELECTION"
            '''))
        self.stub("scripts/ci/plan/verified-base.py", textwrap.dedent('''\
            import os, sys
            if sys.argv[1] == os.environ.get("STUB_VERIFIED", ""):
                print(f"verified_base={sys.argv[1]}\\nevidence=main-ci:17252")
                sys.exit(0)
            print("verified base: main CI verdict: not verified", file=sys.stderr)
            sys.exit(1)
            '''), python=True)
        self.git("init", "-q")
        self.git("add", "-A")
        self.commit("old main")
        self.git("update-ref", "refs/remotes/origin/main", "HEAD")

    def tearDown(self) -> None:
        self.directory.cleanup()

    def stub(self, relative: str, body: str, python: bool = False) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        shebang = "#!/usr/bin/env python3\n" if python else "#!/usr/bin/env bash\nset -euo pipefail\n"
        path.write_text(shebang + body + "\n")
        path.chmod(0o755)

    def git(self, *args: str) -> str:
        return subprocess.run(["git", *args], cwd=self.root, env={**os.environ, **GIT_ENV},
                              check=True, capture_output=True, text=True).stdout.strip()

    def commit(self, message: str) -> str:
        self.git("-c", "user.name=t", "-c", "user.email=t@example.invalid",
                 "-c", "commit.gpgsign=false", "commit", "-q", "--allow-empty", "-m", message)
        return self.git("rev-parse", "HEAD")

    def preflight(self, selection: str, changed: str | None = "Caddyfile\n",
                  **environment: str) -> subprocess.CompletedProcess[str]:
        env = {**os.environ, **GIT_ENV, "CALLS": str(self.calls), "STUB_SELECTION": selection,
               **environment}
        env.pop("CODEWIRE_PREFLIGHT_MODE", None)
        if changed is not None:
            changes = self.root / "changed.txt"
            changes.write_text(changed)
            env["PREFLIGHT_CHANGED_FILES"] = str(changes)
        return subprocess.run(["bash", str(self.root / "scripts/dev/preflight.sh")],
                              cwd=self.root, env=env, capture_output=True, text=True, check=False)

    def calls_log(self) -> list[str]:
        return self.calls.read_text().splitlines() if self.calls.exists() else []

    def test_kind_is_selected_but_reported_and_never_run(self) -> None:
        result = self.preflight("|valid:v3|edge_kind|kind|policy|complete|")
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.calls_log()
        self.assertIn("selector KIND_E2E_OPT_IN=true", calls)
        self.assertIn("product policy", calls)
        self.assertIn("product edge", calls)
        self.assertNotIn("kind-e2e", calls)
        self.assertRegex(result.stdout, r"kind is not required before merge \(scripts/ci/select/"
                                        r"merge-gate.tsv\): Post-merge CI on metal")

    def test_flipping_a_row_changes_what_runs(self) -> None:
        table = self.root / "scripts/ci/select/merge-gate.tsv"
        text = table.read_text()
        text = re.sub(r"^kind\tno\t", "kind\tyes\t", text, flags=re.M)
        text = re.sub(r"^policy\tyes\t", "policy\tno\t", text, flags=re.M)
        table.write_text(text)
        result = self.preflight("|valid:v3|kind|policy|complete|")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("kind-e2e", self.calls_log())
        self.assertNotIn("product policy", self.calls_log())
        self.assertIn("policy is not required before merge", result.stdout)

    def test_a_selected_family_without_a_row_fails_closed(self) -> None:
        table = self.root / "scripts/ci/select/merge-gate.tsv"
        table.write_text(re.sub(r"^release\t.*\n", "", table.read_text(), flags=re.M))
        result = self.preflight("|valid:v3|release|complete|")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("family release has no row in scripts/ci/select/merge-gate.tsv", result.stderr)

    def test_a_malformed_table_stops_preflight(self) -> None:
        (self.root / "scripts/ci/select/merge-gate.tsv").write_text("policy\tsometimes\twhy\n")
        result = self.preflight("|valid:v3|policy|complete|")
        self.assertEqual(result.returncode, 2)
        self.assertIn("merge-gate.tsv is unusable", result.stderr)

    def test_kind_is_no_longer_a_mode(self) -> None:
        result = subprocess.run(["bash", str(self.root / "scripts/dev/preflight.sh"), "--kind"],
                                cwd=self.root, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("--kind", (self.root / "scripts/dev/preflight.sh").read_text().split(
            "PREFLIGHT_MODE=\"${CODEWIRE_PREFLIGHT_MODE:-default}\"")[0])

    def rewritten_branch(self) -> tuple[str, str]:
        """An old main touching many paths, and an unrelated rewrite of it with one change."""
        for name in ("Caddyfile", "web.ts", "lib.rs"):
            (self.root / name).write_text("same\n")
        self.git("add", "-A")
        old_main = self.commit("old main with files")
        self.git("checkout", "-q", "--orphan", "rewritten")
        (self.root / "lib.rs").write_text("one comment line changed\n")
        self.git("add", "-A")
        head = self.commit("rewritten history")
        return old_main, head

    def test_a_verified_base_selects_from_its_tree(self) -> None:
        old_main, _ = self.rewritten_branch()
        result = self.preflight("|valid:v3|rust|complete|", changed=None,
                                PREFLIGHT_VERIFIED_BASE=old_main, STUB_VERIFIED=old_main)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"selecting from verified base {old_main} (main-ci:17252)", result.stdout)
        self.assertEqual([call for call in self.calls_log() if call.startswith("path ")],
                         ["path lib.rs"])

    def test_an_unverified_base_falls_back_to_the_merge_base(self) -> None:
        # origin/main is still the first, empty commit: the fallback compares
        # with it and sees every file, not just the rewrite's one change.
        old_main, _ = self.rewritten_branch()
        result = self.preflight("|valid:v3|rust|complete|", changed=None,
                                PREFLIGHT_VERIFIED_BASE=old_main, STUB_VERIFIED="0" * 40)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("is not verified; selecting from the merge-base with main", result.stderr)
        paths = [call for call in self.calls_log() if call.startswith("path ")]
        self.assertEqual(paths, ["path Caddyfile", "path lib.rs", "path web.ts"])


class VerifiedBase(unittest.TestCase):
    """verified-base.py reads main CI's verdict through fj, by Dev delivery's predicate."""

    SHA = "1" * 40
    TREE = "2" * 40

    def fj(self, required: str = "success", log: str | None = None):
        run = {"id": 41, "head_sha": self.SHA, "workflow": "ci.yaml", "event": "push",
               "ref": "main", "status": "success"}
        jobs = [{"id": job["id"], "run_id": 41, "name": job["name"], "status": job["status"],
                 "attempt": job["attempt"]} for job in fx.ci_jobs(41, required=required)]
        logs = {fx.required_job_id(41): log if log is not None
                else fx.log_lines(fx.marker(self.SHA, self.TREE, run_id=41))}
        seen: list[list[str]] = []

        def runner(arguments: list[str]) -> str:
            seen.append(arguments)
            if arguments[:3] == ["actions", "runs", "list"]:
                return json.dumps({"schema_version": 1, "runs": [run]})
            if arguments[:3] == ["actions", "runs", "view"]:
                return json.dumps({"schema_version": 1, "run": run, "jobs": jobs})
            if arguments[:3] == ["actions", "runs", "logs"]:
                return logs[int(arguments[arguments.index("--job") + 1])]
            raise AssertionError(arguments)

        return verified_base.FjForgejo(fx.REPOSITORY, runner), seen

    def test_a_verified_main_commit_is_accepted_with_its_run(self) -> None:
        api, seen = self.fj()
        self.assertEqual(verified_base.verify(self.SHA, api, lambda _: self.TREE), (True, "main-ci:41"))
        self.assertIn(["actions", "runs", "list", "--head", self.SHA, "--workflow", "ci.yaml",
                       "-L", "100", "--output", "json"], seen)

    def test_anything_short_of_verified_is_refused(self) -> None:
        superseded = fx.log_lines(f"main CI verdict: not verified; superseded by {'9' * 40}")
        for name, api in {
            "red": self.fj(required="failure")[0],
            "pending": self.fj(required="running")[0],
            "superseded": self.fj(log=superseded)[0],
            "marker for another tree": self.fj(log=fx.log_lines(fx.marker(self.SHA, "3" * 40, run_id=41)))[0],
        }.items():
            with self.subTest(name):
                verified, _ = verified_base.verify(self.SHA, api, lambda _: self.TREE)
                self.assertFalse(verified)

    def test_unreadable_or_malformed_input_is_refused(self) -> None:
        def broken(arguments: list[str]) -> str:
            raise verified_base.verdicts.Unproven("fj-failed")

        verified, detail = verified_base.verify(
            self.SHA, verified_base.FjForgejo(fx.REPOSITORY, broken), lambda _: self.TREE)
        self.assertFalse(verified)
        self.assertIn("unreadable", detail)
        self.assertEqual(verified_base.verify("main", None, lambda _: self.TREE)[0], False)


if __name__ == "__main__":
    unittest.main(verbosity=1)
