"""verify-support-alias.py: a release accepts a support pair built for an
earlier commit only when the planner aliases exactly that pair to it (#3504).

v0.4.3 (deploy-prod run 24911) shipped a pair support-images aliased from an
earlier commit with the same base and workspace inputs, and the release
refused it because its provenance named that commit.
"""

from __future__ import annotations

import importlib.util
import io
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from test_planner import FixtureRepository, fixture_cargo_metadata, run

VERIFIER_PATH = Path(__file__).parents[1] / "verify-support-alias.py"
SPEC = importlib.util.spec_from_file_location("codewire_ci_verify_support_alias", VERIFIER_PATH)
assert SPEC and SPEC.loader
verifier = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = verifier
SPEC.loader.exec_module(verifier)

BASE_DIGEST = "sha256:" + "1" * 64
WORKSPACE_DIGEST = "sha256:" + "2" * 64


class VerifySupportAliasTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="codewire-support-alias-test-")
        self.repo = FixtureRepository(Path(self.temporary.name))
        cargo = mock.patch.object(
            verifier.planner, "cargo_metadata", side_effect=fixture_cargo_metadata
        )
        cargo.start()
        self.addCleanup(cargo.stop)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def main(self, source: str, origin: str, *digests: str) -> tuple[int, str]:
        base, workspace = digests or (BASE_DIGEST, WORKSPACE_DIGEST)
        output = io.StringIO()
        with redirect_stdout(output), redirect_stderr(output):
            status = verifier.main(
                [
                    "--repository", str(self.repo.root),
                    "--source", source,
                    "--origin", origin,
                    "--base-digest", base,
                    "--workspace-digest", workspace,
                ]
            )
        return status, output.getvalue()

    def test_pair_built_for_an_ancestor_with_the_same_support_inputs_is_its_alias(self) -> None:
        source = self.repo.change("apps/dashboard/README.md", "unrelated to the support pair\n")
        status, output = self.main(source, self.repo.base)
        self.assertEqual(status, 0, output)
        self.assertIn(f"has the base and workspace inputs of {self.repo.base}", output)

    def test_changed_base_input_is_not_an_alias(self) -> None:
        self.repo.write("images/base/entrypoint.sh", "#!/bin/sh\nset -eu\nexec \"$@\"\n", 0o755)
        source = self.repo.commit("base image change")
        status, output = self.main(source, self.repo.base)
        self.assertEqual(status, 1, output)
        self.assertIn("the support inputs differ (base affected, workspace affected)", output)

    def test_changed_workspace_input_is_not_an_alias(self) -> None:
        source = self.repo.change("images/workspace/Dockerfile", "FROM ${BASE_IMAGE_REF}\nRUN true\n")
        status, output = self.main(source, self.repo.base)
        self.assertEqual(status, 1, output)
        self.assertIn("base unaffected, workspace affected", output)

    def test_input_changed_and_reverted_in_between_is_still_an_alias(self) -> None:
        # The alias compares the two commits' inputs, not the path between them.
        self.repo.change("images/base/entrypoint.sh", "#!/bin/sh\nexit 1\n")
        source = self.repo.change("images/base/entrypoint.sh", "#!/bin/sh\nexec \"$@\"\n")
        status, output = self.main(source, self.repo.base)
        self.assertEqual(status, 0, output)

    def test_commit_that_is_not_an_ancestor_is_refused(self) -> None:
        source = self.repo.change("apps/dashboard/README.md", "head\n")
        tree = run(["git", "rev-parse", "HEAD^{tree}"], self.repo.root)
        unrelated = run(["git", "commit-tree", tree, "-m", "unrelated build"], self.repo.root)
        status, output = self.main(source, unrelated)
        self.assertEqual(status, 1, output)
        self.assertIn("not an ancestor of the exact head", output)

    def test_descendant_is_not_an_alias_of_its_ancestor(self) -> None:
        later = self.repo.change("apps/dashboard/README.md", "later\n")
        status, output = self.main(self.repo.base, later)
        self.assertEqual(status, 1, output)

    def test_invalid_arguments_are_refused(self) -> None:
        source = self.repo.change("apps/dashboard/README.md", "head\n")
        for arguments in (
            (source, source),
            (source, self.repo.base[:12]),
            (source, self.repo.base, "sha256:abc", WORKSPACE_DIGEST),
        ):
            with self.subTest(arguments=arguments):
                status, _ = self.main(*arguments)
                self.assertEqual(status, 2)

    def test_command_line_runs_from_any_directory(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(VERIFIER_PATH), "--help"],
            cwd=self.repo.root,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("--origin", completed.stdout)


if __name__ == "__main__":
    unittest.main()
