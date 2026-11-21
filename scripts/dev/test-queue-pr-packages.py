#!/usr/bin/env python3
"""Tests for queue_pr_packages.py: which packages queue-pr.sh checks."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from queue_pr_packages import packages  # noqa: E402


def package(name, path, deps=()):
    return {
        "id": f"path+file:///w/{path}#{name}@0.1.0",
        "name": name,
        "manifest_path": f"/w/{path}/Cargo.toml",
        "dependencies": [{"name": d, "path": f"/w/{p}"} for d, p in deps] + [{"name": "serde"}],
    }


METADATA = {
    "workspace_root": "/w",
    "packages": [
        package("broker", "crates/broker"),
        package("cli", "crates/cli", [("broker", "crates/broker")]),
        package("cli-macros", "crates/cli/macros"),
        package("daemon", "crates/daemon", [("cli-macros", "crates/cli/macros")]),
        package("store", "libs/store"),
    ],
}
METADATA["workspace_members"] = [p["id"] for p in METADATA["packages"]]


class Packages(unittest.TestCase):
    def test_only_the_touched_package_by_default(self):
        # #5512's shape: the broker itself, which is where its skew failed.
        self.assertEqual(packages(METADATA, ["crates/broker/src/runtime.rs"]), ["broker"])

    def test_direct_dependents_when_asked(self):
        self.assertEqual(packages(METADATA, ["crates/broker/src/runtime.rs"], True), ["broker", "cli"])

    def test_a_nested_package_owns_its_own_files(self):
        self.assertEqual(packages(METADATA, ["crates/cli/macros/src/lib.rs"]), ["cli-macros"])
        self.assertEqual(packages(METADATA, ["crates/cli/macros/src/lib.rs"], True), ["cli-macros", "daemon"])

    def test_no_rust_package_touched_checks_nothing(self):
        self.assertEqual(packages(METADATA, ["docs/dev/x.md", "scripts/ci/a.sh", "Cargo.lock"]), [])

    def test_a_dependent_that_is_also_touched_is_listed_once(self):
        self.assertEqual(packages(METADATA, ["crates/broker/a.rs", "crates/cli/b.rs"], True), ["broker", "cli"])

    def test_packages_outside_crates_count(self):
        self.assertEqual(packages(METADATA, ["libs/store/src/lib.rs"]), ["store"])


if __name__ == "__main__":
    unittest.main()
