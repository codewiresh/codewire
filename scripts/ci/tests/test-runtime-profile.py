#!/usr/bin/env python3
"""The one runtime Cargo profile every image builds is a single knob.

It is written out in both manifests an image builds from: the workspace
Cargo.toml and the curated DERP manifest. The two tables must be equal, must
inherit only release, and must set every key [profile.release] sets, so a
change to [profile.ci] or [profile.release] never reaches an image.
"""

from pathlib import Path
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[3]
MANIFESTS = ("Cargo.toml", "deployments/docker/derp.Cargo.toml")


def runtime_profile_problems(manifests):
    """Return what keeps the named manifests from sharing one runtime profile."""
    problems, tables = [], {}
    for name, data in manifests.items():
        profiles = data.get("profile", {})
        runtime = profiles.get("runtime")
        if not isinstance(runtime, dict):
            problems.append(f"{name} has no [profile.runtime]")
            continue
        tables[name] = runtime
        if runtime.get("inherits") != "release":
            problems.append(f"{name} [profile.runtime] must inherit release, not {runtime.get('inherits')!r}")
        inherited = sorted(set(profiles.get("release", {})) - set(runtime))
        if inherited:
            problems.append(f"{name} [profile.runtime] inherits {', '.join(inherited)} from [profile.release]")
    first = next(iter(tables.items()), None)
    for name, table in tables.items():
        if table != first[1]:
            problems.append(f"{name} [profile.runtime] differs from {first[0]}")
    return problems


def manifest(**profiles):
    return {"profile": profiles}


RUNTIME = {"inherits": "release", "lto": False, "codegen-units": 16, "strip": True}
RELEASE = {"lto": True, "codegen-units": 1, "strip": True}


class RuntimeProfileTests(unittest.TestCase):
    def test_repository_manifests_share_one_runtime_profile(self):
        manifests = {name: tomllib.loads((ROOT / name).read_text()) for name in MANIFESTS}
        self.assertEqual(runtime_profile_problems(manifests), [])

    def test_equal_tables_pass(self):
        self.assertEqual(runtime_profile_problems({
            "a": manifest(release=RELEASE, runtime=RUNTIME),
            "b": manifest(release=RELEASE, runtime=dict(RUNTIME)),
        }), [])

    def test_a_differing_value_fails(self):
        problems = runtime_profile_problems({
            "a": manifest(release=RELEASE, runtime=RUNTIME),
            "b": manifest(release=RELEASE, runtime=RUNTIME | {"lto": "thin"}),
        })
        self.assertEqual(problems, ["b [profile.runtime] differs from a"])

    def test_a_key_only_one_table_sets_fails(self):
        problems = runtime_profile_problems({
            "a": manifest(release=RELEASE, runtime=RUNTIME | {"debug": 1}),
            "b": manifest(release=RELEASE, runtime=RUNTIME),
        })
        self.assertEqual(problems, ["b [profile.runtime] differs from a"])

    def test_a_missing_table_fails(self):
        problems = runtime_profile_problems({
            "a": manifest(release=RELEASE, runtime=RUNTIME),
            "b": manifest(release=RELEASE),
        })
        self.assertEqual(problems, ["b has no [profile.runtime]"])

    def test_inheriting_ci_fails_even_when_both_agree(self):
        ci = RUNTIME | {"inherits": "ci"}
        problems = runtime_profile_problems({
            "a": manifest(release=RELEASE, runtime=ci),
            "b": manifest(release=RELEASE, runtime=ci),
        })
        self.assertEqual(problems, ["a [profile.runtime] must inherit release, not 'ci'",
                                    "b [profile.runtime] must inherit release, not 'ci'"])

    def test_a_release_key_the_runtime_table_leaves_inherited_fails(self):
        problems = runtime_profile_problems({
            "a": manifest(release=RELEASE | {"panic": "abort"}, runtime=RUNTIME),
            "b": manifest(release=RELEASE, runtime=RUNTIME),
        })
        self.assertEqual(problems, ["a [profile.runtime] inherits panic from [profile.release]"])

    def test_the_retired_thin_lto_tables_fail(self):
        # The tables before #2892 left strip to [profile.release].
        retired = {"inherits": "release", "lto": "thin", "codegen-units": 16}
        problems = runtime_profile_problems({
            "a": manifest(release=RELEASE, runtime=retired),
            "b": manifest(release=RELEASE, runtime=retired),
        })
        self.assertEqual(problems, ["a [profile.runtime] inherits strip from [profile.release]",
                                    "b [profile.runtime] inherits strip from [profile.release]"])


if __name__ == "__main__":
    unittest.main()
