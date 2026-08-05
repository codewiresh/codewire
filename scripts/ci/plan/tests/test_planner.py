from __future__ import annotations

import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock


PLANNER_PATH = Path(__file__).parents[1] / "planner.py"
SPEC = importlib.util.spec_from_file_location("codewire_ci_planner", PLANNER_PATH)
assert SPEC and SPEC.loader
planner = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = planner
SPEC.loader.exec_module(planner)


def run(argv: list[str], cwd: Path) -> str:
    completed = subprocess.run(argv, cwd=cwd, text=True, capture_output=True, check=False)
    if completed.returncode:
        raise AssertionError(f"command failed: {argv}\n{completed.stderr}")
    return completed.stdout.strip()


class FixtureRepository:
    def __init__(self, root: Path):
        self.root = root
        self._write_policy()
        self._write_workspace()
        run(["git", "init", "-q"], root)
        run(["git", "config", "user.name", "CI fixture"], root)
        run(["git", "config", "user.email", "ci-fixture@codewire.invalid"], root)
        self.base = self.commit("fixture baseline")

    def write(self, relative: str, content: str, mode: int | None = None) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        if mode is not None:
            path.chmod(mode)

    def _write_policy(self) -> None:
        policy_root = self.root / "scripts/ci/plan"
        (policy_root / "schemas").mkdir(parents=True)
        shutil.copy2(PLANNER_PATH, policy_root / "planner.py")
        shutil.copy2(PLANNER_PATH.parent / "apply-support-plan.py", policy_root / "apply-support-plan.py")
        images_root = self.root / "scripts/ci/images"
        images_root.mkdir(parents=True)
        shutil.copy2(
            PLANNER_PATH.parents[1] / "images" / "resolve-published-support-pair.sh",
            images_root / "resolve-published-support-pair.sh",
        )
        workflow_root = self.root / ".gitea/workflows"
        workflow_root.mkdir(parents=True)
        shutil.copy2(
            PLANNER_PATH.parents[3] / ".gitea" / "workflows" / "support-images.yaml",
            workflow_root / "support-images.yaml",
        )
        for name in ("baseline.schema.json", "plan.schema.json"):
            shutil.copy2(PLANNER_PATH.parent / "schemas" / name, policy_root / "schemas" / name)
        graph = {
            "schema": "codewire.ci-artifact-graph/v1",
            "policy_files": [
                ".gitea/workflows/support-images.yaml",
                "scripts/ci/images/resolve-published-support-pair.sh",
                "scripts/ci/plan/apply-support-plan.py",
                "scripts/ci/plan/artifact-graph.json",
                "scripts/ci/plan/planner.py",
                "scripts/ci/plan/schemas/baseline.schema.json",
                "scripts/ci/plan/schemas/plan.schema.json",
            ],
            "artifacts": {
                "cw_cli_release_assets": {
                    "kind": "rust-package",
                    "manifest": "Cargo.toml",
                    "package": "cli-bin",
                    "lockfile": "Cargo.lock",
                    "profiles": ["release"],
                    "release_targets": ["one", "two", "three", "four"],
                    "package_inputs": {"core": ["generated/descriptor.bin"]},
                    "explicit_inputs": ["scripts/ci/release/package-cli.sh"],
                },
                "desktop_package": {
                    "kind": "rust-package",
                    "manifest": "desktop/Cargo.toml",
                    "package": "desktop",
                    "lockfile": "desktop/Cargo.lock",
                    "profiles": ["release"],
                    "release_targets": ["host"],
                    "package_inputs": {"core": ["generated/descriptor.bin"]},
                    "explicit_inputs": ["desktop/LICENSE"],
                },
                "workspace_cw_binary": {
                    "kind": "rust-package",
                    "manifest": "Cargo.toml",
                    "package": "cli-bin",
                    "lockfile": "Cargo.lock",
                    "profiles": ["release"],
                    "release_targets": ["host"],
                    "package_inputs": {"core": ["generated/descriptor.bin"]},
                    "explicit_inputs": [],
                },
                "dashboard_image": {
                    "kind": "file-set",
                    "inputs": [
                        ".dockerignore",
                        "Cargo.toml",
                        "Cargo.lock",
                        "LICENSE",
                        "apps/cli/install.sh",
                        "apps/dashboard/Dockerfile",
                        "apps/dashboard/runtime-inventory.json",
                        "apps/docs/zola/**",
                        "crates/**",
                        "libs/gateway-proto/**",
                        "packages/codewire-design/**",
                        "proto/**",
                    ],
                },
                "gateway_image": {
                    "kind": "file-set",
                    "inputs": [
                        "Cargo.toml",
                        "Cargo.lock",
                        "crates/**",
                        "deployments/docker/gateway.Cargo.lock",
                        "deployments/docker/gateway.Cargo.toml",
                        "deployments/docker/gateway.Dockerfile",
                        "deployments/docker/gateway.Dockerfile.dockerignore",
                        "libs/gateway-proto/**",
                        "proto/**",
                    ],
                },
                "derp_image": {
                    "kind": "file-set",
                    "inputs": [
                        "crates/codewire-derp/**",
                        "crates/codewire-proto/**",
                        "crates/codewire-tailnet/**",
                        "deployments/docker/derp.Cargo.lock",
                        "deployments/docker/derp.Cargo.toml",
                        "deployments/docker/derp.Dockerfile",
                        "deployments/docker/derp.Dockerfile.dockerignore",
                        "proto/**",
                    ],
                },
                "services_image": {
                    "kind": "file-set",
                    "inputs": [
                        "Cargo.toml",
                        "Cargo.lock",
                        "crates/**",
                        "deployments/docker/services.Dockerfile",
                        "deployments/docker/services.Dockerfile.dockerignore",
                        "libs/gateway-proto/**",
                        "proto/**",
                    ],
                },
                "mesh_image": {
                    "kind": "file-set",
                    "inputs": [
                        "Cargo.toml",
                        "Cargo.lock",
                        "crates/**",
                        "deployments/docker/mesh.Dockerfile",
                        "deployments/docker/mesh.Dockerfile.dockerignore",
                        "proto/**",
                    ],
                },
                "base_image": {
                    "kind": "file-set",
                    "inputs": ["images/base/**"],
                },
                "workspace_image": {
                    "kind": "composite",
                    "dependencies": ["base_image", "workspace_cw_binary"],
                    "inputs": ["images/workspace/**"],
                },
            },
        }
        self.write("scripts/ci/plan/artifact-graph.json", json.dumps(graph, sort_keys=True, indent=2) + "\n")

    def _write_workspace(self) -> None:
        self.write(
            "Cargo.toml",
            """[workspace]
members = ["cli", "core", "build-helper", "optional-helper", "target-helper", "billing", "admin-proto", "unrelated"]
exclude = ["desktop"]
resolver = "2"

[profile.release]
lto = true
""",
        )
        self.write(
            "cli/Cargo.toml",
            """[package]
name = "cli-bin"
version = "0.1.0"
edition = "2021"
build = "build.rs"

[dependencies]
renamed-core = { package = "core", path = "../core" }
optional-helper = { path = "../optional-helper", optional = true }

[features]
optional-feature = ["dep:optional-helper"]

[target.'cfg(unix)'.dependencies]
target-helper = { path = "../target-helper" }

[build-dependencies]
build-helper = { path = "../build-helper" }

[dev-dependencies]
unrelated = { path = "../unrelated" }
""",
        )
        self.write("cli/src/main.rs", "fn main() { renamed_core::run(); }\n")
        self.write("cli/build.rs", "fn main() {}\n")
        self.write("cli/tests/cli.rs", "#[test] fn smoke() {}\n")
        self.write(
            "core/Cargo.toml",
            """[package]
name = "core"
version = "0.1.0"
edition = "2021"
""",
        )
        self.write("core/src/lib.rs", "pub fn run() {}\n")
        self.write(
            "build-helper/Cargo.toml",
            """[package]
name = "build-helper"
version = "0.1.0"
edition = "2021"
""",
        )
        self.write("build-helper/src/lib.rs", "pub fn emit() {}\n")
        self.write(
            "optional-helper/Cargo.toml",
            """[package]
name = "optional-helper"
version = "0.1.0"
edition = "2021"
""",
        )
        self.write("optional-helper/src/lib.rs", "pub fn optional() {}\n")
        self.write(
            "target-helper/Cargo.toml",
            """[package]
name = "target-helper"
version = "0.1.0"
edition = "2021"
""",
        )
        self.write("target-helper/src/lib.rs", "pub fn target() {}\n")
        self.write(
            "admin-proto/Cargo.toml",
            """[package]
name = "admin-proto"
version = "0.1.0"
edition = "2021"
""",
        )
        self.write("admin-proto/src/lib.rs", "pub fn admin_contract() {}\n")
        self.write(
            "billing/Cargo.toml",
            """[package]
name = "billing"
version = "0.1.0"
edition = "2021"

[dependencies]
admin-proto = { path = "../admin-proto" }
""",
        )
        self.write("billing/src/lib.rs", "pub fn bill() { admin_proto::admin_contract(); }\n")
        self.write(
            "unrelated/Cargo.toml",
            """[package]
name = "unrelated"
version = "0.1.0"
edition = "2021"
""",
        )
        self.write("unrelated/src/lib.rs", "pub fn unrelated() {}\n")
        self.write(
            "Cargo.lock",
            """# This file is automatically @generated by Cargo.
version = 4

[[package]]
name = "admin-proto"
version = "0.1.0"

[[package]]
name = "billing"
version = "0.1.0"
dependencies = ["admin-proto"]

[[package]]
name = "build-helper"
version = "0.1.0"

[[package]]
name = "cli-bin"
version = "0.1.0"
dependencies = [
 "build-helper",
 "core",
 "optional-helper",
 "target-helper",
 "unrelated",
]

[[package]]
name = "core"
version = "0.1.0"

[[package]]
name = "optional-helper"
version = "0.1.0"

[[package]]
name = "target-helper"
version = "0.1.0"

[[package]]
name = "unrelated"
version = "0.1.0"
""",
        )
        self.write(
            "desktop/Cargo.toml",
            """[package]
name = "desktop"
version = "0.1.0"
edition = "2021"

[dependencies]
core = { path = "../core" }

[profile.release]
strip = true
""",
        )
        self.write("desktop/src/main.rs", "fn main() { core::run(); }\n")
        self.write("desktop/LICENSE", "fixture license\n")
        self.write(
            "desktop/Cargo.lock",
            """# This file is automatically @generated by Cargo.
version = 4

[[package]]
name = "core"
version = "0.1.0"

[[package]]
name = "desktop"
version = "0.1.0"
dependencies = ["core"]
""",
        )
        self.write("generated/descriptor.bin", "descriptor-v1\n")
        self.write("scripts/ci/release/package-cli.sh", "#!/bin/sh\nexit 0\n", 0o755)
        self.write(".dockerignore", "target\n")
        self.write("LICENSE", "fixture license\n")
        self.write("apps/cli/install.sh", "#!/bin/sh\nexit 0\n", 0o755)
        self.write("apps/dashboard/Dockerfile", "FROM fixture-dashboard@sha256:one\n")
        self.write("apps/dashboard/runtime-inventory.json", "{}\n")
        self.write("apps/dashboard/README.md", "unrelated app\n")
        self.write("apps/docs/zola/content/_index.md", "fixture docs\n")
        self.write("crates/codewire-derp/src/lib.rs", "pub fn derp() {}\n")
        self.write("crates/codewire-proto/src/lib.rs", "pub fn proto() {}\n")
        self.write("crates/codewire-tailnet/src/lib.rs", "pub fn tailnet() {}\n")
        self.write("crates/unrelated/src/lib.rs", "pub fn runtime_unrelated() {}\n")
        self.write("libs/gateway-proto/proto/gateway.proto", "syntax = \"proto3\";\n")
        self.write("libs/sdk-go/environment.go", "package codewire\n")
        self.write("packages/codewire-design/styles.css", ":root {}\n")
        self.write("proto/codewire/v1/api.proto", "syntax = \"proto3\";\n")
        for family in ("gateway", "derp", "services", "mesh"):
            self.write(
                f"deployments/docker/{family}.Dockerfile",
                f"FROM fixture-{family}@sha256:one\n",
            )
            self.write(
                f"deployments/docker/{family}.Dockerfile.dockerignore",
                "*\n!fixture\n",
            )
        for family in ("gateway", "derp"):
            self.write(f"deployments/docker/{family}.Cargo.toml", "[workspace]\n")
            self.write(f"deployments/docker/{family}.Cargo.lock", "version = 4\n")
        self.write("images/base/Dockerfile", "FROM fixture-base@sha256:base\n")
        self.write("images/base/entrypoint.sh", "#!/bin/sh\nexec \"$@\"\n", 0o755)
        self.write("images/workspace/Dockerfile", "FROM ${BASE_IMAGE_REF}\n")

    def commit(self, message: str) -> str:
        run(["git", "add", "-A"], self.root)
        run(["git", "commit", "-q", "-m", message], self.root)
        return run(["git", "rev-parse", "HEAD"], self.root)

    def change(self, relative: str, content: str, message: str = "fixture change") -> str:
        self.write(relative, content)
        return self.commit(message)

    def plan(self, head: str | None = None) -> dict:
        return planner.plan(self.root, self.base, head or "HEAD", self.base)

    def support_candidate(
        self,
        source: str,
        *,
        base_source: str | None = None,
        workspace_source: str | None = None,
        retrieval_valid: bool = True,
        base_digest: str = "sha256:" + "1" * 64,
        workspace_digest: str = "sha256:" + "2" * 64,
    ) -> Path:
        path = self.root / ".support-candidate.json"
        path.write_text(
            json.dumps(
                {
                    "schema": planner.SUPPORT_CANDIDATE_SCHEMA,
                    "retrieval": {
                        "valid": retrieval_valid,
                        "reasons": [] if retrieval_valid else ["workspace_registry_lookup_failed"],
                    },
                    "images": {
                        "base": {
                            "repository": "ghcr.io/codewiresh/base",
                            "tag": "latest",
                            "digest": base_digest,
                            "revision": base_source or source,
                        },
                        "workspace": {
                            "repository": "ghcr.io/codewiresh/workspace",
                            "tag": "latest",
                            "digest": workspace_digest,
                            "revision": workspace_source or source,
                        },
                    },
                },
                sort_keys=True,
                indent=2,
            )
            + "\n"
        )
        return path

    def support_plan(self, candidate: Path, head: str | None = None) -> dict:
        exact_head = head or run(["git", "rev-parse", "HEAD"], self.root)
        return planner.plan(self.root, exact_head, exact_head, exact_head, candidate)


class PlannerFixtureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="codewire-planner-test-")
        self.repo = FixtureRepository(Path(self.temporary.name))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def states(self, document: dict) -> tuple[str, str]:
        artifacts = document["artifacts"]
        return artifacts["cw_cli_release_assets"]["state"], artifacts["desktop_package"]["state"]

    def workspace_states(self, document: dict) -> tuple[str, str, str]:
        artifacts = document["artifacts"]
        return (
            artifacts["workspace_cw_binary"]["state"],
            artifacts["base_image"]["state"],
            artifacts["workspace_image"]["state"],
        )

    def runtime_states(self, document: dict) -> tuple[str, str, str, str, str]:
        artifacts = document["artifacts"]
        return tuple(
            artifacts[name]["state"]
            for name in (
                "dashboard_image",
                "gateway_image",
                "derp_image",
                "services_image",
                "mesh_image",
            )
        )

    def test_same_tree_is_deterministic_and_rust_artifacts_are_unaffected(self) -> None:
        first = self.repo.plan(self.repo.base)
        second = self.repo.plan(self.repo.base)
        self.assertEqual(first, second)
        self.assertEqual(self.states(first), ("unaffected", "unaffected"))
        self.assertEqual(self.workspace_states(first), ("unaffected", "unaffected", "unaffected"))
        self.assertEqual(self.runtime_states(first), ("unaffected",) * 5)
        self.assertFalse(first["verification"]["workspace_image"])

    def test_each_runtime_direct_input_affects_only_its_image(self) -> None:
        cases = (
            ("apps/dashboard/runtime-inventory.json", '{"changed":true}\n', 0),
            ("deployments/docker/gateway.Dockerfile", "FROM changed-gateway\n", 1),
            ("deployments/docker/derp.Cargo.lock", "version = 4\n# changed\n", 2),
            (
                "deployments/docker/services.Dockerfile.dockerignore",
                "*\n!changed\n",
                3,
            ),
            ("deployments/docker/mesh.Dockerfile", "FROM changed-mesh\n", 4),
        )
        for path, content, affected_index in cases:
            with self.subTest(path=path), tempfile.TemporaryDirectory(
                prefix="codewire-runtime-image-test-"
            ) as temporary:
                repository = FixtureRepository(Path(temporary))
                repository.change(path, content)
                expected = ["unaffected"] * 5
                expected[affected_index] = "affected"
                artifacts = repository.plan()["artifacts"]
                self.assertEqual(
                    tuple(
                        artifacts[name]["state"]
                        for name in (
                            "dashboard_image",
                            "gateway_image",
                            "derp_image",
                            "services_image",
                            "mesh_image",
                        )
                    ),
                    tuple(expected),
                )

    def test_broad_runtime_crate_contexts_remain_broad(self) -> None:
        self.repo.change(
            "crates/unrelated/src/lib.rs",
            "pub fn runtime_unrelated() { panic!(); }\n",
        )
        self.assertEqual(
            self.runtime_states(self.repo.plan()),
            ("affected", "affected", "unaffected", "affected", "affected"),
        )

    def test_proto_input_affects_every_runtime_image(self) -> None:
        self.repo.change(
            "proto/codewire/v1/api.proto",
            'syntax = "proto3";\n// changed\n',
        )
        self.assertEqual(self.runtime_states(self.repo.plan()), ("affected",) * 5)

    def test_gateway_proto_input_affects_exact_consumers(self) -> None:
        self.repo.change(
            "libs/gateway-proto/proto/gateway.proto",
            'syntax = "proto3";\n// changed\n',
        )
        self.assertEqual(
            self.runtime_states(self.repo.plan()),
            ("affected", "affected", "unaffected", "affected", "unaffected"),
        )

    def test_matching_published_support_pair_uses_exact_ancestor(self) -> None:
        head = self.repo.change("apps/dashboard/README.md", "unrelated support baseline change\n")
        candidate = self.repo.support_candidate(self.repo.base)
        document = self.repo.support_plan(candidate, head)
        self.assertTrue(document["baseline"]["validation"]["valid"])
        self.assertEqual(document["baseline"]["mode"], "published_support_pair")
        self.assertEqual(document["baseline"]["baseline_commit"], self.repo.base)
        self.assertEqual(self.workspace_states(document), ("unaffected", "unaffected", "unaffected"))

    def test_published_support_pair_selects_relevant_changes(self) -> None:
        self.repo.write("images/base/entrypoint.sh", "#!/bin/sh\nset -eu\nexec \"$@\"\n", 0o755)
        head = self.repo.commit("base image change")
        candidate = self.repo.support_candidate(self.repo.base)
        document = self.repo.support_plan(candidate, head)
        self.assertEqual(self.workspace_states(document), ("unaffected", "affected", "affected"))

    def test_missing_or_failed_support_candidate_fails_pair_closed(self) -> None:
        missing = self.repo.root / "missing-candidate.json"
        missing_document = self.repo.support_plan(missing, self.repo.base)
        self.assertFalse(missing_document["baseline"]["validation"]["valid"])
        self.assertEqual(self.workspace_states(missing_document), ("unclassified", "unclassified", "unclassified"))

        failed = self.repo.support_candidate(self.repo.base, retrieval_valid=False)
        failed_document = self.repo.support_plan(failed, self.repo.base)
        self.assertFalse(failed_document["baseline"]["validation"]["valid"])
        self.assertEqual(self.workspace_states(failed_document), ("unclassified", "unclassified", "unclassified"))

        oversized = self.repo.root / "oversized-candidate.json"
        oversized.write_bytes(b"x" * (planner.MAX_BASELINE_CANDIDATE_BYTES + 1))
        oversized_document = self.repo.support_plan(oversized, self.repo.base)
        self.assertIn(
            "published support candidate exceeds the size limit",
            oversized_document["baseline"]["validation"]["reasons"],
        )
        self.assertEqual(
            self.workspace_states(oversized_document),
            ("unclassified", "unclassified", "unclassified"),
        )

    def test_mismatched_or_malformed_support_pair_fails_closed(self) -> None:
        head = self.repo.change("apps/dashboard/README.md", "head\n")
        mismatch = self.repo.support_candidate(
            self.repo.base,
            workspace_source=head,
        )
        mismatch_document = self.repo.support_plan(mismatch, head)
        self.assertIn(
            "published support image revisions do not match",
            mismatch_document["baseline"]["validation"]["reasons"],
        )
        self.assertEqual(self.workspace_states(mismatch_document), ("unclassified", "unclassified", "unclassified"))

        malformed = self.repo.support_candidate(self.repo.base, base_digest="not-a-digest")
        malformed_document = self.repo.support_plan(malformed, head)
        self.assertIn(
            "published support base digest is invalid",
            malformed_document["baseline"]["validation"]["reasons"],
        )
        self.assertEqual(self.workspace_states(malformed_document), ("unclassified", "unclassified", "unclassified"))

    def test_non_ancestor_support_source_fails_closed(self) -> None:
        tree = run(["git", "rev-parse", "HEAD^{tree}"], self.repo.root)
        unrelated = run(["git", "commit-tree", tree, "-m", "unrelated published source"], self.repo.root)
        candidate = self.repo.support_candidate(unrelated)
        document = self.repo.support_plan(candidate, self.repo.base)
        self.assertIn(
            "published support source is not an ancestor of the exact head",
            document["baseline"]["validation"]["reasons"],
        )
        self.assertEqual(self.workspace_states(document), ("unclassified", "unclassified", "unclassified"))

    def test_direct_cli_change_affects_only_cli(self) -> None:
        self.repo.change("cli/src/main.rs", "fn main() { core::run(); /* changed */ }\n")
        document = self.repo.plan()
        self.assertEqual(self.states(document), ("affected", "unaffected"))
        self.assertEqual(self.workspace_states(document), ("affected", "unaffected", "affected"))
        self.assertTrue(document["verification"]["workspace_image"])

    def test_reachable_normal_dependency_affects_both_packages(self) -> None:
        self.repo.change("core/src/lib.rs", "pub fn run() { println!(\"changed\"); }\n")
        self.assertEqual(self.states(self.repo.plan()), ("affected", "affected"))

    def test_reachable_build_dependency_affects_cli(self) -> None:
        self.repo.change("build-helper/src/lib.rs", "pub fn emit() { println!(\"cargo:rerun\"); }\n")
        document = self.repo.plan()
        self.assertEqual(self.states(document), ("affected", "unaffected"))
        self.assertEqual(self.workspace_states(document), ("affected", "unaffected", "affected"))

    def test_optional_dependency_is_conservatively_included(self) -> None:
        self.repo.change("optional-helper/src/lib.rs", "pub fn optional() { println!(\"optional\"); }\n")
        self.assertEqual(self.states(self.repo.plan()), ("affected", "unaffected"))

    def test_target_dependency_is_conservatively_included(self) -> None:
        self.repo.change("target-helper/src/lib.rs", "pub fn target() { println!(\"target\"); }\n")
        self.assertEqual(self.states(self.repo.plan()), ("affected", "unaffected"))

    def test_dev_only_and_unrelated_package_changes_do_not_affect_packages(self) -> None:
        self.repo.change("unrelated/src/lib.rs", "pub fn unrelated() { panic!(); }\n")
        self.assertEqual(self.states(self.repo.plan()), ("unaffected", "unaffected"))

    def test_billing_and_admin_proto_outside_cli_closure_do_not_package_cli(self) -> None:
        self.repo.write("billing/src/lib.rs", "pub fn bill() { /* durable billing change */ }\n")
        self.repo.write("admin-proto/src/lib.rs", "pub fn admin_contract() { /* v2 */ }\n")
        self.repo.commit("billing and isolated admin contract")
        document = self.repo.plan()
        self.assertEqual(self.states(document), ("unaffected", "unaffected"))
        self.assertEqual(self.workspace_states(document), ("unaffected", "unaffected", "unaffected"))
        self.assertFalse(document["verification"]["workspace_image"])

    def test_relevant_generated_input_affects_both_packages(self) -> None:
        self.repo.change("generated/descriptor.bin", "descriptor-v2\n")
        document = self.repo.plan()
        self.assertEqual(self.states(document), ("affected", "affected"))
        self.assertEqual(self.workspace_states(document), ("affected", "unaffected", "affected"))

    def test_desktop_detached_manifest_change_is_isolated(self) -> None:
        self.repo.change("desktop/src/main.rs", "fn main() { core::run(); println!(\"desktop\"); }\n")
        self.assertEqual(self.states(self.repo.plan()), ("unaffected", "affected"))

    def test_detached_release_profile_change_affects_desktop(self) -> None:
        manifest = (self.repo.root / "desktop/Cargo.toml").read_text().replace(
            "strip = true", "strip = true\nlto = true"
        )
        self.repo.change("desktop/Cargo.toml", manifest)
        self.assertEqual(self.states(self.repo.plan()), ("unaffected", "affected"))

    def test_compile_time_package_metadata_change_affects_cli(self) -> None:
        manifest = (self.repo.root / "cli/Cargo.toml").read_text().replace(
            'edition = "2021"', 'edition = "2021"\nauthors = ["Changed Author"]'
        )
        self.repo.change("cli/Cargo.toml", manifest)
        self.assertEqual(self.states(self.repo.plan()), ("affected", "unaffected"))

    def test_test_only_change_does_not_change_package_artifact(self) -> None:
        self.repo.change("cli/tests/cli.rs", "#[test] fn smoke() { assert!(true); }\n")
        self.assertEqual(self.states(self.repo.plan()), ("unaffected", "unaffected"))

    def test_unknown_reachable_path_fails_closed_for_owning_artifact(self) -> None:
        self.repo.change("cli/assets/theme.dat", "new asset\n")
        document = self.repo.plan()
        self.assertEqual(self.states(document), ("unclassified", "unaffected"))
        self.assertEqual(
            self.workspace_states(document),
            ("unclassified", "unaffected", "unclassified"),
        )

    def test_base_change_affects_the_atomic_workspace_pair(self) -> None:
        self.repo.write("images/base/entrypoint.sh", "#!/bin/sh\nset -eu\nexec \"$@\"\n", 0o755)
        self.repo.commit("base entrypoint change")
        self.assertEqual(
            self.workspace_states(self.repo.plan()),
            ("unaffected", "affected", "affected"),
        )

    def test_workspace_dockerfile_change_affects_only_workspace_image(self) -> None:
        self.repo.change(
            "images/workspace/Dockerfile",
            "FROM ${BASE_IMAGE_REF}\nRUN printf workspace-v2\\n\n",
        )
        self.assertEqual(
            self.workspace_states(self.repo.plan()),
            ("unaffected", "unaffected", "affected"),
        )

    def test_unrelated_lock_record_does_not_affect_workspace_binary(self) -> None:
        lockfile = (self.repo.root / "Cargo.lock").read_text()
        self.repo.change(
            "Cargo.lock",
            lockfile
            + "\n[[package]]\nname = \"unreachable-external\"\nversion = \"9.9.9\"\n"
            + "source = \"registry+https://example.invalid/index\"\n"
            + "checksum = \"unreachable\"\n",
        )
        self.assertEqual(
            self.workspace_states(self.repo.plan()),
            ("unaffected", "unaffected", "unaffected"),
        )

    def test_policy_change_fails_every_artifact_closed(self) -> None:
        self.repo.change("scripts/ci/plan/new-policy-input.txt", "policy change\n")
        document = self.repo.plan()
        self.assertTrue(all(value["state"] == "unclassified" for value in document["artifacts"].values()))

    def test_legacy_selector_change_fails_every_artifact_closed(self) -> None:
        self.repo.change("scripts/ci/select/select-verification.sh", "#!/bin/sh\nexit 0\n")
        document = self.repo.plan()
        self.assertTrue(all(value["state"] == "unclassified" for value in document["artifacts"].values()))

    def test_unrelated_app_change_does_not_package_rust(self) -> None:
        self.repo.change("apps/dashboard/README.md", "billing-only equivalent\n")
        self.assertEqual(self.states(self.repo.plan()), ("unaffected", "unaffected"))

    def test_go_sdk_only_change_emits_unselected_cw_and_desktop_outputs(self) -> None:
        self.repo.change(
            "libs/sdk-go/environment.go",
            "package codewire\n\nfunc ResizeEnvironment() {}\n",
        )
        document = self.repo.plan()
        self.assertEqual(self.states(document), ("unaffected", "unaffected"))

        with tempfile.TemporaryDirectory(prefix="codewire-plan-adapter-test-") as temporary:
            root = Path(temporary)
            plan_path = root / "plan.json"
            plan_path.write_text(json.dumps(document, sort_keys=True, indent=2) + "\n")
            completed = subprocess.run(
                [
                    sys.executable,
                    str(PLANNER_PATH.parent / "apply-verification-plan.py"),
                    "--plan",
                    str(plan_path),
                ],
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        outputs = dict(line.split("=", 1) for line in completed.stdout.splitlines())
        self.assertEqual(outputs["cw_package_selected"], "false")
        self.assertEqual(outputs["desktop_package_selected"], "false")
        self.assertEqual(outputs["workspace_image_selected"], "false")
        self.assertNotIn("selection", outputs)
        self.assertNotIn("selector_version", outputs)
        print(
            "non-Rust planner fixture: cw_package_selected=false "
            "desktop_package_selected=false workspace_image_selected=false"
        )

    def test_missing_cargo_fails_closed_with_diagnostic(self) -> None:
        original_run = subprocess.run

        def run_without_cargo(argv: list[str], *args: object, **kwargs: object) -> subprocess.CompletedProcess:
            if argv[0] == "cargo":
                raise FileNotFoundError(2, "No such file or directory", "cargo")
            return original_run(argv, *args, **kwargs)

        with mock.patch.object(planner.subprocess, "run", side_effect=run_without_cargo):
            document = self.repo.plan()

        self.assertEqual(self.states(document), ("unclassified", "unclassified"))
        diagnostic = json.dumps(document["degraded_reasons"], sort_keys=True)
        self.assertIn("command could not run: cargo", diagnostic)
        print(f"missing-Cargo planner fixture fails closed: {diagnostic}")

    def test_candidate_cargo_configuration_fails_closed(self) -> None:
        self.repo.change(".cargo/config.toml", "[net]\noffline = false\n")
        document = self.repo.plan()
        self.assertTrue(document["degraded_reasons"])
        self.assertTrue(all(value["state"] == "unclassified" for value in document["artifacts"].values()))


class LockClosureTests(unittest.TestCase):
    def test_only_reachable_external_lock_records_are_hashed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            tree = Path(temporary)
            (tree / "Cargo.lock").write_text(
                """version = 4

[[package]]
name = "app"
version = "1.0.0"
dependencies = ["normal 2.0.0", "dev-only 9.0.0"]

[[package]]
name = "normal"
version = "2.0.0"
source = "registry+https://example.invalid/index"
checksum = "normal"
dependencies = ["transitive 3.0.0"]

[[package]]
name = "transitive"
version = "3.0.0"
source = "registry+https://example.invalid/index"
checksum = "transitive"

[[package]]
name = "dev-only"
version = "9.0.0"
source = "registry+https://example.invalid/index"
checksum = "dev"
"""
            )
            closure = [
                {
                    "name": "app",
                    "version": "1.0.0",
                    "dependencies": [
                        {"name": "normal", "kind": None, "path": None},
                        {"name": "dev-only", "kind": "dev", "path": None},
                    ],
                }
            ]
            records = planner.reachable_lock_records(tree, "Cargo.lock", closure)
            self.assertEqual([record["name"] for record in records], ["normal", "transitive"])

    def test_ambiguous_lock_reference_fails_closed(self) -> None:
        records = [
            {"name": "same", "version": "1.0.0"},
            {"name": "same", "version": "2.0.0"},
        ]
        with self.assertRaises(planner.PlannerError):
            planner.resolve_lock_reference("same", records)


class FileSetAndCompositeTests(unittest.TestCase):
    def test_file_set_is_deterministic_and_hashes_mode_path_and_content(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            tree = Path(temporary)
            path = tree / "images/base/entrypoint.sh"
            path.parent.mkdir(parents=True)
            path.write_text("#!/bin/sh\n")
            path.chmod(0o755)
            spec = {"kind": "file-set", "inputs": ["images/base/**"]}
            first = planner.file_set_fingerprint(tree, spec)
            second = planner.file_set_fingerprint(tree, spec)
            self.assertEqual(first, second)
            path.chmod(0o644)
            self.assertNotEqual(first.fingerprint, planner.file_set_fingerprint(tree, spec).fingerprint)

    def test_missing_pattern_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(planner.PlannerError):
                planner.file_set_fingerprint(
                    Path(temporary), {"kind": "file-set", "inputs": ["images/base/**"]}
                )

    def test_symlink_input_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            tree = Path(temporary)
            directory = tree / "images/base"
            directory.mkdir(parents=True)
            (directory / "target").write_text("safe\n")
            (directory / "link").symlink_to("target")
            with self.assertRaises(planner.PlannerError):
                planner.file_set_fingerprint(
                    tree, {"kind": "file-set", "inputs": ["images/base/**"]}
                )

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO creation is unavailable")
    def test_special_file_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            tree = Path(temporary)
            directory = tree / "images/base"
            directory.mkdir(parents=True)
            os.mkfifo(directory / "unexpected")
            with self.assertRaises(planner.PlannerError):
                planner.TreeIndex(tree)

    def test_missing_dependency_and_cycle_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            tree = Path(temporary)
            (tree / "one").write_text("one\n")
            index = planner.TreeIndex(tree)
            missing = {
                "artifacts": {
                    "root": {
                        "kind": "composite",
                        "dependencies": ["absent"],
                        "inputs": ["one"],
                    }
                }
            }
            with self.assertRaises(planner.PlannerError):
                planner.artifact_fingerprint("root", tree, missing, None, index, {})
            cycle = {
                "artifacts": {
                    "one": {"kind": "composite", "dependencies": ["two"], "inputs": ["one"]},
                    "two": {"kind": "composite", "dependencies": ["one"], "inputs": ["one"]},
                }
            }
            with self.assertRaises(planner.PlannerError):
                planner.artifact_fingerprint("one", tree, cycle, None, index, {})


class HostileArchiveTests(unittest.TestCase):
    def archive(self, members: list[tuple[tarfile.TarInfo, bytes]]) -> io.BytesIO:
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w") as archive:
            for info, content in members:
                archive.addfile(info, io.BytesIO(content) if content else None)
        stream.seek(0)
        return stream

    def test_path_traversal_is_rejected(self) -> None:
        info = tarfile.TarInfo("../escape")
        info.size = 1
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(planner.PlannerError):
                planner.safe_extract_tar(self.archive([(info, b"x")]), Path(temporary))

    def test_escaping_symlink_is_rejected(self) -> None:
        info = tarfile.TarInfo("safe/link")
        info.type = tarfile.SYMTYPE
        info.linkname = "../../escape"
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(planner.PlannerError):
                planner.safe_extract_tar(self.archive([(info, b"")]), Path(temporary))

    def test_duplicate_path_is_rejected(self) -> None:
        first_info = tarfile.TarInfo("duplicate")
        first_info.size = 1
        second_info = tarfile.TarInfo("duplicate")
        second_info.size = 1
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(planner.PlannerError):
                planner.safe_extract_tar(
                    self.archive([(first_info, b"a"), (second_info, b"b")]), Path(temporary)
                )

    def test_internal_symlink_is_allowed(self) -> None:
        target = tarfile.TarInfo("target")
        target.size = 1
        link = tarfile.TarInfo("link")
        link.type = tarfile.SYMTYPE
        link.linkname = "target"
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary)
            planner.safe_extract_tar(self.archive([(target, b"x"), (link, b"")]), destination)
            planner.validate_exported_tree(destination)
            self.assertEqual((destination / "link").read_text(), "x")


if __name__ == "__main__":
    unittest.main()
