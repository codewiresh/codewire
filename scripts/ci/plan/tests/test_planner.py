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
import tomllib
import unittest
from pathlib import Path
from unittest import mock


PLANNER_PATH = Path(__file__).parents[1] / "planner.py"
SELECTOR_PATH = PLANNER_PATH.parents[1] / "select" / "select-verification.sh"
SPEC = importlib.util.spec_from_file_location("codewire_ci_planner", PLANNER_PATH)
assert SPEC and SPEC.loader
planner = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = planner
SPEC.loader.exec_module(planner)
PRODUCTION_GRAPH = json.loads(
    (PLANNER_PATH.parent / "artifact-graph.json").read_text()
)
WORKSPACE_VERIFICATION_SPEC = PRODUCTION_GRAPH["artifacts"]["workspace_image_verification"]
DEV_ACCEPTANCE_HARNESS_SPEC = PRODUCTION_GRAPH["artifacts"]["dev_acceptance_harness"]
CREDENTIAL_ACCEPTANCE_PATHS = (
    "scripts/runtime/dev/provider-anthropic-output.py",
    "scripts/runtime/dev/provider-anthropic-smoke.sh",
    "scripts/runtime/dev/provider-anthropic-workload.sh",
    "scripts/runtime/dev/provider-codex-output.py",
    "scripts/runtime/dev/provider-codex-smoke.sh",
    "scripts/runtime/dev/provider-codex-workload.sh",
    "scripts/runtime/dev/provider-openai-smoke.sh",
    "scripts/runtime/dev/provider-openai-workload.py",
    "scripts/runtime/dev/smoke-local-platform-sources.sh",
    "scripts/runtime/tests/test-local-platform-sources-smoke.sh",
    "scripts/runtime/tests/test-provider-anthropic-smoke.sh",
    "scripts/runtime/tests/test-provider-anthropic-workload.py",
    "scripts/runtime/tests/test-provider-codex-smoke.sh",
    "scripts/runtime/tests/test-provider-codex-workload.py",
    "scripts/runtime/tests/test-provider-openai-smoke.sh",
    "scripts/runtime/tests/test-provider-openai-workload.py",
    "scripts/runtime/tests/test-secrets-credentials-acceptance-runner.sh",
)


def fixture_cargo_metadata(tree: Path, manifest: Path, _cargo_env: dict[str, str]) -> dict:
    """Small deterministic Cargo-metadata model for this synthetic fixture.

    Production planning still invokes isolated Cargo.  The fixture's package
    grammar is intentionally narrow and is checked against one real Cargo
    metadata invocation below; it avoids making every unit case a cold Cargo
    subprocess test on CI.
    """
    root_document = tomllib.loads((tree / "Cargo.toml").read_text())
    relative_manifest = manifest.resolve().relative_to(tree.resolve()).as_posix()
    if relative_manifest == "Cargo.toml":
        manifests = [f"{member}/Cargo.toml" for member in root_document["workspace"]["members"]]
    else:
        manifests = [relative_manifest]

    def dependencies(document: dict, package_manifest: Path) -> list[dict]:
        result: list[dict] = []
        sections = [("dependencies", None), ("build-dependencies", "build"), ("dev-dependencies", "dev")]
        for section, kind in sections:
            for name, spec in document.get(section, {}).items():
                detail = spec if isinstance(spec, dict) else {}
                path = detail.get("path")
                result.append({"name": detail.get("package", name), "path": str((package_manifest.parent / path).resolve()) if path else None, "req": "*" if path else detail.get("version", "*"), "kind": kind, "rename": name if detail.get("package") else None, "optional": bool(detail.get("optional")), "uses_default_features": detail.get("default-features", True), "features": detail.get("features", []), "target": None})
        for target, table in document.get("target", {}).items():
            for name, spec in table.get("dependencies", {}).items():
                detail = spec if isinstance(spec, dict) else {}
                path = detail.get("path")
                result.append({"name": detail.get("package", name), "path": str((package_manifest.parent / path).resolve()) if path else None, "req": "*" if path else detail.get("version", "*"), "kind": None, "rename": name if detail.get("package") else None, "optional": bool(detail.get("optional")), "uses_default_features": detail.get("default-features", True), "features": detail.get("features", []), "target": target})
        return result

    packages = []
    for relative in manifests:
        package_manifest = tree / relative
        document = tomllib.loads(package_manifest.read_text())
        package = document["package"]
        package_root = package_manifest.parent
        targets = []
        if (package_root / "src/lib.rs").is_file():
            targets.append({"name": package["name"].replace("-", "_"), "kind": ["lib"], "crate_types": ["lib"], "src_path": str(package_root / "src/lib.rs"), "edition": package.get("edition"), "required-features": []})
        if (package_root / "src/main.rs").is_file():
            targets.append({"name": package["name"], "kind": ["bin"], "crate_types": ["bin"], "src_path": str(package_root / "src/main.rs"), "edition": package.get("edition"), "required-features": []})
        build_path = package_root / package.get("build", "build.rs")
        if build_path.is_file():
            targets.append({"name": "build-script-build", "kind": ["custom-build"], "crate_types": ["bin"], "src_path": str(build_path), "edition": package.get("edition"), "required-features": []})
        packages.append({"name": package["name"], "version": package["version"], "edition": package.get("edition"), "authors": package.get("authors", []), "license": package.get("license"), "license_file": package.get("license-file"), "description": package.get("description"), "homepage": package.get("homepage"), "documentation": package.get("documentation"), "repository": package.get("repository"), "readme": package.get("readme"), "keywords": package.get("keywords", []), "categories": package.get("categories", []), "rust_version": package.get("rust-version"), "links": package.get("links"), "default_run": package.get("default-run"), "metadata": package.get("metadata"), "manifest_path": str(package_manifest), "dependencies": dependencies(document, package_manifest), "targets": targets, "features": document.get("features", {})})
    for package in packages:
        package["id"] = f"{package['name']} 0.1.0 (path+file://fixture)"
    return {
        "packages": packages,
        "workspace_members": [package["id"] for package in packages],
    }


def run(argv: list[str], cwd: Path) -> str:
    completed = subprocess.run(argv, cwd=cwd, text=True, capture_output=True, check=False)
    if completed.returncode:
        raise AssertionError(f"command failed: {argv}\n{completed.stderr}")
    return completed.stdout.strip()


def select_capabilities(paths: list[str]) -> dict[str, str]:
    with tempfile.TemporaryDirectory(prefix="codewire-selector-boundary-") as temporary:
        path_file = Path(temporary) / "paths"
        path_file.write_text("\n".join(paths) + "\n")
        env = os.environ.copy()
        env.pop("GITHUB_OUTPUT", None)
        env.pop("GITHUB_EVENT_PATH", None)
        env.update(
            {
                "GITHUB_EVENT_NAME": "pull_request",
                "GITHUB_REF": "refs/pull/fixture/head",
                "KIND_E2E_OPT_IN": "false",
            }
        )
        completed = subprocess.run(
            [str(SELECTOR_PATH), str(path_file)],
            cwd=PLANNER_PATH.parents[3],
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        if completed.returncode:
            raise AssertionError(f"selector failed:\n{completed.stderr}")
        return dict(line.split("=", 1) for line in completed.stdout.splitlines())


class FixtureRepository:
    def __init__(self, root: Path):
        self.root = root
        self._write_policy()
        self._write_workspace()
        run(["git", "init", "-q"], root)
        run(["git", "config", "user.name", "CI fixture"], root)
        run(["git", "config", "user.email", "ci-fixture@codewire.invalid"], root)
        # Fixture commits are planner inputs, not a signing-path test.  Keep
        # them hermetic when a developer workstation enables commit signing.
        run(["git", "config", "commit.gpgsign", "false"], root)
        self.base = self.commit("fixture baseline")

    def write(self, relative: str, content: str, mode: int | None = None) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        if mode is not None:
            path.chmod(mode)

    def _write_policy(self) -> None:
        policy_root = self.root / "scripts/ci/plan"
        policy_root.mkdir(parents=True)
        shutil.copy2(PLANNER_PATH, policy_root / "planner.py")
        shutil.copy2(PLANNER_PATH.parent / "apply-deploy-plan.py", policy_root / "apply-deploy-plan.py")
        shutil.copy2(PLANNER_PATH.parent / "apply-support-plan.py", policy_root / "apply-support-plan.py")
        deploy_root = self.root / "scripts/ci/deploy"
        deploy_root.mkdir(parents=True)
        shutil.copy2(
            PLANNER_PATH.parents[1] / "deploy" / "resolve-deployed-source.sh",
            deploy_root / "resolve-deployed-source.sh",
        )
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
        shutil.copy2(
            PLANNER_PATH.parents[3] / ".gitea" / "workflows" / "deploy-dev.yaml",
            workflow_root / "deploy-dev.yaml",
        )
        graph = {
            "schema": "codewire.ci-artifact-graph/v1",
            "policy_files": [
                ".gitea/workflows/deploy-dev.yaml",
                ".gitea/workflows/support-images.yaml",
                "scripts/ci/deploy/resolve-deployed-source.sh",
                "scripts/ci/images/resolve-published-support-pair.sh",
                "scripts/ci/plan/apply-deploy-plan.py",
                "scripts/ci/plan/apply-support-plan.py",
                "scripts/ci/plan/artifact-graph.json",
                "scripts/ci/plan/planner.py",
            ],
            "non_artifact_inputs": list(PRODUCTION_GRAPH["non_artifact_inputs"]),
            "artifacts": {
                "dev_release_tree": {
                    "kind": "file-set",
                    "inputs": ["deployments/k8s/**"],
                },
                "dev_acceptance_harness": DEV_ACCEPTANCE_HARNESS_SPEC,
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
                "rust_cache_cli": {
                    "kind": "rust-cache",
                    "manifest": "Cargo.toml",
                    "packages": ["cli-bin"],
                    "lockfile": "Cargo.lock",
                    "profiles": ["release"],
                    "targets": ["host"],
                    "features": ["default"],
                    "dependency_kinds": ["normal", "build"],
                    "runner_pool": "generic",
                    "warm_mode": "fixture",
                    "max_bytes": 4294967296,
                    "compatibility_inputs": ["generated/descriptor.bin"],
                    "tool_inputs": {"cache_format": "v1"},
                },
                "rust_cache_workspace": {
                    "kind": "rust-cache",
                    "manifest": "Cargo.toml",
                    "packages": "workspace",
                    "lockfile": "Cargo.lock",
                    "profiles": ["release"],
                    "targets": ["host"],
                    "features": ["default"],
                    "dependency_kinds": ["normal", "build", "dev"],
                    "runner_pool": "generic",
                    "warm_mode": "fixture-workspace",
                    "max_bytes": 4294967296,
                    "compatibility_inputs": ["generated/descriptor.bin"],
                    "tool_inputs": {"cache_format": "v1"},
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
                        "crates/codewire-netstack/**",
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
                "confidential_probe_image": {
                    "kind": "file-set",
                    "inputs": ["images/confidential-probe/**"],
                },
                "confidential_workspace_acceptance_contract": {
                    "kind": "file-set",
                    "inputs": [
                        "deployments/k8s/orchestration/deployment.yaml",
                        "deployments/k8s/overlays/dev/config-runtime-profile.yaml",
                        "deployments/k8s/overlays/dev/config-runtime-profile-commodity.yaml",
                        "deployments/k8s/overlays/dev/config-runtime-profile-confidential-snp.yaml",
                        "deployments/k8s/runtime-profiles/confidential/**",
                        "deployments/k8s/runtime-profiles/confidential-smoke/**",
                        "scripts/runtime/confidential/**",
                    ],
                },
                "workspace_image_verification": WORKSPACE_VERIFICATION_SPEC,
                "workspace_image": {
                    "kind": "composite",
                    "dependencies": [
                        "base_image",
                        "workspace_cw_binary",
                        "confidential_workspace_acceptance_contract",
                        "dev_release_tree",
                        "dev_acceptance_harness",
                        "dashboard_image",
                        "gateway_image",
                        "derp_image",
                        "services_image",
                        "mesh_image",
                    ],
                    "inputs": ["images/workspace/**"],
                },
            },
        }
        self.write("scripts/ci/plan/artifact-graph.json", json.dumps(graph, sort_keys=True, indent=2) + "\n")

    def _write_workspace(self) -> None:
        self.write(
            "deployments/k8s/base/runtime-profile.yaml",
            "apiVersion: v1\nkind: ConfigMap\n",
        )
        self.write(
            "deployments/k8s/orchestration/deployment.yaml",
            "apiVersion: apps/v1\nkind: Deployment\n",
        )
        for profile in (
            "config-runtime-profile.yaml",
            "config-runtime-profile-commodity.yaml",
            "config-runtime-profile-confidential-snp.yaml",
        ):
            self.write(
                f"deployments/k8s/overlays/dev/{profile}",
                "apiVersion: v1\nkind: ConfigMap\n",
            )
        self.write(
            "deployments/k8s/runtime-profiles/confidential/coco-support-images.lock.json",
            "{}\n",
        )
        self.write(
            "deployments/k8s/runtime-profiles/confidential-smoke/kustomization.yaml",
            "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\n",
        )
        self.write(
            "scripts/runtime/confidential/smoke-dev-confidential-snp.sh",
            "#!/usr/bin/env bash\nset -euo pipefail\n",
            0o755,
        )
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
readme = "README.md"
""",
        )
        self.write("core/src/lib.rs", "pub fn run() {}\n")
        self.write("core/README.md", "# Fixture core\n")
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
        self.write("crates/codewire-netstack/src/lib.rs", "pub fn netstack() {}\n")
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
        self.write("images/confidential-probe/Dockerfile", "FROM fixture-probe@sha256:probe\n")
        self.write("images/workspace/Dockerfile", "FROM ${BASE_IMAGE_REF}\n")
        for path in WORKSPACE_VERIFICATION_SPEC["inputs"]:
            if "*" not in path and not (self.root / path).exists():
                self.write(path, "# Synthetic workspace verification input\n")
        for path in DEV_ACCEPTANCE_HARNESS_SPEC["inputs"]:
            if "*" not in path and not (self.root / path).exists():
                self.write(path, "# Synthetic Dev acceptance harness input\n")

    def commit(self, message: str) -> str:
        run(["git", "add", "-A"], self.root)
        run(["git", "commit", "-q", "-m", message], self.root)
        return run(["git", "rev-parse", "HEAD"], self.root)

    def change(self, relative: str, content: str, message: str = "fixture change") -> str:
        self.write(relative, content)
        return self.commit(message)

    def plan(self, head: str | None = None) -> dict:
        with mock.patch.object(planner, "cargo_metadata", side_effect=fixture_cargo_metadata):
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
        with mock.patch.object(planner, "cargo_metadata", side_effect=fixture_cargo_metadata):
            return planner.plan(self.root, exact_head, exact_head, exact_head, candidate)

    def deployed_source_candidate(
        self,
        source: str,
        head: str,
        *,
        retrieval_valid: bool = True,
        target_repository: str = "codewire/codewire",
        source_repository: str = "codewire/codewire",
    ) -> Path:
        path = self.root / ".deployed-source-candidate.json"
        path.write_text(
            json.dumps(
                {
                    "schema": planner.DEPLOYED_SOURCE_CANDIDATE_SCHEMA,
                    "retrieval": {
                        "valid": retrieval_valid,
                        "reasons": [] if retrieval_valid else ["api_unavailable"],
                    },
                    "target": {
                        "repository": target_repository,
                        "head_sha": head,
                    },
                    "release": {
                        "repository": "codewire/deploy",
                        "path": "environments/dev/release.json",
                        "ref": "main",
                    },
                    "source": {
                        "repository": source_repository,
                        "sha": source,
                    },
                },
                sort_keys=True,
                indent=2,
            )
            + "\n"
        )
        return path

    def deployed_source_plan(self, candidate: Path, head: str | None = None) -> dict:
        exact_head = head or run(["git", "rev-parse", "HEAD"], self.root)
        with mock.patch.object(planner, "cargo_metadata", side_effect=fixture_cargo_metadata):
            return planner.plan(
                self.root,
                exact_head,
                exact_head,
                trusted_policy_revision=exact_head,
                deployed_source_candidate=candidate,
            )


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

    def dev_release_state(self, document: dict) -> str:
        return document["artifacts"]["dev_release_tree"]["state"]

    def test_fixture_metadata_matches_real_cargo_for_each_artifact_root(self) -> None:
        for manifest in ("Cargo.toml", "desktop/Cargo.toml"):
            with self.subTest(manifest=manifest):
                with tempfile.TemporaryDirectory(
                    prefix="codewire-fixture-cargo-equivalence-"
                ) as temporary:
                    environment = planner.isolated_cargo_environment(
                        Path(temporary),
                        planner.trusted_rust_toolchain(PLANNER_PATH.parents[3]),
                    )
                    real = planner.discover_cargo_universe(self.repo.root, manifest, environment)
                    with mock.patch.object(planner, "cargo_metadata", side_effect=fixture_cargo_metadata):
                        modeled = planner.discover_cargo_universe(self.repo.root, manifest, environment)
                self.assertEqual(
                    {
                        key: planner.normalized_package(value, self.repo.root)
                        for key, value in real.packages.items()
                    },
                    {
                        key: planner.normalized_package(value, self.repo.root)
                        for key, value in modeled.packages.items()
                    },
                )

    def test_same_tree_is_deterministic_and_rust_artifacts_are_unaffected(self) -> None:
        first = self.repo.plan(self.repo.base)
        second = self.repo.plan(self.repo.base)
        self.assertEqual(first, second)
        self.assertEqual(self.states(first), ("unaffected", "unaffected"))
        self.assertEqual(self.workspace_states(first), ("unaffected", "unaffected", "unaffected"))
        self.assertEqual(self.runtime_states(first), ("unaffected",) * 5)
        self.assertEqual(self.dev_release_state(first), "unaffected")
        self.assertEqual(first["artifacts"]["workspace_image_verification"]["state"], "unaffected")

    def test_confidential_deployment_input_selects_exact_workspace_release(self) -> None:
        self.repo.change(
            "deployments/k8s/runtime-profiles/confidential-smoke/job.yaml",
            "apiVersion: batch/v1\nkind: Job\n",
        )
        document = self.repo.plan()
        self.assertEqual(self.dev_release_state(document), "affected")
        self.assertEqual(
            document["artifacts"]["confidential_workspace_acceptance_contract"]["state"],
            "affected",
        )
        self.assertEqual(
            self.workspace_states(document),
            ("unaffected", "unaffected", "affected"),
        )
        self.assertEqual(self.runtime_states(document), ("unaffected",) * 5)
        self.assertEqual(document["artifacts"]["workspace_image_verification"]["state"], "unaffected")

    def test_any_dev_release_input_selects_exact_workspace_release(self) -> None:
        self.repo.change(
            "deployments/k8s/base/runtime-profile.yaml",
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: changed\n",
        )
        document = self.repo.plan()
        self.assertEqual(self.dev_release_state(document), "affected")
        self.assertEqual(
            self.workspace_states(document),
            ("unaffected", "unaffected", "affected"),
        )
        self.assertEqual(document["artifacts"]["workspace_image_verification"]["state"], "unaffected")

    def test_confidential_smoke_script_selects_exact_workspace_release(self) -> None:
        self.repo.change(
            "scripts/runtime/confidential/smoke-dev-confidential-snp.sh",
            "#!/usr/bin/env bash\nset -euo pipefail\nprintf smoke\\n\n",
        )
        document = self.repo.plan()
        self.assertEqual(
            document["artifacts"]["confidential_workspace_acceptance_contract"]["state"],
            "affected",
        )
        self.assertEqual(
            self.workspace_states(document),
            ("unaffected", "unaffected", "affected"),
        )
        self.assertEqual(self.states(document), ("unaffected", "unaffected"))
        self.assertEqual(document["artifacts"]["workspace_image_verification"]["state"], "unaffected")

    def test_runtime_source_keeps_exact_publication_without_workspace_verification(self) -> None:
        self.repo.change("crates/unrelated/src/lib.rs", "pub fn runtime_only() {}\n")
        document = self.repo.plan()
        self.assertEqual(self.states(document), ("unaffected", "unaffected"))
        self.assertEqual(document["artifacts"]["workspace_image"]["state"], "affected")
        self.assertEqual(document["artifacts"]["workspace_image_verification"]["state"], "unaffected")

    def test_workspace_verification_owns_raw_manifest_even_when_cargo_metadata_is_unchanged(self) -> None:
        manifest = (self.repo.root / "Cargo.toml").read_text()
        self.repo.change("Cargo.toml", manifest + "\n# Changed build-context bytes\n")
        document = self.repo.plan()
        self.assertEqual(document["artifacts"]["workspace_cw_binary"]["state"], "unaffected")
        self.assertEqual(document["artifacts"]["workspace_image_verification"]["state"], "affected")

    def test_workspace_verification_build_and_contract_inputs_are_selected(self) -> None:
        for path in (
            ".dockerignore",
            "images/base/entrypoint.sh",
            "images/workspace/Dockerfile",
            "scripts/ci/images/build-local-image.sh",
            "scripts/ci/images/run-rust-build.sh",
            "scripts/ci/images/workspace-cache.sh",
            "scripts/ci/setup/prepare-workspace-cache-measurement.sh",
            "scripts/ci/setup/select-untrusted-workspace-cache.sh",
            "scripts/ci/setup/select-workspace-cache-experiment.py",
            "scripts/ci/tests/canary-workspace-r2-cache.sh",
            "scripts/ci/tests/probe-workspace-r2-cache.sh",
            "scripts/ci/tests/test-workspace-cache-probes.py",
            "scripts/ci/verify/workspace-cache-probes.py",
            "scripts/ci/tests/test-build-local-image.sh",
            "scripts/ci/tests/test-select-untrusted-workspace-cache.sh",
            "scripts/ci/tests/test-workspace-agent-contract.sh",
            "scripts/ci/tests/test-workspace-cache.sh",
            "scripts/ci/tests/test-workspace-cache-experiment.py",
            "scripts/ci/tests/test-workspace-image-artifact.py",
            "scripts/ci/tests/test-workspace-image-verify-workflow.sh",
            "scripts/ci/verify/rehearse-build-local-image.sh",
            "scripts/ci/verify/verify-workspace-image.sh",
            "scripts/ci/verify/workspace-agent-contract.sh",
            "scripts/ci/verify/workspace-cache-report.py",
            "scripts/ci/verify/workspace-image-artifact.py",
        ):
            with self.subTest(path=path):
                original = (self.repo.root / path).read_text()
                head = self.repo.change(path, original + "\n# Changed verification input\n")
                document = self.repo.plan()
                self.assertEqual(self.states(document), ("unaffected", "unaffected"))
                self.assertEqual(document["artifacts"]["workspace_image_verification"]["state"], "affected")
                self.repo.base = head

    def test_workspace_verification_missing_contract_fails_closed(self) -> None:
        (self.repo.root / "scripts/ci/verify/workspace-image-artifact.py").unlink()
        self.repo.commit("missing workspace identity helper")
        document = self.repo.plan()
        artifact = document["artifacts"]["workspace_image_verification"]
        self.assertEqual(artifact["state"], "unclassified")
        self.assertIn("matched no files", artifact["explanations"][0])

    def test_candidate_workspace_policy_cannot_reduce_its_own_verification(self) -> None:
        graph_path = "scripts/ci/plan/artifact-graph.json"
        graph = json.loads((self.repo.root / graph_path).read_text())
        graph["artifacts"]["workspace_image_verification"] = {
            "kind": "file-set", "inputs": ["images/workspace/**"]
        }
        self.repo.change(graph_path, json.dumps(graph, sort_keys=True, indent=2) + "\n")
        document = self.repo.plan()
        self.assertTrue(all(value["state"] == "unclassified" for value in document["artifacts"].values()))

    def test_rust_cache_identity_reuses_dependencies_but_not_changed_source(self) -> None:
        baseline = self.repo.plan(self.repo.base)["artifacts"]["rust_cache_cli"]
        head = self.repo.change(
            "cli/src/main.rs",
            "fn main() { println!(\"changed CLI source\"); }\n",
        )
        changed = self.repo.plan(head)["artifacts"]["rust_cache_cli"]
        self.assertEqual(changed["state"], "unaffected")
        self.assertEqual(changed["head_fingerprint"], baseline["head_fingerprint"])

    def test_rust_cache_identity_changes_with_the_release_profile(self) -> None:
        baseline = self.repo.plan(self.repo.base)["artifacts"]["rust_cache_cli"]
        root_manifest = (self.repo.root / "Cargo.toml").read_text()
        head = self.repo.change(
            "Cargo.toml",
            root_manifest.replace("lto = true", "lto = false"),
        )
        changed = self.repo.plan(head)["artifacts"]["rust_cache_cli"]
        self.assertEqual(changed["state"], "affected")
        self.assertNotEqual(
            changed["head_cache_fingerprint"], baseline["head_cache_fingerprint"]
        )

    def test_workspace_rust_cache_closure_contains_every_member(self) -> None:
        artifact = self.repo.plan(self.repo.base)["artifacts"]["rust_cache_workspace"]
        self.assertEqual(artifact["state"], "unaffected")
        self.assertRegex(artifact["head_cache_fingerprint"], r"^[0-9a-f]{64}$")

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
                document = repository.plan()
                self.assertEqual(self.runtime_states(document), tuple(expected))
                self.assertEqual(
                    self.workspace_states(document),
                    ("unaffected", "unaffected", "affected"),
                )

    def test_runtime_artifact_fact_does_not_change_capability_ownership(self) -> None:
        path = "deployments/docker/gateway.Dockerfile"
        capabilities_before = select_capabilities([path])
        self.repo.change(path, "FROM changed-gateway\n")
        self.assertEqual(
            self.runtime_states(self.repo.plan()),
            ("unaffected", "affected", "unaffected", "unaffected", "unaffected"),
        )
        capabilities_after = select_capabilities([path])
        self.assertEqual(capabilities_after, capabilities_before)
        self.assertEqual(capabilities_after["selector_version"], "v3")
        self.assertEqual(
            capabilities_after["selection"],
            "|valid:v3|deploy|go_consumer_interop|go_support|policy|"
            "policy_shell_omittable|release|runtime_confidential|complete|",
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

    def test_shared_netstack_affects_tailnet_runtime_images(self) -> None:
        self.repo.change(
            "crates/codewire-netstack/src/lib.rs",
            "pub fn netstack() { panic!(); }\n",
        )
        self.assertEqual(self.runtime_states(self.repo.plan()), ("affected",) * 5)

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

    def test_matching_deployed_source_uses_exact_ancestor(self) -> None:
        head = self.repo.change("apps/dashboard/README.md", "unrelated deploy baseline change\n")
        candidate = self.repo.deployed_source_candidate(self.repo.base, head)
        document = self.repo.deployed_source_plan(candidate, head)
        self.assertTrue(document["baseline"]["validation"]["valid"])
        self.assertEqual(document["baseline"]["mode"], "deployed_source")
        self.assertEqual(document["baseline"]["baseline_commit"], self.repo.base)
        self.assertEqual(self.runtime_states(document), ("unaffected",) * 5)
        self.assertEqual(self.dev_release_state(document), "unaffected")

    def test_dev_release_change_is_visible_from_deployed_source(self) -> None:
        head = self.repo.change(
            "deployments/k8s/runtime-profiles/confidential-smoke/job.yaml",
            "apiVersion: batch/v1\nkind: Job\n",
        )
        candidate = self.repo.deployed_source_candidate(self.repo.base, head)
        document = self.repo.deployed_source_plan(candidate, head)
        self.assertTrue(document["baseline"]["validation"]["valid"])
        self.assertEqual(self.dev_release_state(document), "affected")
        self.assertEqual(self.runtime_states(document), ("unaffected",) * 5)

    def deploy_outputs(self, repository: FixtureRepository, document: dict, head: str) -> dict[str, str]:
        tree = run(["git", "rev-parse", f"{head}^{{tree}}"], repository.root)
        with tempfile.TemporaryDirectory(prefix="codewire-deploy-adapter-") as temporary:
            plan_path = Path(temporary) / "plan.json"
            plan_path.write_text(json.dumps(document, sort_keys=True) + "\n")
            completed = subprocess.run(
                [
                    sys.executable,
                    str(PLANNER_PATH.parent / "apply-deploy-plan.py"),
                    "--plan",
                    str(plan_path),
                    "--head",
                    head,
                    "--head-tree",
                    tree,
                ],
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, "")
        return dict(line.split("=", 1) for line in completed.stdout.splitlines())

    def test_acceptance_harness_input_selects_exact_source_promotion(self) -> None:
        # promote-dev runs Dev acceptance only from the exact promoted source,
        # so a harness-only edit must promote that source to be accepted.
        for path in DEV_ACCEPTANCE_HARNESS_SPEC["inputs"]:
            with self.subTest(path=path), tempfile.TemporaryDirectory(
                prefix="codewire-acceptance-harness-test-"
            ) as temporary:
                repository = FixtureRepository(Path(temporary))
                head = repository.change(path, "# Synthetic harness edit\n")
                candidate = repository.deployed_source_candidate(repository.base, head)
                document = repository.deployed_source_plan(candidate, head)
                self.assertTrue(document["baseline"]["validation"]["valid"])
                self.assertFalse(document["degraded_reasons"])
                self.assertEqual(
                    document["artifacts"]["dev_acceptance_harness"]["state"], "affected"
                )
                self.assertEqual(self.dev_release_state(document), "unaffected")
                self.assertEqual(self.runtime_states(document), ("unaffected",) * 5)
                self.assertEqual(self.states(document), ("unaffected", "unaffected"))
                # Every Dev-selected source still publishes its exact workspace.
                self.assertEqual(
                    self.workspace_states(document),
                    ("unaffected", "unaffected", "affected"),
                )
                self.assertEqual(
                    document["artifacts"]["workspace_image_verification"]["state"],
                    "unaffected",
                )
                outputs = self.deploy_outputs(repository, document, head)
                self.assertEqual(outputs["deploy_dev"], "true")
                self.assertEqual(outputs["reason"], "dev_acceptance_affected")
                self.assertEqual(outputs["dev_acceptance_harness_state"], "affected")

    def test_unrelated_dashboard_script_and_docs_edits_still_skip_deployment(self) -> None:
        self.repo.write("apps/dashboard/scripts/unrelated-helper.ts", "export {};\n")
        self.repo.write("apps/dashboard/README.md", "unrelated app edit\n")
        head = self.repo.change("docs/dev/notes.md", "# Unrelated notes\n")
        candidate = self.repo.deployed_source_candidate(self.repo.base, head)
        document = self.repo.deployed_source_plan(candidate, head)
        self.assertTrue(document["baseline"]["validation"]["valid"])
        self.assertEqual(document["artifacts"]["dev_acceptance_harness"]["state"], "unaffected")
        self.assertTrue(all(
            artifact["state"] == "unaffected"
            for artifact in document["artifacts"].values()
        ))
        outputs = self.deploy_outputs(self.repo, document, head)
        self.assertEqual(outputs["deploy_dev"], "false")
        self.assertEqual(outputs["reason"], "artifacts_unaffected")

    def test_acceptance_entrypoint_keeps_its_verification_capabilities(self) -> None:
        path = "scripts/runtime/dev/run-secrets-credentials-acceptance.sh"
        self.assertIn(path, DEV_ACCEPTANCE_HARNESS_SPEC["inputs"])
        self.assertNotIn(path, PRODUCTION_GRAPH["non_artifact_inputs"])
        capabilities = select_capabilities([path])
        self.assertIn("|runtime_dev_smoke|", capabilities["selection"])

    def test_each_runtime_positive_is_visible_from_deployed_source(self) -> None:
        cases = (
            ("apps/dashboard/runtime-inventory.json", '{"changed":true}\n', 0),
            ("deployments/docker/gateway.Dockerfile", "FROM changed-gateway\n", 1),
            ("deployments/docker/derp.Cargo.lock", "version = 4\n# changed\n", 2),
            ("deployments/docker/services.Dockerfile.dockerignore", "*\n!changed\n", 3),
            ("deployments/docker/mesh.Dockerfile", "FROM changed-mesh\n", 4),
        )
        for path, content, affected_index in cases:
            with self.subTest(path=path), tempfile.TemporaryDirectory(
                prefix="codewire-deployed-source-test-"
            ) as temporary:
                repository = FixtureRepository(Path(temporary))
                head = repository.change(path, content)
                candidate = repository.deployed_source_candidate(repository.base, head)
                expected = ["unaffected"] * 5
                expected[affected_index] = "affected"
                document = repository.deployed_source_plan(candidate, head)
                self.assertEqual(
                    tuple(
                        document["artifacts"][name]["state"]
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

    def test_missing_failed_or_stale_deployed_source_fails_closed(self) -> None:
        missing = self.repo.root / "missing-deployed-source.json"
        missing_document = self.repo.deployed_source_plan(missing, self.repo.base)
        self.assertIn(
            "deployed source candidate is unavailable",
            missing_document["baseline"]["validation"]["reasons"],
        )
        self.assertEqual(self.runtime_states(missing_document), ("unclassified",) * 5)

        failed = self.repo.deployed_source_candidate(
            self.repo.base, self.repo.base, retrieval_valid=False
        )
        failed_document = self.repo.deployed_source_plan(failed, self.repo.base)
        self.assertIn(
            "deployed source candidate retrieval did not succeed",
            failed_document["baseline"]["validation"]["reasons"],
        )
        self.assertEqual(self.runtime_states(failed_document), ("unclassified",) * 5)

        head = self.repo.change("apps/dashboard/README.md", "new exact head\n")
        stale = self.repo.deployed_source_candidate(self.repo.base, self.repo.base)
        stale_document = self.repo.deployed_source_plan(stale, head)
        self.assertIn(
            "deployed source candidate is stale for the exact head",
            stale_document["baseline"]["validation"]["reasons"],
        )
        self.assertEqual(self.runtime_states(stale_document), ("unclassified",) * 5)

    def test_ambiguous_or_wrong_deployed_source_identity_fails_closed(self) -> None:
        wrong_repository = self.repo.deployed_source_candidate(
            self.repo.base,
            self.repo.base,
            source_repository="other/repository",
        )
        wrong_document = self.repo.deployed_source_plan(wrong_repository, self.repo.base)
        self.assertIn(
            "deployed source repository is invalid",
            wrong_document["baseline"]["validation"]["reasons"],
        )
        self.assertEqual(self.runtime_states(wrong_document), ("unclassified",) * 5)

        duplicate = self.repo.root / ".duplicate-deployed-source.json"
        duplicate.write_text(
            '{"schema":"codewire.ci-deployed-source-candidate/v1",'
            '"schema":"ambiguous"}\n'
        )
        duplicate_document = self.repo.deployed_source_plan(duplicate, self.repo.base)
        self.assertIn(
            "deployed source candidate is malformed",
            duplicate_document["baseline"]["validation"]["reasons"],
        )
        self.assertEqual(self.runtime_states(duplicate_document), ("unclassified",) * 5)

    def test_absent_or_non_ancestor_deployed_source_fails_closed(self) -> None:
        absent = self.repo.deployed_source_candidate("f" * 40, self.repo.base)
        absent_document = self.repo.deployed_source_plan(absent, self.repo.base)
        self.assertIn(
            "deployed source is absent from canonical Git history",
            absent_document["baseline"]["validation"]["reasons"],
        )
        self.assertEqual(self.runtime_states(absent_document), ("unclassified",) * 5)

        tree = run(["git", "rev-parse", "HEAD^{tree}"], self.repo.root)
        unrelated = run(["git", "commit-tree", tree, "-m", "unrelated deployed source"], self.repo.root)
        candidate = self.repo.deployed_source_candidate(unrelated, self.repo.base)
        document = self.repo.deployed_source_plan(candidate, self.repo.base)
        self.assertIn(
            "deployed source is not an ancestor of the exact head",
            document["baseline"]["validation"]["reasons"],
        )
        self.assertEqual(self.runtime_states(document), ("unclassified",) * 5)

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

    def test_relevant_generated_input_affects_both_packages(self) -> None:
        self.repo.change("generated/descriptor.bin", "descriptor-v2\n")
        document = self.repo.plan()
        self.assertEqual(self.states(document), ("affected", "affected"))
        self.assertEqual(self.workspace_states(document), ("affected", "unaffected", "affected"))

    def test_embedded_policy_and_private_protos_affect_every_reachable_package(self) -> None:
        inputs = {
            "codewire-egress-policy": "policies/developer-v1.yaml",
            "codewire-local-credentials": "proto/codewire/local/credentials/v1/authority.proto",
            "codewire-local-vmm": "proto/codewire/local/v1/control.proto",
        }
        graph_path = "scripts/ci/plan/artifact-graph.json"
        graph = json.loads((self.repo.root / graph_path).read_text())
        for name in ("cw_cli_release_assets", "desktop_package", "workspace_cw_binary"):
            # Exercise the real package-input maps, including all three
            # consumers, against synthetic reachable dependencies.
            graph["artifacts"][name]["package_inputs"].update(
                PRODUCTION_GRAPH["artifacts"][name]["package_inputs"]
            )
        self.repo.write(graph_path, json.dumps(graph, sort_keys=True, indent=2) + "\n")
        for package, relative in inputs.items():
            directory = f"crates/{package}"
            self.repo.write(
                f"{directory}/Cargo.toml",
                f'[package]\nname = "{package}"\nversion = "0.1.0"\nedition = "2021"\n',
            )
            self.repo.write(f"{directory}/src/lib.rs", "pub fn embedded_contract() {}\n")
            self.repo.write(f"{directory}/{relative}", "synthetic embedded input\n")
            workspace = (self.repo.root / "Cargo.toml").read_text()
            self.repo.write("Cargo.toml", workspace.replace('members = [', f'members = ["{directory}", '))
            for manifest_path in ("cli/Cargo.toml", "desktop/Cargo.toml"):
                manifest = (self.repo.root / manifest_path).read_text()
                self.repo.write(
                    manifest_path,
                    manifest.replace("[dependencies]\n", f'[dependencies]\n{package} = {{ path = "../{directory}" }}\n'),
                )
            for lock_path in ("Cargo.lock", "desktop/Cargo.lock"):
                lock = (self.repo.root / lock_path).read_text()
                self.repo.write(lock_path, lock + f'\n[[package]]\nname = "{package}"\nversion = "0.1.0"\n')
        self.repo.base = self.repo.commit("reachable embedded policy and private protocol inputs")

        for package, relative in inputs.items():
            with self.subTest(package=package):
                head = self.repo.change(f"crates/{package}/{relative}", "changed embedded input\n")
                document = self.repo.plan()
                self.assertEqual(self.states(document), ("affected", "affected"))
                self.assertEqual(document["artifacts"]["workspace_cw_binary"]["state"], "affected")
                self.assertEqual(document["artifacts"]["workspace_image_verification"]["state"], "affected")
                self.repo.base = head

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

    def test_runtime_crates_ownership_does_not_hide_unknown_reachable_input(self) -> None:
        # Production runtime images own crates/**. An overlapping image input
        # must not classify an unmodeled embedded CLI asset as unchanged.
        (self.repo.root / "crates").mkdir(exist_ok=True)
        (self.repo.root / "cli").rename(self.repo.root / "crates/cli")
        manifest = (self.repo.root / "crates/cli/Cargo.toml").read_text()
        self.repo.write("crates/cli/Cargo.toml", manifest.replace('path = "../', 'path = "../../'))
        workspace = (self.repo.root / "Cargo.toml").read_text()
        self.repo.write("Cargo.toml", workspace.replace('"cli",', '"crates/cli",'))
        self.repo.base = self.repo.commit("reachable CLI under runtime image ownership")

        self.repo.change("crates/cli/assets/theme.dat", "new embedded asset\n")
        document = self.repo.plan()
        self.assertEqual(self.states(document), ("unclassified", "unaffected"))
        self.assertEqual(
            document["artifacts"]["workspace_cw_binary"]["state"], "unclassified"
        )
        self.assertIn(
            "crates/cli/assets/theme.dat",
            document["artifacts"]["workspace_cw_binary"]["explanations"][0],
        )
        self.assertEqual(document["artifacts"]["services_image"]["state"], "affected")

        self.repo.base = run(["git", "rev-parse", "HEAD"], self.repo.root)
        (self.repo.root / "crates/cli/assets/theme.dat").unlink()
        self.repo.commit("remove unknown reachable input")
        self.assertEqual(self.states(self.repo.plan()), ("unclassified", "unaffected"))

        self.repo.base = run(["git", "rev-parse", "HEAD"], self.repo.root)
        self.repo.change("crates/cli/src/main.rs", "fn main() { println!(\"known source\"); }\n")
        self.assertEqual(self.states(self.repo.plan()), ("affected", "unaffected"))

    def test_unrelated_runtime_asset_does_not_select_rust_artifacts(self) -> None:
        self.repo.change("crates/unrelated/assets/theme.dat", "runtime-only asset\n")
        document = self.repo.plan()
        self.assertEqual(self.states(document), ("unaffected", "unaffected"))
        self.assertEqual(document["artifacts"]["workspace_cw_binary"]["state"], "unaffected")
        self.assertEqual(document["artifacts"]["workspace_image_verification"]["state"], "unaffected")
        self.assertEqual(document["artifacts"]["services_image"]["state"], "affected")

    def test_known_non_artifact_changes_leave_artifacts_unaffected(self) -> None:
        self.repo.change("AGENTS.md", "# Agent policy\n")
        self.repo.change("CLAUDE.md", "AGENTS.md\n")
        self.repo.change(".agents/skills/example/SKILL.md", "# Example skill\n")
        self.repo.change("docs/dev/AGENT-WORKFLOW.md", "# Agent workflow\n")
        document = self.repo.plan()
        self.assertFalse(document["degraded_reasons"])
        self.assertEqual(self.states(document), ("unaffected", "unaffected"))
        self.assertEqual(
            self.workspace_states(document),
            ("unaffected", "unaffected", "unaffected"),
        )
        self.assertEqual(
            self.runtime_states(document),
            (
                "unaffected",
                "unaffected",
                "unaffected",
                "unaffected",
                "unaffected",
            ),
        )

    def test_runtime_signing_changes_do_not_select_product_builds(self) -> None:
        self.repo.write(
            "scripts/ci/images/cosign-private-signing-config.json",
            '{"privateInfrastructure": true}\n',
        )
        self.repo.write(
            "scripts/ci/images/sign-runtime-image-set.sh",
            "#!/usr/bin/env bash\nset -euo pipefail\n",
            0o755,
        )
        self.repo.write(
            "scripts/ci/tests/test-sign-runtime-image-set.sh",
            "#!/usr/bin/env bash\nset -euo pipefail\n",
            0o755,
        )
        self.repo.write(
            "scripts/ci/trust/codewire-runtime-signing.pub",
            "fixture public key\n",
        )
        self.repo.commit("runtime signing change")

        document = self.repo.plan()
        self.assertFalse(document["degraded_reasons"])
        self.assertTrue(
            all(
                artifact["state"] == "unaffected"
                for artifact in document["artifacts"].values()
            )
        )

    def test_kind_suite_fixture_is_policy_only_without_artifact_changes(self) -> None:
        path = "scripts/ci/tests/test-kind-e2e-suites.sh"
        self.assertIn(path, PRODUCTION_GRAPH["non_artifact_inputs"])
        self.repo.write(path, "#!/usr/bin/env bash\nset -euo pipefail\n", 0o755)
        self.repo.commit("kind suite fixture change")
        document = self.repo.plan()
        self.assertFalse(document["degraded_reasons"])
        self.assertTrue(all(
            artifact["state"] == "unaffected"
            for artifact in document["artifacts"].values()
        ))
        capabilities = select_capabilities([path])
        self.assertIn("|policy|", capabilities["selection"])

    def test_unknown_kind_suite_fixture_neighbor_remains_unclassified(self) -> None:
        # The exact fixture exemption must not cover its unreviewed neighbors.
        self.repo.write(
            "scripts/ci/tests/test-kind-e2e-suites.sh",
            "#!/usr/bin/env bash\nset -euo pipefail\n",
            0o755,
        )
        self.repo.change("scripts/ci/tests/test-kind-e2e-unreviewed.sh", "# Unknown input\n")
        document = self.repo.plan()
        self.assertEqual(self.states(document), ("unclassified",) * 2)

    def test_credential_acceptance_paths_keep_capability_checks_without_artifact_changes(self) -> None:
        for path in CREDENTIAL_ACCEPTANCE_PATHS:
            self.assertIn(path, PRODUCTION_GRAPH["non_artifact_inputs"])
            self.repo.write(path, "# Synthetic acceptance-only edit\n")
        self.repo.commit("credential acceptance helpers")
        document = self.repo.plan()
        self.assertTrue(all(
            artifact["state"] == "unaffected"
            for artifact in document["artifacts"].values()
        ))
        capabilities = select_capabilities(list(CREDENTIAL_ACCEPTANCE_PATHS))
        self.assertIn("|runtime_dev_smoke|", capabilities["selection"])
        self.assertIn("|policy|", capabilities["selection"])

    def test_exact_main_credential_acceptance_and_policy_edits_skip_publication(self) -> None:
        for path in CREDENTIAL_ACCEPTANCE_PATHS:
            self.repo.write(path, "# Synthetic acceptance-only edit\n")
        for path in (
            "scripts/ci/select/select-verification.sh",
            "scripts/ci/tests/test-select-verification.sh",
            "scripts/ci/verify/run-product-verification.sh",
        ):
            self.repo.write(path, "# Synthetic verifier-policy edit\n")
        head = self.repo.commit("acceptance helpers plus verifier policy")
        # Proposed policy must not exempt its own PR qualification.
        self.assertTrue(all(
            artifact["state"] == "unclassified"
            for artifact in self.repo.plan()["artifacts"].values()
        ))
        deployed = self.repo.deployed_source_candidate(self.repo.base, head)
        support = self.repo.support_candidate(self.repo.base)
        for document in (
            self.repo.deployed_source_plan(deployed, head),
            self.repo.support_plan(support, head),
        ):
            self.assertTrue(document["baseline"]["validation"]["valid"])
            self.assertFalse(document["degraded_reasons"])
            self.assertTrue(all(
                artifact["state"] == "unaffected"
                for artifact in document["artifacts"].values()
            ))

    def test_unknown_credential_acceptance_neighbor_remains_unclassified(self) -> None:
        # An unknown neighbor must not join the canonical policy-only exemption.
        self.repo.write("scripts/ci/select/credential-fixture.sh", "# Policy edit\n")
        head = self.repo.change(
            "scripts/runtime/dev/provider-openai-unreviewed.sh", "# Unknown input\n"
        )
        candidate = self.repo.deployed_source_candidate(self.repo.base, head)
        support = self.repo.support_candidate(self.repo.base)
        for document in (
            self.repo.deployed_source_plan(candidate, head),
            self.repo.support_plan(support, head),
        ):
            self.assertEqual(self.runtime_states(document), ("unclassified",) * 5)
            self.assertEqual(self.states(document), ("unclassified",) * 2)

    def test_credential_acceptance_does_not_hide_real_runtime_image_changes(self) -> None:
        self.repo.write(CREDENTIAL_ACCEPTANCE_PATHS[0], "# Acceptance-only edit\n")
        head = self.repo.change("apps/dashboard/runtime-inventory.json", '{"new":true}\n')
        candidate = self.repo.deployed_source_candidate(self.repo.base, head)
        document = self.repo.deployed_source_plan(candidate, head)
        self.assertEqual(
            self.runtime_states(document),
            ("affected", "unaffected", "unaffected", "unaffected", "unaffected"),
        )
        self.assertEqual(document["artifacts"]["workspace_image"]["state"], "affected")

    def test_unknown_root_path_still_fails_closed(self) -> None:
        self.repo.change("unknown-root-input.txt", "unknown\n")
        document = self.repo.plan()
        self.assertEqual(self.states(document), ("unclassified", "unclassified"))
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

    def test_confidential_probe_change_affects_only_probe_image(self) -> None:
        self.repo.change(
            "images/confidential-probe/Dockerfile",
            "FROM scratch\n",
        )
        artifacts = self.repo.plan()["artifacts"]
        self.assertEqual(artifacts["confidential_probe_image"]["state"], "affected")
        self.assertEqual(self.workspace_states(self.repo.plan()), ("unaffected",) * 3)

    def test_unrelated_lock_record_selects_workspace_for_runtime_release(self) -> None:
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
            ("unaffected", "unaffected", "affected"),
        )

    def test_policy_change_fails_every_artifact_closed(self) -> None:
        self.repo.change("scripts/ci/plan/new-policy-input.txt", "policy change\n")
        with mock.patch.object(
            planner, "cargo_metadata", side_effect=fixture_cargo_metadata
        ) as metadata:
            document = planner.plan(
                self.repo.root, self.repo.base, "HEAD", self.repo.base
            )
        self.assertTrue(all(value["state"] == "unclassified" for value in document["artifacts"].values()))
        self.assertEqual(metadata.call_count, 2)
        for artifact in ("rust_cache_cli", "rust_cache_workspace"):
            cache = document["artifacts"][artifact]
            self.assertRegex(cache["baseline_cache_fingerprint"], r"^[0-9a-f]{64}$")
            self.assertEqual(
                cache["baseline_cache_fingerprint"], cache["head_cache_fingerprint"]
            )

    def test_exact_main_policy_change_uses_artifact_fingerprints(self) -> None:
        head = self.repo.change(
            "scripts/ci/plan/new-policy-input.txt",
            "protected main policy change\n",
        )

        deployed_candidate = self.repo.deployed_source_candidate(self.repo.base, head)
        deployed_document = self.repo.deployed_source_plan(deployed_candidate, head)
        self.assertTrue(deployed_document["baseline"]["validation"]["valid"])
        self.assertTrue(
            all(
                artifact["state"] == "unaffected"
                for artifact in deployed_document["artifacts"].values()
            )
        )

        support_candidate = self.repo.support_candidate(self.repo.base)
        support_document = self.repo.support_plan(support_candidate, head)
        self.assertTrue(support_document["baseline"]["validation"]["valid"])
        self.assertTrue(
            all(
                artifact["state"] == "unaffected"
                for artifact in support_document["artifacts"].values()
            )
        )

        mixed_head = self.repo.change(
            "apps/dashboard/runtime-inventory.json",
            '{"changed": true}\n',
        )
        mixed_candidate = self.repo.deployed_source_candidate(
            self.repo.base,
            mixed_head,
        )
        mixed_document = self.repo.deployed_source_plan(
            mixed_candidate,
            mixed_head,
        )
        self.assertTrue(
            all(
                artifact["state"] == "unclassified"
                for artifact in mixed_document["artifacts"].values()
            )
        )

    def test_non_artifact_workflow_change_does_not_select_builds(self) -> None:
        self.repo.change(
            ".gitea/workflows/mirror-github.yaml",
            "name: Mirror GitHub\n",
        )
        document = self.repo.plan()
        self.assertTrue(
            all(
                value["state"] == "unaffected"
                for value in document["artifacts"].values()
            )
        )

    def test_exact_main_dispatch_controls_do_not_select_builds(self) -> None:
        self.repo.write(".gitea/workflows/ci.yaml", "name: CI\n")
        self.repo.write(
            "scripts/ci/select/emit-verification-matrices.sh",
            "#!/usr/bin/env bash\nset -euo pipefail\n",
            0o755,
        )
        self.repo.write(
            "scripts/ci/select/require-verification-results.sh",
            "#!/usr/bin/env bash\nset -euo pipefail\n",
            0o755,
        )
        self.repo.write(
            "scripts/ci/select/select-verification.sh",
            "#!/usr/bin/env bash\nset -euo pipefail\n",
            0o755,
        )
        self.repo.write(
            "scripts/ci/receipts/verify-tested-tree-receipt.sh",
            "#!/usr/bin/env bash\nset -euo pipefail\n",
            0o755,
        )
        for name in (
            "test-emit-verification-matrices.sh",
            "test-require-verification-results.sh",
            "test-select-verification.sh",
            "test-shellcheck-policy-domain.sh",
            "test-verify-tested-tree-receipt.sh",
        ):
            self.repo.write(
                f"scripts/ci/tests/{name}",
                "#!/usr/bin/env bash\nset -euo pipefail\n",
                0o755,
            )
        self.repo.write(
            "scripts/ci/verify/run-product-verification.sh",
            "#!/usr/bin/env bash\nset -euo pipefail\n",
            0o755,
        )
        head = self.repo.commit("reviewed dispatch-only controls")
        candidate = self.repo.deployed_source_candidate(self.repo.base, head)
        document = self.repo.deployed_source_plan(candidate, head)
        self.assertFalse(document["degraded_reasons"])
        self.assertTrue(
            all(
                value["state"] == "unaffected"
                for value in document["artifacts"].values()
            )
        )

    def test_legacy_selector_change_fails_every_artifact_closed(self) -> None:
        self.repo.change("scripts/ci/select/select-verification.sh", "#!/bin/sh\nexit 0\n")
        document = self.repo.plan()
        self.assertTrue(all(value["state"] == "unclassified" for value in document["artifacts"].values()))
        for artifact in ("rust_cache_cli", "rust_cache_workspace"):
            cache = document["artifacts"][artifact]
            self.assertEqual(
                cache["baseline_cache_fingerprint"], cache["head_cache_fingerprint"]
            )

    def test_policy_change_does_not_hide_a_cache_input_change(self) -> None:
        self.repo.change("scripts/ci/select/select-verification.sh", "#!/bin/sh\nexit 0\n")
        self.repo.change("generated/descriptor.bin", "changed descriptor\n")
        document = self.repo.plan()
        self.assertTrue(all(value["state"] == "unclassified" for value in document["artifacts"].values()))
        for artifact in ("rust_cache_cli", "rust_cache_workspace"):
            cache = document["artifacts"][artifact]
            self.assertNotEqual(
                cache["baseline_cache_fingerprint"], cache["head_cache_fingerprint"]
            )

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
            document = planner.plan(self.repo.root, self.repo.base, "HEAD", self.repo.base)

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

    def test_git_archive_stream_is_drained_before_the_producer_is_reaped(self) -> None:
        target = tarfile.TarInfo("target")
        target.size = 1
        archive = self.archive([(target, b"x")]).getvalue()

        class ChunkedArchiveStream(io.BytesIO):
            def __init__(self, content: bytes) -> None:
                super().__init__(content)
                self.length = len(content)
                self.drained_before_close = False

            def read(self, size: int = -1) -> bytes:
                return super().read(512 if size < 0 else min(size, 512))

            def close(self) -> None:
                self.drained_before_close = self.tell() == self.length
                super().close()

        class ArchiveProcess:
            def __init__(self, content: bytes) -> None:
                self.stdout = ChunkedArchiveStream(content)
                self.stderr = io.BytesIO()
                self.returncode: int | None = None

            def communicate(self) -> tuple[bytes, bytes]:
                remaining = b"".join(iter(lambda: self.stdout.read(8192), b""))
                stderr = self.stderr.read()
                self.stdout.close()
                self.stderr.close()
                self.returncode = 0 if self.stdout.drained_before_close else -13
                return remaining, stderr

            def kill(self) -> None:
                self.returncode = -9

        process = ArchiveProcess(archive)
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary)
            with mock.patch.object(planner.subprocess, "Popen", return_value=process):
                planner.export_git_tree(Path("."), "HEAD", destination)
            self.assertEqual((destination / "target").read_text(), "x")

        self.assertTrue(process.stdout.drained_before_close)


if __name__ == "__main__":
    unittest.main()
