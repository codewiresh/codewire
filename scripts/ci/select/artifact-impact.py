#!/usr/bin/env python3
"""Classify cumulative source changes by their published artifact impact."""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path, PurePosixPath
import re
import shlex
import subprocess
import sys
import tomllib
from typing import Any, Iterable


SHA_RE = re.compile(r"^[0-9a-f]{40}$")
ZERO_SHA = "0" * 40

RUNTIME_PACKAGES = {
    "codewire-gateway",
    "codewire-cli-bin",
    "codewire-derp",
    "codewire-idp",
    "codewire-orchestration",
    "codewire-billing",
    "codewire-coordinator",
    "codewire-udp-relay",
    "codewire-mesh",
}
SUPPORT_PACKAGES = {"codewire-cli-bin"}

CARGO_PRESENTATION_KEYS = {
    "authors",
    "categories",
    "description",
    "documentation",
    "homepage",
    "keywords",
    "license",
    "license-file",
    "license-files",
    "publish",
    "readme",
    "repository",
}
NPM_PRESENTATION_KEYS = {
    "author",
    "bugs",
    "contributors",
    "description",
    "funding",
    "homepage",
    "keywords",
    "license",
    "repository",
}

RUNTIME_EXACT_INPUTS = {
    ".gitea/workflows/deploy-dev.yaml",
    "Cargo.lock",
    "rust-toolchain.toml",
    "scripts/ci/deploy/dispatch-deploy-dev.sh",
    "scripts/ci/deploy/resolve-deployed-source.sh",
    "scripts/ci/select/select-deploy-dev.sh",
    "scripts/ci/setup/fetch-infisical-ci-secret.sh",
}
SUPPORT_EXACT_INPUTS = {
    ".gitea/workflows/support-images.yaml",
    "Cargo.lock",
    "rust-toolchain.toml",
    "scripts/ci/select/select-support-images.sh",
    "scripts/ci/setup/fetch-infisical-ci-secret.sh",
}

# These helpers build disposable, locally loaded verification images. They do
# not build, tag, copy, sign, bundle, or publish a release artifact. Keep this
# allowlist exact so new scripts below scripts/ci/images continue to fail
# closed as publication inputs until they are deliberately classified.
LOCAL_ONLY_IMAGE_HELPERS = {
    "scripts/ci/images/build-local-image.sh",
}

RUNTIME_DOCKERFILES = {
    "deployments/docker/gateway.Dockerfile": ".",
    "deployments/docker/derp.Dockerfile": ".",
    "deployments/docker/services.Dockerfile": ".",
    "deployments/docker/mesh.Dockerfile": ".",
    "apps/dashboard/Dockerfile": ".",
}
SUPPORT_DOCKERFILES = {
    "images/base/Dockerfile": "images/base",
    "images/workspace/Dockerfile": ".",
}

RUNTIME_DOCKER_MODELED_ROOTS = {
    "Cargo.toml",
    "Cargo.lock",
    "deployments/docker",
    "crates",
    "proto",
    "libs/gateway-proto",
    "package.json",
    "bun.lock",
    "apps/dashboard",
    "apps/docs",
    "packages/auth/package.json",
    "packages/codewire-design",
    "packages/codewire-proto-ts",
}
SUPPORT_DOCKER_MODELED_ROOTS = {
    "Cargo.toml",
    "Cargo.lock",
    "crates",
    "proto",
    "libs/gateway-proto",
    "images/base",
}

DEV_FIXED_PREFIXES = (
    "deployments/k8s/flux/temporal-dev/",
    "deployments/k8s/flux/mesh-dev/",
    "deployments/k8s/agent-sandbox/base/",
    "deployments/k8s/runtime-profiles/base/",
    "deployments/k8s/runtime-profiles/confidential-smoke/",
    "apps/cli/charts/codewire-mesh/",
)
DEV_FIXED_FILES = {"deployments/k8s/mesh-dev/values.yaml"}


class ImpactError(RuntimeError):
    """A relevant definition cannot be classified safely."""


def run(
    args: list[str],
    *,
    cwd: Path,
    check: bool = True,
    text: bool = True,
) -> subprocess.CompletedProcess[str] | subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        args,
        cwd=cwd,
        check=check,
        capture_output=True,
        text=text,
    )


def git(root: Path, *args: str, check: bool = True) -> str:
    result = run(["git", *args], cwd=root, check=check)
    assert isinstance(result.stdout, str)
    return result.stdout


def valid_commit(root: Path, revision: str) -> bool:
    if not SHA_RE.fullmatch(revision) or revision == ZERO_SHA:
        return False
    result = run(
        ["git", "cat-file", "-e", f"{revision}^{{commit}}"],
        cwd=root,
        check=False,
    )
    return result.returncode == 0


def git_file(root: Path, revision: str, path: str) -> bytes | None:
    result = run(
        ["git", "show", f"{revision}:{path}"],
        cwd=root,
        check=False,
        text=False,
    )
    if result.returncode != 0:
        return None
    assert isinstance(result.stdout, bytes)
    return result.stdout


def changed_paths(root: Path, base: str, head: str) -> list[str]:
    result = run(
        ["git", "diff", "--name-status", "-z", "--find-renames", base, head],
        cwd=root,
        text=False,
    )
    assert isinstance(result.stdout, bytes)
    fields = result.stdout.split(b"\0")
    if fields and fields[-1] == b"":
        fields.pop()

    paths: list[str] = []
    index = 0
    while index < len(fields):
        status = fields[index].decode("ascii", "strict")
        index += 1
        count = 2 if status.startswith(("R", "C")) else 1
        if index + count > len(fields):
            raise ImpactError("malformed Git name-status output")
        for _ in range(count):
            paths.append(fields[index].decode("utf-8", "surrogateescape"))
            index += 1
    return sorted(set(paths))


def is_legal_or_repository_text(path: str) -> bool:
    name = PurePosixPath(path).name.upper()
    return (
        name == "AGENTS.MD"
        or name == "README"
        or name.startswith("README.")
        or name == "LICENSE"
        or name.startswith("LICENSE-")
        or name.startswith("LICENSE.")
    )


def is_test_only(path: str) -> bool:
    parts = PurePosixPath(path).parts
    return any(part in {"test", "tests", "__tests__", "fixtures"} for part in parts)


def normalized_repo_path(root: Path, value: str) -> str:
    path = Path(value)
    if path.is_absolute():
        path = path.resolve().relative_to(root)
    return path.as_posix().removeprefix("./")


def cargo_closure(root: Path, package_names: set[str]) -> tuple[set[str], set[str]]:
    result = run(
        ["cargo", "metadata", "--format-version", "1", "--no-deps"],
        cwd=root,
        check=False,
    )
    if result.returncode != 0:
        raise ImpactError("cargo metadata failed")
    try:
        metadata = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise ImpactError("cargo metadata returned invalid JSON") from error

    packages = metadata.get("packages")
    if not isinstance(packages, list):
        raise ImpactError("cargo metadata omitted packages")

    by_name: dict[str, dict[str, Any]] = {}
    by_root: dict[str, dict[str, Any]] = {}
    for package in packages:
        if not isinstance(package, dict):
            raise ImpactError("cargo metadata package is malformed")
        name = package.get("name")
        manifest_path = package.get("manifest_path")
        if not isinstance(name, str) or not isinstance(manifest_path, str):
            raise ImpactError("cargo metadata package identity is malformed")
        package_root = normalized_repo_path(root, str(Path(manifest_path).parent))
        by_name[name] = package
        by_root[package_root] = package

    missing = sorted(package_names - by_name.keys())
    if missing:
        raise ImpactError(f"shipped Cargo packages missing: {', '.join(missing)}")

    selected_roots: set[str] = set()
    manifests: set[str] = {"Cargo.toml"}
    pending = [by_name[name] for name in sorted(package_names)]
    while pending:
        package = pending.pop()
        manifest_path = package["manifest_path"]
        package_root = normalized_repo_path(root, str(Path(manifest_path).parent))
        if package_root in selected_roots:
            continue
        selected_roots.add(package_root)
        manifests.add(normalized_repo_path(root, manifest_path))
        dependencies = package.get("dependencies")
        if not isinstance(dependencies, list):
            raise ImpactError("cargo metadata dependencies are malformed")
        for dependency in dependencies:
            if not isinstance(dependency, dict):
                raise ImpactError("cargo metadata dependency is malformed")
            dependency_path = dependency.get("path")
            if dependency_path is None:
                continue
            if not isinstance(dependency_path, str):
                raise ImpactError("cargo metadata dependency path is malformed")
            dependency_root = normalized_repo_path(root, dependency_path)
            local = by_root.get(dependency_root)
            if local is None:
                raise ImpactError(f"unresolved local Cargo dependency: {dependency_root}")
            pending.append(local)
    return selected_roots, manifests


def strip_cargo_presentation(document: dict[str, Any]) -> dict[str, Any]:
    stripped = copy.deepcopy(document)
    package = stripped.get("package")
    if isinstance(package, dict):
        for key in CARGO_PRESENTATION_KEYS:
            package.pop(key, None)
    workspace = stripped.get("workspace")
    if isinstance(workspace, dict):
        workspace_package = workspace.get("package")
        if isinstance(workspace_package, dict):
            for key in CARGO_PRESENTATION_KEYS:
                workspace_package.pop(key, None)
    return stripped


def strip_npm_presentation(document: dict[str, Any]) -> dict[str, Any]:
    stripped = copy.deepcopy(document)
    for key in NPM_PRESENTATION_KEYS:
        stripped.pop(key, None)
    return stripped


def semantic_manifest_changed(
    root: Path,
    base: str,
    head: str,
    path: str,
    kind: str,
) -> bool:
    before = git_file(root, base, path)
    after = git_file(root, head, path)
    if before is None or after is None:
        return True
    try:
        if kind == "cargo":
            before_value = strip_cargo_presentation(tomllib.loads(before.decode()))
            after_value = strip_cargo_presentation(tomllib.loads(after.decode()))
        elif kind == "npm":
            before_document = json.loads(before)
            after_document = json.loads(after)
            if not isinstance(before_document, dict) or not isinstance(after_document, dict):
                raise ImpactError(f"{path} is not a JSON object")
            before_value = strip_npm_presentation(before_document)
            after_value = strip_npm_presentation(after_document)
        else:
            raise AssertionError(kind)
    except (UnicodeDecodeError, tomllib.TOMLDecodeError, json.JSONDecodeError) as error:
        raise ImpactError(f"cannot parse relevant manifest {path}") from error
    return before_value != after_value


def parse_kustomization_resources(path: Path) -> list[str]:
    resources: list[str] = []
    list_key: str | None = None
    list_indent = -1
    patches_indent: int | None = None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as error:
        raise ImpactError(f"cannot read {path}") from error

    for raw in lines:
        line = raw.split("#", 1)[0].rstrip()
        if not line:
            continue
        indent = len(line) - len(line.lstrip())
        stripped = line.strip()
        if (
            patches_indent is not None
            and indent <= patches_indent
            and not re.fullmatch(r"patches:\s*", stripped)
        ):
            patches_indent = None
        unsupported_inline = re.fullmatch(
            r"(resources|bases|components|patchesStrategicMerge|envs|files):\s*(.+)",
            stripped,
        )
        if unsupported_inline:
            raise ImpactError(f"inline Kustomize file list in {path}")
        key_match = re.fullmatch(
            r"(resources|bases|components|patchesStrategicMerge|envs|files):\s*",
            stripped,
        )
        if key_match:
            list_key = key_match.group(1)
            list_indent = indent
            continue
        if re.fullmatch(r"patches:\s*", stripped):
            patches_indent = indent
            list_key = None
            continue
        patch_match = re.fullmatch(r"-\s+path:\s*(.+)", stripped)
        if (
            patch_match
            and patches_indent is not None
            and indent > patches_indent
        ):
            resources.append(patch_match.group(1).strip().strip("\"'"))
            continue
        value_file_match = re.fullmatch(r"valuesFile:\s*(.+)", stripped)
        if value_file_match:
            resources.append(value_file_match.group(1).strip().strip("\"'"))
            continue
        if list_key is not None and indent <= list_indent:
            list_key = None
        if list_key is None:
            continue
        item_match = re.fullmatch(r"-\s+(.+)", stripped)
        if item_match:
            value = item_match.group(1).strip().strip("\"'")
            if list_key == "files" and "=" in value:
                value = value.split("=", 1)[1]
            if "://" in value or value.startswith("git::"):
                raise ImpactError(f"remote Kustomize resource in {path}")
            resources.append(value)
    return resources


def dev_kustomize_closure(root: Path) -> tuple[set[str], set[str]]:
    files: set[str] = set()
    directories: set[str] = set()
    pending = [root / "deployments/k8s/overlays/dev"]
    visited: set[Path] = set()

    while pending:
        directory = pending.pop().resolve()
        try:
            relative_directory = directory.relative_to(root).as_posix()
        except ValueError as error:
            raise ImpactError("Kustomize resource escaped repository") from error
        if directory in visited:
            continue
        visited.add(directory)
        directories.add(relative_directory)
        if not directory.is_dir():
            raise ImpactError(f"missing Kustomize directory: {relative_directory}")

        kustomization = next(
            (
                candidate
                for candidate in (
                    directory / "kustomization.yaml",
                    directory / "kustomization.yml",
                    directory / "Kustomization",
                )
                if candidate.is_file()
            ),
            None,
        )
        if kustomization is None:
            raise ImpactError(f"missing Kustomization in {relative_directory}")

        for child in directory.iterdir():
            if child.is_file():
                files.add(child.relative_to(root).as_posix())

        for resource in parse_kustomization_resources(kustomization):
            candidate = (directory / resource).resolve()
            try:
                relative = candidate.relative_to(root).as_posix()
            except ValueError as error:
                raise ImpactError("Kustomize resource escaped repository") from error
            if candidate.is_dir():
                pending.append(candidate)
            elif candidate.is_file():
                files.add(relative)
            else:
                raise ImpactError(f"missing Kustomize resource: {relative}")
    return files, directories


def path_in_directory(path: str, directory: str) -> bool:
    return path == directory or path.startswith(f"{directory}/")


def parse_docker_copy_sources(dockerfile: Path, context: str) -> list[str]:
    logical_lines: list[str] = []
    current = ""
    try:
        lines = dockerfile.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as error:
        raise ImpactError(f"cannot read {dockerfile}") from error
    for raw in lines:
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        current = f"{current} {stripped}".strip()
        if current.endswith("\\"):
            current = current[:-1].rstrip()
            continue
        logical_lines.append(current)
        current = ""
    if current:
        raise ImpactError(f"unterminated Dockerfile continuation: {dockerfile}")

    sources: list[str] = []
    for line in logical_lines:
        if not re.match(r"^(COPY|ADD)\s", line, re.IGNORECASE):
            continue
        try:
            tokens = shlex.split(line)
        except ValueError as error:
            raise ImpactError(f"cannot parse Docker instruction in {dockerfile}") from error
        arguments = tokens[1:]
        from_stage = any(argument.startswith("--from=") for argument in arguments)
        arguments = [argument for argument in arguments if not argument.startswith("--")]
        if from_stage:
            continue
        if len(arguments) < 2:
            raise ImpactError(f"malformed Docker copy in {dockerfile}")
        for source in arguments[:-1]:
            if any(character in source for character in ("$", "*", "?", "[", "]")):
                raise ImpactError(f"dynamic Docker copy source in {dockerfile}: {source}")
            if source in {".", "./"}:
                raise ImpactError(f"whole-context Docker copy in {dockerfile}")
            joined = (PurePosixPath(context) / source).as_posix()
            sources.append(str(PurePosixPath(joined)))
    return sources


def modeled_path(path: str, roots: set[str]) -> bool:
    return any(path == root or path.startswith(f"{root}/") for root in roots)


def docker_contract_errors(root: Path, mode: str) -> list[str]:
    definitions = RUNTIME_DOCKERFILES if mode == "runtime" else SUPPORT_DOCKERFILES
    modeled_roots = (
        RUNTIME_DOCKER_MODELED_ROOTS
        if mode == "runtime"
        else SUPPORT_DOCKER_MODELED_ROOTS
    )
    errors: list[str] = []
    for dockerfile, context in sorted(definitions.items()):
        try:
            sources = parse_docker_copy_sources(root / dockerfile, context)
        except ImpactError as error:
            errors.append(str(error))
            continue
        for source in sources:
            if not modeled_path(source, modeled_roots):
                errors.append(f"{dockerfile} consumes uncovered source root {source}")
    return errors


def artifact_contract_errors(root: Path, mode: str) -> list[str]:
    errors = docker_contract_errors(root, mode)
    if mode == "runtime":
        try:
            dev_kustomize_closure(root)
        except ImpactError as error:
            errors.append(str(error))
    return errors


def classify_rust(
    root: Path,
    base: str,
    head: str,
    paths: Iterable[str],
    mode: str,
) -> set[str]:
    path_set = set(paths)
    if not any(
        path == "Cargo.toml"
        or path == "Cargo.lock"
        or path == "rust-toolchain.toml"
        or path.startswith("crates/")
        for path in path_set
    ):
        return set()

    roots, manifests = cargo_closure(
        root,
        RUNTIME_PACKAGES if mode == "runtime" else SUPPORT_PACKAGES,
    )
    categories: set[str] = set()
    for path in path_set:
        if is_legal_or_repository_text(path):
            continue
        if path in {"Cargo.lock", "rust-toolchain.toml"}:
            categories.add("rust-lock-or-toolchain")
            continue
        if path == "Cargo.toml" or path in manifests:
            if semantic_manifest_changed(root, base, head, path, "cargo"):
                categories.add("rust-manifest")
            continue
        for package_root in roots:
            if not path_in_directory(path, package_root):
                continue
            relative = PurePosixPath(path).relative_to(package_root)
            if (
                relative.parts
                and relative.parts[0] in {"src", "migrations"}
                or relative.as_posix() == "build.rs"
            ):
                categories.add("rust-source")
            break
    return categories


def classify_web(root: Path, base: str, head: str, paths: Iterable[str]) -> set[str]:
    categories: set[str] = set()
    relevant_manifests = {
        "package.json",
        "apps/dashboard/package.json",
        "apps/docs/package.json",
        "packages/auth/package.json",
        "packages/codewire-design/package.json",
        "packages/codewire-proto-ts/package.json",
    }
    for path in paths:
        if is_legal_or_repository_text(path):
            continue
        if path == "bun.lock":
            categories.add("web-lock")
            continue
        if path in relevant_manifests:
            if semantic_manifest_changed(root, base, head, path, "npm"):
                categories.add("web-manifest")
            continue
        if path.startswith(("apps/dashboard/", "apps/docs/")):
            if not is_test_only(path):
                categories.add("web-source")
            continue
        if path.startswith(
            (
                "packages/codewire-design/",
                "packages/codewire-proto-ts/",
            )
        ):
            if not is_test_only(path):
                categories.add("web-source")
    return categories


def classify(
    root: Path,
    base: str,
    head: str,
    mode: str,
) -> tuple[bool, str, list[str]]:
    if not valid_commit(root, head):
        return True, "head_invalid", ["ambiguous-baseline"]
    current_head = git(root, "rev-parse", "HEAD").strip()
    if current_head != head:
        return True, "head_not_checked_out", ["ambiguous-baseline"]
    if not valid_commit(root, base):
        return True, "baseline_invalid", ["ambiguous-baseline"]
    ancestor = run(
        ["git", "merge-base", "--is-ancestor", base, head],
        cwd=root,
        check=False,
    )
    if ancestor.returncode != 0:
        return True, "baseline_not_ancestor", ["ambiguous-baseline"]

    try:
        paths = changed_paths(root, base, head)
    except ImpactError:
        return True, "diff_ambiguous", ["ambiguous-diff"]
    if not paths:
        return False, "no_changes", []

    categories: set[str] = set()
    exact_inputs = RUNTIME_EXACT_INPUTS if mode == "runtime" else SUPPORT_EXACT_INPUTS
    for path in paths:
        if is_legal_or_repository_text(path):
            continue
        if path in exact_inputs:
            categories.add("ci-contract")
        if (
            path.startswith("scripts/ci/images/")
            and path not in LOCAL_ONLY_IMAGE_HELPERS
        ):
            categories.add("image-publication")
        if mode == "runtime":
            if path.startswith("deployments/docker/") and (
                path.endswith(".Dockerfile")
                or path.endswith(".Cargo.toml")
                or path.endswith(".Cargo.lock")
            ):
                categories.add("runtime-image-definition")
            if path in RUNTIME_DOCKERFILES:
                categories.add("runtime-image-definition")
            if path.startswith(("proto/", "libs/gateway-proto/")):
                categories.add("protocol")
        else:
            if path.startswith(("images/base/", "images/workspace/")):
                categories.add("support-image-definition")
            if path.startswith(("proto/", "libs/gateway-proto/")):
                categories.add("protocol")

    try:
        categories.update(classify_rust(root, base, head, paths, mode))
        if mode == "runtime":
            categories.update(classify_web(root, base, head, paths))
            if any(
                path.startswith("deployments/k8s/")
                or path.startswith("apps/cli/charts/codewire-mesh/")
                for path in paths
            ):
                closure_files, closure_directories = dev_kustomize_closure(root)
                for path in paths:
                    if is_legal_or_repository_text(path):
                        continue
                    if (
                        path in DEV_FIXED_FILES
                        or path.startswith(DEV_FIXED_PREFIXES)
                        or path in closure_files
                        or any(
                            PurePosixPath(path).parent.as_posix() == directory
                            for directory in closure_directories
                        )
                    ):
                        categories.add("dev-render")
    except ImpactError:
        return True, "relevant_definition_ambiguous", ["ambiguous-definition"]

    contract_errors = artifact_contract_errors(root, mode)
    if contract_errors:
        return True, "build_contract_ambiguous", ["ambiguous-build-contract"]

    if categories:
        return True, "material_change", sorted(categories)
    return False, "no_material_change", []


def write_result(
    selected: bool,
    reason: str,
    categories: list[str],
    output: Path | None,
) -> None:
    values = {
        "selected": "true" if selected else "false",
        "reason": reason,
        "matched_categories": ",".join(categories),
    }
    rendered = "".join(f"{key}={value}\n" for key, value in values.items())
    sys.stdout.write(rendered)
    if output is not None:
        with output.open("a", encoding="utf-8") as stream:
            stream.write(rendered)


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    select_parser = subparsers.add_parser("select")
    select_parser.add_argument("--mode", choices=("runtime", "support"), required=True)
    select_parser.add_argument("--base", required=True)
    select_parser.add_argument("--head", required=True)
    select_parser.add_argument("--output", type=Path)

    contract_parser = subparsers.add_parser("check-contract")
    contract_parser.add_argument(
        "--mode",
        choices=("runtime", "support", "all"),
        default="all",
    )

    args = parser.parse_args()
    root = Path.cwd().resolve()
    if args.command == "check-contract":
        modes = ("runtime", "support") if args.mode == "all" else (args.mode,)
        errors = [
            error
            for mode in modes
            for error in artifact_contract_errors(root, mode)
        ]
        if errors:
            for error in errors:
                print(f"[artifact-impact] ERROR: {error}", file=sys.stderr)
            return 1
        print("[artifact-impact] build and dev-render input contract: OK")
        return 0

    selected, reason, categories = classify(root, args.base, args.head, args.mode)
    write_result(selected, reason, categories, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
