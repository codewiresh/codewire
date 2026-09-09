#!/usr/bin/env python3
"""Move exact Kind build outputs between native Forgejo artifact jobs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any


ROOT = Path(__file__).resolve().parents[3]
SCHEMA = "codewire.kind-build-artifact/v1"
GROUPS = {"workspace", "product", "smokes"}
HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")
POSITIVE = re.compile(r"[1-9][0-9]{0,19}")
NONCE = re.compile(r"[0-9a-f]{32}")
MANIFEST = "manifest.json"
WORKSPACE_RECEIPT = "workspace-receipt.json"
IMAGE_ARCHIVE = "images.tar"
PRODUCT_IMAGES = tuple(f"codewire-{name}:e2e" for name in (
    "dashboard", "services", "mesh", "gateway"
))
SMOKE_FILES = {
    "bin-crd-smoke": "crd-smoke",
    "bin-environment-setup-smoke": "environment-setup-smoke",
    "bin-exec-smoke": "exec-smoke",
    "bin-exec-stream-smoke": "exec-stream-smoke",
    "bin-file-service-smoke": "file-service-smoke",
    "bin-prepare-stream-smoke": "prepare-stream-smoke",
    "bin-log-stream-smoke": "log-stream-smoke",
    "bin-temporal-smoke": "temporal-smoke",
    "bin-temporal-fencing-smoke": "temporal-fencing-smoke",
    "bin-reconciler-ttl-smoke": "reconciler-ttl-smoke",
    "bin-cw": "cw",
    "example-platform-run-smoke": "examples/platform-run-smoke",
    "example-environment-session-smoke": "examples/environment-session-smoke",
    "example-coordinator-ingress-smoke": "examples/coordinator-ingress-smoke",
}
TEST_FILES = {
    "test-codewire-orchestration": (
        "credential-bootstrap-build.jsonl", "codewire_orchestration", ["lib"],
    ),
    "test-billing-wire-contract": (
        "billing-contract-build.jsonl", "wire_contract", ["test"],
    ),
}
BUILD_ENTRYPOINTS = {
    "workspace": "scripts/ci/verify/verify-workspace-image.sh",
    "product": "scripts/ci/images/build-kind-images.sh",
    "smokes": "scripts/ci/images/build-kind-smokes.sh",
}


class ArtifactError(RuntimeError):
    """A build artifact did not satisfy its closed transport contract."""


def run(*args: str, capture: bool = True) -> str:
    result = subprocess.run(args, check=True, capture_output=capture, text=True)
    return result.stdout.strip() if capture else ""


def normalized_attempt(environment: dict[str, str]) -> str:
    value = environment.get("GITHUB_RUN_ATTEMPT", "") or "1"
    if not POSITIVE.fullmatch(value):
        raise ArtifactError("invalid workflow run attempt")
    return value


def identity(group: str, environment: dict[str, str] | None = None) -> dict[str, Any]:
    environment = os.environ if environment is None else environment
    try:
        repository = environment["GITHUB_REPOSITORY"]
        run_id = environment["GITHUB_RUN_ID"]
        source = environment["GITHUB_SHA"]
    except KeyError as error:
        raise ArtifactError(f"missing workflow identity: {error.args[0]}") from error
    if repository != "codewire/codewire" or not POSITIVE.fullmatch(run_id):
        raise ArtifactError("invalid workflow repository or run")
    if run("git", "-C", str(ROOT), "status", "--porcelain", "--untracked-files=normal"):
        raise ArtifactError("Kind artifact source tree is not clean")
    head, tree = run("git", "-C", str(ROOT), "rev-parse", "HEAD", "HEAD^{tree}").splitlines()
    if source != head or not HEX40.fullmatch(head) or not HEX40.fullmatch(tree):
        raise ArtifactError("checkout does not match workflow source")
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise ArtifactError("Kind artifacts require Linux amd64")
    return {
        "repository": repository,
        "run_id": run_id,
        "run_attempt": normalized_attempt(environment),
        "head": head,
        "tree": tree,
        "platform": "linux/amd64",
        "profile": "workspace-verify" if group == "workspace" else "ci",
        "build_entrypoint_sha256": hashlib.sha256(
            (ROOT / BUILD_ENTRYPOINTS[group]).read_bytes()
        ).hexdigest(),
        "rust_toolchain_sha256": hashlib.sha256(
            (ROOT / "rust-toolchain.toml").read_bytes()
        ).hexdigest(),
    }


def require_directory(path: Path, *, create: bool) -> Path:
    if create:
        path.mkdir(mode=0o700)
    if path.is_symlink() or not path.is_dir():
        raise ArtifactError("artifact directory is not a real directory")
    resolved = path.resolve()
    try:
        resolved.relative_to(ROOT.resolve())
    except ValueError:
        return resolved
    raise ArtifactError("artifact transport directory must be outside the checkout")


def regular_file(path: Path) -> None:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError as error:
        raise ArtifactError(f"missing artifact member: {path.name}") from error
    if not stat.S_ISREG(mode):
        raise ArtifactError(f"artifact member is not a regular file: {path.name}")


def sha256(path: Path) -> tuple[str, int]:
    regular_file(path)
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            size += len(chunk)
            digest.update(chunk)
    return digest.hexdigest(), size


def copy_source(source: Path, destination: Path) -> None:
    regular_file(source)
    with source.open("rb") as incoming, destination.open("xb") as outgoing:
        shutil.copyfileobj(incoming, outgoing, 1024 * 1024)


def docker() -> str:
    return os.environ.get("CODEWIRE_DOCKER_BIN", "docker")


def inspect_image(reference: str) -> dict[str, Any]:
    raw = run(docker(), "image", "inspect", reference)
    if len(raw) > 512 * 1024:
        raise ArtifactError("image inspection exceeds its bound")
    value = json.loads(raw)
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise ArtifactError("expected one inspected image")
    return value[0]


def validate_product_images(expected: dict[str, Any], source: str) -> None:
    if set(expected) != set(PRODUCT_IMAGES):
        raise ArtifactError("product image set differs")
    for reference in PRODUCT_IMAGES:
        recorded = expected[reference]
        if not isinstance(recorded, dict) or set(recorded) != {"id"}:
            raise ArtifactError("invalid product image identity")
        value = inspect_image(reference)
        config = value.get("Config")
        labels = config.get("Labels") if isinstance(config, dict) else None
        if not isinstance(labels, dict):
            raise ArtifactError("invalid product image labels")
        image_id = value.get("Id")
        if (not isinstance(image_id, str)
                or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id)
                or recorded["id"] != image_id
                or value.get("Os") != "linux" or value.get("Architecture") != "amd64"
                or labels.get("dev.codewire.build.profile") != "ci"
                or labels.get("dev.codewire.promotable") != "false"
                or labels.get("org.opencontainers.image.revision") != source):
            raise ArtifactError(f"product image identity mismatch: {reference}")


def workspace_reuse(receipt: Path) -> str:
    return run(
        sys.executable, str(ROOT / "scripts/ci/verify/workspace-image-artifact.py"),
        "reuse", str(ROOT), str(receipt),
    )


def select_test_artifact(path: Path, target: str, target_kind: list[str]) -> Path:
    regular_file(path)
    matches: list[Path] = []
    with path.open(encoding="utf-8") as source:
        for number, line in enumerate(source, 1):
            if number > 100_000 or len(line) > 1024 * 1024:
                raise ArtifactError("Cargo artifact JSONL exceeds its bound")
            try:
                value = json.loads(line)
            except json.JSONDecodeError as error:
                raise ArtifactError("invalid Cargo artifact JSONL") from error
            if (isinstance(value, dict) and value.get("reason") == "compiler-artifact"
                    and isinstance(value.get("profile"), dict)
                    and value["profile"].get("test") is True
                    and isinstance(value.get("target"), dict)
                    and value["target"].get("name") == target
                    and value["target"].get("kind") == target_kind
                    and isinstance(value.get("executable"), str)):
                matches.append(Path(value["executable"]))
    if len(matches) != 1:
        raise ArtifactError(f"expected one Cargo test artifact for {target}")
    regular_file(matches[0])
    return matches[0]


def smoke_sources() -> dict[str, tuple[Path, int]]:
    target = Path(os.environ["CARGO_TARGET_DIR"])
    run_directory = Path(os.environ["RUN_DIR"])
    if not target.is_absolute() or not run_directory.is_absolute():
        raise ArtifactError("smoke source directories must be absolute")
    sources: dict[str, tuple[Path, int]] = {
        artifact: (target / "ci" / relative, 0o755)
        for artifact, relative in SMOKE_FILES.items()
    }
    allowed = (target / "ci").resolve()
    for source, _mode in sources.values():
        regular_file(source)
        if not os.access(source, os.X_OK):
            raise ArtifactError(f"smoke source is not executable: {source.name}")
        try:
            source.resolve().relative_to(allowed)
        except ValueError as error:
            raise ArtifactError("smoke source escaped the configured Cargo target") from error
    for artifact, (jsonl, cargo_target, target_kind) in TEST_FILES.items():
        selected = select_test_artifact(run_directory / jsonl, cargo_target, target_kind)
        try:
            selected.resolve().relative_to(allowed)
        except ValueError as error:
            raise ArtifactError("Cargo test artifact escaped the configured target") from error
        if not os.access(selected, os.X_OK):
            raise ArtifactError("Cargo test artifact is not executable")
        sources[artifact] = (selected, 0o755)
    return sources


def file_contract(paths: dict[str, tuple[Path, int]], directory: Path) -> dict[str, Any]:
    result = {}
    for name, (source, mode) in paths.items():
        if "/" in name or name in ("", ".", "..", MANIFEST):
            raise ArtifactError("invalid flat artifact name")
        destination = directory / name
        copy_source(source, destination)
        digest, size = sha256(destination)
        result[name] = {"sha256": digest, "bytes": size, "mode": mode}
    return result


def produce(group: str, directory: Path) -> dict[str, str]:
    started = time.monotonic()
    context = identity(group)
    directory = require_directory(directory, create=True)
    nonce = secrets.token_hex(16)
    extra: dict[str, Any] = {}
    if group == "workspace":
        receipt = ROOT / ".tmp/codewire-workspace-image-verification.json"
        alias = workspace_reuse(receipt)
        copy_source(receipt, directory / WORKSPACE_RECEIPT)
        run(docker(), "save", "--output", str(directory / IMAGE_ARCHIVE), alias)
        sources = {
            WORKSPACE_RECEIPT: (directory / WORKSPACE_RECEIPT, 0o600),
            IMAGE_ARCHIVE: (directory / IMAGE_ARCHIVE, 0o600),
        }
        files = {name: dict(zip(("sha256", "bytes"), sha256(path))) | {"mode": mode}
                 for name, (path, mode) in sources.items()}
    elif group == "product":
        images = {reference: {"id": inspect_image(reference).get("Id")}
                  for reference in PRODUCT_IMAGES}
        validate_product_images(images, context["head"])
        run(docker(), "save", "--output", str(directory / IMAGE_ARCHIVE), *PRODUCT_IMAGES)
        digest, size = sha256(directory / IMAGE_ARCHIVE)
        files = {IMAGE_ARCHIVE: {"sha256": digest, "bytes": size, "mode": 0o600}}
        extra["images"] = images
    else:
        files = file_contract(smoke_sources(), directory)
    manifest = {
        "schema": SCHEMA, "group": group, "identity": context, "nonce": nonce,
        "files": files, **extra,
    }
    encoded = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
    (directory / MANIFEST).write_bytes(encoded)
    digest = hashlib.sha256(encoded).hexdigest()
    artifact_name = "codewire-kind-{}-v1-{}-{}-{}-{}".format(
        group, context["run_id"], context["run_attempt"], context["head"], nonce,
    )
    output = Path(os.environ["GITHUB_OUTPUT"])
    with output.open("a", encoding="utf-8") as destination:
        destination.write(f"artifact_name={artifact_name}\nmanifest_sha256={digest}\n")
    total_bytes = len(encoded) + sum(item["bytes"] for item in files.values())
    print(
        "CODEWIRE_CI_PHASE name=kind-artifact-{}-produce seconds={} bytes={}".format(
            group, int(time.monotonic() - started), total_bytes,
        )
    )
    return {"artifact_name": artifact_name, "manifest_sha256": digest}


def read_manifest(directory: Path, group: str, expected_digest: str) -> dict[str, Any]:
    if not HEX64.fullmatch(expected_digest):
        raise ArtifactError("missing producer manifest digest")
    manifest_path = directory / MANIFEST
    regular_file(manifest_path)
    if manifest_path.stat().st_size > 64 * 1024:
        raise ArtifactError("artifact manifest exceeds its bound")
    raw = manifest_path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_digest:
        raise ArtifactError("producer manifest digest mismatch")
    value = json.loads(raw)
    expected_keys = {"schema", "group", "identity", "nonce", "files"}
    if group == "product":
        expected_keys.add("images")
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise ArtifactError("invalid artifact manifest fields")
    if value["schema"] != SCHEMA or value["group"] != group:
        raise ArtifactError("artifact schema or group mismatch")
    if value["identity"] != identity(group) or not isinstance(value["nonce"], str) \
            or not NONCE.fullmatch(value["nonce"]):
        raise ArtifactError("artifact source, run, or nonce mismatch")
    return value


def validate_files(directory: Path, value: dict[str, Any]) -> None:
    files = value["files"]
    if not isinstance(files, dict) or not files:
        raise ArtifactError("invalid artifact file contract")
    if {entry.name for entry in directory.iterdir()} != set(files) | {MANIFEST}:
        raise ArtifactError("artifact file set differs")
    for name, expected in files.items():
        if not isinstance(name, str) or "/" in name or name in ("", ".", "..", MANIFEST):
            raise ArtifactError("invalid artifact member name")
        if (not isinstance(expected, dict) or set(expected) != {"sha256", "bytes", "mode"}
                or not isinstance(expected["sha256"], str)
                or not HEX64.fullmatch(expected["sha256"])
                or type(expected["bytes"]) is not int or expected["bytes"] < 0
                or expected["mode"] not in (0o600, 0o755)):
            raise ArtifactError("invalid artifact member contract")
        digest, size = sha256(directory / name)
        if digest != expected["sha256"] or size != expected["bytes"]:
            raise ArtifactError(f"artifact member bytes differ: {name}")


def atomic_install(source: Path, destination: Path, mode: int) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.parent.is_symlink():
        raise ArtifactError("artifact install parent is a symlink")
    descriptor, temporary_name = tempfile.mkstemp(prefix=".kind-artifact-", dir=destination.parent)
    temporary = Path(temporary_name)
    try:
        with source.open("rb") as incoming, os.fdopen(descriptor, "wb") as outgoing:
            shutil.copyfileobj(incoming, outgoing, 1024 * 1024)
            outgoing.flush()
            os.fsync(outgoing.fileno())
        temporary.chmod(mode)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def write_test_jsonl(path: Path, target: str, target_kind: list[str], executable: Path) -> None:
    value = {
        "reason": "compiler-artifact", "profile": {"test": True},
        "target": {"name": target, "kind": target_kind}, "executable": str(executable),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".kind-artifact-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(value, output, sort_keys=True, separators=(",", ":"))
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def consume(group: str, directory: Path) -> None:
    started = time.monotonic()
    directory = require_directory(directory, create=False)
    value = read_manifest(directory, group, os.environ.get("EXPECTED_MANIFEST_SHA256", ""))
    validate_files(directory, value)  # No image load or executable copy precedes this.
    if group == "workspace":
        if set(value["files"]) != {WORKSPACE_RECEIPT, IMAGE_ARCHIVE}:
            raise ArtifactError("workspace artifact file set differs")
        if any(item["mode"] != 0o600 for item in value["files"].values()):
            raise ArtifactError("workspace artifact mode differs")
        run(docker(), "load", "--input", str(directory / IMAGE_ARCHIVE), capture=False)
        workspace_reuse(directory / WORKSPACE_RECEIPT)
        atomic_install(
            directory / WORKSPACE_RECEIPT,
            ROOT / ".tmp/codewire-workspace-image-verification.json", 0o600,
        )
    elif group == "product":
        if set(value["files"]) != {IMAGE_ARCHIVE} or not isinstance(value.get("images"), dict):
            raise ArtifactError("product artifact file set differs")
        if value["files"][IMAGE_ARCHIVE]["mode"] != 0o600:
            raise ArtifactError("product artifact mode differs")
        run(docker(), "load", "--input", str(directory / IMAGE_ARCHIVE), capture=False)
        validate_product_images(value["images"], value["identity"]["head"])
    else:
        expected_files = set(SMOKE_FILES) | set(TEST_FILES)
        if set(value["files"]) != expected_files:
            raise ArtifactError("smoke artifact file set differs")
        if any(item["mode"] != 0o755 for item in value["files"].values()):
            raise ArtifactError("smoke artifact mode differs")
        target = Path(os.environ["CARGO_TARGET_DIR"])
        run_directory = Path(os.environ["RUN_DIR"])
        if not target.is_absolute() or not run_directory.is_absolute():
            raise ArtifactError("smoke install directories must be absolute")
        installed: dict[str, Path] = {}
        for artifact, relative in SMOKE_FILES.items():
            destination = target / "ci" / relative
            atomic_install(directory / artifact, destination, 0o755)
            installed[artifact] = destination
        for artifact, (jsonl, cargo_target, target_kind) in TEST_FILES.items():
            destination = target / "ci/deps" / artifact
            atomic_install(directory / artifact, destination, 0o755)
            write_test_jsonl(run_directory / jsonl, cargo_target, target_kind, destination)
    total_bytes = (directory / MANIFEST).stat().st_size + sum(
        item["bytes"] for item in value["files"].values()
    )
    print(
        "CODEWIRE_CI_PHASE name=kind-artifact-{}-consume seconds={} bytes={}".format(
            group, int(time.monotonic() - started), total_bytes,
        )
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("produce", "consume"))
    parser.add_argument("group", choices=sorted(GROUPS))
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    if args.operation == "produce":
        produce(args.group, args.directory)
    else:
        consume(args.group, args.directory)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ArtifactError, KeyError, OSError, TypeError, ValueError,
            json.JSONDecodeError, subprocess.CalledProcessError) as error:
        print(f"Kind build artifact rejected: {error}", file=sys.stderr)
        raise SystemExit(1) from error
