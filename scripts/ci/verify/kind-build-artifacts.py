#!/usr/bin/env python3
"""Move exact Kind build outputs between native Forgejo artifact jobs."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
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
GROUPS = {"workspace", "product", "daemon", "smokes"}
HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")
POSITIVE = re.compile(r"[1-9][0-9]{0,19}")
NONCE = re.compile(r"[0-9a-f]{32}")
MANIFEST = "manifest.json"
WORKSPACE_RECEIPT = "workspace-receipt.json"
IMAGE_ARCHIVE = "images.tar"
WORKSPACE_OCI = re.compile(r"workspace-image-[0-9a-f]{64}\.oci\.tar")
# The Kind runtime workspace: the exact-source build, or the published pin
# when this change leaves the workspace image definition unchanged. The pin is
# pulled by digest from its public repository on each consumer, so only this
# small record crosses the artifact boundary.
WORKSPACE_PIN = "workspace-pin.json"
WORKSPACE_PIN_SCHEMA = "codewire.kind-workspace-pin/v1"
WORKSPACE_SOURCES = ("pinned", "source")
WORKSPACE_SELECTION = ".tmp/codewire-kind-workspace-selection.json"
WORKSPACE_SELECTION_SCHEMA = "codewire.kind-workspace-selection/v1"
PINNED_WORKSPACE_ALIAS = "localhost/codewire-ci/workspace:pinned-"
PIN_TOOL = "scripts/ci/images/workspace-image-pin.py"
DIGEST_REFERENCE = re.compile(r"[a-z0-9.-]+(?:/[a-z0-9._-]+)+@sha256:[0-9a-f]{64}")
# The service images and the daemon image build on separate workers: the
# daemon's static CW producer is independent of the three service compiles.
GROUP_IMAGES = {
    "product": tuple(f"codewire-{name}:e2e" for name in ("dashboard", "services", "mesh")),
    "daemon": ("codewire-daemon:e2e",),
}
PRODUCT_IMAGES = GROUP_IMAGES["product"] + GROUP_IMAGES["daemon"]
SMOKE_INVENTORY = "scripts/ci/verify/kind/smokes.txt"
SMOKE_FIELD = re.compile(r"[a-z0-9][a-z0-9_,-]*")
# The receipt the smoke build writes for its test target, which the suites read.
SMOKE_TEST_RECEIPT = "billing-contract-build.jsonl"


def smoke_inventory(path: Path | None = None) -> list[tuple[str, str, str, str, str]]:
    """The Kind smoke inventory's rows: group, crate, features, kind, name.

    The builds read the same file (build-kind-smokes.sh, build-smokes.sh); a
    group is one crate and one feature set.
    """
    path = ROOT / SMOKE_INVENTORY if path is None else path
    rows, groups = [], {}
    for number, line in enumerate(path.read_text().splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        fields = line.split()
        if len(fields) != 5 or not all(SMOKE_FIELD.fullmatch(field) or (index == 2 and field == "-")
                                       for index, field in enumerate(fields)):
            raise ArtifactError(f"{path}:{number}: want GROUP CRATE FEATURES KIND NAME")
        group, crate, features, kind, name = fields
        if kind not in ("bin", "example", "test"):
            raise ArtifactError(f"{path}:{number}: unknown smoke kind {kind}")
        if groups.setdefault(group, (crate, features, kind == "test")) != (crate, features, kind == "test"):
            raise ArtifactError(f"{path}:{number}: group {group} mixes crates, feature sets or targets")
        rows.append((group, crate, features, kind, name))
    return rows


def _smoke_files() -> tuple[dict[str, str], dict[str, tuple[str, str, list[str]]]]:
    programs, tests = {}, {}
    for group, _crate, _features, kind, name in smoke_inventory():
        if kind == "bin":
            programs[f"bin-{name}"] = name
        elif kind == "example":
            programs[f"example-{name}"] = f"examples/{name}"
        else:
            tests[f"test-{group}-{name.replace('_', '-')}"] = (SMOKE_TEST_RECEIPT, name, ["test"])
    if len(tests) != 1:
        raise ArtifactError("the smoke inventory must name exactly one test target, the billing contract")
    return programs, tests


# Every program and test target the Kind suites run, as the artifact names
# them: from the smoke inventory, never a second list.
SMOKE_FILES, TEST_FILES = _smoke_files()
BUILD_ENTRYPOINTS = {
    "workspace": "scripts/ci/verify/verify-workspace-image.sh",
    "product": "scripts/ci/images/build-kind-images.sh",
    "daemon": "scripts/ci/images/build-kind-images.sh",
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
        # The commit ci.yaml verifies: its own, or the earlier main commit a
        # Kind dispatch names (scripts/ci/select/dispatch-source.sh).
        source = environment["CODEWIRE_VERIFICATION_SOURCE_SHA"]
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
        # Product and daemon images build the runtime profile; the host smoke
        # binaries keep the ci profile.
        "profile": {"workspace": "workspace-verify", "smokes": "ci"}.get(group, "runtime"),
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


def validate_product_images(expected: dict[str, Any], source: str,
                            group: str = "product") -> None:
    if set(expected) != set(GROUP_IMAGES[group]):
        raise ArtifactError(f"{group} image set differs")
    for reference in GROUP_IMAGES[group]:
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
                or labels.get("dev.codewire.build.profile") != "runtime"
                or labels.get("dev.codewire.promotable") != "false"
                or labels.get("org.opencontainers.image.revision") != source):
            raise ArtifactError(f"product image identity mismatch: {reference}")


def workspace_reuse(receipt: Path) -> str:
    return run(
        sys.executable, str(ROOT / "scripts/ci/verify/workspace-image-artifact.py"),
        "reuse", str(ROOT), str(receipt),
    )


def workspace_native_input(receipt: Path) -> dict[str, Any]:
    raw = run(
        sys.executable, str(ROOT / "scripts/ci/verify/workspace-image-artifact.py"),
        "native-input", str(ROOT), str(receipt),
    )
    if len(raw) > 4096:
        raise ArtifactError("workspace native input exceeds its bound")
    value = json.loads(raw)
    if (not isinstance(value, dict)
            or set(value) != {"file", "sha256", "size", "source_digest", "path"}
            or not isinstance(value["file"], str)
            or not WORKSPACE_OCI.fullmatch(value["file"])
            or not isinstance(value["sha256"], str) or not HEX64.fullmatch(value["sha256"])
            or value["file"] != "workspace-image-" + value["sha256"] + ".oci.tar"
            or type(value["size"]) is not int or value["size"] <= 0
            or not isinstance(value["source_digest"], str)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", value["source_digest"])
            or not isinstance(value["path"], str)):
        raise ArtifactError("invalid workspace native input")
    path = Path(value["path"])
    if path != path.resolve(strict=True) or path.name != value["file"] \
            or path.parent != receipt.parent.resolve(strict=True):
        raise ArtifactError("workspace native archive escaped its receipt directory")
    digest, size = sha256(path)
    if digest != value["sha256"] or size != value["size"]:
        raise ArtifactError("workspace native archive bytes differ")
    return {**value, "path": path}


def receipt_workspace_oci(receipt: Path) -> dict[str, Any]:
    regular_file(receipt)
    if receipt.stat().st_size > 64 * 1024:
        raise ArtifactError("workspace receipt exceeds its bound")
    value = json.loads(receipt.read_bytes())
    oci = value.get("workspace_oci") if isinstance(value, dict) else None
    if (not isinstance(oci, dict)
            or set(oci) != {"file", "sha256", "size", "source_digest"}
            or not isinstance(oci["file"], str) or not WORKSPACE_OCI.fullmatch(oci["file"])
            or not isinstance(oci["sha256"], str) or not HEX64.fullmatch(oci["sha256"])
            or oci["file"] != "workspace-image-" + oci["sha256"] + ".oci.tar"
            or type(oci["size"]) is not int or oci["size"] <= 0
            or not isinstance(oci["source_digest"], str)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", oci["source_digest"])):
        raise ArtifactError("invalid workspace OCI receipt fields")
    return oci


def pin_tool() -> Any:
    spec = importlib.util.spec_from_file_location("kind_workspace_image_pin", ROOT / PIN_TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def workspace_source(head: str, base: str | None) -> tuple[str, str]:
    """Choose the Kind workspace: the published pin only when it is this tree's.

    The definition is the pin generator's identity of images/base and
    images/workspace. The pin is used only when it was built from exactly this
    tree's definition. A definition unchanged from the base is not enough: the
    pin is refreshed only after a definition change merges, so it can lag the
    tree (#2803 left it two definitions behind, and Kind ran a workspace image
    this tree does not deploy). The base is checked for form only.
    """
    if not HEX40.fullmatch(head) or (base is not None and not HEX40.fullmatch(base)):
        raise ArtifactError("workspace source selection needs full commit IDs")
    tool = pin_tool()
    try:
        pin = tool.read_pin(ROOT, head)
        if tool.inputs_sha256(ROOT, head) == pin["inputs_sha256"]:
            return "pinned", "the pin was built from this tree's workspace image definition"
        return "source", "the pin was built from another workspace image definition"
    except tool.PinError as error:
        return "source", f"the pin could not be compared ({error})"


def workspace_source_mode(environment: dict[str, str] | None = None) -> str:
    environment = os.environ if environment is None else environment
    mode = environment.get("CODEWIRE_KIND_WORKSPACE_SOURCE", "") or "source"
    if mode not in WORKSPACE_SOURCES:
        raise ArtifactError("CODEWIRE_KIND_WORKSPACE_SOURCE must be pinned or source")
    return mode


def pinned_workspace_record() -> dict[str, Any]:
    """The checkout's published pin, in the closed form the consumer pulls."""
    tool = pin_tool()
    try:
        pin = tool.read_pin(ROOT, None)
    except tool.PinError as error:
        raise ArtifactError(f"workspace pin is invalid: {error}") from error
    image = tool.field(pin, "public-image")
    if not isinstance(image, str) or not DIGEST_REFERENCE.fullmatch(image) \
            or not image.endswith("@" + pin["digest"]):
        raise ArtifactError("workspace pin does not name one public digest")
    return {
        "schema": WORKSPACE_PIN_SCHEMA,
        "image": image,
        "digest": pin["digest"],
        "source_sha": pin["source_sha"],
        "inputs_sha256": pin["inputs_sha256"],
    }


def read_workspace_pin(path: Path) -> dict[str, Any]:
    regular_file(path)
    if path.stat().st_size > 4096:
        raise ArtifactError("workspace pin record exceeds its bound")
    value = json.loads(path.read_bytes())
    if (not isinstance(value, dict)
            or set(value) != {"schema", "image", "digest", "source_sha", "inputs_sha256"}
            or value["schema"] != WORKSPACE_PIN_SCHEMA
            or not isinstance(value["image"], str) or not DIGEST_REFERENCE.fullmatch(value["image"])
            or not isinstance(value["digest"], str)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", value["digest"])
            or not value["image"].endswith("@" + value["digest"])
            or not isinstance(value["source_sha"], str) or not HEX40.fullmatch(value["source_sha"])
            or not isinstance(value["inputs_sha256"], str)
            or not HEX64.fullmatch(value["inputs_sha256"])):
        raise ArtifactError("invalid workspace pin record")
    return value


def pinned_workspace_image(reference: str, source_sha: str, *, alias: str | None = None) -> str:
    """Prove the local image is the published pin and return its image ID."""
    value = inspect_image(alias or reference)
    config = value.get("Config")
    labels = config.get("Labels") if isinstance(config, dict) else None
    image_id = value.get("Id")
    repo_digests = value.get("RepoDigests")
    if (not isinstance(labels, dict) or not isinstance(image_id, str)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id)
            or not isinstance(repo_digests, list) or reference not in repo_digests
            or value.get("Os") != "linux" or value.get("Architecture") != "amd64"
            or labels.get("org.opencontainers.image.revision") != source_sha):
        raise ArtifactError("pulled workspace is not the published pin")
    return image_id


def write_workspace_selection(value: dict[str, Any]) -> None:
    path = ROOT / WORKSPACE_SELECTION
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.parent.is_symlink() or path.is_symlink():
        raise ArtifactError("workspace selection destination is a symlink")
    descriptor, temporary_name = tempfile.mkstemp(prefix=".kind-workspace-selection-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump({"schema": WORKSPACE_SELECTION_SCHEMA, **value}, output,
                      sort_keys=True, separators=(",", ":"))
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        temporary.chmod(0o600)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def consume_pinned_workspace(directory: Path, value: dict[str, Any]) -> None:
    if value["files"][WORKSPACE_PIN]["mode"] != 0o600:
        raise ArtifactError("workspace pin record mode differs")
    record = read_workspace_pin(directory / WORKSPACE_PIN)
    if record != pinned_workspace_record():
        raise ArtifactError("workspace pin record differs from the checkout's pin")
    pull_pinned_workspace(record)


def pull_pinned_workspace(record: dict[str, Any]) -> None:
    """Pull the pin by digest from its public mirror, prove it, and select it.

    No credential is involved: the public mirror serves the same digest. The
    pulled image must list the requested digest reference, run on linux/amd64
    and carry the pin's source revision before an alias is recorded.
    """
    reference = record["image"]
    for attempt in range(1, 4):
        try:
            run(docker(), "pull", "--platform", "linux/amd64", reference, capture=False)
            break
        except subprocess.CalledProcessError:
            if attempt == 3:
                raise
            print(f"Kind artifact: workspace pull attempt {attempt} failed; retrying",
                  file=sys.stderr)
            time.sleep(10 * attempt)
    image_id = pinned_workspace_image(reference, record["source_sha"])
    alias = PINNED_WORKSPACE_ALIAS + image_id.removeprefix("sha256:")
    run(docker(), "image", "tag", image_id, alias)
    if pinned_workspace_image(reference, record["source_sha"], alias=alias) != image_id:
        raise ArtifactError("pinned workspace alias names another image")
    write_workspace_selection({
        "mode": "pinned", "image": alias, "image_id": image_id, "reference": reference,
        "source_sha": record["source_sha"],
    })
    print(f"Kind artifact: pinned workspace {reference} loaded as {alias}")


def head_commit() -> str:
    head = run("git", "-C", str(ROOT), "rev-parse", "HEAD")
    if not HEX40.fullmatch(head):
        raise ArtifactError("the checkout has no commit")
    return head


def select_local_workspace() -> str:
    """Choose a local Kind run's workspace image the way CI does (#2965).

    The published pin is used when it was built from this tree's workspace
    image definition: it is pulled by digest with no credential and proved
    before use, so a local cluster opens without building the workspace image.
    Any other tree builds and verifies the exact source as before.
    """
    source, reason = workspace_source(head_commit(), None)
    print(f"Kind workspace: {source} ({reason})", file=sys.stderr)
    if source == "pinned":
        pull_pinned_workspace(pinned_workspace_record())
    else:
        write_workspace_selection({"mode": "source"})
    return source


def workspace_runtime_image() -> str:
    """The workspace image this checkout's consumed Kind artifact selected."""
    path = ROOT / WORKSPACE_SELECTION
    if not path.exists() and not path.is_symlink():
        return workspace_reuse(ROOT / ".tmp/codewire-workspace-image-verification.json")
    regular_file(path)
    if path.stat().st_size > 4096:
        raise ArtifactError("workspace selection exceeds its bound")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict) or value.get("schema") != WORKSPACE_SELECTION_SCHEMA:
        raise ArtifactError("invalid workspace selection")
    if value.get("mode") == "source" and set(value) == {"schema", "mode"}:
        return workspace_reuse(ROOT / ".tmp/codewire-workspace-image-verification.json")
    if (value.get("mode") != "pinned"
            or set(value) != {"schema", "mode", "image", "image_id", "reference", "source_sha"}
            or not isinstance(value["image_id"], str)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", value["image_id"])
            or value["image"] != PINNED_WORKSPACE_ALIAS + value["image_id"].removeprefix("sha256:")
            or not isinstance(value["reference"], str) or not DIGEST_REFERENCE.fullmatch(value["reference"])
            or not isinstance(value["source_sha"], str) or not HEX40.fullmatch(value["source_sha"])):
        raise ArtifactError("invalid pinned workspace selection")
    if value["reference"] != pinned_workspace_record()["image"]:
        raise ArtifactError("pinned workspace selection differs from the checkout's pin")
    if workspace_source(head_commit(), None)[0] != "pinned":
        raise ArtifactError("pinned workspace selection predates a change to this tree's workspace definition")
    if pinned_workspace_image(value["reference"], value["source_sha"],
                              alias=value["image"]) != value["image_id"]:
        raise ArtifactError("pinned workspace alias names another image")
    return value["image"]


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
    if group == "workspace" and workspace_source_mode() == "pinned":
        destination = directory / WORKSPACE_PIN
        with destination.open("x", encoding="utf-8") as output:
            json.dump(pinned_workspace_record(), output, sort_keys=True, separators=(",", ":"))
            output.write("\n")
        destination.chmod(0o600)
        read_workspace_pin(destination)
        files = {WORKSPACE_PIN: dict(zip(("sha256", "bytes"), sha256(destination))) | {"mode": 0o600}}
    elif group == "workspace":
        receipt = ROOT / ".tmp/codewire-workspace-image-verification.json"
        alias = workspace_reuse(receipt)
        native = workspace_native_input(receipt)
        copy_source(receipt, directory / WORKSPACE_RECEIPT)
        copy_source(native["path"], directory / native["file"])
        copied_digest, copied_size = sha256(directory / native["file"])
        if (copied_digest, copied_size) != (native["sha256"], native["size"]):
            raise ArtifactError("copied workspace native archive differs")
        run(docker(), "save", "--output", str(directory / IMAGE_ARCHIVE), alias)
        sources = {
            WORKSPACE_RECEIPT: (directory / WORKSPACE_RECEIPT, 0o600),
            native["file"]: (directory / native["file"], 0o400),
            IMAGE_ARCHIVE: (directory / IMAGE_ARCHIVE, 0o600),
        }
        files = {name: dict(zip(("sha256", "bytes"), sha256(path))) | {"mode": mode}
                 for name, (path, mode) in sources.items()}
    elif group in GROUP_IMAGES:
        images = {reference: {"id": inspect_image(reference).get("Id")}
                  for reference in GROUP_IMAGES[group]}
        validate_product_images(images, context["head"], group)
        run(docker(), "save", "--output", str(directory / IMAGE_ARCHIVE), *GROUP_IMAGES[group])
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
    if group in GROUP_IMAGES:
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
                or expected["mode"] not in (0o400, 0o600, 0o755)):
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
        with os.fdopen(descriptor, "wb") as outgoing, source.open("rb") as incoming:
            shutil.copyfileobj(incoming, outgoing, 1024 * 1024)
            outgoing.flush()
            os.fsync(outgoing.fileno())
        temporary.chmod(mode)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def install_immutable_archive(source: Path, destination: Path,
                              expected: dict[str, Any]) -> bool:
    if destination.name != "workspace-image-" + expected["sha256"] + ".oci.tar":
        raise ArtifactError("workspace OCI archive name differs")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.parent.is_symlink():
        raise ArtifactError("workspace archive parent is a symlink")
    try:
        descriptor = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o400,
        )
    except FileExistsError:
        info = destination.lstat()
        if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o400
                or info.st_uid != os.getuid() or info.st_nlink != 1
                or sha256(destination) != (expected["sha256"], expected["bytes"])):
            raise ArtifactError("existing workspace OCI archive differs")
        return False
    try:
        with os.fdopen(descriptor, "wb") as outgoing, source.open("rb") as incoming:
            shutil.copyfileobj(incoming, outgoing, 1024 * 1024)
            outgoing.flush()
            os.fsync(outgoing.fileno())
        if sha256(destination) != (expected["sha256"], expected["bytes"]):
            raise ArtifactError("published workspace OCI archive differs")
    except BaseException:
        destination.unlink(missing_ok=True)
        raise
    return True


def publish_workspace(receipt: Path, archive: Path, archive_contract: dict[str, Any]) -> None:
    canonical_receipt = ROOT / ".tmp/codewire-workspace-image-verification.json"
    canonical_archive = canonical_receipt.parent / archive.name
    canonical_receipt.parent.mkdir(parents=True, exist_ok=True)
    created_archive = install_immutable_archive(archive, canonical_archive, archive_contract)
    backup: Path | None = None
    try:
        if canonical_receipt.exists() or canonical_receipt.is_symlink():
            if canonical_receipt.is_symlink() or not canonical_receipt.is_file():
                raise ArtifactError("invalid existing workspace receipt")
            descriptor, backup_name = tempfile.mkstemp(
                prefix=".kind-workspace-receipt-", dir=canonical_receipt.parent,
            )
            os.close(descriptor)
            backup = Path(backup_name)
            backup.unlink()
            os.replace(canonical_receipt, backup)
        try:
            atomic_install(receipt, canonical_receipt, 0o600)
            workspace_reuse(canonical_receipt)
            workspace_native_input(canonical_receipt)
        except BaseException:
            canonical_receipt.unlink(missing_ok=True)
            if backup is not None:
                os.replace(backup, canonical_receipt)
                backup = None
            raise
        if backup is not None:
            try:
                backup.unlink()
            except OSError:
                print("Kind artifact: prior workspace receipt cleanup deferred", file=sys.stderr)
            backup = None
    except BaseException:
        if created_archive:
            canonical_archive.unlink(missing_ok=True)
        raise
    finally:
        if backup is not None:
            # A failed rollback is never hidden by deleting the only saved receipt.
            if not canonical_receipt.exists():
                os.replace(backup, canonical_receipt)
            else:
                backup.unlink()


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
    if group == "workspace" and set(value["files"]) == {WORKSPACE_PIN}:
        consume_pinned_workspace(directory, value)
    elif group == "workspace":
        oci_names = [name for name in value["files"] if WORKSPACE_OCI.fullmatch(name)]
        if (len(oci_names) != 1
                or set(value["files"]) != {WORKSPACE_RECEIPT, IMAGE_ARCHIVE, oci_names[0]}):
            raise ArtifactError("workspace artifact file set differs")
        oci_name = oci_names[0]
        if oci_name != "workspace-image-" + value["files"][oci_name]["sha256"] + ".oci.tar":
            raise ArtifactError("workspace OCI archive name differs")
        receipt_oci = receipt_workspace_oci(directory / WORKSPACE_RECEIPT)
        if (receipt_oci["file"] != oci_name
                or receipt_oci["sha256"] != value["files"][oci_name]["sha256"]
                or receipt_oci["size"] != value["files"][oci_name]["bytes"]):
            raise ArtifactError("workspace receipt and transport archive differ")
        if (value["files"][WORKSPACE_RECEIPT]["mode"] != 0o600
                or value["files"][IMAGE_ARCHIVE]["mode"] != 0o600
                or value["files"][oci_name]["mode"] != 0o400):
            raise ArtifactError("workspace artifact mode differs")
        (ROOT / ".tmp").mkdir(parents=True, exist_ok=True)
        run(docker(), "load", "--input", str(directory / IMAGE_ARCHIVE), capture=False)
        with tempfile.TemporaryDirectory(prefix=".kind-workspace-stage-", dir=ROOT / ".tmp") as name:
            staging = Path(name)
            staged_receipt = staging / WORKSPACE_RECEIPT
            staged_archive = staging / oci_name
            copy_source(directory / WORKSPACE_RECEIPT, staged_receipt)
            staged_receipt.chmod(0o600)
            copy_source(directory / oci_name, staged_archive)
            staged_archive.chmod(0o400)
            workspace_reuse(staged_receipt)
            publish_workspace(
                staged_receipt, staged_archive, value["files"][oci_name],
            )
        write_workspace_selection({"mode": "source"})
    elif group in GROUP_IMAGES:
        if set(value["files"]) != {IMAGE_ARCHIVE} or not isinstance(value.get("images"), dict):
            raise ArtifactError(f"{group} artifact file set differs")
        if value["files"][IMAGE_ARCHIVE]["mode"] != 0o600:
            raise ArtifactError(f"{group} artifact mode differs")
        run(docker(), "load", "--input", str(directory / IMAGE_ARCHIVE), capture=False)
        validate_product_images(value["images"], value["identity"]["head"], group)
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
    operations = parser.add_subparsers(dest="operation", required=True)
    for operation in ("produce", "consume"):
        transfer = operations.add_parser(operation)
        transfer.add_argument("group", choices=sorted(GROUPS))
        transfer.add_argument("directory", type=Path)
    select = operations.add_parser(
        "workspace-source", help="choose the pinned or exact-source Kind workspace")
    select.add_argument("--head", required=True)
    select.add_argument("--base", default="")
    select.add_argument("--github-output", action="store_true")
    operations.add_parser(
        "workspace-image", help="print the workspace image the consumed artifact selected")
    operations.add_parser(
        "select-workspace",
        help="local Kind: pull the published pin when it is this tree's (exit 0), else exit 3 to build")
    args = parser.parse_args()
    if args.operation == "produce":
        produce(args.group, args.directory)
    elif args.operation == "consume":
        consume(args.group, args.directory)
    elif args.operation == "workspace-source":
        base = args.base if args.base and args.base != "0" * 40 else None
        source, reason = workspace_source(args.head, base)
        print(f"Kind workspace: {source} ({reason})")
        if args.github_output:
            with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
                output.write(f"kind_workspace_source={source}\n")
    elif args.operation == "select-workspace":
        return 0 if select_local_workspace() == "pinned" else 3
    else:
        print(workspace_runtime_image())
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ArtifactError, KeyError, OSError, TypeError, ValueError,
            json.JSONDecodeError, subprocess.CalledProcessError) as error:
        print(f"Kind build artifact rejected: {error}", file=sys.stderr)
        raise SystemExit(1) from error
