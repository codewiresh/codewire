#!/usr/bin/env python3
"""Create and validate the source-side Codewire ImageBundle contract."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any


API_VERSION = "deploy.codewire.sh/v1alpha1"
KIND = "ImageBundle"
SOURCE_REPOSITORY = "codewire/codewire"
FAMILIES = ("dashboard", "derp", "daemon", "services", "mesh")
PUBLICATION_FAMILIES = FAMILIES + ("base", "workspace", "confidential-probe")
ENVIRONMENTS = ("dev", "prod")
SOURCE_SHA = re.compile(r"[0-9a-f]{40}")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


class BundleError(ValueError):
    """The aggregate candidate set is not one complete source-owned bundle."""


def _repository_prefix() -> str:
    """The Harbor codewire project on the host CI names in CODEWIRE_IMAGE_REGISTRY."""
    host = os.environ.get("CODEWIRE_IMAGE_REGISTRY", "")
    if not host:
        raise BundleError("CODEWIRE_IMAGE_REGISTRY must name the image registry host")
    return f"{host}/codewire"


def _repository(family: str) -> str:
    return f"{_repository_prefix()}/{family}"


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BundleError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_non_json_constant(value: str) -> None:
    raise BundleError(f"invalid JSON constant: {value}")


def _exact_keys(value: Any, expected: set[str], where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BundleError(f"{where} must be an object")
    actual = set(value)
    missing = sorted(expected - actual)
    unknown = sorted(actual - expected)
    if missing:
        raise BundleError(f"{where} missing field(s): {', '.join(missing)}")
    if unknown:
        raise BundleError(f"{where} unknown field(s): {', '.join(unknown)}")
    return value


def _source(value: Any, where: str) -> tuple[str, str]:
    source = _exact_keys(value, {"repository", "sha"}, where)
    repository = source["repository"]
    sha = source["sha"]
    if repository != SOURCE_REPOSITORY:
        raise BundleError(
            f"{where}.repository must be exactly {SOURCE_REPOSITORY}"
        )
    if not isinstance(sha, str) or SOURCE_SHA.fullmatch(sha) is None:
        raise BundleError(f"{where}.sha must be 40 lowercase hexadecimal characters")
    if sha == "0" * 40:
        raise BundleError(f"{where}.sha cannot be the all-zero object ID")
    return repository, sha


def validate_bundle(value: Any) -> dict[str, Any]:
    expected_keys = {"apiVersion", "kind", "source", "images"}
    if isinstance(value, dict) and "environment" in value:
        expected_keys.add("environment")
    root = _exact_keys(
        value,
        expected_keys,
        "bundle",
    )
    if root["apiVersion"] != API_VERSION:
        raise BundleError(f"apiVersion must be exactly {API_VERSION}")
    if root["kind"] != KIND:
        raise BundleError(f"kind must be exactly {KIND}")
    environment = root.get("environment", "dev")
    if environment not in ENVIRONMENTS:
        raise BundleError(
            "environment must be exactly one of: " + ", ".join(ENVIRONMENTS)
        )

    root_source = _source(root["source"], "source")
    images = root["images"]
    if not isinstance(images, list) or len(images) != len(FAMILIES):
        raise BundleError(f"images must contain exactly {len(FAMILIES)} entries")

    seen: set[str] = set()
    for index, image_value in enumerate(images):
        where = f"images[{index}]"
        image = _exact_keys(image_value, {"family", "source", "ref"}, where)
        family = image["family"]
        if not isinstance(family, str) or family not in FAMILIES:
            raise BundleError(f"{where}.family is unknown: {family!r}")
        if family in seen:
            raise BundleError(f"duplicate image family: {family}")
        seen.add(family)

        if _source(image["source"], f"{where}.source") != root_source:
            raise BundleError(
                f"{where}.source must match the bundle source; split source ownership is forbidden"
            )

        ref = image["ref"]
        repository = _repository(family)
        prefix = f"{repository}@"
        if not isinstance(ref, str) or not ref.startswith(prefix):
            raise BundleError(f"{where}.ref must use {repository}")
        if DIGEST.fullmatch(ref[len(prefix) :]) is None:
            raise BundleError(
                f"{where}.ref must be an immutable lowercase sha256 digest reference"
            )

    actual_order = tuple(image["family"] for image in images)
    if actual_order != FAMILIES:
        raise BundleError(
            "images must use the exact family order: " + ", ".join(FAMILIES)
        )
    return root


def load_bundle(path: Path) -> dict[str, Any]:
    try:
        with path.open(encoding="utf-8") as handle:
            value = json.load(
                handle,
                object_pairs_hook=_unique_object,
                parse_constant=_reject_non_json_constant,
            )
    except OSError as error:
        raise BundleError(f"cannot read {path}: {error}") from error
    except json.JSONDecodeError as error:
        raise BundleError(f"invalid JSON in {path}: {error}") from error
    return validate_bundle(value)


def validate_boundary(old: dict[str, Any], new: dict[str, Any]) -> None:
    old_environment = old.get("environment", "dev")
    new_environment = new.get("environment", "dev")
    if old_environment != new_environment:
        raise BundleError(
            "bundle boundary cannot change environment: "
            f"{old_environment} -> {new_environment}"
        )
    if old["source"] == new["source"]:
        raise BundleError("bundle boundary must change the exact source SHA")
    if old == new:
        raise BundleError("bundle boundary must change the bundle object")


def _create_bundle(
    source_sha: str,
    candidates: list[list[str]],
    environment: str | None = None,
) -> dict[str, Any]:
    source = {"repository": SOURCE_REPOSITORY, "sha": source_sha}
    images = [
        {"family": family, "source": dict(source), "ref": ref}
        for family, candidate_source, ref in candidates
        if candidate_source == source_sha
    ]
    if len(images) != len(candidates):
        raise BundleError("every candidate source SHA must match the bundle source SHA")
    bundle = {
        "apiVersion": API_VERSION,
        "kind": KIND,
        "source": source,
        "images": images,
    }
    if environment is not None:
        bundle["environment"] = environment
    return validate_bundle(bundle)


def _write_bundle(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", delete=False
    )
    temporary = Path(handle.name)
    try:
        with handle:
            json.dump(value, handle, indent=2)
            handle.write("\n")
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _candidate_from_metadata(
    family: str, source_sha: str, registry: str, metadata_path: Path
) -> tuple[str, str, str]:
    if family not in PUBLICATION_FAMILIES:
        raise BundleError(f"unknown image family: {family}")
    if not SOURCE_SHA.fullmatch(source_sha) or source_sha == "0" * 40:
        raise BundleError("candidate source SHA must be an exact Git object ID")
    if registry != _repository_prefix():
        raise BundleError("candidate repository prefix must be exactly the Harbor codewire project")
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise BundleError(f"cannot read Buildx metadata: {error}") from error
    if not isinstance(metadata, dict):
        raise BundleError("Buildx metadata must be an object")
    digest = metadata.get("containerimage.digest")
    if not isinstance(digest, str) or DIGEST.fullmatch(digest) is None:
        raise BundleError("Buildx metadata is missing an immutable image digest")
    return family, source_sha, f"{_repository(family)}@{digest}"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create", help="create one complete bundle")
    create.add_argument("--source-sha", required=True)
    create.add_argument("--output", required=True, type=Path)
    create.add_argument(
        "--environment",
        choices=ENVIRONMENTS,
        help="explicit closed release-tree environment; omission is legacy dev",
    )
    create.add_argument(
        "--candidate",
        action="append",
        nargs=3,
        metavar=("FAMILY", "SOURCE_SHA", "DIGEST_REF"),
        required=True,
    )

    validate = subparsers.add_parser("validate", help="validate one bundle")
    validate.add_argument("bundle", type=Path)

    boundary = subparsers.add_parser(
        "boundary", help="validate two complete bundles as one change boundary"
    )
    boundary.add_argument("old_bundle", type=Path)
    boundary.add_argument("new_bundle", type=Path)

    candidate = subparsers.add_parser(
        "candidate", help="emit one candidate from Docker Buildx metadata"
    )
    candidate.add_argument("family")
    candidate.add_argument("source_sha")
    candidate.add_argument("registry")
    candidate.add_argument("metadata", type=Path)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        if args.command == "create":
            _write_bundle(
                args.output,
                _create_bundle(
                    args.source_sha,
                    args.candidate,
                    args.environment,
                ),
            )
        elif args.command == "validate":
            load_bundle(args.bundle)
        elif args.command == "boundary":
            validate_boundary(
                load_bundle(args.old_bundle), load_bundle(args.new_bundle)
            )
        elif args.command == "candidate":
            family, source_sha, ref = _candidate_from_metadata(
                args.family, args.source_sha, args.registry, args.metadata
            )
            output = sys.stdout
            if os.environ.get("GITHUB_OUTPUT"):
                output = open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8")
            try:
                print(f"family={family}", file=output)
                print(f"source_sha={source_sha}", file=output)
                print(f"candidate_ref={ref}", file=output)
            finally:
                if output is not sys.stdout:
                    output.close()
        else:  # pragma: no cover - argparse enforces this
            raise AssertionError(args.command)
    except BundleError as error:
        print(f"bundle error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
