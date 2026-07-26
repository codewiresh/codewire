#!/usr/bin/env python3
"""Repository policy checks for Codewire.

This is intentionally stdlib-only. These checks run in CI and during local
preflight, so they should not depend on the JavaScript toolchain unless the
check is explicitly validating JavaScript package output.
"""

from __future__ import annotations

import argparse
from collections import Counter
import copy
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[2]
OPENAPI_METHODS = {"delete", "get", "head", "options", "patch", "post", "put", "trace"}


def read_text(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def read_json(rel: str) -> Any:
    return json.loads(read_text(rel))


def write_json(rel: str, value: Any) -> None:
    (ROOT / rel).write_text(json_string(value), encoding="utf-8")


def json_string(value: Any) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False) + "\n"


def stable_json(value: Any) -> str:
    return json.dumps(sort_json(value), ensure_ascii=False, separators=(",", ":"))


def sort_json(value: Any) -> Any:
    if isinstance(value, list):
        return [sort_json(item) for item in value]
    if isinstance(value, dict):
        return {key: sort_json(value[key]) for key in sorted(value)}
    return value


def run(
    args: list[str],
    *,
    cwd: Path = ROOT,
    check: bool = True,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    result = subprocess.run(
        args,
        cwd=cwd,
        env=merged_env,
        text=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if check and result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        raise RuntimeError(f"{args[0]} {' '.join(args[1:])} failed: {detail}")
    return result


def line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def walk_files(directory: Path) -> list[Path]:
    return [path for path in directory.rglob("*") if path.is_file()]


def report(prefix: str, failures: list[str], *, error_annotation: bool = False) -> int:
    if failures:
        for failure in failures:
            if error_annotation:
                print(f"::error::{prefix}: {failure}", file=sys.stderr)
            else:
                print(f"{prefix}: {failure}", file=sys.stderr)
        return 1
    return 0


def git_source_files() -> list[str]:
    result = run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        check=True,
    )
    return [path for path in result.stdout.split("\0") if path]


# ---------------------------------------------------------------------------
# OpenAPI preview helpers


RUST_OPENAPI_PREVIEW_COMMANDS: list[tuple[str, list[str]]] = [
    (
        "orchestration",
        ["cargo", "run", "-q", "-p", "codewire-orchestration", "--bin", "openapi-preview"],
    ),
    (
        "billing",
        ["cargo", "run", "-q", "-p", "codewire-billing", "--bin", "billing-openapi-preview"],
    ),
    ("idp", ["cargo", "run", "-q", "-p", "codewire-idp", "--bin", "openapi-preview"]),
]


def load_rust_openapi_previews(fail: Callable[[str], None]) -> list[tuple[str, Any | None]]:
    previews: list[tuple[str, Any | None]] = []
    for name, args in RUST_OPENAPI_PREVIEW_COMMANDS:
        previews.append((name, run_preview_json(name, args, fail)))
    return previews


def run_preview_json(name: str, args: list[str], fail: Callable[[str], None]) -> Any | None:
    result = run(args, check=False)
    if result.returncode != 0:
        fail(f"{name} preview command failed")
        if result.stdout:
            print(result.stdout, end="")
        if result.stderr:
            print(result.stderr, end="", file=sys.stderr)
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as error:
        fail(f"{name} preview did not emit valid JSON: {error}")
        return None


def merge_rust_openapi_previews(
    previews: list[tuple[str, Any | None]],
    fail: Callable[[str], None],
) -> dict[str, Any]:
    merged: dict[str, Any] = {
        "openapi": "3.1.0",
        "info": {
            "title": "Codewire API (Rust preview)",
            "version": "0.1.0",
        },
        "paths": {},
        "components": {
            "schemas": {},
        },
    }

    for name, doc in previews:
        if doc is None:
            continue
        if doc.get("openapi") != "3.1.0":
            fail(f"{name} preview must be OpenAPI 3.1.0, got {doc.get('openapi', '<missing>')}")
            continue
        merge_paths(merged["paths"], doc.get("paths") or {}, name, fail)
        merge_components(
            merged["components"]["schemas"],
            (doc.get("components") or {}).get("schemas") or {},
            name,
            "schema",
            fail,
        )

    return sort_json(merged)


def merge_paths(
    target: dict[str, Any],
    paths: dict[str, Any],
    service_name: str,
    fail: Callable[[str], None],
) -> None:
    for path, item in paths.items():
        target.setdefault(path, {})
        for method, operation in (item or {}).items():
            existing = target[path].get(method)
            if existing is None:
                target[path][method] = operation
                continue
            if stable_json(existing) == stable_json(operation):
                continue
            fail(f"{service_name} preview conflicts with existing operation {method.upper()} {path}")


def merge_components(
    target: dict[str, Any],
    components: dict[str, Any],
    service_name: str,
    component_kind: str,
    fail: Callable[[str], None],
) -> None:
    for name, component in components.items():
        existing = target.get(name)
        if existing is None:
            target[name] = component
            continue
        if stable_json(existing) == stable_json(component):
            continue
        fail(f"{service_name} preview conflicts with existing {component_kind} component {name}")


def downgrade_openapi_31_to_30(doc: dict[str, Any], fail: Callable[[str], None]) -> dict[str, Any]:
    downgraded = copy.deepcopy(doc)
    downgraded["openapi"] = "3.0.3"
    downgrade_boolean_schemas(downgraded, "$", fail)
    downgrade_nullable_types(downgraded, "$", fail)
    return sort_json(downgraded)


def downgrade_boolean_schemas(value: Any, path: str, fail: Callable[[str], None]) -> None:
    if isinstance(value, list):
        for index, item in enumerate(value):
            downgrade_boolean_schemas(item, f"{path}[{index}]", fail)
        return
    if not isinstance(value, dict):
        return

    components = value.get("components")
    schemas = components.get("schemas") if isinstance(components, dict) else None
    if isinstance(schemas, dict):
        for name, schema in list(schemas.items()):
            schemas[name] = downgrade_schema(schema, f"{path}.components.schemas.{name}", fail)

    for key, child in list(value.items()):
        if key == "schema":
            value[key] = downgrade_schema(child, f"{path}.{key}", fail)
        else:
            downgrade_boolean_schemas(child, f"{path}.{key}", fail)


def downgrade_schema(schema: Any, path: str, fail: Callable[[str], None]) -> Any:
    if schema is True:
        return {}
    if schema is False:
        fail(f"{path} is boolean schema false, which cannot be downgraded to OpenAPI 3.0")
        return {}
    if isinstance(schema, list) or not isinstance(schema, dict):
        return schema

    downgrade_nullable_any_of(schema)

    for key in [
        "additionalProperties",
        "contains",
        "if",
        "items",
        "not",
        "propertyNames",
        "then",
        "else",
        "unevaluatedProperties",
    ]:
        if key in schema:
            schema[key] = downgrade_schema(schema[key], f"{path}.{key}", fail)

    for key in ["allOf", "anyOf", "oneOf", "prefixItems"]:
        if isinstance(schema.get(key), list):
            schema[key] = [
                downgrade_schema(child, f"{path}.{key}[{index}]", fail)
                for index, child in enumerate(schema[key])
            ]

    for key in ["properties", "patternProperties", "dependentSchemas"]:
        if isinstance(schema.get(key), dict):
            for name, child in list(schema[key].items()):
                schema[key][name] = downgrade_schema(child, f"{path}.{key}.{name}", fail)

    return schema


def downgrade_nullable_any_of(schema: dict[str, Any]) -> None:
    any_of = schema.get("anyOf")
    if not isinstance(any_of, list):
        return
    non_null_schemas = [child for child in any_of if not is_null_schema(child)]
    if len(non_null_schemas) == len(any_of):
        return
    schema["anyOf"] = non_null_schemas
    schema["nullable"] = True


def is_null_schema(schema: Any) -> bool:
    return isinstance(schema, dict) and schema.get("type") == "null" and "$ref" not in schema


def downgrade_nullable_types(value: Any, path: str, fail: Callable[[str], None]) -> None:
    if isinstance(value, list):
        for index, item in enumerate(value):
            downgrade_nullable_types(item, f"{path}[{index}]", fail)
        return
    if not isinstance(value, dict):
        return

    schema_type = value.get("type")
    if isinstance(schema_type, list):
        non_null_types = [item for item in schema_type if item != "null"]
        if "null" not in schema_type or len(non_null_types) != 1:
            fail(
                f"{path}.type cannot be downgraded from OpenAPI 3.1 array type "
                f"{json.dumps(schema_type, ensure_ascii=False)}"
            )
        else:
            value["type"] = non_null_types[0]
            value["nullable"] = True

    for key, child in list(value.items()):
        downgrade_nullable_types(child, f"{path}.{key}", fail)


def openapi_operations(paths: dict[str, Any]) -> list[str]:
    operations: list[str] = []
    for path, item in (paths or {}).items():
        for method in (item or {}).keys():
            if method in OPENAPI_METHODS:
                operations.append(f"{method.upper()} {path}")
    return sorted(operations)


def check_openapi_contract_source(_args: argparse.Namespace) -> int:
    failures: list[str] = []

    def fail(message: str) -> None:
        failures.append(f"openapi contract source: {message}")

    pkg = read_json("package.json")
    scripts = pkg.get("scripts") or {}

    if scripts.get("types:generate") != "bun run types:generate:ts":
        fail("types:generate must only consume the checked-in openapi.json")

    for name in ["types:generate", "types:generate:ts"]:
        script = scripts.get(name) or ""
        if re.search(r"\bgo\s+test\b", script) or "TestExportOpenAPISpec" in script:
            fail(f"{name} must not invoke an OpenAPI exporter")

    for name, script in scripts.items():
        references_go_exporter = "TestExportOpenAPISpec" in script or re.search(
            r"\bopenapi:export:go\b", script
        )
        if "openapi" in name and references_go_exporter:
            fail(f"{name} must not reference the retired Go/huma OpenAPI exporter")

    rust_export = scripts.get("openapi:export:rust") or ""
    if (
        "repo_checks.py openapi-preview-export" not in rust_export
        or "--openapi 3.0.3" not in rust_export
        or "--output openapi.json" not in rust_export
    ):
        fail("openapi:export:rust must write the Rust-generated OpenAPI 3.0.3 contract to openapi.json")

    rust_refresh = scripts.get("openapi:refresh-from-rust") or ""
    if "openapi:export:rust" not in rust_refresh or "types:generate:ts" not in rust_refresh:
        fail("openapi:refresh-from-rust must refresh the Rust spec and generated TypeScript types together")

    rust_source = scripts.get("openapi:check-rust-source") or ""
    if "repo_checks.py openapi-check-rust-source" not in rust_source:
        fail("openapi:check-rust-source must verify openapi.json against the merged Rust previews")

    spec = read_json("openapi.json")
    if spec.get("openapi") != "3.0.3":
        fail(f"openapi.json must remain the downgraded 3.0.3 contract, got {spec.get('openapi', '<missing>')}")

    assert_no_boolean_schemas(spec, "$", fail)

    for path in [
        "/api/auth/sign-in",
        "/api/v1/git-credentials",
        "/api/v1/organizations",
        "/api/v1/organizations/{orgId}/billing",
        "/api/v1/github/repos",
    ]:
        if path not in (spec.get("paths") or {}):
            fail(f"openapi.json is missing expected path {path}")

    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        return 1
    print("openapi contract source: OK")
    return 0


def assert_no_boolean_schemas(value: Any, path: str, fail: Callable[[str], None]) -> None:
    if isinstance(value, list):
        for index, item in enumerate(value):
            assert_no_boolean_schemas(item, f"{path}[{index}]", fail)
        return
    if not isinstance(value, dict):
        return

    components = value.get("components")
    schemas = components.get("schemas") if isinstance(components, dict) else None
    if isinstance(schemas, dict):
        for name, schema in schemas.items():
            assert_schema_no_boolean(schema, f"{path}.components.schemas.{name}", fail)

    for key, child in value.items():
        if key == "schema":
            assert_schema_no_boolean(child, f"{path}.{key}", fail)
        else:
            assert_no_boolean_schemas(child, f"{path}.{key}", fail)


def assert_schema_no_boolean(schema: Any, path: str, fail: Callable[[str], None]) -> None:
    if isinstance(schema, bool):
        fail(f"{path} must not be a boolean schema in the checked-in OpenAPI 3.0.3 contract")
        return
    if isinstance(schema, list) or not isinstance(schema, dict):
        return
    if schema.get("type") == "null":
        fail(f'{path}.type must not be "null" in the checked-in OpenAPI 3.0.3 contract')
    if isinstance(schema.get("type"), list) and "null" in schema["type"]:
        fail(f'{path}.type must not include "null" in the checked-in OpenAPI 3.0.3 contract')

    for key in [
        "additionalProperties",
        "contains",
        "if",
        "items",
        "not",
        "propertyNames",
        "then",
        "else",
        "unevaluatedProperties",
    ]:
        if key in schema:
            assert_schema_no_boolean(schema[key], f"{path}.{key}", fail)

    for key in ["allOf", "anyOf", "oneOf", "prefixItems"]:
        if isinstance(schema.get(key), list):
            for index, child in enumerate(schema[key]):
                assert_schema_no_boolean(child, f"{path}.{key}[{index}]", fail)

    for key in ["properties", "patternProperties", "dependentSchemas"]:
        if isinstance(schema.get(key), dict):
            for name, child in schema[key].items():
                assert_schema_no_boolean(child, f"{path}.{key}.{name}", fail)


def check_rust_openapi_preview(_args: argparse.Namespace) -> int:
    failures: list[str] = []
    fail = lambda message: failures.append(f"rust openapi preview: {message}")
    canonical = read_json("openapi.json")
    previews = load_rust_openapi_previews(fail)
    merged = merge_rust_openapi_previews(previews, fail)

    canonical_paths = sorted((canonical.get("paths") or {}).keys())
    rust_paths = sorted((merged.get("paths") or {}).keys())
    missing = [path for path in canonical_paths if path not in (merged.get("paths") or {})]
    extra = [path for path in rust_paths if path not in (canonical.get("paths") or {})]
    canonical_operations = openapi_operations(canonical.get("paths") or {})
    rust_operations = set(openapi_operations(merged.get("paths") or {}))
    missing_operations = [op for op in canonical_operations if op not in rust_operations]

    if missing:
        fail("missing %d canonical path(s):\n%s" % (len(missing), "\n".join(f"  {path}" for path in missing)))
    if missing_operations:
        fail(
            "missing %d canonical operation(s):\n%s"
            % (len(missing_operations), "\n".join(f"  {operation}" for operation in missing_operations))
        )
    if extra:
        print(f"rust openapi preview: {len(extra)} Rust-only preview path(s):")
        for path in extra:
            print(f"  {path}")

    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        return 1
    print(
        f"rust openapi preview: OK ({len(canonical_operations)} canonical operations "
        f"across {len(canonical_paths)} paths covered)"
    )
    return 0


def check_rust_openapi_source(_args: argparse.Namespace) -> int:
    failures: list[str] = []
    fail = lambda message: failures.append(f"rust openapi source: {message}")
    checked_in = read_json("openapi.json")
    previews = load_rust_openapi_previews(fail)
    generated = downgrade_openapi_31_to_30(merge_rust_openapi_previews(previews, fail), fail)
    if stable_json(checked_in) != stable_json(generated):
        fail("openapi.json is stale; run `bun run openapi:refresh-from-rust`")
    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        return 1
    print("rust openapi source: OK")
    return 0


def export_rust_openapi_preview(args: argparse.Namespace) -> int:
    failures: list[str] = []
    fail = lambda message: failures.append(f"rust openapi preview export: {message}")
    if args.openapi not in {"3.1.0", "3.0.3"}:
        fail("--openapi must be 3.1.0 or 3.0.3")
    previews = load_rust_openapi_previews(fail)
    merged31 = merge_rust_openapi_previews(previews, fail)
    merged = downgrade_openapi_31_to_30(merged31, fail) if args.openapi == "3.0.3" else merged31
    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        return 1
    rendered = json_string(merged)
    if args.output:
        Path(args.output).resolve().write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


def check_rust_openapi_types(_args: argparse.Namespace) -> int:
    failures: list[str] = []
    fail = lambda message: failures.append(f"rust openapi types: {message}")
    temp_dir = Path(tempfile.mkdtemp(prefix="codewire-rust-openapi-types-"))
    try:
        previews = load_rust_openapi_previews(fail)
        merged31 = merge_rust_openapi_previews(previews, fail)
        merged30 = downgrade_openapi_31_to_30(merged31, fail)
        spec_path = temp_dir / "openapi.json"
        spec_path.write_text(json_string(merged30), encoding="utf-8")

        openapi_typescript = ROOT / "node_modules" / ".bin" / "openapi-typescript"
        command = str(openapi_typescript) if openapi_typescript.exists() else "openapi-typescript"
        for output_path in [
            "packages/codewire-types/generated/api.d.ts",
            "libs/api-client-ts/src/schema.gen.ts",
        ]:
            absolute_output_path = temp_dir / output_path
            absolute_output_path.parent.mkdir(parents=True, exist_ok=True)
            result = run(
                [
                    command,
                    str(spec_path),
                    "--default-non-nullable",
                    "false",
                    "-o",
                    str(absolute_output_path),
                ],
                check=False,
            )
            if result.returncode != 0:
                fail(f"openapi-typescript failed for {output_path}")
                if result.stdout:
                    print(result.stdout, end="")
                if result.stderr:
                    print(result.stderr, end="", file=sys.stderr)
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        return 1
    print("rust openapi types: OK")
    return 0


# ---------------------------------------------------------------------------
# REST surface freeze


def check_rest_surface_freeze(args: argparse.Namespace) -> int:
    failures: list[str] = []

    def fail(message: str) -> None:
        failures.append(f"rest surface freeze: {message}")

    freeze_doc = "docs/plans/connect-rpc/13-rest-sunset-and-openapi-removal.md"
    baseline_rel = "scripts/checks/contracts/rest-surface-baseline.json"
    service_crates = [
        "crates/codewire-orchestration",
        "crates/codewire-billing",
        "crates/codewire-idp",
        "crates/codewire-coordinator",
    ]
    oidc_transport_rel = "crates/codewire-oidc/src/transport.rs"
    oidc_defaults_rel = "crates/codewire-oidc/src/discovery.rs"
    expected_oidc_config_routes = 8

    spec = read_json("openapi.json")
    spec_operations = set(openapi_operations(spec.get("paths") or {}))

    swept_routes: set[str] = set()
    for crate in service_crates:
        for file in walk_files(ROOT / crate / "src"):
            if file.suffix != ".rs":
                continue
            rel = file.relative_to(ROOT).as_posix()
            text = file.read_text(encoding="utf-8")
            sanitized = sanitize_rust_source(text)
            for match in re.finditer(r"\.nest(?:_service)?\(", sanitized):
                fail(
                    f"{rel}:{line_number(text, match.start())} uses "
                    f"{match.group(0)[:-1]}; nested routers hide the mounted prefix from the "
                    "REST-freeze sweep — register full literal paths with .route("
                )
            for index, path in route_registrations(sanitized):
                if path is None:
                    fail(
                        f"{rel}:{line_number(text, index)} registers a route from a non-literal "
                        "path expression; the REST-freeze sweep only sees literal paths — use a "
                        f"string literal (config-mounted library routes need a baseline decision, see {freeze_doc})"
                    )
                    continue
                if path.startswith("/api/"):
                    swept_routes.add(path)

    transport_text = read_text(oidc_transport_rel)
    transport_sanitized = sanitize_rust_source(transport_text)
    for match in re.finditer(r"\.nest(?:_service)?\(", transport_sanitized):
        fail(
            f"{oidc_transport_rel}:{line_number(transport_text, match.start())} uses "
            f"{match.group(0)[:-1]}; nested routers hide the mounted prefix from the REST-freeze sweep"
        )
    transport_config_routes = [
        route for route in route_registrations(transport_sanitized) if route[1] is None
    ]
    if len(transport_config_routes) != expected_oidc_config_routes:
        fail(
            f"{oidc_transport_rel} has {len(transport_config_routes)} config-mounted route "
            f"registrations, expected {expected_oidc_config_routes}; the OIDC transport surface "
            f"is frozen (permanent raw HTTP, {freeze_doc})"
        )

    defaults_text = read_text(oidc_defaults_rel)
    oidc_seeded_routes = endpoint_path_defaults(sanitize_rust_source(defaults_text))
    if len(oidc_seeded_routes) != expected_oidc_config_routes:
        fail(
            f"{oidc_defaults_rel} declares {len(oidc_seeded_routes)} EndpointPaths defaults, "
            f"expected {expected_oidc_config_routes}; the OIDC transport surface is frozen "
            f"(permanent raw HTTP, {freeze_doc})"
        )

    current_routes = set(swept_routes) | set(oidc_seeded_routes)

    try:
        baseline = read_json(baseline_rel)
    except Exception as error:  # noqa: BLE001 - this is a repo check script
        fail(f"cannot read {baseline_rel}: {error}")
        for failure in failures:
            print(failure, file=sys.stderr)
        return 1

    baseline_operations = set(baseline.get("operations") or [])
    baseline_routes = set(baseline.get("raw_routes") or [])
    allowlist = baseline.get("allowlist") or []

    allowed_operations: set[str] = set()
    allowed_routes: set[str] = set()
    for index, entry in enumerate(allowlist):
        label = f"{baseline_rel} allowlist[{index}]"
        if not isinstance(entry.get("issue"), str) or entry.get("issue", "").strip() == "":
            fail(f"{label} is missing the required issue field")
        if not isinstance(entry.get("justification"), str) or entry.get("justification", "").strip() == "":
            fail(f"{label} is missing the required justification field")
        if "operation" not in entry and "raw_route" not in entry:
            fail(f"{label} must name an operation or a raw_route")
            continue
        if "operation" in entry:
            if entry["operation"] in baseline_operations:
                fail(
                    f"{label} operation {entry['operation']} is already in the frozen baseline; "
                    "drop the allowlist entry"
                )
            allowed_operations.add(entry["operation"])
        if "raw_route" in entry:
            if entry["raw_route"] in baseline_routes:
                fail(
                    f"{label} raw_route {entry['raw_route']} is already in the frozen baseline; "
                    "drop the allowlist entry"
                )
            allowed_routes.add(entry["raw_route"])

    new_operations = sorted(spec_operations - baseline_operations - allowed_operations)
    new_routes = sorted(current_routes - baseline_routes - allowed_routes)
    stale_operations = sorted(baseline_operations - spec_operations)
    stale_routes = sorted(baseline_routes - current_routes)
    stale_allowlist = [
        entry
        for entry in allowlist
        if ("operation" in entry and entry["operation"] not in spec_operations)
        or ("raw_route" in entry and entry["raw_route"] not in current_routes)
    ]

    for operation in new_operations:
        fail(
            f"new REST operation not in the freeze baseline: {operation} — the REST surface is "
            f"frozen (gate G3, {freeze_doc}); new endpoints are proto-first. A genuinely exempt "
            "endpoint needs an allowlist entry with issue + justification."
        )
    for route in new_routes:
        fail(
            f"new /api route not in the freeze baseline: {route} — the REST surface is frozen "
            f"(gate G3, {freeze_doc}); new endpoints are proto-first. A genuinely exempt route "
            "needs an allowlist entry with issue + justification."
        )

    if args.update:
        removed = len(stale_operations) + len(stale_routes) + len(stale_allowlist)
        baseline["operations"] = sorted(
            [operation for operation in (baseline.get("operations") or []) if operation in spec_operations]
        )
        baseline["raw_routes"] = sorted(
            [route for route in (baseline.get("raw_routes") or []) if route in current_routes]
        )
        baseline["allowlist"] = [entry for entry in allowlist if entry not in stale_allowlist]
        write_json(baseline_rel, baseline)
        suffix = "y" if removed == 1 else "ies"
        print(
            f"rest surface freeze: baseline updated ({removed} stale entr{suffix} removed; "
            "additions are never written — the baseline only shrinks)"
        )
    else:
        for operation in stale_operations:
            fail(f"baseline operation no longer exists: {operation}; run 'bun run rest:freeze:update'")
        for route in stale_routes:
            fail(f"baseline raw route no longer exists: {route}; run 'bun run rest:freeze:update'")
        for entry in stale_allowlist:
            fail(
                f"allowlist entry for {entry.get('operation') or entry.get('raw_route')} no longer "
                "matches a live operation/route; run 'bun run rest:freeze:update'"
            )

    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        return 1
    mesh_result = check_mesh_surface_freeze(argparse.Namespace(self_test=True))
    if mesh_result != 0:
        return mesh_result
    if not args.update:
        print(
            f"rest surface freeze: OK ({len(baseline_operations)} operations, "
            f"{len(baseline_routes)} raw routes frozen, {len(allowlist)} allowlisted)"
        )
    return 0


def route_registrations(sanitized: str) -> list[tuple[int, str | None]]:
    routes: list[tuple[int, str | None]] = []
    for match in re.finditer(r"\.route\(", sanitized):
        index = match.end()
        while index < len(sanitized) and sanitized[index].isspace():
            index += 1
        literal = re.match(r'"((?:[^"\\]|\\.)*)"', sanitized[index:])
        routes.append((match.start(), literal.group(1) if literal else None))
    return routes


def endpoint_path_defaults(sanitized: str) -> list[str]:
    impl = re.search(r"impl\s+Default\s+for\s+EndpointPaths\s*\{", sanitized)
    if not impl:
        return []
    start = impl.end()
    depth = 1
    end = start
    while end < len(sanitized) and depth > 0:
        char = sanitized[end]
        if char in {'"', "'"} or is_raw_string_start(sanitized, end):
            end = skip_token(sanitized, end)
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
        end += 1
    return [
        match.group(1)
        for match in re.finditer(r'"(/(?:[^"\\]|\\.)*)"', sanitized[start:end])
    ]


def sanitize_rust_source(text: str) -> str:
    chars = list(text)

    def blank(start: int, end: int) -> None:
        for index in range(start, min(end, len(chars))):
            if chars[index] != "\n":
                chars[index] = " "

    index = 0
    while index < len(text):
        char = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ""
        if char == "/" and next_char == "/":
            end = index
            while end < len(text) and text[end] != "\n":
                end += 1
            blank(index, end)
            index = end
        elif char == "/" and next_char == "*":
            depth = 1
            end = index + 2
            while end < len(text) and depth > 0:
                if text[end : end + 2] == "/*":
                    depth += 1
                    end += 2
                elif text[end : end + 2] == "*/":
                    depth -= 1
                    end += 2
                else:
                    end += 1
            blank(index, end)
            index = end
        else:
            index = skip_token(text, index)

    comment_free = "".join(chars)
    for match in re.finditer(r"#\[cfg\(test\)\]", comment_free):
        if chars[match.start()] == " ":
            continue
        index = match.end()
        depth = 0
        entered = False
        while index < len(comment_free):
            char = comment_free[index]
            if char in {'"', "'"} or is_raw_string_start(comment_free, index):
                index = skip_token(comment_free, index)
                continue
            if not entered and char == ";":
                index += 1
                break
            if char == "{":
                depth += 1
                entered = True
            elif char == "}":
                depth -= 1
                if entered and depth == 0:
                    index += 1
                    break
            index += 1
        blank(match.start(), index)

    return "".join(chars)


def skip_token(text: str, index: int) -> int:
    char = text[index] if index < len(text) else ""
    if char == '"':
        cursor = index + 1
        while cursor < len(text):
            if text[cursor] == "\\":
                cursor += 2
            elif text[cursor] == '"':
                return cursor + 1
            else:
                cursor += 1
        return cursor
    if is_raw_string_start(text, index):
        hashes = 0
        cursor = index + 1
        while cursor < len(text) and text[cursor] == "#":
            hashes += 1
            cursor += 1
        cursor += 1
        closer = '"' + ("#" * hashes)
        end = text.find(closer, cursor)
        return len(text) if end == -1 else end + len(closer)
    if char == "'":
        literal = re.match(r"'(?:\\u\{[0-9a-fA-F]{1,6}\}|\\.|[^\\'])'", text[index : index + 12])
        return index + len(literal.group(0)) if literal else index + 1
    return index + 1


def is_raw_string_start(text: str, index: int) -> bool:
    if index >= len(text) or text[index] != "r":
        return False
    if index > 0 and re.match(r'[A-Za-z0-9_"]', text[index - 1]):
        return False
    return re.match(r'r#*"', text[index : index + 64]) is not None


# ---------------------------------------------------------------------------
# Hosted Mesh surface inventory and freeze


MESH_SURFACE_REL = "scripts/checks/contracts/rest-surface-baseline.json"
MESH_SERVER_REL = "crates/codewire-mesh/src/server.rs"
MESH_EXPECTED_REGISTRATIONS = 24
MESH_EXPECTED_OPERATIONS = 31
MESH_EXPECTED_ROUTER_SHA256 = (
    "604338c2d59548a3e4077a90ff99da428be93512d56e50e607f4d3691bb9256b"
)
MESH_EXPECTED_COUNTS = {
    "route_registrations": 24,
    "method_path_operations": 31,
    "router_new_expressions": 2,
    "router_merges": 1,
    "app_builder_route_mounts": 1,
    "caller_operation_references": {
        "browser": 5,
        "ci-smoke": 0,
        "go-sdk": 21,
        "node-runtime": 0,
        "python-sdk": 21,
        "rust-cli": 9,
        "rust-client": 0,
        "rust-tailnet": 0,
        "typescript-sdk": 21,
    },
    "credential_operations": {
        "enrollment-code": 1,
        "invite-code": 1,
        "mesh-identity": 17,
        "mesh-identity-plus-invite-code": 1,
        "mesh-session-bearer-or-cookie": 1,
        "node-bearer": 1,
        "node-or-mesh-identity": 5,
        "none": 2,
        "oidc-device-code": 0,
        "oidc-state-and-code": 1,
        "runtime-credential": 1,
    },
    "disposition_operations": {"connect": 26, "delete": 5},
    "package_operations": {
        "codewire.internal.v1": 6,
        "codewire.v1": 20,
        "none": 5,
    },
    "operations_without_callers": 3,
    "client_url_template_records": 58,
    "client_url_template_occurrences": 74,
}
MESH_HTTP_METHODS = {"delete", "get", "head", "options", "patch", "post", "put"}
MESH_CALLER_CLASSES = {
    "browser",
    "ci-smoke",
    "go-sdk",
    "node-runtime",
    "python-sdk",
    "rust-cli",
    "rust-client",
    "rust-tailnet",
    "typescript-sdk",
}
MESH_CLIENT_PATH_PREFIXES = (
    "api/v1/access-grants",
    "api/v1/auth/config",
    "api/v1/auth/validate",
    "api/v1/device",
    "api/v1/groups",
    "api/v1/invites",
    "api/v1/join",
    "api/v1/kv",
    "api/v1/network-auth",
    "api/v1/networks",
    "api/v1/node-enrollments",
    "api/v1/nodes",
    "api/v1/tailnet/coordinate",
    "api/v1/tasks",
)
MESH_CLIENT_RAW_PATH_PREFIXES = (
    "auth/oidc",
    "auth/session",
    "node/back",
    "node/connect",
)
MESH_FORBIDDEN_ROUTER_METHODS = (
    "any_service",
    "delete_service",
    "fallback",
    "fallback_service",
    "get_service",
    "head_service",
    "nest",
    "nest_service",
    "on",
    "on_service",
    "options_service",
    "patch_service",
    "post_service",
    "put_service",
    "route_service",
    "trace_service",
    "with_connect_routes",
    "with_connect_routes_auth",
    "with_connect_routes_auth_and_protocol_policy",
    "with_unary_connect_routes_auth",
)


def check_mesh_surface_freeze(args: argparse.Namespace) -> int:
    try:
        baseline = read_json(MESH_SURFACE_REL)
        inventory = baseline["mesh_surface"]
        mesh_sources = mesh_production_sources()
        client_sources = mesh_client_sources()
        failures = mesh_surface_failures(mesh_sources, client_sources, inventory)
        if not failures and args.self_test:
            mesh_surface_self_test(mesh_sources, client_sources, inventory)
    except Exception as error:  # noqa: BLE001 - this is a repository guard
        failures = [str(error)]

    if failures:
        for failure in failures:
            print(f"mesh surface freeze: {failure}", file=sys.stderr)
        return 1
    print(
        "mesh surface freeze: OK "
        f"({MESH_EXPECTED_REGISTRATIONS} registrations, "
        f"{MESH_EXPECTED_OPERATIONS} operations, "
        f"{len(inventory['client_url_templates'])} client URL template records)"
    )
    return 0


def mesh_surface_failures(
    mesh_sources: dict[str, str],
    client_sources: dict[str, tuple[str, str]],
    inventory: dict[str, Any],
) -> list[str]:
    failures: list[str] = []
    server_source = mesh_sources.get(MESH_SERVER_REL)
    if server_source is None:
        return [f"missing production Mesh router source {MESH_SERVER_REL}"]
    registrations = mesh_route_registrations(server_source)
    operation_count = sum(len(route["operations"]) for route in registrations)
    topology, forbidden_router_uses = mesh_router_topology(mesh_sources)
    router_sha256 = mesh_router_fingerprint(server_source)

    if inventory.get("router_from_state_sha256") != MESH_EXPECTED_ROUTER_SHA256:
        failures.append(
            "router_from_state_sha256 must equal the frozen production router fingerprint"
        )
    if router_sha256 != MESH_EXPECTED_ROUTER_SHA256:
        failures.append(
            f"{MESH_SERVER_REL} router_from_state fingerprint drift: "
            f"found {router_sha256}"
        )

    expected_counts = inventory.get("expected_counts")
    if expected_counts != MESH_EXPECTED_COUNTS:
        failures.append(
            "expected_counts does not match the exact frozen Mesh topology, "
            "caller, credential, disposition, package, and client URL counts"
        )
    if topology != {
        "route_registrations": MESH_EXPECTED_COUNTS["route_registrations"],
        "router_new_expressions": MESH_EXPECTED_COUNTS["router_new_expressions"],
        "router_merges": MESH_EXPECTED_COUNTS["router_merges"],
        "app_builder_route_mounts": MESH_EXPECTED_COUNTS[
            "app_builder_route_mounts"
        ],
    }:
        failures.append(
            "production Mesh router topology drift: "
            f"found {stable_json(topology)}"
        )
    for source, method in forbidden_router_uses:
        failures.append(
            f"production Mesh router uses unsupported .{method}(...) in {source}"
        )
    if len(registrations) != MESH_EXPECTED_REGISTRATIONS:
        failures.append(
            f"{MESH_SERVER_REL} has {len(registrations)} production route registrations, "
            f"expected {MESH_EXPECTED_REGISTRATIONS}"
        )
    if operation_count != MESH_EXPECTED_OPERATIONS:
        failures.append(
            f"{MESH_SERVER_REL} has {operation_count} production method/path operations, "
            f"expected {MESH_EXPECTED_OPERATIONS}"
        )

    caller_classes = inventory.get("caller_classes")
    credential_classes = inventory.get("credential_classes")
    if not isinstance(caller_classes, dict) or not caller_classes:
        failures.append("caller_classes must be a non-empty object")
        caller_classes = {}
    elif set(caller_classes) != MESH_CALLER_CLASSES:
        failures.append(
            "caller_classes must classify exactly browser, ci-smoke, Go SDK, "
            "node runtime, Python SDK, Rust CLI, Rust client, Rust Tailnet, "
            "and TypeScript SDK"
        )
    if not isinstance(credential_classes, dict) or not credential_classes:
        failures.append("credential_classes must be a non-empty object")
        credential_classes = {}

    inventory_routes = inventory.get("routes")
    if not isinstance(inventory_routes, list):
        failures.append("routes must be a list")
        inventory_routes = []

    inventory_core: list[dict[str, Any]] = []
    inventoried_operation_count = 0
    caller_operation_references: Counter[str] = Counter(
        {caller: 0 for caller in MESH_CALLER_CLASSES}
    )
    credential_operations: Counter[str] = Counter(
        {credential: 0 for credential in credential_classes}
    )
    disposition_operations: Counter[str] = Counter()
    package_operations: Counter[str] = Counter()
    operations_without_callers = 0
    for route_index, route in enumerate(inventory_routes):
        label = f"routes[{route_index}]"
        if not isinstance(route, dict):
            failures.append(f"{label} must be an object")
            continue
        operations = route.get("operations")
        if not isinstance(operations, list) or not operations:
            failures.append(f"{label}.operations must be a non-empty list")
            operations = []
        inventoried_operation_count += len(operations)
        core_operations: list[dict[str, str]] = []
        seen_methods: set[str] = set()
        for operation_index, operation in enumerate(operations):
            operation_label = f"{label}.operations[{operation_index}]"
            if not isinstance(operation, dict):
                failures.append(f"{operation_label} must be an object")
                continue
            method = operation.get("method")
            handler = operation.get("handler")
            credential = operation.get("credential")
            callers = operation.get("callers")
            disposition = operation.get("disposition")
            package = operation.get("package")
            if not isinstance(method, str) or method.lower() not in MESH_HTTP_METHODS:
                failures.append(f"{operation_label} has invalid method {method!r}")
            elif method in seen_methods:
                failures.append(f"{operation_label} duplicates method {method}")
            else:
                seen_methods.add(method)
            if not isinstance(handler, str) or not handler:
                failures.append(f"{operation_label} is missing handler")
            if credential not in credential_classes:
                failures.append(
                    f"{operation_label} has unclassified credential {credential!r}"
                )
            if not isinstance(callers, list):
                failures.append(f"{operation_label}.callers must be a list")
                callers = []
            elif len(callers) != len(set(callers)):
                failures.append(f"{operation_label}.callers contains a duplicate")
            if not callers:
                operations_without_callers += 1
            for caller in callers:
                if caller not in caller_classes:
                    failures.append(
                        f"{operation_label} has unclassified caller {caller!r}"
                    )
                elif isinstance(caller, str):
                    caller_operation_references[caller] += 1
            if isinstance(credential, str):
                credential_operations[credential] += 1
            if isinstance(disposition, str):
                disposition_operations[disposition] += 1
            package_operations[package if isinstance(package, str) else "none"] += 1
            if disposition not in {"connect", "delete"}:
                failures.append(
                    f"{operation_label} is missing disposition 'connect' or 'delete'"
                )
            if disposition == "connect" and package not in {
                "codewire.v1",
                "codewire.internal.v1",
            }:
                failures.append(
                    f"{operation_label} Connect disposition has invalid package {package!r}"
                )
            if disposition == "delete" and package is not None:
                failures.append(
                    f"{operation_label} delete disposition must use a null package"
                )
            if isinstance(method, str) and isinstance(handler, str):
                core_operations.append(
                    {"method": method.lower(), "handler": handler}
                )
        inventory_core.append(
            {
                "scope": route.get("scope"),
                "path": route.get("path"),
                "operations": core_operations,
            }
        )

    if len(inventory_routes) != MESH_EXPECTED_REGISTRATIONS:
        failures.append(
            f"inventory has {len(inventory_routes)} route registrations, "
            f"expected {MESH_EXPECTED_REGISTRATIONS}"
        )
    if inventoried_operation_count != MESH_EXPECTED_OPERATIONS:
        failures.append(
            f"inventory has {inventoried_operation_count} method/path operations, "
            f"expected {MESH_EXPECTED_OPERATIONS}"
        )
    if inventory_core != registrations:
        failures.append(
            "production route inventory drift: extracted scope/path/method/handler "
            f"does not match {MESH_SURFACE_REL} mesh_surface.routes"
        )

    actual_templates = mesh_client_url_templates(client_sources)
    expected_templates = inventory.get("client_url_templates")
    if not isinstance(expected_templates, list):
        failures.append("client_url_templates must be a list")
        expected_templates = []
    for index, item in enumerate(expected_templates):
        if not isinstance(item, dict):
            failures.append(f"client_url_templates[{index}] must be an object")
        elif item.get("caller") not in caller_classes:
            failures.append(
                f"client_url_templates[{index}] has unclassified caller "
                f"{item.get('caller')!r}"
            )
    if expected_templates != actual_templates:
        expected_keys = {stable_json(item) for item in expected_templates}
        actual_keys = {stable_json(item) for item in actual_templates}
        for item in actual_templates:
            if stable_json(item) not in expected_keys:
                failures.append(
                    "unclassified hand-written client URL construction: "
                    f"{item['source']} ({item['caller']}), "
                    f"{item['count']} × {item['template']!r}"
                )
        for item in expected_templates:
            if stable_json(item) not in actual_keys:
                failures.append(
                    "stale hand-written client URL inventory: "
                    f"{item.get('source')} ({item.get('caller')}), "
                    f"{item.get('count')} × {item.get('template')!r}"
                )

    actual_semantic_counts = {
        "caller_operation_references": dict(sorted(caller_operation_references.items())),
        "credential_operations": dict(sorted(credential_operations.items())),
        "disposition_operations": dict(sorted(disposition_operations.items())),
        "package_operations": dict(sorted(package_operations.items())),
        "operations_without_callers": operations_without_callers,
        "client_url_template_records": len(expected_templates),
        "client_url_template_occurrences": sum(
            item.get("count", 0)
            for item in expected_templates
            if isinstance(item, dict) and isinstance(item.get("count"), int)
        ),
    }
    expected_semantic_counts = {
        key: MESH_EXPECTED_COUNTS[key] for key in actual_semantic_counts
    }
    if actual_semantic_counts != expected_semantic_counts:
        failures.append(
            "Mesh inventory semantic count drift: "
            f"found {stable_json(actual_semantic_counts)}"
        )

    implicit_raw = inventory.get("implicit_raw_routes")
    if implicit_raw != [
        {"method": "GET", "path": "/healthz", "disposition": "permanent-raw"},
        {"method": "GET", "path": "/readyz", "disposition": "permanent-raw"},
    ]:
        failures.append(
            "implicit_raw_routes must contain only GET /healthz and GET /readyz"
        )
    router_source = rust_function_source(server_source, "router_from_state")
    if ".with_health()" not in router_source:
        failures.append(
            f"{MESH_SERVER_REL} router_from_state must retain AppBuilder.with_health()"
        )
    compact_router_source = re.sub(r"\s+", "", sanitize_rust_source(router_source))
    if ".with_routes(public_routes.merge(protected_routes))" not in compact_router_source:
        failures.append(
            f"{MESH_SERVER_REL} router_from_state must mount exactly the frozen "
            "public and protected route trees"
        )
    return failures


def mesh_production_sources() -> dict[str, str]:
    return {
        path.relative_to(ROOT).as_posix(): path.read_text(encoding="utf-8")
        for path in walk_files(ROOT / "crates/codewire-mesh/src")
        if path.suffix == ".rs"
    }


def mesh_router_topology(
    mesh_sources: dict[str, str],
) -> tuple[dict[str, int], list[tuple[str, str]]]:
    topology: Counter[str] = Counter()
    forbidden_uses: list[tuple[str, str]] = []
    for source, raw_text in sorted(mesh_sources.items()):
        text = rust_code_without_literals(sanitize_rust_source(raw_text))
        topology["route_registrations"] += len(
            re.findall(r"\.route\s*\(", text)
        )
        topology["router_new_expressions"] += len(
            re.findall(r"\bRouter(?:\s*::<[^>]+>)?::new\s*\(", text)
        )
        topology["router_merges"] += len(re.findall(r"\.merge\s*\(", text))
        topology["app_builder_route_mounts"] += len(
            re.findall(r"\.with_routes\s*\(", text)
        )
        for method in MESH_FORBIDDEN_ROUTER_METHODS:
            if re.search(rf"\.{re.escape(method)}\s*\(", text):
                forbidden_uses.append((source, method))
    return (
        {
            "route_registrations": topology["route_registrations"],
            "router_new_expressions": topology["router_new_expressions"],
            "router_merges": topology["router_merges"],
            "app_builder_route_mounts": topology["app_builder_route_mounts"],
        },
        forbidden_uses,
    )


def mesh_router_fingerprint(server_source: str) -> str:
    router_source = rust_function_source(server_source, "router_from_state")
    normalized = re.sub(r"\s+", "", sanitize_rust_source(router_source))
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def rust_code_without_literals(text: str) -> str:
    chars = list(text)
    index = 0
    while index < len(text):
        if text[index] in {'"', "'"} or is_raw_string_start(text, index):
            end = skip_token(text, index)
            for cursor in range(index, end):
                if chars[cursor] != "\n":
                    chars[cursor] = " "
            index = end
        else:
            index += 1
    return "".join(chars)


def mesh_route_registrations(source: str) -> list[dict[str, Any]]:
    function = rust_function_source(source, "router_from_state")
    sanitized = sanitize_rust_source(function)
    oidc_start = sanitized.find("if state.config.auth_mode == AuthMode::Oidc")
    protected_start = sanitized.find("let protected_routes = Router::new()")
    if oidc_start == -1 or protected_start == -1 or oidc_start >= protected_start:
        raise RuntimeError(
            f"{MESH_SERVER_REL} router_from_state lost its public/OIDC/protected structure"
        )

    registrations: list[dict[str, Any]] = []
    for match in re.finditer(r"\.route\(", sanitized):
        open_paren = match.end() - 1
        close_paren = matching_delimiter(sanitized, open_paren, "(", ")")
        arguments = sanitized[open_paren + 1 : close_paren]
        path_match = re.match(r'\s*"((?:[^"\\]|\\.)*)"\s*,', arguments)
        if not path_match:
            raise RuntimeError(
                f"{MESH_SERVER_REL} router_from_state has a non-literal .route registration"
            )
        handler_expression = arguments[path_match.end() :]
        operations = [
            {"method": operation.group(1), "handler": operation.group(2)}
            for operation in re.finditer(
                r"\b(delete|get|head|options|patch|post|put)\s*\(\s*"
                r"([A-Za-z_][A-Za-z0-9_]*)",
                handler_expression,
            )
        ]
        if not operations:
            raise RuntimeError(
                f"{MESH_SERVER_REL} route {path_match.group(1)} has no recognized method handler"
            )
        scope = (
            "public"
            if match.start() < oidc_start
            else "oidc"
            if match.start() < protected_start
            else "protected"
        )
        registrations.append(
            {
                "scope": scope,
                "path": path_match.group(1),
                "operations": operations,
            }
        )
    return registrations


def rust_function_source(source: str, name: str) -> str:
    sanitized = sanitize_rust_source(source)
    signature = re.search(rf"\bfn\s+{re.escape(name)}\s*\(", sanitized)
    if not signature:
        raise RuntimeError(f"cannot find Rust function {name}")
    open_brace = sanitized.find("{", signature.end())
    if open_brace == -1:
        raise RuntimeError(f"Rust function {name} has no body")
    close_brace = matching_delimiter(sanitized, open_brace, "{", "}")
    return source[signature.start() : close_brace + 1]


def matching_delimiter(
    text: str,
    open_index: int,
    opener: str,
    closer: str,
) -> int:
    depth = 0
    index = open_index
    while index < len(text):
        char = text[index]
        if char == '"' or char == "'" or is_raw_string_start(text, index):
            index = skip_token(text, index)
            continue
        if char == opener:
            depth += 1
        elif char == closer:
            depth -= 1
            if depth == 0:
                return index
        index += 1
    raise RuntimeError(f"unclosed {opener!r} delimiter")


def mesh_client_sources() -> dict[str, tuple[str, str]]:
    sources: dict[str, tuple[str, str]] = {}
    roots = (
        ROOT / "crates",
        ROOT / "apps",
        ROOT / "libs",
        ROOT / "packages",
        ROOT / "scripts/ci/verify",
        ROOT / "scripts/runtime",
    )
    for root in roots:
        for path in walk_files(root):
            if not is_mesh_client_candidate(path):
                continue
            rel = path.relative_to(ROOT).as_posix()
            if rel.startswith("crates/codewire-mesh/"):
                continue
            sources[rel] = (
                mesh_caller_for_source(rel),
                path.read_text(encoding="utf-8"),
            )
    return sources


def is_mesh_client_candidate(path: Path) -> bool:
    rel = path.relative_to(ROOT)
    if path.suffix not in {
        ".go",
        ".js",
        ".jsx",
        ".py",
        ".rs",
        ".sh",
        ".swift",
        ".ts",
        ".tsx",
    }:
        return False
    if any(part.lower() in {"fixtures", "test", "tests", "testdata"} for part in rel.parts):
        return False
    name = path.name.lower()
    return not (
        name.endswith("_test.go")
        or name.startswith("test_")
        or "_test." in name
        or ".spec." in name
        or ".test." in name
    )


def mesh_caller_for_source(rel: str) -> str:
    classifications = (
        ("crates/codewire-cli/", "rust-cli"),
        ("crates/codewire-tailnet/", "rust-tailnet"),
        ("libs/sdk-go/", "go-sdk"),
        ("libs/sdk-python/", "python-sdk"),
        ("libs/sdk-ts/", "typescript-sdk"),
        ("apps/dashboard/", "browser"),
        ("scripts/ci/verify/", "ci-smoke"),
        ("scripts/runtime/", "ci-smoke"),
    )
    for prefix, caller in classifications:
        if rel.startswith(prefix):
            return caller
    if rel.startswith(
        (
            "crates/codewire-client/",
            "crates/codewire-core/",
            "crates/codewire-desktop/",
            "crates/codewire-platform-native/",
            "crates/codewire-ui/",
            "apps/ios/",
        )
    ):
        return "rust-client"
    if rel.startswith(
        (
            "crates/codewire-coordinator/",
            "crates/codewire-daemon/",
            "crates/codewire-derp/",
            "crates/codewire-gateway/",
            "crates/codewire-orchestration/",
            "crates/codewire-udp-relay/",
        )
    ):
        return "node-runtime"
    return "unclassified"


def mesh_client_url_templates(
    sources: dict[str, tuple[str, str]],
) -> list[dict[str, Any]]:
    counts: Counter[tuple[str, str, str]] = Counter()
    for source, (caller, raw_text) in sources.items():
        if source.endswith(".rs"):
            text = sanitize_rust_source(raw_text)
            string_literals = rust_string_literals(text)
        elif source.endswith((".go", ".js", ".jsx", ".swift", ".ts", ".tsx")):
            text = strip_source_comments(raw_text, c_like=True)
            string_literals = source_string_literals(text)
        elif source.endswith(".py"):
            text = strip_source_comments(raw_text, c_like=False)
            string_literals = source_string_literals(text)
        else:
            text = raw_text
            string_literals = source_string_literals(text)
        for template in string_literals:
            if not is_mesh_client_template(template):
                continue
            counts[(source, caller, template)] += 1
    return [
        {
            "source": source,
            "caller": caller,
            "template": template,
            "count": count,
        }
        for (source, caller, template), count in sorted(counts.items())
    ]


def is_mesh_client_template(template: str) -> bool:
    if template in {"api/v1", "/api/v1"}:
        return True
    if re.search(r"(?:^|/)join(?:$|[/?#])", template):
        return True
    for prefix in MESH_CLIENT_RAW_PATH_PREFIXES:
        match = re.search(
            rf"(?:^|/){re.escape(prefix)}(?:$|[/?#{{])",
            template,
        )
        if match:
            return True
    for marker, trim in (("api/v1/", 0), ("v1/", len("api/"))):
        index = template.find(marker)
        if index == -1:
            continue
        path = template[index:]
        for prefix in MESH_CLIENT_PATH_PREFIXES:
            candidate = prefix[trim:]
            if (
                path == candidate
                or path.startswith(candidate + "/")
                or path.startswith(candidate + "?")
            ):
                return True
    return False


def rust_string_literals(text: str) -> list[str]:
    literals: list[str] = []
    index = 0
    while index < len(text):
        if is_raw_string_start(text, index):
            hashes = 0
            cursor = index + 1
            while cursor < len(text) and text[cursor] == "#":
                hashes += 1
                cursor += 1
            content_start = cursor + 1
            closer = '"' + ("#" * hashes)
            end = text.find(closer, content_start)
            if end == -1:
                break
            literals.append(text[content_start:end])
            index = end + len(closer)
        elif text[index] == '"':
            cursor = index + 1
            while cursor < len(text):
                if text[cursor] == "\\":
                    cursor += 2
                elif text[cursor] == '"':
                    literals.append(text[index + 1 : cursor])
                    index = cursor + 1
                    break
                else:
                    cursor += 1
            else:
                break
        else:
            index += 1
    return literals


def source_string_literals(text: str) -> list[str]:
    literals: list[str] = []
    index = 0
    while index < len(text):
        match = re.search(r"(?:[furbFURB]{0,2})([\"'`])", text[index:])
        if not match:
            break
        quote = match.group(1)
        start = index + match.end()
        cursor = start
        while cursor < len(text):
            if text[cursor] == "\\":
                cursor += 2
                continue
            if text[cursor] == quote:
                literals.append(text[start:cursor])
                index = cursor + 1
                break
            cursor += 1
        else:
            break
    return literals


def strip_source_comments(text: str, *, c_like: bool) -> str:
    chars = list(text)
    index = 0
    while index < len(text):
        if c_like and text[index : index + 2] == "//":
            end = text.find("\n", index)
            end = len(text) if end == -1 else end
            for cursor in range(index, end):
                chars[cursor] = " "
            index = end
            continue
        if c_like and text[index : index + 2] == "/*":
            end = text.find("*/", index + 2)
            end = len(text) if end == -1 else end + 2
            for cursor in range(index, end):
                if chars[cursor] != "\n":
                    chars[cursor] = " "
            index = end
            continue
        if not c_like and text[index] == "#":
            end = text.find("\n", index)
            end = len(text) if end == -1 else end
            for cursor in range(index, end):
                chars[cursor] = " "
            index = end
            continue
        if text[index] in {'"', "'", "`"}:
            quote = text[index]
            index += 1
            while index < len(text):
                if text[index] == "\\":
                    index += 2
                elif text[index] == quote:
                    index += 1
                    break
                else:
                    index += 1
            continue
        index += 1
    return "".join(chars)


def mesh_surface_self_test(
    mesh_sources: dict[str, str],
    client_sources: dict[str, tuple[str, str]],
    inventory: dict[str, Any],
) -> None:
    server_source = mesh_sources[MESH_SERVER_REL]

    helper_route_sources = copy.deepcopy(mesh_sources)
    helper_route_sources[MESH_SERVER_REL] = server_source.replace(
        ".with_routes(public_routes.merge(protected_routes))",
        ".with_routes(\n"
        "            public_routes\n"
        "                .merge(protected_routes)\n"
        "                .merge(extra_mesh_routes()),\n"
        "        )",
        1,
    )
    helper_route_sources["crates/codewire-mesh/src/extra_routes.rs"] = (
        "fn extra_mesh_routes() -> Router {\n"
        '    Router::new().route("/api/v1/new-mesh-route", get(new_mesh_route))\n'
        "}\n"
    )
    helper_route_failures = mesh_surface_failures(
        helper_route_sources,
        client_sources,
        copy.deepcopy(inventory),
    )
    if not any(
        "router topology drift" in failure for failure in helper_route_failures
    ):
        raise RuntimeError("self-test accepted a helper-mounted Mesh route")

    alternate_router_sources = copy.deepcopy(mesh_sources)
    alternate_router_source = server_source.replace(
        '.route("/api/v1/tailnet/coordinate", get(tailnet_coordinate))',
        '.route_service("/api/v1/new-service", get(new_mesh_service))\n'
        "        .route(\n"
        '            "/api/v1/tailnet/coordinate",\n'
        "            get(tailnet_coordinate)\n"
        "                .on(MethodFilter::POST, new_handler)\n"
        "                .post_service(new_service),\n"
        "        )",
        1,
    )
    alternate_router_sources[MESH_SERVER_REL] = alternate_router_source.replace(
        ".with_health()",
        ".with_health()\n"
        "        .with_connect_routes(mesh_connect_router())",
        1,
    )
    alternate_router_failures = mesh_surface_failures(
        alternate_router_sources,
        client_sources,
        copy.deepcopy(inventory),
    )
    for method in ("on", "post_service", "route_service", "with_connect_routes"):
        if not any(
            f"unsupported .{method}" in failure
            for failure in alternate_router_failures
        ):
            raise RuntimeError(
                f"self-test accepted alternate Mesh router method .{method}"
            )

    new_client_sources = copy.deepcopy(client_sources)
    caller, cli_source = new_client_sources["crates/codewire-cli/src/mesh.rs"]
    new_client_sources["crates/codewire-cli/src/mesh.rs"] = (
        caller,
        cli_source.replace(
            "impl MeshClient {",
            'const UNCLASSIFIED_MESH_URL: &str = "api/v1/networks/unclassified-client";\n\n'
            "impl MeshClient {",
            1,
        ),
    )
    new_client_failures = mesh_surface_failures(
        mesh_sources,
        new_client_sources,
        copy.deepcopy(inventory),
    )
    if not any(
        "unclassified hand-written client URL construction" in failure
        for failure in new_client_failures
    ):
        raise RuntimeError("self-test accepted a new hand-written Mesh client URL")

    raw_client_sources = copy.deepcopy(client_sources)
    caller, client_source = raw_client_sources["crates/codewire-client/src/lib.rs"]
    raw_client_sources["crates/codewire-client/src/lib.rs"] = (
        caller,
        client_source + '\nconst UNCLASSIFIED_SESSION_URL: &str = "auth/session";\n',
    )
    raw_client_failures = mesh_surface_failures(
        mesh_sources,
        raw_client_sources,
        copy.deepcopy(inventory),
    )
    if not any(
        "unclassified hand-written client URL construction" in failure
        for failure in raw_client_failures
    ):
        raise RuntimeError("self-test accepted a non-/api Mesh client URL")

    split_client_sources = copy.deepcopy(client_sources)
    caller, client_source = split_client_sources["crates/codewire-client/src/lib.rs"]
    split_client_sources["crates/codewire-client/src/lib.rs"] = (
        caller,
        client_source
        + '\nconst CONCAT_MESH_URL: &str = concat!("api/v1", "/networks/new");\n'
        + 'fn format_mesh_url() -> String { format!("{}/networks/new", "api/v1") }\n'
        + 'fn joined_mesh_url() -> String { "/api/".to_owned() + "v1/networks/new" }\n',
    )
    split_records = mesh_client_url_templates(
        {"crates/codewire-client/src/lib.rs": split_client_sources[
            "crates/codewire-client/src/lib.rs"
        ]}
    )
    split_counts = Counter(
        {
            item["template"]: item["count"]
            for item in split_records
        }
    )
    if split_counts["api/v1"] != 2 or split_counts["v1/networks/new"] != 1:
        raise RuntimeError("self-test did not classify all split Mesh URL forms")
    split_client_failures = mesh_surface_failures(
        mesh_sources,
        split_client_sources,
        copy.deepcopy(inventory),
    )
    if not any(
        "unclassified hand-written client URL construction" in failure
        for failure in split_client_failures
    ):
        raise RuntimeError("self-test accepted a split Mesh client URL")

    unclassified_source = "crates/codewire-billing/src/lib.rs"
    if client_sources.get(unclassified_source, (None,))[0] != "unclassified":
        raise RuntimeError("self-test lost repo-wide client source discovery")
    unclassified_client_sources = copy.deepcopy(client_sources)
    caller, source = unclassified_client_sources[unclassified_source]
    unclassified_client_sources[unclassified_source] = (
        caller,
        source + '\nconst MISPLACED_MESH_URL: &str = "api/v1/networks/new";\n',
    )
    unclassified_source_failures = mesh_surface_failures(
        mesh_sources,
        unclassified_client_sources,
        copy.deepcopy(inventory),
    )
    if not any(
        "unclassified hand-written client URL construction" in failure
        for failure in unclassified_source_failures
    ):
        raise RuntimeError("self-test accepted a Mesh URL in an unknown source root")

    missing_disposition = copy.deepcopy(inventory)
    missing_disposition["routes"][0]["operations"][0].pop("disposition", None)
    disposition_failures = mesh_surface_failures(
        mesh_sources,
        client_sources,
        missing_disposition,
    )
    if not any("missing disposition" in failure for failure in disposition_failures):
        raise RuntimeError("self-test accepted an operation without a disposition")

    reclassified = copy.deepcopy(inventory)
    reclassified_operation = reclassified["routes"][0]["operations"][0]
    reclassified_operation["credential"] = "mesh-identity"
    reclassified_operation["callers"] = ["browser"]
    reclassified_failures = mesh_surface_failures(
        mesh_sources,
        client_sources,
        reclassified,
    )
    if not any(
        "semantic count drift" in failure for failure in reclassified_failures
    ):
        raise RuntimeError("self-test accepted Mesh credential/caller reclassification")


# ---------------------------------------------------------------------------
# Package license policy


def check_license_map(_args: argparse.Namespace) -> int:
    failures: list[str] = []

    canonical_licenses = {
        "AGPL-3.0-only": (
            "LICENSE",
            "0d96a4ff68ad6d4b6f1f30f713b18d5184912ba8dd389f86aa7710db079abcb0",
        ),
        "MIT": (
            "LICENSE-MIT",
            "9d7d7be3a6331ef710cf4747b47584de9cad5fb2cbd135f5c455039eb414c97f",
        ),
        "Apache-2.0": (
            "LICENSE-APACHE",
            "f31c91d1278c0590110d023f34ecc5825ec897dd3aa4693cc374fd6c4b86914d",
        ),
        "BSD-3-Clause": (
            "LICENSE-BSD-3-CLAUSE",
            "1dba73130cc42806fcd2a72bc3452bcb72e82d525fcad1cc80af795b880302ba",
        ),
    }

    def toml(rel: str) -> dict[str, Any]:
        with (ROOT / rel).open("rb") as handle:
            return tomllib.load(handle)

    def check_copy(rel: str, license_name: str) -> None:
        canonical_rel = canonical_licenses[license_name][0]
        path = ROOT / rel
        if not path.is_file():
            failures.append(f"{rel}: missing packaged {license_name} text")
            return
        if path.read_bytes() != (ROOT / canonical_rel).read_bytes():
            failures.append(f"{rel}: differs from canonical {canonical_rel}")

    for license_name, (rel, expected_sha256) in canonical_licenses.items():
        path = ROOT / rel
        if not path.is_file():
            failures.append(f"{rel}: missing canonical {license_name} text")
            continue
        actual_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual_sha256 != expected_sha256:
            failures.append(
                f"{rel}: canonical {license_name} text hash {actual_sha256}, "
                f"expected {expected_sha256}"
            )

    root_manifest = toml("Cargo.toml")
    workspace_license = root_manifest.get("workspace", {}).get("package", {}).get("license")
    if workspace_license != "AGPL-3.0-only":
        failures.append(
            f"Cargo.toml: workspace license {workspace_license!r}, expected 'AGPL-3.0-only'"
        )

    cargo_declarations = {
        "crates/codewire-api-contract/Cargo.toml": "AGPL-3.0-only",
        "crates/codewire-api-types/Cargo.toml": "MIT",
        "crates/codewire-billing/Cargo.toml": "AGPL-3.0-only",
        "crates/codewire-cli-bin/Cargo.toml": "workspace",
        "crates/codewire-cli/Cargo.toml": "workspace",
        "crates/codewire-client/Cargo.toml": "AGPL-3.0-only",
        "crates/codewire-coordinator/Cargo.toml": "AGPL-3.0-only",
        "crates/codewire-core/Cargo.toml": "MIT",
        "crates/codewire-daemon/Cargo.toml": "AGPL-3.0-only",
        "crates/codewire-derp/Cargo.toml": "BSD-3-Clause",
        "crates/codewire-desktop/Cargo.toml": "MIT",
        "crates/codewire-gateway-proto/Cargo.toml": "AGPL-3.0-only",
        "crates/codewire-gateway/Cargo.toml": "AGPL-3.0-only",
        "crates/codewire-idp/Cargo.toml": "AGPL-3.0-only",
        "crates/codewire-mesh/Cargo.toml": "AGPL-3.0-only",
        "crates/codewire-network-auth/Cargo.toml": "workspace",
        "crates/codewire-oidc/Cargo.toml": "MIT OR Apache-2.0",
        "crates/codewire-orchestration/Cargo.toml": "AGPL-3.0-only",
        "crates/codewire-platform-native/Cargo.toml": "MIT",
        "crates/codewire-proto/Cargo.toml": "AGPL-3.0-only",
        "crates/codewire-server-core/Cargo.toml": "AGPL-3.0-only",
        "crates/codewire-tailnet/Cargo.toml": "BSD-3-Clause",
        "crates/codewire-types/Cargo.toml": "MIT",
        "crates/codewire-udp-relay/Cargo.toml": "AGPL-3.0-only",
        "crates/codewire-ui/Cargo.toml": "MIT",
    }
    actual_cargo_manifests = {
        path.relative_to(ROOT).as_posix()
        for path in (ROOT / "crates").glob("*/Cargo.toml")
    }
    if actual_cargo_manifests != set(cargo_declarations):
        failures.append(
            "Cargo package inventory differs from the accepted license map: "
            f"missing={sorted(set(cargo_declarations) - actual_cargo_manifests)}, "
            f"unclassified={sorted(actual_cargo_manifests - set(cargo_declarations))}"
        )

    for rel, declaration in cargo_declarations.items():
        package = toml(rel).get("package", {})
        actual = package.get("license")
        expected = {"workspace": True} if declaration == "workspace" else declaration
        if actual != expected:
            failures.append(f"{rel}: license declaration {actual!r}, expected {expected!r}")
        effective = "AGPL-3.0-only" if declaration == "workspace" else declaration
        crate_dir = Path(rel).parent
        if effective == "MIT OR Apache-2.0":
            check_copy((crate_dir / "LICENSE-MIT").as_posix(), "MIT")
            check_copy((crate_dir / "LICENSE-APACHE").as_posix(), "Apache-2.0")
        else:
            check_copy((crate_dir / "LICENSE").as_posix(), effective)

    docker_workspace_licenses = {
        "deployments/docker/gateway.Cargo.toml": "AGPL-3.0-only",
        "deployments/docker/derp.Cargo.toml": "BSD-3-Clause",
    }
    for rel, expected in docker_workspace_licenses.items():
        actual = toml(rel).get("workspace", {}).get("package", {}).get("license")
        if actual != expected:
            failures.append(f"{rel}: workspace license {actual!r}, expected {expected!r}")

    npm_licenses = {
        "package.json": "AGPL-3.0-only",
        "apps/dashboard/package.json": "AGPL-3.0-only",
        "apps/docs/package.json": "AGPL-3.0-only",
        "libs/api-client-ts/package.json": "MIT",
        "libs/sdk-examples/run-claude/typescript/package.json": "MIT",
        "libs/sdk-ts/package.json": "MIT",
        "packages/auth/package.json": "MIT",
        "packages/codewire-proto-ts/package.json": "MIT",
        "packages/codewire-types/package.json": "MIT",
    }
    actual_package_json = {
        rel
        for rel in git_source_files()
        if rel == "package.json" or rel.endswith("/package.json")
    }
    if actual_package_json != set(npm_licenses):
        failures.append(
            "npm package inventory differs from the accepted license map: "
            f"missing={sorted(set(npm_licenses) - actual_package_json)}, "
            f"unclassified={sorted(actual_package_json - set(npm_licenses))}"
        )
    for rel, expected in npm_licenses.items():
        actual = read_json(rel).get("license")
        if actual != expected:
            failures.append(f"{rel}: license {actual!r}, expected {expected!r}")
        if rel == "package.json":
            check_copy("LICENSE", expected)
        else:
            check_copy((Path(rel).parent / "LICENSE").as_posix(), expected)

    python_licenses = {
        "libs/api-client-python/pyproject.toml": ("MIT", ["LICENSE"]),
        "libs/sdk-python/pyproject.toml": (
            "MIT",
            ["LICENSE", "LICENSE-APACHE"],
        ),
    }
    actual_pyprojects = {
        rel for rel in git_source_files() if rel.endswith("pyproject.toml")
    }
    if actual_pyprojects != set(python_licenses):
        failures.append(
            "Python package inventory differs from the accepted license map: "
            f"missing={sorted(set(python_licenses) - actual_pyprojects)}, "
            f"unclassified={sorted(actual_pyprojects - set(python_licenses))}"
        )
    for rel, (expected, expected_files) in python_licenses.items():
        project = toml(rel).get("project", {})
        if project.get("license") != expected:
            failures.append(
                f"{rel}: license {project.get('license')!r}, expected {expected!r}"
            )
        if project.get("license-files") != expected_files:
            failures.append(
                f"{rel}: license-files {project.get('license-files')!r}, "
                f"expected {expected_files!r}"
            )
        package_dir = Path(rel).parent
        check_copy((package_dir / "LICENSE").as_posix(), expected)
        if "LICENSE-APACHE" in expected_files:
            check_copy(
                (package_dir / "LICENSE-APACHE").as_posix(),
                "Apache-2.0",
            )

    go_licenses = {
        "libs/api-client-go/go.mod": "MIT",
        "libs/gen-go/go.mod": "MIT",
        "libs/sdk-examples/run-claude/go/go.mod": "MIT",
        "libs/sdk-go/go.mod": "MIT",
        "libs/tailnet/go.mod": "BSD-3-Clause",
        "tests/contract/go.mod": "AGPL-3.0-only",
    }
    actual_go_modules = {rel for rel in git_source_files() if rel.endswith("go.mod")}
    if actual_go_modules != set(go_licenses):
        failures.append(
            "Go module inventory differs from the accepted license map: "
            f"missing={sorted(set(go_licenses) - actual_go_modules)}, "
            f"unclassified={sorted(actual_go_modules - set(go_licenses))}"
        )
    for rel, expected in go_licenses.items():
        check_copy((Path(rel).parent / "LICENSE").as_posix(), expected)

    apache_copies = [
        "crates/codewire-proto/LICENSE-APACHE",
        "libs/gen-go/LICENSE-APACHE",
        "libs/gen-python/LICENSE-APACHE",
        "libs/sdk-python/LICENSE-APACHE",
        "packages/codewire-proto-ts/LICENSE-APACHE",
        "proto/LICENSE-APACHE",
    ]
    for rel in apache_copies:
        check_copy(rel, "Apache-2.0")

    claims = {
        "README.md": [
            "Open source under AGPL-3.0-only.",
            "Codewire is licensed under AGPL-3.0-only.",
        ],
        "crates/README.md": [
            "The root workspace default is **AGPL-3.0-only**.",
            "a combined distribution must therefore satisfy the",
            "AGPL-3.0-only obligations for the combined work.",
        ],
        "apps/cli/nfpm.yaml": ["license: AGPL-3.0-only"],
        "apps/cli/aur/PKGBUILD": ["license=('AGPL-3.0-only')"],
        "aur/PKGBUILD": ["license=('MIT')"],
    }
    for rel, expected_fragments in claims.items():
        text = read_text(rel)
        for fragment in expected_fragments:
            if fragment not in text:
                failures.append(f"{rel}: missing accepted license claim {fragment!r}")
    check_copy("apps/cli/LICENSE", "AGPL-3.0-only")

    if failures:
        for failure in failures:
            print(f"license map: {failure}", file=sys.stderr)
        return 1
    print(
        "license map: OK "
        f"({len(cargo_declarations)} Cargo packages, "
        f"{len(npm_licenses)} npm packages, "
        f"{len(python_licenses)} Python packages, "
        f"{len(go_licenses)} Go modules)"
    )
    return 0


# ---------------------------------------------------------------------------
# Source-retirement and validation guards


def check_rust_validation_source(_args: argparse.Namespace) -> int:
    failures: list[str] = []
    allowed_raw_body_extractors: dict[str, dict[str, Any]] = {}
    raw_json_body_extractor = re.compile(
        r"Json\s*\(\s*[^)]*\)\s*:\s*Json\s*<\s*(?:serde_json::)?Value\s*>"
    )
    matches_by_file: dict[str, list[tuple[int, str]]] = {}

    for file in walk_files(ROOT / "crates"):
        if file.suffix != ".rs":
            continue
        rel = file.relative_to(ROOT).as_posix()
        text = file.read_text(encoding="utf-8")
        for match in raw_json_body_extractor.finditer(text):
            line = line_number(text, match.start())
            source = text.splitlines()[line - 1].strip() if line - 1 < len(text.splitlines()) else ""
            matches_by_file.setdefault(rel, []).append((line, source))

    for file, matches in matches_by_file.items():
        allowed = allowed_raw_body_extractors.get(file)
        if not allowed:
            for line, _source in matches:
                failures.append(
                    f"rust validation source: {file}:{line} uses raw Json<serde_json::Value> "
                    "request extraction; use ValidatedJson<T>"
                )
            continue
        if len(matches) != allowed["expected"]:
            failures.append(
                f"rust validation source: {file} has {len(matches)} raw JSON request extractors, "
                f"expected {allowed['expected']} ({allowed['reason']})"
            )

    for file, allowed in allowed_raw_body_extractors.items():
        if file not in matches_by_file and allowed["expected"] > 0:
            failures.append(
                f"rust validation source: {file} has no raw JSON request extractors, "
                f"expected {allowed['expected']} ({allowed['reason']}); update the #60 allowlist"
            )

    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        return 1
    print("rust validation source: OK")
    return 0


def check_retired_reference_source(_args: argparse.Namespace) -> int:
    retired_coder_pattern = re.compile(r"(?<![A-Za-z])coder(?![A-Za-z])", re.IGNORECASE)
    allowed: list[dict[str, Any]] = [
        {
            "path": "docs/dev/GO-RUST-RETIREMENT-LEDGER.md",
            "line": re.compile(
                r"(?:legacy|retired) Coder-reference classification|"
                r"(?:Legacy|Retired) Coder/product-integration references|"
                r"remaining `coder` strings|github\.com/coder/websocket|"
                r"unclassified Coder(?:/resource)? references|"
                r"`coder` strings outside immutable migration history",
                re.IGNORECASE,
            ),
            "reason": "canonical #48 classification for remaining retired references",
        },
    ]
    for path in [
        "libs/tailnet/go.mod",
        "libs/tailnet/go.sum",
        "tests/contract/go.mod",
        "tests/contract/go.sum",
    ]:
        allowed.append(
            {
                "path": path,
                "line": re.compile(r"github\.com/coder/websocket"),
                "reason": "known third-party module debt; not a Coder product integration",
            }
        )

    def is_allowed(path: str, line: str, kind: str) -> bool:
        for entry in allowed:
            if entry["path"] != path:
                continue
            if kind == "path":
                return entry.get("path_only") is True
            pattern = entry.get("line")
            if pattern is not None and pattern.search(line):
                return True
        return False

    findings: list[str] = []
    self_path = Path(__file__).relative_to(ROOT).as_posix()
    for rel in git_source_files():
        if rel == self_path or rel == ".git" or rel.startswith(".git/"):
            continue
        path = ROOT / rel
        if not path.exists():
            continue
        if retired_coder_pattern.search(rel) and not is_allowed(rel, "", "path"):
            findings.append(f"{rel}: path contains unclassified retired Coder wording")
        data = path.read_bytes()
        if b"\0" in data:
            continue
        text = data.decode("utf-8", errors="replace")
        for index, line in enumerate(text.split("\n"), start=1):
            if retired_coder_pattern.search(line) and not is_allowed(rel, line, "line"):
                findings.append(f"{rel}:{index}: {line.strip()}")

    if findings:
        print("retired reference guard: unclassified Coder references found", file=sys.stderr)
        for finding in findings:
            print(f"  {finding}", file=sys.stderr)
        print(
            "Either remove the reference or classify it in "
            "scripts/checks/repo_checks.py for #48.",
            file=sys.stderr,
        )
        return 1
    print("retired reference guard: OK")
    return 0


def check_go_source_classification(_args: argparse.Namespace) -> int:
    retired_runtime_paths = [
        "apps/api",
        "autoagent",
        "apps/cli/go.mod",
        "apps/cli/cmd/cw",
        "apps/cli/cmd/codewire-relay",
        "apps/cli/cwshell",
        "apps/cli/demo/broker",
        "apps/cli/internal",
        "apps/cli/internal/relay",
        "libs/gateway-proto/buf.gen.yaml",
        "libs/gateway-proto/gen",
        "libs/gateway-proto/go.mod",
        "libs/gateway-proto/go.sum",
        "libs/gatewayauth",
        "tests/contract/billing",
        "tests/contract/connectcore",
        "tests/contract/coordinator",
        "tests/contract/file",
        "tests/contract/orchestration",
    ]
    categories: list[tuple[str, re.Pattern[str]]] = [
        (
            "Tailscale Go-client DERP interoperability",
            re.compile(r"^tests/contract/derp/.*\.go$"),
        ),
        ("bounded Go Tailnet oracle", re.compile(r"^libs/tailnet/.*\.go$")),
        (
            "generated Go API consumers",
            re.compile(r"^(libs/api-client-go|libs/gen-go)/.*\.go$"),
        ),
        (
            "public Go SDK and examples",
            re.compile(r"^(libs/sdk-go|libs/sdk-examples/run-claude/go)/.*\.go$"),
        ),
    ]
    allowed_package_main = {"libs/sdk-examples/run-claude/go/main.go"}
    findings: list[str] = []
    counts = {name: 0 for name, _pattern in categories}

    for rel in retired_runtime_paths:
        if (ROOT / rel).exists():
            findings.append(f"{rel}: retired Go runtime/source path must not exist")

    for rel in [
        path
        for path in git_source_files()
        if path.endswith(".go") and (ROOT / path).is_file()
    ]:
        category = next((item for item in categories if item[1].search(rel)), None)
        if category is None:
            findings.append(f"{rel}: unclassified Go source; update #45 and this guard or delete it")
            continue
        counts[category[0]] += 1
        package = package_name(rel)
        if package == "main" and rel not in allowed_package_main:
            findings.append(f"{rel}: package main is not allowed outside accepted SDK examples")

    if findings:
        print("Go source classification guard: unaccepted Go source found", file=sys.stderr)
        for finding in findings:
            print(f"  {finding}", file=sys.stderr)
        print(
            "Remaining Go must be accepted support/test/generated/oracle/SDK surface in "
            "docs/dev/GO-RUST-RETIREMENT-LEDGER.md.",
            file=sys.stderr,
        )
        return 1
    print("Go source classification guard: OK")
    for name, count in counts.items():
        print(f"  {name}: {count}")
    return 0


def package_name(rel: str) -> str:
    text = read_text(rel)
    match = re.search(r"^\s*package\s+([A-Za-z_][A-Za-z0-9_]*)\b", text, re.MULTILINE)
    return match.group(1) if match else ""


# ---------------------------------------------------------------------------
# Connect edge routing


def check_connect_edge_routing(_args: argparse.Namespace) -> int:
    caddy_files = ["Caddyfile", "Caddyfile.docker"]
    prod_ingress_files = ["deployments/k8s/base/ingress.yaml"]
    local_ingress_files = [
        "deployments/k8s/overlays/local-kind/ingress.yaml",
        "deployments/k8s/overlays/local-kind-static/ingress.yaml",
        "tests/e2e/kind/ingress.yaml",
    ]
    all_files = caddy_files + prod_ingress_files + local_ingress_files
    failures: list[str] = []
    fail = failures.append

    services: set[str] = set()
    for directory in ["proto/codewire", "proto/coordinator"]:
        for file in sorted((ROOT / directory).rglob("*.proto")):
            services.update(services_in_proto(file))

    ownership = read_json("scripts/checks/contracts/connect-edge-ownership.json")
    owners = ownership.get("owners") or {}
    explicit = set(ownership.get("explicit") or [])
    pending = ownership.get("pending") or {}
    unrouted = ownership.get("unrouted") or {}

    for service in sorted(services):
        classifications = sum(service in group for group in (owners, pending, unrouted))
        if classifications == 0:
            fail(
                f"proto service {service} is neither owned, pending, nor unrouted — add it to "
                "scripts/checks/contracts/connect-edge-ownership.json"
            )
        elif classifications > 1:
            fail(f"service {service} has more than one ownership classification — pick one")
    for service in sorted(set(owners) | set(pending) | set(unrouted)):
        if service not in services:
            fail(f"stale ownership entry {service}: no such service under proto/")
    for service in sorted(explicit):
        if service not in owners:
            fail(f"explicit edge entry {service} has no owner")

    per_file = {rel: connect_rules(rel, fail) for rel in all_files}

    for file, data in per_file.items():
        if not data["fallback"]:
            fail(f"{file}: missing the /codewire. -> orchestration Connect fallback rule")

    for file in prod_ingress_files + local_ingress_files:
        assert_connect_streaming_ingress_shape(file, fail)

    for service, owner in owners.items():
        for file, data in per_file.items():
            here = [rule for rule in data["rules"] if rule["service"] == service]
            if owner == "billing":
                if not any(rule["backend"] == "billing" for rule in here):
                    fail(f"{file}: billing-owned {service} has no billing-targeted Connect rule")
                if any(rule["backend"] == "orchestration" for rule in here):
                    fail(f"{file}: billing-owned {service} appears in an orchestration-targeted rule")
            elif owner == "orchestration":
                if service in explicit and not any(
                    rule["backend"] == "orchestration" for rule in here
                ):
                    fail(f"{file}: explicitly routed {service} has no orchestration-targeted rule")
                for rule in here:
                    if rule["backend"] != "orchestration":
                        fail(f"{file}: orchestration-owned {service} routed to {rule['backend']}")
            elif owner == "coordinator":
                if not any(rule["backend"] == "coordinator" for rule in here):
                    fail(f"{file}: coordinator-owned {service} has no coordinator-targeted Connect rule")
                if any(rule["backend"] != "coordinator" for rule in here):
                    fail(f"{file}: coordinator-owned {service} is also routed to another binary")
            elif owner == "testing":
                is_local = file in local_ingress_files
                if is_local:
                    if not any(rule["backend"] == "billing" for rule in here):
                        fail(
                            f"{file}: the D8 probe needs its billing routing-proof rule "
                            f"({service} -> codewire-billing) in kind/local manifests"
                        )
                elif here:
                    fail(f"{file}: the D8 testing probe must not be routed outside kind/local manifests")
            else:
                fail(f"unknown owner kind '{owner}' for {service} in connect-edge-ownership.json")

    assert_internal_connect_listener_exemption(unrouted, per_file, fail)
    if getattr(_args, "self_test", False):
        try:
            internal_connect_listener_self_test()
        except RuntimeError as error:
            fail(f"internal-connect listener self-test: {error}")

    for file in all_files:
        assert_coordinator_transport_shape(file, fail)
        assert_environment_session_transport_shape(file, fail)
    assert_native_grpc_opt_in_sites(fail)
    assert_rendered_dev_ingress_identities(fail)

    for service in pending.keys():
        for file, data in per_file.items():
            if any(rule["service"] == service for rule in data["rules"]):
                fail(
                    f"{file}: {service} is routed but still on the pending allowlist — "
                    "remove it from 'pending' in scripts/checks/contracts/connect-edge-ownership.json"
                )

    if failures:
        for failure in failures:
            print(f"::error::connect edge routing: {failure}", file=sys.stderr)
        return 1
    print(
        f"connect edge routing: OK ({len(services)} proto service(s): "
        f"{', '.join(sorted(services))}; {len(pending)} pending; {len(unrouted)} unrouted)"
    )
    return 0


INTERNAL_CONNECT_SERVICES = {
    "codewire.internal.v1.GatewayBindingService": "gateway_binding_router",
    "codewire.internal.v1.EnvironmentCredentialService": "environment_credentials_router",
}


def assert_internal_connect_listener_exemption(
    unrouted: dict[str, Any],
    per_file: dict[str, dict[str, Any]],
    fail: Callable[[str], None],
    reader: Callable[[str], str] = read_text,
) -> None:
    """Validate the closed `codewire.internal.v1` listener exception."""
    for service, record in unrouted.items():
        if service not in INTERNAL_CONNECT_SERVICES:
            fail(f"unrouted service {service} is not a declared internal-listener exception")
        if not isinstance(record, dict):
            fail(f"unrouted service {service} must record binary, listener, and port")
            continue
        if record.get("binary") != "orchestration":
            fail(f"unrouted service {service} must be owned by orchestration")
        if record.get("listener") != "internal-connect" or record.get("port") != 8085:
            fail(
                f"unrouted service {service} must use the internal-connect listener on port 8085"
            )
        for file, data in per_file.items():
            if any(rule["service"] == service for rule in data["rules"]):
                fail(f"{file}: unrouted {service} has a prohibited public edge matcher")
    if set(unrouted) != set(INTERNAL_CONNECT_SERVICES):
        fail(
            "unrouted listener map must contain exactly GatewayBindingService and "
            "EnvironmentCredentialService"
        )
    assert_internal_connect_listener_boundary(INTERNAL_CONNECT_SERVICES, fail, reader)


def assert_internal_connect_listener_boundary(
    services: dict[str, str],
    fail: Callable[[str], None],
    reader: Callable[[str], str] = read_text,
) -> None:
    """Prove the closed cluster-local exception cannot leak onto 8084.

    The edge parser above proves the broad public fallback remains in every
    lockstep config. This companion structural check proves the two exception
    services are mounted only by the dedicated internal application and that
    the Deployment/ClusterIP Service bind its exact named port.
    """
    main = reader("crates/codewire-orchestration/src/main.rs")
    internal_start = main.find('let internal_app = AppBuilder::new("codewire-orchestration-internal")')
    public_start = main.find('let app = AppBuilder::new("codewire-orchestration")')
    if internal_start < 0 or public_start < 0 or internal_start >= public_start:
        fail("orchestration must build its internal Connect app before the public app")
        return
    internal_section = main[internal_start:public_start]
    public_section = main[public_start:]
    for service, router in services.items():
        if f"connect::internal::{router}" not in internal_section:
            fail(f"{service} is not mounted on the internal-connect app")
        if f"connect::internal::{router}" in public_section:
            fail(f"{service} is prohibited from the public 8084 app")

    deployment = reader("deployments/k8s/orchestration/deployment.yaml")
    if not re.search(r"containerPort:\s*8084\s*\n\s*name:\s*http", deployment):
        fail("orchestration Deployment must preserve named public http container port 8084")
    if not re.search(
        r"name:\s*ORCHESTRATION_PORT\s*\n\s*value:\s*['\"]8084['\"]", deployment
    ):
        fail("orchestration Deployment must set ORCHESTRATION_PORT=8084 for the public listener")
    if not re.search(
        r"containerPort:\s*8085\s*\n\s*name:\s*internal-api", deployment
    ):
        fail("orchestration Deployment must declare named internal-api container port 8085")
    if not re.search(
        r"name:\s*ORCHESTRATION_INTERNAL_CONNECT_PORT\s*\n\s*value:\s*['\"]8085['\"]",
        deployment,
    ):
        fail("orchestration Deployment must set ORCHESTRATION_INTERNAL_CONNECT_PORT=8085")

    service = reader("deployments/k8s/orchestration/service.yaml")
    if not re.search(
        r"port:\s*8084\s*\n\s*targetPort:\s*8084\s*\n\s*name:\s*http", service
    ):
        fail("orchestration ClusterIP Service must preserve named public http port 8084 -> 8084")
    if not re.search(
        r"port:\s*8085\s*\n\s*targetPort:\s*internal-api\s*\n\s*name:\s*internal-api",
        service,
    ):
        fail("orchestration ClusterIP Service must expose named internal-api port 8085")


def internal_connect_listener_self_test() -> None:
    """Exercise every closed-listener failure mode without mutating the repo."""
    source = {
        path: read_text(path)
        for path in [
            "crates/codewire-orchestration/src/main.rs",
            "deployments/k8s/orchestration/deployment.yaml",
            "deployments/k8s/orchestration/service.yaml",
        ]
    }
    valid_unrouted = {
        service: {"binary": "orchestration", "listener": "internal-connect", "port": 8085}
        for service in INTERNAL_CONNECT_SERVICES
    }

    def expect_rejection(
        label: str,
        expected: str,
        *,
        unrouted: dict[str, Any] | None = None,
        per_file: dict[str, dict[str, Any]] | None = None,
        replacement: tuple[str, str, str] | None = None,
    ) -> None:
        files = source.copy()
        if replacement is not None:
            path, before, after = replacement
            if before not in files[path]:
                raise RuntimeError(f"{label}: self-test fixture did not contain expected source")
            files[path] = files[path].replace(before, after, 1)
        failures: list[str] = []
        assert_internal_connect_listener_exemption(
            copy.deepcopy(valid_unrouted if unrouted is None else unrouted),
            copy.deepcopy({"fixture": {"rules": []}} if per_file is None else per_file),
            failures.append,
            files.__getitem__,
        )
        if not any(expected in failure for failure in failures):
            raise RuntimeError(f"{label}: expected rejection {expected!r}, got {failures!r}")

    missing = copy.deepcopy(valid_unrouted)
    missing.pop("codewire.internal.v1.GatewayBindingService")
    expect_rejection("missing exception record", "must contain exactly", unrouted=missing)

    wrong_port = copy.deepcopy(valid_unrouted)
    wrong_port["codewire.internal.v1.GatewayBindingService"]["port"] = 8086
    expect_rejection("wrong exception record", "must use the internal-connect listener", unrouted=wrong_port)

    expect_rejection(
        "public edge matcher",
        "prohibited public edge matcher",
        per_file={
            "fixture": {
                "rules": [
                    {"service": "codewire.internal.v1.GatewayBindingService", "backend": "orchestration"}
                ]
            }
        },
    )
    expect_rejection(
        "public app mount",
        "prohibited from the public 8084 app",
        replacement=(
            "crates/codewire-orchestration/src/main.rs",
            'let app = AppBuilder::new("codewire-orchestration")',
            'let app = AppBuilder::new("codewire-orchestration")\n'
            '        .with_connect_routes(codewire_orchestration::connect::internal::gateway_binding_router(api_state.clone()))',
        ),
    )
    expect_rejection(
        "internal Service retarget",
        "must expose named internal-api port 8085",
        replacement=(
            "deployments/k8s/orchestration/service.yaml",
            "targetPort: internal-api",
            "targetPort: 8084",
        ),
    )
    expect_rejection(
        "public Service retarget",
        "must preserve named public http port 8084 -> 8084",
        replacement=(
            "deployments/k8s/orchestration/service.yaml",
            "port: 8084\n      targetPort: 8084\n      name: http",
            "port: 8084\n      targetPort: internal-api\n      name: http",
        ),
    )


def services_in_proto(file: Path) -> list[str]:
    text = file.read_text(encoding="utf-8")
    pkg = re.search(r"^\s*package\s+([\w.]+)\s*;", text, re.MULTILINE)
    if not pkg:
        return []
    return [f"{pkg.group(1)}.{match.group(1)}" for match in re.finditer(r"^\s*service\s+(\w+)\s*\{", text, re.MULTILINE)]


def connect_rules(rel_path: str, fail: Callable[[str], None]) -> dict[str, Any]:
    text = read_text(rel_path)
    rules: list[dict[str, str | None]] = []
    fallback = False

    if rel_path.startswith("Caddyfile"):
        lines = text.split("\n")
        matcher_paths: dict[str, list[str]] = {}
        for line in lines:
            named = re.match(r"^\s*(@\w+)\s+path\s+(.+)$", line)
            if named:
                matcher_paths[named.group(1)] = named.group(2).strip().split()
        for index, line in enumerate(lines):
            handle = re.match(r"^\s*handle\s+(\S+)\s*\{", line)
            if not handle:
                continue
            window = "\n".join(lines[index + 1 : index + 4])
            target = re.search(r"reverse_proxy\s+(?:localhost|127\.0\.0\.1):(\d+)", window)
            backend: str | None
            if not target:
                backend = None
            elif target.group(1) == "8084":
                backend = "orchestration"
            elif target.group(1) == "8081":
                backend = "billing"
            elif target.group(1) == "8090":
                backend = "coordinator"
            else:
                backend = target.group(1)
            paths = matcher_paths.get(handle.group(1), []) if handle.group(1).startswith("@") else [handle.group(1)]
            for path in paths:
                if path == "/codewire.*":
                    if backend == "orchestration":
                        fallback = True
                    else:
                        fail(f"{rel_path}: /codewire.* fallback must target orchestration (:8084)")
                    continue
                service = re.match(r"^/((?:codewire|coordinator)\.[\w.]+)/", path)
                if service:
                    rules.append({"service": service.group(1), "backend": backend})
    else:
        lines = text.split("\n")
        for index, line in enumerate(lines):
            match = re.match(r"^\s*-\s+path:\s+(\S+)\s*$", line)
            if not match:
                continue
            path = match.group(1)
            if not re.match(r"^/(codewire|coordinator)[\\.]", path):
                continue
            backend = None
            for candidate in lines[index + 1 : min(index + 8, len(lines))]:
                backend_match = re.match(r"^\s*name:\s+codewire-(\w+)", candidate)
                if backend_match:
                    backend = backend_match.group(1)
                    break
            unescaped = path.replace("\\.", ".")
            if unescaped == "/codewire.":
                if backend == "orchestration":
                    fallback = True
                else:
                    fail(f"{rel_path}: /codewire\\. fallback must target codewire-orchestration")
                continue
            service = re.match(r"^/((?:codewire|coordinator)\.[\w.]+)/", unescaped)
            if service:
                rules.append({"service": service.group(1), "backend": backend})
    return {"rules": rules, "fallback": fallback}


def caddy_handle_block(text: str, path: str) -> str | None:
    lines = text.split("\n")
    try:
        start = next(index for index, line in enumerate(lines) if line.strip() == f"handle {path} {{")
    except StopIteration:
        return None
    depth = 0
    block: list[str] = []
    for line in lines[start:]:
        block.append(line)
        depth += line.count("{")
        depth -= line.count("}")
        if depth == 0:
            return "\n".join(block)
    return None


def coordinator_ingress_document(text: str, label: str, fail: Callable[[str], None]) -> str | None:
    matching = [
        document
        for document in re.split(r"^\s*---\s*$", text, flags=re.MULTILINE)
        if re.search(r"path:\s+/coordinator(?:\\\.|\.)v1(?:\\\.|\.)CoordinatorService/", document)
    ]
    if len(matching) != 1:
        fail(f"{label}: expected exactly one separate CoordinatorService Ingress, found {len(matching)}")
        return None
    return matching[0]


def environment_session_ingress_document(
    text: str, label: str, fail: Callable[[str], None]
) -> str | None:
    matching = [
        document
        for document in re.split(r"^\s*---\s*$", text, flags=re.MULTILINE)
        if re.search(
            r"path:\s+/codewire(?:\\\.|\.)v1(?:\\\.|\.)EnvironmentSessionService/",
            document,
        )
    ]
    if len(matching) != 1:
        fail(
            f"{label}: expected exactly one separate EnvironmentSessionService "
            f"Ingress, found {len(matching)}"
        )
        return None
    return matching[0]


def connect_fallback_ingress_document(
    text: str, label: str, fail: Callable[[str], None]
) -> str | None:
    matching = [
        document
        for document in re.split(r"^\s*---\s*$", text, flags=re.MULTILINE)
        if re.search(
            r"^\s+name:\s+codewire-connect(?:-(?:local|e2e))?\s*$",
            document,
            re.MULTILINE,
        )
    ]
    if len(matching) != 1:
        fail(f"{label}: expected exactly one general Connect ingress, found {len(matching)}")
        return None
    return matching[0]


def assert_connect_streaming_ingress_shape(
    rel_path: str, fail: Callable[[str], None]
) -> None:
    document = connect_fallback_ingress_document(read_text(rel_path), rel_path, fail)
    if document is None:
        return
    if re.search(
        r"nginx\.ingress\.kubernetes\.io/service-upstream:\s+[\"']?true[\"']?",
        document,
    ):
        fail(
            f"{rel_path}: general Connect ingress must keep endpoint routing; "
            "service-upstream is reserved for the isolated native-gRPC ingress"
        )
    for annotation in ["proxy-request-buffering", "proxy-buffering"]:
        if not re.search(
            rf"nginx\.ingress\.kubernetes\.io/{annotation}:\s+[\"']?off[\"']?",
            document,
        ):
            fail(f"{rel_path}: general Connect ingress {annotation} must be off for streaming RPCs")
    if not re.search(
        r"nginx\.ingress\.kubernetes\.io/proxy-body-size:\s+[\"']?0[\"']?",
        document,
    ):
        fail(f"{rel_path}: general Connect ingress proxy-body-size must be 0 for streaming uploads")


def assert_coordinator_ingress_shape(document: str | None, label: str, fail: Callable[[str], None]) -> None:
    if document is None:
        return
    if not re.search(r"^kind:\s+Ingress\s*$", document, re.MULTILINE):
        fail(f"{label}: CoordinatorService route must live in an Ingress object")
    if not re.search(r"pathType:\s+ImplementationSpecific\b", document):
        fail(f"{label}: CoordinatorService regex route must use pathType ImplementationSpecific")
    if re.search(r"path:\s+/api/v1/.*coordinate", document, re.MULTILINE):
        fail(f"{label}: CoordinatorService Connect route must not share the WebSocket Ingress")
    if not re.search(r"nginx\.ingress\.kubernetes\.io/use-regex:\s+[\"']?true[\"']?", document):
        fail(f"{label}: CoordinatorService Ingress must enable use-regex explicitly")
    if not re.search(r"nginx\.ingress\.kubernetes\.io/backend-protocol:\s+[\"']?GRPC[\"']?", document):
        fail(f"{label}: CoordinatorService Ingress is missing backend-protocol GRPC")
    if re.search(
        r"nginx\.ingress\.kubernetes\.io/service-upstream:\s+[\"']?true[\"']?",
        document,
    ):
        fail(
            f"{label}: CoordinatorService keeps its accepted endpoint routing; "
            "service-upstream is reserved for EnvironmentSessionService"
        )
    for annotation in ["proxy-request-buffering", "proxy-buffering"]:
        if not re.search(rf"nginx\.ingress\.kubernetes\.io/{annotation}:\s+[\"']?off[\"']?", document):
            fail(f"{label}: CoordinatorService Ingress {annotation} must be off for bidi DATA")
    for annotation in ["proxy-read-timeout", "proxy-send-timeout"]:
        if not re.search(rf"nginx\.ingress\.kubernetes\.io/{annotation}:\s+[\"']?3600[\"']?", document):
            fail(f"{label}: CoordinatorService Ingress {annotation} must be 3600")
    if not re.search(r"name:\s+codewire-coordinator\b", document):
        fail(f"{label}: CoordinatorService Ingress must target codewire-coordinator")
    if not re.search(r"port:\s*\n\s+name:\s+http\b", document):
        fail(f"{label}: CoordinatorService Ingress must target coordinator's named http port")


def assert_coordinator_transport_shape(rel_path: str, fail: Callable[[str], None]) -> None:
    text = read_text(rel_path)
    if rel_path.startswith("Caddyfile"):
        block = caddy_handle_block(text, "/coordinator.v1.CoordinatorService/*")
        if not block:
            fail(f"{rel_path}: missing explicit CoordinatorService handle block")
            return
        if not re.search(r"reverse_proxy\s+(?:localhost|127\.0\.0\.1):8090\b", block):
            fail(f"{rel_path}: CoordinatorService must target coordinator :8090 explicitly")
        if not re.search(r"transport\s+http\s*\{[\s\S]*?versions\s+h2c\s+2\b", block):
            fail(f"{rel_path}: CoordinatorService backend transport must enable versions h2c 2")
        return
    assert_coordinator_ingress_shape(coordinator_ingress_document(text, rel_path, fail), rel_path, fail)


def assert_environment_session_ingress_shape(
    document: str | None, label: str, fail: Callable[[str], None]
) -> None:
    if document is None:
        return
    if not re.search(r"^kind:\s+Ingress\s*$", document, re.MULTILINE):
        fail(f"{label}: EnvironmentSessionService route must live in an Ingress object")
    if not re.search(r"pathType:\s+ImplementationSpecific\b", document):
        fail(
            f"{label}: EnvironmentSessionService regex route must use "
            "pathType ImplementationSpecific"
        )
    if not re.search(
        r"nginx\.ingress\.kubernetes\.io/use-regex:\s+[\"']?true[\"']?",
        document,
    ):
        fail(f"{label}: EnvironmentSessionService Ingress must enable use-regex explicitly")
    if not re.search(
        r"nginx\.ingress\.kubernetes\.io/backend-protocol:\s+[\"']?GRPC[\"']?",
        document,
    ):
        fail(f"{label}: EnvironmentSessionService Ingress is missing backend-protocol GRPC")
    if not re.search(
        r"nginx\.ingress\.kubernetes\.io/service-upstream:\s+[\"']?true[\"']?",
        document,
    ):
        fail(
            f"{label}: EnvironmentSessionService Ingress must route through "
            "the dedicated Service ClusterIP"
        )
    for annotation in ["proxy-request-buffering", "proxy-buffering"]:
        if not re.search(
            rf"nginx\.ingress\.kubernetes\.io/{annotation}:\s+[\"']?off[\"']?",
            document,
        ):
            fail(f"{label}: EnvironmentSessionService Ingress {annotation} must be off for bidi DATA")
    for annotation in ["proxy-read-timeout", "proxy-send-timeout"]:
        if not re.search(
            rf"nginx\.ingress\.kubernetes\.io/{annotation}:\s+[\"']?3600[\"']?",
            document,
        ):
            fail(f"{label}: EnvironmentSessionService Ingress {annotation} must be 3600")
    if not re.search(r"name:\s+codewire-orchestration-grpc\b", document):
        fail(
            f"{label}: EnvironmentSessionService Ingress must target the isolated "
            "codewire-orchestration-grpc upstream"
        )
    if not re.search(r"port:\s*\n\s+name:\s+grpc\b", document):
        fail(
            f"{label}: EnvironmentSessionService Ingress must target the isolated "
            "named grpc port"
        )


def assert_environment_session_transport_shape(
    rel_path: str, fail: Callable[[str], None]
) -> None:
    text = read_text(rel_path)
    if rel_path.startswith("Caddyfile"):
        block = caddy_handle_block(text, "/codewire.v1.EnvironmentSessionService/*")
        if not block:
            fail(f"{rel_path}: missing explicit EnvironmentSessionService handle block")
            return
        if not re.search(r"reverse_proxy\s+(?:localhost|127\.0\.0\.1):8084\b", block):
            fail(f"{rel_path}: EnvironmentSessionService must target orchestration :8084")
        if not re.search(r"transport\s+http\s*\{[\s\S]*?versions\s+h2c\s+2\b", block):
            fail(
                f"{rel_path}: EnvironmentSessionService backend transport must enable "
                "versions h2c 2"
            )
        return
    assert_environment_session_ingress_shape(
        environment_session_ingress_document(text, rel_path, fail),
        rel_path,
        fail,
    )


def assert_native_grpc_opt_in_sites(fail: Callable[[str], None]) -> None:
    expected = {
        "crates/codewire-coordinator/src/connect.rs": 1,
        "crates/codewire-orchestration/src/main.rs": 1,
    }
    actual: dict[str, int] = {}
    for rel_path in git_source_files():
        if not rel_path.endswith(".rs") or "/tests/" in rel_path:
            continue
        if rel_path == "crates/codewire-server-core/src/connect.rs":
            continue
        count = read_text(rel_path).count("ProtocolPolicy::ConnectAndGrpc")
        if count:
            actual[rel_path] = count
    if actual != expected:
        fail(
            "native-gRPC policy opt-ins must be exactly CoordinatorService and "
            f"EnvironmentSessionService: got {actual}, want {expected}"
        )


def ingress_document_by_name(text: str, name: str, label: str, fail: Callable[[str], None]) -> str | None:
    matches: list[str] = []
    for document in re.split(r"^\s*---\s*$", text, flags=re.MULTILINE):
        if not re.search(r"^kind:\s+Ingress\s*$", document, re.MULTILINE):
            continue
        metadata = re.split(r"^spec:\s*$", document, maxsplit=1, flags=re.MULTILINE)[0]
        if re.search(rf"^\s*name:\s+{re.escape(name)}\s*$", metadata, re.MULTILINE):
            matches.append(document)
    if len(matches) != 1:
        fail(f"{label}: expected exactly one Ingress named {name}, found {len(matches)}")
        return None
    return matches[0]


def service_document_by_name(
    text: str, name: str, label: str, fail: Callable[[str], None]
) -> str | None:
    matches: list[str] = []
    for document in re.split(r"^\s*---\s*$", text, flags=re.MULTILINE):
        if not re.search(r"^kind:\s+Service\s*$", document, re.MULTILINE):
            continue
        metadata = re.split(r"^spec:\s*$", document, maxsplit=1, flags=re.MULTILINE)[0]
        if re.search(rf"^\s*name:\s+{re.escape(name)}\s*$", metadata, re.MULTILINE):
            matches.append(document)
    if len(matches) != 1:
        fail(f"{label}: expected exactly one Service named {name}, found {len(matches)}")
        return None
    return matches[0]


def assert_environment_session_grpc_service_shape(
    document: str | None, label: str, fail: Callable[[str], None]
) -> None:
    if document is None:
        return
    for selector in [
        r"app\.kubernetes\.io/name:\s+codewire\b",
        r"app\.kubernetes\.io/component:\s+orchestration\b",
    ]:
        if not re.search(selector, document):
            fail(f"{label}: isolated gRPC Service must select orchestration pods")
    if not re.search(
        r"ports:\s*\n\s*-\s+name:\s+grpc\s*\n\s+port:\s+8084\s*\n"
        r"\s+targetPort:\s+http\b",
        document,
    ):
        fail(f"{label}: isolated gRPC Service must expose 8084 -> named target http")
    if re.search(r"name:\s+internal-api\b", document):
        fail(f"{label}: isolated gRPC Service must not expose the internal API")


def ingress_identity(document: str | None, label: str, fail: Callable[[str], None]) -> dict[str, str] | None:
    if document is None:
        return None
    rule_host = re.search(r"^\s*-\s+host:\s+(\S+)\s*$", document, re.MULTILINE)
    tls = re.search(
        r"^\s*tls:\s*\n\s*-\s+hosts:\s*\n\s*-\s+(\S+)\s*\n\s+secretName:\s+(\S+)\s*$",
        document,
        re.MULTILINE,
    )
    if not rule_host or not tls:
        fail(f"{label}: unable to read Ingress rule host and TLS identity")
        return None
    return {"ruleHost": rule_host.group(1), "tlsHost": tls.group(1), "tlsSecret": tls.group(2)}


def assert_rendered_dev_ingress_identities(fail: Callable[[str], None]) -> None:
    label = "deployments/k8s/overlays/dev (rendered)"
    result = run(["kustomize", "build", "deployments/k8s/overlays/dev"], check=False)
    if result.returncode != 0:
        fail(f"{label}: kustomize build failed: {result.stderr.strip() or result.stdout.strip()}")
        return
    websocket = ingress_document_by_name(result.stdout, "codewire-coordinator", label, fail)
    coordinator_connect = ingress_document_by_name(result.stdout, "codewire-coordinator-connect", label, fail)
    environment_session = ingress_document_by_name(
        result.stdout, "codewire-environment-session-grpc", label, fail
    )
    environment_session_upstream = service_document_by_name(
        result.stdout, "codewire-orchestration-grpc", label, fail
    )
    general_connect = ingress_document_by_name(result.stdout, "codewire-connect", label, fail)
    assert_coordinator_ingress_shape(coordinator_connect, f"{label} codewire-coordinator-connect", fail)
    assert_environment_session_ingress_shape(
        environment_session,
        f"{label} codewire-environment-session-grpc",
        fail,
    )
    assert_environment_session_grpc_service_shape(
        environment_session_upstream,
        f"{label} codewire-orchestration-grpc",
        fail,
    )

    websocket_identity = ingress_identity(websocket, f"{label} codewire-coordinator", fail)
    coordinator_connect_identity = ingress_identity(
        coordinator_connect, f"{label} codewire-coordinator-connect", fail
    )
    environment_session_identity = ingress_identity(
        environment_session, f"{label} codewire-environment-session-grpc", fail
    )
    general_connect_identity = ingress_identity(general_connect, f"{label} codewire-connect", fail)
    if (
        not websocket_identity
        or not coordinator_connect_identity
        or not environment_session_identity
        or not general_connect_identity
    ):
        return

    expected = {
        "ruleHost": "codewire-dev.sh",
        "tlsHost": "codewire-dev.sh",
        "tlsSecret": "codewire-dev-tls",
    }
    for name, identity in [
        ("codewire-coordinator", websocket_identity),
        ("codewire-coordinator-connect", coordinator_connect_identity),
        ("codewire-environment-session-grpc", environment_session_identity),
        ("codewire-connect", general_connect_identity),
    ]:
        for field, value in expected.items():
            if identity[field] != value:
                fail(f"{label}: {name} {field} must be {value}, got {identity[field]}")
    if websocket_identity != coordinator_connect_identity:
        fail(f"{label}: coordinator WS and Connect Ingress host/TLS identities must match")


# ---------------------------------------------------------------------------
# Kubernetes/security source guards


def documents(rendered: str) -> list[str]:
    return [document.strip() for document in re.split(r"^---\s*$", rendered, flags=re.MULTILINE) if document.strip()]


def top_level_field(document: str, field: str) -> str | None:
    match = re.search(rf"^{re.escape(field)}:\s*(\S+)\s*$", document, re.MULTILINE)
    return match.group(1) if match else None


def metadata_field(document: str, field: str) -> str | None:
    lines = document.split("\n")
    try:
        metadata = lines.index("metadata:")
    except ValueError:
        return None
    for line in lines[metadata + 1 :]:
        if re.match(r"^[^ ]", line):
            break
        match = re.match(rf"^  {re.escape(field)}:\s*(\S+)\s*$", line)
        if match:
            return match.group(1)
    return None


def resource_name(document: str) -> str | None:
    return metadata_field(document, "name")


def top_level_block(document: str, field: str) -> str:
    lines = document.split("\n")
    start = next((index for index, line in enumerate(lines) if line == f"{field}:"), -1)
    if start < 0:
        return ""
    end = len(lines)
    for index in range(start + 1, len(lines)):
        if re.match(r"^[A-Za-z][A-Za-z0-9_.-]*:", lines[index]):
            end = index
            break
    return "\n".join(lines[start:end])


def compact(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def resources_by_kind_and_name(resources: list[str], kind: str, name: str) -> list[str]:
    return [
        resource
        for resource in resources
        if top_level_field(resource, "kind") == kind and metadata_field(resource, "name") == name
    ]


def exactly_one(
    resources: list[str],
    kind: str,
    name: str,
    label: str,
    failures: list[str],
) -> str | None:
    matches = resources_by_kind_and_name(resources, kind, name)
    if len(matches) != 1:
        failures.append(f"{label}: expected exactly one {kind}/{name}, found {len(matches)}")
        return None
    return matches[0]


def check_production_source_ownership(args: argparse.Namespace) -> int:
    try:
        files = load_production_source_files(Path(args.root).resolve())
        tag = validate_production_source(files)
        if args.self_test:
            production_source_self_test(files)
        print(f"production source ownership: OK ({tag})")
        return 0
    except Exception as error:  # noqa: BLE001 - repo check script
        print(f"production source ownership: {error}", file=sys.stderr)
        return 1


def collect_files(root: Path, directory: Path, files: dict[str, str]) -> None:
    for path in sorted(directory.rglob("*")):
        if path.is_file() and path.stat().st_size > 0:
            files[path.relative_to(root).as_posix()] = path.read_text(encoding="utf-8")


def one_match(text: str, pattern: str, label: str) -> re.Match[str]:
    matches = list(re.finditer(pattern, text, re.MULTILINE))
    if len(matches) != 1:
        raise RuntimeError(f"{label}: expected exactly one immutable source pin, found {len(matches)}")
    return matches[0]


def load_production_source_files(root: Path) -> dict[str, Any]:
    def read(path: str) -> str:
        return (root / path).read_text(encoding="utf-8")

    retired_control_paths = [
        ".gitea/workflows/observe-prod-release.yaml",
        "scripts/ci/codewire-prod-observer-authz.tsv",
        "scripts/ci/codewire-prod-observer-minter-authz.tsv",
        "scripts/ci/deploy-prod-observer.sh",
        "scripts/ci/observe-deploy-dev.py",
        "scripts/ci/test-deploy-prod-observer.sh",
        "scripts/ci/test-observe-deploy-dev.py",
        "scripts/ci/test-observe-prod-release.sh",
        "scripts/ci/verify-prod-observer-receipt.sh",
        "scripts/ci/promote-image-bundle.sh",
        "scripts/ci/promotion-receipt.py",
        "scripts/ci/test-promote-image-bundle.sh",
        "scripts/ci/test-promotion-receipt.py",
    ]
    production_files: dict[str, str] = {}
    for directory in [
        "deployments/k8s/overlays/production",
        "deployments/k8s/flux/production",
        "deployments/k8s/flux/temporal-production",
        "deployments/k8s/mesh-production",
    ]:
        collect_files(root, root / directory, production_files)

    return {
        "kustomization": read("deployments/k8s/overlays/production/kustomization.yaml"),
        "gateway_patch": read("deployments/k8s/overlays/production/config-images.yaml"),
        "mesh_release": read("deployments/k8s/flux/production/mesh-helmrelease.yaml"),
        "deploy_script": read("scripts/ci/deploy/deploy-prod.sh"),
        "ci_workflow": read(".gitea/workflows/ci.yaml"),
        "production_workflow": read(".gitea/workflows/deploy-prod.yaml"),
        "production_files": production_files,
        "retired_control_paths_present": [
            path for path in retired_control_paths if (root / path).exists()
        ],
        "retired_temporal_preflight_present": (root / ".gitea/workflows/prod-temporal-preflight.yaml").exists(),
    }


def validate_production_source(files: dict[str, Any]) -> str:
    if files["retired_temporal_preflight_present"]:
        raise RuntimeError("retired manual production Temporal preflight workflow remains")
    if files["retired_control_paths_present"]:
        raise RuntimeError(
            "retired source deployment control remains: "
            + ", ".join(files["retired_control_paths_present"])
        )
    if re.search(r"promotion-receipt-(?:publish|consume):", files["ci_workflow"]):
        raise RuntimeError("synthetic promotion receipt CI transport remains")

    for path, text in files["production_files"].items():
        if "$imagepolicy" in text:
            raise RuntimeError(f"retired Flux image setter marker remains in {path}")

    if not re.search(r"^\s*- path: config-images\.yaml\s*$", files["kustomization"], re.MULTILINE):
        raise RuntimeError("production Kustomization must apply config-images.yaml")

    tags: dict[str, str] = {}
    digests: dict[str, str] = {}
    for name in ["services", "derp", "dashboard"]:
        pin = one_match(
            files["kustomization"],
            rf"^\s*- name: git\.example\.com/codewire/{name}\s*\n"
            rf"\s+newName: git\.example\.invalid/codewire/{name}\s*\n"
            r"\s+newTag: (v\d+\.\d+\.\d+)\s*\n"
            r"\s+digest: (sha256:[0-9a-f]{64})\s*$",
            f"{name} image",
        )
        tags[name] = pin.group(1)
        digests[name] = pin.group(2)

    gateway = one_match(
        files["gateway_patch"],
        r"^\s*SANDBOX_GATEWAY_IMAGE:\s*git\.example\.invalid/codewire/gateway:(v\d+\.\d+\.\d+)@(sha256:[0-9a-f]{64})\s*$",
        "gateway image",
    )
    tags["gateway"] = gateway.group(1)
    digests["gateway"] = gateway.group(2)

    mesh = one_match(
        files["mesh_release"],
        r"^\s*image:\s*\n\s+repository:\s*git\.example\.invalid/codewire/mesh\s*\n"
        r"\s+tag:\s*(v\d+\.\d+\.\d+)\s*\n"
        r"\s+digest:\s*(sha256:[0-9a-f]{64})\s*$",
        "mesh image",
    )
    tags["mesh"] = mesh.group(1)
    digests["mesh"] = mesh.group(2)

    unique_tags = set(tags.values())
    if len(unique_tags) != 1:
        raise RuntimeError(
            "mixed credential-free source tags: "
            + ", ".join(f"{name}={tag}" for name, tag in tags.items())
        )
    if len(digests) != 5:
        raise RuntimeError(f"expected five immutable source digests, found {len(digests)}")

    if "scripts/ci/deploy/deploy-prod.sh --render-only" not in files["deploy_script"]:
        raise RuntimeError("credential-free production render mode is missing")
    if (
        re.search(
            r"--preflight-only|setup-kubeconfig|ci-deployer-rbac|CODEWIRE_(?:TOKEN_PATH|K8S_SERVER)|TEMPORAL_PREFLIGHT",
            files["deploy_script"],
        )
        or re.search(r"\bkubectl\s+(?:apply|delete|get|run|wait|logs|describe|rollout)\b", files["deploy_script"])
        or re.search(r"\bhelm\s+(?:upgrade|uninstall)\b", files["deploy_script"])
    ):
        raise RuntimeError("direct production mutation or cluster credential path remains in deploy-prod.sh")

    for required in [
        "publish-runtime-images:",
        "image-bundle.py create",
        "publish-image-to-ghcr.sh",
        "dispatch-deploy-prod.sh",
        "CODEWIRE_DEPLOY_PROMOTION_TOKEN",
    ]:
        if required not in files["production_workflow"]:
            raise RuntimeError(f"source production workflow lost required boundary: {required}")
    for retired in [
        "aggregate-image-promotion:",
        "CODEWIRE_DEPLOY_PROMOTION_USERNAME",
        "promote-image-bundle.sh",
        "promotion-receipt",
        "observe-production:",
        "deploy-prod-observer.sh",
    ]:
        if retired in files["production_workflow"]:
            raise RuntimeError(f"source production workflow retains retired control plane: {retired}")
    if "scripts/ci/deploy/deploy-prod.sh" in files["production_workflow"]:
        raise RuntimeError("production workflow reintroduced the retired direct deploy script")

    return next(iter(unique_tags))


def production_source_self_test(files: dict[str, Any]) -> None:
    def expect_rejected(label: str, fixture: dict[str, Any], expected: str) -> None:
        try:
            validate_production_source(fixture)
        except Exception as error:  # noqa: BLE001 - negative fixture
            if expected in str(error):
                return
            raise
        raise RuntimeError(f"self-test accepted {label}")

    fixture = dict(files)
    fixture["gateway_patch"] = re.sub(
        r"gateway:v\d+\.\d+\.\d+@",
        "gateway:v999.999.999@",
        files["gateway_patch"],
    )
    expect_rejected("mixed image tags", fixture, "mixed credential-free source tags")

    fixture = dict(files)
    fixture["production_files"] = {**files["production_files"], "fixture.yaml": '# {"$imagepolicy": "flux-system:retired"}'}
    expect_rejected("retired image setter", fixture, "retired Flux image setter marker")

    fixture = dict(files)
    fixture["deploy_script"] = files["deploy_script"] + "\nkubectl apply -k .\n"
    expect_rejected("direct production mutation", fixture, "direct production mutation")

    fixture = dict(files)
    fixture["retired_control_paths_present"] = ["scripts/ci/retired-observer.sh"]
    expect_rejected("retired source deployment control", fixture, "retired source deployment control remains")

    fixture = dict(files)
    fixture["ci_workflow"] = files["ci_workflow"] + "\npromotion-receipt-publish:\n"
    expect_rejected("synthetic promotion receipt CI transport", fixture, "synthetic promotion receipt CI transport remains")

    fixture = dict(files)
    fixture["retired_temporal_preflight_present"] = True
    expect_rejected("retired Temporal preflight workflow", fixture, "retired manual production Temporal preflight workflow")


def check_orchestration_host_key_authz(args: argparse.Namespace) -> int:
    name = "codewire-orchestration-gateway-host-key"
    orchestration = "codewire-orchestration"
    forbidden_secret_verbs = ["get", "list", "watch", "update", "patch"]
    targets = [
        {"path": "deployments/k8s/orchestration", "role_namespace": "prod-sandboxes", "subject_namespace": "prod"},
        {"path": "deployments/k8s/overlays/dev", "role_namespace": "dev-sandboxes", "subject_namespace": "dev"},
        {"path": "deployments/k8s/overlays/production", "role_namespace": "prod-sandboxes", "subject_namespace": "prod"},
        {"path": "deployments/k8s/overlays/local-kind", "role_namespace": "dev-sandboxes", "subject_namespace": "default"},
        {"path": "deployments/k8s/overlays/local-kind-static", "role_namespace": "dev-sandboxes", "subject_namespace": "default"},
        {"path": "tests/e2e/kind", "role_namespace": "dev-sandboxes", "subject_namespace": "codewire-e2e"},
    ]
    failures: list[str] = []

    def assert_cluster_role(resources: list[str], label: str, output: list[str]) -> None:
        role = exactly_one(resources, "ClusterRole", orchestration, label, output)
        if role and re.search(r"^\s*- secrets\s*$", role, re.MULTILINE):
            output.append(f"{label}: cluster-wide orchestration role still grants Secret access")

    def assert_role(resources: list[str], target: dict[str, str], label: str, output: list[str]) -> None:
        role = exactly_one(resources, "Role", name, label, output)
        if not role:
            return
        if metadata_field(role, "namespace") != target["role_namespace"]:
            output.append(f"{label}: host-key Role must live in {target['role_namespace']}")
        expected_rules = compact(
            """
            rules:
            - apiGroups:
              - ""
              resources:
              - secrets
              verbs:
              - create
              - delete
            """
        )
        actual_rules = compact(top_level_block(role, "rules"))
        if actual_rules != expected_rules:
            output.append(f"{label}: host-key Role must grant only Secret create/delete")
        for verb in forbidden_secret_verbs:
            if re.search(rf"^\s*- {verb}\s*$", role, re.MULTILINE):
                output.append(f"{label}: host-key Role grants forbidden Secret verb {verb}")

    def assert_role_binding(resources: list[str], target: dict[str, str], label: str, output: list[str]) -> None:
        binding = exactly_one(resources, "RoleBinding", name, label, output)
        if not binding:
            return
        if metadata_field(binding, "namespace") != target["role_namespace"]:
            output.append(f"{label}: host-key RoleBinding must live in {target['role_namespace']}")
        expected_role_ref = compact(
            f"""
            roleRef:
              apiGroup: rbac.authorization.k8s.io
              kind: Role
              name: {name}
            """
        )
        if compact(top_level_block(binding, "roleRef")) != expected_role_ref:
            output.append(f"{label}: host-key RoleBinding must reference Role/{name}")
        expected_subjects = compact(
            f"""
            subjects:
            - kind: ServiceAccount
              name: {orchestration}
              namespace: {target['subject_namespace']}
            """
        )
        if compact(top_level_block(binding, "subjects")) != expected_subjects:
            output.append(
                f"{label}: host-key RoleBinding must select "
                f"{target['subject_namespace']}/{orchestration}"
            )

    def assert_bound_surface(resources: list[str], target: dict[str, str], label: str, output: list[str]) -> None:
        bindings = [
            resource
            for resource in resources
            if top_level_field(resource, "kind") in {"RoleBinding", "ClusterRoleBinding"}
            and re.search(rf"^  name: {orchestration}$", top_level_block(resource, "subjects"), re.MULTILINE)
        ]
        actual = sorted(
            f"{top_level_field(binding, 'kind')}/"
            f"{metadata_field(binding, 'namespace') or '<cluster>'}/"
            f"{metadata_field(binding, 'name')}"
            for binding in bindings
        )
        expected = sorted(
            [
                f"ClusterRoleBinding/<cluster>/{orchestration}",
                f"RoleBinding/{target['role_namespace']}/{name}",
            ]
        )
        if actual != expected:
            output.append(
                f"{label}: orchestration ServiceAccount binding surface is "
                f"{', '.join(actual) if actual else 'empty'}"
            )

    def assert_admission(resources: list[str], label: str, output: list[str]) -> None:
        policy = exactly_one(resources, "ValidatingAdmissionPolicy", name, label, output)
        binding = exactly_one(resources, "ValidatingAdmissionPolicyBinding", name, label, output)
        if policy:
            if metadata_field(policy, "namespace") is not None:
                output.append(f"{label}: ValidatingAdmissionPolicy must remain cluster-scoped")
            normalized = compact(top_level_block(policy, "spec"))
            required = [
                "failurePolicy: Fail",
                "matchPolicy: Equivalent",
                "operations: - CREATE - DELETE",
                "resources: - secrets",
                "request.userInfo.username.matches('^system:serviceaccount:[^:]+:codewire-orchestration$')",
                "request.name.startsWith('cw-gateway-host-key-')",
                "request.operation != 'CREATE' || object.type == 'Opaque'",
                "object.metadata.labels['app.kubernetes.io/name'] == 'codewire-gateway'",
                "object.metadata.labels['app.kubernetes.io/component'] == 'gateway-host-key'",
                "object.metadata.labels['app.kubernetes.io/managed-by'] == 'codewire'",
                "object.metadata.labels['codewire.sh/type'] == 'gateway-host-key'",
                "request.name == 'cw-gateway-host-key-' + object.metadata.labels['codewire.sh/environment-id']",
            ]
            for fragment in required:
                if fragment not in normalized:
                    output.append(f"{label}: admission policy is missing {fragment}")
        if binding:
            if metadata_field(binding, "namespace") is not None:
                output.append(f"{label}: ValidatingAdmissionPolicyBinding must remain cluster-scoped")
            expected = compact(
                f"""
                spec:
                  matchResources:
                    namespaceSelector:
                      matchLabels:
                        codewire.sh/resource-type: sandbox
                  policyName: {name}
                  validationActions:
                  - Deny
                """
            )
            if compact(top_level_block(binding, "spec")) != expected:
                output.append(f"{label}: admission binding must fail closed in sandbox-labeled namespaces")

    def verify_resources(resources: list[str], target: dict[str, str], label: str) -> list[str]:
        output: list[str] = []
        assert_cluster_role(resources, label, output)
        assert_role(resources, target, label, output)
        assert_role_binding(resources, target, label, output)
        assert_bound_surface(resources, target, label, output)
        assert_admission(resources, label, output)
        return output

    def expected_admission_allows(operation: str, secret_name: str, obj: dict[str, Any] | None = None) -> bool:
        obj = obj or {}
        if not secret_name.startswith("cw-gateway-host-key-"):
            return False
        if operation == "DELETE":
            return True
        if operation != "CREATE" or obj.get("type") != "Opaque":
            return False
        labels = ((obj.get("metadata") or {}).get("labels") or {})
        return (
            labels.get("app.kubernetes.io/name") == "codewire-gateway"
            and labels.get("app.kubernetes.io/component") == "gateway-host-key"
            and labels.get("app.kubernetes.io/managed-by") == "codewire"
            and labels.get("codewire.sh/type") == "gateway-host-key"
            and secret_name == f"cw-gateway-host-key-{labels.get('codewire.sh/environment-id')}"
        )

    def self_test() -> None:
        target = targets[0]
        base = documents(run(["kustomize", "build", target["path"]]).stdout)

        def expect_rejected(label: str, mutate: Callable[[list[str]], list[str]]) -> None:
            fixture = mutate(list(base))
            if not verify_resources(fixture, target, f"negative fixture {label}"):
                raise RuntimeError(f"negative fixture {label} was accepted")

        expect_rejected(
            "application namespace binding",
            lambda resources: resources
            + [resources_by_kind_and_name(resources, "RoleBinding", name)[0].replace("namespace: prod-sandboxes", "namespace: prod")],
        )
        expect_rejected(
            "wildcard Secret grant",
            lambda resources: [
                resource.replace("  - secrets", '  - "*"')
                if top_level_field(resource, "kind") == "Role" and metadata_field(resource, "name") == name
                else resource
                for resource in resources
            ],
        )
        expect_rejected(
            "Secret get verb",
            lambda resources: [
                resource.replace("  - delete", "  - delete\n  - get")
                if top_level_field(resource, "kind") == "Role" and metadata_field(resource, "name") == name
                else resource
                for resource in resources
            ],
        )
        expect_rejected(
            "absent admission enforcement",
            lambda resources: [
                resource
                for resource in resources
                if not (top_level_field(resource, "kind") or "").startswith("ValidatingAdmissionPolicy")
            ],
        )
        expect_rejected(
            "unrelated Secret guard",
            lambda resources: [
                resource.replace("cw-gateway-host-key-", "cw-any-secret-")
                if top_level_field(resource, "kind") == "ValidatingAdmissionPolicy"
                else resource
                for resource in resources
            ],
        )
        if expected_admission_allows("CREATE", "unrelated-secret", {"type": "Opaque", "metadata": {"labels": {}}}) or expected_admission_allows("DELETE", "unrelated-secret"):
            raise RuntimeError("unrelated Secret create/delete fixture was accepted")

    try:
        for target in targets:
            rendered = run(["kustomize", "build", target["path"]]).stdout
            failures.extend(verify_resources(documents(rendered), target, f"{target['path']} (rendered)"))
        if args.self_test:
            self_test()
    except Exception as error:  # noqa: BLE001 - repo check script
        failures.append(str(error))

    if failures:
        for failure in failures:
            print(f"::error::orchestration host-key authorization: {failure}", file=sys.stderr)
        return 1
    print(f"orchestration host-key authorization: OK ({len(targets)} rendered target(s))")
    return 0


def check_idp_signing_kek_isolation(args: argparse.Namespace) -> int:
    secret = "codewire-idp-signing-keks"
    volume = "idp-signing-keks"
    kek_dir = "/var/run/secrets/codewire/idp-signing-keks"
    default_active_id = "v1"
    dev_active_id = "v2"
    env_names = ["IDP_SIGNING_KEK_DIR", "IDP_SIGNING_ACTIVE_KEK_ID"]
    workload_markers = [secret, volume, kek_dir, *env_names]
    pod_workload_kinds = {"Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"}
    synthetic_kek = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    overlays = [
        {"path": "deployments/k8s/idp", "local": False, "active_id": default_active_id},
        {"path": "deployments/k8s/overlays/dev", "local": False, "active_id": dev_active_id},
        {"path": "deployments/k8s/overlays/production", "local": False, "active_id": default_active_id},
        {"path": "deployments/k8s/overlays/local-kind", "local": True, "active_id": default_active_id},
        {"path": "deployments/k8s/overlays/local-kind-static", "local": True, "active_id": default_active_id},
    ]
    failures: list[str] = []

    def fail(message: str) -> None:
        failures.append(message)

    def count(document: str, needle: str) -> int:
        return document.count(needle)

    def assert_env(document: str, name: str, value: str, label: str) -> None:
        expression = re.compile(
            rf"^\s*- name: {re.escape(name)}\s*\n\s+value: [\"']?{re.escape(value)}[\"']?\s*$",
            re.MULTILINE,
        )
        if not expression.search(document):
            fail(f"{label}: codewire-idp must set {name}={value}")
        if count(document, f"name: {name}") != 1:
            fail(f"{label}: codewire-idp must contain {name} exactly once")

    def assert_idp_deployment(document: str, label: str, active_id: str) -> None:
        assert_env(document, "IDP_SIGNING_KEK_DIR", kek_dir, label)
        assert_env(document, "IDP_SIGNING_ACTIVE_KEK_ID", active_id, label)
        if count(document, f"mountPath: {kek_dir}") != 1:
            fail(f"{label}: codewire-idp must mount the signing keyring exactly once")
        if count(document, f"name: {volume}") != 2:
            fail(f"{label}: codewire-idp must have one {volume} mount and one volume")
        read_only_kek_mount = re.compile(
            rf"^\s*- mountPath: {re.escape(kek_dir)}\s*\n"
            rf"\s+name: {re.escape(volume)}\s*\n"
            r"\s+readOnly: true\s*$",
            re.MULTILINE,
        )
        if not read_only_kek_mount.search(document):
            fail(f"{label}: the signing keyring mount must be explicitly read-only")
        if count(document, f"secretName: {secret}") != 1:
            fail(f"{label}: codewire-idp must reference only the dedicated target Secret")
        if re.search(rf"secretRef:\s*\n\s+name: {re.escape(secret)}", document):
            fail(f"{label}: the signing keyring must never be injected through envFrom")

    def assert_synthetic_secret(document: str, label: str) -> None:
        if top_level_field(document, "type") != "Opaque":
            fail(f"{label}: the local signing-key Secret must be Opaque")
        string_data = (re.search(r"^stringData:\s*\n([\s\S]*)$", document, re.MULTILINE) or [None, ""])[1]
        entries = list(re.finditer(r"^  ([^:#\s]+):\s*[\"']?([^\"'\s]+)[\"']?\s*$", string_data, re.MULTILINE))
        if len(entries) != 1 or entries[0].group(1) != default_active_id:
            fail(f"{label}: the local signing-key Secret must contain only {default_active_id}")
            return
        if entries[0].group(2) != synthetic_kek:
            fail(f"{label}: local kind must use the checked-in synthetic 32-byte key")

    def assert_static_overlay(overlay: dict[str, Any]) -> None:
        path = overlay["path"]
        label = f"{path} (rendered)"
        rendered = run(["kustomize", "build", path]).stdout
        resources = documents(rendered)
        deployments = [resource for resource in resources if top_level_field(resource, "kind") == "Deployment"]
        idp = [resource for resource in deployments if resource_name(resource) == "codewire-idp"]
        if len(idp) != 1:
            fail(f"{label}: expected exactly one codewire-idp Deployment, found {len(idp)}")
        else:
            assert_idp_deployment(idp[0], label, overlay["active_id"])

        for workload in [
            resource for resource in resources if top_level_field(resource, "kind") in pod_workload_kinds
        ]:
            kind = top_level_field(workload, "kind")
            name = resource_name(workload) or "<unnamed>"
            if kind == "Deployment" and name == "codewire-idp":
                continue
            for marker in workload_markers:
                if marker in workload:
                    fail(f"{label}: unrelated {kind} {name} inherits signing marker {marker}")

        for resource in resources:
            if top_level_field(resource, "kind") != "ConfigMap":
                continue
            name = resource_name(resource) or "<unnamed>"
            for marker in [kek_dir, *env_names]:
                if marker in resource:
                    fail(f"{label}: ConfigMap {name} leaks idp-only configuration {marker}")

        targets = [
            resource
            for resource in resources
            if top_level_field(resource, "kind") == "Secret" and resource_name(resource) == secret
        ]
        if overlay["local"]:
            if len(targets) != 1:
                fail(f"{label}: expected one synthetic {secret} Secret, found {len(targets)}")
            else:
                assert_synthetic_secret(targets[0], label)
        elif targets:
            fail(f"{label}: live/base renders must reference, never generate, {secret}")

    def assert_live_kind() -> None:
        context = args.context
        namespace = args.namespace
        if not context.startswith("kind-") or namespace != "default":
            raise RuntimeError("--live is restricted to a local kind-* context in namespace default")

        def kubectl(*kubectl_args: str) -> str:
            return run(["kubectl", "--context", context, "-n", namespace, *kubectl_args]).stdout

        deployment_list = json.loads(kubectl("get", "deployments", "-o", "json"))
        idp = [item for item in deployment_list.get("items", []) if item.get("metadata", {}).get("name") == "codewire-idp"]
        if len(idp) != 1:
            fail(f"live {context}/{namespace}: expected one codewire-idp Deployment")
        else:
            idp_spec = json.dumps(idp[0].get("spec", {}).get("template", {}).get("spec", {}), ensure_ascii=False)
            for marker in workload_markers:
                if marker not in idp_spec:
                    fail(f"live {context}/{namespace}: codewire-idp is missing {marker}")

        for deployment in deployment_list.get("items", []):
            if deployment.get("metadata", {}).get("name") == "codewire-idp":
                continue
            spec = json.dumps(deployment.get("spec", {}).get("template", {}).get("spec", {}), ensure_ascii=False)
            for marker in workload_markers:
                if marker in spec:
                    fail(
                        f"live {context}/{namespace}: unrelated Deployment "
                        f"{deployment.get('metadata', {}).get('name')} inherits {marker}"
                    )

        pod_list = json.loads(kubectl("get", "pods", "-o", "json"))
        idp_labels = idp[0].get("spec", {}).get("selector", {}).get("matchLabels", {}) if idp else {}

        def is_idp_pod(pod: dict[str, Any]) -> bool:
            labels = pod.get("metadata", {}).get("labels", {})
            return bool(idp_labels) and all(labels.get(key) == value for key, value in idp_labels.items())

        idp_pod_count = len([pod for pod in pod_list.get("items", []) if is_idp_pod(pod)])
        if idp_pod_count < 1:
            fail(f"live {context}/{namespace}: no Pod matches the codewire-idp selector")
        for pod in pod_list.get("items", []):
            if is_idp_pod(pod):
                continue
            spec = json.dumps(pod.get("spec", {}), ensure_ascii=False)
            for marker in workload_markers:
                if marker in spec:
                    fail(f"live {context}/{namespace}: unrelated Pod {pod.get('metadata', {}).get('name')} inherits {marker}")

        config_maps = json.loads(kubectl("get", "configmaps", "-o", "json"))
        for config_map in config_maps.get("items", []):
            data = json.dumps(config_map.get("data", {}), ensure_ascii=False)
            for marker in [kek_dir, *env_names]:
                if marker in data:
                    fail(f"live {context}/{namespace}: ConfigMap {config_map.get('metadata', {}).get('name')} contains {marker}")

        kubectl(
            "exec",
            "deployment/codewire-idp",
            "-c",
            "idp",
            "--",
            "/bin/sh",
            "-ceu",
            f'test "$IDP_SIGNING_KEK_DIR" = "{kek_dir}"; '
            f'test "$IDP_SIGNING_ACTIVE_KEK_ID" = "{default_active_id}"; '
            'test -r "$IDP_SIGNING_KEK_DIR/$IDP_SIGNING_ACTIVE_KEK_ID"; '
            'test "$(wc -c < "$IDP_SIGNING_KEK_DIR/$IDP_SIGNING_ACTIVE_KEK_ID")" -eq 64',
        )
        print(
            f"idp signing KEK isolation: live kind OK ({context}/{namespace}; "
            f"{len(deployment_list.get('items', [])) - 1} unrelated Deployment and "
            f"{len(pod_list.get('items', [])) - idp_pod_count} unrelated Pod spec(s) excluded)"
        )

    try:
        for overlay in overlays:
            assert_static_overlay(overlay)
        if args.live:
            assert_live_kind()
    except Exception as error:  # noqa: BLE001 - repo check script
        fail(str(error))

    if failures:
        for failure in failures:
            print(f"::error::idp signing KEK isolation: {failure}", file=sys.stderr)
        return 1
    print(f"idp signing KEK isolation: static OK ({len(overlays)} rendered target(s))")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Codewire repository policy checks")
    subparsers = parser.add_subparsers(dest="command", required=True)

    edge_parser = subparsers.add_parser("connect-edge-routing")
    edge_parser.add_argument("--self-test", action="store_true")
    edge_parser.set_defaults(func=check_connect_edge_routing)
    subparsers.add_parser("openapi-check-source").set_defaults(func=check_openapi_contract_source)
    subparsers.add_parser("openapi-preview-check").set_defaults(func=check_rust_openapi_preview)
    export_parser = subparsers.add_parser("openapi-preview-export")
    export_parser.add_argument("--output")
    export_parser.add_argument("--openapi", default="3.1.0")
    export_parser.set_defaults(func=export_rust_openapi_preview)
    subparsers.add_parser("openapi-preview-types-check").set_defaults(func=check_rust_openapi_types)
    subparsers.add_parser("openapi-check-rust-source").set_defaults(func=check_rust_openapi_source)
    rest_parser = subparsers.add_parser("rest-surface-freeze")
    rest_parser.add_argument("--update", action="store_true")
    rest_parser.set_defaults(func=check_rest_surface_freeze)
    mesh_parser = subparsers.add_parser("mesh-surface-freeze")
    mesh_parser.add_argument("--self-test", action="store_true")
    mesh_parser.set_defaults(func=check_mesh_surface_freeze)
    subparsers.add_parser("license-map").set_defaults(func=check_license_map)
    subparsers.add_parser("rust-validation-source").set_defaults(func=check_rust_validation_source)
    subparsers.add_parser("retired-reference-source").set_defaults(func=check_retired_reference_source)
    subparsers.add_parser("go-source-classification").set_defaults(func=check_go_source_classification)
    prod_parser = subparsers.add_parser("production-source-ownership")
    prod_parser.add_argument("--self-test", action="store_true")
    prod_parser.add_argument("--root", default=str(ROOT))
    prod_parser.set_defaults(func=check_production_source_ownership)
    host_key_parser = subparsers.add_parser("orchestration-host-key-authz")
    host_key_parser.add_argument("--self-test", action="store_true")
    host_key_parser.set_defaults(func=check_orchestration_host_key_authz)
    idp_parser = subparsers.add_parser("idp-signing-kek-isolation")
    idp_parser.add_argument("--live", action="store_true")
    idp_parser.add_argument("--context", default="kind-codewire")
    idp_parser.add_argument("--namespace", default="default")
    idp_parser.set_defaults(func=check_idp_signing_kek_isolation)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
