from .shared import *
from .mesh import (
    check_mesh_surface_freeze,
    endpoint_path_defaults,
    route_registrations,
    sanitize_rust_source,
)



# ---------------------------------------------------------------------------
# Permanent control-plane raw surface guard


PERMANENT_RAW_POLICY_REL = "scripts/checks/contracts/permanent-raw-surface-policy.json"
PERMANENT_RAW_SERVICE_ROOTS = (
    "crates/codewire-orchestration",
    "crates/codewire-billing",
    "crates/codewire-idp",
    "crates/codewire-coordinator",
)
PERMANENT_RAW_OIDC_TRANSPORT = "crates/codewire-oidc/src/transport.rs"
PERMANENT_RAW_OIDC_DEFAULTS = "crates/codewire-oidc/src/discovery.rs"
PERMANENT_RAW_CLIENT_ROOTS = (
    "apps/dashboard/src/",
    "apps/ios/Sources/",
    "crates/codewire-cli/src/",
    "crates/codewire-client/src/",
    "crates/codewire-desktop/src/",
    "libs/sdk-go/",
    "libs/sdk-python/",
    "libs/sdk-ts/",
)
PERMANENT_RAW_CLIENT_SUFFIXES = {".go", ".py", ".rs", ".swift", ".ts", ".tsx"}
RETIRED_OPENAPI_PATHS = (
    "openapi.json",
    "crates/codewire-api-contract/",
    "crates/codewire-api-types/",
    "crates/codewire-core/",
    "libs/api-client-go/",
    "libs/api-client-python/",
    "libs/api-client-ts/",
    "packages/codewire-types/",
)
PERMANENT_RAW_POLICY_KEYS = {
    "$comment",
    "schema_version",
    "allowed_raw_routes",
    "required_server_fragments",
    "oidc_config_route_count",
    "client_raw_v1_suffixes",
}


def check_permanent_raw_surface(args: argparse.Namespace) -> int:
    try:
        policy = load_permanent_raw_policy()
        sources = permanent_raw_service_sources()
        client_sources = permanent_raw_client_sources()
        failures = permanent_raw_surface_failures(sources, policy, client_sources)
        if not failures and args.self_test:
            permanent_raw_surface_self_test(sources, policy, client_sources)
    except Exception as error:  # noqa: BLE001 - repository guard boundary
        failures = [str(error)]

    if failures:
        for failure in failures:
            print(f"permanent raw surface: {failure}", file=sys.stderr)
        return 1
    mesh_result = check_mesh_surface_freeze(argparse.Namespace(self_test=True))
    if mesh_result != 0:
        return mesh_result
    print(
        "permanent raw surface: OK "
        f"({len(policy['allowed_raw_routes'])} approved raw routes; Connect owns the remainder)"
    )
    return 0


def load_permanent_raw_policy() -> dict[str, Any]:
    policy = read_json(PERMANENT_RAW_POLICY_REL)
    if not isinstance(policy, dict) or set(policy) != PERMANENT_RAW_POLICY_KEYS:
        raise RuntimeError(
            "permanent raw policy keys must be exactly "
            f"{stable_json(sorted(PERMANENT_RAW_POLICY_KEYS))}"
        )
    if policy.get("schema_version") != 1:
        raise RuntimeError("permanent raw policy schema_version must equal 1")
    if not isinstance(policy.get("$comment"), str) or not policy["$comment"].strip():
        raise RuntimeError("permanent raw policy must have a non-empty $comment")
    for key in ("allowed_raw_routes", "client_raw_v1_suffixes"):
        values = policy.get(key)
        if not isinstance(values, list) or not values or not all(
            isinstance(value, str) and value.startswith("/") for value in values
        ):
            raise RuntimeError(f"permanent raw policy {key} must be a non-empty route list")
        if len(values) != len(set(values)):
            raise RuntimeError(f"permanent raw policy {key} contains duplicate values")
    fragments = policy.get("required_server_fragments")
    if not isinstance(fragments, dict) or not fragments:
        raise RuntimeError("permanent raw policy requires server fragments for every binary")
    for rel, values in fragments.items():
        if (
            not isinstance(rel, str)
            or not rel.startswith("crates/")
            or not isinstance(values, list)
            or not values
            or not all(isinstance(value, str) and value for value in values)
        ):
            raise RuntimeError("permanent raw policy server fragments are malformed")
    count = policy.get("oidc_config_route_count")
    if not isinstance(count, int) or count <= 0:
        raise RuntimeError("permanent raw policy oidc_config_route_count must be positive")
    return policy


def permanent_raw_service_sources() -> dict[str, str]:
    sources: dict[str, str] = {}
    for root in PERMANENT_RAW_SERVICE_ROOTS:
        for path in walk_files(ROOT / root / "src"):
            if path.suffix == ".rs":
                sources[path.relative_to(ROOT).as_posix()] = path.read_text(encoding="utf-8")
    for rel in (PERMANENT_RAW_OIDC_TRANSPORT, PERMANENT_RAW_OIDC_DEFAULTS):
        sources[rel] = read_text(rel)
    return sources


def is_permanent_raw_client_source(rel_path: str) -> bool:
    path = Path(rel_path)
    if not rel_path.startswith(PERMANENT_RAW_CLIENT_ROOTS):
        return False
    if path.suffix not in PERMANENT_RAW_CLIENT_SUFFIXES:
        return False
    if any(part in {"fixtures", "test", "tests"} for part in path.parts):
        return False
    if path.name.startswith("test_") or path.name.endswith(
        ("_test.go", "_test.py", "_test.rs", ".test.ts", ".test.tsx", ".spec.ts", ".spec.tsx")
    ):
        return False
    return rel_path not in {
        "apps/dashboard/src/routeTree.gen.ts",
        "apps/dashboard/src/routes/api/v1/$.ts",
    }


def permanent_raw_client_sources(source_corpus: dict[str, str] | None = None) -> dict[str, str]:
    if source_corpus is None:
        source_corpus = {
            rel_path: (ROOT / rel_path).read_text(encoding="utf-8")
            for rel_path in git_source_files()
            if is_permanent_raw_client_source(rel_path)
        }
    return {
        rel_path: source
        for rel_path, source in source_corpus.items()
        if is_permanent_raw_client_source(rel_path)
    }


def permanent_raw_surface_failures(
    sources: dict[str, str], policy: dict[str, Any], client_sources: dict[str, str]
) -> list[str]:
    failures: list[str] = []
    for rel in git_source_files():
        if any(rel == path or rel.startswith(path) for path in RETIRED_OPENAPI_PATHS):
            failures.append(f"retired OpenAPI source path was restored: {rel}")
    routes = {"/healthz", "/readyz"}
    oidc_non_literal = 0

    for rel, source in sorted(sources.items()):
        sanitized = sanitize_rust_source(source)
        for match in re.finditer(r"\.(?:nest|nest_service|route_service)\s*\(", sanitized):
            failures.append(
                f"{rel}:{line_number(source, match.start())} hides a raw route behind {match.group(0)[:-1]}"
            )
        for index, path in route_registrations(sanitized):
            if path is None:
                if rel == PERMANENT_RAW_OIDC_TRANSPORT:
                    oidc_non_literal += 1
                else:
                    failures.append(
                        f"{rel}:{line_number(source, index)} has a non-literal raw route registration"
                    )
            elif path.startswith("/"):
                routes.add(path)

    oidc_defaults = endpoint_path_defaults(sanitize_rust_source(sources[PERMANENT_RAW_OIDC_DEFAULTS]))
    if len(oidc_defaults) != policy["oidc_config_route_count"]:
        failures.append(
            f"{PERMANENT_RAW_OIDC_DEFAULTS} declares {len(oidc_defaults)} OIDC paths; expected "
            f"{policy['oidc_config_route_count']}"
        )
    if oidc_non_literal != policy["oidc_config_route_count"]:
        failures.append(
            f"{PERMANENT_RAW_OIDC_TRANSPORT} has {oidc_non_literal} config-mounted routes; expected "
            f"{policy['oidc_config_route_count']}"
        )
    routes.update(oidc_defaults)

    allowed = set(policy["allowed_raw_routes"])
    unexpected = sorted(routes - allowed)
    missing = sorted(allowed - routes)
    if unexpected:
        failures.append(f"unapproved raw routes: {stable_json(unexpected)}")
    if missing:
        failures.append(f"approved raw routes are no longer mounted: {stable_json(missing)}")

    for rel, fragments in policy["required_server_fragments"].items():
        path = ROOT / rel
        if not path.is_file():
            failures.append(f"serving binary source is missing: {rel}")
            continue
        source = path.read_text(encoding="utf-8")
        for fragment in fragments:
            if fragment not in source:
                failures.append(f"{rel} lost required serving shape {fragment!r}")

    for rel, source in sorted(client_sources.items()):
        sanitized = sanitize_rust_source(source) if rel.endswith(".rs") else source
        for match in re.finditer(r"/api/v1/[A-Za-z0-9_./${}?=-]+", sanitized):
            fragment = match.group(0)
            if not any(suffix in fragment for suffix in policy["client_raw_v1_suffixes"]):
                failures.append(f"{rel} formats retired control-plane URL {fragment!r}")

    return failures


def permanent_raw_surface_self_test(
    sources: dict[str, str], policy: dict[str, Any], client_sources: dict[str, str]
) -> None:
    # Admit only the browser confirmation transport, never a family of raw
    # credential APIs. Preserve the old-policy failure and sibling rejection.
    preview_route = "/api/v1/preview-auth/authorize"
    prior_preview_policy = dict(policy)
    prior_preview_policy["allowed_raw_routes"] = [
        route for route in policy["allowed_raw_routes"] if route != preview_route
    ]
    if not any(
        failure.startswith("unapproved raw routes:") and preview_route in failure
        for failure in permanent_raw_surface_failures(sources, prior_preview_policy, client_sources)
    ):
        raise RuntimeError("permanent raw guard lost the exact preview-route admission proof")
    unknown_preview = dict(sources)
    unknown_preview["crates/codewire-orchestration/src/unapproved_preview.rs"] = (
        'fn unapproved() { Router::new().route("/api/v1/preview-auth/tokens", get(handler)); }'
    )
    if not permanent_raw_surface_failures(unknown_preview, policy, client_sources):
        raise RuntimeError("permanent raw guard accepted an unapproved preview credential API")

    # The cookie-owned IdP inventory is an explicit identity boundary, not a
    # wildcard exception for new control-plane or authentication procedures.
    session_routes = {"/api/auth/sessions", "/api/auth/sessions/revoke"}
    prior_policy = dict(policy)
    prior_policy["allowed_raw_routes"] = [
        route for route in policy["allowed_raw_routes"] if route not in session_routes
    ]
    prior_failures = permanent_raw_surface_failures(sources, prior_policy, client_sources)
    if not any(
        failure.startswith("unapproved raw routes:")
        and all(route in failure for route in session_routes)
        for failure in prior_failures
    ):
        raise RuntimeError("permanent raw guard lost the exact session-route admission proof")
    unknown_identity = dict(sources)
    unknown_identity["crates/codewire-idp/src/restored_session.rs"] = (
        'fn restored() { Router::new().route("/api/auth/sessions/unapproved", get(handler)); }'
    )
    if not permanent_raw_surface_failures(unknown_identity, policy, client_sources):
        raise RuntimeError("permanent raw guard accepted an unapproved identity route")

    restored_route = dict(sources)
    restored_route["crates/codewire-orchestration/src/restored_raw.rs"] = (
        'fn restored() { Router::new().route("/api/v1/restored", get(handler)); }'
    )
    if not permanent_raw_surface_failures(restored_route, policy, client_sources):
        raise RuntimeError("permanent raw guard accepted a restored control-plane route")

    restored_client = dict(client_sources)
    restored_client["libs/sdk-ts/src/restored-raw.ts"] = (
        'export const restored = "/api/v1/organizations";\n'
    )
    if not permanent_raw_surface_failures(
        sources, policy, permanent_raw_client_sources(restored_client)
    ):
        raise RuntimeError("permanent raw guard accepted a restored client REST URL")
