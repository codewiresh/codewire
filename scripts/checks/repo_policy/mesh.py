from .shared import *

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
# Final Mesh surface guard


MESH_FINAL_POLICY_REL = "scripts/checks/contracts/mesh-final-surface-policy.json"
MESH_SERVER_REL = "crates/codewire-mesh/src/server.rs"
MESH_CONNECT_REL = "crates/codewire-mesh/src/connect.rs"
MESH_FINAL_POLICY_KEYS = {
    "$comment",
    "schema_version",
    "required_server_fragments",
    "forbidden_server_fragments",
    "required_source_fragments",
    "forbidden_source_fragments",
    "absent_paths",
    "forbidden_edge_fragments",
}
MESH_FINAL_CLIENT_SOURCE_ROOTS = (
    "apps/desktop/",
    "apps/ios/",
    "crates/codewire-cli/src/",
    "crates/codewire-client/",
    "crates/codewire-dashboard-web/",
    "crates/codewire-desktop/",
    "libs/sdk-go/",
    "libs/sdk-python/",
    "libs/sdk-ts/",
)
MESH_FINAL_CLIENT_SOURCE_SUFFIXES = {".go", ".py", ".rs", ".ts", ".tsx"}
MESH_FINAL_CLIENT_IGNORED_PARTS = {"fixtures", "test", "tests"}
MESH_RAW_ROUTER_METHODS = (
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
    "with_connect_routes_auth",
    "with_connect_routes_auth_and_protocol_policy",
    "with_unary_connect_routes_auth",
    "with_routes",
)
MESH_RAW_ROUTER_METHOD_PATTERN = "|".join(MESH_RAW_ROUTER_METHODS)
MESH_RETIRED_CLIENT_PATH_FRAGMENTS = (
    "/api/v1/nodes",
    "/api/v1/groups",
    "/api/v1/invites",
    "/api/v1/kv",
    "/api/v1/networks",
    "/api/v1/node-enrollments",
    "/api/v1/network-auth",
    "/api/v1/tailnet/coordinate",
    "/auth/oidc",
    "/auth/session",
    "/join",
)
MESH_CONTRACT_PROTO_FILES = (
    "proto/codewire/v1/mesh_network.proto",
    "proto/codewire/v1/mesh_node.proto",
    "proto/codewire/v1/mesh_invite.proto",
    "proto/codewire/v1/mesh_group.proto",
    "proto/codewire/v1/mesh_kv.proto",
    "proto/codewire/internal/v1/mesh_authorization.proto",
    "proto/codewire/internal/v1/coordinate.proto",
)
MESH_PUBLIC_SERVICE_METHODS = {
    "MeshNetworkService": {
        "ListMeshNetworks",
        "CreateMeshNetwork",
        "JoinMeshNetwork",
    },
    "MeshNodeService": {
        "ListMeshNodes",
        "RevokeMeshNode",
        "CreateMeshNodeEnrollment",
        "RedeemMeshNodeEnrollment",
    },
    "MeshInviteService": {
        "ListMeshInvites",
        "CreateMeshInvite",
        "DeleteMeshInvite",
    },
    "MeshGroupService": {
        "ListMeshGroups",
        "CreateMeshGroup",
        "GetMeshGroup",
        "DeleteMeshGroup",
        "SetMeshGroupPolicy",
        "AddMeshGroupMember",
        "RemoveMeshGroupMember",
    },
    "MeshKeyValueService": {
        "ListMeshKeyValues",
        "GetMeshKeyValue",
        "SetMeshKeyValue",
        "DeleteMeshKeyValue",
    },
}
MESH_INTERNAL_SERVICE_METHODS = {
    "MeshAuthorizationService": {"ResolveMeshAuthorization"},
    "CoordinatorService": {"Coordinate"},
    "MeshCoordinatorService": {"Coordinate"},
}
# Every declared Mesh RPC carries an explicit expected idempotency posture.
# Internal reads must not escape the mechanical NO_SIDE_EFFECTS contract.
MESH_RPC_IDEMPOTENCY = {
    "MeshNetworkService": {
        "ListMeshNetworks": True,
        "CreateMeshNetwork": False,
        "JoinMeshNetwork": False,
    },
    "MeshNodeService": {
        "ListMeshNodes": True,
        "RevokeMeshNode": False,
        "CreateMeshNodeEnrollment": False,
        "RedeemMeshNodeEnrollment": False,
    },
    "MeshInviteService": {
        "ListMeshInvites": True,
        "CreateMeshInvite": False,
        "DeleteMeshInvite": False,
    },
    "MeshGroupService": {
        "ListMeshGroups": True,
        "CreateMeshGroup": False,
        "GetMeshGroup": True,
        "DeleteMeshGroup": False,
        "SetMeshGroupPolicy": False,
        "AddMeshGroupMember": False,
        "RemoveMeshGroupMember": False,
    },
    "MeshKeyValueService": {
        "ListMeshKeyValues": True,
        "GetMeshKeyValue": True,
        "SetMeshKeyValue": False,
        "DeleteMeshKeyValue": False,
    },
    "MeshAuthorizationService": {"ResolveMeshAuthorization": True},
    "CoordinatorService": {"Coordinate": False},
    "MeshCoordinatorService": {"Coordinate": False},
}
MESH_ORG_OWNED_RESOURCES = {
    "MeshNetwork",
    "MeshNode",
    "MeshNodeEnrollment",
    "MeshInvite",
    "MeshGroup",
    "MeshGroupMember",
    "MeshGroupPolicy",
    "MeshKeyValue",
}
MESH_ORG_SCOPED_REQUESTS = {
    "ListMeshNetworksRequest",
    "CreateMeshNetworkRequest",
    "ListMeshNodesRequest",
    "RevokeMeshNodeRequest",
    "CreateMeshNodeEnrollmentRequest",
    "ListMeshInvitesRequest",
    "CreateMeshInviteRequest",
    "DeleteMeshInviteRequest",
    "ListMeshGroupsRequest",
    "CreateMeshGroupRequest",
    "GetMeshGroupRequest",
    "DeleteMeshGroupRequest",
    "SetMeshGroupPolicyRequest",
    "AddMeshGroupMemberRequest",
    "RemoveMeshGroupMemberRequest",
    "ListMeshKeyValuesRequest",
    "GetMeshKeyValueRequest",
    "SetMeshKeyValueRequest",
    "DeleteMeshKeyValueRequest",
}
PROTO_TS_EXPORTS = {
    ".": "./src/index.ts",
    "./gen/codewire/v1/*": "./src/gen/codewire/v1/*.ts",
    "./gen/codewire/console/v1/*": "./src/gen/codewire/console/v1/*.ts",
    "./gen/codewire/admin/v1/*": "./src/gen/codewire/admin/v1/*.ts",
    "./gen/google/rpc/*": "./src/gen/google/rpc/*.ts",
}
MESH_EXPECTED_CONNECT_METHODS = {
    "MESH_NETWORK_SERVICE_SERVICE_NAME": {
        "CreateMeshNetwork",
        "JoinMeshNetwork",
        "ListMeshNetworks",
    },
    "MESH_NODE_SERVICE_SERVICE_NAME": {
        "CreateMeshNodeEnrollment",
        "ListMeshNodes",
        "RedeemMeshNodeEnrollment",
        "RevokeMeshNode",
    },
    "MESH_INVITE_SERVICE_SERVICE_NAME": {
        "CreateMeshInvite",
        "DeleteMeshInvite",
        "ListMeshInvites",
    },
    "MESH_GROUP_SERVICE_SERVICE_NAME": {
        "AddMeshGroupMember",
        "CreateMeshGroup",
        "DeleteMeshGroup",
        "GetMeshGroup",
        "ListMeshGroups",
        "RemoveMeshGroupMember",
        "SetMeshGroupPolicy",
    },
    "MESH_KEY_VALUE_SERVICE_SERVICE_NAME": {
        "DeleteMeshKeyValue",
        "GetMeshKeyValue",
        "ListMeshKeyValues",
        "SetMeshKeyValue",
    },
}
def check_mesh_surface_freeze(args: argparse.Namespace) -> int:
    try:
        policy = load_mesh_final_surface_policy()
        mesh_sources = mesh_production_sources()
        client_sources = mesh_final_client_sources()
        failures = mesh_final_surface_failures(mesh_sources, policy, client_sources)
        if not failures and args.self_test:
            mesh_final_surface_self_test(mesh_sources, policy, client_sources)
    except Exception as error:  # noqa: BLE001 - this is a repository guard
        failures = [str(error)]

    if failures:
        for failure in failures:
            print(f"mesh final surface: {failure}", file=sys.stderr)
        return 1
    print(
        "mesh final surface: OK "
        "(generated product Connect, typed coordinator, health/readiness only)"
    )
    return 0


def load_mesh_final_surface_policy() -> dict[str, Any]:
    policy = read_json(MESH_FINAL_POLICY_REL)
    if not isinstance(policy, dict) or set(policy) != MESH_FINAL_POLICY_KEYS:
        raise RuntimeError(
            "final Mesh policy keys must be exactly "
            f"{stable_json(sorted(MESH_FINAL_POLICY_KEYS))}"
        )
    if policy.get("schema_version") != 1:
        raise RuntimeError("final Mesh policy schema_version must equal 1")
    if not isinstance(policy.get("$comment"), str) or not policy["$comment"].strip():
        raise RuntimeError("final Mesh policy must have a non-empty $comment")
    for key in ("required_server_fragments", "forbidden_server_fragments", "absent_paths"):
        values = policy.get(key)
        if not isinstance(values, list) or not values or not all(
            isinstance(value, str) and value for value in values
        ):
            raise RuntimeError(f"final Mesh policy {key} must be a non-empty string list")
    for key in (
        "required_source_fragments",
        "forbidden_source_fragments",
        "forbidden_edge_fragments",
    ):
        records = policy.get(key)
        if not isinstance(records, dict) or not records:
            raise RuntimeError(f"final Mesh policy {key} must be a non-empty object")
        for path, fragments in records.items():
            if (
                not isinstance(path, str)
                or not path
                or Path(path).is_absolute()
                or ".." in Path(path).parts
                or not isinstance(fragments, list)
                or not fragments
                or not all(isinstance(fragment, str) and fragment for fragment in fragments)
            ):
                raise RuntimeError(
                    f"final Mesh policy {key} must map repository-relative paths "
                    "to non-empty string lists"
                )
    return policy


def mesh_final_surface_failures(
    mesh_sources: dict[str, str],
    policy: dict[str, Any],
    client_sources: dict[str, str] | None = None,
) -> list[str]:
    failures: list[str] = []
    server_source = mesh_sources.get(MESH_SERVER_REL)
    if server_source is None:
        return [f"missing production Mesh router source {MESH_SERVER_REL}"]

    for fragment in policy["required_server_fragments"]:
        if fragment not in server_source:
            failures.append(f"Mesh router lost required final shape {fragment!r}")
    for fragment in policy["forbidden_server_fragments"]:
        if fragment in server_source:
            failures.append(f"Mesh router restored retired raw/auth shape {fragment!r}")
    for rel_path, source in sorted(mesh_sources.items()):
        sanitized = sanitize_rust_source(source)
        # `connectrpc::Router` is generated Connect composition, not Axum. It
        # may register generated procedures with `.route`, so only a raw
        # Router construction or a raw alternate mount is forbidden there.
        patterns = [
            (
                r"(?<!connectrpc::)\bRouter(?:\s*::<[^;(){}]+>)?::(?:new|default)\s*\(",
                "raw Router construction",
            ),
            (
                rf"\.({MESH_RAW_ROUTER_METHOD_PATTERN})\s*\(",
                "raw Axum alternate router mount",
            ),
        ]
        if rel_path != MESH_CONNECT_REL:
            patterns.extend(
                [
                    (r"\.route(?:_layer)?\s*\(", "raw route registration"),
                    (r"\.merge\s*\(", "raw router merge"),
                ]
            )
        for pattern, label in patterns:
            if re.search(pattern, sanitized):
                failures.append(f"{rel_path} restores {label}")

    mesh_connect_surface_failures(mesh_sources, server_source, failures)

    for policy_key, expectation in (
        ("required_source_fragments", True),
        ("forbidden_source_fragments", False),
        ("forbidden_edge_fragments", False),
    ):
        for source, fragments in policy[policy_key].items():
            text = mesh_sources.get(source)
            if text is None:
                path = ROOT / source
                if not path.is_file():
                    failures.append(f"final Mesh policy source is missing: {source}")
                    continue
                text = path.read_text(encoding="utf-8")
            for fragment in fragments:
                present = fragment in text
                if expectation and not present:
                    failures.append(f"{source} lost required final shape {fragment!r}")
                if not expectation and present:
                    failures.append(f"{source} restored retired Mesh shape {fragment!r}")

    for rel_path in policy["absent_paths"]:
        if (ROOT / rel_path).exists():
            failures.append(f"retired Mesh path remains present: {rel_path}")

    if client_sources is None:
        client_sources = mesh_final_client_sources()
    for source, text in sorted(client_sources.items()):
        for fragment in MESH_RETIRED_CLIENT_PATH_FRAGMENTS:
            if fragment in text:
                failures.append(
                    f"first-party Mesh client {source} retains raw Mesh path {fragment!r}"
                )
    return failures


def mesh_final_surface_self_test(
    mesh_sources: dict[str, str],
    policy: dict[str, Any],
    client_sources: dict[str, str],
) -> None:
    helper_route = dict(mesh_sources)
    helper_route["crates/codewire-mesh/src/raw_helper.rs"] = """
        use axum::{Router, routing::get};

        pub(crate) fn raw_helper_routes() -> Router {
            Router::new().route("/api/v1/restored", get(|| async { "no" }))
        }
    """
    if not mesh_final_surface_failures(helper_route, policy, client_sources):
        raise RuntimeError("final Mesh guard accepted a helper raw route")

    for method in (*MESH_RAW_ROUTER_METHODS, "merge"):
        restored_mount = dict(mesh_sources)
        original = restored_mount[MESH_SERVER_REL]
        if ".into_router()" not in original:
            raise RuntimeError("final Mesh router self-test cannot find into_router chain")
        restored_mount[MESH_SERVER_REL] = original.replace(
            ".into_router()",
            f".into_router().{method}(retired_raw_handler)",
            1,
        )
        if not mesh_final_surface_failures(restored_mount, policy, client_sources):
            raise RuntimeError(
                f"final Mesh guard accepted a raw {method} mount after into_router"
            )

    removed_connect = dict(mesh_sources)
    removed_connect[MESH_SERVER_REL] = removed_connect[MESH_SERVER_REL].replace(
        '.with_connect_routes(crate::connect::router(state.clone()))',
        '.with_connect_routes(connectrpc::Router::new())',
    )
    if not mesh_final_surface_failures(removed_connect, policy, client_sources):
        raise RuntimeError("final Mesh guard accepted a missing generated Connect mount")

    restored_client_corpus = dict(client_sources)
    restored_client_path = "libs/sdk-ts/src/restored-mesh-client.ts"
    restored_client_corpus[restored_client_path] = (
        'export const restoredMeshPath = "/api/v1/networks";\n'
    )
    restored_clients = mesh_final_client_sources(restored_client_corpus)
    if restored_client_path not in restored_clients:
        raise RuntimeError("final Mesh guard did not discover a new first-party client")
    if not mesh_final_surface_failures(mesh_sources, policy, restored_clients):
        raise RuntimeError("final Mesh guard accepted a new first-party raw Mesh client")

    store_rel = "crates/codewire-mesh/src/store.rs"
    atomic_create = "async fn network_create_with_owner("
    legacy_create = "async fn network_create_owned("
    store_source = mesh_sources.get(store_rel)
    if store_source is None or atomic_create not in store_source:
        raise RuntimeError("final Mesh guard self-test cannot find atomic owner creation")
    restored_split_create = dict(mesh_sources)
    restored_split_create[store_rel] = store_source.replace(atomic_create, legacy_create)
    split_failures = mesh_final_surface_failures(
        restored_split_create, policy, client_sources
    )
    if not any(atomic_create in failure for failure in split_failures):
        raise RuntimeError("final Mesh guard accepted removal of atomic owner creation")
    if not any(legacy_create in failure for failure in split_failures):
        raise RuntimeError("final Mesh guard accepted restored split network creation")


def mesh_final_client_sources(
    source_corpus: dict[str, str] | None = None,
) -> dict[str, str]:
    if source_corpus is None:
        source_corpus = {
            rel_path: (ROOT / rel_path).read_text(encoding="utf-8")
            for rel_path in git_source_files()
            if is_mesh_final_client_source_path(rel_path)
        }
    sources: dict[str, str] = {}
    for rel_path, source in source_corpus.items():
        if not is_mesh_final_client_source_path(rel_path):
            continue
        sources[rel_path] = source
    if not sources:
        raise RuntimeError("final Mesh guard found no tracked first-party client sources")
    return sources


def is_mesh_final_client_source_path(rel_path: str) -> bool:
    path = Path(rel_path)
    if not rel_path.startswith(MESH_FINAL_CLIENT_SOURCE_ROOTS):
        return False
    if path.suffix not in MESH_FINAL_CLIENT_SOURCE_SUFFIXES:
        return False
    if any(part in MESH_FINAL_CLIENT_IGNORED_PARTS for part in path.parts):
        return False
    return not path.name.startswith("test_") and not path.name.endswith(
        (
            "_test.go",
            "_test.py",
            "_test.rs",
            ".test.ts",
            ".test.tsx",
            ".spec.ts",
            ".spec.tsx",
        )
    )


def mesh_production_sources() -> dict[str, str]:
    return {
        path.relative_to(ROOT).as_posix(): path.read_text(encoding="utf-8")
        for path in walk_files(ROOT / "crates/codewire-mesh/src")
        if path.suffix == ".rs"
    }


def mesh_connect_surface_failures(
    mesh_sources: dict[str, str], server_source: str, failures: list[str]
) -> None:
    connect_source = mesh_sources.get(MESH_CONNECT_REL)
    if connect_source is None:
        failures.append(f"missing generated Mesh Connect router {MESH_CONNECT_REL}")
        return
    sanitized = sanitize_rust_source(connect_source)
    expected_methods = {
        method
        for methods in MESH_EXPECTED_CONNECT_METHODS.values()
        for method in methods
    }
    actual_methods = set(
        re.findall(
            r'\.route(?:_idempotent)?\(\s*[A-Z0-9_]+\s*,\s*"([^"]+)"',
            sanitized,
        )
    )
    if actual_methods != expected_methods:
        failures.append(
            "retained Mesh Connect method set drift: "
            f"found {stable_json(sorted(actual_methods))}"
        )
    if len(re.findall(r"\.with_spec\(\s*[A-Z0-9_]+\s*\)", sanitized)) != len(
        expected_methods
    ):
        failures.append("retained Mesh Connect generated spec bindings drift")
    if len(re.findall(r"\.with_connect_routes\s*\(", server_source)) != 1:
        failures.append("Mesh must mount the generated product Connect router exactly once")

    coordinate_source = mesh_sources.get("crates/codewire-mesh/src/mesh_coordinate.rs")
    if coordinate_source is None:
        failures.append("missing typed Mesh coordinator service")
    else:
        for fragment in (
            "impl MeshCoordinatorService for MeshCoordinateService",
            "MeshCoordinatorServiceCoordinateRequest",
            "authorize_coordinate(&org_id, &network_id, credential)",
        ):
            if fragment not in coordinate_source:
                failures.append(
                    f"typed Mesh coordinator lost required shape {fragment!r}"
                )
