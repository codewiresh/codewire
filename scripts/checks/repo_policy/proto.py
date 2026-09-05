from .shared import *
from .mesh import (
    MESH_CONTRACT_PROTO_FILES,
    MESH_INTERNAL_SERVICE_METHODS,
    MESH_ORG_OWNED_RESOURCES,
    MESH_ORG_SCOPED_REQUESTS,
    MESH_PUBLIC_SERVICE_METHODS,
    MESH_RPC_IDEMPOTENCY,
    PROTO_TS_EXPORTS,
)

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


def strip_proto_comments(source: str) -> str:
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.DOTALL)
    return re.sub(r"//[^\n]*", "", source)


def proto_named_blocks(source: str, keyword: str) -> dict[str, str]:
    source = strip_proto_comments(source)
    blocks: dict[str, str] = {}
    expression = re.compile(rf"\b{re.escape(keyword)}\s+([A-Za-z][A-Za-z0-9_]*)\s*\{{")
    for match in expression.finditer(source):
        depth = 1
        cursor = match.end()
        while cursor < len(source) and depth:
            if source[cursor] == "{":
                depth += 1
            elif source[cursor] == "}":
                depth -= 1
            cursor += 1
        if depth:
            raise RuntimeError(f"unterminated {keyword} {match.group(1)}")
        blocks[match.group(1)] = source[match.end() : cursor - 1]
    return blocks


def proto_rpc_annotations(service_body: str) -> dict[str, bool]:
    expression = re.compile(
        r"\brpc\s+([A-Za-z][A-Za-z0-9_]*)\s*"
        r"\(\s*(?:stream\s+)?[.A-Za-z0-9_]+\s*\)\s*"
        r"returns\s*\(\s*(?:stream\s+)?[.A-Za-z0-9_]+\s*\)\s*"
        r"(\{[^{}]*\}|;)",
        re.DOTALL,
    )
    return {
        match.group(1): "idempotency_level = NO_SIDE_EFFECTS" in match.group(2)
        for match in expression.finditer(service_body)
    }


def proto_field_names(message_body: str) -> set[str]:
    expression = re.compile(
        r"^\s*(?:optional\s+|repeated\s+)?"
        r"(?:map\s*<[^>]+>|[.A-Za-z][.A-Za-z0-9_]*)\s+"
        r"([a-z][a-z0-9_]*)\s*=\s*[0-9]+\s*(?:\[[^\]]*\]\s*)?;",
        re.MULTILINE,
    )
    return {match.group(1) for match in expression.finditer(message_body)}


def proto_debug_redacted_field_names(message_body: str) -> set[str]:
    expression = re.compile(
        r"^\s*(?:optional\s+|repeated\s+)?"
        r"(?:map\s*<[^>]+>|[.A-Za-z][.A-Za-z0-9_]*)\s+"
        r"([a-z][a-z0-9_]*)\s*=\s*[0-9]+\s*"
        r"\[([^\]]*)\]\s*;",
        re.MULTILINE,
    )
    return {
        match.group(1)
        for match in expression.finditer(message_body)
        if re.search(r"(?:^|,)\s*debug_redact\s*=\s*true\s*(?:,|$)", match.group(2))
    }


def proto_package_boundary_failures(
    proto_sources: dict[str, str],
    ts_manifest: dict[str, Any],
    ts_index: str,
    python_manifest: dict[str, Any],
    sdk_sources: dict[str, str],
) -> list[str]:
    failures: list[str] = []
    services: dict[str, dict[str, bool]] = {}
    messages: dict[str, set[str]] = {}
    debug_redacted_fields: set[tuple[str, str]] = set()

    for rel, source in proto_sources.items():
        package_match = re.search(r"^\s*package\s+([.a-z0-9]+)\s*;", source, re.MULTILINE)
        expected_package = (
            "codewire.internal.v1"
            if "/internal/v1/" in rel
            else "codewire.v1"
        )
        if package_match is None or package_match.group(1) != expected_package:
            failures.append(f"{rel}: expected package {expected_package}")
        for name, body in proto_named_blocks(source, "service").items():
            if name in services:
                failures.append(f"duplicate Mesh service declaration {name}")
            services[name] = proto_rpc_annotations(body)
        for name, body in proto_named_blocks(source, "message").items():
            if name in messages:
                failures.append(f"duplicate Mesh message declaration {name}")
            messages[name] = proto_field_names(body)
            debug_redacted_fields.update(
                (name, field) for field in proto_debug_redacted_field_names(body)
            )

    expected_services = {
        **MESH_PUBLIC_SERVICE_METHODS,
        **MESH_INTERNAL_SERVICE_METHODS,
    }
    if set(services) != set(expected_services):
        failures.append(
            "Mesh service set differs: "
            f"actual={sorted(services)}, expected={sorted(expected_services)}"
        )
    for service, expected_methods in expected_services.items():
        actual_methods = set(services.get(service, {}))
        if actual_methods != expected_methods:
            failures.append(
                f"{service} methods differ: "
                f"actual={sorted(actual_methods)}, expected={sorted(expected_methods)}"
            )

    public_method_count = sum(
        len(services.get(service, {})) for service in MESH_PUBLIC_SERVICE_METHODS
    )
    if public_method_count != 21:
        failures.append(f"public Mesh RPC count is {public_method_count}, expected 21")

    if services != MESH_RPC_IDEMPOTENCY:
        failures.append(
            "Mesh RPC idempotency classification differs: "
            f"actual={services}, expected={MESH_RPC_IDEMPOTENCY}"
        )

    for name in sorted(MESH_ORG_OWNED_RESOURCES | MESH_ORG_SCOPED_REQUESTS):
        if "org_id" not in messages.get(name, set()):
            failures.append(f"{name} must carry explicit org_id ownership")

    redeem_fields = messages.get("RedeemMeshNodeEnrollmentResponse", set())
    if redeem_fields != {"node", "enrollment"}:
        failures.append(
            "RedeemMeshNodeEnrollmentResponse must contain only node and enrollment metadata"
        )

    expected_capability_fields = {
        ("CreateMeshInviteResponse", "invite_code"),
        ("JoinMeshNetworkRequest", "invite_code"),
        ("CreateMeshNodeEnrollmentResponse", "enrollment_code"),
        ("RedeemMeshNodeEnrollmentRequest", "enrollment_code"),
    }
    actual_capability_fields = {
        (message, field)
        for message, fields in messages.items()
        for field in fields
        if field.endswith("_code")
    }
    if actual_capability_fields != expected_capability_fields:
        failures.append(
            "one-use capability fields differ: "
            f"actual={sorted(actual_capability_fields)}, "
            f"expected={sorted(expected_capability_fields)}"
        )
    unredacted_capability_fields = expected_capability_fields - debug_redacted_fields
    if unredacted_capability_fields:
        failures.append(
            "one-use capability fields must set debug_redact = true: "
            f"missing={sorted(unredacted_capability_fields)}"
        )
    for message in ["MeshInvite", "MeshNodeEnrollment"]:
        legacy_count_fields = messages.get(message, set()) & {"uses", "uses_remaining"}
        if legacy_count_fields:
            failures.append(
                f"{message} retains legacy multi-use fields {sorted(legacy_count_fields)}"
            )
    for message in ["CreateMeshInviteRequest", "CreateMeshNodeEnrollmentRequest"]:
        if "uses" in messages.get(message, set()):
            failures.append(f"{message} must create exactly one-use capabilities")

    auth_context_fields = messages.get("MeshAuthorizationContext", set())
    expected_auth_context_fields = {
        "principal_id",
        "principal_kind",
        "org_id",
        "role",
        "credential_kind",
    }
    if auth_context_fields != expected_auth_context_fields:
        failures.append(
            "MeshAuthorizationContext fields differ: "
            f"actual={sorted(auth_context_fields)}, "
            f"expected={sorted(expected_auth_context_fields)}"
        )

    mesh_hello_fields = messages.get("MeshCoordinateHello", set())
    if mesh_hello_fields != {"org_id", "network_id", "role"}:
        failures.append(
            "MeshCoordinateHello must contain exactly org_id, network_id, and role"
        )

    for message, fields in sorted(messages.items()):
        for field in sorted(fields):
            pagination_token = field in {"page_token", "next_page_token"}
            raw_secret = (
                field == "token"
                or (field.endswith("_token") and not pagination_token)
                or field in {
                    "authorization",
                    "authorized",
                    "credential",
                    "credentials",
                    "scope",
                    "scopes",
                    "verifier_bundle",
                    "sender_delegation",
                }
                or ("credential" in field and field != "credential_kind")
            )
            if raw_secret:
                failures.append(f"{message}.{field}: forbidden raw auth/credential field")

    ts_exports = ts_manifest.get("exports")
    if ts_manifest.get("private") is not True:
        failures.append("TypeScript generated package must be private")
    if ts_exports != PROTO_TS_EXPORTS:
        failures.append(
            "TypeScript generated exports differ from the explicit first-party allowlist"
        )
    for match in re.finditer(r"""["'](\./gen/codewire/[^"']+)["']""", ts_index):
        if not match.group(1).startswith("./gen/codewire/v1/"):
            failures.append(
                f"TypeScript root exports forbidden non-public package {match.group(1)}"
            )

    python_wheel = (
        python_manifest.get("tool", {})
        .get("hatch", {})
        .get("build", {})
        .get("targets", {})
        .get("wheel", {})
    )
    if python_wheel.get("force-include"):
        failures.append(
            "Python wheel must not depend on repository-relative generated includes"
        )
    python_hooks = (
        python_manifest.get("tool", {})
        .get("hatch", {})
        .get("build", {})
        .get("hooks", {})
    )
    if python_hooks != {"custom": {}} or not (
        ROOT / "libs/sdk-python/hatch_build.py"
    ).is_file():
        failures.append("Python SDK must use the self-contained custom build hook")

    forbidden_sdk_package = re.compile(
        r"(?:codewire[./](?:admin|console|internal|testing)[./]v1"
        r"|@codewire/proto-ts/gen/codewire/(?!v1/))"
    )
    for rel, source in sorted(sdk_sources.items()):
        match = forbidden_sdk_package.search(source)
        if match:
            failures.append(
                f"{rel}: public SDK imports/exports forbidden generated package "
                f"{match.group(0)}"
            )

    return failures


def proto_package_boundary_self_test(
    proto_sources: dict[str, str],
    ts_manifest: dict[str, Any],
    ts_index: str,
    python_manifest: dict[str, Any],
    sdk_sources: dict[str, str],
) -> None:
    def require_failure(label: str, failures: list[str], needle: str) -> None:
        if not any(needle in failure for failure in failures):
            raise RuntimeError(f"self-test accepted {label}")

    missing_read = dict(proto_sources)
    missing_read["proto/codewire/v1/mesh_network.proto"] = missing_read[
        "proto/codewire/v1/mesh_network.proto"
    ].replace("    option idempotency_level = NO_SIDE_EFFECTS;\n", "", 1)
    require_failure(
        "a read RPC without NO_SIDE_EFFECTS",
        proto_package_boundary_failures(
            missing_read, ts_manifest, ts_index, python_manifest, sdk_sources
        ),
        "idempotency classification differs",
    )

    missing_internal_read = dict(proto_sources)
    missing_internal_read["proto/codewire/internal/v1/mesh_authorization.proto"] = (
        missing_internal_read["proto/codewire/internal/v1/mesh_authorization.proto"].replace(
            "    option idempotency_level = NO_SIDE_EFFECTS;\n", "", 1
        )
    )
    require_failure(
        "an internal read RPC without NO_SIDE_EFFECTS",
        proto_package_boundary_failures(
            missing_internal_read, ts_manifest, ts_index, python_manifest, sdk_sources
        ),
        "idempotency classification differs",
    )

    missing_org = dict(proto_sources)
    missing_org["proto/codewire/v1/mesh_network.proto"] = missing_org[
        "proto/codewire/v1/mesh_network.proto"
    ].replace("  string org_id = 2;\n", "  string tenant_id = 2;\n", 1)
    require_failure(
        "a resource without org_id",
        proto_package_boundary_failures(
            missing_org, ts_manifest, ts_index, python_manifest, sdk_sources
        ),
        "MeshNetwork must carry explicit org_id",
    )

    raw_token = dict(proto_sources)
    raw_token["proto/codewire/v1/mesh_node.proto"] = raw_token[
        "proto/codewire/v1/mesh_node.proto"
    ].replace(
        "  string peer_url = 4;\n",
        "  string peer_url = 4;\n  string node_token = 99;\n",
        1,
    )
    require_failure(
        "a persistent node bearer field",
        proto_package_boundary_failures(
            raw_token, ts_manifest, ts_index, python_manifest, sdk_sources
        ),
        "MeshNode.node_token",
    )

    unredacted_capability = dict(proto_sources)
    unredacted_capability["proto/codewire/v1/mesh_invite.proto"] = (
        unredacted_capability["proto/codewire/v1/mesh_invite.proto"].replace(
            "  string invite_code = 2 [debug_redact = true];\n",
            "  string invite_code = 2;\n",
            1,
        )
    )
    require_failure(
        "a one-use capability without debug redaction",
        proto_package_boundary_failures(
            unredacted_capability, ts_manifest, ts_index, python_manifest, sdk_sources
        ),
        "one-use capability fields must set debug_redact = true",
    )

    internal_export = copy.deepcopy(ts_manifest)
    internal_export["exports"]["./gen/codewire/internal/v1/*"] = (
        "./src/gen/codewire/internal/v1/*.ts"
    )
    require_failure(
        "an internal TypeScript deep export",
        proto_package_boundary_failures(
            proto_sources, internal_export, ts_index, python_manifest, sdk_sources
        ),
        "TypeScript generated exports differ",
    )

    repository_relative_python = copy.deepcopy(python_manifest)
    repository_relative_python["tool"]["hatch"]["build"]["targets"]["wheel"][
        "force-include"
    ] = {"../gen-python/codewire/v1": "codewire/v1"}
    require_failure(
        "a repository-relative Python generated include",
        proto_package_boundary_failures(
            proto_sources,
            ts_manifest,
            ts_index,
            repository_relative_python,
            sdk_sources,
        ),
        "must not depend on repository-relative generated includes",
    )

    missing_python_hook = copy.deepcopy(python_manifest)
    missing_python_hook["tool"]["hatch"]["build"]["hooks"] = {}
    require_failure(
        "a Python package without the self-contained build hook",
        proto_package_boundary_failures(
            proto_sources, ts_manifest, ts_index, missing_python_hook, sdk_sources
        ),
        "must use the self-contained custom build hook",
    )

    internal_import = dict(sdk_sources)
    internal_import["libs/sdk-ts/src/self-test-internal.ts"] = (
        'import "@codewire/proto-ts/gen/codewire/internal/v1/coordinate_pb";\n'
    )
    require_failure(
        "a public SDK internal-package import",
        proto_package_boundary_failures(
            proto_sources, ts_manifest, ts_index, python_manifest, internal_import
        ),
        "public SDK imports/exports forbidden",
    )


def check_proto_package_boundaries(args: argparse.Namespace) -> int:
    try:
        proto_sources = {rel: read_text(rel) for rel in MESH_CONTRACT_PROTO_FILES}
        ts_manifest = read_json("packages/codewire-proto-ts/package.json")
        ts_index = read_text("packages/codewire-proto-ts/src/index.ts")
        with (ROOT / "libs/sdk-python/pyproject.toml").open("rb") as handle:
            python_manifest = tomllib.load(handle)
        sdk_sources = {
            rel: read_text(rel)
            for rel in git_source_files()
            if (
                (
                    rel.startswith("libs/sdk-go/")
                    and rel.endswith(".go")
                )
                or (
                    rel.startswith("libs/sdk-ts/src/")
                    and rel.endswith((".ts", ".tsx"))
                )
                or (
                    rel.startswith("libs/sdk-python/codewire/")
                    and rel.endswith(".py")
                )
            )
        }
        failures = proto_package_boundary_failures(
            proto_sources,
            ts_manifest,
            ts_index,
            python_manifest,
            sdk_sources,
        )
        if not failures and args.self_test:
            proto_package_boundary_self_test(
                proto_sources,
                ts_manifest,
                ts_index,
                python_manifest,
                sdk_sources,
            )
    except Exception as error:  # noqa: BLE001 - repository guard
        failures = [str(error)]

    if failures:
        return report("proto package boundaries", failures, error_annotation=True)
    print(
        "proto package boundaries: OK "
        "(21 public Mesh RPCs, 7 annotated reads, 8 services, 5 explicit TS exports)"
    )
    return 0
