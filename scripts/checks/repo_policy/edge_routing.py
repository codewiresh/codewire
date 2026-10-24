from .shared import *


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
    for directory in ["proto/codewire"]:
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
            elif owner == "mesh":
                if not any(rule["backend"] == "mesh" for rule in here):
                    fail(f"{file}: Mesh-owned {service} has no Mesh-targeted Connect rule")
                if any(rule["backend"] != "mesh" for rule in here):
                    fail(f"{file}: Mesh-owned {service} is also routed to another binary")
            elif owner == "coordinator":
                if not any(rule["backend"] == "coordinator" for rule in here):
                    fail(f"{file}: coordinator-owned {service} has no coordinator-targeted Connect rule")
                if any(rule["backend"] != "coordinator" for rule in here):
                    fail(f"{file}: coordinator-owned {service} is also routed to another binary")
            elif owner == "credential-service":
                if service not in ISOLATED_CREDENTIAL_SERVICES:
                    fail(f"{file}: isolated credential authority cannot own {service}")
                if len(here) != 1 or here[0]["backend"] != "credential-service":
                    fail(f"{file}: {service} needs one isolated credential-service route")
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

    assert_mesh_connect_backend_topology(ownership, owners, per_file, fail)
    assert_credential_mutation_edges(per_file, fail)
    assert_credential_delegation_edges(per_file, fail)
    assert_github_repository_edges(per_file, fail)
    assert_internal_connect_listener_exemption(unrouted, per_file, fail)
    assert_mesh_primary_origin_rest_edge(fail)
    assert_github_browser_callback_edges(fail)
    assert_idp_session_edges(fail)
    if getattr(_args, "self_test", False):
        try:
            internal_connect_listener_self_test()
            isolated_grpc_service_self_test()
            mesh_connect_backend_topology_self_test(ownership, owners, per_file)
            mesh_coordinator_transport_self_test()
            mesh_primary_origin_rest_edge_self_test()
            github_browser_callback_edges_self_test()
            idp_session_edges_self_test()
            credential_mutation_edges_self_test(per_file)
            credential_delegation_edges_self_test(per_file)
            github_repository_edges_self_test(per_file)
            native_grpc_opt_in_sites_self_test()
        except RuntimeError as error:
            fail(f"Connect edge self-test: {error}")

    for file in all_files:
        assert_coordinator_transport_shape(file, fail)
        assert_mesh_coordinator_transport_shape(file, fail)
        assert_environment_session_transport_shape(file, fail)
    assert_native_grpc_opt_in_sites(fail)
    assert_rendered_grpc_service(fail)

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
    "codewire.internal.v1.MeshAuthorizationService": (
        "codewire_orchestration::connect::mesh_authorization::router"
    ),
    # Hosted Mesh's questions about environment members (#3350).
    "codewire.internal.v1.EnvironmentMeshService": (
        "codewire_orchestration::environment_mesh::environment_mesh_router"
    ),
}

# The second closed listener class: every tenant workload can open TCP to it,
# so it carries exactly this one service and nothing else.
WORKSPACE_BINDING_SERVICES = {
    "codewire.internal.v1.WorkspaceBindingService": (
        "codewire_orchestration::workspace_binding::workspace_binding_router"
    ),
}

# The third closed listener class: Codewire's public DERP relay asks whether a
# node key belongs to a live session (codewire#2844). The coordinator and Mesh
# each serve it for their own sessions on 8097, which no edge routes to; the
# site's network policy admits only the relay.
DERP_ADMISSION_SERVICES = {
    "codewire.internal.v1.DerpAdmissionService": "derp_verify_router",
}

CLOSED_LISTENERS = {
    "internal-connect": (8088, INTERNAL_CONNECT_SERVICES),
    "workspace-binding": (8087, WORKSPACE_BINDING_SERVICES),
    "derp-admission": (8097, DERP_ADMISSION_SERVICES),
}

# The binaries that serve each closed listener. A single-binary class records
# `binary`; a class served by several binaries records them as `binaries`.
CLOSED_LISTENER_BINARIES = {
    "internal-connect": ("orchestration",),
    "workspace-binding": ("orchestration",),
    "derp-admission": ("coordinator", "mesh"),
}

WORKSPACE_BINDING_SERVICE_NAME = "codewire-orchestration-workspace-binding"

ISOLATED_CREDENTIAL_SERVICES = {
    "codewire.v1.CredentialMutationService",
    "codewire.v1.CredentialDelegationService",
    "codewire.v1.GithubRepositoryService",
}


GITHUB_BROWSER_CALLBACK = "/api/v1/github/oauth/callback"
GITHUB_BROWSER_INGRESSES = {
    "deployments/k8s/base/ingress.yaml": ("codewire-dashboard", "codewire-dashboard", "name: http"),
    "deployments/k8s/overlays/local-kind/ingress.yaml": ("codewire-local", "dashboard", "number: 5173"),
    "deployments/k8s/overlays/local-kind-static/ingress.yaml": ("codewire-local", "dashboard", "number: 5173"),
    "tests/e2e/kind/ingress.yaml": ("codewire-preview-e2e", "codewire-dashboard", "name: http"),
}

# Local edges only. The Kind-watch and Caddy dashboards reach the IdP through
# the public edge; Dev and Production dashboards call it inside the cluster, so
# the production ingress does not expose this raw IdP path.
IDP_SESSION_INGRESSES = {
    "deployments/k8s/overlays/local-kind/ingress.yaml": "codewire-idp-local",
    "deployments/k8s/overlays/local-kind-static/ingress.yaml": "codewire-idp-local",
    "tests/e2e/kind/ingress.yaml": "codewire-idp-e2e",
}


def assert_idp_session_edges(
    fail: Callable[[str], None], reader: Callable[[str], str] = read_text
) -> None:
    # The browser-facing Account inventory and revoke action both use this
    # cookie-only IdP boundary. The broader /api fallback is orchestration.
    for file in ("Caddyfile", "Caddyfile.docker"):
        source = reader(file)
        matchers = re.findall(r"^[ \t]*@idp path ([^\n]+)$", source, re.MULTILINE)
        paths = matchers[0].split() if len(matchers) == 1 else []
        for path in ("/api/auth/sessions", "/api/auth/sessions/revoke"):
            if paths.count(path) != 1:
                fail(f"{file}: Account sessions need one exact IdP matcher for {path}")
        handlers = re.findall(r"handle @idp\s*\{([^}]*)\}", source, re.DOTALL)
        if len(handlers) != 1 or not re.search(
            r"reverse_proxy\s+(?:localhost|127\.0\.0\.1):8091\b", handlers[0]
        ):
            fail(f"{file}: Account sessions must use the IdP listener on 8091")
    for file, name in IDP_SESSION_INGRESSES.items():
        document = ingress_document_by_name(reader(file), name, file, fail)
        if document is None:
            continue
        entries = re.findall(
            r"^[ \t]*- path: /api/auth/sessions[ \t]*\n[\s\S]*?(?=^[ \t]*- path:|\Z)",
            document, re.MULTILINE,
        )
        if len(entries) != 1:
            fail(f"{file}: Account sessions need one IdP ingress path")
            continue
        shape = re.sub(r"\s+", " ", entries[0])
        if not re.search(
            r"path: /api/auth/sessions pathType: Prefix backend: service: "
            r"name: codewire-idp port: name: http(?: |$)", shape
        ):
            fail(f"{file}: Account sessions must use IdP http with Prefix routing")


def idp_session_edges_self_test() -> None:
    for file in ("Caddyfile", "Caddyfile.docker", *IDP_SESSION_INGRESSES):
        original = read_text(file)
        if file.startswith("Caddyfile"):
            attacks = {
                "missing inventory": original.replace("/api/auth/sessions ", "", 1),
                "missing revoke": original.replace("/api/auth/sessions/revoke", "/api/auth/other", 1),
                "wrong backend": original.replace(":8091", ":8084", 1),
            }
        else:
            entry = re.search(
                r"^[ \t]*- path: /api/auth/sessions[ \t]*\n[\s\S]*?(?=^[ \t]*- path:|\Z)",
                original, re.MULTILINE,
            )
            if entry is None:
                raise RuntimeError(f"{file}: missing Account session route fixture")
            block = entry.group(0)
            attacks = {
                "missing": original.replace(block, "", 1),
                "wrong backend": original.replace(block, block.replace("name: codewire-idp", "name: codewire-orchestration"), 1),
                "wrong path type": original.replace(block, block.replace("pathType: Prefix", "pathType: Exact"), 1),
                "duplicate": original.replace(block, block + block, 1),
            }
        for attack, changed in attacks.items():
            failures: list[str] = []
            assert_idp_session_edges(
                failures.append, lambda path: changed if path == file else read_text(path)
            )
            if not any(file in failure for failure in failures):
                raise RuntimeError(f"{file}: accepted {attack} Account session edge")


def assert_github_browser_callback_ingress(
    document: str, label: str, backend: str, port: str, fail: Callable[[str], None]
) -> None:
    # Keep the callback in the application rule, never the wildcard preview rule.
    rules = re.split(r"^\s{2,4}- (?:host|http):", document, flags=re.MULTILINE)[1:]
    callback_rules = [rule for rule in rules if GITHUB_BROWSER_CALLBACK in rule]
    if len(callback_rules) != 1:
        fail(f"{label}: browser GitHub callback needs exactly one application rule")
        return
    rule = callback_rules[0]
    # Kustomize sorts path entries as backend/path/pathType, unlike source YAML.
    entries = list(re.finditer(
        r"^([ ]*)- (?:path|backend):[^\n]*\n[\s\S]*?(?=^\1- |\Z)",
        rule, re.MULTILINE,
    ))
    paths: list[tuple[str, str, str]] = []
    for entry in entries:
        block = entry.group(0)
        path = re.search(r"^\s*(?:- )?path: (\S+)[ \t]*$", block, re.MULTILINE)
        mode = re.search(r"^\s*pathType: (\S+)[ \t]*$", block, re.MULTILINE)
        if path is not None and mode is not None:
            body = re.sub(r"^\s*(?:- )?(?:path|pathType):[^\n]*\n?", "", block, flags=re.MULTILINE)
            body = re.sub(r"\s+", " ", body).strip().removeprefix("- ")
            paths.append((path.group(1), mode.group(1), body))
    callbacks = [(mode, body) for path, mode, body in paths if path.startswith(GITHUB_BROWSER_CALLBACK)]
    expected = ("Exact", f"backend: service: name: {backend} port: {port}")
    if callbacks != [expected]:
        fail(f"{label}: browser GitHub callback must be Exact -> {backend} {port}")
    if not any(path == GITHUB_BROWSER_CALLBACK for path, _, _ in paths):
        fail(f"{label}: browser GitHub callback must use the exact callback path")
    fallbacks = [(mode, body) for path, mode, body in paths if path == "/api"]
    fallback = ("Prefix", "backend: service: name: codewire-orchestration port: name: http")
    if fallbacks != [fallback]:
        fail(f"{label}: browser callback must preserve the application /api orchestration fallback")
    if "*." in rule.split("paths:", 1)[0]:
        fail(f"{label}: browser GitHub callback must not use a wildcard preview host")


def assert_github_browser_callback_edges(
    fail: Callable[[str], None], reader: Callable[[str], str] = read_text
) -> None:
    for file in ("Caddyfile", "Caddyfile.docker"):
        text = reader(file)
        block = caddy_handle_block(text, GITHUB_BROWSER_CALLBACK)
        if len(re.findall(r"\bhandle\s+" + re.escape(GITHUB_BROWSER_CALLBACK) + r"\s*\{", text)) != 1 or not block:
            fail(f"{file}: browser GitHub callback needs one exact dashboard handle")
        elif not re.search(r"reverse_proxy\s+(?:localhost|127\.0\.0\.1):5173\s*\}", block):
            fail(f"{file}: browser GitHub callback must use dashboard port 5173")
        fallback = caddy_handle_block(text, "/api/*") or ""
        if not re.search(r"reverse_proxy\s+(?:localhost|127\.0\.0\.1):8084\s*\}", fallback):
            fail(f"{file}: browser callback must preserve /api orchestration port 8084")
        if block and text.index(block) > text.index(fallback or text):
            fail(f"{file}: browser GitHub callback must precede the broad API handle")
    for file, (name, backend, port) in GITHUB_BROWSER_INGRESSES.items():
        document = ingress_document_by_name(reader(file), name, file, fail)
        if document is not None:
            assert_github_browser_callback_ingress(document, file, backend, port, fail)


def github_browser_callback_edges_self_test() -> None:
    files = ["Caddyfile", "Caddyfile.docker", *GITHUB_BROWSER_INGRESSES]
    for file in files:
        original = read_text(file)
        attacks = {
            "missing": original.replace(GITHUB_BROWSER_CALLBACK, "/wrong-callback"),
            "non-exact path": original.replace(GITHUB_BROWSER_CALLBACK, GITHUB_BROWSER_CALLBACK + "/*"),
        }
        if file.startswith("Caddyfile"):
            block = caddy_handle_block(original, GITHUB_BROWSER_CALLBACK)
            if not block:
                raise RuntimeError(f"{file}: missing browser callback fixture")
            attacks["wrong backend"] = original.replace(block, block.replace(":5173", ":8084"))
            attacks["duplicate"] = original.replace(block, block + "\n" + block)
            fallback = caddy_handle_block(original, "/api/*") or ""
            attacks["changed fallback"] = original.replace(fallback, fallback.replace(":8084", ":5173"))
            attacks["wrong order"] = original.replace(block, "CALLBACK_ORDER_FIXTURE", 1).replace(fallback, block, 1).replace("CALLBACK_ORDER_FIXTURE", fallback, 1)
        else:
            _, backend, port = GITHUB_BROWSER_INGRESSES[file]
            block_match = re.search(r"^\s*- path: " + re.escape(GITHUB_BROWSER_CALLBACK) + r"\n[\s\S]*?(?=^\s*- path:)", original, re.MULTILINE)
            if not block_match:
                raise RuntimeError(f"{file}: missing browser callback fixture")
            block = block_match.group(0)
            attacks["Prefix"] = original.replace(block, block.replace("pathType: Exact", "pathType: Prefix"))
            attacks["wrong backend"] = original.replace(block, block.replace(f"name: {backend}", "name: codewire-orchestration"))
            attacks["wrong port"] = original.replace(block, block.replace(port, "number: 8084"))
            attacks["duplicate"] = original.replace(block, block + block)
            attacks["changed fallback"] = original.replace("path: /api\n", "path: /other-api\n")
            if file == "deployments/k8s/base/ingress.yaml":
                attacks["wildcard preview rule"] = original.replace("- host: codewire.sh", '- host: "*.codewire.sh"', 1)
            else:
                attacks["wildcard preview rule"] = original.replace("    - http:\n", '    - host: "*.codewire-dev.local"\n      http:\n', 1)
        for attack, changed in attacks.items():
            failures: list[str] = []
            assert_github_browser_callback_edges(failures.append, lambda path: changed if path == file else read_text(path))
            if not any(file in message for message in failures):
                raise RuntimeError(f"{file}: browser callback accepted {attack}")


def assert_github_repository_edges(
    per_file: dict[str, dict[str, Any]],
    fail: Callable[[str], None],
    reader: Callable[[str], str] = read_text,
) -> None:
    service = "codewire.v1.GithubRepositoryService"
    for file, data in per_file.items():
        rules = [rule for rule in data["rules"] if rule["service"] == service]
        if len(rules) != 1 or rules[0]["backend"] != "credential-service":
            fail(f"{file}: GitHub discovery requires the isolated credential listener")
        text = reader(file)
        if file.startswith("Caddyfile"):
            block = caddy_handle_block(text, f"/{service}/*") or ""
            if not re.search(r"reverse_proxy\s+(?:localhost|127\.0\.0\.1):8086\b", block):
                fail(f"{file}: GitHub discovery must use public port 8086")
        else:
            expected = (
                "path: /codewire\\.v1\\.GithubRepositoryService/ "
                "pathType: ImplementationSpecific backend: service: "
                "name: codewire-credential-service port: name: http"
            )
            if expected not in re.sub(r"\s+", " ", text):
                fail(f"{file}: GitHub discovery must use credential-service http, never broker TLS")


def github_repository_edges_self_test(per_file: dict[str, dict[str, Any]]) -> None:
    service = "codewire.v1.GithubRepositoryService"
    for file in per_file:
        broken = copy.deepcopy(per_file)
        for rule in broken[file]["rules"]:
            if rule["service"] == service:
                rule["backend"] = "orchestration"
        failures: list[str] = []
        assert_github_repository_edges(broken, failures.append)
        if not any(file in message and "isolated credential listener" in message for message in failures):
            raise RuntimeError(f"{file}: accepted GitHub discovery through orchestration")
    for file in per_file:
        original = read_text(file)
        before = caddy_handle_block(original, f"/{service}/*") if file.startswith("Caddyfile") else (
            "path: /codewire\\.v1\\.GithubRepositoryService/\n"
            "            pathType: ImplementationSpecific\n"
            "            backend:\n"
            "              service:\n"
            "                name: codewire-credential-service\n"
            "                port:\n"
            "                  name: http"
        )
        if not before or before not in original:
            raise RuntimeError(f"{file}: missing GitHub discovery negative fixture")
        after = before.replace(":8086", ":9443") if file.startswith("Caddyfile") else before.replace("name: http", "name: broker-tls")
        changed = original.replace(before, after, 1)
        failures = []
        assert_github_repository_edges(per_file, failures.append, lambda path: changed if path == file else read_text(path))
        if not any(file in message for message in failures):
            raise RuntimeError(f"{file}: accepted GitHub discovery through broker TLS")


def assert_credential_mutation_edges(
    per_file: dict[str, dict[str, Any]],
    fail: Callable[[str], None],
    reader: Callable[[str], str] = read_text,
) -> None:
    """Enrollment streams use only the isolated public listener, never broker TLS."""
    service = "codewire.v1.CredentialMutationService"
    for file, data in per_file.items():
        rules = [rule for rule in data["rules"] if rule["service"] == service]
        if len(rules) != 1 or rules[0]["backend"] != "credential-service":
            fail(f"{file}: credential mutation route must target the isolated public listener")
        text = reader(file)
        if "broker.v1.CredentialBrokerService" in text.replace("\\.", "."):
            fail(f"{file}: private credential broker must not have a public edge matcher")
        if file.startswith("Caddyfile"):
            block = caddy_handle_block(text, f"/{service}/*") or ""
            if not re.search(r"reverse_proxy\s+(?:localhost|127\.0\.0\.1):8086\b", block):
                fail(f"{file}: credential mutation edge must use public port 8086")
            if not re.search(r"flush_interval\s+-1\b", block):
                fail(f"{file}: credential mutation challenge must stream without buffering")
        else:
            document = connect_fallback_ingress_document(text, file, fail) or ""
            expected = (
                "path: /codewire\\.v1\\.CredentialMutationService/ "
                "pathType: ImplementationSpecific backend: service: "
                "name: codewire-credential-service port: name: http"
            )
            if expected not in re.sub(r"\s+", " ", document):
                fail(f"{file}: credential mutation must share the unbuffered Connect edge on http")
            if rules and rules[0].get("backend_service") != "codewire-credential-service":
                fail(f"{file}: credential mutation needs the exact credential-service Service")


def credential_mutation_edges_self_test(per_file: dict[str, dict[str, Any]]) -> None:
    service = "codewire.v1.CredentialMutationService"
    for file in per_file:
        broken = copy.deepcopy(per_file)
        for rule in broken[file]["rules"]:
            if rule["service"] == service:
                rule["backend"] = "orchestration"
        failures: list[str] = []
        assert_credential_mutation_edges(broken, failures.append)
        if not any(file in message and "isolated public listener" in message for message in failures):
            raise RuntimeError(f"{file}: accepted credential mutation via orchestration")

    for file, before, after, wanted in [
        ("Caddyfile", ":8086", ":9443", "public port 8086"),
        ("Caddyfile.docker", "flush_interval -1", "flush_interval 1s", "without buffering"),
        (
            "tests/e2e/kind/ingress.yaml",
            "name: codewire-credential-service\n                port:\n                  name: http",
            "name: codewire-credential-service\n                port:\n                  name: broker-tls",
            "unbuffered Connect edge on http",
        ),
        ("Caddyfile", "/codewire.*", "/broker.v1.CredentialBrokerService/*", "private credential broker"),
    ]:
        original = read_text(file)
        # The delegation edge also uses :8086/http and unbuffered streaming.
        # Mutate the mutation service's exact existing object, not whichever
        # credential-service route happens to appear first in the file.
        scope = original
        if wanted != "private credential broker":
            if file.startswith("Caddyfile"):
                scope = caddy_handle_block(original, f"/{service}/*") or ""
            else:
                scope = connect_fallback_ingress_document(original, file, lambda _: None) or ""
        if before not in scope:
            raise RuntimeError(f"{file}: missing credential edge negative fixture")
        changed = original.replace(scope, scope.replace(before, after, 1), 1)
        failures = []
        assert_credential_mutation_edges(
            per_file, failures.append, lambda path: changed if path == file else read_text(path)
        )
        if not any(file in message and wanted in message for message in failures):
            raise RuntimeError(f"{file}: accepted broken credential edge: {wanted}")


def assert_credential_delegation_ingress_shape(
    document: str | None, label: str, fail: Callable[[str], None]
) -> None:
    # The two admitted first-party bidi paths share the existing object and its
    # TLS/host patches, but retain distinct exact Service/port backends.
    assert_environment_session_ingress_shape(document, label, fail)
    if document is None:
        return
    paths = re.findall(r"^\s*(?:-\s+)?path:\s+(\S+)\s*$", document, re.MULTILINE)
    expected_paths = {
        r"/codewire\.v1\.EnvironmentSessionService/",
        r"/codewire\.v1\.CredentialDelegationService/",
    }
    if len(paths) != 2 or set(paths) != expected_paths:
        fail(f"{label}: native-bidi ingress must share only the two exact session/delegation paths")
    flat = re.sub(r"\s+", " ", document)
    for service, backend, port in [
        ("EnvironmentSessionService", "codewire-orchestration-grpc", "grpc"),
        ("CredentialDelegationService", "codewire-credential-service", "http"),
    ]:
        expected = (
            f"path: /codewire\\.v1\\.{service}/ pathType: ImplementationSpecific "
            f"backend: service: name: {backend} port: name: {port}"
        )
        # kustomize emits backend before path; source uses path before backend.
        # Accept only these exact route/backend/port tuples in either ordering.
        rendered = (
            f"backend: service: name: {backend} port: name: {port} "
            f"path: /codewire\\.v1\\.{service}/ pathType: ImplementationSpecific"
        )
        if expected not in flat and rendered not in flat:
            fail(f"{label}: {service} must target exact {backend}:{port} on the native-bidi edge")


def assert_credential_delegation_edges(
    per_file: dict[str, dict[str, Any]],
    fail: Callable[[str], None],
    reader: Callable[[str], str] = read_text,
) -> None:
    service = "codewire.v1.CredentialDelegationService"
    for file, data in per_file.items():
        rules = [rule for rule in data["rules"] if rule["service"] == service]
        if len(rules) != 1 or rules[0]["backend"] != "credential-service":
            fail(f"{file}: credential delegation needs one exact isolated public listener route")
        text = reader(file)
        if file.startswith("Caddyfile"):
            block = caddy_handle_block(text, f"/{service}/*") or ""
            if not re.search(r"reverse_proxy\s+(?:localhost|127\.0\.0\.1):8086\b", block):
                fail(f"{file}: credential delegation must use public port 8086")
            if not re.search(r"transport\s+http\s*\{[\s\S]*?versions\s+h2c\s+2\b", block):
                fail(f"{file}: credential delegation backend must enable versions h2c 2")
            if not re.search(r"flush_interval\s+-1\b", block):
                fail(f"{file}: credential delegation must stream without buffering")
        else:
            assert_credential_delegation_ingress_shape(
                environment_session_ingress_document(text, file, fail), file, fail
            )
            if rules and rules[0].get("backend_service") != "codewire-credential-service":
                fail(f"{file}: credential delegation needs the exact credential-service Service")


def credential_delegation_edges_self_test(per_file: dict[str, dict[str, Any]]) -> None:
    service = "codewire.v1.CredentialDelegationService"
    for file in per_file:
        for attack in ["missing", "wrong backend", "duplicate"]:
            broken = copy.deepcopy(per_file)
            rules = broken[file]["rules"]
            selected = next((rule for rule in rules if rule["service"] == service), None)
            if selected is None:
                raise RuntimeError(f"{file}: missing delegation route positive fixture")
            if attack == "missing":
                rules.remove(selected)
            elif attack == "wrong backend":
                selected["backend"] = "orchestration"
            else:
                rules.append(copy.deepcopy(selected))
            failures: list[str] = []
            assert_credential_delegation_edges(broken, failures.append)
            if not any(file in message and "one exact isolated public listener" in message for message in failures):
                raise RuntimeError(f"{file}: accepted {attack} delegation routing")

        original = read_text(file)
        if file.startswith("Caddyfile"):
            scope = caddy_handle_block(original, f"/{service}/*") or ""
            mutations = [
                (":8086", ":9443", "public port 8086"),
                ("versions h2c 2", "versions 1.1", "versions h2c 2"),
                ("flush_interval -1", "flush_interval 1s", "without buffering"),
            ]
        else:
            scope = environment_session_ingress_document(original, file, lambda _: None) or ""
            mutations = [
                ("name: codewire-credential-service", "name: codewire-orchestration", "exact codewire-credential-service:http"),
                ("name: http", "name: broker-tls", "exact codewire-credential-service:http"),
                ('backend-protocol: "GRPC"', 'backend-protocol: "HTTP"', "backend-protocol GRPC"),
                ('service-upstream: "true"', 'service-upstream: "false"', "dedicated Service ClusterIP"),
                ('proxy-request-buffering: "off"', 'proxy-request-buffering: "on"', "proxy-request-buffering must be off"),
                ('proxy-buffering: "off"', 'proxy-buffering: "on"', "proxy-buffering must be off"),
                ('proxy-read-timeout: "3600"', 'proxy-read-timeout: "30"', "proxy-read-timeout must be 3600"),
                ('proxy-send-timeout: "3600"', 'proxy-send-timeout: "30"', "proxy-send-timeout must be 3600"),
                (r"/codewire\.v1\.EnvironmentSessionService/", r"/codewire\.v1\.CredentialMutationService/", "EnvironmentSessionService Ingress"),
                (r"/codewire\.v1\.CredentialDelegationService/", r"/codewire\.v1\.CredentialService/", "share only the two exact"),
            ]
        for before, after, wanted in mutations:
            if before not in scope:
                raise RuntimeError(f"{file}: missing delegation transport negative fixture: {before}")
            changed = original.replace(scope, scope.replace(before, after, 1), 1)
            failures = []
            assert_credential_delegation_edges(
                per_file, failures.append, lambda path: changed if path == file else read_text(path)
            )
            if not any(file in message and wanted in message for message in failures):
                raise RuntimeError(f"{file}: accepted broken delegation transport: {wanted}; {failures!r}")


MESH_KUBERNETES_BACKENDS = {
    "deployments/k8s/base/ingress.yaml": "codewire-mesh-http",
    "deployments/k8s/overlays/local-kind/ingress.yaml": "codewire-mesh",
    "deployments/k8s/overlays/local-kind-static/ingress.yaml": "codewire-mesh",
    "tests/e2e/kind/ingress.yaml": "codewire-mesh",
}


def assert_mesh_connect_backend_topology(
    ownership: dict[str, Any],
    owners: dict[str, str],
    per_file: dict[str, dict[str, Any]],
    fail: Callable[[str], None],
) -> None:
    """Prove every Mesh Connect rule targets its topology's real Service."""
    expected_backends = ownership.get("mesh_kubernetes_backends")
    if expected_backends != MESH_KUBERNETES_BACKENDS:
        fail(
            "Mesh Connect ownership fixture must pin the hosted "
            "codewire-mesh-http Service and every Kind codewire-mesh Service"
        )
        return

    mesh_services = {service for service, owner in owners.items() if owner == "mesh"}
    for file, expected_backend in expected_backends.items():
        rules = per_file.get(file, {}).get("rules", [])
        for service in sorted(mesh_services):
            matching = [rule for rule in rules if rule["service"] == service]
            if not matching or any(
                rule.get("backend_service") != expected_backend for rule in matching
            ):
                fail(
                    f"{file}: Mesh-owned {service} must target "
                    f"{expected_backend}:http"
                )


def mesh_connect_backend_topology_self_test(
    ownership: dict[str, Any],
    owners: dict[str, str],
    per_file: dict[str, dict[str, Any]],
) -> None:
    """Demonstrate rejection of wrong hosted and Kind Connect backends."""

    def expect_rejection(file: str, wrong_backend: str, expected_backend: str) -> None:
        broken = copy.deepcopy(per_file)
        rules = broken[file]["rules"]
        mesh_rule = next(
            (
                rule
                for rule in rules
                if owners.get(rule["service"]) == "mesh"
                and rule.get("backend_service") == expected_backend
            ),
            None,
        )
        if mesh_rule is None:
            raise RuntimeError(
                f"{file}: self-test fixture is missing expected {expected_backend} backend"
            )
        mesh_rule["backend_service"] = wrong_backend
        failures: list[str] = []
        assert_mesh_connect_backend_topology(ownership, owners, broken, failures.append)
        if not any(
            file in failure and f"{expected_backend}:http" in failure
            for failure in failures
        ):
            raise RuntimeError(
                f"{file}: Mesh Connect topology accepted {wrong_backend}: {failures!r}"
            )

    expect_rejection(
        "deployments/k8s/base/ingress.yaml",
        "codewire-mesh",
        "codewire-mesh-http",
    )
    expect_rejection(
        "tests/e2e/kind/ingress.yaml",
        "codewire-mesh-http",
        "codewire-mesh",
    )


def assert_mesh_primary_origin_rest_edge(
    fail: Callable[[str], None],
    reader: Callable[[str], str] = read_text,
) -> None:
    """Reject the retired primary-origin Mesh network REST bridge everywhere."""
    for file in (
        "Caddyfile",
        "Caddyfile.docker",
        "deployments/k8s/base/ingress.yaml",
        "deployments/k8s/overlays/local-kind/ingress.yaml",
        "deployments/k8s/overlays/local-kind-static/ingress.yaml",
        "tests/e2e/kind/ingress.yaml",
    ):
        if "/api/v1/networks" in reader(file):
            fail(f"{file}: retired Mesh network REST edge remains present")


def mesh_primary_origin_rest_edge_self_test() -> None:
    """Demonstrate rejection when the retired Mesh REST edge returns."""
    source = {
        file: read_text(file)
        for file in [
            "Caddyfile",
            "Caddyfile.docker",
            "deployments/k8s/base/ingress.yaml",
            "deployments/k8s/overlays/local-kind/ingress.yaml",
            "deployments/k8s/overlays/local-kind-static/ingress.yaml",
            "tests/e2e/kind/ingress.yaml",
        ]
    }
    def expect_rejection(file: str) -> None:
        broken = source.copy()
        broken[file] += "\n# restored /api/v1/networks\n"
        failures: list[str] = []
        assert_mesh_primary_origin_rest_edge(failures.append, broken.__getitem__)
        if not any(file in failure for failure in failures):
            raise RuntimeError(
                f"{file}: Mesh raw-edge guard accepted a restored route: {failures!r}"
            )

    expect_rejection("deployments/k8s/base/ingress.yaml")
    expect_rejection("tests/e2e/kind/ingress.yaml")


def assert_internal_connect_listener_exemption(
    unrouted: dict[str, Any],
    per_file: dict[str, dict[str, Any]],
    fail: Callable[[str], None],
    reader: Callable[[str], str] = read_text,
) -> None:
    """Validate the closed cluster-local listener exceptions.

    Two listener classes exist: internal-connect (8088, TLS-only) for Mesh,
    and workspace-binding (8087), which tenant workloads can reach and which
    therefore carries only WorkspaceBindingService.
    """
    for service, record in unrouted.items():
        listener = next(
            (name for name, (_, services) in CLOSED_LISTENERS.items() if service in services),
            None,
        )
        if listener is None:
            fail(f"unrouted service {service} is not a declared closed-listener exception")
        if not isinstance(record, dict):
            fail(f"unrouted service {service} must record binary, listener, and port")
            continue
        binaries = CLOSED_LISTENER_BINARIES.get(listener or "", ("orchestration",))
        if len(binaries) == 1:
            if record.get("binary") != binaries[0] or "binaries" in record:
                fail(f"unrouted service {service} must be owned by {binaries[0]}")
        elif record.get("binaries") != list(binaries) or "binary" in record:
            fail(f"unrouted service {service} must be served by exactly {', '.join(binaries)}")
        if listener is not None:
            port = CLOSED_LISTENERS[listener][0]
            if record.get("listener") != listener or record.get("port") != port:
                fail(
                    f"unrouted service {service} must use the {listener} listener on port {port}"
                )
        for file, data in per_file.items():
            if any(rule["service"] == service for rule in data["rules"]):
                fail(f"{file}: unrouted {service} has a prohibited public edge matcher")
    expected = set().union(*(services for _, services in CLOSED_LISTENERS.values()))
    if set(unrouted) != expected:
        fail(
            "unrouted listener map must contain exactly MeshAuthorizationService, "
            "EnvironmentMeshService, WorkspaceBindingService and DerpAdmissionService"
        )
    assert_internal_connect_listener_boundary(INTERNAL_CONNECT_SERVICES, fail, reader)
    assert_workspace_binding_listener_boundary(fail, reader)
    assert_derp_admission_listener_boundary(fail, reader)


DERP_ADMISSION_EDGE_FILES = (
    "deployments/k8s/base/ingress.yaml",
    "deployments/k8s/overlays/local-kind/ingress.yaml",
    "deployments/k8s/overlays/local-kind-static/ingress.yaml",
    "tests/e2e/kind/ingress.yaml",
    "Caddyfile",
    "Caddyfile.docker",
)


def assert_derp_admission_listener_boundary(
    fail: Callable[[str], None],
    reader: Callable[[str], str] = read_text,
) -> None:
    """Prove 8097 carries only DerpAdmissionService, from both its binaries.

    Each binary builds the admission router once, serves it only on its own
    8097 listener and never on its public app; the manifests name the port
    and the relay's verifier URLs; and no edge routes to it.
    """
    coordinator = reader("crates/codewire-coordinator/src/main.rs")
    public_start = coordinator.find('AppBuilder::new("codewire-coordinator")')
    if public_start < 0:
        fail("coordinator must build its public AppBuilder app")
    elif "derp_verify_router" in coordinator[public_start:]:
        fail("DerpAdmissionService is prohibited from the coordinator's public app")
    if coordinator.count("derp_verify_router(") != 1 or not re.search(
        r'std::env::var\("COORDINATOR_DERP_VERIFY_ADDR"\)[\s\S]*?'
        r"codewire_server_core::serve\(\s*derp_verify_router\(state\.clone\(\)\),\s*addr,",
        coordinator,
    ):
        fail(
            "the coordinator must serve DerpAdmissionService once, only on its "
            "COORDINATOR_DERP_VERIFY_ADDR listener"
        )

    mesh = reader("crates/codewire-mesh/src/server.rs")
    routes = mesh.find("fn router_from_state")
    if routes < 0:
        fail("Mesh must build its public app in router_from_state")
    elif "derp_verify" in mesh[routes:]:
        fail("DerpAdmissionService is prohibited from Mesh's public app")
    if mesh.count("crate::derp_verify::router(") != 1 or not re.search(
        r"match state\.config\.derp_verify_addr \{[\s\S]*?"
        r"crate::derp_verify::router\(state\.mesh_coordinate\.clone\(\)\)",
        mesh,
    ):
        fail("Mesh must serve DerpAdmissionService once, only on its derp_verify_addr listener")

    deployment = reader("deployments/k8s/coordinator/deployment.yaml")
    if not re.search(r"containerPort:\s*8097\s*\n\s*name:\s*derp-verify", deployment):
        fail("coordinator Deployment must declare named derp-verify container port 8097")
    for patch in (
        "deployments/k8s/coordinator/deployment.yaml",
        "deployments/k8s/overlays/local-kind/coordinator-deployment-patch.yaml",
        "deployments/k8s/overlays/local-kind-static/coordinator-deployment-patch.yaml",
    ):
        if not re.search(
            r"name:\s*COORDINATOR_DERP_VERIFY_ADDR\s*\n\s*value:\s*['\"]0\.0\.0\.0:8097['\"]",
            reader(patch),
        ):
            fail(f"{patch}: must set COORDINATOR_DERP_VERIFY_ADDR=0.0.0.0:8097")
    if ("8097", "8097", "derp-verify") not in service_ports(
        reader("deployments/k8s/coordinator/service.yaml")
    ):
        fail("codewire-coordinator Service must expose derp-verify 8097 -> 8097")
    if not re.search(r"derpVerifyPort:\s*8097\b", reader("apps/cli/charts/codewire-mesh/values.yaml")):
        fail("the Mesh chart must default mesh.derpVerifyPort to 8097")
    if "name: derp-verify" not in reader("apps/cli/charts/codewire-mesh/templates/service-http.yaml"):
        fail("the Mesh chart's http Service must expose the derp-verify port")
    derp = reader("deployments/k8s/derp/deployment.yaml")
    for url in (
        "http://codewire-coordinator.$(POD_NAMESPACE).svc.cluster.local:8097",
        "http://codewire-mesh-http.$(POD_NAMESPACE).svc.cluster.local:8097",
    ):
        if url not in derp:
            fail(f"DERP must verify clients against {url}")

    for file in DERP_ADMISSION_EDGE_FILES:
        source = reader(file)
        if re.search(r":8097\b|derp-verify|DerpAdmissionService", source):
            fail(f"{file}: no edge may route to the DERP admission listener")


def orchestration_app_sections(main: str) -> dict[str, str] | None:
    """Split orchestration main.rs into its three application sections."""
    markers = {
        "workspace-binding": "let workspace_binding_app = codewire_orchestration::workspace_binding::app(",
        "internal-connect": 'let internal_app = AppBuilder::new("codewire-orchestration-internal")',
        "public": 'let app = AppBuilder::new("codewire-orchestration")',
    }
    starts = {name: main.find(marker) for name, marker in markers.items()}
    order = ["workspace-binding", "internal-connect", "public"]
    if any(starts[name] < 0 for name in order) or not (
        starts["workspace-binding"] < starts["internal-connect"] < starts["public"]
    ):
        return None
    return {
        "workspace-binding": main[starts["workspace-binding"] : starts["internal-connect"]],
        "internal-connect": main[starts["internal-connect"] : starts["public"]],
        "public": main[starts["public"] :],
    }


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
    sections = orchestration_app_sections(main)
    if sections is None:
        fail(
            "orchestration must build its workspace-binding app, then its internal Connect "
            "app, then the public app"
        )
        return
    internal_section = sections["internal-connect"]
    public_section = sections["public"]
    for service, router in services.items():
        if router not in internal_section:
            fail(f"{service} is not mounted on the internal-connect app")
        if router in public_section:
            fail(f"{service} is prohibited from the public 8084 app")
        if router in sections["workspace-binding"]:
            fail(f"{service} is prohibited from the workspace-binding 8087 app")

    deployment = reader("deployments/k8s/orchestration/deployment.yaml")
    if not re.search(r"containerPort:\s*8084\s*\n\s*name:\s*http", deployment):
        fail("orchestration Deployment must preserve named public http container port 8084")
    if not re.search(
        r"name:\s*ORCHESTRATION_PORT\s*\n\s*value:\s*['\"]8084['\"]", deployment
    ):
        fail("orchestration Deployment must set ORCHESTRATION_PORT=8084 for the public listener")
    # The internal app is served only behind TLS on 8088, and nothing else is.
    if not re.search(
        r"TlsListener::new\(listener, files\)[^;]*?\binternal_app\b",
        main,
        re.DOTALL,
    ):
        fail("the internal TLS listener must serve only the internal Connect app")
    if re.search(r"serve_with_listener\(\s*internal_app\b", main):
        fail("the internal Connect app must never be served without TLS")
    if re.search(r"internal-api\b|ORCHESTRATION_INTERNAL_CONNECT_PORT", deployment):
        fail("orchestration Deployment must not restore the plaintext internal listener")
    if not re.search(r"containerPort:\s*8088\s*\n\s*name:\s*internal-tls", deployment):
        fail("orchestration Deployment must declare named internal-tls container port 8088")
    if not re.search(
        r"name:\s*ORCHESTRATION_INTERNAL_TLS_PORT\s*\n\s*value:\s*['\"]8088['\"]",
        deployment,
    ):
        fail("orchestration Deployment must set ORCHESTRATION_INTERNAL_TLS_PORT=8088")

    service = reader("deployments/k8s/orchestration/service.yaml")
    if not re.search(
        r"port:\s*8084\s*\n\s*targetPort:\s*8084\s*\n\s*name:\s*http", service
    ):
        fail("orchestration ClusterIP Service must preserve named public http port 8084 -> 8084")
    if re.search(r"internal-api\b|port:\s*8085\b", service):
        fail("orchestration ClusterIP Service must not restore the plaintext internal listener")
    if not re.search(
        r"port:\s*8088\s*\n\s*targetPort:\s*internal-tls\s*\n\s*name:\s*internal-tls",
        service,
    ):
        fail("orchestration ClusterIP Service must expose named internal-tls port 8088")


def yaml_documents(source: str) -> list[str]:
    return [document for document in re.split(r"(?m)^---\s*$", source) if document.strip()]


def service_ports(document: str) -> list[tuple[str, str, str]]:
    """(port, targetPort, name) triples of one Service document."""
    return re.findall(
        r"-\s*port:\s*(\S+)\s*\n\s*targetPort:\s*(\S+)\s*\n\s*name:\s*(\S+)",
        document,
    )


def assert_workspace_binding_listener_boundary(
    fail: Callable[[str], None],
    reader: Callable[[str], str] = read_text,
) -> None:
    """Prove 8087 carries only WorkspaceBindingService and nothing else does.

    Every tenant workload can open TCP to this port for the workspace Pod's
    life, so its app mounts one router, has no AppBuilder (no health, metrics,
    REST or CORS routes), is served by the bounded HTTP/1.1 accept loop, and
    has its own Service that exposes only 8087 and that no Ingress names.
    """
    main = reader("crates/codewire-orchestration/src/main.rs")
    sections = orchestration_app_sections(main)
    if sections is None:
        fail("orchestration must build a dedicated workspace-binding app first")
        return
    binding_section = sections["workspace-binding"]
    for service, router in WORKSPACE_BINDING_SERVICES.items():
        if router not in binding_section:
            fail(f"{service} is not mounted on the workspace-binding app")
        if router in sections["internal-connect"]:
            fail(f"{service} is prohibited from the internal-connect 8088 app")
        if router in sections["public"]:
            fail(f"{service} is prohibited from the public 8084 app")
    for router in INTERNAL_CONNECT_SERVICES.values():
        if router in binding_section:
            fail(f"{router} is prohibited from the workspace-binding 8087 app")
    if "AppBuilder" in binding_section or "with_" in binding_section:
        fail("the workspace-binding app must mount only its router, with no shared app routes")
    if not re.search(
        r"serve_bounded_http1_upgraded\(\s*workspace_binding_app,\s*listeners\.workspace_binding,"
        r"\s*codewire_orchestration::workspace_binding::LISTENER_LIMITS,",
        main,
    ):
        fail(
            "the workspace-binding app must be served only by the bounded HTTP/1.1 listener "
            "with LISTENER_LIMITS"
        )
    if not re.search(
        r"Some\(tls\) => \{\s*codewire_server_core::bounded_http1::serve_bounded_http1_upgraded\("
        r"\s*workspace_binding_app,\s*listeners\.workspace_binding,"
        r"\s*codewire_orchestration::workspace_binding::LISTENER_LIMITS,\s*tls,\s*\)",
        main,
    ) or not re.search(
        r"let workspace_binding_tls = internal_tls\s*\.clone\(\)\s*"
        r"\.map\(codewire_orchestration::workspace_binding::WorkspaceBindingTls\);",
        main,
    ):
        fail("the workspace-binding listener must be served only over the internal TLS identity")
    if main.count("workspace_binding_app") != 2:
        fail("the workspace-binding app must be built once and served once")

    deployment = reader("deployments/k8s/orchestration/deployment.yaml")
    if not re.search(r"containerPort:\s*8087\s*\n\s*name:\s*workspace-bind", deployment):
        fail("orchestration Deployment must declare named workspace-bind container port 8087")
    for patch in (
        "deployments/k8s/orchestration/deployment.yaml",
        "deployments/k8s/overlays/local-kind/orchestration-deployment-patch.yaml",
        "deployments/k8s/overlays/local-kind-static/orchestration-deployment-patch.yaml",
    ):
        if not re.search(
            r"name:\s*ORCHESTRATION_WORKSPACE_BINDING_PORT\s*\n\s*value:\s*['\"]8087['\"]",
            reader(patch),
        ):
            fail(f"{patch}: must set ORCHESTRATION_WORKSPACE_BINDING_PORT=8087")

    services = yaml_documents(reader("deployments/k8s/orchestration/service.yaml"))
    binding = [
        document
        for document in services
        if re.search(rf"name:\s*{WORKSPACE_BINDING_SERVICE_NAME}\s*$", document, re.MULTILINE)
    ]
    if len(binding) != 1 or service_ports(binding[0]) != [
        ("8087", "workspace-bind", "workspace-bind")
    ]:
        fail(
            f"{WORKSPACE_BINDING_SERVICE_NAME} must be one ClusterIP Service exposing only "
            "8087 -> workspace-bind"
        )
    elif not re.search(r"type:\s*ClusterIP", binding[0]):
        fail(f"{WORKSPACE_BINDING_SERVICE_NAME} must be a ClusterIP Service")
    for document in services:
        if document in binding:
            continue
        for port, target, name in service_ports(document):
            if "8087" in (port, target) or "workspace-bind" in (target, name):
                fail("only the workspace-binding Service may expose port 8087")

    for file in (
        "deployments/k8s/base/ingress.yaml",
        "deployments/k8s/overlays/local-kind/ingress.yaml",
        "deployments/k8s/overlays/local-kind-static/ingress.yaml",
        "tests/e2e/kind/ingress.yaml",
        "Caddyfile",
        "Caddyfile.docker",
    ):
        source = reader(file)
        if WORKSPACE_BINDING_SERVICE_NAME in source or re.search(r":8087\b", source):
            fail(f"{file}: no edge may route to the workspace-binding listener")


def internal_connect_listener_self_test() -> None:
    """Exercise every closed-listener failure mode without mutating the repo."""
    paths = [
        "crates/codewire-orchestration/src/main.rs",
        "crates/codewire-coordinator/src/main.rs",
        "crates/codewire-mesh/src/server.rs",
        "deployments/k8s/coordinator/deployment.yaml",
        "deployments/k8s/coordinator/service.yaml",
        "deployments/k8s/overlays/local-kind/coordinator-deployment-patch.yaml",
        "deployments/k8s/overlays/local-kind-static/coordinator-deployment-patch.yaml",
        "deployments/k8s/derp/deployment.yaml",
        "apps/cli/charts/codewire-mesh/values.yaml",
        "apps/cli/charts/codewire-mesh/templates/service-http.yaml",
        "deployments/k8s/orchestration/deployment.yaml",
        "deployments/k8s/orchestration/service.yaml",
        "deployments/k8s/overlays/local-kind/orchestration-deployment-patch.yaml",
        "deployments/k8s/overlays/local-kind-static/orchestration-deployment-patch.yaml",
        "deployments/k8s/base/ingress.yaml",
        "deployments/k8s/overlays/local-kind/ingress.yaml",
        "deployments/k8s/overlays/local-kind-static/ingress.yaml",
        "tests/e2e/kind/ingress.yaml",
        "Caddyfile",
        "Caddyfile.docker",
    ]
    source = {path: read_text(path) for path in paths}
    def record(listener: str, port: int) -> dict[str, Any]:
        binaries = CLOSED_LISTENER_BINARIES[listener]
        owner: dict[str, Any] = (
            {"binary": binaries[0]} if len(binaries) == 1 else {"binaries": list(binaries)}
        )
        return {**owner, "listener": listener, "port": port}

    valid_unrouted = {
        service: record(listener, port)
        for listener, (port, services) in CLOSED_LISTENERS.items()
        for service in services
    }

    def failures_for(
        *,
        unrouted: dict[str, Any] | None = None,
        per_file: dict[str, dict[str, Any]] | None = None,
        replacement: tuple[str, str, str] | None = None,
        label: str,
    ) -> list[str]:
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
        return failures

    baseline = failures_for(label="current tree")
    if baseline:
        raise RuntimeError(f"closed-listener fixtures reject the current tree: {baseline!r}")

    def expect_rejection(label: str, expected: str, **kwargs: Any) -> None:
        failures = failures_for(label=label, **kwargs)
        if not any(expected in failure for failure in failures):
            raise RuntimeError(f"{label}: expected rejection {expected!r}, got {failures!r}")

    derp = "codewire.internal.v1.DerpAdmissionService"
    missing_derp = copy.deepcopy(valid_unrouted)
    missing_derp.pop(derp)
    expect_rejection("missing DERP admission record", "must contain exactly", unrouted=missing_derp)
    derp_on_orchestration = copy.deepcopy(valid_unrouted)
    derp_on_orchestration[derp] = {"binary": "orchestration", "listener": "derp-admission", "port": 8097}
    expect_rejection(
        "DERP admission owned by orchestration",
        "must be served by exactly coordinator, mesh",
        unrouted=derp_on_orchestration,
    )
    derp_coordinator_only = copy.deepcopy(valid_unrouted)
    derp_coordinator_only[derp]["binaries"] = ["coordinator"]
    expect_rejection(
        "DERP admission without Mesh",
        "must be served by exactly coordinator, mesh",
        unrouted=derp_coordinator_only,
    )
    derp_on_8088 = copy.deepcopy(valid_unrouted)
    derp_on_8088[derp].update(listener="internal-connect", port=8088)
    expect_rejection(
        "DERP admission recorded on 8088",
        "must use the derp-admission listener on port 8097",
        unrouted=derp_on_8088,
    )
    expect_rejection(
        "public edge matcher for DERP admission",
        "prohibited public edge matcher",
        per_file={"fixture": {"rules": [{"service": derp, "backend": "coordinator"}]}},
    )
    expect_rejection(
        "DERP admission on the coordinator's public app",
        "prohibited from the coordinator's public app",
        replacement=(
            "crates/codewire-coordinator/src/main.rs",
            ".with_routes(router(state, auth))",
            ".with_routes(router(state.clone(), auth))\n        .merge(derp_verify_router(state))",
        ),
    )
    expect_rejection(
        "coordinator DERP admission without its listener",
        "only on its COORDINATOR_DERP_VERIFY_ADDR listener",
        replacement=(
            "crates/codewire-coordinator/src/main.rs",
            "derp_verify_router(state.clone()),\n                addr,",
            "derp_verify_router(state.clone()),\n                cfg.bind_addr,",
        ),
    )
    expect_rejection(
        "DERP admission on Mesh's public app",
        "prohibited from Mesh's public app",
        replacement=(
            "crates/codewire-mesh/src/server.rs",
            'AppBuilder::new("mesh")',
            'AppBuilder::new("mesh").with_connect_routes(crate::derp_verify::router(state.mesh_coordinate.clone()))',
        ),
    )
    expect_rejection(
        "coordinator Service without the derp-verify port",
        "must expose derp-verify 8097",
        replacement=("deployments/k8s/coordinator/service.yaml", "name: derp-verify", "name: verify"),
    )
    expect_rejection(
        "Kind coordinator without the DERP admission listener",
        "local-kind/coordinator-deployment-patch.yaml: must set COORDINATOR_DERP_VERIFY_ADDR",
        replacement=(
            "deployments/k8s/overlays/local-kind/coordinator-deployment-patch.yaml",
            "- name: COORDINATOR_DERP_VERIFY_ADDR",
            "- name: COORDINATOR_DERP_VERIFY_OFF",
        ),
    )
    expect_rejection(
        "DERP not verifying against Mesh",
        "DERP must verify clients against http://codewire-mesh-http",
        replacement=(
            "deployments/k8s/derp/deployment.yaml",
            ",http://codewire-mesh-http.$(POD_NAMESPACE).svc.cluster.local:8097",
            "",
        ),
    )
    expect_rejection(
        "edge route to the DERP admission listener",
        "no edge may route to the DERP admission listener",
        replacement=("Caddyfile", "\n", "\n# reverse_proxy codewire-coordinator:8097\n"),
    )

    missing = copy.deepcopy(valid_unrouted)
    missing.pop("codewire.internal.v1.MeshAuthorizationService")
    expect_rejection("missing exception record", "must contain exactly", unrouted=missing)

    missing_binding = copy.deepcopy(valid_unrouted)
    missing_binding.pop("codewire.internal.v1.WorkspaceBindingService")
    expect_rejection("missing workspace-binding record", "must contain exactly", unrouted=missing_binding)

    wrong_port = copy.deepcopy(valid_unrouted)
    wrong_port["codewire.internal.v1.MeshAuthorizationService"]["port"] = 8086
    expect_rejection("wrong exception record", "must use the internal-connect listener", unrouted=wrong_port)

    binding_on_8088 = copy.deepcopy(valid_unrouted)
    binding_on_8088["codewire.internal.v1.WorkspaceBindingService"] = {
        "binary": "orchestration",
        "listener": "internal-connect",
        "port": 8088,
    }
    expect_rejection(
        "workspace binding recorded on 8088",
        "must use the workspace-binding listener on port 8087",
        unrouted=binding_on_8088,
    )

    mesh_on_8087 = copy.deepcopy(valid_unrouted)
    mesh_on_8087["codewire.internal.v1.MeshAuthorizationService"] = {
        "binary": "orchestration",
        "listener": "workspace-binding",
        "port": 8087,
    }
    expect_rejection(
        "mesh authorization recorded on 8087",
        "must use the internal-connect listener on port 8088",
        unrouted=mesh_on_8087,
    )

    expect_rejection(
        "public edge matcher",
        "prohibited public edge matcher",
        per_file={
            "fixture": {
                "rules": [
                    {"service": "codewire.internal.v1.MeshAuthorizationService", "backend": "orchestration"}
                ]
            }
        },
    )
    expect_rejection(
        "public edge matcher for workspace binding",
        "prohibited public edge matcher",
        per_file={
            "fixture": {
                "rules": [
                    {"service": "codewire.internal.v1.WorkspaceBindingService", "backend": "orchestration"}
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
            '        .with_connect_routes(codewire_orchestration::connect::mesh_authorization::router(pool.clone()))',
        ),
    )
    expect_rejection(
        "workspace binding on the internal app",
        "WorkspaceBindingService is prohibited from the internal-connect 8088 app",
        replacement=(
            "crates/codewire-orchestration/src/main.rs",
            'let internal_app = AppBuilder::new("codewire-orchestration-internal")',
            'let internal_app = AppBuilder::new("codewire-orchestration-internal")\n'
            "        .with_connect_routes(codewire_orchestration::workspace_binding::workspace_binding_router(state))",
        ),
    )
    expect_rejection(
        "workspace binding on the public app",
        "WorkspaceBindingService is prohibited from the public 8084 app",
        replacement=(
            "crates/codewire-orchestration/src/main.rs",
            'let app = AppBuilder::new("codewire-orchestration")',
            'let app = AppBuilder::new("codewire-orchestration")\n'
            "        .with_connect_routes(codewire_orchestration::workspace_binding::workspace_binding_router(state))",
        ),
    )
    expect_rejection(
        "mesh authorization on the workspace-binding app",
        "is prohibited from the workspace-binding 8087 app",
        replacement=(
            "crates/codewire-orchestration/src/main.rs",
            "let workspace_binding_app = codewire_orchestration::workspace_binding::app(",
            "let workspace_binding_app = codewire_orchestration::workspace_binding::app(\n"
            "        codewire_orchestration::connect::mesh_authorization::router(pool.clone()),",
        ),
    )
    expect_rejection(
        "unbounded workspace-binding serving",
        "served only by the bounded HTTP/1.1 listener",
        replacement=(
            "crates/codewire-orchestration/src/main.rs",
            "codewire_server_core::bounded_http1::serve_bounded_http1_upgraded(",
            "codewire_server_core::serve_with_listener(",
        ),
    )
    expect_rejection(
        "plaintext workspace-binding serving",
        "served only over the internal TLS identity",
        replacement=(
            "crates/codewire-orchestration/src/main.rs",
            "LISTENER_LIMITS,\n                        tls,",
            "LISTENER_LIMITS,\n                        codewire_server_core::bounded_http1::Plaintext,",
        ),
    )
    expect_rejection(
        "public app on the internal TLS listener",
        "the internal TLS listener must serve only the internal Connect app",
        replacement=(
            "crates/codewire-orchestration/src/main.rs",
            "            internal_app,\n        )),",
            "            app.clone(),\n        )),",
        ),
    )
    expect_rejection(
        "plaintext internal serving",
        "the internal Connect app must never be served without TLS",
        replacement=(
            "crates/codewire-orchestration/src/main.rs",
            "codewire_server_core::serve_with_listener(app, listeners.public),",
            "codewire_server_core::serve_with_listener(app, listeners.public),\n"
            "        codewire_server_core::serve_with_listener(internal_app, plain),",
        ),
    )
    expect_rejection(
        "plaintext internal Deployment port restored",
        "orchestration Deployment must not restore the plaintext internal listener",
        replacement=(
            "deployments/k8s/orchestration/deployment.yaml",
            "            - containerPort: 8088\n",
            "            - containerPort: 8085\n              name: internal-api\n"
            "            - containerPort: 8088\n",
        ),
    )
    expect_rejection(
        "internal TLS Service retarget",
        "must expose named internal-tls port 8088",
        replacement=(
            "deployments/k8s/orchestration/service.yaml",
            "targetPort: internal-tls",
            "targetPort: 8084",
        ),
    )
    expect_rejection(
        "plaintext internal Service port restored",
        "must not restore the plaintext internal listener",
        replacement=(
            "deployments/k8s/orchestration/service.yaml",
            "    - port: 8088\n      targetPort: internal-tls\n      name: internal-tls",
            "    - port: 8085\n      targetPort: internal-api\n      name: internal-api\n"
            "    - port: 8088\n      targetPort: internal-tls\n      name: internal-tls",
        ),
    )
    expect_rejection(
        "public Service retarget",
        "must preserve named public http port 8084 -> 8084",
        replacement=(
            "deployments/k8s/orchestration/service.yaml",
            "port: 8084\n      targetPort: 8084\n      name: http",
            "port: 8084\n      targetPort: internal-tls\n      name: http",
        ),
    )
    expect_rejection(
        "workspace-binding Service carrying 8088",
        "must be one ClusterIP Service exposing only 8087",
        replacement=(
            "deployments/k8s/orchestration/service.yaml",
            "    - port: 8087\n      targetPort: workspace-bind\n      name: workspace-bind",
            "    - port: 8087\n      targetPort: workspace-bind\n      name: workspace-bind\n"
            "    - port: 8088\n      targetPort: internal-tls\n      name: internal-tls",
        ),
    )
    expect_rejection(
        "main Service carrying 8087",
        "only the workspace-binding Service may expose port 8087",
        replacement=(
            "deployments/k8s/orchestration/service.yaml",
            "    - port: 8088\n      targetPort: internal-tls\n      name: internal-tls",
            "    - port: 8088\n      targetPort: internal-tls\n      name: internal-tls\n"
            "    - port: 8087\n      targetPort: workspace-bind\n      name: workspace-bind",
        ),
    )
    expect_rejection(
        "missing workspace-bind container port",
        "must declare named workspace-bind container port 8087",
        replacement=(
            "deployments/k8s/orchestration/deployment.yaml",
            "containerPort: 8087",
            "containerPort: 8089",
        ),
    )
    expect_rejection(
        "local overlay without the binding port",
        "local-kind/orchestration-deployment-patch.yaml: must set ORCHESTRATION_WORKSPACE_BINDING_PORT=8087",
        replacement=(
            "deployments/k8s/overlays/local-kind/orchestration-deployment-patch.yaml",
            "ORCHESTRATION_WORKSPACE_BINDING_PORT",
            "ORCHESTRATION_UNUSED_PORT",
        ),
    )
    expect_rejection(
        "ingress to the workspace-binding Service",
        "no edge may route to the workspace-binding listener",
        replacement=(
            "deployments/k8s/base/ingress.yaml",
            "kind: Ingress",
            "kind: Ingress\n# backend: codewire-orchestration-workspace-binding",
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
            elif target.group(1) == "8086":
                backend = "credential-service"
            elif target.group(1) == "8090":
                backend = "coordinator"
            elif target.group(1) == "18090":
                backend = "mesh"
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
            backend_service = None
            for candidate in lines[index + 1 : min(index + 8, len(lines))]:
                backend_match = re.match(
                    r"^\s*name:\s+(codewire-[a-z0-9-]+)", candidate
                )
                if backend_match:
                    backend_service = backend_match.group(1)
                    backend = (
                        "credential-service" if backend_service == "codewire-credential-service"
                        else backend_service.removeprefix("codewire-").split("-", 1)[0]
                    )
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
                rules.append(
                    {
                        "service": service.group(1),
                        "backend": backend,
                        "backend_service": backend_service,
                    }
                )
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
        if re.search(
            r"path:\s+/codewire(?:\\\.|\.)internal(?:\\\.|\.)v1"
            r"(?:\\\.|\.)CoordinatorService/",
            document,
        )
    ]
    if len(matching) != 1:
        fail(f"{label}: expected exactly one separate CoordinatorService Ingress, found {len(matching)}")
        return None
    return matching[0]


def mesh_coordinator_ingress_document(
    text: str, label: str, fail: Callable[[str], None]
) -> str | None:
    matching = [
        document
        for document in re.split(r"^\s*---\s*$", text, flags=re.MULTILINE)
        if re.search(
            r"path:\s+/codewire(?:\\\.|\.)internal(?:\\\.|\.)v1"
            r"(?:\\\.|\.)MeshCoordinatorService/",
            document,
        )
    ]
    if len(matching) != 1:
        fail(
            f"{label}: expected exactly one separate MeshCoordinatorService "
            f"Ingress, found {len(matching)}"
        )
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
        block = caddy_handle_block(text, "/codewire.internal.v1.CoordinatorService/*")
        if not block:
            fail(f"{rel_path}: missing explicit CoordinatorService handle block")
            return
        if not re.search(r"reverse_proxy\s+(?:localhost|127\.0\.0\.1):8090\b", block):
            fail(f"{rel_path}: CoordinatorService must target coordinator :8090 explicitly")
        if not re.search(r"transport\s+http\s*\{[\s\S]*?versions\s+h2c\s+2\b", block):
            fail(f"{rel_path}: CoordinatorService backend transport must enable versions h2c 2")
        return
    assert_coordinator_ingress_shape(coordinator_ingress_document(text, rel_path, fail), rel_path, fail)


def assert_mesh_coordinator_ingress_shape(
    document: str | None,
    label: str,
    expected_backend: str,
    fail: Callable[[str], None],
) -> None:
    if document is None:
        return
    if not re.search(r"^kind:\s+Ingress\s*$", document, re.MULTILINE):
        fail(f"{label}: MeshCoordinatorService route must live in an Ingress object")
    if not re.search(r"pathType:\s+ImplementationSpecific\b", document):
        fail(
            f"{label}: MeshCoordinatorService regex route must use "
            "pathType ImplementationSpecific"
        )
    if not re.search(
        r"nginx\.ingress\.kubernetes\.io/use-regex:\s+[\"']?true[\"']?",
        document,
    ):
        fail(f"{label}: MeshCoordinatorService Ingress must enable use-regex explicitly")
    if not re.search(
        r"nginx\.ingress\.kubernetes\.io/backend-protocol:\s+[\"']?GRPC[\"']?",
        document,
    ):
        fail(f"{label}: MeshCoordinatorService Ingress is missing backend-protocol GRPC")
    if re.search(
        r"nginx\.ingress\.kubernetes\.io/service-upstream:\s+[\"']?true[\"']?",
        document,
    ):
        fail(f"{label}: MeshCoordinatorService must preserve endpoint routing")
    for annotation in ["proxy-request-buffering", "proxy-buffering"]:
        if not re.search(
            rf"nginx\.ingress\.kubernetes\.io/{annotation}:\s+[\"']?off[\"']?",
            document,
        ):
            fail(f"{label}: MeshCoordinatorService Ingress {annotation} must be off for bidi DATA")
    for annotation in ["proxy-read-timeout", "proxy-send-timeout"]:
        if not re.search(
            rf"nginx\.ingress\.kubernetes\.io/{annotation}:\s+[\"']?3600[\"']?",
            document,
        ):
            fail(f"{label}: MeshCoordinatorService Ingress {annotation} must be 3600")
    if not re.search(rf"name:\s+{re.escape(expected_backend)}\b", document):
        fail(
            f"{label}: MeshCoordinatorService Ingress must target "
            f"{expected_backend}:http"
        )
    if not re.search(r"port:\s*\n\s+name:\s+http\b", document):
        fail(f"{label}: MeshCoordinatorService Ingress must target the named http port")


def assert_mesh_coordinator_transport_shape(
    rel_path: str, fail: Callable[[str], None]
) -> None:
    text = read_text(rel_path)
    if rel_path.startswith("Caddyfile"):
        block = caddy_handle_block(
            text, "/codewire.internal.v1.MeshCoordinatorService/*"
        )
        if not block:
            fail(f"{rel_path}: missing explicit MeshCoordinatorService handle block")
            return
        if not re.search(
            r"reverse_proxy\s+(?:localhost|127\.0\.0\.1):18090\b", block
        ):
            fail(f"{rel_path}: MeshCoordinatorService must target Mesh :18090 explicitly")
        if not re.search(
            r"transport\s+http\s*\{[\s\S]*?versions\s+h2c\s+2\b", block
        ):
            fail(
                f"{rel_path}: MeshCoordinatorService backend transport must enable "
                "versions h2c 2"
            )
        return
    assert_mesh_coordinator_ingress_shape(
        mesh_coordinator_ingress_document(text, rel_path, fail),
        rel_path,
        MESH_KUBERNETES_BACKENDS[rel_path],
        fail,
    )


def mesh_coordinator_transport_self_test() -> None:
    """Demonstrate that the Mesh bidi route cannot fall back to HTTP/1."""
    rel_path = "tests/e2e/kind/ingress.yaml"
    document = mesh_coordinator_ingress_document(
        read_text(rel_path), rel_path, lambda message: None
    )
    if document is None:
        raise RuntimeError("Mesh coordinator transport fixture is missing")
    broken = document.replace(
        'nginx.ingress.kubernetes.io/backend-protocol: "GRPC"',
        'nginx.ingress.kubernetes.io/backend-protocol: "HTTP"',
        1,
    )
    failures: list[str] = []
    assert_mesh_coordinator_ingress_shape(
        broken,
        rel_path,
        MESH_KUBERNETES_BACKENDS[rel_path],
        failures.append,
    )
    if not any("backend-protocol GRPC" in failure for failure in failures):
        raise RuntimeError(
            f"Mesh coordinator transport accepted an HTTP/1 backend: {failures!r}"
        )


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


def assert_native_grpc_opt_in_sites(
    fail: Callable[[str], None],
    reader: Callable[[str], str] = read_text,
    sources: list[str] | None = None,
) -> None:
    expected = {
        "crates/codewire-coordinator/src/connect.rs": 1,
        "crates/codewire-mesh/src/server.rs": 1,
        "crates/codewire-orchestration/src/main.rs": 1,
        "crates/codewire-credential-service/src/delegation/wire.rs": 1,
    }
    actual: dict[str, int] = {}
    for rel_path in git_source_files() if sources is None else sources:
        if (
            not rel_path.endswith(".rs")
            or "/tests/" in rel_path
            or rel_path.endswith("/tests.rs")
        ):
            continue
        if rel_path == "crates/codewire-server-core/src/connect.rs":
            continue
        count = reader(rel_path).count("ProtocolPolicy::ConnectAndGrpc")
        if count:
            actual[rel_path] = count
    if actual != expected:
        fail(
            "native-gRPC policy opt-ins must be exactly CoordinatorService, "
            "MeshCoordinatorService, EnvironmentSessionService, and the isolated CredentialDelegationService: "
            f"got {actual}, want {expected}"
        )


def native_grpc_opt_in_sites_self_test() -> None:
    paths = [
        "crates/codewire-coordinator/src/connect.rs",
        "crates/codewire-mesh/src/server.rs",
        "crates/codewire-orchestration/src/main.rs",
        "crates/codewire-credential-service/src/delegation/wire.rs",
    ]
    baseline = {path: read_text(path) for path in paths}
    with_tests = dict(baseline)
    for path in [
        "crates/codewire-credential-service/src/delegation/wire/lifetime/tests.rs",
        "crates/codewire-credential-service/src/delegation/authority/tests/public_wire.rs",
    ]:
        with_tests[path] = "ProtocolPolicy::ConnectAndGrpc"
    failures: list[str] = []
    assert_native_grpc_opt_in_sites(failures.append, with_tests.__getitem__, list(with_tests))
    if failures:
        raise RuntimeError(f"native-gRPC ownership counted test-only mounts: {failures!r}")
    for attack in ["missing delegation opt-in", "duplicate delegation opt-in", "mutation opt-in"]:
        changed = dict(baseline)
        delegation = "crates/codewire-credential-service/src/delegation/wire.rs"
        if attack == "missing delegation opt-in":
            changed[delegation] = changed[delegation].replace("ProtocolPolicy::ConnectAndGrpc", "ProtocolPolicy::ConnectOnly")
        elif attack == "duplicate delegation opt-in":
            changed[delegation] += "\nProtocolPolicy::ConnectAndGrpc\n"
        else:
            changed["crates/codewire-credential-service/src/wire.rs"] = "ProtocolPolicy::ConnectAndGrpc"
        failures: list[str] = []
        assert_native_grpc_opt_in_sites(failures.append, changed.__getitem__, list(changed))
        if not any("native-gRPC policy opt-ins must be exactly" in message for message in failures):
            raise RuntimeError(f"native-gRPC ownership accepted {attack}")


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
    if re.search(r"(name|targetPort):\s+internal-(api|tls)\b", document):
        fail(f"{label}: isolated gRPC Service must not expose the internal API")


def isolated_grpc_service_self_test() -> None:
    """Both internal listeners stay off the native-gRPC Service."""
    base = (
        "kind: Service\nmetadata:\n  name: codewire-orchestration-grpc\nspec:\n"
        "  selector:\n    app.kubernetes.io/name: codewire\n"
        "    app.kubernetes.io/component: orchestration\n"
        "  ports:\n    - name: grpc\n      port: 8084\n      targetPort: http\n"
    )
    failures: list[str] = []
    assert_environment_session_grpc_service_shape(base, "self-test", failures.append)
    if failures:
        raise RuntimeError(f"isolated gRPC Service fixture rejected: {failures!r}")
    for listener, port in [("internal-api", 8085), ("internal-tls", 8088)]:
        failures = []
        assert_environment_session_grpc_service_shape(
            base + f"    - name: {listener}\n      port: {port}\n      targetPort: {listener}\n",
            "self-test",
            failures.append,
        )
        if not any("must not expose the internal API" in failure for failure in failures):
            raise RuntimeError(f"isolated gRPC Service accepted {listener}: {failures!r}")


def assert_rendered_grpc_service(fail: Callable[[str], None]) -> None:
    """The isolated native-gRPC Service, as the orchestration source renders it.

    codewire/deploy's hosted guards check the hosted Dev and Production
    Ingress identities.
    """
    label = "deployments/k8s/orchestration (rendered)"
    result = run(["kustomize", "build", "deployments/k8s/orchestration"], check=False)
    if result.returncode != 0:
        fail(f"{label}: kustomize build failed: {result.stderr.strip() or result.stdout.strip()}")
        return
    assert_environment_session_grpc_service_shape(
        service_document_by_name(result.stdout, "codewire-orchestration-grpc", label, fail),
        f"{label} codewire-orchestration-grpc",
        fail,
    )
