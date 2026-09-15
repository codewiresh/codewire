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
    if getattr(_args, "self_test", False):
        try:
            internal_connect_listener_self_test()
            mesh_connect_backend_topology_self_test(ownership, owners, per_file)
            mesh_coordinator_transport_self_test()
            mesh_primary_origin_rest_edge_self_test()
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
    "codewire.internal.v1.GatewayBindingService": (
        "codewire_orchestration::connect::internal::gateway_binding_router"
    ),
    "codewire.internal.v1.MeshAuthorizationService": (
        "codewire_orchestration::connect::mesh_authorization::router"
    ),
}

ISOLATED_CREDENTIAL_SERVICES = {
    "codewire.v1.CredentialMutationService",
    "codewire.v1.CredentialDelegationService",
    "codewire.v1.GithubRepositoryService",
}


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
            "unrouted listener map must contain exactly GatewayBindingService "
            "and MeshAuthorizationService"
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
        if router not in internal_section:
            fail(f"{service} is not mounted on the internal-connect app")
        if router in public_section:
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
    assert_credential_delegation_ingress_shape(
        environment_session,
        f"{label} codewire-environment-session-grpc",
        fail,
    )
    assert_environment_session_grpc_service_shape(
        environment_session_upstream,
        f"{label} codewire-orchestration-grpc",
        fail,
    )

    coordinator_connect_identity = ingress_identity(
        coordinator_connect, f"{label} codewire-coordinator-connect", fail
    )
    environment_session_identity = ingress_identity(
        environment_session, f"{label} codewire-environment-session-grpc", fail
    )
    general_connect_identity = ingress_identity(general_connect, f"{label} codewire-connect", fail)
    if (
        not coordinator_connect_identity
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
        ("codewire-coordinator-connect", coordinator_connect_identity),
        ("codewire-environment-session-grpc", environment_session_identity),
        ("codewire-connect", general_connect_identity),
    ]:
        for field, value in expected.items():
            if identity[field] != value:
                fail(f"{label}: {name} {field} must be {value}, got {identity[field]}")
