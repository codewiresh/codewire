"""Static isolated-service deployment proof; not live admission or role provisioning."""

from .shared import *
from .kubernetes import compact, exactly_one, metadata_field, top_level_block, top_level_field


def assert_credential_service(
    resources: list[str], target: dict[str, str], label: str, failures: list[str]
) -> None:
    name = "codewire-credential-service"
    namespace = target["subject_namespace"]
    sandbox = target["role_namespace"]
    roles = [
        ("ClusterRole", f"{name}-tokenreview", None,
         'rules: - apiGroups: - authentication.k8s.io resources: - tokenreviews verbs: - create'),
        ("Role", f"{name}-tokenrequest", namespace,
         f'rules: - apiGroups: - "" resourceNames: - {name} resources: - serviceaccounts/token verbs: - create'),
        ("Role", f"{name}-runtime", sandbox,
         'rules: - apiGroups: - "" resources: - pods verbs: - get '
         '- apiGroups: - agents.x-k8s.io resources: - sandboxes verbs: - get '
         '- apiGroups: - extensions.agents.x-k8s.io resources: - sandboxclaims verbs: - get'),
    ]
    expected_bindings = set()
    for kind, role_name, role_namespace, rules in roles:
        role = exactly_one(resources, kind, role_name, label, failures)
        if role and (
            metadata_field(role, "namespace") != role_namespace
            or compact(top_level_block(role, "rules")) != rules
        ):
            failures.append(f"{label}: isolated credential role {role_name} escaped exact authority")
        binding_kind = "ClusterRoleBinding" if kind == "ClusterRole" else "RoleBinding"
        expected_bindings.add((binding_kind, role_name, role_namespace))
        binding = exactly_one(resources, binding_kind, role_name, label, failures)
        if binding and (
            metadata_field(binding, "namespace") != role_namespace
            or compact(top_level_block(binding, "roleRef")) !=
                f"roleRef: apiGroup: rbac.authorization.k8s.io kind: {kind} name: {role_name}"
            or compact(top_level_block(binding, "subjects")) !=
                f"subjects: - kind: ServiceAccount name: {name} namespace: {namespace}"
        ):
            failures.append(f"{label}: isolated credential binding {role_name} escaped its identity")
    actual_bindings = [
        (top_level_field(resource, "kind"), metadata_field(resource, "name"), metadata_field(resource, "namespace"))
        for resource in resources
        if top_level_field(resource, "kind") in {"RoleBinding", "ClusterRoleBinding"}
        and re.search(rf"\bname: {name}\b", top_level_block(resource, "subjects"))
    ]
    if len(actual_bindings) != 3 or set(actual_bindings) != expected_bindings:
        failures.append(f"{label}: isolated credential service has unexpected authority bindings")

    deployment = exactly_one(resources, "Deployment", name, label, failures)
    service = exactly_one(resources, "Service", name, label, failures)
    certificate = exactly_one(resources, "Certificate", "codewire-credential-broker", label, failures)
    policy = exactly_one(resources, "NetworkPolicy", name, label, failures)
    for resource in [deployment, service, certificate, policy]:
        if resource and metadata_field(resource, "namespace") != namespace:
            failures.append(f"{label}: credential runtime object escaped its application namespace")
    if deployment:
        shape = compact(top_level_block(deployment, "spec"))
        for required in [
            f"serviceAccountName: {name}", f"command: - /{name}",
            "automountServiceAccountToken: true", "enableServiceLinks: false",
            "readOnlyRootFilesystem: true", "allowPrivilegeEscalation: false",
            "capabilities: drop: - ALL", "runAsNonRoot: true",
            "runAsUser: 65532", "runAsGroup: 65532", "fsGroup: 65532",
            "seccompProfile: type: RuntimeDefault",
            "name: CREDENTIAL_DATABASE_URL valueFrom: secretKeyRef: key: url name: codewire-credential-database",
            "name: CREDENTIAL_GITHUB_APP_CLIENT_ID valueFrom: secretKeyRef: key: client-id name: codewire-github-app-authorization optional: true",
            "name: CREDENTIAL_GITHUB_APP_CLIENT_SECRET valueFrom: secretKeyRef: key: client-secret name: codewire-github-app-authorization optional: true",
            "name: CREDENTIAL_GITHUB_APP_SLUG valueFrom: secretKeyRef: key: slug name: codewire-github-app-authorization optional: true",
            "name: CREDENTIAL_RUNTIME_DIR value: /run/codewire-credentials",
            "name: broker-tls secret: defaultMode: 288 secretName: codewire-credential-broker-tls",
            "emptyDir: medium: Memory sizeLimit: 64Mi name: enrollment-runtime",
            "mountPath: /run/codewire-credential-tls name: broker-tls readOnly: true",
            "configMap: name: codewire-credential-database-roots name: database-roots",
            "startupProbe: failureThreshold: 18 httpGet: path: /healthz port: http periodSeconds: 5 timeoutSeconds: 2",
        ]:
            if required not in shape:
                failures.append(f"{label}: isolated credential Deployment missing {required}")
        # Provider logins are native OAuth; the service runs no provider CLI.
        for forbidden in ["envFrom:", "hostPath:", "hostNetwork: true", "privileged: true", "subPath:",
                          "CREDENTIAL_CODEX_EXECUTABLE", "CREDENTIAL_GITHUB_EXECUTABLE"]:
            if forbidden in shape:
                failures.append(f"{label}: isolated credential Deployment contains {forbidden}")
        if (shape.count("secretKeyRef:") != 4 or shape.count("secretName:") != 1
                or "SESSION_SECRET" in shape or "PGPASSWORD" in shape):
            failures.append(f"{label}: isolated credential Deployment has an unexpected secret input")
    if service and compact(top_level_block(service, "spec")) != (
        "spec: ports: - name: http port: 8086 targetPort: http "
        "- name: broker-tls port: 9443 targetPort: broker-tls "
        "selector: app.kubernetes.io/component: credential-service app.kubernetes.io/name: codewire type: ClusterIP"
    ):
        failures.append(f"{label}: isolated credential Service must separate public 8086/private 9443")
    if certificate and compact(top_level_block(certificate, "spec")) != (
        f"spec: dnsNames: - {name}.{namespace}.svc.cluster.local duration: 24h isCA: false "
        "issuerRef: group: cert-manager.io kind: Issuer name: codewire-credential-broker "
        "privateKey: algorithm: ECDSA encoding: PKCS8 rotationPolicy: Always size: 256 "
        "renewBefore: 8h revisionHistoryLimit: 1 secretName: codewire-credential-broker-tls "
        "usages: - digital signature - server auth"
    ):
        failures.append(f"{label}: broker certificate must bind exact DNS and its dedicated Issuer")
    local = namespace in {"default", "codewire-e2e"}
    dev = namespace == "dev"
    ingress_namespace = "ingress-nginx" if local or dev else "kube-system"
    ingress_app = "ingress-nginx" if local or dev else "rke2-ingress-nginx"
    ingress_labels = f"app.kubernetes.io/name: {ingress_app} "
    if dev:
        ingress_labels = (
            "app.kubernetes.io/component: controller "
            "app.kubernetes.io/instance: ingress-nginx "
            f"{ingress_labels}"
        )
    if policy and compact(top_level_block(policy, "spec")) != (
        "spec: ingress: - from: - namespaceSelector: matchLabels: "
        f"kubernetes.io/metadata.name: {ingress_namespace} podSelector: matchLabels: "
        f"{ingress_labels}"
        "- podSelector: matchLabels: app.kubernetes.io/component: dashboard "
        "app.kubernetes.io/name: codewire ports: - port: 8086 protocol: TCP "
        "- from: - podSelector: matchLabels: app.kubernetes.io/component: orchestration "
        "app.kubernetes.io/name: codewire ports: - port: 9443 protocol: TCP "
        "podSelector: matchLabels: app.kubernetes.io/component: credential-service "
        "app.kubernetes.io/name: codewire policyTypes: - Ingress"
    ):
        failures.append(f"{label}: credential ingress must separate the public edge/same-namespace dashboard and the same-namespace credential relay")


def credential_service_self_test(resources: list[str], target: dict[str, str]) -> None:
    mutations = [
        ("Role", "codewire-credential-service-runtime", "- pods", "- secrets", "exact authority"),
        ("Role", "codewire-credential-service-tokenrequest", "- codewire-credential-service",
         "- codewire-orchestration", "exact authority"),
        ("RoleBinding", "codewire-credential-service-runtime",
         f"namespace: {target['role_namespace']}", f"namespace: {target['subject_namespace']}", "identity"),
        ("Deployment", "codewire-credential-service", "medium: Memory", "medium: Disk", "Memory"),
        ("Deployment", "codewire-credential-service", "secretKeyRef:", "envFrom:", "unexpected secret input"),
        ("Deployment", "codewire-credential-service", "name: codewire-credential-database",
         "name: codewire-secrets", "CREDENTIAL_DATABASE_URL"),
        ("Deployment", "codewire-credential-service", "name: CREDENTIAL_BROKER_TLS_KEY_FILE",
         "name: CREDENTIAL_CODEX_EXECUTABLE", "contains CREDENTIAL_CODEX_EXECUTABLE"),
        ("Deployment", "codewire-credential-service", "name: CREDENTIAL_BROKER_TLS_KEY_FILE",
         "name: CREDENTIAL_GITHUB_EXECUTABLE", "contains CREDENTIAL_GITHUB_EXECUTABLE"),
        ("Deployment", "codewire-credential-service", "key: client-secret",
         "key: deploy-key", "CREDENTIAL_GITHUB_APP_CLIENT_SECRET"),
        ("Deployment", "codewire-credential-service", "name: codewire-github-app-authorization",
         "name: codewire-secrets", "CREDENTIAL_GITHUB_APP_CLIENT_ID"),
        ("Deployment", "codewire-credential-service", "startupProbe:", "missingProbe:", "startupProbe"),
        ("Certificate", "codewire-credential-broker", "isCA: false", "isCA: true", "exact DNS"),
        ("Certificate", "codewire-credential-broker",
         f".{target['subject_namespace']}.svc.cluster.local", ".foreign.svc.cluster.local", "exact DNS"),
        ("NetworkPolicy", "codewire-credential-service", "app.kubernetes.io/component: orchestration",
         "app.kubernetes.io/component: workspace", "credential relay"),
        ("NetworkPolicy", "codewire-credential-service", "port: 9443", "port: 8086", "credential relay"),
        ("NetworkPolicy", "codewire-credential-service",
         "    - podSelector:\n        matchLabels:\n          app.kubernetes.io/component: orchestration",
         "    - namespaceSelector: {}\n      podSelector:\n        matchLabels:\n          app.kubernetes.io/component: orchestration",
         "credential relay"),
        ("NetworkPolicy", "codewire-credential-service", "app.kubernetes.io/component: dashboard",
         "app.kubernetes.io/component: coordinator", "same-namespace dashboard"),
        ("NetworkPolicy", "codewire-credential-service", "port: 8086", "port: 9443", "credential relay"),
        ("NetworkPolicy", "codewire-credential-service",
         "    - podSelector:\n        matchLabels:\n          app.kubernetes.io/component: dashboard",
         "    - namespaceSelector: {}\n      podSelector:\n        matchLabels:\n          app.kubernetes.io/component: dashboard",
         "same-namespace dashboard"),
        ("NetworkPolicy", "codewire-credential-service",
         "    - podSelector:\n        matchLabels:\n          app.kubernetes.io/component: dashboard\n          app.kubernetes.io/name: codewire",
         "    - podSelector: {}", "same-namespace dashboard"),
    ]
    if target["subject_namespace"] == "dev":
        mutations.extend([
            ("NetworkPolicy", "codewire-credential-service",
             "kubernetes.io/metadata.name: ingress-nginx",
             "kubernetes.io/metadata.name: ingress-tenant", "credential ingress"),
            ("NetworkPolicy", "codewire-credential-service",
             "kubernetes.io/metadata.name: ingress-nginx",
             "kubernetes.io/metadata.name: ingress-derp", "credential ingress"),
            ("NetworkPolicy", "codewire-credential-service",
             "app.kubernetes.io/name: ingress-nginx",
             "app.kubernetes.io/name: rke2-ingress-nginx", "credential ingress"),
            ("NetworkPolicy", "codewire-credential-service",
             "app.kubernetes.io/component: controller",
             "app.kubernetes.io/component: default-backend", "credential ingress"),
            ("NetworkPolicy", "codewire-credential-service",
             "app.kubernetes.io/instance: ingress-nginx",
             "app.kubernetes.io/instance: other", "credential ingress"),
        ])
    for kind, name, before, after, wanted in mutations:
        changed = []
        matched = False
        for resource in resources:
            if top_level_field(resource, "kind") == kind and metadata_field(resource, "name") == name:
                if before not in resource:
                    raise RuntimeError(f"missing {name} credential deployment fixture: {before}")
                resource = resource.replace(before, after, 1)
                matched = True
            changed.append(resource)
        failures: list[str] = []
        assert_credential_service(changed, target, "fixture", failures)
        if not matched or not any(wanted in message for message in failures):
            raise RuntimeError(f"accepted broken credential {name}: {before}")
