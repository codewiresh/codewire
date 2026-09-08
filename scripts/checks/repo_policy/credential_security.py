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
         '- apiGroups: - apps resources: - deployments - replicasets verbs: - get '
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
            "name: CREDENTIAL_CODEX_EXECUTABLE value: /usr/local/bin/codex",
            "name: CREDENTIAL_GITHUB_EXECUTABLE value: /usr/local/bin/gh",
            "name: CREDENTIAL_RUNTIME_DIR value: /run/codewire-credentials",
            "name: broker-tls secret: defaultMode: 288 secretName: codewire-credential-broker-tls",
            "emptyDir: medium: Memory sizeLimit: 64Mi name: enrollment-runtime",
            "mountPath: /run/codewire-credential-tls name: broker-tls readOnly: true",
            "configMap: name: codewire-credential-database-roots name: database-roots",
            "startupProbe: failureThreshold: 18 httpGet: path: /healthz port: http periodSeconds: 5 timeoutSeconds: 2",
        ]:
            if required not in shape:
                failures.append(f"{label}: isolated credential Deployment missing {required}")
        for forbidden in ["envFrom:", "hostPath:", "hostNetwork: true", "privileged: true", "subPath:"]:
            if forbidden in shape:
                failures.append(f"{label}: isolated credential Deployment contains {forbidden}")
        if (shape.count("secretKeyRef:") != 1 or shape.count("secretName:") != 1
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
    ingress_namespace = "ingress-nginx" if local else "kube-system"
    ingress_app = "ingress-nginx" if local else "rke2-ingress-nginx"
    if policy and compact(top_level_block(policy, "spec")) != (
        "spec: ingress: - from: - namespaceSelector: matchLabels: "
        f"kubernetes.io/metadata.name: {ingress_namespace} podSelector: matchLabels: "
        f"app.kubernetes.io/name: {ingress_app} ports: - port: 8086 protocol: TCP "
        "- from: - namespaceSelector: matchLabels: "
        f"kubernetes.io/metadata.name: {sandbox} podSelector: matchLabels: "
        "app.kubernetes.io/managed-by: codewire app.kubernetes.io/name: codewire-gateway "
        "codewire.sh/type: gateway ports: - port: 9443 protocol: TCP "
        "podSelector: matchLabels: app.kubernetes.io/component: credential-service "
        "app.kubernetes.io/name: codewire policyTypes: - Ingress"
    ):
        failures.append(f"{label}: credential ingress must separate the public edge and managed gateways")


def credential_service_self_test(resources: list[str], target: dict[str, str]) -> None:
    for kind, name, before, after, wanted in [
        ("Role", "codewire-credential-service-runtime", "- pods", "- secrets", "exact authority"),
        ("Role", "codewire-credential-service-tokenrequest", "- codewire-credential-service",
         "- codewire-orchestration", "exact authority"),
        ("RoleBinding", "codewire-credential-service-runtime",
         f"namespace: {target['role_namespace']}", f"namespace: {target['subject_namespace']}", "identity"),
        ("Deployment", "codewire-credential-service", "medium: Memory", "medium: Disk", "Memory"),
        ("Deployment", "codewire-credential-service", "secretKeyRef:", "envFrom:", "unexpected secret input"),
        ("Deployment", "codewire-credential-service", "name: codewire-credential-database",
         "name: codewire-secrets", "CREDENTIAL_DATABASE_URL"),
        ("Deployment", "codewire-credential-service", "CREDENTIAL_GITHUB_EXECUTABLE",
         "MISSING_GITHUB_EXECUTABLE", "CREDENTIAL_GITHUB_EXECUTABLE"),
        ("Deployment", "codewire-credential-service", "/usr/local/bin/gh",
         "/untrusted/bin/gh", "CREDENTIAL_GITHUB_EXECUTABLE"),
        ("Deployment", "codewire-credential-service", "startupProbe:", "missingProbe:", "startupProbe"),
        ("Certificate", "codewire-credential-broker", "isCA: false", "isCA: true", "exact DNS"),
        ("Certificate", "codewire-credential-broker", ".prod.svc.cluster.local", ".foreign.svc.cluster.local", "exact DNS"),
        ("NetworkPolicy", "codewire-credential-service", "codewire.sh/type: gateway", "codewire.sh/type: workspace", "managed gateways"),
        ("NetworkPolicy", "codewire-credential-service", "port: 9443", "port: 8086", "managed gateways"),
    ]:
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
