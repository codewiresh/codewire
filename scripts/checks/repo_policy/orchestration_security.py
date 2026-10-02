from .shared import *
from .credential_security import assert_credential_service, credential_service_self_test
from .kubernetes import (
    compact,
    documents,
    exactly_one,
    metadata_field,
    resources_by_kind_and_name,
    top_level_block,
    top_level_field,
)


def assert_credential_bootstrap(resources: list[str], target: dict[str, str], label: str, output: list[str]) -> None:
    """Static permission/intent checks; actual CEL denial is a Kind assertion."""
    name = "codewire-orchestration-credential-bootstrap"
    role = exactly_one(resources, "Role", name, label, output)
    binding = exactly_one(resources, "RoleBinding", name, label, output)
    expected_rules = compact('''
        rules:
        - apiGroups:
          - cert-manager.io
          resources:
          - certificates
          verbs:
          - get
          - create
          - update
          - delete
        - apiGroups:
          - ""
          resources:
          - configmaps
          verbs:
          - get
          - create
          - update
          - delete
    ''')
    if role and (metadata_field(role, "namespace") != target["role_namespace"] or compact(top_level_block(role, "rules")) != expected_rules):
        output.append(f"{label}: credential bootstrap Role must grant only exact namespaced public-object CRUD")
    if binding:
        expected_ref = compact(f"roleRef: apiGroup: rbac.authorization.k8s.io kind: Role name: {name}")
        expected_subject = compact(f"subjects: - kind: ServiceAccount name: codewire-orchestration namespace: {target['subject_namespace']}")
        if (metadata_field(binding, "namespace") != target["role_namespace"]
                or compact(top_level_block(binding, "roleRef")) != expected_ref
                or compact(top_level_block(binding, "subjects")) != expected_subject):
            output.append(f"{label}: credential bootstrap binding escaped its namespace or identity")
    required_by_policy = {
        name: [
            "operations: - CREATE - UPDATE - DELETE",
            "resources: - certificates", "resources: - configmaps",
            "request.operation == 'DELETE' ? oldObject : object",
            "request.resource.resource == 'certificates' ? 'cw-credential-gateway-' : 'cw-credential-codex-'",
            "variables.environment.matches('^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')",
            "request.name == variables.prefix + variables.environment",
            "variables.target.metadata.namespace == request.namespace",
            "oldObject.metadata.labels['codewire.sh/environment-id'] == variables.environment",
            "oldObject.metadata.labels['codewire.sh/org-id'] == variables.labels['codewire.sh/org-id']",
            "oldObject.metadata.labels['app.kubernetes.io/managed-by'] == 'codewire'",
            "oldObject.metadata.labels['codewire.sh/type'] == 'credential-bootstrap'",
            "size(object.data) == 1 && 'config.toml' in object.data && !has(object.binaryData)",
            "object.spec.secretName == request.name",
            "object.spec.issuerRef == {'name':'codewire-credential-gateway','kind':'Issuer','group':'cert-manager.io'}",
            "object.spec.dnsNames == ['cw-gateway-svc-' + variables.environment + '.' + request.namespace + '.svc.cluster.local']",
            "object.spec.isCA == false",
            "object.spec.usages == ['digital signature', 'server auth']",
            "object.spec.duration == '24h' && object.spec.renewBefore == '8h'",
            "object.spec.privateKey == {'algorithm':dyn('ECDSA'),'size':dyn(256),'encoding':dyn('PKCS8'),'rotationPolicy':dyn('Always')}",
            "object.spec.revisionHistoryLimit == 1",
            "object.spec.secretTemplate.labels == variables.labels",
        ] + [f"!has(object.spec.{field})" for field in [
            "subject", "literalSubject", "commonName", "ipAddresses", "uris", "emailAddresses", "otherNames",
            "nameConstraints", "keystores", "additionalOutputFormats", "renewBeforePercentage", "secretTemplate.annotations",
        ]],
        "codewire-orchestration-credential-leaf-cleanup": [
            "operations: - CREATE - UPDATE - DELETE", "resources: - secrets",
            "request.name.startsWith('cw-credential-gateway-')",
            "expression: request.operation == 'DELETE'",
            "oldObject.type == 'kubernetes.io/tls'",
            "oldObject.metadata.namespace == request.namespace",
            "request.name == 'cw-credential-gateway-' + oldObject.metadata.labels['codewire.sh/environment-id']",
            "oldObject.metadata.labels['app.kubernetes.io/managed-by'] == 'codewire'",
            "oldObject.metadata.labels['codewire.sh/type'] == 'credential-bootstrap'",
            "owner.apiVersion == 'cert-manager.io/v1' && owner.kind == 'Certificate'",
            "owner.name == request.name && size(owner.uid) > 0 && has(owner.controller) && owner.controller",
        ],
    }
    for policy_name, required in required_by_policy.items():
        policy = exactly_one(resources, "ValidatingAdmissionPolicy", policy_name, label, output)
        binding = exactly_one(resources, "ValidatingAdmissionPolicyBinding", policy_name, label, output)
        if policy:
            # Kustomize single-quotes scalar CEL ternaries and YAML doubles
            # their embedded apostrophes. Compare the decoded spelling.
            normalized = compact(top_level_block(policy, "spec")).replace("''", "'")
            for fragment in ["failurePolicy: Fail", "matchPolicy: Equivalent",
                    "request.userInfo.username.matches('^system:serviceaccount:[^:]+:codewire-orchestration$')", *required]:
                if fragment not in normalized:
                    output.append(f"{label}: {policy_name} missing {fragment}")
            if metadata_field(policy, "namespace") is not None:
                output.append(f"{label}: {policy_name} must remain cluster-scoped")
        if binding:
            expected = compact(f"spec: policyName: {policy_name} validationActions: - Deny")
            if metadata_field(binding, "namespace") is not None or compact(top_level_block(binding, "spec")) != expected:
                output.append(f"{label}: {policy_name} must deny by identity without mutable namespace selectors")


IMAGE_CACHE_ROLE = "codewire-orchestration-image-cache"
IMAGE_CACHE_NAME = "cw-image-cache"
RELEASE_REVISION_ROLE = "codewire-orchestration-release-revision"
IMAGE_CACHE_IDLE_IMAGE = (
    "docker.io/library/docker:29.7.1-dind@sha256:"
    "e8faad5a8dc5279dff929afc5449f2791736912fff9f99351d742db2fad01b4c"
)
IMAGE_CACHE_IMAGE_PATTERN = (
    "^(registry[.]example[.]invalid|docker[.]io/library)/[a-z0-9]+([._/-][a-z0-9]+)*"
    "(:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?@sha256:[0-9a-f]{64}$"
)


def assert_image_cache(resources: list[str], target: dict[str, str], label: str, output: list[str]) -> None:
    """Static grant/intent checks. The renderer's golden and policy-binding
    tests pin the admitted shape; CEL behaviour is proven on Dev."""
    cluster_role = exactly_one(resources, "ClusterRole", "codewire-orchestration", label, output)
    if cluster_role and re.search(r"^\s*- daemonsets\s*$", cluster_role, re.MULTILINE):
        output.append(f"{label}: cluster-wide orchestration role must not grant DaemonSets")
    revision_role = exactly_one(resources, "Role", RELEASE_REVISION_ROLE, label, output)
    revision_binding = exactly_one(resources, "RoleBinding", RELEASE_REVISION_ROLE, label, output)
    expected_revision_rules = compact("rules: - apiGroups: - apps resources: - replicasets verbs: - get")
    if revision_role and (metadata_field(revision_role, "namespace") != target["subject_namespace"]
            or compact(top_level_block(revision_role, "rules")) != expected_revision_rules):
        output.append(f"{label}: release revision Role must grant only ReplicaSet get in orchestration's namespace")
    if revision_binding:
        expected_ref = compact(f"roleRef: apiGroup: rbac.authorization.k8s.io kind: Role name: {RELEASE_REVISION_ROLE}")
        expected_subject = compact(f"subjects: - kind: ServiceAccount name: codewire-orchestration namespace: {target['subject_namespace']}")
        if (metadata_field(revision_binding, "namespace") != target["subject_namespace"]
                or compact(top_level_block(revision_binding, "roleRef")) != expected_ref
                or compact(top_level_block(revision_binding, "subjects")) != expected_subject):
            output.append(f"{label}: release revision binding escaped its namespace or identity")
    role = exactly_one(resources, "Role", IMAGE_CACHE_ROLE, label, output)
    binding = exactly_one(resources, "RoleBinding", IMAGE_CACHE_ROLE, label, output)
    account = exactly_one(resources, "ServiceAccount", IMAGE_CACHE_NAME, label, output)
    network = exactly_one(resources, "NetworkPolicy", IMAGE_CACHE_NAME, label, output)
    expected_rules = compact('''
        rules:
        - apiGroups:
          - apps
          resources:
          - daemonsets
          verbs:
          - create
        - apiGroups:
          - apps
          resourceNames:
          - cw-image-cache
          resources:
          - daemonsets
          verbs:
          - get
          - update
          - patch
    ''')
    if role and (metadata_field(role, "namespace") != target["role_namespace"] or compact(top_level_block(role, "rules")) != expected_rules):
        output.append(f"{label}: image cache Role must grant only DaemonSet create and cw-image-cache get/update/patch in the sandbox namespace")
    if binding:
        expected_ref = compact(f"roleRef: apiGroup: rbac.authorization.k8s.io kind: Role name: {IMAGE_CACHE_ROLE}")
        expected_subject = compact(f"subjects: - kind: ServiceAccount name: codewire-orchestration namespace: {target['subject_namespace']}")
        if (metadata_field(binding, "namespace") != target["role_namespace"]
                or compact(top_level_block(binding, "roleRef")) != expected_ref
                or compact(top_level_block(binding, "subjects")) != expected_subject):
            output.append(f"{label}: image cache binding escaped its namespace or identity")
    if account and (metadata_field(account, "namespace") != target["role_namespace"]
            or top_level_field(account, "automountServiceAccountToken") != "false"
            or top_level_block(account, "secrets") or top_level_block(account, "imagePullSecrets")):
        output.append(f"{label}: image cache ServiceAccount must be tokenless and credential-free in the sandbox namespace")
    expected_network = compact(f"spec: podSelector: matchLabels: app.kubernetes.io/name: {IMAGE_CACHE_NAME} policyTypes: - Ingress - Egress")
    if network and (metadata_field(network, "namespace") != target["role_namespace"]
            or compact(top_level_block(network, "spec")) != expected_network):
        output.append(f"{label}: image cache NetworkPolicy must deny all ingress and egress in the sandbox namespace")
    policy = exactly_one(resources, "ValidatingAdmissionPolicy", IMAGE_CACHE_ROLE, label, output)
    policy_binding = exactly_one(resources, "ValidatingAdmissionPolicyBinding", IMAGE_CACHE_ROLE, label, output)
    if policy:
        normalized = compact(top_level_block(policy, "spec")).replace("''", "'")
        for fragment in [
            "failurePolicy: Fail", "matchPolicy: Equivalent",
            "operations: - CREATE - UPDATE", "resources: - daemonsets",
            "request.userInfo.username.matches('^system:serviceaccount:[^:]+:codewire-orchestration$')",
            "request.name == 'cw-image-cache'",
            "object.metadata.labels == variables.labels",
            "object.spec.template.metadata.labels == variables.labels",
            "object.spec.selector.matchLabels == {'app.kubernetes.io/name': 'cw-image-cache'}",
            "variables.pod.serviceAccountName == 'cw-image-cache'",
            "never codewire-sandbox",
            "variables.pod.automountServiceAccountToken == false",
            "!has(variables.pod.runtimeClassName)",
            "!variables.pod.hostNetwork", "!variables.pod.hostPID", "!variables.pod.hostIPC",
            "variables.pod.hostUsers == false",
            "size(variables.volumes) <= 6",
            "has(v.image) && has(v.image.reference)",
            f"v.image.reference.matches('{IMAGE_CACHE_IMAGE_PATTERN}')",
            "v.image.pullPolicy == 'IfNotPresent'",
            "(!has(c.securityContext.privileged) || !c.securityContext.privileged)",
            "!c.securityContext.allowPrivilegeEscalation",
            "c.securityContext.readOnlyRootFilesystem",
            "c.securityContext.capabilities.drop == ['ALL']",
            "!has(c.securityContext.capabilities.add)",
            "variables.pod.securityContext.runAsNonRoot",
            "variables.pod.securityContext.seccompProfile.type == 'RuntimeDefault'",
            f"c.image == '{IMAGE_CACHE_IDLE_IMAGE}'",
            "size(object.spec.template.spec.initContainers) == 0",
            "size(variables.containers) == 1",
            "c.command == ['/bin/busybox', 'sleep', '2147483647']",
            "has(m.readOnly) && m.readOnly",
            "m.mountPath == '/cw-image-cache/' + m.name",
            "!has(m.subPath) && !has(m.subPathExpr)",
            "variables.volumes.all(v, variables.containers.exists(c,",
            "c.resources == {'requests': {'cpu': '1m', 'memory': '4Mi'}, 'limits': {'cpu': '10m', 'memory': '16Mi'}}",
            "variables.pod.nodeSelector == {'katacontainers.io/kata-runtime': 'true', 'node.codewire.sh/runtime-candidate': 'true'}",
            "!has(c.env) && !has(c.envFrom) && !has(c.ports)",
            "t.key == 'node.codewire.sh/runtime-candidate'",
            "!has(variables.pod.priorityClassName)",
            "s.name == 'harbor-registry'",
        ]:
            if fragment not in normalized:
                output.append(f"{label}: {IMAGE_CACHE_ROLE} missing {fragment}")
        if metadata_field(policy, "namespace") is not None:
            output.append(f"{label}: {IMAGE_CACHE_ROLE} must remain cluster-scoped")
    if policy_binding:
        expected = compact(f"spec: policyName: {IMAGE_CACHE_ROLE} validationActions: - Deny")
        if metadata_field(policy_binding, "namespace") is not None or compact(top_level_block(policy_binding, "spec")) != expected:
            output.append(f"{label}: {IMAGE_CACHE_ROLE} must deny by identity without mutable namespace selectors")


GATEWAY_REPLICASET_ROLE = "codewire-orchestration-gateway-replicaset"


def assert_gateway_replicaset(resources: list[str], target: dict[str, str], label: str, output: list[str]) -> None:
    """IssueGatewayDaemonCredential reads the gateway Pod's controlling
    ReplicaSet in the sandbox namespace. Without this exact grant every call is
    a 403 and the RPC can only answer unavailable."""
    role = exactly_one(resources, "Role", GATEWAY_REPLICASET_ROLE, label, output)
    binding = exactly_one(resources, "RoleBinding", GATEWAY_REPLICASET_ROLE, label, output)
    expected_rules = compact("rules: - apiGroups: - apps resources: - replicasets verbs: - get")
    if role and (metadata_field(role, "namespace") != target["role_namespace"]
            or compact(top_level_block(role, "rules")) != expected_rules):
        output.append(f"{label}: gateway ReplicaSet Role must grant only ReplicaSet get in the sandbox namespace")
    if binding:
        expected_ref = compact(f"roleRef: apiGroup: rbac.authorization.k8s.io kind: Role name: {GATEWAY_REPLICASET_ROLE}")
        expected_subject = compact(f"subjects: - kind: ServiceAccount name: codewire-orchestration namespace: {target['subject_namespace']}")
        if (metadata_field(binding, "namespace") != target["role_namespace"]
                or compact(top_level_block(binding, "roleRef")) != expected_ref
                or compact(top_level_block(binding, "subjects")) != expected_subject):
            output.append(f"{label}: gateway ReplicaSet binding escaped its namespace or identity")


WORKSPACE_BINDING_INGRESS = "codewire-orchestration-workspace-binding"


def assert_workspace_binding_ingress(resources: list[str], target: dict[str, str], label: str, output: list[str]) -> None:
    """TCP 8087 serves only WorkspaceBindingService, for workspace Pods. Its
    ingress policy must admit only workspace Pods in the target's sandbox
    namespace on 8087, selected by the immutable kubernetes.io/metadata.name
    rather than a namespace label, while every other port keeps accepting
    every source, so adding it never changes what 8084, 8085 or any other
    orchestration port accepts."""
    policy = exactly_one(resources, "NetworkPolicy", WORKSPACE_BINDING_INGRESS, label, output)
    if not policy:
        return
    if metadata_field(policy, "namespace") != target["subject_namespace"]:
        output.append(f"{label}: workspace binding ingress policy must live with orchestration")
    expected = compact(
        f"""
        spec:
          ingress:
          - ports:
            - endPort: 8086
              port: 1
              protocol: TCP
            - endPort: 65535
              port: 8088
              protocol: TCP
            - endPort: 65535
              port: 1
              protocol: UDP
          - from:
            - namespaceSelector:
                matchLabels:
                  kubernetes.io/metadata.name: {target["role_namespace"]}
              podSelector:
                matchLabels:
                  codewire.sh/type: workspace
            ports:
            - port: 8087
              protocol: TCP
          podSelector:
            matchLabels:
              app.kubernetes.io/component: orchestration
              app.kubernetes.io/name: codewire
          policyTypes:
          - Ingress
        """
    )
    if compact(top_level_block(policy, "spec")) != expected:
        output.append(
            f"{label}: workspace binding ingress must admit only {target['role_namespace']} workspace Pods on 8087 "
            "and leave every other orchestration port open to every source"
        )
    others = [
        resource
        for resource in resources
        if top_level_field(resource, "kind") == "NetworkPolicy"
        and metadata_field(resource, "namespace") == target["subject_namespace"]
        and metadata_field(resource, "name") != WORKSPACE_BINDING_INGRESS
        and "component: orchestration" in top_level_block(resource, "spec")
    ]
    if others:
        output.append(f"{label}: another NetworkPolicy also selects orchestration Pods")


def check_orchestration_host_key_authz(args: argparse.Namespace) -> int:
    name = "codewire-orchestration-gateway-host-key"
    orchestration = "codewire-orchestration"
    token_request_name = "codewire-orchestration-tokenrequest"
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

    def assert_token_request_authz(resources: list[str], target: dict[str, str], label: str, output: list[str]) -> None:
        role = exactly_one(resources, "Role", token_request_name, label, output)
        binding = exactly_one(resources, "RoleBinding", token_request_name, label, output)
        if role:
            if metadata_field(role, "namespace") != target["subject_namespace"]:
                output.append(f"{label}: TokenRequest Role must live with orchestration")
            expected_rules = compact(
                f"""
                rules:
                - apiGroups:
                  - ""
                  resourceNames:
                  - {orchestration}
                  resources:
                  - serviceaccounts/token
                  verbs:
                  - create
                """
            )
            if compact(top_level_block(role, "rules")) != expected_rules:
                output.append(
                    f"{label}: TokenRequest Role must grant only create on "
                    f"ServiceAccount/{orchestration}'s token subresource"
                )
        if binding:
            if metadata_field(binding, "namespace") != target["subject_namespace"]:
                output.append(f"{label}: TokenRequest RoleBinding must live with orchestration")
            expected_role_ref = compact(
                f"""
                roleRef:
                  apiGroup: rbac.authorization.k8s.io
                  kind: Role
                  name: {token_request_name}
                """
            )
            if compact(top_level_block(binding, "roleRef")) != expected_role_ref:
                output.append(f"{label}: TokenRequest RoleBinding must reference Role/{token_request_name}")
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
                    f"{label}: TokenRequest RoleBinding must select "
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
                f"RoleBinding/{target['role_namespace']}/codewire-orchestration-credential-bootstrap",
                f"RoleBinding/{target['role_namespace']}/{IMAGE_CACHE_ROLE}",
                f"RoleBinding/{target['role_namespace']}/{GATEWAY_REPLICASET_ROLE}",
                f"RoleBinding/{target['subject_namespace']}/{RELEASE_REVISION_ROLE}",
                f"RoleBinding/{target['subject_namespace']}/{token_request_name}",
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
                "(request.operation == 'DELETE' && request.name.startsWith('cw-credential-gateway-'))",
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
        assert_token_request_authz(resources, target, label, output)
        assert_bound_surface(resources, target, label, output)
        assert_admission(resources, label, output)
        assert_credential_bootstrap(resources, target, label, output)
        assert_image_cache(resources, target, label, output)
        assert_gateway_replicaset(resources, target, label, output)
        assert_workspace_binding_ingress(resources, target, label, output)
        if target["path"] != "deployments/k8s/orchestration":
            assert_credential_service(resources, target, label, output)
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
            "broad TokenRequest grant",
            lambda resources: [
                resource.replace("  - serviceaccounts/token", "  - serviceaccounts")
                if top_level_field(resource, "kind") == "Role"
                and metadata_field(resource, "name") == token_request_name
                else resource
                for resource in resources
            ],
        )
        expect_rejected(
            "unbound TokenRequest resource",
            lambda resources: [
                re.sub(r"  resourceNames:\n  - codewire-orchestration\n", "", resource)
                if top_level_field(resource, "kind") == "Role"
                and metadata_field(resource, "name") == token_request_name
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
        for before, after in [
            ("  - certificates", "  - issuers"),
            ("  - configmaps", "  - secrets"),
            ("kind: Role\n  name: codewire-orchestration-credential-bootstrap", "kind: ClusterRole\n  name: codewire-orchestration-credential-bootstrap"),
            ("'name':'codewire-credential-gateway'", "'name':'unrelated-issuer'"),
            ("'kind':'Issuer'", "'kind':'ClusterIssuer'"),
            ("object.spec.isCA == false", "object.spec.isCA == true"),
            ("'size':dyn(256)", "'size':dyn(384)"),
            ("'rotationPolicy':dyn('Always')", "'rotationPolicy':dyn('Never')"),
            ("'size':dyn(256)", "'size':256"),
            ("!has(object.spec.uris)", "true"),
            ("!has(object.spec.keystores)", "true"),
            ("!has(object.binaryData)", "true"),
            ("oldObject.metadata.labels['codewire.sh/environment-id'] == variables.environment", "true"),
            ("size(owner.uid) > 0", "true"),
            ("has(owner.controller) && owner.controller", "true"),
        ]:
            expect_rejected(f"credential guard {before}", lambda resources, before=before, after=after: [resource.replace(before, after) for resource in resources])
        expect_rejected("credential namespace-label bypass", lambda resources: [
            resource.replace("spec:\n", "spec:\n  matchResources:\n    namespaceSelector:\n      matchLabels:\n        codewire.sh/resource-type: sandbox\n", 1)
            if top_level_field(resource, "kind") == "ValidatingAdmissionPolicyBinding" and metadata_field(resource, "name") == "codewire-orchestration-credential-bootstrap"
            else resource for resource in resources
        ])
        def image_cache_rejected(label: str, kind: str, before: str, after: str, name: str = IMAGE_CACHE_ROLE) -> None:
            # Rendered CEL folds across lines at spaces, and single-quoted
            # YAML scalars double embedded apostrophes; match either spelling.
            def spelling(text: str) -> re.Pattern[str]:
                indent = text[: len(text) - len(text.lstrip(" "))]
                return re.compile(re.escape(indent) + r"\s+".join(re.escape(part) for part in re.split(r" +", text.strip(" "))))

            patterns = [spelling(before), spelling(before.replace("'", "''"))]

            def rewrite(resource: str) -> str:
                for pattern in patterns:
                    if pattern.search(resource):
                        return pattern.sub(lambda _: after.replace("'", "''") if pattern is patterns[1] else after, resource)
                return resource

            def mutate(resources: list[str]) -> list[str]:
                changed = [
                    rewrite(resource)
                    if top_level_field(resource, "kind") == kind and metadata_field(resource, "name") == name
                    else resource
                    for resource in resources
                ]
                if changed == resources:
                    raise RuntimeError(f"image cache negative fixture {label} did not change the render")
                return changed
            expect_rejected(f"image cache {label}", mutate)

        image_cache_rejected("delete verb", "Role", "  - patch", "  - patch\n  - delete")
        image_cache_rejected("unnamed get", "Role", "  resourceNames:\n  - cw-image-cache\n", "")
        image_cache_rejected("pods grant", "Role", "  - daemonsets\n  verbs:\n  - create", "  - daemonsets\n  - pods\n  verbs:\n  - create")
        image_cache_rejected("application namespace", "RoleBinding", "namespace: prod-sandboxes", "namespace: prod")
        image_cache_rejected("token automount", "ServiceAccount", "automountServiceAccountToken: false", "automountServiceAccountToken: true", IMAGE_CACHE_NAME)
        image_cache_rejected("open egress", "NetworkPolicy", "  - Egress", "  - Egress\n  egress:\n  - {}", IMAGE_CACHE_NAME)
        image_cache_rejected("runtime class allowed", "ValidatingAdmissionPolicy", "!has(variables.pod.runtimeClassName)", "true")
        image_cache_rejected("host path allowed", "ValidatingAdmissionPolicy", "has(v.image) && has(v.image.reference)", "true")
        image_cache_rejected("any idle image", "ValidatingAdmissionPolicy", f"c.image == '{IMAGE_CACHE_IDLE_IMAGE}'", "true")
        image_cache_rejected("unbounded volumes", "ValidatingAdmissionPolicy", "size(variables.volumes) <= 6", "true")
        image_cache_rejected("writable image mounts", "ValidatingAdmissionPolicy", "has(m.readOnly) && m.readOnly", "true")
        image_cache_rejected("unmounted volumes", "ValidatingAdmissionPolicy", "variables.volumes.all(v, variables.containers.exists(c,", "variables.volumes.all(v, true || variables.containers.exists(c,")
        image_cache_rejected("any node", "ValidatingAdmissionPolicy", "'katacontainers.io/kata-runtime': 'true', ", "")
        image_cache_rejected("host users", "ValidatingAdmissionPolicy", "variables.pod.hostUsers == false", "true")
        image_cache_rejected("ReplicaSet list", "Role", "  - get", "  - get\n  - list", RELEASE_REVISION_ROLE)
        image_cache_rejected("tag images allowed", "ValidatingAdmissionPolicy", "@sha256:[0-9a-f]{64}$", "")
        image_cache_rejected("sandbox identity allowed", "ValidatingAdmissionPolicy", "serviceAccountName == 'cw-image-cache'", "serviceAccountName != ''")
        image_cache_rejected("any command allowed", "ValidatingAdmissionPolicy", "'sleep', '2147483647'", "'sh'")
        image_cache_rejected("namespace-label bypass", "ValidatingAdmissionPolicyBinding",
                             "spec:\n", "spec:\n  matchResources:\n    namespaceSelector:\n      matchLabels:\n        codewire.sh/resource-type: sandbox\n")
        expect_rejected("missing gateway ReplicaSet grant", lambda resources: [
            resource for resource in resources
            if metadata_field(resource, "name") != GATEWAY_REPLICASET_ROLE
        ])
        image_cache_rejected("gateway ReplicaSet list", "Role", "  - get", "  - get\n  - list", GATEWAY_REPLICASET_ROLE)
        image_cache_rejected("gateway ReplicaSet Pods", "Role", "  - replicasets", "  - replicasets\n  - pods", GATEWAY_REPLICASET_ROLE)
        image_cache_rejected("gateway ReplicaSet in orchestration namespace", "Role",
                             "namespace: prod-sandboxes", "namespace: prod", GATEWAY_REPLICASET_ROLE)
        image_cache_rejected("gateway ReplicaSet other identity", "RoleBinding",
                             "kind: ServiceAccount\n  name: codewire-orchestration", "kind: ServiceAccount\n  name: default",
                             GATEWAY_REPLICASET_ROLE)
        expect_rejected("missing workspace binding ingress", lambda resources: [
            resource for resource in resources
            if not (top_level_field(resource, "kind") == "NetworkPolicy"
                    and metadata_field(resource, "name") == WORKSPACE_BINDING_INGRESS)
        ])
        for binding_label, before, after in [
            ("8087 open to every source", "endPort: 8086", "endPort: 8087"),
            ("8085 narrowed", "endPort: 8086", "endPort: 8084"),
            ("high ports narrowed", "port: 8088", "port: 9000"),
            ("UDP narrowed", "      port: 1\n      protocol: UDP", "      port: 53\n      protocol: UDP"),
            ("any namespace", "    - namespaceSelector:\n        matchLabels:\n          kubernetes.io/metadata.name: prod-sandboxes\n", "    - namespaceSelector: {}\n"),
            ("mutable namespace label", "kubernetes.io/metadata.name: prod-sandboxes", "codewire.sh/resource-type: sandbox"),
            ("another namespace", "kubernetes.io/metadata.name: prod-sandboxes", "kubernetes.io/metadata.name: prod"),
            ("any Pod", "codewire.sh/type: workspace", "codewire.sh/type: gateway"),
            ("egress isolation", "  - Ingress", "  - Ingress\n  - Egress"),
        ]:
            def mutate(resources: list[str], before: str = before, after: str = after) -> list[str]:
                changed = [
                    resource.replace(before, after, 1)
                    if top_level_field(resource, "kind") == "NetworkPolicy"
                    and metadata_field(resource, "name") == WORKSPACE_BINDING_INGRESS
                    else resource
                    for resource in resources
                ]
                if changed == resources:
                    raise RuntimeError(f"workspace binding negative fixture {binding_label} did not change the render")
                return changed
            expect_rejected(f"workspace binding ingress {binding_label}", mutate)
        expect_rejected("second orchestration ingress policy", lambda resources: resources + [
            resources_by_kind_and_name(resources, "NetworkPolicy", WORKSPACE_BINDING_INGRESS)[0]
            .replace(f"name: {WORKSPACE_BINDING_INGRESS}", "name: codewire-orchestration-extra")
        ])
        expect_rejected("image cache cluster-wide DaemonSets", lambda resources: [
            resource.replace("  - deployments\n", "  - deployments\n  - daemonsets\n", 1)
            if top_level_field(resource, "kind") == "ClusterRole" and metadata_field(resource, "name") == orchestration
            else resource for resource in resources
        ])
        if expected_admission_allows("CREATE", "unrelated-secret", {"type": "Opaque", "metadata": {"labels": {}}}) or expected_admission_allows("DELETE", "unrelated-secret"):
            raise RuntimeError("unrelated Secret create/delete fixture was accepted")

    try:
        credential_target = {"subject_namespace": "prod", "role_namespace": "prod-sandboxes"}
        credential_resources = documents(run(["kustomize", "build", "deployments/k8s/credential-service"]).stdout)
        assert_credential_service(credential_resources, credential_target, "credential-service (rendered)", failures)
        for target in targets:
            rendered = run(["kustomize", "build", target["path"]]).stdout
            failures.extend(verify_resources(documents(rendered), target, f"{target['path']} (rendered)"))
        if args.self_test:
            self_test()
            credential_service_self_test(credential_resources, credential_target)
            dev_target = targets[1]
            dev_resources = documents(run(["kustomize", "build", dev_target["path"]]).stdout)
            credential_service_self_test(dev_resources, dev_target)
    except Exception as error:  # noqa: BLE001 - repo check script
        failures.append(str(error))

    if failures:
        for failure in failures:
            print(f"::error::orchestration host-key authorization: {failure}", file=sys.stderr)
        return 1
    print(f"orchestration host-key authorization: OK ({len(targets)} rendered target(s))")
    return 0
