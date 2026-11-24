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


INTERNAL_ROOTS_ROLE = "codewire-orchestration-internal-roots"


def assert_internal_roots(resources: list[str], target: dict[str, str], label: str, output: list[str]) -> None:
    """Orchestration reads exactly the published roots of its internal TLS
    listeners in the sandbox namespace, and writes nothing there."""
    role = exactly_one(resources, "Role", INTERNAL_ROOTS_ROLE, label, output)
    binding = exactly_one(resources, "RoleBinding", INTERNAL_ROOTS_ROLE, label, output)
    expected_rules = compact('''
        rules:
        - apiGroups:
          - ""
          resourceNames:
          - codewire-orchestration-internal-roots
          resources:
          - configmaps
          verbs:
          - get
    ''')
    if role and (metadata_field(role, "namespace") != target["role_namespace"]
            or compact(top_level_block(role, "rules")) != expected_rules):
        output.append(f"{label}: internal roots Role must grant only get of the published roots ConfigMap")
    if binding:
        expected_ref = compact(f"roleRef: apiGroup: rbac.authorization.k8s.io kind: Role name: {INTERNAL_ROOTS_ROLE}")
        expected_subject = compact(f"subjects: - kind: ServiceAccount name: codewire-orchestration namespace: {target['subject_namespace']}")
        if (metadata_field(binding, "namespace") != target["role_namespace"]
                or compact(top_level_block(binding, "roleRef")) != expected_ref
                or compact(top_level_block(binding, "subjects")) != expected_subject):
            output.append(f"{label}: internal roots binding escaped its namespace or identity")


IMAGE_CACHE_ROLE = "codewire-orchestration-image-cache"
IMAGE_CACHE_NAME = "cw-image-cache"
RELEASE_REVISION_ROLE = "codewire-orchestration-release-revision"
SANDBOX_ROLE = "codewire-orchestration-sandboxes"
# codewire#2282: cluster-scoped grants only, all read-only but TokenReview.
CLUSTER_ROLE_RULES = (
    'rules: - apiGroups: - authentication.k8s.io resources: - tokenreviews verbs: - create '
    '- apiGroups: - "" resources: - namespaces verbs: - get '
    '- apiGroups: - "" resources: - persistentvolumes verbs: - list '
    '- apiGroups: - storage.k8s.io resources: - storageclasses verbs: - get '
    '- apiGroups: - "" resources: - nodes verbs: - get - list '
    '- apiGroups: - node.k8s.io resources: - runtimeclasses verbs: - get '
    # codewire#2238: the API servers' ready list, default/kubernetes only.
    '- apiGroups: - discovery.k8s.io resourceNames: - kubernetes resources: - endpointslices verbs: - get'
)
# Every environment write, only in the shared Sandbox namespace.
SANDBOX_ROLE_RULES = (
    'rules: - apiGroups: - "" resources: - pods verbs: - get - list - delete '
    '- apiGroups: - "" resources: - pods/resize verbs: - patch '
    '- apiGroups: - "" resources: - pods/log verbs: - get '
    '- apiGroups: - "" resources: - pods/exec - pods/portforward verbs: - create - get '
    '- apiGroups: - "" resources: - persistentvolumeclaims verbs: - get - list - patch - delete '
    '- apiGroups: - snapshot.storage.k8s.io resources: - volumesnapshots verbs: - get - create - delete '
    '- apiGroups: - "" resources: - services verbs: - get - list - create - update - delete '
    '- apiGroups: - networking.k8s.io resources: - networkpolicies verbs: - get - list - create - update - delete '
    '- apiGroups: - agents.x-k8s.io resources: - sandboxes verbs: - get - list - patch - update - delete '
    '- apiGroups: - extensions.agents.x-k8s.io resources: - sandboxclaims verbs: - get - list - watch - create - patch - delete '
    '- apiGroups: - extensions.agents.x-k8s.io resources: - sandboxtemplates verbs: - get - list - create - update - patch - delete '
    '- apiGroups: - extensions.agents.x-k8s.io resources: - sandboxwarmpools verbs: - get - list - create - update - delete'
)
IMAGE_CACHE_IDLE_IMAGE = (
    "docker.io/library/docker:29.9.2-dind@sha256:"
    "9e79b879b177fbd72c34376a3dd3d91747da5db49e1f560f76aea59561471977"
)
# The image cache admits images only from the registries
# CODEWIRE_APPROVED_IMAGE_REGISTRIES approves, read from the ConfigMap
# orchestration reads it from (docs/CONFIGURATION.md).
IMAGE_CACHE_REGISTRIES_CONFIGMAP = "codewire-image-registries"
IMAGE_CACHE_REGISTRY_PATTERN = "^[a-z0-9]+([.-][a-z0-9]+)*(:[0-9]+)?(/[a-z0-9]+([._-][a-z0-9]+)*)*/$"
IMAGE_CACHE_NAME_PATTERN = (
    "^[a-z0-9]+([._/-][a-z0-9]+)*"
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
    expected_revision_rules = compact('rules: - apiGroups: - "" resources: - pods verbs: - get - apiGroups: - apps resources: - replicasets verbs: - get')
    if revision_role and (metadata_field(revision_role, "namespace") != target["subject_namespace"]
            or compact(top_level_block(revision_role, "rules")) != expected_revision_rules):
        output.append(f"{label}: release revision Role must grant only Pod and ReplicaSet get in orchestration's namespace")
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
            "paramKind: apiVersion: v1 kind: ConfigMap",
            "params.data['CODEWIRE_APPROVED_IMAGE_REGISTRIES'].split(',')"
            f".filter(r, r.matches('{IMAGE_CACHE_REGISTRY_PATTERN}'))",
            "variables.registries.exists(r, v.image.reference.startsWith(r) && "
            f"v.image.reference.substring(size(r)).matches('{IMAGE_CACHE_NAME_PATTERN}'))",
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
        expected = compact(
            f"spec: paramRef: name: {IMAGE_CACHE_REGISTRIES_CONFIGMAP} "
            f"namespace: {target['subject_namespace']} parameterNotFoundAction: Deny "
            f"policyName: {IMAGE_CACHE_ROLE} validationActions: - Deny"
        )
        if metadata_field(policy_binding, "namespace") is not None or compact(top_level_block(policy_binding, "spec")) != expected:
            output.append(
                f"{label}: {IMAGE_CACHE_ROLE} must deny by identity without mutable namespace selectors, "
                f"reading {IMAGE_CACHE_REGISTRIES_CONFIGMAP} in orchestration's namespace"
            )


WARM_POOL_POLICY = "codewire-orchestration-warm-pool"
WARM_POOL_TEMPLATE_POLICY = "codewire-orchestration-warm-pool-template"
WARM_POOL_MEMBER_POLICY = "codewire-orchestration-warm-pool-member"
WARM_POOL_NAME_PATTERN = "^cw-pool-[1-9][0-9]{0,9}m-[1-9][0-9]{0,9}mi-[1-9][0-9]{0,9}gi-[0-9a-f]{8}$"
WARM_POOL_DIGEST_PATTERN = "^[^@ ]+@sha256:[0-9a-f]{64}$"
# The identity-free workspace and DinD variables, and the pool revision
# marker: the only environment a pool template may set (review M2).
WARM_POOL_ENVIRONMENT = (
    "CODEWIRE_WORKSPACE_SHIM_ADDR", "HOME", "USER", "CODEWIRE_WORKSPACE_BINDING_URL", "CODEWIRE_POD_UID",
    "CODEWIRE_WORKSPACE_POOL_REVISION", "DOCKER_HOST", "DOCKER_TLS_CERTDIR", "CODEWIRE_DOCKER_DATA_IMAGE",
    "CODEWIRE_DOCKER_DATA_ROOT", "CODEWIRE_DOCKER_DATA_SIZE", "CODEWIRE_DOCKER_MOUNT_MODE",
)
WARM_POOL_AUDIENCES = ("codewire.internal.workspace-binding.v1", "codewire.internal.credential-workspace.v1")
# codewire#3626: the pool template's ingress, pinned whole. The controller
# manages the policy (outside the OR: Unmanaged admits all ingress), and the
# ingress is either absent or an empty list (the rollout arm, for templates
# an older orchestration replica writes; removed in #3640) or exactly one
# rule, orchestration's namespace AND its Pod labels in one peer, each
# selector exactly its labels, on exactly TCP 7777 and 2222 (integer ports).
WARM_POOL_MANAGED_POLICY = (
    "(!has(object.spec.networkPolicyManagement) || object.spec.networkPolicyManagement == 'Managed') && "
    "has(object.spec.networkPolicy) && "
)
WARM_POOL_NO_INGRESS_ARM = (
    "(!has(object.spec.networkPolicy.ingress) || size(object.spec.networkPolicy.ingress) == 0 || "
)
WARM_POOL_EXACT_RULE_ARM = (
    "(size(object.spec.networkPolicy.ingress) == 1 && "
    "object.spec.networkPolicy.ingress.all(r, dyn(r).all(k, k in ['from', 'ports']) && "
    "has(r.from) && size(r.from) == 1 && "
    "r.from.all(f, dyn(f).all(k, k in ['namespaceSelector', 'podSelector']) && "
    "has(f.namespaceSelector) && dyn(f.namespaceSelector).all(k, k == 'matchLabels') && "
    "has(f.namespaceSelector.matchLabels) && size(f.namespaceSelector.matchLabels) == 1 && "
    "'kubernetes.io/metadata.name' in f.namespaceSelector.matchLabels && "
    "f.namespaceSelector.matchLabels['kubernetes.io/metadata.name'] == variables.serverNamespace && "
    "has(f.podSelector) && dyn(f.podSelector).all(k, k == 'matchLabels') && "
    "has(f.podSelector.matchLabels) && size(f.podSelector.matchLabels) == 2 && "
    "'app.kubernetes.io/name' in f.podSelector.matchLabels && "
    "f.podSelector.matchLabels['app.kubernetes.io/name'] == 'codewire' && "
    "'app.kubernetes.io/component' in f.podSelector.matchLabels && "
    "f.podSelector.matchLabels['app.kubernetes.io/component'] == 'orchestration') && "
    "has(r.ports) && size(r.ports) == 2 && "
    "r.ports.all(q, dyn(q).all(k, k in ['port', 'protocol']) && has(q.port) && has(q.protocol) && "
    "q.protocol == 'TCP' && type(q.port) == int) && "
    "r.ports.exists(q, q.port == 7777) && r.ports.exists(q, q.port == 2222)))) "
    "message: unclaimed warm-pool members admit no ingress, or only orchestration's identity, in one peer, on TCP 7777 and 2222"
)
WARM_POOL_INGRESS_RULE = WARM_POOL_MANAGED_POLICY + WARM_POOL_NO_INGRESS_ARM + WARM_POOL_EXACT_RULE_ARM
CREDENTIAL_SELF_TEST_TARGETS = ("deployments/k8s/overlays/local-kind",)
WARM_POOL_KIND_TARGETS = ("deployments/k8s/overlays/local-kind", "deployments/k8s/overlays/local-kind-static", "tests/e2e/kind")
# Images without a registry digest a pool template may still run: only the
# Kind e2e overlay's side-loaded daemon image (C4). Every other target admits
# digest-pinned images alone.
WARM_POOL_LOCAL_IMAGES = {"tests/e2e/kind": ["codewire-daemon:e2e"]}
# The public roots ConfigMaps a pool template mounts, each only as its ca.crt:
# orchestration's internal roots everywhere, and the Kind e2e coordinator's
# extra roots there alone (SANDBOX_COORDINATOR_EXTRA_ROOTS).
WARM_POOL_ROOTS_CONFIGMAPS = ["codewire-orchestration-internal-roots"]
WARM_POOL_EXTRA_ROOTS_CONFIGMAPS = {"tests/e2e/kind": ["codewire-coordinator-extra-roots"]}
# The Kind e2e overlay's one test knob beside WARM_POOL_ENVIRONMENT:
# SANDBOX_CODEX_LOGIN_CHECK_PERIOD_SECONDS renders the daemon's period for pool
# members as for environments, so a member renders exactly as the environment
# that adopts it (#3852).
WARM_POOL_EXTRA_ENVIRONMENT = {"tests/e2e/kind": ["CODEWIRE_CODEX_LOGIN_CHECK_PERIOD_SECONDS"]}
# codewire#4000: the template policy's hosted-egress switch, the
# codewire-hosted-egress ConfigMap that orchestration's environment also
# reads (private-docs designs/hosted-egress.md, "Warm-pool template
# admission"). On, only broker-mode templates are admitted; off, only today's.
# Every target here ships it off; only the deploy repository turns it on.
HOSTED_EGRESS_CONFIGMAP = "codewire-hosted-egress"
HOSTED_EGRESS_SWITCH = "CODEWIRE_HOSTED_EGRESS_ENABLED"
HOSTED_EGRESS_KEYS = (
    HOSTED_EGRESS_SWITCH, "CODEWIRE_HOSTED_EGRESS_DAEMON_REPOSITORY", "CODEWIRE_HOSTED_EGRESS_GATEWAY_NAMESPACE",
    "CODEWIRE_HOSTED_EGRESS_GATEWAY_NAME", "CODEWIRE_HOSTED_EGRESS_GATEWAY_OWNER_NAMESPACE",
    "CODEWIRE_HOSTED_EGRESS_GATEWAY_PORT",
    # Orchestration's broker-mode render (#4000): the gateway Service it holds
    # to the pinned address, that address, the fence revision and cluster DNS.
    "CODEWIRE_HOSTED_EGRESS_GATEWAY_SERVICE", "CODEWIRE_HOSTED_EGRESS_GATEWAY_CLUSTER_IP",
    "CODEWIRE_HOSTED_EGRESS_FENCE_REVISION", "CODEWIRE_CLUSTER_DNS_IP",
    # codewire#5602: the one `standard` workspace disk the template policies admit.
    "CODEWIRE_STANDARD_IMAGE_DISK_REFERENCE",
)
HOSTED_EGRESS_BROKER_ENVIRONMENT = ("CODEWIRE_EGRESS_STREAM_ADDR", "CODEWIRE_WORKSPACE_BINDING_ADDR",
    "CODEWIRE_API_ADDR", "CODEWIRE_MESH_ADDR", "CODEWIRE_DERP_ADDR", "CODEWIRE_CLUSTER_DNS_IP",
)
HOSTED_EGRESS_BROKER_AUDIENCES = ("codewire.internal.egress.v1",)
# The broker variables every broker-mode workspace must set (cw-security).
HOSTED_EGRESS_BROKER_REQUIRED_ENVIRONMENT = ("CODEWIRE_EGRESS_STREAM_ADDR", "CODEWIRE_WORKSPACE_BINDING_ADDR",
    "CODEWIRE_API_ADDR", "CODEWIRE_MESH_ADDR", "CODEWIRE_DERP_ADDR", "CODEWIRE_CLUSTER_DNS_IP",
)
# The VM classes the privileged TUN init may run under, on every target: Kind
# adds diagnostic runtimes to runtimeClasses, never to these.
HOSTED_EGRESS_VM_RUNTIME_CLASSES = ("commodity", "commodity-32g")
HOSTED_EGRESS_TUN_COMMAND = "['/usr/local/bin/cw', '__hosted-egress-tun', '--owner-uid', '1000']"
# codewire#5002: a confidential per-environment template's one extra egress
# rule, the Trustee KBS on one port, never in a pool: by namespace alone, or,
# when kbsPeer carries Pod labels (#4000), by namespace and exactly those.
ENVIRONMENT_KBS_FRAGMENTS = (
    "expression: '['codewire-trustee', 'TCP/8080']' name: kbsPeer",
    "object.spec.networkPolicy.egress.all(r, (variables.environmentTemplate && has(variables.pod.runtimeClassName) && "
    "variables.pod.runtimeClassName == 'confidential' && dyn(r).all(k, k in ['to', 'ports']) && has(r.to) && size(r.to) == 1 && "
    "dyn(r.to[0]).all(k, k in ['namespaceSelector', 'podSelector']) && has(r.to[0].namespaceSelector) && "
    "dyn(r.to[0].namespaceSelector).all(k, k == 'matchLabels') && has(r.to[0].namespaceSelector.matchLabels) && "
    "size(r.to[0].namespaceSelector.matchLabels) == 1 && 'kubernetes.io/metadata.name' in r.to[0].namespaceSelector.matchLabels && "
    "r.to[0].namespaceSelector.matchLabels['kubernetes.io/metadata.name'] == variables.kbsPeer[0] && "
    "(size(variables.kbsPeer) == 2 ? !has(r.to[0].podSelector) : "
    "has(r.to[0].podSelector) && dyn(r.to[0].podSelector).all(k, k == 'matchLabels') && "
    "has(r.to[0].podSelector.matchLabels) && "
    "size(r.to[0].podSelector.matchLabels) == size(variables.kbsPeer) - 2 && "
    "r.to[0].podSelector.matchLabels.all(k, (k + '=' + r.to[0].podSelector.matchLabels[k]) in variables.kbsPeer)) && "
    "has(r.ports) && size(r.ports) == 1 && dyn(r.ports[0]).all(k, k in ['port', 'protocol']) && "
    "has(r.ports[0].port) && has(r.ports[0].protocol) && type(r.ports[0].port) == int && "
    "r.ports[0].protocol + '/' + string(r.ports[0].port) == variables.kbsPeer[1]) || ",
)
# codewire#5002: orchestration never takes broker mode off a Sandbox.
SANDBOX_KEEPS_BROKER_MODE = (
    "request.operation != 'UPDATE' || !(has(oldObject.spec.podTemplate) && has(oldObject.spec.podTemplate.metadata) && "
    "has(oldObject.spec.podTemplate.metadata.labels) && 'codewire.sh/egress' in oldObject.spec.podTemplate.metadata.labels && "
    "oldObject.spec.podTemplate.metadata.labels['codewire.sh/egress'] == 'broker') || "
    "has(object.spec.podTemplate) && has(object.spec.podTemplate.metadata) && "
    "has(object.spec.podTemplate.metadata.labels) && 'codewire.sh/egress' in object.spec.podTemplate.metadata.labels && "
    "object.spec.podTemplate.metadata.labels['codewire.sh/egress'] == 'broker'"
)
# codewire#4000: with hosted egress on, orchestration never starts or changes a
# VM Sandbox made before it, only stops it. Every class but runc and none is a
# VM, an unknown one included, so the rule fails closed; on every target.
SANDBOX_DIRECT_RUNTIME_CLASSES = ("runc", "")
SANDBOX_PRE_SWITCH = [
    "paramKind: apiVersion: v1 kind: ConfigMap",
    "- expression: has(params.data) && "
    f"'{HOSTED_EGRESS_SWITCH}' in params.data && params.data['{HOSTED_EGRESS_SWITCH}'] == 'true' name: hostedEgress",
    "- expression: has(object.spec.podTemplate) && has(object.spec.podTemplate.metadata) && "
    "has(object.spec.podTemplate.metadata.labels) && 'codewire.sh/egress' in object.spec.podTemplate.metadata.labels && "
    "object.spec.podTemplate.metadata.labels['codewire.sh/egress'] == 'broker' name: broker",
    # A Sandbox with the broker label alone is made before it too.
    "request.operation != 'UPDATE' || !variables.hostedEgress || variables.wholeBroker || "
    "has(object.spec.operatingMode) && object.spec.operatingMode == 'Suspended' || "
    "![object, oldObject].exists(s, has(s.spec.podTemplate) && has(s.spec.podTemplate.spec) && "
    "has(s.spec.podTemplate.spec.runtimeClassName) && "
    "!(s.spec.podTemplate.spec.runtimeClassName in variables.directRuntimeClasses))",
    "- expression: has(oldObject.spec.podTemplate) && has(oldObject.spec.podTemplate.metadata) && "
    "has(oldObject.spec.podTemplate.metadata.labels) && 'codewire.sh/egress' in oldObject.spec.podTemplate.metadata.labels && "
    "oldObject.spec.podTemplate.metadata.labels['codewire.sh/egress'] == 'broker' name: wasBroker",
    # Broker mode is added to an existing Sandbox only by a start's move to
    # it: with the switch on, to a Sandbox bound to an environment, while it
    # was and stays suspended. What it adds is held by the template policy's
    # broker checks (member_broker_shape_violations).
    "- expression: '!variables.addsBroker || variables.hostedEgress && "
    "has(oldObject.spec.operatingMode) && oldObject.spec.operatingMode == 'Suspended' && "
    "has(object.spec.operatingMode) && object.spec.operatingMode == 'Suspended' && "
    "has(oldObject.spec.podTemplate) && has(oldObject.spec.podTemplate.metadata) && "
    "has(oldObject.spec.podTemplate.metadata.labels) && "
    "'codewire.sh/environment-id' in oldObject.spec.podTemplate.metadata.labels && "
    "size(oldObject.spec.podTemplate.metadata.labels['codewire.sh/environment-id']) > 0 && "
    "'codewire.sh/environment-id' in object.spec.podTemplate.metadata.labels && "
    "object.spec.podTemplate.metadata.labels['codewire.sh/environment-id'] == "
    "oldObject.spec.podTemplate.metadata.labels['codewire.sh/environment-id']' message:",
    # A move keeps the Sandbox's runtime class, none included.
    "- expression: '!variables.addsBroker || has(oldObject.spec.podTemplate) && has(oldObject.spec.podTemplate.spec) && "
    "has(object.spec.podTemplate.spec.runtimeClassName) == has(oldObject.spec.podTemplate.spec.runtimeClassName) && "
    "(!has(object.spec.podTemplate.spec.runtimeClassName) || "
    "object.spec.podTemplate.spec.runtimeClassName == oldObject.spec.podTemplate.spec.runtimeClassName)' message:",
    # The label never goes on without the rest of the shape.
    "request.operation != 'UPDATE' || !variables.broker || variables.wasBroker || variables.wholeBroker message:",
]
# codewire#4000: every identity but orchestration's is refused broker mode
# added to an existing Sandbox; the controller makes one only by creating it.
SANDBOX_BROKER_WRITER_POLICY = "codewire-sandbox-broker-mode"
SANDBOX_BROKER_WRITER = [
    "operations: - UPDATE resources: - sandboxes",
    "- expression: '!request.userInfo.username.matches('^system:serviceaccount:[^:]+:codewire-orchestration$')' "
    "name: not-orchestration",
    "validations: - expression: (variables.wasBroker || !variables.broker) && "
    "(variables.wasWholeBroker || !variables.wholeBroker) message:",
]
# The writer policy's variables are the member policy's, verbatim.
SANDBOX_BROKER_WRITER_VARIABLES = ("broker", "wasBroker", "wholeBroker", "wasWholeBroker")
# codewire#4000, cw-security's first condition on the move to broker mode: the
# member policy holds what a move adds to every check the template policy's
# broker arm applies, from one source. Its validations that start with this
# gate are the template policy's broker rules, each whole, in order: every
# template rule that reads the switch or sets CODEWIRE_VM_EGRESS_MODE
# (codewire#6033), but for the pool's own (gated on the name) and the one
# that reads a template's network policy, which a Sandbox has none of. Every variable those rules read is the template's, verbatim,
# but for these, which a Sandbox decides for itself; its `broker` reads the
# same label (SANDBOX_PRE_SWITCH).
MEMBER_BROKER_SHAPE_GATE = "!variables.addsBroker || ( "
MEMBER_BROKER_SHAPE_RULES = 9
# The whole broker shape: the label, the fence revision annotation, and the
# TUN init or a standard VM. It must match hollow_broker_mode
# (crates/codewire-orchestration/src/sandbox/client/egress_migration.rs),
# whose test pins the same text.
def whole_broker(side: str, label: str) -> str:
    return (f"variables.{label} && has({side}.spec.podTemplate.metadata.annotations) && "
            f"'codewire.sh/egress-fence-revision' in {side}.spec.podTemplate.metadata.annotations && "
            f"has({side}.spec.podTemplate.spec) && (has({side}.spec.podTemplate.spec.runtimeClassName) && "
            f"{side}.spec.podTemplate.spec.runtimeClassName == 'standard' || "
            f"has({side}.spec.podTemplate.spec.initContainers) && "
            f"{side}.spec.podTemplate.spec.initContainers.exists(c, c.name == 'hosted-egress-tun'))")


HOSTED_EGRESS_SWITCH_EXPRESSION = (f"has(params.data) && '{HOSTED_EGRESS_SWITCH}' in params.data && "
                                   f"params.data['{HOSTED_EGRESS_SWITCH}'] == 'true'")
MEMBER_OWN_VARIABLES = {
    "clearing": "false",
    # The switch alone. The template policy's hostedEgress also holds an
    # update that keeps a whole broker template (keepsBroker); a move adds
    # the broker shape to a Sandbox that lacks it, so it is never a keep, and
    # the two differ by design.
    "hostedEgress": HOSTED_EGRESS_SWITCH_EXPRESSION,
    "wholeBroker": whole_broker("object", "broker"),
    "wasWholeBroker": whole_broker("oldObject", "wasBroker"),
    "addsBroker": "request.operation == 'UPDATE' && variables.wholeBroker && !variables.wasWholeBroker",
}
# codewire#6121, cw-security's terms: with the switch off, the template
# policy's broker arm holds a template, and so admits a broker-mode one, only
# for an UPDATE of a per-environment template whose stored version is whole
# broker, to the whole broker shape again, while the switch names a fence
# revision. Its hostedEgress is the switch or that keep, and only switchOn
# reads the switch, so every rule that reads hostedEgress, every broker check
# among them, holds a kept template as it holds one with the switch on.
TEMPLATE_KEEPS_BROKER_VARIABLES = {
    "switchOn": HOSTED_EGRESS_SWITCH_EXPRESSION,
    "wasBroker": "has(oldObject.spec.podTemplate.metadata) && has(oldObject.spec.podTemplate.metadata.labels) && "
                 "'codewire.sh/egress' in oldObject.spec.podTemplate.metadata.labels && "
                 "oldObject.spec.podTemplate.metadata.labels['codewire.sh/egress'] == 'broker'",
    "wholeBroker": whole_broker("object", "broker"),
    "wasWholeBroker": whole_broker("oldObject", "wasBroker"),
    "keepsBroker": "variables.environmentTemplate && request.operation == 'UPDATE' && "
                   "variables.wasWholeBroker && variables.wholeBroker && "
                   "has(params.data) && 'CODEWIRE_HOSTED_EGRESS_FENCE_REVISION' in params.data && "
                   "size(params.data['CODEWIRE_HOSTED_EGRESS_FENCE_REVISION']) > 0",
    "hostedEgress": "variables.switchOn || variables.keepsBroker",
}


def template_keeps_broker_violations(template: str) -> list[str]:
    output: list[str] = []
    variables = {item["name"]: item["expression"] for item in policy_items(template, "variables")}
    for name, expression in TEMPLATE_KEEPS_BROKER_VARIABLES.items():
        if variables.get(name) != expression:
            output.append(f"{WARM_POOL_TEMPLATE_POLICY} variable {name} must be exactly {expression}: {variables.get(name)}")
    readers = sorted(name for name, expression in variables.items() if f"'{HOSTED_EGRESS_SWITCH}'" in expression)
    if readers != ["switchOn"]:
        output.append(f"{WARM_POOL_TEMPLATE_POLICY} reads the switch only in switchOn, not in {readers}")
    readers = sorted(name for name, expression in variables.items() if "variables.switchOn" in expression)
    if readers != ["hostedEgress"]:
        output.append(f"{WARM_POOL_TEMPLATE_POLICY} reads switchOn only in hostedEgress, not in {readers}")
    direct = [item["expression"] for item in policy_items(template, "validations")
              if "variables.switchOn" in item["expression"] or f"'{HOSTED_EGRESS_SWITCH}'" in item["expression"]]
    if direct:
        output.append(f"{WARM_POOL_TEMPLATE_POLICY} rules read the switch only through hostedEgress: {direct[0][:160]}")
    return output


def yaml_scalar(lines: list[str]) -> str:
    """One scalar as kustomize renders it: plain, quoted or a block, folded
    across its lines."""
    first = lines[0].strip()
    if first in ("|", "|-", ">", ">-"):
        return "\n".join(line.strip() for line in lines[1:])
    text = " ".join(line.strip() for line in lines)
    if len(text) > 1 and text[0] == text[-1] == "'":
        return text[1:-1].replace("''", "'")
    if len(text) > 1 and text[0] == text[-1] == '"':
        return json.loads(text)
    return text


def policy_items(policy: str, field: str) -> list[dict[str, str]]:
    """A policy's `validations` or `variables`, each value compacted, as
    kustomize renders it or as its source writes it."""
    lines = [line for line in top_level_block(policy, "spec").split("\n") if not line.lstrip().startswith("#")]
    if f"  {field}:" not in lines:
        return []
    rest = lines[lines.index(f"  {field}:") + 1 :]
    dash = next((line[: len(line) - len(line.lstrip())] for line in rest if line.lstrip().startswith("- ")), "")
    if dash not in ("  ", "    "):
        return []
    key_indent = dash + "  "
    items: list[dict[str, list[str]]] = []
    key = ""
    for line in rest:
        indent = len(line) - len(line.lstrip())
        # A line out of the list's indentation, or at it but not an item,
        # ends the list.
        if line.strip() and (indent < len(dash) or indent == len(dash) and not line.lstrip().startswith("- ")):
            break
        match = re.match(rf"^(?:{re.escape(dash)}- |{re.escape(key_indent)})([A-Za-z]+):(?: (.*))?$", line)
        if match and not line.startswith(key_indent + " "):
            if line.startswith(dash + "- "):
                items.append({})
            key = match.group(1)
            items[-1][key] = [match.group(2) or ""]
        elif items and line.strip():
            items[-1][key].append(line)
    return [{key: compact(yaml_scalar(value)) for key, value in item.items()} for item in items]


def template_broker_rules(template: str) -> list[dict[str, str]]:
    return [
        item for item in policy_items(template, "validations")
        if not item["expression"].startswith("variables.environmentTemplate ||")
        and ("variables.hostedEgress" in item["expression"] or "'CODEWIRE_VM_EGRESS_MODE'" in item["expression"])
        and "object.spec.networkPolicy" not in item["expression"]
    ]


def member_broker_shape_violations(template: str, member: str) -> list[str]:
    output: list[str] = []
    rules = template_broker_rules(template)
    if len(rules) != MEMBER_BROKER_SHAPE_RULES:
        output.append(f"the template policy has {len(rules)} broker rules a move to broker mode is held to, "
                      f"not {MEMBER_BROKER_SHAPE_RULES}")
    expected = [(MEMBER_BROKER_SHAPE_GATE + rule["expression"] + " )", rule.get("message"))
                for rule in rules]
    gated = [(item["expression"], item.get("message")) for item in policy_items(member, "validations")
             if item["expression"].startswith(MEMBER_BROKER_SHAPE_GATE.strip())]
    if gated != expected:
        difference = next((pair for pair in zip(gated, expected) if pair[0] != pair[1]), None)
        output.append(f"{WARM_POOL_MEMBER_POLICY} must hold a move to broker mode to the template policy's "
                      f"{len(expected)} broker rules, each whole and in order, behind {MEMBER_BROKER_SHAPE_GATE.strip()}; "
                      f"it has {len(gated)}" + (f", first differing: {difference[0][0]}" if difference else ""))
    template_variables = {item["name"]: item["expression"] for item in policy_items(template, "variables")}
    member_variables = {item["name"]: item["expression"] for item in policy_items(member, "variables")}
    read: set[str] = set()
    pending = [rule["expression"] for rule in rules]
    while pending:
        for name in re.findall(r"variables\.([A-Za-z]+)", pending.pop()):
            if name not in read:
                read.add(name)
                if name not in MEMBER_OWN_VARIABLES and name != "broker":
                    pending.append(template_variables.get(name, ""))
    for name in sorted(read - set(MEMBER_OWN_VARIABLES) - {"broker"}):
        if member_variables.get(name) != template_variables.get(name):
            output.append(f"{WARM_POOL_MEMBER_POLICY} variable {name} must be the template policy's, verbatim: "
                          f"{member_variables.get(name)}")
    for name, expression in MEMBER_OWN_VARIABLES.items():
        if member_variables.get(name) != expression:
            output.append(f"{WARM_POOL_MEMBER_POLICY} variable {name} must be exactly {expression}: "
                          f"{member_variables.get(name)}")
    return output
# A snapshot's clearing template, exactly as rendered, is excepted from the
# broker arm's shape (codewire#4000): the arm itself, the workspace addresses,
# the resolver, the privilege rule and the TUN init's and its volume's presence;
# and, since it runs no daemon, from the run directory's volume and mount rules.
SNAPSHOT_CLEARING = (
    "- expression: request.name.matches('^cw-snap-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}-clear$') && "
    "has(object.metadata.labels) && 'codewire.sh/type' in object.metadata.labels && "
    "object.metadata.labels['codewire.sh/type'] == 'snapshot-clearing' && "
    "has(object.spec.podTemplate.metadata) && has(object.spec.podTemplate.metadata.labels) && "
    "'codewire.sh/type' in object.spec.podTemplate.metadata.labels && "
    "object.spec.podTemplate.metadata.labels['codewire.sh/type'] == 'snapshot-clearing' && "
    "!variables.egressLabelled && variables.containers.all(c, c.name != 'hosted-egress-tun') && "
    "has(object.spec.networkPolicy) && dyn(object.spec.networkPolicy).all(k, k in ['ingress', 'egress']) && "
    "has(object.spec.networkPolicy.ingress) && size(object.spec.networkPolicy.ingress) == 0 && "
    "has(object.spec.networkPolicy.egress) && size(object.spec.networkPolicy.egress) == 0 name: clearing"
)
SNAPSHOT_CLEARING_USES = 8
# The daemon's run directory is bounded memory on every template but the
# clearing one (docs/dev/SANDBOX-IDENTITY.md, "Memory only"); an update that
# keeps the stored template's run directory unchanged is admitted, so a
# Sandbox rendered before this keeps its own.
RUN_VOLUME_RULE = (
    "variables.clearing || "
    "request.operation == 'UPDATE' && has(oldObject.spec.podTemplate.spec.volumes) && "
    "oldObject.spec.podTemplate.spec.volumes.filter(v, v.name == 'codewire-run') == "
    "variables.volumes.filter(v, v.name == 'codewire-run') || "
    "size(variables.volumes.filter(v, v.name == 'codewire-run')) == 1 && "
    "variables.volumes.all(v, v.name != 'codewire-run' || "
    "dyn(v).all(k, k in ['name', 'emptyDir']) && has(v.emptyDir) && "
    "dyn(v.emptyDir).all(k, k in ['medium', 'sizeLimit']) && "
    "has(v.emptyDir.medium) && v.emptyDir.medium == 'Memory' && "
    "has(v.emptyDir.sizeLimit) && string(v.emptyDir.sizeLimit) == '16Mi')"
)
# What touches the run directory: a mount of codewire-run, a mount at or under
# /codewire/run, or a mount path a runtime would clean onto another path.
RUN_MOUNT_TOUCHES = (
    "m.name == 'codewire-run' || !m.mountPath.startsWith('/') || "
    "m.mountPath.matches('//|(^|/)[.][.]?(/|$)') || "
    "m.mountPath == '/codewire/run' || m.mountPath.startsWith('/codewire/run/')"
)
# Nothing else is mounted over or under the run directory, and the workspace
# container mounts it at exactly /codewire/run; an update that keeps those
# mounts as stored is admitted.
RUN_MOUNT_RULE = (
    "variables.clearing || "
    "request.operation == 'UPDATE' && has(oldObject.spec.podTemplate.spec.containers) && "
    "(oldObject.spec.podTemplate.spec.containers + (has(oldObject.spec.podTemplate.spec.initContainers) ? "
    "oldObject.spec.podTemplate.spec.initContainers : [])).map(c, has(c.volumeMounts) ? "
    f"c.volumeMounts.filter(m, {RUN_MOUNT_TOUCHES}) : []) == "
    f"variables.containers.map(c, has(c.volumeMounts) ? c.volumeMounts.filter(m, {RUN_MOUNT_TOUCHES}) : []) || "
    "variables.containers.all(c, !has(c.volumeMounts) || c.volumeMounts.all(m, "
    f"!({RUN_MOUNT_TOUCHES}) || "
    "dyn(m).all(k, k in ['name', 'mountPath']) && m.name == 'codewire-run' && m.mountPath == '/codewire/run')) && "
    "variables.pod.containers.exists(c, c.name == 'workspace' && has(c.volumeMounts) && "
    "c.volumeMounts.exists(m, m.name == 'codewire-run' && m.mountPath == '/codewire/run'))"
)
# The member policy holds a Sandbox's run directory to the same two rules. A
# Sandbox is never a clearing template (its clearing variable is false), so
# neither carries that exception; an unchanged update keeps a stored one, and
# a stored Sandbox with no volumes, as a snapshot's clearing Sandbox is, has
# no codewire-run to keep (codewire#6344).
MEMBER_RUN_VOLUME_RULE = RUN_VOLUME_RULE.removeprefix("variables.clearing || ").replace(
    "has(oldObject.spec.podTemplate.spec.volumes) && oldObject.spec.podTemplate.spec.volumes.filter(",
    "(has(oldObject.spec.podTemplate.spec.volumes) ? oldObject.spec.podTemplate.spec.volumes : []).filter(",
)
MEMBER_RUN_MOUNT_RULE = RUN_MOUNT_RULE.removeprefix("variables.clearing || ")
HOSTED_EGRESS_FRAGMENTS = [
    # codewire#4000: a broker-mode Pod shares no host namespace, mounts no host
    # path and carries the switch's fence revision; a Sandbox's move to broker
    # mode is held to the same rules (member_broker_shape_violations).
    "!variables.hostedEgress || !variables.broker || (!has(variables.pod.hostNetwork) || !variables.pod.hostNetwork) && "
    "(!has(variables.pod.hostPID) || !variables.pod.hostPID) && (!has(variables.pod.hostIPC) || !variables.pod.hostIPC) && "
    "variables.volumes.all(v, !has(v.hostPath))",
    "!variables.hostedEgress || !variables.broker || has(params.data) && "
    "'CODEWIRE_HOSTED_EGRESS_FENCE_REVISION' in params.data && "
    "size(params.data['CODEWIRE_HOSTED_EGRESS_FENCE_REVISION']) > 0 && "
    "has(object.spec.podTemplate.metadata.annotations) && "
    "'codewire.sh/egress-fence-revision' in object.spec.podTemplate.metadata.annotations && "
    "object.spec.podTemplate.metadata.annotations['codewire.sh/egress-fence-revision'] == "
    "params.data['CODEWIRE_HOSTED_EGRESS_FENCE_REVISION']",
    "paramKind: apiVersion: v1 kind: ConfigMap",
    f"'{HOSTED_EGRESS_SWITCH}' in params.data && params.data['{HOSTED_EGRESS_SWITCH}'] == 'true'",
    "'codewire.sh/egress' in object.spec.podTemplate.metadata.labels",
    "object.spec.podTemplate.metadata.labels['codewire.sh/egress'] == 'broker'",
    # The switch, not the template, picks the arm.
    "variables.hostedEgress ? variables.broker || variables.clearing : !variables.egressLabelled",
    "variables.hostedEgress || has(object.spec.networkPolicy) && dyn(object.spec.networkPolicy).all(k, k in ['ingress', 'egress'])",
    # The broker variables and audience, only with the switch on.
    "variables.hostedEgress && c.name == 'workspace' && e.name in variables.brokerEnvironment && "
    "dyn(e).all(k, k in ['name', 'value']) && has(e.value)",
    "variables.hostedEgress && dyn(s).all(k, k == 'serviceAccountToken') && "
    "has(s.serviceAccountToken.audience) && s.serviceAccountToken.audience in variables.brokerAudiences",
    # The broker arm's egress: each peer exactly one broker peer.
    "!variables.hostedEgress || has(object.spec.networkPolicy) && dyn(object.spec.networkPolicy).all(k, k in ['ingress', 'egress'])",
    "has(r.to) && size(r.to) > 0 && has(r.ports) && size(r.ports) > 0 && r.to.all(t, dyn(t).all(k, k in ['namespaceSelector', 'podSelector'])",
    "has(t.podSelector) && dyn(t.podSelector).all(k, k == 'matchLabels') && has(t.podSelector.matchLabels) && "
    "variables.brokerEgressPeers.exists(b, b[0] == t.namespaceSelector.matchLabels['kubernetes.io/metadata.name'] && "
    "size(t.podSelector.matchLabels) == size(b) - 2 && "
    "t.podSelector.matchLabels.all(k, (k + '=' + t.podSelector.matchLabels[k]) in b)",
    "type(p.port) == int && (p.protocol + '/' + string(p.port)) in b[1].split(',')",
    "[[variables.serverNamespace, 'TCP/8089', 'app.kubernetes.io/name=codewire', 'app.kubernetes.io/component=egress'], "
    "[variables.serverNamespace, 'TCP/8087', 'app.kubernetes.io/name=codewire', 'app.kubernetes.io/component=orchestration'], "
    "[variables.serverNamespace, 'TCP/8443', 'app.kubernetes.io/name=codewire', 'app.kubernetes.io/component=derp'], "
    "[variables.serverNamespace, 'UDP/41641', 'app.kubernetes.io/name=codewire', 'app.kubernetes.io/component=udp-relay']] "
    "+ variables.gatewayPeers",
    # The TUN init: an init container only, switch on, a VM class, exactly
    # its command with nothing added, from the deployment's daemon image.
    "variables.pod.containers.all(c, c.name != 'hosted-egress-tun')",
    "(variables.hostedEgress && has(variables.pod.runtimeClassName) && "
    "(variables.pod.runtimeClassName in variables.vmRuntimeClasses || "
    "variables.environmentTemplate && variables.pod.runtimeClassName == 'confidential') && "
    f"has(c.command) && c.command == {HOSTED_EGRESS_TUN_COMMAND} && "
    "!has(c.args) && !has(c.env) && !has(c.envFrom) && !has(c.volumeDevices) && "
    "has(c.volumeMounts) && size(c.volumeMounts) == 1 && "
    "dyn(c.volumeMounts[0]).all(k, k in ['name', 'mountPath']) && "
    "c.volumeMounts[0].name == 'egress-devnet' && c.volumeMounts[0].mountPath == '/dev/net' && "
    "c.image.matches('^[^@ ]+@sha256:[0-9a-f]{64}$') && "
    "c.image.split('@')[0] in variables.daemonRepositories && "
    "(variables.volumes.exists(v, v.name == 'codewire-bin' && has(v.image) && has(v.image.reference) && "
    "v.image.reference == c.image) || "
    "variables.environmentTemplate && variables.pod.runtimeClassName == 'confidential' && "
    "variables.pod.initContainers.exists(i, i.name == 'codewire-daemon-init' && i.image == c.image)))))",
    # The TUN device's volume: memory-backed exactly as rendered, only with
    # the switch on and always then, mounted at exactly /dev/net by the TUN
    # init and the workspace container only.
    "variables.volumes.all(v, v.name != 'egress-devnet' || "
    "variables.hostedEgress && !variables.standardTemplate && dyn(v).all(k, k in ['name', 'emptyDir']) && has(v.emptyDir) && "
    "dyn(v.emptyDir).all(k, k in ['medium', 'sizeLimit']) && "
    "has(v.emptyDir.medium) && v.emptyDir.medium == 'Memory' && "
    "has(v.emptyDir.sizeLimit) && string(v.emptyDir.sizeLimit) == '1Mi') && "
    "variables.containers.all(c, !has(c.volumeMounts) || c.volumeMounts.all(m, m.name != 'egress-devnet' || "
    "(c.name == 'workspace' || c.name == 'hosted-egress-tun') && "
    "dyn(m).all(k, k in ['name', 'mountPath']) && m.mountPath == '/dev/net')) && "
    "(!variables.hostedEgress || variables.clearing || variables.standardTemplate || variables.volumes.exists(v, v.name == 'egress-devnet'))",
    # The broker arm's privilege: root only for the TUN init, mount-workspace
    # ordered before it, and dind from the official DinD image; no added
    # capability or escalation anywhere.
    "variables.pod.initContainers.map(i, i.name).indexOf('mount-workspace') < "
    "variables.pod.initContainers.map(i, i.name).indexOf('hosted-egress-tun')",
    "size(c.securityContext.capabilities.add) == 0",
    # Neither root init container is a sidecar, and a broker template has the TUN init.
    "c.name == 'hosted-egress-tun' && !has(c.restartPolicy) || c.name == 'mount-workspace' && !has(c.restartPolicy) &&",
    "(!variables.hostedEgress || variables.clearing || variables.standardTemplate || has(variables.pod.initContainers) && "
    "variables.pod.initContainers.exists(c, c.name == 'hosted-egress-tun'))",
    # codewire#5602: only a `standard` template goes without the TUN init and
    # its device; the TUN rule's VM classes still refuse a TUN init under
    # `standard`.
    "expression: variables.environmentTemplate && has(variables.pod.runtimeClassName) && "
    "variables.pod.runtimeClassName == 'standard' name: standardEnvironment",
    "expression: '!variables.environmentTemplate && has(variables.pod.runtimeClassName) && "
    "variables.pod.runtimeClassName == 'standard'' name: standardPool",
    "expression: variables.standardEnvironment || variables.standardPool name: standardTemplate",
    # codewire#5602: the egress mode is a standard template's own, literal,
    # one of two values on an environment and guest-carried on a pool, and
    # always present on one.
    "variables.containers.all(c, !has(c.env) || c.env.all(e, e.name != 'CODEWIRE_VM_EGRESS_MODE' || "
    "c.name == 'workspace' && !has(e.valueFrom) && has(e.value) && "
    "(variables.standardEnvironment && e.value in ['guest-carried', 'broker'] || "
    "variables.standardPool && e.value == 'guest-carried'))) && "
    "(!variables.standardTemplate || variables.pod.containers.exists(c, c.name == 'workspace' && has(c.env) && "
    "c.env.exists_one(e, e.name == 'CODEWIRE_VM_EGRESS_MODE')))",
    # codewire#5602: a standard pool is admitted only in the standard shape.
    "variables.environmentTemplate || variables.standardPool || "
    "(has(variables.pod.runtimeClassName) ? variables.pod.runtimeClassName : '') in variables.runtimeClasses",
    "!variables.standardPool || size(variables.pod.containers) == 1 && variables.pod.containers[0].name == 'workspace' && "
    "!has(variables.pod.initContainers) && size(variables.volumes.filter(v, has(v.image))) == 1 &&",
    "'codewire.sh/kvm' in c.resources.limits && string(c.resources.limits['codewire.sh/kvm']) == '1' &&",
    "c.env.exists(e, e.name == 'CODEWIRE_VM_STATE' && has(e.value) && e.value == 'new') &&",
    # codewire#5602: a standard Pod mounts exactly the deployment's disk, by
    # the parameter's exact reference, and fails closed without one.
    "size(variables.standardDiskReference) > 0 && "
    "variables.volumes.exists(v, v.name == 'image-disk' && has(v.image) && has(v.image.reference) && "
    "v.image.reference == variables.standardDiskReference) &&",
    "variables.standardPool && c.name == 'workspace' && e.name in variables.standardPoolEnvironment && "
    "dyn(e).all(k, k in ['name', 'value']) && has(e.value))))",
    # A broker-mode workspace always has its stream and binding addresses.
    "variables.brokerRequiredEnvironment.all(n, c.env.exists(e, e.name == n && has(e.value) && size(e.value) > 0))",
    # The netstack is the only resolver.
    "has(variables.pod.dnsPolicy) && variables.pod.dnsPolicy == 'None' && has(variables.pod.dnsConfig) && "
    "dyn(variables.pod.dnsConfig).all(k, k in ['nameservers', 'searches']) && has(variables.pod.dnsConfig.nameservers) && "
    "variables.pod.dnsConfig.nameservers == ['192.0.2.1'] && "
    "(!has(variables.pod.dnsConfig.searches) || size(variables.pod.dnsConfig.searches) == 0)",
    "has(variables.pod.securityContext.runAsUser) && variables.pod.securityContext.runAsUser == 1000 && "
    "has(variables.pod.securityContext.runAsGroup) && variables.pod.securityContext.runAsGroup == 1000",
    "(!has(variables.pod.securityContext.supplementalGroups) || size(variables.pod.securityContext.supplementalGroups) == 0)",
    "(!has(c.securityContext.allowPrivilegeEscalation) || !c.securityContext.allowPrivilegeEscalation)",
    "c.name == 'dind' && c.image.matches('^docker[.]io/library/docker:[0-9][0-9.]*-dind@sha256:[0-9a-f]{64}$')",
    # An empty or malformed repository admits no TUN image.
    "params.data['CODEWIRE_HOSTED_EGRESS_DAEMON_REPOSITORY'].matches("
    "'^[a-z0-9]+([.-][a-z0-9]+)*(:[0-9]+)?(/[a-z0-9]+([._-][a-z0-9]+)*)+$') ? "
    "[string(params.data['CODEWIRE_HOSTED_EGRESS_DAEMON_REPOSITORY'])] : []",
]
# Verbs that create, change or remove a ConfigMap.
CONFIGMAP_WRITE_VERBS = {"create", "update", "patch", "delete", "deletecollection", "*"}


def cel_list(values: tuple[str, ...] | list[str]) -> str:
    return "[" + ", ".join(f"'{value}'" for value in values) + "]"


def cluster_role_rules(cluster_role: str) -> list[str]:
    """The ClusterRole's rules, one compacted rule per entry."""
    rules = top_level_block(cluster_role, "rules")
    return [compact("- apiGroups:" + rule) for rule in re.split(r"^- apiGroups:", rules, flags=re.MULTILINE)[1:]]


def assert_warm_pool(resources: list[str], target: dict[str, str], label: str, output: list[str]) -> None:
    """Program #2238 C2. The warm-pool reconciler reads runtime nodes and the
    pool RuntimeClass, nothing more, and three identity-bound admission
    policies bound every pool and pool template orchestration writes and keep
    it off unclaimed members. Template admission is an allowlist (review M2);
    only Kind targets add diagnostic runtimes. CEL behaviour is evaluated
    against the renderer's goldens out of tree and proven on Kind."""
    cluster_role = exactly_one(resources, "ClusterRole", "codewire-orchestration", label, output)
    if cluster_role:
        rules = cluster_role_rules(cluster_role)
        node_rules = [rule for rule in rules if re.search(r"resources: (- [^ ]+ )*- nodes( |$)", rule)]
        if node_rules != ['- apiGroups: - "" resources: - nodes verbs: - get - list']:
            output.append(f"{label}: orchestration may only get and list nodes, in one rule: {node_rules}")
        class_rules = [rule for rule in rules if "runtimeclasses" in rule]
        if class_rules != ["- apiGroups: - node.k8s.io resources: - runtimeclasses verbs: - get"]:
            output.append(f"{label}: orchestration may only get RuntimeClasses, in one rule: {class_rules}")
    required_by_policy = {
        WARM_POOL_POLICY: [
            "operations: - CREATE - UPDATE", "resources: - sandboxwarmpools",
            "request.name.startsWith('cw-pool-')",
            "variables.pool || (has(object.spec.replicas) && object.spec.replicas == 0)",
            f"request.name.matches('{WARM_POOL_NAME_PATTERN}')",
            "object.metadata.labels['app.kubernetes.io/managed-by'] == 'codewire'",
            "object.metadata.labels['codewire.sh/type'] == 'workspace-pool'",
            "object.metadata.annotations['codewire.sh/pool-revision'].matches('^[0-9a-f]{64}$')",
            "object.spec.sandboxTemplateRef.name == request.name",
            "object.spec.updateStrategy.type == 'Recreate'",
            "object.spec.replicas >= 0 && object.spec.replicas <= 16",
        ],
        WARM_POOL_TEMPLATE_POLICY: [
            "operations: - CREATE - UPDATE", "resources: - sandboxtemplates",
            # Every template is matched (#5002): the pool's allowlist gates on
            # the name, and the broker arm holds every template.
            "expression: '!request.name.startsWith('cw-pool-')' name: environmentTemplate",
            f"variables.environmentTemplate || request.name.matches('{WARM_POOL_NAME_PATTERN}')",
            "!variables.identity.exists(k, k in object.metadata.labels)",
            "!variables.identity.exists(k, k in object.spec.podTemplate.metadata.labels)",
            f"variables.containers.all(c, c.image.matches('{WARM_POOL_DIGEST_PATTERN}') || c.image in variables.localImages)",
            f"(v.image.reference.matches('{WARM_POOL_DIGEST_PATTERN}') || v.image.reference in variables.localImages)",
            "!has(variables.pod.ephemeralContainers)",
            "variables.containers.all(c, !has(c.envFrom)",
            f"- expression: '{cel_list(WARM_POOL_AUDIENCES)}' name: audiences",
            "e.name in variables.environment && dyn(e).all(k, k in ['name', 'value', 'valueFrom'])",
            "(!has(e.valueFrom) || (e.name == 'CODEWIRE_POD_UID' && dyn(e.valueFrom).all(k, k == 'fieldRef')",
            "dyn(e.valueFrom.fieldRef).all(k, k in ['fieldPath', 'apiVersion'])",
            "e.valueFrom.fieldRef.fieldPath == 'metadata.uid'",
            "variables.pod.containers.exists_one(c, c.name == 'workspace')",
            "e.name == 'CODEWIRE_WORKSPACE_BINDING_URL'",
            "c.env.exists_one(e, e.name == 'CODEWIRE_WORKSPACE_POOL_REVISION')",
            "e.value == object.metadata.annotations['codewire.sh/pool-revision']",
            "variables.volumes.all(v, dyn(v).all(k, k in ['name', 'image', 'emptyDir', 'configMap', 'projected'])",
            "v.configMap.name in variables.rootsConfigMaps",
            "dyn(v.configMap).all(k, k in ['name', 'items', 'defaultMode'])",
            "has(v.configMap.items) && size(v.configMap.items) == 1",
            "dyn(v.configMap.items[0]).all(k, k in ['key', 'path'])",
            "v.configMap.items[0].key == 'ca.crt' && v.configMap.items[0].path == 'ca.crt'",
            "v.projected.sources.all(s, dyn(s).all(k, k == 'serviceAccountToken')",
            "has(s.serviceAccountToken.audience) && s.serviceAccountToken.audience in variables.audiences",
            "variables.pod.serviceAccountName == 'codewire-sandbox'",
            "variables.pod.automountServiceAccountToken == false",
            "(has(variables.pod.runtimeClassName) ? variables.pod.runtimeClassName : '') in variables.runtimeClasses",
            "(!has(variables.pod.hostNetwork) || !variables.pod.hostNetwork)",
            "(!has(variables.pod.hostPID) || !variables.pod.hostPID)",
            "(!has(variables.pod.hostIPC) || !variables.pod.hostIPC)",
            "!has(variables.pod.hostAliases) && !has(variables.pod.nodeName)",
            "variables.pod.runtimeClassName != 'confidential'",
            "'io.katacontainers.config.hypervisor.kernel_params' in object.spec.podTemplate.metadata.annotations",
            # A Block claim is commodity's (codewire#3718); the confidential
            # claim is ReadWriteOncePod.
            "(!has(t.spec.accessModes) || !('ReadWriteOncePod' in t.spec.accessModes))",
            # Only the one-shot mount-workspace init container holds the
            # workspace device (codewire#3718).
            "variables.pod.containers.all(c, !has(c.volumeDevices))",
            "(c.name == 'mount-workspace' && size(c.volumeDevices) == 1 &&",
            "c.command[2] == variables.mountWorkspaceScript && c.command[3] == 'mount-workspace' &&",
            "v.image.reference == c.image",
            "object.spec.networkPolicyManagement == 'Managed'",
            # codewire#3626: the template ingress is exactly orchestration's
            # identity, in one AND-ed peer, on TCP 7777 and 2222.
            WARM_POOL_MANAGED_POLICY,
            WARM_POOL_NO_INGRESS_ARM,
            WARM_POOL_EXACT_RULE_ARM,
            WARM_POOL_INGRESS_RULE,
            # codewire#3318: egress is the renderer's allowlist.
            "expression: request.userInfo.username.split(':')[2] name: serverNamespace",
            "has(object.spec.networkPolicy.egress) && object.spec.networkPolicy.egress.all(r, dyn(r).all(k, k in ['to', 'ports'])",
            "(t.ipBlock.cidr == '0.0.0.0/0' && variables.nonWorldIPv4.all(c, c in t.ipBlock.except))",
            "(t.ipBlock.cidr == '::/0' && variables.nonWorldIPv6.all(c, c in t.ipBlock.except))",
            "size(t.namespaceSelector.matchLabels) == 1",
            "size(t.podSelector.matchLabels) == 1",
            "r.ports.all(p, dyn(p).all(k, k in ['port', 'protocol'])",
            "'|' + p.protocol + '/' + string(p.port)) in variables.egressPeers",
            "'kube-system||UDP/53', 'kube-system||TCP/53'",
            "variables.serverNamespace + '|app.kubernetes.io/component=orchestration|TCP/8087'",
            "variables.serverNamespace + '|app.kubernetes.io/component=udp-relay|UDP/41641']",
            "'10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16'",
            *HOSTED_EGRESS_FRAGMENTS,
            *ENVIRONMENT_KBS_FRAGMENTS,
            SNAPSHOT_CLEARING,
            RUN_VOLUME_RULE,
            RUN_MOUNT_RULE,
        ],
        WARM_POOL_MEMBER_POLICY: [
            "apiGroups: - agents.x-k8s.io apiVersions: - v1beta1 operations: - CREATE - UPDATE resources: - sandboxes",
            "!(has(object.metadata.labels) && 'agents.x-k8s.io/warm-pool-sandbox' in object.metadata.labels)",
            "!(has(object.metadata.ownerReferences) && object.metadata.ownerReferences.exists(o, o.kind == 'SandboxWarmPool'))",
            "request.operation != 'UPDATE' || (!(has(oldObject.metadata.labels) && 'agents.x-k8s.io/warm-pool-sandbox' in oldObject.metadata.labels)",
            "!(has(oldObject.metadata.ownerReferences) && oldObject.metadata.ownerReferences.exists(o, o.kind == 'SandboxWarmPool'))",
            SANDBOX_KEEPS_BROKER_MODE,
            *SANDBOX_PRE_SWITCH,
            MEMBER_RUN_VOLUME_RULE,
            MEMBER_RUN_MOUNT_RULE,
        ],
        SANDBOX_BROKER_WRITER_POLICY: SANDBOX_BROKER_WRITER,
    }
    for policy_name, required in required_by_policy.items():
        policy = exactly_one(resources, "ValidatingAdmissionPolicy", policy_name, label, output)
        binding = exactly_one(resources, "ValidatingAdmissionPolicyBinding", policy_name, label, output)
        if policy:
            normalized = compact(top_level_block(policy, "spec")).replace("''", "'")
            for fragment in ["failurePolicy: Fail", "matchPolicy: Equivalent",
                    "request.userInfo.username.matches('^system:serviceaccount:[^:]+:codewire-orchestration$')", *required]:
                if fragment not in normalized:
                    output.append(f"{label}: {policy_name} missing {fragment}")
            if metadata_field(policy, "namespace") is not None:
                output.append(f"{label}: {policy_name} must remain cluster-scoped")
            if policy_name == WARM_POOL_TEMPLATE_POLICY:
                # Only Kind adds diagnostic runtimes; the variable stays first
                # so the Kind overlays' test-guarded patch replaces it.
                commodity = ["commodity", "commodity-32g"]
                classes = [*commodity, "runc", ""] if target["path"] in WARM_POOL_KIND_TARGETS else commodity
                found = re.search(r"variables: - expression: '?(\[[^\]]*\])'? name: runtimeClasses ", normalized)
                if not found or found.group(1) != cel_list(classes):
                    output.append(f"{label}: {policy_name} runtime classes must be exactly {cel_list(classes)}, first: "
                                  f"{found.group(1) if found else None}")
                # Only the Kind e2e overlay names a local image, second.
                local = WARM_POOL_LOCAL_IMAGES.get(target["path"], [])
                found = re.search(r"name: runtimeClasses - expression: '?(\[[^\]]*\])'? name: localImages ", normalized)
                if not found or found.group(1) != cel_list(local):
                    output.append(f"{label}: {policy_name} local images must be exactly {cel_list(local)}, second: "
                                  f"{found.group(1) if found else None}")
                # Only the Kind e2e overlay adds its coordinator's roots, third.
                roots = WARM_POOL_ROOTS_CONFIGMAPS + WARM_POOL_EXTRA_ROOTS_CONFIGMAPS.get(target["path"], [])
                found = re.search(r"name: localImages - expression: '?(\[[^\]]*\])'? name: rootsConfigMaps ", normalized)
                if not found or found.group(1) != cel_list(roots):
                    output.append(f"{label}: {policy_name} roots ConfigMaps must be exactly {cel_list(roots)}, third: "
                                  f"{found.group(1) if found else None}")
                # The broker arm's literals are the same on every target.
                for name, values in [("brokerEnvironment", HOSTED_EGRESS_BROKER_ENVIRONMENT),
                                     ("brokerRequiredEnvironment", HOSTED_EGRESS_BROKER_REQUIRED_ENVIRONMENT),
                                     ("brokerAudiences", HOSTED_EGRESS_BROKER_AUDIENCES),
                                     ("vmRuntimeClasses", HOSTED_EGRESS_VM_RUNTIME_CLASSES)]:
                    found = re.search(rf"- expression: '?(\[[^\]]*\])'? name: {name} ", normalized)
                    if not found or found.group(1) != cel_list(values):
                        output.append(f"{label}: {policy_name} {name} must be exactly {cel_list(values)}: "
                                      f"{found.group(1) if found else None}")
                if not prune_protected(policy):
                    output.append(f"{label}: {policy_name} must never be pruned")
                # The clearing exception reaches only the broker arm's shape
                # and the run directory's volume and mount rules.
                uses = normalized.count("variables.clearing")
                if uses != SNAPSHOT_CLEARING_USES:
                    output.append(f"{label}: {policy_name} excepts the clearing template in exactly "
                                  f"{SNAPSHOT_CLEARING_USES} rules (the broker arm's and the run directory's two), not {uses}")
                # Only the Kind e2e overlay adds its test knob's variable (#3852).
                environment = [*WARM_POOL_ENVIRONMENT, *WARM_POOL_EXTRA_ENVIRONMENT.get(target["path"], [])]
                found = re.search(r"- expression: '?(\[[^\]]*\])'? name: environment ", normalized)
                if not found or found.group(1) != cel_list(environment):
                    output.append(f"{label}: {policy_name} workspace environment must be exactly {cel_list(environment)}: "
                                  f"{found.group(1) if found else None}")
            if policy_name == WARM_POOL_MEMBER_POLICY:
                found = re.search(r"- expression: '?(\[[^\]]*\])'? name: directRuntimeClasses(?: |$)", normalized)
                if not found or found.group(1) != cel_list(SANDBOX_DIRECT_RUNTIME_CLASSES):
                    output.append(f"{label}: {policy_name} directRuntimeClasses must be exactly "
                                  f"{cel_list(SANDBOX_DIRECT_RUNTIME_CLASSES)}: {found.group(1) if found else None}")
        if binding:
            expected = compact(f"spec: policyName: {policy_name} validationActions: - Deny")
            if policy_name in (WARM_POOL_TEMPLATE_POLICY, WARM_POOL_MEMBER_POLICY):
                # A missing switch denies, never admits (codewire#4000).
                expected = compact(
                    f"spec: paramRef: name: {HOSTED_EGRESS_CONFIGMAP} namespace: {target['subject_namespace']} "
                    f"parameterNotFoundAction: Deny policyName: {policy_name} validationActions: - Deny"
                )
            if policy_name == WARM_POOL_TEMPLATE_POLICY:
                if not prune_protected(binding):
                    output.append(f"{label}: {policy_name} binding must never be pruned")
            if metadata_field(binding, "namespace") is not None or compact(top_level_block(binding, "spec")) != expected:
                output.append(f"{label}: {policy_name} must deny by identity without mutable namespace selectors")
    template = resources_by_kind_and_name(resources, "ValidatingAdmissionPolicy", WARM_POOL_TEMPLATE_POLICY)
    member = resources_by_kind_and_name(resources, "ValidatingAdmissionPolicy", WARM_POOL_MEMBER_POLICY)
    if len(template) == 1:
        output.extend(f"{label}: {violation}" for violation in template_keeps_broker_violations(template[0]))
    if len(template) == 1 and len(member) == 1:
        output.extend(f"{label}: {violation}" for violation in member_broker_shape_violations(template[0], member[0]))
    writer = resources_by_kind_and_name(resources, "ValidatingAdmissionPolicy", SANDBOX_BROKER_WRITER_POLICY)
    if len(writer) == 1 and len(member) == 1:
        ours = {item["name"]: item["expression"] for item in policy_items(writer[0], "variables")}
        theirs = {item["name"]: item["expression"] for item in policy_items(member[0], "variables")}
        for name in SANDBOX_BROKER_WRITER_VARIABLES:
            if name not in theirs or ours.get(name) != theirs[name]:
                output.append(f"{label}: {SANDBOX_BROKER_WRITER_POLICY} variable {name} must be "
                              f"{WARM_POOL_MEMBER_POLICY}'s, verbatim: {ours.get(name)}")
    assert_hosted_egress_param(resources, target, label, output)
    output.extend(orchestration_configmap_writes(resources, label))


def prune_protected(document: str) -> bool:
    return "kustomize.toolkit.fluxcd.io/prune: disabled" in compact(top_level_block(document, "metadata"))


def assert_hosted_egress_param(resources: list[str], target: dict[str, str], label: str, output: list[str]) -> None:
    """codewire#4000: one switch for orchestration and the template policy,
    in orchestration's namespace, never pruned, and off on every target here."""
    param = exactly_one(resources, "ConfigMap", HOSTED_EGRESS_CONFIGMAP, label, output)
    if param:
        if metadata_field(param, "namespace") != target["subject_namespace"]:
            output.append(f"{label}: {HOSTED_EGRESS_CONFIGMAP} must be in orchestration's namespace")
        if not prune_protected(param):
            output.append(f"{label}: {HOSTED_EGRESS_CONFIGMAP} must never be pruned")
        data = top_level_block(param, "data")
        keys = re.findall(r"^  ([A-Z0-9_]+):", data, re.MULTILINE)
        if sorted(keys) != sorted(HOSTED_EGRESS_KEYS):
            output.append(f"{label}: {HOSTED_EGRESS_CONFIGMAP} must carry exactly {sorted(HOSTED_EGRESS_KEYS)}: {sorted(keys)}")
        if not re.search(rf"^  {HOSTED_EGRESS_SWITCH}: ['\"]?false['\"]?$", data, re.MULTILINE):
            output.append(f"{label}: {HOSTED_EGRESS_CONFIGMAP} ships hosted egress off")
    deployment = exactly_one(resources, "Deployment", "codewire-orchestration", label, output)
    if deployment and compact(
        f"- name: {HOSTED_EGRESS_SWITCH} valueFrom: configMapKeyRef: key: {HOSTED_EGRESS_SWITCH} name: {HOSTED_EGRESS_CONFIGMAP}"
    ) not in compact(deployment):
        output.append(f"{label}: orchestration must read {HOSTED_EGRESS_SWITCH} from {HOSTED_EGRESS_CONFIGMAP}")
    for config in resources_by_kind_and_name(resources, "ConfigMap", "codewire-config") + [
        resource for resource in resources
        if top_level_field(resource, "kind") == "ConfigMap" and (metadata_field(resource, "name") or "").startswith("codewire-config-")
    ]:
        if re.search(rf"^  {HOSTED_EGRESS_SWITCH}:", top_level_block(config, "data"), re.MULTILINE):
            output.append(f"{label}: {HOSTED_EGRESS_SWITCH} has one source, {HOSTED_EGRESS_CONFIGMAP}")


def rule_lists(rule: str) -> dict[str, list[str]]:
    """One rendered RBAC rule's lists (apiGroups, resources, verbs, ...)."""
    lists: dict[str, list[str]] = {}
    key = ""
    for line in rule.split("\n"):
        field = re.match(r"^(?:- |  )([A-Za-z]+):\s*(\[\])?$", line)
        if field:
            key = field.group(1)
            lists[key] = []
            continue
        item = re.match(r"^  - ['\"]?([^'\"]*)['\"]?$", line)
        if item and key:
            lists[key].append(item.group(1))
    return lists


def orchestration_configmap_writes(resources: list[str], label: str) -> list[str]:
    """codewire#4000 (cw-security): the hosted-egress switch is only as
    strong as orchestration's inability to write it. No Role or ClusterRole
    bound to orchestration's service account, the only one its TokenRequest
    grant mints for, or to a group holding every service account, may create,
    change or remove a ConfigMap, by name or by wildcard."""
    holders = re.compile(
        r"^- kind: ServiceAccount\n  name: codewire-orchestration$"
        r"|^- apiGroup: rbac.authorization.k8s.io\n  kind: Group\n  name: system:(serviceaccounts(:[^\n]+)?|authenticated)$",
        re.MULTILINE,
    )
    bound: set[tuple[str, str, str | None]] = set()
    for resource in resources:
        kind = top_level_field(resource, "kind")
        if kind not in ("RoleBinding", "ClusterRoleBinding") or not holders.search(top_level_block(resource, "subjects")):
            continue
        reference = re.search(r"kind: (Role|ClusterRole) name: (\S+)", compact(top_level_block(resource, "roleRef")))
        if reference:
            namespace = metadata_field(resource, "namespace") if reference.group(1) == "Role" else None
            bound.add((reference.group(1), reference.group(2), namespace))
    output = []
    for kind, name, namespace in sorted(bound, key=str):
        for role in resources_by_kind_and_name(resources, kind, name):
            if namespace is not None and metadata_field(role, "namespace") != namespace:
                continue
            for rule in re.split(r"^(?=- )", top_level_block(role, "rules"), flags=re.MULTILINE):
                lists = rule_lists(rule)
                if (set(lists.get("apiGroups", [])) & {"", "*"} and set(lists.get("resources", [])) & {"configmaps", "*"}
                        and set(lists.get("verbs", [])) & CONFIGMAP_WRITE_VERBS):
                    output.append(f"{label}: {kind}/{name} lets orchestration write ConfigMaps, "
                                  f"which would let it flip {HOSTED_EGRESS_CONFIGMAP}: {compact(rule)}")
    return output


WORKSPACE_BINDING_INGRESS = "codewire-orchestration-workspace-binding"


def own_pod_selector(policy: str) -> str:
    """A NetworkPolicy's own spec.podSelector, not the selectors of its peers:
    the credential service admits orchestration as a peer without selecting
    orchestration's Pods."""
    lines = top_level_block(policy, "spec").split("\n")
    start = next((index for index, line in enumerate(lines) if line == "  podSelector:"), -1)
    if start < 0:
        return ""
    end = next(
        (index for index in range(start + 1, len(lines)) if not lines[index].startswith("    ")),
        len(lines),
    )
    return "\n".join(lines[start:end])


def assert_workspace_binding_ingress(resources: list[str], target: dict[str, str], label: str, output: list[str]) -> None:
    """TCP 8087 serves only WorkspaceBindingService, for workspace Pods. Its
    ingress policy must admit only workspace Pods in the target's sandbox
    namespace on 8087, selected by the immutable kubernetes.io/metadata.name
    rather than a namespace label, while every other port keeps accepting
    every source, so adding it never changes what 8084, 8088 or any other
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
        and "component: orchestration" in own_pod_selector(resource)
    ]
    if others:
        output.append(f"{label}: another NetworkPolicy also selects orchestration Pods")


# Program #2238 C6 (#2434): the warm-member bridge. Orchestration renders
# every NetworkPolicy it creates in template/network.rs; the Rust test pins the
# renderer to these goldens, and this guard pins every rendered policy that
# selects through an agents.x-k8s.io label against the bridge invariant, so
# neither can drift alone.
WARM_BRIDGE_FIXTURE_DIR = "crates/codewire-orchestration/tests/fixtures/sandbox"
WARM_BRIDGE_FIXTURES = {
    "daemon": f"{WARM_BRIDGE_FIXTURE_DIR}/warm-member-bridge-daemon-networkpolicy.golden.json",
}
WARM_BRIDGE_RENDERER = "crates/codewire-orchestration/src/sandbox/template/network.rs"
WARM_BRIDGE_NAMING = "crates/codewire-orchestration/src/sandbox/template/naming.rs"
AGENTS_LABEL_PREFIX = "agents.x-k8s.io/"
SANDBOX_UID_LABEL = "agents.x-k8s.io/sandbox-uid"
CANONICAL_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
WARM_BRIDGE_NAME = re.compile(rf"cw-(daemon)-warm-({CANONICAL_UUID})")
ORCHESTRATION_PEER_POD = {"app.kubernetes.io/name": "codewire", "app.kubernetes.io/component": "orchestration"}
# The daemon's tailnet UDP port admits the world only (design §5, N1): every
# cluster and Pod range is excepted.
WORKSPACE_TAILNET_UDP_PORTS = [{"port": 31000, "protocol": "UDP"}]
WORLD_EXCEPTIONS = {
    "0.0.0.0/0": {"10.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12", "192.168.0.0/16"},
    "::/0": {"fc00::/7"},
}


UDP_RELAY = "codewire-udp-relay"
UDP_RELAY_TLS_SECRET = "codewire-udp-relay-allocator-tls"
# The allocator's TLS port 8097 is its only one; the plain port is gone (#4011).
UDP_RELAY_PLAIN_ALLOCATOR_PORT = 8095
# Rendered keys are sorted, so each list ends at the key that follows it.
UDP_RELAY_PORTS = """
ports:
- containerPort: 41641
  name: udp
  protocol: UDP
- containerPort: 8097
  name: allocator-tls
- containerPort: 8096
  name: http
readinessProbe:
"""
UDP_RELAY_SERVICE_PORTS = """
spec:
  ports:
  - name: udp
    port: 41641
    protocol: UDP
    targetPort: 41641
  - name: allocator-tls
    port: 8097
    targetPort: 8097
  selector:
"""
# The relay allocates over TLS only for the certificate with this name, which
# orchestration's client leaf carries.
UDP_RELAY_TLS_ENV = [
    """
    - name: CODEWIRE_UDP_RELAY_ALLOCATOR_TLS_CERT
      value: /run/codewire-udp-relay-allocator-tls/tls.crt
    """,
    """
    - name: CODEWIRE_UDP_RELAY_ALLOCATOR_TLS_KEY
      value: /run/codewire-udp-relay-allocator-tls/tls.key
    """,
    """
    - name: CODEWIRE_UDP_RELAY_ALLOCATOR_CLIENT_ROOTS
      value: /run/codewire-udp-relay-allocator-roots/ca.crt
    """,
    """
    - name: CODEWIRE_UDP_RELAY_ALLOCATOR_CLIENT_NAME
      value: orchestration.udp-relay-allocator.codewire.internal
    """,
]
UDP_RELAY_VOLUMES = """
      volumes:
      - name: allocator-tls
        secret:
          defaultMode: 288
          items:
          - key: tls.crt
            path: tls.crt
          - key: tls.key
            path: tls.key
          secretName: codewire-udp-relay-allocator-tls
      - configMap:
          items:
          - key: ca.crt
            path: ca.crt
          name: codewire-udp-relay-allocator-roots
        name: allocator-roots
"""
UDP_RELAY_CERTIFICATE_SPEC = """
spec:
  dnsNames:
  - codewire-udp-relay
  duration: 24h
  isCA: false
  issuerRef:
    group: cert-manager.io
    kind: Issuer
    name: codewire-udp-relay-allocator
  privateKey:
    algorithm: ECDSA
    encoding: PKCS8
    rotationPolicy: Always
    size: 256
  renewBefore: 8h
  revisionHistoryLimit: 1
  secretName: codewire-udp-relay-allocator-tls
  usages:
  - digital signature
  - server auth
"""


def assert_udp_relay(resources: list[str], label: str, output: list[str]) -> None:
    """The relay parses UDP from the internet, so it holds no shared secret and
    its allocator answers only orchestration (#3926). Its one Secret is its own
    TLS leaf, from the authority that signs nothing but that leaf and
    orchestration's client leaf, and its TLS listener allocates only for that
    client's name (#4011). That listener is the only allocator: no Deployment,
    Service or policy names the plain port it replaced. Relay data stays open to
    every source, because the LoadBalancer sends the internet there, and so do the
    read-only endpoints, because Prometheus runs on host networking and matches no
    Pod selector. Those endpoints stay on the port named http, which the PodMonitor
    scrapes."""
    deployment = exactly_one(resources, "Deployment", UDP_RELAY, label, output)
    if deployment and (
        re.search(r"secretRef:|secretKeyRef:", deployment)
        or len(re.findall(r"\bsecret:", deployment)) != 1
        or compact(UDP_RELAY_VOLUMES) not in compact(deployment)
    ):
        output.append(
            f"{label}: the UDP relay must take no Secret but its own allocator TLS leaf, "
            "and its client roots from the published ConfigMap"
        )
    if deployment and compact(UDP_RELAY_PORTS) not in compact(deployment):
        output.append(
            f"{label}: the UDP relay must serve relay data on 41641/UDP, its allocator over TLS on 8097 only, "
            "and the port named http on 8096"
        )
    service = exactly_one(resources, "Service", UDP_RELAY, label, output)
    if service and not compact(top_level_block(service, "spec")).startswith(compact(UDP_RELAY_SERVICE_PORTS)):
        output.append(f"{label}: the UDP relay Service must expose 41641/UDP and the TLS allocator on 8097 only")
    plain = re.compile(rf"\b(containerPort|port|targetPort): {UDP_RELAY_PLAIN_ALLOCATOR_PORT}\b")
    for resource in (deployment, service):
        if resource and plain.search(resource):
            output.append(f"{label}: the UDP relay must not serve the plain allocator port {UDP_RELAY_PLAIN_ALLOCATOR_PORT}")
    for line in UDP_RELAY_TLS_ENV:
        name = line.split()[2]
        # Kubernetes takes the last of two entries with one name.
        if deployment and (compact(line) not in compact(deployment) or deployment.count(f"name: {name}\n") != 1):
            output.append(f"{label}: the UDP relay must set {name} once, as checked in")
    issued = [
        resource
        for resource in resources
        if top_level_field(resource, "kind") == "Certificate" and "name: codewire-udp-relay-allocator\n" in resource
    ]
    if len(issued) != 1:
        output.append(f"{label}: the relay allocator authority must sign exactly one leaf here, the relay's own")
    certificate = exactly_one(resources, "Certificate", "codewire-udp-relay-allocator", label, output)
    if certificate and compact(top_level_block(certificate, "spec")) != compact(UDP_RELAY_CERTIFICATE_SPEC):
        output.append(
            f"{label}: the relay allocator leaf must be a 24-hour server certificate for the relay's Service name "
            "from the codewire-udp-relay-allocator Issuer"
        )
    policy = exactly_one(resources, "NetworkPolicy", UDP_RELAY, label, output)
    if not policy:
        return
    expected = compact(
        """
        spec:
          ingress:
          - ports:
            - port: 41641
              protocol: UDP
          - from:
            - podSelector:
                matchLabels:
                  app.kubernetes.io/component: orchestration
                  app.kubernetes.io/name: codewire
            ports:
            - port: 8097
              protocol: TCP
          - ports:
            - port: 8096
              protocol: TCP
          podSelector:
            matchLabels:
              app.kubernetes.io/component: udp-relay
              app.kubernetes.io/name: codewire
          policyTypes:
          - Ingress
        """
    )
    if compact(top_level_block(policy, "spec")) != expected:
        output.append(
            f"{label}: UDP relay ingress must keep 41641/UDP and 8096 open and admit only orchestration, on 8097 only"
        )


def udp_relay_self_test(resources: list[str]) -> None:
    label = "udp-relay negative fixture"
    clean: list[str] = []
    assert_udp_relay(resources, label, clean)
    if clean:
        raise RuntimeError(f"{label} failed before any change: {clean}")
    for kind, name, before, after in [
        ("Deployment", "takes every shared secret", "envFrom:\n", "envFrom:\n        - secretRef:\n            name: codewire-secrets\n"),
        ("NetworkPolicy", "relay data closed", "port: 41641", "port: 41642"),
        ("NetworkPolicy", "plain allocator open to every source", "  - from:\n", "  - ports:\n    - port: 8095\n      protocol: TCP\n  - from:\n"),
        ("NetworkPolicy", "plain allocator open to orchestration", "    - port: 8097\n", "    - port: 8095\n      protocol: TCP\n    - port: 8097\n"),
        ("Deployment", "the plain allocator port back", "        - containerPort: 8097\n", "        - containerPort: 8095\n          name: allocator\n        - containerPort: 8097\n"),
        ("Deployment", "the plain allocator port after the others", "          name: http\n", "          name: http\n        - containerPort: 8095\n"),
        ("Service", "the plain allocator port back", "  - name: allocator-tls\n", "  - name: allocator\n    port: 8095\n    targetPort: 8095\n  - name: allocator-tls\n"),
        ("Service", "the plain allocator port after the others", "    targetPort: 8097\n", "    targetPort: 8097\n  - name: allocator\n    port: 8095\n"),
        ("NetworkPolicy", "another component", "app.kubernetes.io/component: orchestration", "app.kubernetes.io/component: dashboard"),
        ("NetworkPolicy", "read-only endpoints closed", "port: 8096", "port: 8098"),
        ("NetworkPolicy", "TLS allocator open to every source", "  - from:\n", "  - ports:\n    - port: 8097\n      protocol: TCP\n  - from:\n"),
        ("Deployment", "metrics back on the allocator's port", "name: allocator-tls\n        - containerPort: 8096", "name: http\n        - containerPort: 8096"),
        ("Deployment", "another Secret mounted", "secretName: codewire-udp-relay-allocator-tls", "secretName: codewire-secrets"),
        ("Deployment", "a second Secret mounted", "      volumes:\n", "      volumes:\n      - name: extra\n        secret:\n          secretName: codewire-secrets\n"),
        ("Deployment", "a projected shared secret", "      volumes:\n", "      volumes:\n      - name: extra\n        projected:\n          sources:\n          - secret:\n              name: codewire-secrets\n"),
        ("Deployment", "client roots from another authority", "name: codewire-udp-relay-allocator-roots", "name: codewire-orchestration-internal-roots"),
        ("Deployment", "a second client name that wins", "        envFrom:\n", "        - name: CODEWIRE_UDP_RELAY_ALLOCATOR_CLIENT_NAME\n          value: mesh.udp-relay-allocator.codewire.internal\n        envFrom:\n"),
        ("Deployment", "another client named", "orchestration.udp-relay-allocator.codewire.internal", "mesh.udp-relay-allocator.codewire.internal"),
        ("Deployment", "client roots from the leaf Secret", "/run/codewire-udp-relay-allocator-roots/ca.crt", "/run/codewire-udp-relay-allocator-tls/ca.crt"),
        ("Certificate", "the orchestration-internal authority", "name: codewire-udp-relay-allocator\n  privateKey", "name: codewire-orchestration-internal\n  privateKey"),
        ("Certificate", "a client-capable leaf", "  - server auth", "  - server auth\n  - client auth"),
        ("Certificate", "a wildcard name", "  - codewire-udp-relay\n", "  - '*.svc.cluster.local'\n"),
    ]:
        changed = [
            resource.replace(before, after, 1) if top_level_field(resource, "kind") == kind else resource
            for resource in resources
        ]
        if changed == resources:
            raise RuntimeError(f"{label} {name} did not change the render")
        output: list[str] = []
        assert_udp_relay(changed, label, output)
        if not output:
            raise RuntimeError(f"{label} {name} passed the check")
    second_leaf = [
        resource.replace("name: codewire-udp-relay-allocator\n", "name: codewire-udp-relay-allocator-client\n", 1)
        for resource in resources
        if top_level_field(resource, "kind") == "Certificate"
    ]
    forged: list[str] = []
    assert_udp_relay(resources + second_leaf, label, forged)
    if not forged:
        raise RuntimeError(f"{label} a second leaf from the allocator authority passed the check")
    missing: list[str] = []
    assert_udp_relay(
        [resource for resource in resources if top_level_field(resource, "kind") != "NetworkPolicy"],
        label,
        missing,
    )
    if not missing:
        raise RuntimeError(f"{label} without its policy passed the check")


RELAY_ALLOCATOR_CLIENT = "codewire-orchestration-udp-relay-allocator-client"
RELAY_ALLOCATOR_CLIENT_SPEC = """
spec:
  dnsNames:
  - orchestration.udp-relay-allocator.codewire.internal
  duration: 24h
  isCA: false
  issuerRef:
    group: cert-manager.io
    kind: Issuer
    name: codewire-udp-relay-allocator
  privateKey:
    algorithm: ECDSA
    encoding: PKCS8
    rotationPolicy: Always
    size: 256
  renewBefore: 8h
  revisionHistoryLimit: 1
  secretName: codewire-orchestration-udp-relay-allocator-client-tls
  usages:
  - digital signature
  - client auth
"""
RELAY_ALLOCATOR_CLIENT_VOLUMES = """
      - name: udp-relay-allocator-client-tls
        secret:
          defaultMode: 288
          items:
          - key: tls.crt
            path: tls.crt
          - key: tls.key
            path: tls.key
          optional: true
          secretName: codewire-orchestration-udp-relay-allocator-client-tls
      - configMap:
          items:
          - key: ca.crt
            path: ca.crt
          name: codewire-udp-relay-allocator-roots
          optional: true
        name: udp-relay-allocator-roots
"""
RELAY_ALLOCATOR_CLIENT_MOUNTS = """
        - mountPath: /run/codewire-udp-relay-allocator-client-tls
          name: udp-relay-allocator-client-tls
          readOnly: true
        - mountPath: /run/codewire-udp-relay-allocator-roots
          name: udp-relay-allocator-roots
          readOnly: true
"""
# How often each path appears in the Deployment: its mount, and the settings
# that name a file under it.
RELAY_ALLOCATOR_CLIENT_PATHS = {
    "/run/codewire-udp-relay-allocator-client-tls": 3,
    "/run/codewire-udp-relay-allocator-roots": 2,
}
# Every leaf the allocator authority may sign, in any package.
RELAY_ALLOCATOR_LEAVES = {"codewire-udp-relay-allocator", "codewire-orchestration-udp-relay-allocator-client"}


def relay_allocator_leaves(resources: list[str]) -> list[str]:
    """The names of everything in `resources` that asks the allocator
    authority for a certificate."""
    return sorted(
        metadata_field(resource, "name")
        for resource in resources
        if top_level_field(resource, "kind") in ("Certificate", "CertificateRequest")
        and re.search(r"^    name: codewire-udp-relay-allocator$", resource, flags=re.MULTILINE)
    )


RELAY_ALLOCATOR_CLIENT_ENV = [
    """
    - name: CODEWIRE_UDP_RELAY_ALLOCATOR_ROOTS_FILE
      value: /run/codewire-udp-relay-allocator-roots/ca.crt
    """,
    """
    - name: CODEWIRE_UDP_RELAY_ALLOCATOR_CLIENT_CERT_FILE
      value: /run/codewire-udp-relay-allocator-client-tls/tls.crt
    """,
    """
    - name: CODEWIRE_UDP_RELAY_ALLOCATOR_CLIENT_KEY_FILE
      value: /run/codewire-udp-relay-allocator-client-tls/tls.key
    """,
]


def assert_relay_allocator_client(resources: list[str], label: str, output: list[str]) -> None:
    """The UDP relay allocates over TLS only for the certificate that carries
    orchestration's name (#4011). Orchestration holds the one client leaf with
    that name, from the authority that signs nothing else here, and verifies
    the relay with that authority's published roots, never with whatever CA a
    leaf Secret carries."""
    certificate = exactly_one(resources, "Certificate", RELAY_ALLOCATOR_CLIENT, label, output)
    if certificate and compact(top_level_block(certificate, "spec")) != compact(RELAY_ALLOCATOR_CLIENT_SPEC):
        output.append(
            f"{label}: the relay allocator client leaf must be a 24-hour client-only certificate for "
            "orchestration's allocator name from the codewire-udp-relay-allocator Issuer"
        )
    if relay_allocator_leaves(resources) != [RELAY_ALLOCATOR_CLIENT]:
        output.append(f"{label}: the relay allocator authority must sign exactly one leaf here, orchestration's client")
    deployment = exactly_one(resources, "Deployment", "codewire-orchestration", label, output)
    if deployment and (
        compact(RELAY_ALLOCATOR_CLIENT_VOLUMES) not in compact(deployment)
        or compact(RELAY_ALLOCATOR_CLIENT_MOUNTS) not in compact(deployment)
        # Each path is mounted once, so no other volume or subPath covers it.
        or any(deployment.count(path) != count for path, count in RELAY_ALLOCATOR_CLIENT_PATHS.items())
    ):
        output.append(
            f"{label}: orchestration must mount its relay allocator client leaf and the published relay roots, "
            "both optional, each at its own path and nothing else there"
        )
    for line in RELAY_ALLOCATOR_CLIENT_ENV:
        name = line.split()[2]
        # Kubernetes takes the last of two entries with one name.
        if deployment and (compact(line) not in compact(deployment) or deployment.count(f"name: {name}\n") != 1):
            output.append(f"{label}: orchestration must set {name} once, as checked in")


def relay_allocator_client_self_test(resources: list[str]) -> None:
    label = "relay allocator client negative fixture"
    clean: list[str] = []
    assert_relay_allocator_client(resources, label, clean)
    if clean:
        raise RuntimeError(f"{label} failed before any change: {clean}")
    client = "name: codewire-orchestration-udp-relay-allocator-client\n"
    for kind, name, before, after in [
        ("Certificate", "a server-capable leaf", "  - client auth", "  - client auth\n  - server auth"),
        ("Certificate", "another caller named", "orchestration.udp-relay-allocator", "mesh.udp-relay-allocator"),
        ("Certificate", "a wildcard name", "orchestration.udp-relay-allocator.codewire.internal", "'*.codewire.internal'"),
        ("Certificate", "the orchestration-internal authority", "name: codewire-udp-relay-allocator\n  privateKey", "name: codewire-orchestration-internal\n  privateKey"),
        ("Deployment", "relay roots from another authority", "name: codewire-udp-relay-allocator-roots", "name: codewire-orchestration-internal-roots"),
        ("Deployment", "relay roots from the leaf Secret", "/run/codewire-udp-relay-allocator-roots/ca.crt", "/run/codewire-udp-relay-allocator-client-tls/ca.crt"),
        ("Deployment", "another volume at the roots path", "          name: udp-relay-allocator-roots\n", "          name: internal-tls\n"),
        ("Deployment", "a file mounted over the roots", "        volumeMounts:\n", "        volumeMounts:\n        - mountPath: /run/codewire-udp-relay-allocator-roots/ca.crt\n          name: internal-tls\n          subPath: ca.crt\n"),
        ("Deployment", "a second roots path that wins", "        envFrom:\n", "        - name: CODEWIRE_UDP_RELAY_ALLOCATOR_ROOTS_FILE\n          value: /tmp/ca.crt\n        envFrom:\n"),
    ]:
        changed = [
            resource.replace(before, after, 1)
            if top_level_field(resource, "kind") == kind and (kind != "Certificate" or client in resource)
            else resource
            for resource in resources
        ]
        if changed == resources:
            raise RuntimeError(f"{label} {name} did not change the render")
        output: list[str] = []
        assert_relay_allocator_client(changed, label, output)
        if not output:
            raise RuntimeError(f"{label} {name} passed the check")
    second_leaf = [
        resource.replace(client, "name: codewire-orchestration-udp-relay-allocator-other\n", 1)
        for resource in resources
        if top_level_field(resource, "kind") == "Certificate" and client in resource
    ]
    for name, leaf in [
        ("a second leaf", second_leaf),
        ("a second leaf with a default key", [re.sub(r"  privateKey:\n(?:    .*\n)+", "", second_leaf[0])]),
    ]:
        forged: list[str] = []
        assert_relay_allocator_client(resources + leaf, label, forged)
        if not forged:
            raise RuntimeError(f"{label} {name} from the allocator authority passed the check")
    elsewhere = relay_allocator_leaves(resources + second_leaf)
    if set(elsewhere) <= RELAY_ALLOCATOR_LEAVES:
        raise RuntimeError(f"{label} a leaf in another package passed the check")


def world_peer(peer: Any) -> bool:
    """An ipBlock peer for the whole world less every cluster and Pod range."""
    if not isinstance(peer, dict) or set(peer) != {"ipBlock"} or not isinstance(peer["ipBlock"], dict):
        return False
    block = peer["ipBlock"]
    required = WORLD_EXCEPTIONS.get(block.get("cidr"))
    return required is not None and set(block) == {"cidr", "except"} and required <= set(block.get("except") or [])


def label_selectors(policy: dict[str, Any]) -> list[Any]:
    """Every label selector of a NetworkPolicy: its own and each peer's."""
    spec = policy.get("spec") if isinstance(policy.get("spec"), dict) else {}
    found: list[Any] = [spec.get("podSelector")]
    for direction, peers_key in (("ingress", "from"), ("egress", "to")):
        for rule in spec.get(direction) or []:
            for peer in (rule or {}).get(peers_key) or []:
                for key in ("podSelector", "namespaceSelector"):
                    if isinstance(peer, dict) and key in peer:
                        found.append(peer[key])
    return found


def selector_keys(selector: Any) -> list[str]:
    if not isinstance(selector, dict):
        return []
    keys = list((selector.get("matchLabels") or {}).keys())
    keys += [expression.get("key", "") for expression in selector.get("matchExpressions") or [] if isinstance(expression, dict)]
    return [str(key) for key in keys]


def uses_agents_selector(policy: dict[str, Any]) -> bool:
    return any(key.startswith(AGENTS_LABEL_PREFIX) for selector in label_selectors(policy) for key in selector_keys(selector))


def warm_bridge_violations(policy: dict[str, Any], label: str) -> list[str]:
    """A NetworkPolicy selecting through any agents.x-k8s.io label must be one
    environment's warm-member bridge: named cw-daemon-warm-<env>, selecting
    the member by exactly its Sandbox UID and the workspace type, and
    admitting only what cw-daemon-net-<env> admits: orchestration, and the
    world on the tailnet UDP port. There is no gateway to peer."""
    if not uses_agents_selector(policy):
        return []
    output: list[str] = []
    name = str((policy.get("metadata") or {}).get("name", ""))
    matched = WARM_BRIDGE_NAME.fullmatch(name)
    if policy.get("kind") != "NetworkPolicy" or not matched:
        return [f"{label}: {name!r} selects through an agents.x-k8s.io label but is not cw-daemon-warm-<env>"]
    _, environment = matched.groups()
    members = [selector for selector in label_selectors(policy) if any(key.startswith(AGENTS_LABEL_PREFIX) for key in selector_keys(selector))]
    uids = set()
    for selector in members:
        labels = selector.get("matchLabels") if isinstance(selector, dict) else None
        if (set(selector) != {"matchLabels"} or not isinstance(labels, dict) or set(labels) != {SANDBOX_UID_LABEL, "codewire.sh/type"}
                or labels.get("codewire.sh/type") != "workspace" or not re.fullmatch(CANONICAL_UUID, str(labels.get(SANDBOX_UID_LABEL)))):
            output.append(f"{label}: a member selector is not exactly {{{SANDBOX_UID_LABEL}: <uid>, codewire.sh/type: workspace}}: {selector}")
        else:
            uids.add(labels[SANDBOX_UID_LABEL])
    if len(uids) > 1:
        output.append(f"{label}: the bridge names more than one Sandbox UID: {sorted(uids)}")
    member = members[0] if len(members) > 0 else None
    spec = policy.get("spec") if isinstance(policy.get("spec"), dict) else {}
    if spec.get("podSelector") != member:
        output.append(f"{label}: the bridge must apply to the member alone: {spec.get('podSelector')}")
    expected_types = [direction.capitalize() for direction in ("ingress", "egress") if spec.get(direction)]
    if spec.get("policyTypes") != expected_types:
        output.append(f"{label}: policyTypes must be exactly the granted directions {expected_types}: {spec.get('policyTypes')}")
    for direction, peers_key in (("ingress", "from"), ("egress", "to")):
        for rule in spec.get(direction) or []:
            peers = (rule or {}).get(peers_key)
            if not peers:
                output.append(f"{label}: a {direction} rule without {peers_key!r} peers admits every source or destination")
                continue
            for peer in peers:
                allowed = direction == "ingress" and (
                    (
                        isinstance(peer, dict)
                        and set(peer) == {"namespaceSelector", "podSelector"}
                        and set((peer["namespaceSelector"] or {}).get("matchLabels") or {}) == {"kubernetes.io/metadata.name"}
                        and set(peer["namespaceSelector"]) == {"matchLabels"}
                        and peer["podSelector"] == {"matchLabels": ORCHESTRATION_PEER_POD}
                    )
                    or (world_peer(peer) and (rule or {}).get("ports") == WORKSPACE_TAILNET_UDP_PORTS)
                )
                if not allowed:
                    output.append(f"{label}: environment {environment}'s bridge admits something other than orchestration or the world's tailnet traffic: {peer}")
    return output


def warm_bridge_manifest_violations(resources: list[str], label: str) -> list[str]:
    """Bridges are per environment and created only by orchestration at
    runtime: no deployment manifest may select through agents.x-k8s.io."""
    return [
        f"{label}: NetworkPolicy {metadata_field(resource, 'name')} selects through an agents.x-k8s.io label in a manifest"
        for resource in resources
        if top_level_field(resource, "kind") == "NetworkPolicy" and AGENTS_LABEL_PREFIX in top_level_block(resource, "spec")
    ]


def warm_bridge_source_violations(renderer: str, naming: str) -> list[str]:
    """The renderer names no agents.x-k8s.io label key itself; the naming
    leaf's only one is the Sandbox UID the bridge selects by."""
    output: list[str] = []
    if re.search(r'"agents\.x-k8s\.io/', renderer):
        output.append(f"{WARM_BRIDGE_RENDERER}: names an agents.x-k8s.io label key directly")
    keys = re.findall(r'"(agents\.x-k8s\.io/[^"]*)"', naming)
    if keys != [SANDBOX_UID_LABEL]:
        output.append(f"{WARM_BRIDGE_NAMING}: agents.x-k8s.io label keys must be exactly [{SANDBOX_UID_LABEL!r}]: {keys}")
    return output


def warm_bridge_golden_violations(goldens: dict[str, Any], others: list[tuple[str, Any]]) -> list[str]:
    output: list[str] = []
    for half, policy in goldens.items():
        rel = WARM_BRIDGE_FIXTURES[half]
        if not uses_agents_selector(policy):
            output.append(f"{rel}: the {half} bridge golden does not select through the Sandbox UID")
        name = str((policy.get("metadata") or {}).get("name", ""))
        matched = WARM_BRIDGE_NAME.fullmatch(name)
        if not matched or matched.group(1) != half:
            output.append(f"{rel}: is not the {half} half: {name!r}")
        output.extend(warm_bridge_violations(policy, rel))
    for rel, document in others:
        if isinstance(document, dict) and document.get("kind") == "NetworkPolicy":
            output.extend(warm_bridge_violations(document, rel))
    return output


def warm_bridge_self_test(goldens: dict[str, Any], manifests: list[str]) -> None:
    other_environment = "3d6bb495-efac-419f-bf3a-91696e7c7ca4"

    def rejected(name: str, half: str, mutate: Callable[[dict[str, Any]], Any]) -> None:
        fixture = copy.deepcopy(goldens[half])
        mutate(fixture)
        if not warm_bridge_violations(fixture, f"negative bridge fixture {name}"):
            raise RuntimeError(f"negative bridge fixture {name} was accepted")

    def member_labels(fixture: dict[str, Any]) -> dict[str, Any]:
        return fixture["spec"]["podSelector"]["matchLabels"]

    def name_hash(labels: dict[str, Any]) -> None:
        labels.pop(SANDBOX_UID_LABEL)
        labels["agents.x-k8s.io/sandbox-name-hash"] = "d0258436"

    # Old and new: the reviewed UID bridge and the unchanged environment
    # policies pass, while the issue's first design (a name-hash selector)
    # fails both as a bridge and as an extra cw-daemon-net term.
    for half, policy in goldens.items():
        if warm_bridge_violations(policy, f"positive bridge fixture {half}"):
            raise RuntimeError(f"positive bridge fixture {half} was rejected")
    legacy = copy.deepcopy(goldens["daemon"])
    legacy["metadata"]["name"] = legacy["metadata"]["name"].replace("cw-daemon-warm-", "cw-daemon-net-")
    legacy["spec"]["podSelector"] = {"matchLabels": {"codewire.sh/environment-id": legacy["metadata"]["labels"]["codewire.sh/environment-id"], "codewire.sh/type": "workspace"}}
    if warm_bridge_violations(legacy, "unchanged cw-daemon-net"):
        raise RuntimeError("an environment policy without agents.x-k8s.io selectors was rejected")
    rejected("name-hash bridge (old design)", "daemon", lambda f: name_hash(member_labels(f)))

    def name_hash_term(f: dict[str, Any]) -> None:
        f["metadata"]["name"] = f["metadata"]["name"].replace("cw-daemon-warm-", "cw-daemon-net-")
        name_hash(member_labels(f))

    def world_rule(f: dict[str, Any]) -> dict[str, Any]:
        return next(rule for rule in f["spec"]["ingress"] if any("ipBlock" in peer for peer in rule["from"]))

    environment = goldens["daemon"]["metadata"]["labels"]["codewire.sh/environment-id"]
    rejected("name-hash term on cw-daemon-net (old design)", "daemon", name_hash_term)
    rejected("name hash beside the UID", "daemon", lambda f: member_labels(f).__setitem__("agents.x-k8s.io/sandbox-name-hash", "d0258436"))
    rejected("claim UID instead of the Sandbox UID", "daemon", lambda f: member_labels(f).__setitem__(
        "agents.x-k8s.io/claim-uid", member_labels(f).pop(SANDBOX_UID_LABEL)))
    rejected("UID without the workspace type", "daemon", lambda f: member_labels(f).pop("codewire.sh/type"))
    rejected("gateway type", "daemon", lambda f: member_labels(f).__setitem__("codewire.sh/type", "gateway"))
    rejected("uppercase UID", "daemon", lambda f: member_labels(f).__setitem__(SANDBOX_UID_LABEL, member_labels(f)[SANDBOX_UID_LABEL].upper()))
    rejected("UID expression", "daemon", lambda f: f["spec"].__setitem__("podSelector", {
        "matchExpressions": [{"key": SANDBOX_UID_LABEL, "operator": "Exists"}], "matchLabels": {"codewire.sh/type": "workspace"}}))
    rejected("another name", "daemon", lambda f: f["metadata"].__setitem__("name", "cw-pool-member-bridge"))
    rejected("unsuffixed name", "daemon", lambda f: f["metadata"].__setitem__("name", "cw-daemon-warm"))
    rejected("gateway half name", "daemon", lambda f: f["metadata"].__setitem__("name", f"cw-gw-warm-{environment}"))
    rejected("this environment's gateway (old design)", "daemon", lambda f: f["spec"]["ingress"][0]["from"].append(
        {"podSelector": {"matchLabels": {"codewire.sh/environment-id": environment, "codewire.sh/type": "gateway"}}}))
    rejected("a server Pod other than orchestration", "daemon", lambda f: f["spec"]["ingress"][0]["from"][0]["podSelector"]["matchLabels"].__setitem__(
        "app.kubernetes.io/component", "gateway"))
    rejected("every Pod in the namespace", "daemon", lambda f: f["spec"]["ingress"][0]["from"].append({"podSelector": {}}))
    rejected("every namespace", "daemon", lambda f: f["spec"]["ingress"][0]["from"].append({"namespaceSelector": {}}))
    rejected("an address block on the daemon ports", "daemon", lambda f: f["spec"]["ingress"][0]["from"].append({"ipBlock": {"cidr": "10.0.0.0/8"}}))
    rejected("cluster addresses on the tailnet port", "daemon", lambda f: world_rule(f)["from"][0]["ipBlock"].__setitem__("except", ["127.0.0.0/8"]))
    rejected("the world on a TCP port", "daemon", lambda f: world_rule(f).__setitem__("ports", [{"port": 31000, "protocol": "TCP"}]))
    rejected("every source", "daemon", lambda f: f["spec"]["ingress"][0].pop("from"))
    rejected("orchestration egress", "daemon", lambda f: f["spec"].update(
        egress=[{"to": f["spec"]["ingress"][0]["from"], "ports": [{"port": 8084, "protocol": "TCP"}]}],
        policyTypes=["Ingress", "Egress"]))
    rejected("isolating an ungranted direction", "daemon", lambda f: f["spec"]["policyTypes"].append("Egress"))
    if not warm_bridge_source_violations('json!({"agents.x-k8s.io/sandbox-name-hash": hash})', 'pub const SANDBOX_UID_LABEL: &str = "agents.x-k8s.io/sandbox-uid";'):
        raise RuntimeError("negative bridge source fixture (renderer names a label key) was accepted")
    if not warm_bridge_source_violations("", 'pub const SANDBOX_UID_LABEL: &str = "agents.x-k8s.io/sandbox-name-hash";'):
        raise RuntimeError("negative bridge source fixture (name-hash constant) was accepted")
    manifest = next(resource for resource in manifests if top_level_field(resource, "kind") == "NetworkPolicy")
    if not warm_bridge_manifest_violations([manifest.replace("spec:\n", "spec:\n  podSelector:\n    matchLabels:\n      agents.x-k8s.io/sandbox-name-hash: d0258436\n", 1)], "negative manifest"):
        raise RuntimeError("negative bridge manifest fixture was accepted")


def check_warm_member_bridge(self_test: bool, manifests: list[str]) -> list[str]:
    failures: list[str] = []
    goldens: dict[str, Any] = {}
    for half, rel in WARM_BRIDGE_FIXTURES.items():
        try:
            goldens[half] = json.loads((ROOT / rel).read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            failures.append(f"{rel}: unreadable ({error})")
    others: list[tuple[str, Any]] = []
    for path in sorted((ROOT / WARM_BRIDGE_FIXTURE_DIR).glob("*.json")):
        rel = str(path.relative_to(ROOT))
        if rel not in WARM_BRIDGE_FIXTURES.values():
            try:
                others.append((rel, json.loads(path.read_text(encoding="utf-8"))))
            except (OSError, ValueError) as error:
                failures.append(f"{rel}: unreadable ({error})")
    if len(goldens) == len(WARM_BRIDGE_FIXTURES):
        failures.extend(warm_bridge_golden_violations(goldens, others))
    failures.extend(warm_bridge_source_violations(read_text(WARM_BRIDGE_RENDERER), read_text(WARM_BRIDGE_NAMING)))
    if self_test and len(goldens) == len(WARM_BRIDGE_FIXTURES):
        try:
            warm_bridge_self_test(goldens, manifests)
        except (RuntimeError, KeyError, IndexError, TypeError, StopIteration) as error:
            failures.append(f"warm member bridge self-test: {error!r}")
    return failures


def check_orchestration_authz(args: argparse.Namespace) -> int:
    orchestration = "codewire-orchestration"
    token_request_name = "codewire-orchestration-tokenrequest"
    targets = [
        {"path": "deployments/k8s/orchestration", "role_namespace": "prod-sandboxes", "subject_namespace": "prod"},
        {"path": "deployments/k8s/overlays/local-kind", "role_namespace": "dev-sandboxes", "subject_namespace": "default"},
        {"path": "deployments/k8s/overlays/local-kind-static", "role_namespace": "dev-sandboxes", "subject_namespace": "default"},
        {"path": "tests/e2e/kind", "role_namespace": "dev-sandboxes", "subject_namespace": "codewire-e2e"},
    ]
    failures: list[str] = []

    def assert_cluster_role(resources: list[str], label: str, output: list[str]) -> None:
        role = exactly_one(resources, "ClusterRole", orchestration, label, output)
        if role and re.search(r"^\s*- secrets\s*$", role, re.MULTILINE):
            output.append(f"{label}: cluster-wide orchestration role still grants Secret access")
        if role and re.search(r"^\s*- deployments\s*$", role, re.MULTILINE):
            output.append(f"{label}: cluster-wide orchestration role still grants Deployment access")
        if role and compact(top_level_block(role, "rules")) != CLUSTER_ROLE_RULES:
            output.append(f"{label}: cluster-wide orchestration role must grant only its cluster-scoped reads and TokenReview")

    def assert_sandbox_role(resources: list[str], target: dict[str, str], label: str, output: list[str]) -> None:
        role = exactly_one(resources, "Role", SANDBOX_ROLE, label, output)
        binding = exactly_one(resources, "RoleBinding", SANDBOX_ROLE, label, output)
        if role and (metadata_field(role, "namespace") != target["role_namespace"]
                or compact(top_level_block(role, "rules")) != SANDBOX_ROLE_RULES):
            output.append(f"{label}: Sandbox Role must grant exactly the environment lifecycle in {target['role_namespace']}")
        if binding:
            expected_ref = compact(f"roleRef: apiGroup: rbac.authorization.k8s.io kind: Role name: {SANDBOX_ROLE}")
            expected_subject = compact(
                f"subjects: - kind: ServiceAccount name: {orchestration} namespace: {target['subject_namespace']}"
            )
            if (metadata_field(binding, "namespace") != target["role_namespace"]
                    or compact(top_level_block(binding, "roleRef")) != expected_ref
                    or compact(top_level_block(binding, "subjects")) != expected_subject):
                output.append(f"{label}: Sandbox Role binding escaped its namespace or identity")

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
                f"RoleBinding/{target['role_namespace']}/{INTERNAL_ROOTS_ROLE}",
                f"RoleBinding/{target['role_namespace']}/{IMAGE_CACHE_ROLE}",
                f"RoleBinding/{target['role_namespace']}/{SANDBOX_ROLE}",
                f"RoleBinding/{target['subject_namespace']}/{RELEASE_REVISION_ROLE}",
                f"RoleBinding/{target['subject_namespace']}/{token_request_name}",
            ]
        )
        if actual != expected:
            output.append(
                f"{label}: orchestration ServiceAccount binding surface is "
                f"{', '.join(actual) if actual else 'empty'}"
            )

    def verify_resources(resources: list[str], target: dict[str, str], label: str) -> list[str]:
        output: list[str] = []
        assert_cluster_role(resources, label, output)
        assert_sandbox_role(resources, target, label, output)
        assert_token_request_authz(resources, target, label, output)
        assert_bound_surface(resources, target, label, output)
        assert_internal_roots(resources, target, label, output)
        assert_image_cache(resources, target, label, output)
        assert_warm_pool(resources, target, label, output)
        assert_workspace_binding_ingress(resources, target, label, output)
        output.extend(warm_bridge_manifest_violations(resources, label))
        if target["path"] != "deployments/k8s/orchestration":
            assert_credential_service(resources, target, label, output)
        return output

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
            + [resources_by_kind_and_name(resources, "RoleBinding", INTERNAL_ROOTS_ROLE)[0].replace("namespace: prod-sandboxes", "namespace: prod")],
        )
        for internal_roots_label, before, after in [
            ("any ConfigMap", "  resourceNames:\n  - codewire-orchestration-internal-roots\n", ""),
            ("another ConfigMap", "  - codewire-orchestration-internal-roots", "  - codewire-credential-broker-roots"),
            ("ConfigMap list", "  - get", "  - get\n  - list"),
            ("ConfigMap write", "  - get", "  - get\n  - update"),
            ("Secrets", "  - configmaps", "  - secrets"),
        ]:
            expect_rejected(
                f"internal roots {internal_roots_label}",
                lambda resources, before=before, after=after: [
                    resource.replace(before, after)
                    if top_level_field(resource, "kind") == "Role" and metadata_field(resource, "name") == INTERNAL_ROOTS_ROLE
                    else resource
                    for resource in resources
                ],
            )
        expect_rejected(
            "cluster-wide Deployment grant",
            lambda resources: [
                resource.replace('  - tokenreviews\n', '  - tokenreviews\n- apiGroups:\n  - apps\n  resources:\n  - deployments\n  verbs:\n  - get\n', 1)
                if top_level_field(resource, "kind") == "ClusterRole" and metadata_field(resource, "name") == orchestration
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

        # codewire#4000: the hosted-egress switch and its ConfigMap.
        def edited(kind: str, name: str, before: str, after: str) -> Callable[[list[str]], list[str]]:
            # Rendered CEL wraps wherever its line fills, so a space in
            # `before` matches any run of whitespace, line breaks included.
            pattern = re.compile(r"\s+".join(re.escape(part) for part in before.split()))

            def mutate(resources: list[str]) -> list[str]:
                changed = [
                    pattern.sub(lambda _: after, resource, count=1)
                    if top_level_field(resource, "kind") == kind and metadata_field(resource, "name") == name
                    else resource
                    for resource in resources
                ]
                if changed == resources:
                    raise RuntimeError(f"self-test edit of {kind}/{name} matched nothing: {before!r}")
                return changed
            return mutate

        configmap_writer = (
            "apiVersion: rbac.authorization.k8s.io/v1\nkind: {kind}\nmetadata:\n  name: cw-selftest-configmaps\n"
            "{namespace}rules:\n- apiGroups:\n  - \"\"\n  resources:\n  - {resource}\n  verbs:\n  - {verb}\n"
        )
        writer_binding = (
            "apiVersion: rbac.authorization.k8s.io/v1\nkind: {kind}\nmetadata:\n  name: cw-selftest-configmaps\n"
            "{namespace}roleRef:\n  apiGroup: rbac.authorization.k8s.io\n  kind: {role_kind}\n  name: cw-selftest-configmaps\n"
            "subjects:\n{subject}"
        )
        orchestration_subject = "- kind: ServiceAccount\n  name: codewire-orchestration\n  namespace: prod\n"
        group_subject = "- apiGroup: rbac.authorization.k8s.io\n  kind: Group\n  name: system:serviceaccounts\n"
        for writer_label, role_kind, binding_kind, resource, verb, subject in [
            ("a Role that updates ConfigMaps", "Role", "RoleBinding", "configmaps", "update", orchestration_subject),
            ("a ClusterRole that patches every resource", "ClusterRole", "ClusterRoleBinding", "'*'", "patch", orchestration_subject),
            ("a ClusterRole that creates ConfigMaps", "ClusterRole", "RoleBinding", "configmaps", "create", orchestration_subject),
            ("a group grant to every service account", "ClusterRole", "ClusterRoleBinding", "configmaps", "'*'", group_subject),
        ]:
            namespace = "  namespace: prod\n" if role_kind == "Role" else ""
            binding_namespace = "  namespace: prod\n" if binding_kind == "RoleBinding" else ""
            expect_rejected(
                f"hosted egress: {writer_label}",
                lambda resources, role_kind=role_kind, binding_kind=binding_kind, resource=resource, verb=verb,
                subject=subject, namespace=namespace, binding_namespace=binding_namespace: resources + [
                    configmap_writer.format(kind=role_kind, namespace=namespace, resource=resource, verb=verb),
                    writer_binding.format(kind=binding_kind, namespace=binding_namespace, role_kind=role_kind, subject=subject),
                ],
            )
        for param_label, mutate in [
            ("switched on", edited("ConfigMap", HOSTED_EGRESS_CONFIGMAP, f'{HOSTED_EGRESS_SWITCH}: "false"', f'{HOSTED_EGRESS_SWITCH}: "true"')),
            ("pruneable", edited("ConfigMap", HOSTED_EGRESS_CONFIGMAP, "kustomize.toolkit.fluxcd.io/prune: disabled", "codewire.sh/x: y")),
            ("another namespace", edited("ConfigMap", HOSTED_EGRESS_CONFIGMAP, "  namespace: prod", "  namespace: prod-sandboxes")),
            ("an extra key", edited("ConfigMap", HOSTED_EGRESS_CONFIGMAP, "data:\n", "data:\n  CODEWIRE_HOSTED_EGRESS_PLATFORM_ALLOW: x\n")),
            ("a binding without the param", edited("ValidatingAdmissionPolicyBinding", WARM_POOL_TEMPLATE_POLICY,
                                                   f"  paramRef:\n    name: {HOSTED_EGRESS_CONFIGMAP}\n    namespace: prod\n"
                                                   "    parameterNotFoundAction: Deny\n", "")),
            ("a binding that admits without the param", edited("ValidatingAdmissionPolicyBinding", WARM_POOL_TEMPLATE_POLICY,
                                                                "parameterNotFoundAction: Deny", "parameterNotFoundAction: Allow")),
            ("a member binding without the param", edited("ValidatingAdmissionPolicyBinding", WARM_POOL_MEMBER_POLICY,
                                                          f"  paramRef:\n    name: {HOSTED_EGRESS_CONFIGMAP}\n    namespace: prod\n"
                                                          "    parameterNotFoundAction: Deny\n", "")),
            ("a member binding that admits without the param", edited("ValidatingAdmissionPolicyBinding", WARM_POOL_MEMBER_POLICY,
                                                                       "parameterNotFoundAction: Deny", "parameterNotFoundAction: Allow")),
            ("a pruneable policy", edited("ValidatingAdmissionPolicy", WARM_POOL_TEMPLATE_POLICY,
                                          "kustomize.toolkit.fluxcd.io/prune: disabled", "codewire.sh/x: y")),
            ("the template picking its own arm", edited("ValidatingAdmissionPolicy", WARM_POOL_TEMPLATE_POLICY,
                                                        "variables.hostedEgress ? variables.broker || variables.clearing : !variables.egressLabelled", "true")),
            # codewire#6121: each of cw-security's terms for keeping a broker
            # template with the switch off is load-bearing.
            ("a broker template kept on a CREATE", edited("ValidatingAdmissionPolicy", WARM_POOL_TEMPLATE_POLICY,
                                                          "request.operation == 'UPDATE' && variables.wasWholeBroker", "variables.wasWholeBroker")),
            ("a broker template made from a non-broker one", edited("ValidatingAdmissionPolicy", WARM_POOL_TEMPLATE_POLICY,
                                                                    "variables.wasWholeBroker && variables.wholeBroker &&", "variables.wholeBroker &&")),
            ("a broker template kept without the whole shape", edited("ValidatingAdmissionPolicy", WARM_POOL_TEMPLATE_POLICY,
                                                                      "variables.wasWholeBroker && variables.wholeBroker &&", "variables.wasWholeBroker &&")),
            ("a broker template kept without the fence setting", edited("ValidatingAdmissionPolicy", WARM_POOL_TEMPLATE_POLICY,
                                                                        "variables.wholeBroker && has(params.data) && "
                                                                        "'CODEWIRE_HOSTED_EGRESS_FENCE_REVISION' in params.data && "
                                                                        "size(params.data['CODEWIRE_HOSTED_EGRESS_FENCE_REVISION']) > 0",
                                                                        "variables.wholeBroker")),
            ("a broker pool template kept", edited("ValidatingAdmissionPolicy", WARM_POOL_TEMPLATE_POLICY,
                                                   "variables.environmentTemplate && request.operation == 'UPDATE'", "request.operation == 'UPDATE'")),
            ("a hollow template counted whole", edited("ValidatingAdmissionPolicy", WARM_POOL_TEMPLATE_POLICY,
                                                       "'codewire.sh/egress-fence-revision' in oldObject.spec.podTemplate.metadata.annotations &&", "")),
            ("a template kept broker under the label alone", edited("ValidatingAdmissionPolicy", WARM_POOL_TEMPLATE_POLICY,
                                                                    "oldObject.spec.podTemplate.metadata.labels['codewire.sh/egress'] == 'broker'", "true")),
            ("the broker arm on the switch alone", edited("ValidatingAdmissionPolicy", WARM_POOL_TEMPLATE_POLICY,
                                                          "variables.switchOn || variables.keepsBroker", "variables.switchOn")),
            ("the broker arm on any update", edited("ValidatingAdmissionPolicy", WARM_POOL_TEMPLATE_POLICY,
                                                    "variables.switchOn || variables.keepsBroker",
                                                    "variables.switchOn || request.operation == 'UPDATE'")),
            ("the arm rule reading the switch alone", edited("ValidatingAdmissionPolicy", WARM_POOL_TEMPLATE_POLICY,
                                                             "variables.hostedEgress ? variables.broker", "variables.switchOn ? variables.broker")),
            ("the broker egress reading the switch alone", edited("ValidatingAdmissionPolicy", WARM_POOL_TEMPLATE_POLICY,
                                                                  "!variables.hostedEgress || has(object.spec.networkPolicy)",
                                                                  "!variables.switchOn || has(object.spec.networkPolicy)")),
            ("the resolver reading the switch alone", edited("ValidatingAdmissionPolicy", WARM_POOL_TEMPLATE_POLICY,
                                                             "!variables.hostedEgress || variables.clearing || has(variables.pod.dnsPolicy)",
                                                             "!variables.switchOn || variables.clearing || has(variables.pod.dnsPolicy)")),
            # codewire#4000: the clearing exception stays exactly the rendered clearing template.
            ("any cw-snap- template as clearing", edited("ValidatingAdmissionPolicy", WARM_POOL_TEMPLATE_POLICY,
                                                         "-clear$') &&", "-clear') &&")),
            ("a clearing template with egress", edited("ValidatingAdmissionPolicy", WARM_POOL_TEMPLATE_POLICY,
                                                       "size(object.spec.networkPolicy.egress) == 0", "true")),
            ("a clearing template with the egress label", edited("ValidatingAdmissionPolicy", WARM_POOL_TEMPLATE_POLICY,
                                                                 "!variables.egressLabelled && variables.containers.all(", "variables.containers.all(")),
            ("a clearing template of another type", edited("ValidatingAdmissionPolicy", WARM_POOL_TEMPLATE_POLICY,
                                                           "object.metadata.labels['codewire.sh/type'] == 'snapshot-clearing' &&", "")),
            ("the clearing exception in the broker egress", edited("ValidatingAdmissionPolicy", WARM_POOL_TEMPLATE_POLICY,
                                                                   "!variables.hostedEgress || has(object.spec.networkPolicy)",
                                                                   "!variables.hostedEgress || variables.clearing || has(object.spec.networkPolicy)")),
            ("the TUN init as a regular container", edited("ValidatingAdmissionPolicy", WARM_POOL_TEMPLATE_POLICY,
                                                           "variables.pod.containers.all(c, c.name != 'hosted-egress-tun') &&", "")),
            ("a broker peer with any labels", edited("ValidatingAdmissionPolicy", WARM_POOL_TEMPLATE_POLICY,
                                                     "size(t.podSelector.matchLabels) == size(b) - 2 &&", "")),
            ("a disk-backed TUN device volume", edited("ValidatingAdmissionPolicy", WARM_POOL_TEMPLATE_POLICY,
                                                       "v.emptyDir.medium == 'Memory' &&", "true &&")),
            ("the TUN device volume in any container", edited("ValidatingAdmissionPolicy", WARM_POOL_TEMPLATE_POLICY,
                                                              "(c.name == 'workspace' || c.name == 'hosted-egress-tun') &&", "true &&")),
            ("the TUN init with any mount", edited("ValidatingAdmissionPolicy", WARM_POOL_TEMPLATE_POLICY,
                                                   "c.volumeMounts[0].name == 'egress-devnet' &&", "true &&")),
            ("the TUN init on any runtime", edited("ValidatingAdmissionPolicy", WARM_POOL_TEMPLATE_POLICY,
                                                   "variables.pod.runtimeClassName in variables.vmRuntimeClasses", "true")),
            ("a diagnostic VM class", edited("ValidatingAdmissionPolicy", WARM_POOL_TEMPLATE_POLICY,
                                             "'[''commodity'', ''commodity-32g'']'\n    name: vmRuntimeClasses",
                                             "'[''commodity'', ''commodity-32g'', ''runc'']'\n    name: vmRuntimeClasses")),
            # Rendered single-quoted: apostrophes double.
            ("mount-workspace after the TUN init", edited("ValidatingAdmissionPolicy", WARM_POOL_TEMPLATE_POLICY,
                                                          "i.name).indexOf(''mount-workspace'') <", "i.name).indexOf(''mount-workspace'') >")),
            ("any root regular container", edited("ValidatingAdmissionPolicy", WARM_POOL_TEMPLATE_POLICY,
                                                  "c.name == ''dind'' && c.image.matches(", "true || c.image.matches(")),
            ("a root Pod user", edited("ValidatingAdmissionPolicy", WARM_POOL_TEMPLATE_POLICY,
                                       "variables.pod.securityContext.runAsUser == 1000 &&", "true &&")),
            ("a root sidecar", edited("ValidatingAdmissionPolicy", WARM_POOL_TEMPLATE_POLICY,
                                      "c.name == ''hosted-egress-tun'' && !has(c.restartPolicy) ||",
                                      "c.name == ''hosted-egress-tun'' ||")),
            ("a broker template without the TUN init", edited("ValidatingAdmissionPolicy", WARM_POOL_TEMPLATE_POLICY,
                                                              # This rule renders unquoted, so its apostrophes stay single.
                                                              "variables.pod.initContainers.exists(c, c.name == 'hosted-egress-tun'))",
                                                              "true)")),
            ("optional broker addresses", edited("ValidatingAdmissionPolicy", WARM_POOL_TEMPLATE_POLICY,
                                                 "variables.brokerRequiredEnvironment.all(n,", "[].all(n,")),
            ("cluster DNS", edited("ValidatingAdmissionPolicy", WARM_POOL_TEMPLATE_POLICY,
                                   "variables.pod.dnsPolicy == ''None'' &&", "true &&")),
            ("added capabilities", edited("ValidatingAdmissionPolicy", WARM_POOL_TEMPLATE_POLICY,
                                          "|| size(c.securityContext.capabilities.add) == 0)", "|| true)")),
            ("orchestration reading the switch elsewhere", edited("Deployment", "codewire-orchestration",
                                                                  f"name: {HOSTED_EGRESS_CONFIGMAP}", "name: codewire-config")),
        ]:
            expect_rejected(f"hosted egress: {param_label}", mutate)
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
        for policy_name, before, after in [
            (WARM_POOL_POLICY, "variables.pool ||", "true ||"),
            (WARM_POOL_POLICY, "object.spec.updateStrategy.type == 'Recreate'", "true"),
            (WARM_POOL_POLICY, "object.spec.replicas <= 16", "true"),
            (WARM_POOL_POLICY, "object.spec.sandboxTemplateRef.name == request.name", "true"),
            (WARM_POOL_TEMPLATE_POLICY, "@sha256:[0-9a-f]{64}$') || c.image in", "') || c.image in"),
            (WARM_POOL_TEMPLATE_POLICY, "@sha256:[0-9a-f]{64}$') || v.image.reference in", "') || v.image.reference in"),
            (WARM_POOL_TEMPLATE_POLICY, "|| c.image in variables.localImages", "|| true"),
            (WARM_POOL_TEMPLATE_POLICY, "|| v.image.reference in variables.localImages", "|| true"),
            # C4: only the Kind e2e overlay admits a local image.
            (WARM_POOL_TEMPLATE_POLICY, "- expression: '[]'", "- expression: '[''codewire-daemon:e2e'']'"),
            (WARM_POOL_TEMPLATE_POLICY, "variables.pod.runtimeClassName != 'confidential'", "true"),
            # codewire#3626: every term of the ingress rule is load-bearing.
            (WARM_POOL_TEMPLATE_POLICY, "(size(object.spec.networkPolicy.ingress) == 1 &&", "(size(object.spec.networkPolicy.ingress) >= 1 &&"),
            (WARM_POOL_TEMPLATE_POLICY, "size(object.spec.networkPolicy.ingress) == 0 ||", "true ||"),
            (WARM_POOL_TEMPLATE_POLICY, "object.spec.networkPolicyManagement == 'Managed') &&", "true) &&"),
            (WARM_POOL_TEMPLATE_POLICY, "(!has(object.spec.networkPolicy.ingress) ||", "(true ||"),
            (WARM_POOL_TEMPLATE_POLICY, "has(r.from) && size(r.from) == 1", "has(r.from)"),
            (WARM_POOL_TEMPLATE_POLICY, "dyn(f).all(k, k in ['namespaceSelector', 'podSelector'])", "dyn(f).all(k, k in ['namespaceSelector', 'podSelector', 'ipBlock'])"),
            (WARM_POOL_TEMPLATE_POLICY, "== variables.serverNamespace &&", "!= '' &&"),
            (WARM_POOL_TEMPLATE_POLICY, "has(f.podSelector) &&", "true &&"),
            (WARM_POOL_TEMPLATE_POLICY, "size(f.podSelector.matchLabels) == 2", "size(f.podSelector.matchLabels) >= 1"),
            (WARM_POOL_TEMPLATE_POLICY, "f.podSelector.matchLabels['app.kubernetes.io/name'] == 'codewire'", "true"),
            (WARM_POOL_TEMPLATE_POLICY, "has(r.ports) && size(r.ports) == 2", "has(r.ports)"),
            (WARM_POOL_TEMPLATE_POLICY, "dyn(q).all(k, k in ['port', 'protocol'])", "dyn(q).all(k, k in ['port', 'protocol', 'endPort'])"),
            (WARM_POOL_TEMPLATE_POLICY, "q.protocol == 'TCP' && type(q.port) == int", "type(q.port) == int"),
            (WARM_POOL_TEMPLATE_POLICY, "q.port == 2222", "q.port == 38081"),
            (WARM_POOL_TEMPLATE_POLICY, "variables.pod.automountServiceAccountToken == false", "true"),
            # Review M2: every allowlist and host rule is load-bearing.
            (WARM_POOL_TEMPLATE_POLICY, "e.name in variables.environment &&", "true &&"),
            (WARM_POOL_TEMPLATE_POLICY, "'CODEWIRE_DOCKER_MOUNT_MODE']", "'CODEWIRE_DOCKER_MOUNT_MODE', 'OPENAI_API_KEY']"),
            (WARM_POOL_TEMPLATE_POLICY, "dyn(e).all(k, k in ['name', 'value', 'valueFrom'])", "true"),
            (WARM_POOL_TEMPLATE_POLICY, "(!has(e.valueFrom) || (e.name == 'CODEWIRE_POD_UID' &&", "(true || (e.name == 'CODEWIRE_POD_UID' &&"),
            (WARM_POOL_TEMPLATE_POLICY, "dyn(e.valueFrom).all(k, k == 'fieldRef')", "true"),
            (WARM_POOL_TEMPLATE_POLICY, "e.valueFrom.fieldRef.fieldPath == 'metadata.uid'", "true"),
            (WARM_POOL_TEMPLATE_POLICY, "'configMap', 'projected'])", "'configMap', 'projected', 'hostPath'])"),
            # Only the public roots ConfigMaps, each only as its ca.crt.
            (WARM_POOL_TEMPLATE_POLICY, "v.configMap.name in variables.rootsConfigMaps", "true"),
            (WARM_POOL_TEMPLATE_POLICY, "dyn(v.configMap).all(k, k in ['name', 'items', 'defaultMode'])", "true"),
            (WARM_POOL_TEMPLATE_POLICY, "size(v.configMap.items) == 1", "true"),
            (WARM_POOL_TEMPLATE_POLICY, "dyn(v.configMap.items[0]).all(k, k in ['key', 'path'])", "true"),
            (WARM_POOL_TEMPLATE_POLICY, "v.configMap.items[0].key == 'ca.crt'", "true"),
            (WARM_POOL_TEMPLATE_POLICY, "v.configMap.items[0].path == 'ca.crt'", "true"),
            (WARM_POOL_TEMPLATE_POLICY, "['codewire-orchestration-internal-roots']",
             "['codewire-orchestration-internal-roots', 'codewire-credential-broker-roots']"),
            (WARM_POOL_TEMPLATE_POLICY, "dyn(s).all(k, k == 'serviceAccountToken')", "true"),
            (WARM_POOL_TEMPLATE_POLICY, "s.serviceAccountToken.audience in variables.audiences", "true"),
            (WARM_POOL_TEMPLATE_POLICY, "'codewire.internal.credential-workspace.v1']", "'codewire.internal.credential-workspace.v1', 'https://kubernetes.default.svc']"),
            (WARM_POOL_TEMPLATE_POLICY, "in variables.runtimeClasses", "!= 'confidential'"),
            (WARM_POOL_TEMPLATE_POLICY, "['commodity', 'commodity-32g']",
             "['commodity', 'commodity-32g', 'runc']"),
            (WARM_POOL_TEMPLATE_POLICY, "!variables.pod.hostNetwork", "true"),
            (WARM_POOL_TEMPLATE_POLICY, "!variables.pod.hostPID", "true"),
            (WARM_POOL_TEMPLATE_POLICY, "!variables.pod.hostIPC", "true"),
            (WARM_POOL_TEMPLATE_POLICY, "!has(variables.pod.hostAliases)", "true"),
            (WARM_POOL_TEMPLATE_POLICY, "!has(variables.pod.nodeName)", "true"),
            (WARM_POOL_TEMPLATE_POLICY, "c.env.exists_one(e, e.name == 'CODEWIRE_WORKSPACE_POOL_REVISION')", "true"),
            (WARM_POOL_TEMPLATE_POLICY, "e.value == object.metadata.annotations['codewire.sh/pool-revision']", "true"),
            # codewire#3318: every egress allowlist term is load-bearing.
            (WARM_POOL_TEMPLATE_POLICY, "variables.nonWorldIPv4.all(c, c in t.ipBlock.except)", "true"),
            (WARM_POOL_TEMPLATE_POLICY, "variables.nonWorldIPv6.all(c, c in t.ipBlock.except)", "true"),
            (WARM_POOL_TEMPLATE_POLICY, "in variables.egressPeers", "|| true"),
            (WARM_POOL_TEMPLATE_POLICY, "size(t.namespaceSelector.matchLabels) == 1", "true"),
            (WARM_POOL_TEMPLATE_POLICY, "size(t.podSelector.matchLabels) == 1", "true"),
            (WARM_POOL_TEMPLATE_POLICY, "dyn(p).all(k, k in ['port', 'protocol'])", "true"),
            (WARM_POOL_TEMPLATE_POLICY, "has(object.spec.networkPolicy.egress) &&", "true &&"),
            (WARM_POOL_TEMPLATE_POLICY, "'kube-system||UDP/53'", "'kube-system||UDP/53', 'kube-system||TCP/9153'"),
            (WARM_POOL_TEMPLATE_POLICY, "'172.16.0.0/12', '192.168.0.0/16'", "'192.168.0.0/16'"),
            (WARM_POOL_MEMBER_POLICY, "o.kind == 'SandboxWarmPool'", "false"),
            (WARM_POOL_MEMBER_POLICY, "'agents.x-k8s.io/warm-pool-sandbox' in object.metadata.labels", "false"),
            (WARM_POOL_MEMBER_POLICY, "'agents.x-k8s.io/warm-pool-sandbox' in oldObject.metadata.labels", "false"),
            (WARM_POOL_MEMBER_POLICY, "request.operation != 'UPDATE' ||", "true ||"),
            (WARM_POOL_MEMBER_POLICY, "- UPDATE\n    resources:", "    resources:"),
            # codewire#5002: every template is matched and the pool's rules
            # gate on the name alone; the KBS rule and the confidential TUN
            # hold only outside pools; broker mode never comes off a Sandbox.
            (WARM_POOL_TEMPLATE_POLICY, "'!request.name.startsWith(''cw-pool-'')'", "'true'"),
            (WARM_POOL_TEMPLATE_POLICY, "variables.environmentTemplate ||", "true ||"),
            (WARM_POOL_TEMPLATE_POLICY, "(variables.environmentTemplate && has(variables.pod.runtimeClassName) &&", "(has(variables.pod.runtimeClassName) &&"),
            (WARM_POOL_TEMPLATE_POLICY, "runtimeClassName == ''confidential'' && dyn(r)", "runtimeClassName !=  && dyn(r)"),
            (WARM_POOL_TEMPLATE_POLICY, "dyn(r.to[0]).all(k, k in ['namespaceSelector', 'podSelector'])", "true"),
            (WARM_POOL_TEMPLATE_POLICY, "? !has(r.to[0].podSelector) :", "? true :"),
            (WARM_POOL_TEMPLATE_POLICY, "== size(variables.kbsPeer) - 2", ">= 0"),
            (WARM_POOL_TEMPLATE_POLICY, "+ r.to[0].podSelector.matchLabels[k]) in variables.kbsPeer))", "+ r.to[0].podSelector.matchLabels[k]) != ''))"),
            (WARM_POOL_TEMPLATE_POLICY, "has(r.ports) && size(r.ports) == 1", "has(r.ports)"),
            (WARM_POOL_TEMPLATE_POLICY, "== variables.kbsPeer[0]", "!= ''"),
            (WARM_POOL_TEMPLATE_POLICY, "== variables.kbsPeer[1]", "!= ''"),
            (WARM_POOL_TEMPLATE_POLICY, "'[''codewire-trustee'', ''TCP/8080'']'", "'[''kube-system'', ''TCP/8080'']'"),
            (WARM_POOL_TEMPLATE_POLICY, "variables.environmentTemplate && variables.pod.runtimeClassName == 'confidential') &&",
             "variables.pod.runtimeClassName == 'confidential') &&"),
            (WARM_POOL_TEMPLATE_POLICY, "i.image == c.image)))))", "true)))))"),
            (WARM_POOL_TEMPLATE_POLICY, "&& variables.pod.initContainers.exists(i, i.name == 'codewire-daemon-init'",
             "|| variables.pod.initContainers.exists(i, i.name == 'codewire-daemon-init'"),
            (WARM_POOL_MEMBER_POLICY, "== 'broker') || has(object.spec.podTemplate)", "== 'broker') || true || has(object.spec.podTemplate)"),
            (WARM_POOL_MEMBER_POLICY, "object.spec.podTemplate.metadata.labels['codewire.sh/egress'] == 'broker'\n", "true\n"),
            # codewire#4000: with the switch on, a pre-switch VM Sandbox only stops.
            (WARM_POOL_MEMBER_POLICY, "|| !variables.hostedEgress ||", "|| true ||"),
            (WARM_POOL_MEMBER_POLICY, "|| variables.wholeBroker ||", "|| variables.broker ||"),
            (WARM_POOL_MEMBER_POLICY, "object.spec.operatingMode == 'Suspended'", "object.spec.operatingMode != ''"),
            (WARM_POOL_MEMBER_POLICY, "[object, oldObject].exists(s,", "[object].exists(s,"),
            # codewire#4000: broker mode is added only by a start's move: with
            # the switch on, to a Sandbox bound to an environment, suspended
            # before and after.
            (WARM_POOL_MEMBER_POLICY, "!variables.addsBroker || variables.hostedEgress &&", "true ||"),
            (WARM_POOL_MEMBER_POLICY, "!variables.addsBroker || variables.hostedEgress && has(oldObject.spec.operatingMode)",
             "!variables.addsBroker || has(oldObject.spec.operatingMode)"),
            # ... it keeps the runtime class ...
            (WARM_POOL_MEMBER_POLICY, "object.spec.podTemplate.spec.runtimeClassName == oldObject.spec.podTemplate.spec.runtimeClassName",
             "true"),
            (WARM_POOL_MEMBER_POLICY, "has(object.spec.podTemplate.spec.runtimeClassName) == has(oldObject.spec.podTemplate.spec.runtimeClassName) &&",
             ""),
            # ... the label never goes on alone ...
            (WARM_POOL_MEMBER_POLICY, "|| variables.wasBroker || variables.wholeBroker", "|| true"),
            # ... and broker mode means the whole shape: the fence revision
            # and the TUN init (or a standard VM), not the label alone.
            (WARM_POOL_MEMBER_POLICY, "'codewire.sh/egress-fence-revision' in object.spec.podTemplate.metadata.annotations &&", ""),
            (WARM_POOL_MEMBER_POLICY, "object.spec.podTemplate.spec.initContainers.exists(c, c.name == 'hosted-egress-tun')", "true"),
            (WARM_POOL_MEMBER_POLICY, "oldObject.spec.podTemplate.spec.initContainers.exists(c, c.name == 'hosted-egress-tun')", "true"),
            (WARM_POOL_MEMBER_POLICY, "oldObject.spec.operatingMode == 'Suspended' &&", "true &&"),
            (WARM_POOL_MEMBER_POLICY, "size(oldObject.spec.podTemplate.metadata.labels['codewire.sh/environment-id']) > 0", "true"),
            (WARM_POOL_MEMBER_POLICY, "object.spec.podTemplate.metadata.labels['codewire.sh/environment-id'] ==", "true ||"),
            # ... and what it adds is the template policy's broker shape, each
            # rule whole, from the same variables.
            (WARM_POOL_MEMBER_POLICY, "!variables.addsBroker || (", "true || ("),
            (WARM_POOL_MEMBER_POLICY, "&& !variables.wasWholeBroker", ""),
            (WARM_POOL_MEMBER_POLICY, "variables.wholeBroker && !variables.wasWholeBroker", "variables.broker && !variables.wasBroker"),
            (WARM_POOL_MEMBER_POLICY, "variables.volumes.all(v, !has(v.hostPath))", "true"),
            # ... the CODEWIRE_VM_EGRESS_MODE rule included (codewire#6033).
            (WARM_POOL_MEMBER_POLICY, "e.value in ['guest-carried', 'broker']", "e.value in ['guest-carried', 'broker', 'direct']"),
            (WARM_POOL_MEMBER_POLICY, "c.env.exists_one(e, e.name == 'CODEWIRE_VM_EGRESS_MODE')", "true"),
            (WARM_POOL_MEMBER_POLICY, "variables.pod.dnsConfig.nameservers == ['192.0.2.1']", "true"),
            (WARM_POOL_MEMBER_POLICY, "variables.pod.runtimeClassName == 'standard'", "true"),
            (WARM_POOL_MEMBER_POLICY, "expression: \"false\"", "expression: \"true\""),
            (WARM_POOL_TEMPLATE_POLICY, "variables.volumes.all(v, !has(v.hostPath))", "true"),
            (WARM_POOL_TEMPLATE_POLICY, "(!has(variables.pod.hostPID) || !variables.pod.hostPID) &&", ""),
            (WARM_POOL_TEMPLATE_POLICY, "object.spec.podTemplate.metadata.annotations['codewire.sh/egress-fence-revision'] ==", "true ||"),
            # No other identity adds broker mode to an existing Sandbox.
            (SANDBOX_BROKER_WRITER_POLICY, "!request.userInfo.username.matches(", "request.userInfo.username.matches("),
            (SANDBOX_BROKER_WRITER_POLICY, "(variables.wasWholeBroker || !variables.wholeBroker)", "true"),
            (SANDBOX_BROKER_WRITER_POLICY, "(variables.wasBroker || !variables.broker)", "true"),
            (SANDBOX_BROKER_WRITER_POLICY, "object.spec.podTemplate.spec.initContainers.exists(c, c.name == 'hosted-egress-tun')", "true"),
            # The VM test stays an exclusion: back to an allow-list, or a
            # VM class counted as direct, is refused.
            (WARM_POOL_MEMBER_POLICY, "!(s.spec.podTemplate.spec.runtimeClassName in variables.directRuntimeClasses))",
             "s.spec.podTemplate.spec.runtimeClassName in ['commodity', 'commodity-32g', 'confidential', 'standard'])"),
            (WARM_POOL_MEMBER_POLICY, "!(s.spec.podTemplate.spec.runtimeClassName in variables.directRuntimeClasses))",
             "!(s.spec.podTemplate.spec.runtimeClassName in ['runc', '', 'another-vm']))"),
            (WARM_POOL_MEMBER_POLICY, "['runc', '']", "['runc', '', 'commodity']"),
            (WARM_POOL_MEMBER_POLICY, "params.data['CODEWIRE_HOSTED_EGRESS_ENABLED'] == 'true'", "true"),
            # codewire#6121: a move is never a keep, so the member's switch
            # admits nothing more than the switch.
            (WARM_POOL_MEMBER_POLICY, "params.data['CODEWIRE_HOSTED_EGRESS_ENABLED'] == 'true'",
             "params.data['CODEWIRE_HOSTED_EGRESS_ENABLED'] == 'true' || request.operation == 'UPDATE'"),
        ]:
            image_cache_rejected(f"warm pool {before}", "ValidatingAdmissionPolicy", before, after, policy_name)
        image_cache_rejected("warm pool namespace-label bypass", "ValidatingAdmissionPolicyBinding",
                             "spec:\n", "spec:\n  matchResources:\n    namespaceSelector:\n      matchLabels:\n        codewire.sh/resource-type: sandbox\n",
                             WARM_POOL_POLICY)
        for missing in [WARM_POOL_TEMPLATE_POLICY, WARM_POOL_MEMBER_POLICY, SANDBOX_BROKER_WRITER_POLICY]:
            expect_rejected(f"missing {missing}", lambda resources, missing=missing: [
                resource for resource in resources
                if metadata_field(resource, "name") != missing
            ])
        for bypassed in [WARM_POOL_TEMPLATE_POLICY, WARM_POOL_MEMBER_POLICY]:
            image_cache_rejected(f"{bypassed} namespace-label bypass", "ValidatingAdmissionPolicyBinding",
                                 "spec:\n", "spec:\n  matchResources:\n    namespaceSelector:\n      matchLabels:\n        codewire.sh/resource-type: sandbox\n",
                                 bypassed)
        for before, after in [
            ("  - nodes\n  verbs:\n  - get\n  - list", "  - nodes\n  verbs:\n  - get\n  - list\n  - watch"),
            ("  - nodes\n  verbs:\n  - get\n  - list", "  - nodes\n  verbs:\n  - get\n  - list\n  - patch"),
            ("  - runtimeclasses\n  verbs:\n  - get", "  - runtimeclasses\n  verbs:\n  - get\n  - update"),
        ]:
            image_cache_rejected(f"warm pool ClusterRole {after.split()[-1]}", "ClusterRole", before, after, orchestration)
        # codewire#2282: no cluster-wide write, exec or namespace mutation.
        for before, after in [
            ("  - namespaces\n  verbs:\n  - get", "  - namespaces\n  verbs:\n  - get\n  - patch"),
            ("  - persistentvolumes\n  verbs:\n  - list", "  - persistentvolumes\n  - pods/exec\n  verbs:\n  - list"),
            ("  - tokenreviews\n  verbs:\n  - create", "  - tokenreviews\n  - services\n  verbs:\n  - create"),
        ]:
            image_cache_rejected(f"cluster-wide {after.split()[-1]}", "ClusterRole", before, after, orchestration)
        # codewire#2238: the API servers' ready list stays one named get.
        # Rendered keys are sorted: resourceNames before resources.
        endpoints = "  resourceNames:\n  - kubernetes\n  resources:\n  - endpointslices\n  verbs:\n  - get"
        for name, after in [
            ("list", endpoints + "\n  - list"),
            ("watch", endpoints + "\n  - watch"),
            ("another name", endpoints.replace("  - kubernetes\n", "  - kubernetes\n  - other\n")),
            ("no name", "  resources:\n  - endpointslices\n  verbs:\n  - get"),
        ]:
            image_cache_rejected(f"cluster-wide EndpointSlice {name}", "ClusterRole", endpoints, after, orchestration)
        for before, after in [
            ("  - sandboxes\n  verbs:\n  - get", "  - sandboxes\n  verbs:\n  - create\n  - get"),
            ("  - pods\n  verbs:\n  - get\n  - list\n  - delete", "  - pods\n  verbs:\n  - get\n  - list\n  - delete\n  - create"),
            ("  - networkpolicies\n  verbs:\n  - get", "  - networkpolicies\n  verbs:\n  - patch\n  - get"),
            # list for the lockdown check, never watch: it reads once per check (#4964).
            ("  - networkpolicies\n  verbs:\n  - get\n  - list", "  - networkpolicies\n  verbs:\n  - get\n  - list\n  - watch"),
        ]:
            image_cache_rejected(f"Sandbox Role {after}", "Role", before, after, SANDBOX_ROLE)
        image_cache_rejected("Sandbox Role in orchestration's namespace", "Role",
                             "  name: codewire-orchestration-sandboxes\n  namespace: prod-sandboxes",
                             "  name: codewire-orchestration-sandboxes\n  namespace: prod", SANDBOX_ROLE)
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
            resource.replace("  - tokenreviews\n", "  - tokenreviews\n  - daemonsets\n", 1)
            if top_level_field(resource, "kind") == "ClusterRole" and metadata_field(resource, "name") == orchestration
            else resource for resource in resources
        ])

    try:
        credential_target = {"subject_namespace": "prod", "role_namespace": "prod-sandboxes"}
        credential_resources = documents(run(["kustomize", "build", "deployments/k8s/credential-service"]).stdout)
        assert_credential_service(credential_resources, credential_target, "credential-service (rendered)", failures)
        udp_relay_resources = documents(run(["kustomize", "build", "deployments/k8s/udp-relay"]).stdout)
        assert_udp_relay(udp_relay_resources, "udp-relay (rendered)", failures)
        orchestration_resources = documents(run(["kustomize", "build", "deployments/k8s/orchestration"]).stdout)
        assert_relay_allocator_client(orchestration_resources, "orchestration (rendered)", failures)
        manifests: list[str] = []
        renders: dict[str, list[str]] = {}
        for target in targets:
            renders[target["path"]] = documents(run(["kustomize", "build", target["path"]]).stdout)
            manifests.extend(renders[target["path"]])
            failures.extend(verify_resources(renders[target["path"]], target, f"{target['path']} (rendered)"))
        unexpected = set(relay_allocator_leaves(manifests + udp_relay_resources + orchestration_resources))
        if not unexpected <= RELAY_ALLOCATOR_LEAVES:
            failures.append(
                "the relay allocator authority signs a leaf it must not: "
                + ", ".join(sorted(unexpected - RELAY_ALLOCATOR_LEAVES))
            )
        failures.extend(check_warm_member_bridge(args.self_test, manifests))
        if args.self_test:
            self_test()
            credential_service_self_test(credential_resources, credential_target)
            udp_relay_self_test(udp_relay_resources)
            relay_allocator_client_self_test(orchestration_resources)
            # The rendered credential edge is proved on the retained local
            # Kind overlay; codewire/deploy guards the hosted renders.
            for path in CREDENTIAL_SELF_TEST_TARGETS:
                target = next(target for target in targets if target["path"] == path)
                credential_service_self_test(renders[path], target)
    except Exception as error:  # noqa: BLE001 - repo check script
        failures.append(str(error))

    if failures:
        for failure in failures:
            print(f"::error::orchestration authorization: {failure}", file=sys.stderr)
        return 1
    print(f"orchestration authorization: OK ({len(targets)} rendered target(s))")
    return 0
