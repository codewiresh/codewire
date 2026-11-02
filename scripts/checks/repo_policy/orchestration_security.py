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
    '- apiGroups: - node.k8s.io resources: - runtimeclasses verbs: - get'
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
    '- apiGroups: - networking.k8s.io resources: - networkpolicies verbs: - get - create - update - delete '
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
            "expression: request.name.startsWith('cw-pool-')",
            f"request.name.matches('{WARM_POOL_NAME_PATTERN}')",
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
            # mount-workspace builds each read-only root from its own
            # container's image, mounted as that image volume, and only it
            # names one (codewire#3718).
            "(c.name == 'mount-workspace' && e.name in ['CODEWIRE_WORKSPACE_IMAGE', 'CODEWIRE_DIND_IMAGE'] &&",
            "w.name == (e.name == 'CODEWIRE_WORKSPACE_IMAGE' ? 'workspace' : 'dind') && w.image == e.value",
            "v.name == (e.name == 'CODEWIRE_WORKSPACE_IMAGE' ? 'rootfs-workspace-image' : 'rootfs-dind-image') &&",
            "has(v.image) && has(v.image.reference) && v.image.reference == e.value",
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
        ],
        WARM_POOL_MEMBER_POLICY: [
            "apiGroups: - agents.x-k8s.io apiVersions: - v1beta1 operations: - CREATE - UPDATE resources: - sandboxes",
            "!(has(object.metadata.labels) && 'agents.x-k8s.io/warm-pool-sandbox' in object.metadata.labels)",
            "!(has(object.metadata.ownerReferences) && object.metadata.ownerReferences.exists(o, o.kind == 'SandboxWarmPool'))",
            "request.operation != 'UPDATE' || (!(has(oldObject.metadata.labels) && 'agents.x-k8s.io/warm-pool-sandbox' in oldObject.metadata.labels)",
            "!(has(oldObject.metadata.ownerReferences) && oldObject.metadata.ownerReferences.exists(o, o.kind == 'SandboxWarmPool'))",
        ],
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
                # Only the Kind e2e overlay adds its test knob's variable (#3852).
                environment = [*WARM_POOL_ENVIRONMENT, *WARM_POOL_EXTRA_ENVIRONMENT.get(target["path"], [])]
                found = re.search(r"- expression: '?(\[[^\]]*\])'? name: environment ", normalized)
                if not found or found.group(1) != cel_list(environment):
                    output.append(f"{label}: {policy_name} workspace environment must be exactly {cel_list(environment)}: "
                                  f"{found.group(1) if found else None}")
        if binding:
            expected = compact(f"spec: policyName: {policy_name} validationActions: - Deny")
            if metadata_field(binding, "namespace") is not None or compact(top_level_block(binding, "spec")) != expected:
                output.append(f"{label}: {policy_name} must deny by identity without mutable namespace selectors")


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
        ]:
            image_cache_rejected(f"warm pool {before}", "ValidatingAdmissionPolicy", before, after, policy_name)
        image_cache_rejected("warm pool namespace-label bypass", "ValidatingAdmissionPolicyBinding",
                             "spec:\n", "spec:\n  matchResources:\n    namespaceSelector:\n      matchLabels:\n        codewire.sh/resource-type: sandbox\n",
                             WARM_POOL_POLICY)
        for missing in [WARM_POOL_TEMPLATE_POLICY, WARM_POOL_MEMBER_POLICY]:
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
        for before, after in [
            ("  - sandboxes\n  verbs:\n  - get", "  - sandboxes\n  verbs:\n  - create\n  - get"),
            ("  - pods\n  verbs:\n  - get\n  - list\n  - delete", "  - pods\n  verbs:\n  - get\n  - list\n  - delete\n  - create"),
            ("  - networkpolicies\n  verbs:\n  - get", "  - networkpolicies\n  verbs:\n  - patch\n  - get"),
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
        manifests: list[str] = []
        renders: dict[str, list[str]] = {}
        for target in targets:
            renders[target["path"]] = documents(run(["kustomize", "build", target["path"]]).stdout)
            manifests.extend(renders[target["path"]])
            failures.extend(verify_resources(renders[target["path"]], target, f"{target['path']} (rendered)"))
        failures.extend(check_warm_member_bridge(args.self_test, manifests))
        if args.self_test:
            self_test()
            credential_service_self_test(credential_resources, credential_target)
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
