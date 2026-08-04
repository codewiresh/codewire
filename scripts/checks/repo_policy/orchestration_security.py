from .shared import *
from .kubernetes import (
    compact,
    documents,
    exactly_one,
    metadata_field,
    resources_by_kind_and_name,
    top_level_block,
    top_level_field,
)

def check_orchestration_host_key_authz(args: argparse.Namespace) -> int:
    name = "codewire-orchestration-gateway-host-key"
    orchestration = "codewire-orchestration"
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
        assert_bound_surface(resources, target, label, output)
        assert_admission(resources, label, output)
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
        if expected_admission_allows("CREATE", "unrelated-secret", {"type": "Opaque", "metadata": {"labels": {}}}) or expected_admission_allows("DELETE", "unrelated-secret"):
            raise RuntimeError("unrelated Secret create/delete fixture was accepted")

    try:
        for target in targets:
            rendered = run(["kustomize", "build", target["path"]]).stdout
            failures.extend(verify_resources(documents(rendered), target, f"{target['path']} (rendered)"))
        if args.self_test:
            self_test()
    except Exception as error:  # noqa: BLE001 - repo check script
        failures.append(str(error))

    if failures:
        for failure in failures:
            print(f"::error::orchestration host-key authorization: {failure}", file=sys.stderr)
        return 1
    print(f"orchestration host-key authorization: OK ({len(targets)} rendered target(s))")
    return 0
