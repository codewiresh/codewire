from .shared import *
from .kubernetes import documents, resource_name, top_level_field

def check_idp_signing_kek_isolation(args: argparse.Namespace) -> int:
    secret = "codewire-idp-signing-keks"
    volume = "idp-signing-keks"
    kek_dir = "/var/run/secrets/codewire/idp-signing-keks"
    default_active_id = "v1"
    env_names = ["IDP_SIGNING_KEK_DIR", "IDP_SIGNING_ACTIVE_KEK_ID"]
    workload_markers = [secret, volume, kek_dir, *env_names]
    pod_workload_kinds = {"Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"}
    synthetic_kek = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    # codewire/deploy's hosted guards check the hosted Dev and Production renders.
    overlays = [
        {"path": "deployments/k8s/idp", "local": False, "active_id": default_active_id},
        {"path": "deployments/k8s/overlays/local-kind", "local": True, "active_id": default_active_id},
        {"path": "deployments/k8s/overlays/local-kind-static", "local": True, "active_id": default_active_id},
    ]
    failures: list[str] = []

    def fail(message: str) -> None:
        failures.append(message)

    def count(document: str, needle: str) -> int:
        return document.count(needle)

    def assert_env(document: str, name: str, value: str, label: str) -> None:
        expression = re.compile(
            rf"^\s*- name: {re.escape(name)}\s*\n\s+value: [\"']?{re.escape(value)}[\"']?\s*$",
            re.MULTILINE,
        )
        if not expression.search(document):
            fail(f"{label}: codewire-idp must set {name}={value}")
        if count(document, f"name: {name}") != 1:
            fail(f"{label}: codewire-idp must contain {name} exactly once")

    def assert_idp_deployment(document: str, label: str, active_id: str) -> None:
        assert_env(document, "IDP_SIGNING_KEK_DIR", kek_dir, label)
        assert_env(document, "IDP_SIGNING_ACTIVE_KEK_ID", active_id, label)
        if count(document, f"mountPath: {kek_dir}") != 1:
            fail(f"{label}: codewire-idp must mount the signing keyring exactly once")
        if count(document, f"name: {volume}") != 2:
            fail(f"{label}: codewire-idp must have one {volume} mount and one volume")
        read_only_kek_mount = re.compile(
            rf"^\s*- mountPath: {re.escape(kek_dir)}\s*\n"
            rf"\s+name: {re.escape(volume)}\s*\n"
            r"\s+readOnly: true\s*$",
            re.MULTILINE,
        )
        if not read_only_kek_mount.search(document):
            fail(f"{label}: the signing keyring mount must be explicitly read-only")
        if count(document, f"secretName: {secret}") != 1:
            fail(f"{label}: codewire-idp must reference only the dedicated target Secret")
        if re.search(rf"secretRef:\s*\n\s+name: {re.escape(secret)}", document):
            fail(f"{label}: the signing keyring must never be injected through envFrom")

    def assert_synthetic_secret(document: str, label: str) -> None:
        if top_level_field(document, "type") != "Opaque":
            fail(f"{label}: the local signing-key Secret must be Opaque")
        string_data = (re.search(r"^stringData:\s*\n([\s\S]*)$", document, re.MULTILINE) or [None, ""])[1]
        entries = list(re.finditer(r"^  ([^:#\s]+):\s*[\"']?([^\"'\s]+)[\"']?\s*$", string_data, re.MULTILINE))
        if len(entries) != 1 or entries[0].group(1) != default_active_id:
            fail(f"{label}: the local signing-key Secret must contain only {default_active_id}")
            return
        if entries[0].group(2) != synthetic_kek:
            fail(f"{label}: local kind must use the checked-in synthetic 32-byte key")

    def assert_static_overlay(overlay: dict[str, Any]) -> None:
        path = overlay["path"]
        label = f"{path} (rendered)"
        rendered = run(["kustomize", "build", path]).stdout
        resources = documents(rendered)
        deployments = [resource for resource in resources if top_level_field(resource, "kind") == "Deployment"]
        idp = [resource for resource in deployments if resource_name(resource) == "codewire-idp"]
        if len(idp) != 1:
            fail(f"{label}: expected exactly one codewire-idp Deployment, found {len(idp)}")
        else:
            assert_idp_deployment(idp[0], label, overlay["active_id"])

        for workload in [
            resource for resource in resources if top_level_field(resource, "kind") in pod_workload_kinds
        ]:
            kind = top_level_field(workload, "kind")
            name = resource_name(workload) or "<unnamed>"
            if kind == "Deployment" and name == "codewire-idp":
                continue
            for marker in workload_markers:
                if marker in workload:
                    fail(f"{label}: unrelated {kind} {name} inherits signing marker {marker}")

        for resource in resources:
            if top_level_field(resource, "kind") != "ConfigMap":
                continue
            name = resource_name(resource) or "<unnamed>"
            for marker in [kek_dir, *env_names]:
                if marker in resource:
                    fail(f"{label}: ConfigMap {name} leaks idp-only configuration {marker}")

        targets = [
            resource
            for resource in resources
            if top_level_field(resource, "kind") == "Secret" and resource_name(resource) == secret
        ]
        if overlay["local"]:
            if len(targets) != 1:
                fail(f"{label}: expected one synthetic {secret} Secret, found {len(targets)}")
            else:
                assert_synthetic_secret(targets[0], label)
        elif targets:
            fail(f"{label}: live/base renders must reference, never generate, {secret}")

    def assert_live_kind() -> None:
        context = args.context
        namespace = args.namespace
        if not context.startswith("kind-") or namespace != "default":
            raise RuntimeError("--live is restricted to a local kind-* context in namespace default")

        def kubectl(*kubectl_args: str) -> str:
            return run(["kubectl", "--context", context, "-n", namespace, *kubectl_args]).stdout

        deployment_list = json.loads(kubectl("get", "deployments", "-o", "json"))
        idp = [item for item in deployment_list.get("items", []) if item.get("metadata", {}).get("name") == "codewire-idp"]
        if len(idp) != 1:
            fail(f"live {context}/{namespace}: expected one codewire-idp Deployment")
        else:
            idp_spec = json.dumps(idp[0].get("spec", {}).get("template", {}).get("spec", {}), ensure_ascii=False)
            for marker in workload_markers:
                if marker not in idp_spec:
                    fail(f"live {context}/{namespace}: codewire-idp is missing {marker}")

        for deployment in deployment_list.get("items", []):
            if deployment.get("metadata", {}).get("name") == "codewire-idp":
                continue
            spec = json.dumps(deployment.get("spec", {}).get("template", {}).get("spec", {}), ensure_ascii=False)
            for marker in workload_markers:
                if marker in spec:
                    fail(
                        f"live {context}/{namespace}: unrelated Deployment "
                        f"{deployment.get('metadata', {}).get('name')} inherits {marker}"
                    )

        pod_list = json.loads(kubectl("get", "pods", "-o", "json"))
        idp_labels = idp[0].get("spec", {}).get("selector", {}).get("matchLabels", {}) if idp else {}

        def is_idp_pod(pod: dict[str, Any]) -> bool:
            labels = pod.get("metadata", {}).get("labels", {})
            return bool(idp_labels) and all(labels.get(key) == value for key, value in idp_labels.items())

        idp_pod_count = len([pod for pod in pod_list.get("items", []) if is_idp_pod(pod)])
        if idp_pod_count < 1:
            fail(f"live {context}/{namespace}: no Pod matches the codewire-idp selector")
        for pod in pod_list.get("items", []):
            if is_idp_pod(pod):
                continue
            spec = json.dumps(pod.get("spec", {}), ensure_ascii=False)
            for marker in workload_markers:
                if marker in spec:
                    fail(f"live {context}/{namespace}: unrelated Pod {pod.get('metadata', {}).get('name')} inherits {marker}")

        config_maps = json.loads(kubectl("get", "configmaps", "-o", "json"))
        for config_map in config_maps.get("items", []):
            data = json.dumps(config_map.get("data", {}), ensure_ascii=False)
            for marker in [kek_dir, *env_names]:
                if marker in data:
                    fail(f"live {context}/{namespace}: ConfigMap {config_map.get('metadata', {}).get('name')} contains {marker}")

        kubectl(
            "exec",
            "deployment/codewire-idp",
            "-c",
            "idp",
            "--",
            "/bin/sh",
            "-ceu",
            f'test "$IDP_SIGNING_KEK_DIR" = "{kek_dir}"; '
            f'test "$IDP_SIGNING_ACTIVE_KEK_ID" = "{default_active_id}"; '
            'test -r "$IDP_SIGNING_KEK_DIR/$IDP_SIGNING_ACTIVE_KEK_ID"; '
            'test "$(wc -c < "$IDP_SIGNING_KEK_DIR/$IDP_SIGNING_ACTIVE_KEK_ID")" -eq 64',
        )
        print(
            f"idp signing KEK isolation: live kind OK ({context}/{namespace}; "
            f"{len(deployment_list.get('items', [])) - 1} unrelated Deployment and "
            f"{len(pod_list.get('items', [])) - idp_pod_count} unrelated Pod spec(s) excluded)"
        )

    try:
        for overlay in overlays:
            assert_static_overlay(overlay)
        if args.live:
            assert_live_kind()
    except Exception as error:  # noqa: BLE001 - repo check script
        fail(str(error))

    if failures:
        for failure in failures:
            print(f"::error::idp signing KEK isolation: {failure}", file=sys.stderr)
        return 1
    print(f"idp signing KEK isolation: static OK ({len(overlays)} rendered target(s))")
    return 0
