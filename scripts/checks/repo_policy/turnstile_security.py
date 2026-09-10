from .shared import *
from .kubernetes import documents, resource_name, top_level_field


def check_turnstile_access_projection(_: argparse.Namespace) -> int:
    """Keep the public widget key separate from the IdP-only verifier secret."""

    site_key = "TURNSTILE_SITE_KEY"
    secret_key = "TURNSTILE_SECRET_KEY"
    public_config = "codewire-dashboard-public-config"
    overlays = [
        ("deployments/k8s/overlays/dev", False),
        ("deployments/k8s/overlays/production", False),
        ("deployments/k8s/overlays/local-kind", True),
        ("deployments/k8s/overlays/local-kind-static", True),
    ]
    failures: list[str] = []

    def fail(message: str) -> None:
        failures.append(message)

    def env_entry(document: str, name: str) -> str | None:
        expression = re.compile(
            rf"^        - name: {re.escape(name)}\s*$([\s\S]*?)"
            r"(?=^        - name:|^        [A-Za-z][A-Za-z0-9_-]*:|\Z)",
            re.MULTILINE,
        )
        matches = expression.findall(document)
        return matches[0] if len(matches) == 1 else None

    def dashboard(resources: list[str], label: str) -> str | None:
        matches = [
            resource
            for resource in resources
            if top_level_field(resource, "kind") == "Deployment"
            and resource_name(resource) == "codewire-dashboard"
        ]
        if len(matches) != 1:
            fail(f"{label}: expected exactly one Deployment/codewire-dashboard, found {len(matches)}")
            return None
        return matches[0]

    def assert_public_key_projection(document: str, label: str) -> None:
        if re.search(rf"^        - name: {re.escape(secret_key)}\s*$", document, re.MULTILINE):
            fail(f"{label}: dashboard must never receive {secret_key}")
        entry = env_entry(document, site_key)
        if entry is None:
            fail(f"{label}: dashboard must project {site_key} exactly once")
            return
        expected = (
            r"^          valueFrom:\s*\n"
            r"            configMapKeyRef:\s*\n"
            r"              key: TURNSTILE_SITE_KEY\s*\n"
            r"              name: codewire-dashboard-public-config(?:-[a-z0-9]{10})?\s*\n"
            r"              optional: true\s*$"
        )
        if not re.search(expected, entry, re.MULTILINE):
            fail(f"{label}: dashboard must optionally read {site_key} from only {public_config}")
        if secret_key in entry:
            fail(f"{label}: dashboard must never receive {secret_key}")

    try:
        config_source = read_text("deployments/k8s/base/config.env")
        if re.search(r"^TURNSTILE_(?:SITE|SECRET)_KEY=", config_source, re.MULTILINE):
            fail("shared codewire-config source must not contain either Turnstile value")

        for path, local in overlays:
            label = f"{path} (rendered)"
            resources = documents(run(["kustomize", "build", path]).stdout)
            rendered_dashboard = dashboard(resources, label)
            if rendered_dashboard is not None:
                assert_public_key_projection(rendered_dashboard, label)

            config_maps = [
                resource
                for resource in resources
                if top_level_field(resource, "kind") == "ConfigMap"
                and (resource_name(resource) or "").startswith(f"{public_config}-")
            ]
            if len(config_maps) != 1:
                fail(f"{label}: expected one generated {public_config} ConfigMap, found {len(config_maps)}")
            else:
                config_map = config_maps[0]
                if not re.search(r"^  TURNSTILE_SITE_KEY: .*?$", config_map, re.MULTILINE):
                    fail(f"{label}: generated {public_config} must contain {site_key}")
                if re.search(r"^  TURNSTILE_SECRET_KEY:", config_map, re.MULTILINE):
                    fail(f"{label}: generated {public_config} must never contain {secret_key}")
                if local and not re.search(r'^  TURNSTILE_SITE_KEY: ""$', config_map, re.MULTILINE):
                    fail(f"{label}: local Kind must leave {site_key} empty")

            shared_config_maps = [
                resource
                for resource in resources
                if top_level_field(resource, "kind") == "ConfigMap"
                and (resource_name(resource) or "").startswith("codewire-config-")
            ]
            if len(shared_config_maps) != 1:
                fail(f"{label}: expected one generated shared codewire-config ConfigMap")
            elif site_key in shared_config_maps[0] or secret_key in shared_config_maps[0]:
                fail(f"{label}: shared codewire-config must not contain a Turnstile value")

            for resource in resources:
                if top_level_field(resource, "kind") != "Deployment":
                    continue
                name = resource_name(resource) or "<unnamed>"
                if name == "codewire-dashboard":
                    continue
                if public_config in resource or site_key in resource:
                    fail(f"{label}: unrelated Deployment/{name} inherits the Turnstile public projection")
    except Exception as error:  # noqa: BLE001 - repository policy boundary
        fail(str(error))

    if failures:
        for failure in failures:
            print(f"::error::turnstile access projection: {failure}", file=sys.stderr)
        return 1
    print(f"turnstile access projection: static OK ({len(overlays)} rendered target(s))")
    return 0
