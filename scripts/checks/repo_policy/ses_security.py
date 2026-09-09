from .shared import *
from .kubernetes import documents, resource_name, top_level_field


def check_ses_sender_isolation(_: argparse.Namespace) -> int:
    """Keep each transactional sender on its own narrow SES projection."""

    ses_env = ["CODEWIRE_SES_ENABLED", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"]
    hardening_env = {
        "AWS_EC2_METADATA_DISABLED": "true",
        "AWS_IGNORE_CONFIGURED_ENDPOINT_URLS": "true",
    }
    overlays = [
        ("deployments/k8s/overlays/dev", True),
        ("deployments/k8s/overlays/production", True),
        ("deployments/k8s/overlays/local-kind", False),
        ("deployments/k8s/overlays/local-kind-static", False),
    ]
    failures: list[str] = []

    def fail(message: str) -> None:
        failures.append(message)

    def find_deployment(resources: list[str], name: str, label: str) -> str | None:
        matches = [
            resource
            for resource in resources
            if top_level_field(resource, "kind") == "Deployment" and resource_name(resource) == name
        ]
        if len(matches) != 1:
            fail(f"{label}: expected exactly one Deployment/{name}, found {len(matches)}")
            return None
        return matches[0]

    def env_entry(document: str, name: str) -> str | None:
        expression = re.compile(
            rf"^        - name: {re.escape(name)}\s*$([\s\S]*?)(?=^        - name:|^        envFrom:)",
            re.MULTILINE,
        )
        matches = expression.findall(document)
        if len(matches) != 1:
            return None
        return matches[0]

    def assert_generation(document: str, label: str, workload: str) -> None:
        if not re.search(
            r'^        codewire\.sh/ses-credential-generation: ["\']?[1-9][0-9]*["\']?$',
            document,
            re.MULTILINE,
        ):
            fail(f"{label}: {workload} must carry a positive SES credential generation")

    def assert_hardening(document: str, label: str, workload: str) -> None:
        for name, value in hardening_env.items():
            entry = env_entry(document, name)
            if entry is None or not re.search(
                rf"^          value: [\"']?{re.escape(value)}[\"']?$", entry, re.MULTILINE
            ):
                fail(f"{label}: {workload} must explicitly set {name}={value}")

    def assert_sender_secret(
        document: str,
        label: str,
        workload: str,
        expected_secret: str,
        other_secret: str,
    ) -> None:
        if other_secret in document:
            fail(f"{label}: {workload} must not reference {other_secret}")
        if document.count(expected_secret) != len(ses_env):
            fail(
                f"{label}: {workload} must reference {expected_secret} exactly once for each SES input"
            )
        if re.search(rf"secretRef:\s*\n\s+name: {re.escape(expected_secret)}\s*$", document):
            fail(f"{label}: {workload} must not import {expected_secret} through envFrom")
        for name in ses_env:
            entry = env_entry(document, name)
            if entry is None:
                fail(f"{label}: {workload} must explicitly project {name}")
                continue
            expected = (
                rf"^          valueFrom:\s*\n"
                rf"            secretKeyRef:\s*\n"
                rf"              key: {re.escape(name)}\s*\n"
                rf"              name: {re.escape(expected_secret)}\s*\n"
                rf"              optional: false\s*$"
            )
            if not re.search(expected, entry, re.MULTILINE):
                fail(
                    f"{label}: {workload} must require {name} from only {expected_secret}"
                )

    try:
        for path, active in overlays:
            label = f"{path} (rendered)"
            resources = documents(run(["kustomize", "build", path]).stdout)
            idp = find_deployment(resources, "codewire-idp", label)
            billing = find_deployment(resources, "codewire-billing", label)
            if idp is None or billing is None:
                continue

            assert_generation(idp, label, "codewire-idp")
            assert_generation(billing, label, "codewire-billing")
            if active:
                assert_hardening(idp, label, "codewire-idp")
                assert_hardening(billing, label, "codewire-billing")
                assert_sender_secret(
                    idp,
                    label,
                    "codewire-idp",
                    "codewire-idp-ses",
                    "codewire-billing-ses",
                )
                assert_sender_secret(
                    billing,
                    label,
                    "codewire-billing",
                    "codewire-billing-ses",
                    "codewire-idp-ses",
                )
                for resource in resources:
                    if top_level_field(resource, "kind") != "ConfigMap":
                        continue
                    for name in ses_env:
                        if name in resource:
                            fail(f"{label}: ConfigMap {resource_name(resource)} leaks {name}")
            else:
                for secret in ["codewire-idp-ses", "codewire-billing-ses"]:
                    if secret in idp or secret in billing:
                        fail(f"{label}: local Kind must not require live SES Secret {secret}")
                config_maps = [
                    resource
                    for resource in resources
                    if top_level_field(resource, "kind") == "ConfigMap"
                    and (resource_name(resource) or "").startswith("codewire-config-")
                ]
                if len(config_maps) != 1:
                    fail(f"{label}: expected one local codewire-config ConfigMap")
                else:
                    for name in ["CODEWIRE_SES_FROM", "CODEWIRE_SES_REGION"]:
                        if not re.search(rf"^  {name}: \"\"$", config_maps[0], re.MULTILINE):
                            fail(f"{label}: local Kind must leave {name} empty")

            for resource in resources:
                if top_level_field(resource, "kind") != "Deployment":
                    continue
                name = resource_name(resource)
                if name in {"codewire-idp", "codewire-billing"}:
                    continue
                for secret in ["codewire-idp-ses", "codewire-billing-ses"]:
                    if secret in resource:
                        fail(f"{label}: unrelated Deployment/{name} inherits {secret}")
    except Exception as error:  # noqa: BLE001 - repository policy boundary
        fail(str(error))

    if failures:
        for failure in failures:
            print(f"::error::ses email isolation: {failure}", file=sys.stderr)
        return 1
    print(f"ses email isolation: static OK ({len(overlays)} rendered target(s))")
    return 0
