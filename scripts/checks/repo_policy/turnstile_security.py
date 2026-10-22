from .shared import *
from .kubernetes import documents, resource_name, top_level_field


TURNSTILE_OVERLAYS = (
    ("deployments/k8s/overlays/dev", "dev"),
    ("deployments/k8s/overlays/production", "production"),
    ("deployments/k8s/overlays/local-kind", "local"),
    ("deployments/k8s/overlays/local-kind-static", "local"),
)


def turnstile_access_projection_failures(render: Callable[[str], str]) -> list[str]:
    """Keep the public widget key separate from the IdP-only verifier secret.

    RENDER returns the kustomize output for an overlay path.
    """

    site_key = "TURNSTILE_SITE_KEY"
    secret_key = "TURNSTILE_SECRET_KEY"
    bypass_email = "IDP_TURNSTILE_BYPASS_EMAIL"
    public_config = "codewire-dashboard-public-config"
    verifier_secret = "codewire-idp-turnstile"
    dev_site_key = "0x4AAAAAAE2ghrxixpYKpljB"
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

    def deployment(resources: list[str], name: str, label: str) -> str | None:
        matches = [
            resource
            for resource in resources
            if top_level_field(resource, "kind") == "Deployment"
            and resource_name(resource) == name
        ]
        if len(matches) != 1:
            fail(f"{label}: expected exactly one Deployment/{name}, found {len(matches)}")
            return None
        return matches[0]

    def assert_public_key_projection(document: str, label: str) -> None:
        for private_name in (secret_key, bypass_email):
            if re.search(
                rf"^        - name: {re.escape(private_name)}\s*$", document, re.MULTILINE
            ):
                fail(f"{label}: dashboard must never receive {private_name}")
        entry = env_entry(document, site_key)
        if entry is None:
            fail(f"{label}: dashboard must project {site_key} exactly once")
            return
        expected = (
            r"^          valueFrom:[ \t]*\n"
            r"            configMapKeyRef:[ \t]*\n"
            r"              key: TURNSTILE_SITE_KEY[ \t]*\n"
            r"              name: codewire-dashboard-public-config(?:-[a-z0-9]{10})?[ \t]*\n"
            r"              optional: true[ \t]*\n?\Z"
        )
        if not re.search(expected, entry, re.MULTILINE):
            fail(f"{label}: dashboard must optionally read {site_key} from only {public_config}")
        if secret_key in entry:
            fail(f"{label}: dashboard must never receive {secret_key}")

    def assert_github_public_projection(resources: list[str], document: str | None, label: str, mode: str) -> None:
        # Browser authorization needs public identifiers, never the App secret or
        # the credential-service's secret-bearing authorization configuration.
        if document is not None:
            for name in ("GITHUB_APP_SLUG", "GITHUB_APP_CLIENT_ID"):
                entry = env_entry(document, name)
                expected = (
                    r"^          valueFrom:[ \t]*\n"
                    r"            configMapKeyRef:[ \t]*\n"
                    rf"              key: {name}[ \t]*\n"
                    r"              name: codewire-dashboard-public-config(?:-[a-z0-9]{10})?[ \t]*\n"
                    r"              optional: true[ \t]*\n?\Z"
                )
                if entry is None or not re.search(expected, entry, re.MULTILINE):
                    fail(f"{label}: dashboard must optionally read {name} exactly once from only {public_config}")
            if re.search(r"^        - name: (?:CREDENTIAL_GITHUB_APP_|GITHUB_APP_(?:CLIENT_SECRET|PRIVATE_KEY))", document, re.MULTILINE):
                fail(f"{label}: dashboard must never receive private GitHub App configuration")
            if re.search(r"\bcodewire-github-app-authorization\b", document):
                fail(f"{label}: dashboard must never receive the GitHub App authorization Secret")
        configs = [
            resource for resource in resources
            if top_level_field(resource, "kind") == "ConfigMap"
            and re.fullmatch(r"codewire-dashboard-public-config(?:-[a-z0-9]{10})?", resource_name(resource) or "")
        ]
        if len(configs) != 1:
            fail(f"{label}: expected one GitHub dashboard public ConfigMap")
        else:
            data = re.search(r"^data:\n([\s\S]*?)(?=^[A-Za-z]|\Z)", configs[0], re.MULTILINE)
            entries = re.findall(r"^  ([A-Za-z0-9_]+): (.*)$", data.group(1) if data else "", re.MULTILINE)
            if sorted(key for key, _ in entries) != sorted((site_key, "GITHUB_APP_SLUG", "GITHUB_APP_CLIENT_ID")):
                fail(f"{label}: GitHub dashboard public ConfigMap must contain only the three public identifiers")
            values = dict(entries)
            client_id = values.get("GITHUB_APP_CLIENT_ID", "")
            slug = values.get("GITHUB_APP_SLUG", "")
            if mode == "local":
                if client_id != "Iv1.kindsynthetic" or slug != "codewire-synthetic":
                    fail(f"{label}: GitHub dashboard App identifiers must use fixed synthetic Kind values")
            elif not re.fullmatch(r'(?:"[A-Za-z0-9.]{0,100}"|[A-Za-z0-9.]{1,100})', client_id) or not re.fullmatch(r'(?:"[A-Za-z0-9-]{0,100}"|[A-Za-z0-9-]{1,100})', slug):
                fail(f"{label}: GitHub dashboard App identifiers must be empty or bounded public metadata")
        for resource in resources:
            if top_level_field(resource, "kind") == "Deployment" and resource_name(resource) != "codewire-dashboard":
                if re.search(r"^        - name: GITHUB_APP_(?:SLUG|CLIENT_ID)\s*$", resource, re.MULTILINE) or public_config in resource:
                    fail(f"{label}: unrelated Deployment/{resource_name(resource)} inherits the GitHub dashboard public projection")
            if top_level_field(resource, "kind") == "ConfigMap" and (resource_name(resource) or "").startswith("codewire-config-"):
                if re.search(r"^  GITHUB_APP_(?:SLUG|CLIENT_ID):", resource, re.MULTILINE):
                    fail(f"{label}: shared codewire-config must not contain GitHub dashboard App identifiers")

    def assert_idp_projection(document: str, label: str, mode: str) -> None:
        if site_key in document or public_config in document:
            fail(f"{label}: IdP must never receive the public Turnstile projection")
        secret_entry = env_entry(document, secret_key)
        frontend_entry = env_entry(document, "FRONTEND_URL")
        bypass_entry = env_entry(document, bypass_email)
        expected_bypass = {
            "dev": "hello@codewire.sh",
            "local": "codewire-e2e@example.test",
        }.get(mode)
        if expected_bypass is None:
            if bypass_entry is not None or bypass_email in document:
                fail(f"{label}: production IdP must not receive the Turnstile bypass email")
        elif bypass_entry is None or not re.search(
            rf"^          value: {re.escape(expected_bypass)}[ \t]*\n?\Z",
            bypass_entry,
            re.MULTILINE,
        ):
            fail(f"{label}: IdP must bind the Turnstile bypass to {expected_bypass}")

        if mode != "dev":
            if secret_entry is not None or secret_key in document or verifier_secret in document:
                fail(f"{label}: inactive IdP must not receive the Turnstile verifier Secret")
            return
        expected_secret = (
            r"^          valueFrom:[ \t]*\n"
            r"            secretKeyRef:[ \t]*\n"
            r"              key: TURNSTILE_SECRET_KEY[ \t]*\n"
            r"              name: codewire-idp-turnstile[ \t]*\n?\Z"
        )
        if secret_entry is None or not re.search(expected_secret, secret_entry, re.MULTILINE):
            fail(f"{label}: IdP must require only {secret_key} from {verifier_secret}")
        if document.count(secret_key) != 2 or document.count(verifier_secret) != 1:
            fail(f"{label}: IdP must contain exactly one bounded Turnstile verifier projection")
        if frontend_entry is None or not re.search(
            r"^          value: https://codewire-dev\.sh[ \t]*\n?\Z",
            frontend_entry,
            re.MULTILINE,
        ):
            fail(f"{label}: IdP must bind Turnstile verification to https://codewire-dev.sh")

    try:
        config_source = read_text("deployments/k8s/base/config.env")
        if re.search(
            r"^(?:TURNSTILE_(?:SITE|SECRET)_KEY|IDP_TURNSTILE_BYPASS_EMAIL)=",
            config_source,
            re.MULTILINE,
        ):
            fail("shared codewire-config source must not contain a Turnstile value")

        for path, mode in TURNSTILE_OVERLAYS:
            label = f"{path} (rendered)"
            resources = documents(render(path))
            rendered_dashboard = deployment(resources, "codewire-dashboard", label)
            rendered_idp = deployment(resources, "codewire-idp", label)
            if rendered_dashboard is not None:
                assert_public_key_projection(rendered_dashboard, label)
            assert_github_public_projection(resources, rendered_dashboard, label, mode)
            if rendered_idp is not None:
                assert_idp_projection(rendered_idp, label, mode)

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
                expected_value = dev_site_key if mode == "dev" else '""'
                if not re.search(
                    rf"^  TURNSTILE_SITE_KEY: {re.escape(expected_value)}$",
                    config_map,
                    re.MULTILINE,
                ):
                    state = "the hostname-bound Dev key" if mode == "dev" else "an empty value"
                    fail(f"{label}: generated {public_config} must contain {state}")
                if re.search(r"^  TURNSTILE_SECRET_KEY:", config_map, re.MULTILINE):
                    fail(f"{label}: generated {public_config} must never contain {secret_key}")

            shared_config_maps = [
                resource
                for resource in resources
                if top_level_field(resource, "kind") == "ConfigMap"
                and (resource_name(resource) or "").startswith("codewire-config-")
            ]
            if len(shared_config_maps) != 1:
                fail(f"{label}: expected one generated shared codewire-config ConfigMap")
            elif any(
                marker in shared_config_maps[0]
                for marker in (site_key, secret_key, bypass_email)
            ):
                fail(f"{label}: shared codewire-config must not contain a Turnstile value")

            for resource in resources:
                if top_level_field(resource, "kind") != "Deployment":
                    continue
                name = resource_name(resource) or "<unnamed>"
                if name == "codewire-dashboard":
                    if verifier_secret in resource:
                        fail(f"{label}: dashboard must never receive {verifier_secret}")
                    continue
                if name == "codewire-idp":
                    continue
                if any(
                    marker in resource
                    for marker in (
                        public_config,
                        site_key,
                        secret_key,
                        verifier_secret,
                        bypass_email,
                    )
                ):
                    fail(f"{label}: unrelated Deployment/{name} inherits a Turnstile projection")
        # The managed E2E topology uses the same dashboard deployment but a
        # non-generated public ConfigMap. Keep its synthetic App contract bound.
        path = "tests/e2e/kind"
        resources = documents(render(path))
        label = f"{path} (rendered)"
        assert_github_public_projection(resources, deployment(resources, "codewire-dashboard", label), label, "local")
    except Exception as error:  # noqa: BLE001 - repository policy boundary
        fail(str(error))
    return failures


# The managed E2E topology is rendered too, for its GitHub App contract only.
TURNSTILE_RENDERED_TARGETS = (
    *(path for path, _ in TURNSTILE_OVERLAYS),
    "tests/e2e/kind",
)


def check_turnstile_access_projection(args: argparse.Namespace) -> int:
    rendered: dict[str, str] = {}

    def render(path: str) -> str:
        if path not in rendered:
            rendered[path] = run(["kustomize", "build", path]).stdout
        return rendered[path]

    failures = turnstile_access_projection_failures(render)
    if not failures and getattr(args, "self_test", False):
        failures = [
            f"self-test: {failure}"
            for failure in turnstile_access_projection_self_test(rendered)
        ]
    if failures:
        for failure in failures:
            print(f"::error::turnstile access projection: {failure}", file=sys.stderr)
        return 1
    suffix = "; negative fixtures rejected" if getattr(args, "self_test", False) else ""
    print(f"turnstile access projection: static OK ({len(TURNSTILE_OVERLAYS)} rendered target(s)){suffix}")
    return 0


def turnstile_access_projection_self_test(rendered: dict[str, str]) -> list[str]:
    """Each mutation of the passing renders must be rejected with its reason."""

    problems: list[str] = []
    if sorted(rendered) != sorted(TURNSTILE_RENDERED_TARGETS):
        return [f"rendered targets are {sorted(rendered)}"]

    def assert_rejected(
        label: str,
        overlay: str,
        old: str,
        new: str,
        expected: str,
        *,
        deployment_name: str | None = None,
    ) -> None:
        fixture = dict(rendered)
        target = fixture[overlay]
        if deployment_name is not None:
            matches = [
                document for document in documents(target)
                if top_level_field(document, "kind") == "Deployment"
                and resource_name(document) == deployment_name
            ]
            if len(matches) != 1:
                problems.append(f"{label}: fixture deployment target is not unique")
                return
            target = matches[0]
        if target.count(old) != 1 or fixture[overlay].count(target) != 1:
            problems.append(f"{label}: fixture mutation target is not unique")
            return
        fixture[overlay] = fixture[overlay].replace(target, target.replace(old, new))
        if deployment_name is not None:
            original_others = [
                document for document in documents(rendered[overlay]) if document != target
            ]
            changed_others = [
                document for document in documents(fixture[overlay])
                if not (top_level_field(document, "kind") == "Deployment"
                        and resource_name(document) == deployment_name)
            ]
            if changed_others != original_others:
                problems.append(f"{label}: mutation changed unrelated resources")
                return
        failures = turnstile_access_projection_failures(lambda path: fixture[path])
        if not any(expected in failure for failure in failures):
            problems.append(
                f"{label}: expected a rejection containing {expected!r}; got {failures!r}"
            )

    dev = "deployments/k8s/overlays/dev"
    production = "deployments/k8s/overlays/production"
    assert_rejected(
        "missing-dev-widget-key",
        dev,
        "  TURNSTILE_SITE_KEY: 0x4AAAAAAE2ghrxixpYKpljB\n",
        '  TURNSTILE_SITE_KEY: ""\n',
        "hostname-bound Dev key",
    )
    assert_rejected(
        "wrong-idp-secret",
        dev,
        "              name: codewire-idp-turnstile\n",
        "              name: codewire-idp-turnstile-wrong\n",
        "IdP must require only TURNSTILE_SECRET_KEY",
    )
    assert_rejected(
        "optional-idp-secret",
        dev,
        "              name: codewire-idp-turnstile\n",
        "              name: codewire-idp-turnstile\n              optional: true\n",
        "IdP must require only TURNSTILE_SECRET_KEY",
    )
    assert_rejected(
        "wrong-idp-hostname",
        dev,
        "        - name: FRONTEND_URL\n          value: https://codewire-dev.sh\n",
        "        - name: FRONTEND_URL\n          value: https://wrong.invalid\n",
        "bind Turnstile verification to https://codewire-dev.sh",
        deployment_name="codewire-idp",
    )
    assert_rejected(
        "active-production-widget",
        production,
        '  TURNSTILE_SITE_KEY: ""\n',
        "  TURNSTILE_SITE_KEY: 0x4AAAAAAE2ghrxixpYKpljB\n",
        "must contain an empty value",
    )
    assert_rejected(
        "production-bypass-email",
        production,
        '        - name: IDP_PORT\n          value: "8091"\n',
        "        - name: IDP_TURNSTILE_BYPASS_EMAIL\n"
        "          value: hello@codewire.sh\n"
        '        - name: IDP_PORT\n          value: "8091"\n',
        "production IdP must not receive the Turnstile bypass email",
    )

    for overlay in TURNSTILE_RENDERED_TARGETS:
        dashboards = [
            document for document in documents(rendered[overlay])
            if top_level_field(document, "kind") == "Deployment"
            and resource_name(document) == "codewire-dashboard"
        ]
        match = re.search(
            r"^        - name: GITHUB_APP_CLIENT_ID\n"
            r"          valueFrom:\n"
            r"            configMapKeyRef:\n"
            r"              key: GITHUB_APP_CLIENT_ID\n"
            r"              name: [^\n]+\n"
            r"              optional: true\n",
            dashboards[0] if dashboards else "", re.MULTILINE,
        )
        if match is None:
            problems.append(f"{overlay}: missing public GitHub client-ID fixture")
            continue
        entry = match.group(0)
        for label, changed in (
            ("missing", ""),
            ("duplicate", entry + entry),
            ("secret-source", entry.replace("configMapKeyRef", "secretKeyRef")),
            ("required", entry.replace("optional: true", "optional: false")),
            ("wrong-key", entry.replace("key: GITHUB_APP_CLIENT_ID", "key: client-secret")),
            ("wrong-config-map", re.sub(r"name: codewire-dashboard-public-config[^\n]*", "name: codewire-config", entry)),
        ):
            assert_rejected(
                f"{overlay}-github-{label}", overlay, entry, changed,
                "dashboard must optionally read GITHUB_APP_CLIENT_ID exactly once",
                deployment_name="codewire-dashboard",
            )
        assert_rejected(
            f"{overlay}-github-private-env", overlay, entry,
            entry + "        - name: GITHUB_APP_CLIENT_SECRET\n          value: synthetic-forbidden\n",
            "dashboard must never receive private GitHub App configuration",
            deployment_name="codewire-dashboard",
        )
        assert_rejected(
            f"{overlay}-github-authorization-secret-dashboard", overlay, entry,
            entry + '        - name: FORBIDDEN_APP_CONFIG\n          valueFrom:\n'
            '            secretKeyRef:\n              name: codewire-github-app-authorization\n'
            '              key: client-secret\n',
            "dashboard must never receive the GitHub App authorization Secret",
            deployment_name="codewire-dashboard",
        )
        public_configs = [
            document for document in documents(rendered[overlay])
            if top_level_field(document, "kind") == "ConfigMap"
            and (resource_name(document) or "").startswith("codewire-dashboard-public-config")
        ]
        id_lines = [
            line + "\n" for line in (public_configs[0] if public_configs else "").splitlines()
            if line.startswith("  GITHUB_APP_CLIENT_ID:")
        ]
        if not id_lines:
            problems.append(f"{overlay}: missing public GitHub client-ID ConfigMap entry")
            continue
        id_line = id_lines[0]
        assert_rejected(
            f"{overlay}-github-private-config", overlay, id_line,
            id_line + "  GITHUB_APP_CLIENT_SECRET: synthetic-forbidden\n",
            "public ConfigMap must contain only the three public identifiers",
        )
        assert_rejected(
            f"{overlay}-github-invalid-id", overlay, id_line,
            '  GITHUB_APP_CLIENT_ID: "https://invalid.example/private?value=x"\n',
            "GitHub dashboard App identifiers must",
        )
    return problems
