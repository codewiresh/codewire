"""Identity-free workspace template guard (Program #2238 B2, invariant 1).

A hosted commodity workspace Pod carries no environment identity: no daemon
token, environment ID, operation generation, projection digest, managed-client
selection or derived client variables; no Codex ConfigMap or init-container
copy; no environment label on its SandboxTemplate; and no template egress to
the environment's own gateway. It carries only the Pod-bound
workspace-binding token (workspace container only), the binding URL and its
own UID from the downward API, plus exactly one new egress rule to the binding
listener.

The orchestration renderer's golden fixtures are the reviewed rendering; the
Rust test pins renderer == fixture, and this guard pins the fixture against
the invariant, so neither can drift alone.
"""

from __future__ import annotations

import copy
import json
from typing import Any

from .shared import ROOT, argparse

FIXTURES = [
    "crates/codewire-orchestration/tests/fixtures/sandbox/identity-free-sandboxtemplate.golden.json",
    "crates/codewire-orchestration/tests/fixtures/sandbox/identity-free-sandboxtemplate-runc.golden.json",
]

FORBIDDEN_ENVIRONMENT = {
    "CODEWIRE_DAEMON_AUTH_TOKEN",
    "CODEWIRE_ENVIRONMENT_ID",
    "CODEWIRE_ENVIRONMENT_OPERATION_GENERATION",
    "CODEWIRE_ENVIRONMENT_PROJECTION_SHA256",
    "CODEWIRE_MANAGED_CREDENTIAL_CLIENTS",
    "OPENAI_BASE_URL",
    "OPENAI_API_KEY",
    "ANTHROPIC_BASE_URL",
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "CODEX_HOME",
    "CODEX_CA_CERTIFICATE",
    "SSH_AUTH_SOCK",
    "GIT_ASKPASS",
}
FORBIDDEN_TEXT = (
    "credential-codex-config",
    "cw-credential-codex-",
    "codex-bootstrap",
    "codewire-client-bootstrap",
)
BINDING_VOLUME = "workspace-binding-identity"
BINDING_AUDIENCE = "codewire.internal.workspace-binding.v1"
BINDING_MOUNT = "/var/run/secrets/codewire/workspace-binding"
ENVIRONMENT_LABEL = "codewire.sh/environment-id"


def containers(spec: dict[str, Any]) -> list[dict[str, Any]]:
    return list(spec.get("containers") or []) + list(spec.get("initContainers") or [])


def violations(template: dict[str, Any], label: str) -> list[str]:
    output: list[str] = []
    text = json.dumps(template, sort_keys=True)
    for fragment in FORBIDDEN_TEXT:
        if fragment in text:
            output.append(f"{label}: carries {fragment}")
    if ENVIRONMENT_LABEL in text:
        output.append(f"{label}: carries the environment label")
    spec = ((template.get("spec") or {}).get("podTemplate") or {}).get("spec") or {}
    for container in containers(spec):
        for entry in container.get("env") or []:
            if entry.get("name") in FORBIDDEN_ENVIRONMENT:
                output.append(f"{label}: container {container.get('name')} renders {entry.get('name')}")
        for entry in container.get("envFrom") or []:
            output.append(f"{label}: container {container.get('name')} imports an environment source")
        mounts_token = any(mount.get("name") == BINDING_VOLUME for mount in container.get("volumeMounts") or [])
        if mounts_token != (container.get("name") == "workspace"):
            output.append(f"{label}: binding token mount is not exactly the workspace container's")
    if spec.get("automountServiceAccountToken") is not False:
        output.append(f"{label}: automounts a Kubernetes API token")
    volumes = [volume for volume in spec.get("volumes") or [] if volume.get("name") == BINDING_VOLUME]
    expected_volume = {
        "name": BINDING_VOLUME,
        "projected": {
            "defaultMode": 0o440,
            "sources": [{"serviceAccountToken": {"audience": BINDING_AUDIENCE, "expirationSeconds": 600, "path": "token"}}],
        },
    }
    if volumes != [expected_volume]:
        output.append(f"{label}: binding token volume is not exactly the workspace-binding audience")
    for volume in spec.get("volumes") or []:
        if "configMap" in volume and volume.get("name") != "credential-gateway-roots":
            output.append(f"{label}: mounts ConfigMap volume {volume.get('name')}")
        if "secret" in volume:
            output.append(f"{label}: mounts Secret volume {volume.get('name')}")
    workspace = next((container for container in spec.get("containers") or [] if container.get("name") == "workspace"), {})
    env = {entry.get("name"): entry for entry in workspace.get("env") or []}
    if env.get("CODEWIRE_POD_UID") != {"name": "CODEWIRE_POD_UID", "valueFrom": {"fieldRef": {"fieldPath": "metadata.uid"}}}:
        output.append(f"{label}: workspace UID is not from the downward API")
    if not str((env.get("CODEWIRE_WORKSPACE_BINDING_URL") or {}).get("value", "")).endswith(":8087"):
        output.append(f"{label}: workspace has no binding listener URL")
    if not any(mount.get("name") == BINDING_VOLUME and mount.get("mountPath") == BINDING_MOUNT and mount.get("readOnly") is True
               for mount in workspace.get("volumeMounts") or []):
        output.append(f"{label}: binding token is not mounted read-only at {BINDING_MOUNT}")
    if "test -f /codewire/run/daemon/ready" not in json.dumps(workspace.get("readinessProbe") or {}):
        output.append(f"{label}: workspace readiness is not the daemon's local marker")
    egress = ((template.get("spec") or {}).get("networkPolicy") or {}).get("egress") or []
    if any(port.get("port") == 8443 for rule in egress for port in rule.get("ports") or []):
        output.append(f"{label}: template egress reaches the environment's gateway")
    binding_rules = [rule for rule in egress if any(port.get("port") == 8087 for port in rule.get("ports") or [])]
    if len(binding_rules) != 1 or binding_rules[0].get("ports") != [{"port": 8087, "protocol": "TCP"}] or not all(
        (peer.get("podSelector") or {}).get("matchLabels") == {"app.kubernetes.io/component": "orchestration"}
        and "namespaceSelector" in peer
        for peer in binding_rules[0].get("to") or [{}]
    ):
        output.append(f"{label}: template egress is not exactly one TCP 8087 rule to orchestration")
    return output


def self_test(base: dict[str, Any]) -> None:
    def rejected(name: str, mutate: Any) -> None:
        fixture = copy.deepcopy(base)
        mutate(fixture)
        if not violations(fixture, f"negative fixture {name}"):
            raise RuntimeError(f"negative fixture {name} was accepted")

    def workspace(fixture: dict[str, Any]) -> dict[str, Any]:
        return next(c for c in fixture["spec"]["podTemplate"]["spec"]["containers"] if c["name"] == "workspace")

    for name in sorted(FORBIDDEN_ENVIRONMENT):
        rejected(f"env {name}", lambda f, name=name: workspace(f)["env"].append({"name": name, "value": "x"}))
    rejected("environment label", lambda f: f["metadata"].__setitem__("labels", {ENVIRONMENT_LABEL: "env"}))
    rejected("codex ConfigMap", lambda f: f["spec"]["podTemplate"]["spec"]["volumes"].append(
        {"name": "credential-codex-config", "configMap": {"name": "cw-credential-codex-env"}}))
    rejected("client bootstrap init", lambda f: f["spec"]["podTemplate"]["spec"].__setitem__(
        "initContainers", [{"name": "codewire-client-bootstrap", "command": ["sh", "-c", "cp /codewire/codex-bootstrap/config.toml x"]}]))
    rejected("token in DinD", lambda f: next(c for c in f["spec"]["podTemplate"]["spec"]["containers"] if c["name"] == "dind")[
        "volumeMounts"].append({"name": BINDING_VOLUME, "mountPath": BINDING_MOUNT, "readOnly": True}))
    rejected("wrong audience", lambda f: next(v for v in f["spec"]["podTemplate"]["spec"]["volumes"] if v["name"] == BINDING_VOLUME)[
        "projected"]["sources"][0]["serviceAccountToken"].__setitem__("audience", "codewire.internal.gateway-binding.v1"))
    rejected("API token automount", lambda f: f["spec"]["podTemplate"]["spec"].__setitem__("automountServiceAccountToken", True))
    rejected("caller-chosen UID", lambda f: workspace(f)["env"].__setitem__(
        next(i for i, e in enumerate(workspace(f)["env"]) if e["name"] == "CODEWIRE_POD_UID"), {"name": "CODEWIRE_POD_UID", "value": "x"}))
    rejected("readiness on binding", lambda f: workspace(f).__setitem__("readinessProbe", {"exec": {"command": ["true"]}}))
    rejected("gateway egress", lambda f: f["spec"]["networkPolicy"]["egress"].append(
        {"to": [{"podSelector": {"matchLabels": {"codewire.sh/type": "gateway"}}}], "ports": [{"protocol": "TCP", "port": 8443}]}))
    rejected("second binding egress", lambda f: f["spec"]["networkPolicy"]["egress"].append(
        {"to": [{"ipBlock": {"cidr": "10.0.0.0/8"}}], "ports": [{"protocol": "TCP", "port": 8087}]}))
    rejected("Secret volume", lambda f: f["spec"]["podTemplate"]["spec"]["volumes"].append({"name": "env", "secret": {"secretName": "env"}}))


def check_identity_free_workspace(args: argparse.Namespace) -> int:
    failures: list[str] = []
    base = None
    for rel in FIXTURES:
        try:
            template = json.loads((ROOT / rel).read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            failures.append(f"{rel}: unreadable ({error})")
            continue
        base = base or template
        failures.extend(violations(template, rel))
    if args.self_test and base is not None:
        try:
            self_test(base)
        except RuntimeError as error:
            failures.append(str(error))
    for failure in failures:
        print(f"::error::identity-free workspace: {failure}")
    if failures:
        return 1
    print(f"identity-free workspace: OK ({len(FIXTURES)} fixture(s){', self-test' if args.self_test else ''})")
    return 0
