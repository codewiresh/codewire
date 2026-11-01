"""Identity-free workspace template guard (Program #2238 B2, invariant 1).

A hosted commodity workspace Pod carries no environment identity: no daemon
token, environment ID, operation generation, projection digest, managed-client
selection or derived client variables; no Codex ConfigMap or init-container
copy; no environment label on its SandboxTemplate; and no template egress to
any per-environment gateway. It carries only the Pod-bound
workspace-binding token (workspace container only), the https binding URL and
its own UID from the downward API, plus exactly one new egress rule to the
binding listener. Its one ConfigMap volume is the exact exception of
daemon-hosted access Q6: the single public key `ca.crt` of
`codewire-orchestration-internal-roots`, mounted read-only into the workspace
container only, to verify the binding listener's TLS identity. A local
cluster may add one more, and only this one: the single public key `ca.crt`
of `codewire-coordinator-extra-roots`, mounted read-only at
`/run/codewire-coordinator-extra-roots` in the workspace container only, which
the daemon trusts beside the WebPKI roots for a coordinator without a WebPKI
certificate. Dev and Production never render it.

Warm pools (Program #2238 C1) share one such template per exact shape. Their
objects carry no environment, organization, generation, UUID or secret at all,
are named `cw-pool-<cpu>m-<mem>mi-<disk>gi-<h8>` (never a legacy
`sandbox-warmpool-` or `shadow-pool-` name), run only digest-pinned images,
never the confidential runtime, and record `codewire.sh/pool-revision` as the
SHA-256 of the template spec.

A confidential workspace (Program #2238 B2c) binds the same way, with the
same binding token, URL and downward-API UID, and never a daemon token. It
mounts no ConfigMap at all, because the host supplies every mounted file under
SEV-SNP. Instead its workspace container carries its measured anchors exactly
once each: the binding roots (a PEM bundle) and the one environment it may bind
as, the UUID its measured init-data names as the storage key ID. Its measured
policy pins those anchors and the binding URL, and its daemon state
(`codewire-run`) is guest memory. It stays cold, and only its storage claim
carries the environment label.

The orchestration renderer's golden fixtures are the reviewed rendering; the
Rust test pins renderer == fixture, and this guard pins the fixture against
the invariant, so neither can drift alone.
"""

from __future__ import annotations

import base64
import copy
import gzip
import hashlib
import json
import re
from typing import Any

from . import pool_ingress
from .shared import ROOT, argparse

FIXTURES = [
    "crates/codewire-orchestration/tests/fixtures/sandbox/identity-free-sandboxtemplate.golden.json",
    "crates/codewire-orchestration/tests/fixtures/sandbox/identity-free-sandboxtemplate-runc.golden.json",
    "crates/codewire-orchestration/tests/fixtures/sandbox/warm-pool-sandboxtemplate.golden.json",
]
CONFIDENTIAL_FIXTURE = "crates/codewire-orchestration/tests/fixtures/sandbox/confidential-sandboxtemplate.golden.json"
MEASURED_ROOTS_ENV = "CODEWIRE_MEASURED_BINDING_ROOTS"
MEASURED_ENVIRONMENT_ENV = "CODEWIRE_MEASURED_ENVIRONMENT_ID"
BINDING_URL_ENV = "CODEWIRE_WORKSPACE_BINDING_URL"
POOL_TEMPLATE_FIXTURE = "crates/codewire-orchestration/tests/fixtures/sandbox/warm-pool-sandboxtemplate.golden.json"
POOL_FIXTURE = "crates/codewire-orchestration/tests/fixtures/sandbox/warm-pool-sandboxwarmpool.golden.json"

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
ROOTS_VOLUME = "orchestration-internal-roots"
ROOTS_MOUNT = "/run/codewire-orchestration-internal-roots"
# The only ConfigMap a workspace may mount: public trust material, one key.
EXPECTED_ROOTS_VOLUME = {
    "name": ROOTS_VOLUME,
    "configMap": {
        "name": "codewire-orchestration-internal-roots",
        "items": [{"key": "ca.crt", "path": "ca.crt"}],
        "defaultMode": 0o444,
    },
}
EXPECTED_ROOTS_MOUNT = {"name": ROOTS_VOLUME, "mountPath": ROOTS_MOUNT, "readOnly": True}
EXTRA_ROOTS_VOLUME = "coordinator-extra-roots"
EXTRA_ROOTS_MOUNT = "/run/codewire-coordinator-extra-roots"
# The optional second ConfigMap (local clusters only): the coordinator's
# public extra roots, one key.
EXPECTED_EXTRA_ROOTS_VOLUME = {
    "name": EXTRA_ROOTS_VOLUME,
    "configMap": {
        "name": "codewire-coordinator-extra-roots",
        "items": [{"key": "ca.crt", "path": "ca.crt"}],
        "defaultMode": 0o444,
    },
}
EXPECTED_EXTRA_ROOTS_MOUNT = {"name": EXTRA_ROOTS_VOLUME, "mountPath": EXTRA_ROOTS_MOUNT, "readOnly": True}
ENVIRONMENT_LABEL = "codewire.sh/environment-id"
POOL_NAME = re.compile(r"^cw-pool-[1-9][0-9]{0,9}m-[1-9][0-9]{0,9}mi-[1-9][0-9]{0,9}gi-[0-9a-f]{8}$")
POOL_REVISION = "codewire.sh/pool-revision"
POOL_LABELS = {"app.kubernetes.io/managed-by": "codewire", "codewire.sh/type": "workspace-pool"}
POOL_POD_LABELS = {"codewire.sh/type": "workspace"}
UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
DIGEST_PINNED = re.compile(r"^[^@\s]+@sha256:[0-9a-f]{64}$")
KATA_INIT_DATA = "io.katacontainers.config.hypervisor.cc_init_data"
# Environment or tenant state that never belongs in a shared pool object.
POOL_FORBIDDEN_TEXT = (
    "codewire.sh/org-id",
    "codewire.sh/environment-operation-generation",
    "codewire.sh/isolation-tier",
    "io.katacontainers.volume.confidential",
    "io.katacontainers.config.hypervisor.kernel_params",
    # The confidential claim shape (codewire#2321), whatever its class.
    '"volumeMode": "Block"',
    "ReadWriteOncePod",
)
# Environment-bound confidential init-data (KBS key IDs and storage contract).
POOL_FORBIDDEN_INIT_DATA = ("codewire_workspace_storage_key_id", "codewire_confidential_storage", "aa.toml")
SECRET_KEYS = {"secret", "secretName", "secretKeyRef", "envFrom"}


# Only the disposable Kind overlay turns the coordinator extra roots on; a
# shipped manifest never names the setting.
EXTRA_ROOTS_SETTING = "SANDBOX_COORDINATOR_EXTRA_ROOTS"
EXTRA_ROOTS_SETTING_OWNER = "tests/e2e/kind/support.yaml"


def extra_roots_setting_violations(manifests: dict[str, str]) -> list[str]:
    output = [f"{rel}: sets {EXTRA_ROOTS_SETTING}, which only {EXTRA_ROOTS_SETTING_OWNER} may"
              for rel, text in sorted(manifests.items())
              if rel != EXTRA_ROOTS_SETTING_OWNER and EXTRA_ROOTS_SETTING in text]
    if EXTRA_ROOTS_SETTING not in manifests.get(EXTRA_ROOTS_SETTING_OWNER, ""):
        output.append(f"{EXTRA_ROOTS_SETTING_OWNER}: Kind no longer mounts the coordinator extra roots")
    return output


def deployment_manifests() -> dict[str, str]:
    manifests = {
        path.relative_to(ROOT).as_posix(): path.read_text(encoding="utf-8")
        for path in (ROOT / "deployments").rglob("*")
        if path.is_file() and path.suffix in {".yaml", ".yml", ".json", ".env"}
    }
    manifests[EXTRA_ROOTS_SETTING_OWNER] = (ROOT / EXTRA_ROOTS_SETTING_OWNER).read_text(encoding="utf-8")
    return manifests


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
    extra_roots = [volume for volume in spec.get("volumes") or [] if volume.get("name") == EXTRA_ROOTS_VOLUME]
    if extra_roots not in ([], [EXPECTED_EXTRA_ROOTS_VOLUME]):
        output.append(f"{label}: coordinator extra roots volume is not exactly the ca.crt key of the extra roots")
    has_extra_roots = bool(extra_roots)
    for container in containers(spec):
        for entry in container.get("env") or []:
            if entry.get("name") in FORBIDDEN_ENVIRONMENT:
                output.append(f"{label}: container {container.get('name')} renders {entry.get('name')}")
        for entry in container.get("envFrom") or []:
            output.append(f"{label}: container {container.get('name')} imports an environment source")
        mounts_token = any(mount.get("name") == BINDING_VOLUME for mount in container.get("volumeMounts") or [])
        if mounts_token != (container.get("name") == "workspace"):
            output.append(f"{label}: binding token mount is not exactly the workspace container's")
        roots_mounts = [mount for mount in container.get("volumeMounts") or [] if mount.get("name") == ROOTS_VOLUME]
        if roots_mounts != ([EXPECTED_ROOTS_MOUNT] if container.get("name") == "workspace" else []):
            output.append(f"{label}: binding roots are not mounted read-only at {ROOTS_MOUNT} in the workspace container only")
        extra_mounts = [mount for mount in container.get("volumeMounts") or [] if mount.get("name") == EXTRA_ROOTS_VOLUME]
        expected_extra = [EXPECTED_EXTRA_ROOTS_MOUNT] if container.get("name") == "workspace" and has_extra_roots else []
        if extra_mounts != expected_extra:
            output.append(f"{label}: coordinator extra roots are not mounted read-only at {EXTRA_ROOTS_MOUNT} "
                          "in the workspace container only, exactly when their volume exists")
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
    roots = [volume for volume in spec.get("volumes") or [] if volume.get("name") == ROOTS_VOLUME]
    if roots != [EXPECTED_ROOTS_VOLUME]:
        output.append(f"{label}: binding roots volume is not exactly the ca.crt key of the internal roots")
    for volume in spec.get("volumes") or []:
        if "configMap" in volume and volume not in (EXPECTED_ROOTS_VOLUME, EXPECTED_EXTRA_ROOTS_VOLUME):
            output.append(f"{label}: mounts ConfigMap volume {volume.get('name')}")
        if "secret" in volume:
            output.append(f"{label}: mounts Secret volume {volume.get('name')}")
    workspace = next((container for container in spec.get("containers") or [] if container.get("name") == "workspace"), {})
    env = {entry.get("name"): entry for entry in workspace.get("env") or []}
    if env.get("CODEWIRE_POD_UID") != {"name": "CODEWIRE_POD_UID", "valueFrom": {"fieldRef": {"fieldPath": "metadata.uid"}}}:
        output.append(f"{label}: workspace UID is not from the downward API")
    binding_url = str((env.get("CODEWIRE_WORKSPACE_BINDING_URL") or {}).get("value", ""))
    if not (binding_url.startswith("https://") and binding_url.endswith(":8087")):
        output.append(f"{label}: workspace has no TLS binding listener URL")
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
    # The daemon's tailnet reaches DERP's STUN port and the public relay's
    # data plane, whose public LoadBalancers land on these Pods: those UDP
    # ports only, never DERP TLS or the relay allocator (design §5).
    for rule in egress:
        components = {
            ((peer.get("podSelector") or {}).get("matchLabels") or {}).get("app.kubernetes.io/component")
            for peer in rule.get("to") or []
        }
        for component in sorted(components & TAILNET_EGRESS.keys()):
            if rule.get("ports") != TAILNET_EGRESS[component] or len(components) != 1:
                output.append(f"{label}: template egress reaches {component} beyond its public UDP port")
    # codewire#3626: the one ingress rule is orchestration's identity on the
    # daemon and SSH ports, nothing wider.
    output.extend(pool_ingress.ingress_violations(template, label))
    return output


def binding_egress_violations(template: dict[str, Any], label: str) -> list[str]:
    egress = ((template.get("spec") or {}).get("networkPolicy") or {}).get("egress") or []
    binding_rules = [rule for rule in egress if any(port.get("port") == 8087 for port in rule.get("ports") or [])]
    if len(binding_rules) != 1 or binding_rules[0].get("ports") != [{"port": 8087, "protocol": "TCP"}] or not all(
        (peer.get("podSelector") or {}).get("matchLabels") == {"app.kubernetes.io/component": "orchestration"}
        and "namespaceSelector" in peer
        for peer in binding_rules[0].get("to") or [{}]
    ):
        return [f"{label}: template egress is not exactly one TCP 8087 rule to orchestration"]
    return []


def confidential_violations(template: dict[str, Any], label: str) -> list[str]:
    """A confidential workspace binds with only its measured anchors (B2c)."""
    output: list[str] = []
    text = json.dumps(template, sort_keys=True)
    for fragment in FORBIDDEN_TEXT + ("codewire-orchestration-internal-roots", "codewire-coordinator-extra-roots"):
        if fragment in text:
            output.append(f"{label}: carries {fragment}")
    pod_template = (template.get("spec") or {}).get("podTemplate") or {}
    spec = pod_template.get("spec") or {}
    if spec.get("runtimeClassName") != "confidential":
        output.append(f"{label}: does not run the confidential runtime")
    if ((pod_template.get("metadata") or {}).get("labels") or {}).get("codewire.sh/isolation-tier") != "confidential":
        output.append(f"{label}: does not carry the confidential tier label")
    if ENVIRONMENT_LABEL in json.dumps(template.get("metadata") or {}) or ENVIRONMENT_LABEL in json.dumps(pod_template):
        output.append(f"{label}: carries the environment label outside its storage claim")
    if spec.get("automountServiceAccountToken") is not False:
        output.append(f"{label}: automounts a Kubernetes API token")
    for volume in spec.get("volumes") or []:
        if "configMap" in volume:
            output.append(f"{label}: mounts ConfigMap volume {volume.get('name')}, which the host would supply")
        if "secret" in volume:
            output.append(f"{label}: mounts Secret volume {volume.get('name')}")
    run = [volume for volume in spec.get("volumes") or [] if volume.get("name") == "codewire-run"]
    if run != [{"name": "codewire-run", "emptyDir": {"medium": "Memory"}}]:
        output.append(f"{label}: the daemon's state is not guest memory")
    binding = [volume for volume in spec.get("volumes") or [] if volume.get("name") == BINDING_VOLUME]
    if binding != [{
        "name": BINDING_VOLUME,
        "projected": {
            "defaultMode": 0o440,
            "sources": [{"serviceAccountToken": {"audience": BINDING_AUDIENCE, "expirationSeconds": 600, "path": "token"}}],
        },
    }]:
        output.append(f"{label}: binding token volume is not exactly the workspace-binding audience")
    for container in containers(spec):
        for entry in container.get("env") or []:
            if entry.get("name") in FORBIDDEN_ENVIRONMENT:
                output.append(f"{label}: container {container.get('name')} renders {entry.get('name')}")
            if container.get("name") != "workspace" and entry.get("name") in (MEASURED_ROOTS_ENV, MEASURED_ENVIRONMENT_ENV):
                output.append(f"{label}: container {container.get('name')} carries a measured anchor")
        if container.get("envFrom"):
            output.append(f"{label}: container {container.get('name')} imports an environment source")
        mounts_token = [mount for mount in container.get("volumeMounts") or [] if mount.get("name") == BINDING_VOLUME]
        expected = ([{"name": BINDING_VOLUME, "mountPath": BINDING_MOUNT, "readOnly": True}]
                    if container.get("name") == "workspace" else [])
        if mounts_token != expected:
            output.append(f"{label}: binding token mount is not exactly the workspace container's")
    workspace = next((c for c in spec.get("containers") or [] if c.get("name") == "workspace"), {})
    entries: dict[str, list[dict[str, Any]]] = {}
    for entry in workspace.get("env") or []:
        entries.setdefault(str(entry.get("name")), []).append(entry)
    if entries.get("CODEWIRE_POD_UID") != [{"name": "CODEWIRE_POD_UID", "valueFrom": {"fieldRef": {"fieldPath": "metadata.uid"}}}]:
        output.append(f"{label}: workspace UID is not from the downward API")
    anchors: dict[str, str] = {}
    for name in (BINDING_URL_ENV, MEASURED_ROOTS_ENV, MEASURED_ENVIRONMENT_ENV):
        found = entries.get(name) or []
        if len(found) != 1 or not isinstance(found[0].get("value"), str) or set(found[0]) != {"name", "value"}:
            output.append(f"{label}: workspace does not carry {name} exactly once as a literal")
            continue
        anchors[name] = found[0]["value"]
    url = anchors.get(BINDING_URL_ENV, "")
    if not (url.startswith("https://") and url.endswith(":8087")):
        output.append(f"{label}: workspace has no TLS binding listener URL")
    roots = anchors.get(MEASURED_ROOTS_ENV, "")
    if "-----BEGIN CERTIFICATE-----" not in roots or "-----END CERTIFICATE-----" not in roots:
        output.append(f"{label}: measured binding roots are not a PEM certificate bundle")
    environment_id = anchors.get(MEASURED_ENVIRONMENT_ENV, "")
    if not UUID.fullmatch(environment_id):
        output.append(f"{label}: measured environment is not a UUID")
    if "test -f /codewire/run/daemon/ready" not in json.dumps(workspace.get("readinessProbe") or {}):
        output.append(f"{label}: workspace readiness is not the daemon's local marker")
    claims = (template.get("spec") or {}).get("volumeClaimTemplates") or []
    if [((claim.get("metadata") or {}).get("labels") or {}).get(ENVIRONMENT_LABEL) for claim in claims] != [environment_id]:
        output.append(f"{label}: the storage claim does not name the measured environment")
    init_data = init_data_text(template)
    if not init_data:
        output.append(f"{label}: Kata init-data is missing or undecodable")
        init_data = ""
    if f'"codewire_workspace_storage_key_id" = "{environment_id}"' not in init_data:
        output.append(f"{label}: init-data does not measure the bound environment as its storage key")
    # The measured policy pins each anchor as a pretty-printed contract entry.
    for name, value in anchors.items():
        if f'"name": {json.dumps(name)}' not in init_data or f'"value": {json.dumps(value)}' not in init_data:
            output.append(f"{label}: init-data does not pin {name}")
    if "CODEWIRE_DAEMON_AUTH_TOKEN" in init_data:
        output.append(f"{label}: init-data names the environment token")
    output.extend(binding_egress_violations(template, label))
    # Confidential is never pooled and keeps no template ingress (#3626).
    if "ingress" in ((template.get("spec") or {}).get("networkPolicy") or {}):
        output.append(f"{label}: a confidential template carries ingress")
    return output


def confidential_self_test(base: dict[str, Any]) -> None:
    def rejected(name: str, mutate: Any) -> None:
        fixture = copy.deepcopy(base)
        mutate(fixture)
        if not confidential_violations(fixture, f"negative confidential fixture {name}"):
            raise RuntimeError(f"negative confidential fixture {name} was accepted")

    def spec(fixture: dict[str, Any]) -> dict[str, Any]:
        return fixture["spec"]["podTemplate"]["spec"]

    def workspace(fixture: dict[str, Any]) -> dict[str, Any]:
        return next(c for c in spec(fixture)["containers"] if c["name"] == "workspace")

    def env(fixture: dict[str, Any], name: str) -> dict[str, Any]:
        return next(e for e in workspace(fixture)["env"] if e["name"] == name)

    def replace_init_data(fixture: dict[str, Any], old: str, new: str) -> None:
        annotations = fixture["spec"]["podTemplate"]["metadata"]["annotations"]
        text = gzip.decompress(base64.b64decode(annotations[KATA_INIT_DATA])).decode("utf-8")
        annotations[KATA_INIT_DATA] = base64.b64encode(gzip.compress(text.replace(old, new).encode("utf-8"))).decode("ascii")

    other = "b3a9c6f2-1d4e-4f5a-8b7c-6d5e4f3a2b1c"
    measured = env(base, MEASURED_ENVIRONMENT_ENV)["value"]
    rejected("daemon token", lambda f: workspace(f)["env"].append({"name": "CODEWIRE_DAEMON_AUTH_TOKEN", "value": "x"}))
    rejected("roots ConfigMap", lambda f: spec(f)["volumes"].append(copy.deepcopy(EXPECTED_ROOTS_VOLUME)))
    rejected("coordinator extra roots", lambda f: spec(f)["volumes"].append(copy.deepcopy(EXPECTED_EXTRA_ROOTS_VOLUME)))
    rejected("disk-backed daemon state", lambda f: next(v for v in spec(f)["volumes"] if v["name"] == "codewire-run").__setitem__(
        "emptyDir", {}))
    rejected("commodity runtime", lambda f: spec(f).__setitem__("runtimeClassName", "commodity"))
    rejected("template environment label", lambda f: f["metadata"].__setitem__("labels", {ENVIRONMENT_LABEL: measured}))
    rejected("missing measured roots", lambda f: workspace(f).__setitem__(
        "env", [e for e in workspace(f)["env"] if e["name"] != MEASURED_ROOTS_ENV]))
    rejected("measured roots from a ConfigMap", lambda f: env(f, MEASURED_ROOTS_ENV).update(
        {"valueFrom": {"configMapKeyRef": {"name": "roots", "key": "ca.crt"}}}))
    rejected("duplicate measured environment", lambda f: workspace(f)["env"].append(
        {"name": MEASURED_ENVIRONMENT_ENV, "value": other}))
    rejected("measured environment not the storage key", lambda f: env(f, MEASURED_ENVIRONMENT_ENV).__setitem__("value", other))
    rejected("unpinned measured roots", lambda f: env(f, MEASURED_ROOTS_ENV).__setitem__(
        "value", "-----BEGIN CERTIFICATE-----\nOTHER\n-----END CERTIFICATE-----\n"))
    rejected("unpinned binding URL", lambda f: env(f, BINDING_URL_ENV).__setitem__(
        "value", "https://attacker.example:8087"))
    rejected("plaintext binding URL", lambda f: env(f, BINDING_URL_ENV).__setitem__(
        "value", "http://codewire-orchestration-workspace-binding.dev.svc.cluster.local:8087"))
    rejected("anchor in DinD", lambda f: next(c for c in spec(f)["containers"] if c["name"] == "dind").setdefault("env", []).append(
        dict(env(f, MEASURED_ROOTS_ENV))))
    rejected("token in DinD", lambda f: next(c for c in spec(f)["containers"] if c["name"] == "dind")["volumeMounts"].append(
        {"name": BINDING_VOLUME, "mountPath": BINDING_MOUNT, "readOnly": True}))
    rejected("caller-chosen UID", lambda f: env(f, "CODEWIRE_POD_UID").__setitem__("valueFrom", {"fieldRef": {"fieldPath": "metadata.name"}}))
    rejected("init-data for another environment", lambda f: replace_init_data(f, measured, other))
    rejected("init-data naming the token", lambda f: replace_init_data(
        f, '"policy.rego"', '"CODEWIRE_DAEMON_AUTH_TOKEN" = "x"\n"policy.rego"'))
    rejected("undecodable init-data", lambda f: f["spec"]["podTemplate"]["metadata"]["annotations"].__setitem__(
        KATA_INIT_DATA, "not base64"))
    rejected("second binding egress", lambda f: f["spec"]["networkPolicy"]["egress"].append(
        {"to": [{"ipBlock": {"cidr": "10.0.0.0/8"}}], "ports": [{"protocol": "TCP", "port": 8087}]}))
    rejected("template ingress", lambda f: f["spec"]["networkPolicy"].__setitem__(
        "ingress", pool_ingress.expected_ingress("dev")))


TAILNET_EGRESS = {
    "derp": [{"port": 3478, "protocol": "UDP"}],
    "udp-relay": [{"port": 41641, "protocol": "UDP"}],
}


POOL_REVISION_ENV = "CODEWIRE_WORKSPACE_POOL_REVISION"


def without_revision_marker(spec: Any) -> Any:
    """The template spec without the workspace container's revision marker."""
    spec = copy.deepcopy(spec)
    containers = (((spec or {}).get("podTemplate") or {}).get("spec") or {}).get("containers") or []
    for container in containers:
        if isinstance(container.get("env"), list):
            container["env"] = [entry for entry in container["env"] if entry.get("name") != POOL_REVISION_ENV]
    return spec


def pool_revision(template: dict[str, Any]) -> str:
    """serde_json's compact, key-sorted serialization of the template spec,
    without the revision marker the spec carries."""
    spec = json.dumps(without_revision_marker(template.get("spec")), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(spec.encode("utf-8")).hexdigest()


def revision_markers(template: dict[str, Any]) -> list[Any]:
    """Every revision marker the template's containers carry, by container."""
    containers = (((template.get("spec") or {}).get("podTemplate") or {}).get("spec") or {}).get("containers") or []
    return [
        (container.get("name"), entry)
        for container in containers
        for entry in container.get("env") or []
        if entry.get("name") == POOL_REVISION_ENV
    ]


def walk_keys(value: Any) -> list[str]:
    if isinstance(value, dict):
        return [key for key, item in value.items() for key in [key, *walk_keys(item)]]
    if isinstance(value, list):
        return [key for item in value for key in walk_keys(item)]
    return []


def pool_images(spec: dict[str, Any]) -> list[str]:
    images = [container.get("image", "") for container in containers(spec)]
    images += [(volume.get("image") or {}).get("reference", "") for volume in spec.get("volumes") or [] if "image" in volume]
    return images


def init_data_text(template: dict[str, Any]) -> str | None:
    """The decoded commodity Kata policy init-data, "" when absent, None when undecodable."""
    annotations = ((template.get("spec") or {}).get("podTemplate") or {}).get("metadata", {}).get("annotations") or {}
    encoded = annotations.get(KATA_INIT_DATA)
    if encoded is None:
        return ""
    try:
        return gzip.decompress(base64.b64decode(encoded, validate=True)).decode("utf-8")
    except (ValueError, OSError, EOFError, UnicodeDecodeError):
        return None


def pool_violations(template: dict[str, Any], pool: dict[str, Any], label: str) -> list[str]:
    output: list[str] = []
    name = (template.get("metadata") or {}).get("name", "")
    if not POOL_NAME.fullmatch(str(name)):
        output.append(f"{label}: template name {name!r} is not a cw-pool-<cpu>m-<mem>mi-<disk>gi-<h8> name")
    if template.get("kind") != "SandboxTemplate" or pool.get("kind") != "SandboxWarmPool":
        output.append(f"{label}: objects are not a SandboxTemplate and its SandboxWarmPool")
    if (pool.get("metadata") or {}).get("name") != name or (pool.get("metadata") or {}).get("namespace") != (
        template.get("metadata") or {}
    ).get("namespace"):
        output.append(f"{label}: pool and template do not share one name and namespace")
    expected_spec_keys = {"replicas", "sandboxTemplateRef", "updateStrategy"}
    pool_spec = pool.get("spec") or {}
    if set(pool_spec) != expected_spec_keys or pool_spec.get("sandboxTemplateRef") != {"name": name}:
        output.append(f"{label}: pool spec is not exactly its own template, replicas and update strategy")
    replicas = pool_spec.get("replicas")
    if not isinstance(replicas, int) or isinstance(replicas, bool) or replicas < 0:
        output.append(f"{label}: pool replicas are not a non-negative integer")
    if pool_spec.get("updateStrategy") != {"type": "Recreate"}:
        output.append(f"{label}: pool does not recreate stale members")
    revision = pool_revision(template)
    # Review M1: the workspace container carries exactly its revision, which
    # the bind reads from the immutable Pod spec.
    if revision_markers(template) != [("workspace", {"name": POOL_REVISION_ENV, "value": revision})]:
        output.append(f"{label}: the workspace container does not carry exactly its pool revision")
    for kind, obj in (("template", template), ("pool", pool)):
        metadata = obj.get("metadata") or {}
        if metadata.get("labels") != POOL_LABELS:
            output.append(f"{label}: {kind} labels are not exactly the pool labels")
        if metadata.get("annotations") != {POOL_REVISION: revision}:
            output.append(f"{label}: {kind} {POOL_REVISION} is not the SHA-256 of the template spec")
        text = json.dumps(obj, sort_keys=True)
        if UUID.search(text):
            output.append(f"{label}: {kind} carries a UUID")
        if ENVIRONMENT_LABEL in text:
            output.append(f"{label}: {kind} carries the environment label")
        for fragment in POOL_FORBIDDEN_TEXT:
            if fragment in text:
                output.append(f"{label}: {kind} carries {fragment}")
        for key in sorted(SECRET_KEYS.intersection(walk_keys(obj))):
            output.append(f"{label}: {kind} references a secret through {key}")
    pod = ((template.get("spec") or {}).get("podTemplate") or {})
    if (pod.get("metadata") or {}).get("labels") != POOL_POD_LABELS:
        output.append(f"{label}: member Pod labels are not exactly the workspace type")
    spec = pod.get("spec") or {}
    if spec.get("runtimeClassName") == "confidential":
        output.append(f"{label}: pools the confidential runtime")
    for image in pool_images(spec):
        if not DIGEST_PINNED.fullmatch(str(image)):
            output.append(f"{label}: image {image!r} is not digest-pinned")
    init_data = init_data_text(template)
    if init_data is None:
        output.append(f"{label}: Kata init-data cannot be decoded and checked")
        init_data = ""
    if UUID.search(init_data):
        output.append(f"{label}: Kata init-data carries a UUID")
    for fragment in POOL_FORBIDDEN_INIT_DATA:
        if fragment in init_data:
            output.append(f"{label}: Kata init-data carries {fragment}")
    return output


def pool_self_test(template: dict[str, Any], pool: dict[str, Any]) -> None:
    environment_id = "3d6bb495-efac-419f-bf3a-91696e7c7ca4"

    def rejected(name: str, mutate: Any, resign: bool = True) -> None:
        fixture = {"template": copy.deepcopy(template), "pool": copy.deepcopy(pool)}
        mutate(fixture)
        # Re-sign the spec so each negative fails for its own reason, not only
        # for a stale revision.
        signed = pool_revision(fixture["template"])
        for obj in fixture.values() if resign else ():
            annotations = (obj.get("metadata") or {}).get("annotations")
            if isinstance(annotations, dict) and POOL_REVISION in annotations:
                annotations[POOL_REVISION] = signed
        if resign:
            for _, entry in revision_markers(fixture["template"]):
                entry["value"] = signed
        if not pool_violations(fixture["template"], fixture["pool"], f"negative pool fixture {name}"):
            raise RuntimeError(f"negative pool fixture {name} was accepted")

    def pod_spec(fixture: dict[str, Any]) -> dict[str, Any]:
        return fixture["template"]["spec"]["podTemplate"]["spec"]

    def workspace(fixture: dict[str, Any]) -> dict[str, Any]:
        return next(c for c in pod_spec(fixture)["containers"] if c["name"] == "workspace")

    def rename(fixture: dict[str, Any], name: str) -> None:
        fixture["template"]["metadata"]["name"] = name
        fixture["pool"]["metadata"]["name"] = name
        fixture["pool"]["spec"]["sandboxTemplateRef"]["name"] = name

    def init_data(fixture: dict[str, Any], text: str) -> None:
        fixture["template"]["spec"]["podTemplate"]["metadata"]["annotations"][KATA_INIT_DATA] = base64.b64encode(
            gzip.compress(text.encode("utf-8"))
        ).decode("ascii")

    rejected("legacy shared name", lambda f: rename(f, "sandbox-warmpool-workspace-5513aec3"))
    rejected("shadow name", lambda f: rename(f, f"shadow-pool-workspace-{environment_id}"))
    rejected("per-environment name", lambda f: rename(f, f"workspace-{environment_id}"))
    rejected("uppercase hash", lambda f: rename(f, f["template"]["metadata"]["name"].upper()))
    rejected("template ref mismatch", lambda f: f["pool"]["spec"]["sandboxTemplateRef"].__setitem__("name", "cw-pool-1m-1mi-1gi-00000000"))
    rejected("pool environment label", lambda f: f["pool"]["metadata"]["labels"].__setitem__(ENVIRONMENT_LABEL, environment_id))
    rejected("pool organization label", lambda f: f["pool"]["metadata"]["labels"].__setitem__("codewire.sh/org-id", "org"))
    rejected("member generation label", lambda f: f["template"]["spec"]["podTemplate"]["metadata"]["labels"].__setitem__(
        "codewire.sh/environment-operation-generation", "7"))
    rejected("missing revision", lambda f: f["pool"]["metadata"].__setitem__("annotations", {}))
    rejected("stale revision", lambda f: f["template"]["metadata"]["annotations"].__setitem__(POOL_REVISION, "0" * 64), resign=False)

    def stale_marker(f: dict[str, Any]) -> None:
        for _, entry in revision_markers(f["template"]):
            entry["value"] = "0" * 64

    rejected("stale revision marker", stale_marker, resign=False)

    def no_marker(f: dict[str, Any]) -> None:
        f["template"]["spec"] = without_revision_marker(f["template"]["spec"])

    rejected("missing revision marker", no_marker)
    rejected("unsigned image change", lambda f: workspace(f).__setitem__(
        "image", "registry.example.invalid/codewire/workspace@sha256:" + "4" * 64), resign=False)
    rejected("environment UUID in env", lambda f: workspace(f)["env"].append({"name": "CODEWIRE_SANDBOX", "value": environment_id}))
    rejected("secret env", lambda f: workspace(f)["env"].append(
        {"name": "TOKEN", "valueFrom": {"secretKeyRef": {"name": "env", "key": "token"}}}))
    rejected("tagged workspace image", lambda f: workspace(f).__setitem__("image", "registry.example.invalid/codewire/workspace:main"))
    rejected("tagged support image", lambda f: next(v for v in pod_spec(f)["volumes"] if "image" in v)["image"].__setitem__(
        "reference", "registry.example.invalid/codewire/daemon:main-4b5b65d"))
    rejected("confidential runtime", lambda f: pod_spec(f).__setitem__("runtimeClassName", "confidential"))
    rejected("confidential tier label", lambda f: f["template"]["spec"]["podTemplate"]["metadata"]["labels"].__setitem__(
        "codewire.sh/isolation-tier", "confidential"))
    rejected("confidential volume", lambda f: f["template"]["spec"]["volumeClaimTemplates"][0]["spec"].__setitem__(
        "accessModes", ["ReadWriteOncePod"]))
    rejected("environment init-data", lambda f: init_data(
        f, f'"codewire_workspace_storage_key_id" = "{environment_id}"\n'))
    rejected("undecodable init-data", lambda f: f["template"]["spec"]["podTemplate"]["metadata"]["annotations"].__setitem__(
        KATA_INIT_DATA, "not base64"))
    rejected("stale member reuse", lambda f: f["pool"]["spec"].__setitem__("updateStrategy", {"type": "OnReplenish"}))
    rejected("negative replicas", lambda f: f["pool"]["spec"].__setitem__("replicas", -1))
    pool_ingress.self_test(template, "warm-pool template ingress")


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
    rejected("broker roots ConfigMap", lambda f: f["spec"]["podTemplate"]["spec"]["volumes"].append(
        {"name": "credential-broker-roots", "configMap": {"name": "codewire-credential-broker-roots"}}))
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
    rejected("relay allocator egress", lambda f: f["spec"]["networkPolicy"]["egress"].append(
        {"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "dev"}},
                 "podSelector": {"matchLabels": {"app.kubernetes.io/component": "udp-relay"}}}],
         "ports": [{"protocol": "TCP", "port": 8095}]}))
    rejected("DERP TLS egress", lambda f: f["spec"]["networkPolicy"]["egress"].append(
        {"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "dev"}},
                 "podSelector": {"matchLabels": {"app.kubernetes.io/component": "derp"}}}],
         "ports": [{"protocol": "UDP", "port": 3478}, {"protocol": "TCP", "port": 8443}]}))
    rejected("second binding egress", lambda f: f["spec"]["networkPolicy"]["egress"].append(
        {"to": [{"ipBlock": {"cidr": "10.0.0.0/8"}}], "ports": [{"protocol": "TCP", "port": 8087}]}))
    rejected("Secret volume", lambda f: f["spec"]["podTemplate"]["spec"]["volumes"].append({"name": "env", "secret": {"secretName": "env"}}))
    # codewire#3626: the renderer emits exactly orchestration on TCP 7777 and
    # 2222. Admission also admits no ingress, for the rollout only; both
    # shapes are positive fixtures, and every widening fails here.
    pool_ingress.self_test(base, "identity-free template ingress")
    rejected("no template ingress", lambda f: f["spec"]["networkPolicy"].pop("ingress"))
    rejected("environment import", lambda f: workspace(f).__setitem__("envFrom", [{"configMapRef": {"name": "environment"}}]))

    def volume(fixture: dict[str, Any], name: str) -> dict[str, Any]:
        return next(v for v in fixture["spec"]["podTemplate"]["spec"]["volumes"] if v["name"] == name)

    def roots_mount(fixture: dict[str, Any]) -> dict[str, Any]:
        return next(m for m in workspace(fixture)["volumeMounts"] if m["name"] == ROOTS_VOLUME)

    def binding_url(fixture: dict[str, Any], value: str) -> None:
        next(e for e in workspace(fixture)["env"] if e["name"] == "CODEWIRE_WORKSPACE_BINDING_URL")["value"] = value

    rejected("plaintext binding URL", lambda f: binding_url(
        f, "http://codewire-orchestration-workspace-binding.dev.svc.cluster.local:8087"))
    rejected("roots in DinD", lambda f: next(c for c in f["spec"]["podTemplate"]["spec"]["containers"] if c["name"] == "dind")[
        "volumeMounts"].append(dict(EXPECTED_ROOTS_MOUNT)))
    rejected("writable roots mount", lambda f: roots_mount(f).__setitem__("readOnly", False))
    rejected("roots at another path", lambda f: roots_mount(f).__setitem__("mountPath", "/etc/ssl/certs"))
    rejected("roots by subPath", lambda f: roots_mount(f).__setitem__("subPath", "ca.crt"))
    rejected("roots without mount", lambda f: workspace(f).__setitem__(
        "volumeMounts", [m for m in workspace(f)["volumeMounts"] if m["name"] != ROOTS_VOLUME]))
    rejected("roots volume missing", lambda f: f["spec"]["podTemplate"]["spec"].__setitem__(
        "volumes", [v for v in f["spec"]["podTemplate"]["spec"]["volumes"] if v["name"] != ROOTS_VOLUME]))
    rejected("whole roots ConfigMap", lambda f: volume(f, ROOTS_VOLUME)["configMap"].pop("items"))
    rejected("another roots key", lambda f: volume(f, ROOTS_VOLUME)["configMap"].__setitem__(
        "items", [{"key": "ca.crt", "path": "ca.crt"}, {"key": "tls.key", "path": "tls.key"}]))
    rejected("another roots ConfigMap", lambda f: volume(f, ROOTS_VOLUME)["configMap"].__setitem__(
        "name", "codewire-credential-broker-roots"))
    rejected("writable roots mode", lambda f: volume(f, ROOTS_VOLUME)["configMap"].__setitem__("defaultMode", 0o666))
    rejected("second roots volume", lambda f: f["spec"]["podTemplate"]["spec"]["volumes"].append(copy.deepcopy(EXPECTED_ROOTS_VOLUME)))
    rejected("roots ConfigMap under another name", lambda f: f["spec"]["podTemplate"]["spec"]["volumes"].append(
        {**copy.deepcopy(EXPECTED_ROOTS_VOLUME), "name": "extra-roots"}))

    # A local cluster's coordinator extra roots: accepted exactly, nothing more.
    def with_extra_roots(fixture: dict[str, Any]) -> None:
        fixture["spec"]["podTemplate"]["spec"]["volumes"].append(copy.deepcopy(EXPECTED_EXTRA_ROOTS_VOLUME))
        workspace(fixture)["volumeMounts"].append(dict(EXPECTED_EXTRA_ROOTS_MOUNT))

    accepted = copy.deepcopy(base)
    with_extra_roots(accepted)
    if violations(accepted, "positive fixture coordinator extra roots"):
        raise RuntimeError("the exact coordinator extra roots were rejected")

    def extra(mutate: Any) -> Any:
        def apply(fixture: dict[str, Any]) -> None:
            with_extra_roots(fixture)
            mutate(fixture)
        return apply

    def extra_mount(fixture: dict[str, Any]) -> dict[str, Any]:
        return next(m for m in workspace(fixture)["volumeMounts"] if m["name"] == EXTRA_ROOTS_VOLUME)

    rejected("extra roots without mount", lambda f: f["spec"]["podTemplate"]["spec"]["volumes"].append(
        copy.deepcopy(EXPECTED_EXTRA_ROOTS_VOLUME)))
    rejected("extra roots mount without volume", lambda f: workspace(f)["volumeMounts"].append(dict(EXPECTED_EXTRA_ROOTS_MOUNT)))
    rejected("extra roots in DinD", extra(lambda f: next(c for c in f["spec"]["podTemplate"]["spec"]["containers"]
                                                         if c["name"] == "dind")["volumeMounts"].append(dict(EXPECTED_EXTRA_ROOTS_MOUNT))))
    rejected("writable extra roots mount", extra(lambda f: extra_mount(f).__setitem__("readOnly", False)))
    rejected("extra roots at another path", extra(lambda f: extra_mount(f).__setitem__("mountPath", "/etc/ssl/certs")))
    rejected("another extra roots ConfigMap", extra(lambda f: volume(f, EXTRA_ROOTS_VOLUME)["configMap"].__setitem__(
        "name", "codewire-credential-broker-roots")))
    rejected("another extra roots key", extra(lambda f: volume(f, EXTRA_ROOTS_VOLUME)["configMap"].__setitem__(
        "items", [{"key": "ca.crt", "path": "ca.crt"}, {"key": "tls.key", "path": "tls.key"}])))
    rejected("writable extra roots mode", extra(lambda f: volume(f, EXTRA_ROOTS_VOLUME)["configMap"].__setitem__("defaultMode", 0o666)))
    rejected("second extra roots volume", extra(lambda f: f["spec"]["podTemplate"]["spec"]["volumes"].append(
        copy.deepcopy(EXPECTED_EXTRA_ROOTS_VOLUME))))


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
    pool_objects = []
    for rel in (POOL_TEMPLATE_FIXTURE, POOL_FIXTURE):
        try:
            pool_objects.append(json.loads((ROOT / rel).read_text(encoding="utf-8")))
        except (OSError, ValueError) as error:
            failures.append(f"{rel}: unreadable ({error})")
    if len(pool_objects) == 2:
        failures.extend(pool_violations(pool_objects[0], pool_objects[1], POOL_FIXTURE))
    confidential = None
    try:
        confidential = json.loads((ROOT / CONFIDENTIAL_FIXTURE).read_text(encoding="utf-8"))
        failures.extend(confidential_violations(confidential, CONFIDENTIAL_FIXTURE))
    except (OSError, ValueError) as error:
        failures.append(f"{CONFIDENTIAL_FIXTURE}: unreadable ({error})")
    try:
        failures.extend(extra_roots_setting_violations(deployment_manifests()))
    except OSError as error:
        failures.append(f"deployment manifests: unreadable ({error})")
    if args.self_test and base is not None:
        try:
            kind = {EXTRA_ROOTS_SETTING_OWNER: f'  {EXTRA_ROOTS_SETTING}: "true"\n'}
            if extra_roots_setting_violations(kind):
                raise RuntimeError("the Kind overlay's coordinator extra roots were rejected")
            for name, manifests in {
                "local overlay setting": {**kind, "deployments/k8s/overlays/local-kind/configmap-patch.yaml": f"{EXTRA_ROOTS_SETTING}: \"true\""},
                "base setting": {**kind, "deployments/k8s/orchestration/deployment.yaml": f"- name: {EXTRA_ROOTS_SETTING}"},
                "Kind without the setting": {EXTRA_ROOTS_SETTING_OWNER: ""},
            }.items():
                if not extra_roots_setting_violations(manifests):
                    raise RuntimeError(f"self-test accepted coordinator extra roots: {name}")
            self_test(base)
            if len(pool_objects) == 2:
                pool_self_test(pool_objects[0], pool_objects[1])
            if confidential is not None:
                confidential_self_test(confidential)
        except RuntimeError as error:
            failures.append(str(error))
    for failure in failures:
        print(f"::error::identity-free workspace: {failure}")
    if failures:
        return 1
    print(f"identity-free workspace: OK ({len(FIXTURES)} fixture(s), 1 warm pool, 1 confidential{', self-test' if args.self_test else ''})")
    return 0
