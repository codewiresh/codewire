#!/usr/bin/env python3
"""Server-side dry runs of the template admission policy (#4000, #5002).

Nothing in the repository evaluates the policy's CEL, so this applies the
rendered policy, its binding and its param to a scratch Kind cluster and has a
real API server admit or deny each case, as orchestration's service account.
It matches every SandboxTemplate orchestration writes: the pool's allowlist
holds cw-pool- templates, and the broker arm holds every template while hosted
egress is on, so per-environment templates are proved here too, and so is
the one template excepted from it, a snapshot's clearing template, and, with
the switch off, an update that keeps an environment's whole-broker template
whole (#6121). The member
policy's broker-mode rules, its hold on a VM Sandbox made before hosted
egress, and a start's move of one to broker mode, held to the template
policy's own broker checks, are proved on Sandboxes, and so is the policy that
keeps every other identity from adding broker mode.
Each case names the outcome it expects and, for a denial, the rule whose
message must be the one reported: validations run in order and the first that
fails is reported, so a case denied by another rule first does not count.

Usage, against a cluster you created for this and nothing else:
  kind create cluster --name warm-pool-admission --kubeconfig KUBECONFIG
  scripts/dev/kind/warm-pool-admission-proof.py --kubeconfig KUBECONFIG

It refuses any context that is not kind-*. It creates the server and sandbox
namespaces, the SandboxTemplate and Sandbox CRDs, a ClusterRole that lets
orchestration's service account create and update both, and the param
ConfigMap; the UPDATE cases create an object, update it and delete it.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parents[3]
FIXTURES = ROOT / "crates/codewire-orchestration/tests/fixtures/sandbox"
CRD = ROOT / "deployments/k8s/agent-sandbox/base/crds/extensions.agents.x-k8s.io_sandboxtemplates.yaml"
SANDBOX_CRD = ROOT / "deployments/k8s/agent-sandbox/base/crds/agents.x-k8s.io_sandboxes.yaml"
POLICY = "codewire-orchestration-warm-pool-template"
MEMBER_POLICY = "codewire-orchestration-warm-pool-member"
PARAM = "codewire-hosted-egress"
# The goldens' server and sandbox namespaces.
SERVER = "dev"
SANDBOXES = "dev-sandboxes"
AS = f"system:serviceaccount:{SERVER}:codewire-orchestration"
REPOSITORY = "registry.example.invalid/codewire/daemon"
OTHER_IMAGE = "registry.example.invalid/other/daemon@sha256:" + "4" * 64

# The first words of each rule's message.
GATE = "with hosted egress on, every template orchestration writes is broker-mode"
RESOLVER = "with hosted egress on, the netstack resolver"
ADDRESSES = "with hosted egress on, the workspace container sets the egress stream"
ENVIRONMENT = "a warm-pool template sets only the identity-free workspace"
EGRESS = "with hosted egress on, a template's egress names only the broker peers"
PRIVILEGE = "with hosted egress on, the Pod runs as 1000:1000"
TUN = "hosted-egress-tun runs only as an init container"
DEVNET = "the TUN device's volume egress-devnet is an emptyDir with medium Memory"
RUN = "the daemon's run directory codewire-run is exactly one emptyDir with medium Memory and sizeLimit 16Mi"
RUN_MOUNT = "every mount at or under /codewire/run, every mount of codewire-run and every mount path that is not plain"
MEMBER_RUN = "a Sandbox's run directory codewire-run is exactly one emptyDir with medium Memory and sizeLimit 16Mi"
MEMBER_RUN_MOUNT = "on a Sandbox, every mount at or under /codewire/run"
RUNTIME = "warm-pool members run under the commodity runtime"
EGRESS_MODE = "CODEWIRE_VM_EGRESS_MODE is set only on a standard template's workspace container"
STANDARD_POOL = "a standard pool template is one workspace container"
DISK = "a standard Pod mounts exactly the deployment's workspace disk"
DISK_KEY = "CODEWIRE_STANDARD_IMAGE_DISK_REFERENCE"
OTHER_DISK = "registry.example.invalid/codewire/workspace-disk@sha256:" + "9" * 64
KEEPS_BROKER = "orchestration never takes broker mode"
MOVE = "orchestration adds broker mode to an existing Sandbox only with hosted egress on"
PRE_SWITCH = "with hosted egress on, orchestration only stops a Sandbox made before it"
HOST = "with hosted egress on, a broker-mode Pod shares no host network"
LABEL_ONLY = "orchestration never adds the broker label (codewire.sh/egress=broker) without the whole broker shape"
CLASS = "orchestration's move of a Sandbox to broker mode keeps its runtime class"
FENCE = "with hosted egress on, a broker-mode Pod carries the fence revision"
WRITER = "only orchestration adds broker mode"
POOL_MEMBER = "orchestration never creates or changes an unclaimed warm-pool member"
WRITER_POLICY = "codewire-sandbox-broker-mode"
OTHER = f"system:serviceaccount:{SERVER}:another-writer"
ENVIRONMENT_ID = "8f0c3a52-6b1e-4f0e-9d3b-2a7c41e5d901"
NO_PARAM = "failed to configure binding: no params found"

OFF: dict[str, str] = {}
ON = {
    "CODEWIRE_HOSTED_EGRESS_ENABLED": "true",
    "CODEWIRE_HOSTED_EGRESS_DAEMON_REPOSITORY": REPOSITORY,
    "CODEWIRE_HOSTED_EGRESS_GATEWAY_NAMESPACE": "gateway-proxies",
    "CODEWIRE_HOSTED_EGRESS_GATEWAY_NAME": "public",
    "CODEWIRE_HOSTED_EGRESS_GATEWAY_OWNER_NAMESPACE": "gateway",
    "CODEWIRE_HOSTED_EGRESS_GATEWAY_PORT": "10443",
    # The goldens' fence revision.
    "CODEWIRE_HOSTED_EGRESS_FENCE_REVISION": "2",
}
# The switch off with the broker settings still named (#6121), as a
# deployment that turned it off after broker-mode Sandboxes were made has it.
OFF_KEEPING = ON | {"CODEWIRE_HOSTED_EGRESS_ENABLED": "false"}
# The key broker's Pods, as a deployment that names them sets kbsPeer (#4000).
KBS_PODS = {"app": "kbs", "app.kubernetes.io/instance": "codewire-trustee", "app.kubernetes.io/name": "trustee"}
WORLD = {"to": [{"ipBlock": {"cidr": "0.0.0.0/0", "except": [
    "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"]}}]}


class Cluster:
    def __init__(self, kubeconfig: str) -> None:
        self.env = dict(os.environ, KUBECONFIG=kubeconfig)
        context = self.kubectl("config", "current-context").stdout.strip()
        if not context.startswith("kind-"):
            sys.exit(f"refusing context {context!r}: this runs only against a scratch Kind cluster")

    def kubectl(self, *args: str, stdin: str | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(["kubectl", *args], input=stdin, capture_output=True, text=True, env=self.env)

    def apply(self, document: object) -> None:
        result = self.kubectl("apply", "-f", "-", stdin=json.dumps(document))
        if result.returncode != 0:
            sys.exit(f"apply failed: {result.stderr.strip()}")

    def param(self, data: dict[str, str] | None) -> None:
        if data is None:
            self.kubectl("delete", "configmap", PARAM, "-n", SERVER, "--ignore-not-found")
            return
        values = {key: "" for key in ON} | {"CODEWIRE_HOSTED_EGRESS_ENABLED": "false"} | data
        self.apply({"apiVersion": "v1", "kind": "ConfigMap",
                    "metadata": {"name": PARAM, "namespace": SERVER}, "data": values})

    def admit(self, verb: str, template: dict, identity: str = AS) -> str | None:
        """None when admitted, else the reported denial."""
        result = self.kubectl(verb, "--dry-run=server", f"--as={identity}", "-f", "-", stdin=json.dumps(template))
        if result.returncode == 0:
            return None
        text = result.stderr.strip()
        return text.split("denied request: ", 1)[-1] if "denied request: " in text else text


def rendered_policy(name: str = POLICY) -> list[dict]:
    """A policy and binding as the orchestration package renders them, with
    the binding reading its param from the goldens' server namespace, as an
    overlay's namespace pass does."""
    rendered = subprocess.run(["kubectl", "kustomize", str(ROOT / "deployments/k8s/orchestration")],
                              capture_output=True, text=True, check=True).stdout
    import yaml  # PyYAML, as the repo's CI scripts use.
    keep = []
    for document in yaml.safe_load_all(rendered):
        if document and document.get("metadata", {}).get("name") == name and document["kind"] in (
                "ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding"):
            if document["kind"] == "ValidatingAdmissionPolicyBinding" and "paramRef" in document["spec"]:
                document["spec"]["paramRef"]["namespace"] = SERVER
            keep.append(document)
    if len(keep) != 2:
        sys.exit(f"expected {name} and its binding, found {len(keep)}")
    return keep


def load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


def pod(t: dict) -> dict:
    return t["spec"]["podTemplate"]["spec"]


def container(t: dict, name: str, field: str = "containers") -> dict:
    return next(c for c in pod(t)[field] if c["name"] == name)


def tun(t: dict) -> dict:
    return container(t, "hosted-egress-tun", "initContainers")


def egress(t: dict) -> list:
    return t["spec"]["networkPolicy"]["egress"]


def peer_rule(t: dict, component: str) -> dict:
    return next(r for r in egress(t) if any(
        p.get("podSelector", {}).get("matchLabels", {}).get("app.kubernetes.io/component") == component
        for p in r["to"]))


def mutate(template: dict, *changes: Callable[[dict], object]) -> dict:
    copied = copy.deepcopy(template)
    for change in changes:
        change(copied)
    return copied


def setting(path: Callable[[dict], dict], key: str, value: object) -> Callable[[dict], object]:
    return lambda t: path(t).__setitem__(key, value)


def security(t: dict, name: str, field: str = "containers") -> dict:
    return container(t, name, field).setdefault("securityContext", {})


def move_mount_after_tun(t: dict) -> None:
    inits = pod(t)["initContainers"]
    mount = container(t, "mount-workspace", "initContainers")
    inits.remove(mount)
    inits.insert(inits.index(tun(t)) + 1, mount)


def tun_to_containers(t: dict) -> None:
    moved = tun(t)
    pod(t)["initContainers"].remove(moved)
    pod(t)["containers"].append(moved)


def other_repository(t: dict) -> None:
    for c in pod(t)["initContainers"] + pod(t)["containers"]:
        if c["image"].startswith(REPOSITORY + "@"):
            c["image"] = OTHER_IMAGE
    for volume in pod(t)["volumes"]:
        if volume["name"] == "codewire-bin":
            volume["image"]["reference"] = OTHER_IMAGE


def drop_label_add_world(t: dict) -> None:
    del t["spec"]["podTemplate"]["metadata"]["labels"]["codewire.sh/egress"]
    egress(t).append(copy.deepcopy(WORLD))


def kbs_rule(t: dict) -> dict:
    return next(r for r in egress(t) if all("podSelector" not in p for p in r["to"]))


def with_kbs(t: dict) -> None:
    egress(t).append({"ports": [{"port": 8080, "protocol": "TCP"}], "to": [
        {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "codewire-trustee"}}}]})


def kbs_pods(t: dict, labels: dict[str, str], namespace: str = "codewire-trustee") -> None:
    """The KBS rule narrowed to the key broker's Pods, as orchestration
    renders it when SANDBOX_KATA_COCO_KBS_PEER is set."""
    kbs_rule(t)["to"][0] = {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": namespace}},
                            "podSelector": {"matchLabels": dict(labels)}}


def labelled_kbs_cases(conf_broker: dict, env_broker: dict) -> list[tuple[str, dict, str | None]]:
    """With kbsPeer carrying the key broker's Pod labels, the confidential
    rule must name exactly them, and a namespace-only rule no longer passes."""
    def drop_one(labels: dict[str, str]) -> dict[str, str]:
        return {k: v for k, v in labels.items() if k != "app"}
    return [
        ("labelled kbsPeer, confidential: exactly the key broker's Pods", mutate(
            conf_broker, lambda t: kbs_pods(t, KBS_PODS)), None),
        ("labelled kbsPeer, confidential: namespace-only", conf_broker, EGRESS),
        ("labelled kbsPeer, confidential: one label missing", mutate(
            conf_broker, lambda t: kbs_pods(t, drop_one(KBS_PODS))), EGRESS),
        ("labelled kbsPeer, confidential: an extra label", mutate(
            conf_broker, lambda t: kbs_pods(t, KBS_PODS | {"extra": "x"})), EGRESS),
        ("labelled kbsPeer, confidential: a label's value changed", mutate(
            conf_broker, lambda t: kbs_pods(t, KBS_PODS | {"app": "attestation-service"})), EGRESS),
        ("labelled kbsPeer, confidential: the Pods in another namespace", mutate(
            conf_broker, lambda t: kbs_pods(t, KBS_PODS, "kube-system")), EGRESS),
        ("labelled kbsPeer, confidential: the Pods on another port", mutate(
            conf_broker, lambda t: kbs_pods(t, KBS_PODS), lambda t: kbs_rule_with_pods(t)["ports"][0].__setitem__(
                "port", 443)), EGRESS),
        ("labelled kbsPeer, environment: the labelled KBS rule under commodity", mutate(
            env_broker, with_kbs, lambda t: kbs_pods(t, KBS_PODS)), EGRESS),
    ]


def kbs_rule_with_pods(t: dict) -> dict:
    return next(r for r in egress(t) if any(p.get("podSelector", {}).get("matchLabels") == KBS_PODS for p in r["to"]))


def pinned(t: dict) -> dict:
    """The commodity environment goldens render a tagged daemon image (their
    test options name one). A deployment gives every template the same daemon
    image, the one the pool policy already holds to a digest, so the proof
    pins it as a deployment does."""
    tagged = REPOSITORY + ":golden"
    digest = REPOSITORY + "@sha256:" + "2" * 64
    return json.loads(json.dumps(t).replace(json.dumps(tagged), json.dumps(digest)))


def environment_cases(env_today: dict, env_broker: dict, conf_today: dict, conf_broker: dict,
                      broker: dict) -> list[tuple[str, dict | None, str, dict, str | None]]:
    """Per-environment templates (#5002): the broker arm holds them as it
    holds the pool, and only a confidential one names its KBS."""
    return [
        ("off, environment: today's golden", OFF, "create", env_today, None),
        ("off, confidential: today's golden", OFF, "create", conf_today, None),
        ("off, environment: the broker golden", OFF, "create", env_broker, GATE),
        ("on, environment: the broker golden", ON, "create", env_broker, None),
        ("on, confidential: the broker golden", ON, "create", conf_broker, None),
        ("on, environment: today's golden", ON, "create", env_today, GATE),
        ("on, confidential: today's golden", ON, "create", conf_today, GATE),
        ("on, environment: the label removed, with world egress", ON, "create",
         mutate(env_broker, drop_label_add_world), GATE),
        ("on, environment: the world rule added", ON, "create",
         mutate(env_broker, lambda t: egress(t).append(copy.deepcopy(WORLD))), EGRESS),
        ("on, environment: cluster DNS", ON, "create", mutate(
            env_broker, setting(pod, "dnsPolicy", "ClusterFirst"), lambda t: pod(t).pop("dnsConfig")), RESOLVER),
        ("on, environment: the broker label under runc", ON, "create",
         mutate(env_broker, setting(pod, "runtimeClassName", "runc")), TUN),
        ("on, environment: the KBS rule under commodity", ON, "create", mutate(env_broker, with_kbs), EGRESS),
        ("on, confidential: the KBS rule under commodity", ON, "create",
         mutate(conf_broker, setting(pod, "runtimeClassName", "commodity")), EGRESS),
        ("on, pool: the KBS rule", ON, "create", mutate(broker, with_kbs), EGRESS),
        ("on, confidential: the KBS in another namespace", ON, "create", mutate(conf_broker, lambda t: kbs_rule(t)[
            "to"][0]["namespaceSelector"]["matchLabels"].__setitem__("kubernetes.io/metadata.name", "kube-system")),
         EGRESS),
        ("on, confidential: the KBS on another port", ON, "create",
         mutate(conf_broker, lambda t: kbs_rule(t)["ports"][0].__setitem__("port", 443)), EGRESS),
        ("on, confidential: the KBS on a second port", ON, "create",
         mutate(conf_broker, lambda t: kbs_rule(t)["ports"].append({"port": 443, "protocol": "TCP"})), EGRESS),
        ("on, confidential: the KBS narrowed to Pods", ON, "create", mutate(conf_broker, lambda t: kbs_rule(t)[
            "to"][0].__setitem__("podSelector", {"matchLabels": {"app": "kbs"}})), EGRESS),
        ("on, confidential: the KBS as an address range", ON, "create", mutate(conf_broker, lambda t: kbs_rule(t)[
            "to"].__setitem__(0, {"ipBlock": {"cidr": "10.0.0.0/8"}})), EGRESS),
        ("on, confidential: the TUN init from another image than the daemon init", ON, "create", mutate(
            conf_broker, lambda t: container(t, "codewire-daemon-init", "initContainers").__setitem__(
                "image", REPOSITORY + "@sha256:" + "3" * 64)), TUN),
        ("on, confidential: a second namespace-only peer", ON, "create", mutate(conf_broker, lambda t: egress(t).append(
            copy.deepcopy(kbs_rule(t)) | {"to": [{"namespaceSelector": {"matchLabels": {
                "kubernetes.io/metadata.name": "kube-system"}}}]})), EGRESS),
    ]


def sandbox(labels: dict[str, str], runtime_class: str | None = None, mode: str | None = None) -> dict:
    spec: dict = {"containers": [{"name": "workspace", "image": "busybox"}]}
    if runtime_class is not None:
        spec["runtimeClassName"] = runtime_class
    document = {"apiVersion": "agents.x-k8s.io/v1beta1", "kind": "Sandbox",
                "metadata": {"name": "broker-mode-proof", "namespace": SANDBOXES},
                "spec": {"podTemplate": {"metadata": {"labels": labels}, "spec": spec}}}
    if mode is not None:
        document["spec"]["operatingMode"] = mode
    return document


def sandbox_change(cluster: "Cluster", before: dict, change: Callable[[dict], object],
                   param: dict[str, str] | None = None, identity: str = AS,
                   creator: str | None = None) -> str | None:
    """With the switch at `param`, create `before` as `creator` (None, the
    default, is the cluster's administrator, whom the member policy does not
    match, so any stored shape can be the starting point, as with Sandboxes
    the controller made before a rule; orchestration never creates one),
    apply `change` to the stored Sandbox and update it as `identity`, then
    delete it. A missing param denies the create too, so that case creates
    with the switch on and then removes it."""
    cluster.param(ON if param is None else param)
    create_as = [f"--as={creator}"] if creator else []
    stored = cluster.kubectl("create", *create_as, "-f", "-", stdin=json.dumps(before))
    if stored.returncode != 0:
        return "create failed: " + stored.stderr.strip()
    if param is None:
        cluster.param(None)
    name = before["metadata"]["name"]
    live = json.loads(cluster.kubectl("get", "sandbox", name, "-n", SANDBOXES, "-o", "json").stdout)
    change(live)
    denial = cluster.admit("replace", live, identity)
    cluster.kubectl("delete", "sandbox", name, "-n", SANDBOXES, "--wait=true")
    return denial

def without_tun(t: dict) -> None:
    # mount-workspace goes too, as in "on: no TUN init": without the TUN init
    # its required place before it fails the privilege rule first.
    pod(t)["initContainers"] = [c for c in pod(t)["initContainers"]
                                if c["name"] not in ("hosted-egress-tun", "mount-workspace")]


def disk_reference(t: dict) -> str:
    return next(v["image"]["reference"] for v in pod(t)["volumes"] if v["name"] == "image-disk")


def with_disk(reference: str) -> dict:
    """Hosted egress on, with the deployment's standard disk named (#5602)."""
    return ON | {DISK_KEY: reference}


def set_disk(reference: str) -> Callable[[dict], object]:
    return lambda t: [v["image"].__setitem__("reference", reference)
                      for v in pod(t)["volumes"] if v["name"] == "image-disk"]


def standard_cases(standard: dict, env_broker: dict,
                   broker: dict) -> list[tuple[str, dict | None, str, dict, str | None]]:
    """A `standard` template (#5602) runs its VM in its one container, with
    no TUN init and no TUN device, and only a per-environment template may."""
    on = with_disk(disk_reference(standard))
    return [
        ("off, standard: the golden", OFF | {DISK_KEY: disk_reference(standard)}, "create", standard, GATE),
        ("on, standard: the golden", on, "create", standard, None),
        ("on, standard: a TUN init added", on, "create", mutate(standard, lambda t: pod(t).__setitem__(
            "initContainers", [copy.deepcopy(tun(env_broker))])), TUN),
        ("on, standard: the TUN device's volume added", on, "create", mutate(standard, lambda t: pod(t)[
            "volumes"].append(copy.deepcopy(devnet(env_broker)))), DEVNET),
        # The disk is the deployment's, by exact reference, and none is
        # admitted while the parameter names none (#5602).
        ("on, standard: no disk named", ON, "create", standard, DISK),
        ("on, standard: an empty disk named", ON | {DISK_KEY: ""}, "create", standard, DISK),
        ("on, standard: a disk named by tag", ON | {DISK_KEY: "registry.example.invalid/codewire/workspace-disk:1"},
         "create", standard, DISK),
        ("on, standard: another disk digest", on, "create", mutate(standard, set_disk(OTHER_DISK)), DISK),
        ("on, standard: the disk by tag", on, "create",
         mutate(standard, set_disk("registry.example.invalid/codewire/workspace-disk:1")), DISK),
        ("on, standard: a second image", on, "create", mutate(standard, lambda t: pod(t)["volumes"].append(
            {"name": "codewire-bin", "image": {"reference": OTHER_IMAGE, "pullPolicy": "IfNotPresent"}})), DISK),
        ("on, environment: a broker template with no disk named", ON, "create", env_broker, None),
        ("on, environment: the broker golden without its TUN init", ON, "create",
         mutate(env_broker, without_tun), TUN),
        ("on, pool: the broker golden under standard without its TUN init", ON, "create",
         mutate(broker, setting(pod, "runtimeClassName", "standard"), without_tun), STANDARD_POOL),
        # The egress mode: the binding listener waives the guest's self-check
        # only for `broker`, so only a standard template's workspace sets it,
        # once, to one of its two values.
        ("on, standard: broker mode", on, "create", mutate(standard, egress_mode("broker")), None),
        ("on, standard: no egress mode", on, "create", mutate(standard, egress_mode(None)), EGRESS_MODE),
        ("on, standard: another egress mode", on, "create", mutate(standard, egress_mode("open")), EGRESS_MODE),
        # A second entry of the same name never reaches this policy: the
        # SandboxTemplate CRD's schema keys env by name, so the API server
        # refuses it as a duplicate value first. (A core Pod only warns; the
        # class's Kyverno rule refuses that one.)
        ("on, standard: the egress mode from a source", on, "create", mutate(standard, egress_mode(None), lambda t: env(t).append(
            {"name": "CODEWIRE_VM_EGRESS_MODE", "valueFrom": {"fieldRef": {"fieldPath": "metadata.name"}}})), EGRESS_MODE),
        ("on, environment: a Kata broker template with an egress mode", ON, "create", mutate(env_broker, lambda t: env(t).append(
            {"name": "CODEWIRE_VM_EGRESS_MODE", "value": "broker"})), EGRESS_MODE),
    ]


def standard_pool_cases(spool: dict, broker: dict) -> list[tuple[str, dict | None, str, dict, str | None]]:
    """A `standard` pool template (#5602) is admitted only in the standard
    shape: one workspace container, its workspace disk the one image volume,
    mounted read-only, the kvm device, a new VM, a literal first process, its
    VM settings as literals and its egress mode guest-carried."""
    disk = next(v for v in pod(spool)["volumes"] if "image" in v)
    support = {"name": "codewire-bin", "image": {"reference": OTHER_IMAGE, "pullPolicy": "IfNotPresent"}}

    def disk_mount(t: dict) -> dict:
        return next(m for m in container(t, "workspace")["volumeMounts"] if m["name"] == disk["name"])

    def set_env(name: str, value: str) -> Callable[[dict], object]:
        return lambda t: [e.__setitem__("value", value) for e in env(t) if e["name"] == name]

    on = with_disk(disk_reference(spool))
    return [
        ("off, standard pool: the golden", OFF, "create", spool, ENVIRONMENT),
        ("on, standard pool: the golden", on, "create", spool, None),
        ("on, standard pool: no disk named", ON, "create", spool, DISK),
        ("on, standard pool: another disk digest", on, "create", mutate(spool, set_disk(OTHER_DISK)), DISK),
        ("on, standard pool: a second image volume", on, "create",
         mutate(spool, lambda t: pod(t)["volumes"].append(copy.deepcopy(support))), STANDARD_POOL),
        ("on, standard pool: the disk mounted read-write", on, "create",
         mutate(spool, lambda t: disk_mount(t).__setitem__("readOnly", False)), STANDARD_POOL),
        ("on, standard pool: no kvm device", on, "create",
         mutate(spool, lambda t: container(t, "workspace")["resources"]["limits"].pop("codewire.sh/kvm")), STANDARD_POOL),
        ("on, standard pool: an existing VM", on, "create",
         mutate(spool, set_env("CODEWIRE_VM_STATE", "existing")), STANDARD_POOL),
        ("on, standard pool: another first process", on, "create",
         mutate(spool, set_env("CODEWIRE_WORKSPACE_INIT", "shell")), STANDARD_POOL),
        ("on, standard pool: a second container", on, "create",
         mutate(spool, lambda t: pod(t)["containers"].append({"name": "sidecar", "image": OTHER_IMAGE})), STANDARD_POOL),
        ("on, standard pool: an init container", on, "create",
         mutate(spool, lambda t: pod(t).__setitem__("initContainers", [{"name": "prepare", "image": OTHER_IMAGE}])),
         STANDARD_POOL),
        ("on, standard pool: broker egress mode", on, "create", mutate(spool, egress_mode("broker")), EGRESS_MODE),
        ("on, standard pool: no egress mode", on, "create", mutate(spool, egress_mode(None)), EGRESS_MODE),
        ("on, standard pool: an unknown VM setting", on, "create",
         mutate(spool, lambda t: env(t).append({"name": "CODEWIRE_VM_DEBUG", "value": "1"})), ENVIRONMENT),
        ("on, standard pool: a VM setting from a source", on, "create",
         mutate(spool, lambda t: [e.pop("value") or e.__setitem__("valueFrom", {"fieldRef": {"fieldPath": "metadata.name"}})
                                  for e in env(t) if e["name"] == "CODEWIRE_VM_VCPUS"]), ENVIRONMENT),
        ("on, commodity pool: a VM setting", ON, "create",
         mutate(broker, lambda t: env(t).append({"name": "CODEWIRE_VM_STATE", "value": "new"})), ENVIRONMENT),
    ]


def env(t: dict) -> list[dict]:
    return container(t, "workspace")["env"]


def egress_mode(value: str | None) -> Callable[[dict], object]:
    """Sets the workspace container's egress mode, or removes it with None."""
    def change(t: dict) -> None:
        kept = [e for e in env(t) if e["name"] != "CODEWIRE_VM_EGRESS_MODE"]
        if value is not None:
            kept.append({"name": "CODEWIRE_VM_EGRESS_MODE", "value": value})
        container(t, "workspace")["env"] = kept
    return change


def sandbox_update(cluster: "Cluster", before: dict[str, str], after: dict[str, str]) -> str | None:
    """Create a Sandbox with `before` as its pod labels, update it to `after`
    as orchestration with hosted egress on, then delete it."""
    return sandbox_change(cluster, sandbox(before),
                          lambda s: s["spec"]["podTemplate"]["metadata"].__setitem__("labels", after), ON)


def labels(s: dict) -> dict:
    return s["spec"]["podTemplate"]["metadata"]["labels"]


def mode(value: str) -> Callable[[dict], object]:
    return lambda s: s["spec"].__setitem__("operatingMode", value)


def pre_switch_cases(cluster: "Cluster") -> list[bool]:
    """codewire#4000: with the switch on, a VM Sandbox made before it is
    only stopped, never started or changed, and broker mode is never added
    by a label alone (move_cases has the whole move)."""
    plain = {"codewire.sh/type": "workspace"}
    broker_label = plain | {"codewire.sh/egress": "broker"}
    def repin(s: dict) -> None:
        s["spec"]["podTemplate"]["spec"]["containers"][0]["image"] = "busybox:1.37"
    def add_broker(s: dict) -> None:
        labels(s)["codewire.sh/egress"] = "broker"
    # A broker-mode Sandbox as create makes it: the label with its fence
    # revision and TUN init. The label alone is a hollow one, made before.
    whole = sandbox(broker_label, "commodity", "Running")
    whole["spec"]["podTemplate"]["metadata"]["annotations"] = {"codewire.sh/egress-fence-revision": ON["CODEWIRE_HOSTED_EGRESS_FENCE_REVISION"]}
    whole["spec"]["podTemplate"]["spec"]["initContainers"] = [{"name": "hosted-egress-tun", "image": "busybox"}]
    # A standard Sandbox mounts the deployment's disk (#5602).
    standard = sandbox(plain, "standard", "Suspended")
    standard["spec"]["podTemplate"]["spec"]["volumes"] = [{"name": "image-disk", "image": {"reference": OTHER_DISK}}]
    results = []
    for name, before, change, param, expected in [
        ("on, Sandbox: a pre-switch commodity one started", sandbox(plain, "commodity", "Suspended"),
         mode("Running"), ON, PRE_SWITCH),
        ("on, Sandbox: a pre-switch commodity one changed while running", sandbox(plain, "commodity", "Running"),
         lambda s: labels(s).__setitem__("x", "y"), ON, PRE_SWITCH),
        ("on, Sandbox: a pre-switch standard one started", standard,
         mode("Running"), with_disk(OTHER_DISK), PRE_SWITCH),
        ("on, Sandbox: a pre-switch confidential one started", sandbox(plain, "confidential", "Suspended"),
         mode("Running"), ON, PRE_SWITCH),
        ("on, Sandbox: a pre-switch commodity one moved to runc and started", sandbox(plain, "commodity", "Suspended"),
         lambda s: (mode("Running")(s), s["spec"]["podTemplate"]["spec"].__setitem__("runtimeClassName", "runc")),
         ON, PRE_SWITCH),
        ("on, Sandbox: a pre-switch commodity one stopped", sandbox(plain, "commodity", "Running"),
         mode("Suspended"), ON, None),
        ("on, Sandbox: a broker commodity one re-pinned", whole, repin, ON, None),
        ("on, Sandbox: a hollow broker commodity one re-pinned", sandbox(broker_label, "commodity", "Running"),
         repin, ON, PRE_SWITCH),
        ("off, Sandbox: a pre-switch commodity one started", sandbox(plain, "commodity", "Suspended"),
         mode("Running"), OFF, None),
        ("on, Sandbox: a pre-switch runc one started", sandbox(plain, "runc", "Suspended"),
         mode("Running"), ON, None),
        # Any class but runc or none is a VM, one admission does not know
        # included, so the rule fails closed.
        ("on, Sandbox: a pre-switch one under an unknown class started", sandbox(plain, "another-vm", "Suspended"),
         mode("Running"), ON, PRE_SWITCH),
        ("on, Sandbox: a pre-switch one with no runtime class started", sandbox(plain, None, "Suspended"),
         mode("Running"), ON, None),
        ("on, Sandbox: only the broker label added to a running commodity one",
         sandbox(plain, "commodity", "Running"), add_broker, ON, LABEL_ONLY),
        ("on, Sandbox: only the broker label added to a stopped commodity one bound to no environment",
         sandbox(plain, "commodity", "Suspended"), add_broker, ON, LABEL_ONLY),
        ("missing param: a Sandbox update", sandbox(plain, "commodity", "Suspended"),
         mode("Running"), None, NO_PARAM),
    ]:
        results.append(check(name, sandbox_change(cluster, before, change, param), expected))
    return results


def moved_sandbox(template: dict, mode: str = "Suspended", bound: bool = True,
                  pool_member: bool = False) -> dict:
    """A Sandbox built from `template`'s pod template, as a create made it,
    bound to an environment as a claim's adoption labels it."""
    pod_template = copy.deepcopy(template["spec"]["podTemplate"])
    if bound:
        pod_template["metadata"].setdefault("labels", {})["codewire.sh/environment-id"] = ENVIRONMENT_ID
    document = {"apiVersion": "agents.x-k8s.io/v1beta1", "kind": "Sandbox",
                "metadata": {"name": "broker-mode-proof", "namespace": SANDBOXES},
                "spec": {"operatingMode": mode, "podTemplate": pod_template}}
    if pool_member:
        document["metadata"]["labels"] = {"agents.x-k8s.io/warm-pool-sandbox": "cw-pool-proof"}
    return document


TEMPLATE_REF_HASH = "agents.x-k8s.io/sandbox-template-ref-hash"
CLAIM_UID_LABEL = "agents.x-k8s.io/claim-uid"


def pool_born_sandbox(pool_template: dict) -> dict:
    """A Sandbox adopted from a shared pool before the switch, as Dev has
    them: named for its pool, built from the pool's direct template and
    labelled with that template's reference, bound to an environment."""
    document = moved_sandbox(pool_template)
    document["metadata"]["name"] = pool_template["metadata"]["name"] + "-bhlxf"
    document["metadata"]["labels"] = {TEMPLATE_REF_HASH: "3c6b81b3", "agents.x-k8s.io/launch-type": "warm"}
    labels(document).update({TEMPLATE_REF_HASH: "3c6b81b3", CLAIM_UID_LABEL: "claim-proof"})
    return document


def hollow_sandbox(template: dict) -> dict:
    """A bound, stopped Sandbox with the broker label and nothing else of the
    broker shape: no fence revision annotation and no TUN init."""
    document = moved_sandbox(template)
    labels(document)["codewire.sh/egress"] = "broker"
    document["spec"]["podTemplate"]["metadata"].get("annotations", {}).pop("codewire.sh/egress-fence-revision", None)
    return document


def onto_own_template(s: dict) -> None:
    """The label that selects the moved Sandbox by its environment's own
    template, on the Sandbox and its pod template."""
    s["metadata"]["labels"][TEMPLATE_REF_HASH] = "7e41d0a2"
    labels(s)[TEMPLATE_REF_HASH] = "7e41d0a2"


def move_to(template: dict, *changes: Callable[[dict], object]) -> Callable[[dict], object]:
    """A start's move: the stored Sandbox's pod template becomes `template`'s,
    keeping the Sandbox's own labels, then `changes` apply to the Sandbox."""
    def change(s: dict) -> None:
        kept = s["spec"]["podTemplate"]["metadata"].get("labels", {})
        s["spec"]["podTemplate"] = copy.deepcopy(template["spec"]["podTemplate"])
        s["spec"]["podTemplate"]["metadata"]["labels"] = kept | s["spec"]["podTemplate"]["metadata"]["labels"]
        for each in changes:
            each(s)
    return change


def move_cases(cluster: "Cluster", env_today: dict, env_broker: dict, pool_today: dict) -> list[bool]:
    """codewire#4000, cw-security's conditions on a start's move to broker
    mode: only the whole broker shape, with the switch on, by orchestration,
    to a Sandbox bound to an environment and suspended before and after; and
    what it adds passes every broker check a created template does."""
    def annotations(s: dict) -> dict:
        return s["spec"]["podTemplate"]["metadata"]["annotations"]
    whole = move_to(env_broker)
    results = []
    for name, before, change, param, identity, creator, expected in [
        ("on, Sandbox: a stopped one moved to the whole broker shape",
         moved_sandbox(env_today), whole, ON, AS, None, None),
        ("on, Sandbox: only the broker label added to a stopped bound one",
         moved_sandbox(env_today), lambda s: labels(s).__setitem__("codewire.sh/egress", "broker"), ON, AS, None,
         LABEL_ONLY),
        # Without its TUN init or its fence revision the label goes on alone.
        ("on, Sandbox: a move without the TUN init", moved_sandbox(env_today), move_to(env_broker, without_tun),
         ON, AS, None, LABEL_ONLY),
        ("on, Sandbox: a move without the resolver", moved_sandbox(env_today),
         move_to(env_broker, setting(pod, "dnsPolicy", "ClusterFirst"), lambda s: pod(s).pop("dnsConfig")),
         ON, AS, None, RESOLVER),
        ("on, Sandbox: the whole shape and a host path", moved_sandbox(env_today), move_to(env_broker, lambda s: pod(
            s)["volumes"].append({"name": "host", "hostPath": {"path": "/"}})), ON, AS, None, HOST),
        ("on, Sandbox: the whole shape and the host network", moved_sandbox(env_today),
         move_to(env_broker, setting(pod, "hostNetwork", True)), ON, AS, None, HOST),
        ("on, Sandbox: the whole shape and a privileged container", moved_sandbox(env_today), move_to(
            env_broker, lambda s: container(s, "workspace").__setitem__("securityContext", {"privileged": True})),
         ON, AS, None, PRIVILEGE),
        ("on, Sandbox: the whole shape and an added capability", moved_sandbox(env_today), move_to(
            env_broker, lambda s: container(s, "workspace").__setitem__(
                "securityContext", {"capabilities": {"add": ["NET_ADMIN"]}})), ON, AS, None, PRIVILEGE),
        ("on, Sandbox: the whole shape and an extra nameserver", moved_sandbox(env_today), move_to(
            env_broker, lambda s: pod(s)["dnsConfig"]["nameservers"].append("10.44.0.10")), ON, AS, None, RESOLVER),
        ("on, Sandbox: the whole shape under another fence revision", moved_sandbox(env_today), move_to(
            env_broker, lambda s: annotations(s).__setitem__("codewire.sh/egress-fence-revision", "1")),
         ON, AS, None, FENCE),
        ("on, Sandbox: the whole shape with no fence revision", moved_sandbox(env_today), move_to(
            env_broker, lambda s: annotations(s).pop("codewire.sh/egress-fence-revision")), ON, AS, None, LABEL_ONLY),
        ("off, Sandbox: a stopped one moved to the whole broker shape",
         moved_sandbox(env_today), whole, OFF, AS, None, MOVE),
        ("on, Sandbox: a running one moved", moved_sandbox(env_today, mode="Running"), whole, ON, AS, None, MOVE),
        ("on, Sandbox: a stopped one moved and started in one update",
         moved_sandbox(env_today), move_to(env_broker, mode("Running")), ON, AS, None, MOVE),
        ("on, Sandbox: a stopped one bound to no environment moved",
         moved_sandbox(env_today, bound=False), whole, ON, AS, None, MOVE),
        ("on, Sandbox: a move that changes the environment", moved_sandbox(env_today), move_to(
            env_broker, lambda s: labels(s).__setitem__("codewire.sh/environment-id", "another")), ON, AS, None, MOVE),
        ("on, Sandbox: the move by another identity", moved_sandbox(env_today), whole, ON, OTHER, None, WRITER),
        ("off, Sandbox: broker mode added by another identity", moved_sandbox(env_today), whole, OFF, OTHER, None,
         WRITER),
        ("on, Sandbox: an unclaimed pool member moved", moved_sandbox(env_today, pool_member=True), whole,
         ON, AS, None, POOL_MEMBER),
        ("on, Sandbox: another identity changes a broker one", moved_sandbox(env_broker),
         lambda s: labels(s).__setitem__("x", "y"), ON, OTHER, None, None),
        # A pool-born Sandbox (every one on Dev) moves onto its environment's
        # own template: the whole shape and the new template reference in
        # one update, under its cw-pool- name.
        ("on, Sandbox: a pool-born one moved onto its own template", pool_born_sandbox(pool_today),
         move_to(env_broker, onto_own_template), ON, AS, None, None),
        ("on, Sandbox: a pool-born one given only the label and its own template reference",
         pool_born_sandbox(pool_today), lambda s: (labels(s).__setitem__("codewire.sh/egress", "broker"),
                                                   onto_own_template(s)), ON, AS, None, LABEL_ONLY),
        # The controller, holding the Sandbox to its Claim's new template
        # before orchestration's patch, may not add the label on its own.
        ("on, Sandbox: the controller giving a pool-born one its new template's labels",
         pool_born_sandbox(pool_today), lambda s: (labels(s).__setitem__("codewire.sh/egress", "broker"),
                                                   onto_own_template(s)), ON, OTHER, None, WRITER),
        ("on, Sandbox: a pool-born one moved while running", pool_born_sandbox(pool_today) | {"spec": dict(
            pool_born_sandbox(pool_today)["spec"], operatingMode="Running")},
         move_to(env_broker, onto_own_template), ON, AS, None, MOVE),
        # codewire#6033: a move is held to the CODEWIRE_VM_EGRESS_MODE rule:
        # only a standard environment's workspace container sets it.
        ("on, Sandbox: a move that sets CODEWIRE_VM_EGRESS_MODE on the DinD container", moved_sandbox(env_today),
         move_to(env_broker, lambda s: container(s, "dind").setdefault("env", []).append(
             {"name": "CODEWIRE_VM_EGRESS_MODE", "value": "broker"})), ON, AS, None, EGRESS_MODE),
        ("on, Sandbox: a commodity move that sets CODEWIRE_VM_EGRESS_MODE on its workspace", moved_sandbox(env_today),
         move_to(env_broker, lambda s: container(s, "workspace").setdefault("env", []).append(
             {"name": "CODEWIRE_VM_EGRESS_MODE", "value": "broker"})), ON, AS, None, EGRESS_MODE),
        # A move keeps the runtime class: never commodity to standard.
        ("on, Sandbox: a commodity one moved to the whole shape under standard", moved_sandbox(env_today),
         move_to(env_broker, setting(pod, "runtimeClassName", "standard")), ON, AS, None, CLASS),
        # A Sandbox with the broker label alone (no fence revision, no TUN
        # init), as only another writer could leave it: made before the
        # switch, so not started as it is, and moved under every broker check.
        ("on, Sandbox: a hollow one started as it is", hollow_sandbox(env_today), mode("Running"),
         ON, AS, None, PRE_SWITCH),
        ("on, Sandbox: a hollow one moved to the whole shape and a host path", hollow_sandbox(env_today),
         move_to(env_broker, lambda s: pod(s)["volumes"].append({"name": "host", "hostPath": {"path": "/"}})),
         ON, AS, None, HOST),
        ("on, Sandbox: a hollow one moved to the whole shape", hollow_sandbox(env_today), whole,
         ON, AS, None, None),
        ("on, Sandbox: another identity completing a hollow one's shape", hollow_sandbox(env_today), whole,
         ON, OTHER, None, WRITER),
    ]:
        results.append(check(name, sandbox_change(cluster, before, change, param, identity, creator), expected))
    return results


def member_run_cases(cluster: "Cluster", env_today: dict, env_broker: dict) -> list[bool]:
    """The member policy holds a Sandbox's run directory as the template
    policy holds a template's. Orchestration never creates a Sandbox, so the
    creates are dry runs as it; a Sandbox made before this, disk-backed,
    stays startable and resizable, and a start's move to broker mode, which
    writes the whole current render, passes."""
    disk = {"name": "codewire-run", "emptyDir": {}}
    host = {"name": "codewire-run", "hostPath": {"path": "/var/lib/codewire-run", "type": "DirectoryOrCreate"}}
    current = moved_sandbox(env_today)
    legacy = mutate(current, set_run(disk))

    def resize(s: dict) -> None:
        container(s, "workspace")["resources"]["limits"]["memory"] = "8192Mi"

    results = []
    cluster.param(OFF)
    for name, sandbox_object, expected in [
        ("off, Sandbox create: as rendered", current, None),
        ("off, Sandbox create: codewire-run on disk", legacy, MEMBER_RUN),
        ("off, Sandbox create: codewire-run a host path", mutate(current, set_run(host)), MEMBER_RUN),
        ("off, Sandbox create: no codewire-run", mutate(current, rename_run(None)), MEMBER_RUN),
        ("off, Sandbox create: a disk emptyDir at /codewire/run/identity",
         mutate(current, add_mounted(IDENTITY_DISK, "/codewire/run/identity")), MEMBER_RUN_MOUNT),
    ]:
        results.append(check(name, cluster.admit("create", sandbox_object), expected))
    for name, before, change, param, expected in [
        ("off, Sandbox: a disk-backed one started", legacy, mode("Running"), OFF, None),
        ("off, Sandbox: a disk-backed one resized", legacy, resize, OFF, None),
        ("off, Sandbox: a disk-backed one updated to a host path", legacy, set_run(host), OFF, MEMBER_RUN),
        ("off, Sandbox: a memory one updated to disk", current, set_run(disk), OFF, MEMBER_RUN),
        ("off, Sandbox: a disk emptyDir added at /codewire/run/identity", current,
         add_mounted(IDENTITY_DISK, "/codewire/run/identity"), OFF, MEMBER_RUN_MOUNT),
        ("on, Sandbox: a disk-backed stopped one moved to the whole broker shape", legacy,
         move_to(env_broker), ON, None),
    ]:
        results.append(check(name, sandbox_change(cluster, before, change, param), expected))
    # A snapshot's clearing Sandbox has no volumes at all, and orchestration
    # only ever suspends it (stop_clearing_pod), which keeps its run directory,
    # none, as stored; giving it one is held to the rule like any other
    # (codewire#6344).
    for block in (False, True):
        kind = "Block" if block else "Filesystem"
        clearing = clearing_sandbox(block)
        for name, change, param, expected in [
            (f"on, clearing Sandbox ({kind}): suspended", mode("Suspended"), ON, None),
            (f"off, clearing Sandbox ({kind}): suspended", mode("Suspended"), OFF, None),
            (f"off, clearing Sandbox ({kind}): a disk codewire-run added", add_volume(disk), OFF, MEMBER_RUN),
        ]:
            results.append(check(name, sandbox_change(cluster, clearing, change, param), expected))
    return results


def add_volume(volume: dict) -> Callable[[dict], object]:
    """Add `volume` to the pod's volumes, making the list if it has none."""
    return lambda s: pod(s).setdefault("volumes", []).append(copy.deepcopy(volume))


def template_change(cluster: "Cluster", before: dict, change: Callable[[dict], object],
                    param: dict[str, str]) -> str | None:
    """With the switch at `param`, create `before` as the cluster's
    administrator, whom the policy does not match, so any stored shape can
    be the starting point; apply `change` to the stored template and update
    it as orchestration, then delete it."""
    cluster.param(param)
    stored = cluster.kubectl("create", "-f", "-", stdin=json.dumps(before))
    if stored.returncode != 0:
        return "create failed: " + stored.stderr.strip()
    name, namespace = before["metadata"]["name"], before["metadata"]["namespace"]
    live = json.loads(cluster.kubectl("get", "sandboxtemplate", name, "-n", namespace, "-o", "json").stdout)
    change(live)
    denial = cluster.admit("replace", live)
    cluster.kubectl("delete", "sandboxtemplate", name, "-n", namespace, "--wait=true")
    return denial


def keep_cases(cluster: "Cluster", env_today: dict, env_broker: dict, standard: dict,
               pool_broker: dict) -> list[bool]:
    """codewire#6121, cw-security's terms: with the switch off, orchestration
    may update an environment's own template that is already whole broker,
    only to the whole broker shape again, held to every broker check as with
    the switch on, and only while the switch names a fence revision. A
    create, or an update that makes a template broker-mode, stays refused."""
    def repin(t: dict) -> None:
        container(t, "workspace")["image"] = "registry.example.invalid/codewire/workspace@sha256:" + "6" * 64

    def annotations(t: dict) -> dict:
        return t["spec"]["podTemplate"]["metadata"]["annotations"]

    def become(template: dict) -> Callable[[dict], object]:
        return lambda t: t.__setitem__("spec", copy.deepcopy(template["spec"]))

    hollow = mutate(env_broker, lambda t: annotations(t).pop("codewire.sh/egress-fence-revision"))
    no_fence = OFF_KEEPING | {"CODEWIRE_HOSTED_EGRESS_FENCE_REVISION": ""}
    results = []
    for name, before, change, param, expected in [
        ("off, keeping: an environment's broker template re-pinned", env_broker, repin, OFF_KEEPING, None),
        ("off, keeping: a standard broker template re-pinned", standard, repin, OFF_KEEPING, None),
        ("off, keeping: the fence revision dropped", env_broker,
         lambda t: (repin(t), annotations(t).pop("codewire.sh/egress-fence-revision")), OFF_KEEPING, GATE),
        ("off, keeping: the TUN init dropped", env_broker, without_tun, OFF_KEEPING, GATE),
        ("off, keeping: a host path added", env_broker,
         lambda t: pod(t)["volumes"].append({"name": "host", "hostPath": {"path": "/"}}), OFF_KEEPING, HOST),
        ("off, keeping: an extra nameserver", env_broker,
         lambda t: pod(t)["dnsConfig"]["nameservers"].append("10.44.0.10"), OFF_KEEPING, RESOLVER),
        ("off, keeping: the world rule added", env_broker,
         lambda t: egress(t).append(copy.deepcopy(WORLD)), OFF_KEEPING, EGRESS),
        ("off, keeping: a privileged workspace", env_broker,
         lambda t: security(t, "workspace").__setitem__("privileged", True), OFF_KEEPING, PRIVILEGE),
        ("off, keeping: under another fence revision", env_broker,
         lambda t: annotations(t).__setitem__("codewire.sh/egress-fence-revision", "1"), OFF_KEEPING, FENCE),
        ("off, keeping: a non-broker template made broker", env_today, become(env_broker), OFF_KEEPING, GATE),
        ("off, keeping: a hollow broker template made whole", hollow, become(env_broker), OFF_KEEPING, GATE),
        ("off, keeping: a pool's broker template re-pinned", pool_broker, repin, OFF_KEEPING, ENVIRONMENT),
        ("off, no fence setting: an environment's broker template re-pinned", env_broker, repin, no_fence, GATE),
        ("off, no settings: an environment's broker template re-pinned", env_broker, repin, OFF, GATE),
        ("on: an environment's broker template re-pinned", env_broker, repin, ON, None),
    ]:
        results.append(check(name, template_change(cluster, before, change, param), expected))
    cluster.param(OFF_KEEPING)
    results.append(check("off, keeping: the broker golden created", cluster.admit("create", env_broker), GATE))
    return results


def run_mount(t: dict, container_name: str = "workspace") -> dict:
    return next(m for m in container(t, container_name)["volumeMounts"] if m["name"] == "codewire-run")


def add_mounted(volume: dict, path: str, container_name: str = "workspace") -> Callable[[dict], object]:
    """`volume` added and mounted at `path`, by the workspace container or by
    a new sidecar of the workspace's image."""
    def change(t: dict) -> None:
        pod(t)["volumes"].append(copy.deepcopy(volume))
        mount = {"name": volume["name"], "mountPath": path}
        if container_name == "workspace":
            container(t, "workspace")["volumeMounts"].append(mount)
        else:
            pod(t)["containers"].append({"name": container_name, "image": container(t, "workspace")["image"],
                                         "volumeMounts": [mount]})
    return change


def drop_run_mount(t: dict) -> None:
    container(t, "workspace")["volumeMounts"].remove(run_mount(t))


IDENTITY_DISK = {"name": "identity-disk", "emptyDir": {}}


def run_mount_cases(today: dict, broker: dict, env_today: dict, conf_today: dict,
                    standard: dict) -> list[tuple[str, dict | None, str, dict, str | None]]:
    """The run directory's mounts: nothing else is mounted over or under
    /codewire/run, or at a path a runtime would clean onto it, and the
    workspace container mounts codewire-run at exactly /codewire/run."""
    host = {"name": "run-host", "hostPath": {"path": "/var/lib/codewire-run", "type": "DirectoryOrCreate"}}
    on_standard = with_disk(disk_reference(standard))
    return [
        ("off, environment: a disk emptyDir at /codewire/run/identity", OFF, "create",
         mutate(env_today, add_mounted(IDENTITY_DISK, "/codewire/run/identity")), RUN_MOUNT),
        ("off, environment: a host path at /codewire/run", OFF, "create",
         mutate(env_today, drop_run_mount, add_mounted(host, "/codewire/run")), RUN_MOUNT),
        ("off, pool: another volume at /codewire/run", OFF, "create",
         mutate(today, lambda t: run_mount(t).__setitem__("name", "codewire-bin")), RUN_MOUNT),
        ("off, pool: the workspace without its /codewire/run mount", OFF, "create",
         mutate(today, drop_run_mount), RUN_MOUNT),
        ("off, environment: a sidecar mounting another volume under /codewire/run", OFF, "create",
         mutate(env_today, add_mounted(IDENTITY_DISK, "/codewire/run/identity", "sidecar")), RUN_MOUNT),
        ("off, environment: a disk emptyDir at an unclean path", OFF, "create",
         mutate(env_today, add_mounted(IDENTITY_DISK, "/codewire//run/identity")), RUN_MOUNT),
        ("off, environment: codewire-run by subPath", OFF, "create",
         mutate(env_today, lambda t: run_mount(t).__setitem__("subPath", "identity")), RUN_MOUNT),
        ("off, confidential: the daemon init's codewire-run at another path", OFF, "create",
         mutate(conf_today, lambda t: next(m for m in container(t, "codewire-daemon-init", "initContainers")[
             "volumeMounts"] if m["name"] == "codewire-run").__setitem__("mountPath", "/codewire/state")), RUN_MOUNT),
        ("on, pool: the broker golden with a disk emptyDir at /codewire/run/identity", ON, "create",
         mutate(broker, add_mounted(IDENTITY_DISK, "/codewire/run/identity")), RUN_MOUNT),
        ("on, standard: a disk emptyDir at /codewire/run/identity", on_standard, "create",
         mutate(standard, add_mounted(IDENTITY_DISK, "/codewire/run/identity")), RUN_MOUNT),
    ]


def run_update_cases(cluster: "Cluster", env_today: dict, env_broker: dict) -> list[bool]:
    """A Sandbox rendered before the run directory moved to memory keeps its
    disk-backed codewire-run (docs/dev/SANDBOX-IDENTITY.md, "Memory only"):
    an update that keeps the stored template's codewire-run unchanged is
    admitted, and any other change to it is held to the rendered shape."""
    def repin(t: dict) -> None:
        container(t, "workspace")["image"] = "registry.example.invalid/codewire/workspace@sha256:" + "6" * 64

    disk = {"name": "codewire-run", "emptyDir": {}}
    host = {"name": "codewire-run", "hostPath": {"path": "/var/lib/codewire-run", "type": "DirectoryOrCreate"}}
    old_env, old_broker = mutate(env_today, set_run(disk)), mutate(env_broker, set_run(disk))
    old_mounts = mutate(env_today, add_mounted(IDENTITY_DISK, "/codewire/run/identity"))
    results = []
    for name, before, change, param, expected in [
        ("off, environment: an update keeping a disk-backed codewire-run", old_env, repin, OFF, None),
        ("on, environment: an update of a broker template keeping a disk-backed codewire-run",
         old_broker, repin, ON, None),
        ("off, environment: an update from a disk-backed codewire-run to a host path", old_env,
         set_run(host), OFF, RUN),
        ("off, environment: an update from a memory codewire-run to disk", env_today, set_run(disk), OFF, RUN),
        ("off, environment: an update removing codewire-run", env_today, rename_run(None), OFF, RUN),
        # The mounts: a stored template keeps its own, unchanged; a change is
        # held to the rendered shape.
        ("off, environment: an update keeping a stored mount under /codewire/run", old_mounts, repin, OFF, None),
        ("off, environment: an update moving a stored mount under /codewire/run", old_mounts,
         lambda t: next(m for m in container(t, "workspace")["volumeMounts"]
                        if m["name"] == "identity-disk").__setitem__("mountPath", "/codewire/run/other"), OFF, RUN_MOUNT),
        ("off, environment: an update adding a disk emptyDir at /codewire/run/identity", env_today,
         add_mounted(IDENTITY_DISK, "/codewire/run/identity"), OFF, RUN_MOUNT),
    ]:
        results.append(check(name, template_change(cluster, before, change, param), expected))
    return results


SNAPSHOT_ID = "550e8400-e29b-41d4-a716-446655440000"


def clearing_template(block: bool) -> dict:
    """A snapshot's clearing template exactly as render_clearing_template
    (crates/codewire-orchestration/src/sandbox/snapshots.rs) renders it."""
    container: dict = {
        "name": "clear", "image": REPOSITORY + "@sha256:" + "2" * 64,
        "command": (["/usr/local/bin/cw", "__snapshot-clear", "--block", "/dev/codewire-clearing",
                     "--report", "/dev/termination-log"] if block
                    else ["/usr/local/bin/cw", "__snapshot-clear", "/workspace"]),
        "resources": {"requests": {"cpu": "250m", "memory": "256Mi"}, "limits": {"cpu": "1", "memory": "512Mi"}},
        "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                            "capabilities": {"drop": ["ALL"], "add": ["DAC_OVERRIDE", "FOWNER"]},
                            "seccompProfile": {"type": "RuntimeDefault"}},
    }
    if block:
        container["volumeDevices"] = [{"name": "workspace", "devicePath": "/dev/codewire-clearing"}]
        container["terminationMessagePath"] = "/dev/termination-log"
    else:
        container["volumeMounts"] = [{"name": "workspace", "mountPath": "/workspace"}]
    claim: dict = {"accessModes": ["ReadWriteOnce"], "storageClassName": "linstor-local",
                   "resources": {"requests": {"storage": "80Gi"}},
                   "dataSource": {"apiGroup": "snapshot.storage.k8s.io", "kind": "VolumeSnapshot",
                                  "name": f"cw-snap-{SNAPSHOT_ID}-raw"}}
    if block:
        claim["volumeMode"] = "Block"
    identity = {"codewire.sh/type": "snapshot-clearing", "codewire.sh/snapshot-id": SNAPSHOT_ID}
    return {"apiVersion": "extensions.agents.x-k8s.io/v1beta1", "kind": "SandboxTemplate",
            "metadata": {"name": f"cw-snap-{SNAPSHOT_ID}-clear", "namespace": SANDBOXES, "labels": dict(identity)},
            "spec": {"podTemplate": {"metadata": {"labels": dict(identity)},
                                     "spec": {"restartPolicy": "Never", "serviceAccountName": "codewire-sandbox",
                                              "automountServiceAccountToken": False, "enableServiceLinks": False,
                                              "securityContext": {"runAsUser": 0, "runAsGroup": 0},
                                              "containers": [container], "runtimeClassName": "commodity"}},
                     "volumeClaimTemplates": [{"metadata": {"name": "workspace"}, "spec": claim}],
                     "networkPolicy": {"ingress": [], "egress": []}}}


def clearing_sandbox(block: bool) -> dict:
    """The Sandbox the controller makes from a snapshot's clearing template:
    its pod template and volume claim, under the template's name, and no
    volumes in the pod."""
    template = clearing_template(block)
    return {"apiVersion": "agents.x-k8s.io/v1beta1", "kind": "Sandbox",
            "metadata": {"name": template["metadata"]["name"], "namespace": SANDBOXES,
                         "labels": dict(template["metadata"]["labels"])},
            "spec": {"podTemplate": copy.deepcopy(template["spec"]["podTemplate"]),
                     "volumeClaimTemplates": copy.deepcopy(template["spec"]["volumeClaimTemplates"])}}


def clearing_cases() -> list[tuple[str, dict | None, str, dict, str | None]]:
    """codewire#4000: with hosted egress on, a snapshot's clearing template,
    exactly as rendered, is excepted from the broker arm's shape. A template
    that is not quite one has no exception: the run directory rule, which
    excepts only a clearing template too, comes first and reports it (#6310)."""
    filesystem, block = clearing_template(False), clearing_template(True)
    dns = {"ports": [{"port": 53, "protocol": "UDP"}], "to": [
        {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}}}]}
    return [
        ("on, clearing: Filesystem", ON, "create", filesystem, None),
        ("on, clearing: Block", ON, "create", block, None),
        ("on, clearing: an egress rule added", ON, "create",
         mutate(filesystem, lambda t: egress(t).append(dns)), RUN),
        ("on, clearing: an ingress rule added", ON, "create", mutate(block, lambda t: t["spec"]["networkPolicy"][
            "ingress"].append({"from": [{"namespaceSelector": {}}]})), RUN),
        ("on, clearing: the template's type changed", ON, "create",
         mutate(filesystem, lambda t: t["metadata"]["labels"].__setitem__("codewire.sh/type", "workspace")), RUN),
        ("on, clearing: the Pod's type changed", ON, "create", mutate(block, lambda t: t["spec"]["podTemplate"][
            "metadata"]["labels"].__setitem__("codewire.sh/type", "workspace")), RUN),
        ("on, clearing: another name", ON, "create",
         mutate(filesystem, lambda t: t["metadata"].__setitem__("name", "cw-snap-x-clear")), RUN),
        ("on, clearing: with the egress label", ON, "create", mutate(filesystem, lambda t: t["spec"]["podTemplate"][
            "metadata"]["labels"].__setitem__("codewire.sh/egress", "broker")), RUN),
        ("off, clearing: Filesystem", OFF, "create", filesystem, None),
        ("off, clearing: Block", OFF, "create", block, None),
    ]


def cases(today: dict, broker: dict) -> list[tuple[str, dict | None, str, dict, str | None]]:
    """(name, param, verb, template, expected rule or None for admitted)."""
    workspace = lambda t: security(t, "workspace")  # noqa: E731
    return [
        ("off: today's golden", OFF, "create", today, None),
        ("off: the broker golden", OFF, "create", broker, ENVIRONMENT),
        ("off: the egress label without the switch", OFF, "create",
         mutate(today, lambda t: t["spec"]["podTemplate"]["metadata"].setdefault("labels", {}).__setitem__(
             "codewire.sh/egress", "broker")), GATE),
        ("off: the broker variables without the label", OFF, "create",
         mutate(today, lambda t: container(t, "workspace")["env"].append(
             {"name": "CODEWIRE_EGRESS_STREAM_ADDR", "value": "10.44.0.89:8089"})), ENVIRONMENT),
        ("on: the broker golden", ON, "create", broker, None),
        ("on: today's golden", ON, "create", today, GATE),
        ("on: the label removed, with world egress", ON, "create", mutate(broker, drop_label_add_world), GATE),
        ("on: no egress stream address", ON, "create", mutate(broker, lambda t: container(t, "workspace").__setitem__(
            "env", [e for e in container(t, "workspace")["env"] if e["name"] != "CODEWIRE_EGRESS_STREAM_ADDR"])),
         ADDRESSES),
        ("on: no workspace binding address", ON, "create", mutate(broker, lambda t: container(t, "workspace").__setitem__(
            "env", [e for e in container(t, "workspace")["env"] if e["name"] != "CODEWIRE_WORKSPACE_BINDING_ADDR"])),
         ADDRESSES),
        ("on: an empty egress stream address", ON, "create", mutate(broker, lambda t: next(
            e for e in container(t, "workspace")["env"] if e["name"] == "CODEWIRE_EGRESS_STREAM_ADDR").__setitem__(
            "value", "")), ADDRESSES),
        ("on: cluster DNS", ON, "create", mutate(broker, setting(pod, "dnsPolicy", "ClusterFirst"),
                                                   lambda t: pod(t).pop("dnsConfig")), RESOLVER),
        ("on: a second nameserver", ON, "create",
         mutate(broker, lambda t: pod(t)["dnsConfig"]["nameservers"].append("10.43.0.10")), RESOLVER),
        ("on: a search list", ON, "create",
         mutate(broker, lambda t: pod(t)["dnsConfig"].__setitem__("searches", ["svc.cluster.local"])), RESOLVER),
        ("on: resolver options", ON, "create",
         mutate(broker, lambda t: pod(t)["dnsConfig"].__setitem__("options", [{"name": "ndots", "value": "5"}])),
         RESOLVER),
        ("on: the world rule added", ON, "create", mutate(broker, lambda t: egress(t).append(copy.deepcopy(WORLD))),
         EGRESS),
        ("on: a peer with an extra label", ON, "create", mutate(broker, lambda t: peer_rule(t, "egress")["to"][0][
            "podSelector"]["matchLabels"].__setitem__("extra", "x")), EGRESS),
        ("on: a peer with an extra port", ON, "create", mutate(broker, lambda t: peer_rule(t, "egress")["ports"].append(
            {"port": 8090, "protocol": "TCP"})), EGRESS),
        ("on: a peer with a namespace selector only", ON, "create",
         mutate(broker, lambda t: [p.pop("podSelector") for p in peer_rule(t, "egress")["to"]]), EGRESS),
        ("on: the ingress controller on 443", ON, "create", mutate(broker, lambda t: egress(t).append(
            {"ports": [{"port": 443, "protocol": "TCP"}], "to": [{
                "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}},
                "podSelector": {"matchLabels": {"app.kubernetes.io/name": "rke2-ingress-nginx"}}}]})), EGRESS),
        ("on: a privileged workspace", ON, "create", mutate(broker, lambda t: workspace(t).__setitem__(
            "privileged", True)), PRIVILEGE),
        ("on: NET_ADMIN on the workspace", ON, "create", mutate(broker, lambda t: workspace(t).__setitem__(
            "capabilities", {"add": ["NET_ADMIN"]})), PRIVILEGE),
        ("on: NET_RAW added to dind", ON, "create", mutate(broker, lambda t: security(t, "dind").__setitem__(
            "capabilities", {"add": ["NET_RAW"]})), PRIVILEGE),
        ("on: an explicitly escalating workspace", ON, "create", mutate(broker, lambda t: workspace(t).__setitem__(
            "allowPrivilegeEscalation", True)), PRIVILEGE),
        ("on: a root Pod user, the workspace setting none", ON, "create", mutate(
            broker, lambda t: pod(t)["securityContext"].__setitem__("runAsUser", 0),
            lambda t: container(t, "workspace").pop("securityContext", None)), PRIVILEGE),
        ("on: a root Pod group", ON, "create",
         mutate(broker, lambda t: pod(t)["securityContext"].__setitem__("runAsGroup", 0)), PRIVILEGE),
        ("on: the root group as a supplemental group", ON, "create",
         mutate(broker, lambda t: pod(t)["securityContext"].__setitem__("supplementalGroups", [0])), PRIVILEGE),
        ("on: mount-workspace after the TUN init", ON, "create", mutate(broker, move_mount_after_tun), PRIVILEGE),
        ("on: mount-workspace as a sidecar", ON, "create", mutate(broker, lambda t: container(
            t, "mount-workspace", "initContainers").__setitem__("restartPolicy", "Always")), PRIVILEGE),
        ("on: dind from another image", ON, "create", mutate(broker, lambda t: container(t, "dind").__setitem__(
            "image", "registry.example.invalid/other/docker@sha256:" + "5" * 64)), PRIVILEGE),
        ("on: the root TUN init as a regular container", ON, "create", mutate(broker, tun_to_containers), PRIVILEGE),
        # The real TUN init stays, so mount-workspace keeps its place before
        # it and only the TUN rule's own clause can refuse the extra container.
        ("on: an unprivileged regular container named hosted-egress-tun", ON, "create", mutate(
            broker, lambda t: pod(t)["containers"].append(
                {key: value for key, value in tun(t).items() if key != "securityContext"})), TUN),
        ("on: no TUN init", ON, "create", mutate(broker, lambda t: pod(t)["initContainers"].remove(tun(t)),
                                                 lambda t: [pod(t)["initContainers"].remove(c) for c in list(
                                                     pod(t)["initContainers"]) if c["name"] == "mount-workspace"]),
         TUN),
        ("on: the TUN init as a sidecar", ON, "create", mutate(broker, setting(tun, "restartPolicy", "Always")),
         PRIVILEGE),
        ("on: the TUN init with a mount", ON, "create", mutate(broker, setting(
            tun, "volumeMounts", [{"name": "codewire-bin", "mountPath": "/usr/local/bin"}])), TUN),
        ("on: the TUN init with a changed command", ON, "create", mutate(broker, setting(
            tun, "command", ["/codewire/bin/cw", "__hosted-egress-tun", "--owner-uid", "1000"])), TUN),
        ("on: the TUN init with arguments", ON, "create", mutate(broker, setting(tun, "args", ["--x"])), TUN),
        ("on: the TUN init with an allowed variable", ON, "create", mutate(broker, setting(
            tun, "env", [{"name": "HOME", "value": "/root"}])), TUN),
        ("on: the TUN init with LD_PRELOAD", ON, "create", mutate(broker, setting(
            tun, "env", [{"name": "LD_PRELOAD", "value": "/x.so"}])), ENVIRONMENT),
        ("on: the TUN image and the daemon volume in another repository", ON, "create",
         mutate(broker, other_repository), TUN),
        ("on: the broker label under runc", ON, "create", mutate(broker, setting(pod, "runtimeClassName", "runc")),
         RUNTIME),
        ("on: a confidential broker template", ON, "create",
         mutate(broker, setting(pod, "runtimeClassName", "confidential")), RUNTIME),
        ("on, empty repository: the broker golden", ON | {"CODEWIRE_HOSTED_EGRESS_DAEMON_REPOSITORY": ""},
         "create", broker, TUN),
        ("on, malformed repository: the broker golden",
         ON | {"CODEWIRE_HOSTED_EGRESS_DAEMON_REPOSITORY": REPOSITORY + "@sha256:" + "2" * 64}, "create", broker, TUN),
        ("missing param: today's golden", None, "create", today, NO_PARAM),
        # The TUN device's volume (#4000): memory-backed exactly as rendered,
        # and only at /dev/net in the TUN init and the workspace container.
        ("on: the TUN device's volume disk-backed", ON, "create", mutate(
            broker, lambda t: devnet(t).__setitem__("emptyDir", {"sizeLimit": "1Mi"})), DEVNET),
        ("on: the TUN device's volume larger", ON, "create", mutate(
            broker, lambda t: devnet(t).__setitem__("emptyDir", {"medium": "Memory", "sizeLimit": "1Gi"})), DEVNET),
        ("on: no TUN device's volume", ON, "create", mutate(broker, without_devnet), DEVNET),
        ("on: the TUN device's volume in dind", ON, "create", mutate(
            broker, lambda t: container(t, "dind").setdefault("volumeMounts", []).append(
                {"name": "egress-devnet", "mountPath": "/dev/net"})), DEVNET),
        ("on: the TUN device's volume at another path", ON, "create", mutate(
            broker, lambda t: devnet_mount(container(t, "workspace")).__setitem__("mountPath", "/dev")), DEVNET),
        ("on: the TUN device's volume with a subPath", ON, "create", mutate(
            broker, lambda t: devnet_mount(container(t, "workspace")).__setitem__("subPath", "x")), DEVNET),
        ("off: the TUN device's volume without the switch", OFF, "create", mutate(
            today, lambda t: pod(t)["volumes"].append(
                {"name": "egress-devnet", "emptyDir": {"medium": "Memory", "sizeLimit": "1Mi"}})), DEVNET),
    ]


def devnet(t: dict) -> dict:
    return next(v for v in pod(t)["volumes"] if v["name"] == "egress-devnet")


def set_run(volume: dict) -> Callable[[dict], object]:
    """Replace the daemon's run directory with `volume`, in its place."""
    return lambda t: [pod(t)["volumes"].__setitem__(i, copy.deepcopy(volume))
                      for i, v in enumerate(pod(t)["volumes"]) if v["name"] == "codewire-run"]


def rename_run(name: str | None) -> Callable[[dict], object]:
    """The run directory renamed with its mounts, or with None removed with
    them, so the template is otherwise whole."""
    def renamed(items: list[dict]) -> list[dict]:
        return [item | {"name": name} if item["name"] == "codewire-run" else item
                for item in items if item["name"] != "codewire-run" or name is not None]

    def change(t: dict) -> None:
        for c in pod(t)["containers"] + pod(t).get("initContainers", []):
            if "volumeMounts" in c:
                c["volumeMounts"] = renamed(c["volumeMounts"])
        pod(t)["volumes"] = renamed(pod(t)["volumes"])
    return change


def run_cases(today: dict, broker: dict, env_today: dict, conf_today: dict,
              standard: dict) -> list[tuple[str, dict | None, str, dict, str | None]]:
    """The daemon's run directory (docs/dev/SANDBOX-IDENTITY.md, "Memory
    only"): exactly one emptyDir with medium Memory and sizeLimit 16Mi on
    every template, pooled or not, on every runtime. The clearing template,
    which has none, is admitted in clearing_cases."""
    disk = {"name": "codewire-run", "emptyDir": {}}
    unbounded = {"name": "codewire-run", "emptyDir": {"medium": "Memory"}}
    host = {"name": "codewire-run", "hostPath": {"path": "/var/lib/codewire-run", "type": "DirectoryOrCreate"}}
    claim = {"name": "codewire-run", "persistentVolumeClaim": {"claimName": "codewire-run"}}
    on_standard = with_disk(disk_reference(standard))
    return [
        ("off, pool: codewire-run on disk", OFF, "create", mutate(today, set_run(disk)), RUN),
        ("off, pool: codewire-run in memory without a size limit", OFF, "create", mutate(today, set_run(unbounded)), RUN),
        ("off, pool: codewire-run larger", OFF, "create", mutate(today, set_run(
            {"name": "codewire-run", "emptyDir": {"medium": "Memory", "sizeLimit": "64Mi"}})), RUN),
        ("off, pool: codewire-run sized on disk", OFF, "create", mutate(today, set_run(
            {"name": "codewire-run", "emptyDir": {"sizeLimit": "16Mi"}})), RUN),
        ("off, pool: codewire-run a host path", OFF, "create", mutate(today, set_run(host)), RUN),
        ("off, pool: codewire-run a volume claim", OFF, "create", mutate(today, set_run(claim)), RUN),
        ("off, pool: no codewire-run", OFF, "create", mutate(today, rename_run(None)), RUN),
        ("off, pool: codewire-run renamed", OFF, "create", mutate(today, rename_run("codewire-state")), RUN),
        ("off, environment: codewire-run on disk", OFF, "create", mutate(env_today, set_run(disk)), RUN),
        ("off, environment: codewire-run a host path", OFF, "create", mutate(env_today, set_run(host)), RUN),
        ("off, environment: codewire-run a volume claim", OFF, "create", mutate(env_today, set_run(claim)), RUN),
        ("off, environment: no codewire-run", OFF, "create", mutate(env_today, rename_run(None)), RUN),
        ("off, confidential: codewire-run in memory without a size limit", OFF, "create",
         mutate(conf_today, set_run(unbounded)), RUN),
        ("on, pool: the broker golden with codewire-run on disk", ON, "create", mutate(broker, set_run(disk)), RUN),
        ("on, standard: codewire-run in memory without a size limit", on_standard, "create",
         mutate(standard, set_run(unbounded)), RUN),
        ("on, standard: codewire-run renamed", on_standard, "create",
         mutate(standard, rename_run("codewire-state")), RUN),
    ]


def devnet_mount(c: dict) -> dict:
    return next(m for m in c["volumeMounts"] if m["name"] == "egress-devnet")


def without_devnet(t: dict) -> None:
    # The mounts stay, so the TUN init's own rule passes and this one is
    # what refuses a broker template with no device volume.
    pod(t)["volumes"] = [v for v in pod(t)["volumes"] if v["name"] != "egress-devnet"]


def wait_for(cluster: Cluster, probe: dict, rule: str) -> None:
    """A policy change reaches admission a moment after it is stored."""
    for _ in range(30):
        denial = cluster.admit("create", probe)
        if denial is not None and denial.startswith(rule):
            return
        time.sleep(1)
    sys.exit(f"the policy change never reached admission (wanted {rule!r})")


def check(name: str, denial: str | None, expected: str | None) -> bool:
    ok = denial is None if expected is None else denial is not None and denial.startswith(expected)
    print(f"{'ok  ' if ok else 'FAIL'} {name}: {'admitted' if denial is None else 'denied: ' + denial[:150]}")
    return ok


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--kubeconfig", required=True)
    args = parser.parse_args()
    cluster = Cluster(args.kubeconfig)
    for namespace in (SERVER, SANDBOXES):
        cluster.kubectl("create", "namespace", namespace)
    for crd in (CRD, SANDBOX_CRD):
        if cluster.kubectl("apply", "--server-side", "-f", str(crd)).returncode != 0:
            sys.exit(f"{crd.name} did not apply")
    cluster.apply({"apiVersion": "v1", "kind": "List", "items": [
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole",
         "metadata": {"name": "warm-pool-admission-proof"},
         "rules": [{"apiGroups": ["extensions.agents.x-k8s.io"], "resources": ["sandboxtemplates"],
                    "verbs": ["get", "create", "update"]},
                   {"apiGroups": ["agents.x-k8s.io"], "resources": ["sandboxes"],
                    "verbs": ["get", "create", "update"]}]},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
         "metadata": {"name": "warm-pool-admission-proof"},
         "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole",
                     "name": "warm-pool-admission-proof"},
         "subjects": [{"kind": "ServiceAccount", "name": "codewire-orchestration", "namespace": SERVER},
                      {"kind": "ServiceAccount", "name": OTHER.split(":")[-1], "namespace": SERVER}]}]})
    policy, binding = rendered_policy()
    cluster.param(OFF)
    cluster.apply(policy)
    cluster.apply(binding)
    for document in rendered_policy(MEMBER_POLICY) + rendered_policy(WRITER_POLICY):
        cluster.apply(document)
    today = load("warm-pool-sandboxtemplate.golden.json")
    broker = load("warm-pool-broker-sandboxtemplate.golden.json")
    environment = environment_cases(
        pinned(load("identity-free-sandboxtemplate.golden.json")),
        pinned(load("environment-broker-sandboxtemplate.golden.json")),
        load("confidential-sandboxtemplate.golden.json"), load("confidential-broker-sandboxtemplate.golden.json"),
        broker) + standard_cases(
        load("standard-sandboxtemplate.golden.json"), pinned(load("environment-broker-sandboxtemplate.golden.json")),
        broker) + standard_pool_cases(load("warm-pool-standard-sandboxtemplate.golden.json"), broker) + run_cases(
        today, broker, pinned(load("identity-free-sandboxtemplate.golden.json")),
        load("confidential-sandboxtemplate.golden.json"), load("standard-sandboxtemplate.golden.json")) + run_mount_cases(
        today, broker, pinned(load("identity-free-sandboxtemplate.golden.json")),
        load("confidential-sandboxtemplate.golden.json"), load("standard-sandboxtemplate.golden.json"))
    wait_for(cluster, mutate(today, lambda t: t["spec"]["podTemplate"]["metadata"].setdefault("labels", {})
                             .__setitem__("codewire.sh/egress", "broker")), GATE)
    results = []
    current: object = "unset"
    for name, param, verb, template, expected in cases(today, broker) + environment + clearing_cases():
        if param != current:
            cluster.param(param)
            current = param
        results.append(check(name, cluster.admit(verb, template), expected))
    results.extend(keep_cases(cluster, pinned(load("identity-free-sandboxtemplate.golden.json")),
                              pinned(load("environment-broker-sandboxtemplate.golden.json")),
                              load("standard-sandboxtemplate.golden.json"), broker))
    results.extend(run_update_cases(cluster, pinned(load("identity-free-sandboxtemplate.golden.json")),
                                    pinned(load("environment-broker-sandboxtemplate.golden.json"))))
    results.extend(member_run_cases(cluster, pinned(load("identity-free-sandboxtemplate.golden.json")),
                                    pinned(load("environment-broker-sandboxtemplate.golden.json"))))

    # An UPDATE to a refused shape: create the broker golden for real, then
    # update it to world egress.
    cluster.param(ON)
    stored = cluster.kubectl("create", f"--as={AS}", "-f", "-", stdin=json.dumps(broker))
    if stored.returncode != 0:
        results.append(check("on: create the broker golden for the UPDATE case", stored.stderr.strip(), None))
    else:
        live = json.loads(cluster.kubectl("get", "sandboxtemplate", broker["metadata"]["name"], "-n",
                                          broker["metadata"]["namespace"], "-o", "json").stdout)
        widened = mutate(live, lambda t: egress(t).append(copy.deepcopy(WORLD)))
        results.append(check("on: an UPDATE adding world egress", cluster.admit("replace", widened), EGRESS))
        cluster.kubectl("delete", "sandboxtemplate", broker["metadata"]["name"], "-n",
                        broker["metadata"]["namespace"])

    # A standard template made under one disk updates as before once the
    # deployment names another, as long as it keeps its own; it never moves
    # to a disk the parameter doesn't name (#5602).
    standard = load("standard-sandboxtemplate.golden.json")
    cluster.param(with_disk(disk_reference(standard)))
    stored = cluster.kubectl("create", f"--as={AS}", "-f", "-", stdin=json.dumps(standard))
    if stored.returncode != 0:
        results.append(check("on: create the standard golden for the UPDATE cases", stored.stderr.strip(), None))
    else:
        cluster.param(with_disk(OTHER_DISK))
        live = json.loads(cluster.kubectl("get", "sandboxtemplate", standard["metadata"]["name"], "-n",
                                          standard["metadata"]["namespace"], "-o", "json").stdout)
        relabelled = mutate(live, lambda t: t["metadata"].setdefault("labels", {}).__setitem__("x", "y"))
        results.append(check("on: an UPDATE of a standard template that keeps its disk after the disk moves on",
                             cluster.admit("replace", relabelled), None))
        live = json.loads(cluster.kubectl("get", "sandboxtemplate", standard["metadata"]["name"], "-n",
                                          standard["metadata"]["namespace"], "-o", "json").stdout)
        moved = mutate(live, set_disk("registry.example.invalid/codewire/workspace-disk@sha256:" + "8" * 64))
        results.append(check("on: an UPDATE moving a standard template to a disk not named",
                             cluster.admit("replace", moved), DISK))
        cluster.kubectl("delete", "sandboxtemplate", standard["metadata"]["name"], "-n",
                        standard["metadata"]["namespace"])

    # Broker mode never comes off a Sandbox (#5002); a Sandbox without it and
    # without a VM runtime class updates as before.
    broker_label = {"codewire.sh/type": "workspace", "codewire.sh/egress": "broker"}
    plain = {"codewire.sh/type": "workspace"}
    for name, before, after, expected in [
        ("Sandbox: the broker label removed", broker_label, plain, KEEPS_BROKER),
        ("Sandbox: the broker label changed", broker_label, plain | {"codewire.sh/egress": "direct"}, KEEPS_BROKER),
        ("Sandbox: the broker label kept", broker_label, broker_label | {"x": "y"}, None),
        ("Sandbox: one without it, updated", plain, plain | {"x": "y"}, None),
    ]:
        results.append(check(name, sandbox_update(cluster, before, after), expected))
    results.extend(pre_switch_cases(cluster))
    results.extend(move_cases(cluster, pinned(load("identity-free-sandboxtemplate.golden.json")),
                              pinned(load("environment-broker-sandboxtemplate.golden.json")), today))
    cluster.param(ON)

    # Kind overlays widen runtimeClasses with diagnostic runtimes; the TUN
    # rule's own VM check must still refuse them.
    widened_policy = copy.deepcopy(policy)
    variable = widened_policy["spec"]["variables"][0]
    if variable["name"] != "runtimeClasses":
        sys.exit("runtimeClasses is no longer the policy's first variable")
    variable["expression"] = "['commodity', 'commodity-32g', 'runc', '']"
    cluster.apply(widened_policy)
    no_class = mutate(broker, lambda t: pod(t).pop("runtimeClassName"))
    wait_for(cluster, no_class, TUN)
    results.append(check("on, Kind's runtime classes: the broker golden", cluster.admit("create", broker), None))
    results.append(check("on, Kind's runtime classes: runc", cluster.admit(
        "create", mutate(broker, setting(pod, "runtimeClassName", "runc"))), TUN))
    results.append(check("on, Kind's runtime classes: no runtime class", cluster.admit("create", no_class), TUN))
    cluster.apply(policy)

    # A deployment that names the key broker's Pods (#4000) gives kbsPeer
    # their labels; namespace-only is then refused.
    labelled_policy = copy.deepcopy(policy)
    kbs_variable = next(v for v in labelled_policy["spec"]["variables"] if v["name"] == "kbsPeer")
    kbs_variable["expression"] = "['codewire-trustee', 'TCP/8080', " + ", ".join(
        f"'{key}={value}'" for key, value in KBS_PODS.items()) + "]"
    cluster.apply(labelled_policy)
    conf_broker = load("confidential-broker-sandboxtemplate.golden.json")
    wait_for(cluster, conf_broker, EGRESS)
    for name, template, expected in labelled_kbs_cases(
            conf_broker, pinned(load("environment-broker-sandboxtemplate.golden.json"))):
        results.append(check(name, cluster.admit("create", template), expected))
    cluster.apply(policy)
    cluster.param(OFF)

    print(f"{sum(results)}/{len(results)} as expected")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
