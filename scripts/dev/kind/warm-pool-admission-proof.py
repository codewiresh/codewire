#!/usr/bin/env python3
"""Server-side dry runs of the template admission policy (#4000, #5002).

Nothing in the repository evaluates the policy's CEL, so this applies the
rendered policy, its binding and its param to a scratch Kind cluster and has a
real API server admit or deny each case, as orchestration's service account.
It matches every SandboxTemplate orchestration writes: the pool's allowlist
holds cw-pool- templates, and the broker arm holds every template while hosted
egress is on, so per-environment templates are proved here too. The member
policy's broker-mode rule is proved on Sandboxes.
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
RUNTIME = "warm-pool members run under the commodity runtime"
KEEPS_BROKER = "orchestration never takes broker mode"
NO_PARAM = "failed to configure binding: no params found"

OFF: dict[str, str] = {}
ON = {
    "CODEWIRE_HOSTED_EGRESS_ENABLED": "true",
    "CODEWIRE_HOSTED_EGRESS_DAEMON_REPOSITORY": REPOSITORY,
    "CODEWIRE_HOSTED_EGRESS_GATEWAY_NAMESPACE": "gateway-proxies",
    "CODEWIRE_HOSTED_EGRESS_GATEWAY_NAME": "public",
    "CODEWIRE_HOSTED_EGRESS_GATEWAY_OWNER_NAMESPACE": "gateway",
    "CODEWIRE_HOSTED_EGRESS_GATEWAY_PORT": "10443",
}
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

    def admit(self, verb: str, template: dict) -> str | None:
        """None when admitted, else the reported denial."""
        result = self.kubectl(verb, "--dry-run=server", f"--as={AS}", "-f", "-", stdin=json.dumps(template))
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


def sandbox(labels: dict[str, str]) -> dict:
    return {"apiVersion": "agents.x-k8s.io/v1beta1", "kind": "Sandbox",
            "metadata": {"name": "broker-mode-proof", "namespace": SANDBOXES},
            "spec": {"podTemplate": {"metadata": {"labels": labels},
                                     "spec": {"containers": [{"name": "workspace", "image": "busybox"}]}}}}


def sandbox_update(cluster: "Cluster", before: dict[str, str], after: dict[str, str]) -> str | None:
    """Create a Sandbox with `before` as its pod labels, update it to `after`
    as orchestration, then delete it."""
    stored = cluster.kubectl("create", f"--as={AS}", "-f", "-", stdin=json.dumps(sandbox(before)))
    if stored.returncode != 0:
        return "create failed: " + stored.stderr.strip()
    live = json.loads(cluster.kubectl("get", "sandbox", "broker-mode-proof", "-n", SANDBOXES, "-o", "json").stdout)
    live["spec"]["podTemplate"]["metadata"]["labels"] = after
    denial = cluster.admit("replace", live)
    cluster.kubectl("delete", "sandbox", "broker-mode-proof", "-n", SANDBOXES, "--wait=true")
    return denial


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
         "subjects": [{"kind": "ServiceAccount", "name": "codewire-orchestration", "namespace": SERVER}]}]})
    policy, binding = rendered_policy()
    cluster.param(OFF)
    cluster.apply(policy)
    cluster.apply(binding)
    for document in rendered_policy(MEMBER_POLICY):
        cluster.apply(document)
    today = load("warm-pool-sandboxtemplate.golden.json")
    broker = load("warm-pool-broker-sandboxtemplate.golden.json")
    environment = environment_cases(
        pinned(load("identity-free-sandboxtemplate.golden.json")),
        pinned(load("environment-broker-sandboxtemplate.golden.json")),
        load("confidential-sandboxtemplate.golden.json"), load("confidential-broker-sandboxtemplate.golden.json"),
        broker)
    wait_for(cluster, mutate(today, lambda t: t["spec"]["podTemplate"]["metadata"].setdefault("labels", {})
                             .__setitem__("codewire.sh/egress", "broker")), GATE)
    results = []
    current: object = "unset"
    for name, param, verb, template, expected in cases(today, broker) + environment:
        if param != current:
            cluster.param(param)
            current = param
        results.append(check(name, cluster.admit(verb, template), expected))

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

    # Broker mode never comes off a Sandbox (#5002); a Sandbox made before
    # hosted egress, without it, updates as before.
    broker_label = {"codewire.sh/type": "workspace", "codewire.sh/egress": "broker"}
    plain = {"codewire.sh/type": "workspace"}
    for name, before, after, expected in [
        ("Sandbox: the broker label removed", broker_label, plain, KEEPS_BROKER),
        ("Sandbox: the broker label changed", broker_label, plain | {"codewire.sh/egress": "direct"}, KEEPS_BROKER),
        ("Sandbox: the broker label kept", broker_label, broker_label | {"x": "y"}, None),
        ("Sandbox: one without it, updated", plain, plain | {"x": "y"}, None),
    ]:
        results.append(check(name, sandbox_update(cluster, before, after), expected))

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
    cluster.param(OFF)

    print(f"{sum(results)}/{len(results)} as expected")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
