#!/usr/bin/env python3
"""Server-side dry runs of the warm-pool template admission policy (#4000).

Nothing in the repository evaluates the policy's CEL, so this applies the
rendered policy, its binding and its param to a scratch Kind cluster and has a
real API server admit or deny each case, as orchestration's service account.
Each case names the outcome it expects and, for a denial, the rule whose
message must be the one reported: validations run in order and the first that
fails is reported, so a case denied by another rule first does not count.

Usage, against a cluster you created for this and nothing else:
  kind create cluster --name warm-pool-admission --kubeconfig KUBECONFIG
  scripts/dev/kind/warm-pool-admission-proof.py --kubeconfig KUBECONFIG

It refuses any context that is not kind-*. It creates the server and sandbox
namespaces, the SandboxTemplate CRD, a ClusterRole that lets orchestration's
service account create and update templates, and the param ConfigMap; one
UPDATE case creates a template, updates it and deletes it.
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
POLICY = "codewire-orchestration-warm-pool-template"
PARAM = "codewire-hosted-egress"
# The goldens' server and sandbox namespaces.
SERVER = "dev"
SANDBOXES = "dev-sandboxes"
AS = f"system:serviceaccount:{SERVER}:codewire-orchestration"
REPOSITORY = "registry.example.invalid/codewire/daemon"
OTHER_IMAGE = "registry.example.invalid/other/daemon@sha256:" + "4" * 64

# The first words of each rule's message.
GATE = "with hosted egress on, every warm-pool template is broker-mode"
RESOLVER = "with hosted egress on, the netstack resolver"
ADDRESSES = "with hosted egress on, the workspace container sets the egress stream"
ENVIRONMENT = "a warm-pool template sets only the identity-free workspace"
EGRESS = "with hosted egress on, warm-pool egress names only the broker peers"
PRIVILEGE = "with hosted egress on, the Pod runs as 1000:1000"
TUN = "hosted-egress-tun runs only as an init container"
RUNTIME = "warm-pool members run under the commodity runtime"
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


def rendered_policy() -> list[dict]:
    """The policy and binding as the orchestration package renders them, with
    the binding reading its param from the goldens' server namespace, as an
    overlay's namespace pass does."""
    rendered = subprocess.run(["kubectl", "kustomize", str(ROOT / "deployments/k8s/orchestration")],
                              capture_output=True, text=True, check=True).stdout
    import yaml  # PyYAML, as the repo's CI scripts use.
    keep = []
    for document in yaml.safe_load_all(rendered):
        if document and document.get("metadata", {}).get("name") == POLICY and document["kind"] in (
                "ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding"):
            if document["kind"] == "ValidatingAdmissionPolicyBinding":
                document["spec"]["paramRef"]["namespace"] = SERVER
            keep.append(document)
    if len(keep) != 2:
        sys.exit(f"expected the template policy and its binding, found {len(keep)}")
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
    ]


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
    if cluster.kubectl("apply", "--server-side", "-f", str(CRD)).returncode != 0:
        sys.exit("the SandboxTemplate CRD did not apply")
    cluster.apply({"apiVersion": "v1", "kind": "List", "items": [
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole",
         "metadata": {"name": "warm-pool-admission-proof"},
         "rules": [{"apiGroups": ["extensions.agents.x-k8s.io"], "resources": ["sandboxtemplates"],
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
    today = load("warm-pool-sandboxtemplate.golden.json")
    broker = load("warm-pool-broker-sandboxtemplate.golden.json")
    wait_for(cluster, mutate(today, lambda t: t["spec"]["podTemplate"]["metadata"].setdefault("labels", {})
                             .__setitem__("codewire.sh/egress", "broker")), GATE)
    results = []
    current: object = "unset"
    for name, param, verb, template, expected in cases(today, broker):
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
