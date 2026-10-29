"""The warm-pool template's one ingress rule (codewire#3626).

A non-confidential SandboxTemplate admits orchestration's own identity, and
nothing wider, to a member's daemon (TCP 7777) and SSH (TCP 2222) ports from
birth: one rule, one peer carrying both the server namespace's
`kubernetes.io/metadata.name` and orchestration's two Pod labels (two peers
would be an OR), and exactly those two ports. Previews and the tailnet's
world UDP stay in the per-environment policies.

`ingress_violations` guards a rendered template against that shape. The
template admission policy in `deployments/k8s/orchestration/warm-pool-authz.yaml`
admits exactly two shapes, which `admission_violations` mirrors: that rule,
or no ingress at all. The no-ingress arm is for the rollout and old
templates (an orchestration replica of the previous release writes them);
it admits strictly less, and goes once every pool template carries the
rule (#3640). Either shape needs the controller to manage the policy.
`positive_fixtures` are the admitted shapes (no ingress both as an absent
field and as an empty list) and `negative_fixtures` each widening the
policy must refuse, Unmanaged with either shape among them. The
identity-free workspace guard runs
them against its Python checks; the Kind warm-pools suite sends each to the
API server as a server-side dry run with orchestration's identity, so the
real CEL decides too:

    python3 -I scripts/checks/repo_policy/pool_ingress.py < template.json

prints one JSON object per line, `{"name": ..., "object": ...}`: first the
positive fixtures, named `accepted ...`, then every negative fixture.
"""

from __future__ import annotations

import copy
import json
import sys
from typing import Any, Callable

DAEMON_PORT = 7777
SSH_PORT = 2222
ORCHESTRATION_POD_LABELS = {"app.kubernetes.io/name": "codewire", "app.kubernetes.io/component": "orchestration"}
NAMESPACE_LABEL = "kubernetes.io/metadata.name"


def expected_ingress(server_namespace: str) -> list[dict[str, Any]]:
    return [{
        "from": [{
            "namespaceSelector": {"matchLabels": {NAMESPACE_LABEL: server_namespace}},
            "podSelector": {"matchLabels": dict(ORCHESTRATION_POD_LABELS)},
        }],
        "ports": [{"port": DAEMON_PORT, "protocol": "TCP"}, {"port": SSH_PORT, "protocol": "TCP"}],
    }]


def server_namespace(template: dict[str, Any]) -> str | None:
    """The namespace the template's egress names for orchestration's binding
    listener: the server namespace the ingress peer must name too."""
    egress = ((template.get("spec") or {}).get("networkPolicy") or {}).get("egress") or []
    for rule in egress:
        if rule.get("ports") != [{"port": 8087, "protocol": "TCP"}]:
            continue
        for peer in rule.get("to") or []:
            namespace = ((peer.get("namespaceSelector") or {}).get("matchLabels") or {}).get(NAMESPACE_LABEL)
            if namespace:
                return str(namespace)
    return None


def management_violations(template: dict[str, Any], label: str) -> list[str]:
    """The controller must manage the template's policy: Unmanaged would
    admit all ingress, whatever the ingress rules say."""
    management = (template.get("spec") or {}).get("networkPolicyManagement", "Managed")
    if management != "Managed" or "networkPolicy" not in (template.get("spec") or {}):
        return [f"{label}: the controller does not manage the template's NetworkPolicy"]
    return []


def ingress_violations(template: dict[str, Any], label: str) -> list[str]:
    if management_violations(template, label):
        return management_violations(template, label)
    policy = (template.get("spec") or {}).get("networkPolicy") or {}
    namespace = server_namespace(template)
    if namespace is None:
        return [f"{label}: names no server namespace for orchestration"]
    if policy.get("ingress") != expected_ingress(namespace):
        return [f"{label}: template ingress is not exactly orchestration's identity on TCP 7777 and 2222 in one peer"]
    return []


def admission_violations(template: dict[str, Any], label: str) -> list[str]:
    """What the template admission policy admits: a managed policy whose
    ingress is absent or an empty list (the rollout arm, removed in #3640),
    or exactly the one rule."""
    if management_violations(template, label):
        return management_violations(template, label)
    policy = template["spec"]["networkPolicy"] or {}
    if policy.get("ingress", []) == []:
        return []
    return ingress_violations(template, label)


def positive_fixtures(template: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """The shapes the policy admits: the exact rule (the template as
    rendered) and, for the rollout, no ingress at all, absent or empty."""
    without = copy.deepcopy(template)
    without["spec"]["networkPolicy"].pop("ingress", None)
    empty = copy.deepcopy(template)
    empty["spec"]["networkPolicy"]["ingress"] = []
    return [
        ("accepted exact rule", copy.deepcopy(template)),
        ("accepted no ingress", without),
        ("accepted empty ingress", empty),
    ]


def _rule(template: dict[str, Any]) -> dict[str, Any]:
    return template["spec"]["networkPolicy"]["ingress"][0]


def _peer(template: dict[str, Any]) -> dict[str, Any]:
    return _rule(template)["from"][0]


def _mutations(namespace: str) -> list[tuple[str, Callable[[dict[str, Any]], None]]]:
    def second_rule(t: dict[str, Any]) -> None:
        t["spec"]["networkPolicy"]["ingress"].append(copy.deepcopy(_rule(t)))

    def split_peers(t: dict[str, Any]) -> None:
        peer = _peer(t)
        _rule(t)["from"] = [{"namespaceSelector": peer["namespaceSelector"]}, {"podSelector": peer["podSelector"]}]

    return [
        ("a second rule", second_rule),
        ("a third port", lambda t: _rule(t)["ports"].append({"port": 8080, "protocol": "TCP"})),
        ("an endPort", lambda t: _rule(t)["ports"][0].__setitem__("endPort", DAEMON_PORT + 1)),
        ("the preview range", lambda t: _rule(t)["ports"].append({"port": 1, "endPort": 65535, "protocol": "TCP"})),
        ("UDP", lambda t: _rule(t)["ports"][1].__setitem__("protocol", "UDP")),
        ("an ipBlock", lambda t: _rule(t).__setitem__("from", [{"ipBlock": {"cidr": "0.0.0.0/0"}}])),
        ("a namespace-only peer", lambda t: _peer(t).pop("podSelector")),
        ("a pod-only peer", lambda t: _peer(t).pop("namespaceSelector")),
        ("a peer missing the name label", lambda t: _peer(t)["podSelector"]["matchLabels"].pop("app.kubernetes.io/name")),
        ("the selectors split into two peers", split_peers),
        ("another namespace", lambda t: _peer(t)["namespaceSelector"]["matchLabels"].__setitem__(
            NAMESPACE_LABEL, f"{namespace}-other")),
        # Beyond the review's list: a selector widened by an expression, a
        # string port (a named-port lookup) and another port in place of SSH.
        ("a pod selector expression", lambda t: _peer(t)["podSelector"].__setitem__(
            "matchExpressions", [{"key": "app.kubernetes.io/part-of", "operator": "Exists"}])),
        ("a string port", lambda t: _rule(t)["ports"][1].__setitem__("port", str(SSH_PORT))),
        ("another port", lambda t: _rule(t)["ports"][1].__setitem__("port", 22)),
    ]


def negative_fixtures(template: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """Each widening of a valid template's ingress, by name, then both
    admitted ingress shapes under an Unmanaged policy, which admits all
    ingress whatever its rules say."""
    namespace = server_namespace(template) or "dev"
    fixtures = []
    for name, mutate in _mutations(namespace):
        fixture = copy.deepcopy(template)
        mutate(fixture)
        if fixture == template:
            raise RuntimeError(f"pool ingress negative fixture {name} did not change the template")
        fixtures.append((name, fixture))
    for name, shape in positive_fixtures(template)[:2]:
        fixture = copy.deepcopy(shape)
        fixture["spec"]["networkPolicyManagement"] = "Unmanaged"
        fixtures.append((f"Unmanaged with {name.removeprefix('accepted ')}", fixture))
    return fixtures


def self_test(template: dict[str, Any], label: str) -> None:
    if ingress_violations(template, label):
        raise RuntimeError(f"{label}: the exact pool ingress was rejected")
    positives = positive_fixtures(template)
    for name, fixture in positives:
        if admission_violations(fixture, f"{label}: positive pool ingress fixture {name}"):
            raise RuntimeError(f"{label}: positive pool ingress fixture {name} was refused")
    # The renderer itself always emits the rule: no ingress is admitted only
    # for the rollout, never rendered.
    if not ingress_violations(positives[1][1], f"{label}: rendered without ingress"):
        raise RuntimeError(f"{label}: a rendering without the ingress rule was accepted")
    negatives = negative_fixtures(template)
    if len(negatives) != 16:
        raise RuntimeError(f"{label}: expected 16 negative pool ingress fixtures, got {len(negatives)}")
    for name, fixture in negatives:
        for check in (ingress_violations, admission_violations):
            if not check(fixture, f"negative pool ingress fixture {name}"):
                raise RuntimeError(f"negative pool ingress fixture {name} was accepted by {check.__name__}")


def main() -> int:
    template = json.load(sys.stdin)
    for name, fixture in positive_fixtures(template):
        print(json.dumps({"name": name, "object": fixture}, sort_keys=True))
    for name, fixture in negative_fixtures(template):
        print(json.dumps({"name": name, "object": fixture}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
