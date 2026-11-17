#!/usr/bin/env python3
"""The Codewire chart renders what the Kustomize trees render (#2908).

The chart takes over the Kustomize trees one component at a time. For each
environment this renders both, keeps the objects the chart has taken over so
far (MIGRATED), and requires each to be the same object in both renders: the
same kind, name and namespace, and equal once parsed, so only formatting and
key order may differ. A generated ConfigMap's hashed name must match too. The
chart may render nothing else, and each migrated object must appear exactly
once in each render. The only exceptions are listed in ALLOWED, each with its
reason.

The environments are the two Kind overlays, and Production's source tree
(its directories composed, as Production's overlay builds on them) with the
values in fixtures/helm-chart-values-source.yaml. Dev and Production
themselves are checked in codewire/deploy, where their overlays live.

Needs `helm` and `kustomize` on PATH, at the versions CI pins.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Iterator

import yaml

ROOT = Path(__file__).resolve().parents[3]
CHART = ROOT / "deployments/helm/codewire"
K8S = ROOT / "deployments/k8s"
SOURCE_VALUES = ROOT / "scripts/ci/tests/fixtures/helm-chart-values-source.yaml"

# ConfigMaps Kustomize generates, whose names end in a hash of their data.
GENERATED = {"codewire-config", "codewire-dashboard-public-config"}
GENERATED_SUFFIX = re.compile(r"-[a-z0-9]{10}$")

# The Rust services, alike in every environment.
_SERVICES = {
    ("Deployment", "codewire-coordinator"),
    ("Service", "codewire-coordinator"),
    ("Deployment", "codewire-idp"),
    ("Service", "codewire-idp"),
    ("NetworkPolicy", "codewire-idp"),
    ("Deployment", "codewire-billing"),
    ("Service", "codewire-billing"),
    ("Deployment", "codewire-credential-service"),
    ("ServiceAccount", "codewire-credential-service"),
    ("Service", "codewire-credential-service"),
    ("ClusterRole", "codewire-credential-service-tokenreview"),
    ("ClusterRoleBinding", "codewire-credential-service-tokenreview"),
    ("Role", "codewire-credential-service-tokenrequest"),
    ("RoleBinding", "codewire-credential-service-tokenrequest"),
    ("Role", "codewire-credential-service-runtime"),
    ("RoleBinding", "codewire-credential-service-runtime"),
    ("Certificate", "codewire-credential-broker"),
    ("NetworkPolicy", "codewire-credential-service"),
    ("PodDisruptionBudget", "codewire-credential-service"),
    # Orchestration, with its RBAC, admission policies and ConfigMaps.
    ("ClusterRole", "codewire-orchestration"),
    ("ClusterRoleBinding", "codewire-orchestration"),
    ("ConfigMap", "codewire-hosted-egress"),
    ("ConfigMap", "codewire-image-registries"),
    ("Deployment", "codewire-orchestration"),
    ("NetworkPolicy", "codewire-orchestration-workspace-binding"),
    ("NetworkPolicy", "cw-image-cache"),
    ("Role", "codewire-orchestration-image-cache"),
    ("Role", "codewire-orchestration-internal-roots"),
    ("Role", "codewire-orchestration-release-revision"),
    ("Role", "codewire-orchestration-sandboxes"),
    ("Role", "codewire-orchestration-tokenrequest"),
    ("RoleBinding", "codewire-orchestration-image-cache"),
    ("RoleBinding", "codewire-orchestration-internal-roots"),
    ("RoleBinding", "codewire-orchestration-release-revision"),
    ("RoleBinding", "codewire-orchestration-sandboxes"),
    ("RoleBinding", "codewire-orchestration-tokenrequest"),
    ("Service", "codewire-orchestration"),
    ("Service", "codewire-orchestration-grpc"),
    ("Service", "codewire-orchestration-workspace-binding"),
    ("ServiceAccount", "codewire-orchestration"),
    ("ServiceAccount", "cw-image-cache"),
    ("ValidatingAdmissionPolicy", "codewire-orchestration-image-cache"),
    ("ValidatingAdmissionPolicy", "codewire-orchestration-warm-pool"),
    ("ValidatingAdmissionPolicy", "codewire-orchestration-warm-pool-member"),
    ("ValidatingAdmissionPolicy", "codewire-orchestration-warm-pool-template"),
    ("ValidatingAdmissionPolicyBinding", "codewire-orchestration-image-cache"),
    ("ValidatingAdmissionPolicyBinding", "codewire-orchestration-warm-pool"),
    ("ValidatingAdmissionPolicyBinding", "codewire-orchestration-warm-pool-member"),
    ("ValidatingAdmissionPolicyBinding", "codewire-orchestration-warm-pool-template"),
}
# DERP, in every environment.
_DERP = {
    ("Deployment", "codewire-derp"),
    ("Service", "codewire-derp"),
    ("Service", "codewire-derp-mesh"),
    ("PodDisruptionBudget", "codewire-derp"),
}
# The UDP relay, which Kind does not run.
_UDP_RELAY = {
    ("Deployment", "codewire-udp-relay"),
    ("Service", "codewire-udp-relay"),
    ("Certificate", "codewire-udp-relay-allocator"),
    ("NetworkPolicy", "codewire-udp-relay"),
}
# Orchestration's cert-manager Certificates, which Kind does not render.
_CERTIFICATES = {
    ("Certificate", "codewire-orchestration-internal"),
    ("Certificate", "codewire-orchestration-udp-relay-allocator-client"),
}
_KIND = {
    ("Namespace", "default"),
    ("ConfigMap", "codewire-config"),
    ("ConfigMap", "codewire-dashboard-public-config"),
    ("Deployment", "codewire-dashboard"),
    ("Service", "dashboard"),
} | _SERVICES | _DERP
# What the chart renders so far, by kind and name, per environment.
MIGRATED: dict[str, set[tuple[str, str]]] = {
    "source": {
        ("Namespace", "prod"),
        ("ConfigMap", "codewire-config"),
        ("ConfigMap", "codewire-dashboard-public-config"),
        ("Deployment", "codewire-dashboard"),
        ("Service", "codewire-dashboard"),
        ("NetworkPolicy", "codewire-dashboard"),
    }
    | _SERVICES
    | _CERTIFICATES
    | _DERP
    | _UDP_RELAY,
    "local-kind": _KIND,
    "local-kind-static": _KIND,
}

# Differences the chart makes on purpose, each with its reason: by environment
# (None for every one), kind, name (None for any) and the path the comparison
# reports, which covers the paths below it. Nothing else may differ.
ALLOWED: dict[tuple[str | None, str, str | None, str], str] = {
    (None, "Namespace", None, "metadata.annotations.helm.sh/resource-policy"): (
        "a Helm uninstall or upgrade keeps the namespace and everything in it, "
        "as the clusters' deletion guard requires (#3542); Kustomize has no "
        "uninstall, and nothing but Helm reads the annotation"
    ),
    **{
        (environment, "NetworkPolicy", "codewire-credential-service", "spec.ingress[0].from[1].podSelector.matchLabels"): (
            "Kind's overlay retargets this policy's edge but not its dashboard "
            "peer, which keeps production's labels that Kind's dashboard does "
            "not carry; the chart names the dashboard each environment runs"
        )
        for environment in ("local-kind", "local-kind-static")
    },
}


def allowed(environment: str | None, kind: str, name: str, path: str) -> bool:
    return any(
        (scope in (None, environment))
        and kind == allowed_kind
        and (allowed_name in (None, name))
        and (path == prefix or path.startswith(prefix + "."))
        for scope, allowed_kind, allowed_name, prefix in ALLOWED
    )


# Deployments whose environment may list the same variables in another order,
# per environment, with the reason. Their variables are compared by name, and
# only while order_cannot_matter holds on both sides.
ENV_ORDER_ALLOWED: dict[str, dict[str, str]] = {
    environment: {
        "codewire-credential-service": (
            "Kind's strategic-merge patch of CREDENTIAL_PUBLIC_ORIGIN moves it "
            "to the front of the list; the chart keeps the source's order"
        ),
        "codewire-derp": (
            "Kind's strategic-merge patch of DERP_MESH_HOSTNAME, TLS_PORT and "
            "TLS_HOSTS moves them to the front of the list; the chart keeps "
            "the source's order"
        ),
    }
    for environment in ("local-kind", "local-kind-static")
}

# Each environment: its namespace, the Kustomize directories it composes, and
# the chart's values files for it, in order.
ENVIRONMENTS: dict[str, tuple[str, list[Path], list[Path]]] = {
    "source": (
        "prod",
        [
            K8S / name
            for name in (
                "base", "dashboard", "coordinator", "idp", "billing", "credential-service", "orchestration",
                "derp", "udp-relay",
            )
        ],
        [SOURCE_VALUES],
    ),
    "local-kind": (
        "default",
        [K8S / "overlays/local-kind"],
        [CHART / "values-local-kind.yaml"],
    ),
    "local-kind-static": (
        "default",
        [K8S / "overlays/local-kind-static"],
        [CHART / "values-local-kind.yaml", CHART / "values-local-kind-static.yaml"],
    ),
}


def run(command: list[str]) -> str:
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"{' '.join(command)} failed:\n{result.stderr}")
    return result.stdout


def kustomize(directories: list[Path]) -> str:
    if len(directories) == 1:
        return run(["kustomize", "build", str(directories[0])])
    # Compose them as an overlay would. Kustomize refuses absolute resource
    # paths, so they are given relative to the scratch directory.
    with tempfile.TemporaryDirectory() as scratch:
        resources = "".join(
            f"  - {os.path.relpath(directory, scratch)}\n" for directory in directories
        )
        Path(scratch, "kustomization.yaml").write_text(f"resources:\n{resources}")
        return run(["kustomize", "build", scratch])


def helm(namespace: str, values: list[Path], extra: tuple[str, ...] = ()) -> str:
    command = ["helm", "template", "codewire", str(CHART), "--namespace", namespace]
    for path in values:
        command += ["-f", str(path)]
    return run([*command, *extra])


def probe(template: str) -> str:
    """Render one template against the chart's helpers alone, so a helper's
    own refusal is tested without the rest of the chart refusing first."""
    with tempfile.TemporaryDirectory() as scratch:
        root = Path(scratch)
        (root / "templates").mkdir()
        (root / "Chart.yaml").write_text("apiVersion: v2\nname: probe\nversion: 0.1.0\n")
        shutil.copy(CHART / "templates/_helpers.tpl", root / "templates/_helpers.tpl")
        # Helm parses what a template renders as an object, so the output is
        # a ConfigMap's value.
        (root / "templates/probe.yaml").write_text(
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: probe\ndata:\n"
            "  out: |\n    {{- " + template.removeprefix("{{ ").removesuffix(" }}") + " | nindent 4 }}\n"
        )
        return objects(run(["helm", "template", "probe", scratch]))[0]["data"]["out"]


def objects(rendered: str) -> list[dict[str, Any]]:
    return [document for document in yaml.safe_load_all(rendered) if document]


def key(document: dict[str, Any]) -> tuple[str, str]:
    name = document["metadata"]["name"]
    base = GENERATED_SUFFIX.sub("", name)
    if document["kind"] == "ConfigMap" and base in GENERATED:
        return ("ConfigMap", base)
    return (document["kind"], name)


def differences(left: Any, right: Any, path: str = "") -> Iterator[tuple[str, str]]:
    """Each path where the chart's object (left) and Kustomize's differ, with
    what differs there."""
    if isinstance(left, dict) and isinstance(right, dict):
        for name in sorted(set(left) | set(right), key=str):
            child = f"{path}.{name}" if path else str(name)
            if name not in right:
                yield child, "only the chart has it"
            elif name not in left:
                yield child, "only Kustomize has it"
            else:
                yield from differences(left[name], right[name], child)
    elif isinstance(left, list) and isinstance(right, list) and len(left) == len(right):
        for index, (a, b) in enumerate(zip(left, right)):
            yield from differences(a, b, f"{path}[{index}]")
    elif left != right:
        yield path, f"chart {left!r}, Kustomize {right!r}"


def order_cannot_matter(deployment: dict[str, Any]) -> bool:
    """Whether every container's variables mean the same in any order.
    Kubernetes expands $(NAME) only from a variable listed earlier, so the
    order is free when no name is listed twice and every reference names a
    variable listed before it (or one never listed, which stays as written)."""
    for container in deployment["spec"]["template"]["spec"]["containers"]:
        env = container.get("env", [])
        names = [variable["name"] for variable in env]
        if len(set(names)) != len(names):
            return False
        for index, variable in enumerate(env):
            for name in re.findall(r"\$\(([^)]*)\)", str(variable.get("value", ""))):
                if name in names and name not in names[:index]:
                    return False
    return True


def sort_env(deployment: dict[str, Any]) -> None:
    for container in deployment["spec"]["template"]["spec"]["containers"]:
        container.get("env", []).sort(key=lambda variable: variable["name"])


def compare(
    migrated: set[tuple[str, str]],
    chart: list[dict[str, Any]],
    kustomized: list[dict[str, Any]],
    environment: str | None = None,
) -> list[str]:
    """Every way the two renders differ on the migrated objects in an
    environment; empty if none."""
    problems = []
    env_order = ENV_ORDER_ALLOWED.get(environment or "", {})
    by_key: dict[str, dict[tuple[str, str], list[dict[str, Any]]]] = {
        "chart": {},
        "Kustomize": {},
    }
    for side, documents in (("chart", chart), ("Kustomize", kustomized)):
        for document in documents:
            by_key[side].setdefault(key(document), []).append(document)
    for extra in sorted(set(by_key["chart"]) - migrated):
        problems.append(f"{extra}: the chart renders it, but it is not migrated")
    for wanted in sorted(migrated):
        found = {side: by_key[side].get(wanted, []) for side in by_key}
        for side, documents in found.items():
            if len(documents) != 1:
                problems.append(f"{wanted}: {side} renders it {len(documents)} times")
        if all(len(documents) == 1 for documents in found.values()):
            # Compared by name only where the order cannot matter on either
            # side; otherwise the order is compared as it is.
            if (
                wanted[0] == "Deployment"
                and wanted[1] in env_order
                and all(order_cannot_matter(found[side][0]) for side in found)
            ):
                for side in found:
                    sort_env(found[side][0])
            for path, what in differences(found["chart"][0], found["Kustomize"][0]):
                if not allowed(environment, wanted[0], wanted[1], path):
                    problems.append(f"{wanted}: {path}: {what}")
    return problems


def check(environment: str, extra: tuple[str, ...] = ()) -> list[str]:
    namespace, directories, values = ENVIRONMENTS[environment]
    return compare(
        MIGRATED[environment],
        objects(helm(namespace, values, extra)),
        objects(kustomize(directories)),
        environment,
    )


class ChartEquivalence(unittest.TestCase):
    def test_each_environment_renders_as_kustomize_does(self) -> None:
        for environment in ENVIRONMENTS:
            with self.subTest(environment=environment):
                self.assertEqual(check(environment), [])

    def test_a_changed_field_is_reported_by_its_path(self) -> None:
        problems = check("local-kind", ("--set", "dashboard.replicas=3"))
        self.assertEqual(
            problems,
            ["('Deployment', 'codewire-dashboard'): spec.replicas: chart 3, Kustomize 1"],
        )

    def test_changed_configuration_renames_its_configmap(self) -> None:
        problems = check("source", ("--set-string", "config.PORT=9090"))
        self.assertIn(
            "('ConfigMap', 'codewire-config'): data.PORT: chart '9090', Kustomize '8080'",
            problems,
        )
        self.assertTrue(
            any(p.startswith("('ConfigMap', 'codewire-config'): metadata.name:") for p in problems),
            problems,
        )

    def test_an_object_only_one_side_renders_is_reported(self) -> None:
        chart = objects(helm("prod", [SOURCE_VALUES], ("--set", "dashboard.networkPolicy.enabled=false")))
        problems = compare(MIGRATED["source"], chart, objects(kustomize(ENVIRONMENTS["source"][1])), "source")
        self.assertEqual(problems, ["('NetworkPolicy', 'codewire-dashboard'): chart renders it 0 times"])

    def test_an_unmigrated_object_the_chart_renders_is_reported(self) -> None:
        migrated = MIGRATED["local-kind"] - {("Service", "dashboard")}
        _, directories, values = ENVIRONMENTS["local-kind"]
        problems = compare(migrated, objects(helm("default", values)), objects(kustomize(directories)), "local-kind")
        self.assertEqual(problems, ["('Service', 'dashboard'): the chart renders it, but it is not migrated"])

    def test_an_allowed_difference_covers_its_own_path_only(self) -> None:
        namespace, directories, values = ENVIRONMENTS["local-kind"]
        chart = objects(helm(namespace, values))
        kustomized = objects(kustomize(directories))
        for document in chart:
            if document["kind"] == "Namespace":
                self.assertEqual(document["metadata"]["annotations"]["helm.sh/resource-policy"], "keep")
                document["metadata"]["annotations"]["example.test/extra"] = "x"
        self.assertEqual(
            compare(MIGRATED["local-kind"], chart, kustomized, "local-kind"),
            ["('Namespace', 'default'): metadata.annotations.example.test/extra: only the chart has it"],
        )

    def test_a_peer_in_no_named_namespace_is_refused(self) -> None:
        # Without a namespace, a peer selects the policy's own namespace, not
        # the sandbox namespace the workspace-binding policy means.
        peer = '{{ include "codewire.podPeer" (dict "labels" (dict "a" "b") "namespace" %s "from" "probe.namespace") }}'
        self.assertIn("kubernetes.io/metadata.name: sandboxes", probe(peer % '"sandboxes"'))
        for empty in ('""', "nil"):
            with self.subTest(namespace=empty):
                with self.assertRaisesRegex(RuntimeError, "probe.namespace is empty: the peer must name its namespace"):
                    probe(peer % empty)

    def test_a_runtime_class_that_is_not_a_name_never_reaches_cel(self) -> None:
        names = '{{ include "codewire.runtimeClassesCel" (dict "names" (list %s) "from" "probe.names") }}'
        self.assertEqual(probe(names % '"commodity" "runc" ""').strip(), "['commodity', 'runc', '']")
        for bad in ("\"x', 'y\"", '"Runc"', '"a b"', '"a\\\\b"', '"-a"', '"a.-b"'):
            with self.subTest(name=bad):
                with self.assertRaisesRegex(RuntimeError, "probe.names: .* is not a RuntimeClass name"):
                    probe(names % bad)

    def test_a_non_string_hosted_egress_value_is_refused(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "codewire-hosted-egress: CODEWIRE_HOSTED_EGRESS_ENABLED must be a string"):
            helm("prod", [SOURCE_VALUES], ("--set", "hostedEgress.CODEWIRE_HOSTED_EGRESS_ENABLED=false"))

    def test_every_policy_peer_goes_through_a_guarded_helper(self) -> None:
        # A peer written into a template would skip the refusal tests above.
        # Only a policy's own podSelector, directly under spec, is written
        # there; every peer comes from codewire.podPeer or codewire.edgePeers.
        selector = re.compile(r"\s*-?\s*(podSelector|namespaceSelector|ipBlock):")
        for template in sorted((CHART / "templates").glob("*.yaml")):
            for number, line in enumerate(template.read_text().splitlines(), 1):
                if selector.match(line) and line.rstrip() != "  podSelector:":
                    self.fail(f"{template.name}:{number} writes a policy peer: use codewire.podPeer or codewire.edgePeers")

    def test_env_order_is_allowed_only_where_order_cannot_matter(self) -> None:
        def deployment(*env: dict[str, str]) -> dict[str, Any]:
            return {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {"name": "codewire-credential-service"},
                "spec": {"template": {"spec": {"containers": [{"name": "c", "env": list(env)}]}}},
            }

        key = {("Deployment", "codewire-credential-service")}
        a, b = {"name": "A", "value": "1"}, {"name": "B", "value": "2"}
        self.assertEqual(compare(key, [deployment(a, b)], [deployment(b, a)], "local-kind"), [])
        # Outside the environments that allow it, order counts.
        self.assertNotEqual(compare(key, [deployment(a, b)], [deployment(b, a)], "source"), [])
        # A $(...) reference or a twice-listed name falls back to the order.
        ref = {"name": "B", "value": "$(A)/x"}
        self.assertEqual(
            compare(key, [deployment(a, ref)], [deployment(ref, a)], "local-kind"),
            [
                "('Deployment', 'codewire-credential-service'): spec.template.spec.containers[0].env[0].name: chart 'A', Kustomize 'B'",
                "('Deployment', 'codewire-credential-service'): spec.template.spec.containers[0].env[0].value: chart '1', Kustomize '$(A)/x'",
                "('Deployment', 'codewire-credential-service'): spec.template.spec.containers[0].env[1].name: chart 'B', Kustomize 'A'",
                "('Deployment', 'codewire-credential-service'): spec.template.spec.containers[0].env[1].value: chart '$(A)/x', Kustomize '1'",
            ],
        )
        # A reference to a variable listed before it in both orders expands
        # alike, so it still compares by name.
        c = {"name": "C", "value": "3"}
        self.assertEqual(compare(key, [deployment(a, ref, c)], [deployment(c, a, ref)], "local-kind"), [])
        twice = {"name": "A", "value": "3"}
        self.assertNotEqual(compare(key, [deployment(a, b, twice)], [deployment(b, twice, a)], "local-kind"), [])

    def test_a_non_string_configuration_value_is_refused(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "codewire-config: PORT must be a string"):
            helm("prod", [SOURCE_VALUES], ("--set", "config.PORT=8080"))

    def test_the_edge_must_be_named(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "edge.peers must name the public edge"):
            helm("prod", [SOURCE_VALUES], ("--set", "edge.peers=null"))

    def test_an_edge_entry_that_selects_every_peer_is_refused(self) -> None:
        for entry in ({}, {"podSelector": {}}, {"namespaceSelector": {"matchLabels": {}}}):
            with self.subTest(entry=entry), tempfile.TemporaryDirectory() as scratch:
                values = Path(scratch, "values.yaml")
                values.write_text(yaml.safe_dump({"edge": {"peers": [entry]}}))
                with self.assertRaisesRegex(RuntimeError, "selects every peer; name the public edge"):
                    helm("prod", [SOURCE_VALUES, values])

    def test_a_pod_peer_that_selects_every_pod_is_refused(self) -> None:
        # Each policy peer the chart builds from labels, by its value's path
        # and default keys. Helm merges a values file's {} into the defaults,
        # so a selector is emptied by null, or by nulling each default key.
        peers = {"dashboard.selectorLabels": ("app.kubernetes.io/component", "app.kubernetes.io/name")}
        for path, keys in peers.items():
            for labels in (None, dict.fromkeys(keys)):
                with self.subTest(path=path, labels=labels), tempfile.TemporaryDirectory() as scratch:
                    values: dict[str, Any] = {}
                    *parents, leaf = path.split(".")
                    node = values
                    for parent in parents:
                        node = node.setdefault(parent, {})
                    node[leaf] = labels
                    Path(scratch, "values.yaml").write_text(yaml.safe_dump(values))
                    with self.assertRaisesRegex(RuntimeError, f"{re.escape(path)} is empty: a peer selecting no labels admits every Pod"):
                        helm("prod", [SOURCE_VALUES, Path(scratch, "values.yaml")])


if __name__ == "__main__":
    sys.exit(unittest.main(verbosity=2))
