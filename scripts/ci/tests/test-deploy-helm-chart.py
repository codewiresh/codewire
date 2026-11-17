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

import os
import re
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
}
_KIND = {
    ("Namespace", "default"),
    ("ConfigMap", "codewire-config"),
    ("ConfigMap", "codewire-dashboard-public-config"),
    ("Deployment", "codewire-dashboard"),
    ("Service", "dashboard"),
} | _SERVICES
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
    | _SERVICES,
    "local-kind": _KIND,
    "local-kind-static": _KIND,
}

# Differences the chart makes on purpose, by kind and the path the comparison
# reports, each with its reason. Nothing else may differ.
ALLOWED: dict[tuple[str, str], str] = {
    ("Namespace", "metadata.annotations.helm.sh/resource-policy"): (
        "a Helm uninstall or upgrade keeps the namespace and everything in it, "
        "as the clusters' deletion guard requires (#3542); Kustomize has no "
        "uninstall, and nothing but Helm reads the annotation"
    ),
}

# Each environment: its namespace, the Kustomize directories it composes, and
# the chart's values files for it, in order.
ENVIRONMENTS: dict[str, tuple[str, list[Path], list[Path]]] = {
    "source": (
        "prod",
        [K8S / name for name in ("base", "dashboard", "coordinator", "idp", "billing")],
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


def compare(
    migrated: set[tuple[str, str]],
    chart: list[dict[str, Any]],
    kustomized: list[dict[str, Any]],
) -> list[str]:
    """Every way the two renders differ on the migrated objects; empty if none."""
    problems = []
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
            for path, what in differences(found["chart"][0], found["Kustomize"][0]):
                if (wanted[0], path) not in ALLOWED:
                    problems.append(f"{wanted}: {path}: {what}")
    return problems


def check(environment: str, extra: tuple[str, ...] = ()) -> list[str]:
    namespace, directories, values = ENVIRONMENTS[environment]
    return compare(
        MIGRATED[environment],
        objects(helm(namespace, values, extra)),
        objects(kustomize(directories)),
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
        problems = compare(MIGRATED["source"], chart, objects(kustomize(ENVIRONMENTS["source"][1])))
        self.assertEqual(problems, ["('NetworkPolicy', 'codewire-dashboard'): chart renders it 0 times"])

    def test_an_unmigrated_object_the_chart_renders_is_reported(self) -> None:
        migrated = MIGRATED["local-kind"] - {("Service", "dashboard")}
        _, directories, values = ENVIRONMENTS["local-kind"]
        problems = compare(migrated, objects(helm("default", values)), objects(kustomize(directories)))
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
            compare(MIGRATED["local-kind"], chart, kustomized),
            ["('Namespace', 'default'): metadata.annotations.example.test/extra: only the chart has it"],
        )

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
