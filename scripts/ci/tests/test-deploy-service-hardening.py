#!/usr/bin/env python3
"""Every service the chart and the Kustomize trees render is hardened (#5505-#5510).

The Rust services all run from the shared services image, and several of them
are reachable from the internet. A bug in one should hand an attacker nothing
more inside its container than the service needs to run. So every container
and init container of every Deployment, DaemonSet and StatefulSet that runs the
services image:

- runs as a non-root user and group named by number: `runAsNonRoot: true`,
  and a `runAsUser` and `runAsGroup` above 0, on the container or its Pod
  (the image names no account for its user, so an unset group is root's);
- cannot gain privileges: `allowPrivilegeEscalation: false`, never privileged;
- drops every capability and adds none;
- runs under the runtime's default seccomp profile, on the container or its Pod;
- has a read-only root filesystem. A path a service writes is an emptyDir
  mounted exactly there.

The renders are those test-deploy-helm-chart.py compares: Production's source
tree (the service directories composed, as Production's overlay builds on
them) and the chart with its fixture values, and the two Kind overlays and the
chart with Kind's values. Dev's and Production's overlays live in
codewire/deploy and build on these directories.

Run it whole for the self-test and the real renders, or name one class:
`HardeningRules` is the self-test, `Renders` the check of the real renders.
Needs `helm` and `kustomize` on PATH, at the versions CI pins, and PyYAML.
"""

from __future__ import annotations

import copy
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Callable

import yaml

ROOT = Path(__file__).resolve().parents[3]
CHART = ROOT / "deployments/helm/codewire"
K8S = ROOT / "deployments/k8s"
SOURCE_VALUES = ROOT / "scripts/ci/tests/fixtures/helm-chart-values-source.yaml"

WORKLOAD_KINDS = {"Deployment", "DaemonSet", "StatefulSet"}
SERVICES_IMAGES = {"services", "codewire-services"}

_SERVICES = (
    "codewire-billing", "codewire-coordinator", "codewire-idp", "codewire-orchestration",
    "codewire-credential-service",
)
# Each environment: its namespace, the Kustomize directories it composes, the
# chart's values files for it, and the services it must render.
ENVIRONMENTS: dict[str, tuple[str, list[Path], list[Path], set[str]]] = {
    "source": (
        "prod",
        [
            K8S / name
            for name in ("base", "coordinator", "idp", "billing", "credential-service", "orchestration", "udp-relay")
        ],
        [SOURCE_VALUES],
        {*_SERVICES, "codewire-udp-relay"},
    ),
    # Kind runs no UDP relay.
    "local-kind": ("default", [K8S / "overlays/local-kind"], [CHART / "values-local-kind.yaml"], set(_SERVICES)),
    "local-kind-static": (
        "default",
        [K8S / "overlays/local-kind-static"],
        [CHART / "values-local-kind.yaml", CHART / "values-local-kind-static.yaml"],
        set(_SERVICES),
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
        resources = "".join(f"  - {os.path.relpath(directory, scratch)}\n" for directory in directories)
        Path(scratch, "kustomization.yaml").write_text(f"resources:\n{resources}")
        return run(["kustomize", "build", scratch])


def helm(namespace: str, values: list[Path]) -> str:
    command = ["helm", "template", "codewire", str(CHART), "--namespace", namespace]
    for path in values:
        command += ["-f", str(path)]
    return run(command)


def objects(rendered: str) -> list[dict[str, Any]]:
    return [document for document in yaml.safe_load_all(rendered) if document]


def runs_services_image(container: dict[str, Any]) -> bool:
    image = container.get("image", "")
    name = image.rsplit("/", 1)[-1].split("@", 1)[0].split(":", 1)[0]
    return name in SERVICES_IMAGES


def service_workloads(documents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        document
        for document in documents
        if document.get("kind") in WORKLOAD_KINDS
        and any(runs_services_image(container) for container in document["spec"]["template"]["spec"]["containers"])
    ]


def violations(workload: dict[str, Any]) -> list[str]:
    """What keeps WORKLOAD's containers from the hardened shape, if anything."""
    name = workload["metadata"]["name"]
    pod = workload["spec"]["template"]["spec"]
    pod_context = pod.get("securityContext") or {}
    found = []
    for container in [*pod.get("initContainers", []), *pod["containers"]]:
        context = container.get("securityContext") or {}
        label = f"{workload['kind']}/{name} container {container['name']}"

        def effective(field: str) -> Any:
            return context[field] if field in context else pod_context.get(field)

        if effective("runAsNonRoot") is not True:
            found.append(f"{label}: runAsNonRoot is not true on the container or its Pod")
        for field in ("runAsUser", "runAsGroup"):
            value = effective(field)
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                found.append(f"{label}: {field} is {value!r}, not above 0, on the container or its Pod")
        if context.get("allowPrivilegeEscalation") is not False:
            found.append(f"{label}: allowPrivilegeEscalation is not false")
        if context.get("privileged") is True:
            found.append(f"{label}: privileged")
        capabilities = context.get("capabilities") or {}
        if capabilities.get("drop") != ["ALL"] or capabilities.get("add"):
            found.append(f"{label}: capabilities are not exactly drop [ALL]")
        if (effective("seccompProfile") or {}).get("type") != "RuntimeDefault":
            found.append(f"{label}: seccompProfile is not RuntimeDefault on the container or its Pod")
        if context.get("readOnlyRootFilesystem") is not True:
            found.append(f"{label}: readOnlyRootFilesystem is not true")
    return found


def check(documents: list[dict[str, Any]], expected: set[str], render: str) -> list[str]:
    workloads = service_workloads(documents)
    found = [f"{render}: {problem}" for workload in workloads for problem in violations(workload)]
    missing = expected - {workload["metadata"]["name"] for workload in workloads}
    found += [f"{render}: renders no {name} from the services image" for name in sorted(missing)]
    return found


def renders() -> dict[str, tuple[list[dict[str, Any]], set[str]]]:
    out = {}
    for environment, (namespace, directories, values, expected) in ENVIRONMENTS.items():
        out[f"{environment} (Kustomize)"] = (objects(kustomize(directories)), expected)
        out[f"{environment} (chart)"] = (objects(helm(namespace, values)), expected)
    return out


class Renders(unittest.TestCase):
    """The check of the real renders."""

    def test_every_service_container_is_hardened(self) -> None:
        problems = [problem for render, (documents, expected) in renders().items()
                    for problem in check(documents, expected, render)]
        self.assertEqual(problems, [])


class HardeningRules(unittest.TestCase):
    """The self-test: each broken shape is refused, and the allowed ones pass."""

    @classmethod
    def setUpClass(cls) -> None:
        _, directories, _, cls.expected = ENVIRONMENTS["source"]
        cls.documents = objects(kustomize(directories))

    def mutated(self, name: str, change: Callable[[dict[str, Any]], None]) -> list[dict[str, Any]]:
        documents = copy.deepcopy(self.documents)
        workload = next(d for d in documents if d.get("kind") == "Deployment" and d["metadata"]["name"] == name)
        change(workload["spec"]["template"]["spec"])
        return documents

    def assertRefused(self, documents: list[dict[str, Any]], wanted: str) -> None:
        problems = check(documents, self.expected, "fixture")
        self.assertTrue(any(wanted in problem for problem in problems), problems)

    def test_the_source_render_passes(self) -> None:
        self.assertEqual(check(self.documents, self.expected, "fixture"), [])

    def test_a_broken_container_is_refused(self) -> None:
        def container(pod: dict[str, Any]) -> dict[str, Any]:
            return pod["containers"][0]["securityContext"]

        cases: list[tuple[str, Callable[[dict[str, Any]], None], str]] = [
            ("codewire-billing", lambda pod: container(pod).pop("readOnlyRootFilesystem"),
             "readOnlyRootFilesystem is not true"),
            ("codewire-udp-relay", lambda pod: container(pod).update(readOnlyRootFilesystem=False),
             "readOnlyRootFilesystem is not true"),
            ("codewire-coordinator", lambda pod: container(pod).update(allowPrivilegeEscalation=True),
             "allowPrivilegeEscalation is not false"),
            ("codewire-idp", lambda pod: container(pod).pop("allowPrivilegeEscalation"),
             "allowPrivilegeEscalation is not false"),
            ("codewire-idp", lambda pod: container(pod).update(privileged=True), "privileged"),
            ("codewire-billing", lambda pod: container(pod).update(capabilities={"drop": ["NET_RAW"]}),
             "capabilities are not exactly drop [ALL]"),
            ("codewire-billing", lambda pod: container(pod)["capabilities"].update(add=["NET_BIND_SERVICE"]),
             "capabilities are not exactly drop [ALL]"),
            ("codewire-coordinator", lambda pod: pod.pop("securityContext"), "runAsNonRoot is not true"),
            ("codewire-coordinator", lambda pod: pod["securityContext"].pop("runAsUser"), "runAsUser is None"),
            ("codewire-coordinator", lambda pod: container(pod).update(runAsUser=0), "runAsUser is 0"),
            ("codewire-udp-relay", lambda pod: container(pod).pop("runAsGroup"), "runAsGroup is None"),
            ("codewire-billing", lambda pod: container(pod).update(runAsGroup=0), "runAsGroup is 0"),
            ("codewire-idp", lambda pod: container(pod).update(runAsNonRoot=False), "runAsNonRoot is not true"),
            ("codewire-idp", lambda pod: pod["securityContext"].pop("seccompProfile"),
             "seccompProfile is not RuntimeDefault"),
            ("codewire-orchestration", lambda pod: container(pod).update(seccompProfile={"type": "Unconfined"}),
             "seccompProfile is not RuntimeDefault"),
            # Orchestration stages cw runtime uploads on its own mount (#5508),
            # so its root is read-only like every other service's.
            ("codewire-orchestration", lambda pod: container(pod).pop("readOnlyRootFilesystem"),
             "readOnlyRootFilesystem is not true"),
            ("codewire-credential-service", lambda pod: pod["containers"][0].pop("securityContext"),
             "allowPrivilegeEscalation is not false"),
            # An init container joins its Pod's attack surface too.
            ("codewire-billing", lambda pod: pod.setdefault("initContainers", []).append(
                {"name": "wait", "image": "postgres:17-alpine"}), "container wait: allowPrivilegeEscalation"),
        ]
        for name, change, wanted in cases:
            with self.subTest(name=name, wanted=wanted):
                self.assertRefused(self.mutated(name, change), wanted)

    def test_a_missing_service_is_refused(self) -> None:
        documents = [d for d in self.documents if d["metadata"]["name"] != "codewire-idp" or d["kind"] != "Deployment"]
        self.assertRefused(documents, "renders no codewire-idp")

    def test_another_workload_on_the_services_image_is_checked(self) -> None:
        documents = copy.deepcopy(self.documents)
        relay = next(d for d in documents if d["metadata"]["name"] == "codewire-udp-relay" and d["kind"] == "Deployment")
        relay["kind"] = "DaemonSet"
        relay["metadata"]["name"] = "codewire-new"
        relay["spec"]["template"]["spec"]["containers"][0].pop("securityContext")
        self.assertRefused(documents, "DaemonSet/codewire-new container udp-relay: runAsNonRoot is not true")

    def test_a_container_setting_overrides_its_pod(self) -> None:
        def move_to_container(pod: dict[str, Any]) -> None:
            pod_context = pod.pop("securityContext")
            pod["containers"][0]["securityContext"].update(pod_context)

        self.assertEqual(check(self.mutated("codewire-billing", move_to_container), self.expected, "fixture"), [])

    def test_another_image_is_not_a_service(self) -> None:
        def other_image(pod: dict[str, Any]) -> None:
            pod["containers"][0]["image"] = "registry.test/codewire/derp:test"
            pod["containers"][0].pop("securityContext")

        problems = check(self.mutated("codewire-billing", other_image), self.expected, "fixture")
        self.assertEqual(problems, ["fixture: renders no codewire-billing from the services image"])


if __name__ == "__main__":
    sys.exit(unittest.main(verbosity=2))
