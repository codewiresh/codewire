"""Every object a chart renders that the deletion guard protects is kept.

The hosted clusters' cluster-deletion-guard admission policy refuses to delete
a Namespace, PersistentVolumeClaim, CustomResourceDefinition or CNPG Cluster
that was not first annotated for deletion. Helm deletes what a chart stops
rendering, so dropping such an object from a chart fails the release in Dev
and Production with everything else already applied (codewire#3542: the Mesh
chart dropped its data claim). Helm skips that delete for an object whose live
copy carries helm.sh/resource-policy: keep. Requiring keep from the first
release that renders a guarded object makes every later removal leave it in
place; retiring it is then a separate, approved step.

Each chart is rendered with its defaults and with every hosted values file
that deploys it. A chart missing from HOSTED_VALUES is refused, so a new
chart is checked from its first change.
"""

from __future__ import annotations

from .kubernetes import documents, metadata_field, top_level_field
from .shared import *

HOSTED_VALUES = {
    "apps/cli/charts/codewire-mesh": (
        "deployments/k8s/mesh-dev/values.yaml",
        "deployments/k8s/mesh-production/values.yaml",
    ),
}
# The defaults leave some required values empty; these fill them for a render.
RENDER_SETS = {
    "apps/cli/charts/codewire-mesh": (
        "mesh.baseURL=https://mesh.test",
        "image.repository=registry.test/codewire/mesh",
        "image.tag=test",
    ),
}
GUARDED_CORE_KINDS = {"Namespace", "PersistentVolumeClaim"}
KEEP = re.compile(r"^    helm\.sh/resource-policy:\s*[\"']?keep[\"']?\s*$", re.MULTILINE)


def guarded(document: str) -> bool:
    kind = top_level_field(document, "kind")
    api_version = top_level_field(document, "apiVersion") or ""
    return (
        (kind in GUARDED_CORE_KINDS and api_version == "v1")
        or (kind == "CustomResourceDefinition" and api_version.startswith("apiextensions.k8s.io/"))
        or (kind == "Cluster" and api_version.startswith("postgresql.cnpg.io/"))
    )


def metadata_annotations(document: str) -> str:
    lines = document.split("\n")
    try:
        start = lines.index("metadata:")
    except ValueError:
        return ""
    block: list[str] = []
    inside = False
    for line in lines[start + 1 :]:
        if re.match(r"^[^ ]", line):
            break
        if re.match(r"^  [^ ]", line):
            inside = line.rstrip() == "  annotations:"
            continue
        if inside:
            block.append(line)
    return "\n".join(block)


def render_failures(label: str, rendered: str) -> list[str]:
    return [
        f"{label} renders {top_level_field(document, 'kind')} "
        f"{metadata_field(document, 'name')} without helm.sh/resource-policy: keep; "
        "the clusters' deletion guard would fail any release that stops rendering it"
        for document in documents(rendered)
        if guarded(document) and not KEEP.search(metadata_annotations(document))
    ]


def helm_render(chart: str, values: str | None) -> str:
    command = ["helm", "template", "deletion-guard-check", chart]
    if values:
        command += ["-f", values]
    for setting in RENDER_SETS.get(chart, ()):
        command += ["--set", setting]
    return subprocess.run(command, cwd=ROOT, check=True, stdout=subprocess.PIPE, text=True).stdout


def claim(annotations: str = "") -> str:
    return (
        "apiVersion: v1\nkind: PersistentVolumeClaim\nmetadata:\n  name: data\n"
        f"{annotations}spec:\n  resources:\n    requests:\n      storage: 1Gi\n"
    )


KEEP_ANNOTATIONS = "  annotations:\n    helm.sh/resource-policy: keep\n"


def self_test() -> list[str]:
    failures: list[str] = []
    admitted = {
        "a kept claim": claim(KEEP_ANNOTATIONS),
        "a kept claim, quoted": claim('  annotations:\n    helm.sh/resource-policy: "keep"\n'),
        "a Deployment": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: app\n",
        "another API's Cluster": "apiVersion: cluster.x-k8s.io/v1beta1\nkind: Cluster\nmetadata:\n  name: c\n",
    }
    refused = {
        "a claim without annotations": claim(),
        "a claim with other annotations": claim("  annotations:\n    example.test/a: b\n"),
        "keep on a label": claim("  labels:\n    helm.sh/resource-policy: keep\n"),
        "keep in the spec": claim() + "  selector:\n    helm.sh/resource-policy: keep\n",
        "a Namespace": "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: n\n",
        "a CRD": "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: a.b\n",
        "a CNPG Cluster": "apiVersion: postgresql.cnpg.io/v1\nkind: Cluster\nmetadata:\n  name: db\n",
    }
    for name, document in admitted.items():
        if render_failures("fixture", "---\n" + document):
            failures.append(f"chart deletion guard self-test: {name} was refused")
    for name, document in refused.items():
        if len(render_failures("fixture", "---\n" + document)) != 1:
            failures.append(f"chart deletion guard self-test: {name} was admitted")
    mixed = "---\n" + claim(KEEP_ANNOTATIONS) + "---\n" + claim()
    if len(render_failures("fixture", mixed)) != 1:
        failures.append("chart deletion guard self-test: one unkept claim among two was not found")
    return failures


def check_chart_deletion_guard(args: argparse.Namespace) -> int:
    if args.self_test:
        if report("chart deletion guard", self_test()):
            return 1
        print("chart deletion guard: OK (self-test)")
        return 0
    charts = sorted(
        str(Path(path).parent) for path in git_source_files() if Path(path).name == "Chart.yaml"
    )
    failures = [
        f"{chart} has no HOSTED_VALUES entry in {Path(__file__).name}"
        for chart in charts
        if chart not in HOSTED_VALUES
    ]
    renders = 0
    for chart in charts:
        for values in (None, *HOSTED_VALUES.get(chart, ())):
            failures.extend(render_failures(f"{chart} ({values or 'defaults'})", helm_render(chart, values)))
            renders += 1
    if report("chart deletion guard", failures):
        return 1
    print(f"chart deletion guard: OK ({renders} renders)")
    return 0
