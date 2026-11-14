"""The Kind overlays name Kind's own edge in every NetworkPolicy (codewire#3297).

The base NetworkPolicies admit the hosted base's edge, the RKE2 ingress
controller in kube-system. Kind runs ingress-nginx instead, so each Kind
overlay patches every policy's edge peer. A policy left unpatched admits
nothing on Kind: its Pods are cut off from the edge, as the IdP and the
dashboard were in tests/e2e/kind after #4557, when that overlay alone missed
the patch. This check renders every Kind overlay and fails on any
NetworkPolicy that still names the RKE2 controller.
"""

from .shared import *
from .kubernetes import documents, metadata_field, top_level_field


# Every overlay a Kind cluster is built from: tests/e2e/kind for kind-up and
# the retained suites, the local-kind pair for the dev loop.
KIND_OVERLAYS = (
    "tests/e2e/kind",
    "deployments/k8s/overlays/local-kind",
    "deployments/k8s/overlays/local-kind-static",
)

# The hosted base's edge, which no Kind cluster runs.
HOSTED_EDGE = "rke2-ingress-nginx"


def unpatched_policies(rendered: str) -> list[str]:
    """The NetworkPolicies in `rendered` that still name the hosted edge."""
    return [
        metadata_field(document, "name") or "?"
        for document in documents(rendered)
        if top_level_field(document, "kind") == "NetworkPolicy" and HOSTED_EDGE in document
    ]


def kind_overlay_peer_failures(renders: dict[str, str]) -> list[str]:
    return [
        f"{overlay}: NetworkPolicy/{name} admits {HOSTED_EDGE}, which Kind doesn't run; "
        "patch its edge peer to ingress-nginx as the overlay's other policies are"
        for overlay, rendered in renders.items()
        for name in unpatched_policies(rendered)
    ]


def kind_overlay_peers_self_test(renders: dict[str, str]) -> list[str]:
    """A policy that keeps the hosted edge must fail, and one with a different
    resource naming it in an expression must not."""
    unpatched = (
        "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: codewire-idp\n"
        "spec:\n  ingress:\n  - from:\n    - podSelector:\n        matchLabels:\n"
        f"          app.kubernetes.io/name: {HOSTED_EDGE}\n"
    )
    elsewhere = (
        "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: admission\n"
        f"data:\n  expression: kube-system|app.kubernetes.io/name={HOSTED_EDGE}\n"
    )
    problems: list[str] = []
    overlay, rendered = next(iter(renders.items()))
    if not kind_overlay_peer_failures({overlay: f"{rendered}\n---\n{unpatched}"}):
        problems.append("self-test: an unpatched NetworkPolicy passed")
    if kind_overlay_peer_failures({overlay: f"{rendered}\n---\n{elsewhere}"}):
        problems.append("self-test: a non-policy resource naming the hosted edge failed")
    return problems


def check_kind_overlay_peers(args: argparse.Namespace) -> int:
    try:
        renders = {overlay: run(["kustomize", "build", overlay]).stdout for overlay in KIND_OVERLAYS}
        failures = kind_overlay_peer_failures(renders)
        if not failures and args.self_test:
            failures = kind_overlay_peers_self_test(renders)
    except Exception as error:  # noqa: BLE001 - repository policy boundary
        failures = [str(error)]
    if failures:
        for failure in failures:
            print(f"::error::kind overlay peers: {failure}", file=sys.stderr)
        return 1
    suffix = "; mutations rejected" if args.self_test else ""
    print(f"kind overlay peers: OK ({len(KIND_OVERLAYS)} overlays){suffix}")
    return 0
