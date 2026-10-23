# Mesh Dev Deployment

This folder contains the dev Helm values for the hosted Codewire Mesh
deployment at `mesh.codewire-dev.sh`.

The Mesh control service is separate from DERP:

- `mesh.codewire-dev.sh` serves the Codewire Mesh API, network membership,
  invite creation, node enrollment, runtime network authorization, and tailnet
  coordination. The hostname is the dev Mesh endpoint.
- `derp.codewire-dev.sh` serves the DERP packet relay used by the tailnet data
  path.

Hosted Mesh forwards canonical browser, OAuth, and organization-scoped API-key
credentials to the private Mesh authorization service. It has no independent
OIDC client, browser-session fallback, or Mesh-owned login flow.

## Deployment ownership

Private `codewire/deploy` is the desired-state source for dev. Its Mesh child
reads the Mesh HelmRelease from deploy's `hosted/`, through the
release-immutable `codewire-hosted-<source-sha>` object, and points it at an
immutable HelmChart built from this repository's `apps/cli/charts/codewire-mesh`
at the exact source (`codewire-source-<source-sha>`), with the release's exact
Mesh digest. Helm Controller remains the sole owner of the `codewire-mesh`
release. The HelmRelease carries its values inline;
`deployments/k8s/mesh-dev/values.yaml` mirrors them and is what deploy's
read-only dry run renders the chart with.

The `Deploy Dev` workflow publishes only the exact source-SHA Mesh candidate
during an ordinary main run. After all five candidates succeed, the aggregate
job writes one complete release tree to `codewire/deploy`; the exact observer
then waits for the immutable chart, Mesh child, HelmRelease, and Deployment to
converge. It must not run a direct `helm upgrade`, because doing so introduces
a second owner and conflicts with Helm Controller's server-side apply fields.

The deploy run reports the exact deploy/source/chart revisions and immutable
Mesh digest it observed. A moving or descendant source revision is not an
acceptable substitute for the promoted release tuple.

DNS for `mesh.codewire-dev.sh` is infrastructure-owned and must point at the
dev management ingress controller, not at the DERP ingress controller.
