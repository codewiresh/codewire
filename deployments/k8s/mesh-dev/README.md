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

Private `codewire/deploy` is the desired-state source for dev. Its active
deploy parent owns a Mesh child that reads this repository through a
release-immutable `codewire-source-<source-sha>` object and replaces the source
HelmRelease's chart and image with the matching immutable chart and digest.
Helm Controller remains the sole owner of the `codewire-mesh` release.
`deployments/k8s/mesh-dev/values.yaml` and
`deployments/k8s/flux/mesh-dev` remain source inputs to that renderer.

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
