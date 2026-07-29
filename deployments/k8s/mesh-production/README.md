# Mesh Production Deployment

This folder provides the production values used by CI when deploying the hosted
Codewire Mesh deployment.

Notes:

- CI deploys the local `apps/cli/charts/codewire-mesh` chart.
- The deployment targets the `prod` namespace and `mesh.codewire.sh`. Hosted
  service resources use Mesh names.

## Authentication

Hosted Mesh does not own a login page, OIDC client, browser session, device
flow, or standalone server token. It forwards exactly one canonical product
credential to the private Mesh authorization service using the existing
cluster-local HMAC. Keep that HMAC secret reference in the chart values; it is
not a product credential and its value must never be copied into a client or
release artifact.

There is no Mesh OIDC bootstrap job or dedicated Mesh OIDC secret. Browser
sign-in, OAuth/device grants, and API-key validation belong to the primary IdP
and control plane.
