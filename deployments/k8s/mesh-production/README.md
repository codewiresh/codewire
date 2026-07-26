# Mesh Production Deployment

This folder provides the production values used by CI when deploying the hosted
Codewire Mesh deployment.

Notes:

- CI deploys the local `apps/cli/charts/codewire-mesh` chart.
- `mesh.authToken` is intentionally blank in `values.yaml`; the chart will
  preserve the existing secret on upgrade and generate one on first install if
  needed.
- The deployment targets the `prod` namespace and `mesh.codewire.sh`. Hosted
  service resources use Mesh names.

## OIDC cutover

The hosted Mesh deployment should use its own dedicated OIDC client instead of
reusing the platform app secret.

Required IdP client:

- client ID: `codewire-mesh`
- client secret: dedicated Mesh client secret
- redirect URI: `https://mesh.codewire.sh/auth/oidc/callback`

Generate a dedicated secret value with something like:

```bash
openssl rand -hex 32
```

Then store that exact same value in two places:

1. App secret store / `codewire-secrets`
   - key: `MESH_OIDC_CLIENT_SECRET`
2. Mesh runtime secret sync
   - `InfisicalSecret` CRD: `codewire-mesh-oidc-sync`
   - target secret name: `codewire-mesh-oidc`
   - target key: `MESH_OIDC_CLIENT_SECRET`

Do not reuse the platform app's `OIDC_CLIENT_SECRET`.

The Mesh runtime secret should be synced by the Infisical operator, not managed
as a handwritten Kubernetes Secret. See:

- `infisical-mesh-oidc.yaml`

Ensure the IdP has a matching `codewire-mesh` client before rolling the Mesh
deployment.

Required chart values overlay:

- `mesh.authMode=oidc`
- `oidc.issuer=https://codewire.sh`
- `oidc.clientID=codewire-mesh`
- `oidc.clientSecretRef.name=codewire-mesh-oidc`
- `oidc.clientSecretRef.key=MESH_OIDC_CLIENT_SECRET`

Example files:

- `values-oidc.yaml`
- `infisical-mesh-oidc.yaml`
