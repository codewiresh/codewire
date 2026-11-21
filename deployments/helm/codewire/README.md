# The Codewire chart

One Helm chart for the whole Codewire platform (#2908). It is being built one component at a time. Until it is complete, the Kustomize trees under `deployments/k8s` deploy everything, and nothing deploys this chart.

## What it renders so far

- The release namespace.
- `codewire-config` and `codewire-dashboard-public-config`, named by a hash of their data as Kustomize's generator names them, so a configuration change rolls the services that read it.
- The dashboard: its Deployment, Service and NetworkPolicy.
- The coordinator, the IdP and billing: their Deployments and Services, and the IdP's NetworkPolicy.
- DERP: its Deployment, Services and PodDisruptionBudget.
- The UDP relay: its Deployment, Service, Certificate and NetworkPolicy (`udpRelay.enabled`; Kind runs none).
- The public edge's Ingresses, each behind its own switch (`ingress.routes`), with the site's, DERP's and the previews' hosts and TLS Secrets as values; and a single-node cluster's hostless edge on 127.0.0.1 (`ingress.local`), as local Kind uses.
- The agent-sandbox controller and its CRDs (`agentSandbox`), from the pinned release vendored byte-identical in `files/agent-sandbox`. The controller's Namespace and every CRD carry `helm.sh/resource-policy: keep`, so a Helm uninstall or upgrade never deletes them, and the check fails if any guarded object lacks it. Until the Kustomize trees go, `files/agent-sandbox` must stay identical to `deployments/k8s/agent-sandbox/base`, which `scripts/ci/tests/test-agent-sandbox-pin.sh` pins.
- The RuntimeClasses: `runc` (`runcRuntimeClass`), and the VM runtime profiles' commodity, commodity-32g, confidential and standard (`runtimeProfiles`, one switch each).
- The confidential runtime smoke (`confidentialSmoke`, off by default): its control ConfigMap, and in the `confidential-snp` phase its three Jobs, as the two kustomization files in `deployments/k8s/runtime-profiles/confidential-smoke` render them.
- Mesh (`mesh.enabled`, off by default): the Mesh chart's own templates, kept verbatim in `templates/_mesh.tpl` and rendered with `mesh.values` as that chart's values and `mesh.release` as its release name, so the objects match today's `codewire-mesh` release. Its `helm test` hook is not rendered. Until the cut-over, Dev and Production still deploy `apps/cli/charts/codewire-mesh`, and a change there must be made in `_mesh.tpl` too.
- Orchestration: its Deployment, ServiceAccount, Services, RBAC (cluster-wide read-only, its own namespace, and the sandbox namespace), admission policies and bindings, the image-registries and hosted-egress ConfigMaps (hosted egress off by default), its Certificates, and its workspace-binding NetworkPolicy.
- The credential service: its Deployment, ServiceAccount, Service, RBAC (its Role and RoleBinding for reading Sandboxes in `sandboxNamespace`), broker Certificate, NetworkPolicy and PodDisruptionBudget.

## Values

- `values.yaml` holds the defaults: production's shape, with no site host, image or secret.
- `values-local-kind.yaml` is the local Kind cluster's values. `values-local-kind-static.yaml` layers the static Kind cluster's differences on top of it. Render both in the namespace `default`.
- Dev's and Production's values will live in codewire/deploy, where their overlays are.

An environment's values file sets only what differs from the defaults, and uses `null` to remove a default it does not have. A service's `env` is a whole list, and an environment that differs replaces it. Every `config` value is a string, and the render refuses any other type.

`publicOrigin` is the site's origin, which the dashboard and the credential service use, and `sandboxNamespace` is where Sandboxes run. Both are required.

`edge.peers` names the cluster's public edge once, for every network policy that admits it. The render refuses an empty list, and any entry whose selectors are empty, since either would admit every peer. Every other policy peer is built by `codewire.podPeer`, which refuses an empty selector, and the check fails on a peer written into a template directly.

## How it is checked

`scripts/ci/tests/test-deploy-helm-chart.py` renders each environment with both Helm and Kustomize, and requires every object the chart has taken over to be the same in both. It runs in CI's Deploy verification. A component joins the chart only together with its entry in that check.

```sh
helm template codewire deployments/helm/codewire --namespace default \
  -f deployments/helm/codewire/values-local-kind.yaml
python3 -B scripts/ci/tests/test-deploy-helm-chart.py
```
