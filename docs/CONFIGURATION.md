# Configuration reference

A Codewire deployment names its own registries and hosts. The product ships no
default that points at one operator's infrastructure: when a required value is
missing, the service that needs it refuses to start, and its error names the
variable and this page.

Services read these values from their environment. In the Kubernetes
manifests (`deployments/k8s`), the `codewire-config` ConfigMap carries most of
them, and each overlay sets its own values. CI and release workflows take their
settings from repository Actions variables; see
[dev/CI-CONFIGURATION.md](dev/CI-CONFIGURATION.md).

## Runtime images

Orchestration renders every Sandbox from three images: the workspace image,
the daemon (support) image, and the Docker-in-Docker image. The workspace
digest is the published pin in `crates/codewire-workspace-image`. The DinD image
is Docker's official image, pinned by digest in the source. The deployment
chooses where the workspace and daemon images are pulled from.

| Variable | Required | Meaning | Example |
|---|---|---|---|
| `CODEWIRE_WORKSPACE_IMAGE_REPOSITORY` | Required by orchestration | The repository the default workspace image is pulled from, with no tag or digest. Orchestration appends the pinned digest. `cw` and the dashboard send the same digest at its public mirror, `ghcr.io/codewiresh/workspace`, and orchestration resolves it to this repository. The public mirror is itself a valid value. | `registry.example.com/codewire/workspace` |
| `CODEWIRE_APPROVED_IMAGE_REGISTRIES` | Required by orchestration | Comma-separated registry prefixes, each ending in `/` and with no spaces, that the runtime-node image cache may hold digest-pinned images from. The image cache admission policy reads the same value, so the two always approve the same registries. An image from any other registry is never cached. | `registry.example.com/,docker.io/library/` |
| `SANDBOX_DAEMON_IMAGE` | Required by orchestration | The support image every workspace runs its daemon from. Pin it by digest: a Start then re-pins an existing Sandbox's daemon to it, but only from an image in the same repository. | `registry.example.com/codewire/daemon@sha256:<digest>` |

### Where the manifests set them

- `CODEWIRE_WORKSPACE_IMAGE_REPOSITORY` and `SANDBOX_DAEMON_IMAGE` are keys of
  the `codewire-config` ConfigMap. Base `config.env` leaves the repository
  empty, so every overlay must set it.
- `CODEWIRE_APPROVED_IMAGE_REGISTRIES` is the only key of the
  `codewire-image-registries` ConfigMap in orchestration's namespace
  (`deployments/k8s/orchestration/image-registries.yaml`). Orchestration reads
  it into its environment. The image cache `ValidatingAdmissionPolicyBinding`
  names the same ConfigMap as its parameter (`paramRef`), and denies every
  image cache write when the ConfigMap is missing. Its name carries no hash
  suffix, so a changed value reaches orchestration only after its Pods
  restart. The policy applies the new value at once.

### Local clusters

The Kind overlays (`deployments/k8s/overlays/local-kind*` and
`tests/e2e/kind`) pull the workspace image from its public mirror:

```text
CODEWIRE_WORKSPACE_IMAGE_REPOSITORY=ghcr.io/codewiresh/workspace
CODEWIRE_APPROVED_IMAGE_REGISTRIES=ghcr.io/codewiresh/,docker.io/library/
```

`make kind-runtime-images` preloads that image into every node.

The process-level harnesses (`scripts/dev/dev-stack.sh` and the integration and
rehearsal runners) use `registry.example.invalid`, a reserved name that never
resolves.

## Transactional email

The IdP and billing send verification, access and receipt email. SES is
selected only by its workload-specific `CODEWIRE_SES_ENABLED=true` marker,
delivered with the SES credential projection. Without that marker, a
`RESEND_API_KEY` in the workload's environment selects the Resend sender.
With neither, the workload starts with email delivery disabled.

| Variable | Required | Meaning | Example |
|---|---|---|---|
| `CODEWIRE_SES_FROM` | Required when SES is enabled | The SES sender: one plain mailbox, verified as an SES identity. | `hello@example.com` |
| `CODEWIRE_SES_REGION` | Required when SES is enabled | The AWS region of that SES identity. | `eu-west-1` |
| `CODEWIRE_RESEND_FROM` | Required when `RESEND_API_KEY` is set and SES is not enabled | The Resend `From` header: one mailbox, optionally with a display name. Its domain must be verified in the Resend account. There is no default: unset or empty, the IdP and billing refuse to start. | `Example <hello@example.com>` |

The Kind overlays provide neither credential, so local email delivery stays
disabled and needs no sender.

## Stripe billing

Billing is disabled unless `STRIPE_SECRET_KEY` is set.

| Variable | Required | Meaning | Example |
|---|---|---|---|
| `STRIPE_SECRET_KEY` | Required for billing | The Stripe secret key. An `sk_live_` key selects live prices; any other key selects test prices. | `sk_test_…` |
| `STRIPE_WEBHOOK_SECRET` | Required with `STRIPE_SECRET_KEY` | The signing secret of the Stripe webhook endpoint. Without it, billing refuses every delivery. | `whsec_…` |
| `FRONTEND_URL` | Yes | The dashboard origin. Checkout and portal redirects must stay on it, and it names the default webhook URL below. | `https://codewire.example.com` |
| `STRIPE_WEBHOOK_URL` | No | The public URL of billing's Stripe webhook endpoint. Unset or empty means `FRONTEND_URL`'s origin plus `/api/webhooks/stripe`. `off` disables the endpoint check, for example when `stripe listen` forwards events in development. | `https://billing.example.com/api/webhooks/stripe` |

With Stripe configured, every billing replica checks its webhook endpoint at
startup and then hourly, using its own key. It lists the account's webhook
endpoints and requires exactly one endpoint for the webhook URL. That
endpoint must be enabled and in the key's mode, use the Stripe API version of
billing's SDK, and send exactly the event types billing handles:
`checkout.session.completed`, `customer.subscription.updated`,
`customer.subscription.deleted`, `customer.subscription.trial_will_end`,
`invoice.created`, `invoice.paid`, `invoice.payment_failed` and
`invoice.finalized`.

A mismatch logs `billing: Stripe webhook endpoint check failed` at ERROR with
every difference. It also sets the `codewire_billing_stripe_webhook_endpoint_healthy`
metric to 0 and reports `degraded` at billing's internal
`/healthz/stripe-webhook-endpoint`. It never fails readiness or liveness, so
a Stripe outage or a mismatched endpoint cannot take billing out of service.
When Stripe cannot be reached, the report says `unknown` and the metric keeps
its last value.

## Workspace storage

| Variable | Required | Meaning | Example |
|---|---|---|---|
| `SANDBOX_WORKSPACE_STORAGE_CLASS` | Required by orchestration, except under the `confidential` runtime profile | The StorageClass of every `commodity` workspace volume. There is no default: empty, orchestration refuses to start. A disk resize expands the volume only when this class allows volume expansion. The `confidential` profile always uses `longhorn-confidential`. | `standard` |

Base `config.env` leaves it empty, so every overlay sets it. The Kind
overlays (`deployments/k8s/overlays/local-kind*` and `tests/e2e/kind`) use
Kind's built-in `standard` class.

## Browser origins

Every Codewire service the browser calls is served from the dashboard's own origin, so by default no service answers cross-origin (CORS) requests at all.

| Variable | Required | Meaning | Example |
|---|---|---|---|
| `CODEWIRE_CORS_ALLOWED_ORIGINS` | No | Comma-separated browser origins, each exactly `scheme://host[:port]` with `http` or `https` and no path, query or wildcard, that may call the Codewire backend services cross-origin, for a deployment whose browser front end is on another origin. Only these get `Access-Control-Allow-Origin`, for `GET` and `POST`, never with credentials. Unset or empty means no CORS. Any other form stops the service at startup. | `https://app.example.com` |

## Workspace network

| Variable | Required | Meaning | Example |
|---|---|---|---|
| `SANDBOX_EGRESS_BANDWIDTH` | No | The egress rate cap on every workspace Pod, rendered as its `kubernetes.io/egress-bandwidth` annotation: a positive whole number of bits per second with an optional `K`, `M` or `G` suffix. Unset or empty means `100M`. Any other form stops orchestration at startup. The cap holds only where the CNI enforces the annotation, such as Cilium with its bandwidth manager enabled; elsewhere the annotation is ignored. | `100M` |
| `CODEWIRE_SANDBOX_PUBLIC_MESH_URL` | No | The public `https` origin of the hosted Codewire Mesh service that cloud environments join networks on, with no path, query or credentials. Orchestration names it to each workspace daemon whose environment joins a network. Unset or empty means this deployment offers no hosted Mesh to environments, and a create that names a network is refused with `mesh_unavailable`. Any other form stops orchestration at startup. | `https://mesh.example.com` |
