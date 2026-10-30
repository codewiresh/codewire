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
| `SANDBOX_WORKSPACE_STORAGE_CLASS` | Required by orchestration, except under the `confidential` runtime profile | The StorageClass of every `commodity` workspace volume. There is no default: empty, orchestration refuses to start. A disk resize expands the volume only when this class allows volume expansion. | `standard` |
| `SANDBOX_CONFIDENTIAL_WORKSPACE_STORAGE_CLASS` | Only where confidential environments are enabled | The StorageClass of every confidential workspace volume, claimed as a raw `volumeMode: Block`, `ReadWriteOncePod` device that the guest encrypts. There is no default: empty, every confidential environment is refused before any workload is created. The class must give a fresh, all-zero device of exactly the requested size with no host encryption layer, and a confidential volume never grows. | `linstor-confidential` |

| `SANDBOX_CONFIDENTIAL_STORAGE_ENABLED` | No | `true` lets the deployment create, start, resize and reach confidential environments. Base `config.env` sets `false`, and Production keeps it off. | `true` |

Base `config.env` leaves the storage classes empty, so every overlay sets them. The Kind
overlays (`deployments/k8s/overlays/local-kind*` and `tests/e2e/kind`) use
Kind's built-in `standard` class.

With the switch on, a confidential environment is still refused until a global
admin opts its organization in, under Confidential environments on that
organization's admin page (`/admin/organizations/<id>/`), whose list also shows
every organization's opt-in; each change is written to the audit log. Then
any active member of that organization, or an API key scoped to it, may create,
start, resize and reach its confidential environments. Every other caller is
refused with `CONFIDENTIAL_NOT_ENABLED` or `CONFIDENTIAL_MEMBERSHIP_REQUIRED`.
Stop, delete and reconciliation never consult the opt-in, so withdrawing it
never strands an environment.

A hosted create that names no disk gets 80 GiB, with 2 vCPU and 8 GiB of
memory (owner, 2026-10-27; #3554); a confidential one gets 50 GiB, its own
limit, and 16 GiB of memory, because its guest unpacks images into RAM-backed
storage and the workspace image does not fit in 8 GiB (owner, 2026-10-30;
#2497). Create and resize accept a disk up to 200 GiB and refuse more with
`disk_limit_exceeded`; a disk never shrinks. These limits are in the code
(`crates/codewire-orchestration/src/api/create.rs`), not configuration. The
class's thin capacity must hold every pool member and live workspace at its
size. A grown disk is expanded by the StorageClass's CSI driver, online when
it can be and otherwise at the Pod replacement `cw resize` asks for; the DinD
bootstrap then grows the Docker data image (`CODEWIRE_DOCKER_DATA_SIZE`, the
disk less 2 GiB) online with `resize2fs` at the next Pod start.

| Variable | Required | Meaning | Example |
|---|---|---|---|
| `SANDBOX_VOLUME_SNAPSHOT_CLASS` | No | VolumeSnapshotClass of hosted disk snapshots (`cw --platform snapshot`). Empty, the default, refuses them. |
| `SANDBOX_WARM_POOL_SHAPES` | No | Comma-separated warm pools, `<cpu>m/<memory>Mi/<disk>Gi=<members>` with 0 to 16 members each. A create of exactly a pool's shape adopts a prestarted member. The default create shape is `2000m/8192Mi/80Gi`, so a pool of that shape serves default creates. Empty means no pools. | `2000m/8192Mi/80Gi=2` |

## Workspace CPU

A workspace's CPU request can be lower than its vCPUs, so more sandboxes fit on a node while each VM keeps the vCPUs it was asked for. Only the scheduler's reservation changes: the CPU limit, quota, billing and the shape users see stay on full vCPUs, and the workspace's memory request and the requests of DinD and the Kata overhead do not change. Under contention, a sandbox gets CPU in proportion to its request.

The setting applies to sandboxes created after it changes, and a change rotates the warm pools like a release. An existing sandbox keeps the ratio it runs at, through a stop, a start or a resize, until it is replaced. Confidential environments are always 1:1.

A global administrator can give an organization dedicated CPU (`SetOrganizationDedicatedCpu`): its new sandboxes are 1:1 whatever this setting says. While the deployment shares, they start cold, because the warm pools share.

| Variable | Required | Meaning | Example |
|---|---|---|---|
| `CODEWIRE_SANDBOX_CPU_SHARING_RATIO` | No | How many vCPUs share one reserved CPU: a whole number from 1 to 8. A workspace requests its vCPUs divided by this, rounded up. Unset, empty or `1` means off, one reserved CPU per vCPU. Any other form stops orchestration at startup. | `2` |

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

## Tracing

Orchestration (its API and its Temporal worker) and the dashboard server export
OpenTelemetry traces over OTLP/gRPC when an endpoint is set. One environment
create is then one trace: the dashboard request, the orchestration
`CreateEnvironment` handler, the Temporal signal, and the claim-authority,
create and setup activities, with the claim, bind, access-ready and setup-phase
functions, each Kubernetes API request and each Postgres statement as child
spans. The trace context crosses HTTP and gRPC as the W3C `traceparent` header
and crosses Temporal inside the signal and activity inputs. No other service
exports traces, whatever its environment says; billing, idp, coordinator and
the other services only log.

| Variable | Required | Meaning | Example |
|---|---|---|---|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | No | The OTLP/gRPC endpoint (a collector or Tempo's OTLP receiver) that orchestration and the dashboard send spans to. Unset or empty means no exporter is installed and tracing costs nothing beyond the compiled-in code. Orchestration logs one line at startup saying whether export is on, naming the endpoint's scheme, host and port only. | `http://tempo.observability.svc:4317` |
| `OTEL_TRACES_SAMPLER` | No | The standard OpenTelemetry sampler: `always_on`, `always_off`, `traceidratio`, `parentbased_always_on`, `parentbased_always_off` or `parentbased_traceidratio`. Unset means `parentbased_always_on`, every trace. | `parentbased_traceidratio` |
| `OTEL_TRACES_SAMPLER_ARG` | No | The ratio, from `0.0` to `1.0`, for the two `traceidratio` samplers. Unset means `1.0`. | `0.1` |
| `OTEL_SERVICE_NAME` | No | Overrides the service name, which is otherwise `codewire-orchestration` or `codewire-dashboard`. | `codewire-orchestration` |
| `OTEL_RESOURCE_ATTRIBUTES` | No | Extra resource attributes. Set `deployment.environment.name` here; without it the `ENVIRONMENT` variable is used when set. `service.version` is the build's version. | `deployment.environment.name=dev` |

What is exported is fixed in code (`crates/codewire-server-core/src/obs.rs`).
Span attributes carry identifiers such as `environment_id`, request methods
and paths, Kubernetes API paths, sqlx's four-word statement summary and row
counts, and timings. They never carry a secret, a token, a credential, an
environment variable's value or user content: a URL's query string is removed
before export (a Kubernetes exec URL carries its command line there), no log
event is exported, and a statement's text and bound values are never recorded.
Health probes and metrics scrapes start no trace, and a Kubernetes request or
statement outside a traced operation (a background reconciler's) is not
exported. A request's `traceparent` is honoured from any caller, so with a
ratio sampler a client can ask for its own request to be sampled.

Codewire's spans are at `DEBUG` level, so at the default `RUST_LOG=info` they
do not appear in the JSON logs, which are the same whether or not export is on.
