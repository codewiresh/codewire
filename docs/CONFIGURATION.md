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
the daemon (support) image, and the Docker-in-Docker image. A `standard`
workspace runs the runtime image instead, and boots the workspace image from
its published disk. The workspace
digest is the published pin in `crates/codewire-workspace-image`. The DinD image
is Docker's official image, pinned by digest in the source. The deployment
chooses where the workspace and daemon images are pulled from.

The default developer workspace includes `kubectl` and Atmos on `PATH` for
infrastructure work. Their versions and per-architecture checksums are pinned
in [the workspace Dockerfile](../images/workspace/Dockerfile) for both amd64
and arm64.

| Variable | Required | Meaning | Example |
|---|---|---|---|
| `CODEWIRE_WORKSPACE_IMAGE_REPOSITORY` | Required by orchestration | The repository the default workspace image is pulled from, with no tag or digest. Orchestration appends the pinned digest. `cw` and the dashboard send the same digest at its public mirror, `ghcr.io/codewiresh/workspace`, and orchestration resolves it to this repository. The public mirror is itself a valid value. | `registry.example.com/codewire/workspace` |
| `CODEWIRE_APPROVED_IMAGE_REGISTRIES` | Required by orchestration | Comma-separated registry prefixes, each ending in `/` and with no spaces, that the runtime-node image cache may hold digest-pinned images from. The image cache admission policy reads the same value, so the two always approve the same registries. An image from any other registry is never cached. | `registry.example.com/,docker.io/library/` |
| `SANDBOX_IMAGE_CACHE_NAMESPACE` | No | The namespace orchestration writes the runtime-node image cache's DaemonSet (`cw-image-cache`) in, and where the warm pools wait for it. Unset, the Sandbox namespace (`SANDBOX_NAMESPACE`). A hosted deployment names its own, outside every Sandbox namespace, so no policy for Sandboxes selects the cache (#5002). Orchestration's image-cache Role must be in the same namespace. | `codewire-image-cache` |
| `SANDBOX_DAEMON_IMAGE` | Required by orchestration | The support image every workspace runs its daemon from. Pin it by digest: a Start then re-pins an existing Sandbox's daemon to it, but only from an image in the same repository. | `registry.example.com/codewire/daemon@sha256:<digest>` |
| `SANDBOX_STANDARD_RUNTIME_IMAGE` | With `SANDBOX_RUNTIME_PROFILE=standard`, or to move an organization onto it | The runtime image every `standard` workspace container runs (#5602, not yet observed working), pinned by digest. Its entrypoint, `cw __pod-runtime`, boots the workspace's VM; the template sets no command. It is built from `images/pod-runtime` over the context `scripts/ci/images/pod-runtime-context.py` assembles: a cw and the local VM runtime of the same source. Dev delivery builds and signs one for each delivered main commit whose cw or runtime inputs changed, and never delivers it; the digest a deployment may run is the merged pin `deployments/k8s/orchestration/pod-runtime-image.digest`, which `scripts/ci/images/pod-runtime-image-pin.py verify` checks against the image's main-CI signature. | `registry.example.com/codewire/pod-runtime@sha256:<digest>` |
| `SANDBOX_STANDARD_IMAGE_DISK` | With `SANDBOX_RUNTIME_PROFILE=standard`, or to move an organization onto it | The workspace image's published disk, as the one line its publish step prints (`scripts/ci/images/workspace-disk.sh line`, after `workspace-disk.sh build` and a push of `images/workspace-disk`): the disk image by digest, its 64-hex image disk id, its 32-hex build id and the workspace image it was built from by digest, separated by spaces. A `standard` workspace mounts the disk read-only and boots that workspace image from it, with systemd as its container's first process when that image is from `CODEWIRE_SYSTEMD_WORKSPACE_IMAGE_REPOSITORY`. Set both or neither. Orchestration reads and validates them whenever they are set, on any profile: with hosted egress on they make `standard` available, the default with `SANDBOX_RUNTIME_PROFILE=standard` and otherwise for the organizations a global administrator moves onto it (docs/dev/CODEWIRE-GUARD-RUNTIME-PROFILES.md, "Moving an organization"). Either one malformed, or the profile `standard` without both or without hosted egress on (`CODEWIRE_HOSTED_EGRESS_ENABLED`), stops orchestration at startup. | `registry.example.com/codewire/workspace-disk@sha256:<digest> <disk id> <build id> registry.example.com/codewire/workspace@sha256:<digest>` |
| `CODEWIRE_SYSTEMD_WORKSPACE_IMAGE_REPOSITORY` | Optional | The repository of the workspace-systemd image, with no tag or digest. Unset, which is the default, no image boots systemd. Set, an environment created with a digest-pinned image from it, by an opted-in organization on `commodity` or by anyone on `standard`, is recorded as a systemd workspace and runs systemd as its first process ([SYSTEMD-WORKSPACE.md](dev/SYSTEMD-WORKSPACE.md)); unset again, such an environment's start is refused. The cluster must admit that workspace container's one added capability first. A `standard` disk built from an image of it boots systemd ([SYSTEMD-WORKSPACE.md](dev/SYSTEMD-WORKSPACE.md), "On the `standard` profile"). | `registry.example.com/codewire/workspace-systemd` |

### Where the manifests set them

- `CODEWIRE_WORKSPACE_IMAGE_REPOSITORY` and `SANDBOX_DAEMON_IMAGE` are keys of
  the `codewire-config` ConfigMap. Base `config.env` leaves the repository
  empty, so every overlay must set it.
- `CODEWIRE_SYSTEMD_WORKSPACE_IMAGE_REPOSITORY` is a key of the same
  ConfigMap where a deployment sets it. No manifest in this repository does.
- `CODEWIRE_APPROVED_IMAGE_REGISTRIES` is the only key of the
  `codewire-image-registries` ConfigMap in orchestration's namespace
  (`deployments/k8s/orchestration/image-registries.yaml`). Orchestration reads
  it into its environment. The image cache `ValidatingAdmissionPolicyBinding`
  names the same ConfigMap as its parameter (`paramRef`), and denies every
  image cache write when the ConfigMap is missing. Its name carries no hash
  suffix, so a changed value reaches orchestration only after its Pods
  restart. The policy applies the new value at once.
- `SANDBOX_STANDARD_RUNTIME_IMAGE` and `SANDBOX_STANDARD_IMAGE_DISK` are the
  keys of the `codewire-standard-runtime` ConfigMap in orchestration's
  namespace (`deployments/k8s/orchestration/standard-runtime.yaml`), never of
  `codewire-config`, so they have one source that orchestration cannot
  write. Base sets both empty. Its name carries no hash suffix, so a changed
  value reaches orchestration only after its Pods restart.

### Local clusters

The Kind overlays (`deployments/k8s/overlays/local-kind*` and
`tests/e2e/kind`) pull the workspace image from its public mirror:

```text
CODEWIRE_WORKSPACE_IMAGE_REPOSITORY=ghcr.io/codewiresh/workspace
CODEWIRE_APPROVED_IMAGE_REGISTRIES=ghcr.io/codewiresh/,docker.io/library/
```

`make kind-runtime-images` preloads that image into every node.

### Workspace Rust toolchains

The default workspace includes Rust 1.99.1 with rustfmt and Clippy outside the
persistent home, under `/opt/codewire/rust`. Cargo keeps its configuration,
registry cache and installed commands in `/home/codewire/.cargo`; its `bin`
directory takes precedence over the image's Rust commands.

The image sets no global `RUSTUP_HOME` or `RUSTUP_TOOLCHAIN`. Each image Rust
command respects an explicit `RUSTUP_HOME`, then an existing `~/.rustup`.
Otherwise it uses the image's writable toolchain store. Rustup still selects
toolchains through its normal command-line, environment and project overrides.
An incomplete user installation reports its normal error instead of silently
switching stores.

The baked Rustup executable is updated through the workspace image. Its
explicit `rustup self update` fails before installing user-prefix proxies;
automatic self-update is skipped. Normal toolchain, component and default
commands can modify the fallback store, but those changes are lost when the
workspace container is replaced. To retain Rustup changes, install Rustup in
the persistent home or select a persistent `RUSTUP_HOME`. A user-installed
Rustup keeps its normal update behavior.

The process-level harnesses (`scripts/dev/dev-stack.sh` and the integration and
rehearsal runners) use `registry.example.invalid`, a reserved name that never
resolves.

## Transactional email

The IdP and billing send verification, access, organization invitation and
receipt email. SES is
selected only by its workload-specific `CODEWIRE_SES_ENABLED=true` marker,
delivered with the SES credential projection. Without that marker, the
workload starts with email delivery disabled. Resend is no longer
supported: a non-empty `RESEND_API_KEY` without the marker stops the IdP and
billing at startup, so a server that used Resend moves to SES instead of
losing its email silently.

| Variable | Required | Meaning | Example |
|---|---|---|---|
| `CODEWIRE_SES_FROM` | Required when SES is enabled | The SES sender: one mailbox, bare or as `Name <address>`, whose address is verified as an SES identity. Codewire's own servers use `Codewire <hello@codewire.sh>`. | `Codewire <hello@example.com>` |
| `CODEWIRE_SES_REGION` | Required when SES is enabled | The AWS region of that SES identity. | `eu-west-1` |

The IdP's SES identity may also read the account-level suppression list,
`ses:GetSuppressedDestination` (#4548). It asks about one
address it holds before a verification resend and for the admin's account list
(`docs/dev/AUTH-POLICY.md`, "An address SES won't deliver to"). Without the
permission every answer is unknown, and the IdP sends as it would without the
check. Billing needs only `ses:SendEmail`.

The Kind overlays provide neither credential, so local email delivery stays
disabled and needs no sender.

**How every email looks** (#4553). One layout in `codewire-email`
(`layout.rs`) renders every IdP and billing email, and each one has an HTML
part and a plain-text part with the same words. The HTML is:
- a centred column at most 640 px wide on a white page, with left-aligned text;
- the system font, about 16 px on a 24 px line;
- a heading, short paragraphs, at most one dark pill button, a thin rule, and a
  small grey footer that names Codewire and says why the email was sent;
- no images, tracking pixels, remote fonts or dark-mode styles.

The text part writes every link out. Codewire's own servers send as
`Codewire <hello@codewire.sh>` (Dev: `Codewire <hello@codewire-dev.sh>`).
The one exception is feedback to the operator (#5466): it carries a person's
own words, so it goes as plain text only. To see every email,
`EMAIL_PREVIEW_DIR=<dir> cargo test -p codewire-idp -p codewire-billing --lib
write_email_previews -- --ignored` writes each one as `<name>.html` and
`<name>.txt`.

Organization invitation email goes through an outbox: CreateInvitation, in
orchestration, queues a row in `org_invitation_emails` in the invitation's
transaction, and every IdP replica sends due rows every 2 seconds, each row
once (`FOR UPDATE SKIP LOCKED` and a 60-second claim). A failed send is retried
after 1 and then 5 minutes and failed after the third attempt. With email
delivery disabled, the IdP marks each invitation email failed with "email
delivery is not configured on this server", which the inviter sees. The email
holds no invitation token: it tells the invitee to sign in at `FRONTEND_URL`
`/login` with the invited address and run `cw org accept <slug>`. No setting
controls it.

## Sign-up

`IDP_SIGNUP` chooses how the IdP admits a new account. Every mode runs the
same sign-up; the mode decides only what admits an account and what a
sign-up that nothing admits does. With mail, every address is verified by
email before it can sign in (#4481).

- `review`, the default: a Turnstile challenge; a code whose SHA-256 digest
  is in `IDP_SIGNUP_INVITE_CODE_HASHES` admits at once, and anyone else waits
  for access review with a reason.
- `open`: a Turnstile challenge; everyone is admitted, including a sign-up
  with GitHub or Google, which signs in at once.
- `invite-only`, for a self-hosted server: setup creates the admin
  (`codewire-idp create-admin`, below), and no sign-up is taken before it
  has. Then an organization invitation for the person's exact address admits;
  anyone else waits, disabled, for the admin to enable them. Turnstile is
  checked only when its keys are set, and never for a sign-up from an invite
  link. `IDP_SIGNUP_REASON=required` makes a sign-up without an invite say
  why. On a server with no mail the admin vouches for each address: by handing
  over an invite link, by creating the admin, or by enabling a waiting
  account, and an invite link admits a sign-up for 24 hours after it was
  issued. If the server adds mail later, each vouched account, the admin
  included, verifies its address by email at its next sign-in. Sign-up with
  GitHub or Google is refused; connect them in Settings after signing up.

On every server, an organization invitation's link admits a sign-up at
exactly the invited address at once, with no code, review or reason, and
without the Turnstile challenge. The link is an admin's copied link or the
invitation email's link. With mail the address is still verified by email
before it signs in, and the invitee then accepts the invitation signed in.

| Variable | Required | Meaning | Example |
|---|---|---|---|
| `IDP_SIGNUP` | No | `review` (the default), `open` or `invite-only`. Any other value stops the IdP from starting. | `invite-only` |
| `IDP_SIGNUP_REASON` | No | `required` asks a sign-up that waits for the admin what they want to build; the admin reads it on Admin → Manage account access. Review mode always asks. | `required` |
| `IDP_METRICS_ADDR` | No | Where the IdP serves `/metrics` on its own, default `0.0.0.0:8092`. The port Prometheus scrapes is named `http`; the API port is `api` (8091). A NetworkPolicy admits the metrics port from every source, because Prometheus runs on host networking, and the API port only from the edge and the dashboard. | `0.0.0.0:8092` |

### Sign-up limits

The IdP refuses a sign-up past either of two counts:
- 30 an hour from one client address: an IPv4 address, or an IPv6 /64, which
  lets an office or a class on one network sign up together;
- 100 an hour across the server.

A sign-up counts once it has passed its own checks (Turnstile and the
reason) and before its account is looked up; an invited sign-up on an
invite-only server doesn't count. The refusal is 429 `rate_limited` with
`Retry-After`.

**The client address** is the last `X-Forwarded-For` hop. Behind the bundled
Caddy alone that is the visitor's address, because Caddy replaces any hop the
client sent with the address it connected from. If another proxy sits in front
of your edge, such as a CDN or a load balancer, the edge must still send the
visitor's address as the last hop, not that proxy's. Otherwise every sign-up
through the proxy counts against the proxy's few addresses and is refused
after thirty. To check, read the IP Address of the newest `user.signup` or
`user.signup.access_requested` row on Admin → Audit Log: it should be the
address of whoever signed up. A sign-up with no `X-Forwarded-For` at all
counts only against the server-wide limit.

**A larger group behind one shared address**, such as a conference on one
network, can reach the per-address count. There is no admin page for the
counts yet. Until there is, raise one with SQL against the application
database; the new value takes effect at once:

```sql
INSERT INTO rate_limit_settings (name, max_requests, updated_by)
VALUES ('signup_address', 100, 'operator')
ON CONFLICT (name) DO UPDATE
   SET max_requests = EXCLUDED.max_requests, updated_by = EXCLUDED.updated_by,
       updated_at = now();
```

`signup` is the server-wide count. Deleting the row returns the default.

Setup makes the server's admin before anything else:

```sh
printf '%s\n' "$password" | codewire-idp create-admin --email admin@example.com
```

The password is read from stdin, so it never appears in a process list. A
second run changes nothing once an admin exists. With mail, the admin verifies
the address before signing in, like any account; without mail, setup vouches
for it.

## Sign in with GitHub or Google

The IdP offers "Continue with GitHub" and "Continue with Google" on the
sign-in and sign-up pages for each provider whose OAuth client is configured.
Each provider's pair is all or none: with neither value the provider is off
and its button is not shown; with only one, the IdP refuses to start. Both
providers are off by default, including when self-hosting. The client secrets
are never logged. In the Kubernetes manifests the IdP reads all four keys,
each optional, from the Secret `codewire-idp-oauth`.

| Variable | Required | Meaning | Example |
|---|---|---|---|
| `CODEWIRE_OAUTH_GITHUB_CLIENT_ID` | With its secret | The GitHub OAuth App's client ID. | `Ov23li…` |
| `CODEWIRE_OAUTH_GITHUB_CLIENT_SECRET` | With its client ID | That OAuth App's client secret. | |
| `CODEWIRE_OAUTH_GOOGLE_CLIENT_ID` | With its secret | The Google OAuth client's ID (a web application client). | `…apps.googleusercontent.com` |
| `CODEWIRE_OAUTH_GOOGLE_CLIENT_SECRET` | With its client ID | That client's secret. | |

Register each provider's callback as `FRONTEND_URL` plus
`/api/auth/oauth/github/callback` or `/api/auth/oauth/google/callback`, for
example `https://codewire.example.com/api/auth/oauth/github/callback`. The IdP
asks GitHub for `read:user user:email` and Google for `openid email profile`.
The edge must send `/api/auth/oauth/` to the IdP, as the manifests and
Caddyfiles do. [dev/AUTH-POLICY.md](dev/AUTH-POLICY.md) says how a provider
identity becomes a Codewire account.

## Stripe billing

Billing is disabled unless `STRIPE_SECRET_KEY` is set.

| Variable | Required | Meaning | Example |
|---|---|---|---|
| `STRIPE_SECRET_KEY` | Required for billing | The Stripe secret key. An `sk_live_` key selects live prices; any other key selects test prices. | `sk_test_…` |
| `STRIPE_WEBHOOK_SECRET` | Required with `STRIPE_SECRET_KEY` | The signing secret of the Stripe webhook endpoint. Without it, billing refuses every delivery. | `whsec_…` |
| `FRONTEND_URL` | Yes | The dashboard origin. Checkout and portal redirects must stay on it, and it names the default webhook URL below. | `https://codewire.example.com` |
| `STRIPE_WEBHOOK_URL` | No | The public URL of billing's Stripe webhook endpoint. Unset or empty means `FRONTEND_URL`'s origin plus `/api/webhooks/stripe`. `off` disables the endpoint check, for example when `stripe listen` forwards events in development. | `https://billing.example.com/api/webhooks/stripe` |
| `CODEWIRE_STRIPE_REQUIRE_TEST_KEY` | No | `on` makes billing refuse to start with anything but a test key, so a test environment can never charge a real card. Unset, empty or `off` accepts any key. Any other value stops billing. | `on` |
| `CODEWIRE_CREDIT_ENFORCEMENT` | No | Set on billing and orchestration. `on` enforces prepaid compute credit: an empty balance charges the card, creates, starts and snapshot captures are refused without credit, and running sandboxes stop 24 hours after credit runs out, shown as `stopped (credit)`. Unset, empty or `off` does none of these, and metering still draws usage from the balance. Any other value stops the service. | `on` |
| `CODEWIRE_IDLE_STOP` | No | Set on orchestration. `on` stops a running cloud Sandbox that has an idle timeout (`idle_stop` in codewire.yaml, `cw create --idle-stop`, `cw update --idle-stop`) once it has had no activity for that long, keeping its disk; it then shows as `stopped (idle)` ([docs/dev/IDLE-STOP.md](dev/IDLE-STOP.md)). Unset, empty or `off` stops nothing; the timeouts are still recorded. Any other value stops the service. | `on` |
| `BILLING_METRICS_ADDR` | No | Where billing serves `/metrics` on its own, default `0.0.0.0:8083`. The port Prometheus scrapes is named `http` and serves nothing but `/metrics`; the API port is `api` (8081) and serves no metrics. A NetworkPolicy admits the metrics port from every source, because Prometheus runs on host networking, and the API port only from the edge and the dashboard (#4901). | `0.0.0.0:8083` |
| `CODEWIRE_BILLING_RECEIPTS` | No | Who emails the receipt for a paid invoice. Unset, empty or `codewire`: billing sends its own receipt to the organization's owner. `stripe`: billing sends none, for an account whose Stripe "Successful payments" customer email is on, so nobody gets two. Either way billing keeps the Stripe customer's email set to the current owner's before each purchase. Low-credit, payment-failed and the other billing emails are always billing's. Any other value stops billing. | `stripe` |

The sign-up credit is not a deployment setting. A platform admin sets it on
the admin Billing page, under Billing Settings, as `signup_credit_cents`: the
euro cents a new organization is granted once when it is created, from 0 (off,
the default) to 100000 (EUR 1,000). Each change is audited. Existing
organizations keep what they have, and the pricing page mentions a sign-up
credit only while it is above 0.

With Stripe configured, every billing replica checks its webhook endpoint at
startup and then hourly, using its own key. It lists the account's webhook
endpoints and requires exactly one endpoint for the webhook URL. That
endpoint must be enabled and in the key's mode, use the Stripe API version of
billing's SDK, and send exactly the event types billing handles:
`checkout.session.completed`, `invoice.created`, `invoice.paid`,
`invoice.payment_failed` and `invoice.finalized`. Billing sells no
subscriptions (#3381), so an endpoint that still sends the
`customer.subscription.*` events reports `degraded` until they are removed
from it. The one other type it may also send is
`customer.updated`, the delivery check's sentinel event below.

A mismatch logs `billing: Stripe webhook endpoint check failed` at ERROR with
every difference. It also sets the `codewire_billing_stripe_webhook_endpoint_healthy`
metric to 0 and reports `degraded` at billing's internal
`/healthz/stripe-webhook-endpoint`. It never fails readiness or liveness, so
a Stripe outage or a mismatched endpoint cannot take billing out of service.
When Stripe cannot be reached, the report says `unknown` and the metric keeps
its last value.

The endpoint check proves the endpoint is configured; the delivery check proves
Stripe's deliveries arrive and pass signature verification with the secret
billing holds. A deployment opts in by creating one Stripe customer with
metadata `codewire_sentinel` = `delivery`. Once a day (first ten minutes after
start), the billing leader:

1. finds that one customer (`sentinel`);
2. sets its `codewire_probe` metadata, which Stripe answers with a
   `customer.updated` event and no charge (`touch`);
3. waits up to ten minutes for a `customer.updated` delivery recorded after the
   touch that Stripe, asked by the event's id, reports as the sentinel's with
   this touch's probe; billing records an event only after its signature
   verifies, and another customer's update doesn't count (`delivery`);
4. posts one event signed with a wrong secret to its own webhook route and
   expects 400 (`forged`).

A failed step logs `billing: Stripe webhook delivery check failed` at ERROR,
naming the sentinel and the step. It sets
`codewire_billing_stripe_webhook_delivery_healthy` to 0 and reports `degraded`
at billing's internal `/healthz/stripe-webhook-delivery`. Like the endpoint
check it never fails readiness or liveness. With no sentinel customer, or
without Stripe, the report says `disabled`. `BILLING_LOOPS` without
`stripe-delivery-check` turns it off.

### Card setup limits

Saving a card on the Billing page starts a card setup, one Stripe
SetupIntent per try. Testing stolen cards takes many tries, so billing
refuses a card setup, before it calls Stripe, past any of three counts:
- 10 an hour for one organization;
- 20 a day for one user, across all their organizations;
- 60 an hour from one client address: an IPv4 address, or an IPv6 /64
  (`card_setup_address`, #4901). That lets an office or a class on one
  network, signing up together as the sign-up limits allow, each save a
  card in one or two tries. One machine with many accounts still can't try
  cards without bound.

Every try counts, accepted or not; opening the form counts nothing. A refusal
is 429 `rate_limited`, saying when to try again. Billing counts it in
`codewire_rate_limit_refusals_total`, labelled with the limit's name, and logs
the organization and user, never the address. No setting changes the
organization and user counts.

**The client address** is the last `X-Forwarded-For` hop, as for sign-up. A
card setup from the dashboard carries the hop the dashboard's own request
arrived with, which replaces whatever `X-Forwarded-For` the browser sent; one
through the public API carries the edge's hop. That hop can be trusted only
because nobody can choose it. The hosted edge takes the address from its
CDN's `CF-Connecting-IP`, refuses a request without one, and accepts only
connections that present the CDN's origin-pull client certificate, so no one
can reach it around the CDN. Behind the bundled Caddy alone it is the address
Caddy connected from. A self-hosted deployment with another proxy in front of
its edge, and nothing equivalent stopping clients from bypassing that proxy or
setting the address, must not rely on the address count. Only the card setup
reads the address. A card setup with no address is refused with 400
`client_address_required` before anything is counted, so a proxy in front of
billing must send one, as the bundled edge does. Billing's API port admits
only the edge and the dashboard (a NetworkPolicy, as on the IdP), so nothing
else in the cluster can write the hop billing counts. Its metrics port is open
to Prometheus.

**A larger group behind one shared address** can raise the address count
with SQL against the application database, as for `signup_address`:

```sql
INSERT INTO rate_limit_settings (name, max_requests, updated_by)
VALUES ('card_setup_address', 120, 'operator')
ON CONFLICT (name) DO UPDATE
   SET max_requests = EXCLUDED.max_requests, updated_by = EXCLUDED.updated_by,
       updated_at = now();
```

Deleting the row returns the default.

## Workspace storage

| Variable | Required | Meaning | Example |
|---|---|---|---|
| `SANDBOX_WORKSPACE_STORAGE_CLASS` | Required by orchestration, except under the `confidential` runtime profile | The StorageClass of every `commodity` and `standard` workspace volume. There is no default: empty, orchestration refuses to start. A disk resize expands the volume only when this class allows volume expansion. | `standard` |
| `SANDBOX_CONFIDENTIAL_WORKSPACE_STORAGE_CLASS` | Only where confidential environments are enabled | The StorageClass of every confidential workspace volume, claimed as a raw `volumeMode: Block`, `ReadWriteOncePod` device that the guest encrypts. There is no default: empty, every confidential environment is refused before any workload is created. The class must give a fresh, all-zero device of exactly the requested size with no host encryption layer, and a confidential volume never grows. | `linstor-confidential` |

| `SANDBOX_CONFIDENTIAL_STORAGE_ENABLED` | No | `true` lets the deployment create, start, resize and reach confidential environments. Base `config.env` sets `false`, and Production keeps it off. | `true` |
| `CONFIDENTIAL_ACTIVATIONS_PER_HOST` | No | How many confidential environments may activate their workspace volume at once on one confidential host, a whole number from 1 to 16; unset or empty is 1. Activating the encrypted volume in the guest is slow and shares the host's disk, so a create or start beyond the bound waits, showing "waiting for confidential capacity on this host", and fails after 30 minutes with "no confidential capacity became free". The bound is cluster-wide, counted over the Ready, schedulable nodes the `confidential` RuntimeClass schedules to. With one such node it is this number. With several, or when they can't be counted, it is 1, because the slot is taken before the scheduler picks a node and nothing yet keeps two activations off one node; per-host placement (#4296) will lift that (#4281). Any other form stops orchestration at startup. | `2` |

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
`disk_limit_exceeded`; a disk never shrinks. A create from a snapshot whose
request names no disk gets at least the snapshot's size, rounded up to a whole
GiB, over the default and a preset's disk alike; one that names a smaller disk
is refused with `snapshot_disk_too_small`, which gives the snapshot's size
(#6276). These limits are in the code
(`crates/codewire-orchestration/src/api/create.rs`), not configuration. The
class's thin capacity must hold every pool member and live workspace at its
size. A grown disk is expanded by the StorageClass's CSI driver, online when
it can be and otherwise at the Pod replacement `cw resize` asks for; the DinD
bootstrap then grows the Docker data image (`CODEWIRE_DOCKER_DATA_SIZE`, the
disk less 2 GiB) online with `resize2fs` at the next Pod start.

| Variable | Required | Meaning | Example |
|---|---|---|---|
| `SANDBOX_VOLUME_SNAPSHOT_CLASS` | No | VolumeSnapshotClass of hosted disk snapshots (`cw --cloud snapshot`). Empty, the default, refuses them. |
| `SANDBOX_WARM_POOL_SHAPES` | No | Comma-separated warm pools, `<cpu>m/<memory>Mi/<disk>Gi=<members>` with 0 to 16 members each. A shape at 0 keeps no members: its pool drains, and so does a previous release's pool of that shape. A create of exactly a pool's shape adopts a prestarted member. On `standard` the members are `standard` Pods, and only while `SANDBOX_STANDARD_IMAGE_DISK` boots the canonical workspace image; with any other disk every pool drains as an invalid configuration, since the canonical image's creates then go to `commodity` (#5602). The default create shape is `2000m/8192Mi/80Gi`, so a pool of that shape serves default creates. Empty means no pools, but clearing it leaves existing pool objects in place: to remove pools, set each shape to 0 first and wait until their members are gone. | `2000m/8192Mi/80Gi=2` |
| `SANDBOX_WARM_POOL_MAX_NODE_PERCENT` | No | Maximum percentage of the smallest schedulable runtime node's allocatable CPU and memory reserved by all unclaimed warm pools together, including Docker requests and RuntimeClass overhead. A whole number from 1 to 100; unset or empty defaults to 25. Deployments can set different budgets. Pools are clamped in configured shape order. Invalid values drain existing pools, as other invalid pool configuration does; with no configured shapes, the reconciler stays inert. Raising this ceiling does not add members beyond the configured counts. | `50` |

## Workspace CPU

A workspace's CPU request can be lower than its vCPUs, so more sandboxes fit on a node while each VM keeps the vCPUs it was asked for. Only the scheduler's reservation changes: the CPU limit, quota, billing and the shape users see stay on full vCPUs, and the workspace's memory request and the requests of DinD and the Kata overhead do not change. Under contention, a sandbox gets CPU in proportion to its request.

The setting applies to sandboxes created after it changes, and a change rotates the warm pools like a release. An existing sandbox keeps the ratio it runs at, through a stop, a start or a resize, until it is replaced. Confidential environments are always 1:1.

A global administrator can give an organization dedicated CPU (`SetOrganizationDedicatedCpu`): its new sandboxes are 1:1 whatever this setting says. While the deployment shares, they start cold, because the warm pools share.

When the scheduler refuses a workspace Pod for lack of a resource for 60 seconds without a break, a create or start ends there instead of waiting out its timeout, with the error code `no_capacity` and a message for the user. A sandbox that has never run is removed; any other goes back to stopped, with its files. A resize that replaces the Pod still waits out its timeout. `codewire_environment_no_capacity_total` counts refusals by `outcome`: `destroyed` or `stopped`.

A create also ends early when a container of its workspace Pod cannot start: after 60 seconds for an image that cannot be pulled, which the kubelet retries, and after 15 seconds for a container that cannot be created, run or started. The sandbox, which has never run, is removed, with the error code `container_start_failed` and a short message that names the image or the container, the cause, HTTP status and exit code where they are known, and what to do next: for example "The image `IMAGE` could not be pulled: access denied (HTTP 401). Check the image name and who may pull it." The message is built from fixed words and checked values only. The container runtime's own text can quote a request or a configuration, so it is stored nowhere and returned by no API; it goes to the server's log, with anything shaped like a secret removed, where an operator finds it by the environment's ID. A container that is still being created or initialized is never counted as failed, however long it takes.

A create the platform ended this way, or for lack of capacity, is destroyed at once and holds no quota. So that its user can still see why it failed, `cw ls` lists it for 24 hours as `failed`, with its age and its reason; `cw info` prints the whole message, and `cw rm` answers at once because nothing is left to remove. The API returns these rows only to a caller that sets `include_failed_creates` on `ListEnvironments`, with their true state, `destroyed`; every other listing, and every command that resolves a name, sees only live environments. A new environment may take the failed one's name straight away.

| Variable | Required | Meaning | Example |
|---|---|---|---|
| `CODEWIRE_SANDBOX_CPU_SHARING_RATIO` | No | How many vCPUs share one reserved CPU: a whole number from 1 to 8. A workspace requests its vCPUs divided by this, rounded up. Unset, empty or `1` means off, one reserved CPU per vCPU. Any other form stops orchestration at startup. | `2` |

## Capacity view

The admin capacity page shows, per runtime node, what is reserved and used and how many more sandboxes of each shape fit. It reads the cluster's own Prometheus, which needs kube-state-metrics and node-exporter. A number it can't read within a few seconds shows as not available, never as zero, and each number shows its age.

| Variable | Required | Meaning | Example |
|---|---|---|---|
| `CODEWIRE_CAPACITY_PROMETHEUS_URL` | No | The Prometheus that scrapes this cluster: an `http` or `https` URL with no credentials, query or fragment. Unset or empty means reservations and usage are not available on the page. Any other form stops orchestration at startup. | `http://prometheus.monitoring.svc:9090` |

## Support address

The dashboard header's Support button writes an email to this address with the subject "[Support]".

| Variable | Required | Meaning | Example |
|---|---|---|---|
| `CODEWIRE_SUPPORT_EMAIL` | No | The address the dashboard's Support button writes to. Unset or empty hides the button. Any value that is not one email address stops the dashboard at startup. | `support@example.com` |

## Updates page

The dashboard's public `/updates` page lists the posts of one site in a Liminal CMS, newest first, and the console sidebar links it above Documentation. The dashboard reads `GET /api/v1/posts` with the site's key at most once every five minutes, keeps the last list it read while the CMS is down, and cleans each post's HTML again before showing it. Images load only from `LIMINAL_MEDIA_ORIGIN`, the one image host the page's Content-Security-Policy admits; without it posts show no images. Without both `LIMINAL_ORIGIN` and `LIMINAL_API_KEY` there is no page and no link.

Each read of the CMS is one `updates.read` trace span, exported when the dashboard's trace export is on (`OTEL_EXPORTER_OTLP_ENDPOINT`). Its `outcome` is `ok`, `timeout`, `connect`, `status` (with `http.response.status_code`), `too_large`, `parse` or `request`. A failed read also writes one JSON warning to the dashboard's standard output with the same two fields, so a deployment without trace export still records why. Neither ever carries the key, a URL or the response. That warning is the dashboard's only log line: its log filter admits the Updates reader at `WARN` and nothing else, whatever `RUST_LOG` says (#5409).

| Variable | Required | Meaning | Example |
|---|---|---|---|
| `LIMINAL_ORIGIN` | No | The CMS origin, `https://` with no path; plain `http://` only on loopback, since the key is sent to it. Set together with `LIMINAL_API_KEY`; one without the other stops the dashboard at startup. | `https://cms.example.com` |
| `LIMINAL_API_KEY` | No | The site-scoped read key from the site's API keys screen. A secret: deliver it from a Secret, never a ConfigMap. The manifests read it from the `codewire-dashboard-liminal` Secret and `LIMINAL_ORIGIN` from the `codewire-dashboard-public-config` ConfigMap, both optional. | |
| `LIMINAL_MEDIA_ORIGIN` | No | The origin the CMS serves post images from, `https://` with no path (plain `http://` only on loopback). Image URLs elsewhere lose their `src`. Needs the two values above; from the same ConfigMap. | `https://media.example.com` |

## Web analytics

The dashboard can count page views on its public pages with a self-hosted Umami (infra#2677). The tag is Umami's own tracker, served from the dashboard's assets with its Subresource Integrity hash, and a small hook of Codewire's that runs first. It sets no cookie and stores nothing in the browser. It sends the page's path with no query string or fragment, and no referrer from the dashboard's own host or its subdomains. It sends only when the page's host is the host of `CODEWIRE_PUBLIC_ORIGIN`. Tagged pages' Content-Security-Policy adds `CODEWIRE_ANALYTICS_ORIGIN` to `connect-src` and changes nothing else.

The tagged pages are `/`, `/pricing`, `/privacy`, `/terms`, `/updates` and the docs under `/docs`. The homepage and the docs are tagged for every visitor, signed in or not, because a shared cache keeps one copy of each for everyone (see [Caching at the edge](#caching-at-the-edge)). The other four leave the tag out for a request that carries a session cookie, or a Cookie header that can't be read. The docs are static, so the dashboard adds the tag as it serves each page, and the page's own meta policy gains the same one connection. A docs redirect page states no connection and stays untagged. No other page is ever tagged, sign-in, sign-up, password reset, verification, invitation and device pages included. Without both values, no page is tagged and every page and policy is served as built.

| Variable | Required | Meaning | Example |
|---|---|---|---|
| `CODEWIRE_ANALYTICS_ORIGIN` | No | The Umami origin the tracker sends to, `https://` with no path. Set together with `CODEWIRE_ANALYTICS_WEBSITE_ID`; one without the other stops the dashboard at startup. From the `codewire-dashboard-public-config` ConfigMap. | `https://analytics.example.com` |
| `CODEWIRE_ANALYTICS_WEBSITE_ID` | No | The Umami website's ID, a UUID. It isn't a secret: every tagged page shows it. From the same ConfigMap. | `00000000-0000-4000-8000-000000000000` |

## Operator notices

The IdP emails the operator once per new person: when an email sign-up's
address is first verified, or when a GitHub or Google sign-up is made. It
names the address, how they signed up, when, and whether they wait for
review, and links to Admin → Manage account access. At most 10 an hour; the
11th sends one "more people are waiting" notice instead. It needs mail
(SES) and never delays or fails a sign-up. The rules are in
[AUTH-POLICY](dev/AUTH-POLICY.md#the-operators-sign-up-notice).

The IdP also emails the operator each piece of feedback sent with `cw
feedback` (#5466). Orchestration, which stores the feedback, holds no mail
credential: in the same transaction it writes an outbox row naming only the
feedback, and the IdP sends it, as it sends organization invitations, with
up to three attempts. The IdP only reads `feedback` and sends and records
`feedback_notices`; it writes no feedback. The email is plain text, from the
fixed sender, with the subject `Codewire feedback <id>`. Its body names the
sender, with "(verified)" or "(not verified)" beside the address, or
"Anonymous", their organization, what `cw` attached and the time, then the
message as sent, without control characters other than line breaks and tabs
and without Unicode line and paragraph separators, direction overrides and
isolates, never longer than feedback's stored maximum (10 KB), and links to
Admin → Feedback on the configured `FRONTEND_URL`. Reply-To is the signed-in
account's verified email address, only when it is one plain address;
anonymous feedback, and an account without one, get no Reply-To. An address
an anonymous sender gave for a reply is shown in the body, marked as not
verified. Codewire never emails a reply address itself: each piece of
feedback sends one email, to the operator. Nothing the sender typed, and no
name, reaches a header. At most 10 an hour, counted apart from the sign-up
notices; the 11th sends one "More feedback is waiting" email instead,
holding only how many arrived and the Admin → Feedback link, and every
message is still stored and on the admin page. A failed send is logged with
the feedback's ID, a fixed reason and the provider's error code, never the
message, a name or an address, and never fails the submit.

Billing emails the operator once per paid credit purchase (#5358):
**Add credit**, with a saved card or through Stripe's page, and an
automatic top-up. It is sent when billing has handled the purchase's
`invoice.paid` delivery: an invoice whose metadata `kind` is
`credit_top_up` or `credit_checkout`. Stripe delivers an event at least
once, and billing handles each event ID once, skipping a repeat, so one
purchase sends one notice. The notice is sent in its own task once the
delivery has been handled. The subject is "Codewire: credit bought, <amount>". The body names
the organization (its name, escaped, and its slug), the amount and
currency, whether it was **Add credit** or an automatic top-up, and the time
in UTC. It links to that organization's admin page,
`<FRONTEND_URL>/admin/organizations/<id>/`. It is a notice, not a receipt:
no card, payment method, invoice number or link, Stripe ID, buyer, or token
of any kind, and nothing the organization typed reaches a header. At most 10
an hour, counted apart from the sign-up and feedback notices; the 11th sends
one "More credit purchases" email instead, holding only how many were paid
and the Admin → Organizations link. A failed send is logged with the
invoice's ID and a fixed reason, is not retried, and never fails the
delivery, so Stripe never redelivers a purchase for its notice.

| Variable | Required | Meaning | Example |
|---|---|---|---|
| `CODEWIRE_OPERATOR_EMAIL` | No | Where the IdP sends the operator's sign-up notices and feedback emails, and billing its credit purchase notices. Unset or empty sends none of them, the default. Any value that is not one email address stops the service that reads it at startup. | `operator@example.com` |

## Browser origins

Every Codewire service the browser calls is served from the dashboard's own origin, so by default no service answers cross-origin (CORS) requests at all.

| Variable | Required | Meaning | Example |
|---|---|---|---|
| `CODEWIRE_CORS_ALLOWED_ORIGINS` | No | Comma-separated browser origins, each exactly `scheme://host[:port]` with `http` or `https` and no path, query or wildcard, that may call the Codewire backend services cross-origin, for a deployment whose browser front end is on another origin. Only these get `Access-Control-Allow-Origin`, for `GET` and `POST`, never with credentials. Unset or empty means no CORS. Any other form stops the service at startup. | `https://app.example.com` |

## Caching at the edge

The dashboard sends `Cache-Control: no-store, private` on every page,
fragment, event stream, action and redirect, and on any response that sets a
cookie, so no cache keeps one visitor's response for another. Only these may
be cached, and each says so in its own `Cache-Control`: the content-hashed
assets under `/assets/`, the docs pages, and the homepage for a visitor who is
not signed in (`public, max-age=0, s-maxage=300`). An edge or CDN in front of
the dashboard must respect the origin's `Cache-Control` and never cache a
response that has none.

## Workspace network

| Variable | Required | Meaning | Example |
|---|---|---|---|
| `SANDBOX_EGRESS_BANDWIDTH` | No | The egress rate cap on every workspace Pod, rendered as its `kubernetes.io/egress-bandwidth` annotation: a positive whole number of bits per second with an optional `K`, `M` or `G` suffix. Unset or empty means `100M`. Any other form stops orchestration at startup. The cap holds only where the CNI enforces the annotation, such as Cilium with its bandwidth manager enabled; elsewhere the annotation is ignored. | `100M` |
| `CODEWIRE_SANDBOX_PUBLIC_MESH_URL` | No | The public `https` origin of the hosted Codewire Mesh service that cloud environments join networks on, with no path, query or credentials. Orchestration names it to each workspace daemon whose environment joins a network. Unset or empty means this deployment offers no hosted Mesh to environments, and a create that names a network is refused with `mesh_unavailable`. Any other form stops orchestration at startup. | `https://mesh.example.com` |
| `CODEWIRE_PLATFORM_NETWORK_POLICIES_ENABLED` | No | `true` turns on the organization network policies of `cw --cloud policy`: `NetworkPolicyService`, `--policy` on a hosted create or update, and each environment's network policy in its status. While it is off, every policy method and every create that names a policy is refused with `NETWORK_POLICIES_DISABLED` (UNAVAILABLE), environments report none, and hosted egress assigns every environment `open` whatever it selected; turning it back on restores the stored selections (#6120). Base `config.env` sets `false`. **Production keeps it off until something enforces hosted policies:** until cw-egress does (#4000), a hosted environment's selection is recorded and reported as not enforced, and its egress is not restricted. Any value other than `true` or `false` stops orchestration at startup. | `true` |
| `CODEWIRE_HOSTED_EGRESS_ENABLED` | No | `true` serves `EgressService` on orchestration's internal listener (8088): cw-egress on each node admits a broker-mode sandbox's egress stream there and receives the sandbox's policy. Unset means off: new Sandboxes are direct. The switch decides only what a create renders and whether a start moves a Sandbox made before it. With it off, orchestration still reads the broker settings (the gateway keys, `CODEWIRE_HOSTED_EGRESS_FENCE_REVISION` and `CODEWIRE_CLUSTER_DNS_IP` below) when every one of them is set, and checks them as with it on; then it keeps serving the broker-mode Sandboxes that exist, and every policy it writes for one follows that Sandbox's own mode, never the switch (#6070). Removing any of them with the switch off stops broker egress: each broker-mode Sandbox is refused by name and never given direct egress, and startup counts them in `codewire_egress_stranded_broker_sandboxes`. It needs orchestration to manage the workspace `NetworkPolicy`: with it on, every Sandbox orchestration renders on a VM runtime profile is broker-mode: labelled, with its TUN, the egress token and no cluster DNS, and with the `codewire-egress`, workspace-binding and `codewire-derp` Services' addresses, which it takes from the Service links Kubernetes gives its own Pod when it starts. A Service missing then refuses every broker-mode render, naming it, and one created or re-created later is seen at orchestration's next rollout; until then new Sandboxes fail closed. Orchestration's Deployment keeps `enableServiceLinks` on for this. A Sandbox made before the switch keeps today's template until it is made again. Orchestration admits a bound sandbox's stream only when the policy the cluster holds equals the one it renders, so a deployment that manages that policy itself has every bound sandbox refused. Each sandbox refused this way is counted in `codewire_egress_lockdown_failed_closed_total` by `reason`. **Production keeps it off until hosted egress has been observed working on Dev** (#4000). Any value other than `true` or `false` stops orchestration at startup. It is a key of the `codewire-hosted-egress` ConfigMap in orchestration's namespace (`deployments/k8s/orchestration/hosted-egress.yaml`), never of `codewire-config`: the template admission policy reads the same ConfigMap as its parameter. That policy holds every SandboxTemplate orchestration writes, pool and per-environment (#5002). On, it admits only broker-mode templates, so a deployment whose runtime profile is a diagnostic one (`runc` or `none`) keeps the switch off; off, it admits only today's; a missing ConfigMap denies every template, and with it every new environment. A confidential per-environment template may also reach its Trustee KBS on one port, by namespace (`codewire-trustee`, TCP 8080), or, when `kbsPeer` also lists the key broker's Pod labels as `key=value`, by namespace and exactly those labels, as orchestration renders it with `SANDBOX_KATA_COCO_KBS_PEER` set (#4000). An overlay whose KBS lives elsewhere, or that names its Pods, patches the policy's `kbsPeer`; its port must equal the key-broker URL's. Orchestration cannot write the ConfigMap, and it can never take broker mode off a Sandbox's pod template. Admission checks a template only when it is written, so templates already stored when the switch turns on are never re-checked: re-create them before it goes on. A Sandbox from one that stays is refused by the lockdown check, which compares every NetworkPolicy that selects it, its template's included (#4964). | `true` |
| `CODEWIRE_EGRESS_PLATFORM_ALLOWS` | No | Leave unset. It is for a placement whose control plane is outside the cluster, which every broker-mode sandbox would reach whatever its network policy. A single-cluster install sets none: a broker-mode daemon reaches the control plane, DERP and Mesh inside the cluster (#4000). It never names a host whose addresses other sites share. Nothing enforces an entry yet, so while `CODEWIRE_HOSTED_EGRESS_ENABLED` is on, any entry stops orchestration at startup; while it is off the list is not read. | unset |
| `CODEWIRE_HOSTED_EGRESS_DAEMON_REPOSITORY` | With `CODEWIRE_HOSTED_EGRESS_ENABLED` | The daemon image's repository, with no tag or digest, in `codewire-hosted-egress`. The template admission policy admits the privileged TUN init container only as `<repository>@sha256:<digest>`, the same image the `codewire-bin` volume is filled from: its image volume, or in a confidential template the `codewire-daemon-init` container. An empty or malformed value admits no broker-mode template but a `standard` one, which has no TUN init. Only the policy reads it. | `registry.example.com/codewire/daemon` |
| `CODEWIRE_HOSTED_EGRESS_GATEWAY_NAMESPACE`, `CODEWIRE_HOSTED_EGRESS_GATEWAY_NAME`, `CODEWIRE_HOSTED_EGRESS_GATEWAY_OWNER_NAMESPACE`, `CODEWIRE_HOSTED_EGRESS_GATEWAY_PORT` | With `CODEWIRE_HOSTED_EGRESS_ENABLED` | The public gateway's proxy Pods, which a broker-mode workspace reaches inside the cluster, in `codewire-hosted-egress`: their namespace, the owning Gateway's name and namespace (the gateway controller's `gateway.envoyproxy.io/owning-gateway-name` and `-namespace` Pod labels) and their listener port. The warm-pool template admission policy admits a broker-mode template's egress to exactly that peer. A missing value leaves no gateway peer, so a template that names one is refused. Orchestration reads them too, as every broker-mode template's gateway peer; with the switch on, a missing one stops its startup. | `gateway-proxies`, `public`, `gateway`, `10443` |
| `CODEWIRE_HOSTED_EGRESS_GATEWAY_CLUSTER_IP` | With `CODEWIRE_HOSTED_EGRESS_ENABLED` | The public gateway Service's ClusterIP, a bare IPv4 address, in `codewire-hosted-egress`. Deploy pins the Service to this address, and its hosted policy holds the two equal. A broker-mode workspace reaches the control plane, its coordinator and Mesh at `<this>:443` by address (`CODEWIRE_API_ADDR`, `CODEWIRE_MESH_ADDR`), since it resolves no names. Orchestration reads it once at startup; with the switch on, a missing value or anything but an IPv4 address stops its startup. | `10.44.0.43` |
| `CODEWIRE_HOSTED_EGRESS_GATEWAY_SERVICE` | With `CODEWIRE_HOSTED_EGRESS_ENABLED` | The gateway Service in `CODEWIRE_HOSTED_EGRESS_GATEWAY_NAMESPACE` whose ClusterIP `CODEWIRE_HOSTED_EGRESS_GATEWAY_CLUSTER_IP` must equal, in `codewire-hosted-egress`. Orchestration reads that one Service by name at startup and every 30 seconds, through a Role the deployment grants for exactly it (`get`, by name, no list or watch). It refuses every broker-mode render unless its last read is under 60 seconds old and found the configured address. A refusal names the Service and both addresses and is counted in `codewire_egress_gateway_check_refused_total` by `reason` (`differs`, `unreadable`, `stale`, `not_read`, `not_started`), which an alert reads. With the switch on, a missing value stops its startup. | `envoy-codewire-public` |
| `CODEWIRE_HOSTED_EGRESS_FENCE_REVISION` | With `CODEWIRE_HOSTED_EGRESS_ENABLED` | The infra#1822 fence revision the cluster runs, a number, in `codewire-hosted-egress`. Orchestration stamps it on every broker-mode Pod as `codewire.sh/egress-fence-revision`. With the switch on, a missing or non-numeric value stops its startup. | `2` |
| `CODEWIRE_STANDARD_IMAGE_DISK_REFERENCE` | With `SANDBOX_STANDARD_IMAGE_DISK` | The `standard` workspace disk the template admission policies admit, in `codewire-hosted-egress`: exactly the first field of `SANDBOX_STANDARD_IMAGE_DISK`, the disk image by digest. A `standard` template, per-environment or pooled, must mount exactly that reference as `image-disk` and no other image; empty, missing or not pinned by digest, no new `standard` template is admitted. An update that keeps an existing Sandbox's image volumes is unaffected, so a republished disk strands nothing. | `registry.example.com/codewire/workspace-disk@sha256:<digest>` |
| `CODEWIRE_CLUSTER_DNS_IP` | With `CODEWIRE_HOSTED_EGRESS_ENABLED` | The cluster DNS Service's IPv4 address, in `codewire-hosted-egress`. Orchestration renders it into every broker-mode workspace for the self-check's DNS probe, which must find it unreachable; the Pod resolves nothing. Only a bare IPv4 address is accepted: an IPv6 address, a name or a port stops orchestration's startup. | `10.44.0.10` |
| `CODEWIRE_EGRESS_ORCHESTRATION_URL` | For cw-egress | The `https` origin of orchestration's internal listener. Its host is only the name cw-egress verifies the certificate against and addresses requests to: cw-egress never resolves it, because its Pod has no cluster DNS. | `https://codewire-orchestration.example.svc.cluster.local:8088` |
| `CODEWIRE_EGRESS_ORCHESTRATION_ADDR` | For cw-egress | The IP address and port cw-egress dials for that origin, such as orchestration's Service cluster IP. Its port must be the URL's port (443 when the URL names none); otherwise, or when it is not an IP address and port, cw-egress refuses to start. | `10.96.0.20:8088` |
| `CODEWIRE_EGRESS_ORCHESTRATION_ROOTS` | For cw-egress | The file holding the public roots orchestration's internal certificate chains to, reread on every call. | `/run/codewire-orchestration-internal-roots/ca.crt` |
| `CODEWIRE_EGRESS_NODE_TOKEN_PATH` | For cw-egress | The file holding cw-egress's own projected service-account token, presented on every call to orchestration. | `/var/run/secrets/codewire/egress-node/token` |
| `CODEWIRE_EGRESS_REFUSED_ADDRESSES` | No | Comma-separated IP addresses, the cluster's own public ones, that every sandbox's broker refuses as an ordinary "not allowed". Empty refuses none beyond the fixed ranges; an entry that is not an IP address stops cw-egress at startup. | `203.0.113.9,2001:db8::1` |
| `CODEWIRE_EGRESS_DRAIN_SECONDS` | For cw-egress | How long, in whole seconds, a cw-egress that is told to stop keeps a sandbox that has open connections before it resets them once. A sandbox with none open moves to the node's new cw-egress at once. cw-egress refuses to start without it. The deployment's grace period must be at least 30 s longer. | `1800` |
| `CODEWIRE_HOSTED_INTERCEPTION_ENABLED` | No | `true` turns on credential interception for broker-mode sandboxes (#4001): each bound sandbox's egress assignment carries the deployment's interception bindings to cw-egress, the hosts the TLS front door serves, on 443, and its bind response says it is intercepted. Today every bound sandbox gets the same default set. The sandbox's daemon then delivers placeholder logins only, drops the managed Anthropic base URL, and projects the Anthropic placeholder each credential epoch brings; cw-egress does not act on the bindings yet (#4001). A warm-pool member that is not yet bound, or a sandbox whose egress does not go through cw-egress, never gets them. Unset means off, and behaviour is exactly as today. Requires `CODEWIRE_HOSTED_EGRESS_ENABLED`; on without it, or any value other than `true` or `false`, stops orchestration at startup. Hosted has no per-host switch: this setting is its rollout. | `true` |
| `CREDENTIAL_HOSTED_PLACEHOLDERS_ENABLED` | No | Read by the credential service, not orchestration. `true` makes a hosted Sandbox's leases carry its credential placeholders, derived under that environment's sealed key, and an intercepted Sandbox's credential epoch brings the placeholder it projects (#4001; `docs/dev/SECRETS-AND-CREDENTIALS.md`, "Per-environment placeholders" and "Hosted interception"). Off, an intercepted Sandbox projects no Anthropic bearer at all. With it on, the service refuses to start unless its database login holds `SELECT` and `INSERT` on `platform_placeholder_keys` and `CREDENTIAL_SANDBOX_NAMESPACE` is set. It must be turned on together with orchestration's hosted interception setting, never alone (#4001 step L). Unset means off. Any value other than `true` or `false` stops the credential service at startup. | `true` |
| `CREDENTIAL_SANDBOX_NAMESPACE` | For hosted interception | Read by the credential service. The Kubernetes namespace its sandbox Pods run in. Before an interception CA is created, the service reads the bound Pod by name there, and every 5 minutes a sweep forgets the CA of a Pod that has left (#5030; `docs/dev/SECRETS-AND-CREDENTIALS.md`, "The Pod check"). The namespace comes only from this setting, never from a request. Unset, the Pod check refuses as unavailable and no sweep runs, so the credential service refuses to start with `CREDENTIAL_HOSTED_PLACEHOLDERS_ENABLED=true` and this unset. A value that is not a valid Kubernetes namespace name stops the credential service at startup. | `sandboxes` |

## Sandbox identity

Orchestration can publish each organization's sandbox identity issuer:
`{issuer base}/orgs/<org id>`, with OIDC discovery at
`…/.well-known/openid-configuration` and its keys at `…/jwks.json`. It serves
them on a listener of its own, and nothing else answers there. The signing key
is an OpenBao transit key (`ecdsa-p256`, never exportable) that orchestration
can only read through its own Kubernetes-auth role. The feature is off unless
switched on, and switching it on needs every value below; a missing or
malformed one stops orchestration at startup. With it on, orchestration also
mints each Sandbox's tokens through the binding listener's
`IssueIdentityToken` ([dev/SANDBOX-IDENTITY.md](dev/SANDBOX-IDENTITY.md)).
The Sandbox's SPIFFE trust domain is `sandboxes.` and the host of
`FRONTEND_URL`, which must then be an `https` URL with a DNS host name.

| Variable | Required | Meaning | Example |
|---|---|---|---|
| `CODEWIRE_IDENTITY_ENABLED` | No | `true` serves the issuer; unset, empty or `false` serves nothing and binds no identity port. Any other value stops orchestration at startup. | `true` |
| `CODEWIRE_IDENTITY_ISSUER_BASE` | When enabled | The `https` URL every issuer starts with: a DNS host name, an optional port and path, no credentials, query, fragment or trailing slash, and never an IP address. Issuers and key URLs are built from it alone, never from a request's headers. The listener serves `/orgs/…` paths, so a base with a path needs the TLS front to strip it. | `https://identity.example.com` |
| `CODEWIRE_IDENTITY_SIGNER` | When enabled | Where the signing key lives. Only `openbao-transit` exists; there is no default. | `openbao-transit` |
| `ORCHESTRATION_IDENTITY_PORT` | No | The identity listener's TCP port. Unset or empty means `8089`. | `8089` |
| `CODEWIRE_IDENTITY_MINTING` | No | The operator's circuit breaker for minting. `off` refuses every token with `identity_unavailable` and asks OpenBao nothing; unset, empty or `on` mints. Any other value stops orchestration at startup while identity is enabled. Separately, 20 signing failures in a row stop minting by themselves for 60 seconds. It is read at startup, so a change takes effect when orchestration restarts. | `off` |
| `SANDBOX_IDENTITY_BAO_ADDR` | When enabled | The OpenBao origin, `https` only; an in-cluster `http` address is refused (#4853). | `https://openbao.example.com` |
| `SANDBOX_IDENTITY_BAO_EXPECTED_CLUSTER_ID` | When enabled | The OpenBao cluster ID every call checks first, so a misrouted address is refused before login. | `b7c2…` |
| `SANDBOX_IDENTITY_BAO_AUTH_MOUNT` | When enabled | The Kubernetes auth mount the Pod logs in through. | `kubernetes` |
| `SANDBOX_IDENTITY_BAO_ROLE` | When enabled | The role: the signer role for orchestration, the rotator role for the rotation job. | `sandbox-identity-signer` |
| `SANDBOX_IDENTITY_BAO_AUDIENCE` | When enabled | The OpenBao audience of the Pod-bound token the Pod logs in with. | `openbao-sandbox-identity` |
| `SANDBOX_IDENTITY_BAO_TRANSIT_MOUNT` | When enabled | The environment's own transit mount, which holds the key `sandbox-identity`. | `codewire-identity` |

The listener also needs the Pod's identity (`POD_NAMESPACE`,
`POD_SERVICE_ACCOUNT_NAME`, `POD_NAME`, `POD_UID`) and
`OPENBAO_KUBERNETES_API_AUDIENCE`, as the other OpenBao clients do.

Its responses:

- **Success** carries `Cache-Control: public, max-age=300`. Every error is
  `no-store`, so the TLS-terminating edge must respect the origin's
  `Cache-Control`, and key its cache on the path alone.
- **Not found (404):** any other path, method or query string, and any org that
  doesn't exist, is being deleted, or isn't spelled exactly as stored. Nothing
  redirects.
- **Unavailable (503):** a key set that can't be read.

The key's versions rotate through `codewire-orchestration identity rotate`,
run daily under the rotator role:

1. A new version is published 24 hours before it signs.
2. Signing moves to it, and the version it replaces stays published for 24
   hours more.
3. The job adds a version when the signing one is 30 days old.

The job refuses to change a key whose configuration has drifted from its pins
(exportable, plaintext backup, deletion allowed, or automatic rotation), and
fails so the drift is seen.

## Tailnet relay

The coordinator advertises the deployment's DERP relay to every `cw` client
and workspace daemon: the path their tailnet connections take when direct UDP
cannot work. There is no default relay. Without `DERP_HOST` the coordinator
refuses to start. That setting and the rest of the DERP, STUN and UDP relay
configuration are in [dev/DERP-STUN.md](dev/DERP-STUN.md#key-config).

## Kubernetes API

In a cluster, orchestration reaches the Kubernetes API through the `kubernetes` Service, which spreads connections over every API server. Where some API servers are far from orchestration, every call through them pays that distance. Naming the near ones sends each new connection to the first of them that is ready, with the Service as the fallback. Only the address dialed changes: requests and TLS still use the Service's name, which every API server's certificate carries. `codewire_kube_api_connections_total{backend}` counts new connections by the server dialed.

| Variable | Required | Meaning | Example |
|---|---|---|---|
| `CODEWIRE_KUBE_API_PREFERRED_ADDRS` | No | Comma-separated `ip:port` addresses of the near API servers, in order of preference. A new connection dials the first one that the `default/kubernetes` EndpointSlice lists as ready and that answered its last dial within 2 s; a server that did not is skipped for 10 s. With none left, it dials the Service. Unset or empty dials the Service only. A name, a missing port or a repeated address stops orchestration at startup. | `192.0.2.12:6443,192.0.2.11:6443` |

## Database pools

Each service's Postgres pool opens at most `DATABASE_MAX_CONNECTIONS`
connections per process, 25 when unset, and a request waits 5 s for one before
it fails (`codewire-server-core` `db::pool_options`). The credential service
reads `CREDENTIAL_DATABASE_MAX_CONNECTIONS` instead, 16 when unset. A value
that is not a whole number above zero stops the service at startup.

A pool opens connections as concurrent work needs them. It hands out its
longest-idle connection first, so steady traffic uses every connection before
the 10-minute idle timeout ends any of them. Instead each connection is retired
two minutes after it opened, so a pool settles at the concurrency it has needed
lately rather than the highest it has met (#6262). Orchestration, the identity
service, billing and the coordinator publish their pool on `/metrics`, sampled
every second:

- `codewire_db_pool_connections{pool, state}`: the pool's open connections,
  `state` `idle` or `in_use`;
- `codewire_db_pool_max_connections{pool}`: its configured maximum.

`pool` is `main`, each service's own pool. Every Pod of every service that
shares a database, during a rollout too, must fit that database's
`max_connections`, less the slots it keeps for superusers. Size each cap from
the pool's `in_use` peak, not its open connections. Count the connections a
service holds outside its pool too: orchestration keeps about ten for its
listeners, its leader lock and its lease heartbeat.

## Unplanned restarts

Orchestration writes one `WARN` line, with the environment's `environment_id`
and a `reason`, each time a running Sandbox restarts without anyone asking:

- `sandbox liveness: running sandbox's runtime is being replaced`, when its Pod
  is deleted or replaced under it;
- `sandbox liveness: running sandbox stopped unexpectedly`, when its Pod failed
  on its node;
- `running bootstrap check: running sandbox's runtime was restarted`, after the
  running reconcile found its workspace bootstrap stale and started it again
  cold (#5950).

A requested start, stop, restart, resize or daemon repair writes none of them.
Infra's unplanned-restart alert matches their text, so a change to the wording
changes that rule too.

## Tracing

Orchestration (its API and its Temporal worker), the dashboard server, the
identity service, billing and the coordinator export OpenTelemetry traces over
OTLP/gRPC when an endpoint is set. Each reads its own environment, so export
is switched on one service at a time. One environment
create is then one trace: the dashboard request, the orchestration
`CreateEnvironment` handler, the Temporal signal, and the claim-authority,
create and setup activities, with the claim, bind, access-ready and setup-phase
functions, each Kubernetes API request and each Postgres statement as child
spans. The trace context crosses HTTP and gRPC as the W3C `traceparent` header
and crosses Temporal inside the signal and activity inputs. No other service
exports traces, whatever its environment says; the credential service, Mesh
and the other services only log.

A sign-in is one trace across the dashboard and the identity service: the
dashboard sends `traceparent` on every call it makes to the identity service,
the read of the session on each signed-in page included, as it does on its
calls to orchestration and billing. A purchase is one trace across the
dashboard and billing up to the redirect to the payment page. The payment
provider's webhook arrives through the public edge, so it is a trace of its
own. The identity service, billing and the coordinator add no span attribute
of their own: each exports the request span and the Postgres statements under
it, as described below. The payment SDK's span that holds a webhook's payload
is never exported, as it is never logged.

The coordinator's one call is a stream that lasts as long as a peer's session.
Under its request span the `authorize` span covers admitting the peer and ends
as soon as the peer is admitted or refused, so that wait can be read at once.
The session's own work is outside the trace, so the trace does not grow with
the session.

A stop and a delete are traced the same way, so the slow step of either can be
read from its trace: the handler (`stop_environment`, `delete_environment`),
the Temporal signal, the stop or destroy activity, and under it each step a
user waits on. For a stop these are scaling the workspace to zero, the wait
until its Pod is gone, releasing the workspace binding, and removing the
access objects and the port DNS records. For a delete they are removing the
port DNS records, tearing down the environment's Kubernetes objects with the
wait until none is left, and releasing the binding. A confidential
environment adds the step that revokes or deletes its keys, and an
environment on a host adds the wait for the host's answer. Each span carries
`environment_id` and nothing else. A stop or delete the platform starts by
itself, such as one for exhausted credit or an expired environment, is one
trace too, from the reconciler's signal.

A resize is one trace as well: the handler (`resize_environment`, with the
plan it builds and the operation it records), the Temporal signal, the resize
activity, and under `handle_environment_resize` each step a user waits on.
Those are applying the new size to the claim and the Sandbox
(`apply_resize_desired_state`), and growing the disk and waiting for the
volume (`apply_workspace_storage_resize`,
`wait_for_workspace_storage_resize`). A resize in place then submits the new
size to the Pod and waits until the kubelet reports it
(`resize_workspace_pod_in_place`, `submit_workspace_pod_resize`,
`wait_for_workspace_pod_resize`). A resize that restarts applies the session
policy first (`enforce_session_policy`), replaces the Pod, waits for its
replacement and for the grown filesystem (`replace_member`,
`wait_replacement`, `wait_for_workspace_storage_capacity`), and
re-establishes the runtime's identity (`reconcile_runtime_identity`). A plan
read on its own is traced too (`plan_environment_resize_core`). A span
carries `environment_id` at most; the waits that know only a Pod or a volume
carry nothing, and no span holds a size.

Whether or not tracing is on, the dashboard answers every signed-in `GET` page
with `Server-Timing: total;dur=MS`, the milliseconds this server took from the
request to its response (#5206). A page that marks its own phases keeps them
beside it: the credentials page adds `shell`, `reads` and `github`. A request
with no session cookie gets no header, so a sign-in form never shows how long a
lookup took. The browser's network panel shows it under Timing, so the
server's share of a slow page reads apart from the network's.

| Variable | Required | Meaning | Example |
|---|---|---|---|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | No | The OTLP/gRPC endpoint (a collector or Tempo's OTLP receiver) that a service sends spans to. Unset or empty means no exporter is installed and tracing costs nothing beyond the compiled-in code. Orchestration, the identity service, billing and the coordinator each log one line at startup saying whether export is on, naming the endpoint's scheme, host and port only. | `http://tempo.observability.svc:4317` |
| `OTEL_TRACES_SAMPLER` | No | The standard OpenTelemetry sampler: `always_on`, `always_off`, `traceidratio`, `parentbased_always_on`, `parentbased_always_off` or `parentbased_traceidratio`. Unset means `parentbased_always_on`, every trace. | `parentbased_traceidratio` |
| `OTEL_TRACES_SAMPLER_ARG` | No | The ratio, from `0.0` to `1.0`, for the two `traceidratio` samplers. Unset means `1.0`. | `0.1` |
| `OTEL_SERVICE_NAME` | No | Overrides the service name, which is otherwise `codewire-` and the service: `orchestration`, `dashboard`, `idp`, `billing` or `coordinator`. | `codewire-orchestration` |
| `OTEL_RESOURCE_ATTRIBUTES` | No | Extra resource attributes. Set `deployment.environment.name` here; without it the `ENVIRONMENT` variable is used when set. `service.version` is the build's version. | `deployment.environment.name=dev` |

What is exported is fixed in code (`crates/codewire-server-core/src/obs.rs`).
Span attributes carry identifiers such as `environment_id`, request methods
and paths, Kubernetes API paths, sqlx's four-word statement summary and row
counts, and timings. They never carry a secret, a token, a credential, an
environment variable's value or user content: the request span holds a
request's path and never its query string, in a trace or in a log line at any
`RUST_LOG` level, since a query can be a credential such as a verification
token. Any other URL's query string is removed before export (a Kubernetes
exec URL carries its command line there), no log event is exported, and a
statement's text and bound values are never recorded.
Health probes and metrics scrapes start no trace.

A service continues the trace named in a request's `traceparent`, whoever sent
it. A deployment's public edge must therefore remove `traceparent`,
`tracestate` and `baggage` from every request that comes from outside, so
each trace starts at the edge. Otherwise a caller can keep its own requests out
of the traces by sending `sampled=0`, or put them under a trace id of its
choosing. Calls between the services inside the cluster keep their headers,
which is how one create stays one trace. A service that calls another through
the public hostname loses its trace link at the edge, like any outside caller.
`traceparent` and `tracestate` are every header a service reads a trace from,
because the W3C trace-context propagator is the only one installed, and a test
pins that. No service reads `baggage`. The edge still removes it, so a caller's
key-value pairs could not reach a span or a log line even if a propagator that
reads them were installed. Before another propagator is installed, its
headers are added to the edge's list.

A preview host is the one place the edge leaves the two headers alone: a
request to a user's app is the app's traffic, and its visitors' trace context
is the app's to read. Orchestration's preview proxy sends the visitor's
`traceparent` and `tracestate` on to the app as they arrived and adds none of
its own. It starts no span for a preview request and continues no trace from
one, and no header of a preview request reaches the API's request span.

Our own trace context is written into an outgoing request in one place: the
dashboard's transport, for its calls to the services inside the deployment
(`inject_http_headers` in `obs.rs`). A repository check
(`trace-context-callers`) refuses a call from anywhere else, so a new caller is
reviewed before our trace ids can reach an outside address or a user's app.

A trace starts at an incoming request or a message, never in a background
loop. A span with no parent is exported only when it is a server span (a
request), a consumer span (a Temporal activity) or a producer span (a signal to
a workflow). Any other span with no parent is dropped with everything under
it, whatever sampler is set: the liveness loop's probe of each running
environment every five seconds, the warm-pool pass, and a reconciler's
Kubernetes requests and statements export nothing. The same probe inside a
create or a request is part of that trace. A loop that starts work on an
environment, such as an automatic stop, sends a signal, so that work is one
trace with its activities. The volume therefore follows requests and actions,
not the number of running environments.

A request's span covers the request until its response starts, in every
service. A response that is streamed afterwards, such as a command's output,
an attached session, a followed log or a watch, holds no span open, and
nothing its stream does later joins the trace. The trace of a session that
lasts hours is the trace of setting it up, and it can be read as soon as the
session is established. A 5xx response still writes its `response failed`
line inside the request span. A failure seen only while a body is streamed,
such as a body that errors halfway, is logged after the span has ended, so
that line carries no trace ids.

Running a command, attaching to a session, opening the browser terminal and
opening an SSH connection are traced through their setup, so a slow or hung
start can be read from its trace. Under the request span are admitting the
stream (`fenced_stream`), resolving the running environment with its access
checks and the runtime's probe (`resolve_running_sandbox_target`), dialling
the workspace daemon (`daemon_channel_for_endpoint`, inside
`environment_daemon_bridge_client_core` for a command or the terminal) and,
for a session, checking the daemon is ready and attaching
(`require_ready_daemon`, `attach_environment_daemon_session_core`). The
terminal and SSH add the check that the environment's claim is ready
(`require_sandbox_claim_ready`), and SSH adds opening the stream to the
workspace (`open_fenced_ssh_stream`, `workspace_ssh_stream`). For a command,
the time left in the request span after the daemon is dialled is the daemon
starting it. A span carries `environment_id` at most: never a command, its
directory or its variables, a path inside the environment, or an SSH user or
key. The relay that follows the setup is in no span.

No log line or span carries a person's name or email address: a user, an
organization or an environment is named by its id. Setup logs that it set a
Sandbox's Git author, never the author itself (#6006).

A snapshot is traced from its request to the kept disk. The handler
(`create_snapshot`, or `delete_snapshot` for a deletion) starts the capture or
delete workflow (`temporal.start_workflow`, a producer span), and each of the
workflow's activities runs in a consumer span with its steps under it. A
capture takes the raw snapshot and waits for it (`capture_raw`,
`snapshot_volume`, `wait_snapshot`), starts a clearing run on a restore of it
and waits for the run to finish (`run_clearing`, `start_clearing`,
`wait_for_clearing`), then stops the run, keeps the cleared volume and removes
the capture's objects (`keep_and_finish`, `stop_clearing`,
`keep_cleared_volume`, `delete_capture`). A failed capture deletes what it made
(`abandon_capture`), and a deletion removes the snapshot's objects
(`delete_snapshot_objects`). A create from a snapshot records
`source_snapshot_id` on its `create_environment` span. A span carries
`snapshot_id`, `environment_id` or `source_snapshot_id`, and nothing else. The
starter puts its trace context in the workflow's input, so a snapshot's
activities join the request's trace and its slowest step can be read there.
Workers accepted that field a release before starters sent it, because a worker
from the release before refuses an input field it does not know. The leader's
sweep that restarts a quiet capture or deletion starts one trace for each
snapshot it restarts.

Codewire's spans are at `DEBUG` level, so at the default `RUST_LOG=info` they
do not appear in the JSON logs.

While export is on, a log line written inside an exported span ends with two
more members, `trace_id` and `span_id`: the ids that span has in the trace
store, as 32 and 16 lowercase hex digits. A line about a failed request
therefore leads to its trace. A line written outside an exported span has
neither: a background loop's line, a line in a trace the sampler dropped, and
every line of a service that does not export. While export is off, every line
is byte for byte what it was.

A request whose span is exported answers with `x-codewire-trace-id`. Its value
is the trace's id as 32 lowercase hex digits, the same id the request's log
lines carry. The request layer of every exporting service sets it once the
handler has answered, and no handler sets it. Some requests
get no header: one the sampler dropped, a probe or a scrape, and every request
while export is off. So an id on a response always finds a trace. The id is
the server's own. A caller's `x-request-id` is echoed back, as before, but it
is never a trace's id and never goes on a span. Knowing an id grants nothing,
because the trace store is not public. A missing header tells a caller only
that its request was not sampled. Nothing that guards the platform depends on
sampling: audit rows, refusal logs and security alerts are written for every
request, sampled or not. Tracing is for diagnosis. It is never the record that
shows an attack.

When a command fails on a server's answer, `cw` prints that answer's trace id.
The line comes after the error and its next step, reads `trace
4bf92f3577b34da6a3ce929d0e0e4736`, and is dim at a terminal. It is printed with
`--local` and `--cloud` alike, and with `--output json`. A failure with no
answer has no id and prints none, such as a host name that doesn't resolve or a
timeout before any response. A "not found" that `cw` concludes itself prints
none either: `cw` looks a cloud name up in the environment list, and the
server answered that list. Three refusals print none, because their error
already says what to do: a sign-in that is no longer accepted, exhausted
credit, and an environment that isn't running. When `cw` puts a server's error
in its own words, such as a refusal it explains in the user's terms, it keeps
that answer's id and prints the line. Nothing is exported from the user's
machine. `cw` sends no `traceparent`, and the edge would remove one.

The workspace daemon calls `BindWorkspace` and `RefreshAccess` on
orchestration's workspace-binding listener, port 8087. The daemon runs inside
a user's environment, so that listener treats it as an outside caller. It
reads no `traceparent`, `tracestate` or `baggage`. Each call is a server span
that starts its own trace and answers with `x-codewire-trace-id`. When the
listener refuses or fails one of the daemon's calls, the daemon logs a line
with that id; a `not_found` while it waits for its binding is not logged. Each
of these traces is one call and its statements, so the volume follows binds
and refreshes.
