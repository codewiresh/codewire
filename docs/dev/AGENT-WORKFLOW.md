# Agent development workflow

Command details routed from `AGENTS.md`; this file grants no authority.
Infrastructure facts (OpenBao, clusters, registries, Forgejo, tailnet) live in
the maintainers' private design repository, not here.

## Forgejo

Use `fj` with the canonical remote. Do not use the legacy `tea` CLI:

```sh
fj issue -R origin view 123
fj pr -R origin view 456
fj actions runs list -R origin --output json
fj actions runs logs 789 --job 101 -R origin
```

Paginate audits. Create with `fj pr -R origin create` and squash-merge with an
explicit title and body, so the commit names the pull request by number and
never links to the forge (the GitHub mirror refuses `Reviewed-on:` links):

```sh
fj pr -R origin merge 456 -M squash -t "feat: do the thing (#456)" -m "Reviewed-on: #456"
```

Read a failing component log before diagnosing. Bind a healthy run once and use
`fj actions runs watch`; do not poll it.

```sh
fj actions runs watch RUN_ID --expect-head FULL_SHA -R origin --output ndjson
```

Bind the workflow, run and full head once. Verify the host can deliver the
observer's failure, success, stall, cancellation or head-mismatch event to the
coordinator. The command's output and exit status are not themselves a session
wake-up. If no supported receiver exists, record that limitation and one bounded
terminal-horizon/stall fallback. An observer connection failure leaves the CI
result unknown; restore observation without rerunning the workflow.

## Failure convergence

Preserve the smallest non-secret error and check partial state. Name the
unproven boundary, then use the cheapest local or read-only discriminator.
Change one factor whose expected result distinguishes the plausible causes.
Repair cohesively and run the focused gate. Repeat an external mutation only
with a fresh valid plan when required and a stated prediction.

Expensive end-to-end, destructive, or clean-room gates qualify a credible
candidate; they are not the debugging loop. After failure, move inward. Do not
rebuild unchanged inputs, rerun unchanged qualifications, or add taxonomy in
place of evidence. An unknown result blocks only the affected mutation.

## Local verification

Inspect the affected capabilities first:

```sh
scripts/dev/preflight.sh --explain
```

This reports selection; it does not qualify the source. Run focused local
checks for the affected failure class. When local qualification is selected,
`scripts/dev/preflight.sh` runs the selected gates; otherwise use the
owner-selected CI route below. If an obviously narrow policy path selects
`full` solely because it is unclassified, repair the selector and add a fixture
before continuing. Do not run the product/Kind suite as a substitute for
classification.

Preflight dispatches policy through
`scripts/ci/verify/run-product-verification.sh policy`. This shares the policy
core with hosted CI: `policy-repo-rules` (the private-content tree scan, every
`repo_checks.py` rule and the guards that read product source) runs on every
change, and `policy-ci-script-tests` runs when a CI or developer script, a
workflow or a hook changes, or a product file one of those tests reads, the
workspace `Cargo.toml` manifests among them.
`policy-shell` runs only when the trusted selection requires it. A part the
trusted selection cannot yet omit always runs. Keep the guard list in that
runner, not in another local checklist. Policy repairs need an old-fail/new-pass
fixture.

Use additional gates only for their failure class:

- database/migration: `scripts/ci/verify/run-integration-verification.sh database`
- service/runtime wiring: `scripts/ci/verify/run-integration-verification.sh services`
- edge/Kind interaction, when it is tricky or slow to test on Dev: the
  selected suites through `make kind-test`, a local tool and never a merge
  requirement; the full `make e2e-kind` only when the owner asks
- Rust CLI-only work: the changed crates' `cargo test` and `cargo clippy`,
  plus the host journey with a built `cw`

Ignored Rust tests either run in a named CI step or are manual. CI runs the
database tests (the database lanes), the egress broker's host-interface refusal
(in a private network namespace, `scripts/ci/verify/run-in-public-netns.sh`;
a job that cannot make one, as CI's container jobs cannot today, says so in a
notice, and local qualification on a host that can runs it),
the daemon's stock-`gh` ingress, the tailnet client through the real relay
binary (beside the DERP contract), and the guest-probe kernel fixtures where the
job can make a mount namespace. The rest need something CI does not have, and
their `#[ignore]` reason says what: live Dev endpoints (`live_tls_derp_relay_two_rust_clients`,
`live_tailscale_stun_server_discovers_mapped_addr`), the host OpenSSH client
(workspace-access's two `openssh_client_*` diagnostics), Docker and the support
image's base (`docker_data_image_prepare_smoke`), standalone Mesh and DERP builds
(`explicit_standalone_overrides_are_pinned_and_reused_by_a_different_cw`), real
agent payloads (`host_members_managed_two_real_endpoints_direct_and_tls_derp`),
a packaged service image (`packaged_agent_signs_and_drains`), an Xvfb/DBus
browser runner (`linux_native_browser_journey`), an overlay lower layer
(`a_share_copied_up_on_overlay_between_boots_is_not_refused`) or a pinned Claude
client (`pinned_claude_2_1_238_client_format`). Run one with `--ignored --exact`
and the environment its reason names.

After focused checks and diff review, commit the credible candidate and push
it. The pre-push hook (`scripts/dev/pre-push.sh`, run by the shared dispatcher)
runs `scripts/dev/preflight.sh --for-push` on every branch push: the
environment precheck, `cargo fmt --check`, clippy and unit tests for the
changed crates, and quick checks for changed file types (ShellCheck on changed
scripts, proto lint and breaking diff, dashboard typecheck). It runs no
verification family and records nothing. `main` takes changes only through
pull requests; push one ref at a time.

Pull-request CI is the merge gate (#3119 step 2). Each pull request merges
alone, without a rebase unless it conflicts, when its required statuses are
green on its exact head, `CI / Required verification (pull_request)` and
`Supply-chain scan / Supply-chain scan (pull_request_target)`, and its product
journey has run (the merge rule in `AGENTS.md`). Forgejo checks the head, not
the merged tree; `main` CI verifies the landed tree after merge, and a failure
is fixed forward. Never cancel a `main` run by hand; cancels and reruns are
the orchestrator's call under the `ci` skill.

Pull-request CI runs every family the change's paths select, as the push to
`main` does: policy, the crate tests of the changed Rust packages and their
dependents, and the web, docs, SDK, contract, database, service, release,
deploy and security families the paths name. The selection follows the
workspace crate graph (`cargo metadata --no-deps`): a changed crate selects its
own tests and those of every workspace crate that depends on it, transitively,
while a dev-dependency selects only its dependent's tests. Runtime families
still follow the changed paths. A pull request with an unclassified path
selects every family until the selector learns the path. Kind is the
exception. To run it on the pull request itself, add the `ci-full` label:

```sh
fj pr -R origin edit 456 labels --add ci-full
```

Add it only when a hosted-only claim (credentials, permissions, scheduling,
cache or timing) needs hosted evidence before merge. It applies to every later
push until removed. Hosted Kind is off on the schedule and on dispatch until
the owner revisits it (owner, 2026-10-25); it runs only on a `ci-full` pull
request. The retired `kind-e2e` label and `[kind-e2e]` marker do nothing.
Adding or removing a label starts a fresh run that supersedes the current one.
`scripts/ci/select/main-push-switch.sh` documents what a push to `main` runs
and the conditions for restoring Kind and the release dry run to every push.

To run the same families locally first, when that is faster than waiting:

```sh
scripts/dev/preflight.sh --all
```

It checks the environment, then compiles every Rust target first (the policy
parts run beside it, one lane each), then runs independent families in
parallel lanes, integration lanes on separate `VERIFICATION_PORT_BASE` ranges.
Contracts and the JavaScript lane (timing-bound tests) run alone first. Each
family logs to `.tmp/preflight/logs/<run>/<family>.log`, and the first failure
stops the other lanes. Changed workflow files also get `supplychain workflows
.`, the zizmor audit the supply-chain scan runs. It never runs Kind, records
nothing and qualifies nothing.

If CI fails, diagnose and repair the candidate before its next push. Never
commit known-bad work.

Run the `release` group, or any of its tests, with `PYTHONDONTWRITEBYTECODE=1`,
as its CI step does. Without it, a local Python can write `__pycache__` into the
CW source capsule, and `test-build-push-image.sh` fails with "capsule contains
an unknown directory".

Record the command and real exit status with its test counts. Label a complete
run, interrupted run and composed proof differently. Reused components must
still match their relevant source, dependency/feature, fixture, toolchain,
topology, selector and entrypoint inputs. Use pipeline failure propagation when
capturing logs so a successful log writer cannot hide a failed check.

For upgrade proof, follow [DATABASE-MIGRATIONS.md](DATABASE-MIGRATIONS.md): bind
the actual accepted prior migration history, then prove the new migration and
the documented reset/rollback boundary. Do not repin applied history to make an
upgrade fixture agree with a rewritten baseline.

The frontend iteration checkpoint still requires an explicit landing
instruction.

Before focused Cargo commands in a linked worktree, unless already set:

```sh
export CARGO_TARGET_DIR="$(scripts/ci/verify/resolve-cargo-target-dir.sh)"
```

Use shared Cargo targets only deliberately; product entrypoints configure this
themselves.

Repository Cargo entrypoints (the verification runners, Kind smoke builds,
`make` targets) share one disk sccache per account in
`~/.cache/codewire-sccache` (50 GiB cap), so a new worktree reuses the
third-party crates other worktrees compiled. It needs the pinned
`sccache 0.17.0` on `PATH` and falls back to uncached builds otherwise; CI
selects its own cache. Run an ad-hoc command, or read the hit rates, through
the same selection; `CODEWIRE_LOCAL_RUST_CACHE=off` opts out:

```sh
scripts/ci/verify/local-rust-cache.sh cargo test -p codewire-cli
scripts/ci/verify/local-rust-cache.sh sccache --show-stats
```

On Linux the same selection replaces a hung server (#2753), before use and
every minute while a build runs. A server is hung when clients have waited on
it for five minutes in which it finished no compile and ran no compiler. The
helper stops that server (`--stop-server`, then TERM and KILL to its exact PID)
and leaves the cache in place. The waiting compiles fall back to compiling
locally. Each restart is logged in
`~/.cache/codewire-sccache/server-check.log`.

CI uses one shared remote cache for sccache objects and BuildKit layers, at
the site's `CODEWIRE_R2_CACHE_ENDPOINT` ([CI configuration](CI-CONFIGURATION.md)).
Only main-only builders write it: the Dev deploy and support-image publishers,
and main `ci.yaml` jobs on the sized main-only runners. A job that fetches
cache credentials and can run a main push on an unsized runner forces its
job-local cache instead; `test-fetch-openbao-sccache-r2-credentials.sh`
enforces that. Pull requests read the cache with a read-only token and write
nothing remote. No CI job uses the retiring untrusted bucket.

`crates/codewire-workspace-hack` (cargo-hakari) unifies third-party features
for builds that compile tests, examples or benches (`cargo test`,
`--all-targets`, clippy over all targets), so their package and feature
selections share those builds. Members take it as a dev-dependency, so a
binary or library build, such as an image or release build, keeps exactly its
own dependency graph; a lib-only `cargo check -p` does not share the unified
units. After changing any manifest or `Cargo.lock`, regenerate it with
`scripts/ci/verify/check-workspace-hack.sh --fix`; the all-target compile
fails while it is stale or a member line is not under `[dev-dependencies]`.

## Frontend iteration

Use `make design-system`, `make dashboard-watch`, or
`make dashboard-watch-kind` for active HTML/CSS iteration. Before a landing
qualification, run
`scripts/dev/preflight.sh --explain`. If a UI-only change is unclassified or
selects integration, Kind, or full verification solely because classification
is missing, repair the selector or separate the unrelated change before running
the expensive gate.

Stop `make dashboard-watch-kind` with Ctrl+C before Kind verification. The
target cleans up its repository-managed Postgres forward on exit.

## Hygiene

Use a fresh worktree from `origin/main`, under one dedicated worktree root
organized as `<owner>/<repository>/<task-slug>`:

```sh
codewire_worktree="$WORKTREE_ROOT/codewire/codewire/<task-slug>"
git fetch origin
git worktree add -b <branch> "$codewire_worktree" origin/main
```

After the task is merged, closed, or explicitly abandoned, stop only processes
owned by that task and remove its disposable artifacts. Then verify and retire
the worktree from the canonical checkout:

```sh
git -C "$codewire_worktree" status --short
git fetch origin
git merge-base --is-ancestor <branch> origin/main
git worktree remove "$codewire_worktree"
git worktree prune
git branch -d <branch>
```

The ancestry check and branch deletion apply to merged work. For a closed or
abandoned branch with intentional retained commits, preserve the branch and
remove only a clean worktree. If the worktree is dirty or ownership is unclear,
retain it and report the exact path instead of forcing removal.

Preserve unrelated dirty worktrees. Search before adding advisory keys, ports,
environment variables, or workspace packages. Copy new packages and build
inputs into every consuming image.

## Workstation CPU limits

On the owner's Linux workstation, agents, preflight runs, image builds and Kind
share the cores with the owner's desktop. `scripts/dev/workstation-cpu.sh` keeps
the desktop responsive with systemd CPU weights and ceilings. Install the
root-owned copy once; it reruns itself under `sudo -n`:

```sh
sudo install -m 0755 scripts/dev/workstation-cpu.sh /usr/local/bin/codewire-cpu
codewire-cpu status   # load, each limit and the CPU each group uses now
codewire-cpu apply    # set the standing limits
codewire-cpu reset    # remove them all, back to systemd's defaults
```

Start each `preflight.sh --all`, local VM run and load-sensitive test in the
preflight and local VM slice (`cwvmtest.slice`), and record that in the
evidence:

```sh
sh -c 'codewire-cpu run $$ && exec scripts/dev/preflight.sh --all' </dev/null
```

| Group | Weight | Ceiling |
| --- | --- | --- |
| Preflight and local VM runs (`cwvmtest.slice`, through `run`) | 200 | 12 cores, shared by every job in it; memory reclaimed above 88G |
| Each Docker image builder (`buildx_buildkit_*`) | default | 4 cores |
| Remote login sessions, such as the tmux server background agents use | default | 3 cores |
| The compositor's session, desktop apps (`app.slice`) and audio (`session.slice`) | 1000 | none |
| Everything users run (`user.slice`), against `system.slice` | 400 | none |

A weight matters only when the cores are contended; a ceiling applies even
when cores are idle. Desktop terminals keep the default weight because many of
them run agents. Kind nodes and other containers are not capped.

The limits are runtime state. A reboot clears them, and the next `apply` or
`run` sets them again, so a `reset` lasts until then. To change a value, edit
the script and reinstall it; a one-off `systemctl set-property` is overwritten
by the next `run`. Run at most three heavy jobs at once: one preflight run, one
image or Kind build and one background build. More parallel work past that only
adds contention.

## Local Kind cluster for manual testing

Keep the existing owner review cluster between sessions. Create a retained
cluster once, then deploy changes into it. Saved named profiles allow a second
cluster for a different worktree or full verification on the same Docker host:

```sh
make kind-up CLUSTER=my-task
make kind-list
make kind-status CLUSTER=my-task
make kind-deploy CLUSTER=my-task SERVICE=orchestration
make kind-watch CLUSTER=my-task
make kind-test CLUSTER=my-task SUITES="edge-contract workspace-services"
make e2e-kind CLUSTER=my-task-verification
make kind-down CLUSTER=my-task
```

Each profile saves seven loopback ports, browser origins, a private kubeconfig,
the actual Docker daemon and node identities, and the committed source and
sealed image/smoke inventory. `kind-list` shows the endpoints. Commands load
those settings from `CLUSTER`; conflicting inherited selectors or endpoints
fail before use. Do not export the legacy review settings when selecting a
named profile. The default named browser URL is its saved loopback watcher
origin; no extra host routing is required.

`kind-up` requires a clean committed initial base. Repeating it validates a
live cluster. After `kind-down`, the same unchanged source reuses saved ports
and artifacts. Use a fresh profile for another committed base. The
`codewire-*:e2e` tags are shared by every checkout on the Docker host, so
`kind-up` admits its product images by ID straight after building them, holds
them as `localhost/codewire-kind-admitted/<cluster>/…:held` until it seals the
profile, and seals those IDs; a tag another checkout moves meanwhile is ignored,
and an admitted image missing from the store fails with its name. `kind-deploy`
builds current changes into qualified per-profile images and, before restarting
the service, brings its admission policies to this tree's (#3833), while `kind-test`
uses the admitted base's immutable client/test executables against that runtime.
The watcher uses a separate mutable build cache; stop it with Ctrl+C before
removing its cluster.

Full verification requires an absent cluster and never replaces a retained
one. It deletes only the node created by that transaction unless
`KEEP_KIND_CLUSTER=1` is selected. Runtime operations lock their own profile;
the shared producer transaction and a browser phase within one checkout have
separate bounded locks. Removing a profile's node preserves its saved config
and cached base; explicit `cluster-profile.py purge --cluster NAME --nonce NONCE`
retires an unused owned profile and its private files. Named profiles currently
use the Linux amd64 synthetic CI product contract. Legacy `up`, `down`, forwards
and default-namespace deployment tools reject `CLUSTER` before effects.

The rendered overlay and credential fixture carry the requested ingress origin
(`http://127.0.0.1:$KIND_INGRESS_HOST_PORT`) as the IdP issuer, frontend,
dashboard and credential origins, so the full gate and its shards also run on a
shifted ingress port.

Legacy `KIND_CLUSTER_NAME` callers may also bind all six templated host ports
explicitly. Keep the assigned ports for the session, retain the owner review
origin where selected, and refuse occupied ports before effects. Startup refuses
an existing legacy cluster; iterate with `kind-deploy`/`kind-test` and remove a
cluster explicitly when finished:

```sh
export KIND_CLUSTER_NAME=codewire-ux-2099 KIND_INGRESS_HOST_PORT=8091 KIND_INGRESS_TLS_HOST_PORT=10444 \
  KIND_TEMPORAL_HOST_PORT=7234 KIND_ORCHESTRATION_HOST_PORT=8085 \
  KIND_COORDINATOR_DIRECT_HOST_PORT=18093 KIND_POSTGRES_HOST_PORT=25433
make kind-up                 # build, create and deploy; no test suites (minutes when cached)
make kind-deploy SERVICE=credential-service   # rebuild one service into the cluster
make kind-trust-roots        # republish the synthetic trust roots (kind-deploy does too)
make kind-test               # only the retained suites this change needs
make kind-db-reset           # new databases at the deployed migrations, with the gate's fixtures
make kind-db-restore BACKUP=<dir>  # return the databases to a backup
make kind-credentials-real   # real credential-service, GitHub App copied from OpenBao
make kind-seed-login         # e2e-owner@codewire.sh / SecureTestPass9#
make kind-runtime-images     # default workspace and DinD images, by digest, from public sources
make kind-watch              # current dashboard on 127.0.0.1:5182 = http://localhost:4174/
make kind-status             # cluster, ingress, dashboard, credential mode and origins
make kind-credentials-fake   # back to the gate's synthetic fixture
```

`kind-watch` first makes the cluster behave like Dev for the review origin: it
sets the browser origin the IdP, orchestration and billing accept (terminal
attach, redirects) to `KIND_PUBLIC_ORIGIN`, and runs `kind-runtime-images`.
`kind-credentials-fake` restores the ingress origin the retained suites use.
Switching credential mode requires restarting a running `make kind-watch`: it
reads the GitHub App settings once, at start, and refuses to start against the
real credential-service without them; both switches say so when one is running.

`kind-runtime-images` preloads every image a default sandbox runs that the Kind
gate does not build, so a create pulls nothing. Its table in
`scripts/dev/kind/dev-loop.sh` has one row per product constant:

| Constant | Rendered reference | Public source, same digest |
|---|---|---|
| `PUBLIC_IMAGE` (`codewire-workspace-image` `pin.rs`) | `ghcr.io/codewiresh/workspace@sha256:…`: Kind configures the public mirror as its workspace repository (`CODEWIRE_WORKSPACE_IMAGE_REPOSITORY`, [configuration reference](../CONFIGURATION.md)) | the same reference |
| `DEFAULT_DIND_IMAGE` (orchestration `sandbox/template/mod.rs`) | `docker.io/library/docker:<version>-dind@sha256:…` | `docker.io/library/docker@sha256:…`, pulled by digest alone |

Each node pulls the source by digest, checks the pulled digest, and names it as
the product renders it; no credential is involved. Images already present at
their digest are skipped. A constant the row does not accept, a source that
does not pin the same digest, or a node record naming another digest stops the
load. `scripts/dev/kind/dev-loop.sh runtime-images --dry-run` prints the plan
without a cluster. Changing either constant's registry means changing its row,
which `scripts/ci/tests/test-kind-runtime-images.sh` enforces.

`make e2e-kind` (with `KEEP_KIND_CLUSTER=1`) also leaves a usable cluster, but
it runs every suite. It is neither a landing gate nor an iteration step; run it
only when the owner asks.
Retained suites require the current kubectl context to be
`kind-$KIND_CLUSTER_NAME`; `kind-test` reads the cluster's current kubeconfig
from kind itself, so a stale default context does not matter there.

`kind-deploy` builds one service (`idp`, `orchestration`, `credential-service`,
`billing`, `coordinator`, `mesh`) incrementally in the services image's
toolchain, layers it onto the cluster's image and restarts only that
Deployment. It uses the local `kind-dev` Cargo profile
(`scripts/dev/kind/cargo-profile.toml`): the workspace's own
crates build at optimization level 1 and external crates as in CI. Nothing
built with it is shipped or used in CI.
`SERVICE=credential-service` also rebuilds the synthetic fixture that the
`credentials` suite and `kind-credentials-fake` run
(`/codewire-kind-fixtures/credential-service`), so fake and real modes both
run the current source.
`SERVICE=daemon` rebuilds the in-workspace `cw` into the daemon image the same
way; sandboxes created afterwards run it. `kind-watch` serves the dashboard from
source for review, but the cluster ingress, and so `kind-test`'s
`dashboard-browser` suite, serves the dashboard image (`SERVICE=dashboard`).
It updates binaries, not manifests; a manifest change needs a
fresh cluster or the full gate. It builds the worktree it runs in: each
worktree has its own incremental target in a shared build cache, so no crate
built from another worktree is reused, and files whose content differs from
that worktree's last build are rebuilt regardless of their modification times.
The first deploy from a new worktree is therefore a cold build. Each deploy
records on its Deployment the digest of the source it built
(`scripts/dev/kind/service-sources.py`) and the image its Pods then run;
`SERVICE=mesh` and the other services take part the same way.

The retained cluster's databases are disposable, and a deploy upgrades them.
`idp`, `orchestration`, `billing`, `coordinator` and `mesh` apply their
migrations at startup, as they do on Dev and Production, so deploying one
applies the tree's new migrations. Before it restarts one of them,
`kind-deploy` (`scripts/dev/kind/database.sh prepare`) compares each SQLx
ledger (`codewire`, `codewire_mesh`) with the tree. When the tree carries new
migrations, it first backs both databases up with `pg_dump` to
`~/.cache/codewire/kind/<cluster>/database-backups/<UTC time>-upgrade` and
prints the path; the newest five backups are kept (`KIND_DB_BACKUP_KEEP`). The
other services keep running their old binaries until they are deployed too,
which `kind-test` does in the same run. The deploy refuses only a downgrade:
the database applied a migration the tree lacks, applied one from other bytes,
or records one as failed. The services would not start on it, so the refusal
names the migration and offers `make kind-db-reset`, the newest backup the tree
can run (`make kind-db-restore BACKUP=<dir>`), or that migration's `.down.sql`
with its `_sqlx_migrations` row removed.

`make kind-db-reset` backs up, stops the services that use the databases,
removes the Sandbox workloads of the environments it forgets (everything in
`dev-sandboxes` labelled `codewire.sh/environment-id`), and recreates
`codewire` and `codewire_mesh`. The IdP then reruns every migration it
embeds, the reset loads the fixtures the Kind gate loads (billing and
coordinator seeds and the restricted credential login), and the other services
start again; `make kind-seed-login` restores the review login. Deploy the tree
first (`make kind-test`) to reset to its migrations. `make kind-db-restore`
backs up, then returns both databases to a backup and restarts the services;
Sandboxes created since the backup keep running without a record. Neither
touches Temporal.

`kind-test` is how an author observes a platform or dashboard change working;
it is not a push or merge gate. It first prints the suites it chose and the
selection tokens that chose each. It refuses to start while a `kind-*` test
environment from an earlier or still running suite is live: a leftover Sandbox
keeps authenticating to the credential bridge and breaks the next credentials
run. A failing credentials stage removes its own environment, profiles and
credentials on exit; remove older leftovers with the product CLI as the suites
do. Then it rebuilds and deploys every service whose Deployment does not
record running this tree's source: what the change feeds (its crate's
workspace dependency closure, plus the protobuf sources and build recipe), and
anything another worktree, an older main or an unrecorded deploy left there.
A repeated run therefore deploys nothing. `kind-up` and a kept full gate
record the source of the images they build, so a new cluster starts current;
on an older cluster the first run rebuilds every service once.
The suites' smoke binaries, billing contract test and host `cw` build in the
same worktree target and builder as those deploys
(`scripts/dev/kind/build-smokes.sh`), so after a deploy they mostly link
what it already compiled, under the same content check. Each suite builds
only the smoke groups it runs, and a run builds each group once.
Then it runs the retained suites (`scripts/dev/kind/test-selected.sh`):
`edge-contract`, `credentials` (fake mode; restarts the credential-service
first; its native stage idles until kubelet really replaces the workspace's
projected token, about eight minutes in, and a fresh-token epoch is admitted,
running the Claude stages meanwhile, and it proves the
60-second authority window at full length; the Kind deployment alone shortens
the daemon's Codex login check to 30 seconds through
`SANDBOX_CODEX_LOGIN_CHECK_PERIOD_SECONDS`, which production builds never read;
on a cluster created before that setting the suite sets the overlay's value in
`codewire-config` itself and restarts orchestration once), `workspace-services`, `dashboard-browser` (installs the
frozen dashboard dependencies and the pinned Chromium on first use; it needs
the ingress origin, so after `make kind-watch` run `make kind-credentials-fake`
first), `final-fencing`, `runtime-acceptance` and
`integrated` (the coordinator, Mesh and billing contract probes; its Mesh
probe creates fixed networks, so it passes once per cluster). A changed
migration selects `edge-contract`, which reaches every service on the upgraded
schema; the deploy before it applies the migration after a backup. Exit status
3 means only the full CI Kind gate covers the change, and nothing was deployed
or run: server-core code other than its migrations, protobuf contracts,
workload secrets, the workspace
manifest or lockfile, manifests, and unmapped crates. Local microVM, DERP,
UDP relay, desktop and workspace-image-pin changes run nothing; the pin is
observed on Dev. On its own selection, `dashboard-browser` runs only the
browser specs the change affects (`docs/TESTING.md`); name the suite, or set
`DASHBOARD_TESTS=all`, for every spec, and `DASHBOARD_TESTS=smoke` or `light`
for the `@smoke` tests or all but `@kind-heavy`. Choose suites explicitly with
`make kind-test SUITES="credentials dashboard-browser"`; on a stacked branch set
`PREFLIGHT_BASE_SHA=<parent branch>` so only your change is classified and
deployed. To rerun one credentials stage while iterating, name it:
`make kind-test SUITES=credentials CREDENTIAL_STAGES=claude-sign-in` (the
stages are `native`, `claude-session` and `claude-sign-in`). The suite's setup
still runs first, and Claude stages named with `native` run during its idle. A
stage subset says it is not the credentials suite and never
counts as a green `make kind-test SUITES=credentials`; the full gate and its
shards refuse a stage list.

`make kind-test SUITES=warm-pools` runs only when named: it times shared warm
pool hits against cold creates and checks the pool journeys (Program #2238
C5). It needs the C0 agent-sandbox controller and `make kind-runtime-images`
(a member runs the canonical workspace image). The e2e overlay configures no
pool, so the suite sets its own `SANDBOX_WARM_POOL_SHAPES` (`500m/1024Mi/5Gi=1`)
on orchestration unless the cluster already runs one, and removes it on exit.
It rolls orchestration a few times and briefly cordons the member nodes,
restoring both.

`real` runs the production credential-service binary. It differs from Dev only
where a laptop must: the non-promotable Kind image's test KEK replaces OpenBao
Transit, and
Postgres uses the cluster's cert-manager root with `sslmode=verify-full`. The
GitHub App identity is copied from the site's OpenBao by
`scripts/dev/kind/sync-local-secrets.sh` through
pipes into the same Secret External Secrets Operator fills on Dev; values are
never written to disk or printed. Both the credential-service and the watcher
use `KIND_PUBLIC_ORIGIN` (default `http://localhost:4174`), which must
be the App's registered callback origin
(`…/api/v1/github/oauth/callback`); real mode also sets the cluster's
`FRONTEND_URL` to it. Browsers reach the cluster API for terminals and streams
at `KIND_BROWSER_API_ORIGIN` (default `http://localhost:8090`), which
must share that host, so a browser on another machine needs the ingress
exposed at that origin too. Test the
real mode through the watcher. Running
Full verification uses a fresh cluster in fake mode; it never replaces this
retained review cluster.

To review UI from another worktree (for example a branch stacked on this one),
set `KIND_WATCH_SOURCE_ROOT=<worktree> make kind-watch`.

When `kind-credentials-real` reports that OpenBao is not readable, your
OpenBao session has expired. Log in again with your site's OpenBao login, then
rerun the target. Never paste a token into chat.

Known workstation requirements. `scripts/dev/preflight-environment.sh` checks
the ones the selected families need before the first family runs. Fix the
tooling when one of these breaks; do not work around it per session:

- An application firewall's loopback rules must match the destination IP,
  not the host name, and must cover your worktree root, including Kind smoke
  binaries under `target/ci` and the pinned Playwright Chromium under `.tmp/`.
  A stalled `SYN-SENT` to 127.0.0.1 means a missing rule.
- `/tmp` does not allow execution, native mount tests refuse projects inside
  `/run`, and the image-source policy test rejects any path with a `.claude`
  component, and Unix-socket tests need a `TMPDIR` of at most 34 characters.
  Use a short per-task executable `TMPDIR=$HOME/.cache/cwt-<short task>`, and
  put `$HOME/.cargo/bin` first on `PATH` so the pinned toolchain (and
  `cargo-zigbuild`) wins over a system Rust.
- `node_modules` and `.venv-proto` must belong to the worktree, not be
  symlinks to another checkout.
- The database lanes keep no test counts. Each suite lists the tests its own
  filter selects and must pass that many, and
  `scripts/ci/verify/database-test-coverage.py` fails the database job when a
  test whose `#[ignore]` reason names `DATABASE_URL` runs in no lane or in
  two. A new database test needs a lane filter that selects it.
- The Kind gate requires the pinned Chromium from
  `scripts/ci/install-pinned-playwright-chromium.sh`.
