# Agent Operating Rules

This file is authoritative for this repo. `CLAUDE.md` is a compatibility
symlink to `AGENTS.md`; do not put independent instructions in it.

## Goals

- Do not set, request, infer, enforce, or report goal token/time budgets in
  this repo. Goal tooling may be used to track objectives and completion state,
  but budget/timer fields are not authoritative and must not be presented as
  meaningful work duration or progress.

## Noel Method

This repository follows this immutable Noel Method runtime pack:

- Release tag: `v0.7.0`
- Release commit: `705a7a3f1aa117cb2ef1358cc75d3bc109cd928f`
- Pack manifest SHA-256:
  `44b08fb6aa6f239c878f09bb16fcad246583b3f72f2d3eca627b0d9743dbdcba`
- Runtime index:
  `https://raw.githubusercontent.com/noeljackson/method/v0.7.0/dist/pack/INDEX.md`

Use only that verified published tag and resolve relative links under the same
`v0.7.0/dist/pack/` path. Codewire uses direct authority mode. Normal repository
work—inspect, edit, run focused checks, commit, push a branch, open a pull
request, and merge—may be authorized directly in conversation. Existing
Codewire instructions and applicable gates still apply.

External state, persistence, or a multi-turn conversation does not force
resolved mode. Release publication, deployment, production or live-state
mutation, and credential access require separate explicit authority.

Load an extra Method protocol only when the task needs it: Program for
persistent dependent work, Experiment for a controlled comparison, and Secrets
for a secret-capable path. Protocols add procedure, not authority.

Resolved mode is optional and Codewire does not use it. No ProjectPolicy,
TaskRequest, ResolvedPermissions, or resolver is required; their absence must
not block work. Never substitute `main` or infer missing modules.

This file and canonical Gitea controls remain authoritative for Codewire.
Method context can add procedure but cannot widen repository authority.

## Plan-bound multi-wave programs

- Every action in a multi-wave program is reported as
  `Program / Wave / Workstream / WI`. An explicitly non-PR release/deploy
  operation may end in `OP-n` only when the master names it, says that it has
  no source edit or PR, and gives exact authority and acceptance evidence. The
  program master must contain a
  binding execution-control block that names the current coordinate, the
  explicitly authorized queue, all hard gates, and all forbidden work. A live
  control may opt into the bounded-parallel admission envelope below instead
  of requiring another master-plan PR for every independent preparable WI.
- Program state is exactly `ACTIVE`, `STOPPED_FOR_REPLAN`, or `COMPLETE`.
  Gate state is exactly `SATISFIED` or `UNSATISFIED`; terms such as "closed",
  "almost green", or "expected to pass" do not authorize later work.
- An `ACTIVE` program whose live control opts into bounded-parallel admission
  may admit an independent WI through a direct owner decision plus a canonical
  Gitea issue or comment receipt. The receipt must name the exact coordinate,
  issue, claimant branch/worktree/PR, prerequisites, exclusive path ownership,
  shared surfaces, verification gates, forbidden work, and merge order.
  Admission does not require a docs/control PR when it stays inside the
  already accepted goal, wave/frontier, dependencies, contracts, program
  gates, repositories, external controls, and acceptance criteria.
- Independently admitted WIs may be inspected, edited, committed, pushed,
  reviewed, and tested concurrently. One WI remains one PR. Main merges and
  shared or external mutations remain serialized unless the live control and
  applicable authority explicitly prove a narrower safe boundary. Before each
  push or merge, reconcile all active claims and stop only a duplicate claim
  on the same coordinate; redirect that session to another admitted WI rather
  than stopping independent work.
- Workflows, dependencies and lockfiles, generated trees, schemas and
  migrations, shared contracts, deployment/image inputs, publication and
  release paths, credentials, and live state are not presumed independent.
  Their admission receipt must prove non-overlap and ownership, and it never
  supplies missing release, deployment, credential, production, or live-state
  authority.
- Before dispatching, pushing, or merging a program PR, reconcile the master,
  workstream status, canonical Gitea issue/PR state, current `gitea/main`, and
  required evidence. A healthy branch or CI run is not authorization, and CI
  from an old head is never evidence for a rebased head.
- Before a master authorizes a new implementation cluster, complete one
  bounded read-only readiness audit and record it on the canonical issue. The
  audit must cover the actual server mounts and shipped callers; ownership,
  schema, and persistence consequences; auth and sensitive-data flow;
  deployment, support-image, and verification selectors; CI token permissions
  and evidence APIs; and the rollback artifact plus local/live smoke shape.
  For a networking or infrastructure correction, the audit must also identify
  the exact enforced object—pod endpoint, host endpoint, load balancer, node or
  provider firewall, or routing boundary—and attach direct flow or verdict
  evidence that the object handled or dropped the failing traffic. A valid
  render/plan, enforcement on an adjacent object, or outbound-only packet
  observation is not attribution.
  Resolve every finding in the cluster definition before source mutation.
  Do not split predictable audit findings into a sequence of implementation-
  time replans.
- One WI is one PR, but a WI is a cohesive deploy/rollback boundary rather
  than a language, file, guard, evidence, or status micro-step. Generated
  clients, all affected ergonomic wrappers, guard ratchets, tests, and the
  workstream status update belong in the same WI when they share
  prerequisites and rollback. Split implementation from a release,
  production, or live-evidence operation only when their prerequisites or
  rollback boundaries genuinely differ. Record routine merge/deploy evidence
  on the canonical issue; do not create a status-only WI unless repository
  state must change or the master names a real downstream decision that
  consumes it.
- Verification and downstream evidence are impact-proportional. Source-only
  docs, guard-data, and SDK changes require their focused local gates,
  exact-head CI, and exact-tree provenance; a no-op deployment selector is a
  classification result, not a reason to wait before independent downstream
  work. Runtime/image changes additionally require exact-source deployment
  evidence. Release, production, credential, and live-state changes require
  their explicitly named operational evidence. Before authorizing a cluster,
  audit the selector result for every planned path; repair an over-broad or
  under-broad selector once, before product implementation.
- Execution controls must distinguish a **merge gate** from a
  **downstream-start gate**. Exact-head CI may be required before merging a
  PR, but it must not automatically block independently authorized local work
  or the next local slice after a predecessor is canonical. A downstream-start
  gate may wait on CI, deployment, or live evidence only when the master names
  the concrete artifact, runtime state, or failure class the next coordinate
  consumes. Docs-only CI is not a downstream-start gate by default.
- When a hard gate is `UNSATISFIED`, do not implement later-wave or unrelated
  dependent work. Same-wave preparation is allowed when the master explicitly
  names the coordinate and prerequisites or when it is admitted through the
  live bounded-parallel envelope. An `UNSATISFIED` gate on one WI does not
  freeze another admitted WI whose independence receipt remains true. Merge
  shared or production mutations serially even when independent preparation
  is concurrent.
- A new finding may be filed with read-only evidence. If reality changes the
  program's scope, dependencies, gates, repositories, contracts, production
  controls, or acceptance criteria, stop all mutations, set the program to
  `STOPPED_FOR_REPLAN`, merge a docs-first replan with the owner's resume
  decision, and only then continue. While stopped, only read-only diagnosis,
  issue filing, and the replan docs PR are allowed; there is no "productive
  side work" exception.
- If a finding is bounded to one WI's implementation, path ownership, or local
  acceptance evidence and does not invalidate the program-level fields above,
  mark that WI's gate `UNSATISFIED` and freeze only the affected or overlapping
  coordinates. The program remains `ACTIVE` for other admitted WIs whose
  receipts still prove independence. A local collision is not by itself a
  program-wide replan.
- Work discovered in one lane may not be pulled into another lane merely
  because it is useful. It executes only at the dependency and coordinate
  recorded by the master or admitted through its bounded-parallel envelope.
  If neither path covers the work, stop the affected lane and replan; do not
  freeze unrelated admitted work unless a program-level invariant changed.
- Examples: `Connect-RPC / Wave 2 / WS04 / WI-8A` is a valid coordinate;
  `Connect cleanup`, `WI-8`, and `work while CI runs` are not sufficient
  execution authorization.

## Gitea and tea

- Gitea (`git.example.invalid/codewire/codewire`) is the source of truth for issues,
  PRs, merges, CI, image builds, and deploys. GitHub is only the public mirror.
- Use command-scoped `tea` flags for routine project work, for example
  `tea issues list --login noel --remote gitea --output json` or
  `tea pulls --login noel --remote gitea <pr> --output yaml`. This installed
  `tea` version does not accept `--login` before the subcommand, and PR/issue
  detail commands are direct entity lookups (`tea pulls <id>`, `tea issues
  <id>`), not `view` subcommands. Prefer `--output yaml` or `--output json`
  when collecting state.
- Open and manage PRs in Gitea with `tea pulls create`, `tea pulls <id>`, and
  `tea pulls merge`. Branch from `gitea/main` and push feature branches to
  `gitea`.
- Poll CI with `tea actions runs list`, `tea actions runs view <run-id>`, and
  `tea actions runs logs <run-id> --job <job-id>`. Always inspect logs when a
  run conclusion is failure; job tables may not expose the failing step.
- Local verification is the development loop; CI is the attestation for the
  exact pushed tree. Run the cheapest meaningful local gates before pushing.
  A required exact-head CI result still controls merge when the repository or
  program says so, and an old-head result never proves a refreshed head.
- Do not continuously watch a healthy CI run. Capture its run ID and exact
  head once. When CI is the only remaining gate, hand it to a transition-only
  observer that waits outside the model and wakes the session on failure,
  stall, or success. Keep the task active until the terminal result is handled;
  token efficiency must never abandon a red run. When no observer is available,
  retain responsibility with sparse checks near the expected terminal horizon.
  Continue independently authorized local work while CI runs; a running check
  grants no authority for unrelated work.
- CI observation output is transition-only: initial run/head binding, changed
  status or conclusion, stall/recovery, and the terminal summary. Do not dump
  complete YAML/JSON repeatedly or read healthy log tails. Inspect only the
  affected job, with a capped tail, on failure, credible stall, empty output,
  or run/job disagreement.
- Retry a runner-owned failure once on the same SHA without a source change.
  If the same failure class repeats, record an infrastructure finding instead
  of entering a retry loop.
- Use CI as the primary reproduction environment only for CI-owned failure
  classes such as runner timing, hosted-cache behavior, workflow permissions,
  or hosted credentials. Locally reproducible product, integration, Kind, or
  contract failures must be diagnosed locally first.
- For bounded Rust CLI-only slices, use the CLI fast-lane rules in
  `docs/dev/RUST-PORT-PLAYBOOK.md`: run focused local CLI gates first, poll CI
  sparsely, inspect logs only on failure or stall, and keep working on
  independent local slices while Gitea runs. Do not use that fast lane for
  workflows, dependencies, lockfiles, deploy/image/KIND surfaces, server
  routes, or live mesh/gateway/daemon behavior.
- Gitea issues are canonical. GitHub issues are closed mirror records that
  point to Gitea replacements; do not reopen or manage active work in GitHub.
  Do not use Linear for active migration tracking.
- Gitea list commands are paginated. When auditing all issues, PRs, runs, or
  milestones, request explicit pages and verify totals.
- The GitHub mirror is maintained by the Gitea mirror workflow using GitHub App
  secrets. Do not add PAT or SSH deploy-key mirror credentials.

## Live smoke topology and evidence

- Before treating a live smoke as product acceptance, name the initiating
  network actor and execution topology—developer workstation, Kubernetes pod,
  host-network Actions job, VM, or another concrete boundary—and explain why
  it represents the supported client path under test. Do not silently promote
  a runner-specific topology into a product gate.
- When a representative client path and a CI runner path differ, classify and
  track their results separately. A runner-only failure blocks product
  acceptance only when that runner topology is itself a supported product path
  or a same-topology reproduction attributes the failure to product behavior.
  Otherwise it is infrastructure coverage and must receive its own bounded
  diagnosis and correction.
- A manual or live acceptance receipt must preserve the exact source and Git
  tree, client binary checksum, deployed image digest, disposable environment
  identifier, named assertions, evidence-bundle digest, authenticated cleanup,
  and zero-resource cleanup proof. Manual does not mean informal; missing
  provenance means the result is diagnostic, not acceptance evidence.
- Do not weaken transport assertions or timeouts to accommodate an executor.
  Change or repair the executor/topology, and keep the product expectation
  fixed. Prefer the representative local/manual smoke as the development loop;
  use CI for exact-tree attestation and separately identified runner coverage.
- A diagnostic must observe the boundary it claims to test. If permissions or
  topology prevent that observation, report the diagnostic as inconclusive and
  preserve its available evidence; do not infer a drop, product regression, or
  successful path from an adjacent endpoint or missing output.

## Local verification before pushing

- Choose verification by what the change actually touches — pick the
  cheapest gate that can catch the failure class at risk, not every
  gate every time. Local kind (`make e2e-kind`,
  `docs/dev/KIND-E2E.md`) earns its run when the change touches edge
  routing, ingress behavior, the kind harness itself, or multi-service
  runtime interaction. Use
  `scripts/ci/verify/run-integration-verification.sh database` for DB schema or
  migration changes and its `services` mode for affected service boot,
  contract, Temporal, NATS, or harness wiring. The selector supplies the
  exact service tokens through `VERIFICATION_SELECTION`. The broader
  `scripts/ci/verify/rust-stack-rehearsal.sh` is an explicit diagnostic, not a
  routine merge gate. None of these helps for docs, pure unit-scope, or
  CLI-only slices (the fast lane covers those); and runner-timing or
  toolchain-cache issues only reproduce in CI. The anti-pattern to avoid is
  using CI as the integration environment for a locally reproducible failure.
- When a squash merge has the same Git tree already proven at the PR head, use
  the tested-tree receipt and only branch-dependent post-merge checks. Do not
  repeat content-equivalent local or CI integration merely because the commit
  object changed.
- Diagnose a red run from the failing component's own log first, and
  confirm that log is non-empty before proposing a mechanism.
- Before focused local Cargo commands in a linked worktree, export
  `CARGO_TARGET_DIR="$(scripts/ci/verify/resolve-cargo-target-dir.sh)"`. This shares
  dependency artifacts through the repository's common Git directory while
  preserving Cargo's profile/fingerprint separation. Product-verification and
  integration entrypoints configure the same resolver automatically, and an
  explicit non-empty `CARGO_TARGET_DIR` remains authoritative.
- Before introducing any new global identifier — Postgres advisory
  key, listen port, env var, bun workspace package — sweep the repo
  for existing users. New bun workspace packages must also be added to
  the enumerated `package.json` COPY lists in
  `apps/dashboard/Dockerfile{,.dev}` and `apps/docs/Dockerfile.dev`,
  and new build-time inputs (e.g. proto compilation) must be shipped
  into the service/mesh image builders.
