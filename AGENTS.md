# Agent Operating Rules

This file is authoritative for Codewire. `CLAUDE.md` is a compatibility
symlink; do not maintain separate instructions there. Commands and verification
details live in [`docs/dev/AGENT-WORKFLOW.md`](docs/dev/AGENT-WORKFLOW.md).

## Authority and safety

Codewire uses direct authority mode. Conversation may authorize normal source
work through inspection, scoped edits, checks, commits, pushes, PRs, exact-head
gates, merge, and closure. Read-only work needs no tracker or claim. An issue
records evidence; it does not authorize implementation.

Carry an authorized landing objective through delivery unless the owner asks
for a checkpoint. Questions, criticism, failed attempts, clean worktrees, and
reverted approaches do not pause it while safe in-scope work remains. Preserve
unrelated changes, never commit known-bad work, and never weaken a gate for
momentum.

Release tags, manual publication or recovery, production or nonstandard live
mutation, and direct credential access require explicit action-scoped
authority. Request it only when that operation is ready and is the immediate
next useful action. A risk tier adds safeguards, not authority.

An automatic consequence inherits authority only when canonical policy already
declares it at the exact base and the authorized action alone triggers it.
Codewire's ordinary merge consequences are CI, support-image publication,
standard Dev delivery, and main-branch GitHub mirroring. Workflow changes,
manual reruns, recovery, releases, production actions, new destinations, and
direct credential handling remain separate operations.

Do not use destructive Git or filesystem operations without explicit request.
During a Forgejo outage, only collision-free local preparation is allowed; no
claim, push, merge, shared mutation, or external effect may proceed until
canonical state is reconciled. Do not set or report goal token or time budgets.

## Noel Method

Codewire pins the immutable Noel Method v0.9.3 runtime pack:

- Commit: `93f68ba4abc9f6e222481265b9b759e71d332575`
- Manifest SHA-256: `a005933cd29affc6555731d5921cbad2977e5d932c1f7a413fdd69da4def9d05`
- Index: `https://raw.githubusercontent.com/noeljackson/method/v0.9.3/dist/pack/INDEX.md`

Resolve Method links only beneath that pack. Direct mode is the default. Load
Program only for persistent dependent work across sessions, repositories, or
operational gates; Experiment only for a controlled comparison; Secrets only
when the agent or a local process can access secret material. Protocols add
procedure, never permission. Several steps alone do not select Program.

Codewire risk tiers are independent of Method protocols:

- **Tier 1:** read-only and reversible single-repository work. Inspect the
  smallest source set and run the cheapest meaningful check.
- **Tier 2:** shared or high-risk source such as migrations, public/generated
  contracts, auth or sensitive-data flow, workflows, selectors, dependencies,
  lockfiles, generated trees, deploy inputs, destructive edits, or a real
  collision. Add one claim-relative readiness pass, focused high-risk checks,
  and exact-head CI.
- **Tier 3:** releases, manual publication or recovery, production mutation,
  direct credentials, or another difficult-to-reverse external effect. Require
  explicit authority, preconditions, acceptance evidence, and rollback.

Readiness is incremental and relative to the next mutation. Reuse accepted
evidence; inspect only unresolved facts that can change its design, ownership,
rollback, verification, or acceptance. Replan only for a material boundary
change.

## Program control

Use the pinned Method Program format: one canonical Forgejo tracker body, one
unambiguous coordinator, a fenced TOML header, then `Goal`, `Done when`,
`Current`, `Next`, `Needs from human`, `Boundaries`, and `Evidence`. Existing
controls migrate at a natural transition; do not pause delivery solely to
reformat one.

Only the named coordinator edits live control after rereading it. Increment
`control_revision` once for a material change to state, coordinator, frontier,
claims, gates, `Next`, or human need. Comments, receipts, PRs, commits, local
plans, worktrees, and host goals are evidence or scheduling only; they never
change Program control. Keep the body compact and replace superseded state.

Bind a collision-prone mutation once. Routine implementation, repair, rebase,
verification, push, and review inherit the claim. Future authority and
downstream gates are not blockers while authorized work remains. Independent
work continues while a passive gate runs.

Keep an in-scope defect under the owning objective and repair it cohesively.
Use `STOPPED_FOR_REPLAN` only for a material change to accepted scope,
dependencies, contracts, effects, recovery, authority, or acceptance. In that
state, stop Program mutations except read-only diagnosis and control repair.

## Forgejo and delivery

Forgejo `origin` is canonical for issues, PRs, merges, CI, image builds, and
deploy evidence; GitHub is a public mirror. Branch from current `origin/main`.
Reconcile the claim at admission or material change and reconcile the PR, main,
and required evidence immediately before merge. An old-head result never
proves a refreshed head.

Local verification is the development loop; CI attests the exact pushed tree.
Use CI first only for CI-owned behavior such as hosted timing, cache,
permissions, or credentials. Bind a run once and use the transition-aware
watcher when early failure matters; do not spend model turns polling unchanged
healthy CI. Continue independent work while it runs.

Verification must use the checked-in topology and documented invocation.
Never add an ad-hoc proxy, relay, listener, tunnel, port-forward, route, hosts
entry, firewall rule, or fixture rewrite to make a hook or gate pass. Do not
bypass or disable a gate. If the documented topology is unavailable, preserve
the failure and stop only the affected push or merge.

Unknown change impact fails closed. A selected gate cannot report success when
its prerequisite is absent or the relevant test skipped. Preserve exact-tree
reuse only when the tested tree and verification controls are unchanged.

## Repository invariants

- Migrations require compatibility, authoritative database verification, and a
  rollback boundary.
- Public/generated contract changes include generated clients, ergonomic
  wrappers, and contract tests in one cohesive change.
- Workflow, selector, artifact, and deploy-input changes prove trusted-base
  behavior and cannot use proposed-head policy to reduce their own checks.
- Search all users before adding a global identifier. New Bun packages must
  reach applicable Dockerfiles; new build inputs must reach every consumer.
- Never add PAT or SSH deploy-key credentials for the GitHub mirror.
