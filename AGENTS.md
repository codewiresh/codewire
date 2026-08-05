# Agent Operating Rules

This file is authoritative for this repository. `CLAUDE.md` is a compatibility
symlink; do not maintain separate instructions there. Detailed commands live in
[`docs/dev/AGENT-WORKFLOW.md`](docs/dev/AGENT-WORKFLOW.md).

## Authority

Codewire uses direct authority mode. Normal repository work may be authorized
in conversation: read-only inspection, scoped edits, focused checks, commits,
branch pushes, pull requests, and merges. Read-only work never needs a tracker,
claim, approval receipt, or Program. Filing an issue records evidence; it does
not authorize implementation.

Release tags, manually initiated publication or recovery, production or
nonstandard live-state mutation, and direct credential access require explicit
action-scoped authority. A risk tier adds safeguards but never creates
authority.

Authorization includes an automatic consequence only when it is pre-existing
and unchanged at the exact canonical base, declared by repository policy,
repository-owned, and triggered solely by the authorized action. Codewire's
enumerated merge consequences are ordinary CI, support-image publication,
standard Dev delivery, and main-branch GitHub mirroring. CI using configured
credentials that the agent cannot read is not direct credential access.
Workflow changes, manual reruns, recovery, release tags, production actions,
new destinations, and direct credential handling remain separate operations.

Preserve unrelated user changes and worktrees. Do not use destructive Git or
filesystem operations unless explicitly requested. A Gitea outage permits only
collision-free local preparation: no canonical claim, push, merge, shared
mutation, or external effect until state is reconciled.

Do not set, request, infer, enforce, or report goal token or time budgets.

## Noel Method

Codewire is pinned to the immutable Noel Method v0.7.0 runtime pack:

- Commit: `705a7a3f1aa117cb2ef1358cc75d3bc109cd928f`
- Manifest SHA-256: `44b08fb6aa6f239c878f09bb16fcad246583b3f72f2d3eca627b0d9743dbdcba`
- Index: `https://raw.githubusercontent.com/noeljackson/method/v0.7.0/dist/pack/INDEX.md`

Resolve Method links only beneath that published pack. Direct mode is the
default. Select protocols independently of repository risk:

- Program only for persistent dependent work across sessions, repositories,
  or operational gates.
- Experiment only for a controlled comparison.
- Secrets only when the agent or a locally invoked process can access secret
  material.

A multi-step task does not by itself require Program. Protocols add procedure,
not authority. Resolved mode, ProjectPolicy, TaskRequest,
ResolvedPermissions, and a resolver are not required in Codewire.

## Risk tiers

- **Tier 1 — normal:** all read-only work and single-repository reversible
  changes without a higher trigger. Inspect the smallest current source set,
  make the scoped change, run the cheapest meaningful check, and use exact-head
  CI when a PR requires it.
- **Tier 2 — shared/high-risk source:** multi-repository source mutation;
  migrations; public or generated contracts; authentication or sensitive-data
  flow; workflows, selectors, dependencies, lockfiles, generated trees, shared
  build/deploy inputs, destructive edits, or a real ownership collision. Add
  one risk-specific readiness pass, a canonical claim when collision risk
  exists, focused high-risk verification, and exact-head CI.
- **Tier 3 — external/irreversible:** releases, manual publication or recovery,
  production mutation, direct credential handling, or another difficult-to-
  reverse external effect. Require explicit authority, preconditions,
  acceptance evidence, and rollback.

The highest matching tier applies to the task. A bounded implementation finding
stays within its change and is repaired once. Replan only when the goal,
repositories, dependency order, public contracts, external effects, or
acceptance criteria materially change.

## Program control

A Program has one live Gitea issue body and one named primary coordinating
session. Its state is exactly `ACTIVE`, `STOPPED_FOR_REPLAN`, `COMPLETE`, or
`TERMINATED`; termination reason is `OWNER_CANCELLED`, `SUPERSEDED`, or
`SAFETY`. Gates are exactly `SATISFIED` or `UNSATISFIED`.

The body owns `control_revision`, coordinator, state, goal, acceptance,
frontier, dependencies, active claims, dispatchable work, merge gates,
downstream-start gates, blockers, and exceptional authority. Only the named
coordinator edits it, after rereading and incrementing `control_revision`.
Comments, PRs, commits, and receipts supply evidence but cannot change live
state, claims, gates, queue, or frontier. Checked-in plans are design or archive,
never live control.

Bind a claim or coordinate once; routine actions inherit it. Reconcile on
admission, material change, merge, and external mutation rather than before
every action. Exact-head CI is a merge gate, not automatically a downstream-
start gate. Independent authorized work may continue while CI runs.

When `STOPPED_FOR_REPLAN`, stop that Program's mutations except its control
repair. Separately authorized work outside the Program remains unaffected.
Branches and worktrees are not canonical claims.

## Gitea and delivery

Gitea (`git.example.invalid/codewire/codewire`) is canonical for issues, PRs, merges,
CI, image builds, and deploy evidence; GitHub is a public mirror. Branch from
current `gitea/main`. Before push or merge, reconcile the owning claim, PR,
current main, and required evidence. An old-head result never proves a refreshed
head.

Local verification is the development loop; CI attests the exact pushed tree.
Run the cheapest gate able to catch the affected failure class. Diagnose
locally reproducible product, integration, contract, or Kind failures locally
first. Use CI first only for CI-owned behavior such as hosted timing, cache,
permissions, or credentials. Poll healthy CI on transitions or when it is the
sole blocker, and inspect component logs on failure.

Unknown or ambiguous change impact fails closed. Selected required work must
not report success when a prerequisite is absent or the relevant test skipped.
Preserve exact-tree reuse when a squash merge has the same tested tree and
unchanged verification controls.

## Durable repository invariants

- Migrations require compatibility, authoritative database verification, and a
  rollback boundary.
- Public/generated contract changes include affected generated clients,
  ergonomic wrappers, and contract tests in one cohesive change.
- Workflow, selector, artifact, and deployment-input changes prove trusted-base
  behavior and cannot use proposed-head policy to reduce their own checks.
- Before adding a global identifier, search all existing users. New Bun
  workspace packages must be copied by the applicable Dockerfiles; new build
  inputs must reach every consuming image builder.
- Never add PAT or SSH deploy-key credentials for the GitHub mirror.
