# Agent Operating Rules

This file is authoritative for this repository. `CLAUDE.md` is a compatibility
symlink; do not maintain separate instructions there. Detailed commands live in
[`docs/dev/AGENT-WORKFLOW.md`](docs/dev/AGENT-WORKFLOW.md).

## Authority

Codewire uses direct authority mode. Normal work may be authorized
in conversation: read-only inspection, scoped edits, focused checks, commits,
branch pushes, pull requests, and merges. Read-only work needs no tracker,
claim, approval receipt, or Program. Filing an issue records evidence; it does
not authorize implementation.

Carry an authorized landing objective through verification, commit, push, PR,
exact-head gates, merge, and closure unless the owner explicitly requests a
checkpoint. A clean worktree, no valid commit yet, or a reverted attempt is not
a terminal condition while a safe in-scope next action remains. Never commit
known-bad work or weaken a gate merely to maintain momentum.
Questions, criticism, and status requests during active work do not pause that
objective; answer them and continue in the same turn unless the owner says to
pause, stop, or change scope.

After failure, preserve non-secret evidence and localize the failing layer
before attribution. Retry a side effect only when a changed factor predicts a
discriminating observation, unless canonical policy identifies a transient
failure. An unknown result freezes only that mutation; continue read-only
diagnosis and independent authorized work. Keep bounded diagnosis and repair
under the same claim and admission; do not create an issue, PR, control
transition, or authority request for each hypothesis.

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
An unchanged exact-head rerun of verification-only CI is routine delivery when
canonical policy classifies the failure as transient; it inherits the landing
objective and needs no new approval or receipt. Retry once, then diagnose a
repeat. Workflow changes, recovery, release tags, production actions, new
destinations, direct credential handling, and workflow reruns capable of
publication, deployment, release, recovery, or live mutation remain separate
operations.

Request separate authority just in time: the exact operation must be ready,
its prerequisites satisfied, and it must be the immediate next useful action
after authorized work is exhausted. First classify whether the effect is an
unchanged automatic consequence. Do not request or batch authority for later
operations whose prerequisites are not yet satisfied.

Preserve unrelated user changes and worktrees. Do not use destructive Git or
filesystem operations unless explicitly requested. A Gitea outage permits only
collision-free local preparation: no canonical claim, push, merge, shared
mutation, or external effect until state is reconciled.

Do not set, request, infer, enforce, or report goal token or time budgets.

## Noel Method

Codewire is pinned to the immutable Noel Method v0.8.1 runtime pack:

- Commit: `1c86e77ccacfa3c29b01e4d14b9f136df9e6f704`
- Manifest SHA-256: `4a6925fee937b200d3e49c5aceae30edfb97af378bb79fef00df68e54ba8299f`
- Index: `https://raw.githubusercontent.com/noeljackson/method/v0.8.1/dist/pack/INDEX.md`

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
  one claim-relative risk-specific readiness pass, a canonical claim when
  collision risk exists, focused high-risk verification, and exact-head CI.
- **Tier 3 — external/irreversible:** releases, manual publication or recovery,
  production mutation, direct credential handling, or another difficult-to-
  reverse external effect. Require explicit authority, preconditions,
  acceptance evidence, and rollback.

The highest matching tier applies. A bounded implementation finding
stays within its change and is repaired once. Replan only when the goal,
repositories, dependency order, public contracts, external effects, or
acceptance criteria materially change.

Readiness reuses accepted current evidence and inspects only unresolved facts
that could change the next cohesive mutation's design, ownership, rollback,
verification, or acceptance. It is incremental: do not make an end-to-end
Program inventory or resolution of later repositories and environments a
prerequisite for an independent source change. Reconcile those surfaces when
their dependent work reaches the frontier, unless they can alter the next
mutation now.

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

Keep the live body current and compact. At a transition, replace superseded
frontier, claim, queue, and gate state rather than appending an action history.
Link completed evidence from comments or child issues instead of copying its
full receipts into the live control.

Describe the current frontier in actionable detail. Future work may remain at
dependency level; resolving every later claim, repository base, branch, and
operational gate is not a prerequisite for dispatching the first safe claim.

A future authority or downstream gate is not a current blocker. The Program is
blocked only when no authorized dispatchable work remains and the immediate
next useful action requires missing authority or an external state change.
`Blockers` contains only conditions preventing every dispatchable action;
later conditions stay under downstream-start gates. Non-empty dispatchable
work means the Program itself is not blocked.

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
current `gitea/main`. Reconcile an owning claim at admission or material change,
and reconcile the PR, current main, and required evidence immediately before
merge. Routine pushes inherit an unchanged claim. An old-head result never
proves a refreshed head.

Local verification is the development loop; CI attests the exact pushed tree.
Run the cheapest gate able to catch the affected failure class. Diagnose
locally reproducible product, integration, contract, or Kind failures locally
first. Follow the failure-convergence ladder in the developer workflow. Use CI
first only for CI-owned behavior such as hosted timing, cache, permissions, or
credentials. Bind remote CI once to its exact head and run. A
transition-aware watcher may surface early failure or terminal completion when
that feedback matters. Starting it is one model action: once bound, let it wait
outside the model. Do not create recurring model turns to call `write_stdin`,
read its terminal session, or query the same healthy run merely to learn that
nothing changed. Continue independent authorized work while CI runs. Resume on
watcher output, an external or user wake, the expected terminal horizon, or a
credible stall. If the host cannot wake the thread automatically, yield with
the bound run ID and head and check once near that horizon instead of simulating
notification with repeated reads. Inspect targeted logs only after failure,
run/job disagreement, empty output, or credible stall.

Verification must use the repository-owned topology and documented invocation
for the exact tree under test. Never introduce an ad-hoc network relay, proxy,
listener, tunnel, port-forward shim, alternate ingress path, host route, hosts
entry, firewall rule, or tracked-fixture rewrite to make a hook or required
gate pass. Do not bypass or disable a hook or gate. This prohibition applies
even when the workaround is local, temporary, non-secret, or outside the
worktree. A network component may be created only when it is itself requested
work or an already checked-in, documented part of the selected verification.
If the documented gate cannot run because of the local environment, stop the
affected push or merge, preserve the failure evidence, and report the blocker;
resume only with the documented topology on a suitable runner or after a
repository change has been separately reviewed and merged.

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
