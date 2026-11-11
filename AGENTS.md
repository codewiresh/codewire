# Agent Operating Rules

This file is authoritative for Codewire. `CLAUDE.md` is its compatibility
symlink. Commands live in [`docs/dev/AGENT-WORKFLOW.md`](docs/dev/AGENT-WORKFLOW.md);
cross-repository rules, decision placement and the orchestrator are in the
root `AGENTS.md` (`/home/user/src/codewire/AGENTS.md` on the owner workstation).
Every rule here has one home; when a doc, skill or script is named, it is the
home and this file only points at it.

## Authority and safety

Codewire uses direct authority. Conversation may authorize normal repository
work through merge and closure. Read-only work needs no tracker or claim. Carry
an authorized landing objective through its safe in-scope steps unless the
owner asks to stop or checkpoint. A complaint, a question or frustration is not
approval: propose and wait for an explicit choice (owner, 2026-10-29).

Routine developer work on owner-designated machines, including Macs, has
standing authority within an authorized task: checked-in verification and
regeneration of derived artifacts, source transfer, tool setup, builds and
tests, ad-hoc development signing, disposable VM lifecycle, checked-in test
networking, retries of existing verification after a diagnosis, and cleanup of
the task's own processes and artifacts. Do not invent one-shot gates because a
command runs remotely, uses real hardware or needs a diagnosed retry. It never
covers real credentials or unrelated user data, release signing or publication,
shared or production infrastructure mutation, or ad-hoc topology changes to
make a gate pass. Use synthetic credentials for verification; checked-in
tooling such as `make kind-credentials-real` may load the owner's development
credentials into the local Kind cluster through pipes into Kubernetes Secrets,
never printed, logged, written to disk or held by the agent. Never ask the
owner to paste a secret; reading or displaying a secret value needs explicit
authority. Preserve unrelated changes and worktrees; never commit known-bad
work, weaken a gate for momentum, or use destructive Git or filesystem
operations without an explicit request.

**Tier 3: recovery, unusual Production mutation and direct credential access
need explicit, action-scoped authority from the owner.** A Production
configuration change observed working on Dev, with a written rollback, that
ships through the normal release path is not unusual and needs no per-action
approval, nor does one merged through its reviewed pull request with a written
rollback (owner, 2026-11-11; cited on #3013; the full list is in the root
`AGENTS.md`). Ordinary merge
consequences already declared at the canonical base (CI, support-image
publication, Dev delivery, GitHub mirroring) inherit merge authority; new
destinations, workflow changes, recovery and unusual Production actions do not.
**Releases are cut without per-release approval** (owner, 2026-10-30: "Releases
can get cut automatically. I don't need to approve."; cited on #3013): the
orchestrator pushes a `v*` tag on a commit with green `main` CI, Dev acceptance,
a green dry run and its support pair. A pushed `v*` tag is a Production action:
within five minutes the scheduled `deploy-prod` verifies and delivers it and
`cli-release` publishes the CLI (owner, 2026-10-23, #2892). A tag not picked up
within 24 hours, or a release that
failed, is recovered only by dispatching `deploy-prod` then `cli-release` for
it; a rerun of a scheduled run reads no release credential. That recovery needs
no per-release approval either (owner, 2026-11-10: "Why do you need me to rerun
releases? You don't need me."; cited on #3013).

## Method and risk

Use Noel Method v0.11.0, commit `19c516e95a1c610cdd7891605ef6be7b044d5390`
(the root `AGENTS.md` has the pin and the Program rules). Direct mode is normal;
Program only for persistent dependent work; Experiment for controlled
comparisons; Secrets when a local process can access secret material.
Protocols add procedure, not permission. Risk tiers: **1** read-only or
reversible single-repository work; **2** shared contracts, auth or data
boundaries, migrations, workflows, selectors, dependencies, generated or deploy
inputs, destructive edits; **3** recovery, unusual Production mutation,
direct credentials. Risk selects safeguards, not unrelated tests.

## Done means observed working

A change that affects anything a user or operator can see or do is not done
until it has run in the product and been observed working. Tests, checks and
CI are necessary evidence; they are never proof of behaviour.

- Walk each user-visible change's acceptance journey where it runs: dashboard
  and platform changes on Dev once delivered (a Dev observation counts only on
  the source `promote-dev` in codewire/deploy actually rolled out), or on the
  retained local Kind cluster before merge when Dev is impractical; CLI and host
  changes with a built `cw` on the host. Include the empty, failure and recovery
  states it touches. Record what was run and what was observed.
- Kind is never a merge requirement (owner, 2026-10-21). It stays a maintained
  local tool for behaviour that is tricky or slow to test on Dev; the commands
  are in `AGENT-WORKFLOW.md`. Never recreate the retained cluster to test a
  change; deploy into it.
- Every workstream and handoff names a mandatory local acceptance journey; if
  it depends on tooling that does not exist yet, that tooling lands first.
- When a real provider step needs the owner, prepare everything else and ask
  once for exactly that step. Until the journey has run, report the change as
  "not yet observed working". Report merged, on Dev and live in Production
  separately.

## Plans and worktrees

Designs, plans, handoffs and research live in the sibling `codewire/private-docs`
repository, never here; its `AGENTS.md` says where each kind goes. A plan's
control is a Forgejo issue; private-docs holds evidence. Shipped-behaviour
documentation stays under `docs/`. Worktrees follow the workstation rule
(`/home/user/src/worktrees/codewire/codewire/<task-slug>`, from a freshly
fetched `origin/main`, cleaned up by the agent that created it); the commands
are in `AGENT-WORKFLOW.md` "Hygiene".

## Delivery and verification

Commit messages and merge metadata are public content. Never include private
URLs, private hostnames or workstation paths there. A `Reviewed-on:` trailer
must name only the pull request number (`#N`), never a URL, including defaults
generated by a CLI or server (owner, 2026-11-08, #3013). Merge with
`scripts/dev/merge-pr.sh` and inspect its explicit title/body; the public-content
gate remains blocking without historical exceptions.

Forgejo `origin` is canonical; GitHub is a mirror. Use the installed `fj` CLI,
never `tea`. Local checks are the development loop: use the smallest check that
catches the affected failure class, plus the product journey above.
`scripts/dev/preflight.sh --all` runs the hosted families locally when that is
faster than waiting; it records nothing and qualifies nothing. The pre-push
hook runs only the fast push check; do not bypass it. A push is never a long
gate.

- **Merge rule.** Pull-request CI is the merge gate (#3119). A pull request
  merges on its required statuses green on its exact head, `CI / Required
  verification (pull_request)` and `Supply-chain scan / Supply-chain scan
  (pull_request_target)`, which branch protection enforces, plus its product
  journey. Local evidence never replaces them. Each pull request merges alone,
  never in a train. One that merges cleanly merges without a rebase (owner,
  2026-10-21). On a conflict, bringing it up to date is judgment (owner,
  2026-10-27, #3013): merge `main` in when someone else works on or has
  reviewed the branch; rebase when it is yours alone; never force-push a branch
  another session drives. The one exception to the statuses is the advisory and
  expiry break-glass (#3119 P3 (a)): one infra PR lifts the `Supply-chain scan`
  context for one reviewed exception PR and a second restores it; advisory and
  expiry checks otherwise stay blocking (owner, 2026-10-21).
- **Forgejo checks the head, not the merged tree.** `main` CI verifies the
  landed tree after merge and a failure there is fixed forward; never cancel a
  `main` run by hand. Cancelling and rerunning runs is the orchestrator's call
  under the `ci` skill (owner, 2026-10-29: cancel only what we don't need to
  finish, after looking), and `main` CI and release publication always finish.
- **Pull-request CI** runs every family the change's paths select, as `main`
  does, except Kind; label the PR `ci-full` to add Kind when a hosted-only
  claim needs it. Kind CI is off on the schedule and on dispatch until the
  owner revisits it (owner, 2026-10-25); where it will run is infra
  `docs/ci/runners.md` and `private-docs: designs/ci-vm-model.md`.
- **Dev** runs only commits whose `main` CI passed. One Dev delivery is in
  flight at a time and always finishes and publishes; at most one waits behind
  it, the newest, a newer commit replaces the waiting one, and no delivery is
  cancelled (owner, 2026-11-10, #4071; replaces the 2026-10-24 cancel rule and
  the 2026-10-21 two-building limit). The mechanism is the "Dev delivery turn"
  job in `.gitea/workflows/deploy-dev.yaml`, `docs/dev/CI-CONFIGURATION.md` and
  codewire/deploy.
- **Release candidates.** A release tag's receipt needs green `main` CI, a
  green dry run and Dev acceptance of the exact candidate commit
  (`scripts/ci/receipts/verify-release-tag-receipt.sh`; what a push to `main`
  runs, and the conditions for restoring Kind and the dry run to every push,
  are in `scripts/ci/select/main-push-switch.sh`). Dispatch the dry run on
  `main` naming the candidate (`fj actions dispatch -R origin
  cw-release-dry-run.yaml main -I source_sha=<candidate>`) so `main` never
  stops for a cut. Never build arm64 under emulation when the native builder
  exists; a tag never points at a commit without its published support images.
- Every CI change follows the `ci` skill. Prefer the faster build or CI option
  and measure afterwards (owner, 2026-10-15). A failing guard fails its run;
  repair the classifier and its fixtures when a narrow path selects an
  expensive suite. Record actual commands, exit status and test counts; reuse
  evidence only while its inputs still match. Use only checked-in verification
  topology, never an ad-hoc proxy, tunnel, port-forward, hosts entry, firewall
  rule or fixture rewrite to make a gate pass; OpenSnitch blocks follow the
  workstation `AGENTS.md`. Bind a hosted run once and let a watcher own the
  passive wait (`AGENT-WORKFLOW.md` "Forgejo"); never poll unchanged CI.

## HTML and frontend

The `codewire-design` skill (`.agents/skills/codewire-design/SKILL.md`) is the
home of the dashboard rules: semantic HTML, no diagnostic instrumentation in
tracked templates, container-owned gutters, token and fixture parity. The UI
iteration checkpoint gates landing, not local development: edit locally, review
the real application, and do not commit, push, open a PR or run hosted CI until
the owner says "land it".

## Rust

The `codewire-rust` skill (`.agents/skills/codewire-rust/SKILL.md`) is the
home of the Rust structure rules: file and function size, enum state, typed
errors, unsafe and syscall wrappers, row structs. Lint levels live in
`[workspace.lints]` in `Cargo.toml` (owner, 2026-11-11; cited on #3013).

## Repository invariants

- Migrations require compatibility, database proof and rollback. Applied
  migration bytes are immutable; upgrade fixtures bind accepted prior bytes,
  never a ledger derived from the edited branch (`docs/dev/DATABASE-MIGRATIONS.md`).
  Local and Kind databases are disposable and move forward on deploy; only a
  downgrade is refused (owner, 2026-10-15). Dev and Production data move only
  forward through the reviewed migration path.
- Public and generated contracts ship generated clients, wrappers and tests
  together. Search existing users before adding global identifiers; send new
  packages and build inputs to every consumer.
- Never add PAT or SSH deploy-key credentials for the GitHub mirror.
- The cargo-hakari workspace-hack is a dev-dependency only, so shipped
  binaries keep exactly their own dependency graph; never move it to
  `[dependencies]` without the owner (owner, 2026-10-12, #2588).
- Product vocabulary (`snapshot`, `environment projection`, `VM checkpoint`)
  is defined in `docs/GLOSSARY.md`; use it in product language and public APIs.
- Secrets and credentials: the product model, the runtime boundaries, the
  direct-delivery exceptions and the bridge-epoch reuse limits are specified in
  `docs/dev/SECRETS-AND-CREDENTIALS.md`, whose "Invariants" section is the one
  home of those rules. Private provider material never enters a sandbox except
  a listed exception; a local VM qualifies and routes credentials exactly as a
  hosted Sandbox; never add a process-wide or persistent material or decision
  cache. The policy checks under `scripts/checks/repo_policy/` enforce the
  reuse boundary.
