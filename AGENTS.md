# Agent Operating Rules

This file is authoritative for Codewire. `CLAUDE.md` is its compatibility
symlink. Commands live in [`docs/dev/AGENT-WORKFLOW.md`](docs/dev/AGENT-WORKFLOW.md).

## Authority and safety

Codewire uses direct authority. Conversation may authorize normal repository
work through merge and closure. Read-only work needs no tracker or claim. Carry
an authorized landing objective through its safe in-scope steps unless the
owner asks to stop or checkpoint.

An authorized landing objective includes repository-selected checked-in
verification and regeneration of intended derived or golden artifacts,
including Kind, renderer-specific browser snapshots, and exact-head CI when
selected; these are not separate authority gates. An explicit named exclusion
applies only to the exact run or effect it names and must not be generalized to
adjacent verification. This inheritance never authorizes access to real
secrets or credentials or bypassing a selected gate: use synthetic credentials
for verification unless direct access is separately authorized, and preserve
the checked-in topology and assertions.

Routine developer work on owner-designated local or remote machines, including
Macs, has standing authority within an authorized task. Run developer commands
without per-operation approval: source/artifact transfer, dependency and tool
setup, builds/tests, ad-hoc development signing, disposable VM lifecycle,
checked-in test networking and synthetic workspace shares, and cleanup of the
test's identified processes and disposable artifacts. These are ordinary
build-loop operations, not separate hardware or destructive-action gates.
Bound runtime and resources, preserve unrelated user state and checked-in
topology, and diagnose failures before rerunning. Do not invent one-shot gates
merely because a command runs remotely, uses real hardware, signs a development
helper, or needs a diagnosed retry.

This standing permission does not authorize access to real credentials or
unrelated user data, release signing/publication, shared/production
infrastructure mutation, or ad-hoc topology changes to make a gate pass.
Explicit owner exclusions and checkpoints still apply; reuse valid evidence
and preserve selected gates. Routine VM networking is not an ad-hoc host change.

Preserve unrelated changes and worktrees. Never commit known-bad work, weaken a
gate for momentum, or use destructive Git/filesystem operations without an
explicit request. A Forgejo outage permits only collision-free local work until
canonical state is reconciled.

Release tags, manual publication/recovery, production or unusual live mutation,
and direct credential access require explicit action-scoped authority. Ordinary
merge consequences already declared at the canonical base—CI, support-image
publication, standard Dev delivery, and GitHub mirroring—inherit merge
authority. New destinations, workflow changes, releases, recovery, and
production actions do not. Routine retries or reruns of existing verification
within an already-authorized task inherit that authority and need no separate
approval. First diagnose why the prior attempt did not produce reusable
evidence, preserve the selected gate, and honor any explicit named exclusion
for the exact run it names.

## Method and risk

Use Noel Method v0.10.0, exact merged commit
`6d7826aecda20f875bc1f9a29c333d5d5ef4e5e7`, manifest
`ff68193d531043d0498841fa104cfc1de713307ab80577eabaaae09c05b53151`.
Direct mode is normal. Use Program only for persistent dependent work across
sessions, repositories, or operational gates; Experiment for controlled
comparisons; Secrets when a local process can access secret material. Protocols
add procedure, not permission.

- **Tier 1:** read-only or reversible single-repository work.
- **Tier 2:** shared contracts, auth/data boundaries, migrations, workflows,
  selectors, dependencies, generated/deploy inputs, destructive edits, or real
  collisions.
- **Tier 3:** releases, recovery, production mutation, or direct credentials.

Risk selects safeguards, not unrelated tests. Inspect only facts that can alter
the next mutation. Reuse accepted evidence and replan only for a material change
to scope, dependencies, contracts, effects, recovery, authority, or acceptance.

## Program control

A Program has one canonical Forgejo issue body and one coordinator. Use the
pinned Method header plus `Goal`, `Done when`, `Current`, `Next`, `Needs from
human`, `Boundaries`, and `Evidence`. Only the coordinator edits it, after a
reread, incrementing `control_revision` for material control changes. Comments,
commits, PRs, receipts, plans, worktrees, and host goals are evidence, not
control. Keep the body compact and replace superseded state.

Bind collision-prone work once; routine implementation, repair, verification,
push, and review inherit it. Continue independent authorized work while passive
gates run; future gates are not current blockers. `STOPPED_FOR_REPLAN` stops
Program mutation except read-only diagnosis and control repair.

For long-running work, use one staged proof loop: confirm canonical control and
risk; get an independent design/security read before broad implementation;
build the smallest coherent slice; run focused checks and review the diff before
committing a credible candidate. Then complete the selected exact-tree
qualification once, locally before push or on self-hosted Forgejo when the
owner selects CI, reusing valid evidence. Complete remaining exact-head landing
gates before merge. Each PR states one bounded
outcome, its dependencies, affected contracts, and acceptance; keep generated
contracts and their consumers atomic. Update Program control at admissions and
material transitions, with evidence labeled accurately. Parallelize read-only
audits and disjoint edits, with one owner for each mutation surface. If review
invalidates a trust boundary, remove or defer that slice before spending the
expensive gate. Keep the main checkout clean, investigate unexpected dirt before
changing it, and reconcile `origin/main` immediately before landing.

## Worktree and artifact lifecycle

On the owner workstation, keep the canonical checkout at
`/home/user/src/codewire/codewire` and put every new linked worktree under
`/home/user/src/worktrees/codewire/codewire/<task-slug>`. Do not create new
worktrees in `/home/user/t`, `/tmp`, cache directories, or beside the canonical
checkout. On another machine, use its dedicated worktree root with the same
`<owner>/<repository>/<task-slug>` organization. Begin each task from current
`origin/main` and use one stable, readable task slug for its branch and path.

The agent that creates a worktree owns its automatic cleanup. After the task is
merged, closed, or explicitly abandoned, stop its processes; remove its
disposable runtime, cache, and build artifacts; prove the worktree is clean and
its commits are merged, pushed, or intentionally preserved; then remove it from
the canonical checkout and prune stale worktree metadata. Delete the local task
branch only after proving it contains no unique work. Never force-remove a dirty
worktree or delete shared caches, toolchains, or paths used by another live
task. If safe cleanup cannot finish, retain the exact path and report the reason.

## Delivery and verification

Forgejo `origin` is canonical; GitHub is a mirror. Branch from current
`origin/main`, and reconcile main, PR head, ownership, and required evidence
immediately before merge.

Use the installed `fj` CLI for Forgejo issues, PRs, Actions, and merges. The
legacy `tea` CLI is not part of the supported agent workflow.

Use the smallest check that can catch the affected failure class. Local checks
are the development loop. Hosted CI is required only when a hosted-only claim
(such as scheduling, credentials, permissions, cache, or timing) lacks
equivalent accepted exact local/read-only evidence, or repository protection
explicitly requires it. Otherwise CI is optional confirmation, not a reason to
delay equivalent exact-tree proof.

Local and hosted policy checks share one checked-in core. Never maintain a
separate local subset; preserve capability-selected expensive checks. A failing
guard must fail qualification and prevent successful receipt emission.

Do not run the same exact-tree qualification twice. Reuse a valid receipt or an
already-running owner. If an obviously narrow path selects the full product or
Kind suite only because classification is missing, repair the classifier and
its fixtures; do not use an expensive unrelated suite as the classifier. An
unknown result blocks the affected mutation, not unrelated work.

When the repository owner selects self-hosted Forgejo for full image or
integration verification, complete focused local checks and diff review before
committing. The same CI route remains available after the owner explicitly
accepts locally observed frontend behavior and asks to land it. For a clean,
current, single-feature-branch update, use
`CODEWIRE_PREFLIGHT_MODE=ci git push ...` to defer the selected exact-tree
qualification to required Forgejo CI. Reuse accepted local evidence; do not
rebuild integration, Kind, or product images locally solely to create or refresh
a push receipt. This mode is unavailable for `main`, tags, deletions, multi-ref
pushes, Tier 3 effects, or work whose acceptance depends on local-only hardware.
It is not a waiver: bind the pushed head once and do not merge until every
required exact-head gate succeeds. The frontend iteration checkpoint still
requires an explicit landing instruction.

Bind a hosted run once and use a transition watcher; never spend turns polling
unchanged CI. Inspect component logs after failure before proposing a mechanism.
Verify how terminal events reach the coordinating session. Starting a watcher
is not proof of notification delivery; record a bounded fallback when the host
has no supported wake interface. Keep observer failure distinct from CI failure.

The watcher owns the passive wait, not the model. Continue independent authorized
work; when only passive gates remain, hand off once and resume only for a watcher
transition, owner input, or the recorded fallback. Never turn a heartbeat,
commentary cadence, or short tool timeout into repeated model turns, one-minute
sleep calls, status narration, or unchanged-state reads. If automatic host
goal continuations keep waking the model and no event-driven wake is available,
report that scheduling mismatch once and ask the owner to pause those
continuations; the watcher and canonical Program remain active. Do not cancel CI,
mark a running gate blocked, or repeatedly end and restart turns to simulate a
pause. Instructions do not themselves provide scheduler enforcement.

Record actual commands, exit status and required test counts. Distinguish full
runs, composed component proof, pending checks and unchanged inherited results.
Reuse evidence only while its relevant source, dependencies/features, fixtures,
toolchain, topology, selector and entrypoint inputs still match. Missing,
interrupted or stale proof is not success; emitting a receipt is not running a
check.

Use only checked-in verification topology. Never add an ad-hoc proxy, relay,
tunnel, port-forward, route, hosts entry, firewall rule, or fixture rewrite to
make a gate pass. Do not bypass a selected gate. Verification-policy changes
must prove old and new behavior with focused fixtures and cannot waive their own
chosen proof.

When the repository owner explicitly commands an OpenSnitch rule for checked-in
local VM verification, the agent must add the narrowest rule that permits it and
record the rule's identity and scope. This permits no broader firewall access or
weakening of the required local hardware gate.

## HTML and frontend

- Never inject disposable diagnostic JavaScript, inline browser probes,
  temporary data attributes, console logging, forced scrolling, or similar
  instrumentation into tracked product templates or editable design fixtures,
  even when the plan is to remove it before handoff. Diagnose from external
  browser or repository-owned test tooling. If that tooling is unavailable,
  use static evidence and existing checks or report the verification gap;
  tracked JavaScript must implement intentional product behavior or a durable
  repository-owned test.
- Use native semantic HTML throughout the product and editable design fixtures.
  Landmarks, headings, sections, navigation, lists, tables, forms, labels,
  links, and buttons must describe their actual purpose. Use a `div` or `span`
  only when no native element conveys meaning and the element is strictly for
  layout or text styling.
- Links navigate; buttons perform actions. Navigation collections and repeated
  rows use lists with list items. Every section has a real heading or an
  accessible name, every form control has a label, and table headers declare
  their scope. Prefer native semantics over recreating them with ARIA.
- A container owns its outside gutter. Repeated controls own one shared inside
  padding through a reusable row primitive. Align related content with that
  common inset instead of per-element margins, negative offsets, transparent
  border compensation, or independent wrappers.
- Keep production templates and editable `packages/codewire-design` fixtures on
  the same tokens, components, and route CSS. A fidelity change is incomplete
  when only the fixture or only the production template changes.
- “UI iteration checkpoint” gates landing, not ordinary local development.
  Edit locally, run focused checks, and rebuild local images or update scoped
  development services as needed to review the real application. Image
  rebuilds do not require separate approval. Do not commit, push, open a PR,
  run hosted CI, or recreate Kind until the owner says “land it.” Preserve
  unrelated state and the existing production and credential boundaries.
- During active iteration use `make design-system`, `make dashboard-watch`, or
  `make dashboard-watch-kind`. Run `scripts/dev/preflight.sh --explain` before
  the final landing gate. If an obviously UI-only change is unclassified or
  selects integration, Kind, or full verification solely because classification
  is missing, repair the classifier or split the unrelated change before
  proceeding.
- Stop the Kind-backed dashboard watcher before Kind verification so its exit
  handler releases repository-managed forwards. Reuse existing visual coverage
  and add only the smallest behavioral or accessibility assertion that protects
  a real regression.

## Repository invariants

- Migrations require compatibility, database proof, and rollback.
- Applied migration bytes are immutable. Upgrade fixtures bind accepted prior
  bytes/checksums, not a historical ledger derived from the edited branch.
  Historical migration files do not imply legacy runtime support.
- Public/generated contracts ship generated clients, wrappers, and tests
  together.
- Search existing users before adding global identifiers; send new packages and
  build inputs to every consumer.
- Never add PAT or SSH deploy-key credentials for the GitHub mirror.
- In product language and public APIs, use `snapshot` only for saved state that
  can be reused or restored. Call child-visible values assembled for one
  process launch an `environment projection`. Call saved running-VM execution
  state a `VM checkpoint`.
- Application secrets and provider credentials are separate product concepts.
  Storing either does not attach it to an environment. Selecting an application
  secret source authorizes ordinary child-visible environment projection under
  the original names; selecting a credential profile authorizes its typed
  proxy, signer, or executor, never raw provider material. Never infer the
  category from a key name or value. Profiles contain provider identities only,
  not secret mappings or exposure policies. Reuse the owning environment
  operation identity; do not create a separate secret generation.
- Provider credential delivery keeps private material outside the sandbox. A
  sandbox may receive endpoints, public trust material, placeholders, and a
  bounded runtime capability, but not a provider credential or general
  secret-read API. Application secrets are intentionally visible to their
  receiving workload and root; do not promise secrecy from those processes.
  Keep resolved launch values out of durable configuration, control events and
  session metadata. Credential non-disclosure is not enforced egress mediation;
  claim the latter only where the placement proves direct provider bypass is
  denied.
