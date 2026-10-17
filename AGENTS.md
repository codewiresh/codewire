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

Checked-in local development tooling, such as `make kind-credentials-real`, may load the
owner's development credentials from OpenBao into the local Kind cluster
without asking, provided the values flow only through pipes into Kubernetes
Secrets and are never printed, logged, written to disk, or held by the agent.
Never ask the owner to paste a secret or place one in a file. Reading,
exporting, or displaying a secret value still needs explicit authority.

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

## Done means observed working

A change that affects anything a user or operator can see or do is not done
until it has run in the product and been observed working. Tests, checks, and
CI are necessary evidence; they are never proof of behavior.

- Start every product session on the retained local Kind cluster
  (`make kind-status`, then `make kind-watch`; see `docs/dev/AGENT-WORKFLOW.md`)
  and confirm http://localhost:4174/ loads before editing. A broken local
  cluster is the first blocker, not a later gate.
- Before pushing a user-visible change, walk its acceptance journey where it
  runs: dashboard and platform changes on the retained local Kind cluster through
  the owner URL, CLI and host changes with a built `cw` on the host. Include the
  empty, failure, and recovery states it touches. Record what was run and what
  was observed.
- Every workstream and handoff names a mandatory local acceptance journey. If
  it depends on tooling that does not exist yet, that tooling lands first; a
  journey is never "optional if available".
- When a real provider step needs the owner, such as a GitHub authorization,
  prepare everything else first and ask once for exactly that step.
- Until the journey has run, report the change as "not yet observed working".

## Local development loop

Iterate on one retained local Kind cluster; commands live in
`docs/dev/AGENT-WORKFLOW.md`.

- Never recreate the cluster to test a change. Create it once (`make kind-up`,
  or keep the gate's cluster), then deploy changed services into it
  (`make kind-deploy`) and serve UI from source (`make kind-watch`).
- Run only the Kind suites a change needs (`make kind-test`). It maps the
  repository classifier's selection to retained suites, deploys only the
  services whose source differs from what the cluster runs, and removes what a
  failed suite created. If a narrow change asks for the full gate only because
  a mapping is missing, add the mapping and its suite instead of running the
  full gate.
- The full `make e2e-kind` is not a landing gate. Land on the merge rule in
  "Delivery and verification"; a CLI change needs no Kind run unless it changes
  a platform or dashboard path. Run the full gate only when the owner asks,
  never as an iteration step, and never twice for an unchanged tree.
- Switch the credential-service to `real` only for journeys that need a real
  provider; the synthetic fixture remains the gate's default.

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
committing a credible candidate. Then push it, and complete the merge rule's
checks once for the exact tree before merge, reusing valid evidence. Each PR
states one bounded
outcome, its dependencies, affected contracts, and acceptance; keep generated
contracts and their consumers atomic. Update Program control at admissions and
material transitions, with evidence labeled accurately. Parallelize read-only
audits and disjoint edits, with one owner for each mutation surface. If review
invalidates a trust boundary, remove or defer that slice before spending the
expensive gate. Keep the main checkout clean, investigate unexpected dirt before
changing it, and reconcile `origin/main` immediately before landing.

## Plans

Plans, proposals, handoffs, goals and design history live in the sibling
`codewire/private-docs` repository, checked out at `../private-docs`
(`/home/user/src/codewire/private-docs` on the owner workstation), not in
this repository. Write new plans there as `YYYY-MM-DD-<slug>.md`, commit and
push them to its `main`, and link them from issues by path. Stable,
shipped-behavior documentation stays under `docs/`.

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

Use the smallest check that can catch the affected failure class, plus the
product journey that "Done means observed working" requires. Local checks
are the development loop.

A push is never a long gate. The pre-push hook runs only the fast push check:
formatting, lints and unit tests for the changed crates, and quick checks for
the changed file types. Do not bypass the hook.

Each pull request merges alone. Never bundle pull requests into a train or an
integration branch: one failure then hides in several changes. Bring the branch
up to date with `main`, which branch protection requires, and merge on:

- the focused checks the change needs. `scripts/dev/preflight.sh --for-merge`
  runs the families the selection names, in parallel, with the same scripts as
  CI on the shared compiler cache. Use it when a change crosses crates or
  contracts; the changed crates' tests and lints are enough when it does not;
- its product journey;
- for a change to credential, broker, bridge or relay code, a green
  `make kind-test SUITES=credentials` on the retained cluster.

When `main` moves after a check passed, bring the branch up to date again and
reuse the result if the new commits touch none of the change's inputs. Rerun
only what overlaps.

Hosted CI confirms after merge; it is not a merge gate. The exception is a
hosted-only claim (such as scheduling, credentials, permissions, cache, or
timing) that lacks equivalent accepted exact local/read-only evidence. Every
`main` run finishes: never cancel one by hand, and fix forward when it fails.
Pull-request CI runs only the quick checks (selection, policy, compiling every
Rust target); `main` runs the full verification after merge. Label the pull
request `ci-full` to run that full verification, Kind included, on the pull
request when such a hosted-only claim needs it.

Local and hosted policy checks share one checked-in core. Never maintain a
separate local subset; preserve capability-selected expensive checks. A failing
guard must fail qualification and prevent successful receipt emission.

Do not run the same exact-tree qualification twice. Reuse a valid receipt or an
already-running owner. If an obviously narrow path selects the full product or
Kind suite only because classification is missing, repair the classifier and
its fixtures; do not use an expensive unrelated suite as the classifier. An
unknown result blocks the affected mutation, not unrelated work.

For a clean, current, single-feature-branch update whose checks already ran,
`CODEWIRE_PREFLIGHT_MODE=ci git push ...` skips the local push check and leaves
the rest to hosted CI. Reuse accepted local evidence; do not rebuild
integration, Kind, or product images locally solely to create or refresh a push
receipt. This mode is unavailable for `main`, tags, deletions, multi-ref
pushes, Tier 3 effects, or work whose acceptance depends on local-only hardware.
It is not a waiver of the merge rule, and CI never substitutes for the local
product journey. The frontend iteration checkpoint still requires an explicit
landing instruction.

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
- During active iteration use `make kind-watch` against the retained local
  cluster; use `make design-system` only for fixture-only work. Run `scripts/dev/preflight.sh --explain` before
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
- Local and Kind databases are disposable. Deploying to them applies new
  migrations; a migration is never a reason to skip a local or Kind run. To
  reset one, recreate it and rerun every migration (plus the checked-in
  fixtures). A backup before upgrading a retained cluster is a convenience, not
  a gate. Hosted Dev and Production data are not disposable: they move only
  forward through the reviewed migration path.
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
  proxy, signer, or executor, never raw provider material except the listed
  direct delivery exceptions. Never infer the category from a key name or
  value. Profiles contain provider identities only, not secret mappings or
  exposure policies. Reuse the owning environment operation identity; do not
  create a separate secret generation.
- Provider credential delivery keeps private material outside the sandbox. A
  sandbox may receive endpoints, public trust material, placeholders, and a
  bounded runtime capability, but not a provider credential or general
  secret-read API, except a listed direct delivery exception. Application
  secrets are intentionally visible to their receiving workload and root; do
  not promise secrecy from those processes. Keep resolved launch values out of
  durable configuration, control events and session metadata. Credential
  non-disclosure is not enforced egress mediation; claim the latter only where
  the placement proves direct provider bypass is denied.
- Direct delivery of provider material into a sandbox is allowed only where the
  proxy cannot work, with owner approval, listed with its reason in
  docs/dev/SECRETS-AND-CREDENTIALS.md "Direct delivery exceptions" and cited at
  the delivering code. The only exceptions are the environment creator's own
  personal sign-ins for Codex and Claude Code, in a hosted Sandbox and in the
  creator's own local VM: the Codex ChatGPT access token and ID token, written
  as Codex's `auth.json`, and the Claude access token, written as Claude
  Code's `~/.claude/.credentials.json` (`claudeAiOauth`), each with a
  non-empty placeholder refresh token, because each agent enables `/usage` and
  its plan and account features only with its own login. The Claude token
  carries exactly the six scopes Claude Code's own login has (`user:inference`,
  `user:profile`, `user:sessions:claude_code`, `user:mcp_servers`,
  `user:file_upload`, `user:plugins`) and never a scope beyond them; the owner
  accepted that on 2026-10-14 so Claude Code in a Sandbox behaves like their
  own login. Refresh tokens, API keys, Claude setup tokens, GitHub and SSH
  material and organization-owned credentials are never delivered. A delivered
  token is a bearer token for the creator's account, usable from anywhere, and
  stays valid at the provider until it expires (about 8 hours for Claude); every
  process in the Sandbox or VM, and anyone who can open its terminal, can read
  it, and a stopped local VM keeps it on its state disk until its next boot's
  check removes it or it expires.
- A hosted platform broker bridge epoch may reuse one authority decision (its
  runtime session and derived grants, never material) for at most 60 seconds,
  and releases nothing under an older one. Only epoch admission creates it, and
  a lease evaluates it again inline, one evaluation at a time. Every lease of a
  granted slot rereads its credential's record by id and owner, and evaluates
  again at once when that record is missing, inactive or of another revocation
  generation than its grant. A refused slot is answered from the decision unless
  its withheld credential is usable again or the GitHub connection it follows
  changed. So a credential change applies to the next request, and a membership,
  organization, environment, binding, personal-credential confirmation or Pod
  lineage change within 60 seconds. Decrypted provider material may be reused
  only within one bridge epoch (hosted or owner-local delegation), for at most
  two minutes, for exactly the record that lease admitted. Codex and Claude
  login delivery, owner-local delegation leases, SSH signing, OAuth refresh
  admission and keep-alive, and environment projection keep full per-call
  authority checks.
  SSH signing, OAuth keep-alive refresh and direct delivery never reuse
  material; an on-demand OAuth refresh uses the request's own lease, whose exact
  generation refresh admission rechecks. Do not add a process-wide or persistent
  material or decision cache.
