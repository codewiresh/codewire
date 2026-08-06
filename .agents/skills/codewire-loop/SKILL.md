---
name: codewire-loop
description: Persistent Codewire work loop for long-running repo tasks. Use when the user asks to keep going, loop until done, continue without stopping, set a durable goal, schedule wakeups, babysit CI/PRs, or drive a Codewire task through issue tracking, implementation, verification, Gitea PR, merge, and issue closure. Do not use for quick one-off answers that do not need persistence.
---

# Codewire Loop

Use this skill to keep Codewire work moving until it is complete, genuinely
blocked, or explicitly stopped. Treat it as the Codex-native replacement for a
Claude-style `/loop` command.

## Start The Loop

1. Read the nearest `AGENTS.md` and `CLAUDE.md` before changing files.
2. Convert the user's request into a concrete goal:
   - objective
   - success criteria
   - repo(s), issue(s), branch/PR, and constraints
   - stop conditions
3. If a goal tool or `/goal` surface is available, set or update the active
   goal. Keep the goal under 4,000 characters; put long context in a doc or
   Gitea issue and reference it.
4. Use a durable Gitea tracker when repository rules require one, Program is
   selected, a real collision risk needs a canonical claim, or closure depends
   on evidence across sessions. Do not create a tracker merely because normal
   scoped work is non-trivial. Use GitHub only as a public mirror unless local
   repo rules explicitly say otherwise.
5. Work in a focused branch from the Gitea main branch unless the current repo
   rules or user instructions require a different branch.

## Schedule Wakeups

Prefer Codex app thread automations for scheduling. If the current surface can
create or update thread automations, create one attached to this thread.

Use this heartbeat prompt:

```text
Use $codewire-loop. Inspect the active goal, newest user messages, git state,
Gitea issues/PRs, relevant CI transitions, and any running Codewire sessions.
Continue the next unblocked step. Do not stop merely because one turn ended.
Do not wake solely to re-read an unchanged healthy CI run. Report only when the
goal is complete, genuinely blocked, or a user decision is required. If
complete, summarize evidence and stop the automation.
An eventual authority gate is not a blocker while authorized dispatchable work
remains.
```

Default cadence:

- Active implementation with an actionable next step: every 10 minutes.
- Slow infra, provisioning, or external dependency work: every 30 minutes.

Healthy CI is a passive exact-head attestation, not heartbeat work. Capture the
workflow, run ID, and head SHA once. If CI is the only remaining gate, hand it
to `tea actions runs watch <run-id> --expect-head <sha> --login noel --remote
gitea --output ndjson`, a transition-only observer that waits outside the model
and wakes the thread on failure, stall, or success. Keep the goal active until
that terminal result is handled; reducing token use must never abandon the gate.
When the watcher is unavailable, retain responsibility with sparse checks near
the expected terminal horizon. Never use periodic model automation merely to
narrate unchanged CI state.

Starting that watcher is one model action. Once it yields a terminal session,
do not use recurring model turns to call `write_stdin`, poll the session, or run
parallel status queries merely to discover unchanged state. Let the watcher own
the wait and resume on its output or process exit. If the host cannot wake the
thread from watcher output, yield with the bound run ID and head; resume only on
an external or user wake, at the expected terminal horizon, or for a credible
stall. One read at such a trigger is enough unless it reveals a new actionable
transition.

If Codex app automations are unavailable, do not claim scheduling was created.
Instead, give an explicit fallback using Codewire `cw`, cron, systemd, or a
human reminder to resume Codex with the same goal and heartbeat prompt.

## Run Each Iteration

At the start of every turn or wakeup:

1. Re-read the newest user message and let it override older instructions.
2. Check the active goal and live control's dispatchable work before evaluating
   the terminal goal. If authorized work is actionable, the Program is not
   blocked by a future gate; continue the smallest useful item.
3. Inspect repo state before edits:
   - `git status --short --branch`
   - relevant Gitea issue/PR state with command-scoped `tea` flags
   - CI transitions when a failure notification, credible stall, terminal
     horizon, or merge decision makes them relevant
   - active claims in the canonical Program control; inspect branches,
     worktrees, or PRs only when investigating a concrete collision
4. Continue the smallest unblocked step through implementation, validation,
   PR, CI, merge, and issue closure.
5. Give brief progress updates during long work.

At a material transition or after canonical main advances, compare the bound
instruction revision with current `AGENTS.md`, the invoked `SKILL.md`, and any
routed workflow document. Re-read only instruction files that changed, then
bind the new revision. Do not keep acting from stale loaded instructions or
re-read unchanged files every iteration.

For bounded Rust CLI-only slices that qualify for the fast lane in
`docs/dev/RUST-PORT-PLAYBOOK.md`, treat local CLI gates as the primary loop and
Gitea CI as the merge gate. Capture the PR run once, poll sparsely, inspect logs
only on failure/cancel/timeout/stall or run/job disagreement, and keep working
on the next independent CLI branch while healthy CI is in progress. If the
change touches workflows, dependencies, lockfiles, deploy/images, server routes,
or live runtime mesh/gateway/daemon behavior, stop using the fast lane and run
the normal verification ladder.

Do not ask "should I continue?" while the goal is actionable. Ask only for a
decision that materially changes scope, risk, credentials, production impact,
or an unresolved ambiguity that cannot be discovered locally. Request external
authority only when the exact operation is ready, immediate, and all authorized
useful work is exhausted. Classify automatic consequences first, and never
batch later operations whose prerequisites remain unsatisfied.

## Coordinate Program Work

When a live Program is `ACTIVE`:

1. Read its canonical live control and revision. Only mutation claims listed
   there are claims. Comments, branches, worktrees, and PRs may provide evidence
   of a collision, but they never admit or authorize work.
2. If this is the named coordinating session, update the live control only at
   admission, material transition, merge, or external mutation. Otherwise work
   only an already dispatched claim and report evidence without changing live
   state. Replace superseded live state at transitions and link completed
   evidence from comments or child issues instead of appending action history.
3. Make readiness relative to the next proposed mutation. Reuse accepted issue
   evidence and inspect only unresolved facts capable of changing that
   mutation's design, ownership, rollback, verification, or acceptance. Defer
   later repositories and environments unless the next mutation consumes them.
4. Bind a claim once. Routine implementation, repair, rebase, push, review, and
   CI inherit it while admission remains unchanged. Several claims may proceed
   only when the live control proves independence; shared or external mutations
   remain serialized unless a narrower boundary is proven and authorized.
5. A concrete collision freezes only overlapping work. Keep independent
   dispatchable work moving, and use `STOPPED_FOR_REPLAN` only when a
   program-level field named by `AGENTS.md` is materially invalidated.

## Codewire Defaults

- Use Gitea and `tea` for issues, PRs, merges, CI, and deploy state.
- Prefer `tea ... --login noel --remote gitea --output yaml` or JSON in the
  Codewire repo; adjust the remote name only after inspecting `git remote -v`.
- Bind CI once with `tea actions runs list` and `tea actions runs view`,
  recording the workflow, run ID, and exact head. Use `tea actions runs watch
  <run-id> --expect-head <sha> --login noel --remote gitea --output ndjson` for
  the transition-only observer. Do not repeatedly print full YAML/JSON or
  healthy log tails. On failure, credible stall, empty output, or run/job
  disagreement, start with `tea actions runs logs <run-id> --failed --tail 200`
  and inspect a specific affected job only if necessary.
- Retry a runner-owned failure once on the same SHA without changing source.
  If it repeats, record an infrastructure finding instead of entering a retry
  or observation loop.
- Close issues with evidence when their acceptance criteria are met.
- Do not add AI attribution to commits, PRs, issues, or docs.
- Preserve unrelated user changes in dirty worktrees.
- If work crosses sibling repos, read each repo's local instructions before
  acting there.

## Final-Response Gate

A final response is a terminal handoff, not a progress update. Immediately
before sending one, reread the objective and live control and check the active
goal when goal tooling is available. Name which Stop Condition below holds. If
none holds, do not send a final response: execute the next safe in-scope action.
A user question, criticism, correction, or status request does not suspend the
objective unless it explicitly pauses, stops, or changes scope; answer it in
commentary and continue in the same turn. Never end by promising to resume—take
the next action first.

## Stop Conditions

Stop the loop only when one of these is true:

- The goal is complete and evidence is recorded.
- The same blocker has repeated after real attempts to make progress, and
  further work needs user input or an external state change.
- The user explicitly pauses, stops, or changes the goal.
- The immediate next useful action requires destructive or high-risk authority,
  all authorized dispatchable work is exhausted, and no prerequisite work can
  proceed. Eventual gated operations do not satisfy this stop condition.

A clean worktree, no valid commit yet, or a reverted attempt is not a stop
condition. Intermediate requests such as `push` or `open the PR` do not narrow
an already-authorized landing objective unless the user explicitly requests a
checkpoint.

When stopping, report the current goal status, branch/PR/issue state, completed
evidence, and the exact next unblock step.
