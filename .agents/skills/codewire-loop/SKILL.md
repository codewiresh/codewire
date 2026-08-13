---
name: codewire-loop
description: Persistent Codewire work loop for long-running repo tasks. Use when the user asks to keep going, loop until done, continue without stopping, set a durable goal, schedule wakeups, babysit CI/PRs, or drive a Codewire task through issue tracking, implementation, verification, Forgejo PR, merge, and issue closure. Do not use for quick one-off answers that do not need persistence.
---

# Codewire Loop

Use this skill to keep Codewire work moving until it is complete, genuinely
blocked, or explicitly stopped. Treat it as the Codex-native replacement for a
Claude-style `/loop` command.

## Start The Loop

1. Read the nearest `AGENTS.md` and `CLAUDE.md` before changing files.
2. Identify owning objective, success criteria, repositories, issues or
   PRs, constraints, and stop conditions.
3. For Program, its canonical Forgejo body is the durable objective and live
   control; host-goal state may schedule but cannot alter it. For direct work,
   use a host goal only when explicitly requested; mirror the owning objective,
   never an incidental subtask. Reference longer canonical context.
4. Use a durable Forgejo tracker when repository rules require one, Program is
   selected, a real collision risk needs a canonical claim, or closure depends
   on evidence across sessions. Do not create a tracker merely because normal
   scoped work is non-trivial. Use GitHub only as a public mirror unless local
   repo rules explicitly say otherwise.
5. Work in a focused branch from the Forgejo main branch unless the current repo
   rules or user instructions require a different branch.

## Schedule Wakeups

Prefer Codex app thread automations for scheduling. If the current surface can
create or update thread automations, create one attached to this thread.

Use this heartbeat prompt:

```text
Use $codewire-loop. Inspect the newest user messages, git state, Forgejo
issues/PRs, relevant CI transitions, and any running Codewire sessions. For a
Program, the live Forgejo issue body is the objective; do not treat host-goal
status as control state.
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

Healthy CI is passive exact-head attestation, not heartbeat work. Bind its
workflow, run ID, and head once. When it is the only gate, hand it to `fj
actions runs watch <run-id> --expect-head <sha> -R origin --output ndjson`;
let that observer wait outside the model and wake only on
failure, stall, or success. Do not use recurring turns, `write_stdin`, or
parallel queries for unchanged state. If the host cannot wake the thread,
yield with the run and head and check once near the terminal horizon or a
credible stall. Keep the objective active until the result is handled.

If Codex app automations are unavailable, do not claim scheduling was created.
Instead, give an explicit fallback using Codewire `cw`, cron, systemd, or a
human reminder to resume Codex with the same goal and heartbeat prompt.

## Run Each Iteration

At the start of every turn or wakeup:

1. Re-read the newest user message and let it override older instructions.
2. For a Program, check its live control's dispatchable work before evaluating
   a terminal handoff. Host-goal status is non-authoritative and must not
   suspend the Program. If authorized work is actionable, the Program is not
   blocked by a future gate; continue the smallest useful item.
3. Inspect repo state before edits:
   - `git status --short --branch`
   - relevant Forgejo issue, PR, and Actions state with command-scoped `fj`
   - CI transitions when a failure notification, credible stall, terminal
     horizon, or merge decision makes them relevant
   - active claims in the canonical Program control; inspect branches,
     worktrees, or PRs only when investigating a concrete collision
4. Continue the smallest unblocked step through implementation, validation,
   PR, CI, merge, and issue closure. When a bounded diagnostic identifies a
   repository defect and its source repair remains authorized, retain the
   claim and proceed directly to one cohesive repair. Do not stop after filing
   its issue, reverting an invalid attempt, or producing a receipt. Repair an
   incidental prerequisite only enough to unblock delivery, then return to the
   owning objective instead of promoting it to the host goal or a workstream.
5. Give brief progress updates during long work.

At a material transition or after canonical main advances, compare the bound
instruction revision with current `AGENTS.md`, the invoked `SKILL.md`, and any
routed workflow document. Re-read only instruction files that changed, then
bind the new revision. Do not keep acting from stale loaded instructions or
re-read unchanged files every iteration.

For bounded Rust CLI-only slices that qualify for the fast lane in
`docs/dev/RUST-PORT-PLAYBOOK.md`, treat local CLI gates as the primary loop and
Forgejo CI as the merge gate. Capture the PR run once, poll sparsely, inspect logs
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
   admission or a material transition. A merge or external result earns a
   revision only when it changes a live field. Otherwise work only an already
   dispatched claim and report evidence without changing live state. Replace
   superseded live state at transitions and link completed evidence instead of
   appending action history.
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

- Use Forgejo and `fj` for issues, PRs, merges, Actions, and deploy state.
- Prefer command-scoped `-R origin` or `-C <worktree>` and inspect
  `git remote -v` before assuming a remote.
- Bind CI once with `fj actions runs list` and `fj actions runs view`,
  recording the workflow, run ID, and exact head. Use `fj actions runs watch
  <run-id> --expect-head <sha> -R origin --output ndjson` for the
  transition-only observer. Do not repeatedly print full JSON or
  healthy log tails. On failure, credible stall, empty output, or run/job
  disagreement, start with `fj actions runs logs <run-id> --failed --tail 200`
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
before sending one, reread the objective and live control. For a Program, the
live Forgejo body is authoritative; never check or report host-goal status as a
terminal condition. Name which Stop Condition below holds. If none holds, do
not send a final response: execute the next safe in-scope action.
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
