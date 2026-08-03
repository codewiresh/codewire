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
4. If no issue tracks non-trivial work, create or identify a Gitea issue before
   implementation. Use GitHub only as a public mirror unless local repo rules
   explicitly say otherwise.
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

If Codex app automations are unavailable, do not claim scheduling was created.
Instead, give an explicit fallback using Codewire `cw`, cron, systemd, or a
human reminder to resume Codex with the same goal and heartbeat prompt.

## Run Each Iteration

At the start of every turn or wakeup:

1. Re-read the newest user message and let it override older instructions.
2. Check the active goal and decide whether it is complete, blocked, or still
   actionable.
3. Inspect repo state before edits:
   - `git status --short --branch`
   - relevant Gitea issue/PR state with command-scoped `tea` flags
   - CI transitions when a failure notification, credible stall, terminal
     horizon, or merge decision makes them relevant
   - active program-coordinate claims in issues, branches, worktrees, and PRs
4. Continue the smallest unblocked step through implementation, validation,
   PR, CI, merge, and issue closure.
5. Give brief progress updates during long work.

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
or an unresolved ambiguity that cannot be discovered locally.

## Coordinate Parallel Work

When a live `ACTIVE` ProgramControl opts into the repository's bounded-parallel
admission envelope:

1. Use the direct owner decision and canonical Gitea issue/comment receipt as
   the admission record. Confirm that it names the coordinate, claimant
   branch/worktree/PR, prerequisites, exclusive paths, shared surfaces, gates,
   forbidden work, and merge order.
2. Check open issues, branches, worktrees, and PRs before editing. One session
   claims one coordinate and one PR. Never open a competing PR for a coordinate
   that another session already owns.
3. Let disjoint admitted WIs edit, commit, push, review, and run CI
   concurrently. Do not tell an entire session to stop merely because another
   coordinate is active; redirect it only when it collides with an existing
   claim or lacks admission.
4. Serialize main merges and shared/external mutations. Immediately before
   each push or merge, reconcile all active claims, the exact current main
   revision, and the declared merge order. Rebase or otherwise reconcile the
   next PR and rerun its exact-head gates after an earlier merge.
5. If new evidence affects only one WI, mark that WI or its overlapping
   coordinates `UNSATISFIED` and keep independent admitted WIs moving. Use a
   program-wide `STOPPED_FOR_REPLAN` only when a program-level field named by
   `AGENTS.md` is materially invalidated.

The envelope does not make workflows, lockfiles, generated output, schemas,
deployments, publications, releases, credentials, or live state implicitly
independent and does not grant authority for those actions.

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

## Stop Conditions

Stop the loop only when one of these is true:

- The goal is complete and evidence is recorded.
- The same blocker has repeated after real attempts to make progress, and
  further work needs user input or an external state change.
- The user explicitly pauses, stops, or changes the goal.
- Continuing would require destructive or high-risk action that lacks explicit
  authorization.

When stopping, report the current goal status, branch/PR/issue state, completed
evidence, and the exact next unblock step.
