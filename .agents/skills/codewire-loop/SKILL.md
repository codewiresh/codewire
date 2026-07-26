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
Gitea issues/PRs, CI status, and any running Codewire sessions. Continue the
next unblocked step. Do not stop merely because one turn ended. Report only
when the goal is complete, genuinely blocked, or a user decision is required.
If complete, summarize evidence and stop the automation.
```

Default cadence:

- Active implementation or CI babysitting: every 10 minutes.
- Slow infra, provisioning, or external dependency work: every 30 minutes.

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
   - CI runs and failing logs when a PR or merge run exists
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

## Codewire Defaults

- Use Gitea and `tea` for issues, PRs, merges, CI, and deploy state.
- Prefer `tea ... --login noel --remote gitea --output yaml` or JSON in the
  Codewire repo; adjust the remote name only after inspecting `git remote -v`.
- Poll CI with `tea actions runs list`, `tea actions runs view`, and
  `tea actions runs logs`; inspect logs on failures. For CLI-only fast-lane
  slices, do not stream logs for healthy in-progress runs.
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
