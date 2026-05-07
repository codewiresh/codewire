# LLM UX Notes — Codewire

First-person notes from actually using Codewire as an LLM (via CLI, 2026-02-20).
Written to inform what docs need to exist and what traps to call out.

---

## What Was Smooth

**Dispatcher one-shots should use `cw exec --output json`.** This is the clean
non-interactive pattern for "run a command and give me structured stdout/stderr
back". It avoids allocating a session just to ask one question.

```bash
cw exec --on codewire --output json -- bash -lc 'echo hi'
```

This should be the documented default for dispatcher probes and setup work.
`cw run` is the right tool only when the dispatcher intends to keep a worker
alive and steer it over time.

**Core loop is frictionless.** `cw launch -- <command>` → `cw wait <id>` → `cw logs <id>` works
exactly as you'd expect. The session ID is the stable handle — every command takes it.

**Error messages are helpful.** "session 9999 not found / Use 'cw list' to see active sessions"
is exactly the right hint. Doesn't leave you guessing.

**Tags make fan-out clean.** Launching multiple sessions with `--tag foo` then `cw wait --tag foo`
is genuinely elegant. Once you know about tags, the multi-agent pattern is one conceptual step.

**`cw send` works cleanly for interactive sessions.** Launched a bash shell, sent a command
without attaching, read the output with `cw logs`. No TTY weirdness, no pipes needed.

**`cw status` output is informative.** Shows working dir, PID, exit code, output size — all the
things you'd reach for when debugging why a session behaved unexpectedly. For dispatcher loops,
`cw status --output json` is the cheap structured check to prefer over scraping large log blobs.

---

## What Was Confusing or Missing

### 1. `launch` is an alias, `run` is the canonical command

`cw --help` lists `run`, not `launch`. An LLM reading the help output will reach for `cw run`.
Docs and examples use `cw launch` (the alias). These both work but the inconsistency is a
papercut — documentation should pick one and stick with it. `launch` reads more naturally for
"start a new agent session", so docs should feature it prominently.

### 2. The `--` separator is easy to forget and the error is opaque

```
$ cw launch -- bash -c 'echo hi'   # works
$ cw launch bash -c 'echo hi'      # Error: unknown shorthand flag: 'c' in -c
```

The error message "unknown shorthand flag: 'c' in -c" doesn't hint at the missing `--`. An LLM
(or human) will be confused — `bash` clearly doesn't have flags, why is `cw` parsing `-c`?
The fix: add a note in the error ("Did you forget `--` before the command?").

### 3. `watch` vs `logs -f` — two commands for "see output"

`cw watch <id>` — streams live output while session runs, exits when session completes.
`cw logs <id>` — reads accumulated output after the fact (also `logs -f` for follow mode).

An LLM's instinct: "I want to see output → use `logs`." That works. But `watch` is the right
tool when the session is still running, since it connects to the live broadcast stream.
The distinction isn't obvious from the help text alone.

### 4. MCP server does NOT auto-start a node

All CLI commands auto-start the node if it isn't running. The MCP server does not — it
connects to the existing socket. If an LLM tells a user to add the MCP server without first
explaining the node, sessions will fail with a connection error. This is the #1 footgun for
MCP onboarding.

### 5. `cw list` shows ALL sessions including old completed/killed ones

After a few sessions, `cw list` returns a lot of noise. There's no default "show only running"
view. An LLM scanning for a session will have to parse through history. The `status_filter`
parameter on the MCP tool (`"running"`) solves this, but CLI needs `--status` filtering too
(or the docs should say `cw list | grep running`).

### 6. Positional name vs `--name` flag

`cw run <name> -- command` vs `cw run --name <name> -- command` — both work. The `[name]`
positional isn't clearly called out in common examples. LLMs will reach for `--name` which
is fine, but it's worth knowing the shorthand exists.

### 7. Tags are repeatable but docs don't emphasize it

`--tag` can be specified multiple times: `cw launch --tag worker --tag batch-42 -- cmd`. An
LLM would reasonably assume `--tag worker,batch-42` works (it doesn't — comma-separated not
supported for tags in the CLI). Needs a clear example.

### 8. No obvious `cw ps` or "show running sessions only" shortcut

LLM instinct after launching: "how do I check if it's still running?" → reach for `cw ps`
or `cw status`. The actual command is `cw list` (all sessions) or `cw status <id>` (one
session). `cw list` with 20 old sessions is noisy. A quick `cw list --status running` would
be a quality-of-life improvement.

### 9. Dispatcher docs should separate one-shot vs persistent patterns

There are two distinct workflows:

- `cw exec --output json` for one-shot commands where the dispatcher needs a
  structured result immediately
- `cw run` + `cw status` + `cw send` + `cw logs` / `cw watch` for persistent
  worker sessions

Mixing them together makes `cw run` look like the answer to every problem,
which is wrong. The docs should present `exec --output json` as the default
dispatcher tool and `run` as the long-lived worker primitive.

---

## LLM Instinct vs Codewire Idiom

| LLM instinct | Codewire idiom | Notes |
|---|---|---|
| `cw ps` | `cw list` | — |
| `cw run cmd` | `cw run -- cmd` | `--` required |
| poll loop to wait | `cw wait <id>` | Never poll |
| for-each kill sessions | `cw kill --tag foo` | Tags are the right abstraction |
| pipe stdout to file | `cw logs <id> > file` | Logs are persisted server-side |
| re-attach to check output | `cw logs <id>` | Don't attach just to read output |
| `cw stop <id>` | `cw kill <id>` | Command is `kill`, not `stop` |

---

## Gaps in Discoverability

- **No `--help` summary mentions detach chord.** Ctrl+B d is the only way to detach from an
  attached session without killing it. This is not in `cw attach --help` or `cw --help`. A
  new user who attaches will have no idea how to get back to their shell without Ctrl+C (which
  kills the session).

- **MCP registration instruction should be in `cw --help`.** `cw mcp-server` is listed but
  the one-liner to register it (`claude mcp add --scope user codewire -- cw mcp-server`) is
  only discoverable if you read the docs. Add it to the `mcp-server` subcommand help.

- **`cw node` vs auto-start.** Most commands auto-start the node. But `cw node -d` is needed
  for the daemon mode that survives your terminal closing. The relationship isn't documented in
  the help text — you have to find it in the docs.

---

## Summary

Codewire's core primitives are well-designed and mostly intuitive. The dispatcher-facing docs
should now lead with `cw exec --output json` for one-shots and treat `cw run` as the persistent
worker path. The remaining friction points are: (1) the `--` separator that's easy to forget,
(2) the `run`/`launch` naming inconsistency, (3) the MCP node-not-auto-started footgun, and
(4) the `watch` vs `logs` distinction. These should be addressed in LLM-facing docs by being
explicit about them upfront.
