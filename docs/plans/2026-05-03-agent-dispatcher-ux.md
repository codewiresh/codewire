# Agent dispatcher UX — make `cw` first-class for LLM-to-LLM driving

Status: draft, 2026-05-03
Author: noel + dispatcher-claude (from live friction in isol8 codex 297)

## Why

Dispatcher agents (Claude in `~/src/codewire/isol8`) drive worker agents
(codex `app-server` over JSON-RPC) via `cw run` / `cw send` / `cw logs`.
Today the dispatcher has to grep raw event streams and hand-parse status
output to know whether a worker is alive, reasoning, executing, idle,
or done. That works but it's brittle and costly on every cadence tick.

This plan tightens the existing primitives so any LLM (Claude, codex,
Gemini, locally-hosted models, future runtimes) can drive a `cw run`
session through clean structured surfaces without bespoke per-model
parsers.

**LLM-agnostic is a hard constraint.** No codex-specific verbs in core
`cw`. No JSON-RPC envelopes baked into core commands. Anything codex-
specific lives as `contrib/` shell helpers that compose existing
primitives.

## Existing surface (what works today)

Verified 2026-05-03:

- `cw list --json [--local|--runs] [--status running]` — enumerate
  runs structurally. Default in standalone mode is local-running.
- `cw status <name> --json` — full structured status for one run.
- `cw send <name> [input] --no-newline --file <f> --paste` — push
  bytes into a session's stdin (PTY or pipe).
- `cw msg <target> <body> --delivery {auto,inbox,pty,both} --from <s>`
  — agent-to-agent messages, decoupled from PTY stdin.
- `cw inbox <name> --tail N` — read messages delivered to a run.
- `cw listen [--session <s>]` — stream message traffic live.
- `cw logs <name> [-f] [--tail N]` — read or follow saved output.
- `cw watch <name> [--no-history] [--tail] [--timeout]` — stream live
  output.
- `cw kill <name>` — terminate a run.

These cover ~80% of what an LLM dispatcher needs. Gaps are below.

## Confirmed gaps (from this session)

### 1. `cw run` has no non-interactive one-shot mode — **already solved by `cw exec --json`**

Initial drafting friction: `cw run -- cmd` always allocates a PTY,
so a dispatcher tool-call gets only "Session NNN launched" with no
output flowing back. **This is already solved by `cw exec --json`**
(verified 2026-05-03). `cw exec --on <env> --json -- bash -lc 'cmd'`
returns `{exit_code, stdout, stderr}` cleanly. The only remaining
need here is **discoverability**: `docs/llm-ux-notes.md` and
`docs/agent-to-agent.md` should call out `cw exec --json` as the
default for dispatcher one-shots, with `cw run` reserved for
persistent sessions.

No code change for this gap — drop from implementation scope; lift
into Gap E doc work.

### 2. `cw watch` only streams raw bytes

For codex `app-server` the bytes are JSON-RPC events. The dispatcher
wants "show me only turn-lifecycle transitions" or "tail one event
type." Today: pipe `cw logs --tail N` through `grep` / `jq`. That's
fine for humans, expensive for LLMs (every check costs a Bash call
plus parsing).

### 3. `cw status --json` lacks idle / liveness signal

`cw status --json` reports lifecycle (running / completed / killed),
PID, output size, last-output blob. It does NOT report:
- `last_event_at` (when the session last produced output)
- `idle_seconds` (derived; cheap)
- `last_event_summary` (line-bounded preview, not 87KB blob)

A dispatcher that wants "is this stuck" has to fetch the whole 87KB
status, dig through, and decide. A two-line `idle_seconds: 412` would
collapse the tick to one cheap call.

### 4. No structured "agent-state" abstraction

`cw status` is process-state oriented (running / killed / completed).
LLM dispatchers also care about model-specific states — codex emits
`turn/started`, `turn/completed`, `tokenUsage/updated` — but those are
embedded in the JSON-RPC stream. A neutral concept of "session is
active vs idle" (last event within last N seconds) would let any
worker model report liveness without exposing model internals.

This is the LLM-agnostic part: `cw` does NOT need to know what codex
or Claude emit. It only needs to expose `last_event_at` and let the
dispatcher decide what idle means for that worker's protocol.

### 5. `cw msg` between sessions is undocumented for agent-to-agent

`cw msg` already supports inbox / pty / both delivery. The agent-to-
agent pattern (Agent A reads its own inbox, Agent B sends to A) isn't
in the docs as a first-class scenario. `docs/llm-ux-notes.md` covers
single-agent driving; the multi-agent shape needs a sibling doc.

## Output-format flag UX

Today: `cw exec --json` is a boolean. Decision (2026-05-03): standardize
on `-o|--output <format>` mirroring kubectl / aws / gcloud, since `cw`
sits in the same dev-ops tooling space.

- `--output json` — primary, structured for dispatchers.
- `--output text` — human, pretty (current default behavior).
- `-o` — short alias.
- **No back-compat.** `--json` is removed in this change; everywhere
  it appears in code and docs becomes `--output json`. We don't ship
  shims.

Future-room: `--output yaml` and `--output wide` slots open. No need
to implement yet.

## Proposed additions

### A. ~~`cw run --capture`~~ — already covered by `cw exec --json`

Dropped from implementation scope. `cw exec --json` already returns
`{exit_code, stdout, stderr}` and works against `--on <env>` targets.
Action: update docs (Gap E) to make `cw exec --json` the documented
dispatcher pattern.

### B. `cw watch --json [--filter <jq-path>]`

```
cw watch <name> --json --filter '.method'
# emits one JSON object per server-side event, with --filter applying
# a jq-style projection. Works for ANY worker — codex JSON-RPC,
# Claude SSE, raw text — bytes-level events become parseable.
```

For raw text workers: each line of stdout becomes
`{"timestamp": "...", "stream": "stdout", "text": "..."}`.
For workers that already emit JSON (codex app-server): pass-through.

This unblocks LLM-agnostic event filtering without baking model-
specific parsers into core.

### C. `cw status --json` adds liveness fields

```
{
  "name": "codex-297",
  "status": "running",
  ...
  "last_event_at": "2026-05-03T15:24:11Z",
  "idle_seconds": 47,
  "last_event_preview": "first 200 chars of last event, single-line"
}
```

`last_event_preview` replaces the current 87KB last-output dump —
keep the dump available behind `--full` for forensics.

### D. `cw watch --turn-stream` (worker-aware optional helper)

For workers that announce a "turn" abstraction in their event stream,
ship a helper that recognizes it via a small protocol-detection file
(`~/.codewire/protocols/codex.json` mapping events → turn lifecycle).
Each protocol file is plain JSON and ships in `contrib/protocols/`.
LLM-agnostic because there's no special-casing in core — just a
protocol descriptor file the dispatcher can install.

If we don't want to ship protocol files in core, this can live as a
contrib script entirely outside `cw`.

### E. `docs/agent-to-agent.md`

New document covering:
- How an LLM dispatcher launches another LLM via `cw run`
- Reading peer state via `cw status --json`
- Sending input (`cw send` for PTY/stdio, `cw msg` for messages)
- Watching with filters
- Worked example: dispatcher Claude driving codex `app-server`

Calls out LLM-agnostic patterns; codex JSON-RPC envelopes appear in
ONE worked example as a concrete instance, not as the API.

## Non-goals

- No codex-specific verbs in core `cw` (no `cw codex steer`, no
  `cw turn`, no JSON-RPC awareness baked into `cw msg`).
- No assumption that workers expose token-usage / context-window
  signals. If a dispatcher wants those, it parses the worker's events
  itself via `cw watch --json`.
- No new "agent" abstraction in `cw`. A run is a run; agency is in
  the bytes the run emits.

## Acceptance

For the gaps above, "done" looks like:

- A. ~~`cw run --capture`~~ removed — `cw exec --json` already does
  this. Verified 2026-05-03:
  `cw exec --on codewire --json -- bash -lc 'echo hi'` →
  `{"exit_code":0,"stdout":"hi\n","stderr":""}`.
- B. `cw watch <n> --json` emits structured events for any session;
  jq-filter pipeline tested end-to-end against a codex session.
- C. `cw status --json` returns `idle_seconds` and `last_event_preview`;
  dispatcher cadence collapses from "fetch 87KB + grep" to one parse.
- D. Either protocol-descriptor file or contrib script exists for
  codex's turn lifecycle; reference impl runs under
  `contrib/codex-turn-watch.sh`.
- E. `docs/agent-to-agent.md` exists, links from `docs/llms.txt`,
  walks one Claude-drives-codex worked example.

## Estimated effort

- A. ~~`cw run --capture`~~ — done (use `cw exec --json`). 0h.
- B. `cw watch --json [--filter]`: ~4-6h (event-schema definition +
  jq integration; tests).
- C. `cw status --json` liveness: ~2h (event-bus already tracks last
  event; surface in JSON; bound `last_output_snippet` to e.g. 200
  chars by default and put the unbounded blob behind `--full`).
- D. Protocol files + `contrib/codex-turn-watch.sh`: ~2h.
- E. `docs/agent-to-agent.md`: ~2h. **Includes documenting
  `cw exec --json` as the dispatcher one-shot pattern (Gap A
  resolved by docs only).**

Total: 10-12h. Phased: C first (highest cadence-cost relief — fixes
the 87KB-status-blob problem), then E (docs unblock dispatcher
adoption), then B, then D.

## Out-of-scope follow-ups (note for later)

- Multi-worker fan-out from one dispatcher (already mostly works via
  tags; revisit when we have multiple concurrent codex sessions).
- Cross-environment routing (dispatcher in env-A, worker in env-B).
- Token / context-window pressure as a first-class signal in `cw
  status --json` — only if multiple worker protocols converge on a
  shared shape.
