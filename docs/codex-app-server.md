# Driving codex via cw + JSON-RPC

How to run an autonomous Codex session under `cw exec --name` and send it
mid-flight redirects, using `cw msg` / `cw send` and codex's
`app-server` JSON-RPC protocol.

---

## TL;DR

```bash
# Start codex as a JSON-RPC server, named so it's addressable.
cw exec --name codex-256 -- codex app-server

# Initialize + start a thread + start a turn.
echo '{"jsonrpc":"2.0","id":1,"method":"initialize",
       "params":{"clientInfo":{"name":"dispatcher","version":"0.1"}}}' \
  | cw send codex-256 --stdin --no-newline

echo '{"jsonrpc":"2.0","id":2,"method":"thread/start",
       "params":{"cwd":"/home/noel/src/codewire/isol8"}}' \
  | cw send codex-256 --stdin --no-newline

# Read the response to get threadId.
cw logs codex-256 --tail 50
# -> {"id":2,"result":{"thread":{"id":"019de...","..."}}}

# Start the actual work.
echo '{"jsonrpc":"2.0","id":3,"method":"turn/start",
       "params":{"threadId":"019de...","input":[{"type":"text","text":"<brief>"}]}}' \
  | cw send codex-256 --stdin --no-newline

# Mid-flight redirect. Track turnId from `turn/started` notifications.
echo '{"jsonrpc":"2.0","id":4,"method":"turn/steer",
       "params":{"threadId":"019de...","expectedTurnId":"019df...",
                 "input":[{"type":"text","text":"actually use dev only"}]}}' \
  | cw send codex-256 --stdin --no-newline
```

That is the entire architecture. No wrapper, no extra binary. `cw`
stays generic; `codex` stays generic; the dispatching agent is the
JSON-RPC client.

---

## Why this and not `cw msg`

`cw msg <session> <body>` injects bytes into a session's PTY
stdin. That works when the receiving program is reading raw
keyboard input (a TUI, a shell). For codex, the right channel is
its JSON-RPC `app-server`, because:

- `codex exec` (non-interactive) consumes stdin once at startup and
  never re-reads. PTY injection after startup goes nowhere.
- `codex` (interactive TUI) reads stdin but its TUI input handler
  panics on certain pasted multi-line content (upstream issue
  [openai/codex#20587](https://github.com/openai/codex/issues/20587)).
- `codex app-server` exposes `turn/start`, `turn/steer`,
  `turn/interrupt` over line-delimited JSON-RPC on stdio. That
  protocol is designed exactly for "drive codex from a script."

`cw send` is the right `cw` verb to use because we're delivering
bytes verbatim (no header wrapper, no bracketed-paste markers), and
codex's app-server expects exactly that.

---

## Useful methods

The full protocol is in codex's `app-server generate-json-schema`
output. The methods worth knowing:

| Method            | Purpose                                                |
|-------------------|--------------------------------------------------------|
| `initialize`      | Handshake. Required before anything else.              |
| `thread/start`    | Begin a new thread (session). Returns `threadId`.      |
| `thread/resume`   | Resume a previously-archived thread.                   |
| `turn/start`      | Run a turn (one execution) with given input.           |
| `turn/steer`      | Inject new user input into the active turn mid-flight. |
| `turn/interrupt`  | Cancel the active turn.                                |
| `turn/list`       | List turns in a thread.                                |

All return `{"id":<n>,"result":{...}}` or notify with
`{"method":"turn/started", "params":{...}}` etc.

---

## Tracking turnId

`turn/steer` requires `expectedTurnId`. Get it from the
`turn/started` notification that codex emits after `turn/start`:

```bash
cw logs codex-256 --tail 200 \
  | jq -c 'select(.method == "turn/started") | .params.turnId' \
  | tail -1
```

A naive script:

```bash
TURN_ID=$(cw logs codex-256 --tail 500 \
  | jq -c -r 'select(.method == "turn/started") | .params.turnId' \
  | tail -1)
echo "{\"jsonrpc\":\"2.0\",\"id\":99,\"method\":\"turn/steer\",
       \"params\":{\"threadId\":\"$THREAD_ID\",
                   \"expectedTurnId\":\"$TURN_ID\",
                   \"input\":[{\"type\":\"text\",\"text\":\"$BODY\"}]}}" \
  | cw send codex-256 --stdin --no-newline
```

`turn/steer` will fail with a precondition-mismatch error if the
turn already moved on (completed, failed, or been replaced). That
is intentional — it's how the protocol prevents a stale steer from
clobbering a new turn.

---

## When to use `cw msg` vs this

- `cw msg <session> <body>` -- delivers via PTY. Use when the
  receiving program reads stdin as keyboard/paste input. Bracketed-
  paste delivery is automatic. Examples: a bash shell, claude TUI,
  an interactive REPL.
- `cw send <session> --stdin` + JSON-RPC -- use for codex
  app-server. Use also for any other program that has its own stdio
  protocol (MCP servers, language servers, etc.).

---

## TUI capability shim

`cw exec --name` allocates a bare PTY without a terminal emulator behind
it. TUIs (codex's TUI mode, claude code) emit terminal-capability
queries (`\x1b[6n` cursor-position, `\x1b[c` device-attributes,
OSC 10/11/12 color queries) at startup and block waiting for
replies.

cw's session layer auto-responds to those queries with canned
answers so the child program unblocks. This applies to ANY child,
not just codex. It is on by default; opt out with
`CW_NO_TTY_QUERIES=1`.

For codex specifically, you don't need this if you're using
`codex app-server` (no TUI), but it's harmless either way.

---

## Lifecycle hygiene

- Stop the session when done: `cw stop codex-256` or send
  `turn/interrupt` then close stdin.
- `cw list` shows all running sessions.
- `cw status codex-256` shows lifecycle state.
- The cw daemon (`cw node`) persists session metadata across
  daemon restarts; sessions survive node restarts.

---

## Related upstream issues

- [openai/codex#20587](https://github.com/openai/codex/issues/20587)
  -- TUI panics in `tui/src/wrapping.rs:52` on stdin-injected
  bracketed-paste content. Workaround for cw users: use
  `codex app-server`, not the TUI.
