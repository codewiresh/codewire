# Agent-to-Agent Patterns

Use `cw` as a thin session/runtime layer. A run is just a process with durable
stdin/stdout, saved logs, and optional mailbox traffic. Keep the worker
protocol in the bytes the worker already speaks.

## Default split

- Use `cw exec --output json` for dispatcher one-shots.
- Use `cw run` for persistent workers that need a long-lived session.
- Use `cw status --output json` for cheap liveness checks.
- Use `cw send` for stdin / PTY input.
- Use `cw msg` when you want mailbox-style delivery decoupled from stdin.

## Dispatcher one-shots

When the dispatcher just needs one command result, do not allocate a persistent
session. Use buffered JSON output:

```bash
cw exec --on codewire --output json -- bash -lc 'pwd'
```

Response shape:

```json
{
  "exit_code": 0,
  "stdout": "/workspace\n",
  "stderr": ""
}
```

This is the default pattern for setup, probes, and small repo queries. Reserve
`cw run` for processes you intend to steer over time.

## Persistent worker

Launch the worker once, then drive it through `status`, `send`, `logs`, and
`msg`:

```bash
cw run --name coder -- codex app-server
cw status coder --output json
cw logs coder --tail 20
```

For cheap cadence ticks, prefer:

```bash
cw status coder --output json
```

Phase C status output includes `last_event_at`, `idle_seconds`, and a bounded
`last_event_preview`. Add `--full` when you need the unbounded tail blob for
forensics:

```bash
cw status coder --output json --full
```

## Sending control

Use `cw send` when the worker expects input on stdin / PTY:

```bash
cw send coder '{"jsonrpc":"2.0","id":1,"method":"ping"}' --no-newline
```

Use `cw msg` when one agent wants to leave a message for another without
touching the worker's stdin:

```bash
cw msg coder "Review the auth refactor next."
cw inbox coder --tail 10
```

`cw msg` is the cleaner fit for agent-to-agent coordination. `cw send` is the
cleaner fit for protocol traffic.

## Worked example: Claude dispatches a codex worker

1. Claude uses `cw exec --output json` for one-shot repo checks.
2. Claude launches codex once with `cw run --name coder -- codex app-server`.
3. Claude polls `cw status coder --output json` to decide whether the worker is
   active, idle, or done.
4. Claude injects protocol input with `cw send coder ... --no-newline`.
5. Claude reads output with `cw logs coder --tail 50` or `cw watch coder`.
6. Claude uses `cw msg coder ...` for higher-level instructions that should not
   be mixed into protocol stdin.

This stays LLM-agnostic. Nothing in `cw` needs to know that codex is speaking
JSON-RPC or that Claude is the dispatcher.
