# CLI verb restructure: collapse run into exec via cw node auto-routing

## Goal

Reduce the CLI verb surface to two primitives by making `cw exec` the single
entry point for "run a command on a target" and `cw shell` the single entry
point for "interactive PTY on a target." Persistence, naming, and attachability
become capabilities of `cw exec` that scale with whether `cw node` is running.

No public commitments to break — this is the moment for a ruthless cleanup.

## Final verb shape

```
cw exec [target] -- <cmd>          # one verb for "run a command"
cw exec ls
cw exec attach [target] <name>
cw exec kill [target] <name> [--signal N]

cw shell [target]                  # interactive PTY (was cw ssh)

cw target ls / set / show          # explicit target context, unchanged
cw sandbox|env <subcommands>       # lifecycle, unchanged
cw node <subcommands>              # local daemon mgmt, unchanged
```

`target` is positional. If omitted, falls back to `cw target` current target.
Errors with a hint if neither is provided.

`target` accepts:
- `local` — host
- a local VM name (lima/incus/docker instance from `cw target ls`)
- an env name or ID (remote sandbox)

## Routing rule for `cw exec`

When `cw exec` is invoked, choose backend by capability, not by flag:

1. If `cw node` is running AND can reach the target → route through cw node.
   The command runs as a tracked, named PTY session. Output streams to the
   user's terminal. CLI exits with the command's exit code. The session record
   is a *side effect* of running it; the user-visible contract is identical to
   the no-node case.

2. Else if target is a remote env → call the platform `/exec` endpoint
   directly. One-shot, sync, dies with the request.

3. Else if target is local (host or local VM) → fork-exec or runtime-exec
   directly (the existing `execLocally` / `execInLocalRuntimeTarget` paths).

The default contract is the same in all three cases:
- streams stdout/stderr to terminal
- exits with the command's exit code
- inherits stdin

The cw-node-routed case adds capability the others can't:
- session is named (auto-generated, or `--name` if specified)
- if user detaches (Ctrl-\ or whatever cwshell's detach key is) the session
  keeps running on cw node; reattach via `cw exec attach <target> <name>`
- listing/killing via `cw exec ls / kill`
- no HTTP request-deadline pressure (cw node uses pubsub, not request/response)

The non-routed cases simply lack those capabilities — `cw exec ls` returns an
empty list, `cw exec attach` returns "no node running" with a hint to start it.

## What dies

- `cw run` — the entire verb. Its job is now `cw exec` with cw node available.
- `cw env exec` — duplicate of `cw exec <env>`.
- `cw ssh` — renamed to `cw shell`. No alias.
- `--on` flag everywhere. Target is positional.
- The "current target" *implicit* model stays via `cw target` but `--on` does
  not. To override per-command, type the target positionally.

## What stays

- `cw shell` — separate verb. Wire protocol is genuinely different (websocket
  PTY vs the exec/run path), and "give me a shell" is a distinct user intent.
- `cw target ls / set / show` — explicit context selector. Not implicit state;
  it's the daily workflow's "which computer am I on" axis (local host /
  local VM / remote env). Should be displayed in the prompt/status line.
- `cw sandbox`, `cw env`, `cw node`, `cw secrets`, etc. — lifecycle and admin
  verbs unaffected.

## Already in the tree (orthogonal)

- `cw exec` / `cw env exec` / `cw run --on env` default `--timeout` is now `0`
  (server picks 10-min default). This stands regardless of the restructure.
  Once cw-node-routing lands, the HTTP-timeout question goes away for the
  cw-node-routed path entirely.

## Migration steps

Sequence the change so each step is a small, reviewable PR. Phase boundaries
are based on what the *user* sees breaking; internal refactors can ride along.

### Step 1 — `cw shell` rename

- Rename `cw ssh` → `cw shell`. No alias, no back-compat (per user direction).
- Update help text and any docs.
- Tests: existing ssh tests pass under the new name.

### Step 2 — positional target on `cw exec` and `cw shell`

- Accept positional first arg as target on both verbs.
- If positional present, use it. Else fall back to current target. Else error.
- `--on` flag deleted.
- Update tests.
- `cw env exec` deleted.

### Step 3 — cw-node-routing in `cw exec`

- In `cw exec`, before dispatching to the existing local/local-VM/remote-env
  paths, check `cw node` reachability and target compatibility.
- If routable, invoke through cw node's session manager. Synchronously stream
  output, exit with command's code. Generate a session name if `--name` not
  given. Record the session as a side effect.
- If not routable, dispatch to the existing path unchanged.
- Add `cw exec ls`, `cw exec attach`, `cw exec kill` subcommands. They wrap
  cw node's existing equivalents (the same calls `cw run ls/attach/kill`
  uses today).

### Step 4 — delete `cw run`

- Removed from cobra command tree.
- `cw run` callers in our own code (e.g. `buildEnvironmentRunCommand` in
  `cmd/cw/run_target.go`) are deleted along with the rest of the run-target
  plumbing if no longer referenced.
- Docs updated. README, blog drafts, any demo scripts.

### Step 5 — current-target prompt/status integration

- After the dust settles, surface the current target in the shell prompt
  helper / status bar so users always see where their next `cw exec` will go.
  This is the substitute for the safety-net role that `--on` used to play.

## Platform-side changes

The CLI restructure assumes platform behavior the platform doesn't fully
provide today. These are the platform deltas required:

- **Streaming exec endpoint.** Today `/organizations/{org}/environments/{env}/exec`
  buffers stdout/stderr into a single `ExecResult`. The no-node fallback path
  needs streaming so long-running commands don't sit on the HTTP request
  deadline. Add an SSE or chunked variant (`/exec/stream`) returning a typed
  framed wire (`{type: "stdout"|"stderr"|"exit", ...}`). The buffered endpoint
  can stay for `--json` callers and existing SDK consumers; the CLI prefers
  streaming when available.
- **Session list / attach endpoints.** cw-node-routed sessions live as
  cwshell-managed PTYs *inside* the sandbox. `cw exec ls / attach / kill`
  against a remote env therefore needs the platform to proxy those calls
  through to the in-sandbox cwshell control socket. Verify the existing
  `cw run` flow already does this; if it relies on cw node having direct
  network access to the sandbox (e.g. via WireGuard relay), document that
  prerequisite explicitly. If not, add platform endpoints that proxy
  list/attach/kill into the sandbox.
- **Auth threading.** Whatever path proxies session calls into the sandbox
  must thread the caller's org/env access checks through. Reuse
  `resolveRunningSandboxTarget` (already gates `/exec`).
- **Target reachability metadata.** The CLI routing rule needs to know
  whether the target is reachable for cw-node routing without round-tripping
  to the sandbox. The environments API already returns enough state
  (`state == "running"`, type, network info); confirm cw node's reachability
  check can decide locally without a probe. If a probe is needed, expose a
  cheap `/environments/{env}/ready` endpoint.
- **Timeout default.** The CLI default timeout is now `0` (server picks).
  Server-side `defaultEnvironmentExecTimeout = 10 * time.Minute` is the
  right default for buffered exec. The streaming variant should not impose
  any timeout on the response itself — the request stays open as long as the
  command runs. Idle/heartbeat handling should be at the wire-frame layer.

## isol8 changes

The cw-node-routed and `cw shell` paths exercise CRI-exec semantics harder
than buffered one-shot exec does. isol8's CRI implementation needs to
support each of these without a layer of buffering or truncation:

- **Streaming stdout/stderr from CRI exec.** The kubelet exec API streams
  by design (it's a websocket / SPDY-multiplexed channel). Verify isol8's
  exec into the Xen PV domain does not collect output before forwarding —
  any byte of stdout produced by the workload must flow out without waiting
  for command completion. This is what makes the streaming endpoint above
  actually useful end-to-end.
- **TTY allocation.** `cw shell` and any cw-node-routed session that needs
  TTY semantics requires a PTY pair allocated at the Xen domain boundary.
  The runtime's exec path must propagate the `tty=true` request through to
  the workload and feed terminal-resize events back through CRI.
- **Long-running exec session lifecycle.** A `cw shell` session can be open
  for hours. Verify isol8 has no internal exec-session timeout, no idle
  reaper that kills exec channels, no hard cap on concurrent exec sessions
  per pod that would surprise users with multiple shells/agents.
- **Signal forwarding.** `cw exec kill <session> --signal N` must deliver
  the signal to the actual process inside the Xen domain, not just close
  the exec channel. isol8 needs a CRI ContainerStatus / signal path that
  reaches the workload.
- **stdin pipe lifecycle.** Interactive exec keeps stdin open. Closing
  stdin (e.g. user types Ctrl-D in `cw shell`) must propagate cleanly so
  the workload sees EOF, not a hang.

Most of this is "verify" rather than "build" — the assumption is isol8
already implements CRI-exec correctly. Each item above becomes a checkbox
in the implementation: confirm-or-fix.

## Critical files

- `cmd/cw/exec_cmd.go` — main verb logic. Step 2 adds positional, step 3 adds
  routing dispatch.
- `cmd/cw/run_target.go` — deleted in step 4.
- `cmd/cw/env_exec_cmd.go` — deleted in step 2.
- `cmd/cw/ssh_cmd.go` (or wherever `cw ssh` lives) — renamed in step 1.
- `cmd/cw/exec_cmd_test.go` and any sibling tests — updated in steps 2 and 3.
- `cwshell/cwshell.go` and the cw node session manager — already implements
  attach/ls/kill; step 3 wires those into `cw exec` subcommands.
- README and any onboarding docs that reference `cw run`, `cw ssh`, or
  `--on` — updated in step 4.

## Verification

Each step:

- `go build ./... && go test ./... -count=1` clean.
- Manual smoke:
  - `cw exec local -- echo hi` → streams "hi", exit 0.
  - `cw exec lima-default -- ls /workspace` → runs in lima VM, streams.
  - `cw exec env-abc123 -- pnpm test` → runs in remote sandbox, streams.
  - With `cw node` up: `cw exec env-abc123 -- claude`, detach, `cw exec ls`
    shows the session, `cw exec attach env-abc123 <name>` reconnects.
  - Without `cw node`: same first three commands work, `cw exec ls` returns
    "no node running" with a start hint.
  - `cw shell env-abc123` opens an interactive PTY.
  - `cw target set env-abc123` then `cw exec -- ls` runs against env-abc123
    without typing the target.

## Open choices

- Detach key binding for cw-node-routed exec sessions. cwshell already has
  one; whatever it is, document it in `cw exec --help`.
- Behavior of `cw exec ls` and `cw exec attach` when no node is running:
  current preference is friendly error with start hint, not silent empty.
- Whether `cw exec attach` accepts target positional + name positional, or
  just `<name>` and the target is inferred from the session record. Probably
  the latter (sessions are unique per node, target is metadata).
