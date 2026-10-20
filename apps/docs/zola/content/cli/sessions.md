---
title: Sessions
description: run, ls, attach, logs, send, wait, stop and restart, and the attach key bindings.
weight: 2
---

Every session belongs to one environment. `ENV` is a name or ID and defaults
to the environment selected with `cw use`; `SESSION` is a name or ID within
it. `stop`, `restart` and `logs` name the environment as a positional or with
`--in ENV` (not both) and the session with `--session`. For `run`, `ls` and
`attach` a single positional is an environment (`attach` also accepts a
session of the selected environment); for `send`, `wait`, `msg`, `steer`,
`interrupt` and `inbox` a single positional is a session.

## cw run

```sh
cw run [ENV] [OPTIONS] -- COMMAND [ARG]...
cw run [ENV] --agent codex|claude [--prompt TEXT] [--name NAME] [--parent SESSION] [--model M] [--effort E] --detach
```

| Flag | Meaning |
| --- | --- |
| `--name NAME` | Unique session name within this environment |
| `--parent SESSION` | Parent session name or ID within this environment |
| `-w, --workdir DIR` | Working directory inside the environment |
| `-e, --env KEY=VALUE` | Set a variable for this session; repeatable. Not kept across a daemon restart |
| `-t, --tty`, `--no-tty` | Allocate a terminal, or not; the default is a terminal when stdin and stdout are terminals |
| `-d, --detach` | Launch without attaching |
| `--agent codex\|claude\|noel` | Launch a managed agent conversation instead of a command; `noel` on a trusted Linux host only |
| `--prompt TEXT` | Initial task for the conversation |
| `--model M` | Agent model; Codex and Claude Code default to their own, noel requires `PROVIDER/ID` |
| `--effort low\|medium\|high\|xhigh\|max` | Agent reasoning effort |
| `-o, --output json` | Print the session and do not attach |

A foreground run streams output and fails when the command exits
unsuccessfully. A hosted sandbox refuses `--tty`, a command and `--env`
together with `--agent`.

## cw ls

```sh
cw ls [ENV] [--output json]     # alias: list
```

Without `ENV`, lists every environment with its location, state and session
count; see [Environments](@/cli/environments.md). With `ENV`, lists that
environment's sessions with their state, mode (`normal` or `managed`),
parent and command.

## cw attach

```sh
cw attach [ENV] [SESSION]
cw attach --session SESSION
```

With no session, one is selected automatically; with several and a terminal,
a picker opens; with none, `cw` offers to create a shell. Attaching to a
managed agent is refused: use `cw msg`, `cw steer` and `cw logs`.

| Keys | Action |
| --- | --- |
| `Ctrl+B d` | Detach; the session keeps running |
| `Ctrl+B h` / `Ctrl+B l` | Previous / next session in this environment |
| `Ctrl+B k` / `Ctrl+B j` | Previous / next environment |
| `Ctrl+B w` | Show the environment list |
| `Ctrl+B r` | Restart the session once it has exited |
| `Ctrl+B b` | Send a literal Ctrl+B |

## cw logs

```sh
cw logs [ENV] --session SESSION [-f|--follow] [-t|--tail N] [--raw]
cw logs ENV --setup [-f|--follow]
```

Saved session output, retained across disconnects and across an
environment's stop and start. `--raw` keeps ANSI escape codes. `--setup`
shows how a cloud environment was set up instead: provisioning, repository
clones, and the install and startup steps. Without `--session` or `--setup`,
an interactive call shows the environment's only session (naming it) or
offers a choice; a script must name the source.

## cw send

```sh
cw send [ENV] SESSION TEXT [--no-newline]
cw send [ENV] SESSION --key ctrl-c|ctrl-d|enter|escape|tab
```

Writes to a terminal or command session's stdin and acknowledges the write;
it does not report that a command finished. Input is 1 to 65536 bytes.
Managed agents refuse raw input.

## cw wait

```sh
cw wait [ENV] SESSION [--timeout 30m] [-o json]
cw wait --message MESSAGE_ID [--timeout 30m]
```

Succeeds only after an observed zero exit, confirmed cleanup and drained
output; a timeout, a nonzero exit or an unknown outcome fails. Timeouts take
`s`, `ms` or `m`. `--message` waits for a managed message's final reply; the
ID alone names its session.

## cw stop

```sh
cw stop ENV [-o json]                          # the whole environment
cw stop [ENV] --session SESSION [--all] [-o json]
```

Without `--session`, `stop` stops the whole environment and needs `ENV`. With
`--session` it stops one owned session, in the selected environment unless
`ENV` names another, and leaves its siblings running. At a terminal it asks
whether to stop the session's running children; `--all` stops every
descendant without asking; without a terminal, children keep running and are
named. `--all` needs `--session`. A managed hosted session also accepts
`--cleanup-request-id UUID` to clean up an earlier operation whose reply was
lost.

## cw restart

```sh
cw restart ENV [-o json]                       # the whole environment: local VMs and hosts
cw restart [ENV] --session SESSION [-o json]
```

Without `--session`, `restart` restarts a whole local environment; a cloud
environment is refused. With `--session` it restarts a retained session with
its canonical identity. A managed
conversation resumes from its saved session; restart is refused when the
saved process identity is missing or no longer matches.

The `--request-id` and `--expected-launch-generation` flags shown in help are
for `--member` control of a trusted host; see
[Networking](@/cli/networking.md).
