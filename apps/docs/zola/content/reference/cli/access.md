---
title: Access
description: run, exec, ls, attach, logs, send, wait, stop and restart, and the attach key bindings.
updated: 2026-11-14
weight: 3
aliases: ["/cli/sessions"]
---

Every session belongs to one environment. `ENV` is a name or ID and defaults
to the environment selected with `cw use`; `SESSION` is a name or ID within
it. `attach`, `send`, `wait`, `stop`, `restart` and `logs` name the
environment as a positional or with `--in ENV` (not both) and an existing
session with `--session`; a positional is always an environment, never a
session. `run` names its environment only with `--in ENV`, because its
positional is the agent. `--name` names a new session and never selects an
existing one. With no environment named or selected, commands other than
interactive `run` say how to choose one: `cw use ENV`, or `--in ENV`.

## cw run

```sh
cw run [--in ENV] [OPTIONS] COMMAND [ARG]...
cw run [--in ENV] [OPTIONS] -- COMMAND [ARG]...
cw run claude|codex [--in ENV] [--name NAME] [--env KEY=VALUE]... [-- AGENT_ARG...]
cw run --in ENV --agent codex|claude [--prompt TEXT] [--name NAME] [--parent SESSION] [--model M] [--effort E] --detach
cw run
```

`cw run COMMAND` runs any command in a new session in the environment: a
dev server, a test suite, a build or a shell script. The session keeps running
when you detach, and `cw attach` reconnects to it. `cw`'s options go before
the command, and every word after the command is the command's, so `--` before
it is optional: `cw run --in app npm test` and `cw run --in app -- npm test`
are the same. An option of `cw`'s written after the command, such as
`cw run npm test --in app`, is refused before anything starts, with the line
that means it; `cw run -- npm test --in app` passes `--in app` to `npm`. A
first word of `claude` or `codex` opens that agent, as below; `cw run -- claude`
runs the `claude` command itself.

`cw run claude` and `cw run codex` open that agent's own terminal UI in a new
session, with arguments after `--` passed to the agent (for example
`-- --resume ID`). Before the agent takes the terminal, `cw` names the
environment and session and the way back: detach with Ctrl-B, then d, and
reconnect with `cw attach ENV --session SESSION`. An environment is always
named with `--in`, so one named `claude` is `cw run claude --in claude`. Bare `cw run` asks
which agent to open on a terminal and is refused in a script or with JSON
output. If no environment is selected, the terminal flow offers an existing
sandbox or explicit local/cloud creation, constrained by placement flags. A
stopped choice asks before starting; an existing choice keeps its saved
configuration. Creating a new environment requires a settings review. A missing
cloud login or pinned local VM runtime offers the supported setup step before
continuing. Choosing an environment for this run does not change `cw use`.
Scripts and JSON commands never provision from a missing target. With `--agent`
the run starts a managed conversation instead (see [Agents](@/reference/cli/agents.md));
it cannot be combined with an agent positional, a command after `--`, or
`--tty`.

Without `--name`, a session is named after its agent or command (`claude`,
then `claude-2`; `npm` for `npm test`). A name already used in the
environment is refused before anything starts, with the command that reaches
that session. `--local` or `--cloud` limits where `ENV`, or the selected
environment, may be.

| Flag | Meaning |
| --- | --- |
| `--in ENV` | Environment name or ID; defaults to the selected environment |
| `--name NAME` | Unique name for the new session; never reuses one |
| `--parent SESSION` | Parent session name or ID within this environment |
| `-w, --workdir DIR` | Working directory inside the environment |
| `-e, --env KEY=VALUE` | Set a variable for this session; repeatable. Not kept across a daemon restart |
| `-t, --tty`, `--no-tty` | Allocate a terminal, or not; the default is a terminal when stdin and stdout are terminals, and always for `claude` and `codex` |
| `-d, --detach` | Launch without attaching |
| `-y, --yes` | Never ask: without an agent, a command or an environment, fail and name what to pass instead of opening a picker or setup |
| `--agent codex\|claude\|noel` | Launch a managed agent conversation instead of a command; `noel` on a trusted Linux host only |
| `--prompt TEXT` | Initial task for the conversation |
| `--model M` | Agent model; Codex and Claude Code default to their own, noel requires `PROVIDER/ID` |
| `--effort low\|medium\|high\|xhigh\|max` | Agent reasoning effort |
| `-o, --output json` | Print the session and do not attach |

A foreground run streams output and fails when the command exits
unsuccessfully. A hosted sandbox refuses `--tty`, a command and `--env`
together with `--agent`.

Example:

```sh
cw run --in app --name tests --no-tty --detach -- sh -c 'sleep 2; echo 12 passed'
cw run --in app --no-tty -- sh -c 'echo building; exit 3'
```

```text
✓ Started session app/tests · local VM
✓ Started session app/sh · local VM
building
session exited with code 3
```

The second command exits 1 because the session failed.

## cw exec

```sh
cw exec [--in ENV] [-w DIR] [-e KEY=VALUE]... [-t] COMMAND [ARG]...
```

Runs a command once and waits for it, as `ssh HOST COMMAND` does. No session
is made, so nothing appears in `cw ls` and nothing is left behind. The
command's output and errors stream here, stdin is passed through, and `cw`
exits with the command's exit status. Ctrl-C, or losing the connection, ends
the command. `-t` gives it a terminal, for programs that need one, such as
`htop` or `vim`; then Ctrl-C goes to the program. Use `cw run` for anything
that should keep running after you leave.

Options go before the command and every word after it is the command's, as
for `cw run`. In a local VM or a cloud environment the command runs through
the environment daemon. On a trusted host it runs on that machine as you,
in the environment's folder; a relative `-w` is inside it.

| Flag | Meaning |
| --- | --- |
| `--in ENV` | Environment name or ID; defaults to the selected environment |
| `-w, --workdir DIR` | Working directory inside the environment |
| `-e, --env KEY=VALUE` | Set a variable for this command; repeatable |
| `-t, --tty` | Give the command a terminal |

## cw ls

```sh
cw ls [ENV] [--output json]     # alias: list
```

Without `ENV`, lists every environment with its location, state and session
count; see [Environments](@/reference/cli/environments.md). With `ENV`, lists that
environment's sessions with their state, mode (`normal` or `managed`),
parent and command.

Example:

```sh
cw ls app
```

```text
NAME   STATE    MODE    PARENT  SESSION                                       COMMAND
dev    Running  normal  -       session-5c7443a7-2a7e-409f-b684-bd74c8b580b5  python3 -m http.server 8080
shell  Running  normal  -       session-a09621a6-d205-4ebb-8a6c-045c7cab5f19  bash
```

## cw attach

```sh
cw attach ENV --session SESSION
cw attach --session SESSION       # in the selected environment
cw attach ENV                     # its only session, or a choice
```

Without `--session`, an environment with one session attaches to it and says
which; with several, a terminal gets a searchable picker and a script must
name `--session`; with none, a terminal is offered a new shell. The terminal's
size follows into the session as it changes. Attaching to a managed agent is
refused: use `cw msg`, `cw steer` and `cw logs`.

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
cw send [ENV] --session SESSION TEXT [--no-newline]
cw send [ENV] --session SESSION --key ctrl-c|ctrl-d|enter|escape|tab
```

With `TEXT`, a single positional is the text and two are `ENV TEXT`; with
`--key`, a single positional is `ENV`.

Writes to a terminal or command session's stdin and acknowledges the write;
it does not report that a command finished. Input is 1 to 65536 bytes.
Managed agents refuse raw input. To type a line into a terminal program such
as Claude Code or Codex, `cw msg ENV --session SESSION TEXT` writes the text
and the Enter key it submits on; see [Agents](@/reference/cli/agents.md#cw-msg).

Example:

```sh
cw send app --session shell 'echo hello from send'
```

```text
Input written to session-a09621a6-d205-4ebb-8a6c-045c7cab5f19
```

## cw wait

```sh
cw wait [ENV] --session SESSION [--timeout 30m] [-o json]
cw wait --message MESSAGE_ID [--timeout 30m]
```

Succeeds only after an observed zero exit, confirmed cleanup and drained
output; a timeout, a nonzero exit or an unknown outcome fails. Timeouts take
`s`, `ms` or `m`. `--message` waits for a managed message's final reply; the
ID alone names its session.

Example:

```sh
cw wait app --session tests --timeout 1m
```

```text
12 passed
```

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

Example:

```sh
cw stop app --session dev
```

```text
NAME  STATE    MODE    PARENT  SESSION                                       COMMAND
dev   Stopped  normal  -       session-5c7443a7-2a7e-409f-b684-bd74c8b580b5  python3 -m http.server 8080
```

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
[Networking](@/reference/cli/networking.md).

Example:

```sh
cw restart app --session dev
```

```text
NAME  STATE    MODE    PARENT  SESSION                                       COMMAND
dev   Running  normal  -       session-5c7443a7-2a7e-409f-b684-bd74c8b580b5  python3 -m http.server 8080
```
