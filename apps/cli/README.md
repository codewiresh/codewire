# Codewire CLI

The Rust `cw` CLI manages Codewire environments and their durable terminal
and agent sessions. Choose an environment once, then launch and control its
sessions with the same commands.

## Build

```bash
cargo build -p codewire-cli-bin --bin cw
```

The binary is written to `target/debug/cw`.

## Install

```bash
curl -fsSL https://codewire.sh/install.sh | sh
```

The installer needs only a POSIX shell, curl and a SHA-256 tool, so it works on
a stock Mac. It installs a managed cw that `cw upgrade` keeps current. From an
authorized source checkout, `make cli-install` builds and installs the same way.

cw verifies every release with its compiled key. To check release assets by
hand, from the repository root:

```bash
gpg --import apps/cli/GPG_PUBLIC_KEY.asc
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum --check SHA256SUMS
```

## Environment lifecycle

Choose a placement:

| Placement | Create command | Execution |
| --- | --- | --- |
| Local host, Linux | `cw create --local --type host --name dev --path .` | Your current OS user and project directory |
| Local sandbox | `cw create --local --type sandbox --name dev --image workspace --path .` | A hardware-accelerated native VM |
| Platform sandbox | `cw create --name dev --image workspace` | A platform environment, after `cw login` |

Local host creation requires no platform account. It uses the tools and
provider configuration available to your host user. Linux and macOS are the
admitted hosts.

Create a local sandbox with the workspace image:

```bash
cw create --local \
  --type sandbox \
  --name my-app \
  --image workspace \
  --path .
```

Manage the same local environment with:

```bash
cw ls --local
cw info --local my-app
cw stop --local my-app
cw start --local my-app
cw restart --local my-app
cw daemon status --local my-app
cw daemon repair --local my-app
cw rm --local my-app
```

Platform lifecycle uses the same commands without `--local`:

```bash
cw login
cw create --name my-app --image workspace
cw info my-app
cw stop my-app
cw start my-app
cw rm my-app
```

`cw init` writes `codewire.yaml`, which can be used for either placement.
Environment AI-tool selection is `--coding-agent`.

## Durable sessions

```bash
cw run --in my-app -- cargo test
cw run --no-tty --in my-app -- sh -lc 'printf ready'
cw run codex --in my-app --detach

cw ls my-app
cw attach my-app
cw attach my-app --session <session-id>
cw logs my-app --session <session-id>
cw logs my-app --session <session-id> --follow
cw shell my-app
cw ls
```

`cw ls` (alias `cw list`) shows every environment with its location, state and
session count; `cw ls my-app` shows that environment's sessions. `cw use
my-app` selects a default environment, after which the environment argument
of other session commands may be omitted. The foreground `cw run` streams retained output and
fails when the durable command exits unsuccessfully. `--detach` returns after
launch.

For a persistent shell, launch a named terminal and send ordinary commands:

```bash
cw run --in my-app --name shell --tty --detach -- bash
cw send my-app --session shell 'git status'
cw send my-app --session shell --key ctrl-c
cw stop my-app --session shell
```

Session names remain reserved after exit. Use a new name for a new session,
or `cw restart ENV --session SESSION` to restart the retained session.
`cw stop my-app` without `--session` stops the whole environment.

Interactive attachment uses `Ctrl+B d` to detach. Other `Ctrl+B` actions move
between sessions and environments or restart a completed session.

## Orchestrator and workers

Use managed agents for conversation-aware messages and parent completion:

```bash
cw create --local --type host --name dev --path .
cw run --in dev --name lead --agent codex --model gpt-6.1-sol --effort max \
  --detach --prompt 'Coordinate this repository task and review worker results.'
cw run --in dev --name review --agent claude --parent lead --detach \
  --prompt 'Review the proposed changes and report concrete findings.'

cw ls dev
cw inbox dev --session review
cw msg dev --session review 'Also check cancellation and cleanup.'
cw inbox dev --session lead
cw wait --message <message-id> --timeout 10m
cw steer dev --session lead --turn-id <active-turn-id> 'Prioritize the Linux acceptance.'
cw interrupt dev --session review
cw stop dev --session review
```

Use a model and effort supported by your configured provider. `cw msg`
queues a task in the same conversation; the driver delivers it through the
provider's native protocol. `cw inbox` reports messages, results and active
turn identity. A worker's terminal result is delivered once to its parent,
including an idle parent. These controls need no extra MCP server.

Active steering currently supports Codex. Claude accepts queued follow-ups
and native interruption. Use `cw send` for terminal sessions; managed agents
receive tasks through `cw msg` and `cw steer`.

Managed Codex/Claude commands work the same in a local VM created with
`--local --type sandbox` and in a platform sandbox. In both, the agent needs
a selected credential profile with a provider for it, and the provider
material stays outside the environment.

## Updating cw without restarting

The installer and `make cli-install` both create a managed installation
(`cw install --managed` does the same for a cw you built yourself):

```bash
cw upgrade                # at a terminal, choose the newer CLI and VM restarts
cw upgrade --cli          # in a script: the stable channel, no question
cw upgrade status
cw upgrade --version v1.2.3 --expect-generation <generation>
cw upgrade rollback --expect-generation <generation>
cw upgrade --from ./verified-release --sha256 <cw-sha256> --expect-generation <generation>
```

New invocations use the selected version; running processes keep their original
executable. Read the current generation from `cw upgrade status` before each
selection change. A `--from` release directory contains `cw` and its
`cw-runtime.json` identity.

cw verifies the signed release from `releases.codewire.sh` with its compiled
release key, without GnuPG, and checks the executable before selecting it;
stable refuses downgrades and different bytes with the same version.

For cw inside a running native Linux VM:

```bash
cw --local runtime info dev
cw --local runtime update dev --source ./cw-runtime.lock.json \
  --image-sha256 <image-index-sha256> --target-sha256 <cw-sha256> \
  --expected-revision <revision> --request-id <uuid>
cw --local runtime observe dev --request-id <uuid>
cw --local runtime rollback dev --expected-revision <revision> --request-id <new-uuid>
```

The runtime source is an already admitted image-derived lock. Keep the request
UUID when a reply is interrupted and observe that request's outcome. This
runtime command currently supports native Linux VMs; platform and Mac runtime
updates have separate remaining acceptance work.

## SSH and editor integration

```bash
cw setup ssh
cw shell --stdio my-app
cw vscode my-app
cw setup ssh remove
```

`cw shell --stdio` is the permanent OpenSSH/VS Code proxy path.

`cw setup ssh` writes its managed block first in `~/.ssh/config`: `Host
cw-cloud-*`, whose commands pass `--cloud`, then the catch-all `Host cw-*`,
which keeps bare `cw-NAME` aliases on the cloud through at least v0.5.
`cw-local-` is reserved for local VMs and refused for now. The block goes first
because OpenSSH keeps the first value it finds. The block runs the `cw` that
wrote it by absolute path, because OpenSSH runs `KnownHostsCommand` only from
one; re-run `cw setup ssh` if you move `cw`. Host keys are trusted only
through `KnownHostsCommand <cw> ssh known-hosts %H`, which prints the key the
platform recorded for the environment's current workspace Pod; any failure
refuses the connection rather than trusting on first use. The block accepts
only Ed25519 host keys, the one type the platform records, which also saves
OpenSSH a second `KnownHostsCommand` run per connection. The SSH server runs
inside the environment's sandbox, so the block also turns off agent and X11
forwarding, GSSAPI delegation and password, keyboard-interactive and public-key
authentication. `--ssh-option` cannot override these. `cw doctor` warns when
the block is outdated or not first. `cw setup ssh remove` deletes only the
managed block and keeps every other line. Both commands replace the file
through a new file beside it and a rename, never in place, and write through a
symlinked config to the file it names.

## Mesh

Environment daemons own node participation. User-facing network commands
manage networks and inventory:

```bash
cw network list
cw network use project-alpha
cw network nodes
```

`cw mesh up`, `cw mesh status`, and `cw mesh down` manage an optional local
Mesh service installation.

`cw member` pins an enrolled trusted Linux host, and `cw --member NAME`
routes session commands to it; see
[docs/dev/CLI-ORCHESTRATION.md](../../docs/dev/CLI-ORCHESTRATION.md).

See [docs/quickstart.md](docs/quickstart.md) for the concise user flow.
