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
a stock Mac. It installs a managed cw that `cw update` keeps current. From an
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
| Local host, Linux | `cw env create --local --type host --name dev --path .` | Your current OS user and project directory |
| Local sandbox | `cw env create --local --type sandbox --name dev --image workspace --path .` | A hardware-accelerated native VM |
| Platform sandbox | `cw env create --name dev --image workspace` | A platform environment, after `cw login` |

Local host creation requires no platform account. It uses the tools and
provider configuration available to your host user. Host execution is
currently qualified on Linux; Mac host support follows its cleanup adapter.

Create a local sandbox with the workspace image:

```bash
cw env create --local \
  --type sandbox \
  --name my-app \
  --image workspace \
  --path .
```

Manage the same local environment with:

```bash
cw env list --local
cw env info --local my-app
cw env stop --local my-app
cw env start --local my-app
cw env restart --local my-app
cw env daemon status --local my-app
cw env daemon repair --local my-app
cw env rm --local my-app
```

Platform lifecycle uses the same commands without `--local`:

```bash
cw login
cw env create --name my-app --image workspace
cw env info my-app
cw env stop my-app
cw env start my-app
cw env rm my-app
```

`cw init` writes `codewire.yaml`, which can be used for either placement.
Environment AI-tool selection is `--coding-agent`.

## Durable sessions

```bash
cw run my-app -- cargo test
cw run --no-tty my-app -- sh -lc 'printf ready'
cw run --detach my-app -- codex

cw list my-app
cw attach my-app
cw attach my-app <session-id>
cw logs my-app <session-id>
cw logs --follow my-app <session-id>
cw shell my-app
cw list
```

`cw list` (or `cw ls`) shows every environment and its sessions. `cw use
my-app` selects a default environment, after which the environment argument
of other session commands may be omitted. The foreground `cw run` streams retained output and
fails when the durable command exits unsuccessfully. `--detach` returns after
launch.

For a persistent shell, launch a named terminal and send ordinary commands:

```bash
cw run my-app --name shell --tty --detach -- bash
cw send my-app shell 'git status'
cw send my-app shell --key ctrl-c
cw stop my-app shell
```

Session names remain reserved after exit. Use a new name for a new session,
or `cw restart ENV SESSION` to restart the retained session.

Interactive attachment uses `Ctrl+B d` to detach. Other `Ctrl+B` actions move
between sessions and environments or restart a completed session.

## Orchestrator and workers

Use managed agents for conversation-aware messages and parent completion:

```bash
cw env create --local --type host --name dev --path .
cw run dev --name lead --agent codex --model gpt-6.1-sol --effort max \
  --detach --prompt 'Coordinate this repository task and review worker results.'
cw run dev --name review --agent claude --parent lead --detach \
  --prompt 'Review the proposed changes and report concrete findings.'

cw list dev
cw inbox dev review
cw msg dev review 'Also check cancellation and cleanup.'
cw inbox dev lead
cw wait --message <message-id> --timeout 10m
cw steer dev lead --turn-id <active-turn-id> 'Prioritize the Linux acceptance.'
cw interrupt dev review
cw stop dev review
```

Use a model and effort supported by your configured provider. `cw msg`
queues a task in the same conversation; the driver delivers it through the
provider's native protocol. `cw inbox` reports messages, results and active
turn identity. A worker's terminal result is delivered once to its parent,
including an idle parent. These controls need no extra MCP server.

Active steering currently supports Codex. Claude accepts queued follow-ups
and native interruption. Use `cw send` for terminal sessions; managed agents
receive tasks through `cw msg` and `cw steer`.

Managed Codex/Claude commands also target a native Linux sandbox created with
`--local --type sandbox`. Platform sandboxes already support ordinary terminal
sessions; their managed-agent integration remains a separate delivery step.
Sandbox provider credentials stay with the selected external credential profile.

## Updating cw without restarting

The installer and `make cli-install` both create a managed installation
(`cw install --managed` does the same for a cw you built yourself):

```bash
cw update                 # follow the stable channel
cw update status
cw update --version v1.2.3 --expect-generation <generation>
cw update rollback --expect-generation <generation>
cw update --from ./verified-release --sha256 <cw-sha256> --expect-generation <generation>
```

New invocations use the selected version; running processes keep their original
executable. Read the current generation from `cw update status` before each
selection change. A `--from` release directory contains `cw` and its
`cw-runtime.json` identity.

cw verifies the signed release from `releases.codewire.sh` with its compiled
release key, without GnuPG, and checks the executable before selecting it;
stable refuses downgrades and different bytes with the same version.

For cw inside a running native Linux VM:

```bash
cw env --local runtime info dev
cw env --local runtime update dev --source ./cw-runtime.lock.json \
  --image-sha256 <image-index-sha256> --target-sha256 <cw-sha256> \
  --expected-revision <revision> --request-id <uuid>
cw env --local runtime observe dev --request-id <uuid>
cw env --local runtime rollback dev --expected-revision <revision> --request-id <new-uuid>
```

The runtime source is an already admitted image-derived lock. Keep the request
UUID when a reply is interrupted and observe that request's outcome. This
runtime command currently supports native Linux VMs; platform and Mac runtime
updates have separate remaining acceptance work.

## SSH and editor integration

```bash
cw config-ssh
cw shell --stdio my-app
cw vscode my-app
```

`cw shell --stdio` is the permanent OpenSSH/VS Code proxy path.

`cw config-ssh` writes its managed `Host cw-*` block first in `~/.ssh/config`,
because OpenSSH keeps the first value it finds. The block runs the `cw` that
wrote it by absolute path, because OpenSSH runs `KnownHostsCommand` only from
one; re-run `cw config-ssh` if you move `cw`. Host keys are trusted only
through `KnownHostsCommand <cw> ssh known-hosts %H`, which prints the key the
platform recorded for the environment's current workspace Pod; any failure
refuses the connection rather than trusting on first use. The block accepts
only Ed25519 host keys, the one type the platform records, which also saves
OpenSSH a second `KnownHostsCommand` run per connection. The SSH server runs
inside the environment's sandbox, so the block also turns off agent and X11
forwarding, GSSAPI delegation and password, keyboard-interactive and public-key
authentication. `--ssh-option` cannot override these. `cw doctor` warns when
the block is outdated or not first.

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

Remote member execution is planned in [#2269](https://git.example.invalid/codewire/codewire/issues/2269).
Its execution grants and `--member` routing remain unimplemented.

## Clean cutover

Migration diagnostics map retired grammar to the environment/session model:

- `cw local ...` → `cw env COMMAND --local ...`
- `cw exec ENV -- COMMAND` → `cw run ENV -- COMMAND`
- `cw node` → `cw env daemon ...` or `cw network nodes`
- `cw run --local` / `cw run --node` → explicit environment lifecycle plus
  `cw run ENV`
- Environment setup's old `--agent` → `--coding-agent`; managed `cw run --agent`
  selects a conversation driver
- `node:session` → `ENV SESSION`

See [docs/quickstart.md](docs/quickstart.md) for the concise user flow.
