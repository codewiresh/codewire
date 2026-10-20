# Codewire Quick Start

Codewire environments own durable command and managed agent sessions. The same
session grammar works for local hosts, local sandboxes and platform sandboxes.

## Install

```bash
curl -fsSL https://get.codewire.sh | sh
```

Or build the Rust CLI from this repository:

```bash
cargo build -p codewire-cli-bin --bin cw
```

## Create an environment

Create a native local environment using the workspace image:

```bash
cw create --local \
  --type sandbox \
  --name my-app \
  --image workspace \
  --path .
```

For execution directly on your host, use its project directory:

```bash
cw create --local --type host --name host-work --path .
```

Platform environments use the same commands without `--local`:

```bash
cw login
cw create --name my-app --image workspace
```

`codewire.yaml` can define the image, repositories, setup, ports, and coding
agent for either placement:

```bash
cw init --image workspace --coding-agent codex
cw create --local --name my-app --file codewire.yaml
```

## Coding-agent tools and credentials

The canonical `workspace` image includes Codex, Claude Code, Gemini CLI, Kimi
Code, Pi, and Aider as the `codewire` user. Agent selection records the tool
you intend to use; setup validates that the selected command is present and
does not download packages. Choose a current `workspace` image or recreate a
local environment that still references an older image rather than modifying
the image in place.

Protected local provider accounts are enrolled on the host with
`cw credentials --local` and exposed only through an explicit access profile.
The managed credential value is never copied into the workspace.

To use a Claude Pro, Max, Team or Enterprise plan with Claude Code in a hosted
Sandbox, run `claude setup-token`, then paste the freshly printed token into
`cw credentials --cloud add claude-subscription --name NAME` and select it
with `cw credentials --cloud --profile=PROFILE set anthropic NAME`. The token
stays in Codewire; the Sandbox receives only a placeholder. Codewire records an
expiry one year after you add it; replace it with `cw credentials --cloud
rotate NAME`.

Or sign in to Claude itself: `cw credentials --cloud connect claude --name
NAME` prints a link to Claude's sign-in page. Sign in with the account whose
plan you want; after you approve, Claude shows a code. Copy it, paste it at
the prompt and press Enter (what you paste stays hidden; the CLI confirms its
length), then select the credential the same way. Codewire keeps the login and refreshes it; repeat the command
with the same name to reconnect.

## Run durable sessions

Pass the environment first and the command after `--`:

```bash
cw run --in my-app -- cargo test
cw run --no-tty --in my-app -- sh -lc 'printf ready'
cw run codex --in my-app --detach
```

Select an environment once when convenient:

```bash
cw use my-app
cw run -- npm test
cw current
```

Inspect and resume its sessions:

```bash
cw ls my-app
cw attach my-app
cw attach my-app --session <session-id>
cw logs my-app --session <session-id>
cw logs my-app --session <session-id> --follow
cw shell my-app
```

Detach from an interactive attachment with `Ctrl+B d`. Session navigation uses
the other documented `Ctrl+B` actions.

## Orchestrate managed agents

Create or select an environment, then launch an orchestrator and its workers:

```bash
cw run --in host-work --name orchestrator --agent codex \
  --prompt 'Coordinate the backlog review and collect worker results.'
cw run --in host-work --name review --parent orchestrator --agent claude \
  --prompt 'Review the assigned issues and report dependencies and acceptance criteria.'
cw ls host-work
cw ls
cw msg host-work --session review 'Include the Linux sandbox dependencies in your report.'
cw inbox host-work --session review
cw logs host-work --session review
```

`--agent` launches a managed conversation. `cw msg` sends a task or follow-up
through its driver. `cw steer` and `cw interrupt` control an active turn when
the driver advertises that capability; unsupported controls return an error.
Use `--model` and `--effort` to select settings supported by the chosen driver.
Parent sessions receive worker completion notifications, and `cw inbox` keeps
message results available after reconnecting.

Run a normal shell command as another named session in the same environment:

```bash
cw run --in host-work --name checks --parent orchestrator -- cargo test
cw attach host-work --session checks
```

For a local sandbox, create it with `--local --type sandbox`; for a platform
sandbox, create it without `--local`. Pass that environment name to the same
`run`, `ls`, `msg`, `inbox`, `attach` and `logs` commands.

## Manage lifecycle

```bash
cw info --local my-app
cw stop --local my-app
cw start --local my-app
cw restart --local my-app
cw daemon status --local my-app
cw daemon repair --local my-app
cw rm --local my-app
```

For a platform environment, omit `--local`:

```bash
cw info my-app
cw stop my-app
cw start my-app
cw rm my-app
```

## Mesh inventory

Environment daemons own runtime participation. The CLI manages networks and
shows registered nodes. `cw member` manages explicitly pinned trusted hosts
for remote control over the Mesh; execution requires the member's granted
capability.

```bash
cw network list
cw network use project-alpha
cw network nodes
cw member identity
cw member status
```

After enrolling and pinning a trusted member, target its environment explicitly:

```bash
cw --member build-linux ls
cw --member build-linux run host-work --name checks -- cargo test
```

Use `cw mesh up`, `cw mesh status`, and `cw mesh down` only to manage a local
Mesh service installation.
