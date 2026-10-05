# Codewire Quick Start

Codewire environments own durable sessions. The same session grammar works for
native local environments and platform environments.

## Install

```bash
brew install codewiresh/tap/codewire
```

Or build the Rust CLI from this repository:

```bash
cargo build -p codewire-cli-bin --bin cw
```

## Create an environment

Create a native local environment using the workspace image:

```bash
cw env create --local \
  --name my-app \
  --image workspace \
  --path .
```

Platform environments use the same `env` family without `--local`:

```bash
cw login
cw env create --name my-app --image workspace
```

`codewire.yaml` can define the image, repositories, setup, ports, and coding
agent for either placement:

```bash
cw init --image workspace --coding-agent codex
cw env create --local --name my-app --file codewire.yaml
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
`cw credentials --platform add claude-subscription --name NAME` and select it
with `cw credentials --platform --profile=PROFILE set anthropic NAME`. The token
stays in Codewire; the Sandbox receives only a placeholder. Codewire records an
expiry one year after you add it; replace it with `cw credentials --platform
rotate NAME`.

## Run durable sessions

Pass the environment first and the command after `--`:

```bash
cw run my-app -- cargo test
cw run --no-tty my-app -- sh -lc 'printf ready'
cw run --detach my-app -- codex
```

Select an environment once when convenient:

```bash
cw use my-app
cw run -- npm test
cw current
```

Inspect and resume its sessions:

```bash
cw list my-app
cw attach my-app
cw attach my-app <session-id>
cw logs my-app <session-id>
cw logs --follow my-app <session-id>
cw shell my-app
```

Detach from an interactive attachment with `Ctrl+B d`. Session navigation uses
the other documented `Ctrl+B` actions.

## Manage lifecycle

```bash
cw env info --local my-app
cw env stop --local my-app
cw env start --local my-app
cw env restart --local my-app
cw env daemon status --local my-app
cw env daemon repair --local my-app
cw env rm --local my-app
```

For a platform environment, omit `--local`:

```bash
cw env info my-app
cw env stop my-app
cw env start my-app
cw env rm my-app
```

## Mesh inventory

Environment daemons own runtime participation. The CLI manages networks and
shows registered nodes; it does not run a second host-owned node or session
service.

```bash
cw network list
cw network use project-alpha
cw network nodes
```

Use `cw mesh up`, `cw mesh status`, and `cw mesh down` only to manage a local
Mesh service installation.

## Removed grammar

There is no compatibility execution path. The CLI reports exact migration
guidance for removed commands:

- `cw local ...` → `cw env COMMAND --local ...`
- `cw exec ENV -- COMMAND` → `cw run ENV -- COMMAND`
- `cw node` → environment daemon lifecycle or `cw network nodes`
- `cw run --local` and `cw run --node` → create/select an environment, then
  pass that environment to `cw run`
- `--agent` → `--coding-agent`
- `node:session` → separate `ENV SESSION` arguments
