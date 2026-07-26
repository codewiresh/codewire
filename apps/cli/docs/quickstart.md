# Codewire Quick Start

Codewire environments own durable sessions. The same session grammar works for
local Docker/Lima environments and platform environments.

## Install

```bash
brew install codewiresh/tap/codewire
```

Or build the Rust CLI from this repository:

```bash
cargo build -p codewire-cli-bin --bin cw
```

## Create an environment

Create a local Lima environment using the workspace image:

```bash
cw env --local create \
  --backend lima \
  --name my-app \
  --image workspace \
  --path .
```

Use `--backend docker` for a local Docker environment. Platform environments
use the same `env` family without `--local`:

```bash
cw login
cw env create --name my-app --image workspace
```

`codewire.yaml` can define the image, repositories, setup, ports, and coding
agent for either placement:

```bash
cw init --image workspace --coding-agent codex
cw env --local create --backend lima --name my-app --file codewire.yaml
```

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
cw env --local info my-app
cw env --local stop my-app
cw env --local start my-app
cw env --local daemon status my-app
cw env --local daemon repair my-app
cw env --local rm my-app
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

- `cw local ...` → `cw env --local ...`
- `cw exec ENV -- COMMAND` → `cw run ENV -- COMMAND`
- `cw node` → environment daemon lifecycle or `cw network nodes`
- `cw run --local` and `cw run --node` → create/select an environment, then
  pass that environment to `cw run`
- `--agent` → `--coding-agent`
- `node:session` → separate `ENV SESSION` arguments
