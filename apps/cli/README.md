# Codewire CLI

The Rust `cw` CLI manages Codewire environments and their durable sessions.
Local Docker/Lima and platform placements share one environment-first grammar
and one environment-owned session model.

## Build

```bash
cargo build -p codewire-cli-bin --bin cw
```

The binary is written to `target/debug/cw`.

## Private-preview install and release verification

Install from an authorized source checkout:

```bash
make cli-install
```

Signed release assets use the public key committed with the selected source.
From the repository root:

```bash
gpg --import apps/cli/GPG_PUBLIC_KEY.asc
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum --check SHA256SUMS
```

## Environment lifecycle

Create a local environment with the workspace image:

```bash
cw env create --local \
  --backend lima \
  --name my-app \
  --image workspace \
  --path .
```

Use `--backend docker` for Docker. Manage the same local environment with:

```bash
cw env list --local
cw env info --local my-app
cw env stop --local my-app
cw env start --local my-app
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
```

`cw use my-app` selects a default environment, after which the environment
argument may be omitted. The foreground `cw run` streams retained output and
fails when the durable command exits unsuccessfully. `--detach` returns after
launch.

Interactive attachment uses `Ctrl+B d` to detach. Other `Ctrl+B` actions move
between sessions and environments or restart a completed session.

## SSH and editor integration

```bash
cw config-ssh
cw shell --stdio my-app
cw vscode my-app
```

`cw shell --stdio` is the permanent OpenSSH/VS Code proxy path. It is distinct
from the deleted host-owned session runtime.

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

## Clean cutover

The CLI intentionally has no compatibility implementation for the retired
host-owned runtime. Migration diagnostics map old grammar to the new model:

- `cw local ...` → `cw env COMMAND --local ...`
- `cw exec ENV -- COMMAND` → `cw run ENV -- COMMAND`
- `cw node` → `cw env daemon ...` or `cw network nodes`
- `cw run --local` / `cw run --node` → explicit environment lifecycle plus
  `cw run ENV`
- `--agent` → `--coding-agent`
- `node:session` → `ENV SESSION`

See [docs/quickstart.md](docs/quickstart.md) for the concise user flow.
