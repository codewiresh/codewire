# SDK parity smoke test

Three equivalent programs — one per SDK — that each:

1. Create a docker-backed local VM from a configurable image.
2. Run a shell command inside (`echo hello from codewire` by default).
3. Print exit code + stdout + stderr.
4. Tear down.

If Go, Python, and TypeScript all drive `client.local` correctly, the
observable output is identical across languages. That's the parity test.

The directory is named `run-claude/` because the eventual goal is to invoke
`claude -p <prompt>` inside the VM end-to-end. See [Running Claude](#running-claude)
below for the blocker and the workaround.

## Prerequisites

- Docker daemon running.
- `cw` CLI binary: either on `$PATH`, or exported as `$CW_BIN`. From the
  CLI repo: `make build && export CW_BIN="$PWD/cw"`.

## Running one language at a time

```bash
# Go
cd sdk/examples/run-claude/go && go run .

# Python
cd sdk/examples/run-claude/python && python3 run_claude.py

# TypeScript
cd sdk/examples/run-claude/typescript
npm install                # first time only; links the local SDK via file:
npx tsx run_claude.ts
```

## Running all three in one shot

From `sdk/`:

```bash
make run-claude-examples
```

This runs Go → Python → TypeScript sequentially. All three must succeed.

## Observed output (current)

```
==> Creating docker local instance…
    created cw-example-<lang>-<suffix> (backend=docker status=running)
==> Running: echo hello from codewire

--- exit 0 ---
hello from codewire
--- end ---
==> Removing instance…
```

Identical structure in all three languages. Name suffix differs (each
language mints its own tempdir). Everything else matches byte-for-byte.

## Overriding image and command

Both are env-driven:

```bash
CW_EXAMPLE_IMAGE=docker.io/library/ubuntu:24.04 \
CW_EXAMPLE_CMD='cat /etc/os-release' \
  make run-claude-examples
```

## Running Claude for real

Swap the defaults to hit an image that has `claude` preinstalled:

```
CW_EXAMPLE_IMAGE=ghcr.io/codewiresh/workspace@sha256:03571275319488cd317d7f405fc22057214906fba0c6727160090286a17f7467 \
CW_EXAMPLE_CMD='claude -p "Reply with exactly one word: hello"' \
  make run-claude-examples
```

Expected output (identical across all three SDKs):

```
==> Creating docker local instance…
    created cw-example-<lang>-<suffix> (backend=docker status=running)
==> Running: claude -p "Reply with exactly one word: hello"

--- exit 0 ---
hello
--- end ---
==> Removing instance…
```

Authentication: either of these works on the host, and local environment
creation forwards whichever is set into the container automatically:

- **`ANTHROPIC_API_KEY`** (`sk-ant-api…`) — pay-per-token API key from
  console.anthropic.com. Standard for CI / programmatic use; rotatable.
- **`CLAUDE_CODE_OAUTH_TOKEN`** (`sk-ant-oat01…`) — Claude Code OAuth
  token, billed against your subscription. Picked up automatically from
  `~/.claude/.credentials.json`.

For the local parity smoke, prefer `ANTHROPIC_API_KEY`. It can run
`claude --model haiku` to keep per-run cost minimal. Codewire deliberately
does not run this paid, credential-bearing smoke in hosted CI.

### CLI changes this depends on

- **Entrypoint override.** `cw env create --local` (Docker and Lima backends)
  starts containers with `--entrypoint /bin/sh`, so images whose
  own entrypoints try to mutate `/home/codewire/.ssh` (mounted read-only)
  don't abort on boot.
- **No spurious `ANTHROPIC_AUTH_TOKEN` (cw ≥ v0.3.28)**. Previously the
  OAuth token was also exported as `ANTHROPIC_AUTH_TOKEN`, which
  `claude-code` preferred and then failed against with 401. Only
  `CLAUDE_CODE_OAUTH_TOKEN` is forwarded now.
- **`ANTHROPIC_API_KEY` forwarding.** When set on the host, local environment
  creation injects it into the container as `--env ANTHROPIC_API_KEY=…` on
  Docker and Lima backends. This is the path CI uses.
