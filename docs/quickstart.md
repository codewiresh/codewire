# Codewire Quick Start

Codewire runs PTY sessions that survive process exits. Launch a command, detach, come back
later. Designed for AI agents managing long-running tasks.

---

## Install

```bash
brew install codewiresh/tap/codewire
```

Or download a binary from [GitHub releases](https://github.com/codewiresh/codewire/releases).

The node auto-starts on first use. No daemon to configure.

---

## First Session

```bash
# Launch a session (-- is required before the command)
cw run -- bash -c 'echo hello; sleep 2; echo done'

# Output: Session 1 launched: bash -c echo hello; ...

# Check status
cw list

# Read output after it completes
cw logs 1
```

---

## Presets And Workspaces

Use `codewire.yaml` as the canonical preset file for both cloud environments and local
containers.

```bash
# Write a preset file in the current repo
cw preset init --image full --install "pnpm install" --startup "pnpm dev"

# Launch a cloud environment from the preset
cw env create --file codewire.yaml

# Or create a local runtime from the same preset
cw local create --backend docker
cw local create --backend incus
```

You can also generate and save a reusable server preset:

```bash
cw preset init --image go --save-preset go-dev
cw env create --preset go-dev
```

---

## Local Containers

Local runtimes are first-class `cw` targets. Create them once from `codewire.yaml`, then
start, stop, inspect, and exec into them by name.

```bash
# Create from the repo preset
cw local create --backend docker --name my-app

# Inspect and manage lifecycle
cw local info my-app
cw local stop my-app
cw local start my-app
cw local rm my-app

# Run commands inside the container
cw exec --on my-app -- pwd
cw use my-app
cw exec -- pwd
cw current -v
```

Notes:
- Docker works out of the box when the Docker daemon is available.
- Incus with OCI images like `docker.io/...` or `ghcr.io/...` requires `skopeo` on the host.
- `cw ssh` is for remote environments; for local runtimes, use `cw exec`.

---

## Core Commands

```bash
cw run -- <command>          # Start a session
cw run --name myapp -- cmd   # Start with a name (reference by name later)
cw run --tag worker -- cmd   # Tag for group operations

cw list                         # Show all sessions
cw status <id>                  # Detailed status for one session
cw logs <id>                    # Read accumulated output
cw logs -f <id>                 # Follow output (streaming)
cw watch <id>                   # Stream live output until session ends

cw wait <id>                    # Block until session completes
cw wait --tag worker            # Wait for all sessions with tag

cw kill <id>                    # Terminate a session
cw kill --tag worker            # Kill all sessions with tag

cw attach <id>                  # Attach interactive TTY (use Ctrl+B d to detach)
cw send <id> 'input text'       # Send input without attaching

cw preset init                  # Write codewire.yaml in the current repo
cw preset list                  # List reusable server presets
cw preset create <slug> ...     # Save a reusable server preset

cw env create --file codewire.yaml  # Create a cloud environment from a preset

cw local create --backend docker    # Create a local Docker runtime
cw local create --backend incus     # Create a local Incus runtime
cw local list                       # List local runtimes
cw local info <name>                # Show local runtime details
cw local start <name>               # Start a stopped local runtime
cw local stop <name>                # Stop a running local runtime
cw local rm <name>                  # Delete a local runtime

cw use <target>                  # Set current target (env, local runtime, or host local)
cw current -v                    # Show the current target
cw exec -- <command>             # Exec on the current target
cw exec --on <target> -- <cmd>   # Exec on a specific target
```

---

## Detach Without Killing

When attached (`cw attach`), press **Ctrl+B d** to detach. The session keeps running.
Ctrl+C will kill the process — don't use it to get back to your shell.

---

## Naming and Tags

```bash
# Reference sessions by ID or name
cw logs myapp
cw kill myapp

# Tags enable group operations
cw run --tag batch-1 -- ./worker.sh shard-a
cw run --tag batch-1 -- ./worker.sh shard-b
cw run --tag batch-1 -- ./worker.sh shard-c
cw wait --tag batch-1            # blocks until all three finish
cw kill --tag batch-1            # cleanup
```

---

## MCP Setup (for AI agents)

Register Codewire as an MCP server with Claude Code:

```bash
claude mcp add --scope user codewire -- cw mcp-server
```

The MCP server connects to the running node — start it first:

```bash
cw node -d    # start node in background (survives terminal close)
```

**Important:** Unlike the CLI, the MCP server does not auto-start a node. If no node is
running, MCP tool calls will fail with a connection error.

MCP tools mirror the CLI: `codewire_launch_session`, `codewire_wait_for`,
`codewire_read_session_output`, etc. See [mcp.md](https://codewire.sh/mcp.md) for the
full reference.

---

## When to Use Codewire

**Use Codewire when:**
- Running a command that takes minutes to hours (builds, tests, AI agents)
- You need to detach and check back later
- You're orchestrating multiple parallel tasks and want to fan-out + wait
- You want to send input to a running process without attaching
- Multiple clients (terminals, agents) need to observe the same session

**Skip Codewire when:**
- The command completes in under a second — just run it directly
- You don't need persistence or remote access
- It's a one-shot pipeline (`cmd | grep ...`) — pipes work fine

---

## Common Patterns

**Wait for completion, then read output:**
```bash
cw run --name build -- make test
cw wait build
cw logs build
```

**Launch and check later (non-blocking):**
```bash
cw run --name deploy -- ./deploy.sh
# ... do other things ...
cw status deploy
cw logs deploy --tail 20
```

**Fan-out with tags:**
```bash
for shard in a b c; do
  cw run --tag run-42 -- ./process.sh $shard
done
cw wait --tag run-42
cw logs --tag run-42    # (use cw list + per-ID logs)
```

---

## Full Reference

Everything in one file: [llms-full.txt](https://codewire.sh/llms-full.txt)
