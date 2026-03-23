# Codewire

Persistent process server for AI coding agents. Like tmux, but purpose-built for long-running LLM processes — with native terminal scrolling, copy/paste, and no weird key chords.

Codewire runs as a background node inside your development environment (e.g., a Coder workspace). You launch AI agent sessions with a prompt, and they keep running even if you disconnect. Reconnect anytime to pick up where you left off.

Works with any CLI-based AI agent: Claude Code, Aider, Goose, Codex, or anything else.

## Install

### Homebrew (macOS/Linux)

```bash
brew install codewiresh/codewire/codewire
```

### Install Script

```bash
curl -fsSL https://raw.githubusercontent.com/codewiresh/codewire/main/install.sh | bash
```

This downloads the latest binary, verifies its SHA256 checksum (and GPG signature if `gpg` is installed), and installs `cw` to `/usr/local/bin`.

Options:

```bash
# Install a specific version
curl -fsSL .../install.sh | bash -s -- --version v0.1.0

# Install to a custom prefix
curl -fsSL .../install.sh | bash -s -- --prefix ~/.local
```

### Build from source

```bash
go build -o cw ./cmd/cw
sudo mv cw /usr/local/bin/cw
```

Or use `make`:

```bash
make install
```

## Quick Start

```bash
# Launch a session (node auto-starts)
cw launch -- claude -p "fix the auth bug in login.ts"

# Use a different AI agent
cw launch -- aider --message "fix the auth bug"
cw launch -- goose run

# Specify a working directory
cw launch --dir /home/coder/project -- claude -p "add tests"

# List running sessions
cw list

# Attach to a session
cw attach 1

# Detach: Ctrl+B then d

# View what the agent did while you were away
cw logs 1
```

## Presets, Cloud Environments, And Local Runtimes

`codewire.yaml` is the shared preset file for both managed environments and local
containers.

```bash
# Write a preset for this repo
cw preset init --image full --install "pnpm install" --startup "pnpm dev"

# Launch a cloud environment from the preset
cw env create --file codewire.yaml

# Or create a local container from the same preset
cw local create --backend docker
```

Local runtimes become normal `cw` targets:

```bash
cw local info my-app
cw exec --on my-app -- pwd
cw use my-app
cw exec -- pwd
cw use local
```

Notes:
- `cw exec` works across the current target, including remote envs and local Docker/Incus runtimes.
- `cw ssh` remains for remote environments; local runtimes use backend-native exec.
- Incus with OCI registry images like `docker.io/...` and `ghcr.io/...` requires `skopeo` on the host.

## Commands

### Workspace Lifecycle

```bash
cw preset init                              # Write codewire.yaml
cw preset list                              # List reusable server presets
cw preset create <slug> --image full ...    # Save a reusable server preset

cw env create --file codewire.yaml          # Create a cloud environment from a preset
cw env create --preset full                 # Create from a saved server preset

cw local create --backend docker            # Create a local Docker runtime
cw local create --backend incus             # Create a local Incus runtime
cw local list                               # List local runtimes
cw local info <name>                        # Show local runtime details
cw local start <name>                       # Start a stopped local runtime
cw local stop <name>                        # Stop a running local runtime
cw local rm <name>                          # Delete a local runtime

cw use <target>                             # Set current target
cw current -v                               # Show current target details
cw exec -- <command>                        # Run on the current target
cw exec --on <target> -- <command>          # Run on a specific target
```

### `cw launch [name] [--dir <dir>] [--tag <tag>...] -- <command> [args...]`

Start a new session running the given command in a persistent PTY. Everything after `--` is the command and its arguments. An optional positional name before `--` gives the session a stable identifier for messaging. Tags enable filtering and coordination.

```bash
cw launch -- claude -p "refactor the database layer"
cw launch planner -- claude -p "plan the refactor"
cw launch --dir /home/coder/project -- claude -p "add unit tests for auth"
cw launch --tag worker --tag build -- claude -p "fix tests"
cw launch -- bash -c "npm test && npm run lint"
```

Options:
- Positional name (before `--`) — Unique name for the session (alphanumeric + hyphens, 1-32 chars). Used for addressing in messaging. Equivalent to `--name`.
- `--name` — Alternative to positional name (useful for programmatic/MCP use)
- `--dir`, `-d` — Working directory (defaults to current dir)
- `--tag`, `-t` — Tag the session (repeatable)

### `cw list`

Show all sessions with their name, status, age, and command.

```bash
cw list
# ID   NAME           COMMAND                          STATUS     AGE
# 1    planner        claude -p "plan the refactor"    running    2m ago
# 2    coder          claude -p "implement changes"    running    45s ago

cw list --json   # machine-readable output
```

### `cw attach <id>`

Take over your terminal and connect to a running session. You get full terminal I/O — native scrolling, native copy/paste, everything your terminal emulator supports.

Detach with **Ctrl+B d** (press Ctrl+B, release, then press d). The session keeps running.

### `cw logs <id>`

View captured output from a session without attaching.

```bash
cw logs 1              # full output
cw logs 1 --follow     # tail -f style, streams new output
cw logs 1 --tail 100   # last 100 lines
```

Works on completed sessions too — review what the agent did after it finished.

### `cw kill <id>`

Terminate a session. Supports tag-based filtering.

```bash
cw kill 3
cw kill --all
cw kill --tag worker          # Kill all sessions tagged "worker"
```

### `cw send <id> [input]`

Send input to a session without attaching. Useful for multi-agent coordination.

```bash
cw send 1 "Status update?"                    # Send text with newline
cw send 1 "test" --no-newline                 # No newline
echo "command" | cw send 1 --stdin            # From stdin
cw send 1 --file commands.txt                 # From file
```

### `cw watch <id>`

Monitor a session in real-time without attaching. Perfect for observing another agent's progress.

```bash
cw watch 1                      # Watch with recent history
cw watch 1 --tail 50            # Start from last 50 lines
cw watch 1 --no-history         # Only new output
cw watch 1 --timeout 60         # Auto-exit after 60 seconds
```

### `cw msg <target> <body> [-f <session>] [--delivery auto|inbox|pty|both]`

Send a direct message to a session. Target can be a session ID or name.

```bash
cw msg coder "start with the auth module"              # by name
cw msg 2 "start with the auth module"                  # by ID
cw msg -f planner coder "start with the auth module"   # with sender
cw msg --delivery pty coder "check this out"            # PTY injection only
cw msg --delivery both coder "review please"            # inbox + PTY injection
```

**Delivery modes:**
- `inbox` — write to inbox/message log only (safe default for shell sessions)
- `pty` — inject a formatted prompt into the recipient's PTY only
- `both` — inbox logging + PTY injection
- `auto` (default) — uses `both` when called from inside another cw session (`--from` or `CW_SESSION_ID` set), otherwise `inbox`

### `cw inbox <session> [-t <N>]`

Read messages from a session's inbox. Shows direct messages and pending requests.

```bash
cw inbox coder                # latest 50 messages
cw inbox planner -t 10        # last 10 messages
```

### `cw request <target> <body> [-f <session>] [--timeout <s>] [--delivery auto|inbox|pty|both]`

Send a request to a session and block until a reply arrives. Like `msg` but synchronous — the caller waits for a response.

```bash
cw request -f planner coder "ready for review?"
# [reply from coder] yes, PR #42 is up

cw request coder "status?" --timeout 30    # 30s timeout (default: 60s)
cw request --delivery both coder "need approval"  # inbox + PTY injection
```

Uses the same delivery modes as `cw msg`. When `--delivery pty` or `both` is used, the recipient sees a formatted prompt in their terminal with a reply hint.

### `cw reply <request-id> <body> [-f <session>]`

Reply to a pending request. The request ID comes from `cw inbox` or from a `message.request` event.

```bash
cw reply req_x7y8z9 "yes, PR #42 is up" -f coder
```

### `cw listen [--session <session>]`

Stream all message traffic on the node in real-time. Shows direct messages, requests, and replies as they happen.

```bash
cw listen                     # all message traffic
cw listen --session planner   # only messages involving planner
```

Output format:
```
[planner → coder] start with the auth module
[coder → planner] REQUEST (req_x7y8): need the DB schema?
[planner] REPLY (req_x7y8): use the existing users table
```

### `cw status <id>`

Get detailed session status including PID, output size, and recent output.

```bash
cw status 1                     # Human-readable format
cw status 1 --json              # JSON output
```

### `cw subscribe [node] [--tag <tag>] [--event <type>]`

Subscribe to real-time session events. Events stream until you disconnect.

```bash
cw subscribe --tag worker                           # Events from sessions tagged "worker"
cw subscribe --event session.status                  # Only status change events
cw subscribe dev-1 --tag build                       # Events from remote node
```

### `cw wait [node:]<id> [--tag <tag>] [--condition all|any] [--timeout <seconds>]`

Block until sessions complete.

```bash
cw wait 3                                            # Wait for session 3 to complete
cw wait --tag worker --condition all                 # Wait for ALL workers to complete
cw wait --tag worker --condition any --timeout 60    # Wait for ANY worker, 60s timeout
```

### `cw relay nodes`

List all nodes registered with the relay.

```bash
cw relay nodes
```

### `cw relay setup [relay-url]`

Authorize this node with a relay using the device authorization flow.

```bash
cw relay setup https://relay.codewire.sh
```

### `cw relay serve`

Run a relay server. The relay provides SSH gateway access, node discovery, and shared KV storage.

```bash
cw relay serve --base-url https://relay.example.com --data-dir /data/relay
```

### `cw mcp-server`

Start an MCP (Model Context Protocol) server for programmatic access.

```bash
cw mcp-server
```

See [MCP Integration](#mcp-integration) section below for details.

### `cw start` / `cw node`

Start the node manually. Usually you don't need this — the node auto-starts on first CLI invocation.

```bash
cw start
```

### `cw stop`

Stop the running node gracefully.

```bash
cw stop
```

### `cw server`

Manage saved remote server connections.

```bash
cw server add my-gpu ws://gpu-host:9100 --token <token>   # Save a server
cw server remove my-gpu                                    # Remove it
cw server list                                             # List saved servers
```

Saved servers can be referenced by name with `--server`:

```bash
cw --server my-gpu list
cw --server my-gpu attach 1
```

## How It Works

Codewire is a single Go binary (`cw`) that acts as both node and CLI client.

**Node** (`cw node`): Listens on a Unix socket at `~/.codewire/codewire.sock`. Manages PTY sessions — each AI agent runs in its own pseudoterminal. The node owns the master side of each PTY and keeps processes alive regardless of client connections.

**Client** (`cw launch`, `attach`, etc.): Connects to the node's Unix socket. When you attach, the client puts your terminal in raw mode and bridges your stdin/stdout directly to the PTY. Your terminal emulator handles all rendering — that's why scrolling and copy/paste work natively.

**Logs**: All PTY output is teed to `~/.codewire/sessions/<id>/output.log` so you can review what happened while disconnected.

### Using Different AI Agents

Pass the exact command you want to run after `--`. No magic — what you type is what runs:

```bash
cw launch -- claude -p "fix the bug"              # Claude Code
cw launch -- aider --message "fix the bug"         # Aider
cw launch -- goose run                             # Goose
cw launch -- codex "refactor auth"                 # Codex
```

### Wire Protocol

Communication between client and node uses a frame-based binary protocol over the Unix socket:

- Frame format: `[type: u8][length: u32 BE][payload]`
- Type `0x00`: Control messages (JSON) — launch, list, attach, detach, kill, resize
- Type `0x01`: Data messages (raw bytes) — PTY I/O

### Data Directory

```
~/.codewire/
├── codewire.sock         # Unix domain socket
├── codewire.pid          # Node PID file
├── token                 # Auth token (for direct WS fallback)
├── config.toml           # Configuration (optional)
├── servers.toml          # Saved remote servers (optional)
├── sessions.json         # Session metadata
└── sessions/
    ├── 1/
    │   ├── output.log    # Captured PTY output
    │   └── events.jsonl  # Metadata event log
    └── 2/
        ├── output.log
        └── events.jsonl
```

### Configuration

All settings via `~/.codewire/config.toml` or environment variables:

```toml
[node]
name = "my-node"                          # CODEWIRE_NODE_NAME
listen = "0.0.0.0:9100"                   # CODEWIRE_LISTEN — direct WebSocket (optional)
external_url = "wss://host/ws"            # CODEWIRE_EXTERNAL_URL
relay_url = "https://relay.codewire.sh"  # CODEWIRE_RELAY_URL — opt-in remote access
```

When no config file exists, codewire runs in standalone mode (Unix socket only, no relay).

## Remote Access (SSH Relay)

Codewire uses an SSH gateway for remote access. Nodes establish persistent WebSocket connections to a relay server — no root required, works behind NAT.

### Quick Setup

```bash
# Register your node with a relay
cw relay setup https://relay.codewire.sh

# Or with an invite token
cw relay setup https://relay.codewire.sh <token>

# That's it. Your node is now accessible remotely via SSH.
```

The setup flow registers the node, receives a node token, and persists the relay config. The node then maintains a persistent WebSocket connection to the relay.

### Remote Commands

All commands accept an optional node prefix for remote access:

```bash
# Local (no prefix)
cw list                                    # Local sessions
cw attach 3                                # Local session

# Remote (node prefix)
cw nodes                                   # List all nodes from relay
cw list dev-1                              # Sessions on dev-1
cw attach dev-1:3                          # Session 3 on dev-1
cw launch dev-1 -- claude -p "fix bug"     # Launch on dev-1
cw kill dev-1:3                            # Kill on dev-1
```

### Direct WebSocket (alternative)

You can also connect directly via WebSocket without a relay:

```bash
cw server add my-server wss://remote-host:9100 --token <token>
cw --server my-server list
cw --server my-server attach 1
```

### Architecture

```
                          INTERNET
                             |
                    +--------+--------+
                    |   cw relay      |
                    | HTTPS :443      |  <- Clients connect here
                    | SSH  :2222      |  <- SSH into any node
                    | /node/connect   |  <- Nodes connect here (WS)
                    +--------+--------+
                        |         |
           WS agent     |         |   WS agent
           (outbound)   |         |   (outbound)
                        |         |
                +-------+--+  +---+-------+
                | cw node  |  | cw node   |
                | "dev-1"  |  | "gpu-box" |
                +----------+  +-----------+
```

- **Relay** = SSH gateway + HTTP API (node discovery, shared KV, device auth)
- **Nodes** = connect outward via persistent WebSocket agents (no inbound ports needed)
- **Clients** = SSH into `<node>@relay:2222`; same PTY experience

### Local Development (Docker Compose)

The repo includes a Docker Compose stack:

- **Relay** — SSH gateway + HTTP API on `localhost:8080`
- **Caddy** — TLS reverse proxy on `localhost:9443` with wildcard subdomain support
- **Codewire** — containerized node (`docker-test`) on `localhost:9100`

```bash
# Start the stack
docker compose up -d --build

# List nodes
cw nodes

# Tear down
docker compose down
```

## Deployment

### Helm Chart (Kubernetes)

```bash
helm install my-relay oci://ghcr.io/codewiresh/charts/codewire-relay \
  --set relay.baseURL=https://relay.example.com
```

See [`charts/codewire-relay/values.yaml`](charts/codewire-relay/values.yaml) for full configuration. Verify with `helm test my-relay`.

### Kubernetes Operator

For multi-tenant clusters or automated provisioning. Install the operator, then create a `CodewireRelay` CR:

```bash
kubectl apply -f operator/config/crd/codewire.io_codewirerelays.yaml
kubectl apply -f operator/config/manager/deployment.yaml
```

```yaml
apiVersion: codewire.io/v1alpha1
kind: CodewireRelay
metadata:
  name: production
spec:
  baseURL: https://relay.example.com
  authMode: token
  ingress:
    className: nginx
```

### systemd (VPS / Bare Metal)

```bash
# Install the binary
curl -fsSL https://codewire.dev/install.sh | sh

# Configure
sudo cp deploy/systemd/codewire-relay.service /etc/systemd/system/
sudo cp deploy/systemd/codewire-relay.env /etc/codewire-relay/env
sudo editor /etc/codewire-relay/env  # set CW_BASE_URL, CW_AUTH_TOKEN

# Start
sudo systemctl enable --now codewire-relay
```

### Docker Compose

See [Local Development (Docker Compose)](#local-development-docker-compose) above for a ready-to-use `docker-compose.yml`.

## LLM Orchestration

CodeWire is designed for LLM-driven multi-agent workflows. Tags, subscriptions, and wait provide structured coordination primitives.

### Tags

Label sessions at launch for filtering and coordination:

```bash
cw launch --tag worker --tag build -- claude -p "fix tests"
cw launch --tag worker --tag lint -- claude -p "fix lint issues"

# List sessions by tag (via MCP or API)
# Kill all workers
cw kill --tag worker
```

### Subscribe to Events

Stream structured events from sessions:

```bash
# Watch all status changes for "worker" sessions
cw subscribe --tag worker --event session.status

# Subscribe to all events from session 3
cw subscribe --session 3
```

Event types: `session.created`, `session.status`, `session.output_summary`, `session.input`, `session.attached`, `session.detached`, `direct.message`, `message.request`, `message.reply`

### Wait for Completion

Block until sessions finish — replaces polling:

```bash
# Wait for session 3 to complete
cw wait 3

# Wait for ALL workers to complete
cw wait --tag worker --condition all

# Wait for ANY worker to complete, 60s timeout
cw wait --tag worker --condition any --timeout 60
```

### Multi-Agent Patterns

**Supervisor pattern** — one orchestrator coordinates workers:

```bash
# Launch tagged workers
cw launch --tag worker -- claude -p "implement feature X"
cw launch --tag worker -- claude -p "write tests for X"

# Wait for all workers to finish
cw wait --tag worker --condition all --timeout 300

# Check results
cw list
```

**Agent messaging** — named agents exchanging structured messages:

```bash
# Launch named agents
cw launch planner -- claude -p "plan the refactor"
cw launch coder -- claude -p "implement changes"

# Send a direct message
cw msg -f planner coder "start with the auth module"

# Request/reply — synchronous coordination
cw request -f planner coder "ready for review?"
# [reply from coder] yes, PR #42 is up

# Monitor all message traffic
cw listen
```

**Agent swarms** — parallel agents with cross-session communication:

```bash
cw launch --tag backend -- claude -p "optimize queries"
cw launch --tag frontend -- claude -p "optimize bundle"

# Send coordination message
cw send 1 "Backend ready for integration"

# Monitor in real-time
cw watch 2 --tail 100
```

**Multiple attachments** — multiple clients can attach to the same session:

```bash
# Terminal 1
cw attach 1

# Terminal 2 (both see output)
cw attach 1
```

## Claude Code Integration

### Skill (recommended)

Install the codewire skill so Claude Code knows how to use `cw` for session management:

```bash
curl -fsSL https://raw.githubusercontent.com/codewiresh/codewire/main/.claude/skills/install.sh | bash
```

This installs two skills to `~/.claude/skills/`:
- **codewire** — teaches Claude Code to launch, monitor, and coordinate sessions
- **codewire-dev** — development workflow for contributing to the codewire codebase

### MCP Server (optional)

For programmatic tool access, add CodeWire as an MCP server:

```bash
# User-level (available in all projects)
claude mcp add --scope user codewire -- cw mcp-server

# Or project-level
claude mcp add codewire -- cw mcp-server
```

This exposes 18 tools:

| Tool | Description |
|------|-------------|
| `codewire_launch_session` | Launch new session (with name and tags) |
| `codewire_list_sessions` | List sessions with enriched metadata |
| `codewire_read_session_output` | Read output snapshot |
| `codewire_send_input` | Send input to a session |
| `codewire_watch_session` | Monitor session (time-bounded) |
| `codewire_get_session_status` | Get detailed status (exit code, duration, etc.) |
| `codewire_kill_session` | Terminate session (by ID or tags) |
| `codewire_subscribe` | Subscribe to session events |
| `codewire_wait_for` | Block until sessions complete |
| `codewire_msg` | Send a direct message to a session |
| `codewire_read_messages` | Read messages from a session's inbox |
| `codewire_request` | Send a request and block for reply |
| `codewire_reply` | Reply to a pending request |
| `codewire_list_nodes` | List nodes from relay |
| `codewire_kv_set` | Set key-value (shared KV store) |
| `codewire_kv_get` | Get value by key |
| `codewire_kv_list` | List keys by prefix |
| `codewire_kv_delete` | Delete key |

## Contributing

```bash
# Build
make build

# Run unit tests
make test

# Run all tests (unit + integration)
go test ./internal/... ./tests/... -timeout 120s

# Lint
make lint

# Manual CLI test
make test-manual

# Run with debug logging
cw node  # slog outputs to stderr by default
```

## Security

Release binaries are signed with GPG. The public key is committed to this repository at [`GPG_PUBLIC_KEY.asc`](GPG_PUBLIC_KEY.asc).

To verify a release:

```bash
# Import the public key
curl -fsSL https://raw.githubusercontent.com/codewiresh/codewire/main/GPG_PUBLIC_KEY.asc | gpg --import

# Verify checksums signature
gpg --verify SHA256SUMS.asc SHA256SUMS

# Verify binary checksum
sha256sum --check --ignore-missing SHA256SUMS
```

## License

MIT

---
Latest release: v0.2.26 — 2026-02-21
