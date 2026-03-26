# MCP Server

Codewire exposes an [MCP](https://modelcontextprotocol.io/) server so AI agents (Claude Code, Cursor, etc.) can manage sessions programmatically.

## Quick Start

Register the server with Claude Code:

```bash
claude mcp add --scope user codewire -- cw mcp-server
```

That's it. Claude Code will now have access to all Codewire tools.

## Prerequisites

**Session tools** require a running Codewire node:

```bash
cw node          # foreground
cw node -d       # background (daemonize)
```

The node auto-starts on most `cw` commands, but the MCP server itself does not auto-start a node -- it connects to the existing Unix socket at `~/.codewire/codewire.sock`.

**Environment tools** only require `cw login` (they use the Codewire platform API directly, no local node needed).

## Tool Reference

### Session Management

#### `codewire_list_sessions`

List all Codewire sessions with their status.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `status_filter` | string | no | `"all"` | Filter by status: `"all"`, `"running"`, or `"completed"` |

#### `codewire_launch_session`

Launch a new Codewire session with optional name and tags for grouping and filtering.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `command` | string[] | **yes** | — | Command and arguments to run |
| `working_dir` | string | no | current dir | Working directory |
| `name` | string | no | — | Unique name for the session (alphanumeric + hyphens, 1-32 chars) |
| `tags` | string[] | no | — | Tags for grouping/filtering (e.g. `["worker", "build"]`) |

#### `codewire_kill_session`

Terminate a running session by ID or by tag filter.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `session_id` | integer | no | — | The session ID to kill (optional if tags provided) |
| `tags` | string[] | no | — | Kill all sessions matching these tags |

At least one of `session_id` or `tags` must be provided.

#### `codewire_get_session_status`

Get detailed status information for a session.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `session_id` | integer | **yes** | — | The session ID to query |

#### `codewire_read_session_output`

Read output from a session (snapshot, not live).

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `session_id` | integer | **yes** | — | The session ID to read from |
| `tail` | integer | no | — | Number of lines to show from end |
| `max_chars` | integer | no | `50000` | Maximum characters to return |

#### `codewire_send_input`

Send input to a session without attaching.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `session_id` | integer | **yes** | — | The session ID to send input to |
| `input` | string | **yes** | — | The input text to send |
| `auto_newline` | boolean | no | `true` | Automatically add newline |

### Live Monitoring

#### `codewire_watch_session`

Monitor a session in real-time (time-bounded). Connects to the session and collects output until the duration expires or the session completes.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `session_id` | integer | **yes** | — | The session ID to watch |
| `include_history` | boolean | no | `true` | Include recent history |
| `history_lines` | integer | no | `50` | Number of history lines to include |
| `max_duration_seconds` | integer | no | `30` | Maximum watch duration in seconds |

#### `codewire_subscribe`

Subscribe to session events (returns events as they arrive, time-bounded).

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `session_id` | integer | no | — | Filter by session ID |
| `tags` | string[] | no | — | Filter by tags |
| `event_types` | string[] | no | — | Filter by event type (`session.created`, `session.status`, etc.) |
| `max_duration_seconds` | integer | no | `30` | Maximum subscription duration in seconds |

### Blocking / Sync

#### `codewire_wait_for`

Block until session(s) complete. Returns enriched session info when done.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `session_id` | integer | no | — | Wait for this session ID to complete |
| `tags` | string[] | no | — | Wait for sessions matching these tags |
| `condition` | string | no | `"all"` | Wait condition: `"all"` or `"any"` |
| `timeout_seconds` | integer | no | `300` | Timeout in seconds |

### Messaging

#### `codewire_msg`

Send a direct message to a session.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `to_session_id` | integer | no | — | Recipient session ID |
| `to_name` | string | no | — | Recipient session name |
| `from_session_id` | integer | no | — | Sender session ID |
| `body` | string | **yes** | — | Message body |

At least one of `to_session_id` or `to_name` should be provided to target a specific session.

#### `codewire_read_messages`

Read messages from a session's inbox. Includes pending requests at the top.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `session_id` | integer | no | — | Session ID to read inbox of |
| `tail` | integer | no | `20` | Number of messages to return |

#### `codewire_request`

Send a request to a session and block until a reply is received.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `to_session_id` | integer | no | — | Recipient session ID |
| `to_name` | string | no | — | Recipient session name |
| `from_session_id` | integer | no | — | Sender session ID |
| `body` | string | **yes** | — | Request body |
| `timeout_seconds` | integer | no | `60` | Timeout in seconds |

#### `codewire_reply`

Reply to a pending request.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `request_id` | string | **yes** | — | The request ID to reply to |
| `body` | string | **yes** | — | Reply body |
| `from_session_id` | integer | no | — | Session ID sending the reply |

### Network / Relay

#### `codewire_list_nodes`

List all registered nodes from the relay. Requires relay to be configured (`cw relay setup <relay-url>`).

No parameters.

### Key-Value Store

These tools require a relay connection. The KV store is shared across all nodes in a network.

#### `codewire_kv_set`

Set a key-value pair in the shared relay store.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `key` | string | **yes** | — | The key to set |
| `value` | string | **yes** | — | The value to store |
| `namespace` | string | no | `"default"` | Namespace |
| `ttl` | string | no | — | Time-to-live as Go duration (e.g. `"60s"`, `"5m"`) |

#### `codewire_kv_get`

Get a value from the shared relay store.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `key` | string | **yes** | — | The key to get |
| `namespace` | string | no | `"default"` | Namespace |

#### `codewire_kv_list`

List keys from the shared relay store.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `prefix` | string | no | — | Key prefix to filter by |
| `namespace` | string | no | `"default"` | Namespace |

#### `codewire_kv_delete`

Delete a key from the shared relay store.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `key` | string | **yes** | — | The key to delete |
| `namespace` | string | no | `"default"` | Namespace |

### Environment Management

#### `codewire_list_environments`

List environments in the default organization.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `type` | string | no | -- | Filter: `"coder"` or `"sandbox"` |
| `state` | string | no | -- | Filter by state (e.g. `"running"`, `"stopped"`) |
| `include_destroyed` | boolean | no | `false` | Include destroyed environments |

#### `codewire_create_environment`

Create a new environment. Specify `preset_id`/`preset_slug` for a preset, or `image` for a custom container.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `preset_id` | string | no | -- | Preset ID |
| `preset_slug` | string | no | -- | Preset slug (e.g. `"go"`, `"node"`) |
| `image` | string | no | -- | Container image (e.g. `"python:3.12"`) |
| `name` | string | no | -- | Environment name |
| `ttl` | string | no | -- | Time to live (e.g. `"1h"`, `"30m"`) |
| `cpu` | integer | no | -- | CPU in millicores |
| `memory` | integer | no | -- | Memory in MB |
| `disk` | integer | no | -- | Disk in GB |
| `repo_url` | string | no | -- | Git repository URL to clone |
| `branch` | string | no | -- | Git branch |
| `install_command` | string | no | -- | Post-clone install command |
| `startup_script` | string | no | -- | Startup script |
| `agent` | string | no | -- | AI agent (e.g. `"claude-code"`) |
| `env_vars` | object | no | -- | Environment variables |
| `secret_project` | string | no | -- | Secret project to bind |
| `include_org_secrets` | boolean | no | `true` | Include org secrets |
| `include_user_secrets` | boolean | no | `true` | Include user secrets |
| `network` | string | no | -- | Relay network to join |

At least one of `preset_id`, `preset_slug`, or `image` is required.

#### `codewire_get_environment`

Get detailed environment information.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `environment_id` | string | **yes** | The environment ID |

#### `codewire_start_environment` / `codewire_stop_environment` / `codewire_delete_environment`

Start, stop, or permanently delete an environment.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `environment_id` | string | **yes** | The environment ID |

#### `codewire_exec_in_environment`

Execute a command in a running sandbox environment.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `environment_id` | string | **yes** | -- | The environment ID |
| `command` | string[] | **yes** | -- | Command and arguments |
| `working_dir` | string | no | `"/workspace"` | Working directory |
| `timeout` | integer | no | `30` | Timeout in seconds |

#### `codewire_list_files`

List files in a directory in a running sandbox.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `environment_id` | string | **yes** | -- | The environment ID |
| `path` | string | no | `"/workspace"` | Directory path |

#### `codewire_upload_file`

Upload a file to a running sandbox.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `environment_id` | string | **yes** | The environment ID |
| `path` | string | **yes** | Remote file path |
| `content` | string | **yes** | File content as text |

#### `codewire_download_file`

Download a file from a running sandbox. Returns content as text.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `environment_id` | string | **yes** | The environment ID |
| `path` | string | **yes** | Remote file path |

#### `codewire_get_environment_logs`

Get startup/provisioning logs for an environment.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `environment_id` | string | **yes** | The environment ID |

#### `codewire_list_presets`

List available environment presets.

No parameters.

## Common Workflows

### Create and use a sandbox

Create an environment, run commands, upload files, and clean up:

```
1. codewire_create_environment
     image: "python:3.12"
     name: "sandbox"
     ttl: "30m"

2. codewire_exec_in_environment
     environment_id: "<id from step 1>"
     command: ["python3", "--version"]

3. codewire_upload_file
     environment_id: "<id>"
     path: "/workspace/script.py"
     content: "print('hello')"

4. codewire_exec_in_environment
     environment_id: "<id>"
     command: ["python3", "/workspace/script.py"]

5. codewire_delete_environment
     environment_id: "<id>"
```

### Launch, watch, and read output

Launch a build, watch it live, then grab the full output when done:

```
1. codewire_launch_session
     command: ["make", "build"]
     name: "build"

2. codewire_watch_session
     session_id: 1
     max_duration_seconds: 60

3. codewire_read_session_output
     session_id: 1
     tail: 50
```

### Fan-out workers with tags + wait

Launch parallel workers tagged for batch cleanup, then wait for all to finish:

```
1. codewire_launch_session
     command: ["./worker.sh", "shard-1"]
     tags: ["batch-42", "worker"]

2. codewire_launch_session
     command: ["./worker.sh", "shard-2"]
     tags: ["batch-42", "worker"]

3. codewire_launch_session
     command: ["./worker.sh", "shard-3"]
     tags: ["batch-42", "worker"]

4. codewire_wait_for
     tags: ["batch-42"]
     condition: "all"
     timeout_seconds: 600

5. codewire_kill_session
     tags: ["batch-42"]          # cleanup any stragglers
```

### Request/reply between sessions

Use the request/reply pattern for synchronous inter-session communication:

```
1. codewire_launch_session
     command: ["python", "server.py"]
     name: "backend"

2. codewire_request
     to_name: "backend"
     body: "What is the current status?"
     timeout_seconds: 30

   # Blocks until the backend session replies.
   # Returns: "Reply from backend: All systems operational"
```

On the receiving side, the backend session reads its inbox with `codewire_read_messages` to see pending requests, then calls `codewire_reply` with the `request_id` from the message.

### Subscribe to events across sessions

Monitor lifecycle events across tagged sessions:

```
1. codewire_subscribe
     tags: ["batch-42"]
     event_types: ["session.status"]
     max_duration_seconds: 120

   # Returns a stream of events as sessions start, complete, or fail.
```
