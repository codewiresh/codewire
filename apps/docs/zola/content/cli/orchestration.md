---
title: Agent Orchestration
description: Launch a managed lead and workers, exchange tasks, and reconnect to durable sessions.
---

{% aside(kind="note") %}
  This is an unpublished private preview draft. Publication depends on the
  acceptance of #2255, #952, and #1914. Use an authorized preview checkout that
  includes the orchestration changes; these examples do not establish release
  availability or completed host, VM, platform, or live-provider qualification.
{% end %}

An environment owns its sessions. A managed session adds a native Codex or
Claude conversation to that process identity. A lead and its workers exchange
tasks and results through their durable message records.

## Install the private preview

From the authorized source checkout, choose an unused preview directory:

```bash
PREVIEW_DIR="$HOME/.local/share/codewire-preview"
mkdir -p "$HOME/.local/share"
mkdir -m 0700 "$PREVIEW_DIR"
make cli-build
apps/cli/cw install --managed --bin-dir "$PREVIEW_DIR/bin" \
  --store "$PREVIEW_DIR/cli-store"

export PATH="$PREVIEW_DIR/bin:$PATH"
export CW_HOST_DATA_DIR="$PREVIEW_DIR/hosts"
export CW_CONFIG_DIR="$PREVIEW_DIR/config"
cw --version
```

This uses the source installer with a separate managed version store, host
registry, and platform client configuration. Keep the executable and these
directories while retaining its environments. Restore the same exports when
opening another terminal.

For host agents, install Codex and Claude on your normal `PATH` and complete
their own sign-in setup. The host uses your ordinary HOME and installed tools.
See [Configuration](@/cli/configuration.md) for platform configuration.

## Choose an environment

Run the commands from the project directory. Choose one placement; subsequent
commands use its `ENV` value.

### Trusted Linux host

```bash
cw env create --local --type host --name host-team --path .
ENV=host-team
```

A host runs as your local user with access to that user's files and network.
Its owner daemon manages session processes through a private Unix socket.
Managed Codex uses `danger-full-access` with approvals disabled in this trusted
placement. Claude retains its installed CLI's permission settings.

### Native Linux VM

Install the matching native base artifacts and managed CW runtime bundle
provided with the preview first. Select an existing local credential profile
with the provider types needed by your agents; replace `local:agent-team` with
that profile's selector.

```bash
cw env create --local --type sandbox --name vm-team --path . \
  --profile local:agent-team
ENV=vm-team
```

The native supervisor owns the VM lifecycle and the guest daemon owns its
sessions. Launch the lead and workers through the host CLI. Their parent must
be a running managed session in this same VM.

As in a platform sandbox, a managed agent runs the workspace image's pinned
Codex or Claude Code, even after you update that CLI inside the VM; your
updated version is what your own terminal runs. On an image without the pinned
clients, such as a custom image, the managed agent runs the CLI on the VM's
PATH, and `cw run --agent` prints one line naming it and the reason.

In a VM or a platform sandbox, managed Claude starts in auto mode
(`--permission-mode auto`), so it can run tools such as Bash without a prompt.
It keeps the Sandbox user's Claude settings and permission rules; setting
`permissions.disableAutoMode` there turns auto mode off.

### Platform sandbox

Sign in and select your organization, then use your repository URL and an
existing platform credential profile with a credential for each agent. Codex
uses the profile's Codex credential (your ChatGPT sign-in or an API key), or
its OpenAI API key when it has no Codex credential. Claude uses its Anthropic
credential: an API key or a Claude subscription token. With a subscription
token from `claude setup-token`, managed and interactive turns work, but
Claude Code shows "Claude API" in place of your plan and `/usage` is not
available. Codewire adds the credential outside the Sandbox. A managed Codex
agent's own Codex home holds only the local route; a managed Claude agent uses
the Sandbox's own Claude settings and the same local route as your terminal:

```bash
cw setup
cw env create --platform --type sandbox --name cloud-team \
  --image workspace --repo "$REPO_URL" --profile platform:agent-team
ENV=cloud-team
```

The platform environment needs the preview's managed-agent runtime support.
See [Platform commands](@/cli/platform.md) for authentication and environment
management, and [Repository access](@/settings/github-integration.md) for its
repository boundary.

Credential profiles and application-secret sources are separate selections.
A profile authorizes provider-specific execution or proxying; application
secrets supply ordinary workload environment values. In a VM or a platform
sandbox a managed agent starts with the selected application secrets in its
environment, as a terminal session does. Keep provider credentials
out of task prompts and inline `--env` arguments. See
[Secrets](@/organizations/secrets.md) for the storage and delivery distinction.

## Launch a lead and two workers

```bash
cw run "$ENV" --name lead --agent codex --detach --output json \
  --prompt 'Coordinate the assigned change and review worker results.'
cw run "$ENV" --name implement --parent lead --agent codex \
  --detach --output json --prompt 'Implement the assigned change and report the result.'
cw run "$ENV" --name review --parent lead --agent claude \
  --detach --output json --prompt 'Review the assigned change without editing files.'

cw list "$ENV" --output json
```

Omitting `--model` and `--effort` uses the adapter's defaults. Each launch
returns a session ID; a launch with `--prompt` also returns a message ID.
Save those IDs. Names are unique within the environment, and the parent is
bound to that environment's managed session and driver.

## Send a task and read the result

```bash
cw msg "$ENV" implement 'Include the failed-start recovery case.' --output json
cw inbox "$ENV" implement --output json
cw inbox "$ENV" lead --output json
```

Set `MESSAGE_ID` to the message ID returned by `msg` for the task you want to
observe:

```bash
cw wait --message "$MESSAGE_ID" --timeout 10m --output json
```

`msg` sends a semantic task, follow-up, or reply. A completed worker task
creates a deterministic result notification in the parent's inbox. An idle
lead adopts it; a busy lead queues it; a stopped lead can adopt it after
restart. Deterministic notification IDs prevent duplicate admission.

Waits are bounded. A timeout or unknown result returns failure. Reconnect and
inspect the original message before deciding what to do next. Recovery does
not automatically replay completed or ambiguous provider work.

## Steer or interrupt an active turn

Inspect the worker's inbox for `.driver.current_turn_id` and advertised
capabilities. Set `TURN_ID` to that active Codex turn before steering:

```bash
cw inbox "$ENV" implement --output json
cw steer "$ENV" implement 'Focus on ownership and cleanup.' \
  --turn-id "$TURN_ID" --output json
cw interrupt "$ENV" implement --output json
```

Codex steering requires the expected active turn. Claude steering is
unsupported. Claude interruption is available only when its native control
probe advertises it. An idle or unsupported control is refused. `steer` and
`interrupt` return only after the provider accepts or refuses the control, so
a nonzero exit means it did not apply.

## Run a terminal command

Use an ordinary session when you need a command's exit status:

```bash
cw run "$ENV" --name terminal-check --detach --no-tty -- printf 'TERMINAL_OK\n'
cw wait "$ENV" terminal-check --timeout 10s
cw logs "$ENV" terminal-check
```

`wait` succeeds after observed zero exit, confirmed cleanup, and drained
output. For an interactive shell:

```bash
cw run "$ENV" --name shell --tty --detach -- sh
cw send "$ENV" shell 'pwd'
cw attach "$ENV" shell
```

Detach with `Ctrl+B d`, then run `cw attach "$ENV" shell` again to reconnect.
`send` acknowledges a write to terminal stdin; use `run` and `wait` for command
completion. Managed agents accept `msg`, `steer`, and `interrupt`; raw `send`
and key input are refused for those sessions.

See [Sessions](@/cli/sessions.md) for attachment and log options.

## Reconnect, cancel, and resume

Closing a CLI connection leaves the environment's durable sessions available:

```bash
cw list "$ENV"
cw logs "$ENV" implement
cw inbox "$ENV" implement --output json
```

Use `interrupt` to end an active agent turn. Use `stop` to cancel the whole
session, then `restart` to resume its retained conversation:

```bash
cw stop "$ENV" implement --output json
cw restart "$ENV" implement --output json
```

Restart requires confirmed cleanup of the original launch. An interrupted turn
can remain unknown; restarting the conversation does not resubmit that task.
For a native VM, repeat an interrupted `stop` to join its durable cleanup
operation. Restart is refused when the saved process identity is missing or
no longer matches.

For a platform sandbox, keep the original request UUID printed after a lost
reply. Set `ORIGINAL_REQUEST_ID` to that UUID and observe it without resending
its operation:

```bash
cw env agent observe "$ENV" --request-id "$ORIGINAL_REQUEST_ID" --output json
```

If the original operation remains unknown and prevents further control, use
a fresh Stop request linked to that operation. The CLI generates a new Stop
request UUID and pins the selected session's launch generation:

```bash
cw stop "$ENV" implement --cleanup-request-id "$ORIGINAL_REQUEST_ID" --output json
```

Confirm that cleanup completed before restarting. Retain the original task's
unknown result; cleanup does not authorize replaying it.

A managed conversation in a platform sandbox stops with the sandbox. After
Start, `cw list` still shows it, and `cw msg` or `cw restart` resumes it in the
new sandbox first: its agent starts again from its saved session, with its
earlier turns, and the message goes to it. What was in flight when the sandbox
stopped is not replayed; the agent may see an interrupted step and redo it.
`cw wait --message` for a message sent before the Stop says that it ended with
the environment.

A conversation waits, and `cw msg` says to try again shortly, while:

- the sandbox's previous Pod is still stopping;
- another resume of it is already starting in this sandbox;
- its agent is still running in this sandbox.

A conversation cannot resume, and `cw msg` says why, when:

- the environment's selected credentials or secret sources changed since it
  started, or the agent's credential changed (for example from an API key to
  a sign-in);
- its working directory no longer exists in the sandbox;
- the sandbox's agent provider is not admitted for it;
- its last start, restart or resume has an unknown outcome;
- it is a child conversation (resume its parent instead).

Start a new conversation with `cw run "$ENV" --agent ...` then.

A launch that the platform refuses, for example because a selected secret
source was removed, reports that it was refused: nothing was started or
changed, and it can be run again once the cause is fixed.

## Control an enrolled trusted member

Use an already-enrolled Linux member whose exact control and WireGuard keys,
environment UUID, and required execution grants have been pinned by its owner.
The example alias is `build-linux`. See [Mesh](@/cli/mesh.md) for networks and
enrollment.

```bash
cw member info build-linux --output json
cw --member build-linux list --output json
cw --member build-linux run --name lead --agent codex --detach \
  --output json --prompt 'Coordinate the assigned change.'
```

Save the returned canonical `session-UUID` as `LEAD_ID`. Use canonical IDs
for member session controls and parents:

```bash
cw --member build-linux run --name implement --parent "$LEAD_ID" \
  --agent codex --detach --output json --prompt 'Implement the assigned change.'
cw --member build-linux run --name review --parent "$LEAD_ID" \
  --agent claude --detach --output json --prompt 'Review the assigned change.'
cw --member build-linux list --output json
```

Save the implement worker's canonical ID as `WORKER_ID`. Its lead and workers
must belong to the member's same pinned environment:

```bash
cw --member build-linux msg "$WORKER_ID" 'Include the recovery case.' --output json
cw --member build-linux inbox "$LEAD_ID" --output json
```

Set `MESSAGE_ID` to the returned member message ID, then observe that task:

```bash
cw --member build-linux wait --message "$MESSAGE_ID" --timeout 10m --output json
cw --member build-linux logs "$WORKER_ID"
```

Member steering and interruption follow the same provider capabilities above.
Ordinary member commands use `run --no-tty -- COMMAND`, `wait`, and `logs`;
member PTY attachment is unsupported. Parent notifications stay within the
member's environment. A coordinator on another host reads that inbox explicitly.

For a control operation, retain its original request UUID and positive launch
generation. Choose `REQUEST_ID` before the single control call and read
`LAUNCH_GENERATION` from the original session's JSON record. If its reply is
lost, observe that same request:

```bash
cw --member build-linux stop "$WORKER_ID" --request-id "$REQUEST_ID" \
  --expected-launch-generation "$LAUNCH_GENERATION" --output json
cw member observe build-linux "$REQUEST_ID" --output json
```

Observation does not resend the mutation. Environment lifecycle and updater
operations run on the member owner; `--member` does not provide those controls.

## Clean up this journey

Stop the sessions you created before retiring their environment:

```bash
cw stop "$ENV" implement
cw stop "$ENV" review
cw stop "$ENV" lead
cw stop "$ENV" shell
cw env stop "$ENV"
cw env rm "$ENV"
```

For a trusted host, environment removal preserves the project directory.
For member sessions, use their canonical IDs with `--member` and let that
member's owner manage its environment lifecycle.
