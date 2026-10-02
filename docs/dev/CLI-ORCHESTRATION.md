# CLI sessions and agent orchestration

The CLI uses an environment as the execution placement and a durable session
as the process identity. Session names are unique within an environment;
commands resolve an exact ID before a name. `cw list --all` inventories
accessible environments and reports unavailable targets as errors.

## Placements

| Placement | Create | Terminal sessions | Managed agents |
| --- | --- | --- | --- |
| Trusted Linux host | `--local --type host` | Owner daemon and private Unix socket | Codex and Claude |
| Native Linux sandbox | `--local --type sandbox` | Native supervisor and guest daemon | Codex/Claude implementation; VM qualification pending |
| Platform sandbox | `--platform --type sandbox` | Authenticated platform API | Qualification pending |
| macOS host or sandbox | Separate hardware qualification | See Program #2064 | Qualification pending |

```sh
cw env create --local --type host --name host-team --path .
cw env create --local --type sandbox --name vm-team --path .
cw env create --platform --type sandbox --name cloud-team --repo REPOSITORY_URL
```

A trusted host runs as the local user with their ordinary HOME and installed
tools. Its daemon uses a dedicated state directory, outside the workspace by
default; `CW_HOST_DATA_DIR` selects another registry location. It provides
owned process cleanup, not filesystem or network containment. Stop and remove
retire its owned runtime; they preserve the workspace. Linux is the admitted host
implementation. Other hosts fail before creation effects.

Native sandboxes retain their protected credential and workspace contracts.
Creating a host does not copy authentication files into a sandbox.

Managed Linux VM sessions require a selected local credential profile with a
typed Codex or Anthropic provider. Provider material stays in the host broker;
the guest receives its generated proxy configuration. VM sessions use the same
`run --agent`, `msg`, `steer`, `interrupt`, `inbox` and `wait --message` commands.
Their parent must be a running managed session in the same VM. A worker writes
one deterministic notification into that parent's private inbox; the parent
adopts it when idle or after restart. Guest agents do not have authority to
launch sessions through the host CLI.

Managed native shutdown is durable: if the local `cw stop` caller is cancelled,
the driver can still finish cleanup. Run `cw stop` again to join that operation.
`cw restart` waits for confirmed child cleanup and driver exit, then compares the
selected launch generation at the daemon. If another caller has replaced that
launch, the request fails before stopping the replacement. JSON session output
includes `launch_generation`; zero means the daemon does not support this fence.
Missing or stale custody records prevent managed restart. An interrupted active
turn stays unknown and is never replayed automatically.

## Ordinary commands

Use the same session commands with `host-team`, `vm-team`, or `cloud-team`:

```sh
cw run host-team --name tests --detach --no-tty -- make test
cw list host-team
cw list --all
cw wait host-team tests --timeout 10m
cw logs host-team tests
cw stop host-team tests
cw restart host-team tests
```

`wait` succeeds only after observed zero exit, confirmed cleanup and drained
output EOF. Timeouts,
nonzero exits, interrupted processes and unknown cleanup return failure.
Output retains its absolute cursor across reconnects and restarts. A history
gap is reported rather than silently treated as complete output.

For an interactive shell:

```sh
cw run host-team --name shell --tty --detach -- sh
cw send host-team shell 'pwd'
cw send host-team shell 'partial text' --no-newline
cw send host-team shell --key enter
cw send host-team shell --key ctrl-c
cw attach host-team shell
```

`send` acknowledges a bounded write to stdin. It does not prove that a shell
command finished. Use a separate `run` and `wait` when command completion is
needed. Input is never automatically resent after an ambiguous write.

Inline `run --env NAME=VALUE` overrides stay with the live daemon owner. They
are absent from saved session metadata. After daemon recovery, restart refuses
sessions requiring those unavailable values; launch a new session with fresh
overrides. Environment-owned application projections continue to use their
existing source and delivery contracts.

## Orchestrator and workers on a host

```sh
cw run host-team --name lead --agent codex --model gpt-6.1-sol \
  --effort max --detach --prompt 'Coordinate the assigned work.'
cw run host-team --name runtime --parent lead --agent claude \
  --model claude-opus-5-5 --effort xhigh --detach \
  --prompt 'Implement the assigned runtime slice and report the result.'
cw run host-team --name review --parent lead --agent codex \
  --model gpt-6.1-sol --effort max --detach \
  --prompt 'Review the runtime change without editing it.'

cw msg host-team runtime 'Cover the failed-start recovery case too.'
cw inbox host-team lead
cw wait --message MESSAGE_ID --timeout 10m
cw steer host-team review 'Focus on ownership and cleanup.' --turn-id TURN_ID
cw interrupt host-team runtime
cw stop host-team runtime
cw restart host-team runtime
```

Agent launches with `--prompt` and message commands return durable message
IDs. `msg` sends a semantic task, follow-up or reply to the native agent protocol.
A raw terminal write is refused for managed sessions. Parents are bound to canonical session
and driver identities in the same host environment; an unmanaged process
cannot receive semantic worker results.

```mermaid
flowchart LR
    CLI[cw run / msg] --> Daemon[Host session daemon]
    Daemon --> Worker[Managed driver + native worker]
    Worker --> Result[Durable result and parent inbox]
    Result --> Lead[Managed lead driver]
    Lead --> Turn[Native lead turn]
    Turn --> CLI
```

An idle parent starts a turn when a worker completes. A busy parent queues the
notification. A stopped parent adopts it after restart. Deterministic message
identities prevent duplicate admission. Recovery repairs a missing result
notification without replaying a completed or ambiguous provider task.

| Provider | Receiver | Mid-turn steering | Interrupt | Resume |
| --- | --- | --- | --- | --- |
| Codex | App Server stdio | `turn/steer`, expected turn required | Native turn control | Saved thread ID |
| Claude | CLI stream JSON | Explicitly unsupported | Advertised after native control probe | Saved session UUID |
| Kimi | ACP adapter planned | Qualification pending | Qualification pending | Qualification pending |

Managed Codex uses `danger-full-access` and `approvalPolicy: never` on the
explicitly trusted host. Claude retains the installed CLI's settings and
permission rules. Neither adapter copies login material. Claude supports
`low`, `medium`, `high`, `xhigh`, and `max`; omitting effort preserves its
configured default.

No additional MCP server is needed to receive these messages. A native protocol
driver owns delivery and completion. A foreground controller can forward
terminal events to its coordinating session; this does not establish an
unattended wake interface for the Codex application.

## Mesh members

Today `cw mesh up/status/down` manages a local Mesh service, and
`cw network create/join/nodes/use` manages network membership. Native sandbox
peers have the existing WireGuard direct/relay transport and declared ingress.
These commands do not expose a host session daemon for remote execution.

The next member-control design is in
[CLI delivery backlog](plans/2026-09-29-cli-delivery-backlog.md).
Proposed member selectors and remote grants there are future UX.

## Install local execution

Install the production host CLI before creating environments or sessions that
you intend to retain:

```sh
make cli-install-user
```

Trusted hosts use that installed executable and the user's ordinary agent
tools. Native Linux VMs also need durable base artifacts, their matching lock
file, and the static managed guest runtime. Keep those inputs outside a
disposable worktree. The base defaults are
`$HOME/.cache/codewire/local-vmm-v1/artifacts` and the adjacent
`artifacts.lock.json`; `CODEWIRE_NATIVE_ARTIFACT_ROOT` and
`CODEWIRE_NATIVE_ARTIFACT_LOCK` select absolute alternatives that share one
parent directory.

Build the static runtime, then its minimal OCI image, in fresh owned directories:

```sh
scripts/dev/build-native-managed-agent.py \
  --rust-tools /absolute/path/to/rust/toolchain/bin \
  --protoc /absolute/path/to/protoc \
  --output /absolute/fresh/owned/cw-build
python3 scripts/dev/cw-runtime-image.py build \
  --artifact /absolute/fresh/owned/cw-build/managed-agent-cw.json \
  --output /absolute/fresh/owned/cw-image
```

The image contains only static Linux/amd64 `cw` and public build provenance.
It is an OCI image with one uncompressed layer; this local producer neither
executes the image nor publishes it. Its external `image.json` receipt pins
the index, manifest and payload. Pass the image and index pin to
`scripts/ci/verify/build-local-vmm-initramfs.sh --verify-root` using
`--cw-image /absolute/fresh/owned/cw-image/cw.oci.tar` and
`--cw-image-index-sha256 <index_sha256 from image.json>`, alongside the required
BusyBox/runc inputs. Include the resulting initramfs's exact digest and size
in the matching base artifact lock before installing those durable inputs.

Every VM boot exposes that image payload at
`/run/codewire-runtime/cw/<cw_sha256>/cw`, on a read-only root-owned system
mount outside HOME. Managed launches do not upload or install a helper. The
host selects the expected image from the VM UUID's retained boot generation;
each invocation verifies and seals the selected bytes before execution. The
workspace still needs the checked-in `/usr/bin/python3` launcher prerequisite.
Conversation journals remain private to the workload user under HOME.

A changed global image or artifact lock does not change an existing VM's
retained runtime on restart. Missing retained bytes refuse recovery without
replaying a task. Keep the durable base inputs outside disposable worktrees.
Stop task-owned daemons and retire task-only environments before deleting their
executable paths. Retained host managed sessions still need the original `cw`
path after daemon shutdown; preserve that executable and their state.

## Verification

```sh
scripts/dev/test-cli-host.py --cw target/debug/cw
scripts/dev/test-cli-host.py --cw target/debug/cw --native-agents
```

The first journey uses independent synthetic native peers and owned runtime
fixtures. It covers input, names, process ownership, parent wake, native
controls, durable outbox recovery, startup failure, and launch projection
recovery. The second uses ordinary installed Codex/Claude login and observes
conversation resume, Claude xhigh and a resumed lead invoking `cw` itself.
Neither replaces the matching native Linux hardware or retained Kind sandbox
journey. Program #2255 holds current commands, outcomes and landing evidence.

The managed VM journey runs the actual pinned guest agents through the
synthetic protected broker. Supply the image-derived initramfs described above,
then add `--managed-agent-sessions --managed-agent-cw-image-receipt
/absolute/cw-image/image.json` to the existing
`smoke-native-local-environment.sh --managed-credential-broker` command. Its
verified workspace OCI receipt and existing broker assertions remain required.
Before the first conversation, the journey observes root ownership, read-only
mount flags, image identity and payload digest. It then checks native
acknowledgement, two turns, resume, guest tool execution, held-turn controls,
parent continuation, history and cleanup. Custody cases exercise detached and
TERM-resistant tools, a cancelled stop caller, driver death, safe generation
admission, missing/stale receipt refusal and an unrelated sentinel. Provider
responses are synthetic; live provider enrollment remains under #1902.

Stalled provider initialization has a separate bounded isolated check:

```sh
scripts/dev/test-native-managed-startup.py --cw /absolute/candidate/cw
```

This runs the actual guest driver and control helper with synthetic stalled
peers on Linux. Its shutdown, startup-signal and custody assertions are focused
development proof; the VM journey remains required.
