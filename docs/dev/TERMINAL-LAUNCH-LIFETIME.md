# Durable terminal launch lifetime

Launch and Restart have a 40-second daemon request budget. Connection,
readiness and ordinary controls retain their five-second budgets. The longer
launch budget accommodates the existing 30-second environment-projection
authorization deadline; it does not renew or extend that authorization.

The session engine owns each admitted launch operation in a tracked task.
Dropping the requesting RPC cancels that attempt but does not drop its child,
cleanup or session-operation lock. A launch deadline also requests cooperative
cancellation rather than abandoning the operation. A queued attempt with no
child can cancel while waiting for retention admission or the operation lock.
Once Restart has dispatched Stop, it must await the previous monitor's
settlement before releasing serial ownership, even if its caller disappears.

Before the active monitor takes ownership, cancellation denies pending
projection and kills/reaps the exact daemon child with a bounded cleanup wait.
For Runc execution, the guest's workspace-exec trampoline also installs and
rechecks a SIGKILL parent-death binding before projection READY/COMMIT. Reaping
the Runc client confirms that exact parent's exit; it is not an independent
grandchild-reap acknowledgement or a guarantee about arbitrary forked process
trees. Managed-Runc commit/handoff verification remains separate from the
synthetic native projection fixture.

After handoff, caller loss deliberately does not terminate the running shell.
Disconnect releases an attachment; Stop explicitly terminates a session.
Reconnect attaches to the existing durable identity and output cursor rather
than creating a replacement process.

Private persisted cleanup flags distinguish reclaimable failures from
unresolved obligations. Every new attempt clears cleanup_confirmed and sets
cleanup_unknown until handoff or confirmed cleanup. Known pre-spawn failures
and confirmed reaps can become reclaimable Failed records. An unconfirmed
cleanup becomes Interrupted, blocks Restart and overrides retention eligibility
even if another state/flag would otherwise permit retirement. Existing records
default the new cleanup_unknown field to false; their prior retention rules
remain unchanged.

Server shutdown cancels launch admission and drains tracked owners with a
ten-second bound. Draining is not itself proof of cleanup: shutdown returns an
error if persisted session ownership remains unconfirmed. It does not claim
that all already-running durable shells have been stopped.

Focused verification uses the existing daemon library and projection fixture:

```sh
cargo test --locked -p codewire-daemon --lib
cargo test --locked -p codewire-daemon --test projection
cargo test --locked -p codewire-orchestration --lib api::environment_daemon::tests::launch_deadline_accounts_for_projection_without_relaxing_control_or_connect
```

The synthetic projection fixture covers real RPC/launcher/bridge cancellation,
late-response denial, delayed Launch/Restart projection, and server shutdown
while its exact projection response remains gated. These tests use synthetic
material and preserve the original authorization deadline.
