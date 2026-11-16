//! `workspace-flush`, the sidecar that flushes a Block workspace when its
//! Pod stops (#3718).

use serde_json::{Value, json};

use super::workspace::WORKSPACE_MOUNT_VOLUME;

/// The native sidecar that flushes a Block workspace when its Pod stops
/// (#3718, durability design §1).
pub(crate) const WORKSPACE_FLUSH_CONTAINER: &str = "workspace-flush";

/// `workspace-flush`: a sidecar (an init container with `restartPolicy:
/// Always`), so the kubelet stops it only after the workspace and DinD have
/// exited, and the VM is destroyed only after it returns. Without it, writes
/// still in guest memory are lost when the VM goes. It is unprivileged and
/// sees only the mounted workspace, as the workspace does.
pub(crate) fn workspace_flush_container(support_image: &str) -> Value {
    json!({
        "name": WORKSPACE_FLUSH_CONTAINER,
        "image": support_image,
        "restartPolicy": "Always",
        "securityContext": {
            "runAsUser": 1000, "runAsGroup": 1000, "runAsNonRoot": true,
            "allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true,
            "capabilities": { "drop": ["ALL"] },
        },
        "command": ["sh", "-c", WORKSPACE_FLUSH_SCRIPT],
        "volumeMounts": [
            { "name": WORKSPACE_MOUNT_VOLUME, "mountPath": "/mnt/ws", "mountPropagation": "HostToContainer" },
        ],
        "resources": {
            "requests": { "cpu": "5m", "memory": "8Mi" },
            "limits": { "cpu": "100m", "memory": "32Mi" },
        },
    })
}

/// A Block workspace Pod's termination grace period: `workspace-flush`'s bound plus
/// the workspace and DinD shutdowns before it (dockerd's own shutdown waits up
/// to 15 s), so the kubelet never kills a Pod mid-flush. Only a stop with that
/// much unwritten data ever waits this long; on Dev, a full dirty pool took
/// 4.2 s (8 GiB) and 8.0 s (32 GiB) from SIGTERM to the flush done.
pub(crate) const BLOCK_WORKSPACE_GRACE_SECONDS: u32 = 60;

/// `workspace-flush`'s shell. It waits for SIGTERM, then `syncfs` writes every
/// completed write of the workspace filesystem to the disk. ext4's journal
/// keeps the unmounted filesystem consistent, and `mount-workspace` checks it
/// at the next start. The guest keeps the kernel's writeback defaults (owner,
/// 2026-11-02: "If the sandbox crashes, the sandbox crashes"), so the flush
/// may have up to the default dirty limit to write: 6.22 GiB (6.68 GB) in the
/// largest, 32 GiB guest, measured on Dev (`nr_dirty_threshold`, #3718). At
/// the 327 MB/s the workspace disk was measured to write, that is 20.4 s;
/// with half again as margin, 30.6 s, so `syncfs` gets 35 s, inside the Pod's
/// [`BLOCK_WORKSPACE_GRACE_SECONDS`]. A failed or late flush is logged, and the
/// Pod still stops.
///
/// The bound is a watchdog that signals the shell, never a signal to `sync`
/// (#5089): a `sync` stuck in uninterruptible sleep on writeback holds TERM
/// and KILL alike, and `timeout` would go on waiting for it. A trapped signal
/// ends the shell's `wait`, so the flush reports a failure at 35 s and exits.
/// Nothing waits for the stuck `sync` again: it is left behind, holding the
/// disk until its writes complete or the Pod's VM goes. A `sync` that returns
/// first is reported by its own status, however close to the bound.
pub(crate) const WORKSPACE_FLUSH_SCRIPT: &str = r#"# The path and the bound are overridable only for the script's own test.
ws="${CODEWIRE_WORKSPACE_FLUSH_ROOT:-/mnt/ws}"
bound="${CODEWIRE_WORKSPACE_FLUSH_BOUND:-35}"
flush() {
  began="$(date +%s%N)"
  trap : USR1
  sync -f "$ws" &
  syncer=$!
  (sleep "$bound"; kill -USR1 $$) &
  watchdog=$!
  wait "$syncer"
  status=$?
  kill "$watchdog" 2>/dev/null
  # Only the watchdog ends the wait early, and then sync is still running.
  if kill -0 "$syncer" 2>/dev/null; then status=timeout; fi
  took=$((($(date +%s%N) - began) / 1000000))
  if [ "$status" = 0 ]; then
    echo "codewire workspace-flush: flushed the workspace (flush_ms=$took)"
  else
    echo "codewire workspace-flush: flushing the workspace failed (status=$status flush_ms=$took)" >&2
  fi
  kill "$sleeper" 2>/dev/null
  exit 0
}
trap flush TERM
while :; do
  sleep 3600 &
  sleeper=$!
  wait "$sleeper"
done
"#;
