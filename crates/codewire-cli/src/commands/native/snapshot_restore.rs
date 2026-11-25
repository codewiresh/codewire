//! What a create from a disk snapshot or a VM checkpoint asks the supervisor
//! to restore.

use super::*;

/// The restore of `snapshot_id` that `args` asks for, at the given vCPUs and
/// memory, for the signed-in `account`. A fork of a VM checkpoint may carry
/// the one-fork override of a disk that may hold an earlier sign-in (#6277).
pub(super) fn request(
    args: &EnvCreateArgs,
    snapshot_id: &str,
    (vcpus, memory_mib): (u32, u32),
    account: &Option<v1::PlatformAccount>,
) -> v1::SnapshotRestore {
    v1::SnapshotRestore {
        snapshot_id: snapshot_id.to_owned(),
        vcpus,
        memory_mib,
        share_mounts: args.share_mounts,
        account: account.clone(),
        start_with_uncleared_disk: args.start_with_uncleared_disk,
    }
}
