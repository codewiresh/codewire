//! The warning at a Mac's first VM checkpoint when FileVault is off (#4654,
//! cw-security's condition 11): APFS clones share blocks, so a removed
//! checkpoint's memory stays on the disk until the blocks are reused.

use std::process::Stdio;

use super::*;

const WARNING: &str = "FileVault is off on this Mac. A VM checkpoint holds the VM's memory, sign-ins included, and after `cw checkpoint rm` its blocks stay readable on the disk, and in Time Machine's local snapshots for about a day, unless FileVault is on. Turn it on in System Settings > Privacy & Security > FileVault.";

/// `checkpoint` with the warning added, once, at the host's first VM
/// checkpoint.
pub(super) async fn at_first_checkpoint(
    client: &codewire_local_vmm::supervisor::NativeSupervisorClient,
    mut checkpoint: v1::Checkpoint,
) -> v1::Checkpoint {
    if client
        .list_checkpoints("")
        .await
        .is_ok_and(|all| all.len() == 1)
        && let Some(warning) = warning()
    {
        checkpoint.warnings.push(warning.to_owned());
    }
    checkpoint
}

/// The warning, when `fdesetup isactive` says FileVault is off. A state it
/// cannot tell shows nothing.
fn warning() -> Option<&'static str> {
    let output = crate::process::command("/usr/bin/fdesetup", &[])
        .arg("isactive")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    is_off(&output.stdout).then_some(WARNING)
}

fn is_off(isactive: &[u8]) -> bool {
    isactive.trim_ascii() == b"false"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_definite_false_is_off() {
        assert!(is_off(b"false\n"));
        for unknown in [&b"true\n"[..], b"", b"Error: unknown\n"] {
            assert!(!is_off(unknown));
        }
    }
}
