//! The macOS half of a VM checkpoint's capture (#4654 M4b, design §5): the
//! helper pauses the VM, saves its state and resumes it over the control
//! channel, and the runner clones the disks while the VM is paused.
//!
//! The helper writes only `checkpoints/vz-save`, the one path its sandbox
//! profile lets it write. The runner moves that file into the capture's tree
//! as `vmm/state.vzsave` after checking it is the plain file the save made
//! (cw-security, condition 6), and writes `vmm/vz.json`: the configuration
//! the VM was started with, with its kept machine identifier, which a restore
//! reproduces exactly.

use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

use super::*;
use crate::vz::{VzOperation, VzReply};

/// Pausing and resuming take milliseconds; these only bound a stuck helper.
const PAUSE_TIMEOUT: Duration = Duration::from_secs(10);
const RESUME_TIMEOUT: Duration = Duration::from_secs(10);
/// A VM's `vz.json` is a few KiB.
const MAX_CONFIGURATION_BYTES: u64 = 1 << 20;

impl RunningVm {
    /// Pause, save the VM's state, clone the disks, resume. Returns the
    /// timings and whether the resume failed after a complete capture.
    pub(super) async fn pause_and_capture(
        &mut self,
        vmm: &Path,
        disks: &Path,
        generation_dir: &Path,
    ) -> Result<(CaptureTimings, bool), RunnerError> {
        let saved = self.paths.checkpoints_dir.join(crate::vz::SAVE_STATE_NAME);
        let configuration = self.checkpoint_configuration()?;
        let clones = self.disk_clones(disks, generation_dir)?;
        let memory_mib = self.request.memory_mib;
        let control = self.control.as_mut().ok_or(RunnerError::Checkpoint(
            "this VM's helper cannot be checkpointed; stop and start the VM with this cw, then checkpoint it",
        ))?;
        // A save never replaces a file, and nothing but this capture's save may
        // be read back from this path: remove what an earlier capture left.
        remove_saved_state(&saved)?;

        let mut timings = CaptureTimings::default();
        let paused_at = Instant::now();
        match control.request(VzOperation::Pause, PAUSE_TIMEOUT).await {
            Ok(VzReply::Done { .. }) => {}
            // Refused or failed: the VM was not paused.
            Ok(_) => return Err(RunnerError::Checkpoint("the helper could not pause the VM")),
            // An unanswered pause may still have paused it.
            Err(error) => {
                control.resume(RESUME_TIMEOUT).await;
                return Err(error.into());
            }
        }
        let captured = async {
            let started = Instant::now();
            match control
                .request(VzOperation::Save, snapshot_timeout(memory_mib))
                .await?
            {
                VzReply::Done { .. } => {}
                _ => {
                    return Err(RunnerError::Checkpoint(
                        "the helper could not save the VM's state",
                    ));
                }
            }
            timings.memory_write = started.elapsed();
            let started = Instant::now();
            for (source, destination) in &clones {
                clone_disk(source, destination)?;
            }
            timings.disk_clone = started.elapsed();
            Ok::<_, RunnerError>(())
        }
        .await;
        // Also after a failed save, which broke the channel.
        let resumed = control.resume(RESUME_TIMEOUT).await;
        timings.vm_paused = paused_at.elapsed();
        // Outside the pause.
        let captured = captured.and_then(|()| {
            move_saved_state(&saved, &vmm.join(crate::vz::CHECKPOINT_STATE_NAME))?;
            write_new(&vmm.join(crate::vz::CONFIG_NAME), &configuration)
        });
        if captured.is_err() {
            let _ = remove_saved_state(&saved);
        }
        match (captured, resumed) {
            (Ok(()), true) => Ok((timings, false)),
            // Consistent and complete: kept, and the VM is reported failed.
            (Ok(()), false) => Ok((timings, true)),
            (Err(error), true) => Err(error),
            (Err(_), false) => Err(RunnerError::Checkpoint(
                "the checkpoint failed and the VM did not resume",
            )),
        }
    }

    /// The `vz.json` this VM was started with, with its kept machine
    /// identifier in place of the `null` a first start has, so a restore
    /// reproduces its devices and identity (design §4).
    fn checkpoint_configuration(&self) -> Result<Vec<u8>, RunnerError> {
        let identifier = crate::vz::read_machine_identifier(&self.paths.open_vm_root()?)?.ok_or(
            RunnerError::Checkpoint(
                "this VM's machine identifier was not kept; stop and start it with this cw, then checkpoint it",
            ),
        )?;
        let configuration = read_bounded(&self.paths.vm_dir.join(crate::vz::CONFIG_NAME))?;
        rewrite_configuration(&configuration, &identifier)
    }
}

/// `configuration` with `machineIdentifier` set to `identifier`. Only a
/// schema 3 configuration has one.
fn rewrite_configuration(configuration: &[u8], identifier: &str) -> Result<Vec<u8>, RunnerError> {
    let invalid = || RunnerError::Checkpoint("this VM's helper configuration is not schema 3");
    let mut value: serde_json::Value =
        serde_json::from_slice(configuration).map_err(|_| invalid())?;
    let object = value.as_object_mut().ok_or_else(invalid)?;
    if object
        .get("schemaVersion")
        .and_then(serde_json::Value::as_u64)
        != Some(u64::from(crate::vz::CHECKPOINTING_SCHEMA_VERSION))
        || !object.contains_key("machineIdentifier")
    {
        return Err(invalid());
    }
    object.insert(
        "machineIdentifier".to_owned(),
        serde_json::Value::String(identifier.to_owned()),
    );
    serde_json::to_vec(&value).map_err(|_| invalid())
}

/// Remove `saved`, never following a link; absent is fine.
fn remove_saved_state(saved: &Path) -> Result<(), RunnerError> {
    match std::fs::remove_file(saved) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(PathError::Io {
            path: saved.to_owned(),
            source,
        }
        .into()),
    }
}

/// Move the saved state into the tree (cw-security, condition 6). It must be
/// a plain file this user owns with one link, reached without following one;
/// `renamex_np` with `RENAME_EXCL` never replaces anything at `destination`,
/// and the moved file must still be the one checked.
fn move_saved_state(saved: &Path, destination: &Path) -> Result<(), RunnerError> {
    let not_plain =
        || RunnerError::Checkpoint("the saved VM state is not the plain file the helper wrote");
    let io = |path: &Path, source: io::Error| PathError::Io {
        path: path.to_owned(),
        source,
    };
    let checked = std::fs::symlink_metadata(saved).map_err(|source| io(saved, source))?;
    // SAFETY: getuid takes no arguments and cannot fail.
    let user = unsafe { libc::getuid() };
    if !checked.file_type().is_file() || checked.uid() != user || checked.nlink() != 1 {
        return Err(not_plain());
    }
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        saved,
        rustix::fs::CWD,
        destination,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(|error| io(destination, error.into()))?;
    let moved = std::fs::symlink_metadata(destination).map_err(|source| io(destination, source))?;
    if !moved.file_type().is_file() || (moved.dev(), moved.ino()) != (checked.dev(), checked.ino())
    {
        return Err(not_plain());
    }
    Ok(())
}

/// What a restore reads from `checkpoints/in`, admitted (#4654 M4c).
pub(in crate::runner) struct RestoreInput {
    /// The checkpoint's helper configuration, as recorded.
    pub(in crate::runner) captured: Vec<u8>,
    /// Its saved state, `checkpoints/in/state.vzsave` (condition 7).
    pub(in crate::runner) state: PathBuf,
    /// An empty stand-in for the captured boot's setup disk, when it had one:
    /// the guest read it only while it booted, but its device must exist.
    pub(in crate::runner) setup: Option<PathBuf>,
}

/// Admit the VM checkpoint the supervisor placed in `checkpoints/in`: its
/// configuration and saved state as recorded, and the setup disk's stand-in.
pub(in crate::runner) fn restore_input(
    paths: &VmPaths,
    restore: &RestoreBoot,
) -> Result<RestoreInput, RunnerError> {
    use sha2::{Digest as _, Sha256};
    let input = paths.checkpoints_dir.join(crate::state::CHECKPOINT_IN);
    let captured = read_bounded(&input.join(crate::vz::CONFIG_NAME))?;
    if format!("{:x}", Sha256::digest(&captured)) != restore.config_sha256 {
        return Err(RunnerError::Checkpoint(
            "the placed VM checkpoint is not the recorded one",
        ));
    }
    let state = input.join(crate::vz::CHECKPOINT_STATE_NAME);
    admit_restore_state(
        &state,
        &restore.state_sha256,
        restore.state_identity.as_ref(),
    )?;
    let setup = restore
        .setup_disk_bytes
        .map(|bytes| {
            let placeholder = input.join(SETUP_PLACEHOLDER);
            remove_saved_state(&placeholder)?;
            write_new(&placeholder, &[])?;
            let io = |source: io::Error| PathError::Io {
                path: placeholder.clone(),
                source,
            };
            let file = std::fs::OpenOptions::new()
                .write(true)
                .open(&placeholder)
                .map_err(io)?;
            file.set_len(bytes)
                .and_then(|()| file.sync_all())
                .map_err(io)?;
            std::fs::set_permissions(&placeholder, std::fs::Permissions::from_mode(0o400))
                .map_err(io)?;
            Ok::<_, RunnerError>(placeholder)
        })
        .transpose()?;
    Ok(RestoreInput {
        captured,
        state,
        setup,
    })
}

/// This boot's configuration, made to restore the captured one (design §4).
/// Virtualization.framework restores only into the device set it saved
/// (`VZErrorDomain` 12 otherwise), so each disk's serial, order and access,
/// the CPUs, the memory, the boot artifacts and the command line must equal
/// the checkpoint's, and neither has a share. Paths may differ: a fork's
/// disks are its own. The result is this boot's configuration with the
/// checkpoint's machine identifier and `restoreState` set.
pub(in crate::runner) fn restore_configuration(
    captured: &[u8],
    current: &[u8],
    restore_state: &Path,
) -> Result<Vec<u8>, RunnerError> {
    use serde_json::{Map, Value};
    let parse = |bytes: &[u8]| {
        serde_json::from_slice::<Map<String, Value>>(bytes)
            .ok()
            .filter(|object| {
                object.get("schemaVersion").and_then(Value::as_u64)
                    == Some(u64::from(crate::vz::CHECKPOINTING_SCHEMA_VERSION))
            })
    };
    let captured = parse(captured).ok_or(RunnerError::Checkpoint(
        "the VM checkpoint's helper configuration is not schema 3",
    ))?;
    let mut current = parse(current).ok_or(RunnerError::Checkpoint(
        "this boot's helper configuration is not schema 3",
    ))?;
    let devices = |object: &Map<String, Value>| -> Option<Vec<(String, bool)>> {
        object
            .get("disks")?
            .as_array()?
            .iter()
            .map(|disk| {
                Some((
                    disk.get("serial")?.as_str()?.to_owned(),
                    disk.get("readOnly")?.as_bool()?,
                ))
            })
            .collect()
    };
    let no_shares = |object: &Map<String, Value>| {
        object
            .get("shares")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
    };
    let same = [
        "cpuCount",
        "memoryMiB",
        "kernel",
        "initialRamdisk",
        "commandLine",
    ]
    .iter()
    .all(|key| captured.get(*key).is_some() && captured.get(*key) == current.get(*key));
    if devices(&captured).is_none()
        || devices(&captured) != devices(&current)
        || !same
        || !no_shares(&captured)
        || !no_shares(&current)
    {
        return Err(RunnerError::Checkpoint(
            "this VM's devices differ from the ones its checkpoint was taken with",
        ));
    }
    let identifier = captured
        .get("machineIdentifier")
        .and_then(Value::as_str)
        .filter(|identifier| crate::vz::is_machine_identifier(identifier))
        .ok_or(RunnerError::Checkpoint(
            "the VM checkpoint has no machine identifier",
        ))?;
    let restore_state = restore_state.to_str().ok_or(RunnerError::Checkpoint(
        "this VM's restore path is not text",
    ))?;
    current.insert(
        "machineIdentifier".to_owned(),
        Value::String(identifier.to_owned()),
    );
    current.insert(
        "restoreState".to_owned(),
        Value::String(restore_state.to_owned()),
    );
    serde_json::to_vec(&current)
        .map_err(|_| RunnerError::Checkpoint("this boot's helper configuration is not schema 3"))
}

/// Condition 7 (cw-security, #4654): the state a restore reads is this VM's
/// own copy, a plain `0400` file this user owns with one link, reached
/// without following a link, with the sha256 its checkpoint recorded. When
/// the descriptor opened here has exactly the identity the supervisor pinned
/// at the clone, it is that content and isn't digested again (#6124).
fn admit_restore_state(
    path: &Path,
    sha256: &str,
    pinned: Option<&crate::checkpoint_pin::StateIdentity>,
) -> Result<(), RunnerError> {
    use sha2::{Digest as _, Sha256};
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let not_ours =
        || RunnerError::Checkpoint("the VM checkpoint's saved state is not this VM's own copy");
    let io = |source: io::Error| PathError::Io {
        path: path.to_owned(),
        source,
    };
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| not_ours())?;
    let metadata = file.metadata().map_err(io)?;
    // SAFETY: getuid takes no arguments and cannot fail.
    let user = unsafe { libc::getuid() };
    if !metadata.file_type().is_file()
        || metadata.permissions().mode() & 0o7777 != 0o400
        || metadata.uid() != user
        || metadata.nlink() != 1
    {
        return Err(not_ours());
    }
    if pinned.is_some_and(|pin| pin.holds_for(&file, sha256)) {
        return Ok(());
    }
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 1 << 20];
    loop {
        let read = file.read(&mut buffer).map_err(io)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    if format!("{:x}", digest.finalize()) != sha256 {
        return Err(RunnerError::Checkpoint(
            "the placed VM checkpoint is not the recorded one",
        ));
    }
    Ok(())
}

/// At most [`MAX_CONFIGURATION_BYTES`] of a regular file, without following
/// a link.
fn read_bounded(path: &Path) -> Result<Vec<u8>, RunnerError> {
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let io = |source: io::Error| PathError::Io {
        path: path.to_owned(),
        source,
    };
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(io)?;
    let mut bytes = Vec::new();
    file.take(MAX_CONFIGURATION_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(io)?;
    if bytes.len() as u64 > MAX_CONFIGURATION_BYTES {
        return Err(RunnerError::Checkpoint(
            "this VM's helper configuration is too large",
        ));
    }
    Ok(bytes)
}

/// Write `bytes` to the new file `path` (0600), durably.
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), RunnerError> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let io = |source: io::Error| PathError::Io {
        path: path.to_owned(),
        source,
    };
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(io)?;
    file.write_all(bytes).map_err(io)?;
    file.sync_all().map_err(io)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn configuration(
        disks: &[(&str, &str, bool)],
        memory: u64,
        identifier: Option<&str>,
    ) -> Vec<u8> {
        let disks: Vec<_> = disks
            .iter()
            .map(|(path, serial, read_only)| {
                serde_json::json!({"path": path, "serial": serial, "readOnly": read_only})
            })
            .collect();
        serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 3, "kernel": "/runtime/kernel", "initialRamdisk": "/runtime/initramfs",
            "commandLine": "console=ttyS0 codewire.clock=rtc", "cpuCount": 2, "memoryMiB": memory,
            "disks": disks, "shares": [], "vsockSocket": "/vm/vsock",
            "machineIdentifier": identifier, "saveState": "/vm/checkpoints/vz-save",
            "restoreState": null, "controlDescriptor": 5,
        }))
        .unwrap()
    }

    /// Design §4: a restore reproduces the captured device set exactly, on
    /// this boot's own paths, with the checkpoint's identity.
    #[test]
    fn a_restore_reproduces_the_captured_devices_on_its_own_paths() {
        let captured = configuration(
            &[
                ("/a/state.raw", "CWSTATE1", false),
                ("/a/seed.raw", "CWSEED1", true),
            ],
            4096,
            Some("YnBsaXN0MDA="),
        );
        let fork = configuration(
            &[
                ("/b/state.raw", "CWSTATE1", false),
                ("/b/seed.raw", "CWSEED1", true),
            ],
            4096,
            None,
        );
        let restored: serde_json::Value = serde_json::from_slice(
            &restore_configuration(
                &captured,
                &fork,
                Path::new("/b/checkpoints/in/state.vzsave"),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(restored["machineIdentifier"], "YnBsaXN0MDA=");
        assert_eq!(restored["restoreState"], "/b/checkpoints/in/state.vzsave");
        assert_eq!(restored["disks"][0]["path"], "/b/state.raw");

        let restore = |current: &[u8]| {
            restore_configuration(
                &captured,
                current,
                Path::new("/b/checkpoints/in/state.vzsave"),
            )
        };
        for (current, case) in [
            (
                configuration(
                    &[
                        ("/b/seed.raw", "CWSEED1", true),
                        ("/b/state.raw", "CWSTATE1", false),
                    ],
                    4096,
                    None,
                ),
                "another order",
            ),
            (
                configuration(
                    &[
                        ("/b/state.raw", "CWSTATE1", false),
                        ("/b/seed.raw", "CWSEED1", true),
                        ("/b/image.raw", "CWIMAGE1", true),
                    ],
                    4096,
                    None,
                ),
                "one more disk",
            ),
            (
                configuration(
                    &[
                        ("/b/state.raw", "CWSTATE1", true),
                        ("/b/seed.raw", "CWSEED1", true),
                    ],
                    4096,
                    None,
                ),
                "another access",
            ),
            (
                configuration(
                    &[
                        ("/b/state.raw", "CWSTATE1", false),
                        ("/b/seed.raw", "CWSEED1", true),
                    ],
                    8192,
                    None,
                ),
                "another memory size",
            ),
        ] {
            assert!(restore(&current).is_err(), "{case}");
        }
        let without_identity = configuration(
            &[
                ("/a/state.raw", "CWSTATE1", false),
                ("/a/seed.raw", "CWSEED1", true),
            ],
            4096,
            None,
        );
        assert!(
            restore_configuration(
                &without_identity,
                &fork,
                Path::new("/b/checkpoints/in/state.vzsave")
            )
            .is_err()
        );
    }

    /// Condition 7: only this VM's own plain 0400 copy with the recorded
    /// sha256 is restored from.
    #[test]
    fn only_the_recorded_private_saved_state_is_restored_from() {
        use std::os::unix::fs::PermissionsExt as _;
        let directory = tempfile::tempdir().unwrap();
        let state = directory.path().join("state.vzsave");
        std::fs::write(&state, b"saved").unwrap();
        let sha256 = format!("{:x}", <sha2::Sha256 as sha2::Digest>::digest(b"saved"));
        let mode =
            |mode| std::fs::set_permissions(&state, std::fs::Permissions::from_mode(mode)).unwrap();

        mode(0o400);
        admit_restore_state(&state, &sha256, None).unwrap();
        assert!(
            admit_restore_state(&state, &"0".repeat(64), None).is_err(),
            "another sha256"
        );
        mode(0o600);
        assert!(
            admit_restore_state(&state, &sha256, None).is_err(),
            "writable"
        );
        mode(0o400);
        let second = directory.path().join("second");
        std::fs::hard_link(&state, &second).unwrap();
        assert!(
            admit_restore_state(&state, &sha256, None).is_err(),
            "a second link"
        );
        std::fs::remove_file(&second).unwrap();
        let link = directory.path().join("link");
        std::os::unix::fs::symlink(&state, &link).unwrap();
        assert!(
            admit_restore_state(&link, &sha256, None).is_err(),
            "a symbolic link"
        );
        assert!(
            admit_restore_state(&directory.path().join("absent"), &sha256, None).is_err(),
            "absent"
        );
    }

    /// #6124: the supervisor's pin of this VM's clone stands for the digest
    /// only while the descriptor opened here still has that identity; the
    /// other checks apply either way.
    #[test]
    fn a_pin_that_holds_skips_the_digest_and_one_that_doesnt_digests() {
        use std::os::unix::fs::PermissionsExt as _;
        let directory = tempfile::tempdir().unwrap();
        let state = directory.path().join("state.vzsave");
        std::fs::write(&state, b"saved").unwrap();
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o400)).unwrap();
        let sha256 = format!("{:x}", <sha2::Sha256 as sha2::Digest>::digest(b"saved"));
        let wrong = "0".repeat(64);
        let identity =
            crate::checkpoint_pin::StateIdentity::of(&std::fs::File::open(&state).unwrap())
                .unwrap();
        let pin = identity.clone().vouching_for(&sha256);

        // A pin vouching for a digest the file doesn't have passes while it
        // holds, so nothing was read; it vouches only for that digest.
        let vouching = identity.vouching_for(&wrong);
        admit_restore_state(&state, &wrong, Some(&vouching)).unwrap();
        admit_restore_state(&state, &sha256, Some(&vouching)).unwrap();
        admit_restore_state(&state, &sha256, Some(&pin)).unwrap();
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&state, b"saves").unwrap();
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(
            admit_restore_state(&state, &sha256, Some(&pin)).is_err(),
            "a changed byte"
        );
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&state, b"saved").unwrap();
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o400)).unwrap();
        admit_restore_state(&state, &sha256, Some(&pin)).unwrap();
        assert!(
            admit_restore_state(&state, &wrong, Some(&pin)).is_err(),
            "a broken pin is digested"
        );
        let link = directory.path().join("link");
        std::os::unix::fs::symlink(&state, &link).unwrap();
        let held = crate::checkpoint_pin::StateIdentity::of(&std::fs::File::open(&state).unwrap())
            .unwrap()
            .vouching_for(&sha256);
        assert!(
            admit_restore_state(&link, &sha256, Some(&held)).is_err(),
            "a symbolic link, pinned or not"
        );
    }

    #[test]
    fn the_checkpoint_configuration_carries_the_kept_identifier() {
        let first_start = br#"{"schemaVersion":3,"machineIdentifier":null,"cpuCount":2}"#;
        let rewritten: serde_json::Value =
            serde_json::from_slice(&rewrite_configuration(first_start, "YnBsaXN0MDA=").unwrap())
                .unwrap();
        assert_eq!(rewritten["machineIdentifier"], "YnBsaXN0MDA=");
        assert_eq!(rewritten["cpuCount"], 2);
        // Only a schema 3 configuration, which has the member, is captured.
        for refused in [
            &br#"{"schemaVersion":2,"cpuCount":2}"#[..],
            br#"{"schemaVersion":3,"cpuCount":2}"#,
            br#"[3]"#,
            b"not json",
        ] {
            assert!(rewrite_configuration(refused, "YQ==").is_err());
        }
    }

    /// Condition 6: only the plain file the save made moves, and never over
    /// anything.
    #[test]
    fn only_a_plain_saved_state_moves_and_never_replaces() {
        let directory = tempfile::tempdir().unwrap();
        let saved = directory.path().join("vz-save");
        let destination = directory.path().join(crate::vz::CHECKPOINT_STATE_NAME);

        std::fs::write(&saved, b"state").unwrap();
        move_saved_state(&saved, &destination).unwrap();
        assert!(!saved.exists());
        assert_eq!(std::fs::read(&destination).unwrap(), b"state");

        // Something already at the destination is never replaced.
        std::fs::write(&saved, b"second").unwrap();
        assert!(move_saved_state(&saved, &destination).is_err());
        assert_eq!(std::fs::read(&destination).unwrap(), b"state");
        std::fs::remove_file(&destination).unwrap();

        // A link, a second link to the file, or a directory never moves.
        let elsewhere = directory.path().join("elsewhere");
        std::fs::write(&elsewhere, b"other").unwrap();
        std::fs::remove_file(&saved).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &saved).unwrap();
        assert!(move_saved_state(&saved, &destination).is_err());
        std::fs::remove_file(&saved).unwrap();
        std::fs::hard_link(&elsewhere, &saved).unwrap();
        assert!(move_saved_state(&saved, &destination).is_err());
        std::fs::remove_file(&saved).unwrap();
        std::fs::create_dir(&saved).unwrap();
        assert!(move_saved_state(&saved, &destination).is_err());
        assert!(!destination.exists());

        // Removing leftovers never follows a link and tolerates absence.
        std::fs::remove_dir(&saved).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &saved).unwrap();
        remove_saved_state(&saved).unwrap();
        assert!(std::fs::symlink_metadata(&saved).is_err());
        assert_eq!(std::fs::read(&elsewhere).unwrap(), b"other");
        remove_saved_state(&saved).unwrap();
    }
}
