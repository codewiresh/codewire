//! What a schema 3 helper gets beyond schema 2 (#4654): the control channel,
//! the machine identifier kept from the VM's first start, and the file a save
//! writes. A helper from before schema 3 gets none of it and runs as before.

use std::os::fd::{AsRawFd as _, BorrowedFd};
use std::path::Path;

use super::{
    CHECKPOINTING_SCHEMA_VERSION, ControlPair, MACHINE_IDENTIFIER_NAME, SAVE_STATE_NAME,
    SCHEMA_VERSION, VzCheckpointing, VzConfiguration, VzControl, probe_protocol,
    read_machine_identifier,
};
use crate::host::path::PrivateRoot;
use crate::runner::RunnerError;
use crate::state::VmPaths;

/// The newest schema the admitted helper accepts, kept once it is certain.
#[derive(Debug, Default)]
pub(crate) struct ProtocolCache(tokio::sync::OnceCell<u32>);

impl ProtocolCache {
    /// The schema to start `executable` with. A probe with no answer, such
    /// as a slow first exec of a newly installed helper, starts this VM on
    /// schema 2 and is asked again next time, never kept.
    pub(crate) async fn schema(&self, executable: &Path) -> u32 {
        if let Some(schema) = self.0.get() {
            return *schema;
        }
        match probe_protocol(executable).await {
            Some(schema) => {
                // Another start may have kept the same answer first.
                let _ = self.0.set(schema);
                schema
            }
            None => SCHEMA_VERSION,
        }
    }
}

/// A schema 3 start: its control channel, the identifier the VM keeps, and
/// the one this boot's configuration gives the helper. They differ only on a
/// restore, which gives the checkpoint's.
pub(crate) struct Checkpointing {
    pair: ControlPair,
    kept_identifier: Option<String>,
    given_identifier: Option<String>,
}

impl Checkpointing {
    /// `configuration` for the helper at `executable`. One that speaks
    /// schema 3 gets a new control channel, the VM's kept identifier and the
    /// file its saves write; an older one, still pinned by the VM's
    /// artifacts, gets `configuration` unchanged and runs as before.
    pub(crate) async fn configure(
        protocol: &ProtocolCache,
        executable: &Path,
        paths: &VmPaths,
        configuration: VzConfiguration,
    ) -> Result<(VzConfiguration, Option<Self>), RunnerError> {
        if protocol.schema(executable).await < CHECKPOINTING_SCHEMA_VERSION {
            return Ok((configuration, None));
        }
        let kept_identifier = read_machine_identifier(&paths.open_vm_root()?)?;
        let checkpointing = Self {
            pair: ControlPair::new()?,
            given_identifier: kept_identifier.clone(),
            kept_identifier,
        };
        let configuration = configuration.with_checkpointing(VzCheckpointing {
            machine_identifier: checkpointing.kept_identifier.clone(),
            save_state: paths.checkpoints_dir.join(SAVE_STATE_NAME),
            restore_state: None,
            control_descriptor: checkpointing.pair.helper().as_raw_fd(),
        });
        Ok((configuration, Some(checkpointing)))
    }

    /// A restore's configuration, as `restore_configuration` made it: the
    /// helper is given the checkpoint's identifier, which the VM keeps once
    /// the helper reports it.
    pub(crate) fn restoring(&mut self, configuration: Vec<u8>) -> Result<Vec<u8>, RunnerError> {
        let identifier = serde_json::from_slice::<serde_json::Value>(&configuration)
            .ok()
            .and_then(|value| Some(value.get("machineIdentifier")?.as_str()?.to_owned()))
            .ok_or(RunnerError::Checkpoint(
                "the VM checkpoint has no machine identifier",
            ))?;
        self.given_identifier = Some(identifier);
        Ok(configuration)
    }

    /// The end the helper inherits.
    pub(crate) fn helper(&self) -> BorrowedFd<'_> {
        self.pair.helper()
    }

    /// After the spawn: this process's copy of the helper's end closes.
    pub(crate) fn into_started(self) -> StartedHelper {
        StartedHelper {
            control: self.pair.into_control(),
            kept_identifier: self.kept_identifier,
            given_identifier: self.given_identifier,
        }
    }
}

/// A started helper's channel, before its `started` event.
pub(crate) struct StartedHelper {
    control: VzControl,
    kept_identifier: Option<String>,
    given_identifier: Option<String>,
}

impl StartedHelper {
    /// Waits for the helper's `started` event and keeps the identifier it
    /// reports, so later starts and restores use the same one. Nothing here
    /// stops a VM that runs; each failure only leaves it without a usable
    /// kept identifier, and a checkpoint then refuses:
    ///
    /// - no event, or a malformed one: the channel is broken;
    /// - an identifier other than the one this boot's configuration gave the
    ///   helper: it broke the protocol, so the kept file stays as it was and
    ///   the channel is broken;
    /// - an identifier that cannot be written, a VM's first or a restored
    ///   checkpoint's: the kept file stays as it was.
    ///
    /// Each of these is recorded in the runner's log, as
    /// `vz_machine_identifier_not_kept` with its reason.
    pub(crate) async fn keep_identifier(mut self, vm: &Path, vm_id: uuid::Uuid) -> VzControl {
        let not_kept = |reason| {
            if let Some(log) = crate::diagnostic_log::DiagnosticLog::inherited() {
                log.record(
                    "vz_machine_identifier_not_kept",
                    &[
                        ("vm", crate::diagnostic_log::LogField::Id(vm_id)),
                        ("reason", crate::diagnostic_log::LogField::Name(reason)),
                    ],
                );
            }
        };
        let Ok(identifier) = self.control.started().await else {
            not_kept("no_started_event");
            return self.control;
        };
        if self
            .given_identifier
            .as_deref()
            .is_some_and(|given| given != identifier)
        {
            self.control.mark_broken();
            not_kept("another_identifier");
        } else if self.kept_identifier.as_deref() != Some(identifier.as_str()) {
            let written = PrivateRoot::open(vm).and_then(|vm| {
                vm.atomic_replace(
                    Path::new(MACHINE_IDENTIFIER_NAME),
                    format!("{identifier}\n").as_bytes(),
                    0o600,
                )
            });
            if written.is_err() {
                not_kept("write_failed");
            }
        }
        self.control
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::net::UnixStream;

    use super::super::control::VzControlFailure;
    use super::*;
    use crate::vz::VzOperation;

    const KEPT: &str = "a2VwdA==";
    const OTHER: &str = "b3RoZXI=";

    /// A started helper whose `started` event reports `reported`, or that
    /// closes without one, for a VM that keeps `kept` and was given `given`.
    fn started(kept: Option<&str>, given: Option<&str>, reported: Option<&str>) -> StartedHelper {
        let pair = ControlPair::new().unwrap();
        let mut helper = UnixStream::from(pair.helper().try_clone_to_owned().unwrap());
        if let Some(reported) = reported {
            helper
                .write_all(
                    format!("{{\"event\":\"started\",\"machineIdentifier\":\"{reported}\"}}\n")
                        .as_bytes(),
                )
                .unwrap();
            // Kept open, so the channel stays up after the event.
            std::mem::forget(helper);
        }
        StartedHelper {
            control: pair.into_control(),
            kept_identifier: kept.map(str::to_owned),
            given_identifier: given.map(str::to_owned),
        }
    }

    fn vm_dir(kept: Option<&str>) -> tempfile::TempDir {
        let vm = tempfile::tempdir().unwrap();
        std::fs::set_permissions(vm.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        if let Some(kept) = kept {
            let file = vm.path().join(MACHINE_IDENTIFIER_NAME);
            std::fs::write(&file, format!("{kept}\n")).unwrap();
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        vm
    }

    fn kept_file(vm: &tempfile::TempDir) -> Option<String> {
        std::fs::read_to_string(vm.path().join(MACHINE_IDENTIFIER_NAME)).ok()
    }

    async fn usable(control: &mut VzControl) -> bool {
        control
            .request(VzOperation::Pause, std::time::Duration::from_millis(1))
            .await
            != Err(VzControlFailure::Broken)
    }

    /// The one rule (cw-review on #4685): a VM's first identifier is
    /// written; the same one again changes nothing; a restore keeps the
    /// checkpoint's; another than given keeps the old file and breaks the
    /// channel; no event breaks it. None of them stops the VM.
    #[tokio::test]
    async fn the_kept_identifier_follows_one_rule() {
        let id = uuid::Uuid::new_v4();
        let first = vm_dir(None);
        let mut control = started(None, None, Some(KEPT))
            .keep_identifier(first.path(), id)
            .await;
        assert_eq!(kept_file(&first).as_deref(), Some("a2VwdA==\n"));
        assert!(usable(&mut control).await);

        let same = vm_dir(Some(KEPT));
        let mut control = started(Some(KEPT), Some(KEPT), Some(KEPT))
            .keep_identifier(same.path(), id)
            .await;
        assert_eq!(kept_file(&same).as_deref(), Some("a2VwdA==\n"));
        assert!(usable(&mut control).await);

        let restored = vm_dir(Some(KEPT));
        let mut control = started(Some(KEPT), Some(OTHER), Some(OTHER))
            .keep_identifier(restored.path(), id)
            .await;
        assert_eq!(kept_file(&restored).as_deref(), Some("b3RoZXI=\n"));
        assert!(usable(&mut control).await);

        let mismatch = vm_dir(Some(KEPT));
        let mut control = started(Some(KEPT), Some(KEPT), Some(OTHER))
            .keep_identifier(mismatch.path(), id)
            .await;
        assert_eq!(kept_file(&mismatch).as_deref(), Some("a2VwdA==\n"));
        assert!(!usable(&mut control).await);

        let silent = vm_dir(None);
        let mut control = started(None, None, None)
            .keep_identifier(silent.path(), id)
            .await;
        assert_eq!(kept_file(&silent), None);
        assert!(!usable(&mut control).await);
    }
}
