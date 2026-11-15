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
                let _ = self.0.set(schema);
                schema
            }
            None => SCHEMA_VERSION,
        }
    }
}

/// A schema 3 start: its control channel and the identifier it is given.
pub(crate) struct Checkpointing {
    pair: ControlPair,
    kept_identifier: Option<String>,
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
        let checkpointing = Self {
            pair: ControlPair::new()?,
            kept_identifier: read_machine_identifier(&paths.open_vm_root()?)?,
        };
        let configuration = configuration.with_checkpointing(VzCheckpointing {
            machine_identifier: checkpointing.kept_identifier.clone(),
            save_state: paths.checkpoints_dir.join(SAVE_STATE_NAME),
            restore_state: None,
            control_descriptor: checkpointing.pair.helper().as_raw_fd(),
        });
        Ok((configuration, Some(checkpointing)))
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
        }
    }
}

/// A started helper's channel, before its `started` event.
pub(crate) struct StartedHelper {
    control: VzControl,
    kept_identifier: Option<String>,
}

impl StartedHelper {
    /// Waits for the helper's `started` event and keeps the identifier it
    /// reports, so later starts and restores use the same one. Nothing here
    /// stops a VM that runs; each failure only leaves it without a usable
    /// kept identifier, and a checkpoint then refuses:
    ///
    /// - no event, or a malformed one: the channel is broken;
    /// - a VM's first identifier that cannot be written: no kept identifier;
    /// - an identifier other than the one the helper was given: the helper
    ///   broke the protocol, so the kept file stays as it was and the channel
    ///   is broken.
    pub(crate) async fn keep_identifier(mut self, vm: &Path) -> VzControl {
        let Ok(identifier) = self.control.started().await else {
            return self.control;
        };
        match self.kept_identifier.as_deref() {
            Some(kept) if kept == identifier => {}
            Some(_) => self.control.mark_broken(),
            None => {
                let _ = PrivateRoot::open(vm).and_then(|vm| {
                    vm.atomic_replace(
                        Path::new(MACHINE_IDENTIFIER_NAME),
                        format!("{identifier}\n").as_bytes(),
                        0o600,
                    )
                });
            }
        }
        self.control
    }
}
