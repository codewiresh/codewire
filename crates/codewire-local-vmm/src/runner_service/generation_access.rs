//! The one current generation's daemon access: published once its VMM is
//! owned, revoked when it retires, and only while that process lives.

use std::os::fd::{AsRawFd as _, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as SyncMutex};

use tonic::Status;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::GENERATION_ACCESS_MAX_BYTES;
use crate::RunningVm;
use crate::control::v1;
use crate::hybrid_vsock::HybridVsockTarget;
use crate::runner::{BootRecords, BootSecrets};

/// A generation's boot secrets and its records of its bound secrets
/// (#4003), local and platform, as the supervisor asks for them.
pub type BootSecretsAnswer = (Vec<v1::BootSecret>, crate::runner::BootRecords);

pub(super) fn validate_generation_access(
    environment_id: Uuid,
    generation: u64,
    access: &v1::DaemonAccess,
) -> Result<(), Status> {
    let front_door_socket = Path::new(&access.front_door_socket);
    if access.hybrid_socket.len() > GENERATION_ACCESS_MAX_BYTES
        || access.hybrid_socket.contains('\0')
        || access.front_door_socket.len() > GENERATION_ACCESS_MAX_BYTES
        || access.front_door_socket.contains('\0')
        || (!access.front_door_socket.is_empty() && !front_door_socket.is_absolute())
        || HybridVsockTarget::new(PathBuf::from(&access.hybrid_socket), access.guest_port).is_err()
        || codewire_vmm_guest_probe::Seed::new(
            environment_id,
            generation,
            access.guest_port,
            access.generation_capability.clone(),
        )
        .is_err()
    {
        return Err(Status::failed_precondition(
            "invalid runner generation transport",
        ));
    }
    Ok(())
}

/// A second, short-held lock is intentional: startup retains the lifecycle
/// mutex while install may need this transport. No VM mutation uses this cell.
/// Its token is ephemeral and never Debug/serialized except the private reply.
pub(super) struct GenerationAccessCell {
    environment_id: Uuid,
    pub(super) current: SyncMutex<GenerationAccessState>,
}

#[derive(Default)]
pub(super) struct GenerationAccessState {
    pub(super) retiring: bool,
    pub(super) access: Option<PublishedGenerationAccess>,
    /// The generation a credential broker is awaited for, and whether one
    /// has taken its daemon access. Kept beside `access`, which a VMM that
    /// went takes with it.
    broker: Option<(u64, bool)>,
}

/// Whether the credential broker the supervisor starts for a generation came
/// for that generation's daemon access.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum BrokerSeen {
    /// No broker is started for the generation.
    None,
    Never,
    Connected,
}

impl BrokerSeen {
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Never => "never",
            Self::Connected => "connected",
        }
    }
}

pub(super) struct PublishedGenerationAccess {
    generation: u64,
    socket: String,
    front_door_socket: String,
    port: u32,
    token: Zeroizing<String>,
    /// An intercepting boot's secrets, each with its purpose; empty for any
    /// other boot. Never part of `DaemonAccess`.
    boot_secrets: Vec<(i32, Zeroizing<Vec<u8>>)>,
    /// The boot's record of its bound secrets (#4003), handed to each of its
    /// credential brokers beside the secrets.
    bound_secrets: BootRecords,
    liveness: OwnedFd,
}

pub(super) struct GenerationAccessGuard {
    cell: Arc<GenerationAccessCell>,
    generation: u64,
}

impl GenerationAccessCell {
    pub(super) fn new(environment_id: Uuid) -> Arc<Self> {
        Arc::new(Self {
            environment_id,
            current: SyncMutex::new(GenerationAccessState::default()),
        })
    }

    pub(super) fn retire(&self) {
        // Publication, lookup, and this permanent revocation use one lock.
        // No install/get can race a separate retirement flag and restore a
        // capability after the lifecycle owner has begun retirement.
        let mut current = self
            .current
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        current.retiring = true;
        current.access = None;
    }

    pub(super) fn publish(
        self: &Arc<Self>,
        running: &RunningVm,
    ) -> Result<GenerationAccessGuard, Status> {
        if running.vm_id() != self.environment_id {
            return Err(Status::permission_denied("runner identity mismatch"));
        }
        let (socket, port, token) = running.daemon_access_parts();
        let socket = socket
            .to_str()
            .ok_or_else(|| Status::internal("invalid runner transport path"))?;
        let front_door_socket = running
            .front_door_socket()
            .map(|socket| {
                socket
                    .to_str()
                    .ok_or_else(|| Status::internal("invalid runner transport path"))
            })
            .transpose()?
            .unwrap_or_default();
        let liveness = running
            .duplicate_liveness_descriptor()
            .map_err(|_| Status::internal("observe owned VMM liveness failed"))?;
        let boot_secrets = running
            .boot_secrets()
            .map(BootSecrets::to_proto)
            .unwrap_or_default()
            .into_iter()
            .map(|secret| (secret.purpose, Zeroizing::new(secret.value)))
            .collect();
        self.install_with_secrets(
            running.generation(),
            v1::DaemonAccess {
                hybrid_socket: socket.to_owned(),
                guest_port: port,
                generation_capability: token.to_owned(),
                front_door_socket: front_door_socket.to_owned(),
            },
            boot_secrets,
            running.boot_bindings().bound_secrets.clone(),
            liveness,
        )
    }

    /// A boot without secrets, as one that does not intercept.
    #[cfg(test)]
    pub(super) fn install(
        self: &Arc<Self>,
        generation: u64,
        access: v1::DaemonAccess,
        liveness: OwnedFd,
    ) -> Result<GenerationAccessGuard, Status> {
        self.install_with_secrets(
            generation,
            access,
            Vec::new(),
            BootRecords::default(),
            liveness,
        )
    }

    pub(super) fn install_with_secrets(
        self: &Arc<Self>,
        generation: u64,
        access: v1::DaemonAccess,
        boot_secrets: Vec<(i32, Zeroizing<Vec<u8>>)>,
        records: BootRecords,
        liveness: OwnedFd,
    ) -> Result<GenerationAccessGuard, Status> {
        validate_generation_access(self.environment_id, generation, &access)?;
        if !generation_process_alive(&liveness) {
            return Err(Status::failed_precondition("runner generation is not live"));
        }
        let mut current = self
            .current
            .lock()
            .map_err(|_| Status::unavailable("runner generation access unavailable"))?;
        if current.retiring {
            return Err(Status::failed_precondition("runner is retiring"));
        }
        if current.access.is_some() {
            return Err(Status::failed_precondition(
                "runner generation access already owned",
            ));
        }
        current.access = Some(PublishedGenerationAccess {
            generation,
            socket: access.hybrid_socket,
            front_door_socket: access.front_door_socket,
            port: access.guest_port,
            token: Zeroizing::new(access.generation_capability),
            boot_secrets,
            bound_secrets: records,
            liveness,
        });
        Ok(GenerationAccessGuard {
            cell: Arc::clone(self),
            generation,
        })
    }

    pub(super) fn get(
        &self,
        environment_id: Uuid,
        generation: u64,
    ) -> Result<v1::DaemonAccess, Status> {
        let access = self.with_live(environment_id, generation, |access| v1::DaemonAccess {
            hybrid_socket: access.socket.clone(),
            guest_port: access.port,
            generation_capability: access.token.to_string(),
            front_door_socket: access.front_door_socket.clone(),
        })?;
        let mut current = self
            .current
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some((awaited, connected)) = &mut current.broker
            && *awaited == generation
        {
            *connected = true;
        }
        Ok(access)
    }

    /// Starts `generation` with or without a credential broker to come.
    pub(super) fn await_broker(&self, generation: u64, awaited: bool) {
        self.current
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .broker = awaited.then_some((generation, false));
    }

    /// Whether the broker awaited for `generation` took its daemon access.
    /// While a generation starts, only its broker asks for it: the supervisor
    /// asks only of a runner that already reports the generation running.
    pub(super) fn broker_seen(&self, generation: u64) -> BrokerSeen {
        let current = self
            .current
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match current.broker {
            Some((awaited, true)) if awaited == generation => BrokerSeen::Connected,
            Some((awaited, false)) if awaited == generation => BrokerSeen::Never,
            _ => BrokerSeen::None,
        }
    }

    /// The current generation's boot secrets, only for an intercepting boot,
    /// with its record of its bound secrets. Every other request gets the
    /// same answer, naming nothing.
    pub(super) fn boot_secrets(
        &self,
        environment_id: Uuid,
        generation: u64,
    ) -> Result<v1::GetBootSecretsResponse, Status> {
        let (secrets, records) = self
            .with_live(environment_id, generation, |access| {
                let secrets = access
                    .boot_secrets
                    .iter()
                    .map(|(purpose, value)| v1::BootSecret {
                        purpose: *purpose,
                        value: value.to_vec(),
                    })
                    .collect::<Vec<_>>();
                (secrets, access.bound_secrets.clone())
            })
            .ok()
            .filter(|(secrets, _)| !secrets.is_empty())
            .ok_or_else(|| Status::failed_precondition("no boot secrets"))?;
        Ok(v1::GetBootSecretsResponse {
            secrets,
            bound_secrets: crate::runner::records_to_proto(records.local),
            platform_bound_secrets: BootRecords::platform_to_proto(records.platform),
        })
    }

    /// `read` of the live access for `environment_id`'s `generation`.
    fn with_live<T>(
        &self,
        environment_id: Uuid,
        generation: u64,
        read: impl FnOnce(&PublishedGenerationAccess) -> T,
    ) -> Result<T, Status> {
        if environment_id != self.environment_id {
            return Err(Status::permission_denied("runner identity mismatch"));
        }
        if generation == 0 {
            return Err(Status::invalid_argument(
                "invalid runner generation identity",
            ));
        }
        let mut current = self
            .current
            .lock()
            .map_err(|_| Status::unavailable("runner generation access unavailable"))?;
        if current.retiring {
            return Err(Status::failed_precondition("runner is retiring"));
        }
        let access = current
            .access
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("runner generation access unavailable"))?;
        if access.generation != generation {
            return Err(Status::failed_precondition(
                "runner generation does not match",
            ));
        }
        if !generation_process_alive(&access.liveness) {
            current.access = None;
            return Err(Status::failed_precondition("runner generation is not live"));
        }
        Ok(read(access))
    }
}

impl GenerationAccessGuard {
    pub(super) fn revoke(&self) {
        let mut current = self
            .cell
            .current
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if current
            .access
            .as_ref()
            .is_some_and(|access| access.generation == self.generation)
        {
            current.access = None;
        }
    }
}

impl Drop for GenerationAccessGuard {
    fn drop(&mut self) {
        self.revoke();
    }
}

fn generation_process_alive(liveness: &OwnedFd) -> bool {
    let mut descriptor = libc::pollfd {
        fd: liveness.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one owned pidfd pins the process birth. Zero-timeout poll never
    // waits on lifecycle state; exit, descriptor errors and interruption deny.
    unsafe { libc::poll(&mut descriptor, 1, 0) == 0 && descriptor.revents == 0 }
}
