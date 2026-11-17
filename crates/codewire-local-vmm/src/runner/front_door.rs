//! The runner's side of an environment's front-door process (#3999).
//!
//! `prepare()` spawns it before the seed is written: the process confines
//! itself, generates the environment's CA for the interception bindings and
//! returns the CA certificate, which goes into the seed. Once the egress
//! broker and the credential broker are up, the runner passes it their two
//! sockets. The protocol is in [`crate::front_door`].

use std::os::fd::{AsFd as _, AsRawFd as _, OwnedFd};
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use codewire_egress_policy::handoff::stream_pair;
use codewire_egress_policy::intercept::InterceptSet;
use uuid::Uuid;

use super::intercept::BootSecrets;
use super::{
    EgressBrokerProcess, FrontDoorFailure, NetworkWorkerProcess, RunnerError, SIGNAL_STOP_TIMEOUT,
    duplicate_inherited_descriptor, prepare_isolated_child, raise_open_file_limit,
};
use crate::broker_control::encode_intercept_frame;
use crate::diagnostic_log::{DiagnosticLog, LogField, record};
use crate::front_door::{
    ControlChannel, FRONT_DOOR_CONTROL_FD, FRONT_DOOR_CREDENTIALS_MESSAGE,
    FRONT_DOOR_READY_MESSAGE, FRONT_DOOR_SOCKETS_MESSAGE,
};

/// How long the front door has to confine itself and make its CA.
const FRONT_DOOR_READY_TIMEOUT: Duration = Duration::from_secs(10);
/// A ready message: the prefix and a DER certificate of well under 4 KiB.
const MAX_READY_MESSAGE: usize = 8 * 1024;

/// A running front-door process. Dropping it kills the process, which fails
/// every intercepted dial closed. Its control channel moves to the pairing
/// once the egress broker is up.
pub(crate) struct FrontDoorProcess {
    child: tokio::process::Child,
    control: Option<ControlChannel>,
    ca_der: Vec<u8>,
}

impl std::fmt::Debug for FrontDoorProcess {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FrontDoorProcess")
            .field("pid", &self.child.id())
            .finish_non_exhaustive()
    }
}

impl FrontDoorProcess {
    /// Start the environment's front door for `intercepts` and wait for its
    /// CA certificate. Any failure kills the process and fails the boot.
    pub(crate) async fn spawn(
        executable: &Path,
        working_directory: &Path,
        vm_id: Uuid,
        generation: u64,
        intercepts: &InterceptSet,
    ) -> Result<Self, RunnerError> {
        let (runner_end, child_end) = stream_pair().map_err(|_| FrontDoorFailure::Spawn)?;
        let inherited = duplicate_inherited_descriptor(child_end.as_raw_fd())
            .map_err(|_| FrontDoorFailure::Spawn)?;
        drop(child_end);
        let descriptors = [(inherited.as_raw_fd(), FRONT_DOOR_CONTROL_FD)];
        // SAFETY: getpid has no preconditions.
        let expected_parent = unsafe { libc::getpid() };
        let mut command = tokio::process::Command::new(executable);
        command
            .arg("__native-front-door")
            .arg("--environment-id")
            .arg(vm_id.to_string())
            .arg("--generation")
            .arg(generation.to_string())
            .env_clear()
            .current_dir(working_directory)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        // SAFETY: the hook makes only async-signal-safe calls on descriptors
        // this process owns, as for the runner's other isolated children.
        unsafe {
            command.pre_exec(move || {
                raise_open_file_limit()?;
                prepare_isolated_child(expected_parent, &descriptors)
            });
        }
        let child = command.spawn().map_err(|_| FrontDoorFailure::Spawn)?;
        drop(inherited);
        let control = ControlChannel::new(runner_end).map_err(|_| FrontDoorFailure::Spawn)?;
        let mut process = Self {
            child,
            control: Some(control),
            ca_der: Vec::new(),
        };
        match process.start(intercepts).await {
            Ok(ca_der) => {
                process.ca_der = ca_der;
                Ok(process)
            }
            Err(error) => {
                process.stop().await?;
                Err(error)
            }
        }
    }

    async fn start(&mut self, intercepts: &InterceptSet) -> Result<Vec<u8>, RunnerError> {
        let control = self.control.as_mut().ok_or(FrontDoorFailure::Startup)?;
        let bindings = encode_intercept_frame(intercepts).map_err(|_| FrontDoorFailure::Startup)?;
        let exchange = async {
            control.send(&bindings, &[]).await?;
            control.receive(MAX_READY_MESSAGE, 0).await
        };
        let (reply, _) = tokio::time::timeout(FRONT_DOOR_READY_TIMEOUT, exchange)
            .await
            .map_err(|_| FrontDoorFailure::StartTimeout)?
            .map_err(|_| FrontDoorFailure::Startup)?;
        match reply.strip_prefix(FRONT_DOOR_READY_MESSAGE) {
            Some(der) if !der.is_empty() => Ok(der.to_vec()),
            _ => Err(RunnerError::FrontDoor(FrontDoorFailure::Startup)),
        }
    }

    /// The environment CA's certificate, in DER, for the seed.
    pub(crate) fn ca_certificate_der(&self) -> &[u8] {
        &self.ca_der
    }

    /// Kill the process and wait for it.
    pub(crate) async fn stop(&mut self) -> Result<(), RunnerError> {
        if self
            .child
            .try_wait()
            .map_err(|_| FrontDoorFailure::Wait)?
            .is_some()
        {
            return Ok(());
        }
        // A process that already exited cannot be signalled; the wait below
        // reaps it either way.
        let _ = self.child.start_kill();
        tokio::time::timeout(SIGNAL_STOP_TIMEOUT, self.child.wait())
            .await
            .map_err(|_| FrontDoorFailure::Wait)?
            .map_err(|_| FrontDoorFailure::Wait)?;
        Ok(())
    }
}

/// A generation's front door: the process `prepare()` started and the
/// socket its credential broker pairs through, bound with it, so the socket
/// exists before the generation's access names it. The egress broker's
/// hand-off end follows once that broker is up.
pub(crate) struct RunningFrontDoor {
    _process: FrontDoorProcess,
    socket: std::path::PathBuf,
    handoff: Option<tokio::sync::oneshot::Sender<OwnedFd>>,
    _pairing: FrontDoorPairing,
    secrets: BootSecrets,
}

impl std::fmt::Debug for RunningFrontDoor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RunningFrontDoor")
            .field("process", &self._process)
            .field("handed_off", &self.handoff.is_none())
            .finish_non_exhaustive()
    }
}

impl RunningFrontDoor {
    /// Bind `socket` for this generation's credential brokers, each of which
    /// presents the boot's pairing secret from `secrets`.
    pub(crate) fn listen(
        mut process: FrontDoorProcess,
        socket: &Path,
        secrets: BootSecrets,
    ) -> Result<Self, RunnerError> {
        let control = process.control.take().ok_or(FrontDoorFailure::Sockets)?;
        let (handoff, pairing) = FrontDoorPairing::listen(
            socket,
            control,
            zeroize::Zeroizing::new(secrets.pairing().to_vec()),
            DiagnosticLog::inherited().map(std::sync::Arc::new),
        )?;
        Ok(Self {
            _process: process,
            socket: socket.to_owned(),
            handoff: Some(handoff),
            _pairing: pairing,
            secrets,
        })
    }

    /// The boot's secrets, for `GetBootSecrets`.
    pub(crate) fn secrets(&self) -> &BootSecrets {
        &self.secrets
    }

    /// The socket the credential broker pairs through.
    pub(crate) fn socket(&self) -> &Path {
        &self.socket
    }

    /// Give the pairing the egress broker's hand-off end, once. A front door
    /// already gone fails the boot, and the end closes here.
    pub(crate) fn hand_off(&mut self, handoff: OwnedFd) -> Result<(), RunnerError> {
        self.handoff
            .take()
            .ok_or(FrontDoorFailure::Sockets)?
            .send(handoff)
            .map_err(|_| RunnerError::FrontDoor(FrontDoorFailure::Sockets))
    }
}

impl super::RunningVm {
    /// Once the egress broker is up (#3999), its hand-off end goes to the
    /// pairing `prepare()` bound. Without a front door there is nothing to
    /// pair; a front door whose broker has no hand-off end fails the boot,
    /// closed.
    pub(super) fn pair_front_door(
        &mut self,
        worker: &mut NetworkWorkerProcess,
    ) -> Result<(), RunnerError> {
        let Some(front_door) = self.front_door.as_mut() else {
            return Ok(());
        };
        let handoff = worker
            .broker
            .as_mut()
            .and_then(EgressBrokerProcess::take_front_door_handoff)
            .ok_or(FrontDoorFailure::Sockets)?;
        front_door.hand_off(handoff)
    }
}

/// How long a connecting credential broker has to present its capability.
const PAIRING_CAPABILITY_TIMEOUT: Duration = Duration::from_secs(2);
/// The most capability bytes a pairing reads: the seed's own bound.
const MAX_PAIRING_CAPABILITY: usize = 512;

/// The private socket through which each of this generation's credential
/// brokers reaches the front door. The credential authority replaces the
/// broker every few minutes, and each successor pairs again, so it listens
/// for the generation's life (#3999). Once the egress broker's hand-off end
/// arrives, the first same-user connection that presents this generation's
/// capability is passed to the front door with it, and each later one alone;
/// any other connection is refused and logged. A broker that connects
/// earlier waits in the listen queue. If the front door fails, the hand-off
/// end is dropped if it is still here and the socket closes. Dropping it
/// stops listening.
pub(crate) struct FrontDoorPairing {
    task: tokio::task::JoinHandle<()>,
}

impl Drop for FrontDoorPairing {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl FrontDoorPairing {
    /// Listen on `socket`, mode 0600 in the environment's private socket
    /// directory, until one credential broker pairs.
    pub(crate) fn listen(
        socket: &Path,
        mut control: ControlChannel,
        capability: zeroize::Zeroizing<Vec<u8>>,
        log: Option<std::sync::Arc<DiagnosticLog>>,
    ) -> Result<(tokio::sync::oneshot::Sender<OwnedFd>, Self), RunnerError> {
        let (mut listener, identity) =
            crate::uds::bind_owner_only_listener(socket).map_err(|_| FrontDoorFailure::Sockets)?;
        let socket = socket.to_owned();
        let (handoff_sender, handoff_receiver) = tokio::sync::oneshot::channel::<OwnedFd>();
        let task = tokio::spawn(async move {
            // A runner that drops the sender has failed the boot.
            let mut handoff = tokio::select! {
                handoff = handoff_receiver => handoff.ok(),
                _ = control.receive(MAX_READY_MESSAGE, 0) => {
                    record(
                        log.as_deref(),
                        "front_door_pairing",
                        &[("outcome", LogField::Name("front_door_gone"))],
                    );
                    None
                }
            };
            let mut pairings = 0_u64;
            while handoff.is_some() || pairings > 0 {
                // Same-user peers only; others are closed unseen. A front door
                // that writes or closes has failed: a hand-off end still here
                // is dropped, so the egress broker sees the closed socket and
                // refuses intercepted dials rather than queueing them for no
                // one.
                let stream = tokio::select! {
                    (stream, _) = axum::serve::Listener::accept(&mut listener) => stream,
                    // The front door sends nothing more unless it failed.
                    _ = control.receive(MAX_READY_MESSAGE, 0) => {
                        drop(handoff.take());
                        record(
                            log.as_deref(),
                            "front_door_pairing",
                            &[("outcome", LogField::Name("front_door_gone"))],
                        );
                        break;
                    }
                };
                let credentials = match admit_pairing(stream, &capability).await {
                    Ok(credentials) => credentials,
                    Err(refusal) => {
                        record(
                            log.as_deref(),
                            "front_door_pairing",
                            &[
                                ("outcome", LogField::Name("refused")),
                                ("reason", LogField::Name(refusal)),
                            ],
                        );
                        continue;
                    }
                };
                // The first broker's session goes with the hand-off end, each
                // later one alone. A front door that cannot take them has
                // died; the runner sees its exit, and dials fail closed.
                let sent = match handoff.take() {
                    Some(waiting) => {
                        let descriptors = [waiting.as_fd(), credentials.as_fd()];
                        control.send(FRONT_DOOR_SOCKETS_MESSAGE, &descriptors).await
                    }
                    None => {
                        control
                            .send(FRONT_DOOR_CREDENTIALS_MESSAGE, &[credentials.as_fd()])
                            .await
                    }
                };
                // The runner keeps no copy of any end.
                drop(credentials);
                let outcome = if sent.is_ok() {
                    pairings += 1;
                    "paired"
                } else {
                    "sockets_failed"
                };
                record(
                    log.as_deref(),
                    "front_door_pairing",
                    &[
                        ("outcome", LogField::Name(outcome)),
                        ("pairing", LogField::Count(pairings)),
                    ],
                );
                if sent.is_err() {
                    break;
                }
            }
            drop(listener);
            // The socket is gone with its listener; a stale file is harmless
            // and the next boot replaces it.
            let _ = crate::uds::remove_bound_socket(&socket, &identity);
        });
        Ok((handoff_sender, Self { task }))
    }
}

/// The connection's descriptor when it presents `capability` first, as a
/// two-byte big-endian length and the capability's bytes.
async fn admit_pairing(
    mut stream: tokio::net::UnixStream,
    capability: &[u8],
) -> Result<OwnedFd, &'static str> {
    use tokio::io::AsyncReadExt as _;
    let presented = tokio::time::timeout(PAIRING_CAPABILITY_TIMEOUT, async {
        let length = usize::from(stream.read_u16().await.ok()?);
        if length > MAX_PAIRING_CAPABILITY {
            return None;
        }
        let mut presented = zeroize::Zeroizing::new(vec![0_u8; length]);
        stream.read_exact(&mut presented).await.ok()?;
        Some(presented)
    })
    .await
    .map_err(|_| "timeout")?
    .ok_or("malformed")?;
    if !constant_time_equal(&presented, capability) {
        return Err("capability");
    }
    let stream = stream.into_std().map_err(|_| "descriptor")?;
    Ok(OwnedFd::from(stream))
}

/// Whether two byte strings are equal, in time that depends only on their
/// lengths, which are not secret.
fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0_u8, |difference, (left, right)| {
                difference | (left ^ right)
            })
            == 0
}

#[cfg(test)]
mod tests;
