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

use super::intercept::{BootSecrets, FrontDoorStop};
use super::{
    EgressBrokerProcess, FrontDoorFailure, NetworkWorkerProcess, RunnerError, SIGNAL_STOP_TIMEOUT,
    duplicate_inherited_descriptor, prepare_isolated_child, raise_open_file_limit,
};
use crate::broker_control::encode_intercept_frame;
use crate::diagnostic_log::{DiagnosticLog, LogField, record};
use crate::front_door::{
    ControlChannel, DroppedSocket, FRONT_DOOR_CONTROL_FD, FRONT_DOOR_CREDENTIALS_MESSAGE,
    FRONT_DOOR_FAILED_PREFIX, FRONT_DOOR_READY_MESSAGE, FRONT_DOOR_SOCKETS_MESSAGE,
    ROLE_TAG_TIMEOUT, front_door_dropped_pairing, front_door_serving_pairing,
};

mod reports;
pub(crate) use reports::FrontDoorReports;

/// The egress broker's hand-off end, and where the front door's refusal
/// reports go once it serves.
type HandedOff = (OwnedFd, Option<FrontDoorReports>);

/// How long the front door has to confine itself and make its CA.
const FRONT_DOOR_READY_TIMEOUT: Duration = Duration::from_secs(10);
/// A ready message: the prefix and a DER certificate of well under 4 KiB.
const MAX_READY_MESSAGE: usize = 8 * 1024;
/// What the front door may say once it serves: a word, or a refusal report
/// (#5058), the longer.
const MAX_SERVING_MESSAGE: usize = crate::front_door::refusals::MAX_FRONT_DOOR_REPORT_BYTES;
/// How long the front door has, once a pairing's sockets reach it, to check
/// their role tags and say it serves. It reads each of a pairing's two role
/// tags within `ROLE_TAG_TIMEOUT` before it can say so, hence twice that and
/// a second for the word; a change to those waits changes this.
const SERVING_TIMEOUT: Duration = Duration::from_secs(2 * ROLE_TAG_TIMEOUT.as_secs() + 1);
/// The most pairings remembered as unanswered. The front door's word for one
/// already forgotten is recorded as unexpected, which changes nothing else.
const MAX_UNANSWERED_PAIRINGS: usize = 8;

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
        let mut command = crate::swept_tokio_command(executable, &[]);
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
    stopped: StopRecord,
    watch: FrontDoorWatch,
    socket: std::path::PathBuf,
    handoff: Option<tokio::sync::oneshot::Sender<HandedOff>>,
    _pairing: FrontDoorPairing,
    secrets: BootSecrets,
}

impl std::fmt::Debug for RunningFrontDoor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RunningFrontDoor")
            .field("pid", &self.watch.pid)
            .field("handed_off", &self.handoff.is_none())
            .finish_non_exhaustive()
    }
}

impl RunningFrontDoor {
    /// Bind `socket` for this generation's credential brokers, each of which
    /// presents the boot's pairing secret from `secrets`.
    pub(crate) fn listen(
        process: FrontDoorProcess,
        socket: &Path,
        secrets: BootSecrets,
    ) -> Result<Self, RunnerError> {
        let log = DiagnosticLog::inherited().map(std::sync::Arc::new);
        Self::listen_recording(process, socket, secrets, log)
    }

    /// [`Self::listen`], recording in `log`.
    fn listen_recording(
        mut process: FrontDoorProcess,
        socket: &Path,
        secrets: BootSecrets,
        log: Option<std::sync::Arc<DiagnosticLog>>,
    ) -> Result<Self, RunnerError> {
        let control = process.control.take().ok_or(FrontDoorFailure::Sockets)?;
        let stopped = StopRecord::default();
        let (handoff, pairing) = FrontDoorPairing::listen(
            socket,
            control,
            zeroize::Zeroizing::new(secrets.pairing().to_vec()),
            log.clone(),
            stopped.clone(),
        )?;
        Ok(Self {
            watch: FrontDoorWatch::start(process, log, stopped.clone()),
            stopped,
            socket: socket.to_owned(),
            handoff: Some(handoff),
            _pairing: pairing,
            secrets,
        })
    }

    /// Stop the front door and reap it.
    pub(crate) async fn stop(&mut self) -> Result<(), RunnerError> {
        self.watch.stop().await
    }

    /// Where the front door stopped, if it has and nobody asked it to.
    pub(crate) fn stopped(&self) -> Option<FrontDoorStop> {
        self.stopped.get()
    }

    /// The boot's secrets, for `GetBootSecrets`.
    pub(crate) fn secrets(&self) -> &BootSecrets {
        &self.secrets
    }

    /// The socket the credential broker pairs through.
    pub(crate) fn socket(&self) -> &Path {
        &self.socket
    }

    /// Give the pairing the egress broker's hand-off end, once, and where
    /// the front door's refusal reports go from then on. A front door
    /// already gone fails the boot, and the end closes here.
    pub(crate) fn hand_off(
        &mut self,
        handoff: OwnedFd,
        reports: Option<FrontDoorReports>,
    ) -> Result<(), RunnerError> {
        self.handoff
            .take()
            .ok_or(FrontDoorFailure::Sockets)?
            .send((handoff, reports))
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
        let reports = worker
            .broker
            .as_ref()
            .and_then(|broker| broker.refusals.clone())
            .map(|log| FrontDoorReports::new(log, self.request.intercepts.clone()));
        front_door.hand_off(handoff, reports)
    }

    /// Stop and reap the generation's front door, when it has one.
    pub(super) async fn stop_front_door(&mut self) -> Result<(), RunnerError> {
        match self.front_door.as_mut() {
            Some(front_door) => front_door.stop().await,
            None => Ok(()),
        }
    }
}

/// Where a generation's front door stopped, as its pairing and its watch
/// learn it, for a start that fails because of it. What the front door said
/// of itself is kept over the closed channel or the exit that follows.
#[derive(Clone, Default)]
pub(crate) struct StopRecord(std::sync::Arc<std::sync::Mutex<Option<FrontDoorStop>>>);

impl StopRecord {
    fn note(&self, stop: FrontDoorStop) {
        let mut recorded = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if recorded.is_none_or(|earlier| !earlier.named() && stop.named()) {
            *recorded = Some(stop);
        }
    }

    fn get(&self) -> Option<FrontDoorStop> {
        *self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Watches a generation's front door from the moment its socket is bound.
/// An exit nobody asked for is recorded in the runner's log with its status:
/// from then on the egress broker's hand-off end is closed, so every
/// intercepted dial is refused, and the log says why. Dropping the watch
/// kills the process.
struct FrontDoorWatch {
    pid: Option<u32>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<Result<(), RunnerError>>,
}

impl Drop for FrontDoorWatch {
    fn drop(&mut self) {
        // The task owns the process, which is killed when it is dropped.
        self.task.abort();
    }
}

impl FrontDoorWatch {
    fn start(
        mut process: FrontDoorProcess,
        log: Option<std::sync::Arc<DiagnosticLog>>,
        cause: StopRecord,
    ) -> Self {
        let pid = process.child.id();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            tokio::select! {
                // A stop that arrives as the process ends is still a stop.
                biased;
                // Asked to stop, or the generation is gone: not an exit to
                // report.
                _ = stopped => process.stop().await,
                exited = process.child.wait() => {
                    cause.note(FrontDoorStop::Exited);
                    record(log.as_deref(), "front_door_exited", &exit_fields(exited.ok()));
                    Ok(())
                }
            }
        });
        Self {
            pid,
            stop: Some(stop),
            task,
        }
    }

    /// Stop the process and reap it. A front door that already exited was
    /// reaped, and recorded, when it did.
    async fn stop(&mut self) -> Result<(), RunnerError> {
        let Some(stop) = self.stop.take() else {
            return Ok(());
        };
        // The watcher may have ended already, having seen the exit itself.
        let _ = stop.send(());
        (&mut self.task)
            .await
            .map_err(|_| RunnerError::FrontDoor(FrontDoorFailure::Wait))?
    }
}

/// How the process ended, as the log records it: its exit code, the signal
/// that killed it, or that neither could be read.
fn exit_fields(status: Option<std::process::ExitStatus>) -> Vec<(&'static str, LogField<'static>)> {
    use std::os::unix::process::ExitStatusExt as _;
    let Some(status) = status else {
        return vec![("status", LogField::Name("unknown"))];
    };
    match (status.code(), status.signal()) {
        (Some(code), _) => vec![("exit_code", LogField::Count(u64::from(code.unsigned_abs())))],
        (None, Some(signal)) => vec![("signal", LogField::Count(u64::from(signal.unsigned_abs())))],
        (None, None) => vec![("status", LogField::Name("unknown"))],
    }
}

/// What the front door said once a pairing's sockets reached it.
enum Acknowledgement {
    /// It serves the pairing it numbers.
    Serving(u64),
    /// It did not take the socket of the pairing it numbers, says why, and
    /// goes on to the next pairing.
    Dropped(u64, DroppedSocket),
    /// It refused them and named the stage that failed, or said something
    /// that is not this protocol.
    Refused(Vec<u8>),
    Gone,
    Silent,
}

impl Acknowledgement {
    fn of(reply: std::io::Result<(Vec<u8>, Vec<OwnedFd>)>) -> Self {
        let Ok((message, _)) = reply else {
            return Self::Gone;
        };
        if let Some(pairing) = front_door_serving_pairing(&message) {
            Self::Serving(pairing)
        } else if let Some((pairing, why)) = front_door_dropped_pairing(&message) {
            Self::Dropped(pairing, why)
        } else {
            Self::Refused(message)
        }
    }

    /// The pairing a word names.
    fn pairing(&self) -> Option<u64> {
        match self {
            Self::Serving(pairing) | Self::Dropped(pairing, _) => Some(*pairing),
            Self::Refused(_) | Self::Gone | Self::Silent => None,
        }
    }

    /// A word for a pairing the runner has not sent.
    fn not_this_protocol() -> Self {
        Self::Refused(Vec::new())
    }

    /// Where the front door stopped, when this says it has.
    fn stop(&self) -> Option<FrontDoorStop> {
        match self {
            Self::Refused(message) => Some(FrontDoorStop::at_stage(failed_stage(message))),
            Self::Gone => Some(FrontDoorStop::Gone),
            Self::Serving(_) | Self::Dropped(..) | Self::Silent => None,
        }
    }
}

/// The stage a front door's failure line names; `invalid` for anything that
/// is not one.
fn failed_stage(message: &[u8]) -> &str {
    message
        .strip_prefix(FRONT_DOOR_FAILED_PREFIX)
        .and_then(|stage| stage.strip_suffix(b"\n"))
        .and_then(|stage| std::str::from_utf8(stage).ok())
        .unwrap_or("invalid")
}

/// The pairings the front door has not answered for. Its word names its
/// pairing because one that arrives late must not be taken for the next
/// pairing's: that would release the next pairing's ends before the front
/// door has them (#4916).
#[derive(Default)]
struct Unanswered(std::collections::VecDeque<u64>);

impl Unanswered {
    fn add(&mut self, pairing: u64) {
        if self.0.len() == MAX_UNANSWERED_PAIRINGS {
            self.0.pop_front();
        }
        self.0.push_back(pairing);
    }

    /// Records the front door's word `said` for the earlier pairing it
    /// names: as that pairing's outcome if it was waiting for one, and as an
    /// unexpected word otherwise.
    fn late(&mut self, log: Option<&DiagnosticLog>, said: &Acknowledgement, pairing: u64) {
        let waiting = self.0.iter().position(|unanswered| *unanswered == pairing);
        if waiting.and_then(|index| self.0.remove(index)).is_some() {
            record_pairing(log, said, pairing);
            return;
        }
        let outcome = match said {
            Acknowledgement::Dropped(..) => "unexpected_dropped",
            _ => "unexpected_serving",
        };
        record(
            log,
            "front_door_pairing",
            &[
                ("outcome", LogField::Name(outcome)),
                ("pairing", LogField::Count(pairing)),
            ],
        );
    }
}

/// The front door's answer for `pairing`, within the serving limit. Its word
/// for an earlier pairing is recorded for that one and the wait goes on with
/// the time left, so only this pairing's own word or the limit ends it; so
/// does a refusal report, which goes to `reports`.
async fn acknowledgement(
    control: &mut ControlChannel,
    log: Option<&DiagnosticLog>,
    pairing: u64,
    unanswered: &mut Unanswered,
    reports: &mut Option<FrontDoorReports>,
) -> Acknowledgement {
    let limit = tokio::time::Instant::now() + SERVING_TIMEOUT;
    loop {
        let reply = tokio::time::timeout_at(limit, control.receive(MAX_SERVING_MESSAGE, 0)).await;
        if let Ok(Ok((message, _))) = &reply
            && reports::taken(reports, message)
        {
            continue;
        }
        let Ok(said) = reply.map(Acknowledgement::of) else {
            return Acknowledgement::Silent;
        };
        match said.pairing() {
            Some(earlier) if earlier < pairing => unanswered.late(log, &said, earlier),
            Some(later) if later > pairing => return Acknowledgement::not_this_protocol(),
            _ => return said,
        }
    }
}

/// Records how the generation's `pairing`th pairing ended. `paired` means
/// the front door said it serves, never only that the sockets were sent.
fn record_pairing(log: Option<&DiagnosticLog>, acknowledgement: &Acknowledgement, pairing: u64) {
    let pairing = ("pairing", LogField::Count(pairing));
    let fields: &[(&'static str, LogField<'_>)] = match acknowledgement {
        Acknowledgement::Serving(_) => &[("outcome", LogField::Name("paired")), pairing],
        Acknowledgement::Dropped(_, why) => &[
            ("outcome", LogField::Name("front_door_dropped")),
            ("stage", LogField::Name(why.stage())),
            pairing,
        ],
        Acknowledgement::Refused(message) => &[
            ("outcome", LogField::Name("front_door_refused")),
            ("stage", LogField::Code(failed_stage(message))),
            pairing,
        ],
        Acknowledgement::Gone => &[("outcome", LogField::Name("front_door_gone")), pairing],
        Acknowledgement::Silent => &[("outcome", LogField::Name("unacknowledged")), pairing],
    };
    record(log, "front_door_pairing", fields);
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
        stopped: StopRecord,
    ) -> Result<(tokio::sync::oneshot::Sender<HandedOff>, Self), RunnerError> {
        let (mut listener, identity) =
            crate::uds::bind_owner_only_listener(socket).map_err(|_| FrontDoorFailure::Sockets)?;
        let socket = socket.to_owned();
        let (handoff_sender, handoff_receiver) = tokio::sync::oneshot::channel::<HandedOff>();
        let task = tokio::spawn(async move {
            // A runner that drops the sender has failed the boot.
            let handed_off = tokio::select! {
                handoff = handoff_receiver => handoff.ok(),
                _ = control.receive(MAX_READY_MESSAGE, 0) => {
                    stopped.note(FrontDoorStop::Gone);
                    record(
                        log.as_deref(),
                        "front_door_pairing",
                        &[("outcome", LogField::Name("front_door_gone"))],
                    );
                    None
                }
            };
            let (mut handoff, mut reports) =
                handed_off.map_or((None, None), |(end, reports)| (Some(end), reports));
            let mut pairings = 0_u64;
            let mut unanswered = Unanswered::default();
            while handoff.is_some() || pairings > 0 {
                // Same-user peers only; others are closed unseen. A front door
                // that writes or closes has failed: a hand-off end still here
                // is dropped, so the egress broker sees the closed socket and
                // refuses intercepted dials rather than queueing them for no
                // one.
                let stream = tokio::select! {
                    (stream, _) = axum::serve::Listener::accept(&mut listener) => stream,
                    // Between pairings the front door says only that a
                    // pairing it was slow to check serves after all, that it
                    // has failed, or what it refused.
                    reply = control.receive(MAX_SERVING_MESSAGE, 0) => {
                        if let Ok((message, _)) = &reply && reports::taken(&mut reports, message) {
                            continue;
                        }
                        let said = Acknowledgement::of(reply);
                        let failed = match said.pairing() {
                            Some(earlier) if earlier <= pairings => {
                                unanswered.late(log.as_deref(), &said, earlier);
                                continue;
                            }
                            Some(_) => Acknowledgement::not_this_protocol(),
                            None => said,
                        };
                        stopped.note(failed.stop().unwrap_or(FrontDoorStop::Failed));
                        record_pairing(log.as_deref(), &failed, pairings);
                        drop(handoff.take());
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
                // The runner's copies of the ends it sends stay open until the
                // front door has said it serves them, or the wait for that
                // ends. A socket whose only reference is in flight can arrive
                // dead on macOS once its sender has closed its last copy
                // (#4916). One pairing is in flight at a time, so at most
                // these two are held.
                let mut in_flight = Vec::with_capacity(2);
                let sent = match handoff.take() {
                    Some(waiting) => {
                        let descriptors = [waiting.as_fd(), credentials.as_fd()];
                        let sent = control.send(FRONT_DOOR_SOCKETS_MESSAGE, &descriptors).await;
                        in_flight.push(waiting);
                        sent
                    }
                    None => {
                        control
                            .send(FRONT_DOOR_CREDENTIALS_MESSAGE, &[credentials.as_fd()])
                            .await
                    }
                };
                in_flight.push(credentials);
                if sent.is_err() {
                    record(
                        log.as_deref(),
                        "front_door_pairing",
                        &[
                            ("outcome", LogField::Name("sockets_failed")),
                            ("pairing", LogField::Count(pairings + 1)),
                        ],
                    );
                    break;
                }
                pairings += 1;
                // The front door checks each socket before it serves it; only
                // its own word says the pairing took. For a later broker's
                // socket it does not take, it says so and why, and the next
                // broker pairs.
                let said = acknowledgement(
                    &mut control,
                    log.as_deref(),
                    pairings,
                    &mut unanswered,
                    &mut reports,
                )
                .await;
                // After its word or the limit the runner keeps no copy of any
                // end: a front door that dies takes them with it, and the
                // egress broker sees the close.
                drop(in_flight);
                if matches!(said, Acknowledgement::Silent) {
                    unanswered.add(pairings);
                }
                let stop = said.stop();
                if let Some(stop) = stop {
                    stopped.note(stop);
                }
                record_pairing(log.as_deref(), &said, pairings);
                if stop.is_some() {
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
