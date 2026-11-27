//! Suspend (#5529, `docs/dev/IDLE-STOP.md`, "Suspend"): a standard Pod's VM
//! pauses inside its Pod, keeping every process, and resumes on use.
//!
//! The guest may ask for a pause on [`HOSTED_SUSPEND_VSOCK_PORT`]; only this
//! runtime resumes it, for a connection on one of the Pod's published ports
//! or for a stop. Nothing the guest sends resumes it. While the VM is paused
//! the readiness file stays, so the Pod stays Ready, and the kubelet's token
//! renewals are held. A wake resumes the vCPUs, delivers the tokens renewed
//! meanwhile while the workload is still frozen, then thaws it, and only then
//! does the waking connection reach the guest. Each pause and resume this
//! runtime performs is recorded on its own line ([`PauseRecord`]), and the
//! boot's state on another ([`StateRecord`]) at each of them and every
//! [`STATE_RECORD_INTERVAL`]; billing reads both.

use std::future::Future;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use codewire_vmm_guest_probe::hosted_control::{
    HOSTED_HIBERNATE_REQUEST, HOSTED_REBIND_COMPLETE_REQUEST, HOSTED_SUSPEND_ACCEPTED,
    HOSTED_SUSPEND_EXCHANGE, HOSTED_SUSPEND_REFUSED, HOSTED_SUSPEND_REQUEST,
    HOSTED_SUSPEND_VSOCK_PORT, HostedMessage, HostedTokens,
};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::UnixListener;
use uuid::Uuid;

use super::PodRuntimeError;
use super::hibernate::HibernateControl;

/// What starts this runtime's record of a pause or resume. Guest output
/// reaches the Pod log only escaped and prefixed with
/// [`super::guest_log::PREFIX`], so a line starting with this was written
/// here and nowhere else.
pub(super) const RECORD_MARKER: &str = "standard runtime: vm-pause-record ";

/// What starts this runtime's record of a boot's pause state, for the same
/// reason.
pub(super) const STATE_MARKER: &str = "standard runtime: vm-pause-state ";

/// How often the state record is written, paused or not, besides at each
/// pause and resume. Billing rebuilds a boot's state from the latest one it
/// has, so one lost line leaves at most this long unknown.
pub(super) const STATE_RECORD_INTERVAL: Duration = Duration::from_secs(30);

/// The guest's suspend requests are answered at most this often. A freeze
/// that fails after `ok` leaves the VM running and writes an error line, so
/// a guest asking in a loop could otherwise multiply that line in the Pod log
/// billing reads.
pub(super) const ANSWER_INTERVAL: Duration = Duration::from_secs(1);

/// The VM a [`Suspender`] pauses and wakes. Production's is the boot's
/// [`crate::runner::SuspendControl`]; a test's records what was asked.
pub(super) trait PausableVm: Send + Sync + 'static {
    fn freeze_and_pause(
        &self,
        operation: Uuid,
    ) -> impl Future<Output = Result<(), PodRuntimeError>> + Send;
    fn resume(&self) -> impl Future<Output = Result<(), PodRuntimeError>> + Send;
    fn thaw(&self, operation: Uuid) -> impl Future<Output = Result<(), PodRuntimeError>> + Send;
    fn deliver_tokens(
        &self,
        tokens: &HostedTokens,
    ) -> impl Future<Output = Result<(), PodRuntimeError>> + Send;
}

impl PausableVm for crate::runner::SuspendControl {
    async fn freeze_and_pause(&self, operation: Uuid) -> Result<(), PodRuntimeError> {
        Ok(Self::freeze_and_pause(self, operation).await?)
    }

    async fn resume(&self) -> Result<(), PodRuntimeError> {
        Ok(Self::resume(self).await?)
    }

    async fn thaw(&self, operation: Uuid) -> Result<(), PodRuntimeError> {
        Ok(Self::thaw(self, operation).await?)
    }

    async fn deliver_tokens(&self, tokens: &HostedTokens) -> Result<(), PodRuntimeError> {
        Ok(self
            .send_hosted(&HostedMessage::Tokens(tokens.clone()))
            .await?)
    }
}

/// One pause or resume, as this runtime performed it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PauseRecord {
    pub(super) event: PauseEvent,
    /// The boot the VM is: a new Pod starts a new generation.
    pub(super) generation: u64,
    /// Counts this boot's records from 1, so a missing one shows.
    pub(super) sequence: u64,
    pub(super) at_unix_ms: u128,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PauseEvent {
    Paused,
    Resumed,
}

impl PauseRecord {
    /// The record's line: the marker, then one JSON object.
    pub(super) fn line(&self) -> String {
        let event = match self.event {
            PauseEvent::Paused => "paused",
            PauseEvent::Resumed => "resumed",
        };
        format!(
            "{RECORD_MARKER}{{\"event\":\"{event}\",\"generation\":{},\"sequence\":{},\"at_unix_ms\":{}}}",
            self.generation, self.sequence, self.at_unix_ms
        )
    }
}

/// A boot's pause state: its latest pause or resume record's sequence and
/// time, or 0 and the boot's start before the first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct StateRecord {
    pub(super) generation: u64,
    pub(super) sequence: u64,
    pub(super) paused: bool,
    pub(super) since_unix_ms: u128,
}

impl StateRecord {
    /// The record's line: the marker, then one JSON object.
    pub(super) fn line(&self) -> String {
        let state = if self.paused { "paused" } else { "running" };
        format!(
            "{STATE_MARKER}{{\"generation\":{},\"sequence\":{},\"state\":\"{state}\",\"since_unix_ms\":{}}}",
            self.generation, self.sequence, self.since_unix_ms
        )
    }
}

/// A line this runtime writes for billing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Record {
    Pause(PauseRecord),
    State(StateRecord),
}

impl Record {
    pub(super) fn line(&self) -> String {
        match self {
            Self::Pause(record) => record.line(),
            Self::State(record) => record.line(),
        }
    }
}

type ReadTokens = Box<dyn Fn() -> Result<HostedTokens, PodRuntimeError> + Send + Sync>;
type RecordSink = Box<dyn Fn(&Record) + Send + Sync>;

/// A boot's suspend state. One lock serializes every pause, wake and token
/// delivery, so a wake can't come between a pause's answer and the pause.
pub(super) struct Suspender<V> {
    vm: V,
    generation: u64,
    read_tokens: ReadTokens,
    record: RecordSink,
    state: tokio::sync::Mutex<State>,
}

struct State {
    /// The operation of the pause in force, while the VM is paused.
    paused: Option<Uuid>,
    /// The tokens the guest last applied.
    delivered: HostedTokens,
    sequence: u64,
    /// The latest pause or resume record's time, or the boot's start.
    since_unix_ms: u128,
    /// When the state record was last written.
    state_written: Option<tokio::time::Instant>,
}

impl<V: PausableVm> Suspender<V> {
    pub(super) fn new(
        vm: V,
        generation: u64,
        delivered: HostedTokens,
        read_tokens: ReadTokens,
        record: RecordSink,
    ) -> Self {
        Self {
            vm,
            generation,
            read_tokens,
            record,
            state: tokio::sync::Mutex::new(State {
                paused: None,
                delivered,
                sequence: 0,
                since_unix_ms: now_unix_ms(),
                state_written: None,
            }),
        }
    }

    #[cfg(test)]
    pub(super) async fn is_paused(&self) -> bool {
        self.state.lock().await.paused.is_some()
    }

    /// Answers a guest's suspend request with `answer(accepted)`, then, when
    /// accepted, freezes the workload and pauses the VM. A VM already paused
    /// refuses. Returns whether it paused.
    pub(super) async fn suspend<F>(
        &self,
        answer: impl FnOnce(bool) -> F,
    ) -> Result<bool, PodRuntimeError>
    where
        F: Future<Output = ()>,
    {
        let mut state = self.state.lock().await;
        let accepted = state.paused.is_none();
        answer(accepted).await;
        if !accepted {
            return Ok(false);
        }
        let operation = Uuid::new_v4();
        self.vm.freeze_and_pause(operation).await?;
        state.paused = Some(operation);
        self.note(&mut state, PauseEvent::Paused);
        Ok(true)
    }

    /// Wakes a paused VM: resumes its vCPUs, delivers any token renewed since
    /// the pause while the workload is still frozen, then thaws it. A VM that
    /// isn't paused is left alone. Returns whether it woke.
    pub(super) async fn wake(&self) -> Result<bool, PodRuntimeError> {
        let mut state = self.state.lock().await;
        let Some(operation) = state.paused else {
            return Ok(false);
        };
        self.vm.resume().await?;
        state.paused = None;
        self.note(&mut state, PauseEvent::Resumed);
        // The workload thaws whatever the delivery did; a failed delivery is
        // this wake's error, as a failed refresh is the running loop's.
        let delivered = self.deliver_if_renewed(&mut state).await;
        self.vm.thaw(operation).await?;
        delivered.map(|()| true)
    }

    /// Delivers the tokens when the kubelet has renewed one, as the running
    /// loop does every tick; while paused they are held for the wake.
    pub(super) async fn refresh(&self) -> Result<(), PodRuntimeError> {
        let mut state = self.state.lock().await;
        if state.paused.is_some() {
            return Ok(());
        }
        self.deliver_if_renewed(&mut state).await
    }

    async fn deliver_if_renewed(&self, state: &mut State) -> Result<(), PodRuntimeError> {
        let current = (self.read_tokens)()?;
        if current != state.delivered {
            self.vm.deliver_tokens(&current).await?;
            state.delivered = current;
        }
        Ok(())
    }

    /// Writes the state record when it wasn't written in the last
    /// [`STATE_RECORD_INTERVAL`], paused or not. The boot's loop calls it
    /// every tick.
    pub(super) async fn write_state_when_due(&self) {
        let mut state = self.state.lock().await;
        if state
            .state_written
            .is_none_or(|written| written.elapsed() >= STATE_RECORD_INTERVAL)
        {
            self.write_state(&mut state);
        }
    }

    fn note(&self, state: &mut State, event: PauseEvent) {
        state.sequence += 1;
        state.since_unix_ms = now_unix_ms();
        (self.record)(&Record::Pause(PauseRecord {
            event,
            generation: self.generation,
            sequence: state.sequence,
            at_unix_ms: state.since_unix_ms,
        }));
        self.write_state(state);
    }

    fn write_state(&self, state: &mut State) {
        state.state_written = Some(tokio::time::Instant::now());
        (self.record)(&Record::State(StateRecord {
            generation: self.generation,
            sequence: state.sequence,
            paused: state.paused.is_some(),
            since_unix_ms: state.since_unix_ms,
        }));
    }
}

fn now_unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_millis())
}

/// A stop of a paused VM wakes it first, so the guest shuts down cleanly
/// rather than being killed paused at the stop's timeout. `stop` runs either
/// way.
pub(super) async fn stop_awake<V: PausableVm, T>(
    suspender: &Suspender<V>,
    stop: impl Future<Output = T>,
) -> T {
    if let Err(error) = suspender.wake().await {
        eprintln!("standard runtime: the stop could not wake the paused VM: {error}");
    }
    stop.await
}

/// Listens for the guest's suspend, hibernate, and restore re-bind completion
/// requests on vsock 7784 until the Pod ends (#5529, #6647).
pub(super) fn listen<V: PausableVm>(
    vsock_socket: &Path,
    suspender: Arc<Suspender<V>>,
    hibernate: Arc<HibernateControl>,
) -> std::io::Result<tokio::task::JoinHandle<()>> {
    let path = super::guest_log::host_socket(vsock_socket, HOSTED_SUSPEND_VSOCK_PORT);
    // A socket left by this Pod's last boot would refuse the bind.
    match std::fs::remove_file(&path) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error),
        _ => {}
    }
    let listener = UnixListener::bind(&path)?;
    Ok(tokio::spawn(serve(listener, suspender, hibernate)))
}

/// One request at a time, each at least [`ANSWER_INTERVAL`] after the last
/// one ended: a second waits.
async fn serve<V: PausableVm>(
    listener: UnixListener,
    suspender: Arc<Suspender<V>>,
    hibernate: Arc<HibernateControl>,
) {
    let mut next = tokio::time::Instant::now();
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            // An accept error such as EMFILE would otherwise spin.
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        };
        tokio::time::sleep_until(next).await;
        if let Err(error) = answer_with_hibernate(stream, &suspender, &hibernate).await {
            eprintln!("standard runtime: the guest's sleep control request failed: {error}");
        }
        next = tokio::time::Instant::now() + ANSWER_INTERVAL;
    }
}

#[cfg(test)]
async fn answer<V, S>(stream: S, suspender: &Suspender<V>) -> Result<(), PodRuntimeError>
where
    V: PausableVm,
    S: AsyncRead + AsyncWrite + Unpin,
{
    answer_with_hibernate(stream, suspender, &HibernateControl::normal()).await
}

/// Reads one newline-terminated request line (at most 16 bytes):
/// - `suspend\n`: pauses the VM (refused if hibernate is already armed).
/// - `hibernate\n`: arms hibernate-on-SIGTERM (at most once; non-billing).
/// - `rebind-ok\n`: signals post-restore re-bind complete (at most once, only
///   while actively restoring).
///
/// Anything else is closed unanswered.
pub(super) async fn answer_with_hibernate<V, S>(
    mut stream: S,
    suspender: &Suspender<V>,
    hibernate: &HibernateControl,
) -> Result<(), PodRuntimeError>
where
    V: PausableVm,
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Some(line) = read_control_line(&mut stream).await else {
        return Ok(());
    };
    if line.as_slice() == HOSTED_SUSPEND_REQUEST {
        if hibernate.is_armed() {
            write_control_reply(&mut stream, false).await;
            return Ok(());
        }
        return suspender
            .suspend(|accepted| async move {
                write_control_reply(&mut stream, accepted).await;
            })
            .await
            .map(drop);
    }
    if line.as_slice() == HOSTED_HIBERNATE_REQUEST {
        let accepted = hibernate.arm();
        write_control_reply(&mut stream, accepted).await;
        return Ok(());
    }
    if line.as_slice() == HOSTED_REBIND_COMPLETE_REQUEST {
        let accepted = hibernate.signal_rebind_ok();
        write_control_reply(&mut stream, accepted).await;
        return Ok(());
    }
    Ok(())
}

async fn read_control_line<S: AsyncRead + Unpin>(stream: &mut S) -> Option<Vec<u8>> {
    const MAX_CONTROL_LINE: usize = 16;
    let mut line = Vec::with_capacity(MAX_CONTROL_LINE);
    let read = async {
        let mut byte = [0_u8; 1];
        while line.len() < MAX_CONTROL_LINE {
            match stream.read(&mut byte).await {
                Ok(0) => return None,
                Ok(_) => {
                    line.push(byte[0]);
                    if byte[0] == b'\n' {
                        return Some(line);
                    }
                }
                Err(_) => return None,
            }
        }
        None
    };
    tokio::time::timeout(HOSTED_SUSPEND_EXCHANGE, read)
        .await
        .ok()
        .flatten()
}

async fn write_control_reply<S: AsyncWrite + Unpin>(stream: &mut S, accepted: bool) {
    let reply = if accepted {
        HOSTED_SUSPEND_ACCEPTED
    } else {
        HOSTED_SUSPEND_REFUSED
    };
    let sent = async {
        stream.write_all(reply).await?;
        stream.shutdown().await
    };
    let _ = tokio::time::timeout(HOSTED_SUSPEND_EXCHANGE, sent).await;
}

#[cfg(test)]
mod tests;
