//! The environment's desktop (`docs/dev/SANDBOX-DESKTOP.md`): an X and VNC
//! server with an XFCE session, started by the launcher the workspace image
//! ships and run as the durable session [`DESKTOP_SESSION_NAME`].
//!
//! The daemon makes the viewer password at each start and writes it to the
//! launcher's standard input. It is held here for the desktop's lifetime and
//! nowhere durable, and reaches a caller only in a `running` answer.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use codewire_daemon_proto::daemon::v1;
use codewire_daemon_proto::{
    DESKTOP_DISPLAY, DESKTOP_SESSION_NAME, DESKTOP_VIEWER_PASSWORD_LENGTH, DESKTOP_VNC_PORT,
};
use tokio::sync::Mutex;
use tokio::time::Instant;
use tonic::Status;

use crate::Config;
use crate::durable_session::{SessionEngine, SessionError};
use crate::env::ProcessEnvironment;
use crate::forward::WorkloadSockets;

/// The line the launcher prints once its own X server holds the display
/// (`images/workspace/desktop/start`). A listener on the port alone would
/// not show that: another process may hold it.
const READY_LINE: &[u8] = b"codewire-desktop: display ready";
const START_TIMEOUT: Duration = Duration::from_secs(10);
const START_POLL: Duration = Duration::from_millis(100);
const LISTENER_PROBE_TIMEOUT: Duration = Duration::from_millis(500);
/// The launcher says little before the ready line; this bounds one read.
const OUTPUT_READ_LIMIT: u64 = 64 * 1024;
const PASSWORD_LENGTH: usize = DESKTOP_VIEWER_PASSWORD_LENGTH;
const PASSWORD_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";

/// Whether a desktop runs, read wherever the daemon starts a process. The
/// session engine owns it and clears it when the desktop's session ends.
#[derive(Clone, Debug, Default)]
pub(crate) struct Display(Arc<AtomicBool>);

impl Display {
    pub(crate) fn set(&self, running: bool) {
        self.0.store(running, Ordering::Release);
    }

    /// The session engine's report that the session `name` ended, however
    /// it ended.
    pub(crate) fn session_ended(&self, name: &str) {
        if name == DESKTOP_SESSION_NAME {
            self.set(false);
        }
    }

    /// Gives a new process the desktop's display while one runs, unless its
    /// request named a display itself. Nothing else is added.
    pub(crate) fn apply(&self, requested: &[String], environment: &mut ProcessEnvironment) {
        let names_display = |entry: &String| entry.starts_with("DISPLAY=");
        if !self.0.load(Ordering::Acquire) || requested.iter().any(names_display) {
            return;
        }
        environment.entries.retain(|entry| !names_display(entry));
        environment
            .entries
            .push(format!("DISPLAY={DESKTOP_DISPLAY}"));
    }
}

/// Where the workspace image keeps the desktop, and the port its VNC server
/// takes on the workload's loopback.
#[derive(Clone, Debug)]
pub(crate) struct Layout {
    pub(crate) launcher: String,
    pub(crate) server: String,
    pub(crate) port: u16,
    /// How long a start may take before the launcher is ended and the start
    /// fails.
    pub(crate) start_timeout: Duration,
}

impl Default for Layout {
    fn default() -> Self {
        Self {
            launcher: "/opt/codewire/desktop/start".into(),
            // The package's own binary: `Xvnc` beside it is a link through
            // /etc/alternatives, which outside the workload's root would
            // resolve against the wrong filesystem.
            server: "/usr/bin/Xtigervnc".into(),
            port: DESKTOP_VNC_PORT,
            start_timeout: START_TIMEOUT,
        }
    }
}

struct Running {
    session_id: String,
    viewer_password: String,
}

struct Inner {
    config: Config,
    engine: SessionEngine,
    sockets: WorkloadSockets,
    layout: Layout,
    /// Held across a start and a stop, so one runs at a time.
    current: Mutex<Option<Running>>,
    /// A start is in flight: a reader answers `starting` instead of waiting.
    starting: AtomicBool,
}

#[derive(Clone)]
pub(crate) struct Desktop {
    inner: Arc<Inner>,
}

impl Desktop {
    pub(crate) fn new(
        config: &Config,
        engine: SessionEngine,
        sockets: WorkloadSockets,
        layout: Layout,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                config: config.clone(),
                engine,
                sockets,
                layout,
                current: Mutex::new(None),
                starting: AtomicBool::new(false),
            }),
        }
    }

    /// Whether `session` is the desktop's, which the generic session API
    /// neither launches, restarts nor writes to.
    pub(crate) fn owns(session: &v1::SessionRecord) -> bool {
        session.name == DESKTOP_SESSION_NAME
    }

    pub(crate) async fn get(&self) -> Result<v1::Desktop, Status> {
        if let Err(reason) = self.available() {
            return Ok(unavailable(reason));
        }
        if self.inner.starting.load(Ordering::Acquire) {
            return Ok(in_state(v1::DesktopState::Starting));
        }
        let mut current = self.inner.current.lock().await;
        Ok(self.observe(&mut current).await)
    }

    /// Starts the desktop, or returns the one that runs. From here the start
    /// finishes even if this caller goes away: one abandoned halfway would
    /// leave a launcher running that nothing records, and a reader told
    /// `starting` for good.
    pub(crate) async fn start(&self) -> Result<v1::Desktop, Status> {
        self.available().map_err(|reason| {
            Status::failed_precondition(format!(
                "this environment's image has no desktop: {reason}"
            ))
        })?;
        let desktop = self.clone();
        tokio::spawn(async move { desktop.start_recorded().await })
            .await
            .map_err(unfinished)?
    }

    async fn start_recorded(&self) -> Result<v1::Desktop, Status> {
        let mut current = self.inner.current.lock().await;
        let desktop = self.observe(&mut current).await;
        if desktop.state == v1::DesktopState::Running as i32 {
            return Ok(desktop);
        }
        self.inner.starting.store(true, Ordering::Release);
        let started = self.launch().await;
        self.inner.starting.store(false, Ordering::Release);
        let (running, desktop) = started?;
        *current = Some(running);
        self.inner.engine.display().set(true);
        Ok(desktop)
    }

    /// Stops the desktop. As a start does, a stop finishes without its
    /// caller, and the desktop is forgotten only once its launcher is ended.
    pub(crate) async fn stop(&self) -> Result<v1::Desktop, Status> {
        if let Err(reason) = self.available() {
            return Ok(unavailable(reason));
        }
        let desktop = self.clone();
        tokio::spawn(async move {
            let mut current = desktop.inner.current.lock().await;
            if let Some(running) = current.as_ref() {
                desktop.end(&running.session_id).await?;
            }
            *current = None;
            desktop.inner.engine.display().set(false);
            Ok(in_state(v1::DesktopState::Stopped))
        })
        .await
        .map_err(unfinished)?
    }

    /// Stops the session `session_id`, which carries the desktop's name.
    /// Stopping the desktop's session is stopping the desktop. A session
    /// that only has the name, taken before it was reserved, is ended as any
    /// session is: nothing else could end it.
    pub(crate) async fn stop_session(&self, session_id: &str) -> Result<v1::SessionRecord, Status> {
        self.stop().await?;
        let engine = &self.inner.engine;
        let session = engine.get(session_id).await.map_err(status)?;
        if is_live(&session) {
            return engine.stop(session_id).await.map_err(status);
        }
        Ok(session)
    }

    /// What the image lacks, if it has no desktop. The image is the same for
    /// the daemon's whole life, but looking costs two `stat` calls. The
    /// answer is advice to a caller and guards nothing: the paths are read
    /// beneath the workload's root without confining links on the way, and
    /// the launcher itself only ever runs inside the workload.
    fn available(&self) -> Result<(), String> {
        let layout = &self.inner.layout;
        for (path, what) in [
            (&layout.launcher, "its launcher"),
            (&layout.server, "its VNC server"),
        ] {
            let seen = self.inner.config.process_execution.workload_path(path);
            if !std::fs::symlink_metadata(&seen).is_ok_and(|found| found.is_file()) {
                return Err(format!("{what} ({path}) is not in the image"));
            }
        }
        Ok(())
    }

    /// The desktop `current` names, if its session still runs; otherwise it
    /// is forgotten, with its password.
    async fn observe(&self, current: &mut Option<Running>) -> v1::Desktop {
        if let Some(running) = current.as_ref() {
            if let Ok(session) = self.inner.engine.get(&running.session_id).await
                && is_live(&session)
            {
                return self.running(&session, &running.viewer_password);
            }
            *current = None;
            self.inner.engine.display().set(false);
        }
        in_state(v1::DesktopState::Stopped)
    }

    async fn launch(&self) -> Result<(Running, v1::Desktop), Status> {
        let viewer_password = viewer_password();
        let session = self.launch_session().await?;
        let session_id = session.session_id.clone();
        let started = async {
            let mut line = viewer_password.clone().into_bytes();
            line.push(b'\n');
            self.inner
                .engine
                .desktop_input(&session_id, line)
                .await
                .map_err(status)?;
            self.wait_until_ready(&session).await
        }
        .await;
        match started {
            Ok(session) => {
                let desktop = self.running(&session, &viewer_password);
                Ok((
                    Running {
                        session_id,
                        viewer_password,
                    },
                    desktop,
                ))
            }
            Err(refusal) => {
                // Best effort: the refusal is what the caller needs, and a
                // launcher that already ended has nothing left to stop.
                let _ = self.end(&session_id).await;
                Err(refusal)
            }
        }
    }

    /// Launches the launcher, or starts its retained session again: a
    /// session's name stays taken while its record is kept.
    async fn launch_session(&self) -> Result<v1::SessionRecord, Status> {
        let engine = &self.inner.engine;
        let command = vec![self.inner.layout.launcher.clone()];
        let retained = engine
            .list()
            .await
            .map_err(status)?
            .into_iter()
            .find(Self::owns);
        match retained {
            None => engine
                .launch(v1::LaunchSessionRequest {
                    command,
                    name: DESKTOP_SESSION_NAME.into(),
                    ..Default::default()
                })
                .await
                .map_err(status),
            Some(session) if session.command == command && !session.pty => {
                engine.restart(&session.session_id).await.map_err(status)
            }
            // Named before the name was reserved. Starting it again would
            // run whatever it was, as the desktop.
            Some(_) => Err(Status::failed_precondition(format!(
                "a session named {DESKTOP_SESSION_NAME} that is not the desktop is in the way; \
                 the desktop can start once that session is stopped and its record is gone"
            ))),
        }
    }

    /// Waits until the launcher has said its display is ready and the VNC
    /// listener accepts. Fails as soon as the launcher ends, which is what
    /// it does when another process holds the display or the port.
    async fn wait_until_ready(
        &self,
        launched: &v1::SessionRecord,
    ) -> Result<v1::SessionRecord, Status> {
        let engine = &self.inner.engine;
        let port = self.inner.layout.port;
        let start_timeout = self.inner.layout.start_timeout;
        let deadline = Instant::now() + start_timeout;
        // A restarted session's earlier output is not this start's.
        let output_start = launched.output_end_offset;
        loop {
            let session = engine.get(&launched.session_id).await.map_err(status)?;
            if !is_live(&session) {
                return Err(ended_start(&session, port));
            }
            if self.said_ready(&launched.session_id, output_start).await? && self.listens().await {
                return Ok(session);
            }
            if Instant::now() >= deadline {
                return Err(Status::deadline_exceeded(format!(
                    "the desktop was not ready within {} seconds",
                    start_timeout.as_secs()
                )));
            }
            tokio::time::sleep(START_POLL).await;
        }
    }

    async fn said_ready(&self, session_id: &str, offset: u64) -> Result<bool, Status> {
        let output = self
            .inner
            .engine
            .read_output(v1::ReadSessionOutputRequest {
                session_id: session_id.to_owned(),
                offset,
                limit: OUTPUT_READ_LIMIT,
                allow_history_gap: true,
            })
            .await
            .map_err(status)?;
        let printed: Vec<u8> = output
            .chunks
            .into_iter()
            .flat_map(|chunk| chunk.data)
            .collect();
        Ok(printed
            .split(|byte| *byte == b'\n')
            .any(|line| line == READY_LINE))
    }

    async fn listens(&self) -> bool {
        let target = SocketAddr::from((Ipv4Addr::LOCALHOST, self.inner.layout.port));
        let connect = self.inner.sockets.connect(&self.inner.config, target);
        matches!(
            tokio::time::timeout(LISTENER_PROBE_TIMEOUT, connect).await,
            Ok(Ok(_))
        )
    }

    /// Ends the desktop's session. The launcher's children end with it.
    async fn end(&self, session_id: &str) -> Result<(), Status> {
        match self.inner.engine.stop(session_id).await {
            Ok(_) | Err(SessionError::NotFound(_)) => Ok(()),
            Err(error) => Err(status(error)),
        }
    }

    fn running(&self, session: &v1::SessionRecord, viewer_password: &str) -> v1::Desktop {
        v1::Desktop {
            state: v1::DesktopState::Running as i32,
            unavailable_reason: String::new(),
            running: Some(v1::DesktopRunning {
                display: DESKTOP_DISPLAY.into(),
                port: u32::from(self.inner.layout.port),
                started_at: session.started_at,
                viewer_password: viewer_password.to_owned(),
            }),
        }
    }
}

fn in_state(state: v1::DesktopState) -> v1::Desktop {
    v1::Desktop {
        state: state as i32,
        unavailable_reason: String::new(),
        running: None,
    }
}

fn unavailable(reason: String) -> v1::Desktop {
    v1::Desktop {
        state: v1::DesktopState::Unavailable as i32,
        unavailable_reason: reason,
        running: None,
    }
}

fn status(error: SessionError) -> Status {
    crate::durable_session::status_from_session_error(error)
}

/// Why a start whose launcher session ended is refused. A launch the
/// environment denied never ran the launcher, so it is no display or port
/// clash, and the code says so where the sentence is not read (#6133).
fn ended_start(session: &v1::SessionRecord, port: u16) -> Status {
    if session.status_message == crate::durable_session::LAUNCH_PROJECTION_DENIED {
        return Status::aborted(format!(
            "the desktop did not start: the environment denied its launch ({})",
            session.status_message
        ));
    }
    Status::failed_precondition(format!(
        "the desktop did not start ({}); another process may hold display \
         {DESKTOP_DISPLAY} or port {port}",
        session.status_message
    ))
}

fn is_live(session: &v1::SessionRecord) -> bool {
    session.state == v1::SessionLifecycleState::Starting as i32
        || session.state == v1::SessionLifecycleState::Running as i32
}

/// A start or stop whose own task ended without an answer.
fn unfinished(error: tokio::task::JoinError) -> Status {
    Status::internal(format!("the desktop's task did not finish: {error}"))
}

/// Eight characters of the launcher's alphabet from the system's random
/// source. It protects nothing: the built-in macOS viewer will not open a
/// desktop that asks for no password. So it is not meant to be uniform
/// either: 256 byte values fold onto 36 characters unevenly.
fn viewer_password() -> String {
    // A version 4 UUID is drawn from the system's random source; these are
    // the bytes of one that carry no version or variant bits.
    const RANDOM_BYTES: [usize; PASSWORD_LENGTH] = [0, 1, 2, 3, 4, 5, 7, 9];
    let random = uuid::Uuid::new_v4();
    RANDOM_BYTES
        .iter()
        .map(|index| {
            let byte = usize::from(random.as_bytes()[*index]);
            char::from(PASSWORD_ALPHABET[byte % PASSWORD_ALPHABET.len()])
        })
        .collect()
}

#[cfg(test)]
mod lifecycle_tests;
#[cfg(test)]
mod service_tests;

#[cfg(test)]
mod tests {
    use super::*;

    /// The image and the daemon ship from one tree; a start that waited for
    /// a line the launcher no longer prints would time out every time.
    #[test]
    fn the_shipped_launcher_prints_the_line_a_start_waits_for() {
        const LAUNCHER: &str = include_str!("../../../images/workspace/desktop/start");
        let ready = std::str::from_utf8(READY_LINE).unwrap();
        let prints = format!("echo '{ready}'");
        assert_eq!(
            LAUNCHER
                .lines()
                .filter(|line| line.trim() == prints)
                .count(),
            1,
            "images/workspace/desktop/start prints {ready:?} exactly once"
        );
    }

    #[test]
    fn a_viewer_password_is_eight_characters_the_launcher_accepts_and_differs_each_time() {
        let passwords: Vec<String> = (0..64).map(|_| viewer_password()).collect();
        for password in &passwords {
            assert!(
                codewire_daemon_proto::is_desktop_viewer_password(password),
                "not the shape a caller accepts"
            );
        }
        let distinct: std::collections::BTreeSet<&String> = passwords.iter().collect();
        assert!(distinct.len() > 60, "{} of 64 distinct", distinct.len());
    }

    #[test]
    fn a_new_process_gets_the_display_only_while_a_desktop_runs_and_only_if_it_named_none() {
        let display = Display::default();
        let environment = || ProcessEnvironment {
            entries: vec!["HOME=/home/codewire".into(), "DISPLAY=:9".into()],
            override_names: Default::default(),
        };

        let mut stopped = environment();
        display.apply(&[], &mut stopped);
        assert_eq!(stopped.entries, environment().entries);

        display.set(true);
        let mut inherited = environment();
        display.apply(&["TERM=xterm".into()], &mut inherited);
        assert_eq!(
            inherited.entries,
            ["HOME=/home/codewire", "DISPLAY=:1"].map(String::from)
        );

        let mut requested = environment();
        display.apply(&["DISPLAY=:7".into()], &mut requested);
        assert_eq!(requested.entries, environment().entries);

        display.set(false);
        let mut after = environment();
        display.apply(&[], &mut after);
        assert_eq!(after.entries, environment().entries);
    }
}
