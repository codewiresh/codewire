//! A managed noel message whose environment is taken down is paused, not
//! ended, and the conversation's next start resumes its run.
//!
//! Only a takedown of the whole environment pauses: `cw env stop`, `restart`
//! and `rm`, a shutdown of its host daemon, and a host's orderly reboot. The
//! host daemon's record helper pauses the active run before the daemon's
//! first signal reaches the conversation (`pause_before_shutdown`), so how
//! the 250 ms between its SIGTERM and SIGKILL fall never changes the outcome.
//! The driver pauses the run itself only with evidence of the takedown. An
//! explicit stop or restart never pauses a message, and never later resumes
//! it. Codex and Claude cannot resume a run, so their message still ends
//! unknown.
//!
//! The host daemon signals a conversation only after it has written what
//! its stop means: an explicit stop's interrupt, or a takedown's pause or
//! marker. So a stop signal from the daemon is decided at once by what is
//! on disk. A signal from anywhere else is never an explicit stop: a host
//! that shuts down signals every process at once, and the driver then waits
//! for the marker its daemon writes when it is signalled too.
//!
//! The parent hears once that the message paused, and once of its final
//! state. When the environment's host daemon starts again it restarts each
//! paused noel conversation itself, and noel's recovery table decides the
//! run (see `noel::resolve`). A conversation that can never start again
//! resolves its paused message once instead, so none stays paused with
//! nothing to resume it.
use super::*;

const REASON: PauseReason = PauseReason::EnvironmentStopped;
/// How long a driver that something other than its host daemon signalled
/// waits for the daemon's takedown marker. A host that shuts down signals
/// the daemon in the same moment, and the daemon writes the marker first;
/// a stray signal brings none, and the run then ends unknown.
pub(super) const FOREIGN_SIGNAL_WAIT: Duration = Duration::from_secs(3);
const EVIDENCE_POLL: Duration = Duration::from_millis(10);

/// Who sent the driver its latest stop signal.
#[cfg(target_os = "linux")]
pub(super) mod sender {
    use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};

    const SIGNALS: [libc::c_int; 3] = [libc::SIGTERM, libc::SIGINT, libc::SIGHUP];
    /// The process that sent the latest of them, or 0: none yet, or none
    /// named.
    static SENDER: AtomicI32 = AtomicI32::new(0);
    /// The host daemon: the driver's parent when the watch began.
    static DAEMON: AtomicI32 = AtomicI32::new(0);
    /// What handled each signal before the watch, which still handles it.
    static PREVIOUS: [AtomicUsize; 3] = [
        AtomicUsize::new(libc::SIG_DFL),
        AtomicUsize::new(libc::SIG_DFL),
        AtomicUsize::new(libc::SIG_DFL),
    ];
    static PREVIOUS_FLAGS: [AtomicI32; 3] =
        [AtomicI32::new(0), AtomicI32::new(0), AtomicI32::new(0)];

    /// Notes the sender, then runs the handler it stands in front of. It
    /// only reads the kernel's siginfo, stores an atomic and calls that
    /// handler, all of which a signal handler may do.
    extern "C" fn note(
        signal: libc::c_int,
        info: *mut libc::siginfo_t,
        context: *mut libc::c_void,
    ) {
        let Some(index) = SIGNALS.iter().position(|known| *known == signal) else {
            return;
        };
        if !info.is_null() {
            // SAFETY: the kernel passes an SA_SIGINFO handler a valid
            // siginfo, and `kill` and `sigqueue` fill in the sender's PID.
            let sender = unsafe {
                if matches!((*info).si_code, libc::SI_USER | libc::SI_QUEUE) {
                    (*info).si_pid()
                } else {
                    0
                }
            };
            SENDER.store(sender, Ordering::SeqCst);
        }
        let previous = PREVIOUS[index].load(Ordering::SeqCst);
        if previous == libc::SIG_IGN {
            return;
        }
        if previous == libc::SIG_DFL {
            // Nothing handled it before: its default action still applies.
            // SAFETY: `signal` and `raise` are async-signal-safe.
            unsafe {
                libc::signal(signal, libc::SIG_DFL);
                libc::raise(signal);
            }
            return;
        }
        // SAFETY: `previous` is the handler `sigaction` reported for this
        // signal, called with the arguments its flags say it takes.
        unsafe {
            if PREVIOUS_FLAGS[index].load(Ordering::SeqCst) & libc::SA_SIGINFO != 0 {
                let handler: extern "C" fn(libc::c_int, *mut libc::siginfo_t, *mut libc::c_void) =
                    std::mem::transmute(previous);
                handler(signal, info, context);
            } else {
                let handler: extern "C" fn(libc::c_int) = std::mem::transmute(previous);
                handler(signal);
            }
        }
    }

    /// Starts noting who sends the driver's stop signals. Call it once the
    /// runtime's own handlers for them exist: each keeps running after the
    /// sender is noted.
    pub(in super::super) fn watch() -> std::io::Result<()> {
        static ONCE: std::sync::Once = std::sync::Once::new();
        let mut result = Ok(());
        ONCE.call_once(|| {
            // SAFETY: getppid reads the current process identity.
            DAEMON.store(unsafe { libc::getppid() }, Ordering::SeqCst);
            for (index, signal) in SIGNALS.iter().enumerate() {
                // SAFETY: both structures are plain data that sigaction
                // fills or reads; `note` is async-signal-safe and chains to
                // the handler saved here before it can run.
                unsafe {
                    let mut previous: libc::sigaction = std::mem::zeroed();
                    if libc::sigaction(*signal, std::ptr::null(), &mut previous) != 0 {
                        result = Err(std::io::Error::last_os_error());
                        return;
                    }
                    PREVIOUS_FLAGS[index].store(previous.sa_flags, Ordering::SeqCst);
                    PREVIOUS[index].store(previous.sa_sigaction, Ordering::SeqCst);
                    let mut action = previous;
                    action.sa_sigaction = note as *const () as usize;
                    action.sa_flags = previous.sa_flags | libc::SA_SIGINFO;
                    if libc::sigaction(*signal, &action, std::ptr::null_mut()) != 0 {
                        result = Err(std::io::Error::last_os_error());
                        return;
                    }
                }
            }
        });
        result
    }

    /// The process that sent the latest stop signal, if one did.
    pub(in super::super) fn latest() -> Option<libc::pid_t> {
        Some(SENDER.load(Ordering::SeqCst)).filter(|sender| *sender > 0)
    }

    /// Whether the host daemon sent the latest stop signal.
    pub(in super::super) fn by_daemon() -> bool {
        latest().is_some_and(|sender| sender == DAEMON.load(Ordering::SeqCst))
    }
}

/// No other host runs noel, and no other driver pauses: its stop is decided
/// at once by what is on disk.
#[cfg(not(target_os = "linux"))]
pub(super) mod sender {
    pub(in super::super) fn by_daemon() -> bool {
        true
    }
}
/// How the paused message ends when retention removes its conversation's
/// session record.
#[cfg(target_os = "linux")]
pub(super) const RETIRED: &str =
    "its conversation's session record was removed, so it can never resume";
/// How it ends when its owner explicitly stops its conversation while the
/// conversation is not running.
#[cfg(target_os = "linux")]
pub(super) const STOPPED: &str = "its conversation was stopped before it resumed";
/// What the inbox notice records say while their parent has not adopted them.
const QUEUED: &str = "queued in the parent's inbox; the parent adopts it when it runs";

/// Which of a message's two parent notices.
#[derive(Clone, Copy)]
enum Notice {
    Pause,
    /// Queued here only for a conversation that can never start again; a
    /// driver delivers its own.
    #[cfg(target_os = "linux")]
    Final,
}

/// "name (session ID)" or "session ID".
fn worker_label(config: &AgentConfig, binding: &AgentBinding) -> String {
    if config.name.is_empty() {
        format!("session {}", binding.session_id)
    } else {
        format!("{} (session {})", config.name, binding.session_id)
    }
}

/// The turn a parent gets when a worker message ends.
pub(super) fn final_notice_text(
    environment_id: &str,
    config: &AgentConfig,
    binding: &AgentBinding,
    source: &MessageRecord,
) -> String {
    let header = format!(
        "[Codewire] Managed worker {} finished message {} as {}.",
        worker_label(config, binding),
        source.id,
        source.state.name()
    );
    let footer = format!(
        "Follow up with: cw msg {environment_id} {} \"...\" --reply-to {}",
        binding.session_id, source.id
    );
    let body = match source.state {
        MessageState::Completed => source
            .result
            .clone()
            .unwrap_or_else(|| "(the worker produced no reply text)".into()),
        _ => source
            .error
            .clone()
            .or_else(|| source.result.clone())
            .unwrap_or_default(),
    };
    let budget = MAX_TEXT_BYTES.saturating_sub(header.len() + footer.len() + 32);
    let (body, truncated) = truncate_utf8(&body, budget);
    format!(
        "{header}\n\n{body}{}\n\n{footer}",
        if truncated { "\n[truncated]" } else { "" }
    )
}

/// The turn a parent gets once when a worker message pauses.
fn pause_notice_text(
    config: &AgentConfig,
    binding: &AgentBinding,
    source: &MessageRecord,
) -> String {
    format!(
        "[Codewire] Managed worker {} paused message {}: its environment stopped. Its run continues when the environment starts again, and you will hear its final state then. Do not send it again.",
        worker_label(config, binding),
        source.id
    )
}

/// Only a conversation the host user launched pauses: noel runs nowhere else.
fn admit_host_owner(environment: &DriverEnvironment, config: &AgentConfig) -> anyhow::Result<()> {
    anyhow::ensure!(
        environment.host().is_some(),
        "only a host user's own conversation pauses"
    );
    #[cfg(target_os = "linux")]
    anyhow::ensure!(
        !host_control::guardian_required(environment, &config.driver_id)?,
        "only a host user's own conversation pauses"
    );
    #[cfg(not(target_os = "linux"))]
    let _ = config;
    Ok(())
}

/// Writes one of a message's two notices into its parent's inbox, once, and
/// records that on the message. It is never written to the parent's pipe:
/// the parent shares the environment, and adopts the notice when it runs.
fn queue_notice(
    environment: &DriverEnvironment,
    dir: &Path,
    config: &AgentConfig,
    binding: &AgentBinding,
    source: &MessageRecord,
    notice: Notice,
) -> anyhow::Result<()> {
    let Some(parent) = &config.parent else {
        return Ok(());
    };
    let (id, text, sent) = match notice {
        Notice::Pause => (
            pause_notification_id(&source.id),
            pause_notice_text(config, binding, source),
            &source.pause_notification,
        ),
        #[cfg(target_os = "linux")]
        Notice::Final => (
            notification_id(&source.id),
            final_notice_text(environment.id(), config, binding, source),
            &source.notification,
        ),
    };
    if sent.is_some() {
        return Ok(());
    }
    let parent_dir = driver_dir(environment, &parent.driver_id)?;
    let parent_binding: AgentBinding = read_record(&parent_dir.join("binding.json"))?;
    anyhow::ensure!(
        parent_binding.driver_id == parent.driver_id
            && parent_binding.session_id == parent.session_id,
        "the parent conversation binding changed; the notice was not redirected"
    );
    let mut record = MessageRecord::new(
        &parent.driver_id,
        &parent.session_id,
        MessageAction::Notification,
        text,
    );
    record.id = id.clone();
    record.source = Some(MessageSource {
        session_id: binding.session_id.clone(),
        driver_id: config.driver_id.clone(),
        message_id: source.id.clone(),
    });
    create_message(&parent_dir, &record)?;
    let queued = ParentNotification {
        message_id: id,
        parent_session_id: parent.session_id.clone(),
        parent_driver_id: parent.driver_id.clone(),
        state: NotificationState::Pending,
        detail: Some(QUEUED.into()),
        updated_at: now(),
    };
    update_message(dir, &source.id, |r| {
        let field = match notice {
            Notice::Pause => &mut r.pause_notification,
            #[cfg(target_os = "linux")]
            Notice::Final => &mut r.notification,
        };
        field.get_or_insert(queued);
    })?;
    Ok(())
}

/// Whether an explicit stop or restart recorded its interrupt for the
/// message, which the host daemon's helper does before the daemon signals,
/// delivered or not. Such a message is never paused, and never resumed
/// later.
pub(super) fn explicit_stop_recorded(dir: &Path, message_id: &str) -> bool {
    fs::symlink_metadata(message_path(dir, &stop_interrupt_id(message_id))).is_ok()
}

/// Pauses a conversation's running turn because its environment is being
/// taken down, and queues its parent's one pause notice. The host daemon's
/// record helper calls it before it signals the conversation; the driver
/// calls it when its stop signal comes with the takedown's evidence. A
/// message that is not running, or that an explicit stop recorded its
/// interrupt for, is left as it is. Returns the record.
pub(super) fn pause_message(
    environment: &DriverEnvironment,
    dir: &Path,
    config: &AgentConfig,
    binding: &AgentBinding,
    message_id: &str,
) -> anyhow::Result<MessageRecord> {
    admit_host_owner(environment, config)?;
    if explicit_stop_recorded(dir, message_id) {
        return load_message(dir, message_id);
    }
    let record = update_message(dir, message_id, |r| {
        r.pause(REASON);
    })?;
    if let Err(error) = ensure_pause_notice(environment, dir, config, binding, &record) {
        // The next start queues it: see `ensure_pause_notice`.
        log(format!(
            "the pause notice for message {message_id} was not queued: {error:#}"
        ));
    }
    load_message(dir, message_id)
}

/// Queues a paused message's notice if it is missing: recovery repairs a
/// pause whose writer stopped between the two writes.
pub(super) fn ensure_pause_notice(
    environment: &DriverEnvironment,
    dir: &Path,
    config: &AgentConfig,
    binding: &AgentBinding,
    record: &MessageRecord,
) -> anyhow::Result<()> {
    if record.state != MessageState::Paused || record.pause_notification.is_some() {
        return Ok(());
    }
    queue_notice(environment, dir, config, binding, record, Notice::Pause)
}

/// Whether a conversation holds a paused message.
#[cfg(target_os = "linux")]
pub(super) fn has_paused(dir: &Path) -> anyhow::Result<bool> {
    for id in message_ids(dir)? {
        if load_message(dir, &id)?.state == MessageState::Paused {
            return Ok(true);
        }
    }
    Ok(false)
}

/// A conversation whose paused messages will not resume, because it can
/// never start again or its owner stopped it, ends each of them unknown,
/// once, with `why`, and queues its final notice. An interrupt that waited
/// for a resolved message ends with it. Returns the resolved message IDs.
#[cfg(target_os = "linux")]
pub(super) fn resolve_paused(
    environment: &DriverEnvironment,
    dir: &Path,
    config: &AgentConfig,
    binding: &AgentBinding,
    why: &str,
) -> anyhow::Result<Vec<String>> {
    admit_host_owner(environment, config)?;
    let error =
        format!("paused when its environment stopped; {why}; outcome unknown; not replayed");
    let ids = message_ids(dir)?;
    let mut resolved = Vec::new();
    for id in &ids {
        if load_message(dir, id)?.state != MessageState::Paused {
            continue;
        }
        let record = update_message(dir, id, |r| {
            if r.state == MessageState::Paused {
                r.fail(MessageState::Unknown, error.clone());
            }
        })?;
        if record.state == MessageState::Unknown {
            queue_notice(environment, dir, config, binding, &record, Notice::Final)?;
            resolved.push(id.clone());
        }
    }
    if !resolved.is_empty() {
        for id in &ids {
            let waits = |record: &MessageRecord| {
                record.action == MessageAction::Interrupt
                    && !record.state.is_terminal()
                    && record
                        .expected_active_message_id
                        .as_ref()
                        .is_some_and(|message| resolved.contains(message))
            };
            if waits(&load_message(dir, id)?) {
                update_message(dir, id, |r| {
                    if waits(r) {
                        r.fail(MessageState::Unknown, error.clone());
                    }
                })?;
            }
        }
    }
    Ok(resolved)
}

/// The environment's takedown marker: `cw env stop`, `restart` and `rm`
/// write it before they ask the host daemon to stop, and the daemon writes
/// it first when a signal stops it. The daemon removes it when it starts.
fn takedown_marked(environment: &DriverEnvironment) -> bool {
    environment
        .host()
        .is_some_and(|host| host.root().join(SHUTDOWN_MARKER).is_file())
}

impl Driver {
    /// An explicit stop or restart of this conversation records its
    /// interrupt before it signals, delivered or not.
    fn explicitly_stopped(&self, message_id: &str) -> bool {
        self.stopping || explicit_stop_recorded(&self.dir, message_id)
    }

    /// Whether the stop is the whole environment's and no explicit stop of
    /// this conversation. The takedown's evidence is its marker or, for the
    /// run that was active, a message the daemon's helper already paused; a
    /// message set aside at startup may still be paused from an earlier
    /// takedown, so only the marker counts for it.
    ///
    /// The daemon writes its evidence before it signals, so its signal is
    /// decided by what is there. A signal from elsewhere waits, at most
    /// [`FOREIGN_SIGNAL_WAIT`], for the daemon's marker, or for the daemon
    /// to stop this conversation itself.
    async fn taken_down(&self, message_id: &str, active: bool, by_daemon: fn() -> bool) -> bool {
        let deadline = tokio::time::Instant::now() + FOREIGN_SIGNAL_WAIT;
        loop {
            if self.explicitly_stopped(message_id) {
                return false;
            }
            let paused = active
                && load_message(&self.dir, message_id)
                    .is_ok_and(|record| record.state == MessageState::Paused);
            if paused || takedown_marked(&self.environment) {
                return true;
            }
            if by_daemon() || tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(EVIDENCE_POLL).await;
        }
    }

    /// A stop signal reached the driver, or noel exited by one. With
    /// evidence that the whole environment is being taken down, a run noel
    /// can resume is paused. Otherwise, as for an explicit stop or any other
    /// signal, the run ends unknown and its parent hears once, as before.
    pub(super) async fn stopped(
        &mut self,
        peer: &mut Peer,
        reason: String,
        stopping: bool,
    ) -> anyhow::Result<()> {
        self.stopped_from(peer, reason, stopping, sender::by_daemon)
            .await
    }

    /// [`Self::stopped`], given whether the host daemon sent the signal.
    pub(super) async fn stopped_from(
        &mut self,
        peer: &mut Peer,
        reason: String,
        stopping: bool,
        by_daemon: fn() -> bool,
    ) -> anyhow::Result<()> {
        let active = self.active.as_ref().map(|active| active.message_id.clone());
        let message = match &active {
            Some(active) if self.state.capabilities.resume => Some((active.clone(), true)),
            Some(_) => None,
            // Only noel sets a message aside for its startup handshake.
            None => self
                .noel
                .set_aside_message()
                .map(|message| (message.to_owned(), false)),
        };
        if let Some((message, active)) = message
            && self.taken_down(&message, active, by_daemon).await
        {
            match pause_message(
                &self.environment,
                &self.dir,
                &self.config,
                &self.binding,
                &message,
            ) {
                Ok(record) if record.state == MessageState::Paused => {
                    log(format!(
                        "message {message} {}: {reason}; it resumes when the environment starts again",
                        state_label(&record)
                    ));
                    return self.paused_peer(peer, reason).await;
                }
                Ok(record) => log(format!(
                    "message {message} is {} and was not paused",
                    state_label(&record)
                )),
                Err(error) => log(format!("could not pause message {message}: {error:#}")),
            }
        }
        self.lose_peer(peer, reason, stopping).await
    }

    /// The environment is being taken down under a run noel can resume, and
    /// its message is paused, not ended; its parent was told once. Steers
    /// sent for the run end unknown, because a resume clears noel's queue
    /// first. Interrupts accepted for it stay, so the next start ends the
    /// run instead of resuming it. Queued messages stay accepted.
    async fn paused_peer(&mut self, peer: &mut Peer, reason: String) -> anyhow::Result<()> {
        let mut steers: Vec<String> = self
            .pending
            .drain()
            .filter_map(|(_, pending)| match pending {
                Pending::Steer(id) => Some(id),
                Pending::TurnStart(_) | Pending::Interrupt(_) => None,
            })
            .collect();
        steers.extend(self.control_pending.drain().map(|(_, id)| id));
        if let Some(active) = self.active.take() {
            steers.extend(active.steers);
        }
        for id in steers {
            if let Err(error) = update_message(&self.dir, &id, |r| {
                r.fail(
                    MessageState::Unknown,
                    format!("{reason}; the steer outcome is unknown and is not replayed"),
                );
            }) {
                log(format!(
                    "could not record message {id} as unknown: {error:#}"
                ));
            }
        }
        // It stays paused on disk for the next start.
        self.noel.forget_set_aside();
        let status = peer.stop().await;
        let cleanup_confirmed = status.is_some();
        self.state.phase = if cleanup_confirmed {
            DriverPhase::Stopped
        } else {
            DriverPhase::Failed
        };
        let reason = match status {
            Some(status) => format!("{reason} (native agent {status})"),
            None => format!("{reason}; native peer cleanup is unknown; restart is fenced"),
        };
        self.state.last_error = (!cleanup_confirmed).then(|| reason.clone());
        self.state.active_message_id = None;
        self.state.current_turn_id = None;
        if let Err(error) = self.persist_state() {
            log(format!("could not persist driver state: {error:#}"));
        }
        log(&reason);
        if cleanup_confirmed {
            Ok(())
        } else {
            Err(anyhow::anyhow!(reason))
        }
    }
}

/// Whether the host daemon will never start this conversation again.
#[cfg(target_os = "linux")]
fn never_restarts(error: &codewire_daemon::client::SessionClientError) -> bool {
    use codewire_daemon::client::SessionClientError as E;
    match error {
        E::Status(status) => match status.code() {
            tonic::Code::ResourceExhausted | tonic::Code::NotFound => true,
            tonic::Code::FailedPrecondition => {
                let message = status.message();
                message.contains("environment projection is no longer available")
                    || message.contains("cleanup is unconfirmed")
            }
            _ => false,
        },
        _ => false,
    }
}

/// The environment's host daemon started: it restarts every noel
/// conversation the environment's takedown paused, and no other. Each start
/// runs the same recover path as `cw restart`, bounded by its handshake. A
/// conversation the daemon will never start again resolves its paused
/// messages once instead. Failures are logged to the daemon log.
#[cfg(target_os = "linux")]
pub(crate) async fn resume_paused(
    environment: &HostEnvironment,
    client: &codewire_daemon::client::SessionClient,
) -> anyhow::Result<()> {
    let store = DriverEnvironment::Host(environment.clone());
    for record in client.list().await? {
        let session = host_environment_session_view(record);
        let Some((environment_id, driver_id)) = driver_identity(&session.command) else {
            continue;
        };
        if environment_id != environment.id || !session_finished(&session) {
            continue;
        }
        let conversation = (|| -> anyhow::Result<Option<(PathBuf, AgentConfig, AgentBinding)>> {
            let dir = driver_dir(&store, &driver_id)?;
            let config: AgentConfig = read_record(&dir.join("config.json"))?;
            config.validate(&environment.id, &driver_id)?;
            if config.agent != AgentKind::Noel {
                return Ok(None);
            }
            let binding: AgentBinding = read_record(&dir.join("binding.json"))?;
            if binding.session_id != session.session_id || !has_paused(&dir)? {
                return Ok(None);
            }
            Ok(Some((dir, config, binding)))
        })();
        let (dir, config, binding) = match conversation {
            Ok(Some(conversation)) => conversation,
            Ok(None) => continue,
            Err(error) => {
                eprintln!(
                    "cw host daemon: could not inspect conversation {}: {error:#}",
                    session.session_id
                );
                continue;
            }
        };
        let never = if session.cleanup_unknown {
            Some(
                "its conversation's process cleanup is unknown, so it cannot start again"
                    .to_owned(),
            )
        } else {
            match client.restart(&session.session_id).await {
                Ok(_) => {
                    eprintln!(
                        "cw host daemon: restarted paused noel conversation {} to resume its run",
                        session.session_id
                    );
                    None
                }
                Err(error) if never_restarts(&error) => {
                    Some(format!("its conversation cannot start again ({error})"))
                }
                Err(error) => {
                    eprintln!(
                        "cw host daemon: could not restart paused noel conversation {}: {error}; it stays paused until it starts",
                        session.session_id
                    );
                    None
                }
            }
        };
        if let Some(why) = never {
            match resolve_paused(&store, &dir, &config, &binding, &why) {
                Ok(resolved) => eprintln!(
                    "cw host daemon: {why}; resolved paused messages {resolved:?} of {}",
                    session.session_id
                ),
                Err(error) => eprintln!(
                    "cw host daemon: could not resolve the paused messages of {}: {error:#}",
                    session.session_id
                ),
            }
        }
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn only_a_refusal_that_cannot_change_resolves_a_paused_conversation() {
        use codewire_daemon::client::SessionClientError as E;
        let status = |status: tonic::Status| E::Status(status);
        // What the host daemon answers a restart it will never admit.
        for never in [
            tonic::Status::failed_precondition(
                "the launch environment projection is no longer available after daemon recovery; launch a new session with the required environment overrides",
            ),
            tonic::Status::failed_precondition(
                "session launch cleanup is unconfirmed; restart is unavailable",
            ),
            tonic::Status::failed_precondition(
                "session process cleanup is unconfirmed; restart is unavailable",
            ),
            tonic::Status::resource_exhausted(
                "session launch generation is exhausted; launch a new session",
            ),
            tonic::Status::not_found("session not found"),
        ] {
            assert!(never_restarts(&status(never.clone())), "{never}");
        }
        // A daemon that is stopping again, or one that cannot be reached,
        // leaves the message paused for its next start.
        for later in [
            status(tonic::Status::failed_precondition(
                "session launch cancelled before completion",
            )),
            status(tonic::Status::unavailable("stopping")),
            status(tonic::Status::deadline_exceeded("slow")),
            E::Connect,
            E::RequestClosed,
        ] {
            assert!(!never_restarts(&later), "{later}");
        }
    }
}
