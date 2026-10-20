//! A managed noel message whose environment is taken down is paused, not
//! ended, and the conversation's next start resumes its run.
//!
//! Only a takedown of the whole environment pauses: `cw stop ENV`, `restart`
//! and `rm`, a shutdown of its host daemon, and a host's orderly reboot. The
//! host daemon's record helper pauses the active run before the daemon's
//! first signal reaches the conversation (`pause_before_shutdown`), so how
//! the 250 ms between its SIGTERM and SIGKILL fall never changes the outcome.
//! An explicit stop or restart never pauses a message, and never later
//! resumes it. Codex and Claude cannot resume a run, so their message still
//! ends unknown.
//!
//! The host daemon writes what a stop means before it signals a session
//! (see `codewire_daemon::stop_evidence`): the environment's takedown marker,
//! or an explicit stop's intent. It writes both itself, so neither depends
//! on the conversation's record helper. A driver that is signalled reads the
//! disk:
//!
//! - an explicit stop is recorded: the run ends as an explicit stop, at
//!   once, and is never paused;
//! - a takedown is recorded, by its marker or by the message the helper
//!   already paused: the run is paused, at once;
//! - neither: the signal is not the daemon's. A host that shuts down
//!   signals every process at once, so the driver waits a moment for the
//!   marker its daemon writes when it is signalled too, and pauses when it
//!   comes. Without one the run ends unknown, as for any stray signal.
//!
//! The parent hears once that the message paused, and once of its final
//! state. When the environment's host daemon starts again it restarts each
//! paused noel conversation itself, and noel's recovery table decides the
//! run (see `noel::resolve`). A conversation that can never start again
//! resolves its paused message once instead, so none stays paused with
//! nothing to resume it.
use super::*;
use codewire_daemon::stop_evidence;

const REASON: PauseReason = PauseReason::EnvironmentStopped;
/// How long a driver that was signalled with nothing recorded waits for its
/// daemon's takedown marker. A host that shuts down signals the daemon in
/// the same moment, and the daemon writes the marker before it stops
/// anything; a stray signal brings none, and the run then ends unknown.
pub(super) const TAKEDOWN_MARKER_WAIT: Duration = Duration::from_secs(3);
const EVIDENCE_POLL: Duration = Duration::from_millis(10);

/// How the paused message ends when retention removes its conversation's
/// session record.
#[cfg(target_os = "linux")]
pub(super) const RETIRED: &str =
    "its conversation's session record was removed, so it can never resume";
/// How it ends when its owner explicitly stops its conversation while the
/// conversation is not running.
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

/// Whether the host daemon recorded an explicit stop or restart of the
/// conversation that no start of it has acted on yet. The daemon writes it
/// itself, before the stop can signal anything.
fn stop_intended(environment: &DriverEnvironment, session_id: &str) -> bool {
    environment
        .host()
        .is_some_and(|host| stop_evidence::stop_intended(&host.root(), session_id))
}

/// Whether an explicit stop or restart is recorded for the message: the
/// daemon's stop intent for its conversation, or the stop's interrupt, which
/// the daemon's record helper writes for the message before the daemon
/// signals, delivered or not. Such a message is never paused, and never
/// resumed later.
pub(super) fn explicit_stop_recorded(
    environment: &DriverEnvironment,
    dir: &Path,
    session_id: &str,
    message_id: &str,
) -> bool {
    stop_intended(environment, session_id)
        || fs::symlink_metadata(message_path(dir, &stop_interrupt_id(message_id))).is_ok()
}

/// How a message of a run noel could have resumed ends at its
/// conversation's next start, when the daemon's stop intent says the
/// conversation was stopped explicitly since.
pub(super) fn stopped_text(paused: bool) -> String {
    if paused {
        format!("paused when its environment stopped; {STOPPED}; outcome unknown; not replayed")
    } else {
        "its conversation was stopped while this was in flight; outcome unknown; not replayed"
            .into()
    }
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
    if explicit_stop_recorded(environment, dir, &binding.session_id, message_id) {
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

/// The environment's takedown marker: `cw stop ENV`, `restart` and `rm`
/// write it to ask the host daemon to stop, and the daemon writes it itself
/// before any other shutdown stops a session. The daemon removes it when it
/// starts.
fn takedown_marked(environment: &DriverEnvironment) -> bool {
    environment
        .host()
        .is_some_and(|host| stop_evidence::takedown_marked(&host.root()))
}

impl Driver {
    /// An explicit stop or restart of this conversation is recorded before
    /// it signals: by the daemon's stop intent, by the stop's interrupt for
    /// the message, or by that interrupt reaching this driver.
    fn explicitly_stopped(&self, message_id: &str) -> bool {
        self.stopping
            || explicit_stop_recorded(
                &self.environment,
                &self.dir,
                &self.binding.session_id,
                message_id,
            )
    }

    /// Whether the daemon's stop intent is recorded for this conversation.
    /// A start acts on it for what the last incarnation left in flight.
    pub(super) fn stop_intended(&self) -> bool {
        stop_intended(&self.environment, &self.binding.session_id)
    }

    /// The start has acted on the stop intent and its records are saved.
    pub(super) fn clear_stop_intent(&self) {
        let Some(host) = self.environment.host() else {
            return;
        };
        if let Err(error) = stop_evidence::clear_stop_intent(&host.root(), &self.binding.session_id)
        {
            log(format!(
                "could not clear the conversation's stop intent: {error}; its next stop is treated as explicit"
            ));
        }
    }

    /// What the driver's stop signal means for a message, read from the
    /// disk: `true` when the whole environment is being taken down and no
    /// explicit stop of this conversation is recorded.
    ///
    /// The host daemon writes its evidence before it signals, so its signal
    /// is decided at once: an explicit stop's record ends the run, never
    /// paused, and a takedown's pauses it. The takedown's evidence is its
    /// marker or, for the run that was active, a message the daemon's helper
    /// already paused; a message set aside at startup may still be paused
    /// from an earlier takedown, so only the marker counts for it.
    ///
    /// With neither, the signal is not the daemon's: the driver waits at
    /// most [`TAKEDOWN_MARKER_WAIT`] for the marker of a daemon that the
    /// same host shutdown signalled, or for an explicit stop to be recorded.
    async fn taken_down(&self, message_id: &str, active: bool) -> bool {
        let deadline = tokio::time::Instant::now() + TAKEDOWN_MARKER_WAIT;
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
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(EVIDENCE_POLL).await;
        }
    }

    /// A stop signal reached the driver, or noel exited by one. With
    /// evidence that the whole environment is being taken down, a run noel
    /// can resume is paused. Otherwise, as for an explicit stop or a stray
    /// signal, the run ends unknown and its parent hears once, as before.
    pub(super) async fn stopped(
        &mut self,
        peer: &mut Peer,
        reason: String,
        stopping: bool,
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
            && self.taken_down(&message, active).await
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

/// Why a daemon that starts leaves a stopped conversation with a paused
/// message stopped, if it does: its owner stopped it since, so it is not
/// started again for a run that must not continue, or its process cleanup
/// is unknown, so the daemon could never start it.
#[cfg(target_os = "linux")]
fn left_stopped(stop_intended: bool, cleanup_unknown: bool) -> Option<&'static str> {
    if stop_intended {
        Some(STOPPED)
    } else if cleanup_unknown {
        Some("its conversation's process cleanup is unknown, so it cannot start again")
    } else {
        None
    }
}

/// The environment's host daemon started: it restarts every noel
/// conversation the environment's takedown paused, and no other. Each start
/// runs the same recover path as `cw restart`, bounded by its handshake. A
/// conversation the daemon will never start again, or whose owner stopped
/// it since, resolves its paused messages once instead. Failures are logged
/// to the daemon log.
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
        let never = if let Some(why) = left_stopped(
            stop_intended(&store, &session.session_id),
            session.cleanup_unknown,
        ) {
            Some(why.to_owned())
        } else {
            match client.restart(&session.session_id).await {
                Ok(_) => {
                    eprintln!(
                        "cw host daemon: restarted paused noel conversation {} to resume its run",
                        session.session_id
                    );
                    None
                }
                // The daemon says so itself: this refusal cannot change.
                Err(error) if error.never_restarts().is_some() => {
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
    use super::{STOPPED, left_stopped};
    use codewire_daemon::NeverRestarts;
    use codewire_daemon::client::SessionClientError as E;

    #[test]
    fn a_daemon_that_starts_restarts_no_conversation_its_owner_stopped_or_it_cannot_start() {
        assert_eq!(left_stopped(false, false), None);
        // An explicit stop comes first: nothing else about the conversation
        // lets its run continue.
        assert_eq!(left_stopped(true, false), Some(STOPPED));
        assert_eq!(left_stopped(true, true), Some(STOPPED));
        assert_eq!(
            left_stopped(false, true),
            Some("its conversation's process cleanup is unknown, so it cannot start again")
        );
    }

    /// What `resume_paused` asks of a refused restart.
    fn never(error: &E) -> bool {
        error.never_restarts().is_some()
    }

    #[test]
    fn only_the_daemons_own_reason_resolves_a_paused_conversation() {
        // Every reason the daemon gives for a restart it will never admit,
        // as the daemon itself answers it.
        for reason in NeverRestarts::ALL {
            let refused = E::Status(reason.status("refused"));
            assert_eq!(refused.never_restarts(), Some(reason));
            assert!(never(&refused), "{reason:?}");
        }
        // The same codes and the same words without the daemon's reason
        // decide nothing: a refusal's text is never read.
        for unmarked in [
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
            assert!(!never(&E::Status(unmarked.clone())), "{unmarked}");
        }
        // A daemon that is stopping again, or one that cannot be reached,
        // leaves the message paused for its next start.
        for later in [
            E::Status(tonic::Status::failed_precondition(
                "session launch cancelled before completion",
            )),
            E::Status(tonic::Status::unavailable("stopping")),
            E::Status(tonic::Status::deadline_exceeded("slow")),
            E::Connect,
            E::RequestClosed,
        ] {
            assert!(!never(&later), "{later}");
        }
    }
}
