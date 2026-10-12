//! An environment's takedown pauses a running noel message and its next
//! start resumes it: the same outcome whichever of the daemon's helper and
//! the driver records the pause and whether the driver is killed first, one
//! pause notice and one final notice, explicit stops that never pause or
//! resume, and Codex and Claude unchanged.
use super::*;

const STOPPED: &str = "the driver was stopped by SIGTERM";
const CLOSED: &str = "the native agent closed its output";
/// What `lose_peer` records for a signalled driver whose noel exited 143.
const STOPPED_UNKNOWN: &str = "the driver was stopped by SIGTERM (native agent exit status: 143); the turn outcome is unknown and is not replayed";

/// An `agent` conversation the host user launched: its records are in a
/// temporary host environment whose daemon is not running, and it has no
/// peer.
fn host(agent: AgentKind) -> Harness {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("environment");
    let driver_id = uuid::Uuid::new_v4().to_string();
    let dir = root.join("agents").join(&driver_id);
    for path in [&root, &root.join("agents"), &dir, &dir.join("messages")] {
        private_directory(path).unwrap();
    }
    let created_at = now();
    let environment = DriverEnvironment::Host(HostEnvironment {
        id: uuid::Uuid::new_v4().to_string(),
        name: "host".into(),
        path: root.clone(),
        created_at: created_at.clone(),
        state: "stopped".into(),
        runtime_root: Some(root),
    });
    let config = AgentConfig {
        version: 1,
        driver_id: driver_id.clone(),
        environment_id: environment.id().into(),
        agent,
        program: PathBuf::from("/usr/local/bin/noel"),
        program_fallback: None,
        model: "faux/echo".into(),
        effort: None,
        working_dir: "/workspace".into(),
        name: String::new(),
        parent: None,
        initial_message_id: None,
        created_at: created_at.clone(),
    };
    let binding = AgentBinding {
        driver_id,
        session_id: "session".into(),
        bound_at: created_at,
    };
    Harness {
        _temporary: temporary,
        driver: driver(environment, dir, config, binding),
    }
}

/// Who signalled the driver: its host daemon, which signals only after it
/// has written what its stop means.
fn daemon() -> bool {
    true
}

/// Or anything else: a host that shuts down, or a stray signal.
fn elsewhere() -> bool {
    false
}

/// The environment's takedown marker, as `cw env stop` and a signalled host
/// daemon write it.
fn mark_takedown(h: &Harness) {
    fs::write(h.driver.environment.root().join(SHUTDOWN_MARKER), "true").unwrap();
}

/// What the host daemon's record helper does before it signals.
fn helper_pauses(h: &Harness, message: &str) -> MessageRecord {
    pause::pause_message(
        &h.driver.environment,
        &h.driver.dir,
        &h.driver.config,
        &h.driver.binding,
        message,
    )
    .unwrap()
}

/// How often the parent was told that `source` paused, and that it ended.
fn told(parent: &Path, source: &str) -> (usize, usize) {
    let ids: Vec<String> = list_messages(parent)
        .unwrap()
        .into_iter()
        .filter(|record| {
            record.action == MessageAction::Notification
                && record
                    .source
                    .as_ref()
                    .is_some_and(|from| from.message_id == source)
        })
        .map(|record| record.id)
        .collect();
    let count = |id: String| ids.iter().filter(|seen| **seen == id).count();
    assert_eq!(
        count(pause_notification_id(source)) + count(notification_id(source)),
        ids.len()
    );
    (
        count(pause_notification_id(source)),
        count(notification_id(source)),
    )
}

/// noel as its session's stop signal leaves it.
fn signalled() -> Peer {
    script_peer("exit 143")
}

/// A stop interrupt for `message`, as the host daemon's helper records it
/// before an explicit stop or restart signals.
fn explicit_stop(h: &Harness, message: &MessageRecord) -> MessageRecord {
    let mut interrupt = MessageRecord::new(
        &h.driver.config.driver_id,
        &h.driver.binding.session_id,
        MessageAction::Interrupt,
        String::new(),
    );
    interrupt.id = stop_interrupt_id(&message.id);
    interrupt.expected_active_message_id = Some(message.id.clone());
    assert!(create_message(&h.driver.dir, &interrupt).unwrap());
    interrupt
}

/// The conversation's next start: a new driver recovers, and noel's
/// handshake answers with `steps` after `get_state` reports `main`'s run
/// interrupted and the queue is cleared. Returns what noel was sent.
async fn next_start(
    h: &mut Harness,
    main: &MessageRecord,
    steps: Vec<Step>,
) -> (Peer, Vec<String>) {
    h.restart();
    h.driver.recover().await.unwrap();
    let trace = h
        ._temporary
        .path()
        .join(format!("sent-{}.jsonl", uuid::Uuid::new_v4()));
    let mut handshake = vec![
        step(vec![reply(
            1,
            "get_state",
            Some(resumable_state(Some(last(
                &main.id,
                "interrupted",
                Some("model"),
            )))),
        )]),
        cleared(2),
    ];
    handshake.extend(steps);
    let mut peer = noel_peer(&trace, handshake);
    h.driver.initialize_noel(&mut peer).await.unwrap();
    (peer, kinds(&trace))
}

/// The next start resumes `main`'s run to its reply.
async fn next_start_resumes(h: &mut Harness, main: &MessageRecord) -> MessageRecord {
    let mut resume = vec![reply(3, "resume_run", started())];
    resume.extend(resumed_run("[faux/echo] task"));
    let (mut peer, sent) = next_start(h, main, vec![step(resume)]).await;
    assert_eq!(sent, ["get_state", "clear_queue", "resume_run"]);
    h.settle(&mut peer).await;
    h.load(&main.id)
}

/// How one takedown recorded its pause.
#[derive(Clone, Copy, Debug)]
enum Takedown {
    /// The daemon's helper before the signal, then the driver's own stop.
    HelperThenDriver,
    /// The helper, and the driver killed before it handled its signal.
    HelperThenKill,
    /// No helper: the driver alone, by the takedown marker.
    DriverByMarker,
}

/// A noel worker whose environment is taken down under its running message.
async fn taken_down(how: Takedown) -> (Harness, PathBuf, MessageRecord) {
    let mut h = host(AgentKind::Noel);
    let parent = h.with_parent();
    let main = h.running("task", Some(RUN));
    match how {
        Takedown::HelperThenDriver => {
            helper_pauses(&h, &main.id);
            h.driver
                .stopped_from(&mut signalled(), STOPPED.into(), true, daemon)
                .await
                .unwrap();
        }
        Takedown::HelperThenKill => {
            helper_pauses(&h, &main.id);
        }
        Takedown::DriverByMarker => {
            mark_takedown(&h);
            h.driver
                .stopped_from(&mut signalled(), STOPPED.into(), true, daemon)
                .await
                .unwrap();
        }
    }
    (h, parent, main)
}

#[tokio::test]
async fn both_kill_orders_pause_the_message_and_resume_it_to_the_same_outcome() {
    let mut outcomes = Vec::new();
    for how in [
        Takedown::HelperThenDriver,
        Takedown::HelperThenKill,
        Takedown::DriverByMarker,
    ] {
        let (mut h, parent, main) = taken_down(how).await;
        let paused = h.load(&main.id);
        assert_eq!(paused.state, MessageState::Paused, "{how:?}");
        assert_eq!(
            state_label(&paused),
            "paused: environment stopped",
            "{how:?}"
        );
        assert!(
            paused.error.is_none() && paused.finished_at.is_none() && paused.result.is_none(),
            "{how:?}"
        );
        assert_eq!(told(&parent, &main.id), (1, 0), "{how:?}");
        if !matches!(how, Takedown::HelperThenKill) {
            assert_eq!(h.driver.state.phase, DriverPhase::Stopped, "{how:?}");
            assert!(h.driver.active.is_none() && h.driver.state.last_error.is_none());
        }

        let ended = next_start_resumes(&mut h, &main).await;
        assert_eq!(told(&parent, &main.id), (1, 1), "{how:?}");
        assert_eq!(
            resumed_note(&ended),
            " (resumed after its environment stopped)"
        );
        outcomes.push((
            ended.state,
            ended.result,
            ended.error,
            ended.native_resumed,
            ended.turn_id,
            ended.pause.map(|pause| pause.reason),
            ended.pause_notification.map(|notice| {
                (
                    notice.message_id == pause_notification_id(&main.id),
                    notice.state,
                )
            }),
            ended
                .notification
                .map(|notice| (notice.message_id == notification_id(&main.id), notice.state)),
        ));
    }
    assert_eq!(outcomes[0], outcomes[1]);
    assert_eq!(outcomes[1], outcomes[2]);
    let (state, result, error, resumed, run, reason, pause_notice, final_notice) =
        outcomes.remove(0);
    assert_eq!(pause_notice, Some((true, NotificationState::Pending)));
    assert_eq!(final_notice, Some((true, NotificationState::Undelivered)));
    assert_eq!(
        (state, result.as_deref(), error, run.as_deref()),
        (
            MessageState::Completed,
            Some("[faux/echo] task"),
            None,
            Some(RUN)
        )
    );
    // Its environment's takedown was no crash.
    assert_eq!(resumed, 0);
    assert_eq!(reason, Some(PauseReason::EnvironmentStopped));
}

#[tokio::test]
async fn a_stop_signal_without_evidence_of_a_takedown_ends_the_run_unknown_as_before() {
    let mut h = host(AgentKind::Noel);
    let parent = h.with_parent();
    let main = h.running("task", Some(RUN));
    h.driver
        .stopped_from(&mut signalled(), STOPPED.into(), true, daemon)
        .await
        .unwrap();
    let ended = h.load(&main.id);
    assert_eq!(
        (ended.state, ended.error.as_deref()),
        (MessageState::Unknown, Some(STOPPED_UNKNOWN))
    );
    assert!(ended.pause.is_none() && ended.pause_notification.is_none());
    assert_eq!(told(&parent, &main.id), (0, 1));
    assert_eq!(h.driver.state.phase, DriverPhase::Stopped);
    // Nothing resumes it later.
    h.restart();
    h.driver.recover().await.unwrap();
    assert!(h.driver.noel.set_aside.is_none());
    assert_eq!(told(&parent, &main.id), (0, 1));
}

#[tokio::test]
async fn a_takedown_that_nothing_recorded_resumes_as_a_crash_without_a_pause_notice() {
    // The helper failed and the driver was killed before its own write.
    let mut h = host(AgentKind::Noel);
    let parent = h.with_parent();
    let main = h.crashed(MessageAction::Message, "task", Some(RUN));
    let ended = next_start_resumes(&mut h, &main).await;
    assert_eq!(
        (ended.state, ended.result.as_deref(), ended.native_resumed),
        (MessageState::Completed, Some("[faux/echo] task"), 1)
    );
    assert!(ended.pause.is_none() && ended.pause_notification.is_none());
    assert_eq!(told(&parent, &main.id), (0, 1));
}

#[tokio::test]
async fn an_explicit_stop_never_pauses_a_message_even_while_its_environment_is_taken_down() {
    // The stop's interrupt was accepted by the driver, or only recorded.
    for accepted in [true, false] {
        let mut h = host(AgentKind::Noel);
        let parent = h.with_parent();
        let main = h.running("task", Some(RUN));
        mark_takedown(&h);
        explicit_stop(&h, &main);
        h.driver.stopping = accepted;
        // Neither the daemon's helper nor the driver pauses it.
        assert_eq!(
            helper_pauses(&h, &main.id).state,
            MessageState::Running,
            "{accepted}"
        );
        h.driver
            .stopped_from(&mut signalled(), STOPPED.into(), true, daemon)
            .await
            .unwrap();
        let ended = h.load(&main.id);
        assert_eq!(
            (ended.state, ended.error.as_deref()),
            (MessageState::Unknown, Some(STOPPED_UNKNOWN)),
            "{accepted}"
        );
        assert!(ended.pause.is_none(), "{accepted}");
        assert_eq!(told(&parent, &main.id), (0, 1), "{accepted}");
    }
}

#[tokio::test]
async fn an_explicit_stop_never_resumes_later_even_when_its_driver_was_killed_first() {
    let mut h = host(AgentKind::Noel);
    let parent = h.with_parent();
    // Killed before it recorded anything: only the stop's interrupt, which
    // the driver refused or never read, says the stop was explicit.
    let main = h.crashed(MessageAction::Message, "task", Some(RUN));
    let interrupt = explicit_stop(&h, &main);
    h.update(&interrupt.id, |r| {
        r.fail(MessageState::Error, "nothing was interrupted");
    });
    let (_peer, sent) = next_start(&mut h, &main, vec![step(vec![reply(3, "abort", None)])]).await;
    // noel is told to end the run, never to resume it.
    assert_eq!(sent, ["get_state", "clear_queue", "abort"]);
    let ended = h.load(&main.id);
    assert_eq!(
        (ended.state, ended.native_resumed),
        (MessageState::Interrupted, 0)
    );
    assert!(h.driver.active.is_none() && h.driver.noel.set_aside.is_none());
    assert_eq!(told(&parent, &main.id), (0, 1));
}

#[test]
fn a_pause_is_no_crash_and_a_paused_message_follows_the_same_table() {
    const M: &str = "message";
    let model = run_of(Some(M), "interrupted", Some("model"));
    let paused = |resumed, interrupted| SetAside {
        paused: true,
        ..aside(M, Some(RUN), resumed, interrupted)
    };
    let resume = Resolution::Resume {
        run: RUN.into(),
        saved_reply: false,
    };
    // Resumed after every crash the cap allows, a paused run still resumes.
    for resumed in [0, MAX_RESUMES, MAX_RESUMES + 5] {
        assert_eq!(resolve(&paused(resumed, false), Some(&model), true), resume);
    }
    // The next crash of that run is what the cap ends.
    assert_eq!(
        resolve(&aside(M, Some(RUN), MAX_RESUMES, false), Some(&model), true),
        Resolution::Unknown {
            abort: Some(RUN.into())
        }
    );
    // Every other row decides a paused message as it does a crashed one.
    assert_eq!(
        resolve(&paused(0, true), Some(&model), true),
        Resolution::Abort { run: RUN.into() }
    );
    assert_eq!(
        resolve(
            &paused(0, false),
            Some(&run_of(Some(M), "interrupted", None)),
            true
        ),
        Resolution::Resume {
            run: RUN.into(),
            saved_reply: true
        }
    );
    for (status, end) in [
        ("completed", RunEnd::Completed),
        ("failed", RunEnd::Failed),
        ("aborted", RunEnd::Aborted),
    ] {
        assert_eq!(
            resolve(
                &paused(0, false),
                Some(&run_of(Some(M), status, None)),
                true
            ),
            Resolution::Ended {
                run: RUN.into(),
                end
            }
        );
    }
    assert_eq!(
        resolve(
            &paused(0, false),
            Some(&run_of(Some("other"), "interrupted", Some("model"))),
            true
        ),
        Resolution::Unknown {
            abort: Some(RUN.into())
        }
    );
    assert_eq!(
        resolve(&paused(0, false), None, true),
        Resolution::Unknown { abort: None }
    );
    assert_eq!(
        resolve(&paused(0, false), Some(&model), false),
        Resolution::Unknown { abort: None }
    );
    // An explicit stop's recorded interrupt ends the run, paused or not.
    for was_paused in [false, true] {
        let stopped = SetAside {
            stopped: true,
            paused: was_paused,
            ..aside(M, Some(RUN), 0, false)
        };
        assert_eq!(
            resolve(&stopped, Some(&model), true),
            Resolution::Abort { run: RUN.into() }
        );
    }
}

#[tokio::test]
async fn a_paused_message_resumes_uncounted_after_every_crash_resume_was_used() {
    let (mut h, parent, main) = taken_down(Takedown::HelperThenKill).await;
    h.update(&main.id, |r| r.native_resumed = MAX_RESUMES);
    let ended = next_start_resumes(&mut h, &main).await;
    assert_eq!(
        (ended.state, ended.native_resumed),
        (MessageState::Completed, MAX_RESUMES)
    );
    assert_eq!(told(&parent, &main.id), (1, 1));
}

#[tokio::test]
async fn a_paused_message_that_cannot_resume_ends_unknown_and_its_parent_hears_once() {
    let (mut h, parent, main) = taken_down(Takedown::HelperThenKill).await;
    h.restart();
    h.driver.recover().await.unwrap();
    assert_eq!(told(&parent, &main.id), (1, 0));
    // This noel reports no resume extensions.
    let mut old = state();
    old["lastRun"] = last(&main.id, "interrupted", Some("model"));
    let trace = h._temporary.path().join("sent.jsonl");
    let mut peer = noel_peer(
        &trace,
        vec![step(vec![reply(1, "get_state", Some(old))]), cleared(2)],
    );
    h.driver.initialize_noel(&mut peer).await.unwrap();
    let ended = h.load(&main.id);
    assert_eq!(
        (ended.state, ended.error.as_deref()),
        (
            MessageState::Unknown,
            Some("paused when its environment stopped; outcome unknown; not replayed")
        )
    );
    assert_eq!(told(&parent, &main.id), (1, 1));
}

#[tokio::test]
async fn repeated_takedowns_tell_the_parent_of_the_pause_once() {
    let (mut h, parent, main) = taken_down(Takedown::DriverByMarker).await;
    let first = h.load(&main.id).pause.unwrap();

    // The next start is taken down during its handshake: the message is
    // still paused, and nothing is written.
    h.restart();
    h.driver.recover().await.unwrap();
    assert_eq!(h.driver.noel.set_aside_message(), Some(main.id.as_str()));
    let record = message_path(&h.driver.dir, &main.id);
    let before = fs::read(&record).unwrap();
    h.driver
        .stopped_from(
            &mut signalled(),
            "startup stopped by SIGTERM".into(),
            true,
            daemon,
        )
        .await
        .unwrap();
    assert_eq!(fs::read(&record).unwrap(), before);
    assert!(h.driver.noel.set_aside.is_none());
    assert_eq!(told(&parent, &main.id), (1, 0));

    // The start after that resumes the run, and a second takedown pauses it
    // again mid-run.
    let (mut peer, sent) = next_start(
        &mut h,
        &main,
        vec![step(vec![
            reply(3, "resume_run", started()),
            json!({"type": "agent_start", "runId": RUN}),
        ])],
    )
    .await;
    assert_eq!(sent, ["get_state", "clear_queue", "resume_run"]);
    assert_eq!(h.load(&main.id).state, MessageState::Running);
    assert_eq!(
        h.driver.state.active_message_id.as_deref(),
        Some(main.id.as_str())
    );
    h.driver
        .stopped_from(&mut peer, STOPPED.into(), true, daemon)
        .await
        .unwrap();
    let again = h.load(&main.id);
    assert_eq!(again.state, MessageState::Paused);
    assert!(again.pause.unwrap().paused_at > first.paused_at);
    assert_eq!(told(&parent, &main.id), (1, 0));

    let ended = next_start_resumes(&mut h, &main).await;
    assert_eq!(
        (ended.state, ended.native_resumed),
        (MessageState::Completed, 0)
    );
    assert_eq!(told(&parent, &main.id), (1, 1));
    // A later start repairs neither notice a second time.
    h.restart();
    h.driver.recover().await.unwrap();
    assert_eq!(told(&parent, &main.id), (1, 1));
}

#[tokio::test]
async fn a_stop_during_the_handshake_without_takedown_evidence_ends_a_paused_message() {
    // A paused message still says paused when its next start is stopped, so
    // only the marker shows that this stop is a takedown too. Without it
    // the stop is treated as explicit: the message ends and never resumes.
    let (mut h, parent, main) = taken_down(Takedown::HelperThenKill).await;
    h.restart();
    h.driver.recover().await.unwrap();
    h.driver
        .stopped_from(
            &mut signalled(),
            "startup stopped by SIGTERM".into(),
            true,
            daemon,
        )
        .await
        .unwrap();
    let ended = h.load(&main.id);
    assert_eq!(
        (ended.state, ended.error.as_deref()),
        (
            MessageState::Unknown,
            Some(
                "paused when its environment stopped; startup stopped by SIGTERM (native agent exit status: 143); outcome unknown; not replayed"
            )
        )
    );
    assert_eq!(told(&parent, &main.id), (1, 1));
    h.restart();
    h.driver.recover().await.unwrap();
    assert!(h.driver.noel.set_aside.is_none());
}

#[tokio::test]
async fn a_takedown_during_the_handshake_pauses_a_message_a_crash_left_running() {
    let mut h = host(AgentKind::Noel);
    let parent = h.with_parent();
    let main = h.crashed(MessageAction::Message, "task", Some(RUN));
    h.driver.recover().await.unwrap();
    mark_takedown(&h);
    h.driver
        .stopped_from(
            &mut signalled(),
            "startup stopped by SIGTERM".into(),
            true,
            daemon,
        )
        .await
        .unwrap();
    assert_eq!(h.load(&main.id).state, MessageState::Paused);
    assert_eq!(told(&parent, &main.id), (1, 0));
    let ended = next_start_resumes(&mut h, &main).await;
    assert_eq!(
        (ended.state, ended.native_resumed),
        (MessageState::Completed, 0)
    );
    assert_eq!(told(&parent, &main.id), (1, 1));
}

#[tokio::test]
async fn a_pause_ends_steers_unknown_keeps_interrupts_for_the_next_start_and_leaves_the_queue() {
    let mut h = host(AgentKind::Noel);
    let parent = h.with_parent();
    let main = h.running("task", Some(RUN));
    let issued = |h: &Harness, action| {
        let record = h.message(action, "be brief");
        h.update(&record.id, |r| {
            r.transition(MessageState::Accepted);
            r.transition(MessageState::Running);
        });
        record
    };
    let joined = issued(&h, MessageAction::Steer);
    let unanswered = issued(&h, MessageAction::Steer);
    let interrupt = h.interrupting(&main);
    let queued = h.message(MessageAction::Message, "next");
    h.update(&queued.id, |r| {
        r.transition(MessageState::Accepted);
    });
    let active = h.driver.active.as_mut().unwrap();
    active.steers.push(joined.id.clone());
    active.interrupts.push(interrupt.id.clone());
    h.driver
        .pending
        .insert(7, Pending::Steer(unanswered.id.clone()));
    h.driver.queue.push_back(queued.id.clone());

    mark_takedown(&h);
    h.driver
        .stopped_from(&mut signalled(), STOPPED.into(), true, daemon)
        .await
        .unwrap();
    assert_eq!(h.load(&main.id).state, MessageState::Paused);
    for steer in [&joined, &unanswered] {
        let steer = h.load(&steer.id);
        assert_eq!(
            (steer.state, steer.error.as_deref()),
            (
                MessageState::Unknown,
                Some(
                    "the driver was stopped by SIGTERM; the steer outcome is unknown and is not replayed"
                )
            )
        );
    }
    assert_eq!(h.load(&interrupt.id).state, MessageState::Running);
    assert_eq!(h.load(&queued.id).state, MessageState::Accepted);

    // The next start ends the run its accepted interrupt was for, and the
    // queued message waits its turn.
    let (_peer, sent) = next_start(&mut h, &main, vec![step(vec![reply(3, "abort", None)])]).await;
    assert_eq!(sent, ["get_state", "clear_queue", "abort"]);
    assert_eq!(h.load(&main.id).state, MessageState::Interrupted);
    assert_eq!(h.load(&interrupt.id).state, MessageState::Completed);
    assert_eq!(h.driver.queue, std::slice::from_ref(&queued.id));
    assert_eq!(h.load(&queued.id).state, MessageState::Accepted);
    assert_eq!(told(&parent, &main.id), (1, 1));
}

#[tokio::test]
async fn losing_the_peer_never_ends_a_message_the_takedown_paused() {
    let mut h = host(AgentKind::Noel);
    let parent = h.with_parent();
    let main = h.running("task", Some(RUN));
    helper_pauses(&h, &main.id);
    assert!(
        h.driver
            .lose_peer(&mut script_peer("exit 1"), CLOSED.into(), false)
            .await
            .is_err()
    );
    assert_eq!(h.load(&main.id).state, MessageState::Paused);
    assert_eq!(told(&parent, &main.id), (1, 0));
}

#[tokio::test]
async fn recovery_queues_a_pause_notice_its_writer_never_queued() {
    let mut h = host(AgentKind::Noel);
    let parent = h.with_parent();
    // Paused, and stopped before the notice was written.
    let main = h.crashed(MessageAction::Message, "task", Some(RUN));
    h.update(&main.id, |r| {
        assert!(r.pause(PauseReason::EnvironmentStopped));
    });
    assert_eq!(told(&parent, &main.id), (0, 0));
    h.driver.recover().await.unwrap();
    assert_eq!(told(&parent, &main.id), (1, 0));
    assert_eq!(
        h.load(&main.id).pause_notification.unwrap().message_id,
        pause_notification_id(&main.id)
    );
    h.restart();
    h.driver.recover().await.unwrap();
    assert_eq!(told(&parent, &main.id), (1, 0));
}

#[tokio::test]
async fn noel_ended_by_its_sessions_signal_pauses_only_with_the_takedowns_evidence() {
    let mut h = host(AgentKind::Noel);
    let parent = h.with_parent();
    let main = h.running("task", Some(RUN));
    mark_takedown(&h);
    // noel's exit is read before the driver's own signal.
    let mut peer = signalled();
    assert_eq!(
        h.driver.respawn_noel(&mut peer, CLOSED).await,
        Respawn::Signalled
    );
    h.driver
        .stopped_from(&mut peer, CLOSED.into(), false, daemon)
        .await
        .unwrap();
    assert_eq!(h.load(&main.id).state, MessageState::Paused);
    assert_eq!(told(&parent, &main.id), (1, 0));
    assert_eq!(h.driver.state.phase, DriverPhase::Stopped);

    // Without it the message ends unknown and the driver fails, as before.
    let mut h = host(AgentKind::Noel);
    let parent = h.with_parent();
    let main = h.running("task", Some(RUN));
    let mut peer = signalled();
    assert_eq!(
        h.driver.respawn_noel(&mut peer, CLOSED).await,
        Respawn::Signalled
    );
    assert!(
        h.driver
            .stopped_from(&mut peer, CLOSED.into(), false, daemon)
            .await
            .is_err()
    );
    let ended = h.load(&main.id);
    assert_eq!(
        (ended.state, ended.error.as_deref()),
        (
            MessageState::Unknown,
            Some(
                "the native agent closed its output (native agent exit status: 143); the turn outcome is unknown and is not replayed"
            )
        )
    );
    assert_eq!(told(&parent, &main.id), (0, 1));
    assert_eq!(h.driver.state.phase, DriverPhase::Failed);
}

#[tokio::test]
async fn codex_claude_and_a_noel_that_cannot_resume_keep_their_stop_in_a_takedown() {
    for agent in [AgentKind::Codex, AgentKind::Claude, AgentKind::Noel] {
        let mut h = host(agent);
        let parent = h.with_parent();
        h.driver.state.capabilities.resume = false;
        let main = h.running("task", Some(RUN));
        // All the evidence of a takedown changes nothing for them.
        mark_takedown(&h);
        let started = Instant::now();
        h.driver
            .stopped_from(&mut signalled(), STOPPED.into(), true, daemon)
            .await
            .unwrap();
        let ended = h.load(&main.id);
        assert_eq!(
            (ended.state, ended.error.as_deref()),
            (MessageState::Unknown, Some(STOPPED_UNKNOWN)),
            "{agent:?}"
        );
        assert_eq!(told(&parent, &main.id), (0, 1), "{agent:?}");
        assert!(started.elapsed() < Duration::from_secs(5), "{agent:?}");
        // Their records and state keep their bytes: nothing about a pause.
        for path in [
            message_path(&h.driver.dir, &main.id),
            h.driver.dir.join("state.json"),
        ] {
            let bytes = fs::read_to_string(path).unwrap();
            assert!(!bytes.contains("pause"), "{agent:?}: {bytes}");
        }
        // The helper pauses nothing for a conversation that cannot resume:
        // it reads the capability from the driver's saved state.
        let state: DriverState = read_record(&h.driver.dir.join("state.json")).unwrap();
        assert!(!state.capabilities.resume, "{agent:?}");
    }
}

#[tokio::test]
async fn a_record_that_no_agent_can_resume_ends_unknown_at_recovery() {
    // Only noel pauses. Another agent's paused record could never resume.
    for agent in [AgentKind::Codex, AgentKind::Claude] {
        let mut h = host(agent);
        let parent = h.with_parent();
        let main = h.crashed(MessageAction::Message, "task", Some(RUN));
        h.update(&main.id, |r| {
            r.pause(PauseReason::EnvironmentStopped);
        });
        h.driver.recover().await.unwrap();
        let ended = h.load(&main.id);
        assert_eq!(
            (ended.state, ended.error.as_deref()),
            (MessageState::Unknown, Some(UNKNOWN)),
            "{agent:?}"
        );
        assert_eq!(told(&parent, &main.id), (0, 1), "{agent:?}");
    }
}

#[test]
fn a_paused_message_says_why_and_notes_its_resume() {
    let mut record = MessageRecord::new("driver", "session", MessageAction::Message, "task".into());
    record.transition(MessageState::Accepted);
    record.transition(MessageState::Running);
    assert_eq!(state_label(&record), "running");
    assert!(record.pause(PauseReason::EnvironmentStopped));
    assert_eq!(state_label(&record), "paused: environment stopped");
    assert_eq!(resumed_note(&record), "");
    let saved = serde_json::to_value(&record).unwrap();
    assert_eq!(saved["state"], "paused");
    assert_eq!(saved["pause"]["reason"], "environment_stopped");
    assert_eq!(saved["pause"]["paused_at"], saved["updated_at"]);
    assert!(record.resume());
    assert_eq!(state_label(&record), "running");
    assert_eq!(
        resumed_note(&record),
        " (resumed after its environment stopped)"
    );
    record.native_resumed = 2;
    assert_eq!(
        resumed_note(&record),
        " (resumed by noel 2 times) (resumed after its environment stopped)"
    );
}

#[tokio::test]
async fn a_parent_adopts_notices_in_the_order_they_were_made() {
    // A worker message's pause notice is made before its final one, so a
    // parent that finds both in its inbox takes the pause first.
    let mut h = host(AgentKind::Noel);
    let mut made = Vec::new();
    for index in 0..8 {
        let mut notice = MessageRecord::new(
            &h.driver.config.driver_id,
            &h.driver.binding.session_id,
            MessageAction::Notification,
            format!("notice {index}"),
        );
        // Written in the reverse of the order they were made.
        notice.created_at = format!("2026-01-01T00:00:{:02}.000000Z", 59 - index);
        assert!(create_message(&h.driver.dir, &notice).unwrap());
        made.push((notice.created_at, notice.id));
    }
    made.sort();
    h.driver.adopt_notifications().await.unwrap();
    assert_eq!(
        Vec::from(h.driver.queue.clone()),
        made.into_iter().map(|(_, id)| id).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn a_signal_from_elsewhere_waits_for_the_marker_its_daemon_writes() {
    // A host that shuts down signals the driver and its daemon at once: the
    // marker comes a moment after the driver's own signal.
    let mut h = host(AgentKind::Noel);
    let parent = h.with_parent();
    let main = h.running("task", Some(RUN));
    let late = Duration::from_millis(400);
    let marked = {
        let marker = h.driver.environment.root().join(SHUTDOWN_MARKER);
        std::thread::spawn(move || {
            std::thread::sleep(late);
            fs::write(marker, "true").unwrap();
        })
    };
    let started = Instant::now();
    h.driver
        .stopped_from(&mut signalled(), STOPPED.into(), true, elsewhere)
        .await
        .unwrap();
    marked.join().unwrap();
    assert!(started.elapsed() >= late);
    assert_eq!(h.load(&main.id).state, MessageState::Paused);
    assert_eq!(told(&parent, &main.id), (1, 0));
}

#[tokio::test]
async fn a_stray_signal_ends_the_run_unknown_once_no_marker_came() {
    let mut h = host(AgentKind::Noel);
    let parent = h.with_parent();
    let main = h.running("task", Some(RUN));
    let started = Instant::now();
    h.driver
        .stopped_from(&mut signalled(), STOPPED.into(), true, elsewhere)
        .await
        .unwrap();
    assert!(started.elapsed() >= pause::FOREIGN_SIGNAL_WAIT);
    let ended = h.load(&main.id);
    assert_eq!(
        (ended.state, ended.error.as_deref()),
        (MessageState::Unknown, Some(STOPPED_UNKNOWN))
    );
    assert_eq!(told(&parent, &main.id), (0, 1));
}

#[tokio::test]
async fn an_explicit_stop_that_follows_a_signal_from_elsewhere_ends_the_wait() {
    // While the driver waits for a marker, its conversation is stopped
    // explicitly: the stop's recorded interrupt decides at once.
    let mut h = host(AgentKind::Noel);
    let parent = h.with_parent();
    let main = h.running("task", Some(RUN));
    let recorded = {
        let (dir, driver, session, message) = (
            h.driver.dir.clone(),
            h.driver.config.driver_id.clone(),
            h.driver.binding.session_id.clone(),
            main.id.clone(),
        );
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            let mut interrupt =
                MessageRecord::new(&driver, &session, MessageAction::Interrupt, String::new());
            interrupt.id = stop_interrupt_id(&message);
            interrupt.expected_active_message_id = Some(message);
            assert!(create_message(&dir, &interrupt).unwrap());
        })
    };
    let started = Instant::now();
    h.driver
        .stopped_from(&mut signalled(), STOPPED.into(), true, elsewhere)
        .await
        .unwrap();
    recorded.join().unwrap();
    assert!(started.elapsed() < pause::FOREIGN_SIGNAL_WAIT);
    assert_eq!(h.load(&main.id).state, MessageState::Unknown);
    assert_eq!(told(&parent, &main.id), (0, 1));
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn the_driver_learns_who_sent_its_stop_signal_and_the_runtime_still_hears_it() {
    use tokio::signal::unix::{SignalKind, signal};
    // As in the driver: the runtime's handlers first, then the watch.
    let mut hangup = signal(SignalKind::hangup()).unwrap();
    let _terminate = signal(SignalKind::terminate()).unwrap();
    let _interrupt = signal(SignalKind::interrupt()).unwrap();
    pause::sender::watch().unwrap();
    pause::sender::watch().unwrap();
    // SAFETY: getpid reads the current process identity, and the signal
    // goes to this process, which now handles it.
    let me = unsafe { libc::getpid() };
    assert_eq!(unsafe { libc::kill(me, libc::SIGHUP) }, 0);
    tokio::time::timeout(Duration::from_secs(10), hangup.recv())
        .await
        .expect("the runtime's own handler still runs")
        .unwrap();
    assert_eq!(pause::sender::latest(), Some(me));
    // This test process is not its own parent, so it is not "the daemon".
    assert!(!pause::sender::by_daemon());
}
