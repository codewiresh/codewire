use super::*;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use tokio::sync::{Notify, mpsc, oneshot};
use tokio_stream::wrappers::ReceiverStream;

type OutputFrame = Result<Option<DaemonRunOutput>, DaemonClientError>;

#[derive(Default)]
struct InputLifetime {
    dropped: AtomicBool,
    changed: Notify,
}
impl InputLifetime {
    async fn wait_dropped(&self) {
        loop {
            let notified = self.changed.notified();
            if self.dropped.load(Ordering::SeqCst) {
                return;
            }
            notified.await;
        }
    }
}
struct FakeInput {
    sender: mpsc::Sender<DaemonRunInput>,
    lifetime: Arc<InputLifetime>,
}
impl Drop for FakeInput {
    fn drop(&mut self) {
        self.lifetime.dropped.store(true, Ordering::SeqCst);
        self.lifetime.changed.notify_waiters();
    }
}
impl TerminalInput for FakeInput {
    async fn send_input(&self, input: DaemonRunInput) -> Result<(), DaemonClientError> {
        self.sender
            .send(input)
            .await
            .map_err(|_| DaemonClientError::RequestClosed)
    }
}
struct FakeOutput {
    receiver: mpsc::Receiver<OutputFrame>,
    require_input_drop_at_eof: Option<Arc<InputLifetime>>,
}
impl TerminalOutput for FakeOutput {
    async fn next_output(&mut self) -> OutputFrame {
        let frame = self.receiver.recv().await.unwrap_or(Ok(None));
        if matches!(frame, Ok(None))
            && let Some(lifetime) = &self.require_input_drop_at_eof
        {
            assert!(
                lifetime.dropped.load(Ordering::SeqCst),
                "input retained after Exit"
            );
        }
        frame
    }
}
struct FakeSession {
    input: FakeInput,
    output: FakeOutput,
}
impl TerminalSession for FakeSession {
    type Input = FakeInput;
    type Output = FakeOutput;
    fn into_parts(self) -> (Self::Input, Self::Output) {
        (self.input, self.output)
    }
}
struct DaemonFixture {
    session: FakeSession,
    input: mpsc::Receiver<DaemonRunInput>,
    output: mpsc::Sender<OutputFrame>,
    lifetime: Arc<InputLifetime>,
}
fn daemon() -> DaemonFixture {
    let (input_tx, input) = mpsc::channel(4);
    let (output, output_rx) = mpsc::channel(16);
    let lifetime = Arc::new(InputLifetime::default());
    DaemonFixture {
        session: FakeSession {
            input: FakeInput {
                sender: input_tx,
                lifetime: lifetime.clone(),
            },
            output: FakeOutput {
                receiver: output_rx,
                require_input_drop_at_eof: None,
            },
        },
        input,
        output,
        lifetime,
    }
}
fn frame(output: DaemonRunOutput) -> OutputFrame {
    Ok(Some(output))
}

#[derive(Default)]
struct SinkState {
    sent: Vec<Message>,
    blocked: bool,
    failed: bool,
    waker: Option<Waker>,
}
#[derive(Clone, Default)]
struct SinkProbe {
    state: Arc<Mutex<SinkState>>,
    attempts: Arc<AtomicUsize>,
    flushes: Arc<AtomicUsize>,
    changed: Arc<Notify>,
}
impl SinkProbe {
    fn unblock(&self) {
        let mut state = self.state.lock().unwrap();
        state.blocked = false;
        if let Some(waker) = state.waker.take() {
            waker.wake();
        }
    }
    async fn wait_attempt(&self) {
        loop {
            let notified = self.changed.notified();
            if self.attempts.load(Ordering::SeqCst) > 0 {
                return;
            }
            notified.await;
        }
    }
    fn close_codes(&self) -> Vec<u16> {
        self.state
            .lock()
            .unwrap()
            .sent
            .iter()
            .filter_map(|message| match message {
                Message::Close(Some(frame)) => Some(frame.code),
                _ => None,
            })
            .collect()
    }
}
struct FakeSink(SinkProbe);
impl Sink<Message> for FakeSink {
    type Error = ();
    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), ()>> {
        self.0.attempts.fetch_add(1, Ordering::SeqCst);
        self.0.changed.notify_waiters();
        let mut state = self.0.state.lock().unwrap();
        if state.failed {
            Poll::Ready(Err(()))
        } else if state.blocked {
            state.waker = Some(cx.waker().clone());
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    }
    fn start_send(self: Pin<&mut Self>, message: Message) -> Result<(), ()> {
        self.0.state.lock().unwrap().sent.push(message);
        Ok(())
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), ()>> {
        self.0.flushes.fetch_add(1, Ordering::SeqCst);
        Poll::Ready(Ok(()))
    }
    fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), ()>> {
        Poll::Ready(Ok(()))
    }
}
type BrowserFixture = (
    mpsc::Sender<Result<Message, ()>>,
    ReceiverStream<Result<Message, ()>>,
    FakeSink,
    SinkProbe,
);

fn browser() -> BrowserFixture {
    let (sender, receiver) = mpsc::channel(TERMINAL_PENDING_FRAMES + 2);
    let probe = SinkProbe::default();
    (
        sender,
        ReceiverStream::new(receiver),
        FakeSink(probe.clone()),
        probe,
    )
}
fn limits() -> TerminalLimits {
    TerminalLimits {
        start: Duration::from_secs(1),
        finalize: Duration::from_secs(1),
        io: Duration::from_secs(1),
    }
}

#[test]
fn tty_request_uses_daemon_default_shell_and_no_inherited_environment() {
    assert_eq!(
        terminal_start(),
        DaemonRunStart {
            command: vec![],
            working_dir: String::new(),
            env: vec![],
            allocate_tty: true,
            term: "xterm-256color".into(),
            columns: 80,
            rows: 24,
        }
    );
}

#[test]
fn input_decoding_preserves_bytes_and_resize_without_close_stdin() {
    let mut pending = PendingInputs::default();
    pending.push(&[]).unwrap();
    pending.push(&[MSG_TYPE_STDIN]).unwrap();
    pending.push(&[MSG_TYPE_STDIN, 0, 255, b'a']).unwrap();
    pending.push(&[MSG_TYPE_RESIZE, 1, 44, 0, 50]).unwrap();
    assert_eq!(
        pending.frames.iter().cloned().collect::<Vec<_>>(),
        vec![
            DaemonRunInput::Stdin(vec![0, 255, b'a']),
            DaemonRunInput::Resize {
                columns: 300,
                rows: 50
            },
        ]
    );
    assert_eq!(pending.bytes, 7);
    pending.pop();
    pending.pop();
    assert_eq!(pending.bytes, 0);
}

#[test]
fn input_frame_count_and_total_bytes_are_independently_bounded() {
    let mut pending = PendingInputs::default();
    for _ in 0..TERMINAL_PENDING_FRAMES {
        pending.push(&[MSG_TYPE_STDIN, b'x']).unwrap();
    }
    assert_eq!(
        pending.push(&[MSG_TYPE_STDIN, b'x']),
        Err(TerminalEnd::InputLimit)
    );
    let mut pending = PendingInputs::default();
    let large = vec![0; TERMINAL_FRAME_BYTES];
    for _ in 0..4 {
        pending.push(&large).unwrap();
    }
    assert_eq!(
        pending.push(&[MSG_TYPE_STDIN, 1, 2, 3, 4, 5]),
        Err(TerminalEnd::InputLimit)
    );
    assert_eq!(
        pending.push(&vec![0; TERMINAL_FRAME_BYTES + 1]),
        Err(TerminalEnd::InputLimit)
    );
    for invalid in [
        &[MSG_TYPE_RESIZE, 0, 0, 0, 1][..],
        &[MSG_TYPE_RESIZE, 0, 1, 0, 0],
        &[MSG_TYPE_RESIZE, 0],
        &[2],
    ] {
        assert_eq!(
            PendingInputs::default().push(invalid),
            Err(TerminalEnd::InputLimit)
        );
    }
}

#[tokio::test]
async fn natural_exit_drops_input_before_clean_eof_and_closes_normally() {
    let mut daemon = daemon();
    daemon.session.output.require_input_drop_at_eof = Some(daemon.lifetime.clone());
    daemon
        .output
        .try_send(frame(DaemonRunOutput::Stdout(vec![0, 255])))
        .unwrap();
    daemon
        .output
        .try_send(frame(DaemonRunOutput::Exit(7)))
        .unwrap();
    daemon.output.try_send(Ok(None)).unwrap();
    let (_browser, mut input, mut output, probe) = browser();
    assert!(
        relay_terminal(
            &mut output,
            &mut input,
            async { Ok(daemon.session) },
            limits()
        )
        .await
    );
    assert_eq!(probe.close_codes(), vec![1000]);
    assert!(
        matches!(&probe.state.lock().unwrap().sent[0], Message::Binary(bytes) if bytes.as_ref() == [0, 255])
    );
    assert!(daemon.input.recv().await.is_none());
}

#[tokio::test(start_paused = true)]
async fn a_terminal_with_no_output_is_pinged_every_30_seconds() {
    let daemon = daemon();
    let (_browser, mut input, mut output, probe) = browser();
    let pings = || {
        probe
            .state
            .lock()
            .unwrap()
            .sent
            .iter()
            .filter(|message| matches!(message, Message::Ping(_)))
            .count()
    };
    let every = crate::api::socket_keepalive::PING_EVERY;
    let relay = relay_terminal(
        &mut output,
        &mut input,
        async { Ok(daemon.session) },
        limits(),
    );
    tokio::select! {
        _ = relay => panic!("the relay ended"),
        () = async {
            tokio::time::sleep(every - Duration::from_millis(1)).await;
            assert_eq!(pings(), 0);
            tokio::time::sleep(Duration::from_millis(2)).await;
            assert_eq!(pings(), 1);
            tokio::time::sleep(every).await;
            assert_eq!(pings(), 2);
        } => {}
    }
}

#[tokio::test]
async fn remote_error_is_redacted_diagnostic_not_exit_proof() {
    let daemon = daemon();
    daemon
        .output
        .try_send(Err(DaemonClientError::Remote(
            "synthetic-private-diagnostic".into(),
        )))
        .unwrap();
    daemon
        .output
        .try_send(frame(DaemonRunOutput::Exit(1)))
        .unwrap();
    daemon.output.try_send(Ok(None)).unwrap();
    let (_browser, mut input, mut output, probe) = browser();
    assert!(
        relay_terminal(
            &mut output,
            &mut input,
            async { Ok(daemon.session) },
            limits()
        )
        .await
    );
    assert_eq!(probe.close_codes(), vec![1011]);
    assert!(
        probe
            .state
            .lock()
            .unwrap()
            .sent
            .iter()
            .all(|frame| matches!(frame, Message::Close(_)))
    );
}

#[tokio::test]
async fn missing_or_invalid_terminal_proof_is_ambiguous() {
    let cases = vec![
        vec![Ok(None)],
        vec![
            Err(DaemonClientError::Remote("diagnostic".into())),
            Ok(None),
        ],
        vec![frame(DaemonRunOutput::Exit(-1)), Ok(None)],
        vec![frame(DaemonRunOutput::Exit(256)), Ok(None)],
        vec![
            frame(DaemonRunOutput::Exit(0)),
            frame(DaemonRunOutput::Exit(0)),
            Ok(None),
        ],
        vec![
            frame(DaemonRunOutput::Exit(0)),
            frame(DaemonRunOutput::Stdout(vec![1])),
            Ok(None),
        ],
        vec![
            frame(DaemonRunOutput::Exit(0)),
            Err(DaemonClientError::Remote("late diagnostic".into())),
            Ok(None),
        ],
        vec![
            Err(DaemonClientError::InvalidFrame("synthetic")),
            frame(DaemonRunOutput::Exit(0)),
            Ok(None),
        ],
        vec![
            frame(DaemonRunOutput::Exit(0)),
            Err(DaemonClientError::Status(tonic::Status::unavailable(
                "synthetic",
            ))),
        ],
        vec![
            frame(DaemonRunOutput::Stdout(vec![0; TERMINAL_FRAME_BYTES + 1])),
            frame(DaemonRunOutput::Exit(0)),
            Ok(None),
        ],
    ];
    for frames in cases {
        let daemon = daemon();
        for frame in frames {
            daemon.output.try_send(frame).unwrap();
        }
        let (_browser, mut input, mut output, probe) = browser();
        assert!(
            !relay_terminal(
                &mut output,
                &mut input,
                async { Ok(daemon.session) },
                limits()
            )
            .await
        );
        assert_eq!(probe.close_codes(), vec![1011]);
        assert!(daemon.lifetime.dropped.load(Ordering::SeqCst));
    }
}

#[tokio::test]
async fn peer_close_keeps_pending_start_then_drops_sole_input_and_drains() {
    let daemon = daemon();
    let (ack, attached) = oneshot::channel();
    let (browser, mut input, mut output, probe) = browser();
    browser.send(Ok(Message::Close(None))).await.unwrap();
    let relay = tokio::spawn(async move {
        relay_terminal(
            &mut output,
            &mut input,
            async { attached.await.map_err(|_| DaemonClientError::RequestClosed) },
            limits(),
        )
        .await
    });
    tokio::task::yield_now().await;
    assert!(!relay.is_finished());
    assert!(!ack.is_closed(), "pending start future was discarded");
    assert!(ack.send(daemon.session).is_ok());
    daemon.lifetime.wait_dropped().await;
    assert!(
        !relay.is_finished(),
        "input drop was mistaken for reaping proof"
    );
    daemon
        .output
        .send(frame(DaemonRunOutput::Exit(137)))
        .await
        .unwrap();
    daemon.output.send(Ok(None)).await.unwrap();
    assert!(relay.await.unwrap());
    assert!(
        probe.close_codes().is_empty(),
        "must flush the automatic Close reply, not send another"
    );
    assert!(probe.flushes.load(Ordering::SeqCst) > 0);
}

#[tokio::test]
async fn pending_start_without_ack_remains_ambiguous_at_bounded_deadline() {
    let (ack, attached) = oneshot::channel::<FakeSession>();
    let (browser, mut input, mut output, _) = browser();
    browser.send(Ok(Message::Close(None))).await.unwrap();
    let mut bounds = limits();
    bounds.finalize = Duration::from_millis(10);
    assert!(
        !relay_terminal(
            &mut output,
            &mut input,
            async { attached.await.map_err(|_| DaemonClientError::RequestClosed) },
            bounds
        )
        .await
    );
    assert!(ack.is_closed());
}

// On the paused clock the relay's finalizer deadline starts at `origin`, as
// the timeline below assumes. On real time it started when the relay was
// first polled, and a host that delayed that past 40 ms let the exit at 140 ms
// land inside the budget (#4707).
#[tokio::test(start_paused = true)]
async fn pending_start_and_final_drain_share_one_original_deadline() {
    let daemon = daemon();
    let (browser, mut input, mut output, _) = browser();
    browser.send(Ok(Message::Close(None))).await.unwrap();
    let origin = tokio::time::Instant::now();
    let mut bounds = limits();
    bounds.finalize = Duration::from_millis(100);
    let delayed_output = async {
        tokio::time::sleep_until(origin + Duration::from_millis(140)).await;
        // Sending may fail because the original finalizer deadline has expired.
        let _ = daemon.output.send(frame(DaemonRunOutput::Exit(0))).await;
        let _ = daemon.output.send(Ok(None)).await;
    };
    let relay = relay_terminal(
        &mut output,
        &mut input,
        async {
            tokio::time::sleep_until(origin + Duration::from_millis(70)).await;
            Ok(daemon.session)
        },
        bounds,
    );
    let (proven, ()) = tokio::join!(relay, delayed_output);
    assert!(!proven, "the start ACK must not renew the finalizer budget");
}

#[tokio::test]
async fn browser_close_interrupts_slow_output_then_waits_for_actual_exit() {
    let daemon = daemon();
    daemon
        .output
        .try_send(frame(DaemonRunOutput::Stdout(vec![1])))
        .unwrap();
    let (browser, mut input, mut output, probe) = browser();
    probe.state.lock().unwrap().blocked = true;
    let relay = tokio::spawn(async move {
        relay_terminal(
            &mut output,
            &mut input,
            async { Ok(daemon.session) },
            limits(),
        )
        .await
    });
    probe.wait_attempt().await;
    browser.send(Ok(Message::Close(None))).await.unwrap();
    daemon.lifetime.wait_dropped().await;
    assert!(!relay.is_finished());
    daemon
        .output
        .send(frame(DaemonRunOutput::Exit(137)))
        .await
        .unwrap();
    daemon.output.send(Ok(None)).await.unwrap();
    assert!(relay.await.unwrap());
    assert!(probe.state.lock().unwrap().sent.is_empty());
    assert!(probe.flushes.load(Ordering::SeqCst) > 0);
}

#[tokio::test]
async fn output_write_failure_still_requires_exit_and_clean_eof() {
    for send_exit in [false, true] {
        let daemon = daemon();
        daemon
            .output
            .try_send(frame(DaemonRunOutput::Stdout(vec![1])))
            .unwrap();
        let (_browser, mut input, mut output, probe) = browser();
        probe.state.lock().unwrap().failed = true;
        let relay = tokio::spawn(async move {
            relay_terminal(
                &mut output,
                &mut input,
                async { Ok(daemon.session) },
                limits(),
            )
            .await
        });
        daemon.lifetime.wait_dropped().await;
        assert!(!relay.is_finished());
        if send_exit {
            daemon
                .output
                .send(frame(DaemonRunOutput::Exit(137)))
                .await
                .unwrap();
        }
        daemon.output.send(Ok(None)).await.unwrap();
        assert_eq!(relay.await.unwrap(), send_exit);
    }
}

#[tokio::test]
async fn input_is_buffered_while_browser_output_waits_and_then_sent_in_order() {
    let mut daemon = daemon();
    daemon
        .output
        .try_send(frame(DaemonRunOutput::Stdout(vec![1])))
        .unwrap();
    let (browser, mut input, mut output, probe) = browser();
    probe.state.lock().unwrap().blocked = true;
    let relay = tokio::spawn(async move {
        relay_terminal(
            &mut output,
            &mut input,
            async { Ok(daemon.session) },
            limits(),
        )
        .await
    });
    probe.wait_attempt().await;
    browser
        .send(Ok(Message::Binary(vec![MSG_TYPE_STDIN, b'a'].into())))
        .await
        .unwrap();
    browser
        .send(Ok(Message::Binary(
            vec![MSG_TYPE_RESIZE, 0, 100, 0, 40].into(),
        )))
        .await
        .unwrap();
    probe.unblock();
    assert_eq!(
        daemon.input.recv().await,
        Some(DaemonRunInput::Stdin(vec![b'a']))
    );
    assert_eq!(
        daemon.input.recv().await,
        Some(DaemonRunInput::Resize {
            columns: 100,
            rows: 40
        })
    );
    daemon
        .output
        .send(frame(DaemonRunOutput::Exit(0)))
        .await
        .unwrap();
    daemon.output.send(Ok(None)).await.unwrap();
    assert!(relay.await.unwrap());
    assert!(daemon.input.recv().await.is_none());
}

#[tokio::test]
async fn prelaunch_queue_overflow_retains_start_and_drains_accepted_session() {
    let daemon = daemon();
    let (ack, attached) = oneshot::channel();
    let (browser, mut input, mut output, probe) = browser();
    for _ in 0..=TERMINAL_PENDING_FRAMES {
        browser
            .send(Ok(Message::Binary(vec![MSG_TYPE_STDIN, 1].into())))
            .await
            .unwrap();
    }
    let relay = tokio::spawn(async move {
        relay_terminal(
            &mut output,
            &mut input,
            async { attached.await.map_err(|_| DaemonClientError::RequestClosed) },
            limits(),
        )
        .await
    });
    probe.wait_attempt().await;
    assert_eq!(probe.close_codes(), vec![1009]);
    assert!(!ack.is_closed());
    assert!(ack.send(daemon.session).is_ok());
    daemon.lifetime.wait_dropped().await;
    daemon
        .output
        .send(frame(DaemonRunOutput::Exit(137)))
        .await
        .unwrap();
    daemon.output.send(Ok(None)).await.unwrap();
    assert!(relay.await.unwrap());
}

#[tokio::test]
async fn a_fence_ends_a_live_session_unproven_with_server_restarting() {
    let daemon = daemon();
    daemon
        .output
        .try_send(frame(DaemonRunOutput::Stdout(vec![1])))
        .unwrap();
    let (_browser, mut input, mut output, probe) = browser();
    let (fence, fenced) = oneshot::channel::<()>();
    let session = daemon.session;
    let lifetime = daemon.lifetime.clone();
    let relay = tokio::spawn(async move {
        relay_until_fenced(
            &mut output,
            &mut input,
            async { Ok(session) },
            limits(),
            async {
                let _ = fenced.await;
            },
            std::future::pending(),
        )
        .await
    });
    // Live: its output reached the browser.
    tokio::time::timeout(Duration::from_secs(30), async {
        while probe.state.lock().unwrap().sent.is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the session never relayed");
    fence.send(()).unwrap();
    assert!(!relay.await.unwrap(), "a fenced session was proven");
    assert_eq!(probe.close_codes(), vec![1012]);
    // The run's input went with the relay, which ends the daemon run.
    lifetime.wait_dropped().await;
    drop(daemon.output);
}

#[tokio::test]
async fn a_fence_raised_before_the_relay_starts_ends_it_at_once() {
    // The relay's own behaviour: a fence already raised when it starts ends
    // it before the session runs. That the handler's fence is taken at
    // admission is `LeaseOwner::admit`'s own test.
    let (owner, switch) = crate::lease_owner::LeaseOwner::switchable();
    let fenced = owner.admit().expect("not yet fenced");
    switch.fence();
    let daemon = daemon();
    let (_browser, mut input, mut output, probe) = browser();
    let proven = tokio::time::timeout(
        Duration::from_secs(30),
        relay_until_fenced(
            &mut output,
            &mut input,
            async { Ok(daemon.session) },
            limits(),
            fenced,
            std::future::pending(),
        ),
    )
    .await
    .expect("the relay ran past a fence raised before it started");
    assert!(!proven);
    assert_eq!(probe.close_codes(), vec![1012]);
}

/// #3586: a revoked credential ends a one-off terminal through the browser
/// close's own path: the browser closes with 1008 "access revoked", the
/// daemon's input is dropped, and the relay waits for the run's actual exit.
#[tokio::test]
async fn a_revocation_closes_the_browser_drops_input_and_waits_for_the_exit() {
    let daemon = daemon();
    let (_browser, mut input, mut output, probe) = browser();
    let (revoke, revoked) = tokio::sync::oneshot::channel::<()>();
    let relay = tokio::spawn(async move {
        relay_terminal_until(
            &mut output,
            &mut input,
            async { Ok(daemon.session) },
            limits(),
            async {
                let _ = revoked.await;
                TerminalEnd::Revoked(Revocation::Session)
            },
        )
        .await
    });
    revoke.send(()).unwrap();
    daemon.lifetime.wait_dropped().await;
    assert!(!relay.is_finished(), "waits for the run's exit");
    assert_eq!(probe.close_codes(), vec![1008]);
    assert!(matches!(
        &probe.state.lock().unwrap().sent[..],
        [Message::Close(Some(frame))] if frame.reason == "access revoked"
    ));
    daemon
        .output
        .send(frame(DaemonRunOutput::Exit(130)))
        .await
        .unwrap();
    daemon.output.send(Ok(None)).await.unwrap();
    assert!(relay.await.unwrap());
}

/// #3586: the organization's deletion closes a one-off terminal with its own
/// reason, so the page shows the organization line.
#[tokio::test]
async fn the_deletion_closes_the_browser_saying_the_organization_is_being_deleted() {
    let daemon = daemon();
    let (_browser, mut input, mut output, probe) = browser();
    let relay = tokio::spawn(async move {
        relay_terminal_until(
            &mut output,
            &mut input,
            async { Ok(daemon.session) },
            limits(),
            async { TerminalEnd::Revoked(Revocation::Organization) },
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(30), async {
        while probe.close_codes().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the browser was closed");
    assert!(matches!(
        &probe.state.lock().unwrap().sent[..],
        [Message::Close(Some(frame))]
            if frame.code == 1008 && frame.reason == codewire_server_core::org::ORGANIZATION_DELETING
    ));
    relay.abort();
}

/// #4459: the drain deadline ends a one-off terminal the way a revocation
/// does, so the kill that follows never resets it: the browser closes with
/// 1012 "server restarting" and may reconnect, the daemon's input is dropped,
/// and the relay waits for the run's exit, so its lease is settled proven.
#[tokio::test]
async fn the_drain_deadline_closes_with_1012_drops_input_and_waits_for_the_exit() {
    let drain = crate::drain::Drain::default();
    let daemon = daemon();
    daemon
        .output
        .try_send(frame(DaemonRunOutput::Stdout(vec![1])))
        .unwrap();
    let (_browser, mut input, mut output, probe) = browser();
    let session = daemon.session;
    let ended = terminal_ended(std::future::pending(), drain.signal(Restart::Deadline));
    let relay = tokio::spawn(async move {
        relay_until_fenced(
            &mut output,
            &mut input,
            async { Ok(session) },
            limits(),
            std::future::pending(),
            ended,
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(30), async {
        while probe.state.lock().unwrap().sent.is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the session never relayed");
    drain.begin(Duration::ZERO);
    tokio::time::timeout(Duration::from_secs(30), daemon.lifetime.wait_dropped())
        .await
        .expect("the deadline left the daemon's input open");
    assert!(!relay.is_finished(), "waits for the run's exit");
    assert_eq!(probe.close_codes(), vec![1012]);
    assert!(
        probe
            .state
            .lock()
            .unwrap()
            .sent
            .iter()
            .any(|message| matches!(
                message,
                Message::Close(Some(frame)) if frame.reason == "server restarting"
            ))
    );
    daemon
        .output
        .send(frame(DaemonRunOutput::Exit(129)))
        .await
        .unwrap();
    daemon.output.send(Ok(None)).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(30), relay)
            .await
            .expect("the relay outlived its run")
            .unwrap(),
        "a run that exited after the deadline is proven"
    );
}
