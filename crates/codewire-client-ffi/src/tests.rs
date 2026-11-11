use std::time::Duration;

use codewire_client::tailnet_session::TailnetPathReport;

use super::*;

/// Records every state it is told.
#[derive(Default)]
struct Recorder(Mutex<Vec<ShellState>>);

impl ShellObserver for Recorder {
    fn state_changed(&self, state: ShellState) {
        self.0.lock().unwrap().push(state);
    }
}

impl Recorder {
    fn states(&self) -> Vec<ShellState> {
        self.0.lock().unwrap().clone()
    }
}

fn target(server_url: &str) -> ShellTarget {
    ShellTarget {
        server_url: server_url.into(),
        access_token: "synthetic-token".into(),
        org_id: "org".into(),
        environment_id: "env".into(),
        term: "xterm-256color".into(),
        columns: 80,
        rows: 24,
    }
}

fn terminal(
    observer: Arc<Recorder>,
) -> (
    ChannelTerminal,
    mpsc::UnboundedSender<Vec<u8>>,
    oneshot::Receiver<Result<(), ShellError>>,
) {
    let (keys, key_receiver) = mpsc::unbounded_channel();
    let (_, sizes) = watch::channel((80, 24));
    let (output, _) = mpsc::channel(1);
    let (attached, first_attachment) = oneshot::channel();
    let terminal = ChannelTerminal {
        keys: Arc::new(tokio::sync::Mutex::new(key_receiver)),
        sizes,
        output,
        connected: Arc::new(AtomicBool::new(false)),
        observer,
        attached: Some(attached),
    };
    (terminal, keys, first_attachment)
}

#[test]
fn the_server_s_answers_keep_their_meaning() {
    let mapped = |code| ShellError::from(ClientError::new(code, "synthetic"));
    let message = || "synthetic".to_owned();
    assert_eq!(
        mapped(ErrorCode::Unauthenticated),
        ShellError::Unauthenticated { message: message() }
    );
    assert_eq!(
        mapped(ErrorCode::PermissionDenied),
        ShellError::PermissionDenied { message: message() }
    );
    assert_eq!(
        mapped(ErrorCode::NotFound),
        ShellError::NotFound { message: message() }
    );
    assert_eq!(
        mapped(ErrorCode::InvalidArgument),
        ShellError::Invalid { message: message() }
    );
    for code in [
        ErrorCode::Unavailable,
        ErrorCode::DeadlineExceeded,
        ErrorCode::Internal,
    ] {
        assert_eq!(mapped(code), ShellError::Unavailable { message: message() });
    }
    let ended = ShellError::from(HostedShellError::Other(anyhow::anyhow!(
        "the shell ended: gone"
    )));
    assert_eq!(
        ended,
        ShellError::Ended {
            message: "the shell ended: gone".into()
        }
    );
}

#[test]
fn each_path_is_reported_with_why_it_is_not_direct() {
    let tailnet = |path, reason: Option<&str>| {
        connected_state(Via::Tailnet(Some(TailnetPathReport {
            path,
            reason: reason.map(String::from),
        })))
    };
    assert_eq!(
        tailnet(TailnetPath::DirectUdp, None),
        ShellState::Connected {
            path: ShellPath::DirectUdp,
            reason: None
        }
    );
    assert_eq!(
        tailnet(TailnetPath::PeerRelay, Some("UDP blocked")),
        ShellState::Connected {
            path: ShellPath::Relay,
            reason: Some("UDP blocked".into())
        }
    );
    assert_eq!(
        tailnet(TailnetPath::Derp, Some("no relay")),
        ShellState::Connected {
            path: ShellPath::Derp,
            reason: Some("no relay".into())
        }
    );
    assert_eq!(
        connected_state(Via::Tailnet(None)),
        ShellState::Connected {
            path: ShellPath::Tailnet,
            reason: None
        }
    );
    assert_eq!(
        connected_state(Via::Api {
            tailnet_unavailable: "coordinator unreachable".into()
        }),
        ShellState::Connected {
            path: ShellPath::Api,
            reason: Some("coordinator unreachable".into())
        }
    );
}

#[tokio::test]
async fn the_first_attachment_answers_dial_and_a_reattachment_drops_the_keys_of_the_cut() {
    let observer = Arc::new(Recorder::default());
    let (mut terminal, keys, first_attachment) = terminal(observer.clone());

    terminal.notice(ShellNotice::Attached(Via::Tailnet(None)));
    assert_eq!(first_attachment.await.unwrap(), Ok(()));
    assert!(terminal.connected.load(Ordering::Acquire));

    terminal.notice(ShellNotice::Reconnecting);
    assert!(!terminal.connected.load(Ordering::Acquire));
    keys.send(b"typed during the cut".to_vec()).unwrap();
    terminal.notice(ShellNotice::Attached(Via::Tailnet(None)));
    keys.send(b"typed after".to_vec()).unwrap();

    let mut attached = terminal.attach().await.unwrap();
    assert_eq!(attached.keys.read().await, Some(b"typed after".to_vec()));
    assert_eq!(
        observer.states(),
        [
            ShellState::Connected {
                path: ShellPath::Tailnet,
                reason: None
            },
            ShellState::Reconnecting {
                reason: "the connection dropped".into()
            },
            ShellState::Connected {
                path: ShellPath::Tailnet,
                reason: None
            },
        ]
    );
}

#[tokio::test]
async fn sizes_start_at_the_target_and_follow_the_app() {
    let (sender, receiver) = watch::channel((80, 24));
    let mut sizes = SizeWatch(receiver);
    assert_eq!(sizes.current(), Some((80, 24)));
    sender.send((120, 40)).unwrap();
    assert_eq!(sizes.changed().await, Some((120, 40)));
    drop(sender);
    let gone = tokio::time::timeout(Duration::from_millis(50), sizes.changed()).await;
    assert!(
        gone.is_err(),
        "a released size watch waits instead of spinning"
    );
}

#[tokio::test]
async fn output_reaches_the_app_in_order() {
    let (sender, mut receiver) = mpsc::channel(4);
    let mut output = OutputSender(sender);
    output.write(b"one").await.unwrap();
    output.write(b"two").await.unwrap();
    assert_eq!(receiver.recv().await, Some(b"one".to_vec()));
    assert_eq!(receiver.recv().await, Some(b"two".to_vec()));
    drop(receiver);
    assert_eq!(
        output.write(b"three").await.unwrap_err().kind(),
        std::io::ErrorKind::BrokenPipe
    );
}

#[tokio::test]
async fn an_incomplete_target_is_refused_before_any_network() {
    let observer = Arc::new(Recorder::default());
    let mut incomplete = target("https://codewire.invalid");
    incomplete.environment_id = " ".into();
    let refused = Shell::dial(incomplete, observer.clone()).await.err();
    assert_eq!(
        refused,
        Some(ShellError::Invalid {
            message: "the environment is empty".into()
        })
    );
    assert!(observer.states().is_empty());
}

#[tokio::test]
async fn a_server_that_cannot_be_reached_fails_dial_and_ends_the_shell() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let closed = listener.local_addr().unwrap();
    drop(listener);
    let observer = Arc::new(Recorder::default());
    let refused = tokio::time::timeout(
        Duration::from_secs(30),
        Shell::dial(target(&format!("http://{closed}")), observer.clone()),
    )
    .await
    .expect("dial answers")
    .err();
    assert!(
        matches!(refused, Some(ShellError::Unavailable { .. })),
        "{refused:?}"
    );
    let states = observer.states();
    assert_eq!(states.first(), Some(&ShellState::Connecting));
    assert!(
        matches!(
            states.last(),
            Some(ShellState::Ended {
                exit_status: None,
                error: Some(_)
            })
        ),
        "{states:?}"
    );
}
