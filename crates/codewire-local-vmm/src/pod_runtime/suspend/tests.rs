use std::sync::Mutex;

use super::*;

/// Every await in these tests is bounded by this.
const BOUND: Duration = Duration::from_secs(5);

/// A VM that records what was asked of it, in order.
#[derive(Clone, Default)]
struct FakeVm {
    calls: Arc<Mutex<Vec<String>>>,
    fail_freeze: bool,
}

impl FakeVm {
    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }

    fn note(&self, call: String) {
        self.calls.lock().unwrap().push(call);
    }
}

impl PausableVm for FakeVm {
    async fn freeze_and_pause(&self, _: Uuid) -> Result<(), PodRuntimeError> {
        if self.fail_freeze {
            return Err(PodRuntimeError::GuestFailed("the freeze failed".to_owned()));
        }
        self.note("pause".to_owned());
        Ok(())
    }

    async fn resume(&self) -> Result<(), PodRuntimeError> {
        self.note("resume".to_owned());
        Ok(())
    }

    async fn thaw(&self, _: Uuid) -> Result<(), PodRuntimeError> {
        self.note("thaw".to_owned());
        Ok(())
    }

    async fn deliver_tokens(&self, tokens: &HostedTokens) -> Result<(), PodRuntimeError> {
        self.note(format!("deliver {}", tokens.binding));
        Ok(())
    }
}

type Current = Arc<Mutex<HostedTokens>>;
type Records = Arc<Mutex<Vec<Record>>>;

/// A fresh fake VM, kubelet tokens reading "first", and no records.
fn parts() -> (FakeVm, Current, Records) {
    (
        FakeVm::default(),
        Arc::new(Mutex::new(tokens("first"))),
        Arc::default(),
    )
}

fn tokens(binding: &str) -> HostedTokens {
    HostedTokens {
        binding: binding.to_owned(),
        credential: None,
        egress: None,
    }
}

/// A suspender over `vm` whose kubelet tokens read as `current`, and whose
/// records land in `records`.
fn suspender(vm: &FakeVm, current: &Current, records: &Records) -> Suspender<FakeVm> {
    let current = Arc::clone(current);
    let records = Arc::clone(records);
    Suspender::new(
        vm.clone(),
        7,
        tokens("first"),
        Box::new(move || Ok(current.lock().unwrap().clone())),
        Box::new(move |record| records.lock().unwrap().push(*record)),
    )
}

/// Sends `request` as the guest would and returns the host's answer.
async fn ask(suspender: &Suspender<FakeVm>, request: &[u8]) -> Vec<u8> {
    let (mut guest, host) = tokio::io::duplex(64);
    guest.write_all(request).await.unwrap();
    let answered = tokio::time::timeout(BOUND, answer(host, suspender));
    let (result, reply) = tokio::join!(answered, async {
        let mut reply = Vec::new();
        let _ = tokio::time::timeout(BOUND, guest.read_to_end(&mut reply)).await;
        reply
    });
    result.expect("the answer hung").unwrap();
    reply
}

fn events(records: &Records) -> Vec<(PauseEvent, u64, u64)> {
    records
        .lock()
        .unwrap()
        .iter()
        .filter_map(|record| match record {
            Record::Pause(record) => Some((record.event, record.generation, record.sequence)),
            Record::State(_) => None,
        })
        .collect()
}

/// The state records written, as (sequence, paused).
fn states(records: &Records) -> Vec<(u64, bool)> {
    records
        .lock()
        .unwrap()
        .iter()
        .filter_map(|record| match record {
            Record::State(state) => Some((state.sequence, state.paused)),
            Record::Pause(_) => None,
        })
        .collect()
}

#[tokio::test]
async fn a_guests_request_is_answered_then_the_vm_freezes_and_pauses() {
    let (vm, current, records) = parts();
    let suspender = suspender(&vm, &current, &records);
    assert_eq!(ask(&suspender, HOSTED_SUSPEND_REQUEST).await, b"ok\n");
    assert_eq!(vm.calls(), ["pause"]);
    assert!(suspender.is_paused().await);
    assert_eq!(events(&records), [(PauseEvent::Paused, 7, 1)]);
}

#[tokio::test]
async fn a_request_while_paused_is_refused_and_nothing_the_guest_sends_resumes() {
    let (vm, current, records) = parts();
    let suspender = suspender(&vm, &current, &records);
    assert_eq!(ask(&suspender, HOSTED_SUSPEND_REQUEST).await, b"ok\n");
    assert_eq!(ask(&suspender, HOSTED_SUSPEND_REQUEST).await, b"no\n");
    // Anything else on the guest's port is closed unanswered and does nothing.
    for other in [&b"resume\n\n"[..], b"suspend", b"SUSPEND\n", b""] {
        assert_eq!(ask(&suspender, other).await, b"");
    }
    assert_eq!(vm.calls(), ["pause"]);
    assert!(suspender.is_paused().await);
    assert_eq!(events(&records), [(PauseEvent::Paused, 7, 1)]);
}

#[tokio::test]
async fn a_freeze_that_fails_leaves_the_vm_running_and_records_nothing() {
    let vm = FakeVm {
        fail_freeze: true,
        ..FakeVm::default()
    };
    let (_, current, records) = parts();
    let suspender = suspender(&vm, &current, &records);
    let (_guest, host) = tokio::io::duplex(64);
    let paused = tokio::time::timeout(BOUND, suspender.suspend(|_| async {}))
        .await
        .unwrap();
    assert!(paused.is_err());
    drop(host);
    assert!(!suspender.is_paused().await);
    assert!(events(&records).is_empty());
}

/// Renewals while paused are held; a wake resumes the vCPUs, delivers them
/// while the workload is still frozen, then thaws it.
#[tokio::test]
async fn a_wake_delivers_tokens_renewed_while_paused_before_the_thaw() {
    let (vm, current, records) = parts();
    let suspender = suspender(&vm, &current, &records);
    assert_eq!(ask(&suspender, HOSTED_SUSPEND_REQUEST).await, b"ok\n");
    *current.lock().unwrap() = tokens("renewed");
    tokio::time::timeout(BOUND, suspender.refresh())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(vm.calls(), ["pause"], "a renewal reached a paused guest");
    let woke = tokio::time::timeout(BOUND, suspender.wake())
        .await
        .unwrap()
        .unwrap();
    assert!(woke);
    assert_eq!(vm.calls(), ["pause", "resume", "deliver renewed", "thaw"]);
    assert_eq!(
        events(&records),
        [(PauseEvent::Paused, 7, 1), (PauseEvent::Resumed, 7, 2)]
    );
    // Delivered once: the next tick finds nothing new.
    tokio::time::timeout(BOUND, suspender.refresh())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(vm.calls().len(), 4);
}

#[tokio::test]
async fn a_wake_of_a_running_vm_does_nothing_and_a_running_vm_gets_renewals_at_once() {
    let (vm, current, records) = parts();
    let suspender = suspender(&vm, &current, &records);
    let woke = tokio::time::timeout(BOUND, suspender.wake())
        .await
        .unwrap()
        .unwrap();
    assert!(!woke);
    *current.lock().unwrap() = tokens("renewed");
    tokio::time::timeout(BOUND, suspender.refresh())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(vm.calls(), ["deliver renewed"]);
    assert!(events(&records).is_empty());
}

/// A stop of a paused VM (SIGTERM, or idle stop) wakes it first, so the
/// guest shuts down cleanly; the stop runs after the thaw.
#[tokio::test]
async fn a_stop_wakes_a_paused_vm_before_it_stops() {
    let (vm, current, records) = parts();
    let suspender = suspender(&vm, &current, &records);
    assert_eq!(ask(&suspender, HOSTED_SUSPEND_REQUEST).await, b"ok\n");
    let stopped = tokio::time::timeout(
        BOUND,
        stop_awake(&suspender, async {
            vm.note("stop".to_owned());
            "stopped"
        }),
    )
    .await
    .unwrap();
    assert_eq!(stopped, "stopped");
    assert_eq!(vm.calls(), ["pause", "resume", "thaw", "stop"]);
    assert_eq!(
        events(&records),
        [(PauseEvent::Paused, 7, 1), (PauseEvent::Resumed, 7, 2)]
    );
}

/// A pause and a wake never interleave: a wake that arrives while a request
/// is being answered waits for the pause, then resumes.
#[tokio::test]
async fn a_wake_during_a_pause_waits_for_it_then_resumes() {
    let (vm, current, records) = parts();
    let suspender = Arc::new(suspender(&vm, &current, &records));
    let (answering, answered) = tokio::sync::oneshot::channel();
    let (release, released) = tokio::sync::oneshot::channel::<()>();
    let pausing = {
        let suspender = Arc::clone(&suspender);
        tokio::spawn(async move {
            suspender
                .suspend(|_| async move {
                    answering.send(()).unwrap();
                    released.await.unwrap();
                })
                .await
        })
    };
    tokio::time::timeout(BOUND, answered)
        .await
        .unwrap()
        .unwrap();
    let waking = {
        let suspender = Arc::clone(&suspender);
        tokio::spawn(async move { suspender.wake().await })
    };
    release.send(()).unwrap();
    assert!(
        tokio::time::timeout(BOUND, pausing)
            .await
            .unwrap()
            .unwrap()
            .unwrap()
    );
    assert!(
        tokio::time::timeout(BOUND, waking)
            .await
            .unwrap()
            .unwrap()
            .unwrap()
    );
    assert_eq!(vm.calls(), ["pause", "resume", "thaw"]);
}

#[test]
fn a_record_is_one_marked_line_no_guest_line_can_start_with() {
    let record = PauseRecord {
        event: PauseEvent::Resumed,
        generation: 3,
        sequence: 2,
        at_unix_ms: 1_764_000_000_000,
    };
    assert_eq!(
        record.line(),
        "standard runtime: vm-pause-record {\"event\":\"resumed\",\"generation\":3,\"sequence\":2,\"at_unix_ms\":1764000000000}"
    );
    // Every line of guest output starts with the guest log's prefix.
    assert!(!RECORD_MARKER.starts_with(super::super::guest_log::PREFIX));
    assert!(!record.line().contains('\n'));

    let state = StateRecord {
        generation: 3,
        sequence: 2,
        paused: false,
        since_unix_ms: 1_764_000_000_000,
    };
    assert_eq!(
        Record::State(state).line(),
        "standard runtime: vm-pause-state {\"generation\":3,\"sequence\":2,\"state\":\"running\",\"since_unix_ms\":1764000000000}"
    );
    let paused = StateRecord {
        paused: true,
        ..state
    };
    assert!(paused.line().contains("\"state\":\"paused\""));
    assert!(!STATE_MARKER.starts_with(super::super::guest_log::PREFIX));
    assert!(!paused.line().contains('\n'));
}

#[tokio::test(start_paused = true)]
async fn the_state_is_written_at_each_pause_and_resume_and_every_interval_paused_or_not() {
    let (vm, current, records) = parts();
    let suspender = suspender(&vm, &current, &records);
    // The first tick writes the boot's state: no record yet, running.
    suspender.write_state_when_due().await;
    suspender.write_state_when_due().await;
    assert_eq!(states(&records), [(0, false)]);
    let Some(Record::State(first)) = records.lock().unwrap().first().copied() else {
        panic!("no state record");
    };
    assert_eq!((first.generation, first.sequence), (7, 0));

    tokio::time::advance(STATE_RECORD_INTERVAL).await;
    suspender.write_state_when_due().await;
    assert_eq!(states(&records), [(0, false), (0, false)]);

    // A pause writes its record, then the state it leaves.
    assert_eq!(ask(&suspender, HOSTED_SUSPEND_REQUEST).await, b"ok\n");
    let pause = records.lock().unwrap()[2..].to_vec();
    let [Record::Pause(paused), Record::State(state)] = &pause[..] else {
        panic!("a pause writes its record then the state: {pause:?}");
    };
    assert_eq!((state.sequence, state.paused), (1, true));
    assert_eq!(state.since_unix_ms, paused.at_unix_ms);

    // Paused, the state is still written every interval, and only then.
    tokio::time::advance(STATE_RECORD_INTERVAL - Duration::from_millis(1)).await;
    suspender.write_state_when_due().await;
    assert_eq!(states(&records).len(), 3);
    tokio::time::advance(Duration::from_millis(1)).await;
    suspender.write_state_when_due().await;
    assert_eq!(
        states(&records),
        [(0, false), (0, false), (1, true), (1, true)]
    );

    assert!(suspender.wake().await.unwrap());
    assert_eq!(
        states(&records),
        [(0, false), (0, false), (1, true), (1, true), (2, false)]
    );
    assert_eq!(
        events(&records),
        [(PauseEvent::Paused, 7, 1), (PauseEvent::Resumed, 7, 2)]
    );
}

#[tokio::test]
async fn requests_are_answered_at_most_once_a_second() {
    let directory = tempfile::tempdir().unwrap();
    let vsock_socket = directory.path().join("vsock");
    let (vm, current, records) = parts();
    let suspender = Arc::new(suspender(&vm, &current, &records));
    let listening = listen(&vsock_socket, Arc::clone(&suspender)).unwrap();
    let path = super::super::guest_log::host_socket(&vsock_socket, HOSTED_SUSPEND_VSOCK_PORT);

    let mut answered = Vec::new();
    for _ in 0..3 {
        let asked = async {
            let mut stream = tokio::net::UnixStream::connect(&path).await.unwrap();
            stream.write_all(HOSTED_SUSPEND_REQUEST).await.unwrap();
            let mut reply = Vec::new();
            stream.read_to_end(&mut reply).await.unwrap();
            reply
        };
        let reply = tokio::time::timeout(BOUND, asked)
            .await
            .expect("the request hung");
        answered.push((reply, std::time::Instant::now()));
    }
    listening.abort();

    let replies: Vec<&[u8]> = answered.iter().map(|(reply, _)| &reply[..]).collect();
    assert_eq!(replies, [&b"ok\n"[..], b"no\n", b"no\n"]);
    // Measured at the guest's end, so allow for scheduling; unpaced, the
    // three answers come within milliseconds.
    for pair in answered.windows(2) {
        let gap = pair[1].1 - pair[0].1;
        assert!(
            gap >= ANSWER_INTERVAL - Duration::from_millis(100),
            "answered {gap:?} after the last"
        );
    }
    assert_eq!(vm.calls(), ["pause"]);
}

/// The guest's end of the VM's hybrid vsock socket: answers each CONNECT,
/// notes the join in `vm`'s calls, then echoes.
async fn fake_guest_ingress(listener: tokio::net::UnixListener, vm: FakeVm) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        let vm = vm.clone();
        tokio::spawn(async move {
            let mut line = Vec::new();
            loop {
                let mut byte = [0_u8; 1];
                if stream.read_exact(&mut byte).await.is_err() {
                    return;
                }
                if byte[0] == b'\n' {
                    break;
                }
                line.push(byte[0]);
            }
            vm.note(format!("join {}", String::from_utf8_lossy(&line)));
            stream.write_all(b"OK 1\n").await.unwrap();
            let (mut read, mut write) = stream.split();
            let _ = tokio::io::copy(&mut read, &mut write).await;
        });
    }
}

/// A connection on either published port wakes a paused VM, and reaches the
/// guest only after the thaw; its bytes then flow both ways.
#[tokio::test]
async fn a_connection_on_a_published_port_wakes_the_vm_before_it_reaches_the_guest() {
    for (_, ingress) in super::super::hosted::PUBLISHED_PORTS {
        let (vm, current, records) = parts();
        let suspender = Arc::new(suspender(&vm, &current, &records));
        assert_eq!(ask(&suspender, HOSTED_SUSPEND_REQUEST).await, b"ok\n");

        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("vsock.sock");
        let ingress_listener = tokio::net::UnixListener::bind(&socket).unwrap();
        // The runner admits only a socket of its own user's, mode 0600.
        std::fs::set_permissions(&socket, std::os::unix::fs::PermissionsExt::from_mode(0o600))
            .unwrap();
        let guest = tokio::spawn(fake_guest_ingress(ingress_listener, vm.clone()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let serving = tokio::spawn(super::super::hosted::serve_published(
            listener,
            socket,
            ingress,
            Arc::clone(&suspender),
        ));

        let mut client = tokio::time::timeout(BOUND, tokio::net::TcpStream::connect(address))
            .await
            .unwrap()
            .unwrap();
        client.write_all(b"ping").await.unwrap();
        let mut echoed = [0_u8; 4];
        tokio::time::timeout(BOUND, client.read_exact(&mut echoed))
            .await
            .expect("the connection never reached the guest")
            .unwrap();
        assert_eq!(&echoed, b"ping");
        assert_eq!(
            vm.calls(),
            [
                "pause".to_owned(),
                "resume".to_owned(),
                "thaw".to_owned(),
                format!("join CONNECT {ingress}")
            ]
        );
        assert!(!suspender.is_paused().await);
        serving.abort();
        guest.abort();
    }
}
