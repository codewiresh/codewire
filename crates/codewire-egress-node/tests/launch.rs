//! The launcher against real processes.
//!
//! The launcher starts children only from its own image, so this test is its
//! own image: it has no test harness, and its `main` dispatches the child
//! command words exactly as `cw-egress`'s does before it runs any test. The
//! test plays the guest's end of the stream.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used)]

use std::future::Future;
use std::pin::Pin;
use std::process::ExitCode;
use std::time::Duration;

use codewire_confinement::spawn::OwnImage;
use codewire_egress_node::children::run_child;
use codewire_egress_node::launch::{ProcessLaunch, ProcessPair, StartError};
use codewire_egress_node::supervisor::{
    Launch as _, Pair as _, PairSpec, PairStatus, SelfCheckProbe,
};
use codewire_egress_policy::host_addresses::HostAddressSet;
use codewire_egress_policy::{BuiltinPolicy, CompiledPolicy};
use codewire_egress_worker::hosted::HOSTED_GENERATION;
use codewire_network_session::guest::{GuestSession, authenticate_guest};
use codewire_network_session::{NetworkKey, SelfCheck, SelfCheckFailure};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

const POD: Uuid = Uuid::from_u128(0x0b8f_6a52_0f6c_4a59_9f43_1b1f_0c3a_9e01);
const KEY: [u8; 32] = [7; 32];
/// Longer than any step here takes, so a missing answer fails, not hangs.
const PATIENCE: Duration = Duration::from_secs(30);

type Test = fn() -> Pin<Box<dyn Future<Output = ()> + Send>>;

/// Each test counts this process's children, so they run one at a time.
const TESTS: &[(&str, Test)] = &[
    (
        "a_pair_is_two_children_of_the_image_that_take_a_new_policy_and_end_together",
        || Box::pin(a_pair_is_two_children_of_the_image_that_take_a_new_policy_and_end_together()),
    ),
    (
        "a_failed_self_check_is_reported_before_the_pairs_end",
        || Box::pin(a_failed_self_check_is_reported_before_the_pairs_end()),
    ),
    ("a_drained_pair_with_no_flow_says_so_before_it_ends", || {
        Box::pin(a_drained_pair_with_no_flow_says_so_before_it_ends())
    }),
    ("a_guest_that_drops_its_stream_ends_the_pair", || {
        Box::pin(a_guest_that_drops_its_stream_ends_the_pair())
    }),
    ("a_broker_that_dies_ends_the_pair", || {
        Box::pin(a_broker_that_dies_ends_the_pair())
    }),
    (
        "a_guest_with_another_key_gets_no_pair_and_leaves_no_process",
        || Box::pin(a_guest_with_another_key_gets_no_pair_and_leaves_no_process()),
    ),
    ("a_dropped_pair_leaves_no_process", || {
        Box::pin(a_dropped_pair_leaves_no_process())
    }),
    ("children_outlive_the_thread_that_asked_for_them", || {
        Box::pin(children_outlive_the_thread_that_asked_for_them())
    }),
];

fn main() -> ExitCode {
    // First, and before any other thread exists: a child confines itself
    // only while it is single-threaded.
    if let Some(status) = run_child(std::env::args_os()) {
        return status;
    }
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let flag = |name: &str| arguments.iter().any(|argument| argument == name);
    // CI runs this binary under nextest, which lists a custom harness's tests
    // with `--list --format terse` (and `--ignored`; there are none) and then
    // runs each as `NAME --exact`.
    if flag("--list") {
        if !flag("--ignored") {
            for (name, _) in TESTS {
                println!("{name}: test");
            }
        }
        return ExitCode::SUCCESS;
    }
    let exact = flag("--exact");
    let filter = arguments
        .iter()
        .find(|argument| !argument.starts_with('-'))
        .cloned();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let mut failed = 0_usize;
    let mut ran = 0_usize;
    for (name, test) in TESTS {
        if filter.as_ref().is_some_and(|filter| {
            if exact {
                *name != filter.as_str()
            } else {
                !name.contains(filter.as_str())
            }
        }) {
            continue;
        }
        ran += 1;
        // A task, so that a panic fails this test and the rest still run.
        let outcome = runtime.block_on(async { tokio::spawn(test()).await });
        if outcome.is_ok() {
            println!("test {name} ... ok");
        } else {
            println!("test {name} ... FAILED");
            failed += 1;
        }
    }
    let verdict = if failed == 0 { "ok" } else { "FAILED" };
    println!(
        "\ntest result: {verdict}. {} passed; {failed} failed; 0 ignored; 0 measured; {} filtered out",
        ran - failed,
        TESTS.len() - ran
    );
    if failed == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn launch() -> ProcessLaunch {
    ProcessLaunch::new(OwnImage::open().unwrap(), HostAddressSet::default()).unwrap()
}

fn key() -> NetworkKey {
    NetworkKey::from_derived_bytes(KEY).unwrap()
}

/// A connected TCP pair on loopback: the guest's end and the accepted one.
async fn stream() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let guest = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (accepted, _) = listener.accept().await.unwrap();
    (guest, accepted)
}

/// Starts a pair for `POD` under `policy` from `launch`, with the guest's
/// handshake played alongside as `guest_key` has it.
async fn start_from(
    launch: &ProcessLaunch,
    policy: CompiledPolicy,
    guest_key: NetworkKey,
) -> (
    Result<ProcessPair, StartError>,
    Option<GuestSession<TcpStream>>,
) {
    let (guest, accepted) = stream().await;
    let guest = tokio::spawn(async move {
        authenticate_guest(guest, &guest_key, POD, HOSTED_GENERATION)
            .await
            .ok()
    });
    let pair = launch
        .start(PairSpec {
            pod_uid: POD,
            stream: accepted,
            key: key(),
            policy,
        })
        .await;
    let guest = tokio::time::timeout(PATIENCE, guest)
        .await
        .expect("the guest's handshake ended")
        .unwrap();
    (pair, guest)
}

async fn start(
    policy: CompiledPolicy,
    guest_key: NetworkKey,
) -> (
    Result<ProcessPair, StartError>,
    Option<GuestSession<TcpStream>>,
) {
    start_from(&launch(), policy, guest_key).await
}

async fn next(pair: &mut ProcessPair) -> PairStatus {
    tokio::time::timeout(PATIENCE, pair.status())
        .await
        .expect("the pair reported a status")
}

/// This process's children: each one's process ID, state and command line.
fn all_children() -> Vec<(i32, String, String)> {
    let me = std::process::id().to_string();
    let mut children = vec![];
    for entry in std::fs::read_dir("/proc").unwrap().flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|pid| pid.parse::<i32>().ok())
        else {
            continue;
        };
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
            continue;
        };
        // After the command's closing parenthesis: a space, the state, then
        // the parent.
        let mut fields = stat
            .rsplit_once(')')
            .map_or("", |(_, rest)| rest)
            .split(' ');
        let (state, parent) = (fields.nth(1), fields.next());
        if parent == Some(me.as_str()) {
            let command = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
            children.push((
                pid,
                state.unwrap_or_default().to_owned(),
                String::from_utf8_lossy(&command).replace('\0', " "),
            ));
        }
    }
    children.sort_by(|left, right| left.2.cmp(&right.2));
    children
}

/// This process's live children: each one's process ID and command line.
fn children() -> Vec<(i32, String)> {
    all_children()
        .into_iter()
        .filter(|(_, state, _)| state != "Z")
        .map(|(pid, _, command)| (pid, command))
        .collect()
}

/// Waits for this process to have no child at all, reaped ones included.
async fn no_child_is_left() {
    let gone = async {
        while !all_children().is_empty() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    };
    tokio::time::timeout(PATIENCE, gone)
        .await
        .unwrap_or_else(|_| panic!("children are left: {:?}", all_children()));
}

async fn send_self_check(guest: &mut GuestSession<TcpStream>, result: SelfCheck) {
    let frame = guest.session.encode_self_check(result).unwrap();
    guest.stream.write_all(&frame).await.unwrap();
}

/// Waits for the guest to see its stream end.
async fn stream_ends(guest: &mut GuestSession<TcpStream>) {
    let mut rest = [0_u8; 64];
    let ended = async {
        loop {
            match guest.stream.read(&mut rest).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    };
    tokio::time::timeout(PATIENCE, ended)
        .await
        .expect("the guest's stream ended");
}

async fn a_pair_is_two_children_of_the_image_that_take_a_new_policy_and_end_together() {
    let (pair, guest) = start(BuiltinPolicy::Open.compile(), key()).await;
    let mut pair = pair.unwrap();
    let mut guest = guest.expect("the guest authenticated the session");

    let commands: Vec<String> = children().into_iter().map(|(_, command)| command).collect();
    assert_eq!(
        commands,
        [
            format!("cw-egress __egress-broker --pod-uid {POD} "),
            format!("cw-egress __egress-worker --pod-uid {POD} "),
        ]
    );

    send_self_check(&mut guest, SelfCheck::Passed).await;
    assert_eq!(next(&mut pair).await, PairStatus::SelfCheckPassed);

    let before = children();
    let locked = BuiltinPolicy::Locked.compile();
    assert_eq!(pair.replace(&locked).await, Ok(locked.digest()));
    assert_eq!(children(), before, "the same two processes");

    pair.end().await;
    // Ended means reaped: nothing is left the moment it returns.
    assert_eq!(all_children(), []);
    // Nothing holds the guest's stream open once the pair is gone, so the
    // guest sees it end and redials.
    stream_ends(&mut guest).await;
}

async fn a_failed_self_check_is_reported_before_the_pairs_end() {
    let (pair, guest) = start(BuiltinPolicy::Open.compile(), key()).await;
    let mut pair = pair.unwrap();
    let mut guest = guest.unwrap();

    // The worker writes the failure and exits at once: the line still comes
    // first, and the end after it.
    send_self_check(&mut guest, SelfCheck::Failed(SelfCheckFailure::Dns)).await;
    assert_eq!(
        next(&mut pair).await,
        PairStatus::SelfCheckFailed(SelfCheckProbe::Dns)
    );
    assert_eq!(next(&mut pair).await, PairStatus::Ended);

    pair.end().await;
    no_child_is_left().await;
}

async fn a_drained_pair_with_no_flow_says_so_before_it_ends() {
    let (pair, guest) = start(BuiltinPolicy::Open.compile(), key()).await;
    let mut pair = pair.unwrap();
    let mut guest = guest.unwrap();
    send_self_check(&mut guest, SelfCheck::Passed).await;
    assert_eq!(next(&mut pair).await, PairStatus::SelfCheckPassed);

    // The guest has nothing open. The worker says so and ends its session at
    // once; the answer still comes first, and the end after it.
    pair.request_drain().await.unwrap();
    assert_eq!(next(&mut pair).await, PairStatus::NoFlow);
    assert_eq!(next(&mut pair).await, PairStatus::Ended);
    stream_ends(&mut guest).await;

    pair.end().await;
    no_child_is_left().await;
}

async fn a_guest_that_drops_its_stream_ends_the_pair() {
    let (pair, guest) = start(BuiltinPolicy::Open.compile(), key()).await;
    let mut pair = pair.unwrap();

    drop(guest);
    assert_eq!(next(&mut pair).await, PairStatus::Ended);

    pair.end().await;
    no_child_is_left().await;
}

async fn a_broker_that_dies_ends_the_pair() {
    let (pair, guest) = start(BuiltinPolicy::Open.compile(), key()).await;
    let mut pair = pair.unwrap();
    let mut guest = guest.unwrap();
    send_self_check(&mut guest, SelfCheck::Passed).await;
    assert_eq!(next(&mut pair).await, PairStatus::SelfCheckPassed);

    let (broker, _) = children()
        .into_iter()
        .find(|(_, command)| command.contains("__egress-broker"))
        .expect("the broker is running");
    rustix::process::kill_process(
        rustix::process::Pid::from_raw(broker).unwrap(),
        rustix::process::Signal::KILL,
    )
    .unwrap();
    assert_eq!(next(&mut pair).await, PairStatus::Ended);

    pair.end().await;
    no_child_is_left().await;
}

async fn a_guest_with_another_key_gets_no_pair_and_leaves_no_process() {
    let another = NetworkKey::from_derived_bytes([8; 32]).unwrap();
    let (pair, guest) = start(BuiltinPolicy::Open.compile(), another).await;

    assert!(guest.is_none(), "the guest cannot authenticate the host");
    assert!(pair.is_err());
    no_child_is_left().await;
}

async fn a_dropped_pair_leaves_no_process() {
    let (pair, _guest) = start(BuiltinPolicy::Open.compile(), key()).await;
    drop(pair.unwrap());
    no_child_is_left().await;
}

/// A child is killed when the thread that forked it exits. A pair asked for
/// from a thread that then exits, runtime and all, must carry on.
async fn children_outlive_the_thread_that_asked_for_them() {
    let launch = std::sync::Arc::new(launch());
    let asking = std::sync::Arc::clone(&launch);
    let short_lived = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(start_from(&asking, BuiltinPolicy::Open.compile(), key()))
    });
    let (pair, guest) = tokio::task::spawn_blocking(move || short_lived.join().unwrap())
        .await
        .unwrap();
    let pair = pair.unwrap();
    assert!(guest.is_some());

    // The thread that asked is gone, and both children are still running.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(children().len(), 2, "{:?}", all_children());

    drop(pair);
    no_child_is_left().await;
}
