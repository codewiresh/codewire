//! The files loop on a temporary directory, from a scripted token source,
//! on tokio's paused clock: the Unix seconds the cache reads follow it, so a
//! token's lifetime passes as the test sleeps.

use std::cell::Cell;
use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use zeroize::Zeroizing;

use super::directory::MemoryCheck;
use super::renewal::run;
use crate::access::{AccessFields, IdentityFileFields, WorkspaceAccessGrant};
use crate::identity_socket::{
    IdentityRefusal, IdentityTokenSource, IdentityTokens, IssuedIdentityToken,
};
use crate::private_files::PrivateDirectory;

const K8S: &str = "https://k8s.walk.example";
const VAULT: &str = "https://vault.walk.example";
/// Unix seconds when a test starts.
const BASE: i64 = 1_900_000_000;
/// The bound on anything a test waits for outside the paused clock.
const STEP: Duration = Duration::from_secs(10);

thread_local! {
    /// When this test's clock started. Each tokio test runs on its own
    /// thread, and every task of its runtime on that thread.
    static EPOCH: Cell<Option<Instant>> = const { Cell::new(None) };
}

fn fake_now() -> i64 {
    let epoch = EPOCH.get().expect("the test clock is started");
    BASE + i64::try_from(epoch.elapsed().as_secs()).unwrap()
}

#[derive(Clone, Copy, Debug)]
enum Answer {
    /// A token living this many seconds.
    Lifetime(i64),
    Refuse(IdentityRefusal),
    /// No answer at all: the call times out.
    Hang,
}

#[derive(Default)]
struct Script {
    answers: HashMap<String, Answer>,
    calls: Vec<(String, Instant)>,
    issued: Vec<String>,
}

#[derive(Clone, Default)]
struct Source(Arc<Mutex<Script>>);

impl Source {
    fn answer(&self, audience: &str, answer: Answer) {
        self.0
            .lock()
            .unwrap()
            .answers
            .insert(audience.to_owned(), answer);
    }

    fn calls(&self) -> Vec<(String, Instant)> {
        self.0.lock().unwrap().calls.clone()
    }

    fn calls_for(&self, audience: &str) -> usize {
        self.calls()
            .iter()
            .filter(|(called, _)| called == audience)
            .count()
    }

    fn issued(&self) -> Vec<String> {
        self.0.lock().unwrap().issued.clone()
    }
}

impl IdentityTokenSource for Source {
    async fn issue(&self, resource: &str) -> Result<IssuedIdentityToken, IdentityRefusal> {
        let answer = {
            let mut script = self.0.lock().unwrap();
            script.calls.push((resource.to_owned(), Instant::now()));
            script
                .answers
                .get(resource)
                .copied()
                .unwrap_or(Answer::Lifetime(600))
        };
        match answer {
            Answer::Lifetime(seconds) => {
                let mut script = self.0.lock().unwrap();
                let token = format!("eyJzeW50aGV0aWM.dG9rZW4.{}", script.issued.len() + 1);
                script.issued.push(token.clone());
                Ok(IssuedIdentityToken {
                    token: Zeroizing::new(token),
                    expires_at: fake_now() + seconds,
                })
            }
            Answer::Refuse(refusal) => Err(refusal),
            Answer::Hang => std::future::pending().await,
        }
    }
}

fn grant(files: Option<&[(&str, &str)]>) -> WorkspaceAccessGrant {
    let now = SystemTime::now();
    let seconds = i64::try_from(now.duration_since(UNIX_EPOCH).unwrap().as_secs()).unwrap();
    WorkspaceAccessGrant::validate(
        &AccessFields {
            peer_token: "synthetic-peer-token",
            peer_token_expires_at: seconds + 600,
            operation_generation: 4,
            coordinator_url: "https://coordinator.codewire.test",
            direct_udp_endpoints: &[],
            peer_relay_endpoints: &[],
            app_ports: &[],
            mesh: None,
            identity_files: files.map(|files| {
                files
                    .iter()
                    .map(|(audience, file_name)| IdentityFileFields {
                        audience,
                        file_name,
                    })
                    .collect()
            }),
        },
        now,
    )
    .unwrap()
}

fn on_tmpfs(_: &PrivateDirectory) -> std::io::Result<bool> {
    Ok(true)
}

fn on_disk(_: &PrivateDirectory) -> std::io::Result<bool> {
    Ok(false)
}

struct Harness {
    root: tempfile::TempDir,
    source: Source,
    tokens: Arc<IdentityTokens<Source>>,
    grants: watch::Sender<WorkspaceAccessGrant>,
    stop: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl Harness {
    /// Start this test's clock; a directory and a source to start with.
    fn prepare() -> (tempfile::TempDir, Source) {
        EPOCH.set(Some(Instant::now()));
        (tempfile::tempdir().unwrap(), Source::default())
    }

    fn start(
        root: tempfile::TempDir,
        source: Source,
        files: Option<&[(&str, &str)]>,
        in_memory: MemoryCheck,
    ) -> Self {
        let tokens = Arc::new(IdentityTokens::with_clock(source.clone(), fake_now));
        let (grants, receiver) = watch::channel(grant(files));
        let (stop, stopped) = watch::channel(false);
        let task = tokio::spawn(run(
            root.path().join("identity"),
            in_memory,
            receiver,
            Arc::clone(&tokens),
            stopped,
        ));
        Self {
            root,
            source,
            tokens,
            grants,
            stop,
            task,
        }
    }

    fn directory(&self) -> PathBuf {
        self.root.path().join("identity")
    }

    fn read(&self, name: &str) -> Option<String> {
        std::fs::read_to_string(self.directory().join(name)).ok()
    }

    /// Every name in the directory, sorted.
    fn names(&self) -> Vec<String> {
        names_in(&self.directory())
    }

    fn send(&self, files: Option<&[(&str, &str)]>) {
        self.grants.send_replace(grant(files));
    }

    async fn stop(self) {
        self.stop.send_replace(true);
        tokio::time::timeout(STEP, self.task)
            .await
            .expect("the loop stops")
            .unwrap();
    }
}

fn names_in(directory: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(directory)
        .map(|entries| {
            entries
                .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

fn mode(path: &Path) -> u32 {
    std::fs::symlink_metadata(path)
        .unwrap()
        .permissions()
        .mode()
        & 0o777
}

/// Let the paused clock run `seconds` on.
async fn pass(seconds: f64) {
    tokio::time::sleep(Duration::from_secs_f64(seconds)).await;
}

#[tokio::test(start_paused = true)]
async fn a_file_is_minted_at_start_owner_only_and_renewed_at_half_life() {
    let (root, source) = Harness::prepare();
    // An earlier daemon's directory, too wide, with its leftovers.
    let directory = root.path().join("identity");
    std::fs::create_dir(&directory).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755)).unwrap();
    for leftover in ["old.jwt", ".old.jwt.tmp", ".k8s.jwt.tmp", "notes.txt"] {
        std::fs::write(directory.join(leftover), "stale").unwrap();
    }
    let files = Harness::start(root, source, Some(&[(K8S, "k8s")]), on_tmpfs);
    pass(0.1).await;

    assert_eq!(mode(&files.directory()), 0o700);
    assert_eq!(mode(&files.directory().join("k8s.jwt")), 0o600);
    let first = files.source.issued()[0].clone();
    assert_eq!(files.read("k8s.jwt").as_deref(), Some(first.as_str()));
    assert_eq!(files.names(), ["k8s.jwt", "notes.txt"]);

    // A 600 s token is renewed at 300 s, not before.
    pass(299.0).await;
    assert_eq!(files.read("k8s.jwt").as_deref(), Some(first.as_str()));
    assert_eq!(files.source.calls_for(K8S), 1);
    pass(1.5).await;
    assert_eq!(files.source.calls_for(K8S), 2);
    let second = files.source.issued()[1].clone();
    assert_ne!(first, second);
    assert_eq!(files.read("k8s.jwt").as_deref(), Some(second.as_str()));
    assert_eq!(mode(&files.directory().join("k8s.jwt")), 0o600);
    assert_eq!(files.names(), ["k8s.jwt", "notes.txt"]);
    files.stop().await;
}

#[tokio::test(start_paused = true)]
async fn a_removed_or_renamed_audience_loses_its_file() {
    let (root, source) = Harness::prepare();
    let files = Harness::start(
        root,
        source,
        Some(&[(K8S, "k8s"), (VAULT, "vault")]),
        on_tmpfs,
    );
    pass(1.0).await;
    assert_eq!(files.names(), ["k8s.jwt", "vault.jwt"]);
    let vault = files.read("vault.jwt").unwrap();

    // k8s is removed; vault is renamed to secrets.
    files.send(Some(&[(VAULT, "secrets")]));
    pass(1.0).await;
    assert_eq!(files.names(), ["secrets.jwt"]);
    // The renamed file holds the cached token: no second mint.
    assert_eq!(files.read("secrets.jwt"), Some(vault));
    assert_eq!(files.source.calls_for(VAULT), 1);
    // A removed audience is no longer renewed.
    pass(600.0).await;
    assert_eq!(files.source.calls_for(K8S), 1);
    files.stop().await;
}

#[tokio::test(start_paused = true)]
async fn an_absent_list_keeps_the_files_and_an_empty_one_deletes_them() {
    let (root, source) = Harness::prepare();
    let files = Harness::start(
        root,
        source,
        Some(&[(K8S, "k8s"), (VAULT, "vault")]),
        on_tmpfs,
    );
    pass(1.0).await;
    let before = (files.read("k8s.jwt"), files.read("vault.jwt"));

    files.send(None);
    pass(1.0).await;
    assert_eq!(files.names(), ["k8s.jwt", "vault.jwt"]);
    assert_eq!((files.read("k8s.jwt"), files.read("vault.jwt")), before);
    // And they are still renewed.
    pass(300.0).await;
    assert_eq!(files.source.calls_for(K8S), 2);

    files.send(Some(&[]));
    pass(1.0).await;
    assert!(files.names().is_empty(), "{:?}", files.names());
    pass(600.0).await;
    assert_eq!(files.source.calls().len(), 4);
    files.stop().await;
}

#[tokio::test(start_paused = true)]
async fn a_grant_with_no_list_writes_nothing_and_creates_no_directory() {
    let (root, source) = Harness::prepare();
    let files = Harness::start(root, source, None, on_tmpfs);
    pass(600.0).await;
    assert!(!files.directory().exists());
    assert!(files.source.calls().is_empty());
    files.stop().await;
}

#[tokio::test(start_paused = true)]
async fn a_stop_deletes_the_file_at_renewal_and_a_resume_brings_it_back_within_a_minute() {
    let (root, source) = Harness::prepare();
    let files = Harness::start(root, source, Some(&[(K8S, "k8s")]), on_tmpfs);
    pass(1.0).await;
    files
        .source
        .answer(K8S, Answer::Refuse(IdentityRefusal::IdentityStopped));
    // The token issued before the stop is served until its renewal.
    pass(298.0).await;
    assert!(files.read("k8s.jwt").is_some());
    pass(1.5).await;
    assert_eq!(files.read("k8s.jwt"), None);

    // Stopped for ten minutes, then resumed.
    pass(600.0).await;
    assert_eq!(files.read("k8s.jwt"), None);
    files.source.answer(K8S, Answer::Lifetime(600));
    pass(60.5).await;
    assert!(files.read("k8s.jwt").is_some());
    files.stop().await;
}

#[tokio::test(start_paused = true)]
async fn key_not_yet_published_and_a_refusal_added_later_delete_the_file_at_once() {
    for refusal in [
        IdentityRefusal::KeyNotYetPublished,
        IdentityRefusal::Unrecognized,
        IdentityRefusal::InvalidTarget,
        IdentityRefusal::NotRunning,
    ] {
        let (root, source) = Harness::prepare();
        let files = Harness::start(root, source, Some(&[(K8S, "k8s")]), on_tmpfs);
        pass(1.0).await;
        files.source.answer(K8S, Answer::Refuse(refusal));
        pass(298.0).await;
        assert!(files.read("k8s.jwt").is_some(), "{refusal:?}");
        pass(1.5).await;
        assert_eq!(files.read("k8s.jwt"), None, "{refusal:?}");
        files.stop().await;
    }
}

#[tokio::test(start_paused = true)]
async fn a_passing_refusal_keeps_the_file_until_ten_seconds_before_its_exp() {
    for answer in [
        Answer::Refuse(IdentityRefusal::IdentityUnavailable),
        Answer::Refuse(IdentityRefusal::ResourceExhausted),
        Answer::Hang,
    ] {
        let (root, source) = Harness::prepare();
        let files = Harness::start(root, source, Some(&[(K8S, "k8s")]), on_tmpfs);
        pass(0.1).await;
        let token = files.read("k8s.jwt").unwrap();
        files.source.answer(K8S, answer);
        // Minted at 0 and valid until 600: kept through 589, retried meanwhile.
        pass(589.0).await;
        assert_eq!(files.read("k8s.jwt").as_ref(), Some(&token), "{answer:?}");
        assert!(files.source.calls_for(K8S) > 2, "{answer:?}");
        pass(1.5).await;
        assert_eq!(files.read("k8s.jwt"), None, "{answer:?}");
        // Renewal goes on, and the next token brings the file back: within
        // a minute's backoff, after a call that may hang for 45 s.
        files.source.answer(K8S, Answer::Lifetime(600));
        pass(106.0).await;
        assert!(files.read("k8s.jwt").is_some(), "{answer:?}");
        files.stop().await;
    }
}

#[tokio::test(start_paused = true)]
async fn a_call_that_hangs_holds_up_no_deletion() {
    let (root, source) = Harness::prepare();
    // Valid until 100 and renewed at 50, by a call that times out at 95.
    source.answer(K8S, Answer::Lifetime(100));
    let files = Harness::start(root, source, Some(&[(K8S, "k8s")]), on_tmpfs);
    pass(1.0).await;
    files.source.answer(K8S, Answer::Hang);
    pass(88.0).await;
    assert!(files.read("k8s.jwt").is_some());
    assert_eq!(files.source.calls_for(K8S), 2);
    pass(2.0).await;
    assert_eq!(files.read("k8s.jwt"), None);
    assert_eq!(files.source.calls_for(K8S), 2, "the call still hangs");
    files.stop().await;
}

/// The gaps between consecutive calls for one audience.
fn gaps(source: &Source, audience: &str) -> Vec<Duration> {
    let times: Vec<Instant> = source
        .calls()
        .into_iter()
        .filter(|(called, _)| called == audience)
        .map(|(_, at)| at)
        .collect();
    times
        .windows(2)
        .map(|pair| pair[1].duration_since(pair[0]))
        .collect()
}

#[tokio::test(start_paused = true)]
async fn the_backoff_is_jittered_doubling_and_bounded() {
    for (refusal, first, most) in [
        (IdentityRefusal::ResourceExhausted, 2, 30),
        (IdentityRefusal::IdentityUnavailable, 5, 60),
        (IdentityRefusal::IdentityStopped, 5, 60),
        (IdentityRefusal::Unrecognized, 5, 60),
    ] {
        let (root, source) = Harness::prepare();
        source.answer(K8S, Answer::Refuse(refusal));
        let files = Harness::start(root, source, Some(&[(K8S, "k8s")]), on_tmpfs);
        pass(1_800.0).await;
        let gaps = gaps(&files.source, K8S);
        assert!(gaps.len() > 10, "{refusal:?}: {gaps:?}");
        // The first retry is jittered within half the first delay and it.
        let first = Duration::from_secs(first);
        assert!(
            gaps[0] >= first / 2 && gaps[0] <= first,
            "{refusal:?}: {gaps:?}"
        );
        let most = Duration::from_secs(most);
        assert!(gaps.iter().all(|gap| *gap <= most), "{refusal:?}: {gaps:?}");
        // It reached its cap's range.
        assert!(
            gaps.iter().any(|gap| *gap >= most / 2),
            "{refusal:?}: {gaps:?}"
        );
        assert!(files.read("k8s.jwt").is_none());
        files.stop().await;
    }
}

#[tokio::test(start_paused = true)]
async fn eight_one_minute_files_stay_within_sixteen_calls_a_minute() {
    let (root, source) = Harness::prepare();
    let audiences: Vec<String> = (0..8)
        .map(|index| format!("https://{index}.example"))
        .collect();
    let names: Vec<String> = (0..8).map(|index| format!("f{index}")).collect();
    for audience in &audiences {
        source.answer(audience, Answer::Lifetime(60));
    }
    let list: Vec<(&str, &str)> = audiences
        .iter()
        .map(String::as_str)
        .zip(names.iter().map(String::as_str))
        .collect();
    let files = Harness::start(root, source, Some(&list), on_tmpfs);

    // Paced at start: one call every 500 ms.
    pass(3.6).await;
    let calls = files.source.calls();
    assert_eq!(calls.len(), 8);
    for pair in calls.windows(2) {
        assert!(pair[1].1.duration_since(pair[0].1) >= Duration::from_millis(500));
    }
    let start = calls[0].1;

    // Ten minutes on: every file present at each check, and no minute with
    // more than 16 calls.
    for _ in 0..120 {
        pass(5.0).await;
        assert_eq!(files.names().len(), 8, "{:?}", files.names());
    }
    let times: Vec<Instant> = files.source.calls().into_iter().map(|(_, at)| at).collect();
    for (index, at) in times.iter().enumerate() {
        let within = times[index..]
            .iter()
            .take_while(|later| later.duration_since(*at) < Duration::from_secs(60))
            .count();
        assert!(
            within <= 16,
            "{within} calls in the minute from {:?}",
            at.duration_since(start)
        );
    }
    // Each file was renewed about every 30 s.
    assert!(times.len() >= 8 * 19, "{}", times.len());
    files.stop().await;
}

#[tokio::test(start_paused = true)]
async fn files_that_want_more_than_the_budget_get_sixteen_calls_a_minute() {
    let (root, source) = Harness::prepare();
    // Six files of 40 s and two of 60 s would want 18 + 4 = 22 calls a
    // minute.
    let audiences: Vec<String> = (0..8)
        .map(|index| format!("https://{index}.example"))
        .collect();
    let names: Vec<String> = (0..8).map(|index| format!("f{index}")).collect();
    for (index, audience) in audiences.iter().enumerate() {
        source.answer(audience, Answer::Lifetime(if index < 6 { 40 } else { 60 }));
    }
    let list: Vec<(&str, &str)> = audiences
        .iter()
        .map(String::as_str)
        .zip(names.iter().map(String::as_str))
        .collect();
    let files = Harness::start(root, source, Some(&list), on_tmpfs);
    pass(600.0).await;
    let times: Vec<Instant> = files.source.calls().into_iter().map(|(_, at)| at).collect();
    for (index, at) in times.iter().enumerate() {
        let within = times[index..]
            .iter()
            .take_while(|later| later.duration_since(*at) < Duration::from_secs(60))
            .count();
        assert!(within <= 16, "{within}");
    }
    files.stop().await;
}

#[tokio::test]
async fn a_socket_request_after_a_file_mint_asks_the_source_no_more() {
    let (root, source) = Harness::prepare();
    let socket = root.path().join("identity.sock");
    let files = Harness::start(root, source, Some(&[(K8S, "k8s")]), on_tmpfs);
    tokio::time::timeout(STEP, async {
        while files.read("k8s.jwt").is_none() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the file is written");

    let (listener, _record) = crate::identity_socket::bind(&socket).unwrap();
    tokio::spawn(crate::identity_socket::serve(
        listener,
        Arc::clone(&files.tokens),
        std::future::pending(),
    ));
    let served = tokio::time::timeout(STEP, crate::identity_socket::fetch(&socket, K8S))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(Some(served.as_str()), files.read("k8s.jwt").as_deref());
    assert_eq!(files.source.calls().len(), 1);
    files.stop().await;
}

#[tokio::test(start_paused = true)]
async fn a_symlink_at_a_file_or_its_temporary_name_is_replaced_and_its_target_untouched() {
    let (root, source) = Harness::prepare();
    let outside = root.path().join("outside");
    std::fs::create_dir(&outside).unwrap();
    let files = Harness::start(root, source, Some(&[(K8S, "k8s")]), on_tmpfs);
    pass(1.0).await;

    for (name, target) in [("k8s.jwt", "file-target"), (".k8s.jwt.tmp", "temp-target")] {
        std::fs::write(outside.join(target), "untouched").unwrap();
        let planted = files.directory().join(name);
        let _ = std::fs::remove_file(&planted);
        std::os::unix::fs::symlink(outside.join(target), &planted).unwrap();
    }
    pass(300.0).await;
    assert_eq!(files.source.calls_for(K8S), 2);
    let renewed = files.directory().join("k8s.jwt");
    assert!(
        std::fs::symlink_metadata(&renewed)
            .unwrap()
            .file_type()
            .is_file()
    );
    assert_eq!(
        files.read("k8s.jwt").as_deref(),
        Some(files.source.issued()[1].as_str())
    );
    assert_eq!(files.names(), ["k8s.jwt"]);
    for target in ["file-target", "temp-target"] {
        assert_eq!(
            std::fs::read_to_string(outside.join(target)).unwrap(),
            "untouched"
        );
    }
    files.stop().await;
}

#[tokio::test(start_paused = true)]
async fn a_symlinked_or_disk_backed_directory_gets_nothing_written() {
    // A symlink where the directory goes.
    let (root, source) = Harness::prepare();
    let elsewhere = root.path().join("elsewhere");
    std::fs::create_dir(&elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, root.path().join("identity")).unwrap();
    let files = Harness::start(root, source, Some(&[(K8S, "k8s")]), on_tmpfs);
    pass(600.0).await;
    assert!(names_in(&elsewhere).is_empty());
    assert!(files.source.calls().is_empty());
    assert!(files.task.is_finished(), "the loop ends, having logged why");
    files.stop().await;

    // A directory on disk.
    let (root, source) = Harness::prepare();
    let files = Harness::start(root, source, Some(&[(K8S, "k8s")]), on_disk);
    pass(600.0).await;
    assert!(files.names().is_empty(), "{:?}", files.names());
    assert!(files.source.calls().is_empty());
    assert!(files.task.is_finished());
    files.stop().await;
}

#[tokio::test(start_paused = true)]
async fn an_entry_with_a_bad_name_is_dropped_and_the_rest_stand() {
    let (root, source) = Harness::prepare();
    let files = Harness::start(
        root,
        source,
        Some(&[(VAULT, "../escape"), (VAULT, "Vault"), (K8S, "k8s")]),
        on_tmpfs,
    );
    pass(1.0).await;
    assert_eq!(files.names(), ["k8s.jwt"]);
    assert!(!files.root.path().join("escape.jwt").exists());
    assert_eq!(files.source.calls_for(VAULT), 0);
    files.stop().await;
}

#[test]
fn proc_is_not_memory() {
    let proc = PrivateDirectory::open_home(Path::new("/proc"))
        .unwrap()
        .expect("root owns /proc");
    assert!(!proc.is_in_memory().unwrap());
}

/// Registered once per test process and never dropped; it enables nothing.
/// Its `sometimes` interest keeps tracing-core from caching a callsite as
/// never enabled when a parallel test thread with no subscriber registers it
/// first, so a thread-local capture sees every event of its own thread.
struct InterestPeer;

impl tracing::Subscriber for InterestPeer {
    fn register_callsite(
        &self,
        _: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        tracing::subscriber::Interest::sometimes()
    }
    fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
        Some(tracing::level_filters::LevelFilter::TRACE)
    }
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        false
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, _: &tracing::Event<'_>) {}
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

static INTEREST_PEER: std::sync::OnceLock<tracing::Dispatch> = std::sync::OnceLock::new();

/// Every log line of a run with mints, a renewal, refusals, a removal and a
/// dropped entry names audiences and files and never a token.
#[test]
fn the_token_never_reaches_the_log() {
    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Captured {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let captured = Captured::default();
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer.clone())
        .finish();
    INTEREST_PEER.get_or_init(|| tracing::Dispatch::new(InterestPeer));
    let _guard = tracing::subscriber::set_default(subscriber);
    tracing::callsite::rebuild_interest_cache();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .unwrap();
    let issued = runtime.block_on(async {
        let (root, source) = Harness::prepare();
        let files = Harness::start(
            root,
            source,
            Some(&[(K8S, "k8s"), (VAULT, "vault"), (VAULT, "../bad")]),
            on_tmpfs,
        );
        pass(301.0).await;
        files
            .source
            .answer(K8S, Answer::Refuse(IdentityRefusal::IdentityStopped));
        files
            .source
            .answer(VAULT, Answer::Refuse(IdentityRefusal::IdentityUnavailable));
        pass(600.0).await;
        files.send(Some(&[(K8S, "k8s")]));
        pass(1.0).await;
        let issued = files.source.issued();
        files.stop().await;
        issued
    });
    assert!(issued.len() >= 4, "{issued:?}");
    let log = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    for token in &issued {
        assert!(!log.contains(token.as_str()), "{log}");
        // Nor the token's signature part on its own.
        let signature = token.rsplit('.').next().unwrap();
        assert!(!log.contains(&format!("dG9rZW4.{signature}")), "{log}");
    }
    for named in [
        "audience=https://k8s.walk.example",
        "file=k8s.jwt",
        "file=vault.jwt",
        "refusal=\"identity_stopped\"",
        "sandbox identity file dropped",
        "sandbox identity file written",
    ] {
        assert!(log.contains(named), "{named} missing from {log}");
    }
}
