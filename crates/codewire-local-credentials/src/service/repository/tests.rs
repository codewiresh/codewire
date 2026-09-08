use super::*;
use std::collections::BTreeMap;
use std::process::Stdio;
use std::sync::Mutex;

use codewire_access::{
    AccessProfileName, CapabilitySlot, CredentialAuthKind, CredentialId, ProviderId,
};
use codewire_protected_store::{ProtectedStorePersistence, ProtectedValue};
use tempfile::TempDir;
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::NewCredential;
use crate::repository::{LocalCredentialRepositoryLeaseClient, LocalRepositorySpawnError};
use crate::tests::TestProtectedStore;

mod platform;

struct RunningChild {
    pid: u32,
    staging: PathBuf,
    exit_gate: std::os::unix::net::UnixStream,
    leased: oneshot::Receiver<()>,
    streaming: oneshot::Receiver<()>,
}

struct SyntheticSpawner {
    store: TestProtectedStore,
    started: mpsc::UnboundedSender<RunningChild>,
    clients: Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

impl Drop for SyntheticSpawner {
    fn drop(&mut self) {
        // Test client tasks contain no process or protected operation once
        // they reach pending(); the production manager owns all real cleanup.
        for task in self.clients.get_mut().unwrap().drain(..) {
            task.abort();
        }
    }
}

impl LocalRepositoryProcessSpawner for SyntheticSpawner {
    fn spawn(
        &self,
        config: &LocalRepositoryProcessConfig,
        authority_peer: std::os::unix::net::UnixStream,
    ) -> Result<tokio::process::Child, LocalRepositorySpawnError> {
        let fail = |_| LocalRepositorySpawnError::Spawn;
        crate::rpc_tests::prepare_test_repository_bundle(&config.staging_directory)
            .map_err(fail)?;
        authority_peer.set_nonblocking(true).map_err(fail)?;
        let stream = UnixStream::from_std(authority_peer).map_err(fail)?;
        let (input, exit_gate) = std::os::unix::net::UnixStream::pair().map_err(fail)?;
        let input: std::os::fd::OwnedFd = input.into();
        let child = tokio::process::Command::new("/bin/cat")
            .env_clear()
            .stdin(Stdio::from(input))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(fail)?;
        let store = self.store.clone();
        let request_id = config.request_id;
        let platform = config.platform_delegated;
        let (leased_tx, leased) = oneshot::channel();
        let (streaming_tx, streaming) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut client = LocalCredentialRepositoryLeaseClient::connect(stream, request_id)
                .await
                .unwrap();
            client.report_ready().await.unwrap();
            if platform {
                use base64::Engine as _;
                use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
                assert_eq!(
                    client.lease_github(store).await.unwrap_err(),
                    RepositoryLeaseChannelError::Denied
                );
                let checkout = client.brokered_checkout().await.unwrap();
                assert_eq!(
                    client.brokered_checkout().await.unwrap_err().code(),
                    tonic::Code::PermissionDenied
                );
                let endpoint = url::Url::parse(&checkout.endpoint).unwrap();
                let address = format!("127.0.0.1:{}", endpoint.port().unwrap());
                let mut stream = tokio::net::TcpStream::connect(&address).await.unwrap();
                let authorization = base64::engine::general_purpose::STANDARD
                    .encode([b"x-access-token:".as_slice(), &checkout.capability].concat());
                stream.write_all(format!("GET {}/info/refs?service=git-upload-pack HTTP/1.1\r\nHost: {address}\r\nAuthorization: Basic {authorization}\r\n\r\n", endpoint.path()).as_bytes()).await.unwrap();
                let mut response = Vec::new();
                while !response.windows(4).any(|bytes| bytes == b"PACK") {
                    let mut chunk = [0; 1024];
                    let length = stream.read(&mut chunk).await.unwrap();
                    assert_ne!(length, 0, "authenticated body must begin");
                    response.extend_from_slice(&chunk[..length]);
                }
                let _ = streaming_tx.send(());
                // Cancellation may close a partially streamed HTTP response.
                // The retained manager, not this synthetic client, owns proof
                // that its child, private channel and ingress have drained.
                if stream.read_to_end(&mut response).await.is_err() {
                    return;
                }
                assert!(response.starts_with(b"HTTP/1.1 200"));
                assert!(response.windows(4).any(|bytes| bytes == b"PACK"));
            } else {
                let lease = client.lease_github(store).await.unwrap();
                drop(lease);
                let _ = streaming_tx.send(());
            }
            let _ = leased_tx.send(());
            // Hold a real idle tonic client while the manager closes its
            // inherited server explicitly; it cannot rely on waiter teardown.
            std::future::pending::<()>().await;
            drop(client);
        });
        self.clients.lock().unwrap().push(task);
        self.started
            .send(RunningChild {
                pid: child.id().unwrap(),
                staging: config.staging_directory.clone(),
                exit_gate,
                leased,
                streaming,
            })
            .map_err(|_| LocalRepositorySpawnError::Spawn)?;
        Ok(child)
    }
}

struct Fixture {
    _temp: TempDir,
    manager: Arc<RepositoryProcessManager<TestProtectedStore>>,
    request: RepositoryCredentialLeaseRequest,
    credential_id: CredentialId,
    started: mpsc::UnboundedReceiver<RunningChild>,
}

impl Fixture {
    fn new() -> Self {
        let temp = TempDir::new().unwrap();
        let store = TestProtectedStore::new(ProtectedStorePersistence::ProcessLifetime);
        let root = temp.path().join("authority");
        let authority = Arc::new(
            LocalCredentialAuthority::open(
                &root,
                store.clone(),
                codewire_access::builtin_provider_catalog(),
            )
            .unwrap(),
        );
        let credential = authority
            .add_credential(
                NewCredential {
                    provider: ProviderId::parse("github").unwrap(),
                    authentication_kind: CredentialAuthKind::OAuth,
                    display_name: "synthetic-checkout".into(),
                    account_hint: None,
                    expires_at_unix: None,
                },
                ProtectedValue::from_slice(b"synthetic-repository-owner-test").unwrap(),
            )
            .unwrap();
        let profile = authority
            .create_profile(
                AccessProfileName::parse("checkout").unwrap(),
                BTreeMap::from([(CapabilitySlot::github(), credential.metadata.id.clone())]),
            )
            .unwrap();
        let request = RepositoryCredentialLeaseRequest {
            request_id: Uuid::new_v4(),
            profile_id: profile.profile.id,
            profile_revision: profile.profile.revision,
            source: "https://github.com/codewire/codewire.git".into(),
            branch: "main".into(),
            revision: String::new(),
            known_hosts: Vec::new(),
        };
        let (started, receiver) = mpsc::unbounded_channel();
        let spawner = Arc::new(SyntheticSpawner {
            store,
            started,
            clients: Mutex::new(Vec::new()),
        });
        Self {
            _temp: temp,
            manager: Arc::new(RepositoryProcessManager::new(
                authority,
                Some(spawner),
                root,
                crate::broker_channel::LocalSshOperationRuntime::new(None),
                None,
            )),
            request,
            credential_id: credential.metadata.id,
            started: receiver,
        }
    }

    fn prepare(&self) -> tokio::task::JoinHandle<Result<PreparedRepository, Status>> {
        let manager = Arc::clone(&self.manager);
        let mut request = self.request.clone();
        request.request_id = Uuid::new_v4();
        tokio::spawn(async move { manager.prepare(request, None).await })
    }

    async fn child(&mut self) -> RunningChild {
        let mut child = tokio::time::timeout(Duration::from_secs(5), self.started.recv())
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), &mut child.leased)
            .await
            .unwrap()
            .unwrap();
        child
    }

    async fn shutdown(&self) {
        tokio::time::timeout(Duration::from_secs(5), self.manager.shutdown_all())
            .await
            .expect("retained repository jobs drained")
            .unwrap();
    }
}

#[test]
fn ssh_runtime_cleanup_preserves_unwound_or_replaced_directory() {
    let temporary = tempfile::tempdir().unwrap();
    let failed = Arc::new(AtomicBool::new(false));
    let guard = create_repository_ssh_runtime(temporary.path(), Arc::clone(&failed)).unwrap();
    let path = guard.path.clone().unwrap();
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _guard = guard;
        panic!("synthetic repository owner unwind");
    }));
    assert!(unwind.is_err());
    assert!(path.is_dir());
    assert!(failed.load(Ordering::Acquire));
    cleanup_repository_ssh_runtimes(temporary.path()).unwrap();
    assert!(!path.exists());

    failed.store(false, Ordering::Release);
    let guard = create_repository_ssh_runtime(temporary.path(), Arc::clone(&failed)).unwrap();
    let path = guard.path.clone().unwrap();
    let moved = temporary.path().join("retained-original");
    fs::rename(&path, &moved).unwrap();
    fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
    drop(guard);
    assert!(failed.load(Ordering::Acquire));
    assert!(path.is_dir());
    fs::remove_dir(&path).unwrap();
    fs::remove_dir(&moved).unwrap();
}

fn assert_reaped(child: &RunningChild) {
    assert!(!std::path::Path::new(&format!("/proc/{}", child.pid)).exists());
    assert!(!child.staging.exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropped_waiter_keeps_child_and_channel_owned_through_reap() {
    let mut fixture = Fixture::new();
    let waiter = fixture.prepare();
    let child = fixture.child().await;
    waiter.abort();
    assert!(waiter.await.err().unwrap().is_cancelled());
    fixture.shutdown().await;
    assert_reaped(&child);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_cancels_live_preparation_and_refuses_readmission() {
    let mut fixture = Fixture::new();
    let waiter = fixture.prepare();
    let child = fixture.child().await;
    fixture.shutdown().await;
    assert!(matches!(waiter.await.unwrap(), Err(error) if error.code() == tonic::Code::Cancelled));
    assert_reaped(&child);
    assert!(
        matches!(fixture.manager.prepare(fixture.request.clone(), None).await,
        Err(error) if error.code() == tonic::Code::Unavailable)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn owner_future_drop_signals_retained_jobs_without_claiming_synchronous_drain() {
    let mut fixture = Fixture::new();
    let guard = fixture.manager.shutdown_on_drop();
    let waiter = fixture.prepare();
    let child = fixture.child().await;
    drop(guard);
    fixture.shutdown().await;
    assert!(matches!(waiter.await.unwrap(), Err(error) if error.code() == tonic::Code::Cancelled));
    assert_reaped(&child);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoked_admission_suppresses_successful_child_bundle() {
    let mut fixture = Fixture::new();
    let waiter = fixture.prepare();
    let child = fixture.child().await;
    fixture
        .manager
        .authority
        .revoke_credential(&fixture.credential_id)
        .unwrap();
    let RunningChild {
        exit_gate,
        staging,
        pid,
        ..
    } = child;
    drop(exit_gate);
    assert!(waiter.await.unwrap().is_err());
    fixture.shutdown().await;
    assert!(!staging.exists());
    assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exact_success_holds_capacity_until_bundle_and_staging_are_dropped() {
    let mut fixture = Fixture::new();
    let waiter = fixture.prepare();
    let child = fixture.child().await;
    let RunningChild {
        exit_gate, staging, ..
    } = child;
    drop(exit_gate);
    let prepared = waiter.await.unwrap().unwrap();
    assert_eq!(prepared.metadata.branch, "main");
    assert_eq!(
        fixture.manager.jobs.available_permits(),
        (MAX_REPOSITORY_JOBS - 1) as usize
    );
    assert!(staging.exists());
    let shutdown = fixture.manager.shutdown_all();
    tokio::pin!(shutdown);
    assert!(
        tokio::time::timeout(Duration::from_millis(25), &mut shutdown)
            .await
            .is_err()
    );
    drop(prepared);
    tokio::time::timeout(Duration::from_secs(5), shutdown)
        .await
        .unwrap()
        .unwrap();
    assert!(!staging.exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_releases_backpressured_bundle_stream_and_its_capacity() {
    let mut fixture = Fixture::new();
    let waiter = fixture.prepare();
    let child = fixture.child().await;
    let RunningChild {
        exit_gate, staging, ..
    } = child;
    drop(exit_gate);
    let prepared = waiter.await.unwrap().unwrap();
    let (sender, mut receiver) = mpsc::channel(1);
    let stream = tokio::spawn(super::super::stream_prepared_repository(prepared, sender));
    // Metadata proves the stream began; don't consume the bundle that follows.
    assert!(receiver.recv().await.unwrap().is_ok());
    fixture.shutdown().await;
    stream.await.unwrap();
    assert!(!staging.exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn manager_bounds_live_executors_and_cancellation_drains_all_eight() {
    let mut fixture = Fixture::new();
    let mut waiters = Vec::new();
    let mut children = Vec::new();
    for _ in 0..MAX_REPOSITORY_JOBS {
        waiters.push(fixture.prepare());
        children.push(fixture.child().await);
    }
    assert!(
        matches!(fixture.manager.prepare(fixture.request.clone(), None).await,
        Err(error) if error.code() == tonic::Code::ResourceExhausted)
    );
    for waiter in &waiters {
        waiter.abort();
    }
    for waiter in waiters {
        assert!(waiter.await.err().unwrap().is_cancelled());
    }
    fixture.shutdown().await;
    for child in &children {
        assert_reaped(child);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_waits_for_a_cancelled_bundle_blocking_read_before_cleanup() {
    use std::io::Write as _;
    use tokio::io::AsyncReadExt as _;

    let mut fixture = Fixture::new();
    let waiter = fixture.prepare();
    let child = fixture.child().await;
    let RunningChild {
        exit_gate, staging, ..
    } = child;
    drop(exit_gate);
    let mut prepared = waiter.await.unwrap().unwrap();
    // Inject a controlled blocking IO object only at this internal ownership
    // seam; product bundle validation still accepts regular files exclusively.
    let (reader, mut writer) = std::os::unix::net::UnixStream::pair().unwrap();
    let reader: std::os::fd::OwnedFd = reader.into();
    prepared.bundle = Some(tokio::fs::File::from_std(std::fs::File::from(reader)));
    let mut byte = [0; 1];
    assert!(
        tokio::time::timeout(
            Duration::from_millis(10),
            prepared.bundle.as_mut().unwrap().read(&mut byte)
        )
        .await
        .is_err()
    );
    fixture.manager.cancel_all();
    let (sender, _receiver) = mpsc::channel(1);
    let stream = tokio::spawn(super::super::stream_prepared_repository(prepared, sender));
    let shutdown = fixture.manager.shutdown_all();
    tokio::pin!(shutdown);
    assert!(
        tokio::time::timeout(Duration::from_millis(25), &mut shutdown)
            .await
            .is_err()
    );
    assert!(staging.exists());
    writer.write_all(b"x").unwrap();
    tokio::time::timeout(Duration::from_secs(5), shutdown)
        .await
        .unwrap()
        .unwrap();
    stream.await.unwrap();
    assert!(!staging.exists());
}

#[tokio::test]
async fn panic_latch_precedes_job_capacity_release_and_blocks_successful_drain() {
    let fixture = Fixture::new();
    let completion = JobCompletion {
        permit: Some(
            Arc::clone(&fixture.manager.jobs)
                .acquire_owned()
                .await
                .unwrap(),
        ),
        failed: Arc::clone(&fixture.manager.failed),
        complete: false,
    };
    drop(completion);
    assert_eq!(
        fixture.manager.jobs.available_permits(),
        MAX_REPOSITORY_JOBS as usize
    );
    assert!(fixture.manager.failed.load(Ordering::Acquire));
    assert!(fixture.manager.shutdown_all().await.is_err());
}

#[tokio::test]
async fn original_deadline_cannot_be_extended_by_a_queued_result() {
    let (shutdown, shutdown_rx) = watch::channel(false);
    let (request, request_rx) = watch::channel(false);
    let mut cancellation = JobCancellation {
        shutdown: shutdown_rx,
        request: request_rx,
        deadline: tokio::time::Instant::now() - Duration::from_millis(1),
    };
    assert!(cancellation.ensure_live().is_err());
    tokio::time::timeout(Duration::from_millis(25), cancellation.cancelled())
        .await
        .unwrap();
    drop((shutdown, request));
}

#[test]
fn failed_staging_cleanup_is_visible_before_a_retained_permit_can_release() {
    let temp = TempDir::new().unwrap();
    let invalid = temp.path().join("unowned-file");
    std::fs::write(&invalid, b"public fixture").unwrap();
    let failed = Arc::new(AtomicBool::new(false));
    drop(RepositoryStagingGuard {
        path: Some(invalid.clone()),
        failed: Arc::clone(&failed),
    });
    assert!(failed.load(Ordering::Acquire));
    assert!(invalid.exists());
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_child_reap_preserves_staging_and_cannot_report_successful_shutdown() {
    struct AlreadyReaped {
        staging: Arc<Mutex<Option<PathBuf>>>,
    }
    impl LocalRepositoryProcessSpawner for AlreadyReaped {
        fn spawn(
            &self,
            config: &LocalRepositoryProcessConfig,
            authority_peer: std::os::unix::net::UnixStream,
        ) -> Result<tokio::process::Child, LocalRepositorySpawnError> {
            drop(authority_peer);
            *self.staging.lock().unwrap() = Some(config.staging_directory.clone());
            let child = tokio::process::Command::new("/bin/true")
                .env_clear()
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .spawn()
                .map_err(|_| LocalRepositorySpawnError::Spawn)?;
            let pid = rustix::process::Pid::from_raw(i32::try_from(child.id().unwrap()).unwrap())
                .unwrap();
            // Reap only this exact synthetic child outside Tokio to inject
            // ECHILD without changing product validation or using unsafe code.
            let (reaped, _) =
                rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::empty())
                    .unwrap()
                    .unwrap();
            assert_eq!(reaped, pid);
            Ok(child)
        }
    }
    let mut fixture = Fixture::new();
    let staging = Arc::new(Mutex::new(None));
    Arc::get_mut(&mut fixture.manager).unwrap().spawner = Some(Arc::new(AlreadyReaped {
        staging: Arc::clone(&staging),
    }));
    assert!(
        fixture
            .manager
            .prepare(fixture.request.clone(), None)
            .await
            .is_err()
    );
    assert!(fixture.manager.shutdown_all().await.is_err());
    assert!(staging.lock().unwrap().as_ref().unwrap().is_dir());
    // The TempDir fixture owns recovery after the synthetic child was in fact
    // reaped. Production preserves this directory for its startup reconciler.
}
