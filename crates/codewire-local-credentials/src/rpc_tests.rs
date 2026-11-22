use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use codewire_access::{
    AccessProfileName, AccessProfileReference, BrokerOperationId, BrokerRouteId, CapabilityPolicy,
    CapabilitySlot, CredentialAuthKind, CredentialStatus, EnvironmentAccessBinding, EnvironmentId,
    GrantPermission, ProviderDefinition, ProviderId,
};
use codewire_protected_store::{
    ProtectedEntryId, ProtectedStore, ProtectedStoreError, ProtectedStorePersistence,
    ProtectedValue,
    ssh_material::{decode_protected_material, generate_ed25519},
};
use tokio::io::AsyncReadExt as _;
use tokio::net::UnixStream;
use tokio::sync::oneshot;
use tokio_stream::StreamExt as _;
use tonic::Code;
use tower::ServiceExt as _;
use zeroize::Zeroizing;

use super::*;
use crate::control::v1;
use crate::service::{serve_until, serve_until_with_process_spawners};
use crate::transport::{
    AUTHORITY_PROTOCOL_VERSION, MINIMUM_AUTHORITY_PROTOCOL_VERSION, bind_owner_only,
    bind_owner_only_for_uid, current_uid, owner_only_connector, remove_bound_socket,
};

const FIRST_MATERIAL: &[u8] = b"synthetic-oauth-material-alpha";
const SECOND_MATERIAL: &[u8] = b"synthetic-oauth-material-bravo";

#[derive(Clone, Default)]
struct TestProtectedStore {
    entries: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    put_gate: Arc<TestPutGate>,
}

#[derive(Default)]
struct TestPutGate {
    blocked: Mutex<bool>,
    changed: Condvar,
    reached: AtomicUsize,
    notify: tokio::sync::Notify,
}

struct TestPutBlock {
    gate: Arc<TestPutGate>,
}

impl Drop for TestPutBlock {
    fn drop(&mut self) {
        *self.gate.blocked.lock().expect("put gate lock") = false;
        self.gate.changed.notify_all();
    }
}

impl TestProtectedStore {
    fn values(&self) -> Vec<Vec<u8>> {
        self.entries
            .lock()
            .expect("store lock")
            .values()
            .cloned()
            .collect()
    }

    fn block_puts(&self) -> TestPutBlock {
        *self.put_gate.blocked.lock().expect("put gate lock") = true;
        TestPutBlock {
            gate: Arc::clone(&self.put_gate),
        }
    }

    /// Waits until `request` reaches the protected-store put, or fails with the
    /// request's own outcome if it ends first, never against a wall clock.
    async fn wait_for_put<T: std::fmt::Debug>(&self, request: &mut tokio::task::JoinHandle<T>) {
        loop {
            let notified = self.put_gate.notify.notified();
            if self.put_gate.reached.load(Ordering::SeqCst) > 0 {
                return;
            }
            tokio::select! {
                () = notified => {}
                ended = &mut *request => {
                    panic!("request ended before reaching the protected-store put: {ended:?}")
                }
            }
        }
    }
}

impl ProtectedStore for TestProtectedStore {
    fn persistence(&self) -> ProtectedStorePersistence {
        ProtectedStorePersistence::ProcessLifetime
    }

    fn get(&self, id: &ProtectedEntryId) -> Result<Option<ProtectedValue>, ProtectedStoreError> {
        self.entries
            .lock()
            .map_err(|_| ProtectedStoreError::Unavailable)?
            .get(id.expose_reference())
            .map(|value| ProtectedValue::from_slice(value))
            .transpose()
    }

    fn put(
        &self,
        id: &ProtectedEntryId,
        value: &ProtectedValue,
    ) -> Result<(), ProtectedStoreError> {
        self.put_gate.reached.fetch_add(1, Ordering::SeqCst);
        self.put_gate.notify.notify_waiters();
        let mut blocked = self
            .put_gate
            .blocked
            .lock()
            .map_err(|_| ProtectedStoreError::Unavailable)?;
        while *blocked {
            blocked = self
                .put_gate
                .changed
                .wait(blocked)
                .map_err(|_| ProtectedStoreError::Unavailable)?;
        }
        drop(blocked);
        self.entries
            .lock()
            .map_err(|_| ProtectedStoreError::Unavailable)?
            .insert(
                id.expose_reference().to_string(),
                value.expose_secret().to_vec(),
            );
        Ok(())
    }

    fn delete(&self, id: &ProtectedEntryId) -> Result<(), ProtectedStoreError> {
        self.entries
            .lock()
            .map_err(|_| ProtectedStoreError::Unavailable)?
            .remove(id.expose_reference());
        Ok(())
    }
}

fn provider(value: &str) -> ProviderId {
    ProviderId::parse(value).expect("provider ID")
}

fn catalog() -> ProviderCatalog {
    ProviderCatalog::from_definitions([
        ProviderDefinition {
            id: provider("openai"),
            authentication_kinds: BTreeSet::from([CredentialAuthKind::OAuth]),
            capabilities: BTreeMap::from([(
                CapabilitySlot::codex(),
                CapabilityPolicy {
                    authentication_kinds: BTreeSet::from([CredentialAuthKind::OAuth]),
                    permissions: BTreeSet::from([GrantPermission {
                        operation: BrokerOperationId::parse("responses").expect("operation ID"),
                        route: BrokerRouteId::parse("openai-api").expect("route ID"),
                    }]),
                },
            )]),
        },
        ProviderDefinition {
            id: provider("ssh"),
            authentication_kinds: BTreeSet::from([CredentialAuthKind::SshKey]),
            capabilities: BTreeMap::new(),
        },
    ])
    .expect("provider catalog")
}

fn runtime_config(temp: &tempfile::TempDir) -> AuthorityRuntimeConfig {
    AuthorityRuntimeConfig {
        root: temp.path().join("authority"),
        executable: fs::canonicalize(std::env::current_exe().expect("current executable"))
            .expect("canonical executable"),
        socket_dir: temp.path().join("authority"),
    }
}

async fn start_server(
    config: AuthorityRuntimeConfig,
    store: TestProtectedStore,
) -> (
    oneshot::Sender<()>,
    tokio::task::JoinHandle<Result<(), AuthorityRuntimeError>>,
) {
    start_listening_authority(config, store, catalog(), Default::default()).await
}

/// Starts an authority and returns once its socket is bound and listening,
/// so a client connects once instead of guessing readiness against a clock.
/// An authority that ends before listening fails the test with its own error.
async fn start_listening_authority(
    config: AuthorityRuntimeConfig,
    store: TestProtectedStore,
    catalog: ProviderCatalog,
    adapters: crate::service::AuthorityRuntimeAdapters,
) -> (
    oneshot::Sender<()>,
    tokio::task::JoinHandle<Result<(), AuthorityRuntimeError>>,
) {
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let (listening_tx, listening_rx) = oneshot::channel();
    let adapters = crate::service::AuthorityRuntimeAdapters {
        listening: Some(listening_tx),
        ..adapters
    };
    let mut task = tokio::spawn(async move {
        serve_until_with_process_spawners(
            config,
            store,
            catalog,
            async move {
                let _ = shutdown_rx.await;
            },
            adapters,
        )
        .await
    });
    tokio::select! {
        listening = listening_rx => {
            if listening.is_err() {
                panic!("authority ended before listening: {:?}", (&mut task).await);
            }
        }
        ended = &mut task => panic!("authority ended before listening: {ended:?}"),
    }
    (shutdown_tx, task)
}

#[derive(Clone)]
struct TestBrokerSpawner {
    store: TestProtectedStore,
    launches: Arc<Mutex<Vec<LocalBrokerProcessConfig>>>,
    child_pids: Arc<Mutex<Vec<u32>>>,
    tasks: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
    leased_material: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
}

impl LocalBrokerProcessSpawner for TestBrokerSpawner {
    fn runner_protocol(&self) -> u32 {
        crate::broker_process::TEST_RUNNER_PROTOCOL
    }

    fn spawn(
        &self,
        config: &LocalBrokerProcessConfig,
        _: &crate::ProviderLookup,
        authority_peer: std::os::unix::net::UnixStream,
        _boot_secrets: &crate::BrokerBootSecrets,
    ) -> Result<tokio::process::Child, LocalBrokerSpawnError> {
        self.launches
            .lock()
            .map_err(|_| LocalBrokerSpawnError::Spawn)?
            .push(config.clone());
        authority_peer
            .set_nonblocking(true)
            .map_err(|_| LocalBrokerSpawnError::Spawn)?;
        let stream =
            UnixStream::from_std(authority_peer).map_err(|_| LocalBrokerSpawnError::Spawn)?;
        let store = self.store.clone();
        let environment_id = config.environment_id.clone();
        let environment_generation = config.environment_generation;
        let leased_material = self.leased_material.clone();
        let task = tokio::spawn(async move {
            let ready = codewire_daemon_proto::codewire::bridge::v1::CredentialBridgeReady {
                protocol_version: codewire_daemon_proto::CREDENTIAL_BRIDGE_PROTOCOL_VERSION,
                environment_id: environment_id.to_string(),
                environment_generation,
            };
            let Ok(mut client) = LocalCredentialBrokerLeaseClient::connect(
                stream,
                store,
                environment_id,
                environment_generation,
            )
            .await
            else {
                return;
            };
            if client.report_ready(ready, Vec::new()).await.is_err() {
                return;
            }
            let Ok(lease) = client
                .lease_operation(
                    uuid::Uuid::new_v4(),
                    CapabilitySlot::codex(),
                    BrokerOperationId::parse("responses").unwrap(),
                    BrokerRouteId::parse("openai-api").unwrap(),
                )
                .await
            else {
                return;
            };
            let _ = leased_material.send(lease.with_material(|value| value.to_vec()));
            std::future::pending::<()>().await;
            drop(client);
        });
        self.tasks
            .lock()
            .map_err(|_| LocalBrokerSpawnError::Spawn)?
            .push(task);
        let child = tokio::process::Command::new("/bin/sleep")
            .arg("60")
            .kill_on_drop(true)
            .spawn()
            .map_err(|_| LocalBrokerSpawnError::Spawn)?;
        self.child_pids
            .lock()
            .map_err(|_| LocalBrokerSpawnError::Spawn)?
            .push(child.id().ok_or(LocalBrokerSpawnError::Spawn)?);
        Ok(child)
    }
}

#[derive(Clone)]
struct TestRepositorySpawner {
    leased_material: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    tasks: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
    /// When set, the stand-in executor treats its login as due and refreshes
    /// it to this material through the lease channel before Git would run.
    refresh_to: Option<&'static [u8]>,
    /// How long the stand-in executor works after its lease, holding the
    /// lease channel open as a real fetch does.
    work_seconds: u32,
}

impl LocalRepositoryProcessSpawner for TestRepositorySpawner {
    fn spawn(
        &self,
        config: &LocalRepositoryProcessConfig,
        authority_peer: std::os::unix::net::UnixStream,
    ) -> Result<tokio::process::Child, LocalRepositorySpawnError> {
        let commit = prepare_test_repository_bundle(&config.staging_directory)
            .map_err(|_| LocalRepositorySpawnError::Spawn)?;
        authority_peer
            .set_nonblocking(true)
            .map_err(|_| LocalRepositorySpawnError::Spawn)?;
        let stream =
            UnixStream::from_std(authority_peer).map_err(|_| LocalRepositorySpawnError::Spawn)?;
        let request_id = config.request_id;
        let leased_material = self.leased_material.clone();
        let refresh_to = self.refresh_to;
        let marker = config.staging_directory.join("lease-complete");
        let work = std::time::Duration::from_secs(u64::from(self.work_seconds));
        let task = tokio::spawn(async move {
            let Ok(mut client) =
                LocalCredentialRepositoryLeaseClient::connect(stream, request_id).await
            else {
                return;
            };
            if client.report_ready().await.is_err() {
                return;
            }
            let Ok(lease) = client.lease_github().await else {
                return;
            };
            let _ = leased_material.send(lease.material().to_vec());
            if let Some(rotated) = refresh_to {
                // No second lease before a refresh outcome.
                let early = client.lease_github().await;
                let _ = leased_material.send(if early.is_err() {
                    b"second-lease-denied".to_vec()
                } else {
                    b"second-lease-allowed".to_vec()
                });
                let Ok(crate::repository::RepositoryRefreshBegin::Reserved(reservation)) =
                    client.begin_github_refresh(&lease).await
                else {
                    return;
                };
                let Ok(started) = client.start_github_refresh(reservation).await else {
                    return;
                };
                let rotated = ProtectedValue::from_slice(rotated).unwrap();
                if client
                    .commit_github_refresh(started, rotated)
                    .await
                    .is_err()
                {
                    return;
                }
                let Ok(lease) = client.lease_github().await else {
                    return;
                };
                let _ = leased_material.send(lease.material().to_vec());
            }
            tokio::time::sleep(work).await;
            let _ = fs::write(marker, b"ready");
        });
        self.tasks
            .lock()
            .map_err(|_| LocalRepositorySpawnError::Spawn)?
            .push(task);
        let marker = config.staging_directory.join("lease-complete");
        let mut child = tokio::process::Command::new("/bin/sh");
        child
            .arg("-c")
            .arg("while [ ! -f \"$1\" ]; do sleep 0.01; done")
            .arg("codewire-test-repository-executor")
            .arg(marker)
            .env_clear()
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true);
        // A macOS executor of either transport leads its process group and
        // pipes stderr, which its authority drains after stopping the group.
        #[cfg(target_os = "macos")]
        child.stderr(std::process::Stdio::piped()).process_group(0);
        let child = child
            .spawn()
            .map_err(|_| LocalRepositorySpawnError::Spawn)?;
        let _ = commit;
        Ok(child)
    }
}

pub(crate) fn prepare_test_repository_bundle(staging: &std::path::Path) -> io::Result<String> {
    // These are synthetic repositories. Never consult owner/global Git
    // configuration, signing agents, templates or hooks for fixture commits.
    let git = || {
        let mut command = Command::new("/usr/bin/git");
        command
            .env_clear()
            .env("HOME", staging)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .args([
                "-c",
                "commit.gpgsign=false",
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "maintenance.autoDetach=false",
                "-c",
                "gc.autoDetach=false",
            ]);
        command
    };
    let repository = staging.join("fixture");
    let status = git()
        .args(["init", "--quiet", "--initial-branch", "main"])
        .arg(&repository)
        .status()?;
    if !status.success() {
        return Err(io::Error::other("initialize fixture repository"));
    }
    fs::write(repository.join("README.md"), b"credential-free fixture\n")?;
    for arguments in [
        vec!["add", "README.md"],
        vec![
            "-c",
            "user.name=Codewire Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "fixture",
        ],
        vec!["update-ref", "refs/codewire/source", "HEAD"],
    ] {
        let status = git().arg("-C").arg(&repository).args(arguments).status()?;
        if !status.success() {
            return Err(io::Error::other("prepare fixture repository"));
        }
    }
    let output = git()
        .arg("-C")
        .arg(&repository)
        .args(["rev-parse", "HEAD"])
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other("resolve fixture commit"));
    }
    let commit = String::from_utf8(output.stdout)
        .map_err(|_| io::Error::other("invalid fixture commit"))?
        .trim()
        .to_owned();
    let bundle = staging.join("source.bundle");
    let status = git()
        .arg("-C")
        .arg(&repository)
        .arg("bundle")
        .arg("create")
        .arg(&bundle)
        .arg("refs/codewire/source")
        .status()?;
    if !status.success() {
        return Err(io::Error::other("create fixture bundle"));
    }
    fs::set_permissions(&bundle, fs::Permissions::from_mode(0o600))?;
    let size = fs::metadata(&bundle)?.len();
    let result = staging.join("result");
    fs::write(&result, format!("main\n{commit}\n{size}\n"))?;
    fs::set_permissions(result, fs::Permissions::from_mode(0o600))?;
    Ok(commit)
}

async fn start_server_with_spawner(
    config: AuthorityRuntimeConfig,
    store: TestProtectedStore,
    spawner: Arc<dyn LocalBrokerProcessSpawner>,
) -> (
    oneshot::Sender<()>,
    tokio::task::JoinHandle<Result<(), AuthorityRuntimeError>>,
) {
    start_listening_authority(
        config,
        store,
        catalog(),
        crate::service::AuthorityRuntimeAdapters {
            broker_spawner: Some(spawner),
            ..Default::default()
        },
    )
    .await
}

async fn start_server_with_repository_spawner(
    config: AuthorityRuntimeConfig,
    store: TestProtectedStore,
    spawner: Arc<dyn LocalRepositoryProcessSpawner>,
) -> (
    oneshot::Sender<()>,
    tokio::task::JoinHandle<Result<(), AuthorityRuntimeError>>,
) {
    start_listening_authority(
        config,
        store,
        codewire_access::builtin_provider_catalog(),
        crate::service::AuthorityRuntimeAdapters {
            repository_spawner: Some(spawner),
            ..Default::default()
        },
    )
    .await
}

/// `start_server`, also handing back the probe of the SSH enrollment workers.
async fn start_server_with_ssh_probe(
    config: AuthorityRuntimeConfig,
    store: TestProtectedStore,
) -> (
    oneshot::Sender<()>,
    tokio::task::JoinHandle<Result<(), AuthorityRuntimeError>>,
    crate::service::SshEnrollmentProbe,
) {
    let (probe_tx, probe_rx) = oneshot::channel();
    let (shutdown, server) = start_listening_authority(
        config,
        store,
        catalog(),
        crate::service::AuthorityRuntimeAdapters {
            ssh_enrollment: Some(probe_tx),
            ..Default::default()
        },
    )
    .await;
    let probe = probe_rx
        .await
        .expect("the authority sends its SSH enrollment probe");
    (shutdown, server, probe)
}

/// Waits until `count` SSH enrollments hold a worker. The bound only turns a
/// request that never arrives into a failure; it is not a timing guess.
async fn wait_for_ssh_admission(probe: &crate::service::SshEnrollmentProbe, count: usize) {
    wait_on_ssh(probe, "SSH enrollments admitted", |probe| {
        probe.admitted() >= count
    })
    .await;
}

/// Waits, bounded, on the enrollment workers' own state, never on a clock.
async fn wait_on_ssh(
    probe: &crate::service::SshEnrollmentProbe,
    what: &str,
    until: impl Fn(&crate::service::SshEnrollmentProbe) -> bool,
) {
    tokio::time::timeout(Duration::from_secs(30), async {
        while !until(probe) {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("not seen: {what}"));
}

/// The start helpers return only once the authority listens, so one connect
/// either succeeds or reports why.
async fn connect_when_ready(config: &AuthorityRuntimeConfig) -> LocalCredentialClient {
    LocalCredentialClient::connect(config)
        .await
        .unwrap_or_else(|error| panic!("the listening authority refused a client: {error}"))
}

#[tokio::test(flavor = "multi_thread")]
async fn rotation_rpc_requires_an_exact_positive_revision_and_clears_account_hint() {
    let temp = tempfile::tempdir().unwrap();
    let config = runtime_config(&temp);
    let store = TestProtectedStore::default();
    let (shutdown, task) = start_server(config.clone(), store.clone()).await;
    let mut client = connect_when_ready(&config).await;
    let credential = client
        .add_credential(
            NewCredential {
                provider: provider("openai"),
                authentication_kind: CredentialAuthKind::OAuth,
                display_name: "reconnect-codex".into(),
                account_hint: Some("old@example.test".into()),
                expires_at_unix: Some(4_102_444_800),
            },
            ProtectedValue::from_slice(FIRST_MATERIAL).unwrap(),
        )
        .await
        .unwrap();
    let profile = client
        .create_profile(
            &AccessProfileName::parse("reconnect-profile").unwrap(),
            &BTreeMap::from([(CapabilitySlot::codex(), credential.metadata.id.clone())]),
        )
        .await
        .unwrap();
    let revoked = client
        .revoke_credential(&credential.metadata.id)
        .await
        .unwrap();
    for (revision, expected_code) in [
        (0, Code::InvalidArgument),
        (
            credential.metadata.revocation_generation,
            Code::FailedPrecondition,
        ),
    ] {
        let error = client
            .rotate_credential_material(
                &credential.metadata.id,
                revision,
                ProtectedValue::from_slice(SECOND_MATERIAL).unwrap(),
                None,
                Some("not-committed@example.test".into()),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code(), expected_code);
        assert!(!error.message().contains("synthetic"));
        if revision != 0 {
            assert_eq!(
                error.message(),
                "local credential revision changed; inspect before retrying"
            );
        }
        assert_eq!(
            client
                .get_credential(&credential.metadata.id)
                .await
                .unwrap(),
            revoked
        );
        assert_eq!(store.values(), vec![FIRST_MATERIAL.to_vec()]);
    }
    let reconnected = client
        .rotate_credential_material(
            &revoked.metadata.id,
            revoked.metadata.revocation_generation,
            ProtectedValue::from_slice(SECOND_MATERIAL).unwrap(),
            revoked.metadata.expires_at_unix,
            None,
        )
        .await
        .unwrap();
    assert_eq!(reconnected.metadata.id, credential.metadata.id);
    assert_eq!(reconnected.metadata.status, CredentialStatus::Active);
    assert_eq!(reconnected.metadata.account_hint, None);
    assert_eq!(
        reconnected.metadata.expires_at_unix,
        credential.metadata.expires_at_unix
    );
    assert_eq!(
        reconnected.metadata.revocation_generation,
        revoked.metadata.revocation_generation + 1
    );
    assert_eq!(store.values(), vec![SECOND_MATERIAL.to_vec()]);
    assert_eq!(
        client.get_profile(&profile.profile.id).await.unwrap(),
        profile
    );
    assert_eq!(
        client
            .list_profile_revisions(&profile.profile.id)
            .await
            .unwrap()
            .len(),
        1
    );
    let request = v1::RotateCredentialMaterialRequest {
        credential_id: credential.metadata.id.to_string(),
        expected_revocation_generation: reconnected.metadata.revocation_generation,
        material: SECOND_MATERIAL.to_vec(),
        expires_at_unix: None,
        account_hint: None,
    };
    let rendered = format!("{request:?}");
    assert!(rendered.contains("[REDACTED]"));
    assert!(!rendered.contains(std::str::from_utf8(SECOND_MATERIAL).unwrap()));
    shutdown.send(()).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn ssh_enrollment_rpcs_return_only_derived_public_metadata() {
    let temp = tempfile::tempdir().unwrap();
    let config = runtime_config(&temp);
    let store = TestProtectedStore::default();
    let (shutdown, task) = start_server(config.clone(), store.clone()).await;
    let mut client = connect_when_ready(&config).await;

    let generated = client
        .generate_ssh_credential("generated-ssh".into(), Some(4_102_444_800))
        .await
        .unwrap();
    assert_eq!(generated.metadata.provider, provider("ssh"));
    assert_eq!(
        generated.metadata.authentication_kind,
        CredentialAuthKind::SshKey
    );
    assert_eq!(generated.metadata.account_hint, None);
    assert_eq!(generated.metadata.revocation_generation, 1);
    let generated_public = generated
        .metadata
        .ssh_public_key
        .as_ref()
        .expect("generated public key");
    assert!(generated_public.openssh.starts_with("ssh-ed25519 "));
    assert!(generated_public.fingerprint.starts_with("SHA256:"));

    let prepared = generate_ed25519().expect("synthetic imported key");
    let expected_openssh = prepared.public_key().openssh().to_string();
    let expected_fingerprint = prepared.public_key().fingerprint().to_string();
    let (_, protected) = prepared.into_parts();
    let imported_material = decode_protected_material(protected).unwrap();
    let (private_key, passphrase) = imported_material.into_parts();
    let imported = client
        .add_ssh_credential("imported-ssh".into(), private_key, passphrase, None)
        .await
        .unwrap();
    let imported_public = imported
        .metadata
        .ssh_public_key
        .expect("imported public key");
    assert_eq!(imported_public.openssh, expected_openssh);
    assert_eq!(imported_public.fingerprint, expected_fingerprint);
    assert_eq!(store.values().len(), 2);

    let before = store.values();
    let invalid = client
        .add_ssh_credential(
            "invalid-ssh".into(),
            Zeroizing::new(b"synthetic invalid private key".to_vec()),
            None,
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(invalid.code(), Code::InvalidArgument);
    assert_eq!(store.values(), before);

    let invalid_name = client
        .generate_ssh_credential(" invalid-name".into(), None)
        .await
        .unwrap_err();
    assert_eq!(invalid_name.code(), Code::InvalidArgument);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    for (name, expiry) in [
        ("zero", 0),
        ("past", now.saturating_sub(1)),
        ("current", now),
        ("overflow", u64::MAX),
    ] {
        let invalid_expiry = client
            .add_ssh_credential(
                format!("invalid-expiry-{name}"),
                Zeroizing::new(b"this invalid key must not be parsed".to_vec()),
                None,
                Some(expiry),
            )
            .await
            .unwrap_err();
        assert_eq!(invalid_expiry.code(), Code::InvalidArgument);
        assert_eq!(
            invalid_expiry.message(),
            "SSH credential expiry must be a future Unix timestamp"
        );
    }
    assert_eq!(store.values(), before);

    let generic = client
        .add_credential(
            NewCredential {
                provider: provider("ssh"),
                authentication_kind: CredentialAuthKind::SshKey,
                display_name: "generic-ssh".into(),
                account_hint: None,
                expires_at_unix: None,
            },
            ProtectedValue::from_slice(b"synthetic generic SSH material").unwrap(),
        )
        .await
        .unwrap_err();
    assert_eq!(generic.code(), Code::FailedPrecondition);
    assert_eq!(store.values(), before);

    let private_canary = b"synthetic-private-key-debug-canary";
    let passphrase_canary = b"synthetic-passphrase-debug-canary";
    let rendered = format!(
        "{:?}",
        v1::AddSshCredentialRequest {
            name: "debug-ssh".into(),
            private_key: private_canary.to_vec(),
            passphrase: Some(passphrase_canary.to_vec()),
            expires_at_unix: None,
        }
    );
    assert!(rendered.contains("[REDACTED]"));
    assert!(!rendered.contains(std::str::from_utf8(private_canary).unwrap()));
    assert!(!rendered.contains(std::str::from_utf8(passphrase_canary).unwrap()));

    shutdown.send(()).unwrap();
    task.await.unwrap().unwrap();
}

/// Shutdown during the first enrollment's write publishes neither: its checks
/// run again at publication (#5413), and the second never wrote. No material.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shutdown_during_an_enrollment_write_publishes_neither_enrollment() {
    let temp = tempfile::tempdir().unwrap();
    let config = runtime_config(&temp);
    let store = TestProtectedStore::default();
    let put_block = store.block_puts();
    let (shutdown, server, mut probe) =
        start_server_with_ssh_probe(config.clone(), store.clone()).await;
    let mut first_client = connect_when_ready(&config).await;
    let mut first = tokio::spawn(async move {
        first_client
            .generate_ssh_credential("first-ssh".into(), None)
            .await
    });
    store.wait_for_put(&mut first).await;

    let mut second_client = connect_when_ready(&config).await;
    let second = tokio::spawn(async move {
        second_client
            .generate_ssh_credential("cancelled-ssh".into(), None)
            .await
    });
    // Both were admitted before shutdown. Every put stays blocked until
    // shutdown has closed publication, so neither can publish.
    wait_for_ssh_admission(&probe, 2).await;
    shutdown.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(30), probe.stopping())
        .await
        .expect("shutdown did not close SSH enrollment publication");
    drop(put_block);
    server.await.unwrap().unwrap();
    let _ = first.await;
    let _ = second.await;

    let authority = LocalCredentialAuthority::open(&config.root, store.clone(), catalog()).unwrap();
    assert!(authority.list_credentials().unwrap().is_empty());
    assert!(store.values().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ninth_concurrent_ssh_enrollment_fails_fast_without_queued_material() {
    let temp = tempfile::tempdir().unwrap();
    let config = runtime_config(&temp);
    let store = TestProtectedStore::default();
    let put_block = store.block_puts();
    let (shutdown, server, probe) =
        start_server_with_ssh_probe(config.clone(), store.clone()).await;
    let mut clients = Vec::new();
    for _ in 0..9 {
        clients.push(connect_when_ready(&config).await);
    }

    let mut requests = Vec::new();
    let mut first_client = clients.remove(0);
    requests.push(tokio::spawn(async move {
        first_client
            .generate_ssh_credential("ssh-worker-0".into(), None)
            .await
    }));
    store.wait_for_put(&mut requests[0]).await;
    for (index, mut client) in clients.drain(..7).enumerate() {
        requests.push(tokio::spawn(async move {
            client
                .generate_ssh_credential(format!("ssh-worker-{}", index + 1), None)
                .await
        }));
    }
    wait_for_ssh_admission(&probe, 8).await;

    let error = clients
        .pop()
        .unwrap()
        .generate_ssh_credential("ssh-worker-overflow".into(), None)
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::ResourceExhausted);
    assert_eq!(store.values().len(), 0);

    drop(put_block);
    for request in requests {
        request.await.unwrap().unwrap();
    }
    assert_eq!(store.values().len(), 8);
    shutdown.send(()).unwrap();
    server.await.unwrap().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn owner_only_rpc_keeps_material_out_of_metadata_and_recovers_process_loss() {
    let temp = tempfile::tempdir().unwrap();
    let config = runtime_config(&temp);
    let store = TestProtectedStore::default();
    let (shutdown, task) = start_server(config.clone(), store.clone()).await;
    let mut client = connect_when_ready(&config).await;
    assert_eq!(
        client.info(),
        AuthorityInfo {
            protocol_version: AUTHORITY_PROTOCOL_VERSION,
            protected_store_persistence: ProtectedStorePersistence::ProcessLifetime,
            protected_store: None,
            // This server has no broker spawner, so it starts no brokers.
            broker_runner_protocol: None,
        }
    );

    let credential = client
        .add_credential(
            NewCredential {
                provider: provider("openai"),
                authentication_kind: CredentialAuthKind::OAuth,
                display_name: "work-codex".into(),
                account_hint: Some("work@example.test".into()),
                expires_at_unix: Some(4_102_444_800),
            },
            ProtectedValue::from_slice(FIRST_MATERIAL).unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(credential.metadata.display_name, "work-codex");
    assert_eq!(store.values(), vec![FIRST_MATERIAL.to_vec()]);

    let profile = client
        .create_profile(
            &AccessProfileName::parse("work").unwrap(),
            &BTreeMap::from([(CapabilitySlot::codex(), credential.metadata.id.clone())]),
        )
        .await
        .unwrap();
    assert_eq!(profile.profile.revision, 1);
    assert_eq!(
        client
            .resolve_profile(&"user/work".parse::<AccessProfileReference>().unwrap())
            .await
            .unwrap()
            .profile
            .id,
        profile.profile.id
    );

    let incompatible = client
        .update_profile(
            &profile.profile.id,
            profile.profile.revision,
            &BTreeMap::from([(
                CapabilitySlot::parse("anthropic").unwrap(),
                credential.metadata.id.clone(),
            )]),
        )
        .await
        .unwrap_err();
    assert_eq!(incompatible.code(), Code::FailedPrecondition);
    assert_eq!(
        incompatible.message(),
        "provider openai does not support slot anthropic with this authentication kind"
    );
    assert!(!incompatible.message().contains("synthetic"));

    let in_use = client
        .delete_credential(&credential.metadata.id)
        .await
        .unwrap_err();
    assert_eq!(in_use.code(), Code::FailedPrecondition);
    assert!(!in_use.message().contains("synthetic"));

    let rotated = client
        .rotate_credential_material(
            &credential.metadata.id,
            credential.metadata.revocation_generation,
            ProtectedValue::from_slice(SECOND_MATERIAL).unwrap(),
            Some(4_102_444_801),
            Some("reconnected@example.test".into()),
        )
        .await
        .unwrap();
    assert_eq!(rotated.metadata.revocation_generation, 2);
    assert_eq!(rotated.metadata.id, credential.metadata.id);
    assert_eq!(
        rotated.metadata.account_hint.as_deref(),
        Some("reconnected@example.test")
    );
    assert_eq!(rotated.metadata.expires_at_unix, Some(4_102_444_801));
    assert_eq!(store.values(), vec![SECOND_MATERIAL.to_vec()]);
    assert_eq!(
        client
            .list_profile_revisions(&profile.profile.id)
            .await
            .unwrap()
            .len(),
        1
    );
    let revoked = client
        .revoke_credential(&credential.metadata.id)
        .await
        .unwrap();
    assert_eq!(revoked.metadata.status, CredentialStatus::Revoked);

    let rendered = format!(
        "{:?}",
        v1::AddCredentialRequest {
            provider: "openai".into(),
            authentication_kind: v1::CredentialAuthenticationKind::Oauth as i32,
            display_name: "debug-proof".into(),
            account_hint: None,
            expires_at_unix: None,
            material: FIRST_MATERIAL.to_vec(),
        }
    );
    assert!(
        !rendered
            .as_bytes()
            .windows(FIRST_MATERIAL.len())
            .any(|value| value == FIRST_MATERIAL)
    );
    assert!(!format!("{client:?}").contains("synthetic"));

    shutdown.send(()).unwrap();
    task.await.unwrap().unwrap();
    assert!(!config.socket().exists());
    drop(client);
    drop(store);

    // A new process-lifetime store has no material. Reconciliation preserves
    // metadata but marks the identity expired rather than pretending it works.
    let empty_store = TestProtectedStore::default();
    let (shutdown, task) = start_server(config.clone(), empty_store).await;
    let mut client = connect_when_ready(&config).await;
    let recovered = client
        .get_credential(&credential.metadata.id)
        .await
        .unwrap();
    assert_eq!(recovered.metadata.status, CredentialStatus::Expired);
    move_default_away(&mut client).await;
    client.delete_profile(&profile.profile.id).await.unwrap();
    client
        .delete_credential(&credential.metadata.id)
        .await
        .unwrap();
    shutdown.send(()).unwrap();
    task.await.unwrap().unwrap();

    let database = fs::read(config.root.join(DATABASE_FILE)).unwrap();
    for material in [FIRST_MATERIAL, SECOND_MATERIAL] {
        assert!(
            !database
                .windows(material.len())
                .any(|value| value == material)
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn owner_rpc_streams_only_public_output_from_one_github_executor_lease() {
    prepare_github_repository_taking(0, None).await;
}

/// A fetch that outlasts the control deadline still completes: the
/// preparation call has its own, longer deadline (#2499). The control client
/// here has a 5 s deadline, so the 6 s fetch passes it without waiting out
/// the real one (#5311); 5 s also leaves its handshake room on a loaded
/// machine.
#[tokio::test(flavor = "multi_thread")]
async fn repository_preparation_outlasts_the_control_request_deadline() {
    prepare_github_repository_taking(6, Some(Duration::from_secs(5))).await;
}

async fn prepare_github_repository_taking(work_seconds: u32, control_deadline: Option<Duration>) {
    let temp = tempfile::tempdir().unwrap();
    let config = runtime_config(&temp);
    let store = TestProtectedStore::default();
    let (material_tx, mut material_rx) = tokio::sync::mpsc::unbounded_channel();
    let spawner = Arc::new(TestRepositorySpawner {
        leased_material: material_tx,
        tasks: Arc::new(Mutex::new(Vec::new())),
        refresh_to: None,
        work_seconds,
    });
    let (shutdown, task) =
        start_server_with_repository_spawner(config.clone(), store, spawner).await;
    let mut client = connect_when_ready(&config).await;
    let token = b"synthetic-private-github-token";
    let _connection = client
        .add_credential(
            NewCredential {
                provider: provider("github"),
                authentication_kind: CredentialAuthKind::OAuth,
                display_name: "github-work".to_owned(),
                account_hint: None,
                expires_at_unix: None,
            },
            ProtectedValue::from_slice(token).unwrap(),
        )
        .await
        .unwrap();
    let profile = client
        .create_profile(
            &AccessProfileName::parse("github-work").unwrap(),
            &BTreeMap::new(),
        )
        .await
        .unwrap();
    let mut control = match control_deadline {
        Some(deadline) => {
            LocalCredentialControlClient::connect_with_request_deadline(&config, deadline).await
        }
        None => LocalCredentialControlClient::connect(&config).await,
    }
    .unwrap();
    let mut prepared = control
        .prepare_git_repository(
            Uuid::new_v4(),
            &profile.profile.id,
            profile.profile.revision,
            "https://github.com/codewire/codewire.git".to_owned(),
            "main".to_owned(),
            String::new(),
            Vec::new(),
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(prepared.branch, "main");
    assert_eq!(prepared.commit.len(), 40);
    let mut bundle = Vec::new();
    while let Some(chunk) = prepared.next_bundle_chunk().await.unwrap() {
        bundle.extend_from_slice(&chunk);
    }
    assert_eq!(u64::try_from(bundle.len()).unwrap(), prepared.bundle_size);
    assert!(!bundle.windows(token.len()).any(|window| window == token));
    assert_eq!(material_rx.recv().await.unwrap(), token);

    shutdown.send(()).unwrap();
    task.await.unwrap().unwrap();
}

/// A checkout whose GitHub login is due refreshes it through the lease channel
/// and the shared journal, then leases the rotated generation.
#[tokio::test(flavor = "multi_thread")]
async fn a_checkout_refreshes_a_due_github_login_through_the_authority_journal() {
    let temp = tempfile::tempdir().unwrap();
    let config = runtime_config(&temp);
    let store = TestProtectedStore::default();
    let (material_tx, mut material_rx) = tokio::sync::mpsc::unbounded_channel();
    let spawner = Arc::new(TestRepositorySpawner {
        leased_material: material_tx,
        tasks: Arc::new(Mutex::new(Vec::new())),
        refresh_to: Some(b"rotated-github-app-bundle"),
        work_seconds: 0,
    });
    let (shutdown, task) =
        start_server_with_repository_spawner(config.clone(), store, spawner).await;
    let mut client = connect_when_ready(&config).await;
    let token = b"synthetic-private-github-token";
    let _connection = client
        .add_credential(
            NewCredential {
                provider: provider("github"),
                authentication_kind: CredentialAuthKind::OAuth,
                display_name: "github-work".to_owned(),
                account_hint: None,
                expires_at_unix: None,
            },
            ProtectedValue::from_slice(token).unwrap(),
        )
        .await
        .unwrap();
    let profile = client
        .create_profile(
            &AccessProfileName::parse("github-work").unwrap(),
            &BTreeMap::new(),
        )
        .await
        .unwrap();
    let mut control = LocalCredentialControlClient::connect(&config)
        .await
        .unwrap();
    let mut prepared = control
        .prepare_git_repository(
            Uuid::new_v4(),
            &profile.profile.id,
            profile.profile.revision,
            "https://github.com/codewire/codewire.git".to_owned(),
            "main".to_owned(),
            String::new(),
            Vec::new(),
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(prepared.branch, "main");
    assert_eq!(prepared.commit.len(), 40);
    let mut bundle = Vec::new();
    while let Some(chunk) = prepared.next_bundle_chunk().await.unwrap() {
        bundle.extend_from_slice(&chunk);
    }
    assert_eq!(u64::try_from(bundle.len()).unwrap(), prepared.bundle_size);
    assert!(!bundle.windows(token.len()).any(|window| window == token));
    assert_eq!(material_rx.recv().await.unwrap(), token);
    assert_eq!(material_rx.recv().await.unwrap(), b"second-lease-denied");
    // Git would send only the refreshed login, admitted again by the authority,
    // and the post-checkout check accepted this channel's own refresh.
    assert_eq!(
        material_rx.recv().await.unwrap(),
        b"rotated-github-app-bundle"
    );
    let refreshed = client
        .get_credential(&_connection.metadata.id)
        .await
        .unwrap();
    assert_eq!(refreshed.metadata.revocation_generation, 2);

    shutdown.send(()).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn owner_only_rpc_persists_exact_bindings_and_returns_material_free_grants() {
    let temp = tempfile::tempdir().unwrap();
    let config = runtime_config(&temp);
    let store = TestProtectedStore::default();
    let (shutdown, task) = start_server(config.clone(), store).await;
    let mut client = connect_when_ready(&config).await;
    let credential = client
        .add_credential(
            NewCredential {
                provider: provider("openai"),
                authentication_kind: CredentialAuthKind::OAuth,
                display_name: "bound-codex".into(),
                account_hint: Some("bound@example.test".into()),
                expires_at_unix: Some(4_102_444_800),
            },
            ProtectedValue::from_slice(FIRST_MATERIAL).unwrap(),
        )
        .await
        .unwrap();
    let entries = BTreeMap::from([(CapabilitySlot::codex(), credential.metadata.id.clone())]);
    let profile = client
        .create_profile(&AccessProfileName::parse("bound").unwrap(), &entries)
        .await
        .unwrap();
    let environment_id = EnvironmentId::parse("env-bound").unwrap();
    let binding = EnvironmentAccessBinding {
        environment_id: environment_id.clone(),
        profile_id: profile.profile.id.clone(),
        profile_revision: profile.profile.revision,
    };
    let mut control = LocalCredentialControlClient::connect(&config)
        .await
        .unwrap();
    let created = control
        .ensure_environment_access_binding(
            &binding,
            &"user/bound".parse::<AccessProfileReference>().unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(created.binding, binding);
    assert_eq!(
        client
            .create_environment_access_binding(&binding)
            .await
            .unwrap_err()
            .code(),
        Code::AlreadyExists
    );
    assert_eq!(
        client
            .get_environment_access_binding(&environment_id)
            .await
            .unwrap(),
        created
    );
    assert_eq!(
        client.list_environment_access_bindings().await.unwrap(),
        vec![created.clone()]
    );
    assert_eq!(control.info(), client.info());
    assert_eq!(
        control
            .ensure_environment_access_binding(
                &binding,
                &"user/bound".parse::<AccessProfileReference>().unwrap(),
            )
            .await
            .unwrap(),
        created
    );
    assert_eq!(
        control
            .ensure_environment_access_binding(
                &binding,
                &"organization/bound"
                    .parse::<AccessProfileReference>()
                    .unwrap(),
            )
            .await
            .unwrap_err()
            .code(),
        Code::FailedPrecondition
    );
    let grants = client
        .evaluate_environment_grants(&environment_id, 41)
        .await
        .unwrap();
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].environment_generation, 41);
    assert_eq!(grants[0].credential_id, credential.metadata.id);
    let rendered = format!("{grants:?}");
    assert!(!rendered.contains("synthetic"));
    assert!(!rendered.contains("protected_entry"));

    let updated = client
        .update_profile(&profile.profile.id, profile.profile.revision, &entries)
        .await
        .unwrap();
    let updated_binding = EnvironmentAccessBinding {
        environment_id: environment_id.clone(),
        profile_id: profile.profile.id.clone(),
        profile_revision: updated.profile.revision,
    };
    assert_eq!(
        control
            .ensure_environment_access_binding(
                &updated_binding,
                &"user/bound".parse::<AccessProfileReference>().unwrap(),
            )
            .await
            .unwrap_err()
            .code(),
        Code::FailedPrecondition
    );
    let reference = "user/bound".parse::<AccessProfileReference>().unwrap();
    let replaced = control
        .apply_environment_access_binding(
            &environment_id,
            Some(&binding),
            Some((&updated_binding, &reference)),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(replaced.binding.profile_revision, updated.profile.revision);
    assert_eq!(
        control
            .apply_environment_access_binding(
                &environment_id,
                Some(&binding),
                Some((&updated_binding, &reference)),
            )
            .await
            .unwrap()
            .unwrap()
            .binding,
        updated_binding
    );
    assert_eq!(
        control
            .apply_environment_access_binding(
                &environment_id,
                Some(&binding),
                Some((&binding, &reference)),
            )
            .await
            .unwrap_err()
            .code(),
        Code::FailedPrecondition
    );
    assert_eq!(
        client
            .delete_profile(&profile.profile.id)
            .await
            .unwrap_err()
            .code(),
        Code::FailedPrecondition
    );
    assert!(
        control
            .apply_environment_access_binding(&environment_id, Some(&updated_binding), None)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        control
            .apply_environment_access_binding(&environment_id, Some(&updated_binding), None)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        control
            .apply_environment_access_binding(
                &environment_id,
                None,
                Some((&updated_binding, &reference)),
            )
            .await
            .unwrap()
            .unwrap()
            .binding,
        updated_binding
    );
    assert_eq!(
        control
            .apply_environment_access_binding(
                &environment_id,
                None,
                Some((&updated_binding, &reference)),
            )
            .await
            .unwrap()
            .unwrap()
            .binding,
        updated_binding
    );

    shutdown.send(()).unwrap();
    task.await.unwrap().unwrap();
    drop(client);
    drop(control);

    let (shutdown, task) = start_server(config.clone(), TestProtectedStore::default()).await;
    let mut client = connect_when_ready(&config).await;
    assert_eq!(
        client
            .get_environment_access_binding(&environment_id)
            .await
            .unwrap()
            .binding,
        replaced.binding
    );
    let mut control = LocalCredentialControlClient::connect(&config)
        .await
        .unwrap();
    assert!(
        control
            .apply_environment_access_binding(&environment_id, Some(&updated_binding), None)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        control
            .apply_environment_access_binding(&environment_id, Some(&updated_binding), None)
            .await
            .unwrap()
            .is_none()
    );
    control
        .delete_environment_access_binding_if_present(&environment_id)
        .await
        .unwrap();
    control
        .delete_environment_access_binding_if_present(&environment_id)
        .await
        .unwrap();
    move_default_away(&mut client).await;
    client.delete_profile(&profile.profile.id).await.unwrap();
    shutdown.send(()).unwrap();
    task.await.unwrap().unwrap();

    let database = fs::read(config.root.join(DATABASE_FILE)).unwrap();
    assert!(
        !database
            .windows(FIRST_MATERIAL.len())
            .any(|value| value == FIRST_MATERIAL)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn connect_or_start_reuses_the_admitted_authority_without_spawning() {
    let temp = tempfile::tempdir().unwrap();
    let config = runtime_config(&temp);
    let (shutdown, task) = start_server(config.clone(), TestProtectedStore::default()).await;
    let client = connect_when_ready(&config).await;
    drop(client);

    let admitted = LocalCredentialClient::admit_existing_or_replace_with(&config, |_| {
        panic!("an admitted authority must not spawn a replacement")
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(admitted.info().protocol_version, AUTHORITY_PROTOCOL_VERSION);
    drop(admitted);

    let client = LocalCredentialClient::connect_or_start_with(
        &config,
        |_| -> Result<Child, AuthorityRuntimeError> {
            panic!("an admitted authority must not spawn a replacement")
        },
    )
    .await
    .unwrap();
    assert_eq!(client.info().protocol_version, AUTHORITY_PROTOCOL_VERSION);
    client.shutdown().await.unwrap();
    task.await.unwrap().unwrap();
    drop(shutdown);
    assert!(!config.socket().exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn existing_authority_admission_skips_an_absent_socket_without_spawning() {
    let temp = tempfile::tempdir().unwrap();
    let config = runtime_config(&temp);
    assert!(
        LocalCredentialClient::admit_existing_or_replace_with(&config, |_| {
            panic!("an absent authority must not spawn")
        })
        .await
        .unwrap()
        .is_none()
    );
    assert!(!config.root.exists());
}

/// An authority running as a task in this test process.
/// Like a dropped `Child`, dropping it leaves the authority running.
struct InProcessAuthority;

impl SpawnedAuthority for InProcessAuthority {
    fn try_wait(&mut self) -> io::Result<Option<std::process::ExitStatus>> {
        Ok(None)
    }

    fn kill(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn wait(&mut self) -> io::Result<std::process::ExitStatus> {
        Ok(std::os::unix::process::ExitStatusExt::from_raw(0))
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_dead_authority_socket_is_absent_for_admission_and_replaced_on_start() {
    let temp = tempfile::tempdir().unwrap();
    let config = runtime_config(&temp);
    config.prepare_root().unwrap();
    let listener = std::os::unix::net::UnixListener::bind(config.socket()).unwrap();
    fs::set_permissions(config.socket(), fs::Permissions::from_mode(0o600)).unwrap();
    drop(listener);
    let before = fs::symlink_metadata(config.socket()).unwrap();

    // Admission alone treats a socket nothing listens on as absent and leaves it.
    assert!(
        LocalCredentialClient::admit_existing_or_replace_with(&config, |_| {
            panic!("admission must not spawn")
        })
        .await
        .unwrap()
        .is_none()
    );
    let after = fs::symlink_metadata(config.socket()).unwrap();
    assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));

    // A start launches a new authority, which takes the lock and only then
    // replaces the dead socket.
    let (shutdown, shutdown_rx) = oneshot::channel::<()>();
    let mut server = None;
    let client = LocalCredentialClient::connect_or_start_with(&config, |config| {
        let config = config.clone();
        server = Some(tokio::spawn(async move {
            serve_until(
                config,
                TestProtectedStore::default(),
                catalog(),
                async move {
                    let _ = shutdown_rx.await;
                },
            )
            .await
        }));
        Ok(InProcessAuthority)
    })
    .await
    .unwrap();
    // The new authority answers where nothing listened before. (A freed
    // inode number can be reused, so the socket's inode proves nothing.)
    assert_eq!(client.info().protocol_version, AUTHORITY_PROTOCOL_VERSION);
    client.shutdown().await.unwrap();
    server.unwrap().await.unwrap().unwrap();
    drop(shutdown);
}

#[tokio::test(flavor = "multi_thread")]
async fn existing_authority_admission_rejects_an_invalid_socket_without_spawning() {
    let temp = tempfile::tempdir().unwrap();
    let config = runtime_config(&temp);
    config.prepare_root().unwrap();
    fs::write(config.socket(), b"not a socket").unwrap();
    fs::set_permissions(config.socket(), fs::Permissions::from_mode(0o600)).unwrap();

    let error = LocalCredentialClient::admit_existing_or_replace_with(&config, |_| {
        panic!("an invalid authority socket must not spawn")
    })
    .await
    .unwrap_err();
    assert!(matches!(error, AuthorityRuntimeError::InvalidPrivateSocket));
    let error = LocalCredentialClient::connect_or_start_with(
        &config,
        |_| -> Result<Child, AuthorityRuntimeError> {
            panic!("a present invalid endpoint must not grant replacement permission")
        },
    )
    .await
    .unwrap_err();
    assert!(matches!(error, AuthorityRuntimeError::InvalidPrivateSocket));
    assert_eq!(fs::read(config.socket()).unwrap(), b"not a socket");
}

const COMPATIBILITY_FIXTURE_ROOT: &str = "CW_AUTHORITY_COMPATIBILITY_FIXTURE_ROOT";
const COMPATIBILITY_FIXTURE_MODE: &str = "CW_AUTHORITY_COMPATIBILITY_FIXTURE_MODE";
const COMPATIBILITY_INFO_ROUTE: &str =
    "/codewire.local.credentials.v1.LocalCredentialAuthorityService/GetAuthorityInfo";
const COMPATIBILITY_SHUTDOWN_ROUTE: &str =
    "/codewire.local.credentials.v1.LocalCredentialAuthorityService/ShutdownAuthority";

/// This service has no protected store or provider operations. It deliberately
/// speaks an older protocol, or refuses info, while observing all received RPCs.
#[derive(Clone)]
struct CompatibilityAuthorityService {
    unavailable: bool,
    requests: Arc<Mutex<Vec<String>>>,
    request_log: std::path::PathBuf,
    shutdown: tokio::sync::watch::Sender<bool>,
}

impl tonic::server::NamedService for CompatibilityAuthorityService {
    const NAME: &'static str = v1::local_credential_authority_service_server::SERVICE_NAME;
}

impl tonic::server::UnaryService<v1::GetAuthorityInfoRequest> for CompatibilityAuthorityService {
    type Response = v1::AuthorityInfo;
    type Future = tonic::codegen::BoxFuture<tonic::Response<Self::Response>, tonic::Status>;

    fn call(&mut self, _: tonic::Request<v1::GetAuthorityInfoRequest>) -> Self::Future {
        let unavailable = self.unavailable;
        Box::pin(async move {
            if unavailable {
                Err(tonic::Status::unavailable("synthetic info unavailable"))
            } else {
                Ok(tonic::Response::new(v1::AuthorityInfo {
                    // Below the supported range: an older authority within it
                    // is admitted.
                    protocol_version: MINIMUM_AUTHORITY_PROTOCOL_VERSION - 1,
                    protected_store_persistence: v1::ProtectedStorePersistence::ProcessLifetime
                        as i32,
                    protected_store_backend: String::new(),
                    broker_runner_protocol: 0,
                }))
            }
        })
    }
}

impl tonic::server::UnaryService<v1::ShutdownAuthorityRequest> for CompatibilityAuthorityService {
    type Response = v1::ShutdownAuthorityResponse;
    type Future = tonic::codegen::BoxFuture<tonic::Response<Self::Response>, tonic::Status>;

    fn call(&mut self, _: tonic::Request<v1::ShutdownAuthorityRequest>) -> Self::Future {
        // A regression requesting shutdown really stops this fixture, making
        // endpoint/process retention assertions fail in addition to the log.
        self.shutdown.send_replace(true);
        Box::pin(async { Ok(tonic::Response::new(v1::ShutdownAuthorityResponse {})) })
    }
}

impl tower::Service<http::Request<tonic::body::Body>> for CompatibilityAuthorityService {
    type Response = http::Response<tonic::body::Body>;
    type Error = std::convert::Infallible;
    type Future = tonic::codegen::BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(
        &mut self,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<tonic::body::Body>) -> Self::Future {
        let route = request.uri().path().to_owned();
        let mut requests = self.requests.lock().expect("synthetic request log lock");
        assert!(requests.len() < 8, "unexpected synthetic RPC replay");
        requests.push(route.clone());
        fs::write(&self.request_log, requests.join("\n")).expect("write synthetic request log");
        drop(requests);
        let method = self.clone();
        Box::pin(async move {
            let response = match route.as_str() {
                COMPATIBILITY_INFO_ROUTE => {
                    tonic::server::Grpc::new(tonic_prost::ProstCodec::<
                        v1::AuthorityInfo,
                        v1::GetAuthorityInfoRequest,
                    >::default())
                    .unary(method, request)
                    .await
                }
                COMPATIBILITY_SHUTDOWN_ROUTE => {
                    tonic::server::Grpc::new(tonic_prost::ProstCodec::<
                        v1::ShutdownAuthorityResponse,
                        v1::ShutdownAuthorityRequest,
                    >::default())
                    .unary(method, request)
                    .await
                }
                _ => {
                    let mut response = http::Response::new(tonic::body::Body::default());
                    response.headers_mut().insert(
                        tonic::Status::GRPC_STATUS,
                        (tonic::Code::Unimplemented as i32).into(),
                    );
                    response.headers_mut().insert(
                        http::header::CONTENT_TYPE,
                        tonic::metadata::GRPC_CONTENT_TYPE,
                    );
                    response
                }
            };
            Ok(response)
        })
    }
}

/// Selected only in an owned child. Ordinary execution does not bind a socket.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn compatibility_authority_process_fixture() {
    let Some(root) = std::env::var_os(COMPATIBILITY_FIXTURE_ROOT) else {
        return;
    };
    let mode = std::env::var(COMPATIBILITY_FIXTURE_MODE).expect("synthetic fixture mode");
    assert!(matches!(
        mode.as_str(),
        "protocol-mismatch" | "info-unavailable"
    ));
    let config = AuthorityRuntimeConfig {
        root: root.clone().into(),
        executable: fs::canonicalize(std::env::current_exe().unwrap()).unwrap(),
        socket_dir: root.into(),
    };
    let (incoming, identity) = bind_owner_only(&config).unwrap();
    let (shutdown, mut shutdown_rx) = tokio::sync::watch::channel(false);
    let service = CompatibilityAuthorityService {
        unavailable: mode == "info-unavailable",
        requests: Arc::new(Mutex::new(Vec::new())),
        request_log: config.root.join("synthetic-requests"),
        shutdown,
    };
    fs::write(config.root.join("synthetic-ready"), b"ready").unwrap();
    tonic::transport::Server::builder()
        .add_service(service)
        .serve_with_incoming_shutdown(incoming, async move {
            while !*shutdown_rx.borrow_and_update() {
                if shutdown_rx.changed().await.is_err() {
                    break;
                }
            }
        })
        .await
        .unwrap();
    remove_bound_socket(&config, &identity).unwrap();
}

struct CompatibilityAuthorityProcess {
    config: AuthorityRuntimeConfig,
    child: Child,
    temp: Option<tempfile::TempDir>,
}

impl Drop for CompatibilityAuthorityProcess {
    fn drop(&mut self) {
        let clean = match self.child.try_wait() {
            Ok(Some(_)) => true,
            Ok(None) => self.child.kill().is_ok() && self.child.wait().is_ok(),
            Err(_) => false,
        };
        if !clean && let Some(temp) = self.temp.take() {
            eprintln!(
                "retained unknown synthetic authority cleanup: {}",
                temp.keep().display()
            );
        }
    }
}

impl CompatibilityAuthorityProcess {
    async fn start(mode: &str) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let config = runtime_config(&temp);
        let child = Command::new(&config.executable)
            .args([
                "rpc_tests::compatibility_authority_process_fixture",
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ])
            .env_clear()
            .env(COMPATIBILITY_FIXTURE_ROOT, &config.root)
            .env(COMPATIBILITY_FIXTURE_MODE, mode)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn metadata-only synthetic authority");
        let mut fixture = Self {
            config,
            child,
            temp: Some(temp),
        };
        // The child writes its witness once its socket is bound, or exits:
        // wait for either, not for a wall clock that its start-up under load
        // can exceed.
        while !fixture.config.root.join("synthetic-ready").exists() {
            assert!(
                fixture.child.try_wait().unwrap().is_none(),
                "synthetic authority exited before readiness"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        fixture
    }
}

async fn assert_present_authority_refusal_retains_process(mode: &str) {
    let mut fixture = CompatibilityAuthorityProcess::start(mode).await;
    let config = fixture.config.clone();
    let pid = fixture.child.id();
    let before = fs::symlink_metadata(config.socket()).unwrap();
    let spawns = AtomicUsize::new(0);
    for (request_count, admission_only) in [(1, true), (2, false)] {
        let spawn = |_: &AuthorityRuntimeConfig| -> Result<Child, AuthorityRuntimeError> {
            spawns.fetch_add(1, Ordering::SeqCst);
            Err(AuthorityRuntimeError::Spawn)
        };
        // Admission carries the client's own connect and request bounds; no
        // shorter wall clock of the test's own sits over them.
        let error = if admission_only {
            LocalCredentialClient::admit_existing_or_replace_with(&config, spawn)
                .await
                .map(|_| ())
        } else {
            LocalCredentialClient::connect_or_start_with(&config, spawn)
                .await
                .map(|_| ())
        }
        .unwrap_err();
        if mode == "protocol-mismatch" {
            assert!(
                matches!(error, AuthorityRuntimeError::ProtocolMismatch),
                "{error:?}"
            );
        } else {
            assert!(matches!(error, AuthorityRuntimeError::Connect), "{error:?}");
        }
        assert_eq!(spawns.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.child.id(), pid);
        assert!(
            fixture.child.try_wait().unwrap().is_none(),
            "existing authority process was stopped"
        );
        let after = fs::symlink_metadata(config.socket()).unwrap();
        assert_eq!(
            (before.dev(), before.ino(), before.uid(), before.mode()),
            (after.dev(), after.ino(), after.uid(), after.mode())
        );
        let requests = fs::read_to_string(config.root.join("synthetic-requests")).unwrap();
        assert_eq!(
            requests.lines().collect::<Vec<_>>(),
            vec![COMPATIBILITY_INFO_ROUTE; request_count],
            "shutdown, replay or unrelated RPC was invoked"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn incompatible_authority_is_retained_without_shutdown_or_spawn() {
    assert_present_authority_refusal_retains_process("protocol-mismatch").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ambiguous_live_authority_is_retained_without_shutdown_or_spawn() {
    assert_present_authority_refusal_retains_process("info-unavailable").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn losing_launcher_waits_for_the_admitted_authority() {
    let temp = tempfile::tempdir().unwrap();
    let config = runtime_config(&temp);
    let delayed_config = config.clone();
    let task = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        serve_until(
            delayed_config,
            TestProtectedStore::default(),
            catalog(),
            std::future::pending(),
        )
        .await
    });

    let client = LocalCredentialClient::connect_or_start_with(&config, |_| {
        Command::new("/bin/sh")
            .args(["-c", "exit 0"])
            .spawn()
            .map_err(|_| AuthorityRuntimeError::Spawn)
    })
    .await
    .unwrap();
    assert_eq!(client.info().protocol_version, AUTHORITY_PROTOCOL_VERSION);
    client.shutdown().await.unwrap();
    task.await.unwrap().unwrap();
    assert!(!config.socket().exists());
}

/// A fresh authority asked for no placeholder still loads its key for an
/// intercepting boot's broker, which a boot whose only agent credential is a
/// sign-in needs (#3999): an ensure that carries boot secrets creates the key
/// before the broker starts; one that carries none leaves the store alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_intercepting_boots_broker_loads_the_placeholder_key_first() {
    let temp = tempfile::tempdir().unwrap();
    let config = runtime_config(&temp);
    let store = TestProtectedStore::default();
    let (material_tx, _material_rx) = tokio::sync::mpsc::unbounded_channel();
    let spawner = Arc::new(TestBrokerSpawner {
        store: store.clone(),
        launches: Arc::new(Mutex::new(Vec::new())),
        child_pids: Arc::new(Mutex::new(Vec::new())),
        tasks: Arc::new(Mutex::new(Vec::new())),
        leased_material: material_tx,
    });
    let (shutdown, server) = start_server_with_spawner(
        config.clone(),
        store.clone(),
        spawner as Arc<dyn LocalBrokerProcessSpawner>,
    )
    .await;
    let mut owner = connect_when_ready(&config).await;
    let credential = owner
        .add_credential(
            NewCredential {
                provider: provider("openai"),
                authentication_kind: CredentialAuthKind::OAuth,
                display_name: "synthetic-sign-in".into(),
                account_hint: None,
                expires_at_unix: None,
            },
            ProtectedValue::from_slice(FIRST_MATERIAL).unwrap(),
        )
        .await
        .unwrap();
    let profile = owner
        .create_profile(
            &AccessProfileName::parse("sign-in").unwrap(),
            &BTreeMap::from([(CapabilitySlot::codex(), credential.metadata.id.clone())]),
        )
        .await
        .unwrap();
    let key_stored = || {
        store
            .entries
            .lock()
            .unwrap()
            .keys()
            .any(|entry| entry.ends_with("/placeholder-key-v1"))
    };
    let mut control = LocalCredentialControlClient::connect(&config)
        .await
        .unwrap();
    for (generation, boot_secrets) in [
        (3, crate::BrokerBootSecrets::default()),
        (
            4,
            crate::BrokerBootSecrets::new([(
                crate::BootSecretPurpose::FrontDoorPairing,
                vec![0x2c; crate::BOOT_SECRET_BYTES],
            )])
            .unwrap(),
        ),
    ] {
        let environment_id = EnvironmentId::parse(uuid::Uuid::new_v4().to_string()).unwrap();
        let selected = EnvironmentAccessBinding {
            environment_id: environment_id.clone(),
            profile_id: profile.profile.id.clone(),
            profile_revision: profile.profile.revision,
        };
        owner
            .create_environment_access_binding(&selected)
            .await
            .unwrap();
        let intercepting = !boot_secrets.is_empty();
        control
            .ensure_environment_broker(
                &environment_id,
                generation,
                "dev",
                &temp.path().join(format!("runtime/{environment_id}.sock")),
                EnvironmentBrokerSelection {
                    local_profile: Some(selected),
                    boot_secrets,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(key_stored(), intercepting, "generation {generation}");
    }
    shutdown.send(()).unwrap();
    server.await.unwrap().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn authority_launches_one_generation_bound_broker_and_stops_it_exactly() {
    let temp = tempfile::tempdir().unwrap();
    let config = runtime_config(&temp);
    let store = TestProtectedStore::default();
    let launches = Arc::new(Mutex::new(Vec::new()));
    let child_pids = Arc::new(Mutex::new(Vec::new()));
    let tasks = Arc::new(Mutex::new(Vec::new()));
    let (material_tx, mut material_rx) = tokio::sync::mpsc::unbounded_channel();
    let spawner = Arc::new(TestBrokerSpawner {
        store: store.clone(),
        launches: Arc::clone(&launches),
        child_pids: Arc::clone(&child_pids),
        tasks: Arc::clone(&tasks),
        leased_material: material_tx,
    });
    let (shutdown, server) = start_server_with_spawner(
        config.clone(),
        store,
        spawner as Arc<dyn LocalBrokerProcessSpawner>,
    )
    .await;
    let mut owner = connect_when_ready(&config).await;
    let credential = owner
        .add_credential(
            NewCredential {
                provider: provider("openai"),
                authentication_kind: CredentialAuthKind::OAuth,
                display_name: "synthetic-broker".into(),
                account_hint: None,
                expires_at_unix: None,
            },
            ProtectedValue::from_slice(FIRST_MATERIAL).unwrap(),
        )
        .await
        .unwrap();
    let profile = owner
        .create_profile(
            &AccessProfileName::parse("broker").unwrap(),
            &BTreeMap::from([(CapabilitySlot::codex(), credential.metadata.id.clone())]),
        )
        .await
        .unwrap();
    let environment_id = EnvironmentId::parse(uuid::Uuid::new_v4().to_string()).unwrap();
    let selected_binding = EnvironmentAccessBinding {
        environment_id: environment_id.clone(),
        profile_id: profile.profile.id,
        profile_revision: profile.profile.revision,
    };
    owner
        .create_environment_access_binding(&selected_binding)
        .await
        .unwrap();
    let mut control = LocalCredentialControlClient::connect(&config)
        .await
        .unwrap();
    let runtime = control
        .ensure_environment_broker(
            &environment_id,
            23,
            "dev",
            &temp.path().join(format!("runtime/{environment_id}.sock")),
            EnvironmentBrokerSelection {
                local_profile: Some(selected_binding),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(
        runtime,
        EnvironmentBrokerRuntime {
            environment_id: environment_id.clone(),
            environment_generation: 23,
            running: true,
        }
    );
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), material_rx.recv())
            .await
            .unwrap()
            .unwrap(),
        FIRST_MATERIAL
    );
    let audit = owner
        .list_recent_broker_lease_audit_events(8)
        .await
        .unwrap();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].decision, BrokerLeaseAuditDecision::Admitted);
    assert_eq!(audit[0].environment_id, environment_id);
    assert_eq!(audit[0].environment_generation, 23);
    assert_eq!(
        audit[0].credential_id.as_ref(),
        Some(&credential.metadata.id)
    );
    assert!(!format!("{audit:?}").contains("synthetic-oauth-material"));
    {
        let launched = launches.lock().unwrap();
        assert_eq!(launched.len(), 1);
        assert_eq!(launched[0].environment_id, environment_id);
        assert_eq!(launched[0].environment_generation, 23);
        assert_eq!(
            launched[0].http_providers,
            std::collections::BTreeSet::from([codewire_access::HttpProvider::CodexOAuth])
        );
        assert!(!format!("{:?}", launched[0]).contains("synthetic-oauth-material"));
    }

    let first_pid = child_pids.lock().unwrap()[0];
    let first_pid = rustix::process::Pid::from_raw(first_pid as i32).unwrap();
    rustix::process::kill_process(first_pid, rustix::process::Signal::KILL).unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if launches.lock().unwrap().len() == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), material_rx.recv())
            .await
            .unwrap()
            .unwrap(),
        FIRST_MATERIAL
    );
    // A launch is recorded before spawn finishes. The lease reply proves the
    // replacement child and its authority channel are ready before counting it.
    assert_eq!(launches.lock().unwrap().len(), 2);
    assert_eq!(child_pids.lock().unwrap().len(), 2);
    let audit = owner
        .list_recent_broker_lease_audit_events(8)
        .await
        .unwrap();
    assert_eq!(audit.len(), 2);
    assert!(audit[0].sequence > audit[1].sequence);

    // The supervisor's material-free client reads one environment's
    // decisions, and none of another's.
    let mut control = LocalCredentialControlClient::connect(&config)
        .await
        .unwrap();
    let named = control
        .environment_lease_audit(&environment_id, 8)
        .await
        .unwrap();
    assert_eq!(named.events, audit);
    assert!(!named.crowded);
    let other = EnvironmentId::parse(uuid::Uuid::new_v4().to_string()).unwrap();
    let none = control.environment_lease_audit(&other, 8).await.unwrap();
    assert!(none.events.is_empty());
    assert!(!none.crowded);
    assert!(
        control
            .environment_lease_audit(&environment_id, 0)
            .await
            .is_err()
    );

    assert_eq!(
        control
            .stop_environment_broker(&environment_id, Some(22))
            .await
            .unwrap_err()
            .code(),
        Code::FailedPrecondition
    );
    control
        .stop_environment_broker(&environment_id, Some(23))
        .await
        .unwrap();
    shutdown.send(()).unwrap();
    server.await.unwrap().unwrap();
    for task in tasks.lock().unwrap().drain(..) {
        task.abort();
    }
}

/// The first child serves; every later one closes its lease channel before
/// it is ready, as a broker does once its environment's runner is gone.
#[derive(Clone)]
struct RunnerGoneBrokerSpawner {
    store: TestProtectedStore,
    child_pids: Arc<Mutex<Vec<u32>>>,
    tasks: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
}

impl LocalBrokerProcessSpawner for RunnerGoneBrokerSpawner {
    fn runner_protocol(&self) -> u32 {
        crate::broker_process::TEST_RUNNER_PROTOCOL
    }

    fn spawn(
        &self,
        config: &LocalBrokerProcessConfig,
        _: &crate::ProviderLookup,
        authority_peer: std::os::unix::net::UnixStream,
        _boot_secrets: &crate::BrokerBootSecrets,
    ) -> Result<tokio::process::Child, LocalBrokerSpawnError> {
        let child = tokio::process::Command::new("/bin/sleep")
            .arg("60")
            .kill_on_drop(true)
            .spawn()
            .map_err(|_| LocalBrokerSpawnError::Spawn)?;
        let first = {
            let mut pids = self
                .child_pids
                .lock()
                .map_err(|_| LocalBrokerSpawnError::Spawn)?;
            pids.push(child.id().ok_or(LocalBrokerSpawnError::Spawn)?);
            pids.len() == 1
        };
        if !first {
            drop(authority_peer);
            return Ok(child);
        }
        authority_peer
            .set_nonblocking(true)
            .map_err(|_| LocalBrokerSpawnError::Spawn)?;
        let stream =
            UnixStream::from_std(authority_peer).map_err(|_| LocalBrokerSpawnError::Spawn)?;
        let store = self.store.clone();
        let environment_id = config.environment_id.clone();
        let environment_generation = config.environment_generation;
        let task = tokio::spawn(async move {
            let ready = codewire_daemon_proto::codewire::bridge::v1::CredentialBridgeReady {
                protocol_version: codewire_daemon_proto::CREDENTIAL_BRIDGE_PROTOCOL_VERSION,
                environment_id: environment_id.to_string(),
                environment_generation,
            };
            let Ok(mut client) = LocalCredentialBrokerLeaseClient::connect(
                stream,
                store,
                environment_id,
                environment_generation,
            )
            .await
            else {
                return;
            };
            if client.report_ready(ready, Vec::new()).await.is_err() {
                return;
            }
            std::future::pending::<()>().await;
            drop(client);
        });
        self.tasks
            .lock()
            .map_err(|_| LocalBrokerSpawnError::Spawn)?
            .push(task);
        Ok(child)
    }
}

/// #2924: a broker that keeps failing is restarted while its environment
/// still selects it, and the stop its environment's removal sends ends that:
/// no child is spawned and nothing is logged for it afterwards.
#[tokio::test(flavor = "multi_thread")]
async fn a_failing_broker_restarts_until_its_environment_stops_it_and_never_after() {
    let temp = tempfile::tempdir().unwrap();
    let config = runtime_config(&temp);
    let store = TestProtectedStore::default();
    let child_pids = Arc::new(Mutex::new(Vec::new()));
    let tasks = Arc::new(Mutex::new(Vec::new()));
    let spawner = Arc::new(RunnerGoneBrokerSpawner {
        store: store.clone(),
        child_pids: Arc::clone(&child_pids),
        tasks: Arc::clone(&tasks),
    });
    let (shutdown, server) = start_server_with_spawner(
        config.clone(),
        store,
        spawner as Arc<dyn LocalBrokerProcessSpawner>,
    )
    .await;
    let mut owner = connect_when_ready(&config).await;
    let credential = owner
        .add_credential(
            NewCredential {
                provider: provider("openai"),
                authentication_kind: CredentialAuthKind::OAuth,
                display_name: "synthetic-broker".into(),
                account_hint: None,
                expires_at_unix: None,
            },
            ProtectedValue::from_slice(FIRST_MATERIAL).unwrap(),
        )
        .await
        .unwrap();
    let profile = owner
        .create_profile(
            &AccessProfileName::parse("broker").unwrap(),
            &BTreeMap::from([(CapabilitySlot::codex(), credential.metadata.id.clone())]),
        )
        .await
        .unwrap();
    let environment_id = EnvironmentId::parse(uuid::Uuid::new_v4().to_string()).unwrap();
    let selected_binding = EnvironmentAccessBinding {
        environment_id: environment_id.clone(),
        profile_id: profile.profile.id,
        profile_revision: profile.profile.revision,
    };
    owner
        .create_environment_access_binding(&selected_binding)
        .await
        .unwrap();
    let mut control = LocalCredentialControlClient::connect(&config)
        .await
        .unwrap();
    let runtime = control
        .ensure_environment_broker(
            &environment_id,
            31,
            "dev",
            &temp.path().join(format!("runtime/{environment_id}.sock")),
            EnvironmentBrokerSelection {
                local_profile: Some(selected_binding),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(runtime.running);

    // The serving child ends; each replacement fails before it is ready.
    let first_pid = child_pids.lock().unwrap()[0];
    rustix::process::kill_process(
        rustix::process::Pid::from_raw(first_pid as i32).unwrap(),
        rustix::process::Signal::KILL,
    )
    .unwrap();
    // A failure of a still-selected broker is transient: it restarts.
    tokio::time::timeout(Duration::from_secs(5), async {
        while child_pids.lock().unwrap().len() < 3 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();

    control
        .stop_environment_broker(&environment_id, Some(31))
        .await
        .unwrap();
    let log_path = config.root.join("logs").join("brokers.log");
    let spawned = child_pids.lock().unwrap().clone();
    // Each replacement's lease closes before it is ready while its child
    // still runs, and that is what the log says (#3069).
    let logged = fs::read_to_string(&log_path).unwrap();
    assert!(
        logged.contains("event=broker_not_ready")
            && logged.contains("reason=lease_closed_before_ready")
            && !logged.contains("reason=ended_before_ready"),
        "{logged}"
    );
    assert!(
        logged.contains("event=broker_restart_scheduled"),
        "{logged}"
    );
    // Well past the next restart delay (at most 1.6 s after three children).
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert_eq!(*child_pids.lock().unwrap(), spawned);
    assert_eq!(fs::read_to_string(&log_path).unwrap(), logged);
    for pid in spawned {
        assert!(matches!(
            rustix::process::test_kill_process(rustix::process::Pid::from_raw(pid as i32).unwrap()),
            Err(rustix::io::Errno::SRCH)
        ));
    }

    shutdown.send(()).unwrap();
    server.await.unwrap().unwrap();
    for task in tasks.lock().unwrap().drain(..) {
        task.abort();
    }
}

#[tokio::test]
async fn owner_filter_rejects_a_peer_before_rpc_dispatch() {
    let temp = tempfile::tempdir().unwrap();
    let config = runtime_config(&temp);
    let rejected_uid = current_uid().wrapping_add(1);
    let (mut incoming, identity) = bind_owner_only_for_uid(&config, rejected_uid).unwrap();
    let mut client = UnixStream::connect(config.socket()).await.unwrap();

    assert!(
        tokio::time::timeout(Duration::from_millis(50), incoming.next())
            .await
            .is_err()
    );
    let mut byte = [0_u8; 1];
    assert_eq!(
        tokio::time::timeout(Duration::from_millis(50), client.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    remove_bound_socket(&config, &identity).unwrap();
}

#[tokio::test]
async fn connector_rejects_a_replaced_socket_identity() {
    let temp = tempfile::tempdir().unwrap();
    let config = runtime_config(&temp);
    let (_first, first_identity) = bind_owner_only(&config).unwrap();
    let connector = owner_only_connector(&config).unwrap();
    remove_bound_socket(&config, &first_identity).unwrap();
    let (_replacement, replacement_identity) = bind_owner_only(&config).unwrap();

    let error = connector
        .oneshot(
            "http://codewire-local-credential-authority"
                .parse()
                .unwrap(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    remove_bound_socket(&config, &replacement_identity).unwrap();
}

#[test]
fn authority_prepares_one_missing_private_state_parent() {
    let temp = tempfile::tempdir().unwrap();
    let mut config = runtime_config(&temp);
    config.root = temp.path().join("state").join("authority");

    config.prepare_root().unwrap();

    for path in [config.root.parent().unwrap(), config.root.as_path()] {
        let metadata = fs::symlink_metadata(path).unwrap();
        assert_eq!(metadata.mode() & 0o7777, 0o700);
        assert_eq!(metadata.uid(), current_uid());
    }
}

/// Waits for an endpoint an in-process authority is about to publish.
async fn wait_for_socket(path: &std::path::Path) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !path.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("authority endpoint appears");
}

/// #2745: the authority listens in its short socket directory. One a cw
/// before that started still listens in the credential root; a client uses
/// it while it runs. The next authority replaces its dead endpoint and
/// listens there too, where a v0.3.388 supervisor still dials it.
#[tokio::test(flavor = "multi_thread")]
async fn a_legacy_authority_serves_until_a_new_one_listens_in_the_socket_dir() {
    let temp = tempfile::tempdir().unwrap();
    let sockets = temp.path().join("sockets");
    fs::create_dir(&sockets).unwrap();
    fs::set_permissions(&sockets, fs::Permissions::from_mode(0o700)).unwrap();
    let config = AuthorityRuntimeConfig {
        socket_dir: sockets.clone(),
        ..runtime_config(&temp)
    };
    let legacy = AuthorityRuntimeConfig {
        socket_dir: config.root.clone(),
        ..config.clone()
    };
    assert_eq!(legacy.socket(), config.legacy_socket());
    assert_eq!(config.socket(), sockets.join("authority.sock"));

    let (shutdown, server) = start_server(legacy.clone(), TestProtectedStore::default()).await;
    wait_for_socket(&config.legacy_socket()).await;
    let client = LocalCredentialClient::connect_or_start_with(
        &config,
        |_| -> Result<Child, AuthorityRuntimeError> {
            panic!("a live earlier authority must not be replaced")
        },
    )
    .await
    .unwrap();
    assert_eq!(client.info().protocol_version, AUTHORITY_PROTOCOL_VERSION);
    assert!(
        LocalCredentialClient::admit_existing_or_replace_with(&config, |_| {
            panic!("admission must not spawn")
        })
        .await
        .unwrap()
        .is_some()
    );
    assert!(!config.socket().exists());
    drop(client);
    shutdown.send(()).unwrap();
    server.await.unwrap().unwrap();

    // A killed earlier authority leaves its endpoint behind.
    if !config.legacy_socket().exists() {
        drop(std::os::unix::net::UnixListener::bind(config.legacy_socket()).unwrap());
        fs::set_permissions(config.legacy_socket(), fs::Permissions::from_mode(0o600)).unwrap();
    }
    let (shutdown, server) = start_server(config.clone(), TestProtectedStore::default()).await;
    wait_for_socket(&config.socket()).await;
    let client = LocalCredentialClient::connect(&config).await.unwrap();
    assert_eq!(client.info().protocol_version, AUTHORITY_PROTOCOL_VERSION);
    drop(client);
    // The same authority answers at the credential root's own socket.
    let through_legacy = LocalCredentialClient::connect(&legacy).await.unwrap();
    assert_eq!(
        through_legacy.info().protocol_version,
        AUTHORITY_PROTOCOL_VERSION
    );
    assert_eq!(
        fs::symlink_metadata(config.legacy_socket())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    drop(through_legacy);
    shutdown.send(()).unwrap();
    server.await.unwrap().unwrap();
}

#[test]
fn a_socket_path_over_the_kernel_limit_is_refused_by_name() {
    let config = AuthorityRuntimeConfig {
        root: "/synthetic/credentials-v1".into(),
        executable: "/synthetic/bin/cw".into(),
        socket_dir: format!("/{}", "d".repeat(crate::MAXIMUM_SOCKET_PATH_BYTES)).into(),
    };
    let error = config.validate().unwrap_err();
    let length = config.socket().as_os_str().len();
    assert!(matches!(
        &error,
        AuthorityRuntimeError::SocketPathTooLong { path, length: found, limit }
            if *path == config.socket()
                && *found == length
                && *limit == crate::MAXIMUM_SOCKET_PATH_BYTES
    ));
    assert_eq!(
        error.to_string(),
        format!(
            "the local credential authority socket path {} is {length} bytes; the limit is {}",
            config.socket().display(),
            crate::MAXIMUM_SOCKET_PATH_BYTES
        )
    );
}

/// The default profile cannot be deleted (#4717): make an empty spare the
/// default so a test can delete the profile it made.
async fn move_default_away(client: &mut LocalCredentialClient) {
    let spare = client
        .create_profile(
            &AccessProfileName::parse("spare").unwrap(),
            &BTreeMap::new(),
        )
        .await
        .unwrap();
    assert!(
        client
            .set_default_profile(&spare.profile.id)
            .await
            .unwrap()
            .is_default
    );
}

/// The value each lease the test executor took carried.
type Leases = Arc<std::sync::Mutex<Vec<Vec<u8>>>>;

/// The provider revocation executor, played in process (#4717): it leases
/// over the inherited stream as the real child does, records the value its
/// lease carried (#4984), and reports `answer`.
struct TestRevocationSpawner {
    answer: Option<crate::control::v1::ProviderRevocation>,
    leased: Leases,
    spawned: Arc<std::sync::atomic::AtomicUsize>,
}

impl crate::LocalRevocationProcessSpawner for TestRevocationSpawner {
    fn spawn(
        &self,
        config: &crate::LocalRevocationProcessConfig,
        authority_peer: std::os::unix::net::UnixStream,
    ) -> Result<tokio::process::Child, crate::LocalRevocationSpawnError> {
        self.spawned
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let Some(answer) = self.answer else {
            return Err(crate::LocalRevocationSpawnError::Spawn);
        };
        authority_peer
            .set_nonblocking(true)
            .map_err(|_| crate::LocalRevocationSpawnError::Spawn)?;
        let stream = UnixStream::from_std(authority_peer)
            .map_err(|_| crate::LocalRevocationSpawnError::Spawn)?;
        let leased = Arc::clone(&self.leased);
        let request_id = config.request_id;
        tokio::spawn(async move {
            let Ok(mut client) =
                crate::LocalRevocationLeaseClient::connect(stream, request_id).await
            else {
                return;
            };
            if client.report_ready().await.is_err() {
                return;
            }
            let Ok(value) = client.lease().await else {
                return;
            };
            let material = value
                .map(|value| value.expose_secret().to_vec())
                .unwrap_or_default();
            leased.lock().unwrap().push(material);
            let _ = client.report(answer).await;
        });
        let mut child = tokio::process::Command::new("/bin/sh");
        child
            .arg("-c")
            .arg("sleep 30")
            .env_clear()
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true);
        child
            .spawn()
            .map_err(|_| crate::LocalRevocationSpawnError::Spawn)
    }
}

fn revocation_spawner(
    _store: &TestProtectedStore,
    answer: Option<crate::control::v1::ProviderRevocation>,
) -> Arc<TestRevocationSpawner> {
    Arc::new(TestRevocationSpawner {
        answer,
        leased: Arc::default(),
        spawned: Arc::default(),
    })
}

async fn start_server_with_revocation_spawner(
    config: AuthorityRuntimeConfig,
    store: TestProtectedStore,
    spawner: Arc<TestRevocationSpawner>,
) -> (
    oneshot::Sender<()>,
    tokio::task::JoinHandle<Result<(), AuthorityRuntimeError>>,
) {
    start_listening_authority(
        config,
        store,
        codewire_access::builtin_provider_catalog(),
        crate::service::AuthorityRuntimeAdapters {
            revocation_spawner: Some(spawner),
            ..Default::default()
        },
    )
    .await
}

fn confirmed() -> crate::control::v1::ProviderRevocation {
    crate::control::v1::ProviderRevocation {
        outcome: crate::control::v1::ProviderRevocationOutcome::Confirmed.into(),
        failure: crate::control::v1::ProviderRevocationFailure::Unspecified.into(),
        http_status: 0,
    }
}

async fn add_revocable(
    client: &mut LocalCredentialClient,
    provider_name: &str,
    kind: CredentialAuthKind,
    name: &str,
) -> CredentialRecord {
    client
        .add_credential(
            NewCredential {
                provider: provider(provider_name),
                authentication_kind: kind,
                display_name: name.into(),
                account_hint: None,
                expires_at_unix: Some(4_102_444_800),
            },
            ProtectedValue::from_slice(FIRST_MATERIAL).unwrap(),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn a_codex_revoke_asks_its_provider_through_one_executor_of_the_revoked_generation() {
    let temp = tempfile::tempdir().unwrap();
    let config = runtime_config(&temp);
    let store = TestProtectedStore::default();
    let spawner = revocation_spawner(&store, Some(confirmed()));
    let (shutdown, server) =
        start_server_with_revocation_spawner(config.clone(), store, Arc::clone(&spawner)).await;
    let mut client = connect_when_ready(&config).await;
    let credential = add_revocable(
        &mut client,
        "openai",
        CredentialAuthKind::OAuth,
        "codex-revoked",
    )
    .await;
    let (revoked, answer) = client
        .revoke_credential_at_provider(&credential.metadata.id)
        .await
        .unwrap();
    assert_eq!(revoked.metadata.status, CredentialStatus::Revoked);
    assert_eq!(answer, Some(confirmed()));
    let leased = spawner.leased.lock().unwrap().clone();
    assert_eq!(leased.len(), 1, "one executor, one lease");
    assert_eq!(
        leased[0], FIRST_MATERIAL,
        "the lease carries the revoked generation's value"
    );
    let _ = shutdown.send(());
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn an_executor_that_cannot_start_is_reported_as_not_read_and_the_revoke_stands() {
    let temp = tempfile::tempdir().unwrap();
    let config = runtime_config(&temp);
    let store = TestProtectedStore::default();
    let spawner = revocation_spawner(&store, None);
    let (shutdown, server) =
        start_server_with_revocation_spawner(config.clone(), store, Arc::clone(&spawner)).await;
    let mut client = connect_when_ready(&config).await;
    let credential = add_revocable(
        &mut client,
        "openai",
        CredentialAuthKind::OAuth,
        "codex-no-executor",
    )
    .await;
    let (revoked, answer) = client
        .revoke_credential_at_provider(&credential.metadata.id)
        .await
        .unwrap();
    assert_eq!(revoked.metadata.status, CredentialStatus::Revoked);
    let answer = answer.unwrap();
    assert_eq!(
        answer.outcome,
        i32::from(crate::control::v1::ProviderRevocationOutcome::Failed)
    );
    assert_eq!(
        answer.failure,
        i32::from(crate::control::v1::ProviderRevocationFailure::NotRead)
    );
    let _ = shutdown.send(());
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn a_provider_without_revocation_is_not_asked_and_a_repeat_reports_nothing() {
    let temp = tempfile::tempdir().unwrap();
    let config = runtime_config(&temp);
    let store = TestProtectedStore::default();
    let spawner = revocation_spawner(&store, Some(confirmed()));
    let (shutdown, server) =
        start_server_with_revocation_spawner(config.clone(), store, Arc::clone(&spawner)).await;
    let mut client = connect_when_ready(&config).await;
    let key = add_revocable(
        &mut client,
        "anthropic",
        CredentialAuthKind::ApiKey,
        "anthropic-key",
    )
    .await;
    let (_, answer) = client
        .revoke_credential_at_provider(&key.metadata.id)
        .await
        .unwrap();
    let answer = answer.unwrap();
    assert_eq!(
        answer.outcome,
        i32::from(crate::control::v1::ProviderRevocationOutcome::NotAvailable)
    );
    let (_, again) = client
        .revoke_credential_at_provider(&key.metadata.id)
        .await
        .unwrap();
    assert_eq!(again, None, "a revoked credential is not asked again");
    assert_eq!(
        spawner.spawned.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "no executor for a provider without revocation"
    );
    let _ = shutdown.send(());
    server.await.unwrap().unwrap();
}

/// An authority tells its clients the runner protocol its brokers accept,
/// which is its spawner's to say (#5238): a client whose runner speaks
/// another protocol, or one that gets no answer, takes the authority for
/// another cw's.
#[tokio::test(flavor = "multi_thread")]
async fn an_authority_reports_the_runner_protocol_its_brokers_accept() {
    let temp = tempfile::tempdir().unwrap();
    let config = runtime_config(&temp);
    let store = TestProtectedStore::default();
    let spawner = Arc::new(RunnerGoneBrokerSpawner {
        store: store.clone(),
        child_pids: Arc::default(),
        tasks: Arc::default(),
    });
    let (shutdown, server) = start_server_with_spawner(
        config.clone(),
        store,
        spawner as Arc<dyn LocalBrokerProcessSpawner>,
    )
    .await;
    let client = connect_when_ready(&config).await;
    let reported = crate::broker_process::TEST_RUNNER_PROTOCOL;
    assert_eq!(client.info().broker_runner_protocol, Some(reported));
    assert!(!client.is_another_cws(reported));
    assert!(client.is_another_cws(reported + 1));
    drop(client);
    shutdown.send(()).unwrap();
    server.await.unwrap().unwrap();
}

mod store_refusal;

mod abandoned_ssh_enrollment;
