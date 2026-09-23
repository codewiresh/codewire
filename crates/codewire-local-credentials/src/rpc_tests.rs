use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::process::Command;
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
use crate::service::{serve_until, serve_until_with_process_spawners, serve_until_with_spawner};
use crate::transport::{
    AUTHORITY_PROTOCOL_VERSION, bind_owner_only, bind_owner_only_for_uid, current_uid,
    owner_only_connector, remove_bound_socket,
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

    async fn wait_for_put(&self) {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let notified = self.put_gate.notify.notified();
                if self.put_gate.reached.load(Ordering::SeqCst) > 0 {
                    return;
                }
                notified.await;
            }
        })
        .await
        .expect("protected-store put was not reached");
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
    }
}

async fn start_server(
    config: AuthorityRuntimeConfig,
    store: TestProtectedStore,
) -> (
    oneshot::Sender<()>,
    tokio::task::JoinHandle<Result<(), AuthorityRuntimeError>>,
) {
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        serve_until(config, store, catalog(), async move {
            let _ = shutdown_rx.await;
        })
        .await
    });
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
    fn spawn(
        &self,
        config: &LocalBrokerProcessConfig,
        authority_peer: std::os::unix::net::UnixStream,
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
            let ready = codewire_gateway_proto::codewire::bridge::v1::CredentialBridgeReady {
                protocol_version: codewire_gateway_proto::CREDENTIAL_BRIDGE_PROTOCOL_VERSION,
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
            if client.report_ready(ready).await.is_err() {
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
    store: TestProtectedStore,
    leased_material: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    tasks: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
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
        let store = self.store.clone();
        let request_id = config.request_id;
        let leased_material = self.leased_material.clone();
        let marker = config.staging_directory.join("lease-complete");
        let task = tokio::spawn(async move {
            let Ok(mut client) =
                LocalCredentialRepositoryLeaseClient::connect(stream, request_id).await
            else {
                return;
            };
            if client.report_ready().await.is_err() {
                return;
            }
            let Ok(lease) = client.lease_github(store).await else {
                return;
            };
            let _ = leased_material.send(lease.material().to_vec());
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
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        serve_until_with_spawner(
            config,
            store,
            catalog(),
            async move {
                let _ = shutdown_rx.await;
            },
            Some(spawner),
        )
        .await
    });
    (shutdown_tx, task)
}

async fn start_server_with_repository_spawner(
    config: AuthorityRuntimeConfig,
    store: TestProtectedStore,
    spawner: Arc<dyn LocalRepositoryProcessSpawner>,
) -> (
    oneshot::Sender<()>,
    tokio::task::JoinHandle<Result<(), AuthorityRuntimeError>>,
) {
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        serve_until_with_process_spawners(
            config,
            store,
            codewire_access::builtin_provider_catalog(),
            async move {
                let _ = shutdown_rx.await;
            },
            crate::service::AuthorityRuntimeAdapters {
                repository_spawner: Some(spawner),
                ..Default::default()
            },
        )
        .await
    });
    (shutdown_tx, task)
}

async fn connect_when_ready(config: &AuthorityRuntimeConfig) -> LocalCredentialClient {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        match LocalCredentialClient::connect(config).await {
            Ok(client) => return client,
            Err(_) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(error) => panic!("authority did not become ready: {error}"),
        }
    }
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn abandoned_ssh_enrollment_waiter_cannot_cancel_published_journal_work() {
    let temp = tempfile::tempdir().unwrap();
    let config = runtime_config(&temp);
    let store = TestProtectedStore::default();
    let put_block = store.block_puts();
    let (shutdown, server) = start_server(config.clone(), store.clone()).await;
    let mut enrolling = connect_when_ready(&config).await;
    let request = tokio::spawn(async move {
        enrolling
            .generate_ssh_credential("abandoned-ssh".into(), None)
            .await
    });
    store.wait_for_put().await;
    request.abort();
    assert!(request.await.unwrap_err().is_cancelled());
    drop(put_block);

    let mut observer = connect_when_ready(&config).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    let credentials = loop {
        let credentials = observer.list_credentials().await.unwrap();
        if !credentials.is_empty() {
            break credentials;
        }
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    assert_eq!(credentials.len(), 1);
    assert_eq!(credentials[0].metadata.display_name, "abandoned-ssh");
    assert_eq!(credentials[0].metadata.provider, provider("ssh"));
    assert_eq!(store.values().len(), 1);

    shutdown.send(()).unwrap();
    server.await.unwrap().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn abandoned_ssh_enrollment_waiter_cancels_before_publication() {
    let temp = tempfile::tempdir().unwrap();
    let config = runtime_config(&temp);
    let store = TestProtectedStore::default();
    let put_block = store.block_puts();
    let (shutdown, server) = start_server(config.clone(), store.clone()).await;
    let mut first_client = connect_when_ready(&config).await;
    let first = tokio::spawn(async move {
        first_client
            .generate_ssh_credential("published-first".into(), None)
            .await
    });
    store.wait_for_put().await;

    let mut cancelled_client = connect_when_ready(&config).await;
    let cancelled = tokio::spawn(async move {
        cancelled_client
            .generate_ssh_credential("cancelled-before-publication".into(), None)
            .await
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    cancelled.abort();
    assert!(cancelled.await.unwrap_err().is_cancelled());
    drop(put_block);
    first.await.unwrap().unwrap();

    let mut observer = connect_when_ready(&config).await;
    let credentials = observer.list_credentials().await.unwrap();
    assert_eq!(credentials.len(), 1);
    assert_eq!(credentials[0].metadata.display_name, "published-first");
    assert_eq!(store.values().len(), 1);
    shutdown.send(()).unwrap();
    server.await.unwrap().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shutdown_cancels_ssh_enrollment_waiting_before_publication() {
    let temp = tempfile::tempdir().unwrap();
    let config = runtime_config(&temp);
    let store = TestProtectedStore::default();
    let put_block = store.block_puts();
    let (shutdown, server) = start_server(config.clone(), store.clone()).await;
    let mut first_client = connect_when_ready(&config).await;
    let first = tokio::spawn(async move {
        first_client
            .generate_ssh_credential("published-ssh".into(), None)
            .await
    });
    store.wait_for_put().await;

    let mut second_client = connect_when_ready(&config).await;
    let second = tokio::spawn(async move {
        second_client
            .generate_ssh_credential("cancelled-ssh".into(), None)
            .await
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    shutdown.send(()).unwrap();
    drop(put_block);
    server.await.unwrap().unwrap();
    let _ = first.await;
    let _ = second.await;

    let authority = LocalCredentialAuthority::open(&config.root, store.clone(), catalog()).unwrap();
    let credentials = authority.list_credentials().unwrap();
    assert_eq!(credentials.len(), 1);
    assert_eq!(credentials[0].metadata.display_name, "published-ssh");
    assert_eq!(store.values().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ninth_concurrent_ssh_enrollment_fails_fast_without_queued_material() {
    let temp = tempfile::tempdir().unwrap();
    let config = runtime_config(&temp);
    let store = TestProtectedStore::default();
    let put_block = store.block_puts();
    let (shutdown, server) = start_server(config.clone(), store.clone()).await;
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
    store.wait_for_put().await;
    for (index, mut client) in clients.drain(..7).enumerate() {
        requests.push(tokio::spawn(async move {
            client
                .generate_ssh_credential(format!("ssh-worker-{}", index + 1), None)
                .await
        }));
    }
    tokio::time::sleep(Duration::from_millis(100)).await;

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
    let temp = tempfile::tempdir().unwrap();
    let config = runtime_config(&temp);
    let store = TestProtectedStore::default();
    let (material_tx, mut material_rx) = tokio::sync::mpsc::unbounded_channel();
    let spawner = Arc::new(TestRepositorySpawner {
        store: store.clone(),
        leased_material: material_tx,
        tasks: Arc::new(Mutex::new(Vec::new())),
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

    let client = LocalCredentialClient::connect_or_start_with(&config, |_| {
        panic!("an admitted authority must not spawn a replacement")
    })
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

#[tokio::test(flavor = "multi_thread")]
async fn existing_authority_admission_fails_closed_for_a_dead_socket_without_spawning() {
    let temp = tempfile::tempdir().unwrap();
    let config = runtime_config(&temp);
    config.prepare_root().unwrap();
    let listener = std::os::unix::net::UnixListener::bind(config.socket()).unwrap();
    fs::set_permissions(config.socket(), fs::Permissions::from_mode(0o600)).unwrap();
    drop(listener);
    let error = LocalCredentialClient::admit_existing_or_replace_with(&config, |_| {
        panic!("an unadmitted authority socket must not spawn")
    })
    .await
    .unwrap_err();
    assert!(matches!(error, AuthorityRuntimeError::Connect));
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
