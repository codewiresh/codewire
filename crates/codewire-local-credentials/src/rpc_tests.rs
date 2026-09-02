use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt as _;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use codewire_access::{
    AccessProfileName, AccessProfileReference, BrokerOperationId, BrokerRouteId, CapabilityPolicy,
    CapabilitySlot, CredentialAuthKind, CredentialStatus, EnvironmentAccessBinding, EnvironmentId,
    GrantPermission, ProviderDefinition, ProviderId,
};
use codewire_protected_store::{
    ProtectedEntryId, ProtectedStore, ProtectedStoreError, ProtectedStorePersistence,
    ProtectedValue,
};
use tokio::io::AsyncReadExt as _;
use tokio::net::UnixStream;
use tokio::sync::oneshot;
use tokio_stream::StreamExt as _;
use tonic::Code;
use tower::ServiceExt as _;

use super::*;
use crate::control::v1;
use crate::service::{serve_until, serve_until_with_spawner};
use crate::transport::{
    bind_owner_only, bind_owner_only_for_uid, current_uid, owner_only_connector,
    remove_bound_socket,
};

const FIRST_MATERIAL: &[u8] = b"synthetic-oauth-material-alpha";
const SECOND_MATERIAL: &[u8] = b"synthetic-oauth-material-bravo";

#[derive(Clone, Default)]
struct TestProtectedStore {
    entries: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
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
    ProviderCatalog::from_definitions([ProviderDefinition {
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
    }])
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
            if client.report_ready().await.is_err() {
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
async fn owner_only_rpc_keeps_material_out_of_metadata_and_recovers_process_loss() {
    let temp = tempfile::tempdir().unwrap();
    let config = runtime_config(&temp);
    let store = TestProtectedStore::default();
    let (shutdown, task) = start_server(config.clone(), store.clone()).await;
    let mut client = connect_when_ready(&config).await;
    assert_eq!(
        client.info(),
        AuthorityInfo {
            protocol_version: 4,
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
            &BTreeMap::from([(CapabilitySlot::github(), credential.metadata.id.clone())]),
        )
        .await
        .unwrap_err();
    assert_eq!(incompatible.code(), Code::FailedPrecondition);
    assert_eq!(
        incompatible.message(),
        "provider openai does not support slot github with this authentication kind"
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
            ProtectedValue::from_slice(SECOND_MATERIAL).unwrap(),
            Some(4_102_444_801),
        )
        .await
        .unwrap();
    assert_eq!(rotated.metadata.revocation_generation, 2);
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
    let created = client
        .create_environment_access_binding(&binding)
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
    let mut control = LocalCredentialControlClient::connect(&config)
        .await
        .unwrap();
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

    let client = LocalCredentialClient::connect_or_start_with(&config, |_| {
        panic!("an admitted authority must not spawn a replacement")
    })
    .await
    .unwrap();
    assert_eq!(client.info().protocol_version, 4);
    client.shutdown().await.unwrap();
    task.await.unwrap().unwrap();
    drop(shutdown);
    assert!(!config.socket().exists());
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
    assert_eq!(client.info().protocol_version, 4);
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
    owner
        .create_environment_access_binding(&EnvironmentAccessBinding {
            environment_id: environment_id.clone(),
            profile_id: profile.profile.id,
            profile_revision: profile.profile.revision,
        })
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
            &temp.path().join("runtime/supervisor.sock"),
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
            launched[0].credential_authentication_kind,
            CredentialAuthKind::OAuth
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
    assert_eq!(child_pids.lock().unwrap().len(), 2);
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
