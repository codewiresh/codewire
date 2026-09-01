use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use codewire_access::{
    AccessProfileName, AccessProfileReference, BrokerOperationId, BrokerRouteId, CapabilityPolicy,
    CapabilitySlot, CredentialAuthKind, CredentialStatus, GrantPermission, ProviderDefinition,
    ProviderId,
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
use crate::service::serve_until;
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
            protocol_version: 1,
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
    assert_eq!(client.info().protocol_version, 1);
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
    assert_eq!(client.info().protocol_version, 1);
    client.shutdown().await.unwrap();
    task.await.unwrap().unwrap();
    assert!(!config.socket().exists());
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
