//! Actual owner control client -> broker manager -> inherited source RPC ->
//! synthetic platform transport -> consuming launcher. Not hardware/Dev proof.

use super::*;
use crate::{
    AuthorityRuntimeConfig, EnvironmentBrokerSelection, LocalBrokerProcessConfig,
    LocalBrokerProcessSpawner, LocalBrokerSpawnError, LocalCredentialClient,
    LocalCredentialControlClient, NewCredential,
};
use codewire_access::{
    AccessProfileName, BrokerOperationId, BrokerRouteId, CapabilitySlot, CredentialAuthKind,
    EnvironmentAccessBinding, ProviderId,
};

struct BrokerPeer {
    recipient: [u8; 32],
    context: ProjectionContext,
    results: mpsc::UnboundedSender<(Vec<u8>, Vec<u8>)>,
    tasks: std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

impl LocalBrokerProcessSpawner for BrokerPeer {
    fn spawn(
        &self,
        config: &LocalBrokerProcessConfig,
        peer: std::os::unix::net::UnixStream,
    ) -> Result<tokio::process::Child, LocalBrokerSpawnError> {
        assert!(!config.platform_delegated);
        assert_eq!(
            config.http_providers,
            [codewire_access::HttpProvider::CodexOAuth].into()
        );
        peer.set_nonblocking(true)
            .map_err(|_| LocalBrokerSpawnError::Spawn)?;
        let stream = UnixStream::from_std(peer).map_err(|_| LocalBrokerSpawnError::Spawn)?;
        let context = self.context.clone();
        let recipient = self.recipient;
        let results = self.results.clone();
        let ready = bridge::CredentialBridgeReady {
            protocol_version: CREDENTIAL_BRIDGE_PROTOCOL_VERSION,
            environment_id: config.environment_id.to_string(),
            environment_generation: config.environment_generation,
        };
        let id = config.environment_id.clone();
        let store = crate::tests::TestProtectedStore::new(
            codewire_protected_store::ProtectedStorePersistence::ProcessLifetime,
        );
        // The test uses the actual inherited RPCs. Its local lease is metadata
        // only; production's protected-store reader is independently exercised.
        let task = tokio::spawn(async move {
            let mut client = LocalCredentialBrokerLeaseClient::connect(
                stream,
                store,
                id,
                context.operation_generation,
            )
            .await
            .unwrap();
            client.report_ready(ready).await.unwrap();
            let lease = client
                .inner
                .clone()
                .lease_credential_operation(v1::BrokerLeaseRequest {
                    request_id: Uuid::new_v4().to_string(),
                    capability_slot: "codex".into(),
                    operation: BrokerOperationId::parse("responses").unwrap().to_string(),
                    route: BrokerRouteId::parse("openai-api").unwrap().to_string(),
                })
                .await
                .unwrap()
                .into_inner();
            let credential = lease.credential.unwrap().id.into_bytes();
            let sealed = client
                .project_environment(
                    Uuid::new_v4(),
                    recipient,
                    context.selection_sha256,
                    context.deadline_unix_ms,
                )
                .await
                .unwrap();
            results.send((credential, sealed)).unwrap();
            std::future::pending::<()>().await;
            drop(client);
        });
        self.tasks.lock().unwrap().push(task);
        tokio::process::Command::new("/bin/sleep")
            .arg("60")
            .kill_on_drop(true)
            .spawn()
            .map_err(|_| LocalBrokerSpawnError::Spawn)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn owner_client_requires_exact_local_profile_and_delivers_both_application_sources() {
    let temp = tempfile::tempdir().unwrap();
    let config = AuthorityRuntimeConfig {
        root: temp.path().join("authority"),
        executable: std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap(),
    };
    let recipient = ProjectionRecipient::new();
    let context = ProjectionContext {
        environment_id: *Uuid::new_v4().as_bytes(),
        operation_generation: 7,
        selection_sha256: [17; 32],
        deadline_unix_ms: crate::unix_millis().unwrap() + 30_000,
    };
    let environment_id =
        EnvironmentId::parse(Uuid::from_bytes(context.environment_id).to_string()).unwrap();
    let (results, mut received) = mpsc::unbounded_channel();
    let spawner = Arc::new(BrokerPeer {
        recipient: recipient.public_key(),
        context: context.clone(),
        results,
        tasks: std::sync::Mutex::new(Vec::new()),
    });
    let observation = Arc::new(Observation::default());
    let connector = Arc::new(SyntheticConnector {
        mode: Mode::Seal,
        observation: Arc::clone(&observation),
    });
    let (shutdown, stopped) = oneshot::channel();
    let server = tokio::spawn(crate::service::serve_until_with_process_spawners(
        config.clone(),
        EphemeralProtectedStore::default(),
        builtin_provider_catalog(),
        async move {
            let _ = stopped.await;
        },
        crate::service::AuthorityRuntimeAdapters {
            broker_spawner: Some(spawner.clone()),
            platform_connector: Some(connector),
            ..Default::default()
        },
    ));
    let mut owner = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Ok(client) = LocalCredentialClient::connect(&config).await {
                break client;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    let credential = owner
        .add_credential(
            NewCredential {
                provider: ProviderId::parse("openai").unwrap(),
                authentication_kind: CredentialAuthKind::OAuth,
                display_name: "synthetic-local-provider".into(),
                account_hint: None,
                expires_at_unix: None,
            },
            ProtectedValue::from_slice(b"synthetic-provider-only").unwrap(),
        )
        .await
        .unwrap();
    let profile = owner
        .create_profile(
            &AccessProfileName::parse("work").unwrap(),
            &[(CapabilitySlot::codex(), credential.metadata.id.clone())].into(), false,
        )
        .await
        .unwrap();
    let local_profile = EnvironmentAccessBinding {
        environment_id: environment_id.clone(),
        profile_id: profile.profile.id,
        profile_revision: profile.profile.revision,
    };
    owner
        .create_environment_access_binding(&local_profile)
        .await
        .unwrap();
    owner
        .set_user_workload_secret(
            "LOCAL_ONLY".into(),
            ProtectedValue::from_slice(b"synthetic-local").unwrap(),
        )
        .await
        .unwrap();
    let platform = PlatformCredentialBinding {
        config_directory: temp.path().join("platform"),
        server_url: "https://platform.invalid".into(),
        selection_sha256: context.selection_sha256,
        selection: PlatformProjectionSelection {
            creator: "owner".into(),
            organization: "organization".into(),
            organization_selected: true,
            project_id: None,
            user_selected: false,
            profile: None,
            ordinary_keys: Default::default(),
            reserved_keys: ["CODEX_HOME".into()].into(),
        },
    };
    let mut selection = EnvironmentBrokerSelection {
        local_profile: None,
        platform: Some(platform.clone()),
        projection: Some(LocalEnvironmentProjectionBinding {
            selection: LocalLaunchSecretSelection {
                user: true,
                reserved_keys: ["CODEX_HOME".into()].into(),
                ..Default::default()
            },
            selection_sha256: context.selection_sha256,
        }),
    };
    let socket = temp.path().join(format!("{environment_id}.sock"));
    let mut client = LocalCredentialControlClient::connect(&config)
        .await
        .unwrap();
    // Absence is an explicit selection, not permission to find the stored one.
    let mut platform_only = selection.clone();
    platform_only.projection = None;
    assert_eq!(
        client
            .ensure_environment_broker(&environment_id, 7, "synthetic", &socket, platform_only)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition
    );
    assert_eq!(
        client
            .ensure_environment_broker(&environment_id, 7, "synthetic", &socket, selection.clone())
            .await
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition
    );
    assert!(spawner.tasks.lock().unwrap().is_empty());
    let mut stale = local_profile.clone();
    stale.profile_revision += 1;
    selection.local_profile = Some(stale);
    assert_eq!(
        client
            .ensure_environment_broker(&environment_id, 7, "synthetic", &socket, selection.clone())
            .await
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition
    );
    selection.local_profile = Some(local_profile);
    assert!(
        client
            .ensure_environment_broker(&environment_id, 7, "synthetic", &socket, selection.clone())
            .await
            .unwrap()
            .running
    );
    let (leased_id, sealed) = tokio::time::timeout(Duration::from_secs(3), received.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(leased_id, credential.metadata.id.to_string().into_bytes());
    let opened = recipient
        .open(&sealed, &context, crate::unix_millis().unwrap())
        .unwrap();
    assert_eq!(
        opened
            .entries()
            .collect::<std::collections::BTreeMap<_, _>>(),
        [
            ("LOCAL_ONLY", "synthetic-local"),
            ("PLATFORM_ONLY", "synthetic-platform"),
        ]
        .into()
    );
    // Codex owns CODEX_HOME/config; OPENAI_* belongs to the separately
    // selectable OpenAI client. Only the selected clients reserve names.
    let expected_platform = platform;
    assert_eq!(
        observation.selection.lock().unwrap().as_ref().unwrap().0,
        expected_platform
    );
    assert_eq!(observation.admissions.load(Ordering::Relaxed), 1);
    // Exact re-ensure reuses the same owner; no second source admission.
    assert!(
        client
            .ensure_environment_broker(&environment_id, 7, "synthetic", &socket, selection)
            .await
            .unwrap()
            .running
    );
    assert_eq!(observation.admissions.load(Ordering::Relaxed), 1);
    client
        .stop_environment_broker(&environment_id, Some(7))
        .await
        .unwrap();
    shutdown.send(()).unwrap();
    server.await.unwrap().unwrap();
    let tasks = std::mem::take(&mut *spawner.tasks.lock().unwrap());
    for task in tasks {
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
    }
    assert!(observation.dropped.load(Ordering::Acquire));
}
