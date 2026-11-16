use super::*;

use codewire_daemon_proto::codewire::bridge::v1::CredentialBridgeReady;
use codewire_protected_store::EphemeralProtectedStore;
use futures::future::BoxFuture;

struct NeverConnect;

impl crate::PlatformCredentialConnector for NeverConnect {
    fn connect(
        &self,
        _: crate::PlatformCredentialBinding,
        _: CredentialBridgeReady,
        _: crate::PlatformCredentialInput,
        _: tokio::time::Instant,
    ) -> BoxFuture<'static, Result<crate::PlatformCredentialOutput, Status>> {
        panic!("connector must not run during owner metadata admission")
    }
}

struct NeverSpawn;

impl LocalBrokerProcessSpawner for NeverSpawn {
    fn spawn(
        &self,
        _: &LocalBrokerProcessConfig,
        _: std::os::unix::net::UnixStream,
    ) -> Result<tokio::process::Child, crate::LocalBrokerSpawnError> {
        panic!("an existing matching generation must not spawn a second owner")
    }
}

fn binding(directory: PathBuf) -> crate::PlatformCredentialBinding {
    crate::PlatformCredentialBinding {
        config_directory: directory,
        server_url: "https://platform.invalid".into(),
        selection: codewire_project::PlatformProjectionSelection {
            creator: "synthetic-owner".into(),
            organization: "synthetic-org".into(),
            organization_selected: true,
            project_id: Some(Uuid::new_v4().to_string()),
            user_selected: true,
            profile: Some((Uuid::new_v4().to_string(), 3)),
            ordinary_keys: BTreeSet::from(["APP_MODE".into()]),
            reserved_keys: BTreeSet::from(["CODEX_HOME".into()]),
        },
        selection_sha256: [7; 32],
    }
}

#[tokio::test]
async fn platform_generation_reuses_only_the_exact_owner_binding() {
    let directory = tempfile::tempdir().unwrap();
    let authority = Arc::new(
        LocalCredentialAuthority::open(
            &directory.path().join("authority"),
            EphemeralProtectedStore::default(),
            builtin_provider_catalog(),
        )
        .unwrap(),
    );
    let manager = BrokerProcessManager::new(
        authority,
        Some(Arc::new(NeverSpawn)),
        Arc::new(BrokerLeaseAuditLog::default()),
        LocalSshOperationRuntime::new(None),
        Some(Arc::new(NeverConnect)),
        Arc::new(crate::broker_log::BrokerLog::disabled()),
    );
    let id = EnvironmentId::parse(Uuid::new_v4().to_string()).unwrap();
    let config = LocalBrokerProcessConfig {
        environment_id: id.clone(),
        environment_generation: 7,
        environment_name: "synthetic".into(),
        runner_socket: directory.path().join(format!("{id}.sock")),
        http_providers: BTreeSet::new(),
        platform_delegated: true,
        network_policy_allows_github: true,
    };
    let selected = binding(directory.path().join("explicit-platform-config"));
    let (finish, completed) = tokio::sync::oneshot::channel();
    manager.entries.lock().await.insert(
        id.clone(),
        BrokerProcessEntry {
            generation: 7,
            config: config.clone(),
            projection: None,
            platform: Some(selected.clone()),
            local_profile: None,
            shutdown: watch::channel(false).0,
            state: watch::channel(BrokerProcessState::Running).1,
            task: tokio::spawn(async {
                let _ = completed.await;
            }),
            drain_failed: false,
        },
    );
    let request = |platform| BrokerEnsureRequest {
        environment_id: id.clone(),
        environment_generation: 7,
        environment_name: config.environment_name.clone(),
        runner_socket: config.runner_socket.clone(),
        projection: None,
        platform: Some(platform),
        local_profile: None,
        network_policy_allows_github: true,
    };
    assert!(
        manager
            .ensure(request(selected.clone()))
            .await
            .unwrap()
            .running
    );
    let mut variants = Vec::new();
    macro_rules! changed {
        ($value:ident, $body:expr) => {{
            let mut $value = selected.clone();
            $body;
            variants.push($value);
        }};
    }
    changed!(v, v.config_directory.push("different"));
    changed!(v, v.server_url = "https://other.invalid".into());
    changed!(v, v.selection.creator = "different-owner".into());
    changed!(v, v.selection.organization = "different-org".into());
    changed!(v, v.selection.organization_selected = false);
    changed!(v, v.selection.user_selected = false);
    changed!(v, v.selection.project_id = Some(Uuid::new_v4().to_string()));
    changed!(
        v,
        v.selection.profile.as_mut().unwrap().0 = Uuid::new_v4().to_string()
    );
    changed!(v, v.selection.profile.as_mut().unwrap().1 += 1);
    changed!(v, v.selection.ordinary_keys.insert("OTHER".into()));
    changed!(v, v.selection.reserved_keys.insert("OTHER_RESERVED".into()));
    changed!(v, v.selection_sha256[0] ^= 1);
    assert_eq!(variants.len(), 12);
    for variant in variants {
        variant.validate().unwrap();
        assert_eq!(
            manager.ensure(request(variant)).await.unwrap_err().code(),
            tonic::Code::FailedPrecondition
        );
    }
    let mut mixed = request(selected.clone());
    mixed.projection = Some(crate::LocalEnvironmentProjectionBinding {
        selection: crate::LocalLaunchSecretSelection {
            project_id: None,
            user: true,
            overridden_keys: BTreeSet::new(),
            reserved_keys: BTreeSet::new(),
        },
        selection_sha256: selected.selection_sha256,
    });
    assert_eq!(
        manager.ensure(mixed).await.unwrap_err().code(),
        tonic::Code::InvalidArgument
    );
    assert!(manager.ensure(request(selected)).await.unwrap().running);
    finish.send(()).unwrap();
    manager.stop(&id, Some(7)).await.unwrap();
    assert!(manager.entries.lock().await.is_empty());
}

/// Records what each launch was told about the network policy, and never
/// starts a child.
struct RefusedSpawns(Arc<std::sync::Mutex<Vec<bool>>>);

impl LocalBrokerProcessSpawner for RefusedSpawns {
    fn spawn(
        &self,
        config: &LocalBrokerProcessConfig,
        _: std::os::unix::net::UnixStream,
    ) -> Result<tokio::process::Child, crate::LocalBrokerSpawnError> {
        self.0
            .lock()
            .unwrap()
            .push(config.network_policy_allows_github);
        Err(crate::LocalBrokerSpawnError::InvalidConfiguration)
    }
}

/// #4926: the network policy's answer for GitHub is the one part of a
/// selection that may change within a generation. The broker that served
/// under the earlier answer is stopped before its replacement is launched,
/// so a replacement that cannot start leaves none serving under the earlier
/// answer.
#[tokio::test(start_paused = true)]
async fn a_network_policy_change_stops_the_broker_before_it_launches_another() {
    let directory = tempfile::tempdir().unwrap();
    let authority = Arc::new(
        LocalCredentialAuthority::open(
            &directory.path().join("authority"),
            EphemeralProtectedStore::default(),
            builtin_provider_catalog(),
        )
        .unwrap(),
    );
    let launches = Arc::new(std::sync::Mutex::new(Vec::new()));
    let manager = BrokerProcessManager::new(
        authority,
        Some(Arc::new(RefusedSpawns(Arc::clone(&launches)))),
        Arc::new(BrokerLeaseAuditLog::default()),
        LocalSshOperationRuntime::new(None),
        Some(Arc::new(NeverConnect)),
        Arc::new(crate::broker_log::BrokerLog::disabled()),
    );
    let id = EnvironmentId::parse(Uuid::new_v4().to_string()).unwrap();
    let config = LocalBrokerProcessConfig {
        environment_id: id.clone(),
        environment_generation: 7,
        environment_name: "synthetic".into(),
        runner_socket: directory.path().join(format!("{id}.sock")),
        http_providers: BTreeSet::new(),
        platform_delegated: true,
        network_policy_allows_github: true,
    };
    let selected = binding(directory.path().join("explicit-platform-config"));
    let (shutdown, mut stopping) = watch::channel(false);
    let stopped = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let observed = Arc::clone(&stopped);
    manager.entries.lock().await.insert(
        id.clone(),
        BrokerProcessEntry {
            generation: 7,
            config: config.clone(),
            projection: None,
            platform: Some(selected.clone()),
            local_profile: None,
            shutdown,
            state: watch::channel(BrokerProcessState::Running).1,
            task: tokio::spawn(async move {
                let _ = stopping.changed().await;
                observed.store(true, std::sync::atomic::Ordering::SeqCst);
            }),
            drain_failed: false,
        },
    );
    let request = |allows| BrokerEnsureRequest {
        environment_id: id.clone(),
        environment_generation: 7,
        environment_name: config.environment_name.clone(),
        runner_socket: config.runner_socket.clone(),
        projection: None,
        platform: Some(selected.clone()),
        local_profile: None,
        network_policy_allows_github: allows,
    };

    // The same answer keeps the running broker.
    assert!(manager.ensure(request(true)).await.unwrap().running);
    assert!(!stopped.load(std::sync::atomic::Ordering::SeqCst));
    assert!(launches.lock().unwrap().is_empty());

    // The policy now refuses GitHub: the old broker is gone, and every
    // launch since was told the new answer. None started, so none runs.
    let replaced = manager.ensure(request(false)).await.unwrap();
    assert!(!replaced.running);
    assert!(stopped.load(std::sync::atomic::Ordering::SeqCst));
    let told = launches.lock().unwrap().clone();
    assert!(
        !told.is_empty() && told.iter().all(|allows| !allows),
        "{told:?}"
    );
    assert!(
        !manager.entries.lock().await[&id]
            .config
            .network_policy_allows_github
    );
    manager.stop(&id, Some(7)).await.unwrap();
}

#[test]
fn platform_startup_budget_does_not_extend_the_drain_bound() {
    assert!(BROKER_PLATFORM_START_TIMEOUT >= Duration::from_secs(7 + 15));
    assert_eq!(BROKER_LOCAL_START_TIMEOUT, Duration::from_secs(10));
    assert_eq!(BROKER_DRAIN_TIMEOUT, Duration::from_secs(10));
}

struct GitHubState(Option<bool>);

impl crate::PlatformCredentialConnector for GitHubState {
    fn connect(
        &self,
        _: crate::PlatformCredentialBinding,
        _: CredentialBridgeReady,
        _: crate::PlatformCredentialInput,
        _: tokio::time::Instant,
    ) -> BoxFuture<'static, Result<crate::PlatformCredentialOutput, Status>> {
        panic!("a GitHub state question never opens a delegation")
    }

    fn github_connected(
        &self,
        binding: crate::PlatformCredentialBinding,
        deadline: tokio::time::Instant,
    ) -> BoxFuture<'static, Result<bool, Status>> {
        // The exact pinned creator and a bounded deadline reach the connector.
        assert_eq!(binding.selection.creator, "synthetic-owner");
        assert!(deadline > tokio::time::Instant::now());
        assert!(deadline <= tokio::time::Instant::now() + PLATFORM_GITHUB_STATE_DEADLINE);
        let state = self.0;
        Box::pin(async move { state.ok_or_else(|| Status::unavailable("synthetic")) })
    }
}

/// A local VM with a platform profile decides GitHub at each start from the
/// platform account's connection, asked through the connector as the pinned
/// creator. A connector that cannot answer, or no connector, is unavailable.
#[tokio::test]
async fn a_platform_start_asks_the_connector_for_the_creators_github_connection() {
    let directory = tempfile::tempdir().unwrap();
    let manager = |connector: Option<Arc<dyn crate::PlatformCredentialConnector>>| {
        BrokerProcessManager::new(
            Arc::new(
                LocalCredentialAuthority::open(
                    &directory
                        .path()
                        .join(format!("authority-{}", Uuid::new_v4())),
                    EphemeralProtectedStore::default(),
                    builtin_provider_catalog(),
                )
                .unwrap(),
            ),
            None,
            Arc::new(BrokerLeaseAuditLog::default()),
            LocalSshOperationRuntime::new(None),
            connector,
            Arc::new(crate::broker_log::BrokerLog::disabled()),
        )
    };
    let selected = || binding(directory.path().join("explicit-platform-config")).into_proto();
    let environment = EnvironmentId::parse(Uuid::new_v4().to_string()).unwrap();
    for (state, expected) in [
        (Some(true), Some(true)),
        (Some(false), Some(false)),
        (None, None),
    ] {
        let answer = manager(Some(Arc::new(GitHubState(state))))
            .platform_github_connected(&environment, 1, selected())
            .await;
        match expected {
            Some(connected) => assert_eq!(answer.unwrap(), connected),
            None => assert_eq!(answer.unwrap_err().code(), tonic::Code::Unavailable),
        }
    }
    // The default connector method and a missing connector cannot answer.
    assert_eq!(
        manager(Some(Arc::new(NeverConnect)))
            .platform_github_connected(&environment, 1, selected())
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Unavailable
    );
    assert_eq!(
        manager(None)
            .platform_github_connected(&environment, 1, selected())
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Unavailable
    );
    // A malformed selection is refused before the connector runs.
    let mut malformed = selected();
    malformed.owner_id.clear();
    assert!(
        manager(Some(Arc::new(GitHubState(Some(true)))))
            .platform_github_connected(&environment, 1, malformed)
            .await
            .is_err()
    );
}

/// A platform that never answers cannot hold a start: the question ends at
/// its deadline, 15 seconds in production, even when the connector itself
/// never returns.
#[tokio::test]
async fn a_hung_platform_question_ends_at_its_deadline() {
    struct Hung;
    impl crate::PlatformCredentialConnector for Hung {
        fn connect(
            &self,
            _: crate::PlatformCredentialBinding,
            _: CredentialBridgeReady,
            _: crate::PlatformCredentialInput,
            _: tokio::time::Instant,
        ) -> BoxFuture<'static, Result<crate::PlatformCredentialOutput, Status>> {
            panic!("a GitHub state question never opens a delegation")
        }

        fn github_connected(
            &self,
            _: crate::PlatformCredentialBinding,
            _: tokio::time::Instant,
        ) -> BoxFuture<'static, Result<bool, Status>> {
            Box::pin(std::future::pending())
        }
    }
    let directory = tempfile::tempdir().unwrap();
    let manager = BrokerProcessManager::new(
        Arc::new(
            LocalCredentialAuthority::open(
                &directory.path().join("authority"),
                EphemeralProtectedStore::default(),
                builtin_provider_catalog(),
            )
            .unwrap(),
        ),
        None,
        Arc::new(BrokerLeaseAuditLog::default()),
        LocalSshOperationRuntime::new(None),
        Some(Arc::new(Hung)),
        Arc::new(crate::broker_log::BrokerLog::disabled()),
    );
    let environment = EnvironmentId::parse(Uuid::new_v4().to_string()).unwrap();
    assert_eq!(PLATFORM_GITHUB_STATE_DEADLINE, Duration::from_secs(15));
    let bound = Duration::from_millis(200);
    let started = tokio::time::Instant::now();
    let answer = manager
        .platform_github_connected_within(
            &environment,
            1,
            binding(directory.path().join("explicit-platform-config")).into_proto(),
            bound,
        )
        .await;
    assert_eq!(answer.unwrap_err().code(), tonic::Code::DeadlineExceeded);
    let elapsed = started.elapsed();
    assert!(
        elapsed >= bound && elapsed < bound + Duration::from_secs(5),
        "{elapsed:?}"
    );
}

/// The platform question is only for an environment a platform broker start
/// would admit: one with a local profile binding is refused before the
/// connector runs.
#[tokio::test]
async fn the_platform_question_refuses_an_environment_with_a_local_binding() {
    let directory = tempfile::tempdir().unwrap();
    let authority = Arc::new(
        LocalCredentialAuthority::open(
            &directory.path().join("authority"),
            EphemeralProtectedStore::default(),
            builtin_provider_catalog(),
        )
        .unwrap(),
    );
    let credential = authority
        .add_credential(
            crate::NewCredential {
                provider: ProviderId::parse("openai").unwrap(),
                authentication_kind: codewire_access::CredentialAuthKind::ApiKey,
                display_name: "synthetic".into(),
                account_hint: None,
                expires_at_unix: None,
            },
            codewire_protected_store::ProtectedValue::from_slice(b"synthetic-openai-material")
                .unwrap(),
        )
        .unwrap();
    let profile = authority
        .create_profile(
            codewire_access::AccessProfileName::parse("synthetic").unwrap(),
            std::collections::BTreeMap::from([(
                codewire_access::CapabilitySlot::codex(),
                credential.metadata.id.clone(),
            )]),
        )
        .unwrap();
    let bound = EnvironmentId::parse(Uuid::new_v4().to_string()).unwrap();
    authority
        .create_environment_access_binding(codewire_access::EnvironmentAccessBinding {
            environment_id: bound.clone(),
            profile_id: profile.profile.id,
            profile_revision: profile.profile.revision,
        })
        .unwrap();
    let manager = BrokerProcessManager::new(
        authority,
        None,
        Arc::new(BrokerLeaseAuditLog::default()),
        LocalSshOperationRuntime::new(None),
        Some(Arc::new(GitHubState(Some(true)))),
        Arc::new(crate::broker_log::BrokerLog::disabled()),
    );
    let selected = || binding(directory.path().join("explicit-platform-config")).into_proto();
    assert!(
        manager
            .platform_github_connected(&bound, 1, selected())
            .await
            .is_err()
    );
    let platform = EnvironmentId::parse(Uuid::new_v4().to_string()).unwrap();
    assert!(
        manager
            .platform_github_connected(&platform, 1, selected())
            .await
            .unwrap()
    );
}
