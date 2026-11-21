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
    fn runner_protocol(&self) -> u32 {
        crate::broker_process::TEST_RUNNER_PROTOCOL
    }

    fn spawn(
        &self,
        _: &LocalBrokerProcessConfig,
        _: &crate::ProviderLookup,
        _: std::os::unix::net::UnixStream,
        _boot_secrets: &crate::BrokerBootSecrets,
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
        network_policy_allowed_hosts: Default::default(),
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
        network_policy_allowed_hosts: Default::default(),
        boot_secrets: Default::default(),
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

/// Records what each launch was told, and never starts a child.
struct RefusedSpawns(Arc<std::sync::Mutex<Vec<LocalBrokerProcessConfig>>>);

impl LocalBrokerProcessSpawner for RefusedSpawns {
    fn runner_protocol(&self) -> u32 {
        crate::broker_process::TEST_RUNNER_PROTOCOL
    }

    fn spawn(
        &self,
        config: &LocalBrokerProcessConfig,
        _: &crate::ProviderLookup,
        _: std::os::unix::net::UnixStream,
        _: &crate::BrokerBootSecrets,
    ) -> Result<tokio::process::Child, crate::LocalBrokerSpawnError> {
        self.0.lock().unwrap().push(config.clone());
        Err(crate::LocalBrokerSpawnError::InvalidConfiguration)
    }
}

/// A manager holding one running broker for generation 7, started under
/// `config`, whose stop is recorded, and the launches it makes after.
struct RunningBroker {
    manager: BrokerProcessManager<EphemeralProtectedStore>,
    id: EnvironmentId,
    config: LocalBrokerProcessConfig,
    selected: crate::PlatformCredentialBinding,
    stopped: Arc<std::sync::atomic::AtomicBool>,
    launches: Arc<std::sync::Mutex<Vec<LocalBrokerProcessConfig>>>,
}

impl RunningBroker {
    async fn new(directory: &std::path::Path) -> Self {
        let authority = Arc::new(
            LocalCredentialAuthority::open(
                &directory.join("authority"),
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
            runner_socket: directory.join(format!("{id}.sock")),
            http_providers: BTreeSet::new(),
            platform_delegated: true,
            network_policy_allows_github: true,
            network_policy_allowed_hosts: ["api.anthropic.com".to_owned()].into(),
        };
        let selected = binding(directory.join("explicit-platform-config"));
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
        Self {
            manager,
            id,
            config,
            selected,
            stopped,
            launches,
        }
    }

    fn request(&self, allows_github: bool, allowed_hosts: &[&str]) -> BrokerEnsureRequest {
        BrokerEnsureRequest {
            environment_id: self.id.clone(),
            environment_generation: 7,
            environment_name: self.config.environment_name.clone(),
            runner_socket: self.config.runner_socket.clone(),
            projection: None,
            platform: Some(self.selected.clone()),
            local_profile: None,
            network_policy_allows_github: allows_github,
            network_policy_allowed_hosts: allowed_hosts
                .iter()
                .map(|host| (*host).to_owned())
                .collect(),
            boot_secrets: Default::default(),
        }
    }

    fn stopped(&self) -> bool {
        self.stopped.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn launches(&self) -> Vec<LocalBrokerProcessConfig> {
        self.launches.lock().unwrap().clone()
    }
}

/// #4926: the network policy's answer for GitHub is one part of a selection
/// that may change within a generation. The broker that served under the
/// earlier answer is stopped before its replacement is launched, so a
/// replacement that cannot start leaves none serving under the earlier
/// answer.
#[tokio::test(start_paused = true)]
async fn a_network_policy_change_stops_the_broker_before_it_launches_another() {
    let directory = tempfile::tempdir().unwrap();
    let running = RunningBroker::new(directory.path()).await;

    // The same answer keeps the running broker.
    let same = running.request(true, &["api.anthropic.com"]);
    assert!(running.manager.ensure(same).await.unwrap().running);
    assert!(!running.stopped());
    assert!(running.launches().is_empty());

    // The policy now refuses GitHub: the old broker is gone, and every
    // launch since was told the new answer. None started, so none runs.
    let refused = running.request(false, &["api.anthropic.com"]);
    let replaced = running.manager.ensure(refused).await.unwrap();
    assert!(!replaced.running);
    assert!(running.stopped());
    let told = running.launches();
    assert!(
        !told.is_empty()
            && told
                .iter()
                .all(|config| !config.network_policy_allows_github),
        "{told:?}"
    );
    assert!(
        !running.manager.entries.lock().await[&running.id]
            .config
            .network_policy_allows_github
    );
    running.manager.stop(&running.id, Some(7)).await.unwrap();
}

/// #5555: the bound hosts the policy allows change with it too. An edit
/// that removes the rule for a host stops the broker that would still
/// forward to it, and every launch after is told the new hosts.
#[tokio::test(start_paused = true)]
async fn a_policy_edit_to_the_allowed_hosts_stops_the_broker_before_it_launches_another() {
    let directory = tempfile::tempdir().unwrap();
    let running = RunningBroker::new(directory.path()).await;

    let edited = running.request(true, &["chatgpt.com"]);
    let replaced = running.manager.ensure(edited).await.unwrap();
    assert!(!replaced.running);
    assert!(running.stopped());
    let told = running.launches();
    let expected: BTreeSet<String> = ["chatgpt.com".to_owned()].into();
    assert!(
        !told.is_empty()
            && told
                .iter()
                .all(|config| config.network_policy_allowed_hosts == expected),
        "{told:?}"
    );
    running.manager.stop(&running.id, Some(7)).await.unwrap();
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
