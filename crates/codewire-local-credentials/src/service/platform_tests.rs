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

#[test]
fn platform_startup_budget_does_not_extend_the_drain_bound() {
    assert!(BROKER_PLATFORM_START_TIMEOUT >= Duration::from_secs(7 + 15));
    assert_eq!(BROKER_LOCAL_START_TIMEOUT, Duration::from_secs(10));
    assert_eq!(BROKER_DRAIN_TIMEOUT, Duration::from_secs(10));
}
