use std::path::Path;
use std::sync::Mutex;

use codewire_access::{CredentialPlaceholder, builtin_provider_catalog};
use codewire_daemon_proto::codewire::bridge::v1::CredentialBridgeReady;
use codewire_protected_store::EphemeralProtectedStore;
use futures::future::BoxFuture;
use uuid::Uuid;

use super::super::{BrokerLeaseAuditLog, LocalSshOperationRuntime};
use super::*;
use crate::LocalCredentialAuthority;
use crate::broker_log::BrokerLog;

/// What one seed question carried to the connector.
type Asked = (String, String, u64, Vec<CapabilitySlot>);

/// Answers each requested slot it is told to grant, and records the
/// question.
struct Platform {
    grants: Vec<CapabilitySlot>,
    asked: Mutex<Vec<Asked>>,
}

fn placeholder() -> CredentialPlaceholder {
    CredentialPlaceholder::parse(&format!("cwp1_{}A", "C".repeat(42))).unwrap()
}

impl crate::PlatformCredentialConnector for Platform {
    fn connect(
        &self,
        _: crate::PlatformCredentialBinding,
        _: CredentialBridgeReady,
        _: crate::PlatformCredentialInput,
        _: tokio::time::Instant,
    ) -> BoxFuture<'static, Result<crate::PlatformCredentialOutput, Status>> {
        panic!("a seed question never opens a delegation")
    }

    fn environment_credential_placeholders(
        &self,
        binding: crate::PlatformCredentialBinding,
        environment_id: String,
        environment_generation: u64,
        slots: Vec<CapabilitySlot>,
        deadline: tokio::time::Instant,
    ) -> BoxFuture<'static, Result<Vec<(CapabilitySlot, CredentialPlaceholder)>, Status>> {
        // One bounded deadline covers the whole question.
        assert!(deadline > tokio::time::Instant::now());
        assert!(deadline <= tokio::time::Instant::now() + PLATFORM_PLACEHOLDERS_DEADLINE);
        self.asked.lock().unwrap().push((
            binding.selection.creator,
            environment_id,
            environment_generation,
            slots.clone(),
        ));
        let granted = slots
            .into_iter()
            .filter(|slot| self.grants.contains(slot))
            .map(|slot| (slot, placeholder()))
            .collect();
        Box::pin(async move { Ok(granted) })
    }
}

fn manager(
    directory: &Path,
    connector: Option<Arc<dyn crate::PlatformCredentialConnector>>,
) -> Arc<BrokerProcessManager<EphemeralProtectedStore>> {
    Arc::new(BrokerProcessManager::new(
        Arc::new(
            LocalCredentialAuthority::open(
                &directory.join(format!("authority-{}", Uuid::new_v4())),
                EphemeralProtectedStore::default(),
                builtin_provider_catalog(),
            )
            .unwrap(),
        ),
        None,
        Arc::new(BrokerLeaseAuditLog::default()),
        LocalSshOperationRuntime::new(None),
        connector,
        Arc::new(BrokerLog::disabled()),
    ))
}

fn platform(directory: &Path) -> v1::PlatformCredentialBinding {
    crate::PlatformCredentialBinding {
        config_directory: directory.join("explicit-platform-config"),
        server_url: "https://platform.invalid".into(),
        selection: codewire_project::PlatformProjectionSelection {
            creator: "synthetic-owner".into(),
            organization: "synthetic-org".into(),
            organization_selected: false,
            project_id: None,
            user_selected: false,
            profile: Some((Uuid::new_v4().to_string(), 3)),
            ordinary_keys: Default::default(),
            reserved_keys: ["CODEX_HOME".into()].into(),
        },
        selection_sha256: [7; 32],
        front_door: false,
    }
    .into_proto()
}

fn request(
    environment: &str,
    platform: Option<v1::PlatformCredentialBinding>,
) -> v1::GetEnvironmentCredentialPlaceholdersRequest {
    v1::GetEnvironmentCredentialPlaceholdersRequest {
        environment_id: environment.to_owned(),
        environment_generation: 4,
        capability_slots: vec!["anthropic".into(), "github".into()],
        platform,
        ..Default::default()
    }
}

/// A platform binding is asked of the platform, as its selection's creator,
/// for the boot's own environment ID and generation; the answer is passed on
/// slot by slot (#4001).
#[tokio::test]
async fn a_platform_binding_is_answered_by_the_platform() {
    let directory = tempfile::tempdir().unwrap();
    let connector = Arc::new(Platform {
        grants: vec![CapabilitySlot::anthropic()],
        asked: Mutex::default(),
    });
    let environment = Uuid::new_v4().to_string();
    let answer = environment_credential_placeholders(
        manager(directory.path(), Some(connector.clone())),
        request(&environment, Some(platform(directory.path()))),
    )
    .await
    .unwrap();
    assert_eq!(answer.placeholders.len(), 1);
    assert_eq!(answer.placeholders[0].capability_slot, "anthropic");
    assert!(
        CredentialPlaceholder::parse(&answer.placeholders[0].placeholder)
            .unwrap()
            .ct_eq(&placeholder())
    );
    assert_eq!(
        *connector.asked.lock().unwrap(),
        [(
            "synthetic-owner".to_owned(),
            environment,
            4,
            vec![CapabilitySlot::anthropic(), CapabilitySlot::github()]
        )]
    );
}

/// A platform question names no local profile; without a connector, or with
/// one that predates the question, it is unavailable.
#[tokio::test]
async fn a_platform_question_needs_a_connector_and_names_no_local_profile() {
    let directory = tempfile::tempdir().unwrap();
    let environment = Uuid::new_v4().to_string();
    let mut with_profile = request(&environment, Some(platform(directory.path())));
    with_profile.profile_id = Uuid::new_v4().to_string();
    with_profile.profile_revision = 3;
    let connector = Arc::new(Platform {
        grants: Vec::new(),
        asked: Mutex::default(),
    });
    let refused = environment_credential_placeholders(
        manager(directory.path(), Some(connector.clone())),
        with_profile,
    )
    .await
    .unwrap_err();
    assert_eq!(refused.code(), tonic::Code::InvalidArgument);
    assert!(connector.asked.lock().unwrap().is_empty());

    struct Older;
    impl crate::PlatformCredentialConnector for Older {
        fn connect(
            &self,
            _: crate::PlatformCredentialBinding,
            _: CredentialBridgeReady,
            _: crate::PlatformCredentialInput,
            _: tokio::time::Instant,
        ) -> BoxFuture<'static, Result<crate::PlatformCredentialOutput, Status>> {
            panic!("a seed question never opens a delegation")
        }
    }
    for connector in [
        None,
        Some(Arc::new(Older) as Arc<dyn crate::PlatformCredentialConnector>),
    ] {
        let status = environment_credential_placeholders(
            manager(directory.path(), connector),
            request(&environment, Some(platform(directory.path()))),
        )
        .await
        .unwrap_err();
        assert_eq!(status.code(), tonic::Code::Unavailable);
    }
}
