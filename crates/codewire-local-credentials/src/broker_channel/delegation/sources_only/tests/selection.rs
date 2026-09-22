//! Exact local profile remains pinned across a concurrent owner mutation.

use super::*;
use codewire_access::{
    AccessProfileName, CapabilitySlot, CredentialAuthKind, EnvironmentAccessBinding, ProviderId,
};

fn profile(f: &Fixture, name: &str) -> EnvironmentAccessBinding {
    let credential = f
        .rpc
        .authority
        .add_credential(
            crate::NewCredential {
                provider: ProviderId::parse("openai").unwrap(),
                authentication_kind: CredentialAuthKind::OAuth,
                display_name: name.into(),
                account_hint: None,
                expires_at_unix: None,
            },
            ProtectedValue::from_slice(b"synthetic-profile-selection").unwrap(),
        )
        .unwrap();
    let profile = f
        .rpc
        .authority
        .create_profile(
            AccessProfileName::parse(name).unwrap(),
            [(CapabilitySlot::codex(), credential.metadata.id)].into(),
        )
        .unwrap()
        .profile;
    EnvironmentAccessBinding {
        environment_id: f.rpc.environment_id.clone(),
        profile_id: profile.id,
        profile_revision: profile.revision,
    }
}

fn bind(f: &mut Fixture, selected: Option<EnvironmentAccessBinding>) {
    if let Some(binding) = &selected {
        f.rpc
            .authority
            .create_environment_access_binding(binding.clone())
            .unwrap();
    }
    Arc::get_mut(&mut f.rpc).unwrap().local_profile = selected;
}

fn replace(f: &Fixture, selected: &EnvironmentAccessBinding) {
    match &f.rpc.local_profile {
        Some(old) => {
            f.rpc
                .authority
                .replace_environment_access_binding(
                    &old.environment_id,
                    &old.profile_id,
                    old.profile_revision,
                    selected.profile_id.clone(),
                    selected.profile_revision,
                )
                .unwrap();
        }
        None => {
            f.rpc
                .authority
                .create_environment_access_binding(selected.clone())
                .unwrap();
        }
    }
}

struct PausedAdmission {
    inner: Arc<dyn PlatformCredentialConnector>,
    entered: Arc<Notify>,
    release: Arc<Semaphore>,
}

impl PlatformCredentialConnector for PausedAdmission {
    fn connect(
        &self,
        binding: PlatformCredentialBinding,
        ready: bridge::CredentialBridgeReady,
        input: PlatformCredentialInput,
        deadline: Instant,
    ) -> BoxFuture<'static, Result<PlatformCredentialOutput, Status>> {
        let inner = Arc::clone(&self.inner);
        let entered = Arc::clone(&self.entered);
        let release = Arc::clone(&self.release);
        Box::pin(async move {
            entered.notify_one();
            release.acquire().await.unwrap().forget();
            inner.connect(binding, ready, input, deadline).await
        })
    }
}

#[tokio::test]
async fn sources_only_profile_change_during_platform_admission_never_reports_ready() {
    for initially_selected in [false, true] {
        let mut f = fixture(Mode::Seal, true);
        let old = initially_selected.then(|| profile(&f, "old"));
        bind(&mut f, old);
        let replacement = profile(&f, "new");
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Semaphore::new(0));
        {
            let mut platform = f.rpc.platform.lock().await;
            let (binding, inner) = platform.take().unwrap();
            *platform = Some((
                binding,
                Arc::new(PausedAdmission {
                    inner,
                    entered: Arc::clone(&entered),
                    release: Arc::clone(&release),
                }),
            ));
        }
        let rpc = Arc::clone(&f.rpc);
        let guest_ready = ready(&f);
        let task = tokio::spawn(async move {
            rpc.report_broker_ready(Request::new(v1::BrokerReadyRequest {
                protocol_version: BROKER_LEASE_PROTOCOL_VERSION,
                guest_ready: Some(guest_ready),
            }))
            .await
        });
        tokio::time::timeout(Duration::from_secs(2), entered.notified())
            .await
            .unwrap();
        replace(&f, &replacement);
        release.add_permits(1);
        let error = task.await.unwrap().unwrap_err();
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert!(f.manager_ready.await.is_err());
        assert!(f.rpc.refresh_lifetime.closed.load(Ordering::Acquire));
    }
}

#[tokio::test]
async fn sources_only_profile_change_after_ready_denies_http_and_refresh() {
    for initially_selected in [false, true] {
        let mut f = fixture(Mode::Seal, true);
        let old = initially_selected.then(|| profile(&f, "old"));
        bind(&mut f, old);
        let replacement = profile(&f, "new");
        admit(&f).await.unwrap();
        let operation = crate::CredentialOperationLeaseRequest {
            environment_id: f.rpc.environment_id.clone(),
            environment_generation: f.rpc.environment_generation,
            capability_slot: CapabilitySlot::codex(),
            operation: codewire_access::BrokerOperationId::parse("responses").unwrap(),
            route: codewire_access::BrokerRouteId::parse("openai-api").unwrap(),
        };
        let old_admission = initially_selected.then(|| {
            f.rpc
                .authority
                .admit_environment_credential_operation(&operation)
                .unwrap()
        });
        replace(&f, &replacement);
        let error = f
            .rpc
            .lease_credential_operation(Request::new(v1::BrokerLeaseRequest {
                request_id: Uuid::new_v4().to_string(),
                capability_slot: "codex".into(),
                operation: "responses".into(),
                route: "openai-api".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        let new_admission = f
            .rpc
            .authority
            .admit_environment_credential_operation(&operation)
            .unwrap();
        for (admission, expected) in std::iter::once((new_admission, tonic::Code::PermissionDenied))
            .chain(old_admission.map(|admission| (admission, tonic::Code::OutOfRange)))
        {
            let error = f
                .rpc
                .begin_credential_refresh(Request::new(v1::BrokerCredentialRefreshRequest {
                    refresh_id: Uuid::new_v4().to_string(),
                    request_id: Uuid::new_v4().to_string(),
                    grant: Some(crate::service::derived_grant_to_proto(admission.grant)),
                    operation: "responses".into(),
                    route: "openai-api".into(),
                    expected_material_generation: admission.material_generation,
                }))
                .await
                .unwrap_err();
            assert_eq!(error.code(), expected);
        }
    }
}
