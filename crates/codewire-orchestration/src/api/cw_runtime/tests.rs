//! Deterministic capture/confinement fixtures, not live PostgreSQL, Kubernetes
//! or platform-update evidence. Credential values below are synthetic only.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use super::*;
use crate::api::environment_daemon::EnvironmentDaemonEndpointOverrides;

const ORGANIZATION: &str = "runtime-capture-organization";
const ENVIRONMENT: &str = "550e8400-e29b-41d4-a716-446655440000";
const POD_A: &str = "7e7b20f6-0bd2-4f11-8b16-9c239851eb52";
const POD_B: &str = "a1560db3-8899-40c9-b521-500f223b04fb";
const CLAIM: &str = "c0ffee00-e29b-41d4-a716-446655440000";
const SANDBOX: &str = "5a4db0c5-e29b-41d4-a716-446655440000";
const PVC: &str = "9d8c7b6a-2222-4f5e-8d4c-3b2a1f0e9d8c";
const NAMESPACE: &str = "runtime-sandboxes";
const SYNTHETIC_SECRET: &str = "runtime-capture-synthetic-key";

fn row() -> CwRuntimeLiveBinding {
    let bound = chrono::DateTime::from_timestamp(1_790_000_000, 0).unwrap();
    CwRuntimeLiveBinding {
        organization_id: ORGANIZATION.into(),
        organization_deletion_state: "active".into(),
        organization_deletion_generation: 0,
        environment_id: ENVIRONMENT.into(),
        environment_state: "running".into(),
        desired_state: "started".into(),
        environment_type: "sandbox".into(),
        isolation_tier: "standard".into(),
        environment_generation: 9,
        deletion_requested_at: None,
        backend_namespace: NAMESPACE.into(),
        backend_pod_name: format!("sandbox-{ENVIRONMENT}"),
        backend_pod_ip: "10.12.3.4".into(),
        backend_pod_uid: POD_A.into(),
        backend_claim_uid: Some(CLAIM.into()),
        backend_pvc_uid: Some(PVC.into()),
        backend_bound_at: bound,
        setup_complete: true,
        setup_owner_status: None,
        pod_uid: POD_A.into(),
        namespace: NAMESPACE.into(),
        pod_name: format!("sandbox-{ENVIRONMENT}"),
        claim_uid: CLAIM.into(),
        sandbox_uid: SANDBOX.into(),
        workspace_pvc_uid: Some(PVC.into()),
        binding_generation: 3,
        projection_selection_sha256: Some("a".repeat(64)),
        managed_credential_clients: codewire_access::ManagedCredentialClients::default()
            .encode()
            .into(),
        credential_scope: "pod".into(),
        binding_bound_at: bound,
    }
}

fn ready_probe(row: &CwRuntimeLiveBinding) -> RuntimeProbe {
    RuntimeProbe {
        claim_exists: true,
        claim_ready: true,
        replicas: 1,
        pod_exists: true,
        pod_phase: "Running".into(),
        pod_name: row.pod_name.clone(),
        pod_uid: row.pod_uid.clone(),
        pod_ip: row.backend_pod_ip.clone(),
        ..Default::default()
    }
}

struct FixtureState {
    rows: VecDeque<Option<CwRuntimeLiveBinding>>,
    probe: RuntimeProbe,
    target: (String, String, String),
    forbidden: bool,
    confidential_allowed: bool,
    // A service may point to B, but it must never obtain B's credential by
    // replacing the original captured identity.
    accepting_pod: String,
    events: Vec<&'static str>,
    connection: Option<(String, String)>,
}

struct FixtureBackend(Mutex<FixtureState>);

struct FixtureClient {
    endpoint: String,
    credential: String,
}

impl FixtureBackend {
    fn new(row: CwRuntimeLiveBinding) -> Self {
        Self(Mutex::new(FixtureState {
            rows: VecDeque::from([Some(row.clone()), Some(row.clone())]),
            probe: ready_probe(&row),
            target: (
                row.environment_id.clone(),
                row.namespace.clone(),
                row.pod_name.clone(),
            ),
            forbidden: false,
            confidential_allowed: false,
            accepting_pod: row.pod_uid,
            events: Vec::new(),
            connection: None,
        }))
    }

    fn connections(&self) -> usize {
        self.0
            .lock()
            .unwrap()
            .events
            .iter()
            .filter(|event| **event == "connect")
            .count()
    }

    fn replace_rows(&self, rows: impl IntoIterator<Item = Option<CwRuntimeLiveBinding>>) {
        self.0.lock().unwrap().rows = rows.into_iter().collect();
    }
}

#[async_trait]
impl CaptureBackend for FixtureBackend {
    type Client = FixtureClient;

    async fn authorize(&self, org: &str, env: &str) -> AppResult<SandboxTarget> {
        let mut state = self.0.lock().unwrap();
        state.events.push("authorize");
        assert_eq!(org, ORGANIZATION);
        assert_eq!(env, ENVIRONMENT);
        if state.forbidden {
            return Err(AppError::Forbidden);
        }
        Ok(SandboxTarget {
            environment_id: state.target.0.clone(),
            namespace: state.target.1.clone(),
            pod_name: state.target.2.clone(),
        })
    }

    async fn binding(&self, org: &str, env: &str) -> AppResult<Option<CwRuntimeLiveBinding>> {
        let mut state = self.0.lock().unwrap();
        state.events.push("binding");
        assert_eq!(org, ORGANIZATION);
        assert_eq!(env, ENVIRONMENT);
        Ok(state
            .rows
            .pop_front()
            .expect("fixture must provide every read"))
    }

    async fn probe(&self, namespace: &str, env: &str) -> AppResult<RuntimeProbe> {
        let mut state = self.0.lock().unwrap();
        state.events.push("probe");
        assert_eq!(namespace, NAMESPACE);
        assert_eq!(env, ENVIRONMENT);
        Ok(state.probe.clone())
    }

    async fn confidential_access(&self, _org: &str, tier: &str) -> AppResult<()> {
        let mut state = self.0.lock().unwrap();
        state.events.push("confidential");
        if tier == "confidential" && !state.confidential_allowed {
            return Err(AppError::Forbidden);
        }
        Ok(())
    }

    fn endpoint(&self, namespace: &str, env: &str) -> String {
        self.0.lock().unwrap().events.push("endpoint");
        EnvironmentDaemonEndpointOverrides::default().endpoint(namespace, env)
    }

    async fn connect(&self, endpoint: String, credential: String) -> AppResult<Self::Client> {
        let mut state = self.0.lock().unwrap();
        state.events.push("connect");
        state.connection = Some((endpoint.clone(), credential.clone()));
        let accepted = daemon_credential_for(
            SYNTHETIC_SECRET,
            ENVIRONMENT,
            &state.accepting_pod,
            WorkspaceCredentialScope::Pod,
        )
        .unwrap();
        if credential != accepted {
            return Err(AppError::Unauthorized);
        }
        Ok(FixtureClient {
            endpoint,
            credential,
        })
    }
}

#[tokio::test]
async fn captures_exact_pod_credential_and_channel_with_distinct_generations() {
    let original = row();
    let expected = incarnation(&original);
    assert_ne!(expected.environment_generation, expected.binding_generation);
    let backend = FixtureBackend::new(original.clone());
    let captured = capture(&backend, &expected, SYNTHETIC_SECRET)
        .await
        .unwrap();
    assert!(captured.row == original);
    assert_eq!(
        captured.client.endpoint,
        format!("http://cw-daemon-{ENVIRONMENT}.{NAMESPACE}.svc.cluster.local:7777")
    );
    assert_eq!(
        captured.client.credential,
        daemon_credential_for(
            SYNTHETIC_SECRET,
            ENVIRONMENT,
            POD_A,
            WorkspaceCredentialScope::Pod
        )
        .unwrap()
    );
    assert_ne!(
        captured.client.credential,
        daemon_credential_for(
            SYNTHETIC_SECRET,
            ENVIRONMENT,
            POD_A,
            WorkspaceCredentialScope::Environment
        )
        .unwrap()
    );
    assert_eq!(
        backend.0.lock().unwrap().events,
        [
            "authorize",
            "binding",
            "confidential",
            "probe",
            "binding",
            "confidential",
            "endpoint",
            "connect"
        ]
    );
}

#[tokio::test]
async fn authorization_refusal_precedes_binding_probe_and_connection() {
    let original = row();
    let backend = FixtureBackend::new(original.clone());
    backend.0.lock().unwrap().forbidden = true;
    let result = capture(&backend, &incarnation(&original), SYNTHETIC_SECRET).await;
    assert!(matches!(result, Err(AppError::Forbidden)));
    assert_eq!(backend.0.lock().unwrap().events, ["authorize"]);
}

#[tokio::test]
async fn malformed_expected_identity_is_refused_before_authorization() {
    let original = row();
    let mut variants = Vec::new();
    let mut add = |change: fn(&mut PlatformCwRuntimeIncarnation)| {
        let mut expected = incarnation(&original);
        change(&mut expected);
        variants.push(expected);
    };
    add(|e| e.organization_id.clear());
    add(|e| e.organization_id = "x".repeat(129));
    add(|e| e.organization_id.push('\n'));
    add(|e| e.environment_id = "../other".into());
    add(|e| e.pod_uid = Uuid::nil().to_string());
    add(|e| e.claim_uid = CLAIM.to_uppercase());
    add(|e| e.sandbox_uid.clear());
    add(|e| e.workspace_pvc_uid = Some("unknown".into()));
    add(|e| e.environment_generation = 0);
    add(|e| e.binding_generation = -1);
    add(|e| e.namespace = "wrong.namespace".into());
    add(|e| e.pod_name = "-invalid".into());
    add(|e| e.projection_selection_sha256 = Some("A".repeat(64)));
    add(|e| e.managed_credential_clients = "legacy".into());
    for expected in variants {
        let backend = FixtureBackend::new(original.clone());
        assert!(matches!(
            capture(&backend, &expected, SYNTHETIC_SECRET).await,
            Err(AppError::BadRequest(_))
        ));
        assert!(backend.0.lock().unwrap().events.is_empty());
    }
}

#[tokio::test]
async fn released_unbound_or_absent_binding_never_resolves_a_client() {
    // The real joined query excludes each of these cases. Here None models
    // its output without claiming PostgreSQL execution.
    let original = row();
    let backend = FixtureBackend::new(original.clone());
    backend.replace_rows([None]);
    assert!(matches!(
        capture(&backend, &incarnation(&original), SYNTHETIC_SECRET).await,
        Err(AppError::Coded {
            code: "invalid_state",
            ..
        })
    ));
    assert_eq!(backend.0.lock().unwrap().events, ["authorize", "binding"]);
}

#[tokio::test]
async fn each_expected_immutable_identity_member_must_match_the_joined_row() {
    let original = row();
    let changes: [fn(&mut CwRuntimeLiveBinding); 14] = [
        |r| r.organization_id = "other-organization".into(),
        |r| r.environment_id = POD_B.into(),
        |r| r.environment_generation += 1,
        |r| r.namespace = "other-namespace".into(),
        |r| r.pod_name = "other-pod".into(),
        |r| r.pod_uid = POD_B.into(),
        |r| r.claim_uid = POD_B.into(),
        |r| r.sandbox_uid = POD_B.into(),
        |r| r.workspace_pvc_uid = Some(POD_B.into()),
        |r| r.workspace_pvc_uid = None,
        |r| r.binding_generation += 1,
        |r| r.projection_selection_sha256 = Some("b".repeat(64)),
        |r| r.managed_credential_clients = "v2:01".into(),
        |r| r.binding_bound_at += chrono::Duration::seconds(1),
    ];
    for (index, change) in changes.into_iter().enumerate() {
        let backend = FixtureBackend::new(original.clone());
        let mut changed = original.clone();
        change(&mut changed);
        backend.replace_rows([Some(changed)]);
        assert!(
            matches!(
                capture(&backend, &incarnation(&original), SYNTHETIC_SECRET).await,
                Err(AppError::Coded {
                    code: "invalid_state",
                    ..
                })
            ),
            "identity case {index}"
        );
        assert_eq!(backend.connections(), 0);
        assert!(!backend.0.lock().unwrap().events.contains(&"probe"));
    }
}

#[tokio::test]
async fn backend_pointer_claim_pvc_and_ip_incoherence_refuse_before_probe() {
    let original = row();
    let changes: [fn(&mut CwRuntimeLiveBinding); 8] = [
        |r| r.backend_namespace = "other-namespace".into(),
        |r| r.backend_pod_name = "other-pod".into(),
        |r| r.backend_pod_uid = POD_B.into(),
        |r| r.backend_claim_uid = Some(POD_B.into()),
        |r| r.backend_claim_uid = None,
        |r| r.backend_pvc_uid = Some(POD_B.into()),
        |r| r.backend_pvc_uid = None,
        |r| r.backend_pod_ip = "not-an-ip".into(),
    ];
    for (index, change) in changes.into_iter().enumerate() {
        let backend = FixtureBackend::new(original.clone());
        let mut changed = original.clone();
        change(&mut changed);
        backend.replace_rows([Some(changed)]);
        assert!(
            matches!(
                capture(&backend, &incarnation(&original), SYNTHETIC_SECRET).await,
                Err(AppError::Coded {
                    code: "invalid_state",
                    ..
                })
            ),
            "pointer case {index}"
        );
        assert_eq!(backend.connections(), 0);
        assert!(!backend.0.lock().unwrap().events.contains(&"probe"));
    }
}

#[tokio::test]
async fn authorized_name_is_not_authority_for_another_namespace_or_environment() {
    for member in 0..3 {
        let original = row();
        let backend = FixtureBackend::new(original.clone());
        {
            let mut state = backend.0.lock().unwrap();
            match member {
                0 => state.target.0 = POD_B.into(),
                1 => state.target.1 = "other-namespace".into(),
                _ => state.target.2 = "other-pod".into(),
            }
        }
        assert!(matches!(
            capture(&backend, &incarnation(&original), SYNTHETIC_SECRET).await,
            Err(AppError::Coded {
                code: "invalid_state",
                ..
            })
        ));
        assert_eq!(backend.connections(), 0);
    }
}

#[tokio::test]
async fn running_desired_started_sandbox_nondeleting_and_setup_idle_are_mandatory() {
    let original = row();
    let changes: [fn(&mut CwRuntimeLiveBinding); 8] = [
        |r| r.environment_state = "stopped".into(),
        |r| r.desired_state = "stopped".into(),
        |r| r.environment_type = "host".into(),
        |r| r.organization_deletion_state = "deleting".into(),
        |r| r.organization_deletion_state = "delete_failed".into(),
        |r| r.deletion_requested_at = Some(r.binding_bound_at.naive_utc()),
        |r| r.setup_complete = false,
        |r| r.setup_owner_status = Some("running".into()),
    ];
    for (index, change) in changes.into_iter().enumerate() {
        let backend = FixtureBackend::new(original.clone());
        let mut changed = original.clone();
        change(&mut changed);
        backend.replace_rows([Some(changed)]);
        assert!(
            matches!(
                capture(&backend, &incarnation(&original), SYNTHETIC_SECRET).await,
                Err(AppError::Precondition(_))
            ),
            "gate case {index}"
        );
        assert_eq!(backend.connections(), 0);
        assert!(!backend.0.lock().unwrap().events.contains(&"probe"));
    }
}

#[tokio::test]
async fn confidential_gate_is_applied_to_fresh_binding_not_prior_authorization() {
    let mut original = row();
    original.isolation_tier = "confidential".into();
    let backend = FixtureBackend::new(original.clone());
    assert!(matches!(
        capture(&backend, &incarnation(&original), SYNTHETIC_SECRET).await,
        Err(AppError::Forbidden)
    ));
    assert_eq!(backend.connections(), 0);
    backend.replace_rows([Some(original.clone()), Some(original.clone())]);
    backend.0.lock().unwrap().confidential_allowed = true;
    assert!(
        capture(&backend, &incarnation(&original), SYNTHETIC_SECRET)
            .await
            .is_ok()
    );
    assert_eq!(backend.connections(), 1);
}

#[tokio::test]
async fn legacy_environment_scope_and_unknown_scope_have_no_token_fallback() {
    for scope in ["environment", "unknown"] {
        let mut original = row();
        original.credential_scope = scope.into();
        let backend = FixtureBackend::new(original.clone());
        assert!(matches!(
            capture(&backend, &incarnation(&original), SYNTHETIC_SECRET).await,
            Err(AppError::Precondition(_))
        ));
        assert_eq!(backend.connections(), 0);
        assert!(!backend.0.lock().unwrap().events.contains(&"endpoint"));
    }
}

#[tokio::test]
async fn probe_requires_exact_running_original_pod_even_if_name_or_ip_is_reused() {
    let original = row();
    let changes: [fn(&mut RuntimeProbe); 7] = [
        |p| p.claim_exists = false,
        |p| p.claim_ready = false,
        |p| p.pod_exists = false,
        |p| p.pod_phase = "Pending".into(),
        |p| p.pod_name = "other-pod".into(),
        |p| p.pod_uid = POD_B.into(),
        |p| p.pod_ip = "10.12.3.5".into(),
    ];
    for (index, change) in changes.into_iter().enumerate() {
        let backend = FixtureBackend::new(original.clone());
        change(&mut backend.0.lock().unwrap().probe);
        assert!(
            matches!(
                capture(&backend, &incarnation(&original), SYNTHETIC_SECRET).await,
                Err(AppError::Coded {
                    code: "invalid_state",
                    ..
                })
            ),
            "probe case {index}"
        );
        assert_eq!(backend.connections(), 0);
        assert_eq!(
            backend
                .0
                .lock()
                .unwrap()
                .events
                .iter()
                .filter(|e| **e == "binding")
                .count(),
            1
        );
    }
}

#[tokio::test]
async fn binding_release_between_probe_and_reread_refuses_before_connect() {
    let original = row();
    let backend = FixtureBackend::new(original.clone());
    backend.replace_rows([Some(original.clone()), None]);
    assert!(matches!(
        capture(&backend, &incarnation(&original), SYNTHETIC_SECRET).await,
        Err(AppError::Coded {
            code: "invalid_state",
            ..
        })
    ));
    assert_eq!(backend.connections(), 0);
    assert!(backend.0.lock().unwrap().events.contains(&"probe"));
}

#[tokio::test]
async fn complete_row_reread_refuses_mutable_gate_and_pointer_changes() {
    let original = row();
    let changes: [fn(&mut CwRuntimeLiveBinding); 7] = [
        |r| {
            r.pod_uid = POD_B.into();
            r.backend_pod_uid = POD_B.into();
        },
        |r| r.backend_pod_ip = "10.12.3.5".into(),
        |r| r.backend_bound_at += chrono::Duration::seconds(1),
        |r| r.environment_generation += 1,
        |r| r.setup_owner_status = Some("claimed".into()),
        |r| r.isolation_tier = "confidential".into(),
        |r| r.organization_deletion_generation += 1,
    ];
    for (index, change) in changes.into_iter().enumerate() {
        let backend = FixtureBackend::new(original.clone());
        let mut changed = original.clone();
        change(&mut changed);
        backend.replace_rows([Some(original.clone()), Some(changed)]);
        assert!(
            matches!(
                capture(&backend, &incarnation(&original), SYNTHETIC_SECRET).await,
                Err(AppError::Coded {
                    code: "invalid_state",
                    ..
                })
            ),
            "reread case {index}"
        );
        assert_eq!(backend.connections(), 0);
    }
}

#[tokio::test]
async fn service_retarget_can_receive_only_original_pod_token_not_latest_token() {
    let original = row();
    let backend = FixtureBackend::new(original.clone());
    backend.0.lock().unwrap().accepting_pod = POD_B.into();
    assert!(matches!(
        capture(&backend, &incarnation(&original), SYNTHETIC_SECRET).await,
        Err(AppError::Unauthorized)
    ));
    let state = backend.0.lock().unwrap();
    let (_, issued) = state.connection.as_ref().unwrap();
    assert_eq!(
        *issued,
        daemon_credential_for(
            SYNTHETIC_SECRET,
            ENVIRONMENT,
            POD_A,
            WorkspaceCredentialScope::Pod
        )
        .unwrap()
    );
    assert_ne!(
        *issued,
        daemon_credential_for(
            SYNTHETIC_SECRET,
            ENVIRONMENT,
            POD_B,
            WorkspaceCredentialScope::Pod
        )
        .unwrap()
    );
    drop(state);
    assert_eq!(backend.connections(), 1);
}

#[tokio::test]
async fn recheck_keeps_original_client_and_does_not_follow_replacement_binding() {
    let original = row();
    let expected = incarnation(&original);
    let backend = FixtureBackend::new(original.clone());
    let captured = capture(&backend, &expected, SYNTHETIC_SECRET)
        .await
        .unwrap();
    let credential = captured.client.credential.clone();
    let mut replacement = original.clone();
    replacement.pod_uid = POD_B.into();
    replacement.backend_pod_uid = POD_B.into();
    backend.replace_rows([Some(replacement)]);
    assert!(matches!(
        recheck_capture(&backend, &expected, &captured.row).await,
        Err(AppError::Coded {
            code: "invalid_state",
            ..
        })
    ));
    assert_eq!(captured.client.credential, credential);
    assert_eq!(backend.connections(), 1);
}

#[tokio::test]
async fn recheck_compares_full_capture_even_when_public_incarnation_is_unchanged() {
    let original = row();
    let expected = incarnation(&original);
    let backend = FixtureBackend::new(original.clone());
    let captured = capture(&backend, &expected, SYNTHETIC_SECRET)
        .await
        .unwrap();
    let mut changed = original;
    changed.backend_bound_at += chrono::Duration::seconds(1);
    assert_eq!(incarnation(&changed), expected);
    backend.replace_rows([Some(changed.clone()), Some(changed)]);
    assert!(matches!(
        recheck_capture(&backend, &expected, &captured.row).await,
        Err(AppError::Coded {
            code: "invalid_state",
            ..
        })
    ));
    assert_eq!(backend.connections(), 1);
}

#[tokio::test]
async fn unchanged_recheck_preserves_original_channel_without_reconnect() {
    let original = row();
    let expected = incarnation(&original);
    let backend = FixtureBackend::new(original.clone());
    let captured = capture(&backend, &expected, SYNTHETIC_SECRET)
        .await
        .unwrap();
    backend.replace_rows([Some(original.clone()), Some(original)]);
    recheck_capture(&backend, &expected, &captured.row)
        .await
        .unwrap();
    assert_eq!(backend.connections(), 1);
}

#[tokio::test]
async fn empty_credential_secret_cannot_connect() {
    let original = row();
    let backend = FixtureBackend::new(original.clone());
    assert!(matches!(
        capture(&backend, &incarnation(&original), "").await,
        Err(AppError::Upstream(_))
    ));
    assert_eq!(backend.connections(), 0);
}

#[tokio::test]
async fn deadline_cancels_the_same_pending_read_with_value_blind_error() {
    struct OnDrop<'a>(&'a AtomicBool);
    impl Drop for OnDrop<'_> {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    let dropped = AtomicBool::new(false);
    let guard = OnDrop(&dropped);
    let error = bounded(
        async move {
            let _held = guard;
            std::future::pending::<AppResult<()>>().await
        },
        Duration::from_millis(1),
    )
    .await
    .unwrap_err();
    assert!(matches!(error, AppError::Upstream(_)));
    assert!(dropped.load(Ordering::SeqCst));
    assert_eq!(
        error.to_string(),
        "upstream service unavailable: environment runtime capture is unavailable"
    );
}

#[test]
fn canonical_and_closed_kind_endpoints_are_the_existing_resolver() {
    let defaults = EnvironmentDaemonEndpointOverrides::default();
    assert_eq!(
        defaults.endpoint(NAMESPACE, ENVIRONMENT),
        format!("http://cw-daemon-{ENVIRONMENT}.{NAMESPACE}.svc.cluster.local:7777")
    );
    let configured = format!(r#"{{"{ENVIRONMENT}":"http://127.0.0.1:8090"}}"#);
    assert!(
        EnvironmentDaemonEndpointOverrides::from_testing_config(false, Some(&configured)).is_err()
    );
    let overrides =
        EnvironmentDaemonEndpointOverrides::from_testing_config(true, Some(&configured)).unwrap();
    assert_eq!(
        overrides.endpoint(NAMESPACE, ENVIRONMENT),
        "http://127.0.0.1:8090"
    );
    assert_eq!(
        overrides.endpoint(NAMESPACE, POD_B),
        defaults.endpoint(NAMESPACE, POD_B)
    );
}
