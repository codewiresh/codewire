//! A broker channel's bound-secret grants and leases come from its own
//! boot record and selection, never from what a request names (#4003).
//! Synthetic values only.

use codewire_access::{BindingWrite, StoredBinding, StoredPresentation, builtin_provider_catalog};
use codewire_protected_store::{EphemeralProtectedStore, ProtectedValue};
use codewire_workload_secrets::ProjectionContext;

use super::*;

const CANARY: &str = "canary-channel-bound-value";

fn binding() -> BindingWrite {
    BindingWrite::Bind(StoredBinding {
        hosts: vec!["api.fancy.com".into()],
        presentation: StoredPresentation::Header {
            headers: vec!["Authorization".into()],
            scheme: Some("Bearer".into()),
        },
        prefix: None,
        preset: None,
    })
}

/// A channel whose boot recorded `FANCY_TOKEN`, and the record.
fn channel() -> (
    tempfile::TempDir,
    BrokerLeaseRpc<EphemeralProtectedStore>,
    Vec<FirstBindSecret>,
) {
    let temp = tempfile::tempdir().unwrap();
    let authority = Arc::new(
        LocalCredentialAuthority::open(
            &temp.path().join("authority"),
            EphemeralProtectedStore::default(),
            builtin_provider_catalog(),
        )
        .unwrap(),
    );
    authority
        .write_user_workload_secret(
            "FANCY_TOKEN",
            Some(ProtectedValue::from_slice(CANARY.as_bytes()).unwrap()),
            binding(),
            true,
        )
        .unwrap();
    let selection = LocalLaunchSecretSelection {
        user: true,
        ..Default::default()
    };
    let record = authority.record_boot_bound_secrets(&selection).unwrap();
    let context = ProjectionContext {
        environment_id: *Uuid::new_v4().as_bytes(),
        operation_generation: 7,
        selection_sha256: [2; 32],
        deadline_unix_ms: crate::unix_millis().unwrap() + 30_000,
    };
    let refresh_lifetime = BrokerChannelRefreshLifetime::new(Arc::clone(&authority));
    let channel_id = refresh_lifetime.channel_id;
    let rpc = BrokerLeaseRpc {
        local_profile: None,
        refresh_lifetime,
        authority,
        channel_id,
        environment_id: EnvironmentId::parse(Uuid::from_bytes(context.environment_id).to_string())
            .unwrap(),
        environment_generation: context.operation_generation,
        audit: Arc::new(BrokerLeaseAuditLog::default()),
        ready: Mutex::new(None),
        projection: Some(LocalEnvironmentProjectionBinding {
            selection,
            selection_sha256: context.selection_sha256,
            bound_secrets: Some(record.clone()),
        }),
        projection_operations: Arc::new(Semaphore::new(1)),
        platform: Mutex::new(None),
        platform_mode: BrokerPlatformMode::Local,
        platform_admitted: Arc::new(AtomicBool::new(false)),
        platform_sources: Mutex::new(None),
        front_door: Default::default(),
    };
    (temp, rpc, record)
}

fn lease(record: &FirstBindSecret, host: &str, value: bool) -> v1::BoundSecretLeaseRequest {
    v1::BoundSecretLeaseRequest {
        path: record.path.clone(),
        key: record.key.clone(),
        host: host.into(),
        value,
    }
}

/// The grants are the boot's record with each placeholder its record
/// derives; a lease passes for a recorded host and refuses another by name;
/// a secret the record doesn't hold is denied whatever the request names.
#[tokio::test]
async fn a_channel_grants_and_leases_only_its_boots_record() {
    let (_temp, rpc, record) = channel();
    let grants = rpc.bound_secret_grants().await.unwrap();
    assert!(!grants.key_unavailable);
    let [grant] = grants.grants.as_slice() else {
        panic!("one grant");
    };
    assert_eq!(record_from_proto(grant.record.clone().unwrap()), record[0]);
    assert!(grant.placeholder.contains("cwp1_"));
    assert!(!grant.placeholder.contains(CANARY));

    let leased = rpc
        .lease_recorded_secret(lease(&record[0], "api.fancy.com", true))
        .await
        .unwrap();
    assert_eq!(leased.value, CANARY.as_bytes());
    assert!(!format!("{leased:?}").contains(CANARY));
    let client_side = LeasedBoundSecret {
        binding: serde_json::from_str(&leased.binding).unwrap(),
        value_version: leased.value_version,
        value: Some(Zeroizing::new(leased.value.clone())),
    };
    let printed = format!("{client_side:?}");
    assert!(
        printed.contains("[REDACTED]") && !printed.contains(CANARY),
        "{printed}"
    );
    let row = rpc
        .lease_recorded_secret(lease(&record[0], "api.fancy.com", false))
        .await
        .unwrap();
    assert!(row.value.is_empty());
    assert_eq!(row.value_version, leased.value_version);
    let other_host = rpc
        .lease_recorded_secret(lease(&record[0], "api.other.com", true))
        .await
        .unwrap();
    assert_eq!(
        other_host.refusal,
        v1::BoundSecretLeaseRefusal::NotBoundToHost as i32
    );
    assert!(other_host.value.is_empty());

    let mut unrecorded = record[0].clone();
    unrecorded.key = "OTHER_TOKEN".into();
    let denied = rpc
        .lease_recorded_secret(lease(&unrecorded, "api.fancy.com", true))
        .await
        .unwrap_err();
    assert_eq!(denied.code(), tonic::Code::PermissionDenied);
}

/// A boot that recorded nothing grants nothing and leases nothing.
#[tokio::test]
async fn a_channel_with_no_record_grants_nothing() {
    let (_temp, mut rpc, record) = channel();
    if let Some(projection) = rpc.projection.as_mut() {
        projection.bound_secrets = None;
    }
    assert!(rpc.bound_secret_grants().await.unwrap().grants.is_empty());
    assert_eq!(
        rpc.lease_recorded_secret(lease(&record[0], "api.fancy.com", true))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );
}
