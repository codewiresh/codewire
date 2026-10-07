//! A decision's reuse window on Tokio's paused clock, and the selection a
//! lease admits from it, without a database.

use codewire_access::{
    BrokerOperationId, BrokerRouteId, CredentialAuthKind, CredentialMetadata, CredentialStatus,
    DerivedGrant, EnvironmentId, GrantContext, GrantPlacement, Owner, OwnerId, Placement,
    ProviderId,
};
use codewire_platform_credentials::{CredentialRecord, CredentialVersion};
use uuid::Uuid;

use super::*;
use crate::platform::{PlatformPodIdentity, unix_now};

fn owner() -> OwnerId {
    OwnerId::parse("synthetic-owner").unwrap()
}

fn permission() -> GrantPermission {
    GrantPermission {
        operation: BrokerOperationId::parse("responses").unwrap(),
        route: BrokerRouteId::parse("openai-api").unwrap(),
    }
}

fn credential() -> CredentialId {
    CredentialId::parse("2d6f0a3e-7a41-4c55-9a39-2f1f0d8b6c10").unwrap()
}

/// A decision granting the Codex slot one credential at revocation
/// generation 1, and withholding the Anthropic slot for Reconnect.
fn decision() -> Decision {
    let pod = |name: &str| PlatformPodIdentity {
        namespace: "synthetic-workloads".into(),
        name: name.into(),
        uid: Uuid::new_v4(),
    };
    let session = PlatformRuntimeSession::new(
        pod("relay"),
        pod("workspace"),
        GrantContext {
            environment_id: EnvironmentId::parse(Uuid::new_v4().to_string()).unwrap(),
            environment_generation: 7,
            placement: GrantPlacement::Platform,
            user_id: owner(),
            organization_id: Some(OwnerId::parse("synthetic-org").unwrap()),
            allow_personal_credentials: true,
            authorized_credentials: Default::default(),
        },
        Owner::User(owner()),
        unix_now().unwrap() + 3_600,
    )
    .unwrap();
    let grant = DerivedGrant {
        environment_id: session.context.environment_id.clone(),
        environment_generation: session.context.environment_generation,
        profile: None,
        capability_slot: CapabilitySlot::codex(),
        credential_id: credential(),
        credential_revocation_generation: 1,
        expires_at_unix: None,
        permissions: [permission()].into(),
    };
    Decision {
        evaluated_at: Instant::now(),
        session,
        grants: AvailableGrants {
            grants: vec![grant],
            reconnect_required: [(
                CapabilitySlot::anthropic(),
                CredentialId::parse("6c1e8d34-29a4-4b6e-9a51-3f0c7e2d9b84").unwrap(),
            )]
            .into(),
        },
        github: Ok(None),
    }
}

fn record(revocation_generation: u64) -> CredentialRecord {
    CredentialRecord {
        metadata: CredentialMetadata {
            id: credential(),
            placement: Placement::Platform,
            owner: Owner::User(owner()),
            provider: ProviderId::parse("openai").unwrap(),
            authentication_kind: CredentialAuthKind::OAuth,
            display_name: "Codex".into(),
            account_hint: None,
            ssh_public_key: None,
            status: CredentialStatus::Active,
            expires_at_unix: None,
            revocation_generation,
        },
        version: CredentialVersion {
            revocation_generation,
            material_generation: revocation_generation,
        },
    }
}

#[tokio::test(start_paused = true)]
async fn a_decision_is_reused_for_exactly_the_reuse_window() {
    // The owner's bound: other authority changes apply within 60 seconds.
    assert_eq!(AUTHORITY_DECISION_REUSE, Duration::from_secs(60));
    let decided = decision();
    assert!(decided.young());
    tokio::time::advance(Duration::from_secs(60) - Duration::from_millis(1)).await;
    assert!(decided.young(), "a decision expired inside 60 seconds");
    tokio::time::advance(Duration::from_millis(1)).await;
    assert!(!decided.young(), "a decision outlived 60 seconds");
}

#[test]
fn a_withheld_credential_is_usable_again_only_once_active_and_unexpired() {
    let mut metadata = record(1).metadata;
    assert!(usable(&metadata));
    metadata.expires_at_unix = Some(unix_now().unwrap() + 60);
    assert!(usable(&metadata));
    for status in [
        CredentialStatus::RefreshFailed,
        CredentialStatus::Revoked,
        CredentialStatus::Expired,
    ] {
        metadata.status = status;
        assert!(!usable(&metadata), "{status:?}");
    }
    metadata.status = CredentialStatus::Active;
    metadata.expires_at_unix = Some(unix_now().unwrap());
    assert!(!usable(&metadata), "past its hard deadline");
}

#[test]
fn a_lease_admits_only_its_granted_slot_and_the_grants_record_generation() {
    let decided = decision();
    let select = |slot: &CapabilitySlot, permission: &GrantPermission| {
        select_grant(&decided.grants, &decided.session, slot, permission)
    };
    let grant = select(&CapabilitySlot::codex(), &permission()).unwrap();
    // The grant's deadline is attenuated to the decision's identity expiry.
    assert_eq!(
        grant.expires_at_unix,
        Some(decided.session.identity_expires_at_unix)
    );
    assert_eq!(
        select(&CapabilitySlot::anthropic(), &permission()).err(),
        Some(BrokerLeaseError::ReconnectRequired)
    );
    assert_eq!(
        select(&CapabilitySlot::github(), &permission()).err(),
        Some(BrokerLeaseError::Denied)
    );
    let other = GrantPermission {
        operation: BrokerOperationId::parse("messages").unwrap(),
        route: BrokerRouteId::parse("anthropic-api").unwrap(),
    };
    assert_eq!(
        select(&CapabilitySlot::codex(), &other).err(),
        Some(BrokerLeaseError::Denied)
    );
    // Rotation, Reconnect, refresh and revocation advance the record's
    // revocation generation, so the decision's grant no longer matches it.
    let owner = &decided.session.credential_owner;
    assert!(record_matches(&record(1), &grant, owner));
    assert!(!record_matches(&record(2), &grant, owner));
    let mut foreign = record(1);
    foreign.metadata.owner = Owner::User(OwnerId::parse("another-user").unwrap());
    assert!(!record_matches(&foreign, &grant, owner));
}
