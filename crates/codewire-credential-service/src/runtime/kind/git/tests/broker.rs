//! Real adapter preparation with a synthetic typed lease, never a DB/auth
//! shortcut for the managed Kind journey. This catches broker-header drift in
//! the final-image stock-Git test without constructing a network transport.

use std::collections::BTreeSet;

use codewire_access::{
    AccessProfileId, BrokerOperationId, BrokerRouteId, CapabilitySlot, CredentialAuthKind,
    CredentialId, CredentialMetadata, CredentialStatus, DerivedGrant, EnvironmentId,
    GrantPermission, GrantProfile, Owner, OwnerId, Placement, ProviderId,
};
use codewire_credential_broker::{BrokerCredentialLease, github::GitHubOAuthAdapter};

use super::*;

struct Lease {
    metadata: CredentialMetadata,
    grant: DerivedGrant,
    permission: GrantPermission,
}

impl Lease {
    fn new() -> Self {
        let id = CredentialId::parse("11111111-1111-4111-8111-111111111111").unwrap();
        let permission = GrantPermission {
            operation: BrokerOperationId::parse("git-fetch").unwrap(),
            route: BrokerRouteId::parse("github-https").unwrap(),
        };
        Self {
            metadata: CredentialMetadata {
                id: id.clone(),
                placement: Placement::Local,
                owner: Owner::User(OwnerId::parse("synthetic-owner").unwrap()),
                provider: ProviderId::parse("github").unwrap(),
                authentication_kind: CredentialAuthKind::OAuth,
                display_name: "synthetic-only".into(),
                account_hint: None,
                ssh_public_key: None,
                status: CredentialStatus::Active,
                expires_at_unix: None,
                revocation_generation: 1,
            },
            grant: DerivedGrant {
                environment_id: EnvironmentId::parse("synthetic-environment").unwrap(),
                environment_generation: 1,
                profile: Some(GrantProfile {
                    id: AccessProfileId::parse("22222222-2222-4222-8222-222222222222").unwrap(),
                    revision: 1,
                }),
                capability_slot: CapabilitySlot::parse("github").unwrap(),
                credential_id: id,
                credential_revocation_generation: 1,
                expires_at_unix: None,
                permissions: BTreeSet::from([permission.clone()]),
            },
            permission,
        }
    }
}

impl BrokerCredentialLease for Lease {
    fn credential_metadata(&self) -> &CredentialMetadata {
        &self.metadata
    }
    fn grant(&self) -> &DerivedGrant {
        &self.grant
    }
    fn permission(&self) -> &GrantPermission {
        &self.permission
    }
    fn material_generation(&self) -> u64 {
        1
    }
    fn with_material<T>(self, operation: impl FnOnce(&[u8]) -> T) -> T {
        operation(GITHUB_APP_USER_TOKEN.as_bytes())
    }
}

pub(super) async fn execute(
    fixture: &Arc<Fixture>,
    method: &Method,
    target: &url::Url,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<(Operation, Vec<u8>), Error> {
    let adapter = GitHubOAuthAdapter::new().unwrap();
    let mut input = headers.clone();
    // These are broker-owned, not client-provided fields. Production adapter
    // preparation must supply them; fixture validation requires exact values.
    for name in ["authorization", "user-agent", "accept-encoding"] {
        input.remove(name);
    }
    let request = adapter
        .validate_request(
            "github-https",
            method,
            target.path(),
            target.query(),
            input,
            body.to_vec(),
        )
        .unwrap();
    let (method, target, headers, body, _response) = adapter
        .prepare_validated(Lease::new(), request)
        .unwrap()
        .into_parts();
    fixture.execute(&method, &target, &headers, &body).await
}
