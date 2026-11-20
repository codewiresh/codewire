//! One OAuth refresh commit through a real authority and broker lease
//! channel, so a child's own store can be tested where it stages (#5537).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;

use codewire_access::{
    AccessProfileName, BrokerOperationId, BrokerRouteId, CapabilityPolicy, CapabilitySlot,
    CredentialAuthKind, EnvironmentAccessBinding, EnvironmentId, GrantPermission, ProviderCatalog,
    ProviderDefinition, ProviderId,
};
use codewire_protected_store::{ProtectedStore, ProtectedValue};
use tokio::net::UnixStream;
use uuid::Uuid;

use crate::{
    BrokerCredentialRefreshAdmission, BrokerLeaseChannelError, LocalCredentialAuthority,
    LocalCredentialBrokerLeaseClient, NewCredential, RefreshStagingStore,
    serve_broker_lease_channel,
};

/// What the next lease sees after a committed refresh.
#[derive(Debug, PartialEq, Eq)]
pub struct RefreshedLease {
    pub material_generation: u64,
    pub material: Vec<u8>,
}

/// Enrols a synthetic Codex OAuth login in a real authority under `root`
/// over `authority_store`, binds an environment to it, and refreshes it once
/// over a broker lease channel whose store is `child_store`: lease, begin,
/// start, then commit `bundle`. Returns what the next lease sees, or the
/// channel's refusal. Both stores must reach the same backend.
pub async fn refresh_through<A, S>(
    root: &Path,
    authority_store: A,
    child_store: S,
    bundle: &[u8],
) -> Result<RefreshedLease, BrokerLeaseChannelError>
where
    A: ProtectedStore + 'static,
    S: RefreshStagingStore + Clone + 'static,
{
    let operation = BrokerOperationId::parse("responses").unwrap();
    let route = BrokerRouteId::parse("openai-api").unwrap();
    let catalog = ProviderCatalog::from_definitions([ProviderDefinition {
        id: ProviderId::parse("openai").unwrap(),
        authentication_kinds: BTreeSet::from([CredentialAuthKind::OAuth]),
        capabilities: BTreeMap::from([(
            CapabilitySlot::codex(),
            CapabilityPolicy {
                authentication_kinds: BTreeSet::from([CredentialAuthKind::OAuth]),
                permissions: BTreeSet::from([GrantPermission {
                    operation: operation.clone(),
                    route: route.clone(),
                }]),
            },
        )]),
    }])
    .unwrap();
    let authority =
        Arc::new(LocalCredentialAuthority::open(root, authority_store, catalog).unwrap());
    let credential = authority
        .add_credential(
            NewCredential {
                provider: ProviderId::parse("openai").unwrap(),
                authentication_kind: CredentialAuthKind::OAuth,
                display_name: format!("synthetic-staging-{}", Uuid::new_v4()),
                account_hint: None,
                expires_at_unix: None,
            },
            ProtectedValue::from_slice(b"synthetic-old-oauth-bundle").unwrap(),
        )
        .unwrap();
    let profile = authority
        .create_profile(
            AccessProfileName::parse("synthetic-staging").unwrap(),
            BTreeMap::from([(CapabilitySlot::codex(), credential.metadata.id.clone())]),
        )
        .unwrap();
    let environment_id = EnvironmentId::parse(Uuid::new_v4().to_string()).unwrap();
    authority
        .create_environment_access_binding(EnvironmentAccessBinding {
            environment_id: environment_id.clone(),
            profile_id: profile.profile.id,
            profile_revision: profile.profile.revision,
        })
        .unwrap();
    let (server_stream, client_stream) = UnixStream::pair().unwrap();
    let binding = authority
        .get_environment_access_binding(&environment_id)
        .unwrap()
        .binding;
    let server = tokio::spawn(serve_broker_lease_channel(
        Arc::clone(&authority),
        server_stream,
        environment_id.clone(),
        7,
        Some(binding),
    ));
    let mut client =
        LocalCredentialBrokerLeaseClient::connect(client_stream, child_store, environment_id, 7)
            .await
            .unwrap();
    let leased = client
        .lease_operation(
            Uuid::new_v4(),
            CapabilitySlot::codex(),
            operation.clone(),
            route.clone(),
        )
        .await?;
    let outcome = async {
        let admission = client
            .begin_credential_refresh(
                Uuid::new_v4(),
                Uuid::new_v4(),
                leased.grant.clone(),
                operation.clone(),
                route.clone(),
                leased.material_generation(),
            )
            .await?;
        let BrokerCredentialRefreshAdmission::Reserved(reservation) = admission else {
            return Err(BrokerLeaseChannelError::InvalidResponse);
        };
        let started = client.start_credential_refresh(reservation).await?;
        client
            .commit_credential_refresh(started, ProtectedValue::from_slice(bundle).unwrap())
            .await?;
        let refreshed = client
            .lease_operation(
                Uuid::new_v4(),
                CapabilitySlot::codex(),
                operation.clone(),
                route.clone(),
            )
            .await?;
        Ok(RefreshedLease {
            material_generation: refreshed.material_generation(),
            material: refreshed.with_material(<[u8]>::to_vec),
        })
    }
    .await;
    client.wait_for_protected_store_operations().await?;
    drop(client);
    server.abort();
    outcome
}
