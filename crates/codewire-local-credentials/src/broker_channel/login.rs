//! The listed direct delivery exceptions a local VM leases: the host
//! owner's own provider logins (docs/dev/SECRETS-AND-CREDENTIALS.md, "Direct
//! delivery exceptions").

use codewire_access::{
    CapabilitySlot, CredentialAuthKind, CredentialMetadata, CredentialStatus, DerivedGrant,
    GrantPermission, Owner, Placement,
};
use codewire_protected_store::ProtectedStore;
use uuid::Uuid;

use super::{BrokerLeaseChannelError, CredentialOperationLease, LocalCredentialBrokerLeaseClient};

impl<S> LocalCredentialBrokerLeaseClient<S>
where
    S: ProtectedStore + Clone + 'static,
{
    /// Lease the Codex login for the one listed direct delivery exception
    /// (docs/dev/SECRETS-AND-CREDENTIALS.md, "Direct delivery exceptions"):
    /// the host owner's own Active Codex ChatGPT login in the Codex slot of
    /// the VM's selected profile. The authority admits it only then
    /// ([`local_codex_login_admissible`]); this side checks the same again.
    pub async fn lease_codex_login(
        &mut self,
        request_id: Uuid,
    ) -> Result<CredentialOperationLease, BrokerLeaseChannelError> {
        self.lease_login(
            request_id,
            CapabilitySlot::codex(),
            codewire_access::codex_login_permission(),
            local_codex_login_admissible,
        )
        .await
    }

    /// [`Self::lease_codex_login`] for the Claude login: the host owner's own
    /// Active Claude sign-in in the Anthropic slot of the VM's selected
    /// profile ([`local_claude_login_admissible`]), never an API key or a
    /// Claude subscription token.
    pub async fn lease_claude_login(
        &mut self,
        request_id: Uuid,
    ) -> Result<CredentialOperationLease, BrokerLeaseChannelError> {
        self.lease_login(
            request_id,
            CapabilitySlot::anthropic(),
            codewire_access::claude_login_permission(),
            local_claude_login_admissible,
        )
        .await
    }

    /// Lease the Antigravity slot's active personal Google OAuth sign-in so
    /// the broker can deliver its placeholder-only login file behind
    /// front-door interception. Real Google tokens never leave the broker.
    pub async fn lease_antigravity_login(
        &mut self,
        request_id: Uuid,
    ) -> Result<CredentialOperationLease, BrokerLeaseChannelError> {
        self.lease_login(
            request_id,
            CapabilitySlot::antigravity(),
            codewire_access::antigravity_login_permission(),
            local_antigravity_login_admissible,
        )
        .await
    }

    async fn lease_login(
        &mut self,
        request_id: Uuid,
        capability_slot: CapabilitySlot,
        permission: GrantPermission,
        admissible: fn(&CredentialMetadata, &DerivedGrant) -> bool,
    ) -> Result<CredentialOperationLease, BrokerLeaseChannelError> {
        if request_id.is_nil() {
            return Err(BrokerLeaseChannelError::InvalidRequest);
        }
        let lease = self
            .lease_admitted(request_id, capability_slot, permission)
            .await?;
        if !admissible(&lease.credential.metadata, &lease.grant) {
            return Err(BrokerLeaseChannelError::Denied);
        }
        Ok(lease)
    }
}

/// Whether the authority refuses an admitted lease because it carries a
/// login permission its credential does not satisfy. Every other permission
/// is decided elsewhere.
pub(crate) fn local_login_refused(
    permission: &GrantPermission,
    credential: &CredentialMetadata,
    grant: &DerivedGrant,
) -> bool {
    if *permission == codewire_access::codex_login_permission() {
        !local_codex_login_admissible(credential, grant)
    } else if *permission == codewire_access::claude_login_permission() {
        !local_claude_login_admissible(credential, grant)
    } else if *permission == codewire_access::antigravity_login_permission() {
        !local_antigravity_login_admissible(credential, grant)
    } else {
        false
    }
}

/// The listed Codex login on a local VM (docs/dev/SECRETS-AND-CREDENTIALS.md,
/// "Direct delivery exceptions"): the host owner's own Active Codex ChatGPT
/// login, an OpenAI OAuth credential in the Codex slot of the VM's selected
/// local profile. Never an API key; a local store holds no organization
/// credential, and its one owner is the VM's creator.
pub(crate) fn local_codex_login_admissible(
    credential: &CredentialMetadata,
    grant: &DerivedGrant,
) -> bool {
    grant.capability_slot == CapabilitySlot::codex()
        && credential.provider.as_str() == "openai"
        && credential.authentication_kind == CredentialAuthKind::OAuth
        && own_active_login_in_profile(credential, grant)
}

/// The listed Claude login on a local VM, under the same conditions as
/// [`local_codex_login_admissible`]: the host owner's own Active Claude
/// sign-in in the Anthropic slot of the VM's selected local profile. Never an
/// Anthropic API key or a Claude subscription token.
pub(crate) fn local_claude_login_admissible(
    credential: &CredentialMetadata,
    grant: &DerivedGrant,
) -> bool {
    grant.capability_slot == CapabilitySlot::anthropic()
        && credential.provider.as_str() == "anthropic"
        && credential.authentication_kind == CredentialAuthKind::ClaudeSignIn
        && own_active_login_in_profile(credential, grant)
}

/// The Antigravity sign-in on a local VM: the host owner's own Active Google
/// OAuth sign-in in the Antigravity slot of the VM's selected local profile.
/// Never a Gemini API key.
pub(crate) fn local_antigravity_login_admissible(
    credential: &CredentialMetadata,
    grant: &DerivedGrant,
) -> bool {
    grant.capability_slot == CapabilitySlot::antigravity()
        && credential.provider.as_str() == "google"
        && credential.authentication_kind == CredentialAuthKind::OAuth
        && own_active_login_in_profile(credential, grant)
}

fn own_active_login_in_profile(credential: &CredentialMetadata, grant: &DerivedGrant) -> bool {
    grant.profile.is_some()
        && grant.credential_id == credential.id
        && credential.status == CredentialStatus::Active
        && credential.placement == Placement::Local
        && matches!(credential.owner, Owner::User(_))
}

#[cfg(test)]
mod tests {
    use codewire_access::{
        AccessProfileId, CredentialId, EnvironmentId, GrantProfile, OwnerId, ProviderId,
    };

    use super::*;

    fn credential(provider: &str, kind: CredentialAuthKind) -> CredentialMetadata {
        CredentialMetadata {
            id: CredentialId::parse("synthetic-credential").unwrap(),
            placement: Placement::Local,
            owner: Owner::User(OwnerId::parse("owner").unwrap()),
            provider: ProviderId::parse(provider).unwrap(),
            authentication_kind: kind,
            display_name: "synthetic".into(),
            account_hint: None,
            ssh_public_key: None,
            status: CredentialStatus::Active,
            expires_at_unix: None,
            revocation_generation: 1,
        }
    }

    fn grant(slot: CapabilitySlot, profile: bool) -> DerivedGrant {
        DerivedGrant {
            environment_id: EnvironmentId::parse(Uuid::new_v4().to_string()).unwrap(),
            environment_generation: 7,
            capability_slot: slot,
            credential_id: CredentialId::parse("synthetic-credential").unwrap(),
            profile: profile.then(|| GrantProfile {
                id: AccessProfileId::parse(Uuid::new_v4().to_string()).unwrap(),
                revision: 1,
            }),
            credential_revocation_generation: 1,
            expires_at_unix: None,
            permissions: Default::default(),
        }
    }

    #[test]
    fn the_local_claude_login_is_only_the_owners_active_sign_in_in_the_anthropic_slot() {
        let sign_in = credential("anthropic", CredentialAuthKind::ClaudeSignIn);
        let slot = || grant(CapabilitySlot::anthropic(), true);
        assert!(local_claude_login_admissible(&sign_in, &slot()));
        for (credential, grant) in [
            // Never an API key or a `claude setup-token` token.
            (credential("anthropic", CredentialAuthKind::ApiKey), slot()),
            (credential("anthropic", CredentialAuthKind::OAuth), slot()),
            // Only a selected profile's Anthropic slot.
            (sign_in.clone(), grant(CapabilitySlot::anthropic(), false)),
            (sign_in.clone(), grant(CapabilitySlot::codex(), true)),
            // Only an Active, local, personal sign-in.
            (
                CredentialMetadata {
                    status: CredentialStatus::RefreshFailed,
                    ..sign_in.clone()
                },
                slot(),
            ),
            (
                CredentialMetadata {
                    status: CredentialStatus::Revoked,
                    ..sign_in.clone()
                },
                slot(),
            ),
            (
                CredentialMetadata {
                    placement: Placement::Platform,
                    ..sign_in.clone()
                },
                slot(),
            ),
            (
                CredentialMetadata {
                    owner: Owner::Organization(OwnerId::parse("org").unwrap()),
                    ..sign_in.clone()
                },
                slot(),
            ),
        ] {
            assert!(
                !local_claude_login_admissible(&credential, &grant),
                "{credential:?}"
            );
        }
    }

    #[test]
    fn each_login_permission_is_decided_by_its_own_provider_rule() {
        let codex = credential("openai", CredentialAuthKind::OAuth);
        let sign_in = credential("anthropic", CredentialAuthKind::ClaudeSignIn);
        let codex_grant = grant(CapabilitySlot::codex(), true);
        let anthropic_grant = grant(CapabilitySlot::anthropic(), true);
        let codex_login = codewire_access::codex_login_permission();
        let claude_login = codewire_access::claude_login_permission();
        assert!(!local_login_refused(&codex_login, &codex, &codex_grant));
        assert!(!local_login_refused(
            &claude_login,
            &sign_in,
            &anthropic_grant
        ));
        // A login permission never admits the other provider's login.
        assert!(local_login_refused(&claude_login, &codex, &codex_grant));
        assert!(local_login_refused(
            &codex_login,
            &sign_in,
            &anthropic_grant
        ));
        // An ordinary operation is not a login and is decided elsewhere.
        let messages = GrantPermission {
            operation: codewire_access::BrokerOperationId::parse("messages").unwrap(),
            route: codewire_access::BrokerRouteId::parse("anthropic-api").unwrap(),
        };
        assert!(!local_login_refused(&messages, &sign_in, &anthropic_grant));
    }
}
