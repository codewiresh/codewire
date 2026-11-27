//! Whether a sign-in may be delivered to a runtime session: the checks a
//! Codex or Claude login lease applies before any material is read.

use super::*;

/// A check a lease applies to its runtime session and, once read, to each
/// credential admission.
pub(super) type DeliveryPredicate =
    fn(&PlatformRuntimeSession, Option<&Admission>) -> Result<(), BrokerLeaseError>;

/// Delivery predicate of a listed direct delivery exception
/// (docs/dev/SECRETS-AND-CREDENTIALS.md, "Direct delivery exceptions"): the
/// environment creator's own personal Codex ChatGPT login, sealed to the
/// daemon of a hosted Sandbox or of the creator's own local VM. Every
/// condition must hold:
///
/// - a hosted Sandbox, or the owner-local delegation of a local VM that
///   selected a profile. A delegation without a profile leases no provider
///   credential at all;
/// - the profile owner is the environment creator (`context.user_id`). For a
///   hosted Sandbox that is the environment's `created_by`, and the creator
///   confirmed the personal profile's consent: the hosted authority sets
///   `allow_personal_credentials` exactly when the bound profile is the
///   creator's own and its `personal_owner_confirmed_by` is the creator, and
///   resolves the profile owner to the creator only then (credential-service
///   `authority.rs`, `Scope::context` and `Scope::owner`). For a local VM it
///   is the owner whose own OAuth login authenticated the delegation and
///   created the VM's platform selection; the delegation authority resolves
///   the profile owner to that owner only for their personal profile
///   (credential-service `delegation/authority.rs`). These facts are part of
///   `same_binding`, so every authority check rechecks them;
/// - the creator confirmed the binding with a sign-in, never a user token
///   (`direct_delivery`, #5688). An owner-local delegation is the owner's own
///   OAuth sign-in, which a user token never reaches;
/// - the Codex grant comes from that profile and carries the dedicated
///   `codex-login` permission, which this lease requested;
/// - the credential is the creator's own Active OpenAI OAuth login on the
///   platform: never an API key, an organization's credential, another
///   user's, or one that is revoked or needs Reconnect.
///
/// Other users who can open the Sandbox's terminal can read a delivered token
/// until its `exp`; the owner accepted that ("always deliver"), so this
/// predicate deliberately does not consider them. A local VM keeps the token
/// on its state disk until its next boot's check removes it or it expires,
/// which the owner accepted on 2026-10-15.
pub(super) fn codex_login_admissible(
    session: &PlatformRuntimeSession,
    admission: Option<&Admission>,
) -> Result<(), BrokerLeaseError> {
    personal_login_admissible(
        session,
        admission,
        &PersonalLogin {
            permission: codex_login_permission(),
            slot: CapabilitySlot::codex(),
            provider: "openai",
            kind: CredentialAuthKind::OAuth,
            direct: true,
        },
    )
}

/// [`codex_login_admissible`] for the other listed exception, the
/// environment creator's own personal Claude sign-in, for a hosted Sandbox or
/// the creator's own local VM alike: the Anthropic grant carries the
/// dedicated `claude-login` permission, and the credential is the creator's
/// own Active Claude sign-in on the platform. An Anthropic API key or Claude
/// subscription token (`claude setup-token`) is never delivered.
pub(super) fn claude_login_admissible(
    session: &PlatformRuntimeSession,
    admission: Option<&Admission>,
) -> Result<(), BrokerLeaseError> {
    personal_login_admissible(
        session,
        admission,
        &PersonalLogin {
            permission: claude_login_permission(),
            slot: CapabilitySlot::anthropic(),
            provider: "anthropic",
            kind: CredentialAuthKind::ClaudeSignIn,
            direct: true,
        },
    )
}

/// Placeholder-only Antigravity login admission: the environment creator's own
/// Active personal Google OAuth sign-in in the `antigravity` slot (never a
/// Gemini API key). Real Google tokens never leave the broker.
pub(super) fn antigravity_login_admissible(
    session: &PlatformRuntimeSession,
    admission: Option<&Admission>,
) -> Result<(), BrokerLeaseError> {
    personal_login_admissible(
        session,
        admission,
        &PersonalLogin {
            permission: antigravity_login_permission(),
            slot: CapabilitySlot::antigravity(),
            provider: "google",
            kind: CredentialAuthKind::OAuth,
            // Placeholder-only: nothing is delivered.
            direct: false,
        },
    )
}

/// The one personal login form a delivery predicate admits.
struct PersonalLogin {
    permission: GrantPermission,
    slot: CapabilitySlot,
    provider: &'static str,
    kind: CredentialAuthKind,
    /// A listed direct delivery exception, which only a binding its creator
    /// confirmed with a sign-in admits.
    direct: bool,
}

fn personal_login_admissible(
    session: &PlatformRuntimeSession,
    admission: Option<&Admission>,
    login: &PersonalLogin,
) -> Result<(), BrokerLeaseError> {
    // A hosted Sandbox, or a local VM's owner-local delegation that selected
    // a profile (owner decision, 2026-10-15). Each runtime identity has its
    // one placement; a delegation without a profile leases no provider
    // credential.
    let placement = match &session.identity {
        RuntimeIdentity::Hosted { .. } => GrantPlacement::Platform,
        RuntimeIdentity::OwnerLocal {
            profile: Some(_), ..
        } => GrantPlacement::PlatformToLocal,
        RuntimeIdentity::OwnerLocal { profile: None, .. } => {
            return Err(BrokerLeaseError::Denied);
        }
    };
    let creator = Owner::User(session.context.user_id.clone());
    if session.context.placement != placement
        || session.credential_owner != creator
        || !session.context.allow_personal_credentials
        || login.direct && !session.direct_delivery
    {
        return Err(BrokerLeaseError::Denied);
    }
    let Some(admission) = admission else {
        return Ok(());
    };
    let metadata = &admission.record.metadata;
    if admission.permission != login.permission
        || admission.grant.capability_slot != login.slot
        || !admission.grant.permissions.contains(&admission.permission)
        || admission.grant.profile.is_none()
        || admission.grant.credential_id != metadata.id
        || metadata.owner != creator
        || metadata.placement != Placement::Platform
        || metadata.provider.as_str() != login.provider
        || metadata.authentication_kind != login.kind
        || metadata.status != CredentialStatus::Active
    {
        return Err(BrokerLeaseError::Denied);
    }
    Ok(())
}
