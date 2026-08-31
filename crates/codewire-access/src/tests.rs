use std::collections::{BTreeMap, BTreeSet};

use super::*;

fn credential_id(value: &str) -> CredentialId {
    CredentialId::parse(value).expect("credential ID")
}

fn profile_id(value: &str) -> AccessProfileId {
    AccessProfileId::parse(value).expect("profile ID")
}

fn owner_id(value: &str) -> OwnerId {
    OwnerId::parse(value).expect("owner ID")
}

fn provider_id(value: &str) -> ProviderId {
    ProviderId::parse(value).expect("provider ID")
}

fn slot(value: &str) -> CapabilitySlot {
    CapabilitySlot::parse(value).expect("capability slot")
}

fn permission(operation: &str, route: &str) -> GrantPermission {
    GrantPermission {
        operation: BrokerOperationId::parse(operation).expect("operation"),
        route: BrokerRouteId::parse(route).expect("route"),
    }
}

fn catalog(auth_kinds: impl IntoIterator<Item = CredentialAuthKind>) -> ProviderCatalog {
    ProviderCatalog::from_definitions([ProviderDefinition {
        id: provider_id("openai"),
        capabilities: [(
            slot("codex"),
            CapabilityPolicy {
                authentication_kinds: auth_kinds.into_iter().collect(),
                permissions: [permission("responses", "openai-api")]
                    .into_iter()
                    .collect(),
            },
        )]
        .into_iter()
        .collect(),
    }])
    .expect("provider catalog")
}

fn credential(id: &str, owner: Owner) -> CredentialMetadata {
    CredentialMetadata {
        id: credential_id(id),
        placement: Placement::Local,
        owner,
        provider: provider_id("openai"),
        authentication_kind: CredentialAuthKind::OAuth,
        display_name: id.to_string(),
        account_hint: Some(format!("{id}@example.test")),
        status: CredentialStatus::Active,
        expires_at_unix: Some(4_102_444_800),
        revocation_generation: 1,
    }
}

fn profile(id: &str, owner: Owner, credential: &str) -> AccessProfile {
    AccessProfile {
        id: profile_id(id),
        placement: Placement::Local,
        owner,
        name: AccessProfileName::parse(id).expect("profile name"),
        revision: 1,
        entries: [(slot("codex"), credential_id(credential))]
            .into_iter()
            .collect(),
    }
}

fn binding(profile: &AccessProfile) -> EnvironmentAccessBinding {
    EnvironmentAccessBinding {
        environment_id: EnvironmentId::parse("env-one").expect("environment ID"),
        profile_id: profile.id.clone(),
        profile_revision: profile.revision,
    }
}

fn context(authorized: impl IntoIterator<Item = CredentialId>) -> GrantContext {
    GrantContext {
        environment_id: EnvironmentId::parse("env-one").expect("environment ID"),
        environment_generation: 7,
        placement: Placement::Local,
        user_id: owner_id("user-one"),
        organization_id: None,
        allow_personal_credentials: false,
        authorized_credentials: authorized.into_iter().collect(),
    }
}

#[test]
fn profile_references_are_scope_qualified_and_canonical() {
    let work: AccessProfileReference = "user/work".parse().expect("user profile");
    assert_eq!(work.scope(), AccessProfileScope::User);
    assert_eq!(work.name().as_str(), "work");
    assert_eq!(work.to_string(), "user/work");
    assert_eq!(serde_json::to_string(&work).unwrap(), "\"user/work\"");
    assert_eq!(
        serde_json::from_str::<AccessProfileReference>("\"organization/production\"")
            .unwrap()
            .scope(),
        AccessProfileScope::Organization
    );

    for invalid in ["work", "local/work", "user/Work", "user/work/extra"] {
        assert!(
            invalid.parse::<AccessProfileReference>().is_err(),
            "{invalid}"
        );
    }
}

#[test]
fn identifiers_fail_closed_during_deserialization() {
    let error =
        serde_json::from_str::<CredentialId>("\"credential with spaces\"").expect_err("invalid ID");
    assert!(!error.to_string().contains("credential with spaces"));
}

#[test]
fn two_profiles_select_different_credentials_without_material() {
    let user = Owner::User(owner_id("user-one"));
    let work = credential("codex-work", user.clone());
    let personal = credential("codex-personal", user.clone());
    let credentials = [
        (work.id.clone(), work.clone()),
        (personal.id.clone(), personal.clone()),
    ]
    .into_iter()
    .collect::<BTreeMap<_, _>>();
    let grant_context = context([work.id.clone(), personal.id.clone()]);

    let work_profile = profile("work", user.clone(), "codex-work");
    let personal_profile = profile("personal", user, "codex-personal");
    let work_grants = derive_grants(
        &grant_context,
        &binding(&work_profile),
        &work_profile,
        &credentials,
        &catalog([CredentialAuthKind::OAuth]),
        1_800_000_000,
    )
    .expect("work grants");
    let personal_grants = derive_grants(
        &grant_context,
        &binding(&personal_profile),
        &personal_profile,
        &credentials,
        &catalog([CredentialAuthKind::OAuth]),
        1_800_000_000,
    )
    .expect("personal grants");

    assert_eq!(work_grants[0].credential_id, work.id);
    assert_eq!(personal_grants[0].credential_id, personal.id);
    let encoded = format!(
        "{} {}",
        serde_json::to_string(&work_grants).expect("grant JSON"),
        serde_json::to_string(&credentials).expect("credential metadata JSON")
    );
    for forbidden in [
        "access_token",
        "refresh_token",
        "api_key",
        "private_key",
        "protected_reference",
        "protected_store",
    ] {
        assert!(
            !encoded.contains(forbidden),
            "unexpected {forbidden}: {encoded}"
        );
    }
}

#[test]
fn profile_revision_is_bound_exactly() {
    let user = Owner::User(owner_id("user-one"));
    let selected = credential("codex-work", user.clone());
    let selected_profile = profile("work", user, "codex-work");
    let mut stale = binding(&selected_profile);
    stale.profile_revision += 1;
    let error = derive_grants(
        &context([selected.id.clone()]),
        &stale,
        &selected_profile,
        &[(selected.id.clone(), selected)].into_iter().collect(),
        &catalog([CredentialAuthKind::OAuth]),
        1_800_000_000,
    )
    .expect_err("stale binding");
    assert_eq!(error, AccessError::BindingMismatch);
}

#[test]
fn credential_map_key_must_match_credential_metadata_identity() {
    let user = Owner::User(owner_id("user-one"));
    let selected = credential("different-id", user.clone());
    let selected_profile = profile("work", user, "codex-work");
    let profile_credential = credential_id("codex-work");
    let error = derive_grants(
        &context([profile_credential.clone()]),
        &binding(&selected_profile),
        &selected_profile,
        &[(profile_credential.clone(), selected)]
            .into_iter()
            .collect(),
        &catalog([CredentialAuthKind::OAuth]),
        1_800_000_000,
    )
    .expect_err("mismatched credential metadata");
    assert_eq!(
        error,
        AccessError::CredentialIdentityMismatch {
            credential: profile_credential
        }
    );
}

#[test]
fn rotation_changes_grant_generation_without_profile_revision() {
    let user = Owner::User(owner_id("user-one"));
    let mut selected = credential("codex-work", user.clone());
    selected.revocation_generation = 3;
    let selected_profile = profile("work", user, "codex-work");
    let grants = derive_grants(
        &context([selected.id.clone()]),
        &binding(&selected_profile),
        &selected_profile,
        &[(selected.id.clone(), selected)].into_iter().collect(),
        &catalog([CredentialAuthKind::OAuth]),
        1_800_000_000,
    )
    .expect("rotated grant");
    assert_eq!(grants[0].profile_revision, 1);
    assert_eq!(grants[0].credential_revocation_generation, 3);
}

#[test]
fn revocation_expiry_and_missing_authorization_fail_closed() {
    let user = Owner::User(owner_id("user-one"));
    let mut selected = credential("codex-work", user.clone());
    let selected_profile = profile("work", user, "codex-work");
    let selected_id = selected.id.clone();

    let error = derive_grants(
        &context(BTreeSet::new()),
        &binding(&selected_profile),
        &selected_profile,
        &[(selected_id.clone(), selected.clone())]
            .into_iter()
            .collect(),
        &catalog([CredentialAuthKind::OAuth]),
        1_800_000_000,
    )
    .expect_err("not authorized");
    assert_eq!(
        error,
        AccessError::CredentialNotAuthorized {
            credential: selected_id.clone()
        }
    );

    selected.status = CredentialStatus::Revoked;
    let error = derive_grants(
        &context([selected_id.clone()]),
        &binding(&selected_profile),
        &selected_profile,
        &[(selected_id.clone(), selected.clone())]
            .into_iter()
            .collect(),
        &catalog([CredentialAuthKind::OAuth]),
        1_800_000_000,
    )
    .expect_err("revoked");
    assert_eq!(
        error,
        AccessError::CredentialInactive {
            credential: selected_id.clone()
        }
    );

    selected.status = CredentialStatus::Active;
    selected.expires_at_unix = Some(1_800_000_000);
    let error = derive_grants(
        &context([selected_id.clone()]),
        &binding(&selected_profile),
        &selected_profile,
        &[(selected_id.clone(), selected)].into_iter().collect(),
        &catalog([CredentialAuthKind::OAuth]),
        1_800_000_000,
    )
    .expect_err("expired");
    assert_eq!(
        error,
        AccessError::CredentialExpired {
            credential: selected_id
        }
    );
}

#[test]
fn provider_capability_matrix_rejects_incompatible_authentication() {
    let user = Owner::User(owner_id("user-one"));
    let selected = credential("codex-work", user.clone());
    let selected_profile = profile("work", user, "codex-work");
    let error = derive_grants(
        &context([selected.id.clone()]),
        &binding(&selected_profile),
        &selected_profile,
        &[(selected.id.clone(), selected)].into_iter().collect(),
        &catalog([CredentialAuthKind::ApiKey]),
        1_800_000_000,
    )
    .expect_err("OAuth not enabled");
    assert!(matches!(error, AccessError::UnsupportedCapability { .. }));
}

#[test]
fn local_organization_records_are_typed_unsupported() {
    let org = Owner::Organization(owner_id("org-one"));
    let selected = credential("codex-org", org.clone());
    let selected_profile = profile("work", org, "codex-org");
    let error = derive_grants(
        &context([selected.id.clone()]),
        &binding(&selected_profile),
        &selected_profile,
        &[(selected.id.clone(), selected)].into_iter().collect(),
        &catalog([CredentialAuthKind::OAuth]),
        1_800_000_000,
    )
    .expect_err("local organization profile");
    assert_eq!(error, AccessError::LocalOrganizationUnsupported);
}

#[test]
fn user_profile_must_belong_to_the_environment_user() {
    let selected = credential("codex-other", Owner::User(owner_id("user-other")));
    let selected_profile = profile("other", Owner::User(owner_id("user-other")), "codex-other");
    let error = derive_grants(
        &context([selected.id.clone()]),
        &binding(&selected_profile),
        &selected_profile,
        &[(selected.id.clone(), selected)].into_iter().collect(),
        &catalog([CredentialAuthKind::OAuth]),
        1_800_000_000,
    )
    .expect_err("another user's profile");
    assert_eq!(error, AccessError::ProfileOwnerMismatch);
}

#[test]
fn adapter_authorization_cannot_bypass_credential_ownership() {
    let profile_owner = Owner::User(owner_id("user-one"));
    let selected = credential("codex-other", Owner::User(owner_id("user-other")));
    let selected_profile = profile("work", profile_owner, "codex-other");
    let error = derive_grants(
        &context([selected.id.clone()]),
        &binding(&selected_profile),
        &selected_profile,
        &[(selected.id.clone(), selected)].into_iter().collect(),
        &catalog([CredentialAuthKind::OAuth]),
        1_800_000_000,
    )
    .expect_err("another user's credential");
    assert!(matches!(error, AccessError::CredentialOwnerMismatch { .. }));
}

#[test]
fn environment_binding_is_not_reusable_for_another_environment() {
    let user = Owner::User(owner_id("user-one"));
    let selected = credential("codex-work", user.clone());
    let selected_profile = profile("work", user, "codex-work");
    let mut wrong_environment = binding(&selected_profile);
    wrong_environment.environment_id = EnvironmentId::parse("env-two").expect("environment ID");
    let error = derive_grants(
        &context([selected.id.clone()]),
        &wrong_environment,
        &selected_profile,
        &[(selected.id.clone(), selected)].into_iter().collect(),
        &catalog([CredentialAuthKind::OAuth]),
        1_800_000_000,
    )
    .expect_err("binding for another environment");
    assert_eq!(error, AccessError::BindingMismatch);
}

#[test]
fn platform_personal_credential_needs_shared_environment_confirmation() {
    let user = Owner::User(owner_id("user-one"));
    let mut selected = credential("codex-user", user.clone());
    selected.placement = Placement::Platform;
    let mut selected_profile = profile("work", user, "codex-user");
    selected_profile.placement = Placement::Platform;
    let mut grant_context = context([selected.id.clone()]);
    grant_context.placement = Placement::Platform;
    grant_context.organization_id = Some(owner_id("org-one"));

    let error = derive_grants(
        &grant_context,
        &binding(&selected_profile),
        &selected_profile,
        &[(selected.id.clone(), selected.clone())]
            .into_iter()
            .collect(),
        &catalog([CredentialAuthKind::OAuth]),
        1_800_000_000,
    )
    .expect_err("personal credential confirmation");
    assert_eq!(error, AccessError::PersonalCredentialsForbidden);

    grant_context.allow_personal_credentials = true;
    derive_grants(
        &grant_context,
        &binding(&selected_profile),
        &selected_profile,
        &[(selected.id.clone(), selected)].into_iter().collect(),
        &catalog([CredentialAuthKind::OAuth]),
        1_800_000_000,
    )
    .expect("confirmed personal credential");
}

#[test]
fn platform_user_profile_can_select_an_authorized_matching_org_credential() {
    let user = Owner::User(owner_id("user-one"));
    let mut selected = credential("codex-org", Owner::Organization(owner_id("org-one")));
    selected.placement = Placement::Platform;
    let mut selected_profile = profile("work", user, "codex-org");
    selected_profile.placement = Placement::Platform;
    let mut grant_context = context([selected.id.clone()]);
    grant_context.placement = Placement::Platform;
    grant_context.organization_id = Some(owner_id("org-one"));

    derive_grants(
        &grant_context,
        &binding(&selected_profile),
        &selected_profile,
        &[(selected.id.clone(), selected.clone())]
            .into_iter()
            .collect(),
        &catalog([CredentialAuthKind::OAuth]),
        1_800_000_000,
    )
    .expect("authorized organization credential");

    grant_context.organization_id = Some(owner_id("org-two"));
    assert!(matches!(
        derive_grants(
            &grant_context,
            &binding(&selected_profile),
            &selected_profile,
            &[(selected.id.clone(), selected)].into_iter().collect(),
            &catalog([CredentialAuthKind::OAuth]),
            1_800_000_000,
        ),
        Err(AccessError::CredentialOwnerMismatch { .. })
    ));
}

#[test]
fn organization_profile_cannot_select_a_personal_credential() {
    let mut selected = credential("codex-user", Owner::User(owner_id("user-one")));
    selected.placement = Placement::Platform;
    let mut selected_profile = profile(
        "organization-work",
        Owner::Organization(owner_id("org-one")),
        "codex-user",
    );
    selected_profile.placement = Placement::Platform;
    let mut grant_context = context([selected.id.clone()]);
    grant_context.placement = Placement::Platform;
    grant_context.organization_id = Some(owner_id("org-one"));
    grant_context.allow_personal_credentials = true;

    let error = derive_grants(
        &grant_context,
        &binding(&selected_profile),
        &selected_profile,
        &[(selected.id.clone(), selected)].into_iter().collect(),
        &catalog([CredentialAuthKind::OAuth]),
        1_800_000_000,
    )
    .expect_err("organization profile with personal credential");
    assert!(matches!(error, AccessError::CredentialOwnerMismatch { .. }));
}

#[test]
fn duplicate_and_empty_provider_definitions_fail_closed() {
    let definition = ProviderDefinition {
        id: provider_id("openai"),
        capabilities: [(
            slot("codex"),
            CapabilityPolicy {
                authentication_kinds: [CredentialAuthKind::OAuth].into_iter().collect(),
                permissions: [permission("responses", "openai-api")]
                    .into_iter()
                    .collect(),
            },
        )]
        .into_iter()
        .collect(),
    };
    assert!(matches!(
        ProviderCatalog::from_definitions([definition.clone(), definition]),
        Err(AccessError::DuplicateProvider { .. })
    ));
    assert_eq!(
        ProviderCatalog::from_definitions([ProviderDefinition {
            id: provider_id("empty"),
            capabilities: BTreeMap::new(),
        }]),
        Err(AccessError::EmptyCollection {
            field: "provider capabilities"
        })
    );
}
