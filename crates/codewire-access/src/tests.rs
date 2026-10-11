use std::collections::{BTreeMap, BTreeSet};

use super::*;

mod grant_placement;

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
    let authentication_kinds = auth_kinds.into_iter().collect::<BTreeSet<_>>();
    ProviderCatalog::from_definitions([ProviderDefinition {
        id: provider_id("openai"),
        authentication_kinds: authentication_kinds.clone(),
        capabilities: [(
            slot("codex"),
            CapabilityPolicy {
                authentication_kinds,
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
        ssh_public_key: None,
        status: CredentialStatus::Active,
        expires_at_unix: Some(4_102_444_800),
        revocation_generation: 1,
    }
}

#[test]
fn ssh_metadata_requires_exact_provider_kind_and_bounded_public_pair() {
    let mut metadata = credential("ssh-work", Owner::User(owner_id("owner")));
    metadata.provider = provider_id("ssh");
    metadata.authentication_kind = CredentialAuthKind::SshKey;
    metadata.account_hint = None;
    assert!(metadata.validate().is_err());
    metadata.ssh_public_key = Some(SshPublicKeyMetadata {
        openssh: format!("ssh-ed25519 {}", "A".repeat(68)),
        fingerprint: format!("SHA256:{}", "A".repeat(43)),
    });
    metadata.validate().unwrap();
    let json = serde_json::to_string(&metadata).unwrap();
    assert_eq!(
        serde_json::from_str::<CredentialMetadata>(&json).unwrap(),
        metadata
    );
    for corruption in 0..10 {
        let mut invalid = metadata.clone();
        match corruption {
            0 => invalid.provider = provider_id("github"),
            1 => invalid.authentication_kind = CredentialAuthKind::OAuth,
            2 => invalid.account_hint = Some("misplaced public identity".into()),
            3 => invalid
                .ssh_public_key
                .as_mut()
                .unwrap()
                .openssh
                .push_str(" comment"),
            4 => invalid.ssh_public_key.as_mut().unwrap().openssh = "x".repeat(4097),
            5 => invalid.ssh_public_key.as_mut().unwrap().openssh = "ssh-ed25519 AAAA".into(),
            6 => invalid.ssh_public_key.as_mut().unwrap().fingerprint = "MD5:unsupported".into(),
            7 => invalid
                .ssh_public_key
                .as_mut()
                .unwrap()
                .fingerprint
                .push('='),
            8 => invalid.ssh_public_key.as_mut().unwrap().openssh.push('\n'),
            9 => invalid.ssh_public_key.as_mut().unwrap().fingerprint = "SHA256:".into(),
            _ => unreachable!(),
        }
        assert!(invalid.validate().is_err(), "corruption {corruption}");
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
        placement: GrantPlacement::Local,
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
fn edit_time_profile_validation_is_shared_and_material_free() {
    let user = Owner::User(owner_id("user-one"));
    let selected = credential("codex-work", user.clone());
    let selected_profile = profile("work", user, "codex-work");
    validate_profile_entries(
        &selected_profile,
        &[(selected.id.clone(), selected)].into_iter().collect(),
        &catalog([CredentialAuthKind::OAuth]),
    )
    .expect("compatible profile");

    let wrong_owner = credential("codex-work", Owner::User(owner_id("user-other")));
    let error = validate_profile_entries(
        &selected_profile,
        &[(wrong_owner.id.clone(), wrong_owner)]
            .into_iter()
            .collect(),
        &catalog([CredentialAuthKind::OAuth]),
    )
    .expect_err("wrong owner");
    assert!(matches!(error, AccessError::CredentialOwnerMismatch { .. }));
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
    assert_eq!(
        grants[0].profile.as_ref().map(|profile| profile.revision),
        Some(1)
    );
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
    grant_context.placement = GrantPlacement::Platform;
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
    selected.authentication_kind = CredentialAuthKind::ApiKey;
    let mut selected_profile = profile("work", user, "codex-org");
    selected_profile.placement = Placement::Platform;
    let mut grant_context = context([selected.id.clone()]);
    grant_context.placement = GrantPlacement::Platform;
    grant_context.organization_id = Some(owner_id("org-one"));

    derive_grants(
        &grant_context,
        &binding(&selected_profile),
        &selected_profile,
        &[(selected.id.clone(), selected.clone())]
            .into_iter()
            .collect(),
        &catalog([CredentialAuthKind::ApiKey]),
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
            &catalog([CredentialAuthKind::ApiKey]),
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
    grant_context.placement = GrantPlacement::Platform;
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
fn organizations_hold_api_keys_and_ssh_but_no_profile_selects_their_oauth() {
    let user = Owner::User(owner_id("user-one"));
    let org = Owner::Organization(owner_id("org-one"));
    for kind in [
        CredentialAuthKind::OAuth,
        CredentialAuthKind::ApiKey,
        CredentialAuthKind::AccessToken,
        CredentialAuthKind::GitHubApp,
        CredentialAuthKind::SshKey,
    ] {
        assert!(user.may_hold(kind));
        assert_eq!(org.may_hold(kind), kind != CredentialAuthKind::OAuth);
    }

    let catalog = builtin_provider_catalog();
    let platform = |id: &str, kind: CredentialAuthKind| CredentialMetadata {
        placement: Placement::Platform,
        authentication_kind: kind,
        ..credential(id, org.clone())
    };
    let codex = platform("codex-org", CredentialAuthKind::OAuth);
    let api_key = platform("openai-org", CredentialAuthKind::ApiKey);
    let ssh = CredentialMetadata {
        provider: provider_id("ssh"),
        account_hint: None,
        ssh_public_key: Some(SshPublicKeyMetadata {
            openssh: format!("ssh-ed25519 {}", "A".repeat(68)),
            fingerprint: format!("SHA256:{}", "A".repeat(43)),
        }),
        ..platform("ssh-org", CredentialAuthKind::SshKey)
    };
    let credentials: BTreeMap<_, _> = [&codex, &api_key, &ssh]
        .into_iter()
        .map(|credential| (credential.id.clone(), credential.clone()))
        .collect();
    let mut grant_context = context(credentials.keys().cloned());
    grant_context.placement = GrantPlacement::Platform;
    grant_context.organization_id = Some(owner_id("org-one"));
    let platform_profile = |owner: &Owner, entries: &[(&str, &CredentialMetadata)]| AccessProfile {
        placement: Placement::Platform,
        entries: entries
            .iter()
            .map(|(slot_name, credential)| (slot(slot_name), credential.id.clone()))
            .collect(),
        ..profile("work", owner.clone(), "unused")
    };

    // An organization's API key and SSH key remain selectable.
    let allowed = platform_profile(&org, &[("codex", &api_key), ("ssh", &ssh)]);
    validate_profile_entries(&allowed, &credentials, &catalog).unwrap();
    let grants = derive_available_grants(
        &grant_context,
        &binding(&allowed),
        &allowed,
        &credentials,
        &catalog,
        1_800_000_000,
    )
    .unwrap();
    assert_eq!(grants.grants.len(), 2);
    assert!(grants.reconnect_required.is_empty());

    // Neither an organization profile nor the creator's own profile may
    // select an organization's OAuth login, even when launch authority
    // authorized it. Hosted admission rejects the whole selection; it is not
    // a per-capability Reconnect.
    for owner in [&org, &user] {
        let selected = platform_profile(owner, &[("codex", &codex), ("ssh", &ssh)]);
        assert_eq!(
            validate_profile_entries(&selected, &credentials, &catalog),
            Err(AccessError::OrganizationOAuthUnsupported)
        );
        let mut personal_context = grant_context.clone();
        personal_context.allow_personal_credentials = !owner.is_organization();
        assert_eq!(
            derive_available_grants(
                &personal_context,
                &binding(&selected),
                &selected,
                &credentials,
                &catalog,
                1_800_000_000,
            ),
            Err(AccessError::OrganizationOAuthUnsupported)
        );
    }
}

/// A Claude subscription token is the Anthropic slot's OAuth form. It is a
/// personal login: an organization can neither hold one nor have any profile
/// select one, while a personal profile selects it for the same two routes as
/// an Anthropic API key.
#[test]
fn claude_subscription_tokens_are_personal_anthropic_oauth_only() {
    let user = Owner::User(owner_id("user-one"));
    let org = Owner::Organization(owner_id("org-one"));
    assert!(user.may_hold(CredentialAuthKind::OAuth));
    assert!(!org.may_hold(CredentialAuthKind::OAuth));
    assert!(org.may_hold(CredentialAuthKind::ApiKey));

    let catalog = builtin_provider_catalog();
    let anthropic = catalog
        .get(&provider_id("anthropic"))
        .expect("Anthropic provider");
    assert!(anthropic.supports_authentication_kind(CredentialAuthKind::OAuth));
    let token = |id: &str, owner: &Owner| CredentialMetadata {
        placement: Placement::Platform,
        provider: provider_id("anthropic"),
        authentication_kind: CredentialAuthKind::OAuth,
        account_hint: None,
        ..credential(id, owner.clone())
    };
    let personal = token("claude-personal", &user);
    let organization = token("claude-org", &org);
    let platform_profile = |owner: &Owner, credential: &CredentialMetadata| AccessProfile {
        placement: Placement::Platform,
        entries: [(slot("anthropic"), credential.id.clone())]
            .into_iter()
            .collect(),
        ..profile("work", owner.clone(), "unused")
    };
    let credentials: BTreeMap<_, _> = [&personal, &organization]
        .into_iter()
        .map(|credential| (credential.id.clone(), credential.clone()))
        .collect();

    // Neither an organization profile nor a personal one may select an
    // organization's subscription token.
    for owner in [&org, &user] {
        assert_eq!(
            validate_profile_entries(
                &platform_profile(owner, &organization),
                &credentials,
                &catalog
            ),
            Err(AccessError::OrganizationOAuthUnsupported)
        );
    }

    // The owner's own token is selectable in the Anthropic slot only, with
    // exactly the Messages and token-counting permissions.
    let selected = platform_profile(&user, &personal);
    validate_profile_entries(&selected, &credentials, &catalog).unwrap();
    let mut grant_context = context([personal.id.clone()]);
    grant_context.placement = GrantPlacement::Platform;
    grant_context.organization_id = Some(owner_id("org-one"));
    grant_context.allow_personal_credentials = true;
    let grants = derive_available_grants(
        &grant_context,
        &binding(&selected),
        &selected,
        &credentials,
        &catalog,
        1_800_000_000,
    )
    .unwrap();
    assert!(grants.reconnect_required.is_empty());
    let grant = grants
        .grants
        .iter()
        .find(|grant| grant.capability_slot == slot("anthropic"))
        .expect("Anthropic grant");
    assert_eq!(
        grant.permissions,
        BTreeSet::from([permission("messages", "anthropic-api")])
    );
    assert_eq!(
        HttpProvider::for_credential(&slot("anthropic"), &personal),
        Some(HttpProvider::AnthropicSubscriptionToken)
    );
    let mut misplaced = platform_profile(&user, &personal);
    misplaced.entries = [(slot("codex"), personal.id.clone())].into_iter().collect();
    assert!(matches!(
        validate_profile_entries(&misplaced, &credentials, &catalog),
        Err(AccessError::UnsupportedCapability { .. })
    ));
}

#[test]
fn duplicate_and_empty_provider_definitions_fail_closed() {
    let definition = ProviderDefinition {
        id: provider_id("openai"),
        authentication_kinds: [CredentialAuthKind::OAuth].into_iter().collect(),
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
            authentication_kinds: BTreeSet::new(),
            capabilities: BTreeMap::new(),
        }]),
        Err(AccessError::EmptyCollection {
            field: "provider authentication kinds"
        })
    );

    let storable_only = ProviderCatalog::from_definitions([ProviderDefinition {
        id: provider_id("github"),
        authentication_kinds: [CredentialAuthKind::OAuth].into_iter().collect(),
        capabilities: BTreeMap::new(),
    }])
    .expect("storable provider without a runnable capability");
    assert!(
        storable_only
            .get(&provider_id("github"))
            .unwrap()
            .supports_authentication_kind(CredentialAuthKind::OAuth)
    );

    assert!(matches!(
        ProviderCatalog::from_definitions([ProviderDefinition {
            id: provider_id("mismatch"),
            authentication_kinds: [CredentialAuthKind::OAuth].into_iter().collect(),
            capabilities: BTreeMap::from([(
                slot("codex"),
                CapabilityPolicy {
                    authentication_kinds: [CredentialAuthKind::ApiKey].into_iter().collect(),
                    permissions: [permission("responses", "openai-api")]
                        .into_iter()
                        .collect(),
                },
            )]),
        }]),
        Err(AccessError::UnsupportedAuthenticationKind {
            kind: CredentialAuthKind::ApiKey,
            ..
        })
    ));
}

fn github_connection(id: &str, owner: Owner, status: CredentialStatus) -> CredentialMetadata {
    CredentialMetadata {
        provider: provider_id("github"),
        status,
        ..credential(id, owner)
    }
}

fn github_profile(owner: Owner) -> AccessProfile {
    AccessProfile {
        entries: BTreeMap::new(),
        ..profile("github-work", owner, "unused")
    }
}

#[test]
fn every_personal_profile_includes_github_and_never_pins_it() {
    let user = Owner::User(owner_id("user-one"));
    let mut pinned = profile("pinned", user.clone(), "github-one");
    pinned.entries = [(CapabilitySlot::github(), credential_id("github-one"))]
        .into_iter()
        .collect();
    assert!(pinned.validate().is_err());

    let empty = github_profile(user.clone());
    empty.validate().unwrap();
    assert!(empty.includes_github());
    assert_eq!(empty.launch_slots(true).collect::<Vec<_>>(), vec!["github"]);
    // A missing connection is omitted from the launch, never fabricated, but
    // GitHub's environment names stay reserved whether or not it is connected.
    assert!(empty.launch_slots(false).next().is_none());
    assert_eq!(empty.reserved_slots().collect::<Vec<_>>(), vec!["github"]);
    let codex = profile("codex", user, "codex-work");
    assert_eq!(
        codex.launch_slots(true).collect::<Vec<_>>(),
        vec!["codex", "github"]
    );
    assert_eq!(codex.launch_slots(false).collect::<Vec<_>>(), vec!["codex"]);
    assert_eq!(
        codex.reserved_slots().collect::<Vec<_>>(),
        vec!["codex", "github"]
    );
    // Organizations cannot hold a GitHub connection.
    let organization = profile(
        "shared",
        Owner::Organization(owner_id("org-one")),
        "codex-org",
    );
    assert!(!organization.includes_github());
    assert_eq!(
        organization.launch_slots(true).collect::<Vec<_>>(),
        vec!["codex"]
    );
    assert_eq!(
        organization.reserved_slots().collect::<Vec<_>>(),
        vec!["codex"]
    );
}

#[test]
fn profiles_grant_only_the_authorized_current_github_connection() {
    let user = Owner::User(owner_id("user-one"));
    let catalog = builtin_provider_catalog();
    let github_profile = github_profile(user.clone());
    let active = github_connection("github-one", user.clone(), CredentialStatus::Active);
    let credentials = [(active.id.clone(), active.clone())]
        .into_iter()
        .collect::<BTreeMap<_, _>>();

    // Launch authority authorized the connection: exactly one GitHub grant.
    let grants = derive_grants(
        &context([active.id.clone()]),
        &binding(&github_profile),
        &github_profile,
        &credentials,
        &catalog,
        1_800_000_000,
    )
    .unwrap();
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].capability_slot, CapabilitySlot::github());
    assert_eq!(grants[0].credential_id, active.id);

    // Not authorized (for example disconnected or expired at launch): GitHub
    // is omitted, never fabricated and never a launch failure.
    let omitted = derive_grants(
        &context([]),
        &binding(&github_profile),
        &github_profile,
        &credentials,
        &catalog,
        1_800_000_000,
    )
    .unwrap();
    assert!(omitted.is_empty());

    // No connection at all: omitted as well.
    let none = derive_grants(
        &context([]),
        &binding(&github_profile),
        &github_profile,
        &BTreeMap::new(),
        &catalog,
        1_800_000_000,
    )
    .unwrap();
    assert!(none.is_empty());

    // Another user's connection is never selected.
    let other = github_connection(
        "github-other",
        Owner::User(owner_id("user-two")),
        CredentialStatus::Active,
    );
    let foreign = [(other.id.clone(), other.clone())]
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    let cross_user = derive_grants(
        &context([other.id.clone()]),
        &binding(&github_profile),
        &github_profile,
        &foreign,
        &catalog,
        1_800_000_000,
    )
    .unwrap();
    assert!(cross_user.is_empty());
}

#[test]
fn a_platform_environment_without_a_profile_uses_the_creators_authorized_github() {
    let user = Owner::User(owner_id("user-one"));
    let catalog = builtin_provider_catalog();
    let active = CredentialMetadata {
        placement: Placement::Platform,
        ..github_connection("github-one", user, CredentialStatus::Active)
    };
    let credentials = [(active.id.clone(), active.clone())]
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    // Selecting a repository is the creator's own consent: an organization
    // environment needs no personal-profile confirmation for it.
    let platform = |authorized: Vec<CredentialId>| GrantContext {
        placement: GrantPlacement::Platform,
        organization_id: Some(owner_id("org-one")),
        ..context(authorized)
    };

    let grant = derive_account_github_grant(
        &platform(vec![active.id.clone()]),
        &credentials,
        &catalog,
        1_800_000_000,
    )
    .unwrap()
    .expect("authorized account connection");
    assert_eq!(grant.capability_slot, CapabilitySlot::github());
    assert_eq!(grant.credential_id, active.id);
    assert_eq!(grant.profile, None);

    // Not authorized by launch authority, or no connection: omitted.
    for (authorized, credentials) in [
        (Vec::new(), credentials.clone()),
        (vec![active.id.clone()], BTreeMap::new()),
    ] {
        assert_eq!(
            derive_account_github_grant(&platform(authorized), &credentials, &catalog, 1),
            Ok(None)
        );
    }

    // Another user's connection is never the creator's.
    let other = CredentialMetadata {
        placement: Placement::Platform,
        ..github_connection(
            "github-other",
            Owner::User(owner_id("user-two")),
            CredentialStatus::Active,
        )
    };
    let foreign = [(other.id.clone(), other.clone())]
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        derive_account_github_grant(&platform(vec![other.id]), &foreign, &catalog, 1),
        Ok(None)
    );

    // Only hosted platform environments hold an account grant.
    for placement in [GrantPlacement::Local, GrantPlacement::PlatformToLocal] {
        let context = GrantContext {
            placement,
            ..platform(vec![active.id.clone()])
        };
        assert!(derive_account_github_grant(&context, &credentials, &catalog, 1).is_err());
    }

    // An authorized but revoked connection fails closed.
    let revoked = CredentialMetadata {
        status: CredentialStatus::Revoked,
        ..active.clone()
    };
    let revoked = [(revoked.id.clone(), revoked)]
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    assert!(
        derive_account_github_grant(&platform(vec![active.id]), &revoked, &catalog, 1).is_err()
    );
}
