use super::*;

const NOW: u64 = 1_800_000_000;
const PLACEMENTS: [(GrantPlacement, Placement, Placement); 3] = [
    (GrantPlacement::Local, Placement::Local, Placement::Local),
    (
        GrantPlacement::Platform,
        Placement::Platform,
        Placement::Platform,
    ),
    (
        GrantPlacement::PlatformToLocal,
        Placement::Platform,
        Placement::Local,
    ),
];

fn fixture(
    placement: GrantPlacement,
    storage: Placement,
) -> (GrantContext, AccessProfile, CredentialMetadata) {
    let owner = Owner::User(owner_id("user-one"));
    let mut selected = credential("codex-work", owner.clone());
    selected.placement = storage;
    selected.revocation_generation = 4;
    let mut profile = profile("work", owner, "codex-work");
    profile.placement = storage;
    profile.revision = 3;
    let mut context = context([selected.id.clone()]);
    context.placement = placement;
    (context, profile, selected)
}

fn evaluate(
    context: &GrantContext,
    profile: &AccessProfile,
    selected: &CredentialMetadata,
) -> Result<Vec<DerivedGrant>, AccessError> {
    derive_grants(
        context,
        &binding(profile),
        profile,
        &BTreeMap::from([(selected.id.clone(), selected.clone())]),
        &catalog([CredentialAuthKind::OAuth]),
        NOW,
    )
}

#[test]
fn three_closed_placements_derive_exact_material_free_grants() {
    for (placement, storage, target) in PLACEMENTS {
        assert_eq!(placement.credential_storage(), storage);
        assert_eq!(placement.execution_target(), target);
        let (context, profile, selected) = fixture(placement, storage);
        assert_eq!(
            evaluate(&context, &profile, &selected).unwrap(),
            vec![DerivedGrant {
                environment_id: context.environment_id.clone(),
                environment_generation: 7,
                profile_id: profile.id.clone(),
                profile_revision: 3,
                capability_slot: slot("codex"),
                credential_id: selected.id.clone(),
                credential_revocation_generation: 4,
                expires_at_unix: selected.expires_at_unix,
                permissions: BTreeSet::from([permission("responses", "openai-api")]),
            }],
            "{placement:?}"
        );
    }
}

#[test]
fn storage_mismatch_is_not_execution_target_compatibility() {
    for (placement, storage, _) in PLACEMENTS {
        let other_storage = match storage {
            Placement::Local => Placement::Platform,
            Placement::Platform => Placement::Local,
        };
        let (context, profile, selected) = fixture(placement, other_storage);
        assert_eq!(
            evaluate(&context, &profile, &selected),
            Err(AccessError::PlacementMismatch {
                subject: "access profile"
            }),
            "{placement:?} must not admit {other_storage:?} records"
        );

        let (context, profile, mut selected) = fixture(placement, storage);
        selected.placement = other_storage;
        assert_eq!(
            evaluate(&context, &profile, &selected),
            Err(AccessError::PlacementMismatch {
                subject: "credential"
            })
        );
    }
}

#[test]
fn placement_serialization_is_explicit_closed_and_keeps_storage_separate() {
    for (placement, encoded) in [
        (GrantPlacement::Local, "local"),
        (GrantPlacement::Platform, "platform"),
        (GrantPlacement::PlatformToLocal, "platform_to_local"),
    ] {
        let expected = serde_json::json!(encoded);
        assert_eq!(serde_json::to_value(placement).unwrap(), expected);
        assert_eq!(
            serde_json::from_value::<GrantPlacement>(expected.clone()).unwrap(),
            placement
        );
        let (context, _, _) = fixture(placement, placement.credential_storage());
        let json = serde_json::to_value(&context).unwrap();
        assert_eq!(json["placement"], expected);
        assert_eq!(
            serde_json::from_value::<GrantContext>(json).unwrap(),
            context
        );
    }
    for invalid in [
        serde_json::json!("local_to_platform"),
        serde_json::json!("PlatformToLocal"),
        serde_json::json!("platform-to-local"),
        serde_json::json!(""),
        serde_json::json!(null),
        serde_json::json!(0),
        serde_json::json!({"platform_to_local": {}}),
    ] {
        assert!(serde_json::from_value::<GrantPlacement>(invalid).is_err());
    }
    let (context, profile, selected) =
        fixture(GrantPlacement::PlatformToLocal, Placement::Platform);
    let mut missing = serde_json::to_value(&context).unwrap();
    missing.as_object_mut().unwrap().remove("placement");
    assert!(serde_json::from_value::<GrantContext>(missing).is_err());
    let mut unknown = serde_json::to_value(context).unwrap();
    unknown["execution_target"] = serde_json::json!("local");
    assert!(serde_json::from_value::<GrantContext>(unknown).is_err());
    let mut profile_json = serde_json::to_value(profile).unwrap();
    assert_eq!(profile_json["placement"], "platform");
    profile_json["placement"] = serde_json::json!("platform_to_local");
    assert!(serde_json::from_value::<AccessProfile>(profile_json).is_err());
    let mut credential_json = serde_json::to_value(selected).unwrap();
    assert_eq!(credential_json["placement"], "platform");
    credential_json["placement"] = serde_json::json!("platform_to_local");
    assert!(serde_json::from_value::<CredentialMetadata>(credential_json).is_err());
}

#[test]
fn every_placement_preserves_owner_and_explicit_authorization_fences() {
    for (placement, storage, _) in PLACEMENTS {
        let (context, profile, selected) = fixture(placement, storage);
        let mut unauthorized = context.clone();
        unauthorized.authorized_credentials.clear();
        assert_eq!(
            evaluate(&unauthorized, &profile, &selected),
            Err(AccessError::CredentialNotAuthorized {
                credential: selected.id.clone()
            })
        );
        let mut wrong_user = context.clone();
        wrong_user.user_id = owner_id("user-other");
        assert_eq!(
            evaluate(&wrong_user, &profile, &selected),
            Err(AccessError::ProfileOwnerMismatch)
        );
        let mut wrong_owner = selected.clone();
        wrong_owner.owner = Owner::User(owner_id("user-other"));
        assert_eq!(
            evaluate(&context, &profile, &wrong_owner),
            Err(AccessError::CredentialOwnerMismatch {
                credential: selected.id
            })
        );
    }
}

#[test]
fn every_placement_rejects_revoked_refresh_failed_and_expired_credentials() {
    for (placement, storage, _) in PLACEMENTS {
        let (context, profile, selected) = fixture(placement, storage);
        for status in [
            CredentialStatus::Revoked,
            CredentialStatus::RefreshFailed,
            CredentialStatus::Expired,
        ] {
            let mut inactive = selected.clone();
            inactive.status = status;
            let expected = if status == CredentialStatus::Expired {
                AccessError::CredentialExpired {
                    credential: selected.id.clone(),
                }
            } else {
                AccessError::CredentialInactive {
                    credential: selected.id.clone(),
                }
            };
            assert_eq!(evaluate(&context, &profile, &inactive), Err(expected));
        }
        for expiry in [NOW - 1, NOW] {
            let mut expired = selected.clone();
            expired.expires_at_unix = Some(expiry);
            assert_eq!(
                evaluate(&context, &profile, &expired),
                Err(AccessError::CredentialExpired {
                    credential: selected.id.clone()
                })
            );
        }
    }
}

#[test]
fn every_placement_keeps_exact_binding_and_positive_environment_generation() {
    for (placement, storage, _) in PLACEMENTS {
        let (mut context, profile, selected) = fixture(placement, storage);
        for corruption in 0..3 {
            let mut stale = binding(&profile);
            match corruption {
                0 => stale.environment_id = EnvironmentId::parse("env-other").unwrap(),
                1 => stale.profile_id = profile_id("other"),
                2 => stale.profile_revision += 1,
                _ => unreachable!(),
            }
            assert_eq!(
                derive_grants(
                    &context,
                    &stale,
                    &profile,
                    &BTreeMap::from([(selected.id.clone(), selected.clone())]),
                    &catalog([CredentialAuthKind::OAuth]),
                    NOW,
                ),
                Err(AccessError::BindingMismatch)
            );
        }
        context.environment_generation = 0;
        assert_eq!(
            evaluate(&context, &profile, &selected),
            Err(AccessError::ZeroGeneration {
                field: "environment generation"
            })
        );
    }
}

#[test]
fn organization_restriction_follows_storage_not_execution_target() {
    for (placement, storage, _) in PLACEMENTS {
        let (mut context, mut profile, mut selected) = fixture(placement, storage);
        context.organization_id = Some(owner_id("org-one"));
        profile.owner = Owner::Organization(owner_id("org-one"));
        selected.owner = profile.owner.clone();
        if placement == GrantPlacement::Local {
            assert_eq!(
                evaluate(&context, &profile, &selected),
                Err(AccessError::LocalOrganizationUnsupported)
            );
            continue;
        }
        assert_eq!(evaluate(&context, &profile, &selected).unwrap().len(), 1);
        context.organization_id = Some(owner_id("org-other"));
        assert_eq!(
            evaluate(&context, &profile, &selected),
            Err(AccessError::ProfileOwnerMismatch)
        );
    }
}

#[test]
fn platform_to_local_retains_personal_confirmation_and_exact_organization_owner() {
    let (mut context, profile, mut selected) =
        fixture(GrantPlacement::PlatformToLocal, Placement::Platform);
    context.organization_id = Some(owner_id("org-one"));
    assert_eq!(
        evaluate(&context, &profile, &selected),
        Err(AccessError::PersonalCredentialsForbidden)
    );
    context.allow_personal_credentials = true;
    assert_eq!(evaluate(&context, &profile, &selected).unwrap().len(), 1);

    selected.owner = Owner::Organization(owner_id("org-one"));
    context.allow_personal_credentials = false;
    assert_eq!(evaluate(&context, &profile, &selected).unwrap().len(), 1);
    context.organization_id = Some(owner_id("org-other"));
    assert_eq!(
        evaluate(&context, &profile, &selected),
        Err(AccessError::CredentialOwnerMismatch {
            credential: selected.id.clone()
        })
    );
    context.organization_id = None;
    assert_eq!(
        evaluate(&context, &profile, &selected),
        Err(AccessError::CredentialOwnerMismatch {
            credential: selected.id.clone()
        })
    );
    context.organization_id = Some(owner_id("org-one"));
    context.allow_personal_credentials = true;
    let mut organization_profile = profile;
    organization_profile.owner = Owner::Organization(owner_id("org-one"));
    selected.owner = Owner::User(owner_id("user-one"));
    assert_eq!(
        evaluate(&context, &organization_profile, &selected),
        Err(AccessError::CredentialOwnerMismatch {
            credential: selected.id
        })
    );
}
