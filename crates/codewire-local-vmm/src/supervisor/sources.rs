//! Exact material-free source metadata for the native lifecycle.

mod metadata;
pub(super) mod platform;
mod transition;
pub(crate) use metadata::PlatformSourceAuthority;

use codewire_project::{ProjectSpec, StoragePlacement, StorageReference};

use super::*;

fn exact_reference(reference: StorageReference<'_>) -> Result<StoragePlacement, SupervisorError> {
    let placement = reference.placement.ok_or(SupervisorError::InvalidRequest)?;
    let id = reference
        .selector
        .strip_prefix("id:")
        .ok_or(SupervisorError::InvalidRequest)?;
    if !Uuid::parse_str(id).is_ok_and(|uuid| !uuid.is_nil() && uuid.to_string() == id) {
        return Err(SupervisorError::InvalidRequest);
    }
    Ok(placement)
}

pub(super) fn profile_placement(
    project: &ProjectSpec,
) -> Result<Option<StoragePlacement>, SupervisorError> {
    project
        .credentials
        .as_ref()
        .map(|credentials| {
            let reference = StorageReference::profile(&credentials.profile)
                .map_err(|_| SupervisorError::InvalidState)?;
            exact_reference(reference)
        })
        .transpose()
}

/// Derive only exact local source metadata. Platform-backed values use their
/// authenticated delegation path; never silently replace them with local data.
pub(super) fn projection_environment_for_boot(
    environment: &EnvironmentRecord,
) -> Result<EnvironmentRecord, SupervisorError> {
    let mut boot = environment.clone();
    if let Some(staging) = environment.staging_workspace_generation.as_ref() {
        let (json, sha256) = staging.project_intent_with_current_sources(
            environment
                .project_spec_json
                .as_deref()
                .ok_or(SupervisorError::InvalidState)?,
            environment
                .project_spec_sha256
                .as_deref()
                .ok_or(SupervisorError::InvalidState)?,
        )?;
        boot.project_spec_json = Some(json);
        boot.project_spec_sha256 = Some(sha256);
    }
    Ok(boot)
}

pub(super) fn local_launch_projection(
    environment: &EnvironmentRecord,
) -> Result<Option<codewire_local_credentials::LocalEnvironmentProjectionBinding>, SupervisorError>
{
    let json = environment
        .project_spec_json
        .as_deref()
        .ok_or(SupervisorError::InvalidState)?;
    let sha256 = environment
        .project_spec_sha256
        .as_deref()
        .ok_or(SupervisorError::InvalidState)?;
    validate_project_intent(json, sha256, None).map_err(|_| SupervisorError::InvalidState)?;
    let project: ProjectSpec =
        serde_json::from_slice(json).map_err(|_| SupervisorError::InvalidState)?;
    let has_platform = platform::requires_platform_authority(&project)?;
    // Validate any pinned platform metadata even when this function returns
    // only local scope IDs (or no local projection). This never reads login or
    // local credential material and never treats platform sources as local.
    platform::managed_clients(environment)?;
    let project_id = if project.secrets.project.is_empty() {
        None
    } else {
        let reference = StorageReference::project(&project.secrets.project)
            .map_err(|_| SupervisorError::InvalidState)?;
        if exact_reference(reference)? == StoragePlacement::Local {
            Some(
                Uuid::parse_str(
                    reference
                        .selector
                        .strip_prefix("id:")
                        .ok_or(SupervisorError::InvalidState)?,
                )
                .map_err(|_| SupervisorError::InvalidState)?,
            )
        } else {
            None
        }
    };
    let user = project.secrets.user == Some(StoragePlacement::Local);
    if project_id.is_none() && !user && (has_platform || project.credentials.is_none()) {
        // A platform authority supplies the admitted empty projection for a
        // provider-only boot. Retain the pure-local empty projection otherwise.
        return Ok(None);
    }
    let selection_sha256 = codewire_vmm_guest_probe::Sha256Value::parse_hex(sha256)
        .map_err(|_| SupervisorError::InvalidState)?;
    // Platform slot metadata is already pinned and validated above. Local
    // slots still come from the parent's existing local-profile admission.
    let mut reserved_keys: BTreeSet<String> = codewire_project::RESERVED_RUNTIME_ENVIRONMENT_KEYS
        .into_iter()
        .chain(["CODEX_HOME"])
        .map(str::to_owned)
        .collect();
    if let Some(authority) = &environment.platform_source_authority {
        reserved_keys.extend(platform::reserved_keys(authority)?);
    }
    Ok(Some(
        codewire_local_credentials::LocalEnvironmentProjectionBinding {
            selection: codewire_local_credentials::LocalLaunchSecretSelection {
                project_id,
                user,
                overridden_keys: project.environment.keys().cloned().collect(),
                // The fixed native agent home owns skills/session state even
                // without credentials. The manager reserves other routing
                // names only for exact selected provider slots.
                reserved_keys,
            },
            selection_sha256: selection_sha256.as_bytes(),
        },
    ))
}

pub(super) fn validate_source_metadata(
    project: &ProjectSpec,
    profile_id: &str,
    revision: u64,
    profile_reference: &str,
    authority: Option<&v1::PlatformSourceAuthority>,
) -> Result<Option<(AccessProfileId, u64, AccessProfileReference)>, SupervisorError> {
    crate::supervisor_metadata::validate_source_metadata(
        project,
        profile_id,
        revision,
        profile_reference,
        authority,
    )
    .map_err(SupervisorError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn environment_for(project: &ProjectSpec) -> EnvironmentRecord {
        let mut environment = super::super::tests::project_environment();
        let mut project = project.clone();
        project.image = "registry.example/codewire/workspace:latest".into();
        let json = project.canonical_json().unwrap();
        environment.project_spec_sha256 = Some(format!("{:x}", Sha256::digest(&json)));
        environment.project_spec_json = Some(json);
        environment
    }

    #[test]
    fn local_projection_preserves_original_keys_exact_ids_and_current_selection_hash() {
        let mut project = ProjectSpec::default();
        project.secrets.project = "local:id:11111111-1111-4111-8111-111111111111".into();
        project.secrets.user = Some(StoragePlacement::Local);
        project
            .environment
            .insert("LOG_LEVEL".into(), "debug".into());
        let environment = environment_for(&project);
        let binding = local_launch_projection(&environment).unwrap().unwrap();
        assert_eq!(
            binding.selection.project_id,
            Some(Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap())
        );
        assert!(binding.selection.user);
        assert_eq!(
            binding.selection.overridden_keys,
            BTreeSet::from(["LOG_LEVEL".into()])
        );
        assert!(binding.selection.reserved_keys.contains("CODEX_HOME"));
        assert!(
            binding
                .selection
                .reserved_keys
                .contains("CODEWIRE_MANAGED_CREDENTIAL_CLIENTS")
        );
        assert_eq!(
            binding.selection_sha256,
            Sha256::digest(environment.project_spec_json.as_ref().unwrap()).as_slice()
        );
        assert!(!format!("{binding:?}").contains("debug"));
    }

    #[test]
    fn no_selection_does_not_create_a_projection_binding() {
        assert!(
            local_launch_projection(&environment_for(&ProjectSpec::default()))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn provider_only_boot_uses_same_empty_projection_without_selecting_app_material() {
        let project = ProjectSpec {
            credentials: Some(codewire_project::CredentialBinding {
                profile: "local:id:11111111-1111-4111-8111-111111111111".into(),
            }),
            ..Default::default()
        };
        let binding = local_launch_projection(&environment_for(&project))
            .unwrap()
            .unwrap();
        assert!(binding.selection.project_id.is_none());
        assert!(!binding.selection.user);
        assert_ne!(binding.selection_sha256, [0; 32]);
    }

    #[test]
    fn platform_sources_never_fall_back_to_local_authority() {
        for field in 0..3 {
            let mut project = ProjectSpec::default();
            match field {
                0 => {
                    project.secrets.project =
                        "platform:id:11111111-1111-4111-8111-111111111111".into()
                }
                1 => project.secrets.user = Some(StoragePlacement::Platform),
                _ => project.secrets.organization = true,
            }
            let mut environment = environment_for(&project);
            assert!(local_launch_projection(&environment).is_err());
            environment.platform_source_authority = Some(PlatformSourceAuthority {
                server_url: "https://platform.invalid".into(),
                organization_id: "synthetic-org".into(),
                user_id: "synthetic-owner".into(),
                profile_slots: BTreeSet::new(),
            });
            assert!(local_launch_projection(&environment).unwrap().is_none());
        }
    }

    #[test]
    fn launch_projection_rejects_unresolved_or_corrupt_selection_metadata() {
        let mut project = ProjectSpec::default();
        project.secrets.project = "local:development".into();
        assert!(local_launch_projection(&environment_for(&project)).is_err());
        project.secrets.project.clear();
        project.secrets.user = Some(StoragePlacement::Local);
        let mut environment = environment_for(&project);
        environment.project_spec_sha256 = Some("a".repeat(64));
        assert!(local_launch_projection(&environment).is_err());
    }

    #[test]
    fn source_metadata_requires_exact_origin_id_and_matching_profile_pin() {
        let mut project = ProjectSpec::default();
        let id = "11111111-1111-4111-8111-111111111111";
        assert!(
            validate_source_metadata(&project, "", 0, "", None)
                .unwrap()
                .is_none()
        );
        project.credentials = Some(codewire_project::CredentialBinding {
            profile: format!("local:id:{id}"),
        });
        assert!(
            validate_source_metadata(&project, id, 1, "user/work", None)
                .unwrap()
                .is_some()
        );
        assert!(validate_source_metadata(&project, id, 0, "user/work", None).is_err());
        assert!(
            validate_source_metadata(
                &project,
                "22222222-2222-4222-8222-222222222222",
                1,
                "user/work",
                None
            )
            .is_err()
        );
        assert!(validate_source_metadata(&project, id, 1, "organization/work", None).is_err());
        project.credentials.as_mut().unwrap().profile = "work".into();
        assert!(validate_source_metadata(&project, id, 1, "user/work", None).is_err());
    }

    #[test]
    fn platform_source_identity_is_required_only_for_selected_platform_sources() {
        let mut authority = v1::PlatformSourceAuthority {
            server_url: "https://synthetic.invalid".into(),
            organization_id: "test-org".into(),
            user_id: "test-owner".into(),
            profile_slots: Vec::new(),
        };
        let mut project = ProjectSpec::default();
        assert!(validate_source_metadata(&project, "", 0, "", Some(&authority)).is_err());
        project.secrets.user = Some(StoragePlacement::Platform);
        assert!(validate_source_metadata(&project, "", 0, "", None).is_err());
        validate_source_metadata(&project, "", 0, "", Some(&authority)).unwrap();
        for server in [
            "file:///tmp/x",
            "https://user@synthetic.invalid",
            "https://synthetic.invalid/path",
            "https://synthetic.invalid?key=value",
        ] {
            let mut invalid = authority.clone();
            invalid.server_url = server.into();
            assert!(validate_source_metadata(&project, "", 0, "", Some(&invalid)).is_err());
        }
        authority.profile_slots = vec!["github".into()];
        assert!(validate_source_metadata(&project, "", 0, "", Some(&authority)).is_err());
        project.credentials = Some(codewire_project::CredentialBinding {
            profile: "platform:id:11111111-1111-4111-8111-111111111111".into(),
        });
        for slot in ["codex", "github"] {
            authority.profile_slots = vec![slot.into()];
            validate_source_metadata(
                &project,
                "11111111-1111-4111-8111-111111111111",
                7,
                "user/work",
                Some(&authority),
            )
            .unwrap();
        }
        for profile_slots in [
            vec!["codex".into(), "codex".into()],
            vec!["openai".into(), "codex".into()],
            vec!["github".into(), "codex".into()],
            vec!["GitHub".into()],
            vec!["unregistered".into()],
        ] {
            let mut invalid = authority.clone();
            invalid.profile_slots = profile_slots;
            assert!(PlatformSourceAuthority::from_proto(&invalid).is_err());
        }
    }

    #[test]
    fn platform_source_json_requires_canonical_profile_slots() {
        let authority = PlatformSourceAuthority {
            server_url: "https://synthetic.invalid".into(),
            organization_id: "test-org".into(),
            user_id: "test-owner".into(),
            profile_slots: ["codex".into(), "github".into(), "openai".into()].into(),
        };
        let encoded = serde_json::to_string(&authority).unwrap();
        assert!(encoded.contains(r#""profile_slots":["codex","github","openai"]"#));
        assert_eq!(
            serde_json::from_str::<PlatformSourceAuthority>(&encoded).unwrap(),
            authority
        );
        for invalid in [
            r#"{"server_url":"https://synthetic.invalid","organization_id":"test-org","user_id":"test-owner"}"#,
            r#"{"server_url":"https://synthetic.invalid","organization_id":"test-org","user_id":"test-owner","profile_slots":["openai","codex"]}"#,
            r#"{"server_url":"https://synthetic.invalid","organization_id":"test-org","user_id":"test-owner","profile_slots":["github","codex"]}"#,
            r#"{"server_url":"https://synthetic.invalid","organization_id":"test-org","user_id":"test-owner","profile_slots":["codex","codex"]}"#,
        ] {
            assert!(serde_json::from_str::<PlatformSourceAuthority>(invalid).is_err());
        }
    }
}
