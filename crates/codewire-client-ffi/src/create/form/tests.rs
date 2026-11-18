use codewire_client::Preset as ProtoPreset;
use codewire_project::{ProjectSpec, ResourceSpec};

use super::*;

const IMAGE: &str = "example.test/workspace@sha256:abc";
const PROFILE: &str = "6bf8d155-e84c-4fc5-b479-b17022fe41dd";

fn preset(ttl_seconds: Option<i32>) -> Preset {
    Preset {
        summary: PresetSummary {
            id: "preset-1".into(),
            name: "Rust".into(),
            description: None,
            official: true,
        },
        defaults: PresetDefaults {
            image: IMAGE.into(),
            ttl_seconds,
            ..Default::default()
        },
    }
}

fn messages(refusals: &[FieldRefusal]) -> Vec<(FormField, &str)> {
    refusals
        .iter()
        .map(|refusal| (refusal.field, refusal.message.as_str()))
        .collect()
}

/// The owner's refused create on 2026-11-16: a preset and nothing else.
#[test]
fn a_preset_alone_sends_its_project() {
    let form = CreateForm {
        preset_id: "preset-1".into(),
        ..Default::default()
    };
    let request = request_for("org-1", &form, &[preset(Some(3_600))], false)
        .ok()
        .unwrap();
    assert_eq!(request.org_id, "org-1");
    assert_eq!(request.preset_id.as_deref(), Some("preset-1"));
    assert_eq!(request.ttl_seconds, Some(3_600));
    assert_eq!(request.project_spec.as_option().unwrap().image, IMAGE);
}

#[test]
fn a_refused_form_names_each_field_in_the_dashboard_s_words() {
    let form = CreateForm {
        image: IMAGE.into(),
        cpu: "5".into(),
        delete_after: "30s".into(),
        confidential: true,
        ports: vec![PortField {
            port: "2222".into(),
            label: "web".into(),
            access: PreviewAccess::OrgMembers,
        }],
        ports_chosen: true,
        ..Default::default()
    };
    let refusals = request_for("org-1", &form, &[], false).err().unwrap();
    assert_eq!(
        messages(&refusals),
        [
            (FormField::Cpu, "CPU must be between 100 and 128000."),
            (
                FormField::DeleteAfter,
                "Enter a duration from 60 seconds to 365 days, such as 8h or 7d, or leave it empty."
            ),
            (
                FormField::Form,
                "Confidential Sandboxes are not available for this organization."
            ),
            (
                FormField::PortNumber { index: 0 },
                "Port 2222 is reserved for the Sandbox runtime."
            ),
        ]
    );
}

#[test]
fn without_a_preset_or_an_image_the_form_asks_for_one() {
    let refusals = request_for("org-1", &CreateForm::default(), &[preset(None)], false)
        .err()
        .unwrap();
    assert_eq!(
        messages(&refusals),
        [(
            FormField::Image,
            "Enter a workspace image or choose a repository."
        )]
    );
}

#[test]
fn sources_authorize_only_the_personal_sources_they_select() {
    let chosen = CreateForm {
        image: IMAGE.into(),
        sources: SourceChoice {
            secret_project_id: None,
            organization_secrets: true,
            personal_secrets: true,
            credential_profile: Some(ProfileChoice {
                id: PROFILE.into(),
                revision: 7,
            }),
        },
        ..Default::default()
    };
    let request = request_for("org-1", &chosen, &[], false).ok().unwrap();
    assert!(request.confirm_personal_secrets && request.confirm_personal_credentials);
    assert_eq!(request.expected_profile_revision, Some(7));
    let spec = request.project_spec.as_option().unwrap();
    assert_eq!(
        spec.credentials.as_option().unwrap().profile,
        format!("platform:id:{PROFILE}")
    );
    assert!(spec.secrets.as_option().unwrap().organization);

    let organization_only = CreateForm {
        sources: SourceChoice {
            organization_secrets: true,
            ..Default::default()
        },
        ..chosen
    };
    let request = request_for("org-1", &organization_only, &[], false)
        .ok()
        .unwrap();
    assert!(!request.confirm_personal_secrets && !request.confirm_personal_credentials);
    assert_eq!(request.expected_profile_revision, None);
}

#[test]
fn a_preset_s_defaults_come_from_its_project_as_form_text() {
    let response = GetEnvironmentCreateOptionsResponse {
        presets: vec![ProtoPreset {
            id: "preset-1".into(),
            name: "Rust".into(),
            description: Some("  ".into()),
            default_ttl_seconds: Some(5_400),
            project_spec: Some(codewire_project_proto::to_proto(ProjectSpec {
                image: IMAGE.into(),
                resources: ResourceSpec {
                    cpu_millicores: Some(2_000),
                    memory_mib: Some(4_096),
                    disk_gib: None,
                },
                ..Default::default()
            }))
            .into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let mut presets = presets(&response).unwrap();
    let preset = presets.remove(0);
    let option = preset_option(preset.summary, preset.defaults);
    assert_eq!(option.description, None);
    assert_eq!(option.image, IMAGE);
    assert_eq!(
        (
            option.cpu.as_str(),
            option.memory.as_str(),
            option.disk.as_str()
        ),
        ("2000", "4096", "")
    );
    assert_eq!(option.delete_after, "90m");
}

#[test]
fn a_preset_without_its_project_cannot_be_offered() {
    let response = GetEnvironmentCreateOptionsResponse {
        presets: vec![ProtoPreset {
            name: "Rust".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    assert!(matches!(
        presets(&response),
        Err(ShellError::Unavailable { message }) if message == "the preset Rust came without its project"
    ));
}
