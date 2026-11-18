//! The `CreateEnvironment` request for a create form's accepted draft and its
//! source selection, so the dashboard and the iOS app send the same request,
//! `project_spec` and personal-access intent included.

use codewire_project::create_input::{CreateDraft, Isolation};
use codewire_proto::codewire::v1 as proto;

use crate::to_proto;

pub fn create_request(
    org_id: &str,
    draft: CreateDraft,
    sources: &proto::EnvironmentSourceSelection,
) -> proto::CreateEnvironmentRequest {
    let mut project_spec = to_proto(draft.project_spec);
    project_spec.secrets = sources.secrets.clone();
    project_spec.credentials = sources.credentials.clone();
    let access = personal_access(sources);
    proto::CreateEnvironmentRequest {
        org_id: org_id.to_owned(),
        preset_id: draft.preset_id,
        name: draft.name,
        ttl_seconds: draft.ttl_seconds,
        isolation_tier: match draft.isolation {
            Isolation::Standard => proto::IsolationTier::Standard,
            Isolation::Confidential => proto::IsolationTier::Confidential,
        }
        .into(),
        omit_application_previews: draft.omit_application_previews,
        project_spec: Some(project_spec).into(),
        expected_profile_revision: sources.profile_revision,
        confirm_personal_secrets: access.secrets,
        confirm_personal_credentials: access.credentials,
        ..Default::default()
    }
}

/// A form's choice of an environment's sources, by platform id.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SourceChoice<'a> {
    pub secret_project: Option<&'a str>,
    pub organization_secrets: bool,
    pub personal_secrets: bool,
    /// A credential profile and the revision the form showed.
    pub credential_profile: Option<(&'a str, u64)>,
}

/// The selection a create or update sends for a form's choice. The server
/// checks each reference and pins the profile to the revision.
pub fn source_selection(choice: SourceChoice<'_>) -> proto::EnvironmentSourceSelection {
    proto::EnvironmentSourceSelection {
        secrets: Some(proto::ProjectSecretBindings {
            project: choice
                .secret_project
                .map(|id| format!("platform:id:{id}"))
                .unwrap_or_default(),
            organization: choice.organization_secrets,
            user: choice
                .personal_secrets
                .then(|| proto::ProjectStoragePlacement::Platform.into()),
            ..Default::default()
        })
        .into(),
        credentials: choice
            .credential_profile
            .map(|(id, _)| proto::ProjectCredentialBinding {
                profile: format!("platform:id:{id}"),
                ..Default::default()
            })
            .into(),
        profile_revision: choice.credential_profile.map(|(_, revision)| revision),
        ..Default::default()
    }
}

/// The personal sources a create or update may use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PersonalAccess {
    pub secrets: bool,
    pub credentials: bool,
}

/// An explicit selection authorizes only the personal sources it selects.
/// The API's guards and exact revision binding stay; loading catalog metadata
/// or carrying an expected prior selection grants nothing.
pub fn personal_access(selection: &proto::EnvironmentSourceSelection) -> PersonalAccess {
    PersonalAccess {
        secrets: selection.secrets.as_option().is_some_and(|secrets| {
            secrets.user.is_some_and(|placement| {
                placement.as_known() == Some(proto::ProjectStoragePlacement::Platform)
            })
        }),
        credentials: selection.credentials.is_set(),
    }
}
