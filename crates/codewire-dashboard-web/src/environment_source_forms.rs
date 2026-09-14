//! Bounded, metadata-only adapters for the source selection forms.

use std::collections::BTreeMap;

use codewire_proto::codewire::v1::{
    CreateEnvironmentRequest, EnvironmentSourceSelection, ProjectCredentialBinding,
    ProjectSecretBindings, ProjectStoragePlacement, UpdateEnvironmentSourcesRequest,
};

pub(crate) const INVALID_SELECTION: &str =
    "The source selection is invalid. Reload and select platform sources again.";

// No Debug: rejected request fields must not leak into diagnostic output.
pub(crate) struct SourceSubmission {
    pub(crate) selection: EnvironmentSourceSelection,
    pub(crate) confirm_personal_secrets: bool,
    pub(crate) confirm_personal_credentials: bool,
}

impl SourceSubmission {
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, ()> {
        let values = source_fields(bytes)?;
        let selection = selection(&values, "")?;
        let (confirm_personal_secrets, confirm_personal_credentials) =
            personal_access_intent(&selection);
        Ok(Self {
            selection,
            confirm_personal_secrets,
            confirm_personal_credentials,
        })
    }

    pub(crate) fn apply_create(&self, request: &mut CreateEnvironmentRequest) -> Result<(), ()> {
        let spec = request.project_spec.as_option_mut().ok_or(())?;
        spec.secrets = self.selection.secrets.clone();
        spec.credentials = self.selection.credentials.clone();
        request.expected_profile_revision = self.selection.profile_revision;
        request.confirm_personal_secrets = self.confirm_personal_secrets;
        request.confirm_personal_credentials = self.confirm_personal_credentials;
        Ok(())
    }

    pub(crate) fn hydrate(&self, fields: &mut crate::view::EnvironmentSourceFieldsView) {
        fields.select(&self.selection);
        fields.personal_secrets_confirmed = self.confirm_personal_secrets;
        fields.personal_credentials_confirmed = self.confirm_personal_credentials;
    }
}

pub(crate) fn create_selection(
    request: &CreateEnvironmentRequest,
) -> Result<EnvironmentSourceSelection, ()> {
    let spec = request.project_spec.as_option().ok_or(())?;
    let selection = EnvironmentSourceSelection {
        secrets: spec.secrets.clone(),
        credentials: spec.credentials.clone(),
        profile_revision: request.expected_profile_revision,
        ..Default::default()
    };
    validate_selection(&selection)?;
    Ok(selection)
}

/// Dashboard inputs carry exact platform IDs, never an ambient storage choice.
pub(crate) fn validate_selection(value: &EnvironmentSourceSelection) -> Result<(), ()> {
    let secrets = value.secrets.as_option().cloned().unwrap_or_default();
    if !secrets.project.is_empty() {
        exact_reference(&secrets.project)?;
    }
    if secrets
        .user
        .is_some_and(|placement| placement.as_known() != Some(ProjectStoragePlacement::Platform))
    {
        return Err(());
    }
    match (value.credentials.as_option(), value.profile_revision) {
        (None, None) => {}
        (Some(profile), Some(revision)) if revision > 0 && revision <= i64::MAX as u64 => {
            exact_reference(&profile.profile)?;
        }
        _ => return Err(()),
    }
    Ok(())
}

pub(crate) fn exact_reference(value: &str) -> Result<&str, ()> {
    exact_id(value.strip_prefix("platform:id:").ok_or(())?)
}

pub(crate) fn update_request(
    bytes: &[u8],
    organization: &str,
    environment: &str,
) -> Result<UpdateEnvironmentSourcesRequest, ()> {
    let values = source_fields(bytes)?;
    let generation = positive(values.get("expected_operation_generation").ok_or(())?)?;
    let replacement = selection(&values, "")?;
    let (confirm_personal_secrets, confirm_personal_credentials) =
        personal_access_intent(&replacement);
    Ok(UpdateEnvironmentSourcesRequest {
        org_id: organization.into(),
        environment_id: environment.into(),
        expected_operation_generation: generation,
        expected: Some(selection(&values, "expected_")?).into(),
        replacement: Some(replacement).into(),
        allow_restart: checkbox(&values, "allow_restart", "true")?,
        confirm_personal_secrets,
        confirm_personal_credentials,
        ..Default::default()
    })
}

/// An explicit, validated selection authorizes only its selected personal
/// sources. Keep the API's guards and exact revision binding; merely loading
/// catalog metadata or carrying an expected prior selection grants nothing.
fn personal_access_intent(selection: &EnvironmentSourceSelection) -> (bool, bool) {
    (
        selection.secrets.as_option().is_some_and(|secrets| {
            secrets.user.is_some_and(|placement| {
                placement.as_known() == Some(ProjectStoragePlacement::Platform)
            })
        }),
        selection.credentials.is_set(),
    )
}

fn source_fields(bytes: &[u8]) -> Result<BTreeMap<String, String>, ()> {
    let mut fields = BTreeMap::new();
    for (key, value) in url::form_urlencoded::parse(bytes) {
        if key.starts_with("agent_secret_")
            || key.starts_with("exposure")
            || matches!(
                key.as_ref(),
                "secret_source" | "access_profile" | "secret_project_name"
            )
        {
            return Err(());
        }
        if matches!(
            key.as_ref(),
            "secret_project"
                | "include_org_secrets"
                | "include_user_secrets"
                | "credential_profile"
                | "confirm_personal_secrets"
                | "confirm_personal_credentials"
                | "allow_restart"
                | "expected_operation_generation"
                | "expected_secret_project"
                | "expected_include_org_secrets"
                | "expected_include_user_secrets"
                | "expected_credential_profile"
        ) && (value.len() > 128
            || fields
                .insert(key.into_owned(), value.into_owned())
                .is_some())
        {
            return Err(());
        }
    }
    // Previously rendered forms may still submit these fields. Validate their
    // closed shape for compatibility, but never use them to authorize sources.
    checkbox(&fields, "confirm_personal_secrets", "true")?;
    checkbox(&fields, "confirm_personal_credentials", "true")?;
    Ok(fields)
}

fn selection(
    fields: &BTreeMap<String, String>,
    prefix: &str,
) -> Result<EnvironmentSourceSelection, ()> {
    let project_key = format!("{prefix}secret_project");
    let project = fields
        .get(&project_key)
        .filter(|value| !value.is_empty())
        .map(|value| exact_id(value).map(|id| format!("platform:id:{id}")))
        .transpose()?
        .unwrap_or_default();
    let credentials_key = format!("{prefix}credential_profile");
    let selected = fields
        .get(&credentials_key)
        .filter(|value| !value.is_empty())
        .map(|value| {
            let (id, revision) = value.split_once('@').ok_or(())?;
            Ok::<_, ()>((exact_id(id)?, positive(revision)?))
        })
        .transpose()?;
    let organization = checkbox(fields, &format!("{prefix}include_org_secrets"), "platform")?;
    let user = checkbox(fields, &format!("{prefix}include_user_secrets"), "platform")?;
    Ok(EnvironmentSourceSelection {
        secrets: Some(ProjectSecretBindings {
            project,
            organization,
            user: user.then(|| ProjectStoragePlacement::Platform.into()),
            ..Default::default()
        })
        .into(),
        credentials: selected
            .as_ref()
            .map(|(id, _)| ProjectCredentialBinding {
                profile: format!("platform:id:{id}"),
                ..Default::default()
            })
            .into(),
        profile_revision: selected.map(|(_, revision)| revision),
        ..Default::default()
    })
}

pub(crate) fn exact_id(value: &str) -> Result<&str, ()> {
    let candidate = format!("platform:id:{value}");
    codewire_project::StorageReference::project(&candidate).map_err(|_| ())?;
    if value.len() != 36 {
        return Err(());
    }
    Ok(value)
}

fn positive(value: &str) -> Result<u64, ()> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(());
    }
    let value: u64 = value.parse().map_err(|_| ())?;
    if value == 0 || value > i64::MAX as u64 {
        return Err(());
    }
    Ok(value)
}

fn checkbox(fields: &BTreeMap<String, String>, key: &str, expected: &str) -> Result<bool, ()> {
    match fields.get(key).map(String::as_str) {
        None | Some("") => Ok(false),
        Some(value) if value == expected => Ok(true),
        _ => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const ID: &str = "6bf8d155-e84c-4fc5-b479-b17022fe41dd";

    #[test]
    fn create_form_derives_intent_from_selection_and_pins_exact_revision() {
        let bytes = format!(
            "secret_project={ID}&credential_profile={ID}%407&include_user_secrets=platform"
        );
        let source = SourceSubmission::parse(bytes.as_bytes()).unwrap();
        let mut request = CreateEnvironmentRequest {
            project_spec: Some(codewire_project_proto::to_proto(Default::default())).into(),
            ..Default::default()
        };
        source.apply_create(&mut request).unwrap();
        assert_eq!(request.expected_profile_revision, Some(7));
        assert!(request.confirm_personal_secrets && request.confirm_personal_credentials);
        assert_eq!(
            request
                .project_spec
                .as_option()
                .unwrap()
                .secrets
                .as_option()
                .unwrap()
                .project,
            format!("platform:id:{ID}")
        );
        assert_eq!(create_selection(&request).unwrap(), source.selection);
    }

    #[test]
    fn each_selected_source_authorizes_only_its_own_personal_access() {
        for (bytes, personal_secrets, personal_credentials) in [
            (String::new(), false, false),
            ("include_org_secrets=platform".into(), false, false),
            (format!("secret_project={ID}"), false, false),
            ("include_user_secrets=platform".into(), true, false),
            (format!("credential_profile={ID}%407"), false, true),
            (
                "confirm_personal_secrets=true&confirm_personal_credentials=true".into(),
                false,
                false,
            ),
        ] {
            let source = SourceSubmission::parse(bytes.as_bytes()).unwrap();
            let mut request = CreateEnvironmentRequest {
                project_spec: Some(codewire_project_proto::to_proto(Default::default())).into(),
                confirm_personal_secrets: true,
                confirm_personal_credentials: true,
                ..Default::default()
            };
            source.apply_create(&mut request).unwrap();
            assert_eq!(request.confirm_personal_secrets, personal_secrets);
            assert_eq!(request.confirm_personal_credentials, personal_credentials);
            assert_eq!(
                request.expected_profile_revision,
                personal_credentials.then_some(7)
            );
        }
    }

    #[test]
    fn update_preserves_expected_revision_and_generation_when_clearing() {
        let bytes = format!(
            "expected_operation_generation=9&expected_credential_profile={ID}%407&expected_include_user_secrets=platform&confirm_personal_secrets=true&confirm_personal_credentials=true"
        );
        let request = update_request(bytes.as_bytes(), "org", "environment").unwrap();
        assert_eq!(request.expected_operation_generation, 9);
        assert_eq!(
            request.expected.as_option().unwrap().profile_revision,
            Some(7)
        );
        assert!(
            request
                .replacement
                .as_option()
                .unwrap()
                .credentials
                .is_unset()
        );
        assert!(
            !request.allow_restart
                && !request.confirm_personal_secrets
                && !request.confirm_personal_credentials
        );
    }

    #[test]
    fn update_intent_comes_from_replacement_not_expected_sources_or_restart() {
        let replacement_id = "315dd4c2-6bf2-4c3b-9d8f-68fc97654a76";
        let bytes = format!(
            "expected_operation_generation=9&expected_credential_profile={ID}%407&expected_include_user_secrets=platform&credential_profile={replacement_id}%4011&allow_restart=true"
        );
        let request = update_request(bytes.as_bytes(), "org", "environment").unwrap();
        let expected = request.expected.as_option().unwrap();
        let replacement = request.replacement.as_option().unwrap();
        assert_eq!(request.expected_operation_generation, 9);
        assert_eq!(expected.profile_revision, Some(7));
        assert_eq!(
            expected.credentials.as_option().unwrap().profile,
            format!("platform:id:{ID}")
        );
        assert_eq!(replacement.profile_revision, Some(11));
        assert_eq!(
            replacement.credentials.as_option().unwrap().profile,
            format!("platform:id:{replacement_id}")
        );
        assert!(!request.confirm_personal_secrets);
        assert!(request.confirm_personal_credentials && request.allow_restart);

        let request = update_request(
            b"expected_operation_generation=9&include_user_secrets=platform",
            "org",
            "environment",
        )
        .unwrap();
        assert!(request.confirm_personal_secrets);
        assert!(!request.confirm_personal_credentials && !request.allow_restart);
    }

    #[test]
    fn untrusted_names_duplicates_unknown_origins_and_zero_revision_are_rejected() {
        for bytes in [
            "secret_project=secret-value-canary",
            "secret_project=&secret_project=",
            "include_user_secrets=local",
            "confirm_personal_credentials=yes",
            "confirm_personal_secrets=true&confirm_personal_secrets=true",
            "credential_profile=invalid%401",
            "credential_profile=6bf8d155-e84c-4fc5-b479-b17022fe41dd%400",
            "credential_profile=6bf8d155-e84c-4fc5-b479-b17022fe41dd%407&credential_profile=",
            "expected_operation_generation=0",
            "expected_operation_generation=9&expected_credential_profile=invalid%407",
            "expected_operation_generation=9&confirm_personal_credentials=yes",
        ] {
            if bytes.starts_with("expected_") {
                assert!(update_request(bytes.as_bytes(), "org", "env").is_err());
            } else {
                assert!(SourceSubmission::parse(bytes.as_bytes()).is_err());
            }
        }
    }
}
