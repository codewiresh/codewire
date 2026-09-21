//! Read-only platform source options. Hosted pages never probe local stores.

use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::http::HeaderValue;
use codewire_proto::codewire::v1::{
    AccessProfile, AccessProfileServiceClient, Credential, CredentialStatus,
    ListAccessProfilesRequest, ListSecretProjectsRequest, SecretServiceClient,
};
use connectrpc::{ConnectError, client::ClientConfig};

use crate::{
    credentials_connect,
    state::AppState,
    transport::BrowserTransport,
    view::{
        EnvironmentCredentialProfileOption, EnvironmentSecretProjectOption,
        EnvironmentSourceFieldsView, GithubProfileConnection,
    },
};

const PAGE_SIZE: i32 = 100;
const MAX_PAGES: usize = 10;
const LOAD_TIMEOUT: Duration = Duration::from_secs(10);

fn transport(state: &AppState, cookie: HeaderValue) -> BrowserTransport {
    BrowserTransport {
        http: state.http.clone(),
        cookie: Some(cookie),
        origin: None,
    }
}

fn config(state: &AppState) -> ClientConfig {
    ClientConfig::new(state.api_origin.clone()).with_default_timeout(LOAD_TIMEOUT)
}

pub(crate) async fn options(
    state: &AppState,
    cookie: HeaderValue,
    org_id: &str,
) -> EnvironmentSourceFieldsView {
    let (projects, profiles) = tokio::join!(
        tokio::time::timeout(LOAD_TIMEOUT, projects(state, cookie.clone(), org_id)),
        tokio::time::timeout(LOAD_TIMEOUT, profiles(state, cookie.clone())),
    );
    let mut options = EnvironmentSourceFieldsView {
        application_selection_enabled: true,
        credential_selection_enabled: true,
        ..Default::default()
    };
    match projects {
        Ok(Ok(projects)) => options.projects = projects,
        _ => {
            options.project_error =
                "Project names could not be loaded. Reload before selecting a project.".to_owned()
        }
    }
    match profiles {
        Ok(Ok(profiles)) => options.profiles = profiles,
        _ => {
            options.profile_error =
                "Credential profiles could not be loaded. Reload before selecting a profile."
                    .to_owned()
        }
    }
    if options
        .profiles
        .iter()
        .any(|profile| !profile.github_credential_id.is_empty())
    {
        let credentials = tokio::time::timeout(
            LOAD_TIMEOUT,
            credentials_connect::list_credentials(state, cookie),
        )
        .await;
        let metadata_available = match credentials {
            Ok(Ok(credentials)) => {
                enrich_github_profiles(&mut options.profiles, credentials).is_ok()
            }
            _ => false,
        };
        if !metadata_available {
            options
                .profiles
                .iter_mut()
                .filter(|profile| !profile.github_credential_id.is_empty())
                .for_each(|profile| {
                    profile.github_connection = GithubProfileConnection::MetadataUnavailable
                });
        }
    }
    options
}

fn enrich_github_profiles(
    profiles: &mut [EnvironmentCredentialProfileOption],
    credentials: Vec<Credential>,
) -> Result<(), ConnectError> {
    let mut by_id = BTreeMap::new();
    for credential in credentials {
        credentials_connect::validate_credential_metadata(&credential)?;
        if by_id.insert(credential.id.clone(), credential).is_some() {
            return Err(invalid_options());
        }
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| invalid_options())?
        .as_secs();
    for profile in profiles {
        if profile.github_credential_id.is_empty() {
            continue;
        }
        let Some(credential) = by_id.get(&profile.github_credential_id) else {
            profile.github_connection = GithubProfileConnection::MetadataUnavailable;
            continue;
        };
        if credentials_connect::credential_slot(credential)? != "github" {
            profile.github_connection = GithubProfileConnection::MetadataUnavailable;
            continue;
        }
        profile.github_connection = if credential.status == CredentialStatus::Active
            && credential.expires_at_unix.is_none_or(|expiry| expiry > now)
        {
            profile.github_account = credential.account_hint.clone().unwrap_or_default();
            GithubProfileConnection::Connected
        } else {
            GithubProfileConnection::Inactive
        };
    }
    Ok(())
}

async fn projects(
    state: &AppState,
    cookie: HeaderValue,
    org_id: &str,
) -> Result<Vec<EnvironmentSecretProjectOption>, ConnectError> {
    let client = SecretServiceClient::new(transport(state, cookie), config(state));
    let mut options = Vec::new();
    let mut page_token = String::new();
    let mut seen = BTreeSet::new();
    for _ in 0..MAX_PAGES {
        let response = client
            .list_secret_projects(ListSecretProjectsRequest {
                org_id: org_id.to_owned(),
                page_size: PAGE_SIZE,
                page_token: page_token.clone(),
                ..Default::default()
            })
            .await?
            .into_owned();
        if response.secret_projects.len() > PAGE_SIZE as usize {
            return Err(invalid_options());
        }
        for project in response.secret_projects {
            if crate::environment_source_forms::exact_id(&project.id).is_err()
                || project.name.is_empty()
                || !seen.insert(project.id.clone())
            {
                return Err(invalid_options());
            }
            options.push(EnvironmentSecretProjectOption {
                id: project.id,
                name: project.name,
                selected: false,
                synthetic: false,
            });
        }
        if response.next_page_token.is_empty() {
            options.sort_by(|a, b| a.name.cmp(&b.name).then(a.id.cmp(&b.id)));
            return Ok(options);
        }
        if response.next_page_token == page_token {
            return Err(invalid_options());
        }
        page_token = response.next_page_token;
    }
    // Never show a partial list as if an omitted selection did not exist.
    Err(invalid_options())
}

async fn profiles(
    state: &AppState,
    cookie: HeaderValue,
) -> Result<Vec<EnvironmentCredentialProfileOption>, ConnectError> {
    let client = AccessProfileServiceClient::new(transport(state, cookie), config(state));
    let mut options = Vec::new();
    let mut page_token = String::new();
    let mut seen = BTreeSet::new();
    for _ in 0..MAX_PAGES {
        let response = client
            .list_access_profiles(ListAccessProfilesRequest {
                page_size: PAGE_SIZE,
                page_token: page_token.clone(),
                ..Default::default()
            })
            .await?
            .into_owned();
        if response.access_profiles.len() > PAGE_SIZE as usize {
            return Err(invalid_options());
        }
        for profile in response.access_profiles {
            if !seen.insert(profile.id.clone()) {
                return Err(invalid_options());
            }
            options.push(profile_option(profile)?);
        }
        if response.next_page_token.is_empty() {
            options.sort_by(|a, b| a.name.cmp(&b.name).then(a.id.cmp(&b.id)));
            return Ok(options);
        }
        if response.next_page_token == page_token {
            return Err(invalid_options());
        }
        page_token = response.next_page_token;
    }
    Err(invalid_options())
}

fn profile_option(
    profile: AccessProfile,
) -> Result<EnvironmentCredentialProfileOption, ConnectError> {
    if crate::environment_source_forms::exact_id(&profile.id).is_err()
        || profile.name.is_empty()
        || profile.revision == 0
        || profile.revision > i64::MAX as u64
    {
        return Err(invalid_options());
    }
    let mut slots = BTreeSet::new();
    let mut github_credential_id = String::new();
    if profile.entries.len() > 5 {
        return Err(invalid_options());
    }
    for entry in &profile.entries {
        if !matches!(
            entry.capability_slot.as_str(),
            "codex" | "openai" | "github" | "anthropic" | "ssh"
        ) || !slots.insert(entry.capability_slot.as_str())
            || crate::environment_source_forms::exact_id(&entry.credential_id).is_err()
        {
            return Err(invalid_options());
        }
        if entry.capability_slot == "github" {
            github_credential_id = entry.credential_id.clone();
        }
    }
    Ok(EnvironmentCredentialProfileOption {
        id: profile.id,
        name: profile.name,
        revision: profile.revision,
        identity_count: profile
            .entries
            .iter()
            .map(|entry| &entry.credential_id)
            .collect::<BTreeSet<_>>()
            .len(),
        bound_revision: false,
        synthetic: false,
        selected: false,
        github_connection: if github_credential_id.is_empty() {
            GithubProfileConnection::NotConfigured
        } else {
            GithubProfileConnection::MetadataUnavailable
        },
        github_credential_id,
        github_account: String::new(),
    })
}

fn invalid_options() -> ConnectError {
    ConnectError::unavailable("complete source selection metadata is unavailable")
}

impl EnvironmentSourceFieldsView {
    pub(crate) fn complete(&self) -> bool {
        self.application_selection_enabled
            && self.credential_selection_enabled
            && self.project_error.is_empty()
            && self.profile_error.is_empty()
    }

    pub(crate) fn ready_for_edit(&self) -> bool {
        self.complete()
            && self.project_selection_error.is_empty()
            && self.profile_selection_error.is_empty()
    }

    /// Preserve an exact prior selection, including an already-bound profile
    /// revision. New catalog metadata must never silently select a newer revision.
    pub(crate) fn select(
        &mut self,
        selection: &codewire_proto::codewire::v1::EnvironmentSourceSelection,
    ) {
        self.select_inner(selection, false);
    }

    pub(crate) fn select_bound(
        &mut self,
        selection: &codewire_proto::codewire::v1::EnvironmentSourceSelection,
    ) {
        self.select_inner(selection, true);
    }

    fn select_inner(
        &mut self,
        selection: &codewire_proto::codewire::v1::EnvironmentSourceSelection,
        already_bound: bool,
    ) {
        use crate::environment_source_forms::{exact_reference, validate_selection};
        // Prior fallback rows are not authoritative catalog entries.
        self.projects.retain(|project| !project.synthetic);
        self.profiles.retain(|profile| !profile.synthetic);
        self.project_selection_error.clear();
        self.profile_selection_error.clear();
        if validate_selection(selection).is_err() {
            self.project_selection_error =
                "Current source selection is invalid. Reload before editing.".into();
            self.profile_selection_error = self.project_selection_error.clone();
            return;
        }
        self.selection = Some(selection.clone());
        let secrets = selection.secrets.as_option().cloned().unwrap_or_default();
        self.organization_selected = secrets.organization;
        self.personal_selected = secrets.user.is_some();
        let project_id = exact_reference(&secrets.project).unwrap_or_default();
        for project in &mut self.projects {
            project.selected = project.id == project_id;
        }
        if !project_id.is_empty() && !self.projects.iter().any(|project| project.selected) {
            self.projects.push(EnvironmentSecretProjectOption {
                id: project_id.into(),
                name: if self.application_selection_enabled && self.project_error.is_empty() {
                    "Current selected project (unavailable)"
                } else {
                    "Current selected project (metadata unavailable)"
                }
                .into(),
                selected: true,
                synthetic: true,
            });
            // A complete catalog may omit a deleted bound source. Keep its
            // expected ID so the owner can clear/replace it. A failed catalog
            // load still carries its error and disables the entire editor.
            if !already_bound && self.application_selection_enabled && self.project_error.is_empty()
            {
                self.project_selection_error =
                    "The selected project is unavailable. Choose no project secrets or an available project to continue.".into();
            }
        }
        let profile_id = selection
            .credentials
            .as_option()
            .and_then(|binding| exact_reference(&binding.profile).ok())
            .unwrap_or_default();
        for profile in &mut self.profiles {
            profile.selected =
                profile.id == profile_id && Some(profile.revision) == selection.profile_revision;
        }
        if !profile_id.is_empty() && !self.profiles.iter().any(|profile| profile.selected) {
            let current_name = self
                .profiles
                .iter()
                .find(|profile| profile.id == profile_id)
                .map(|profile| profile.name.clone());
            if !already_bound && self.credential_selection_enabled && self.profile_error.is_empty()
            {
                self.profile_selection_error =
                    "The selected profile revision is unavailable. Choose no provider credentials or an available revision to continue.".into();
            }
            self.profiles.push(EnvironmentCredentialProfileOption {
                id: profile_id.into(),
                name: current_name.unwrap_or_else(|| {
                    if self.credential_selection_enabled && self.profile_error.is_empty() {
                        "Current selected profile (unavailable)"
                    } else {
                        "Current selected profile (metadata unavailable)"
                    }
                    .into()
                }),
                revision: selection.profile_revision.unwrap_or_default(),
                identity_count: 0,
                bound_revision: already_bound,
                synthetic: true,
                selected: true,
                github_credential_id: String::new(),
                github_account: String::new(),
                github_connection: GithubProfileConnection::MetadataUnavailable,
            });
        }
        // Consent is not inferred from the stored selection.
    }

    pub(crate) fn retain_submission(&mut self, previous: &Self) {
        if let Some(selection) = &previous.selection {
            self.select(selection);
        }
        self.personal_secrets_confirmed = previous.personal_secrets_confirmed;
        self.personal_credentials_confirmed = previous.personal_credentials_confirmed;
    }
}

#[cfg(test)]
mod tests {
    use askama::Template;

    use super::*;

    #[derive(Template)]
    #[template(path = "environment-source-fields.html")]
    struct SourceFieldsTemplate<'a> {
        source_fields_id: &'a str,
        source_creation_draft_parameter: &'a str,
        sources: &'a EnvironmentSourceFieldsView,
        organization: &'a SourceFieldsOrganization,
    }

    struct SourceFieldsOrganization {
        slug: &'static str,
        secrets_url: &'static str,
    }

    const ORGANIZATION: SourceFieldsOrganization = SourceFieldsOrganization {
        slug: "test-org",
        secrets_url: "/test-org/secrets/",
    };

    #[test]
    fn profile_options_keep_exact_revision_without_selecting_it() {
        let option = profile_option(AccessProfile {
            id: "6bf8d155-e84c-4fc5-b479-b17022fe41dd".into(),
            name: "work".into(),
            revision: 7,
            ..Default::default()
        })
        .expect("valid profile metadata");
        assert_eq!(option.id, "6bf8d155-e84c-4fc5-b479-b17022fe41dd");
        assert_eq!(option.name, "work");
        assert_eq!(option.revision, 7);
        assert!(!option.selected);
        assert!(
            profile_option(AccessProfile {
                revision: 0,
                ..Default::default()
            })
            .is_err()
        );
    }

    #[test]
    fn profile_options_reject_noncanonical_ids_and_out_of_range_revisions() {
        for (id, revision) in [
            ("profile-id", 7),
            ("00000000-0000-0000-0000-000000000000", 7),
            ("6bf8d155-e84c-4fc5-b479-b17022fe41dd", i64::MAX as u64 + 1),
        ] {
            assert!(
                profile_option(AccessProfile {
                    id: id.into(),
                    name: "work".into(),
                    revision,
                    ..Default::default()
                })
                .is_err()
            );
        }
    }

    #[test]
    fn github_profile_identity_uses_only_its_exact_current_account_metadata() {
        use codewire_proto::codewire::v1::{AccessProfileEntry, CredentialAuthenticationKind};

        let github_id = "315dd4c2-6bf2-4c3b-9d8f-68fc97654a76";
        let other_id = "6bf8d155-e84c-4fc5-b479-b17022fe41dd";
        let profile = AccessProfile {
            id: "11111111-1111-4111-8111-111111111111".into(),
            name: "work".into(),
            revision: 7,
            entries: vec![
                AccessProfileEntry {
                    capability_slot: "codex".into(),
                    credential_id: other_id.into(),
                    ..Default::default()
                },
                AccessProfileEntry {
                    capability_slot: "github".into(),
                    credential_id: github_id.into(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let option = profile_option(profile.clone()).expect("profile");
        assert_eq!(option.github_credential_id, github_id);
        assert_eq!(
            option.github_connection,
            GithubProfileConnection::MetadataUnavailable
        );
        let github = Credential {
            id: github_id.into(),
            name: "verified-user".into(),
            provider: "github".into(),
            authentication_kind: CredentialAuthenticationKind::Oauth.into(),
            account_hint: Some("verified-user".into()),
            status: CredentialStatus::Active.into(),
            revocation_generation: 1,
            ..Default::default()
        };
        let codex = Credential {
            id: other_id.into(),
            name: "not-the-github-account".into(),
            provider: "openai".into(),
            authentication_kind: CredentialAuthenticationKind::Oauth.into(),
            status: CredentialStatus::Active.into(),
            revocation_generation: 1,
            ..Default::default()
        };
        let mut options = vec![option.clone()];
        enrich_github_profiles(&mut options, vec![codex.clone(), github.clone()])
            .expect("metadata");
        assert_eq!(
            options[0].github_connection,
            GithubProfileConnection::Connected
        );
        assert_eq!(options[0].github_account, "verified-user");

        let mut absent = vec![option.clone()];
        enrich_github_profiles(&mut absent, vec![codex])
            .expect("missing metadata is not a connection");
        assert_eq!(
            absent[0].github_connection,
            GithubProfileConnection::MetadataUnavailable
        );
        assert!(absent[0].github_account.is_empty());

        let mut revoked = github.clone();
        revoked.status = CredentialStatus::Revoked.into();
        let mut inactive = vec![option.clone()];
        enrich_github_profiles(&mut inactive, vec![revoked]).expect("revoked metadata");
        assert_eq!(
            inactive[0].github_connection,
            GithubProfileConnection::Inactive
        );
        assert!(inactive[0].github_account.is_empty());

        let mut wrong_provider = github;
        wrong_provider.provider = "openai".into();
        let mut mismatched = vec![option];
        enrich_github_profiles(&mut mismatched, vec![wrong_provider]).expect("mismatched slot");
        assert_eq!(
            mismatched[0].github_connection,
            GithubProfileConnection::MetadataUnavailable
        );

        let mut duplicated_slot = profile;
        duplicated_slot.entries.push(AccessProfileEntry {
            capability_slot: "github".into(),
            credential_id: other_id.into(),
            ..Default::default()
        });
        assert!(profile_option(duplicated_slot).is_err());
    }

    #[test]
    fn selection_refresh_preserves_the_bound_revision_without_implying_consent() {
        let id = "6bf8d155-e84c-4fc5-b479-b17022fe41dd";
        let selection = crate::environment_source_forms::SourceSubmission::parse(
            format!("credential_profile={id}%407&include_user_secrets=platform").as_bytes(),
        )
        .unwrap()
        .selection;
        let mut fields = EnvironmentSourceFieldsView {
            application_selection_enabled: true,
            credential_selection_enabled: true,
            profiles: vec![
                profile_option(AccessProfile {
                    id: id.into(),
                    name: "work".into(),
                    revision: 8,
                    ..Default::default()
                })
                .unwrap(),
            ],
            ..Default::default()
        };
        fields.select_bound(&selection);
        assert!(fields.complete());
        assert!(!fields.profiles[0].selected);
        assert!(fields.profiles[1].selected && fields.profiles[1].bound_revision);
        assert_eq!(fields.profiles[1].revision, 7);
        assert!(fields.personal_selected);
        assert!(!fields.personal_credentials_confirmed && !fields.personal_secrets_confirmed);
        let mut incomplete = EnvironmentSourceFieldsView::default();
        incomplete.retain_submission(&fields);
        assert!(!incomplete.complete());
        assert_eq!(incomplete.selection, fields.selection);
        assert!(incomplete.profile_selection_error.is_empty());
    }

    #[test]
    fn deleted_bound_source_can_be_cleared_but_incomplete_catalog_cannot_submit() {
        let id = "6bf8d155-e84c-4fc5-b479-b17022fe41dd";
        let selected = crate::environment_source_forms::SourceSubmission::parse(
            format!("secret_project={id}").as_bytes(),
        )
        .unwrap()
        .selection;
        let mut complete = EnvironmentSourceFieldsView {
            application_selection_enabled: true,
            credential_selection_enabled: true,
            ..Default::default()
        };
        let mut create = complete.clone();
        create.select(&selected);
        assert!(create.complete());
        assert!(!create.project_selection_error.is_empty());
        complete.select_bound(&selected);
        assert!(complete.complete());
        assert!(complete.projects[0].selected);
        assert_eq!(complete.selection.as_ref(), Some(&selected));
        let mut unavailable = EnvironmentSourceFieldsView {
            project_error: "Complete catalog unavailable".into(),
            ..complete.clone()
        };
        unavailable.select_bound(&selected);
        assert!(!unavailable.complete());
    }

    #[test]
    fn stale_unbound_revision_requires_an_explicit_choice_and_never_becomes_catalog_metadata() {
        let id = "6bf8d155-e84c-4fc5-b479-b17022fe41dd";
        let selection = |revision| {
            crate::environment_source_forms::SourceSubmission::parse(
                format!("credential_profile={id}%40{revision}").as_bytes(),
            )
            .unwrap()
            .selection
        };
        let mut fields = EnvironmentSourceFieldsView {
            application_selection_enabled: true,
            credential_selection_enabled: true,
            profiles: vec![
                profile_option(AccessProfile {
                    id: id.into(),
                    name: "work".into(),
                    revision: 8,
                    ..Default::default()
                })
                .unwrap(),
            ],
            ..Default::default()
        };
        for _ in 0..3 {
            fields.select(&selection(7));
            assert!(fields.complete());
            assert!(!fields.profile_selection_error.is_empty());
            assert!(fields.profile_error.is_empty());
            assert_eq!(fields.profiles.len(), 2);
            assert!(!fields.profiles[0].selected);
            assert!(fields.profiles[1].selected && fields.profiles[1].synthetic);
            assert!(!fields.profiles[1].bound_revision);
            let body = SourceFieldsTemplate {
                source_creation_draft_parameter: "",
                source_fields_id: "create",
                sources: &fields,
                organization: &ORGANIZATION,
            }
            .render()
            .unwrap();
            assert!(body.contains(&format!("value=\"{id}@7\" selected")));
            assert!(body.contains("revision 7 · unavailable selection"));
            assert!(body.contains("aria-invalid=\"true\""));
            assert!(!body.contains(" disabled"));
            assert!(!body.contains("current bound revision"));
        }
        fields.select(&selection(8));
        assert!(fields.profile_selection_error.is_empty());
        assert_eq!(fields.profiles.len(), 1);
        assert!(fields.profiles[0].selected);
        fields.select(&Default::default());
        assert!(fields.profile_selection_error.is_empty());
        assert!(!fields.profiles[0].selected);
    }

    #[test]
    fn deleted_sources_can_be_explicitly_cleared_without_clearing_catalog_failures() {
        let id = "6bf8d155-e84c-4fc5-b479-b17022fe41dd";
        let selected = crate::environment_source_forms::SourceSubmission::parse(
            format!("secret_project={id}&credential_profile={id}%407").as_bytes(),
        )
        .unwrap()
        .selection;
        let mut fields = EnvironmentSourceFieldsView {
            application_selection_enabled: true,
            credential_selection_enabled: true,
            ..Default::default()
        };
        for _ in 0..3 {
            fields.select(&selected);
            assert_eq!(fields.projects.len(), 1);
            assert_eq!(fields.profiles.len(), 1);
            assert!(!fields.project_selection_error.is_empty());
            assert!(!fields.profile_selection_error.is_empty());
        }
        fields.select(&Default::default());
        assert!(fields.projects.is_empty() && fields.profiles.is_empty());
        assert!(
            fields.project_selection_error.is_empty() && fields.profile_selection_error.is_empty()
        );
        fields.project_error = "Project names could not be loaded.".into();
        fields.profile_error = "Credential profiles could not be loaded.".into();
        fields.select(&selected);
        fields.select(&Default::default());
        assert!(!fields.complete());
        assert!(!fields.project_error.is_empty() && !fields.profile_error.is_empty());
    }

    #[test]
    fn failed_catalog_markup_preserves_exact_metadata_outside_disabled_fieldsets() {
        let id = "6bf8d155-e84c-4fc5-b479-b17022fe41dd";
        let selected = crate::environment_source_forms::SourceSubmission::parse(
            format!("secret_project={id}&credential_profile={id}%407&include_user_secrets=platform&include_org_secrets=platform").as_bytes(),
        ).unwrap().selection;
        let mut fields = EnvironmentSourceFieldsView {
            project_error: "Project names could not be loaded.".into(),
            profile_error: "Credential profiles could not be loaded.".into(),
            ..Default::default()
        };
        fields.select(&selected);
        let body = SourceFieldsTemplate {
            source_creation_draft_parameter: "",
            source_fields_id: "create",
            sources: &fields,
            organization: &ORGANIZATION,
        }
        .render()
        .unwrap();
        for (name, value, fieldset_help) in [
            ("secret_project", id.to_owned(), "secrets"),
            ("include_org_secrets", "platform".into(), "secrets"),
            ("include_user_secrets", "platform".into(), "secrets"),
            ("credential_profile", format!("{id}@7"), "credentials"),
        ] {
            let hidden = format!("<input type=\"hidden\" name=\"{name}\" value=\"{value}\">");
            assert_eq!(body.matches(&hidden).count(), 1);
            let fieldset = format!(
                "<fieldset class=\"cw-source-fields\" aria-describedby=\"create-{fieldset_help}-help\" disabled>"
            );
            assert!(body.find(&hidden).unwrap() < body.find(&fieldset).unwrap());
        }
        assert!(!fields.complete());
        assert!(
            fields.project_selection_error.is_empty() && fields.profile_selection_error.is_empty()
        );
    }

    #[test]
    fn malformed_bound_selection_cannot_enable_the_source_editor() {
        let mut fields = EnvironmentSourceFieldsView {
            application_selection_enabled: true,
            credential_selection_enabled: true,
            ..Default::default()
        };
        fields.select_bound(&codewire_proto::codewire::v1::EnvironmentSourceSelection {
            profile_revision: Some(7),
            ..Default::default()
        });
        assert!(fields.complete());
        assert!(!fields.ready_for_edit());
        fields.select_bound(&Default::default());
        assert!(fields.ready_for_edit());
    }

    #[test]
    fn metadata_does_not_enable_delivery_or_confirm_provider_access() {
        let options = EnvironmentSourceFieldsView::default();
        assert!(!options.application_selection_enabled);
        assert!(!options.credential_selection_enabled);
        assert!(!options.personal_credentials_confirmed);
    }

    #[test]
    fn create_and_edit_share_value_free_platform_selection_fields() {
        let sources = EnvironmentSourceFieldsView {
            personal_selected: true,
            projects: vec![EnvironmentSecretProjectOption {
                id: "project-id".into(),
                name: "<unsafe-project>".into(),
                selected: true,
                synthetic: false,
            }],
            profiles: vec![EnvironmentCredentialProfileOption {
                id: "profile-id".into(),
                name: "<unsafe-profile>".into(),
                revision: 7,
                identity_count: 2,
                bound_revision: false,
                synthetic: false,
                selected: true,
                github_credential_id: String::new(),
                github_account: String::new(),
                github_connection: GithubProfileConnection::NotConfigured,
            }],
            application_selection_enabled: true,
            credential_selection_enabled: true,
            ..Default::default()
        };
        for source_fields_id in ["environment-create", "environment-edit"] {
            let body = SourceFieldsTemplate {
                source_creation_draft_parameter: "",
                source_fields_id,
                sources: &sources,
                organization: &ORGANIZATION,
            }
            .render()
            .expect("selection fields");
            assert!(body.contains(&format!("id=\"{source_fields_id}-secret-project\"")));
            assert!(body.contains("name=\"include_user_secrets\" value=\"platform\" checked"));
            assert!(body.contains("value=\"project-id\" selected"));
            assert!(body.contains("value=\"profile-id@7\" selected"));
            assert!(body.contains("revision 7"));
            assert!(!body.contains("<unsafe-"));
            assert!(!body.contains(" disabled"));
            assert!(!body.contains("name=\"confirm_personal_credentials\""));
            assert!(!body.contains("name=\"confirm_personal_secrets\""));
            assert!(body.contains("href=\"/settings/secrets/?org=test-org\""));
            assert!(body.contains("href=\"/test-org/secrets/organization/\""));
            assert!(body.contains("href=\"/test-org/secrets/\""));
            assert!(body.contains("href=\"/settings/credentials/?org=test-org\""));
            assert!(body.contains("<nav aria-label=\"Manage provider credentials\">"));
            assert!(!body.contains("No secret projects are available"));
            assert!(!body.contains("You have no credential profiles yet"));
            for forbidden in [
                "secret_value",
                "private_key",
                "access_token",
                "exposed",
                "stored_exposures",
                "local:",
            ] {
                assert!(
                    !body.contains(forbidden),
                    "unexpected form surface {forbidden}"
                );
            }
        }
    }

    #[test]
    fn unavailable_metadata_disables_selection_without_echoing_upstream_detail() {
        let sources = EnvironmentSourceFieldsView {
            application_selection_enabled: true,
            credential_selection_enabled: true,
            project_error: "Project names could not be loaded.".into(),
            profile_error: "Credential profiles could not be loaded.".into(),
            ..Default::default()
        };
        let body = SourceFieldsTemplate {
            source_creation_draft_parameter: "",
            source_fields_id: "edit",
            sources: &sources,
            organization: &ORGANIZATION,
        }
        .render()
        .expect("unavailable fields");
        assert!(body.contains("aria-describedby=\"edit-secrets-help\" disabled>"));
        assert!(body.contains("aria-describedby=\"edit-credentials-help\" disabled>"));
        assert!(body.contains("role=\"alert\">Project names could not be loaded."));
        assert!(!body.contains("No secret projects are available"));
        assert!(!body.contains("You have no credential profiles yet"));
        assert!(body.contains("href=\"/settings/secrets/?org=test-org\""));
        assert!(body.contains("Manage personal credentials and profiles</a>"));
    }

    #[test]
    fn empty_catalogs_offer_scoped_setup_without_claiming_all_secrets_are_empty() {
        let sources = EnvironmentSourceFieldsView {
            application_selection_enabled: true,
            credential_selection_enabled: true,
            ..Default::default()
        };
        let body = SourceFieldsTemplate {
            source_creation_draft_parameter: "",
            source_fields_id: "create",
            sources: &sources,
            organization: &ORGANIZATION,
        }
        .render()
        .expect("empty source options");
        assert!(body.contains("No secret projects are available in this organization."));
        assert!(body.contains("You have no credential profiles yet."));
        assert!(body.contains("<nav aria-label=\"Manage provider credentials\">"));
        assert!(body.contains("Create a profile in Settings, then select it here.</p>"));
        assert!(body.contains("href=\"/settings/secrets/?org=test-org\""));
        assert!(body.contains("href=\"/test-org/secrets/organization/\""));
        assert!(body.contains("href=\"/test-org/secrets/\""));
        assert!(body.contains(
            "href=\"/settings/credentials/?org=test-org\">Add credentials and create a profile</a>"
        ));
        assert!(!body.contains("No personal secrets"));
        assert!(!body.contains("No organization secrets"));
        assert!(!body.contains(" checked"));
        assert!(!body.contains(" selected"));

        let disabled = SourceFieldsTemplate {
            source_creation_draft_parameter: "",
            source_fields_id: "create",
            sources: &EnvironmentSourceFieldsView::default(),
            organization: &ORGANIZATION,
        }
        .render()
        .expect("disabled source options");
        assert!(!disabled.contains("No secret projects are available"));
        assert!(!disabled.contains("You have no credential profiles yet"));
    }
}
