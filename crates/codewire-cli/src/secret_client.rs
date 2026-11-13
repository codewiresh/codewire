use std::collections::BTreeSet;

use chrono::{DateTime, SecondsFormat, Utc};
use codewire_client::{self as rpc, CodewireClient};
use codewire_workload_secrets::{
    MAX_WORKLOAD_SECRETS, ResolvedWorkloadSecretMetadata, WorkloadSecretSource,
    validate_workload_secret_key,
};
use serde::{Deserialize, Serialize};

use crate::CLI_VERSION;
use crate::config::ResolvedPlatformConfig;
use crate::environment_client::display_client_error;

const SECRET_LIST_PAGE_SIZE: i32 = 100;
const SECRET_LIST_MAX_PAGES: usize = 10;

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct SecretMetadata {
    pub key: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub created_at: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub updated_at: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct SecretProject {
    pub id: String,
    pub org_id: String,
    pub name: String,
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub secret_count: i64,
    pub created_at: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CreateSecretProjectRequest {
    pub name: String,
}

fn is_zero_i64(value: &i64) -> bool {
    *value == 0
}

/// Typed SecretService facade used while the CLI retains its established
/// presentation DTOs.
///
/// Secret values are passed only to write-only generated request fields. This
/// facade never formats or returns those values.
#[derive(Clone)]
pub struct SecretClient {
    inner: CodewireClient,
}

impl SecretClient {
    pub fn new(config: &ResolvedPlatformConfig) -> anyhow::Result<Self> {
        let client_config = config
            .client_config()?
            .with_user_agent(format!("codewire-cli/{CLI_VERSION}"))?;
        Ok(Self {
            inner: CodewireClient::with_token_provider(client_config, config.token_provider()?)?,
        })
    }

    pub async fn list_org_secrets(&self, org_id: &str) -> anyhow::Result<Vec<SecretMetadata>> {
        let mut secrets = Vec::new();
        let mut page_token = String::new();
        loop {
            let response = self
                .inner
                .list_secrets(rpc::ListSecretsRequest {
                    org_id: org_id.to_string(),
                    page_size: SECRET_LIST_PAGE_SIZE,
                    page_token,
                    ..Default::default()
                })
                .await
                .map_err(display_client_error)?;
            secrets.extend(response.secrets.into_iter().map(legacy_secret_metadata));
            if response.next_page_token.is_empty() {
                return Ok(secrets);
            }
            page_token = response.next_page_token;
        }
    }

    pub async fn set_org_secret(&self, org_id: &str, key: &str, value: &str) -> anyhow::Result<()> {
        self.inner
            .set_secret(rpc::SetSecretRequest {
                org_id: org_id.to_string(),
                key: key.to_string(),
                value: value.to_string(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        Ok(())
    }

    pub async fn delete_org_secret(&self, org_id: &str, key: &str) -> anyhow::Result<()> {
        self.inner
            .delete_secret(rpc::DeleteSecretRequest {
                org_id: org_id.to_string(),
                key: key.to_string(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        Ok(())
    }

    pub async fn rename_org_secret(
        &self,
        org_id: &str,
        old_key: &str,
        new_key: &str,
    ) -> anyhow::Result<()> {
        self.inner
            .rename_secret(rpc::RenameSecretRequest {
                org_id: org_id.to_string(),
                key: old_key.to_string(),
                new_key: new_key.to_string(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        Ok(())
    }

    pub async fn list_user_secrets(&self) -> anyhow::Result<Vec<SecretMetadata>> {
        let mut secrets = Vec::new();
        let mut page_token = String::new();
        loop {
            let response = self
                .inner
                .list_user_secrets(rpc::ListUserSecretsRequest {
                    page_size: SECRET_LIST_PAGE_SIZE,
                    page_token,
                    ..Default::default()
                })
                .await
                .map_err(display_client_error)?;
            secrets.extend(response.secrets.into_iter().map(legacy_secret_metadata));
            if response.next_page_token.is_empty() {
                return Ok(secrets);
            }
            page_token = response.next_page_token;
        }
    }

    pub async fn set_user_secret(&self, key: &str, value: &str) -> anyhow::Result<()> {
        self.inner
            .set_user_secret(rpc::SetUserSecretRequest {
                key: key.to_string(),
                value: value.to_string(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        Ok(())
    }

    pub async fn delete_user_secret(&self, key: &str) -> anyhow::Result<()> {
        self.inner
            .delete_user_secret(rpc::DeleteUserSecretRequest {
                key: key.to_string(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        Ok(())
    }

    pub async fn rename_user_secret(&self, old_key: &str, new_key: &str) -> anyhow::Result<()> {
        self.inner
            .rename_user_secret(rpc::RenameUserSecretRequest {
                key: old_key.to_string(),
                new_key: new_key.to_string(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        Ok(())
    }

    pub async fn list_secret_projects(&self, org_id: &str) -> anyhow::Result<Vec<SecretProject>> {
        let mut projects = Vec::new();
        let mut page_token = String::new();
        let mut cursors = BTreeSet::new();
        for _ in 0..SECRET_LIST_MAX_PAGES {
            let response = self
                .inner
                .list_secret_projects(rpc::ListSecretProjectsRequest {
                    org_id: org_id.to_string(),
                    page_size: SECRET_LIST_PAGE_SIZE,
                    page_token: page_token.clone(),
                    ..Default::default()
                })
                .await
                .map_err(display_client_error)?;
            anyhow::ensure!(
                response.secret_projects.len() <= SECRET_LIST_PAGE_SIZE as usize,
                "platform secret-project metadata exceeded its requested page bound"
            );
            projects.extend(
                response
                    .secret_projects
                    .into_iter()
                    .map(legacy_secret_project),
            );
            if response.next_page_token.is_empty() {
                return Ok(projects);
            }
            anyhow::ensure!(
                cursors.insert(response.next_page_token.clone()),
                "platform secret-project metadata repeated a page cursor"
            );
            page_token = response.next_page_token;
        }
        anyhow::bail!(
            "platform secret-project metadata exceeded the complete-list page bound; no selection was made"
        )
    }

    pub async fn create_secret_project(
        &self,
        org_id: &str,
        request: &CreateSecretProjectRequest,
    ) -> anyhow::Result<SecretProject> {
        let response = self
            .inner
            .create_secret_project(rpc::CreateSecretProjectRequest {
                org_id: org_id.to_string(),
                name: request.name.clone(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        response
            .secret_project
            .into_option()
            .map(legacy_secret_project)
            .ok_or_else(|| anyhow::anyhow!("CreateSecretProject returned no secret project"))
    }

    pub async fn delete_secret_project(
        &self,
        org_id: &str,
        project_id: &str,
    ) -> anyhow::Result<()> {
        self.inner
            .delete_secret_project(rpc::DeleteSecretProjectRequest {
                org_id: org_id.to_string(),
                secret_project_id: project_id.to_string(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        Ok(())
    }

    pub async fn list_project_secrets(
        &self,
        org_id: &str,
        project_id: &str,
    ) -> anyhow::Result<Vec<SecretMetadata>> {
        let mut secrets = Vec::new();
        let mut page_token = String::new();
        loop {
            let response = self
                .inner
                .list_project_secrets(rpc::ListProjectSecretsRequest {
                    org_id: org_id.to_string(),
                    secret_project_id: project_id.to_string(),
                    page_size: SECRET_LIST_PAGE_SIZE,
                    page_token,
                    ..Default::default()
                })
                .await
                .map_err(display_client_error)?;
            secrets.extend(response.secrets.into_iter().map(legacy_secret_metadata));
            if response.next_page_token.is_empty() {
                return Ok(secrets);
            }
            page_token = response.next_page_token;
        }
    }

    pub async fn set_project_secret(
        &self,
        org_id: &str,
        project_id: &str,
        key: &str,
        value: &str,
    ) -> anyhow::Result<()> {
        self.inner
            .set_project_secret(rpc::SetProjectSecretRequest {
                org_id: org_id.to_string(),
                secret_project_id: project_id.to_string(),
                key: key.to_string(),
                value: value.to_string(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        Ok(())
    }

    pub async fn delete_project_secret(
        &self,
        org_id: &str,
        project_id: &str,
        key: &str,
    ) -> anyhow::Result<()> {
        self.inner
            .delete_project_secret(rpc::DeleteProjectSecretRequest {
                org_id: org_id.to_string(),
                secret_project_id: project_id.to_string(),
                key: key.to_string(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        Ok(())
    }

    pub async fn rename_project_secret(
        &self,
        org_id: &str,
        project_id: &str,
        old_key: &str,
        new_key: &str,
    ) -> anyhow::Result<()> {
        self.inner
            .rename_project_secret(rpc::RenameProjectSecretRequest {
                org_id: org_id.to_string(),
                secret_project_id: project_id.to_string(),
                key: old_key.to_string(),
                new_key: new_key.to_string(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        Ok(())
    }

    pub async fn preview_workload_secret_resolution(
        &self,
        org_id: &str,
        organization: bool,
        secret_project_id: Option<&str>,
        user: bool,
        explicit_environment_keys: impl IntoIterator<Item = String>,
    ) -> anyhow::Result<Vec<ResolvedWorkloadSecretMetadata>> {
        let response = self
            .inner
            .preview_workload_secret_resolution(rpc::PreviewWorkloadSecretResolutionRequest {
                org_id: org_id.to_string(),
                organization,
                secret_project_id: secret_project_id.unwrap_or_default().to_string(),
                user,
                explicit_environment_keys: explicit_environment_keys.into_iter().collect(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        validate_preview_response(response)
    }
}

fn validate_preview_response(
    response: rpc::PreviewWorkloadSecretResolutionResponse,
) -> anyhow::Result<Vec<ResolvedWorkloadSecretMetadata>> {
    if response.secrets.len() > MAX_WORKLOAD_SECRETS {
        anyhow::bail!("platform returned invalid workload-secret preview metadata");
    }
    let mut previous_key: Option<&str> = None;
    let mut secrets = Vec::with_capacity(response.secrets.len());
    for secret in &response.secrets {
        validate_workload_secret_key(&secret.key).map_err(|_| {
            anyhow::anyhow!("platform returned invalid workload-secret preview metadata")
        })?;
        if previous_key.is_some_and(|previous| previous >= secret.key.as_str()) {
            anyhow::bail!("platform returned invalid workload-secret preview metadata");
        }
        previous_key = Some(&secret.key);
        let source = workload_secret_source(secret.source.as_known())?;
        let overridden_sources = secret
            .overridden_sources
            .iter()
            .map(|source| workload_secret_source(source.as_known()))
            .collect::<anyhow::Result<Vec<_>>>()?;
        if overridden_sources
            .windows(2)
            .any(|sources| sources[0] >= sources[1])
            || overridden_sources
                .iter()
                .any(|overridden| *overridden >= source)
        {
            anyhow::bail!("platform returned invalid workload-secret preview metadata");
        }
        secrets.push(ResolvedWorkloadSecretMetadata {
            key: secret.key.clone(),
            source,
            overridden_sources,
        });
    }
    Ok(secrets)
}

fn workload_secret_source(
    source: Option<rpc::WorkloadSecretSource>,
) -> anyhow::Result<WorkloadSecretSource> {
    match source {
        Some(rpc::WorkloadSecretSource::Organization) => Ok(WorkloadSecretSource::Organization),
        Some(rpc::WorkloadSecretSource::Project) => Ok(WorkloadSecretSource::Project),
        Some(rpc::WorkloadSecretSource::User) => Ok(WorkloadSecretSource::User),
        Some(rpc::WorkloadSecretSource::ExplicitEnvironment) => {
            Ok(WorkloadSecretSource::ExplicitEnvironment)
        }
        Some(rpc::WorkloadSecretSource::Unspecified) | None => {
            anyhow::bail!("platform returned invalid workload-secret preview metadata")
        }
    }
}

fn legacy_secret_metadata(value: rpc::SecretMetadata) -> SecretMetadata {
    SecretMetadata {
        key: value.key,
        created_at: value
            .created_at
            .into_option()
            .map(timestamp_to_rfc3339)
            .unwrap_or_default(),
        updated_at: value
            .updated_at
            .into_option()
            .map(timestamp_to_rfc3339)
            .unwrap_or_default(),
    }
}

fn legacy_secret_project(value: rpc::SecretProject) -> SecretProject {
    SecretProject {
        id: value.id,
        org_id: value.org_id,
        name: value.name,
        secret_count: value.secret_count,
        created_at: value
            .created_at
            .into_option()
            .map(timestamp_to_rfc3339)
            .unwrap_or_default(),
    }
}

fn timestamp_to_rfc3339(timestamp: rpc::Timestamp) -> String {
    DateTime::<Utc>::from_timestamp(timestamp.seconds, timestamp.nanos as u32)
        .map(|timestamp| timestamp.to_rfc3339_opts(SecondsFormat::Secs, true))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use buffa::Message as _;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    #[test]
    fn legacy_secret_metadata_is_write_only_and_preserves_timestamps() {
        let metadata = legacy_secret_metadata(rpc::SecretMetadata {
            key: "DATABASE_URL".into(),
            created_at: Some(rpc::Timestamp {
                seconds: 1_767_225_600,
                ..Default::default()
            })
            .into(),
            updated_at: Some(rpc::Timestamp {
                seconds: 1_767_312_000,
                ..Default::default()
            })
            .into(),
            ..Default::default()
        });
        let json = serde_json::to_value(metadata).expect("metadata JSON");
        assert_eq!(json["key"], "DATABASE_URL");
        assert!(json.get("value").is_none());
        assert_eq!(json["created_at"], "2026-01-01T00:00:00Z");
        assert_eq!(json["updated_at"], "2026-01-02T00:00:00Z");
    }

    #[test]
    fn legacy_secret_project_preserves_cli_output_shape() {
        let project = legacy_secret_project(rpc::SecretProject {
            id: "sp_123".into(),
            org_id: "org_123".into(),
            name: "production".into(),
            secret_count: 2,
            created_at: Some(rpc::Timestamp {
                seconds: 1_767_225_600,
                ..Default::default()
            })
            .into(),
            ..Default::default()
        });
        assert_eq!(
            serde_json::to_value(project).expect("project JSON"),
            serde_json::json!({
                "id": "sp_123",
                "org_id": "org_123",
                "name": "production",
                "secret_count": 2,
                "created_at": "2026-01-01T00:00:00Z",
            })
        );
    }

    #[test]
    fn secret_presentation_omits_empty_optional_fields() {
        let metadata = SecretMetadata {
            key: "TOKEN".into(),
            ..Default::default()
        };
        let project = SecretProject {
            id: "sp_123".into(),
            org_id: "org_123".into(),
            name: "empty".into(),
            created_at: "2026-01-01T00:00:00Z".into(),
            ..Default::default()
        };

        let metadata_json = serde_json::to_value(metadata).expect("metadata JSON");
        let project_json = serde_json::to_value(project).expect("project JSON");
        assert!(metadata_json.get("created_at").is_none());
        assert!(metadata_json.get("updated_at").is_none());
        assert!(project_json.get("secret_count").is_none());
    }

    #[test]
    fn preview_response_validation_accepts_canonical_metadata_only_results() {
        let response = rpc::PreviewWorkloadSecretResolutionResponse {
            secrets: vec![rpc::ResolvedWorkloadSecretMetadata {
                key: "TOKEN".into(),
                source: rpc::WorkloadSecretSource::User.into(),
                overridden_sources: vec![
                    rpc::WorkloadSecretSource::Organization.into(),
                    rpc::WorkloadSecretSource::Project.into(),
                ],
                ..Default::default()
            }],
            ..Default::default()
        };
        assert_eq!(
            validate_preview_response(response).unwrap(),
            vec![ResolvedWorkloadSecretMetadata {
                key: "TOKEN".into(),
                source: WorkloadSecretSource::User,
                overridden_sources: vec![
                    WorkloadSecretSource::Organization,
                    WorkloadSecretSource::Project,
                ],
            }]
        );
    }

    #[test]
    fn preview_response_validation_rejects_unknown_or_noncanonical_metadata() {
        let secret = |key: &str, source: rpc::EnumValue<rpc::WorkloadSecretSource>| {
            rpc::ResolvedWorkloadSecretMetadata {
                key: key.into(),
                source,
                ..Default::default()
            }
        };
        for response in [
            rpc::PreviewWorkloadSecretResolutionResponse {
                secrets: vec![secret("TOKEN", rpc::EnumValue::Unknown(99))],
                ..Default::default()
            },
            rpc::PreviewWorkloadSecretResolutionResponse {
                secrets: vec![
                    secret("TOKEN", rpc::WorkloadSecretSource::User.into()),
                    secret(
                        "TOKEN",
                        rpc::WorkloadSecretSource::ExplicitEnvironment.into(),
                    ),
                ],
                ..Default::default()
            },
            rpc::PreviewWorkloadSecretResolutionResponse {
                secrets: vec![rpc::ResolvedWorkloadSecretMetadata {
                    key: "TOKEN".into(),
                    source: rpc::WorkloadSecretSource::Project.into(),
                    overridden_sources: vec![rpc::WorkloadSecretSource::User.into()],
                    ..Default::default()
                }],
                ..Default::default()
            },
            rpc::PreviewWorkloadSecretResolutionResponse {
                secrets: vec![secret(
                    "1DIGIT_FIRST",
                    rpc::WorkloadSecretSource::User.into(),
                )],
                ..Default::default()
            },
        ] {
            assert!(validate_preview_response(response).is_err());
        }
    }

    #[tokio::test]
    async fn secret_lists_follow_every_page_token() {
        let server = MockServer::start().await;
        let org_calls = Arc::new(AtomicUsize::new(0));
        let user_calls = Arc::new(AtomicUsize::new(0));
        let project_calls = Arc::new(AtomicUsize::new(0));

        let org_responder_calls = Arc::clone(&org_calls);
        Mock::given(method("POST"))
            .and(path("/codewire.v1.SecretService/ListSecrets"))
            .respond_with(move |request: &wiremock::Request| {
                let mut body = request.body.as_slice();
                let request = rpc::ListSecretsRequest::decode(&mut body)
                    .expect("decode organization secret request");
                let call = org_responder_calls.fetch_add(1, Ordering::SeqCst);
                assert_eq!(request.org_id, "org_123");
                assert_eq!(request.page_size, SECRET_LIST_PAGE_SIZE);
                assert_eq!(request.page_token, if call == 0 { "" } else { "org-next" });
                let response = rpc::ListSecretsResponse {
                    secrets: vec![rpc::SecretMetadata {
                        key: format!("ORG_{call}"),
                        ..Default::default()
                    }],
                    next_page_token: if call == 0 { "org-next" } else { "" }.into(),
                    ..Default::default()
                };
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/proto")
                    .set_body_bytes(response.encode_to_vec())
            })
            .expect(2)
            .mount(&server)
            .await;

        let user_responder_calls = Arc::clone(&user_calls);
        Mock::given(method("POST"))
            .and(path("/codewire.v1.SecretService/ListUserSecrets"))
            .respond_with(move |request: &wiremock::Request| {
                let mut body = request.body.as_slice();
                let request = rpc::ListUserSecretsRequest::decode(&mut body)
                    .expect("decode user secret request");
                let call = user_responder_calls.fetch_add(1, Ordering::SeqCst);
                assert_eq!(request.page_size, SECRET_LIST_PAGE_SIZE);
                assert_eq!(request.page_token, if call == 0 { "" } else { "user-next" });
                let response = rpc::ListUserSecretsResponse {
                    secrets: vec![rpc::SecretMetadata {
                        key: format!("USER_{call}"),
                        ..Default::default()
                    }],
                    next_page_token: if call == 0 { "user-next" } else { "" }.into(),
                    ..Default::default()
                };
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/proto")
                    .set_body_bytes(response.encode_to_vec())
            })
            .expect(2)
            .mount(&server)
            .await;

        let project_responder_calls = Arc::clone(&project_calls);
        Mock::given(method("POST"))
            .and(path("/codewire.v1.SecretService/ListProjectSecrets"))
            .respond_with(move |request: &wiremock::Request| {
                let mut body = request.body.as_slice();
                let request = rpc::ListProjectSecretsRequest::decode(&mut body)
                    .expect("decode project secret request");
                let call = project_responder_calls.fetch_add(1, Ordering::SeqCst);
                assert_eq!(request.org_id, "org_123");
                assert_eq!(request.secret_project_id, "sp_123");
                assert_eq!(request.page_size, SECRET_LIST_PAGE_SIZE);
                assert_eq!(
                    request.page_token,
                    if call == 0 { "" } else { "project-next" }
                );
                let response = rpc::ListProjectSecretsResponse {
                    secrets: vec![rpc::SecretMetadata {
                        key: format!("PROJECT_{call}"),
                        ..Default::default()
                    }],
                    next_page_token: if call == 0 { "project-next" } else { "" }.into(),
                    ..Default::default()
                };
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/proto")
                    .set_body_bytes(response.encode_to_vec())
            })
            .expect(2)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path(
                "/codewire.v1.SecretService/PreviewWorkloadSecretResolution",
            ))
            .respond_with(|request: &wiremock::Request| {
                let mut body = request.body.as_slice();
                let request = rpc::PreviewWorkloadSecretResolutionRequest::decode(&mut body)
                    .expect("decode workload-secret preview request");
                assert_eq!(request.org_id, "org_123");
                assert!(request.organization);
                assert_eq!(request.secret_project_id, "sp_123");
                assert!(request.user);
                assert_eq!(request.explicit_environment_keys, ["EXPLICIT"]);
                let response = rpc::PreviewWorkloadSecretResolutionResponse {
                    secrets: vec![rpc::ResolvedWorkloadSecretMetadata {
                        key: "EXPLICIT".into(),
                        source: rpc::WorkloadSecretSource::ExplicitEnvironment.into(),
                        overridden_sources: vec![rpc::WorkloadSecretSource::User.into()],
                        ..Default::default()
                    }],
                    ..Default::default()
                };
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/proto")
                    .set_body_bytes(response.encode_to_vec())
            })
            .expect(1)
            .mount(&server)
            .await;

        let client = SecretClient::new(&ResolvedPlatformConfig::static_token(
            server.uri(),
            "test-token",
            false,
            None,
        ))
        .expect("secret client");

        assert_eq!(
            client
                .list_org_secrets("org_123")
                .await
                .expect("organization secrets")
                .iter()
                .map(|secret| secret.key.as_str())
                .collect::<Vec<_>>(),
            ["ORG_0", "ORG_1"]
        );
        assert_eq!(
            client
                .list_user_secrets()
                .await
                .expect("user secrets")
                .iter()
                .map(|secret| secret.key.as_str())
                .collect::<Vec<_>>(),
            ["USER_0", "USER_1"]
        );
        assert_eq!(
            client
                .list_project_secrets("org_123", "sp_123")
                .await
                .expect("project secrets")
                .iter()
                .map(|secret| secret.key.as_str())
                .collect::<Vec<_>>(),
            ["PROJECT_0", "PROJECT_1"]
        );
        assert_eq!(
            client
                .preview_workload_secret_resolution(
                    "org_123",
                    true,
                    Some("sp_123"),
                    true,
                    ["EXPLICIT".to_string()],
                )
                .await
                .expect("preview workload-secret resolution"),
            vec![ResolvedWorkloadSecretMetadata {
                key: "EXPLICIT".into(),
                source: WorkloadSecretSource::ExplicitEnvironment,
                overridden_sources: vec![WorkloadSecretSource::User],
            }]
        );
    }

    #[tokio::test]
    async fn secret_project_listing_rejects_repeated_cursors_without_partial_success() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/codewire.v1.SecretService/ListSecretProjects"))
            .respond_with(|_: &wiremock::Request| {
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/proto")
                    .set_body_bytes(
                        rpc::ListSecretProjectsResponse {
                            secret_projects: vec![rpc::SecretProject {
                                id: "11111111-1111-4111-8111-111111111111".into(),
                                org_id: "org_123".into(),
                                name: "development".into(),
                                ..Default::default()
                            }],
                            next_page_token: "repeated-cursor".into(),
                            ..Default::default()
                        }
                        .encode_to_vec(),
                    )
            })
            .expect(2)
            .mount(&server)
            .await;
        let client = SecretClient::new(&ResolvedPlatformConfig::static_token(
            server.uri(),
            "test-token",
            false,
            None,
        ))
        .unwrap();

        assert!(client.list_secret_projects("org_123").await.is_err());
    }

    #[tokio::test]
    async fn secret_project_listing_rejects_unique_nonterminal_pages_at_the_bound() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let server = MockServer::start().await;
        let page = Arc::new(AtomicUsize::new(0));
        Mock::given(method("POST"))
            .and(path("/codewire.v1.SecretService/ListSecretProjects"))
            .respond_with(move |_: &wiremock::Request| {
                let page = page.fetch_add(1, Ordering::SeqCst);
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/proto")
                    .set_body_bytes(
                        rpc::ListSecretProjectsResponse {
                            secret_projects: vec![rpc::SecretProject::default()],
                            next_page_token: format!("cursor-{page}"),
                            ..Default::default()
                        }
                        .encode_to_vec(),
                    )
            })
            .expect(SECRET_LIST_MAX_PAGES as u64)
            .mount(&server)
            .await;
        let client = SecretClient::new(&ResolvedPlatformConfig::static_token(
            server.uri(),
            "test-token",
            false,
            None,
        ))
        .unwrap();

        assert!(client.list_secret_projects("org_123").await.is_err());
        assert_eq!(
            server.received_requests().await.unwrap().len(),
            SECRET_LIST_MAX_PAGES
        );
    }

    #[tokio::test]
    async fn secret_project_listing_accepts_an_exact_terminal_page_and_rejects_oversize() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let server = MockServer::start().await;
        let page = Arc::new(AtomicUsize::new(0));
        Mock::given(method("POST"))
            .and(path("/codewire.v1.SecretService/ListSecretProjects"))
            .respond_with(move |_: &wiremock::Request| {
                let page = page.fetch_add(1, Ordering::SeqCst);
                let next_page_token = if page + 1 == SECRET_LIST_MAX_PAGES {
                    String::new()
                } else {
                    format!("cursor-{page}")
                };
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/proto")
                    .set_body_bytes(
                        rpc::ListSecretProjectsResponse {
                            secret_projects: vec![rpc::SecretProject::default()],
                            next_page_token,
                            ..Default::default()
                        }
                        .encode_to_vec(),
                    )
            })
            .expect(SECRET_LIST_MAX_PAGES as u64)
            .mount(&server)
            .await;
        let client = SecretClient::new(&ResolvedPlatformConfig::static_token(
            server.uri(),
            "test-token",
            false,
            None,
        ))
        .unwrap();
        assert_eq!(
            client.list_secret_projects("org_123").await.unwrap().len(),
            SECRET_LIST_MAX_PAGES
        );

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/codewire.v1.SecretService/ListSecretProjects"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/proto")
                    .set_body_bytes(
                        rpc::ListSecretProjectsResponse {
                            secret_projects: vec![
                                rpc::SecretProject::default();
                                SECRET_LIST_PAGE_SIZE as usize + 1
                            ],
                            ..Default::default()
                        }
                        .encode_to_vec(),
                    ),
            )
            .expect(1)
            .mount(&server)
            .await;
        let client = SecretClient::new(&ResolvedPlatformConfig::static_token(
            server.uri(),
            "test-token",
            false,
            None,
        ))
        .unwrap();
        assert!(client.list_secret_projects("org_123").await.is_err());
    }
}
