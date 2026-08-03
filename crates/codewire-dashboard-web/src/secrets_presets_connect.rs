use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::http::HeaderValue;
use codewire_proto::codewire::v1::{
    CreateSecretProjectRequest, DeletePresetRequest, DeleteProjectSecretRequest,
    DeleteSecretProjectRequest, DeleteSecretRequest, DeleteUserSecretRequest, ListPresetsRequest,
    ListProjectSecretsRequest, ListSecretProjectsRequest, ListSecretsRequest,
    ListUserSecretsRequest, Preset, PresetServiceClient, RenameProjectSecretRequest,
    RenameSecretRequest, RenameUserSecretRequest, SecretMetadata, SecretServiceClient,
    SetProjectSecretRequest, SetSecretRequest, SetUserSecretRequest, UpdatePresetRequest,
};
use connectrpc::{ConnectError, client::ClientConfig};

use crate::{
    state::AppState,
    transport::BrowserTransport,
    view::{PresetFormView, PresetRow, SecretProjectRow, SecretRow},
};

#[derive(Clone, Copy)]
pub(crate) enum SecretBucket<'a> {
    Organization,
    User,
    Project(&'a str),
}

fn transport(state: &AppState, cookie: HeaderValue) -> BrowserTransport {
    BrowserTransport {
        http: state.http.clone(),
        cookie: Some(cookie),
    }
}

fn client_config(state: &AppState) -> ClientConfig {
    ClientConfig::new(state.api_origin.clone()).with_default_timeout(Duration::from_secs(10))
}

fn secret_client(state: &AppState, cookie: HeaderValue) -> SecretServiceClient<BrowserTransport> {
    SecretServiceClient::new(transport(state, cookie), client_config(state))
}

fn preset_client(state: &AppState, cookie: HeaderValue) -> PresetServiceClient<BrowserTransport> {
    PresetServiceClient::new(transport(state, cookie), client_config(state))
}

pub(crate) async fn secret_projects(
    state: &AppState,
    cookie: HeaderValue,
    org_id: &str,
) -> Result<Vec<SecretProjectRow>, ConnectError> {
    let response = secret_client(state, cookie)
        .list_secret_projects(ListSecretProjectsRequest {
            org_id: org_id.to_owned(),
            ..Default::default()
        })
        .await?
        .into_owned();
    Ok(response
        .secret_projects
        .into_iter()
        .map(|project| SecretProjectRow {
            id: project.id,
            name: project.name,
            secret_count: project.secret_count,
            created: project
                .created_at
                .into_option()
                .map(|timestamp| past_time(timestamp.seconds))
                .unwrap_or_else(|| "—".to_owned()),
        })
        .collect())
}

pub(crate) async fn secrets(
    state: &AppState,
    cookie: HeaderValue,
    org_id: &str,
    bucket: SecretBucket<'_>,
) -> Result<Vec<SecretRow>, ConnectError> {
    let client = secret_client(state, cookie);
    let secrets = match bucket {
        SecretBucket::Organization => {
            client
                .list_secrets(ListSecretsRequest {
                    org_id: org_id.to_owned(),
                    ..Default::default()
                })
                .await?
                .into_owned()
                .secrets
        }
        SecretBucket::User => {
            client
                .list_user_secrets(ListUserSecretsRequest::default())
                .await?
                .into_owned()
                .secrets
        }
        SecretBucket::Project(project_id) => {
            client
                .list_project_secrets(ListProjectSecretsRequest {
                    org_id: org_id.to_owned(),
                    secret_project_id: project_id.to_owned(),
                    ..Default::default()
                })
                .await?
                .into_owned()
                .secrets
        }
    };
    Ok(secrets.into_iter().map(secret_row).collect())
}

fn secret_row(secret: SecretMetadata) -> SecretRow {
    let updated = secret
        .updated_at
        .into_option()
        .or_else(|| secret.created_at.into_option())
        .map(|timestamp| past_time(timestamp.seconds))
        .unwrap_or_else(|| "—".to_owned());
    SecretRow {
        key: secret.key,
        updated,
    }
}

pub(crate) async fn create_secret_project(
    state: &AppState,
    cookie: HeaderValue,
    org_id: String,
    name: String,
) -> Result<(), ConnectError> {
    secret_client(state, cookie)
        .create_secret_project(CreateSecretProjectRequest {
            org_id,
            name,
            ..Default::default()
        })
        .await?;
    Ok(())
}

pub(crate) async fn delete_secret_project(
    state: &AppState,
    cookie: HeaderValue,
    org_id: String,
    project_id: String,
) -> Result<(), ConnectError> {
    secret_client(state, cookie)
        .delete_secret_project(DeleteSecretProjectRequest {
            org_id,
            secret_project_id: project_id,
            ..Default::default()
        })
        .await?;
    Ok(())
}

pub(crate) async fn set_secret(
    state: &AppState,
    cookie: HeaderValue,
    org_id: String,
    bucket: SecretBucket<'_>,
    key: String,
    value: String,
) -> Result<(), ConnectError> {
    let client = secret_client(state, cookie);
    match bucket {
        SecretBucket::Organization => {
            client
                .set_secret(SetSecretRequest {
                    org_id,
                    key,
                    value,
                    ..Default::default()
                })
                .await?;
        }
        SecretBucket::User => {
            client
                .set_user_secret(SetUserSecretRequest {
                    key,
                    value,
                    ..Default::default()
                })
                .await?;
        }
        SecretBucket::Project(project_id) => {
            client
                .set_project_secret(SetProjectSecretRequest {
                    org_id,
                    secret_project_id: project_id.to_owned(),
                    key,
                    value,
                    ..Default::default()
                })
                .await?;
        }
    }
    Ok(())
}

pub(crate) async fn delete_secret(
    state: &AppState,
    cookie: HeaderValue,
    org_id: String,
    bucket: SecretBucket<'_>,
    key: String,
) -> Result<(), ConnectError> {
    let client = secret_client(state, cookie);
    match bucket {
        SecretBucket::Organization => {
            client
                .delete_secret(DeleteSecretRequest {
                    org_id,
                    key,
                    ..Default::default()
                })
                .await?;
        }
        SecretBucket::User => {
            client
                .delete_user_secret(DeleteUserSecretRequest {
                    key,
                    ..Default::default()
                })
                .await?;
        }
        SecretBucket::Project(project_id) => {
            client
                .delete_project_secret(DeleteProjectSecretRequest {
                    org_id,
                    secret_project_id: project_id.to_owned(),
                    key,
                    ..Default::default()
                })
                .await?;
        }
    }
    Ok(())
}

pub(crate) async fn rename_secret(
    state: &AppState,
    cookie: HeaderValue,
    org_id: String,
    bucket: SecretBucket<'_>,
    key: String,
    new_key: String,
) -> Result<(), ConnectError> {
    let client = secret_client(state, cookie);
    match bucket {
        SecretBucket::Organization => {
            client
                .rename_secret(RenameSecretRequest {
                    org_id,
                    key,
                    new_key,
                    ..Default::default()
                })
                .await?;
        }
        SecretBucket::User => {
            client
                .rename_user_secret(RenameUserSecretRequest {
                    key,
                    new_key,
                    ..Default::default()
                })
                .await?;
        }
        SecretBucket::Project(project_id) => {
            client
                .rename_project_secret(RenameProjectSecretRequest {
                    org_id,
                    secret_project_id: project_id.to_owned(),
                    key,
                    new_key,
                    ..Default::default()
                })
                .await?;
        }
    }
    Ok(())
}

pub(crate) async fn presets(
    state: &AppState,
    cookie: HeaderValue,
    org_id: &str,
) -> Result<Vec<PresetRow>, ConnectError> {
    let response = preset_client(state, cookie)
        .list_presets(ListPresetsRequest {
            org_id: org_id.to_owned(),
            ..Default::default()
        })
        .await?
        .into_owned();
    Ok(response.presets.into_iter().map(preset_row).collect())
}

fn preset_row(preset: Preset) -> PresetRow {
    let setup = preset
        .default_setup_config
        .into_option()
        .unwrap_or_default();
    let slug = preset.slug.unwrap_or_default();
    let description = preset.description.unwrap_or_default();
    let image = preset.image.unwrap_or_default();
    let ttl_value = preset
        .default_ttl_seconds
        .map(|seconds| seconds.to_string())
        .unwrap_or_default();
    let form = PresetFormView {
        name: preset.name.clone(),
        slug: slug.clone(),
        description: description.clone(),
        image: image.clone(),
        cpu: preset.default_cpu_millicores.to_string(),
        memory: preset.default_memory_mb.to_string(),
        disk: preset.default_disk_gb.to_string(),
        ttl: ttl_value.clone(),
        install_command: setup.install_command,
        startup_script: setup.startup_script,
        ..Default::default()
    };
    PresetRow {
        id: preset.id,
        name: preset.name,
        slug,
        description,
        image,
        cpu: cpu_label(preset.default_cpu_millicores),
        memory: memory_label(preset.default_memory_mb),
        disk: format!("{} GB", preset.default_disk_gb),
        ttl: preset
            .default_ttl_seconds
            .map(ttl_label)
            .unwrap_or_else(|| "No TTL".to_owned()),
        official: preset.official,
        organization_owned: preset.org_id.is_some(),
        form,
    }
}

pub(crate) async fn update_preset(
    state: &AppState,
    cookie: HeaderValue,
    request: UpdatePresetRequest,
) -> Result<(), ConnectError> {
    preset_client(state, cookie).update_preset(request).await?;
    Ok(())
}

pub(crate) async fn delete_preset(
    state: &AppState,
    cookie: HeaderValue,
    org_id: String,
    preset_id: String,
) -> Result<(), ConnectError> {
    preset_client(state, cookie)
        .delete_preset(DeletePresetRequest {
            org_id,
            preset_id,
            ..Default::default()
        })
        .await?;
    Ok(())
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_secs()).ok())
        .unwrap_or_default()
}

fn past_time(seconds: i64) -> String {
    let elapsed = unix_now().saturating_sub(seconds);
    if elapsed < 60 {
        "just now".to_owned()
    } else if elapsed < 3_600 {
        format!("{}m ago", elapsed / 60)
    } else if elapsed < 86_400 {
        format!("{}h ago", elapsed / 3_600)
    } else {
        format!("{}d ago", elapsed / 86_400)
    }
}

fn cpu_label(millicores: i32) -> String {
    if millicores % 1_000 == 0 {
        format!("{} vCPU", millicores / 1_000)
    } else {
        format!("{:.1} vCPU", f64::from(millicores) / 1_000.0)
    }
}

fn memory_label(megabytes: i32) -> String {
    if megabytes % 1_024 == 0 {
        format!("{} GiB", megabytes / 1_024)
    } else {
        format!("{} MB", megabytes)
    }
}

fn ttl_label(seconds: i32) -> String {
    if seconds % 3_600 == 0 {
        format!("{}h TTL", seconds / 3_600)
    } else if seconds % 60 == 0 {
        format!("{}m TTL", seconds / 60)
    } else {
        format!("{seconds}s TTL")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use codewire_proto::codewire::v1::SetupConfig;

    #[test]
    fn preset_mapping_preserves_editable_fields_and_escapes_only_in_templates() {
        let row = preset_row(Preset {
            id: "preset-1".into(),
            org_id: Some("org-1".into()),
            name: "Rust <script>".into(),
            default_cpu_millicores: 1500,
            default_memory_mb: 3072,
            default_disk_gb: 20,
            default_ttl_seconds: Some(3600),
            default_setup_config: Some(SetupConfig {
                install_command: "cargo build".into(),
                startup_script: "cargo run".into(),
                ..Default::default()
            })
            .into(),
            ..Default::default()
        });
        assert_eq!(row.cpu, "1.5 vCPU");
        assert_eq!(row.memory, "3 GiB");
        assert_eq!(row.ttl, "1h TTL");
        assert_eq!(row.form.install_command, "cargo build");
        assert!(row.organization_owned);
    }

    #[test]
    fn secret_metadata_mapping_has_no_value_channel() {
        let row = secret_row(SecretMetadata {
            key: "DATABASE_URL".into(),
            ..Default::default()
        });
        let diagnostic = format!("{row:?}");
        assert!(diagnostic.contains("DATABASE_URL"));
        assert!(!diagnostic.contains("value"));
    }
}
