use std::time::Duration;

use axum::http::HeaderValue;
use codewire_proto::codewire::{
    console::v1::{
        AccountServiceClient, CreateGitCredentialRequest, DeleteGitCredentialRequest,
        DeleteGitHubTokenRequest, EnsureSshKeyRequest, GetGitHubStatusRequest,
        GetGitIdentityRequest, GetSshKeyRequest, GitHubServiceClient, ListGitCredentialsRequest,
        RegenerateSshKeyRequest, UpdateGitIdentityRequest,
    },
    v1::{
        AcceptInvitationRequest, CreateOrganizationRequest, GetInvitationByTokenRequest,
        ListOrganizationsRequest, OrganizationServiceClient,
    },
};
use connectrpc::{ConnectError, ErrorCode, client::ClientConfig};

use crate::{
    dependency::{DependencyResult, PageDependency, resolve_connect},
    error::WebError,
    state::AppState,
    transport::BrowserTransport,
    view::{GitCredentialRow, InvitationView, OrganizationFormView, OrganizationRow, SettingsData},
};

fn transport(state: &AppState, cookie: Option<HeaderValue>) -> BrowserTransport {
    BrowserTransport {
        http: state.http.clone(),
        cookie,
    }
}

fn client_config(state: &AppState) -> ClientConfig {
    ClientConfig::new(state.api_origin.clone()).with_default_timeout(Duration::from_secs(10))
}

pub(crate) async fn organizations(
    state: &AppState,
    cookie: HeaderValue,
) -> Result<Vec<OrganizationRow>, WebError> {
    let client =
        OrganizationServiceClient::new(transport(state, Some(cookie)), client_config(state));
    let response = client
        .list_organizations(ListOrganizationsRequest::default())
        .await
        .map_err(WebError::Connect)?
        .into_owned();

    Ok(response
        .organizations
        .into_iter()
        .filter_map(|membership| {
            let organization = membership.organization.into_option()?;
            let role = role_name(membership.role.to_i32());
            Some(OrganizationRow {
                id: organization.id,
                name: organization.name,
                slug: organization.slug.clone(),
                role,
                can_admin: matches!(role, "Owner" | "Admin")
                    || membership
                        .assignments
                        .iter()
                        .any(|assignment| assignment == "super_admin"),
                billing_plan: membership.billing_plan,
                url: format!("/{}/", organization.slug),
            })
        })
        .collect())
}

pub(crate) async fn github_status(state: &AppState, cookie: HeaderValue) -> Result<bool, WebError> {
    let client = GitHubServiceClient::new(transport(state, Some(cookie)), client_config(state));
    Ok(client
        .get_git_hub_status(GetGitHubStatusRequest::default())
        .await
        .map_err(WebError::Connect)?
        .into_owned()
        .connected)
}

pub(crate) async fn create_organization(
    state: &AppState,
    cookie: HeaderValue,
    form: &OrganizationFormView,
) -> Result<(), ConnectError> {
    let client =
        OrganizationServiceClient::new(transport(state, Some(cookie)), client_config(state));
    client
        .create_organization(CreateOrganizationRequest {
            name: form.name.clone(),
            slug: form.slug.clone(),
            ..Default::default()
        })
        .await?;
    Ok(())
}

pub(crate) async fn invitation(
    state: &AppState,
    token: String,
) -> Result<InvitationView, WebError> {
    let client = OrganizationServiceClient::new(transport(state, None), client_config(state));
    let response = client
        .get_invitation_by_token(GetInvitationByTokenRequest {
            token,
            ..Default::default()
        })
        .await
        .map_err(WebError::Connect)?
        .into_owned();
    let invitation = response
        .invitation
        .into_option()
        .ok_or_else(|| WebError::Connect(ConnectError::not_found("invitation not found")))?;
    Ok(InvitationView {
        organization_name: invitation.org_name,
        email: invitation.email,
        inviter_name: invitation
            .inviter_name
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| "A team administrator".to_owned()),
        role: role_name(invitation.role.to_i32()),
    })
}

pub(crate) async fn accept_invitation(
    state: &AppState,
    cookie: HeaderValue,
    token: String,
) -> Result<(), ConnectError> {
    let client =
        OrganizationServiceClient::new(transport(state, Some(cookie)), client_config(state));
    client
        .accept_invitation(AcceptInvitationRequest {
            token,
            ..Default::default()
        })
        .await?;
    Ok(())
}

pub(crate) async fn settings_data(
    state: &AppState,
    cookie: HeaderValue,
) -> Result<SettingsData, WebError> {
    let account =
        AccountServiceClient::new(transport(state, Some(cookie.clone())), client_config(state));
    let github = GitHubServiceClient::new(transport(state, Some(cookie)), client_config(state));
    let (github, credentials, identity, ssh_key) = tokio::join!(
        github.get_git_hub_status(GetGitHubStatusRequest::default()),
        account.list_git_credentials(ListGitCredentialsRequest::default()),
        account.get_git_identity(GetGitIdentityRequest::default()),
        account.get_ssh_key(GetSshKeyRequest::default()),
    );
    let github = resolve_connect(
        PageDependency::SettingsGithubStatus,
        github.map(|response| response.into_owned()),
    )
    .map_err(WebError::Connect)?;
    let (github, github_available) = match github {
        DependencyResult::Available(github) => (github, true),
        DependencyResult::Unavailable => (Default::default(), false),
    };
    let credentials = resolve_connect(
        PageDependency::SettingsCredentials,
        credentials.map(|response| response.into_owned()),
    )
    .map_err(WebError::Connect)?;
    let (credentials, credentials_available) = match credentials {
        DependencyResult::Available(credentials) => (credentials, true),
        DependencyResult::Unavailable => (Default::default(), false),
    };
    let identity = resolve_connect(
        PageDependency::SettingsGitIdentity,
        identity.map(|response| response.into_owned()),
    )
    .map_err(WebError::Connect)?;
    let (identity, git_identity_available) = match identity {
        DependencyResult::Available(identity) => (identity, true),
        DependencyResult::Unavailable => (Default::default(), false),
    };
    let ssh_key = match ssh_key {
        Ok(response) => Ok(response.into_owned().ssh_key.into_option()),
        Err(error) if error.code == ErrorCode::NotFound => Ok(None),
        Err(error) => Err(error),
    };
    let ssh_key =
        resolve_connect(PageDependency::SettingsSshKey, ssh_key).map_err(WebError::Connect)?;
    let (ssh_key, ssh_key_status_available) = match ssh_key {
        DependencyResult::Available(ssh_key) => (ssh_key, true),
        DependencyResult::Unavailable => (None, false),
    };
    let identity = identity.git_identity.into_option().unwrap_or_default();
    Ok(SettingsData {
        github_available,
        github_connected: github.connected,
        github_username: github.username,
        credentials_available,
        credentials: credentials
            .git_credentials
            .into_iter()
            .map(|credential| GitCredentialRow {
                id: credential.id,
                name: credential.name,
                host: credential.host,
                username: credential.username.unwrap_or_default(),
            })
            .collect(),
        git_identity_available,
        git_name: identity.git_name,
        git_email: identity.git_email,
        ssh_key_status_available,
        ssh_key_available: ssh_key.is_some(),
        ssh_public_key: ssh_key
            .as_ref()
            .map(|key| key.public_key.clone())
            .unwrap_or_default(),
        ssh_fingerprint: ssh_key.map(|key| key.fingerprint).unwrap_or_default(),
    })
}

pub(crate) async fn disconnect_github(
    state: &AppState,
    cookie: HeaderValue,
) -> Result<(), ConnectError> {
    GitHubServiceClient::new(transport(state, Some(cookie)), client_config(state))
        .delete_git_hub_token(DeleteGitHubTokenRequest::default())
        .await?;
    Ok(())
}

pub(crate) async fn create_git_credential(
    state: &AppState,
    cookie: HeaderValue,
    name: String,
    host: String,
    username: String,
    password: String,
) -> Result<(), ConnectError> {
    AccountServiceClient::new(transport(state, Some(cookie)), client_config(state))
        .create_git_credential(CreateGitCredentialRequest {
            name,
            host,
            auth_type: "basic".to_owned(),
            username,
            password,
            ..Default::default()
        })
        .await?;
    Ok(())
}

pub(crate) async fn delete_git_credential(
    state: &AppState,
    cookie: HeaderValue,
    credential_id: String,
) -> Result<(), ConnectError> {
    AccountServiceClient::new(transport(state, Some(cookie)), client_config(state))
        .delete_git_credential(DeleteGitCredentialRequest {
            credential_id,
            ..Default::default()
        })
        .await?;
    Ok(())
}

pub(crate) async fn update_git_identity(
    state: &AppState,
    cookie: HeaderValue,
    git_name: String,
    git_email: String,
) -> Result<(), ConnectError> {
    AccountServiceClient::new(transport(state, Some(cookie)), client_config(state))
        .update_git_identity(UpdateGitIdentityRequest {
            git_name: Some(git_name),
            git_email: Some(git_email),
            ..Default::default()
        })
        .await?;
    Ok(())
}

pub(crate) async fn ensure_ssh_key(
    state: &AppState,
    cookie: HeaderValue,
) -> Result<(), ConnectError> {
    AccountServiceClient::new(transport(state, Some(cookie)), client_config(state))
        .ensure_ssh_key(EnsureSshKeyRequest::default())
        .await?;
    Ok(())
}

pub(crate) async fn regenerate_ssh_key(
    state: &AppState,
    cookie: HeaderValue,
) -> Result<(), ConnectError> {
    AccountServiceClient::new(transport(state, Some(cookie)), client_config(state))
        .regenerate_ssh_key(RegenerateSshKeyRequest::default())
        .await?;
    Ok(())
}

fn role_name(value: i32) -> &'static str {
    match value {
        1 => "Owner",
        2 => "Admin",
        3 => "Member",
        _ => "Member",
    }
}
