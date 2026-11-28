//! The secret service's calls: organization, personal and project secrets,
//! their projects, and the workload-secret preview.

use codewire_proto::codewire::v1::{
    CreateSecretProjectRequest, CreateSecretProjectResponse, DeleteProjectSecretRequest,
    DeleteProjectSecretResponse, DeleteSecretProjectRequest, DeleteSecretProjectResponse,
    DeleteSecretRequest, DeleteSecretResponse, DeleteUserSecretRequest, DeleteUserSecretResponse,
    ListProjectSecretsRequest, ListProjectSecretsResponse, ListSecretProjectsRequest,
    ListSecretProjectsResponse, ListSecretsRequest, ListSecretsResponse, ListUserSecretsRequest,
    ListUserSecretsResponse, PreviewWorkloadSecretResolutionRequest,
    PreviewWorkloadSecretResolutionResponse, RenameProjectSecretRequest,
    RenameProjectSecretResponse, RenameSecretRequest, RenameSecretResponse,
    RenameUserSecretRequest, RenameUserSecretResponse, SetProjectSecretRequest,
    SetProjectSecretResponse, SetSecretRequest, SetSecretResponse, SetUserSecretRequest,
    SetUserSecretResponse,
};

use crate::{ClientError, CodewireClient};

impl CodewireClient {
    pub async fn list_secrets(
        &self,
        request: ListSecretsRequest,
    ) -> Result<ListSecretsResponse, ClientError> {
        self.secrets
            .list_secrets_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn set_secret(
        &self,
        request: SetSecretRequest,
    ) -> Result<SetSecretResponse, ClientError> {
        self.secrets
            .set_secret_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn delete_secret(
        &self,
        request: DeleteSecretRequest,
    ) -> Result<DeleteSecretResponse, ClientError> {
        self.secrets
            .delete_secret_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn rename_secret(
        &self,
        request: RenameSecretRequest,
    ) -> Result<RenameSecretResponse, ClientError> {
        self.secrets
            .rename_secret_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn list_user_secrets(
        &self,
        request: ListUserSecretsRequest,
    ) -> Result<ListUserSecretsResponse, ClientError> {
        self.secrets
            .list_user_secrets_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn set_user_secret(
        &self,
        request: SetUserSecretRequest,
    ) -> Result<SetUserSecretResponse, ClientError> {
        self.secrets
            .set_user_secret_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn delete_user_secret(
        &self,
        request: DeleteUserSecretRequest,
    ) -> Result<DeleteUserSecretResponse, ClientError> {
        self.secrets
            .delete_user_secret_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn rename_user_secret(
        &self,
        request: RenameUserSecretRequest,
    ) -> Result<RenameUserSecretResponse, ClientError> {
        self.secrets
            .rename_user_secret_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn list_secret_projects(
        &self,
        request: ListSecretProjectsRequest,
    ) -> Result<ListSecretProjectsResponse, ClientError> {
        self.secrets
            .list_secret_projects_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn create_secret_project(
        &self,
        request: CreateSecretProjectRequest,
    ) -> Result<CreateSecretProjectResponse, ClientError> {
        self.secrets
            .create_secret_project_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn delete_secret_project(
        &self,
        request: DeleteSecretProjectRequest,
    ) -> Result<DeleteSecretProjectResponse, ClientError> {
        self.secrets
            .delete_secret_project_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn list_project_secrets(
        &self,
        request: ListProjectSecretsRequest,
    ) -> Result<ListProjectSecretsResponse, ClientError> {
        self.secrets
            .list_project_secrets_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn set_project_secret(
        &self,
        request: SetProjectSecretRequest,
    ) -> Result<SetProjectSecretResponse, ClientError> {
        self.secrets
            .set_project_secret_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn delete_project_secret(
        &self,
        request: DeleteProjectSecretRequest,
    ) -> Result<DeleteProjectSecretResponse, ClientError> {
        self.secrets
            .delete_project_secret_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn rename_project_secret(
        &self,
        request: RenameProjectSecretRequest,
    ) -> Result<RenameProjectSecretResponse, ClientError> {
        self.secrets
            .rename_project_secret_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn preview_workload_secret_resolution(
        &self,
        request: PreviewWorkloadSecretResolutionRequest,
    ) -> Result<PreviewWorkloadSecretResolutionResponse, ClientError> {
        self.secrets
            .preview_workload_secret_resolution_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }
}

#[cfg(test)]
#[path = "secrets_tests.rs"]
mod tests;
