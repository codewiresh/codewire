//! Sandbox identity's records (#4663; docs/dev/SANDBOX-IDENTITY.md): a
//! Sandbox's identity groups, the organization's registered audiences, and
//! the switches that stop minting, through the canonical generated client.
//! Nothing here issues a token.

pub use codewire_proto::codewire::v1::{
    EnvironmentIdentityGroups, GetEnvironmentIdentityGroupsRequest,
    GetEnvironmentIdentityGroupsResponse, IdentityAudience, IdentityAudienceGroups,
    IdentityGroupUser, IdentityGroupUserReason, ListIdentityAudiencesRequest,
    ListIdentityAudiencesResponse, RegisterIdentityAudienceRequest,
    RegisterIdentityAudienceResponse, RemoveIdentityAudienceRequest,
    RemoveIdentityAudienceResponse, ResumeIdentityMintingRequest, ResumeIdentityMintingResponse,
    SetEnvironmentIdentityGroupsRequest, SetEnvironmentIdentityGroupsResponse,
    StopIdentityMintingRequest, StopIdentityMintingResponse,
};

use crate::{ClientError, CodewireClient};

impl CodewireClient {
    pub async fn get_environment_identity_groups(
        &self,
        request: GetEnvironmentIdentityGroupsRequest,
    ) -> Result<GetEnvironmentIdentityGroupsResponse, ClientError> {
        self.sandbox_identity
            .get_environment_identity_groups_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn set_environment_identity_groups(
        &self,
        request: SetEnvironmentIdentityGroupsRequest,
    ) -> Result<SetEnvironmentIdentityGroupsResponse, ClientError> {
        self.sandbox_identity
            .set_environment_identity_groups_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn register_identity_audience(
        &self,
        request: RegisterIdentityAudienceRequest,
    ) -> Result<RegisterIdentityAudienceResponse, ClientError> {
        self.sandbox_identity
            .register_identity_audience_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn list_identity_audiences(
        &self,
        request: ListIdentityAudiencesRequest,
    ) -> Result<ListIdentityAudiencesResponse, ClientError> {
        self.sandbox_identity
            .list_identity_audiences_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn remove_identity_audience(
        &self,
        request: RemoveIdentityAudienceRequest,
    ) -> Result<RemoveIdentityAudienceResponse, ClientError> {
        self.sandbox_identity
            .remove_identity_audience_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn stop_identity_minting(
        &self,
        request: StopIdentityMintingRequest,
    ) -> Result<StopIdentityMintingResponse, ClientError> {
        self.sandbox_identity
            .stop_identity_minting_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn resume_identity_minting(
        &self,
        request: ResumeIdentityMintingRequest,
    ) -> Result<ResumeIdentityMintingResponse, ClientError> {
        self.sandbox_identity
            .resume_identity_minting_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }
}
