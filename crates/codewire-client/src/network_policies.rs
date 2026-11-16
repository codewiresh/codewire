//! Organization network policies (#4000) through the canonical generated
//! client.

use crate::*;

impl CodewireClient {
    pub async fn create_network_policy(
        &self,
        request: CreateNetworkPolicyRequest,
    ) -> Result<CreateNetworkPolicyResponse, ClientError> {
        self.network_policies
            .create_network_policy_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn list_network_policies(
        &self,
        request: ListNetworkPoliciesRequest,
    ) -> Result<ListNetworkPoliciesResponse, ClientError> {
        self.network_policies
            .list_network_policies_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn get_network_policy(
        &self,
        request: GetNetworkPolicyRequest,
    ) -> Result<GetNetworkPolicyResponse, ClientError> {
        self.network_policies
            .get_network_policy_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn update_network_policy(
        &self,
        request: UpdateNetworkPolicyRequest,
    ) -> Result<UpdateNetworkPolicyResponse, ClientError> {
        self.network_policies
            .update_network_policy_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn delete_network_policy(
        &self,
        request: DeleteNetworkPolicyRequest,
    ) -> Result<DeleteNetworkPolicyResponse, ClientError> {
        self.network_policies
            .delete_network_policy_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn update_environment_network_policy(
        &self,
        request: UpdateEnvironmentNetworkPolicyRequest,
    ) -> Result<UpdateEnvironmentNetworkPolicyResponse, ClientError> {
        self.network_policies
            .update_environment_network_policy_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }
}
