//! Managed platform conversations on one original scope. Mutations are sent
//! once; an uncertain response retains the request UUID for observation.
use buffa::Message as _;
use sha2::{Digest as _, Sha256};
use std::time::Duration;

use crate::{ClientError, CodewireClient, ErrorCode, ReqwestConnectTransport};
use codewire_proto::codewire::v1::EnvironmentAgentServiceClient;
pub use codewire_proto::codewire::v1::{
    EnvironmentAgentAction, EnvironmentAgentControl, EnvironmentAgentKind, EnvironmentAgentLaunch,
    EnvironmentAgentOperation, EnvironmentAgentPhase, EnvironmentAgentRecordKind,
    EnvironmentAgentScope, EnvironmentAgentSupport, GetEnvironmentAgentInfoRequest,
    GetEnvironmentAgentInfoResponse, ListEnvironmentAgentsRequest, ListEnvironmentAgentsResponse,
    MutateEnvironmentAgentRequest, MutateEnvironmentAgentResponse, ObserveEnvironmentAgentRequest,
    ObserveEnvironmentAgentResponse, ReadEnvironmentAgentRequest, ReadEnvironmentAgentResponse,
    mutate_environment_agent_request,
};

const RECORD_BYTES: usize = 5 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
#[error("agent outcome is uncertain; observe the original request {request_id}")]
pub struct PlatformAgentMutationError {
    pub request_id: String,
    /// Boxed so the error stays small beside the response it replaces.
    #[source]
    pub source: Box<ClientError>,
}

fn invalid_response() -> ClientError {
    ClientError::new(
        ErrorCode::Internal,
        "platform agent response changed its original scope",
    )
}
fn invalid_request() -> ClientError {
    ClientError::new(
        ErrorCode::InvalidArgument,
        "platform agent request omitted its original scope or exceeded its bound",
    )
}
fn canonical_request_id(id: &str) -> bool {
    uuid::Uuid::parse_str(id).is_ok_and(|value| !value.is_nil() && value.to_string() == id)
}
fn scope_matches(scope: &EnvironmentAgentScope, org: &str, environment: &str) -> bool {
    scope
        .incarnation
        .as_option()
        .is_some_and(|value| value.org_id == org && value.environment_id == environment)
        && scope.support_image_sha256.len() == 32
        && scope.support_image_size > 0
}

impl CodewireClient {
    fn platform_agent_client(
        &self,
    ) -> Result<EnvironmentAgentServiceClient<ReqwestConnectTransport>, ClientError> {
        let config = self
            .config
            .connect_config()?
            .with_default_max_message_size(RECORD_BYTES + 32 * 1024)
            .with_default_element_memory_limit(RECORD_BYTES + 64 * 1024);
        Ok(EnvironmentAgentServiceClient::new(
            ReqwestConnectTransport(self.http.clone()),
            config,
        ))
    }

    pub async fn get_environment_agent_info(
        &self,
        request: GetEnvironmentAgentInfoRequest,
    ) -> Result<GetEnvironmentAgentInfoResponse, ClientError> {
        let org = request.org_id.clone();
        let env = request.environment_id.clone();
        let response = self
            .platform_agent_client()?
            .get_environment_agent_info_with_options(
                request,
                self.auth_options()
                    .await?
                    .with_timeout(Duration::from_secs(90)),
            )
            .await?
            .into_owned();
        if response
            .scope
            .as_option()
            .is_none_or(|s| !scope_matches(s, &org, &env))
        {
            return Err(invalid_response());
        }
        Ok(response)
    }

    pub async fn mutate_environment_agent(
        &self,
        request: MutateEnvironmentAgentRequest,
    ) -> Result<MutateEnvironmentAgentResponse, PlatformAgentMutationError> {
        let id = request.request_id.clone();
        let scope = request.expected_scope.clone();
        let call = async {
            if !canonical_request_id(&id)
                || request.operation.is_none()
                || scope
                    .as_option()
                    .is_none_or(|s| !scope_matches(s, &request.org_id, &request.environment_id))
                || request.encode_to_vec().len() > 256 * 1024
            {
                return Err(invalid_request());
            }
            let response = self
                .platform_agent_client()?
                .mutate_environment_agent_with_options(
                    request,
                    self.auth_options()
                        .await?
                        .with_timeout(Duration::from_secs(240)),
                )
                .await?
                .into_owned();
            let op = response
                .operation
                .as_option()
                .ok_or_else(invalid_response)?;
            if op.request_id != id || op.scope != scope {
                return Err(invalid_response());
            }
            Ok(response)
        }
        .await;
        call.map_err(|source| PlatformAgentMutationError {
            request_id: id,
            source: Box::new(source),
        })
    }

    pub async fn observe_environment_agent(
        &self,
        request: ObserveEnvironmentAgentRequest,
    ) -> Result<ObserveEnvironmentAgentResponse, ClientError> {
        let id = request.request_id.clone();
        let org = request.org_id.clone();
        let env = request.environment_id.clone();
        if !canonical_request_id(&id) {
            return Err(invalid_request());
        }
        let response = self
            .platform_agent_client()?
            .observe_environment_agent_with_options(
                request,
                self.auth_options()
                    .await?
                    .with_timeout(Duration::from_secs(90)),
            )
            .await?
            .into_owned();
        let op = response
            .operation
            .as_option()
            .ok_or_else(invalid_response)?;
        if op.request_id != id
            || op
                .scope
                .as_option()
                .is_none_or(|s| !scope_matches(s, &org, &env))
        {
            return Err(invalid_response());
        }
        Ok(response)
    }

    pub async fn list_environment_agents(
        &self,
        request: ListEnvironmentAgentsRequest,
    ) -> Result<ListEnvironmentAgentsResponse, ClientError> {
        let scope = request.expected_scope.clone();
        if scope
            .as_option()
            .is_none_or(|s| !scope_matches(s, &request.org_id, &request.environment_id))
            || request.encode_to_vec().len() > 32 * 1024
        {
            return Err(invalid_request());
        }
        let response = self
            .platform_agent_client()?
            .list_environment_agents_with_options(
                request,
                self.auth_options()
                    .await?
                    .with_timeout(Duration::from_secs(90)),
            )
            .await?
            .into_owned();
        if response.scope != scope || response.sessions.len() > 8 {
            return Err(invalid_response());
        }
        Ok(response)
    }

    pub async fn read_environment_agent(
        &self,
        request: ReadEnvironmentAgentRequest,
    ) -> Result<ReadEnvironmentAgentResponse, ClientError> {
        let expected = request.clone();
        if expected
            .expected_scope
            .as_option()
            .is_none_or(|s| !scope_matches(s, &expected.org_id, &expected.environment_id))
            || expected.encode_to_vec().len() > 32 * 1024
        {
            return Err(invalid_request());
        }
        let response = self
            .platform_agent_client()?
            .read_environment_agent_with_options(
                request,
                self.auth_options()
                    .await?
                    .with_timeout(Duration::from_secs(90)),
            )
            .await?
            .into_owned();
        if response.scope != expected.expected_scope
            || response.session_id != expected.session_id
            || response.driver_id != expected.driver_id
            || response.launch_generation != expected.expected_launch_generation
            || response.kind != expected.kind
            || response.message_id != expected.message_id
            || response.record_json.len() > RECORD_BYTES
            || response.record_sha256.len() != 32
            || Sha256::digest(&response.record_json).as_slice() != response.record_sha256
        {
            return Err(invalid_response());
        }
        Ok(response)
    }
}

#[cfg(test)]
mod tests;
