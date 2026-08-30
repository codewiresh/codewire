//! Public local-environment client over the owner-only supervisor UDS.
//!
//! Lifecycle creation retains the richer private operation/watch API for now.
//! Durable workspace sessions use the unchanged public Codewire contract so
//! the CLI never receives a hybrid-vsock path or guest daemon capability.

use codewire_client::{
    AttachSessionOpen, ClientError, EnvironmentSession, EnvironmentSessionAttachment,
    LaunchSessionRequest, ListSessionsRequest, PublicEnvironmentSessionClient,
    ReadSessionOutputRequest, ReadSessionOutputResponse, RestartSessionRequest,
};
use codewire_proto::codewire::v1::{
    EnvironmentServiceClient, GetSessionRequest, ListEnvironmentsRequest, StopSessionRequest,
};
use connectrpc::client::{ClientConfig, Http2Connection, SharedHttp2Connection};

use crate::supervisor::{NativeRuntimeConfig, NativeSupervisorClient, SupervisorError};
use crate::uds::{UdsError, owner_only_connector};

const LOCAL_AUTHORITY: &str = "http://codewire-local-control";

#[derive(Clone)]
pub struct NativePublicSessionClient {
    inner: PublicEnvironmentSessionClient<SharedHttp2Connection>,
    org_id: String,
    environment_id: String,
}

impl NativePublicSessionClient {
    pub async fn connect_or_start(
        config: &NativeRuntimeConfig,
        target: &str,
    ) -> Result<Self, NativePublicClientError> {
        let _supervisor = NativeSupervisorClient::connect_or_start(config).await?;
        let authority: http::Uri = LOCAL_AUTHORITY
            .parse()
            .map_err(|_| NativePublicClientError::Configuration)?;
        let transport = Http2Connection::connect_with_connector(
            owner_only_connector(&config.supervisor_socket())?,
            authority.clone(),
        )
        .await
        .map_err(|_| NativePublicClientError::Connect)?
        .shared(32);
        let config = ClientConfig::new(authority).proto();
        let environments = EnvironmentServiceClient::new(transport.clone(), config.clone());
        let listed = environments
            .list_environments(ListEnvironmentsRequest::default())
            .await
            .map_err(NativePublicClientError::Rpc)?
            .into_owned();
        let environment = listed
            .environments
            .into_iter()
            .find(|environment| environment.name == target || environment.id == target)
            .ok_or(NativePublicClientError::NotFound)?;
        if environment.org_id.is_empty() || environment.id.is_empty() {
            return Err(NativePublicClientError::Protocol);
        }
        Ok(Self {
            inner: PublicEnvironmentSessionClient::new(transport, config),
            org_id: environment.org_id,
            environment_id: environment.id,
        })
    }

    pub async fn launch(
        &self,
        mut request: LaunchSessionRequest,
    ) -> Result<EnvironmentSession, NativePublicClientError> {
        self.apply_coordinates(&mut request.org_id, &mut request.environment_id);
        required_session(
            self.inner
                .launch_session(request)
                .await?
                .session
                .into_option(),
        )
    }

    pub async fn list(&self) -> Result<Vec<EnvironmentSession>, NativePublicClientError> {
        Ok(self
            .inner
            .list_sessions(ListSessionsRequest {
                org_id: self.org_id.clone(),
                environment_id: self.environment_id.clone(),
                ..Default::default()
            })
            .await?
            .sessions)
    }

    pub async fn get(
        &self,
        session_id: &str,
    ) -> Result<EnvironmentSession, NativePublicClientError> {
        required_session(
            self.inner
                .get_session(GetSessionRequest {
                    org_id: self.org_id.clone(),
                    environment_id: self.environment_id.clone(),
                    session_id: session_id.to_owned(),
                    ..Default::default()
                })
                .await?
                .session
                .into_option(),
        )
    }

    pub async fn stop(
        &self,
        session_id: &str,
    ) -> Result<EnvironmentSession, NativePublicClientError> {
        required_session(
            self.inner
                .stop_session(StopSessionRequest {
                    org_id: self.org_id.clone(),
                    environment_id: self.environment_id.clone(),
                    session_id: session_id.to_owned(),
                    ..Default::default()
                })
                .await?
                .session
                .into_option(),
        )
    }

    pub async fn restart(
        &self,
        session_id: &str,
    ) -> Result<EnvironmentSession, NativePublicClientError> {
        required_session(
            self.inner
                .restart_session(RestartSessionRequest {
                    org_id: self.org_id.clone(),
                    environment_id: self.environment_id.clone(),
                    session_id: session_id.to_owned(),
                    ..Default::default()
                })
                .await?
                .session
                .into_option(),
        )
    }

    pub async fn read_output(
        &self,
        session_id: &str,
        offset: u64,
        limit: u64,
    ) -> Result<ReadSessionOutputResponse, NativePublicClientError> {
        self.inner
            .read_session_output(ReadSessionOutputRequest {
                org_id: self.org_id.clone(),
                environment_id: self.environment_id.clone(),
                session_id: session_id.to_owned(),
                offset,
                limit,
                ..Default::default()
            })
            .await
            .map_err(NativePublicClientError::from)
    }

    pub async fn attach(
        &self,
        session_id: &str,
        output_offset: u64,
    ) -> Result<EnvironmentSessionAttachment, NativePublicClientError> {
        self.inner
            .attach_session(AttachSessionOpen {
                org_id: self.org_id.clone(),
                environment_id: self.environment_id.clone(),
                session_id: session_id.to_owned(),
                output_offset,
                ..Default::default()
            })
            .await
            .map_err(NativePublicClientError::from)
    }

    fn apply_coordinates(&self, org_id: &mut String, environment_id: &mut String) {
        org_id.clone_from(&self.org_id);
        environment_id.clone_from(&self.environment_id);
    }
}

fn required_session(
    session: Option<EnvironmentSession>,
) -> Result<EnvironmentSession, NativePublicClientError> {
    session.ok_or(NativePublicClientError::Protocol)
}

#[derive(Debug, thiserror::Error)]
pub enum NativePublicClientError {
    #[error("local public client configuration is invalid")]
    Configuration,
    #[error("connect to local public supervisor API failed")]
    Connect,
    #[error("local environment was not found")]
    NotFound,
    #[error("local public supervisor returned an invalid response")]
    Protocol,
    #[error(transparent)]
    Supervisor(#[from] SupervisorError),
    #[error(transparent)]
    Socket(#[from] UdsError),
    #[error(transparent)]
    Rpc(#[from] connectrpc::ConnectError),
    #[error(transparent)]
    Client(#[from] ClientError),
}
