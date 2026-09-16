//! Public local-environment client over the owner-only supervisor UDS.
//!
//! Lifecycle creation retains the richer private operation/watch API for now.
//! Durable workspace sessions and the Exec/File data plane use unchanged
//! public Codewire contracts so clients never receive a hybrid-vsock path or
//! guest daemon capability.

use codewire_client::{
    AttachSessionOpen, ClientError, EnvironmentSession, EnvironmentSessionAttachment,
    LaunchSessionRequest, ListSessionsRequest, PublicEnvironmentSessionClient,
    ReadSessionOutputRequest, ReadSessionOutputResponse, RestartSessionRequest,
};
use codewire_proto::codewire::v1::{
    DownloadFileRequest, DownloadFileResponse, EnvironmentDaemonStatus, EnvironmentServiceClient,
    ExecRequest, ExecResponse, ExecServiceClient, FileEntry, FileServiceClient,
    GetEnvironmentDaemonStatusRequest, GetSessionRequest, ListEnvironmentsRequest,
    ListFilesRequest, RepairEnvironmentDaemonRequest, StopSessionRequest,
    StreamEnvironmentDaemonLogsRequest, StreamEnvironmentDaemonLogsResponse, UploadFileHeader,
    UploadFileRequest, UploadFileResponse, download_file_response, upload_file_request,
};
use connectrpc::client::{ClientConfig, Http2Connection, SharedHttp2Connection};

use crate::supervisor::{NativeRuntimeConfig, NativeSupervisorClient, SupervisorError};
use crate::uds::{UdsError, owner_only_connector};

const LOCAL_AUTHORITY: &str = "http://codewire-local-control";
const FILE_CHUNK_BYTES: usize = 64 * 1024;
const MAXIMUM_DAEMON_LOG_BYTES: usize = 64 * 1024;

#[derive(Clone)]
pub struct NativePublicEnvironmentClient {
    inner: EnvironmentServiceClient<SharedHttp2Connection>,
    org_id: String,
    environment_id: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NativeDaemonRepair {
    pub status: EnvironmentDaemonStatus,
    pub replaced_pod_name: String,
}

impl NativePublicEnvironmentClient {
    pub async fn connect_or_start(
        config: &NativeRuntimeConfig,
        target: &str,
    ) -> Result<Self, NativePublicClientError> {
        let target = connect_target(config, target).await?;
        Ok(Self {
            inner: EnvironmentServiceClient::new(target.transport, target.client_config),
            org_id: target.org_id,
            environment_id: target.environment_id,
        })
    }

    pub async fn daemon_status(&self) -> Result<EnvironmentDaemonStatus, NativePublicClientError> {
        self.inner
            .get_environment_daemon_status(GetEnvironmentDaemonStatusRequest {
                org_id: self.org_id.clone(),
                environment_id: self.environment_id.clone(),
                ..Default::default()
            })
            .await?
            .into_owned()
            .status
            .into_option()
            .ok_or(NativePublicClientError::Protocol)
    }

    pub async fn daemon_logs(&self) -> Result<Vec<u8>, NativePublicClientError> {
        let mut stream = self
            .inner
            .stream_environment_daemon_logs(StreamEnvironmentDaemonLogsRequest {
                org_id: self.org_id.clone(),
                environment_id: self.environment_id.clone(),
                ..Default::default()
            })
            .await?;
        let mut data = Vec::new();
        while let Some(message) = stream
            .message::<StreamEnvironmentDaemonLogsResponse>()
            .await?
        {
            let message = message.to_owned_message();
            if data.len().saturating_add(message.data.len()) > MAXIMUM_DAEMON_LOG_BYTES {
                return Err(NativePublicClientError::Protocol);
            }
            data.extend(message.data);
        }
        Ok(data)
    }

    pub async fn repair_daemon(&self) -> Result<NativeDaemonRepair, NativePublicClientError> {
        let response = self
            .inner
            .repair_environment_daemon(RepairEnvironmentDaemonRequest {
                org_id: self.org_id.clone(),
                environment_id: self.environment_id.clone(),
                ..Default::default()
            })
            .await?
            .into_owned();
        Ok(NativeDaemonRepair {
            status: response
                .status
                .into_option()
                .ok_or(NativePublicClientError::Protocol)?,
            replaced_pod_name: response.replaced_pod_name,
        })
    }
}

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
        let target = connect_target(config, target).await?;
        Ok(Self {
            inner: PublicEnvironmentSessionClient::new(target.transport, target.client_config),
            org_id: target.org_id,
            environment_id: target.environment_id,
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
                allow_history_gap: true,
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

#[derive(Clone)]
pub struct NativePublicDataClient {
    exec: ExecServiceClient<SharedHttp2Connection>,
    files: FileServiceClient<SharedHttp2Connection>,
    org_id: String,
    environment_id: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DownloadedFile {
    pub info: FileEntry,
    pub data: Vec<u8>,
}

impl NativePublicDataClient {
    pub async fn connect_or_start(
        config: &NativeRuntimeConfig,
        target: &str,
    ) -> Result<Self, NativePublicClientError> {
        let target = connect_target(config, target).await?;
        Ok(Self {
            exec: ExecServiceClient::new(target.transport.clone(), target.client_config.clone()),
            files: FileServiceClient::new(target.transport, target.client_config),
            org_id: target.org_id,
            environment_id: target.environment_id,
        })
    }

    pub async fn exec(
        &self,
        command: Vec<String>,
        working_dir: impl Into<String>,
        env: impl IntoIterator<Item = (String, String)>,
    ) -> Result<ExecResponse, NativePublicClientError> {
        self.exec
            .exec(ExecRequest {
                org_id: self.org_id.clone(),
                environment_id: self.environment_id.clone(),
                command,
                working_dir: working_dir.into(),
                env: env.into_iter().collect(),
                ..Default::default()
            })
            .await
            .map(|response| response.into_owned())
            .map_err(NativePublicClientError::Rpc)
    }

    pub async fn list_files(
        &self,
        path: impl Into<String>,
    ) -> Result<Vec<FileEntry>, NativePublicClientError> {
        self.files
            .list_files(ListFilesRequest {
                org_id: self.org_id.clone(),
                environment_id: self.environment_id.clone(),
                path: path.into(),
                ..Default::default()
            })
            .await
            .map(|response| response.into_owned().entries)
            .map_err(NativePublicClientError::Rpc)
    }

    pub async fn upload_file(
        &self,
        path: impl Into<String>,
        data: &[u8],
    ) -> Result<UploadFileResponse, NativePublicClientError> {
        let path = path.into();
        let header = UploadFileRequest {
            payload: Some(upload_file_request::Payload::Header(Box::new(
                UploadFileHeader {
                    org_id: self.org_id.clone(),
                    environment_id: self.environment_id.clone(),
                    path,
                    ..Default::default()
                },
            ))),
            ..Default::default()
        };
        let chunks = data
            .chunks(FILE_CHUNK_BYTES)
            .map(|chunk| UploadFileRequest {
                payload: Some(upload_file_request::Payload::Chunk(chunk.to_vec())),
                ..Default::default()
            });
        self.files
            .upload_file(std::iter::once(header).chain(chunks))
            .await
            .map(|response| response.into_owned())
            .map_err(NativePublicClientError::Rpc)
    }

    pub async fn download_file(
        &self,
        path: impl Into<String>,
    ) -> Result<DownloadedFile, NativePublicClientError> {
        let mut stream = self
            .files
            .download_file(DownloadFileRequest {
                org_id: self.org_id.clone(),
                environment_id: self.environment_id.clone(),
                path: path.into(),
                ..Default::default()
            })
            .await
            .map_err(NativePublicClientError::Rpc)?;
        let mut info = None;
        let mut data = Vec::new();
        while let Some(message) = stream
            .message::<DownloadFileResponse>()
            .await
            .map_err(NativePublicClientError::Rpc)?
        {
            match message.to_owned_message().payload {
                Some(download_file_response::Payload::Info(value)) if info.is_none() => {
                    info = Some(*value);
                }
                Some(download_file_response::Payload::Chunk(value)) if info.is_some() => {
                    data.extend(value);
                }
                _ => return Err(NativePublicClientError::Protocol),
            }
        }
        let info = info.ok_or(NativePublicClientError::Protocol)?;
        if info.is_dir || info.size != i64::try_from(data.len()).unwrap_or(i64::MAX) {
            return Err(NativePublicClientError::Protocol);
        }
        Ok(DownloadedFile { info, data })
    }
}

struct ConnectedTarget {
    transport: SharedHttp2Connection,
    client_config: ClientConfig,
    org_id: String,
    environment_id: String,
}

async fn connect_target(
    config: &NativeRuntimeConfig,
    target: &str,
) -> Result<ConnectedTarget, NativePublicClientError> {
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
    let client_config = ClientConfig::new(authority).proto();
    let environments = EnvironmentServiceClient::new(transport.clone(), client_config.clone());
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
    Ok(ConnectedTarget {
        transport,
        client_config,
        org_id: environment.org_id,
        environment_id: environment.id,
    })
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
