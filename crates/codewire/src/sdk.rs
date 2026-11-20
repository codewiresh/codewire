//! The SDK's front door: [`Codewire`], configured from the environment like
//! the Go, Python and TypeScript SDKs, and [`EnvironmentHandle`], one
//! environment's calls with its organization and ID already filled in.
//!
//! Every call takes and returns the generated `codewire.v1` messages; this
//! module only fills the IDs a handle already knows. [`Codewire::client`]
//! reaches every other call.

use std::env;
use std::time::Duration;

use bytes::Bytes;
use connectrpc::ErrorCode;
use futures_util::{StreamExt as _, TryStreamExt as _};

use crate::desktop::{
    EnvironmentDesktop, GetDesktopRequest, StartDesktopRequest, StopDesktopRequest,
};
use crate::{
    ClientConfig, ClientError, CodewireClient, CreateEnvironmentRequest, CreatePortRequest,
    CreatePortResponse, DeleteEnvironmentRequest, DeletePortRequest, DownloadFileRequest,
    Environment, EnvironmentState, ExecRequest, ExecResponse, GetEnvironmentRequest,
    ListFilesRequest, ListFilesResponse, ListPortsRequest, ListPortsResponse,
    StartEnvironmentRequest, StaticTokenProvider, StopEnvironmentRequest, UploadFileHeader,
    UploadFileRequest, download_file_response, upload_file_request,
};

/// The API key the SDKs read, a `cw_` key or an OAuth access token.
pub const CODEWIRE_API_KEY_ENV: &str = "CODEWIRE_API_KEY";
/// The organization the SDKs act in.
pub const CODEWIRE_ORG_ID_ENV: &str = "CODEWIRE_ORG_ID";

/// How often [`EnvironmentHandle::wait_ready`] polls when the server names no
/// interval.
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(2);
/// The size of each upload frame.
const UPLOAD_CHUNK: usize = 256 * 1024;

/// A Codewire client bound to one organization.
#[derive(Clone)]
pub struct Codewire {
    client: CodewireClient,
    org_id: String,
}

impl Codewire {
    /// Reads `CODEWIRE_API_KEY` and `CODEWIRE_ORG_ID`, and the server from
    /// `CODEWIRE_API_URL`, then `CODEWIRE_URL`, then the hosted service.
    pub fn from_env() -> Result<Self, ClientError> {
        Self::from_env_values(
            env::var(CODEWIRE_API_KEY_ENV).ok(),
            env::var(CODEWIRE_ORG_ID_ENV).ok(),
            ClientConfig::from_env()?,
        )
    }

    fn from_env_values(
        api_key: Option<String>,
        org_id: Option<String>,
        config: ClientConfig,
    ) -> Result<Self, ClientError> {
        let api_key = api_key.filter(|key| !key.is_empty()).ok_or_else(|| {
            ClientError::new(
                ErrorCode::Unauthenticated,
                format!("set {CODEWIRE_API_KEY_ENV} to a Codewire API key"),
            )
        })?;
        let org_id = org_id.unwrap_or_default();
        let client = CodewireClient::new(config, StaticTokenProvider::new(api_key)?)?;
        Self::new(client, org_id)
    }

    /// Binds an existing client to an organization.
    pub fn new(client: CodewireClient, org_id: impl Into<String>) -> Result<Self, ClientError> {
        let org_id = org_id.into();
        if org_id.trim().is_empty() {
            return Err(ClientError::new(
                ErrorCode::InvalidArgument,
                format!("set {CODEWIRE_ORG_ID_ENV} to the organization's ID"),
            ));
        }
        Ok(Self { client, org_id })
    }

    /// The client underneath, for every call this type doesn't wrap.
    pub fn client(&self) -> &CodewireClient {
        &self.client
    }

    pub fn org_id(&self) -> &str {
        &self.org_id
    }

    /// Creates an environment, in this client's organization when the
    /// request names none.
    pub async fn create_environment(
        &self,
        mut request: CreateEnvironmentRequest,
    ) -> Result<EnvironmentHandle, ClientError> {
        fill(&mut request.org_id, &self.org_id);
        let response = self.client.create_environment(request).await?;
        let environment = response.environment.into_option().ok_or_else(|| {
            ClientError::new(
                ErrorCode::Internal,
                "the server created an environment but did not return it",
            )
        })?;
        Ok(self.handle(environment, None))
    }

    /// A handle to an existing environment, read from the server.
    pub async fn environment(
        &self,
        environment_id: impl Into<String>,
    ) -> Result<EnvironmentHandle, ClientError> {
        let mut handle = self.handle(
            Environment {
                id: environment_id.into(),
                org_id: self.org_id.clone(),
                ..Default::default()
            },
            None,
        );
        handle.refresh().await?;
        Ok(handle)
    }

    fn handle(
        &self,
        environment: Environment,
        poll_interval: Option<Duration>,
    ) -> EnvironmentHandle {
        EnvironmentHandle {
            codewire: self.clone(),
            environment,
            poll_interval: poll_interval.unwrap_or(DEFAULT_POLL_INTERVAL),
        }
    }
}

/// One environment. Its calls fill in the organization and environment IDs
/// that a request leaves empty.
#[derive(Clone)]
pub struct EnvironmentHandle {
    codewire: Codewire,
    environment: Environment,
    poll_interval: Duration,
}

impl EnvironmentHandle {
    pub fn id(&self) -> &str {
        &self.environment.id
    }

    /// The environment as the server last described it.
    pub fn environment(&self) -> &Environment {
        &self.environment
    }

    fn org_id(&self) -> &str {
        if self.environment.org_id.is_empty() {
            self.codewire.org_id()
        } else {
            &self.environment.org_id
        }
    }

    fn ids(&self, org_id: &mut String, environment_id: &mut String) {
        fill(org_id, self.org_id());
        fill(environment_id, &self.environment.id);
    }

    /// Reads the environment again.
    pub async fn refresh(&mut self) -> Result<&Environment, ClientError> {
        let mut request = GetEnvironmentRequest::default();
        self.ids(&mut request.org_id, &mut request.environment_id);
        let response = self.codewire.client.get_environment(request).await?;
        if let Some(interval) = response
            .poll_interval
            .into_option()
            .and_then(|interval| Duration::try_from(interval).ok())
            .filter(|interval| !interval.is_zero())
        {
            self.poll_interval = interval;
        }
        self.environment = response.environment.into_option().ok_or_else(|| {
            ClientError::new(ErrorCode::NotFound, "the server returned no environment")
        })?;
        Ok(&self.environment)
    }

    /// Polls until the environment is running, at the interval the server
    /// asks for. An environment that fails, or is destroyed, ends the wait
    /// with its reason. A stopped or archived one keeps the wait going until
    /// something starts it; call [`Self::start`] first. Wrap the call in
    /// `tokio::time::timeout` to bound it.
    pub async fn wait_ready(&mut self) -> Result<&Environment, ClientError> {
        loop {
            self.refresh().await?;
            match self.environment.state.as_known() {
                Some(EnvironmentState::Running) => return Ok(&self.environment),
                Some(
                    state @ (EnvironmentState::Error
                    | EnvironmentState::BuildFailed
                    | EnvironmentState::Destroying
                    | EnvironmentState::Destroyed),
                ) => {
                    let reason = [
                        &self.environment.error_reason,
                        &self.environment.setup_error,
                    ]
                    .into_iter()
                    .find(|reason| !reason.is_empty())
                    .map(|reason| format!(": {reason}"))
                    .unwrap_or_default();
                    return Err(ClientError::new(
                        ErrorCode::FailedPrecondition,
                        format!(
                            "environment {} will not become ready; it is {state:?}{reason}",
                            self.environment.id
                        ),
                    ));
                }
                _ => tokio::time::sleep(self.poll_interval).await,
            }
        }
    }

    /// Runs a command and waits for it to finish.
    pub async fn exec(&self, mut request: ExecRequest) -> Result<ExecResponse, ClientError> {
        self.ids(&mut request.org_id, &mut request.environment_id);
        self.codewire.client.exec(request).await
    }

    /// Lists a directory, one page at a time.
    pub async fn list_files(
        &self,
        mut request: ListFilesRequest,
    ) -> Result<ListFilesResponse, ClientError> {
        self.ids(&mut request.org_id, &mut request.environment_id);
        self.codewire.client.list_files(request).await
    }

    /// Writes `contents` to `path`, replacing any file there. The contents
    /// are held in memory; for a file too large for that, stream it with
    /// [`CodewireClient::upload_file`].
    pub async fn upload(
        &self,
        path: impl Into<String>,
        contents: impl Into<Bytes>,
    ) -> Result<(), ClientError> {
        let mut header = UploadFileHeader {
            path: path.into(),
            ..Default::default()
        };
        self.ids(&mut header.org_id, &mut header.environment_id);
        let contents: Bytes = contents.into();
        let header = UploadFileRequest {
            payload: Some(upload_file_request::Payload::Header(Box::new(header))),
            ..Default::default()
        };
        // Each frame copies its chunk only when the call sends it.
        let chunks = futures_util::stream::unfold(contents, |mut rest| async move {
            (!rest.is_empty()).then(|| {
                let chunk = rest.split_to(rest.len().min(UPLOAD_CHUNK));
                let frame = UploadFileRequest {
                    payload: Some(upload_file_request::Payload::Chunk(chunk.to_vec())),
                    ..Default::default()
                };
                (frame, rest)
            })
        });
        let requests = futures_util::stream::once(std::future::ready(header)).chain(chunks);
        self.codewire.client.upload_file(requests).await?;
        Ok(())
    }

    /// Reads the whole file at `path` into memory; for a file too large for
    /// that, stream it with [`CodewireClient::download_file`]. A stream that
    /// ends short of the size the server announced fails as `DataLoss`.
    pub async fn download(&self, path: impl Into<String>) -> Result<Vec<u8>, ClientError> {
        let mut request = DownloadFileRequest {
            path: path.into(),
            ..Default::default()
        };
        self.ids(&mut request.org_id, &mut request.environment_id);
        let frames = self.codewire.client.download_file(request).await?;
        let (size, contents) = frames
            .try_fold(
                (None, Vec::new()),
                |(mut size, mut contents), frame| async move {
                    match frame.payload {
                        Some(download_file_response::Payload::Info(info)) if size.is_none() => {
                            size = Some(u64::try_from(info.size).map_err(|_| {
                                ClientError::new(
                                    ErrorCode::Internal,
                                    "the server announced a negative file size",
                                )
                            })?);
                        }
                        Some(download_file_response::Payload::Chunk(chunk)) if size.is_some() => {
                            contents.extend_from_slice(&chunk);
                            if Some(contents.len() as u64) > size {
                                return Err(ClientError::new(
                                    ErrorCode::DataLoss,
                                    format!(
                                        "the download sent more than the {} bytes it announced",
                                        size.unwrap_or_default()
                                    ),
                                ));
                            }
                        }
                        _ => {
                            return Err(ClientError::new(
                                ErrorCode::Internal,
                                "the server sent a download frame out of order",
                            ));
                        }
                    }
                    Ok((size, contents))
                },
            )
            .await?;
        let size = size.ok_or_else(|| {
            ClientError::new(ErrorCode::Internal, "the server sent no file information")
        })?;
        if contents.len() as u64 != size {
            return Err(ClientError::new(
                ErrorCode::DataLoss,
                format!(
                    "the download ended after {} of {size} bytes",
                    contents.len()
                ),
            ));
        }
        Ok(contents)
    }

    pub async fn list_ports(
        &self,
        mut request: ListPortsRequest,
    ) -> Result<ListPortsResponse, ClientError> {
        self.ids(&mut request.org_id, &mut request.environment_id);
        self.codewire.client.list_ports(request).await
    }

    /// Opens a port, giving it a URL.
    pub async fn create_port(
        &self,
        mut request: CreatePortRequest,
    ) -> Result<CreatePortResponse, ClientError> {
        self.ids(&mut request.org_id, &mut request.environment_id);
        self.codewire.client.create_port(request).await
    }

    pub async fn delete_port(&self, port_id: impl Into<String>) -> Result<(), ClientError> {
        let mut request = DeletePortRequest {
            port_id: port_id.into(),
            ..Default::default()
        };
        self.ids(&mut request.org_id, &mut request.environment_id);
        self.codewire.client.delete_port(request).await?;
        Ok(())
    }

    /// Starts the environment's desktop, or returns the one that runs. A
    /// running desktop carries the password its viewer is asked for.
    pub async fn start_desktop(&self) -> Result<EnvironmentDesktop, ClientError> {
        let mut request = StartDesktopRequest::default();
        self.ids(&mut request.org_id, &mut request.environment_id);
        self.codewire
            .client
            .start_desktop(request)
            .await?
            .desktop
            .into_option()
            .ok_or_else(no_desktop)
    }

    pub async fn desktop(&self) -> Result<EnvironmentDesktop, ClientError> {
        let mut request = GetDesktopRequest::default();
        self.ids(&mut request.org_id, &mut request.environment_id);
        self.codewire
            .client
            .get_desktop(request)
            .await?
            .desktop
            .into_option()
            .ok_or_else(no_desktop)
    }

    /// Stops the desktop. Stopping one that does not run succeeds.
    pub async fn stop_desktop(&self) -> Result<EnvironmentDesktop, ClientError> {
        let mut request = StopDesktopRequest::default();
        self.ids(&mut request.org_id, &mut request.environment_id);
        self.codewire
            .client
            .stop_desktop(request)
            .await?
            .desktop
            .into_option()
            .ok_or_else(no_desktop)
    }

    /// Stops the environment, keeping its disk.
    pub async fn stop(&self) -> Result<(), ClientError> {
        let mut request = StopEnvironmentRequest::default();
        self.ids(&mut request.org_id, &mut request.environment_id);
        self.codewire.client.stop_environment(request).await?;
        Ok(())
    }

    /// Starts a stopped environment. Follow it with [`Self::wait_ready`].
    pub async fn start(&self) -> Result<(), ClientError> {
        let mut request = StartEnvironmentRequest::default();
        self.ids(&mut request.org_id, &mut request.environment_id);
        self.codewire.client.start_environment(request).await?;
        Ok(())
    }

    /// Deletes the environment and its disk.
    pub async fn delete(&self) -> Result<(), ClientError> {
        let mut request = DeleteEnvironmentRequest::default();
        self.ids(&mut request.org_id, &mut request.environment_id);
        self.codewire.client.delete_environment(request).await?;
        Ok(())
    }
}

fn no_desktop() -> ClientError {
    ClientError::new(ErrorCode::Internal, "the server returned no desktop")
}

fn fill(field: &mut String, value: &str) {
    if field.is_empty() {
        value.clone_into(field);
    }
}

#[cfg(test)]
mod tests;
