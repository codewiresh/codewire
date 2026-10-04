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
    DownloadFileRequest, DownloadFileResponse, Environment, EnvironmentDaemonStatus,
    EnvironmentServiceClient, ExecRequest, ExecResponse, ExecServiceClient, FileEntry,
    FileServiceClient, GetEnvironmentDaemonStatusRequest, GetSessionRequest,
    ListEnvironmentsRequest, ListFilesRequest, RepairEnvironmentDaemonRequest, RunRequest,
    RunResponse, RunStart, StopSessionRequest, StreamEnvironmentDaemonLogsRequest,
    StreamEnvironmentDaemonLogsResponse, UploadFileHeader, UploadFileRequest, UploadFileResponse,
    download_file_response, run_request, run_response, upload_file_request,
};
use connectrpc::client::{ClientConfig, Http2Connection, SharedHttp2Connection};
use std::sync::Arc;
use std::time::Duration;

use crate::linux::supervisor_peer::SupervisorPeerPin;

use crate::supervisor::{NativeRuntimeConfig, NativeSupervisorClient, SupervisorError};
use crate::uds::{UdsError, supervisor_peer_connector};

const LOCAL_AUTHORITY: &str = "http://codewire-local-control";
const FILE_CHUNK_BYTES: usize = 64 * 1024;
const MAXIMUM_DAEMON_LOG_BYTES: usize = 64 * 1024;
const STDIN_CHUNK_BYTES: usize = 64 * 1024;
// Legal 64 KiB managed text may expand sixfold in its closed JSON envelope.
const MAXIMUM_EXEC_STDIN_BYTES: usize = 512 * 1024;
// A maximum4MiB managed record plus its bounded JSON response framing.
const MAXIMUM_EXEC_OUTPUT_BYTES: usize = 5 * 1024 * 1024;
const MINIMUM_EXEC_TIMEOUT: Duration = Duration::from_secs(1);
const MAXIMUM_EXEC_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Clone)]
pub struct NativePublicEnvironmentClient {
    _supervisor_peer: Arc<SupervisorPeerPin>,
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
            _supervisor_peer: target.peer_pin,
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
    _supervisor_peer: Arc<SupervisorPeerPin>,
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
            _supervisor_peer: target.peer_pin,
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
        self.restart_with_generation(session_id, None).await
    }

    pub async fn restart_with_generation(
        &self,
        session_id: &str,
        expected_launch_generation: Option<u64>,
    ) -> Result<EnvironmentSession, NativePublicClientError> {
        required_session(
            self.inner
                .restart_session(RestartSessionRequest {
                    org_id: self.org_id.clone(),
                    environment_id: self.environment_id.clone(),
                    session_id: session_id.to_owned(),
                    expected_launch_generation,
                    ..Default::default()
                })
                .await?
                .session
                .into_option(),
        )
    }

    pub async fn send_input(
        &self,
        session_id: &str,
        data: Vec<u8>,
    ) -> Result<(), NativePublicClientError> {
        self.inner
            .send_session_input(codewire_client::SendSessionInputRequest {
                org_id: self.org_id.clone(),
                environment_id: self.environment_id.clone(),
                session_id: session_id.to_owned(),
                data,
                ..Default::default()
            })
            .await?;
        Ok(())
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
    _supervisor_peer: Arc<SupervisorPeerPin>,
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
            _supervisor_peer: target.peer_pin,
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

    /// Run one non-interactive command with bounded stdin over public
    /// `ExecService.Run`. A transport failure or deadline leaves the command's
    /// outcome unknown; it is reported as an error and never replayed.
    pub async fn exec_with_stdin(
        &self,
        command: Vec<String>,
        working_dir: impl Into<String>,
        env: impl IntoIterator<Item = (String, String)>,
        stdin: Vec<u8>,
        timeout: Duration,
    ) -> Result<ExecResponse, NativePublicClientError> {
        validate_exec_with_stdin(stdin.len(), timeout)?;
        let start = RunStart {
            org_id: self.org_id.clone(),
            environment_id: self.environment_id.clone(),
            command,
            working_dir: working_dir.into(),
            env: env.into_iter().collect(),
            timeout: buffa::MessageField::some(timeout.into()),
            allocate_tty: false,
            ..Default::default()
        };
        tokio::time::timeout(timeout, self.run_to_exit(start, &stdin))
            .await
            .map_err(|_| NativePublicClientError::ExecTimeout)?
    }

    async fn run_to_exit(
        &self,
        start: RunStart,
        stdin: &[u8],
    ) -> Result<ExecResponse, NativePublicClientError> {
        let (mut requests, mut responses) = self.exec.run().await?.into_split();
        // Send and drain concurrently so a command that writes before reading
        // stdin cannot deadlock against the request side.
        let send = async {
            for request in run_requests(start, stdin) {
                requests.send(request).await?;
            }
            Ok::<_, connectrpc::ConnectError>(())
        };
        let receive = async {
            let mut output = RunOutput::default();
            loop {
                let Some(response) = responses.message::<RunResponse>().await? else {
                    return Err(NativePublicClientError::Protocol);
                };
                if let Some(exit_code) = output.accept(response.to_owned_message())? {
                    return Ok(output.finish(exit_code));
                }
            }
        };
        let (sent, received) = tokio::join!(send, receive);
        let response = received?;
        sent?;
        // The supervisor drains requests after exit, so the explicit
        // close_stdin above is the only stdin close. Half-close now and require
        // a clean end so a late or duplicate event is rejected, not dropped.
        requests.close_send();
        match responses.message::<RunResponse>().await? {
            None => Ok(response),
            Some(_) => Err(NativePublicClientError::Protocol),
        }
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
        // Client-streaming calls take an owned stream of the chunked file.
        let requests: Vec<_> = std::iter::once(header)
            .chain(
                data.chunks(FILE_CHUNK_BYTES)
                    .map(|chunk| UploadFileRequest {
                        payload: Some(upload_file_request::Payload::Chunk(chunk.to_vec())),
                        ..Default::default()
                    }),
            )
            .collect();
        self.files
            .upload_file(futures::stream::iter(requests))
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
    peer_pin: Arc<SupervisorPeerPin>,
    transport: SharedHttp2Connection,
    client_config: ClientConfig,
    org_id: String,
    environment_id: String,
}

async fn connect_target(
    config: &NativeRuntimeConfig,
    target: &str,
) -> Result<ConnectedTarget, NativePublicClientError> {
    let supervisor = NativeSupervisorClient::connect_or_start(config).await?;
    let authority: http::Uri = LOCAL_AUTHORITY
        .parse()
        .map_err(|_| NativePublicClientError::Configuration)?;
    let transport = Http2Connection::connect_with_connector(
        supervisor_peer_connector(supervisor.supervisor_peer_pin()),
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
    let environment = select_environment(listed.environments, target)?;
    if environment.org_id.is_empty() || environment.id.is_empty() {
        return Err(NativePublicClientError::Protocol);
    }
    Ok(ConnectedTarget {
        peer_pin: supervisor.supervisor_peer_pin(),
        transport,
        client_config,
        org_id: environment.org_id,
        environment_id: environment.id,
    })
}

/// A UUID-shaped target is an immutable environment ID: it matches only that
/// exact ID and never falls back to, or is replaced by, a same-named
/// environment. Other targets keep name-or-ID lookup.
fn select_environment(
    environments: Vec<Environment>,
    target: &str,
) -> Result<Environment, NativePublicClientError> {
    let id_only = uuid::Uuid::parse_str(target).is_ok();
    environments
        .into_iter()
        .find(|environment| environment.id == target || !id_only && environment.name == target)
        .ok_or(NativePublicClientError::NotFound)
}

fn required_session(
    session: Option<EnvironmentSession>,
) -> Result<EnvironmentSession, NativePublicClientError> {
    session.ok_or(NativePublicClientError::Protocol)
}

fn validate_exec_with_stdin(
    stdin_len: usize,
    timeout: Duration,
) -> Result<(), NativePublicClientError> {
    if stdin_len > MAXIMUM_EXEC_STDIN_BYTES {
        return Err(NativePublicClientError::InvalidRequest(
            "stdin must not exceed 512 KiB",
        ));
    }
    if !(MINIMUM_EXEC_TIMEOUT..=MAXIMUM_EXEC_TIMEOUT).contains(&timeout) {
        return Err(NativePublicClientError::InvalidRequest(
            "timeout must be between 1 and 120 seconds",
        ));
    }
    Ok(())
}

/// One non-TTY Run: start, bounded stdin chunks, then an explicit stdin close.
fn run_requests(start: RunStart, stdin: &[u8]) -> impl Iterator<Item = RunRequest> + '_ {
    std::iter::once(run_request::Input::Start(Box::new(start)))
        .chain(
            stdin
                .chunks(STDIN_CHUNK_BYTES)
                .map(|chunk| run_request::Input::Stdin(chunk.to_vec())),
        )
        .chain(std::iter::once(run_request::Input::CloseStdin(
            Box::default(),
        )))
        .map(|input| RunRequest {
            input: Some(input),
            ..Default::default()
        })
}

#[derive(Default)]
struct RunOutput {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl RunOutput {
    /// Accept one event, returning the exit code when the terminal exit
    /// arrives. Output past the combined bound fails rather than truncates.
    fn accept(&mut self, response: RunResponse) -> Result<Option<i32>, NativePublicClientError> {
        let total = self.stdout.len() + self.stderr.len();
        let (target, data) = match response.event {
            Some(run_response::Event::Stdout(data)) => (&mut self.stdout, data),
            Some(run_response::Event::Stderr(data)) => (&mut self.stderr, data),
            Some(run_response::Event::ExitCode(exit_code)) => return Ok(Some(exit_code)),
            None => return Err(NativePublicClientError::Protocol),
        };
        if total.saturating_add(data.len()) > MAXIMUM_EXEC_OUTPUT_BYTES {
            return Err(NativePublicClientError::ExecOutputLimit);
        }
        target.extend(data);
        Ok(None)
    }

    fn finish(self, exit_code: i32) -> ExecResponse {
        ExecResponse {
            exit_code,
            stdout: self.stdout,
            stderr: self.stderr,
            ..Default::default()
        }
    }
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
    #[error("local exec request is invalid: {0}")]
    InvalidRequest(&'static str),
    #[error("local exec output exceeded 5 MiB")]
    ExecOutputLimit,
    #[error("local exec did not finish before its deadline; its outcome is unknown")]
    ExecTimeout,
    #[error(transparent)]
    Supervisor(#[from] SupervisorError),
    #[error(transparent)]
    Socket(#[from] UdsError),
    #[error(transparent)]
    Rpc(#[from] connectrpc::ConnectError),
    #[error(transparent)]
    Client(#[from] ClientError),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(event: run_response::Event) -> RunResponse {
        RunResponse {
            event: Some(event),
            ..Default::default()
        }
    }

    #[test]
    fn run_output_keeps_streams_separate_until_exit() {
        let mut output = RunOutput::default();
        for response in [
            event(run_response::Event::Stdout(b"out-1 ".to_vec())),
            event(run_response::Event::Stderr(b"err".to_vec())),
            event(run_response::Event::Stdout(b"out-2".to_vec())),
        ] {
            assert_eq!(output.accept(response).expect("output event"), None);
        }
        let exit_code = output
            .accept(event(run_response::Event::ExitCode(7)))
            .expect("exit event");
        assert_eq!(exit_code, Some(7));
        let response = output.finish(7);
        assert_eq!(response.exit_code, 7);
        assert_eq!(response.stdout, b"out-1 out-2");
        assert_eq!(response.stderr, b"err");
    }

    #[test]
    fn run_output_rejects_an_empty_event() {
        let mut output = RunOutput::default();
        assert!(matches!(
            output.accept(RunResponse::default()),
            Err(NativePublicClientError::Protocol)
        ));
    }

    #[test]
    fn run_output_fails_past_the_combined_bound_instead_of_truncating() {
        let mut output = RunOutput::default();
        let half = MAXIMUM_EXEC_OUTPUT_BYTES / 2;
        output
            .accept(event(run_response::Event::Stdout(vec![b'o'; half])))
            .expect("stdout within bound");
        output
            .accept(event(run_response::Event::Stderr(vec![b'e'; half])))
            .expect("combined output at bound");
        assert!(matches!(
            output.accept(event(run_response::Event::Stdout(vec![b'x']))),
            Err(NativePublicClientError::ExecOutputLimit)
        ));
        assert_eq!(
            output.stdout.len() + output.stderr.len(),
            MAXIMUM_EXEC_OUTPUT_BYTES
        );
    }

    #[test]
    fn run_requests_start_then_bounded_stdin_then_close() {
        let stdin: Vec<u8> = (0..STDIN_CHUNK_BYTES * 2 + 3)
            .map(|index| index as u8)
            .collect();
        let start = RunStart {
            command: vec!["cat".to_owned()],
            ..Default::default()
        };
        let requests: Vec<_> = run_requests(start, &stdin)
            .map(|request| request.input.expect("request input"))
            .collect();
        assert_eq!(requests.len(), 5);
        assert!(matches!(
            &requests[0],
            run_request::Input::Start(start) if !start.allocate_tty && start.command == ["cat"]
        ));
        assert!(matches!(
            requests.last(),
            Some(run_request::Input::CloseStdin(_))
        ));
        let mut sent = Vec::new();
        for input in &requests[1..requests.len() - 1] {
            let run_request::Input::Stdin(chunk) = input else {
                panic!("stdin chunk expected");
            };
            assert!(!chunk.is_empty() && chunk.len() <= STDIN_CHUNK_BYTES);
            sent.extend_from_slice(chunk);
        }
        assert_eq!(sent, stdin);

        let empty: Vec<_> = run_requests(RunStart::default(), &[])
            .map(|request| request.input.expect("request input"))
            .collect();
        assert!(matches!(
            empty.as_slice(),
            [
                run_request::Input::Start(_),
                run_request::Input::CloseStdin(_)
            ]
        ));
    }

    const OLD_ID: &str = "0f8e5c1a-3b2d-4c6e-9a7f-112233445566";
    const LIVE_ID: &str = "7c9d2e4f-5a6b-4c8d-9e0f-aabbccddeeff";

    fn environment(id: &str, name: &str) -> Environment {
        Environment {
            id: id.to_owned(),
            name: name.to_owned(),
            org_id: "org".to_owned(),
            ..Default::default()
        }
    }

    #[test]
    fn uuid_target_never_resolves_to_an_environment_named_as_a_missing_id() {
        let environments = vec![environment(LIVE_ID, OLD_ID)];
        assert!(matches!(
            select_environment(environments, OLD_ID),
            Err(NativePublicClientError::NotFound)
        ));
    }

    #[test]
    fn uuid_target_selects_its_exact_id_over_an_earlier_same_named_environment() {
        let environments = vec![environment(OLD_ID, LIVE_ID), environment(LIVE_ID, "dev")];
        let selected = select_environment(environments, LIVE_ID).expect("exact ID");
        assert_eq!(
            (selected.id.as_str(), selected.name.as_str()),
            (LIVE_ID, "dev")
        );
    }

    #[test]
    fn non_uuid_target_keeps_name_or_id_lookup() {
        let environments = || vec![environment(LIVE_ID, "dev"), environment("local-1", "other")];
        let by_name = select_environment(environments(), "dev").expect("name");
        assert_eq!(by_name.id, LIVE_ID);
        let by_id = select_environment(environments(), "local-1").expect("non-UUID ID");
        assert_eq!(by_id.name, "other");
        assert!(matches!(
            select_environment(environments(), "missing"),
            Err(NativePublicClientError::NotFound)
        ));
    }

    #[test]
    fn exec_with_stdin_preserves_escaped_managed_envelope_in_bounded_run_frames() {
        let text = "\u{1}".repeat(64 * 1024);
        let request = serde_json::json!({
            "op": "queue",
            "driver_id": OLD_ID,
            "session_id": format!("session-{OLD_ID}"),
            "message_id": LIVE_ID,
            "action": "message",
            "text": text,
        });
        let stdin = serde_json::to_vec(&request).unwrap();
        assert!(stdin.len() > 256 * 1024);
        validate_exec_with_stdin(stdin.len(), Duration::from_secs(30))
            .expect("legal escaped managed request is admitted before transport");
        let command = vec![
            "/synthetic/retained-cw".to_owned(),
            "_agent-control".to_owned(),
        ];
        let start = RunStart {
            command: command.clone(),
            working_dir: "/workspace".into(),
            allocate_tty: false,
            ..Default::default()
        };
        let inputs: Vec<_> = run_requests(start, &stdin)
            .map(|frame| frame.input.expect("Run input"))
            .collect();
        assert_eq!(inputs.len(), stdin.len().div_ceil(STDIN_CHUNK_BYTES) + 2);
        assert!(matches!(
            &inputs[0],
            run_request::Input::Start(start)
                if !start.allocate_tty && start.command == command && start.working_dir == "/workspace"
        ));
        assert!(matches!(
            inputs.last(),
            Some(run_request::Input::CloseStdin(_))
        ));
        assert_eq!(
            inputs
                .iter()
                .filter(|input| matches!(input, run_request::Input::CloseStdin(_)))
                .count(),
            1
        );
        let mut received = Vec::new();
        for input in &inputs[1..inputs.len() - 1] {
            let run_request::Input::Stdin(chunk) = input else {
                panic!("only stdin chunks may occur before the explicit close");
            };
            assert!(!chunk.is_empty() && chunk.len() <= 64 * 1024);
            received.extend_from_slice(chunk);
        }
        assert_eq!(received, stdin);
        let decoded: serde_json::Value = serde_json::from_slice(&received).unwrap();
        assert_eq!(decoded, request);
        assert_eq!(
            decoded["text"].as_str().unwrap().as_bytes(),
            text.as_bytes()
        );
    }

    #[test]
    fn exec_with_stdin_bounds_input_and_deadline() {
        let valid = Duration::from_secs(30);
        validate_exec_with_stdin(MAXIMUM_EXEC_STDIN_BYTES, valid).expect("input at bound");
        validate_exec_with_stdin(0, MINIMUM_EXEC_TIMEOUT).expect("minimum deadline");
        validate_exec_with_stdin(0, MAXIMUM_EXEC_TIMEOUT).expect("maximum deadline");
        for (stdin_len, timeout) in [
            (MAXIMUM_EXEC_STDIN_BYTES + 1, valid),
            (0, Duration::ZERO),
            (0, Duration::from_millis(999)),
            (0, MAXIMUM_EXEC_TIMEOUT + Duration::from_nanos(1)),
            (0, Duration::MAX),
        ] {
            assert!(matches!(
                validate_exec_with_stdin(stdin_len, timeout),
                Err(NativePublicClientError::InvalidRequest(_))
            ));
        }
    }
}
