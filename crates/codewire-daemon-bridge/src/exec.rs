//! Shared public `ExecService` adapter for the private guest daemon.
//!
//! Platform and local backends own coordinate authorization and daemon
//! discovery. This module owns public validation, timeout behavior, private
//! framing, byte-preserving conversion, backpressure, and half-close behavior.

use std::sync::Arc;
use std::time::Duration as StdDuration;

use async_trait::async_trait;
use buffa_types::Duration;
use codewire_proto::codewire::v1 as proto;
use connectrpc::{InboundStream, RequestContext, ServiceRequest, ServiceResult, ServiceStream};
use futures::StreamExt as _;
use tokio::sync::mpsc;

use crate::client::{
    DaemonClient, DaemonClientError, DaemonRunInput, DaemonRunOutput, DaemonRunSession,
    DaemonRunStart,
};
use crate::drain::Restart;
use crate::session::FieldViolation;

const STREAM_BUFFER: usize = 32;
/// Ending the stream ends the command (the daemon stops its process group),
/// so the client is told to run it again.
const COMMAND_RESTARTED: &str =
    "Codewire restarted the server running this command, which stopped it; run it again";
const DEFAULT_EXEC_TIMEOUT: StdDuration = StdDuration::from_secs(600);
// Keep the base64-expanded ProtoJSON response below Connect's default 4 MiB
// message ceiling as well as keeping the protobuf response bounded.
const MAX_UNARY_EXEC_OUTPUT_BYTES: usize = 3 * 1024 * 1024 - 64 * 1024;

#[async_trait]
pub trait ExecBackend: Clone + Send + Sync + 'static {
    /// Completes when this server reaches `restart` (#4426). `None`, the
    /// default, for a server that never drains, as the local supervisor.
    fn server_restart(
        &self,
        _restart: crate::drain::Restart,
    ) -> Option<crate::drain::RestartSignal> {
        None
    }

    fn authorize(&self, ctx: &RequestContext) -> Result<(), connectrpc::ConnectError>;

    fn validation_error(
        &self,
        violations: Vec<FieldViolation>,
        request_id: Option<&str>,
    ) -> connectrpc::ConnectError;

    fn daemon_error(
        &self,
        error: DaemonClientError,
        request_id: Option<&str>,
    ) -> connectrpc::ConnectError;

    fn timeout_error(&self, request_id: Option<&str>) -> connectrpc::ConnectError;

    fn output_limit_error(&self, request_id: Option<&str>) -> connectrpc::ConnectError;

    fn invalid_daemon_frame(&self, request_id: Option<&str>) -> connectrpc::ConnectError;

    async fn daemon(
        &self,
        ctx: &RequestContext,
        org_id: &str,
        environment_id: &str,
    ) -> Result<DaemonClient, connectrpc::ConnectError>;
}

#[derive(Clone)]
pub struct ExecBridge<B> {
    backend: B,
}

impl<B> ExecBridge<B> {
    pub fn new(backend: B) -> Self {
        Self { backend }
    }
}

pub fn router<B>(backend: B) -> connectrpc::Router
where
    B: ExecBackend,
{
    connectrpc::Router::new().add_service(Arc::new(ExecBridge::new(backend)))
}

#[allow(refining_impl_trait)]
impl<B> proto::ExecService for ExecBridge<B>
where
    B: ExecBackend,
{
    async fn exec(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::ExecRequest>,
    ) -> ServiceResult<proto::ExecResponse> {
        self.backend.authorize(&ctx)?;
        let request_id = request_id(&ctx);
        let request = request.to_owned_message();
        let violations = exec_violations(
            &request.org_id,
            &request.environment_id,
            &request.command,
            "/org_id",
            "/environment_id",
            "/command",
        );
        if !violations.is_empty() {
            return Err(self.backend.validation_error(violations, request_id));
        }
        let timeout = exec_timeout(request.timeout.into_option())
            .map_err(|violations| self.backend.validation_error(violations, request_id))?;
        let daemon = self
            .backend
            .daemon(&ctx, &request.org_id, &request.environment_id)
            .await?;
        let start = daemon_start(
            request.command,
            request.working_dir,
            request.env,
            false,
            String::new(),
            0,
            0,
        );
        let mut session = daemon
            .start_run(start)
            .await
            .map_err(|error| self.backend.daemon_error(error, request_id))?;
        session
            .send_input(DaemonRunInput::CloseStdin)
            .await
            .map_err(|error| self.backend.daemon_error(error, request_id))?;

        let backend = self.backend.clone();
        let result = tokio::time::timeout(timeout, async move {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            loop {
                match session.next_output().await {
                    Ok(Some(DaemonRunOutput::Stdout(data))) => {
                        if !extend_unary_output(&mut stdout, &stderr, &data) {
                            return Err(backend.output_limit_error(request_id));
                        }
                    }
                    Ok(Some(DaemonRunOutput::Stderr(data))) => {
                        if !extend_unary_output(&mut stderr, &stdout, &data) {
                            return Err(backend.output_limit_error(request_id));
                        }
                    }
                    Ok(Some(DaemonRunOutput::Exit(exit_code))) => {
                        return Ok(proto::ExecResponse {
                            exit_code,
                            stdout,
                            stderr,
                            ..Default::default()
                        });
                    }
                    Ok(None) => return Err(backend.invalid_daemon_frame(request_id)),
                    Err(error) => return Err(backend.daemon_error(error, request_id)),
                }
            }
        })
        .await
        .map_err(|_| self.backend.timeout_error(request_id))??;
        connectrpc::Response::ok(result)
    }

    async fn stream_exec(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::StreamExecRequest>,
    ) -> ServiceResult<ServiceStream<proto::StreamExecResponse>> {
        self.backend.authorize(&ctx)?;
        let request_id = owned_request_id(&ctx);
        let request = request.to_owned_message();
        let violations = exec_violations(
            &request.org_id,
            &request.environment_id,
            &request.command,
            "/org_id",
            "/environment_id",
            "/command",
        );
        if !violations.is_empty() {
            return Err(self
                .backend
                .validation_error(violations, request_id.as_deref()));
        }
        let daemon = self
            .backend
            .daemon(&ctx, &request.org_id, &request.environment_id)
            .await?;
        let session = daemon
            .start_run(daemon_start(
                request.command,
                request.working_dir,
                request.env,
                false,
                String::new(),
                0,
                0,
            ))
            .await
            .map_err(|error| self.backend.daemon_error(error, request_id.as_deref()))?;
        session
            .send_input(DaemonRunInput::CloseStdin)
            .await
            .map_err(|error| self.backend.daemon_error(error, request_id.as_deref()))?;

        let (tx, rx) = mpsc::channel(STREAM_BUFFER);
        tokio::spawn(relay_stream_exec(
            session,
            self.backend.clone(),
            request_id,
            tx,
        ));
        connectrpc::Response::stream_ok(crate::drain::end_at(
            receiver_stream(rx),
            self.backend.server_restart(Restart::Deadline),
            COMMAND_RESTARTED,
        ))
    }

    async fn run(
        &self,
        ctx: RequestContext,
        mut requests: InboundStream<proto::RunRequest>,
    ) -> ServiceResult<ServiceStream<proto::RunResponse>> {
        self.backend.authorize(&ctx)?;
        let request_id = owned_request_id(&ctx);
        let first = requests
            .next()
            .await
            .ok_or_else(|| {
                self.backend.validation_error(
                    vec![FieldViolation {
                        path: "/start",
                        message: "must be the first message",
                    }],
                    request_id.as_deref(),
                )
            })??
            .to_owned_message();
        let start = match first.input {
            Some(proto::run_request::Input::Start(start)) => *start,
            _ => {
                return Err(self.backend.validation_error(
                    vec![FieldViolation {
                        path: "/start",
                        message: "must be the first message",
                    }],
                    request_id.as_deref(),
                ));
            }
        };
        let violations = exec_violations(
            &start.org_id,
            &start.environment_id,
            &start.command,
            "/start/org_id",
            "/start/environment_id",
            "/start/command",
        );
        if !violations.is_empty() {
            return Err(self
                .backend
                .validation_error(violations, request_id.as_deref()));
        }
        let timeout = run_timeout(start.timeout.clone().into_option()).map_err(|violations| {
            self.backend
                .validation_error(violations, request_id.as_deref())
        })?;
        let daemon = self
            .backend
            .daemon(&ctx, &start.org_id, &start.environment_id)
            .await?;
        let session = daemon
            .start_run(daemon_start(
                start.command,
                start.working_dir,
                start.env,
                start.allocate_tty,
                start.term,
                terminal_dimension(start.columns),
                terminal_dimension(start.rows),
            ))
            .await
            .map_err(|error| self.backend.daemon_error(error, request_id.as_deref()))?;

        let (tx, rx) = mpsc::channel(STREAM_BUFFER);
        tokio::spawn(relay_run(
            requests,
            session,
            timeout,
            self.backend.clone(),
            request_id,
            tx,
        ));
        connectrpc::Response::stream_ok(crate::drain::end_at(
            receiver_stream(rx),
            self.backend.server_restart(Restart::Deadline),
            COMMAND_RESTARTED,
        ))
    }
}

async fn relay_stream_exec<B: ExecBackend>(
    mut session: DaemonRunSession,
    backend: B,
    request_id: Option<String>,
    tx: mpsc::Sender<Result<proto::StreamExecResponse, connectrpc::ConnectError>>,
) {
    loop {
        let output = tokio::select! {
            // Nobody reads the output any more: dropping the daemon session
            // ends the command, as relay_run does.
            () = tx.closed() => return,
            output = session.next_output() => output,
        };
        let message = match output {
            Ok(Some(output)) => stream_output(output),
            Ok(None) => Err(backend.invalid_daemon_frame(request_id.as_deref())),
            Err(error) => Err(backend.daemon_error(error, request_id.as_deref())),
        };
        let terminal = matches!(
            &message,
            Ok(proto::StreamExecResponse {
                event: Some(proto::stream_exec_response::Event::ExitCode(_)),
                ..
            })
        ) || message.is_err();
        if tx.send(message).await.is_err() || terminal {
            return;
        }
    }
}

async fn relay_run<B: ExecBackend>(
    mut requests: InboundStream<proto::RunRequest>,
    mut session: DaemonRunSession,
    timeout: Option<StdDuration>,
    backend: B,
    request_id: Option<String>,
    tx: mpsc::Sender<Result<proto::RunResponse, connectrpc::ConnectError>>,
) {
    let mut deadline = timeout.map(|timeout| Box::pin(tokio::time::sleep(timeout)));
    let mut requests_open = true;
    loop {
        tokio::select! {
            // Nobody reads the output any more: the client went away, which a
            // half-close of its requests cannot show. Dropping the daemon
            // session without CloseStdin ends the command, as it would have
            // the first time the command wrote anything.
            () = tx.closed() => return,
            _ = async {
                match deadline.as_mut() {
                    Some(deadline) => deadline.as_mut().await,
                    None => std::future::pending::<()>().await,
                }
            } => {
                let _ = tx.send(Err(backend.timeout_error(request_id.as_deref()))).await;
                return;
            }
            request = requests.next(), if requests_open => {
                let input = match request {
                    Some(Ok(request)) => match run_input(request.to_owned_message()) {
                        Ok(input) => input,
                        Err(violations) => {
                            let error = backend.validation_error(violations, request_id.as_deref());
                            let _ = tx.send(Err(error)).await;
                            return;
                        }
                    },
                    Some(Err(error)) => {
                        let _ = tx.send(Err(error)).await;
                        return;
                    }
                    None => {
                        requests_open = false;
                        if let Err(error) = session.send_input(DaemonRunInput::CloseStdin).await {
                            let error = backend.daemon_error(error, request_id.as_deref());
                            let _ = tx.send(Err(error)).await;
                            return;
                        }
                        continue;
                    }
                };
                if let Err(error) = session.send_input(input).await {
                    let error = backend.daemon_error(error, request_id.as_deref());
                    let _ = tx.send(Err(error)).await;
                    return;
                }
            }
            output = session.next_output() => {
                let message = match output {
                    Ok(Some(output)) => run_output(output),
                    Ok(None) => Err(backend.invalid_daemon_frame(request_id.as_deref())),
                    Err(error) => Err(backend.daemon_error(error, request_id.as_deref())),
                };
                let exit = matches!(
                    &message,
                    Ok(proto::RunResponse {
                        event: Some(proto::run_response::Event::ExitCode(_)),
                        ..
                    })
                );
                let terminal = exit || message.is_err();
                if tx.send(message).await.is_err() || terminal && !exit {
                    return;
                }
                if exit {
                    while requests_open {
                        match requests.next().await {
                            Some(Ok(_)) => {}
                            Some(Err(_)) | None => requests_open = false,
                        }
                    }
                    return;
                }
            }
        }
    }
}

fn daemon_start(
    command: Vec<String>,
    working_dir: String,
    env: impl IntoIterator<Item = (String, String)>,
    allocate_tty: bool,
    term: String,
    columns: i32,
    rows: i32,
) -> DaemonRunStart {
    DaemonRunStart {
        command,
        working_dir,
        env: env
            .into_iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect(),
        allocate_tty,
        term,
        columns,
        rows,
    }
}

fn exec_violations(
    org_id: &str,
    environment_id: &str,
    command: &[String],
    org_path: &'static str,
    environment_path: &'static str,
    command_path: &'static str,
) -> Vec<FieldViolation> {
    let mut violations = Vec::new();
    if org_id.trim().is_empty() {
        violations.push(FieldViolation {
            path: org_path,
            message: "must not be empty",
        });
    }
    if environment_id.trim().is_empty() {
        violations.push(FieldViolation {
            path: environment_path,
            message: "must not be empty",
        });
    }
    if command.is_empty() {
        violations.push(FieldViolation {
            path: command_path,
            message: "must not be empty",
        });
    }
    violations
}

fn exec_timeout(timeout: Option<Duration>) -> Result<StdDuration, Vec<FieldViolation>> {
    let Some(timeout) = timeout else {
        return Ok(DEFAULT_EXEC_TIMEOUT);
    };
    let timeout = StdDuration::try_from(timeout).map_err(|_| {
        vec![FieldViolation {
            path: "/timeout",
            message: "must be a valid non-negative duration",
        }]
    })?;
    Ok(if timeout.is_zero() {
        DEFAULT_EXEC_TIMEOUT
    } else {
        timeout
    })
}

fn run_timeout(timeout: Option<Duration>) -> Result<Option<StdDuration>, Vec<FieldViolation>> {
    let Some(timeout) = timeout else {
        return Ok(None);
    };
    let timeout = StdDuration::try_from(timeout).map_err(|_| {
        vec![FieldViolation {
            path: "/start/timeout",
            message: "must be a valid non-negative duration",
        }]
    })?;
    Ok((!timeout.is_zero()).then_some(timeout))
}

fn run_input(request: proto::RunRequest) -> Result<DaemonRunInput, Vec<FieldViolation>> {
    match request.input {
        Some(proto::run_request::Input::Stdin(data)) => Ok(DaemonRunInput::Stdin(data)),
        Some(proto::run_request::Input::Resize(resize)) => Ok(DaemonRunInput::Resize {
            columns: terminal_dimension(resize.columns),
            rows: terminal_dimension(resize.rows),
        }),
        Some(proto::run_request::Input::CloseStdin(_)) => Ok(DaemonRunInput::CloseStdin),
        Some(proto::run_request::Input::Start(_)) => Err(vec![FieldViolation {
            path: "/start",
            message: "may only be sent once",
        }]),
        None => Err(vec![FieldViolation {
            path: "/input",
            message: "is required",
        }]),
    }
}

fn extend_unary_output(target: &mut Vec<u8>, other: &[u8], data: &[u8]) -> bool {
    let Some(total) = target
        .len()
        .checked_add(other.len())
        .and_then(|total| total.checked_add(data.len()))
    else {
        return false;
    };
    if total > MAX_UNARY_EXEC_OUTPUT_BYTES {
        return false;
    }
    target.extend_from_slice(data);
    true
}

fn stream_output(
    output: DaemonRunOutput,
) -> Result<proto::StreamExecResponse, connectrpc::ConnectError> {
    use proto::stream_exec_response::Event;
    let event = match output {
        DaemonRunOutput::Stdout(data) => Event::Stdout(data),
        DaemonRunOutput::Stderr(data) => Event::Stderr(data),
        DaemonRunOutput::Exit(code) => Event::ExitCode(code),
    };
    Ok(proto::StreamExecResponse {
        event: Some(event),
        ..Default::default()
    })
}

fn run_output(output: DaemonRunOutput) -> Result<proto::RunResponse, connectrpc::ConnectError> {
    use proto::run_response::Event;
    let event = match output {
        DaemonRunOutput::Stdout(data) => Event::Stdout(data),
        DaemonRunOutput::Stderr(data) => Event::Stderr(data),
        DaemonRunOutput::Exit(code) => Event::ExitCode(code),
    };
    Ok(proto::RunResponse {
        event: Some(event),
        ..Default::default()
    })
}

fn terminal_dimension(value: u32) -> i32 {
    i32::try_from(value).unwrap_or(i32::MAX)
}

fn request_id(ctx: &RequestContext) -> Option<&str> {
    ctx.headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
}

fn owned_request_id(ctx: &RequestContext) -> Option<String> {
    request_id(ctx).map(str::to_owned)
}

fn receiver_stream<T: Send + 'static>(
    rx: mpsc::Receiver<Result<T, connectrpc::ConnectError>>,
) -> impl futures::Stream<Item = Result<T, connectrpc::ConnectError>> + Send + 'static {
    futures::stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|item| (item, rx))
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::test_support::DaemonHarness;
    use buffa::{HasMessageView as _, Message as _};

    #[derive(Clone)]
    struct TestBackend {
        daemon: DaemonClient,
        deny_authorization: bool,
    }

    #[async_trait::async_trait]
    impl ExecBackend for TestBackend {
        fn authorize(&self, _ctx: &RequestContext) -> Result<(), connectrpc::ConnectError> {
            if self.deny_authorization {
                Err(connectrpc::ConnectError::unauthenticated(
                    "test authorization required",
                ))
            } else {
                Ok(())
            }
        }

        fn validation_error(
            &self,
            _violations: Vec<FieldViolation>,
            _request_id: Option<&str>,
        ) -> connectrpc::ConnectError {
            connectrpc::ConnectError::invalid_argument("invalid test request")
        }

        fn daemon_error(
            &self,
            _error: DaemonClientError,
            _request_id: Option<&str>,
        ) -> connectrpc::ConnectError {
            connectrpc::ConnectError::internal("test daemon request failed")
        }

        fn timeout_error(&self, _request_id: Option<&str>) -> connectrpc::ConnectError {
            connectrpc::ConnectError::deadline_exceeded("test command timed out")
        }

        fn output_limit_error(&self, _request_id: Option<&str>) -> connectrpc::ConnectError {
            connectrpc::ConnectError::resource_exhausted("test command output limit exceeded")
        }

        fn invalid_daemon_frame(&self, _request_id: Option<&str>) -> connectrpc::ConnectError {
            connectrpc::ConnectError::internal("invalid test daemon frame")
        }

        async fn daemon(
            &self,
            _ctx: &RequestContext,
            _org_id: &str,
            _environment_id: &str,
        ) -> Result<DaemonClient, connectrpc::ConnectError> {
            Ok(self.daemon.clone())
        }
    }

    #[test]
    fn validation_paths_match_public_messages() {
        assert_eq!(
            exec_violations("", "", &[], "/org_id", "/environment_id", "/command"),
            vec![
                FieldViolation {
                    path: "/org_id",
                    message: "must not be empty",
                },
                FieldViolation {
                    path: "/environment_id",
                    message: "must not be empty",
                },
                FieldViolation {
                    path: "/command",
                    message: "must not be empty",
                },
            ]
        );
    }

    #[test]
    fn output_conversion_preserves_binary_bytes_and_exit() {
        use proto::run_response::Event;
        assert_eq!(
            run_output(DaemonRunOutput::Stdout(vec![0xff, 0x00]))
                .expect("stdout")
                .event,
            Some(Event::Stdout(vec![0xff, 0x00]))
        );
        assert_eq!(
            run_output(DaemonRunOutput::Exit(23)).expect("exit").event,
            Some(Event::ExitCode(23))
        );
    }

    #[test]
    fn unary_output_is_bounded_below_the_default_connect_message_limit() {
        let mut stdout = vec![0; MAX_UNARY_EXEC_OUTPUT_BYTES - 2];
        let stderr = vec![1];
        assert!(extend_unary_output(&mut stdout, &stderr, &[2]));
        assert!(!extend_unary_output(&mut stdout, &stderr, &[3]));
        assert_eq!(stdout.len(), MAX_UNARY_EXEC_OUTPUT_BYTES - 1);
    }

    #[test]
    fn every_generated_exec_route_is_owned_by_the_bridge() {
        let expected = [
            proto::EXEC_SERVICE_EXEC_SPEC,
            proto::EXEC_SERVICE_STREAM_EXEC_SPEC,
            proto::EXEC_SERVICE_RUN_SPEC,
        ]
        .into_iter()
        .map(|spec| spec.method().to_owned())
        .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            crate::test_support::public_service_methods("ExecService"),
            expected
        );
        assert_eq!(expected.len(), 3);
    }

    #[tokio::test]
    async fn authorization_precedes_exec_validation() {
        let harness = DaemonHarness::spawn().await;
        let bridge = ExecBridge::new(TestBackend {
            daemon: harness.client().await,
            deny_authorization: true,
        });
        let message = proto::ExecRequest::default();
        let body = bytes::Bytes::from(message.encode_to_vec());
        let view = proto::ExecRequest::decode_view(&body).expect("decode exec view");
        let error = proto::ExecService::exec(
            &bridge,
            RequestContext::default(),
            ServiceRequest::from_parts(&view, &body),
        )
        .await
        .expect_err("unauthorized empty exec must fail at authorization");
        assert_eq!(error.code, connectrpc::ErrorCode::Unauthenticated);
        harness.shutdown().await;
    }

    #[tokio::test]
    async fn run_half_close_closes_stdin_and_drains_remote_output() {
        let harness = DaemonHarness::spawn().await;
        let bridge = ExecBridge::new(TestBackend {
            daemon: harness.client().await,
            deny_authorization: false,
        });
        let requests = [
            proto::RunRequest {
                input: Some(proto::run_request::Input::Start(Box::new(
                    proto::RunStart {
                        org_id: "local".into(),
                        environment_id: "environment".into(),
                        command: vec![
                            "/bin/sh".into(),
                            "-c".into(),
                            "cat; printf done >&2; exit 19".into(),
                        ],
                        working_dir: harness.workspace_root().to_string_lossy().into_owned(),
                        ..Default::default()
                    },
                ))),
                ..Default::default()
            },
            proto::RunRequest {
                input: Some(proto::run_request::Input::Stdin(b"half-close".to_vec())),
                ..Default::default()
            },
        ]
        .map(|request| Ok(connectrpc::StreamMessage::from_message(&request)));
        let response = proto::ExecService::run(
            &bridge,
            RequestContext::default(),
            Box::pin(futures::stream::iter(requests)),
        )
        .await
        .expect("open public run stream");
        let mut responses = response.body;

        let (stdout, stderr, exit) = tokio::time::timeout(Duration::from_secs(5), async {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            loop {
                match responses.next().await.expect("terminal run response") {
                    Ok(response) => match response.event {
                        Some(proto::run_response::Event::Stdout(data)) => stdout.extend(data),
                        Some(proto::run_response::Event::Stderr(data)) => stderr.extend(data),
                        Some(proto::run_response::Event::ExitCode(code)) => {
                            break (stdout, stderr, code);
                        }
                        None => panic!("empty run response"),
                    },
                    Err(error) => panic!("run response failed: {error:?}"),
                }
            }
        })
        .await
        .expect("run half-close deadline");
        assert_eq!(stdout, b"half-close");
        assert_eq!(stderr, b"done");
        assert_eq!(exit, 19);

        drop(responses);
        harness.shutdown().await;
    }

    #[tokio::test]
    async fn run_ends_a_quiet_command_when_its_client_goes_away() {
        let harness = DaemonHarness::spawn().await;
        let bridge = ExecBridge::new(TestBackend {
            daemon: harness.client().await,
            deny_authorization: false,
        });
        let pid_file = harness.workspace_root().join("quiet.pid");
        let requests = [proto::RunRequest {
            input: Some(proto::run_request::Input::Start(Box::new(
                proto::RunStart {
                    org_id: "local".into(),
                    environment_id: "environment".into(),
                    command: vec![
                        "/bin/sh".into(),
                        "-c".into(),
                        "echo $$ > quiet.pid; exec sleep 300".into(),
                    ],
                    working_dir: harness.workspace_root().to_string_lossy().into_owned(),
                    ..Default::default()
                },
            ))),
            ..Default::default()
        }]
        .map(|request| Ok(connectrpc::StreamMessage::from_message(&request)));
        // The requests end at once, as a client's half-close would; the
        // command writes nothing, so only the closed output can tell.
        let response = proto::ExecService::run(
            &bridge,
            RequestContext::default(),
            Box::pin(futures::stream::iter(requests)),
        )
        .await
        .expect("open public run stream");
        let pid = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                if let Ok(pid) = std::fs::read_to_string(&pid_file)
                    && let Ok(pid) = pid.trim().parse::<u32>()
                {
                    break pid;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the command started");
        let alive = |pid: u32| {
            std::process::Command::new("kill")
                .args(["-0", &pid.to_string()])
                .status()
                .is_ok_and(|status| status.success())
        };
        assert!(alive(pid));
        drop(response);
        tokio::time::timeout(Duration::from_secs(30), async {
            while alive(pid) {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("the quiet command ended after its client went away");
        harness.shutdown().await;
    }
}
