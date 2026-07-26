//! Connect-RPC adapter for non-interactive environment exec.
//!
//! REST and Connect call the same byte-preserving exec core. This module owns
//! protobuf duration conversion and the D12 Connect error renderer only.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use axum::http::StatusCode;
use buffa::MessageField;
use buffa_types::Duration;
use codewire_proto::codewire::v1 as proto;
use codewire_server_core::connect::{auth_user, wire_error};
use codewire_server_core::connect_error::ConnectError as RenderedConnectError;
use codewire_server_core::{AppError, AppResult, ValidationIssue};
use connectrpc::{InboundStream, RequestContext, ServiceRequest, ServiceResult, ServiceStream};
use futures::StreamExt as _;
use tokio::sync::mpsc;

use crate::api::ApiState;
use crate::api::environment_daemon::{
    EnvironmentDaemonRunInput, EnvironmentDaemonRunOutput, EnvironmentDaemonRunStart,
    start_environment_daemon_run_core,
};
use crate::api::proxy::{
    DEFAULT_EXEC_TIMEOUT_SECS, ExecInput, ExecStreamEvent, ExecStreamInput,
    exec_in_environment_core, exec_stream_in_environment_core,
};
use crate::connect::rendered_workspace_error;

/// Registers ExecService. WI-4 serves unary Exec; WI-5 replaces the explicit
/// StreamExec unimplemented response with the shared live stream source.
pub fn router(state: ApiState) -> connectrpc::Router {
    connectrpc::Router::new().add_service(Arc::new(ExecConnectService { state }))
}

struct ExecConnectService {
    state: ApiState,
}

#[allow(refining_impl_trait)]
impl proto::ExecService for ExecConnectService {
    async fn exec(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::ExecRequest>,
    ) -> ServiceResult<proto::ExecResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.to_owned_message();
        let timeout =
            proto_exec_timeout(request.timeout).map_err(|error| exec_rpc_error(&error, &ctx))?;
        let result = exec_in_environment_core(
            &self.state,
            &user,
            &request.org_id,
            &request.environment_id,
            ExecInput {
                command: request.command,
                working_dir: request.working_dir,
                env: request.env.into_iter().collect::<BTreeMap<_, _>>(),
                timeout,
            },
        )
        .await
        .map_err(|error| exec_rpc_error(&error, &ctx))?;

        connectrpc::Response::ok(proto::ExecResponse {
            exit_code: result.exit_code,
            stdout: result.stdout,
            stderr: result.stderr,
            ..Default::default()
        })
    }

    async fn stream_exec(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::StreamExecRequest>,
    ) -> ServiceResult<ServiceStream<proto::StreamExecResponse>> {
        let user = auth_user(&ctx)?.clone();
        let request = request.to_owned_message();
        let events = exec_stream_in_environment_core(
            &self.state,
            &user,
            &request.org_id,
            &request.environment_id,
            ExecStreamInput {
                command: request.command,
                working_dir: request.working_dir,
                env: request.env.into_iter().collect::<BTreeMap<_, _>>(),
            },
        )
        .await
        .map_err(|error| exec_rpc_error(&error, &ctx))?;
        let request_id = ctx
            .headers()
            .get("x-request-id")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);

        let stream = futures::stream::unfold(events, move |mut events| {
            let request_id = request_id.clone();
            async move {
                let event = events.recv().await?;
                let message = stream_exec_message(event, request_id.as_deref());
                Some((message, events))
            }
        });
        connectrpc::Response::stream_ok(stream)
    }

    async fn run(
        &self,
        ctx: RequestContext,
        mut requests: InboundStream<proto::RunRequest>,
    ) -> ServiceResult<ServiceStream<proto::RunResponse>> {
        let user = auth_user(&ctx)?.clone();
        let first = requests
            .next()
            .await
            .ok_or_else(|| connectrpc::ConnectError::invalid_argument("start is required"))??
            .to_owned_message();
        let start = match first.input {
            Some(proto::run_request::Input::Start(start)) => *start,
            _ => {
                return Err(connectrpc::ConnectError::invalid_argument(
                    "start must be the first message",
                ));
            }
        };
        validate_run_start(&start).map_err(|error| exec_rpc_error(&error, &ctx))?;
        let timeout = proto_run_timeout(start.timeout.clone())
            .map_err(|error| exec_rpc_error(&error, &ctx))?;
        let session = start_environment_daemon_run_core(
            &self.state,
            &user,
            &start.org_id,
            &start.environment_id,
            EnvironmentDaemonRunStart {
                command: start.command,
                working_dir: start.working_dir,
                env: start
                    .env
                    .into_iter()
                    .map(|(key, value)| format!("{key}={value}"))
                    .collect(),
                allocate_tty: start.allocate_tty,
                term: start.term,
                columns: terminal_dimension(start.columns),
                rows: terminal_dimension(start.rows),
            },
        )
        .await
        .map_err(|error| exec_rpc_error(&error, &ctx))?;
        let request_id = ctx
            .headers()
            .get("x-request-id")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let (tx, rx) = mpsc::channel(32);
        tokio::spawn(run_daemon_bridge(
            requests, session, timeout, request_id, tx,
        ));
        let stream = futures::stream::unfold(rx, |mut rx| async move {
            rx.recv().await.map(|item| (item, rx))
        });
        connectrpc::Response::stream_ok(stream)
    }
}

async fn run_daemon_bridge(
    mut requests: InboundStream<proto::RunRequest>,
    mut session: crate::api::environment_daemon::EnvironmentDaemonRunSession,
    timeout: Option<StdDuration>,
    request_id: Option<String>,
    tx: mpsc::Sender<Result<proto::RunResponse, connectrpc::ConnectError>>,
) {
    let mut timeout = timeout.map(|timeout| Box::pin(tokio::time::sleep(timeout)));
    loop {
        tokio::select! {
            _ = async {
                match timeout.as_mut() {
                    Some(timeout) => timeout.as_mut().await,
                    None => std::future::pending::<()>().await,
                }
            } => {
                let error = AppError::Coded {
                    status: StatusCode::GATEWAY_TIMEOUT,
                    code: "exec_timeout",
                    detail: "environment command timed out".into(),
                };
                let _ = tx.send(Err(wire_error(&rendered_exec_error(
                    &error,
                    request_id.as_deref(),
                )))).await;
                return;
            }
            request = requests.next() => {
                let input = match request {
                    Some(Ok(request)) => match run_input(request.to_owned_message()) {
                        Ok(input) => input,
                        Err(error) => {
                            let _ = tx.send(Err(error)).await;
                            return;
                        }
                    },
                    Some(Err(error)) => {
                        let _ = tx.send(Err(error)).await;
                        return;
                    }
                    None => return,
                };
                if let Err(error) = session.send_input(input).await {
                    let _ = tx.send(Err(wire_error(&rendered_exec_error(
                        &error,
                        request_id.as_deref(),
                    )))).await;
                    return;
                }
            }
            output = session.next_output() => {
                let output = match output {
                    Ok(Some(output)) => output,
                    Ok(None) => {
                        let error = AppError::Upstream(
                            "environment command ended without an exit status".into(),
                        );
                        let _ = tx.send(Err(wire_error(&rendered_exec_error(
                            &error,
                            request_id.as_deref(),
                        )))).await;
                        return;
                    }
                    Err(error) => {
                        let _ = tx.send(Err(wire_error(&rendered_exec_error(
                            &error,
                            request_id.as_deref(),
                        )))).await;
                        return;
                    }
                };
                let exit = matches!(output, EnvironmentDaemonRunOutput::Exit(_));
                if tx.send(Ok(run_output_message(output))).await.is_err() {
                    return;
                }
                if exit {
                    // Keep the response open until the client half-closes its
                    // bidi request.  Returning immediately after ExitCode
                    // drops the inbound HTTP/1.1 body at ingress and can
                    // leave the next command on a reset keep-alive socket.
                    // Inputs after the remote process has exited carry no
                    // further effect; they are drained only to complete the
                    // transport lifecycle cleanly.
                    while let Some(request) = requests.next().await {
                        if request.is_err() {
                            return;
                        }
                    }
                    return;
                }
            }
        }
    }
}

fn run_input(
    request: proto::RunRequest,
) -> Result<EnvironmentDaemonRunInput, connectrpc::ConnectError> {
    match request.input {
        Some(proto::run_request::Input::Stdin(data)) => Ok(EnvironmentDaemonRunInput::Stdin(data)),
        Some(proto::run_request::Input::Resize(resize)) => Ok(EnvironmentDaemonRunInput::Resize {
            columns: terminal_dimension(resize.columns),
            rows: terminal_dimension(resize.rows),
        }),
        Some(proto::run_request::Input::CloseStdin(_)) => Ok(EnvironmentDaemonRunInput::CloseStdin),
        Some(proto::run_request::Input::Start(_)) => Err(
            connectrpc::ConnectError::invalid_argument("start may only be sent once"),
        ),
        None => Err(connectrpc::ConnectError::invalid_argument(
            "run input is required",
        )),
    }
}

fn run_output_message(output: EnvironmentDaemonRunOutput) -> proto::RunResponse {
    use proto::run_response::Event;

    let event = match output {
        EnvironmentDaemonRunOutput::Stdout(data) => Event::Stdout(data),
        EnvironmentDaemonRunOutput::Stderr(data) => Event::Stderr(data),
        EnvironmentDaemonRunOutput::Exit(code) => Event::ExitCode(code),
    };
    proto::RunResponse {
        event: Some(event),
        ..Default::default()
    }
}

fn validate_run_start(start: &proto::RunStart) -> AppResult<()> {
    let mut errors = Vec::new();
    if start.org_id.trim().is_empty() {
        errors.push(ValidationIssue {
            path: Cow::Borrowed("/start/org_id"),
            message: Cow::Borrowed("must not be empty"),
        });
    }
    if start.environment_id.trim().is_empty() {
        errors.push(ValidationIssue {
            path: Cow::Borrowed("/start/environment_id"),
            message: Cow::Borrowed("must not be empty"),
        });
    }
    if start.command.is_empty() {
        errors.push(ValidationIssue {
            path: Cow::Borrowed("/start/command"),
            message: Cow::Borrowed("must not be empty"),
        });
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(AppError::Validation { errors })
    }
}

fn proto_run_timeout(timeout: MessageField<Duration>) -> AppResult<Option<StdDuration>> {
    let Some(timeout) = timeout.into_option() else {
        return Ok(None);
    };
    let timeout = StdDuration::try_from(timeout).map_err(|error| AppError::Validation {
        errors: vec![ValidationIssue {
            path: Cow::Borrowed("/start/timeout"),
            message: Cow::Owned(error.to_string()),
        }],
    })?;
    Ok((!timeout.is_zero()).then_some(timeout))
}

fn terminal_dimension(value: u32) -> i32 {
    i32::try_from(value).unwrap_or(i32::MAX)
}

fn stream_exec_message(
    event: ExecStreamEvent,
    request_id: Option<&str>,
) -> Result<proto::StreamExecResponse, connectrpc::ConnectError> {
    use proto::stream_exec_response::Event;

    let event = match event {
        ExecStreamEvent::Stdout(bytes) => Event::Stdout(bytes),
        ExecStreamEvent::Stderr(bytes) => Event::Stderr(bytes),
        ExecStreamEvent::Exit(exit_code) => Event::ExitCode(exit_code),
        ExecStreamEvent::UpstreamError(error) => {
            return Err(wire_error(&rendered_exec_error(
                &AppError::Upstream(format!("workspace exec failed: {error}").into()),
                request_id,
            )));
        }
    };
    Ok(proto::StreamExecResponse {
        event: Some(event),
        ..Default::default()
    })
}

fn proto_exec_timeout(timeout: MessageField<Duration>) -> AppResult<StdDuration> {
    let Some(timeout) = timeout.into_option() else {
        return Ok(StdDuration::from_secs(DEFAULT_EXEC_TIMEOUT_SECS));
    };
    let timeout = StdDuration::try_from(timeout).map_err(|error| AppError::Validation {
        errors: vec![ValidationIssue {
            path: Cow::Borrowed("/timeout"),
            message: Cow::Owned(error.to_string()),
        }],
    })?;
    if timeout.is_zero() {
        Ok(StdDuration::from_secs(DEFAULT_EXEC_TIMEOUT_SECS))
    } else {
        Ok(timeout)
    }
}

fn exec_rpc_error(error: &AppError, ctx: &RequestContext) -> connectrpc::ConnectError {
    let request_id = ctx
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok());
    wire_error(&rendered_exec_error(error, request_id))
}

fn rendered_exec_error(error: &AppError, request_id: Option<&str>) -> RenderedConnectError {
    if let AppError::BadRequest(detail) = error
        && detail.as_ref() == "command is required"
    {
        return RenderedConnectError::from_app_error(
            &AppError::Validation {
                errors: vec![ValidationIssue {
                    path: Cow::Borrowed("/command"),
                    message: Cow::Borrowed("must not be empty"),
                }],
            },
            request_id,
        );
    }

    rendered_workspace_error(error, request_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use codewire_server_core::connect_error::{ConnectCode, ConnectErrorDetail, ErrorInfo};
    use connectrpc::ErrorCode;

    #[test]
    fn stream_events_preserve_bytes_and_terminal_exit() {
        use proto::stream_exec_response::Event;

        let stdout = stream_exec_message(ExecStreamEvent::Stdout(vec![0xff, 0x00]), None)
            .expect("stdout frame");
        assert_eq!(stdout.event, Some(Event::Stdout(vec![0xff, 0x00])));

        let stderr = stream_exec_message(ExecStreamEvent::Stderr(vec![0xfe, b'\n']), None)
            .expect("stderr frame");
        assert_eq!(stderr.event, Some(Event::Stderr(vec![0xfe, b'\n'])));

        let exit = stream_exec_message(ExecStreamEvent::Exit(23), None).expect("exit frame");
        assert_eq!(exit.event, Some(Event::ExitCode(23)));
    }

    #[test]
    fn stream_upstream_error_is_retryable_unavailable() {
        let error = stream_exec_message(
            ExecStreamEvent::UpstreamError("transport closed".into()),
            Some("req-stream"),
        )
        .expect_err("upstream event must terminate the stream");

        assert_eq!(error.code, ErrorCode::Unavailable);
        assert_eq!(
            error.message.as_deref(),
            Some("workspace exec failed: transport closed")
        );
        assert!(
            error
                .details
                .iter()
                .any(|detail| detail.type_url == "google.rpc.RetryInfo"),
            "upstream stream errors must carry RetryInfo"
        );
        assert!(
            error.details.iter().any(|detail| {
                detail.type_url == "google.rpc.ErrorInfo"
                    && detail
                        .value
                        .as_deref()
                        .is_some_and(|value| !value.is_empty())
            }),
            "stream error must carry the canonical ErrorInfo detail"
        );
    }

    #[test]
    fn run_frames_preserve_input_resize_output_and_exit() {
        use proto::run_request::Input;
        use proto::run_response::Event;

        assert_eq!(
            run_input(proto::RunRequest {
                input: Some(Input::Stdin(vec![0xff, 0x00])),
                ..Default::default()
            })
            .expect("stdin"),
            EnvironmentDaemonRunInput::Stdin(vec![0xff, 0x00])
        );
        assert_eq!(
            run_input(proto::RunRequest {
                input: Some(Input::Resize(Box::new(proto::RunResize {
                    columns: u32::MAX,
                    rows: 40,
                    ..Default::default()
                }))),
                ..Default::default()
            })
            .expect("resize"),
            EnvironmentDaemonRunInput::Resize {
                columns: i32::MAX,
                rows: 40,
            }
        );
        assert_eq!(
            run_input(proto::RunRequest {
                input: Some(Input::CloseStdin(Box::default())),
                ..Default::default()
            })
            .expect("close stdin"),
            EnvironmentDaemonRunInput::CloseStdin
        );
        assert_eq!(
            run_output_message(EnvironmentDaemonRunOutput::Stdout(vec![0xfe])).event,
            Some(Event::Stdout(vec![0xfe]))
        );
        assert_eq!(
            run_output_message(EnvironmentDaemonRunOutput::Stderr(vec![0xfd])).event,
            Some(Event::Stderr(vec![0xfd]))
        );
        assert_eq!(
            run_output_message(EnvironmentDaemonRunOutput::Exit(29)).event,
            Some(Event::ExitCode(29))
        );
    }

    #[test]
    fn run_requires_exactly_one_valid_start_frame() {
        let error = validate_run_start(&proto::RunStart::default())
            .expect_err("empty run start must be rejected");
        let AppError::Validation { errors } = error else {
            panic!("expected validation error");
        };
        assert_eq!(
            errors
                .iter()
                .map(|error| error.path.as_ref())
                .collect::<Vec<_>>(),
            ["/start/org_id", "/start/environment_id", "/start/command"]
        );

        let repeated = run_input(proto::RunRequest {
            input: Some(proto::run_request::Input::Start(Box::default())),
            ..Default::default()
        })
        .expect_err("repeated start must be rejected");
        assert_eq!(repeated.code, ErrorCode::InvalidArgument);
    }

    #[test]
    fn run_timeout_zero_is_unbounded_and_positive_is_exact() {
        assert_eq!(
            proto_run_timeout(MessageField::none()).expect("absent timeout"),
            None
        );
        assert_eq!(
            proto_run_timeout(
                Duration {
                    seconds: 0,
                    nanos: 0,
                    ..Default::default()
                }
                .into(),
            )
            .expect("zero timeout"),
            None
        );
        assert_eq!(
            proto_run_timeout(
                Duration {
                    seconds: 17,
                    nanos: 0,
                    ..Default::default()
                }
                .into(),
            )
            .expect("positive timeout"),
            Some(StdDuration::from_secs(17))
        );
    }

    #[test]
    fn timeout_defaults_and_preserves_fractional_duration() {
        assert_eq!(
            proto_exec_timeout(MessageField::none()).unwrap(),
            StdDuration::from_secs(600)
        );
        assert_eq!(
            proto_exec_timeout(MessageField::some(Duration::default())).unwrap(),
            StdDuration::from_secs(600)
        );
        assert_eq!(
            proto_exec_timeout(MessageField::some(Duration {
                seconds: 2,
                nanos: 500_000_000,
                ..Default::default()
            }))
            .unwrap(),
            StdDuration::from_millis(2_500)
        );
    }

    #[test]
    fn invalid_timeout_has_bad_request_field_detail() {
        let error = proto_exec_timeout(MessageField::some(Duration {
            seconds: -1,
            ..Default::default()
        }))
        .unwrap_err();
        let rendered = RenderedConnectError::from_app_error(&error, None);
        assert_eq!(rendered.code, ConnectCode::InvalidArgument);
        let ConnectErrorDetail::BadRequest(detail) = &rendered.details[0] else {
            panic!("expected BadRequest detail");
        };
        assert_eq!(detail.field_violations[0].field, "timeout");
    }

    #[test]
    fn exec_gate_errors_follow_d12() {
        let cases = [
            (
                AppError::NotFound("organization not found".into()),
                ConnectCode::NotFound,
            ),
            (
                AppError::Coded {
                    status: StatusCode::FORBIDDEN,
                    code: "",
                    detail: "access denied".into(),
                },
                ConnectCode::PermissionDenied,
            ),
            (
                AppError::BadRequest("only supported for sandbox environments".into()),
                ConnectCode::InvalidArgument,
            ),
            (
                AppError::ServiceUnavailable("sandbox backend not found".into()),
                ConnectCode::Unavailable,
            ),
            (
                AppError::Upstream("workspace exec failed".into()),
                ConnectCode::Unavailable,
            ),
        ];

        for (error, expected) in cases {
            assert_eq!(
                rendered_exec_error(&error, None).code,
                expected,
                "{error:?}"
            );
        }

        let access = rendered_exec_error(
            &AppError::Coded {
                status: StatusCode::FORBIDDEN,
                code: "",
                detail: "access denied".into(),
            },
            None,
        );
        let ConnectErrorDetail::ErrorInfo(ErrorInfo { reason, .. }) = &access.details[0] else {
            panic!("expected access ErrorInfo detail");
        };
        assert_eq!(reason, "ACCESS_DENIED");
    }

    #[test]
    fn state_and_command_errors_gain_canonical_details() {
        let state = rendered_exec_error(
            &AppError::BadRequest("environment must be running".into()),
            Some("req-1"),
        );
        assert_eq!(state.code, ConnectCode::FailedPrecondition);
        let ConnectErrorDetail::ErrorInfo(ErrorInfo {
            reason, metadata, ..
        }) = &state.details[0]
        else {
            panic!("expected ErrorInfo detail");
        };
        assert_eq!(reason, "INVALID_STATE");
        assert_eq!(
            metadata.get("request_id").map(String::as_str),
            Some("req-1")
        );

        let command =
            rendered_exec_error(&AppError::BadRequest("command is required".into()), None);
        assert_eq!(command.code, ConnectCode::InvalidArgument);
        let ConnectErrorDetail::BadRequest(detail) = &command.details[0] else {
            panic!("expected BadRequest detail");
        };
        assert_eq!(detail.field_violations[0].field, "command");

        let backend = rendered_exec_error(
            &AppError::ServiceUnavailable("sandbox backend not found".into()),
            None,
        );
        assert!(
            backend
                .details
                .iter()
                .all(|detail| !matches!(detail, ConnectErrorDetail::RetryInfo(_)))
        );

        let upstream =
            rendered_exec_error(&AppError::Upstream("workspace exec failed".into()), None);
        assert!(
            upstream
                .details
                .iter()
                .any(|detail| matches!(detail, ConnectErrorDetail::RetryInfo(_)))
        );
    }
}
