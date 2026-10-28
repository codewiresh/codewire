//! Raw SSH proxy: Rust port of `environment_ssh_proxy.go`.

use axum::body::Body;
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::{FromRequestParts, Path, Query, State};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use codewire_daemon_bridge::client::DaemonClient;
use codewire_daemon_proto::daemon::v1::DaemonState;
use codewire_server_core::AppError;
use codewire_server_core::org_deletion::{
    RuntimeMutationOutcome, run_environment_runtime_mutation_with_outcome,
};
use futures_util::{SinkExt, StreamExt};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex;
use tonic::transport::{Channel, Endpoint};
use tower::service_fn;
use uuid::Uuid;

use super::ApiState;
use super::prepare::{json_response, plain_error};
use super::proxy::{resolve_running_sandbox_target, resolve_running_sandbox_target_for_role};
use super::terminal::{authenticate_socket_request, require_sandbox_claim_ready};
use crate::sandbox::client::SandboxClient;
use crate::sandbox::sidecar::{PortForwardedStream, WORKSPACE_SSH_PORT};
use crate::worker::workspace_binding::environment_daemon_credential;

const DEFAULT_SHIM_PORT: u16 = 7777;
const DAEMON_HEALTH_PROBE_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug, Deserialize)]
pub struct SshProxyQuery {
    #[serde(default)]
    ticket: String,
}

#[derive(Debug, Serialize)]
pub struct SshProxyCheckResponse {
    available: bool,
    shim_healthy: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    shim_error: String,
}

/// `GET /api/v1/organizations/{org_id}/environments/{env_id}/ssh-proxy`
/// — WebSocket-to-sidecar SSH byte bridge.
pub async fn ssh_proxy_websocket(
    State(state): State<ApiState>,
    Path((org_id, env_id)): Path<(String, String)>,
    Query(query): Query<SshProxyQuery>,
    request: Request<Body>,
) -> Response {
    let headers = request.headers().clone();
    let user = match authenticate_socket_request(&state, &headers, &query.ticket).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let (mut parts, _body) = request.into_parts();
    let ws = match WebSocketUpgrade::from_request_parts(&mut parts, &state).await {
        Ok(ws) => ws,
        Err(rejection) => return rejection.into_response(),
    };

    let target = match resolve_running_sandbox_target(&state, &user, &org_id, &env_id).await {
        Ok(target) => target,
        Err((status, msg)) => return ssh_error(status, msg),
    };

    let Some(kube) = state.kube.clone() else {
        return ssh_error(
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"error":"sandbox backend not configured"}"#,
        );
    };
    let sb = SandboxClient::new(kube, &target.namespace);
    if let Err(msg) = require_sandbox_claim_ready(&sb, &target.environment_id).await {
        return ssh_error(StatusCode::SERVICE_UNAVAILABLE, &msg);
    }

    let connect = {
        let environment_id = target.environment_id.clone();
        async move {
            sb.workspace_ssh_stream(&environment_id, WORKSPACE_SSH_PORT)
                .await
        }
    };
    let stream = match open_fenced_ssh_stream(&state.pool, &org_id, &target.environment_id, connect)
        .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(err)) => {
            tracing::info!(error = %err, env = %target.environment_id, namespace = %target.namespace, "ssh-proxy: workspace SSH connect failed");
            return ssh_error(
                StatusCode::SERVICE_UNAVAILABLE,
                r#"{"error":"sshd not available","tier":"fallback"}"#,
            );
        }
        Err(error) => return error.into_response(),
    };

    let attempt_id = Uuid::new_v4().to_string();
    tracing::info!(
        attempt_id,
        env = %target.environment_id,
        namespace = %target.namespace,
        user_id = %user.user_id,
        "ssh-proxy: connected"
    );

    ws.protocols(["ssh"]).on_upgrade(move |socket| {
        ssh_proxy_session(socket, stream, attempt_id, target.environment_id)
    })
}

/// Open the workspace daemon's SSH stream behind the environment runtime fence.
///
/// The port-forward runs in the shared runtime-mutation owner task, so a
/// client that leaves mid-connect cannot strand the lease. An opened stream
/// releases it; a failed port-forward retains
/// `environment_runtime_dispatch_ambiguous` evidence. A stream opened after the
/// client left still releases the lease and is then dropped, which closes it.
async fn open_fenced_ssh_stream<S, F>(
    pool: &PgPool,
    org_id: &str,
    environment_id: &str,
    connect: F,
) -> Result<anyhow::Result<S>, AppError>
where
    F: Future<Output = anyhow::Result<S>> + Send + 'static,
    S: Send + 'static,
{
    run_environment_runtime_mutation_with_outcome(pool, org_id, environment_id, async move {
        let stream = connect.await;
        if stream.is_ok() {
            RuntimeMutationOutcome::release(stream)
        } else {
            RuntimeMutationOutcome::resolution_required(
                "environment_runtime_dispatch_ambiguous",
                stream,
            )
        }
    })
    .await
}

/// `GET /api/v1/organizations/{org_id}/environments/{env_id}/ssh-proxy/check`
/// — sidecar SSH + workspace shim availability probe.
pub async fn ssh_proxy_check(
    State(state): State<ApiState>,
    Path((org_id, env_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let user = match authenticate_socket_request(&state, &headers, "").await {
        Ok(user) => user,
        Err(response) => return response,
    };

    let Some(kube) = state.kube.clone() else {
        return check_response(false, false, "");
    };

    let target =
        match resolve_running_sandbox_target_for_role(&state, &user, &org_id, &env_id, "viewer")
            .await
        {
            Ok(target) => target,
            Err((StatusCode::BAD_REQUEST, _)) => return check_response(false, false, ""),
            Err((StatusCode::SERVICE_UNAVAILABLE, "sandbox backend not found")) => {
                return check_response(false, false, "");
            }
            Err((status, msg)) => return ssh_error(status, msg),
        };

    let sb = SandboxClient::new(kube, &target.namespace);
    if require_sandbox_claim_ready(&sb, &target.environment_id)
        .await
        .is_err()
    {
        return check_response(false, false, "");
    }

    if sb
        .workspace_ssh_stream(&target.environment_id, WORKSPACE_SSH_PORT)
        .await
        .is_err()
    {
        return check_response(false, false, "");
    }

    let (shim_healthy, shim_error) = probe_shim_health(
        &sb,
        &state.pool,
        &target.environment_id,
        &state.session_secret,
    )
    .await;
    if !shim_error.is_empty() {
        tracing::warn!(env = %target.environment_id, error = %shim_error, "ssh-proxy-check: shim probe failed");
    }
    tracing::info!(
        env = %target.environment_id,
        namespace = %target.namespace,
        ssh_available = true,
        shim_healthy,
        "ssh-proxy-check: result"
    );

    check_response(true, shim_healthy, &shim_error)
}

async fn ssh_proxy_session(
    socket: WebSocket,
    stream: crate::sandbox::sidecar::PortForwardedStream,
    attempt_id: String,
    env_id: String,
) {
    let (mut ws_tx, mut ws_rx) = socket.split();
    let (tcp_tx, mut tcp_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let (ws_to_tcp_tx, mut ws_to_tcp_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();

    let mut tcp_read_task = tokio::spawn(async move {
        while let Some(bytes) = tcp_rx.recv().await {
            if ws_tx.send(Message::Binary(bytes.into())).await.is_err() {
                return;
            }
        }
        let _ = ws_tx
            .send(Message::Close(Some(CloseFrame {
                code: 1000,
                reason: "ssh session ended".into(),
            })))
            .await;
    });

    let mut ws_read_task = tokio::spawn(async move {
        while let Some(next) = ws_rx.next().await {
            let Ok(msg) = next else {
                break;
            };
            match msg {
                Message::Binary(bytes) => {
                    if ws_to_tcp_tx.send(bytes.to_vec()).is_err() {
                        break;
                    }
                }
                Message::Text(text) => {
                    if ws_to_tcp_tx
                        .send(text.as_str().as_bytes().to_vec())
                        .is_err()
                    {
                        break;
                    }
                }
                Message::Close(_) => break,
                Message::Ping(_) | Message::Pong(_) => {}
            }
        }
    });

    let (stream, _connection_guard) = stream.into_parts();
    let (mut tcp_reader, mut tcp_writer) = tokio::io::split(stream);

    let mut bridge_task = tokio::spawn(async move {
        let mut buf = [0u8; 32 * 1024];
        loop {
            tokio::select! {
                read = tcp_reader.read(&mut buf) => {
                    match read {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if tcp_tx.send(buf[..n].to_vec()).is_err() {
                                break;
                            }
                        }
                    }
                }
                Some(bytes) = ws_to_tcp_rx.recv() => {
                    if write_ssh_proxy_bytes(&mut tcp_writer, &bytes).await.is_err() {
                        break;
                    }
                }
                else => break,
            }
        }
    });

    tokio::select! {
        _ = &mut bridge_task => {
            ws_read_task.abort();
            let _ = tcp_read_task.await;
        }
        _ = &mut ws_read_task => {
            bridge_task.abort();
            tcp_read_task.abort();
        }
        _ = &mut tcp_read_task => {
            ws_read_task.abort();
            bridge_task.abort();
        }
    }

    tracing::info!(attempt_id, env = %env_id, "ssh-proxy: session ended");
}

async fn write_ssh_proxy_bytes<W>(writer: &mut W, bytes: &[u8]) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    writer.write_all(bytes).await?;
    writer.flush().await
}

async fn probe_shim_health(
    sb: &SandboxClient,
    pool: &sqlx::PgPool,
    env_id: &str,
    session_secret: &str,
) -> (bool, String) {
    let stream = match sb.port_forward_stream(env_id, DEFAULT_SHIM_PORT).await {
        Ok(stream) => stream,
        Err(err) => return (false, format!("port-forward: {err}")),
    };
    // The live binding decides the credential (design §7), never a name.
    let token =
        match environment_daemon_credential(pool, Some(&sb.client), session_secret, env_id).await {
            Ok(token) => token,
            Err(_) => return (false, "authorize daemon health probe".into()),
        };
    let channel = match daemon_channel_from_port_forward(stream).await {
        Ok(channel) => channel,
        Err(error) => return (false, format!("daemon transport: {error}")),
    };
    let client = match DaemonClient::from_channel(channel, token) {
        Ok(client) => client,
        Err(_) => return (false, "authorize daemon health client".into()),
    };
    let health = match client.get_health().await {
        Ok(health) => health,
        Err(error) => return (false, format!("daemon GetHealth: {error}")),
    };
    daemon_health_result(health.state, &health.message)
}

async fn daemon_channel_from_port_forward(stream: PortForwardedStream) -> anyhow::Result<Channel> {
    let stream = Arc::new(Mutex::new(Some(stream)));
    let connector = service_fn(move |_| {
        let stream = Arc::clone(&stream);
        async move {
            stream.lock().await.take().map(TokioIo::new).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotConnected,
                    "daemon port-forward stream already consumed",
                )
            })
        }
    });
    Endpoint::from_static("http://hosted-daemon.internal")
        .connect_timeout(DAEMON_HEALTH_PROBE_TIMEOUT)
        .timeout(DAEMON_HEALTH_PROBE_TIMEOUT)
        .executor(codewire_server_core::span_free::DetachedExecutor)
        .connect_with_connector(connector)
        .await
        .map_err(Into::into)
}

fn daemon_health_result(state: i32, message: &str) -> (bool, String) {
    let state = DaemonState::try_from(state).unwrap_or(DaemonState::Unspecified);
    if state == DaemonState::Ready {
        (true, String::new())
    } else {
        (false, format!("daemon state {state:?}: {message}"))
    }
}

fn check_response(available: bool, shim_healthy: bool, shim_error: &str) -> Response {
    json_response(
        StatusCode::OK,
        &SshProxyCheckResponse {
            available,
            shim_healthy,
            shim_error: shim_error.to_string(),
        },
    )
}

fn ssh_error(status: StatusCode, body: &str) -> Response {
    plain_error(status, body)
}

#[cfg(test)]
mod database_tests;

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use tokio::io::AsyncWrite;

    use super::{DaemonState, daemon_health_result, write_ssh_proxy_bytes};

    #[test]
    fn typed_daemon_health_accepts_only_ready_state() {
        assert_eq!(
            daemon_health_result(DaemonState::Ready as i32, "ready"),
            (true, String::new())
        );
        assert_eq!(
            daemon_health_result(DaemonState::Unhealthy as i32, "filesystem unavailable"),
            (
                false,
                "daemon state Unhealthy: filesystem unavailable".into()
            )
        );
    }

    #[tokio::test]
    async fn ssh_proxy_flushes_each_websocket_frame_to_stream() {
        let mut writer = FlushCountingWriter::default();

        write_ssh_proxy_bytes(&mut writer, b"SSH-2.0-OpenSSH_10.3\r\n")
            .await
            .expect("write banner");
        write_ssh_proxy_bytes(&mut writer, b"kexinit")
            .await
            .expect("write kex");

        assert_eq!(writer.bytes, b"SSH-2.0-OpenSSH_10.3\r\nkexinit");
        assert_eq!(writer.flushes, 2);
    }

    #[derive(Default)]
    struct FlushCountingWriter {
        bytes: Vec<u8>,
        flushes: usize,
    }

    impl AsyncWrite for FlushCountingWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.bytes.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            self.flushes += 1;
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
}
