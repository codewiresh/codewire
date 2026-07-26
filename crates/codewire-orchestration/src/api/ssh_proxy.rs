//! Raw SSH proxy: Rust port of `environment_ssh_proxy.go`.

use axum::body::Body;
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::{FromRequestParts, Path, Query, State};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use codewire_server_core::org_deletion::{
    acquire_environment_runtime_mutation_lease, mark_organization_mutation_resolution_required,
    release_organization_mutation_lease,
};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use uuid::Uuid;

use super::ApiState;
use super::prepare::{json_response, plain_error};
use super::proxy::{resolve_running_sandbox_target, resolve_running_sandbox_target_for_role};
use super::terminal::{authenticate_socket_request, require_sandbox_claim_ready};
use crate::sandbox::client::SandboxClient;
use crate::sandbox::sidecar::DEFAULT_GATEWAY_SSH_PORT;

const DEFAULT_SHIM_PORT: u16 = 7777;

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

    let lease = match acquire_environment_runtime_mutation_lease(
        &state.pool,
        &org_id,
        &target.environment_id,
    )
    .await
    {
        Ok(lease) => lease,
        Err(error) => return error.into_response(),
    };

    let stream = match sb
        .gateway_port_forward_stream(&target.environment_id, DEFAULT_GATEWAY_SSH_PORT)
        .await
    {
        Ok(stream) => stream,
        Err(err) => {
            if let Err(error) = mark_organization_mutation_resolution_required(
                &state.pool,
                &lease.id,
                "environment_runtime_dispatch_ambiguous",
            )
            .await
            {
                return error.into_response();
            }
            tracing::info!(error = %err, env = %target.environment_id, namespace = %target.namespace, "ssh-proxy: sidecar port-forward failed");
            return ssh_error(
                StatusCode::SERVICE_UNAVAILABLE,
                r#"{"error":"sshd not available","tier":"fallback"}"#,
            );
        }
    };
    if let Err(error) = release_organization_mutation_lease(&state.pool, &lease.id).await {
        return error.into_response();
    }

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
        .gateway_port_forward_stream(&target.environment_id, DEFAULT_GATEWAY_SSH_PORT)
        .await
        .is_err()
    {
        return check_response(false, false, "");
    }

    let (shim_healthy, shim_error) = probe_shim_health(&sb, &target.environment_id).await;
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

async fn probe_shim_health(sb: &SandboxClient, env_id: &str) -> (bool, String) {
    let mut stream = match sb.port_forward_stream(env_id, DEFAULT_SHIM_PORT).await {
        Ok(stream) => stream,
        Err(err) => return (false, format!("port-forward: {err}")),
    };

    let req = b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    if let Err(err) = stream.stream_mut().write_all(req).await {
        return (false, format!("request: {err}"));
    }

    let mut buf = vec![0u8; 1024];
    let n = match stream.stream_mut().read(&mut buf).await {
        Ok(0) => return (false, "dial: empty response".to_string()),
        Ok(n) => n,
        Err(err) => return (false, format!("dial: {err}")),
    };
    let head = String::from_utf8_lossy(&buf[..n]);
    (
        head.starts_with("HTTP/1.1 200 ") || head.starts_with("HTTP/1.0 200 "),
        String::new(),
    )
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
mod tests {
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use tokio::io::AsyncWrite;

    use super::write_ssh_proxy_bytes;

    #[test]
    fn http_status_parser_accepts_ok_responses() {
        let ok = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        let head = String::from_utf8_lossy(ok);
        assert!(head.starts_with("HTTP/1.1 200 "));

        let not_found = b"HTTP/1.1 404 Not Found\r\n\r\n";
        let head = String::from_utf8_lossy(not_found);
        assert!(!head.starts_with("HTTP/1.1 200 "));
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
