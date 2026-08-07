//! Raw terminal proxy: Rust port of `environment_terminal.go`.

use std::future::Future;

use axum::body::Body;
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::{FromRequestParts, Path, Query, State};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use codewire_server_core::AppError;
use codewire_server_core::auth::{AuthUser, SESSION_COOKIE_NAME, authenticate};
use codewire_server_core::org_deletion::{
    acquire_environment_runtime_mutation_lease, mark_organization_mutation_resolution_required,
    release_organization_mutation_lease,
};
use futures_util::{SinkExt, StreamExt};
use hmac::{Hmac, Mac};
use kube::api::TerminalSize;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use super::ApiState;
use super::prepare::plain_error;
use super::proxy::resolve_running_sandbox_target;
use crate::sandbox::client::SandboxClient;

const MSG_TYPE_STDIN: u8 = 0x00;
const MSG_TYPE_RESIZE: u8 = 0x01;
const TERMINAL_TICKET_TTL_SECS: i64 = 30;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Serialize, Deserialize)]
struct TerminalTicketClaims {
    user_id: String,
    #[serde(default)]
    global_admin_user_credential: bool,
    exp: i64,
    nonce: String,
}

enum TerminalInbound {
    Binary(Vec<u8>),
    ClientClose,
    TransportClosed,
}

enum TerminalAttachment<T> {
    Ready(anyhow::Result<T>),
    ClientClose,
    TransportClosed,
}

#[derive(Debug, Deserialize)]
pub struct TerminalQuery {
    #[serde(default)]
    ticket: String,
}

pub(crate) fn issue_terminal_ticket_core(
    state: &ApiState,
    user: &AuthUser,
) -> Result<String, AppError> {
    issue_ticket(
        &state.session_secret,
        &user.user_id,
        user.is_admin && !user.via_api_key,
    )
    .map_err(|_| AppError::InternalMsg("failed to issue ticket".into()))
}

/// Raw terminal WebSocket route. Authenticates manually because the Go
/// route is `OptionalAuth` plus a stateless `?ticket=` fallback.
pub async fn terminal_websocket(
    State(state): State<ApiState>,
    Path((org_id, env_id)): Path<(String, String)>,
    Query(query): Query<TerminalQuery>,
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
        Err((status, msg)) => return terminal_error(status, msg),
    };

    let Some(kube) = state.kube.clone() else {
        return terminal_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "sandbox backend not configured",
        );
    };
    let sb = SandboxClient::new(kube, &target.namespace);
    if let Err(msg) = require_sandbox_claim_ready(&sb, &target.environment_id).await {
        return terminal_error(StatusCode::SERVICE_UNAVAILABLE, &msg);
    }

    let pod_name = if target.pod_name.trim().is_empty() {
        match sb.get_pod_name(&target.environment_id).await {
            Ok(name) => name,
            Err(err) => {
                return terminal_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    &format!("sandbox pod not found: {err}"),
                );
            }
        }
    } else {
        target.pod_name
    };

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
    let command = build_terminal_exec_command("xterm-256color");
    let pool = state.pool.clone();
    ws.protocols(["terminal"])
        .on_upgrade(move |socket| terminal_session(socket, sb, pod_name, command, pool, lease.id))
}

pub(crate) async fn authenticate_socket_request(
    state: &ApiState,
    headers: &HeaderMap,
    ticket: &str,
) -> Result<AuthUser, Response> {
    if !ticket.is_empty() {
        let Some(claims) = redeem_ticket(&state.session_secret, ticket) else {
            return Err(terminal_error(
                StatusCode::UNAUTHORIZED,
                r#"{"error":"invalid or expired ticket"}"#,
            ));
        };
        return Ok(AuthUser {
            user_id: claims.user_id,
            org_id: None,
            is_admin: claims.global_admin_user_credential,
            via_api_key: false,
        });
    }

    let session_token = session_cookie(headers);
    let bearer = bearer_token(headers);
    authenticate(&state.auth, session_token, bearer)
        .await
        .map_err(|err| {
            if err.is_forbidden() {
                terminal_error(StatusCode::FORBIDDEN, r#"{"error":"forbidden"}"#)
            } else {
                terminal_error(StatusCode::UNAUTHORIZED, r#"{"error":"unauthorized"}"#)
            }
        })
}

async fn terminal_session(
    socket: WebSocket,
    sb: SandboxClient,
    pod_name: String,
    command: Vec<String>,
    pool: sqlx::PgPool,
    lease_id: String,
) {
    let (mut ws_tx, mut ws_rx) = socket.split();
    let (inbound_tx, mut inbound_rx) = tokio::sync::mpsc::unbounded_channel();
    let socket_reader_task = tokio::spawn(async move {
        loop {
            let event = match ws_rx.next().await {
                Some(Ok(Message::Binary(data))) => TerminalInbound::Binary(data.to_vec()),
                Some(Ok(Message::Close(_))) => TerminalInbound::ClientClose,
                Some(Ok(Message::Text(_) | Message::Ping(_) | Message::Pong(_))) => continue,
                Some(Err(error)) => {
                    tracing::info!(error = %error, "terminal peer transport closed before frame handling");
                    TerminalInbound::TransportClosed
                }
                None => TerminalInbound::TransportClosed,
            };
            let terminal_closed = matches!(
                event,
                TerminalInbound::ClientClose | TerminalInbound::TransportClosed
            );
            if inbound_tx.send(event).is_err() || terminal_closed {
                return;
            }
        }
    });

    let mut pending_frames = Vec::new();
    let attachment = await_terminal_attachment(
        sb.start_workspace_terminal_on_pod(&pod_name, &command),
        &mut inbound_rx,
        &mut pending_frames,
    )
    .await;
    let handle = match attachment {
        TerminalAttachment::Ready(Ok(handle)) => handle,
        TerminalAttachment::Ready(Err(error)) => {
            socket_reader_task.abort();
            if let Err(mark_error) = mark_organization_mutation_resolution_required(
                &pool,
                &lease_id,
                "environment_runtime_dispatch_ambiguous",
            )
            .await
            {
                tracing::warn!(error = %mark_error, "terminal admission ambiguity marker failed");
            }
            tracing::info!(error = %error, "terminal attachment failed");
            return;
        }
        TerminalAttachment::ClientClose => {
            socket_reader_task.abort();
            if let Err(error) = release_organization_mutation_lease(&pool, &lease_id).await {
                tracing::warn!(error = %error, "terminal admission cancellation lease release failed");
            }
            if let Err(error) = ws_tx.flush().await {
                tracing::info!(error = %error, "terminal client-close response flush failed");
            }
            return;
        }
        TerminalAttachment::TransportClosed => {
            socket_reader_task.abort();
            if let Err(mark_error) = mark_organization_mutation_resolution_required(
                &pool,
                &lease_id,
                "environment_runtime_dispatch_ambiguous",
            )
            .await
            {
                tracing::warn!(error = %mark_error, "terminal admission ambiguity marker failed");
            }
            tracing::info!("terminal peer disconnected before terminal attachment completed");
            return;
        }
    };
    if let Err(error) = release_organization_mutation_lease(&pool, &lease_id).await {
        socket_reader_task.abort();
        tracing::warn!(error = %error, "terminal admission lease release failed");
        return;
    }

    let (stdin_tx, stdin_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let (stdout_tx, mut stdout_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let (resize_tx, resize_rx) = tokio::sync::mpsc::channel::<TerminalSize>(4);
    for frame in pending_frames {
        handle_client_frame(&frame, &stdin_tx, &resize_tx).await;
    }
    let (client_close_tx, client_close_rx) = tokio::sync::oneshot::channel();

    let mut exec_task =
        tokio::spawn(async move { handle.run(stdin_rx, stdout_tx, resize_rx).await });

    let mut input_task = tokio::spawn(async move {
        while let Some(inbound) = inbound_rx.recv().await {
            match inbound {
                TerminalInbound::Binary(data) => {
                    handle_client_frame(&data, &stdin_tx, &resize_tx).await;
                }
                TerminalInbound::ClientClose => {
                    let _ = client_close_tx.send(());
                    break;
                }
                TerminalInbound::TransportClosed => break,
            }
        }
    });

    let mut write_task = tokio::spawn(async move {
        let mut client_close_rx = Some(client_close_rx);
        loop {
            tokio::select! {
                biased;
                close = client_close_rx.as_mut().expect("client close receiver is present"), if client_close_rx.is_some() => {
                    if close.is_ok() {
                        // Tungstenite queues the protocol-required reply when the reader
                        // observes a peer Close. The writer must flush that queued frame;
                        // attempting to send another Close is rejected while closing.
                        let _ = ws_tx.flush().await;
                        return;
                    }
                    client_close_rx = None;
                }
                bytes = stdout_rx.recv() => match bytes {
                    Some(bytes) => {
                        if ws_tx.send(Message::Binary(bytes.into())).await.is_err() {
                            return;
                        }
                    }
                    None => break,
                },
            }
        }
        let _ = ws_tx
            .send(Message::Close(Some(CloseFrame {
                code: 1000,
                reason: "session ended".into(),
            })))
            .await;
    });

    tokio::select! {
        _ = &mut input_task => {
            exec_task.abort();
            let _ = write_task.await;
        }
        _ = &mut write_task => {
            exec_task.abort();
            input_task.abort();
        }
        result = &mut exec_task => {
            if let Ok(Err(err)) = result {
                tracing::info!(error = %err, "terminal exec ended with error");
            }
            input_task.abort();
            let _ = write_task.await;
        }
    }
    socket_reader_task.abort();
}

async fn await_terminal_attachment<T, F>(
    attachment: F,
    inbound_rx: &mut tokio::sync::mpsc::UnboundedReceiver<TerminalInbound>,
    pending_frames: &mut Vec<Vec<u8>>,
) -> TerminalAttachment<T>
where
    F: Future<Output = anyhow::Result<T>>,
{
    tokio::pin!(attachment);
    loop {
        tokio::select! {
            biased;
            inbound = inbound_rx.recv() => match inbound {
                Some(TerminalInbound::Binary(frame)) => pending_frames.push(frame),
                Some(TerminalInbound::ClientClose) => return TerminalAttachment::ClientClose,
                Some(TerminalInbound::TransportClosed) | None => {
                    return TerminalAttachment::TransportClosed;
                }
            },
            result = &mut attachment => return TerminalAttachment::Ready(result),
        }
    }
}

async fn handle_client_frame(
    data: &[u8],
    stdin_tx: &tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    resize_tx: &tokio::sync::mpsc::Sender<TerminalSize>,
) {
    if data.is_empty() {
        return;
    }
    match data[0] {
        MSG_TYPE_STDIN if data.len() > 1 => {
            let _ = stdin_tx.send(data[1..].to_vec());
        }
        MSG_TYPE_STDIN => {}
        MSG_TYPE_RESIZE if data.len() >= 5 => {
            let width = u16::from_be_bytes([data[1], data[2]]);
            let height = u16::from_be_bytes([data[3], data[4]]);
            let _ = resize_tx.try_send(TerminalSize { width, height });
        }
        _ => {}
    }
}

pub(crate) async fn require_sandbox_claim_ready(
    sb: &SandboxClient,
    env_id: &str,
) -> Result<(), String> {
    let (exists, ready, mut reason) = sb
        .get_sandbox_claim_ready_status(env_id)
        .await
        .map_err(|err| format!("get sandbox claim: {err}"))?;
    if !exists {
        return Err("sandbox claim not found".to_string());
    }
    if ready {
        return Ok(());
    }
    if reason.is_empty() {
        reason = "not ready".to_string();
    }
    Err(format!("sandbox not ready: {reason}"))
}

fn terminal_error(status: StatusCode, body: &str) -> Response {
    plain_error(status, body)
}

fn issue_ticket(
    secret: &str,
    user_id: &str,
    global_admin_user_credential: bool,
) -> anyhow::Result<String> {
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce)?;
    let claims = TerminalTicketClaims {
        user_id: user_id.to_string(),
        global_admin_user_credential,
        exp: chrono::Utc::now().timestamp() + TERMINAL_TICKET_TTL_SECS,
        nonce: hex_lower(&nonce),
    };
    let payload = serde_json::to_vec(&claims)?;
    let sig = sign_terminal_ticket(secret, &payload);
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    Ok(format!("{}.{}", engine.encode(payload), engine.encode(sig)))
}

fn redeem_ticket(secret: &str, token: &str) -> Option<TerminalTicketClaims> {
    let (payload_part, sig_part) = token.split_once('.')?;
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let payload = engine.decode(payload_part).ok()?;
    let sig = engine.decode(sig_part).ok()?;
    if !constant_time_eq(&sig, &sign_terminal_ticket(secret, &payload)) {
        return None;
    }
    let claims: TerminalTicketClaims = serde_json::from_slice(&payload).ok()?;
    if claims.user_id.is_empty() || chrono::Utc::now().timestamp() > claims.exp {
        return None;
    }
    Some(claims)
}

fn sign_terminal_ticket(secret: &str, payload: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key size");
    mac.update(payload);
    mac.finalize().into_bytes().to_vec()
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right) {
        diff |= a ^ b;
    }
    diff == 0
}

fn session_cookie(headers: &HeaderMap) -> Option<&str> {
    let raw = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    for pair in raw.split(';') {
        let pair = pair.trim_start();
        if let Some(value) = pair.strip_prefix(SESSION_COOKIE_NAME) {
            let value = value.trim_start();
            if let Some(value) = value.strip_prefix('=') {
                return Some(value.trim_end_matches(|c: char| c.is_whitespace()));
            }
        }
    }
    None
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let raw = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    raw.strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))
}

fn build_terminal_exec_command(term: &str) -> Vec<String> {
    let boot = [
        r#"if [ -f "$HOME/.codewire/environment.sh" ]; then . "$HOME/.codewire/environment.sh"; fi"#,
        r#"shell="${SHELL:-}""#,
        r#"if [ -z "$shell" ] || [ ! -x "$shell" ]; then"#,
        r#"  if [ -x /bin/bash ]; then shell=/bin/bash;"#,
        r#"  elif [ -x /bin/sh ]; then shell=/bin/sh;"#,
        r#"  else shell=sh; fi"#,
        r#"fi"#,
        r#"case "$shell" in"#,
        r#"  */bash|bash|*/zsh|zsh|*/fish|fish|*/ash|ash|*/sh|sh) exec "$shell" -i ;;"#,
        r#"  *) exec "$shell" ;;"#,
        r#"esac"#,
    ]
    .join("\n");
    vec![
        "env".to_string(),
        format!("TERM={term}"),
        "sh".to_string(),
        "-lc".to_string(),
        boot,
    ]
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::{Context, Poll};

    use super::*;

    struct PendingAttachment {
        cancelled: Arc<AtomicBool>,
    }

    impl Future for PendingAttachment {
        type Output = anyhow::Result<()>;

        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            Poll::Pending
        }
    }

    impl Drop for PendingAttachment {
        fn drop(&mut self) {
            self.cancelled.store(true, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn pre_attachment_client_close_cancels_terminal_attachment() {
        let (inbound_tx, mut inbound_rx) = tokio::sync::mpsc::unbounded_channel();
        let cancelled = Arc::new(AtomicBool::new(false));
        inbound_tx.send(TerminalInbound::ClientClose).unwrap();

        let mut pending_frames = Vec::new();
        let outcome = await_terminal_attachment(
            PendingAttachment {
                cancelled: cancelled.clone(),
            },
            &mut inbound_rx,
            &mut pending_frames,
        )
        .await;

        assert!(matches!(outcome, TerminalAttachment::ClientClose));
        assert!(cancelled.load(Ordering::SeqCst));
        assert!(pending_frames.is_empty());
    }

    #[tokio::test]
    async fn pre_attachment_transport_close_remains_ambiguous() {
        let (inbound_tx, mut inbound_rx) = tokio::sync::mpsc::unbounded_channel();
        let cancelled = Arc::new(AtomicBool::new(false));
        inbound_tx.send(TerminalInbound::TransportClosed).unwrap();

        let mut pending_frames = Vec::new();
        let outcome = await_terminal_attachment(
            PendingAttachment {
                cancelled: cancelled.clone(),
            },
            &mut inbound_rx,
            &mut pending_frames,
        )
        .await;

        assert!(matches!(outcome, TerminalAttachment::TransportClosed));
        assert!(cancelled.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn pre_attachment_frames_are_preserved_for_a_successful_terminal() {
        let (inbound_tx, mut inbound_rx) = tokio::sync::mpsc::unbounded_channel();
        inbound_tx
            .send(TerminalInbound::Binary(vec![
                MSG_TYPE_RESIZE,
                0,
                120,
                0,
                32,
            ]))
            .unwrap();

        let mut pending_frames = Vec::new();
        let outcome = await_terminal_attachment(
            async { Ok::<_, anyhow::Error>(()) },
            &mut inbound_rx,
            &mut pending_frames,
        )
        .await;

        assert!(matches!(outcome, TerminalAttachment::Ready(Ok(()))));
        assert_eq!(pending_frames, vec![vec![MSG_TYPE_RESIZE, 0, 120, 0, 32]]);
    }

    #[test]
    fn issue_and_redeem_ticket_round_trips() {
        let ticket =
            issue_ticket("0123456789abcdef0123456789abcdef", "test-user-123", true).unwrap();
        let claims = redeem_ticket("0123456789abcdef0123456789abcdef", &ticket).unwrap();
        assert_eq!(claims.user_id, "test-user-123");
        assert!(claims.global_admin_user_credential);
    }

    #[test]
    fn expired_ticket_is_rejected() {
        let secret = "0123456789abcdef0123456789abcdef";
        let payload = serde_json::to_vec(&TerminalTicketClaims {
            user_id: "user".to_string(),
            global_admin_user_credential: false,
            exp: chrono::Utc::now().timestamp() - 1,
            nonce: "expired".to_string(),
        })
        .unwrap();
        let sig = sign_terminal_ticket(secret, &payload);
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let ticket = format!("{}.{}", engine.encode(payload), engine.encode(sig));
        assert!(redeem_ticket(secret, &ticket).is_none());
    }

    #[test]
    fn tampered_ticket_is_rejected() {
        let secret = "0123456789abcdef0123456789abcdef";
        let ticket = issue_ticket(secret, "user", false).unwrap();
        let (payload_part, sig_part) = ticket.split_once('.').unwrap();
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let mut payload = engine.decode(payload_part).unwrap();
        payload[0] ^= 0x01;
        let tampered = format!("{}.{}", engine.encode(payload), sig_part);
        assert!(redeem_ticket(secret, &tampered).is_none());
    }

    #[test]
    fn invalid_ticket_is_rejected() {
        assert!(redeem_ticket("0123456789abcdef0123456789abcdef", "nonexistent").is_none());
    }

    #[test]
    fn terminal_exec_command_matches_go_shape() {
        let cmd = build_terminal_exec_command("xterm-256color");
        assert_eq!(cmd.len(), 5);
        assert_eq!(cmd[0], "env");
        assert_eq!(cmd[1], "TERM=xterm-256color");
        assert_eq!(cmd[2], "sh");
        assert_eq!(cmd[3], "-lc");
        assert!(cmd[4].contains(
            r#"if [ -f "$HOME/.codewire/environment.sh" ]; then . "$HOME/.codewire/environment.sh"; fi"#
        ));
        assert!(cmd[4].contains(r#"shell="${SHELL:-}""#));
        assert!(cmd[4].contains(r#"exec "$shell" -i"#));

        let status = std::process::Command::new("sh")
            .arg("-n")
            .arg("-c")
            .arg(&cmd[4])
            .status()
            .expect("sh -n should run");
        assert!(status.success());
    }
}
