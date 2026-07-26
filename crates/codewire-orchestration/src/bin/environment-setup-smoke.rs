//! Deploy-shaped proof that a Connect-issued terminal ticket authenticates the
//! permanent raw terminal WebSocket through the same ingress.

use std::time::Duration;

use anyhow::Context as _;
use codewire_proto::codewire::console::v1::{
    EnvironmentSetupServiceClient, IssueTerminalTicketRequest,
};
use connectrpc::client::{ClientConfig, HttpClient};
use futures_util::{SinkExt as _, StreamExt as _};
use reqwest::header::COOKIE;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
use tokio_tungstenite::tungstenite::http::header::SEC_WEBSOCKET_PROTOCOL;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use url::Url;

const MARKER: &[u8] = b"codewire-terminal-ticket-green";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let base_url = required_env("SMOKE_CONNECT_BASE_URL")?;
    let org_id = required_env("SMOKE_ORG_ID")?;
    let environment_id = required_env("SMOKE_ENVIRONMENT_ID")?;
    let session_token = required_env("SMOKE_SESSION_TOKEN")?;

    let config = ClientConfig::new(base_url.parse().context("parse Connect base URL")?)
        .with_default_header(COOKIE, format!("codewire.session_token={session_token}"));
    let client = EnvironmentSetupServiceClient::new(HttpClient::plaintext(), config);
    let ticket = client
        .issue_terminal_ticket(IssueTerminalTicketRequest::default())
        .await
        .context("IssueTerminalTicket")?
        .into_owned()
        .ticket;
    anyhow::ensure!(
        !ticket.is_empty(),
        "IssueTerminalTicket returned an empty ticket"
    );

    let mut websocket_url = Url::parse(&base_url).context("parse WebSocket base URL")?;
    let websocket_scheme = match websocket_url.scheme() {
        "http" => "ws",
        "https" => "wss",
        scheme => anyhow::bail!("unsupported Connect URL scheme {scheme}"),
    };
    websocket_url
        .set_scheme(websocket_scheme)
        .map_err(|_| anyhow::anyhow!("replace WebSocket URL scheme"))?;
    websocket_url.set_path(&format!(
        "/api/v1/organizations/{org_id}/environments/{environment_id}/terminal"
    ));
    websocket_url.set_query(None);
    websocket_url
        .query_pairs_mut()
        .append_pair("ticket", &ticket);

    let mut request = websocket_url
        .as_str()
        .into_client_request()
        .context("build terminal WebSocket request")?;
    request.headers_mut().insert(
        SEC_WEBSOCKET_PROTOCOL,
        "terminal".parse().expect("static terminal subprotocol"),
    );
    let (mut socket, response) = connect_async(request)
        .await
        .context("open ticket-authenticated terminal WebSocket")?;
    anyhow::ensure!(
        response
            .headers()
            .get(SEC_WEBSOCKET_PROTOCOL)
            .and_then(|value| value.to_str().ok())
            == Some("terminal"),
        "terminal WebSocket did not negotiate the terminal subprotocol"
    );

    let mut stdin = vec![0];
    // Keep the final marker out of the literal input so a PTY echo cannot
    // satisfy the assertion without the shell actually executing the command.
    stdin.extend_from_slice(b"printf 'codewire-terminal-%s-green\\n' ticket\n");
    socket
        .send(Message::Binary(stdin.into()))
        .await
        .context("write terminal stdin frame")?;

    tokio::time::timeout(Duration::from_secs(30), async {
        let mut output = Vec::new();
        while let Some(frame) = socket.next().await {
            match frame.context("read terminal WebSocket frame")? {
                Message::Binary(bytes) => output.extend_from_slice(&bytes),
                Message::Text(text) => output.extend_from_slice(text.as_bytes()),
                Message::Close(frame) => {
                    anyhow::bail!("terminal WebSocket closed before marker: {frame:?}")
                }
                Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => {}
            }
            if output.windows(MARKER.len()).any(|window| window == MARKER) {
                return Ok::<_, anyhow::Error>(());
            }
        }
        anyhow::bail!("terminal WebSocket ended before marker")
    })
    .await
    .context("terminal marker timed out")??;

    socket
        .send(Message::Close(Some(CloseFrame {
            code: CloseCode::Normal,
            reason: "environment setup smoke complete".into(),
        })))
        .await
        .context("send normal terminal WebSocket close")?;
    let close = tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(frame) = socket.next().await {
            match frame.context("read terminal WebSocket close response")? {
                Message::Close(Some(frame)) => return Ok::<_, anyhow::Error>(frame),
                Message::Close(None) => {
                    anyhow::bail!("terminal WebSocket close response omitted its frame")
                }
                // Output queued before the terminal reader observes the peer Close can
                // arrive after the client sends its Close. It must still be followed by
                // the protocol Close response; the timeout remains fail-closed.
                Message::Binary(_)
                | Message::Text(_)
                | Message::Ping(_)
                | Message::Pong(_)
                | Message::Frame(_) => {}
            }
        }
        anyhow::bail!("terminal WebSocket ended without a close response")
    })
    .await
    .context("terminal close response timed out")??;
    anyhow::ensure!(
        close.code == CloseCode::Normal,
        "terminal close response code was {:?}, expected normal close",
        close.code
    );
    println!(
        "environment-setup-smoke: Connect ticket opened and cleanly closed raw terminal WebSocket"
    );
    Ok(())
}

fn required_env(name: &str) -> anyhow::Result<String> {
    std::env::var(name).with_context(|| format!("{name} is required"))
}
