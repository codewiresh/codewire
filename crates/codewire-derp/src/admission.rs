//! Client admission against the coordinators' registered nodes (#2844).
//!
//! A relay with verifiers serves only node keys that a coordinator has
//! registered for a live, authorized session. Every client connects to DERP
//! before it sends its node to a coordinator, and its handshake returns once
//! it has written `ClientInfo`, so the relay holds an unknown key (before
//! `ServerInfo` and before it is routable) and asks again with backoff until
//! the handshake deadline. A key still unknown then is refused; so is every
//! new key while no verifier answers. Admission happens once per connection:
//! a live session is never checked again, so a coordinator outage only stops
//! new keys. Mesh peers prove the mesh key and skip admission.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use codewire_tailnet::derp::NodePublic;
use codewire_tailnet::derp::key::KEY_LEN;
use futures_util::future::join_all;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::Instant;

/// The Connect procedure every verifier serves
/// (`codewire.internal.v1.DerpAdmissionService`). The relay calls it as a
/// Connect unary JSON POST, so it needs no generated client.
pub const CHECK_NODE_KEY_PATH: &str = "/codewire.internal.v1.DerpAdmissionService/CheckNodeKey";

/// Waits between lookups of a key no verifier knows yet. Clients register
/// their node within about a second of connecting, so most need one or two.
const POLL_DELAYS: [Duration; 5] = [
    Duration::from_millis(250),
    Duration::from_millis(500),
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(2),
];
const MAX_POLL_DELAY: Duration = Duration::from_secs(2);
/// How long a key a verifier confirmed is admitted without asking again.
const KNOWN_KEY_TTL: Duration = Duration::from_secs(30);
/// Confirmed keys one relay remembers.
const MAX_KNOWN_KEYS: usize = 16_384;
/// Lookups one relay runs at once, so a flood of unknown keys cannot turn
/// into a flood of coordinator requests.
const MAX_LOOKUPS_IN_FLIGHT: usize = 64;
/// Budget for one verifier request.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(2);
/// Largest verifier response the relay reads.
const MAX_RESPONSE_BYTES: usize = 4096;

/// One verifier's (or all verifiers') answer about a key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// A coordinator has registered this key.
    Known,
    /// A verifier answered and does not know this key.
    Unknown,
    /// No verifier answered.
    Unavailable,
}

impl Verdict {
    /// Combines verifiers: any one that knows the key admits it. Each is
    /// authoritative only for its own nodes, so one that answers "unknown"
    /// outweighs others that did not answer.
    fn combine(verdicts: impl IntoIterator<Item = Verdict>) -> Verdict {
        let mut combined = Verdict::Unavailable;
        for verdict in verdicts {
            match verdict {
                Verdict::Known => return Verdict::Known,
                Verdict::Unknown => combined = Verdict::Unknown,
                Verdict::Unavailable => {}
            }
        }
        combined
    }
}

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Answers whether a node key belongs to a registered node.
pub trait KeyVerifier: Send + Sync + 'static {
    fn verify<'a>(&'a self, key: &'a NodePublic) -> BoxFuture<'a, Verdict>;
}

/// Asks each configured coordinator over plain in-cluster HTTP. The lookup
/// carries no credential: the answer is yes or no about an unguessable public
/// key, and the site's network policy admits only the relay to its listener.
pub struct HttpKeyVerifier {
    endpoints: Vec<HttpEndpoint>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct HttpEndpoint {
    /// `host:port` to dial.
    address: String,
    /// The `Host` header.
    authority: String,
}

impl HttpKeyVerifier {
    /// Parses a comma-separated list of `http://host[:port]` base URLs.
    pub fn parse(raw: &str) -> Result<Self, &'static str> {
        let endpoints = raw
            .split(',')
            .map(str::trim)
            .filter(|url| !url.is_empty())
            .map(parse_endpoint)
            .collect::<Result<Vec<_>, _>>()?;
        if endpoints.is_empty() {
            return Err("no DERP client verifier URLs");
        }
        Ok(Self { endpoints })
    }
}

fn parse_endpoint(url: &str) -> Result<HttpEndpoint, &'static str> {
    let rest = url
        .strip_prefix("http://")
        .ok_or("DERP client verifier URLs must be http://host[:port]")?;
    let authority = rest.trim_end_matches('/');
    if authority.is_empty()
        || authority.contains(['/', '?', '#', '@'])
        || authority.chars().any(char::is_whitespace)
    {
        return Err("DERP client verifier URLs must be http://host[:port]");
    }
    let has_port = match authority.rsplit_once(':') {
        Some((host, port)) => {
            if host.is_empty() || (!host.ends_with(']') && host.contains(':')) {
                // A bare IPv6 address without brackets.
                return Err("DERP client verifier URLs must be http://host[:port]");
            }
            port.parse::<u16>()
                .map_err(|_| "DERP client verifier URL port is invalid")?;
            true
        }
        None => false,
    };
    let address = if has_port {
        authority.to_string()
    } else {
        format!("{authority}:80")
    };
    Ok(HttpEndpoint {
        address,
        authority: authority.to_string(),
    })
}

impl KeyVerifier for HttpKeyVerifier {
    fn verify<'a>(&'a self, key: &'a NodePublic) -> BoxFuture<'a, Verdict> {
        Box::pin(async move {
            let body = check_node_key_body(key);
            let verdicts = join_all(self.endpoints.iter().map(|endpoint| {
                let body = body.as_str();
                async move {
                    match tokio::time::timeout(LOOKUP_TIMEOUT, check_node_key(endpoint, body))
                        .await
                    {
                        Ok(Ok(verdict)) => verdict,
                        Ok(Err(error)) => {
                            tracing::debug!(error = %error, verifier = %endpoint.authority, "derp client verifier unreachable");
                            Verdict::Unavailable
                        }
                        Err(_) => {
                            tracing::debug!(verifier = %endpoint.authority, "derp client verifier timed out");
                            Verdict::Unavailable
                        }
                    }
                }
            }))
            .await;
            Verdict::combine(verdicts)
        })
    }
}

/// The Connect JSON request: `node_key` is proto `bytes`, so base64.
pub fn check_node_key_body(key: &NodePublic) -> String {
    format!(r#"{{"nodeKey":"{}"}}"#, base64_standard(key.as_bytes()))
}

fn base64_standard(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for (i, shift) in [18u32, 12, 6, 0].into_iter().enumerate() {
            if i <= chunk.len() {
                out.push(ALPHABET[((n >> shift) & 0x3f) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

async fn check_node_key(endpoint: &HttpEndpoint, body: &str) -> std::io::Result<Verdict> {
    let mut stream = TcpStream::connect(endpoint.address.as_str()).await?;
    let request = format!(
        "POST {CHECK_NODE_KEY_PATH} HTTP/1.1\r\n\
         Host: {}\r\n\
         Content-Type: application/json\r\n\
         Connect-Protocol-Version: 1\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        endpoint.authority,
        body.len()
    );
    stream.write_all(request.as_bytes()).await?;
    let mut response = Vec::with_capacity(512);
    let mut buf = [0u8; 512];
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        response.extend_from_slice(&buf[..n]);
        if response.len() > MAX_RESPONSE_BYTES {
            return Ok(Verdict::Unavailable);
        }
    }
    Ok(parse_check_node_key_response(&response))
}

/// A `200` whose JSON says `registered: true` is known; any other `200` is
/// unknown (proto3 JSON omits `false`); everything else is no answer.
fn parse_check_node_key_response(response: &[u8]) -> Verdict {
    let Some(split) = response.windows(4).position(|w| w == b"\r\n\r\n") else {
        return Verdict::Unavailable;
    };
    let Ok(head) = std::str::from_utf8(&response[..split]) else {
        return Verdict::Unavailable;
    };
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok());
    if status != Some(200) {
        return Verdict::Unavailable;
    }
    let chunked = lines.any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.trim().eq_ignore_ascii_case("transfer-encoding")
                && value.trim().eq_ignore_ascii_case("chunked")
        })
    });
    let raw = &response[split + 4..];
    let body = if chunked {
        dechunk(raw)
    } else {
        Some(raw.to_vec())
    };
    let Some(body) = body else {
        return Verdict::Unavailable;
    };
    match serde_json::from_slice::<CheckNodeKeyResponse>(&body) {
        Ok(CheckNodeKeyResponse { registered: true }) => Verdict::Known,
        Ok(_) => Verdict::Unknown,
        Err(_) => Verdict::Unavailable,
    }
}

#[derive(serde::Deserialize)]
struct CheckNodeKeyResponse {
    #[serde(default)]
    registered: bool,
}

fn dechunk(mut raw: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line_end = raw.windows(2).position(|w| w == b"\r\n")?;
        let size_text = std::str::from_utf8(&raw[..line_end]).ok()?;
        let size = usize::from_str_radix(size_text.split(';').next()?.trim(), 16).ok()?;
        raw = &raw[line_end + 2..];
        if size == 0 {
            return Some(out);
        }
        if raw.len() < size + 2 {
            return None;
        }
        out.extend_from_slice(&raw[..size]);
        raw = &raw[size + 2..];
    }
}

/// A relay's admission state: its verifier, the keys confirmed recently and
/// the bound on lookups in flight.
pub(crate) struct ClientAdmission {
    verifier: Arc<dyn KeyVerifier>,
    known: Mutex<HashMap<[u8; KEY_LEN], Instant>>,
    lookups: Semaphore,
}

impl ClientAdmission {
    pub(crate) fn new(verifier: Arc<dyn KeyVerifier>) -> Self {
        Self {
            verifier,
            known: Mutex::new(HashMap::new()),
            lookups: Semaphore::new(MAX_LOOKUPS_IN_FLIGHT),
        }
    }

    /// Waits until a verifier knows `key`, or returns the last verdict when
    /// `deadline` passes first.
    pub(crate) async fn admit(&self, key: &NodePublic, deadline: Instant) -> Result<(), Verdict> {
        if self.recently_known(key) {
            return Ok(());
        }
        let mut delays = POLL_DELAYS.iter().copied();
        let mut last = Verdict::Unavailable;
        loop {
            match tokio::time::timeout_at(deadline, self.lookup(key)).await {
                Ok(Verdict::Known) => {
                    self.remember(key);
                    return Ok(());
                }
                Ok(verdict) => last = verdict,
                Err(_) => return Err(last),
            }
            let delay = delays.next().unwrap_or(MAX_POLL_DELAY);
            if tokio::time::timeout_at(deadline, tokio::time::sleep(delay))
                .await
                .is_err()
            {
                return Err(last);
            }
        }
    }

    async fn lookup(&self, key: &NodePublic) -> Verdict {
        let Ok(_permit) = self.lookups.acquire().await else {
            return Verdict::Unavailable;
        };
        self.verifier.verify(key).await
    }

    fn recently_known(&self, key: &NodePublic) -> bool {
        let known = self.known.lock().unwrap_or_else(|e| e.into_inner());
        known
            .get(key.as_bytes())
            .is_some_and(|at| at.elapsed() < KNOWN_KEY_TTL)
    }

    fn remember(&self, key: &NodePublic) {
        let mut known = self.known.lock().unwrap_or_else(|e| e.into_inner());
        if known.len() >= MAX_KNOWN_KEYS {
            known.retain(|_, at| at.elapsed() < KNOWN_KEY_TTL);
            if known.len() >= MAX_KNOWN_KEYS {
                known.clear();
            }
        }
        known.insert(*key.as_bytes(), Instant::now());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn any_known_admits_and_an_answer_outweighs_silence() {
        use Verdict::*;
        assert_eq!(Verdict::combine([Unknown, Known, Unavailable]), Known);
        assert_eq!(Verdict::combine([Unavailable, Unknown]), Unknown);
        assert_eq!(Verdict::combine([Unavailable, Unavailable]), Unavailable);
        assert_eq!(Verdict::combine([]), Unavailable);
    }

    #[test]
    fn verifier_urls_are_plain_http_authorities() {
        let verifier = HttpKeyVerifier::parse(
            " http://codewire-coordinator.dev.svc.cluster.local:8097/ ,http://mesh,http://[::1]:9",
        )
        .unwrap();
        assert_eq!(
            verifier.endpoints,
            vec![
                HttpEndpoint {
                    address: "codewire-coordinator.dev.svc.cluster.local:8097".into(),
                    authority: "codewire-coordinator.dev.svc.cluster.local:8097".into(),
                },
                HttpEndpoint {
                    address: "mesh:80".into(),
                    authority: "mesh".into(),
                },
                HttpEndpoint {
                    address: "[::1]:9".into(),
                    authority: "[::1]:9".into(),
                },
            ]
        );
        for bad in [
            "",
            " , ",
            "https://coordinator:8097",
            "http://coordinator:8097/path",
            "http://user@coordinator",
            "http://coordinator:port",
            "http://::1:9",
        ] {
            assert!(HttpKeyVerifier::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn requests_carry_the_key_as_base64_json() {
        assert_eq!(base64_standard(b""), "");
        assert_eq!(base64_standard(b"f"), "Zg==");
        assert_eq!(base64_standard(b"fo"), "Zm8=");
        assert_eq!(base64_standard(b"foo"), "Zm9v");
        let key = NodePublic::from_raw([0xff; KEY_LEN]);
        assert_eq!(
            check_node_key_body(&key),
            format!(r#"{{"nodeKey":"{}8="}}"#, "/".repeat(42))
        );
    }

    #[test]
    fn responses_map_to_verdicts() {
        let ok =
            |body: &str| format!("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n{body}");
        let verdict = |response: &str| parse_check_node_key_response(response.as_bytes());
        assert_eq!(verdict(&ok(r#"{"registered":true}"#)), Verdict::Known);
        assert_eq!(verdict(&ok("{}")), Verdict::Unknown);
        assert_eq!(verdict(&ok("not json")), Verdict::Unavailable);
        assert_eq!(
            verdict(
                "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n13\r\n{\"registered\":true}\r\n0\r\n\r\n"
            ),
            Verdict::Known
        );
        assert_eq!(
            verdict("HTTP/1.1 503 Service Unavailable\r\n\r\n{\"code\":\"unavailable\"}"),
            Verdict::Unavailable
        );
        assert_eq!(verdict("HTTP/1.1 200 OK\r\n"), Verdict::Unavailable);
    }
}
