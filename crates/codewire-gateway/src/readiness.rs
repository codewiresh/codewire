use std::io;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use codewire_tls::{ClientTlsEndpoint, ServerTlsFiles};
use tokio::net::TcpStream;

#[derive(Clone, Debug)]
pub struct ReadinessState {
    ssh_listen_addr: String,
    timeout: Duration,
    startup: Option<StartupGate>,
    credentials: Option<CredentialReadiness>,
}

/// Closed while the gateway waits for its workspace daemon. `/readyz` is
/// served during that wait so probes get an immediate 503 rather than a
/// timeout. The bound SSH listener already accepts TCP then, so the SSH probe
/// alone would report ready before the gateway can serve a session.
#[derive(Clone, Debug, Default)]
pub(crate) struct StartupGate(Arc<AtomicBool>);

impl StartupGate {
    pub(crate) fn open(&self) {
        self.0.store(true, Ordering::Release);
    }

    fn is_open(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct CredentialReadiness {
    live: Arc<AtomicBool>,
    server: ServerTlsFiles,
    broker: ClientTlsEndpoint,
}

impl CredentialReadiness {
    pub(crate) fn new(
        live: Arc<AtomicBool>,
        server: ServerTlsFiles,
        broker: ClientTlsEndpoint,
    ) -> Self {
        Self {
            live,
            server,
            broker,
        }
    }

    async fn validate(&self) -> Result<(), ()> {
        if !self.live.load(Ordering::Acquire) {
            return Err(());
        }
        // Validate the current projection on each probe, not a cached startup
        // success. This never dials the broker or reads a projected Pod token.
        tokio::try_join!(self.server.validate(), self.broker.validate()).map_err(|_| ())?;
        self.live.load(Ordering::Acquire).then_some(()).ok_or(())
    }
}

impl ReadinessState {
    pub fn new(ssh_listen_addr: impl Into<String>) -> Self {
        Self {
            ssh_listen_addr: ssh_listen_addr.into(),
            timeout: Duration::from_secs(1),
            startup: None,
            credentials: None,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub(crate) fn with_credentials(mut self, credentials: Option<CredentialReadiness>) -> Self {
        self.credentials = credentials;
        self
    }

    pub(crate) fn with_startup_gate(mut self, startup: StartupGate) -> Self {
        self.startup = Some(startup);
        self
    }
}

pub fn router(state: ReadinessState) -> Router {
    Router::new()
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        .with_state(state)
}

/// Counters only, from the gateway's private registry.
async fn metrics() -> impl IntoResponse {
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        crate::metrics::render(),
    )
}

pub async fn readiness_check(ssh_listen_addr: &str) -> io::Result<()> {
    let dial_addr = readiness_dial_addr(ssh_listen_addr);
    let stream = TcpStream::connect(dial_addr).await?;
    drop(stream);
    Ok(())
}

pub async fn readiness_check_with_timeout(
    ssh_listen_addr: &str,
    timeout: Duration,
) -> io::Result<()> {
    tokio::time::timeout(timeout, readiness_check(ssh_listen_addr))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "readiness check timed out"))?
}

pub fn readiness_dial_addr(listen_addr: &str) -> String {
    let Some((host, port)) = listen_addr.rsplit_once(':') else {
        return listen_addr.into();
    };
    match host {
        "" | "0.0.0.0" | "::" | "[::]" => format!("127.0.0.1:{port}"),
        _ => listen_addr.into(),
    }
}

async fn readyz(State(state): State<ReadinessState>) -> impl IntoResponse {
    if state
        .startup
        .as_ref()
        .is_some_and(|startup| !startup.is_open())
    {
        return (StatusCode::SERVICE_UNAVAILABLE, "not ready\n").into_response();
    }
    // One short deadline covers both the existing SSH probe and current TLS
    // file validation. A slow projection cannot accumulate serial timeouts.
    let result = tokio::time::timeout(state.timeout, async {
        tokio::try_join!(
            async {
                readiness_check(&state.ssh_listen_addr)
                    .await
                    .map_err(|_| ())
            },
            async {
                match &state.credentials {
                    Some(credentials) => credentials.validate().await,
                    None => Ok(()),
                }
            },
        )?;
        if state
            .credentials
            .as_ref()
            .is_some_and(|credentials| !credentials.live.load(Ordering::Acquire))
        {
            return Err(());
        }
        Ok::<_, ()>(())
    })
    .await;
    match result {
        Ok(Ok(())) => (StatusCode::OK, "ok\n").into_response(),
        _ => (StatusCode::SERVICE_UNAVAILABLE, "not ready\n").into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use std::net::SocketAddr;
    use tower::ServiceExt;

    #[test]
    fn dial_addr_rewrites_unspecified_hosts() {
        assert_eq!(readiness_dial_addr("0.0.0.0:2222"), "127.0.0.1:2222");
        assert_eq!(readiness_dial_addr(":2222"), "127.0.0.1:2222");
        assert_eq!(readiness_dial_addr("[::]:2222"), "127.0.0.1:2222");
        assert_eq!(readiness_dial_addr("127.0.0.1:2222"), "127.0.0.1:2222");
    }

    #[tokio::test]
    async fn credential_readiness_requires_live_validated_listener() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let live = Arc::new(AtomicBool::new(false));
        let identity = crate::credentials::tls_test_support::Identity::new("localhost");
        let app = router(
            ReadinessState::new(listener.local_addr().unwrap().to_string()).with_credentials(Some(
                CredentialReadiness::new(
                    live.clone(),
                    identity.files(),
                    ClientTlsEndpoint::new("https://localhost:1".into(), identity.roots.clone())
                        .unwrap(),
                ),
            )),
        );
        for expected in [
            StatusCode::SERVICE_UNAVAILABLE,
            StatusCode::OK,
            StatusCode::SERVICE_UNAVAILABLE,
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/readyz")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), expected);
            live.store(expected != StatusCode::OK, Ordering::Release);
        }
    }

    #[tokio::test]
    async fn credential_readiness_checks_each_current_tls_projection_without_broker_dial() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let identity = crate::credentials::tls_test_support::Identity::new("localhost");
        let app = router(
            ReadinessState::new(listener.local_addr().unwrap().to_string()).with_credentials(Some(
                CredentialReadiness::new(
                    Arc::new(AtomicBool::new(true)),
                    identity.files(),
                    // An unavailable destination proves this is validation only.
                    ClientTlsEndpoint::new("https://localhost:1".into(), identity.roots.clone())
                        .unwrap(),
                ),
            )),
        );
        for path in [&identity.certificate, &identity.key, &identity.roots] {
            let original = std::fs::read(path).unwrap();
            for (bytes, expected) in [
                (original.as_slice(), StatusCode::OK),
                (
                    b"synthetic-private-readiness-canary".as_slice(),
                    StatusCode::SERVICE_UNAVAILABLE,
                ),
                (original.as_slice(), StatusCode::OK),
            ] {
                std::fs::write(path, bytes).unwrap();
                let response = tokio::time::timeout(
                    Duration::from_secs(2),
                    app.clone().oneshot(
                        Request::builder()
                            .uri("/readyz")
                            .body(Body::empty())
                            .unwrap(),
                    ),
                )
                .await
                .expect("readiness exceeded its single deadline")
                .unwrap();
                assert_eq!(response.status(), expected);
                let body = axum::body::to_bytes(response.into_body(), 1024)
                    .await
                    .unwrap();
                assert_eq!(
                    &body[..],
                    if expected == StatusCode::OK {
                        b"ok\n".as_slice()
                    } else {
                        b"not ready\n".as_slice()
                    }
                );
            }
        }
    }

    #[tokio::test]
    async fn metrics_serves_only_the_gateway_counters() {
        crate::metrics::observe_daemon_credential_refresh(
            crate::metrics::RefreshOutcome::Unchanged,
        );
        let response = router(ReadinessState::new("127.0.0.1:1"))
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(
            text.contains(
                "codewire_gateway_daemon_credential_refreshes_total{result=\"unchanged\"}"
            ),
            "{text}"
        );
        assert!(!text.contains("process_"), "{text}");
    }

    #[tokio::test]
    async fn readyz_returns_ok_when_ssh_listener_accepts_tcp() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let app = router(ReadinessState::new(format!("0.0.0.0:{}", addr.port())));
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/readyz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], b"ok\n");
    }

    #[tokio::test]
    async fn readyz_is_unavailable_until_the_startup_gate_opens() {
        // A bound listener accepts TCP before the gateway serves SSH.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let startup = StartupGate::default();
        let app = router(
            ReadinessState::new(listener.local_addr().unwrap().to_string())
                .with_startup_gate(startup.clone()),
        );
        let probe = || async {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/readyz")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = response.status();
            let body = axum::body::to_bytes(response.into_body(), 1024)
                .await
                .unwrap();
            (status, body)
        };

        let (status, body) = probe().await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(&body[..], b"not ready\n");

        startup.open();
        let (status, body) = probe().await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(&body[..], b"ok\n");
    }

    #[tokio::test]
    async fn readyz_returns_unavailable_when_ssh_listener_is_closed() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        drop(listener);

        let app = router(
            ReadinessState::new(format!("127.0.0.1:{}", addr.port()))
                .with_timeout(Duration::from_millis(100)),
        );
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/readyz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], b"not ready\n");
    }
}
