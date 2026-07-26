use std::io;
use std::time::Duration;

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use tokio::net::TcpStream;

#[derive(Clone, Debug)]
pub struct ReadinessState {
    ssh_listen_addr: String,
    timeout: Duration,
}

impl ReadinessState {
    pub fn new(ssh_listen_addr: impl Into<String>) -> Self {
        Self {
            ssh_listen_addr: ssh_listen_addr.into(),
            timeout: Duration::from_secs(1),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

pub fn router(state: ReadinessState) -> Router {
    Router::new()
        .route("/readyz", get(readyz))
        .with_state(state)
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
    match readiness_check_with_timeout(&state.ssh_listen_addr, state.timeout).await {
        Ok(()) => (StatusCode::OK, "ok\n").into_response(),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "not ready\n").into_response(),
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
