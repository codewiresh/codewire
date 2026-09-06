use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, Response};
use axum::routing::post;
use codewire_credential_bridge::{
    CredentialBridge as SharedCredentialBridge, CredentialBridgeOutput,
};
use codewire_gateway_proto::CREDENTIAL_BRIDGE_PROTOCOL_VERSION;
use codewire_gateway_proto::daemon::v1;
use tokio::net::{UnixListener, UnixStream, unix::SocketAddr};
use tonic::{Status, Streaming};

use crate::CredentialBridgeConfig;

const HOST_OPEN_TIMEOUT: Duration = Duration::from_secs(5);

/// Local transport/configuration adapter. All request/response phases and
/// connection cancellation belong to the shared material-free bridge.
#[derive(Clone)]
pub(crate) struct CredentialBridge {
    config: Option<CredentialBridgeConfig>,
    inner: Result<Option<SharedCredentialBridge>, Status>,
}

pub(crate) struct CredentialBridgeConnection {
    pub output: CredentialBridgeOutput,
}

pub(crate) struct CredentialIngress {
    listener: CredentialIngressListener,
    bridge: SharedCredentialBridge,
    socket: SocketGuard,
}

struct CredentialIngressListener {
    inner: UnixListener,
    uid: u32,
}

struct SocketGuard {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl CredentialBridge {
    pub(crate) fn new(config: Option<CredentialBridgeConfig>) -> Self {
        let inner = config
            .as_ref()
            .map(|config| {
                SharedCredentialBridge::new(config.environment_id, config.environment_generation)
            })
            .transpose();
        Self { config, inner }
    }

    pub(crate) fn is_enabled(&self) -> bool {
        self.config.is_some()
    }

    fn shared(&self) -> Result<&SharedCredentialBridge, Status> {
        self.inner
            .as_ref()
            .map_err(Clone::clone)?
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("credential bridge is unavailable"))
    }

    pub(crate) async fn connect(
        &self,
        mut input: Streaming<v1::CredentialBridgeHostMessage>,
    ) -> Result<CredentialBridgeConnection, Status> {
        let config = self
            .config
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("credential bridge is unavailable"))?;
        let first = tokio::time::timeout(HOST_OPEN_TIMEOUT, input.message())
            .await
            .map_err(|_| Status::deadline_exceeded("credential bridge open timed out"))??
            .ok_or_else(|| Status::invalid_argument("credential bridge open is missing"))?;
        let Some(v1::credential_bridge_host_message::Payload::Open(open)) = first.payload else {
            return Err(Status::invalid_argument(
                "credential bridge must begin with open",
            ));
        };
        if open.protocol_version != CREDENTIAL_BRIDGE_PROTOCOL_VERSION
            || open.environment_id != config.environment_id.to_string()
            || open.environment_generation != config.environment_generation
        {
            return Err(Status::failed_precondition(
                "credential bridge identity is invalid",
            ));
        }

        // DaemonService has already authenticated the caller, and the first
        // Open above matched its configured generation. Only now activate.
        let (prepared, output) = self.shared()?.prepare_connection()?;
        let connection = prepared.activate(input).await?;
        tokio::spawn(connection.run());
        Ok(CredentialBridgeConnection { output })
    }

    pub(crate) fn prepare_ingress(&self) -> Result<Option<CredentialIngress>, io::Error> {
        let Some(config) = self.config.as_ref() else {
            return Ok(None);
        };
        validate_config(config)?;
        let bridge = self.shared().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "credential bridge configuration is invalid",
            )
        })?;
        remove_stale_socket(&config.ingress_socket)?;
        let listener = UnixListener::bind(&config.ingress_socket)?;
        std::fs::set_permissions(
            &config.ingress_socket,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )?;
        chown_socket(
            &config.ingress_socket,
            config.ingress_uid,
            config.ingress_gid,
        )?;
        let metadata = std::fs::symlink_metadata(&config.ingress_socket)?;
        use std::os::unix::fs::MetadataExt as _;
        Ok(Some(CredentialIngress {
            listener: CredentialIngressListener {
                inner: listener,
                uid: config.ingress_uid,
            },
            bridge: bridge.clone(),
            socket: SocketGuard {
                path: config.ingress_socket.clone(),
                device: metadata.dev(),
                inode: metadata.ino(),
            },
        }))
    }
}

impl CredentialIngress {
    pub(crate) async fn serve<F>(self, shutdown: F) -> Result<(), io::Error>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let bridge = self.bridge.clone();
        let router = Router::new()
            .route("/v1/responses", post(handle_responses))
            .with_state(bridge);
        let _socket = self.socket;
        axum::serve(self.listener, router)
            .with_graceful_shutdown(shutdown)
            .await
    }
}

async fn handle_responses(
    State(bridge): State<SharedCredentialBridge>,
    request: Request<Body>,
) -> Response<Body> {
    bridge.respond(request).await
}

impl axum::serve::Listener for CredentialIngressListener {
    type Io = UnixStream;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            match self.inner.accept().await {
                Ok((stream, address)) => match stream.peer_cred() {
                    Ok(credential) if credential.uid() == self.uid => return (stream, address),
                    Ok(_) | Err(_) => continue,
                },
                Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

fn validate_config(config: &CredentialBridgeConfig) -> Result<(), io::Error> {
    if config.environment_id.is_nil()
        || config.environment_generation == 0
        || !config.ingress_socket.is_absolute()
        || config.ingress_socket.file_name().is_none()
        || config.ingress_socket.parent().is_none()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "credential bridge configuration is invalid",
        ));
    }
    Ok(())
}

fn remove_stale_socket(path: &Path) -> Result<(), io::Error> {
    use std::os::unix::fs::FileTypeExt as _;

    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => std::fs::remove_file(path),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "credential bridge ingress path contains an unexpected object",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn chown_socket(path: &Path, uid: u32, gid: u32) -> Result<(), io::Error> {
    use std::os::unix::ffi::OsStrExt as _;

    let path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "socket path contains NUL"))?;
    if unsafe { libc::chown(path.as_ptr(), uid, gid) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};

        let Ok(metadata) = std::fs::symlink_metadata(&self.path) else {
            return;
        };
        if metadata.file_type().is_socket()
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
        {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::MetadataExt as _;

    use codewire_gateway_proto::DAEMON_CAPABILITY_CREDENTIAL_BRIDGE;
    use codewire_gateway_proto::daemon::v1::credential_bridge_guest_message::Payload as GuestPayload;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::sync::oneshot;
    use tokio_stream::wrappers::TcpListenerStream;

    use super::*;
    use crate::client::{SessionClient, SessionClientError};
    use crate::execution::ProcessExecution;
    use crate::{Config, serve_grpc_with_incoming};

    const TEST_TOKEN: &str = "credential-bridge-test-generation-token";

    struct Harness {
        _temp: tempfile::TempDir,
        endpoint: String,
        socket: PathBuf,
        environment_id: uuid::Uuid,
        generation: u64,
        shutdown: Option<oneshot::Sender<()>>,
        server: tokio::task::JoinHandle<anyhow::Result<()>>,
    }

    impl Harness {
        async fn start() -> Self {
            let temp = tempfile::tempdir().expect("harness tempdir");
            let workspace_root = temp.path().join("workspace");
            let home_root = temp.path().join("home");
            let socket = temp.path().join("credential.sock");
            std::fs::create_dir_all(&workspace_root).expect("workspace root");
            std::fs::create_dir_all(&home_root).expect("home root");
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("daemon listener");
            let endpoint = format!("http://{}", listener.local_addr().expect("daemon address"));
            let environment_id = uuid::Uuid::new_v4();
            let generation = 7;
            let config = Config {
                listen_addr: "injected:credential-bridge".to_owned(),
                workspace_root,
                home_root,
                auth_token: crate::DaemonAuthToken::new(TEST_TOKEN).unwrap(),
                process_execution: ProcessExecution::Native,
                credential_bridge: Some(CredentialBridgeConfig {
                    environment_id,
                    environment_generation: generation,
                    ingress_socket: socket.clone(),
                    ingress_uid: unsafe { libc::geteuid() },
                    ingress_gid: unsafe { libc::getegid() },
                }),
            };
            let (shutdown_tx, shutdown_rx) = oneshot::channel();
            let server = tokio::spawn(async move {
                serve_grpc_with_incoming(config, TcpListenerStream::new(listener), async {
                    let _ = shutdown_rx.await;
                })
                .await
            });
            tokio::time::timeout(Duration::from_secs(2), async {
                while !socket.exists() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("credential ingress readiness");
            let metadata = std::fs::symlink_metadata(&socket).expect("credential socket");
            assert_eq!(metadata.mode() & 0o777, 0o600);
            Self {
                _temp: temp,
                endpoint,
                socket,
                environment_id,
                generation,
                shutdown: Some(shutdown_tx),
                server,
            }
        }

        async fn client(&self, token: &str) -> SessionClient {
            SessionClient::connect(&self.endpoint, token)
                .await
                .expect("daemon client")
        }

        async fn stop(mut self) {
            self.shutdown.take().expect("shutdown sender").send(()).ok();
            self.server
                .await
                .expect("server task")
                .expect("server stop");
            assert!(!self.socket.exists());
        }
    }

    async fn raw_request(socket: PathBuf, body: &'static [u8]) -> Vec<u8> {
        let mut stream = UnixStream::connect(socket)
            .await
            .expect("credential ingress");
        let head = format!(
            "POST /v1/responses HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream
            .write_all(head.as_bytes())
            .await
            .expect("request head");
        stream.write_all(body).await.expect("request body");
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .expect("HTTP response");
        response
    }

    #[tokio::test]
    async fn authenticated_bridge_carries_only_bounded_guest_request_and_redacted_response() {
        let harness = Harness::start().await;

        let unavailable = raw_request(harness.socket.clone(), br#"{"model":"synthetic"}"#).await;
        assert!(
            unavailable.starts_with(b"HTTP/1.1 503 Service Unavailable"),
            "unexpected unavailable response: {}",
            String::from_utf8_lossy(&unavailable)
        );

        let client = harness.client(TEST_TOKEN).await;
        let capabilities = client
            .get_capabilities(&[DAEMON_CAPABILITY_CREDENTIAL_BRIDGE])
            .await
            .expect("credential bridge capability");
        assert!(
            capabilities
                .capabilities
                .iter()
                .any(|capability| capability == DAEMON_CAPABILITY_CREDENTIAL_BRIDGE)
        );
        let mut bridge = client
            .open_credential_bridge(harness.environment_id, harness.generation)
            .await
            .expect("open credential bridge");
        let ready = bridge.receive().await.expect("ready frame").expect("ready");
        let Some(GuestPayload::Ready(ready)) = ready.payload else {
            panic!("first credential bridge frame was not ready");
        };
        assert_eq!(ready.environment_id, harness.environment_id.to_string());
        assert_eq!(ready.environment_generation, harness.generation);

        let request_task = tokio::spawn(raw_request(
            harness.socket.clone(),
            br#"{"model":"synthetic"}"#,
        ));
        let request = bridge
            .receive()
            .await
            .expect("request frame")
            .expect("request");
        let Some(GuestPayload::Request(request)) = request.payload else {
            panic!("credential bridge did not carry a request");
        };
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/responses");
        assert!(request.query.is_empty());
        assert_eq!(request.body, br#"{"model":"synthetic"}"#);
        assert!(
            request
                .headers
                .iter()
                .any(|header| header.name == "content-type" && header.value == b"application/json")
        );
        assert!(request.headers.iter().all(|header| {
            !matches!(
                header.name.as_str(),
                "content-length" | "connection" | "transfer-encoding"
            )
        }));

        bridge
            .send_response_start(v1::CredentialBridgeResponseStart {
                request_id: request.request_id.clone(),
                status_code: 200,
                headers: vec![v1::CredentialHttpHeader {
                    name: "content-type".to_owned(),
                    value: b"text/event-stream".to_vec(),
                }],
            })
            .await
            .expect("response start");
        for data in [b"data: synthetic".as_slice(), b" response\n\n".as_slice()] {
            bridge
                .send_response_body(v1::CredentialBridgeResponseBody {
                    request_id: request.request_id.clone(),
                    data: data.to_vec(),
                })
                .await
                .expect("response body");
        }
        bridge
            .send_response_end(v1::CredentialBridgeResponseEnd {
                request_id: request.request_id,
            })
            .await
            .expect("response end");

        let response = request_task.await.expect("request task");
        assert!(response.starts_with(b"HTTP/1.1 200 OK"));
        assert!(
            response
                .windows(b"content-type: text/event-stream".len())
                .any(|window| window == b"content-type: text/event-stream")
        );
        for chunk in [b"data: synthetic".as_slice(), b" response\n\n".as_slice()] {
            assert!(
                response.windows(chunk.len()).any(|window| window == chunk),
                "streamed response chunk was absent: {}",
                String::from_utf8_lossy(&response)
            );
        }

        drop(bridge);
        harness.stop().await;
    }

    #[tokio::test]
    async fn bridge_rejects_wrong_generation_identity_and_daemon_token() {
        let harness = Harness::start().await;
        let client = harness.client(TEST_TOKEN).await;
        let wrong_identity = match client
            .open_credential_bridge(uuid::Uuid::new_v4(), harness.generation)
            .await
        {
            Ok(_) => panic!("wrong environment must fail"),
            Err(error) => error,
        };
        assert!(matches!(
            wrong_identity,
            SessionClientError::Status(status)
                if status.code() == tonic::Code::FailedPrecondition
        ));

        let wrong_generation = match client
            .open_credential_bridge(harness.environment_id, harness.generation + 1)
            .await
        {
            Ok(_) => panic!("wrong generation must fail"),
            Err(error) => error,
        };
        assert!(matches!(
            wrong_generation,
            SessionClientError::Status(status)
                if status.code() == tonic::Code::FailedPrecondition
        ));

        let wrong_token = harness.client("wrong-generation-token").await;
        let error = match wrong_token
            .open_credential_bridge(harness.environment_id, harness.generation)
            .await
        {
            Ok(_) => panic!("wrong token must fail"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            SessionClientError::Status(status) if status.code() == tonic::Code::Unauthenticated
        ));
        harness.stop().await;
    }

    #[tokio::test]
    async fn replacement_closes_stale_stream_and_fails_its_pending_request() {
        let harness = Harness::start().await;
        let client = harness.client(TEST_TOKEN).await;
        let mut first = client
            .open_credential_bridge(harness.environment_id, harness.generation)
            .await
            .expect("first bridge");
        assert!(matches!(
            first.receive().await.unwrap().unwrap().payload,
            Some(GuestPayload::Ready(_))
        ));
        let request_task = tokio::spawn(raw_request(harness.socket.clone(), b"{}"));
        assert!(matches!(
            first.receive().await.unwrap().unwrap().payload,
            Some(GuestPayload::Request(_))
        ));

        let mut second = client
            .open_credential_bridge(harness.environment_id, harness.generation)
            .await
            .expect("replacement bridge");
        assert!(matches!(
            second.receive().await.unwrap().unwrap().payload,
            Some(GuestPayload::Ready(_))
        ));
        let response = request_task.await.expect("pending request");
        assert!(response.starts_with(b"HTTP/1.1 503 Service Unavailable"));
        assert!(first.receive().await.unwrap().is_none());

        harness.stop().await;
    }

    #[tokio::test]
    async fn out_of_order_host_body_fails_closed_and_detaches_the_bridge() {
        let harness = Harness::start().await;
        let client = harness.client(TEST_TOKEN).await;
        let mut bridge = client
            .open_credential_bridge(harness.environment_id, harness.generation)
            .await
            .expect("bridge");
        assert!(matches!(
            bridge.receive().await.unwrap().unwrap().payload,
            Some(GuestPayload::Ready(_))
        ));

        let request_task = tokio::spawn(raw_request(harness.socket.clone(), b"{}"));
        let request = bridge
            .receive()
            .await
            .expect("request frame")
            .expect("request");
        let Some(GuestPayload::Request(request)) = request.payload else {
            panic!("credential bridge did not carry a request");
        };
        bridge
            .send_response_body(v1::CredentialBridgeResponseBody {
                request_id: request.request_id,
                data: b"body-before-start".to_vec(),
            })
            .await
            .expect("enqueue malformed host frame");

        assert!(matches!(
            bridge.receive().await,
            Err(SessionClientError::Status(status))
                if status.code() == tonic::Code::InvalidArgument
        ));
        let response = request_task.await.expect("pending request");
        assert!(response.starts_with(b"HTTP/1.1 503 Service Unavailable"));

        harness.stop().await;
    }
}
