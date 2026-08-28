use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use crate::linux::path::{PathError, SocketIdentity};

const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(1);
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_BODY_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone)]
pub struct ChApiClient {
    socket: PathBuf,
    connect_timeout: Duration,
    request_timeout: Duration,
    identity: SocketIdentity,
}

#[derive(Debug, Clone, Deserialize)]
pub struct VmInfo {
    pub state: Option<String>,
    #[serde(default)]
    pub memory_actual_size: Option<u64>,
    #[serde(flatten)]
    pub additional: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize)]
struct DiskAdditionProbe<'a> {
    path: &'a Path,
    readonly: bool,
    direct: bool,
    vhost_user: bool,
    id: &'static str,
    serial: &'static str,
    backing_files: bool,
    sparse: bool,
    image_type: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeniedStatus(u16);

impl DeniedStatus {
    pub fn get(self) -> u16 {
        self.0
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ChApiError {
    #[error("Cloud Hypervisor API socket path is invalid")]
    InvalidSocketPath,
    #[error("Cloud Hypervisor API connection timed out")]
    ConnectTimeout,
    #[error("connect to Cloud Hypervisor API failed")]
    Connect,
    #[error("Cloud Hypervisor API request timed out")]
    RequestTimeout,
    #[error("Cloud Hypervisor API I/O failed")]
    Io,
    #[error("Cloud Hypervisor API returned a malformed or oversized response")]
    MalformedResponse,
    #[error("Cloud Hypervisor API returned HTTP status {0}")]
    HttpStatus(u16),
    #[error("Cloud Hypervisor API returned invalid JSON")]
    InvalidJson,
    #[error("Cloud Hypervisor unexpectedly accepted the forbidden disk probe")]
    ForbiddenDiskAccepted,
    #[error("encode Cloud Hypervisor API request failed")]
    EncodeRequest,
    #[error("Cloud Hypervisor API denial did not prove a Landlock permission failure")]
    AmbiguousDiskDenial,
    #[error(transparent)]
    SocketIdentity(#[from] PathError),
}

impl ChApiClient {
    pub fn new(socket: impl Into<PathBuf>) -> Result<Self, ChApiError> {
        let socket = socket.into();
        if !socket.is_absolute() || socket.as_os_str().is_empty() {
            return Err(ChApiError::InvalidSocketPath);
        }
        let identity = SocketIdentity::capture(&socket)?;
        Ok(Self {
            socket,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            identity,
        })
    }

    pub fn socket(&self) -> &Path {
        &self.socket
    }

    pub async fn ping(&self) -> Result<(), ChApiError> {
        self.expect_success(Method::Get, Endpoint::VmmPing, &[])
            .await
            .map(|_| ())
    }

    pub async fn info(&self) -> Result<VmInfo, ChApiError> {
        let body = self
            .expect_success(Method::Get, Endpoint::VmInfo, &[])
            .await?;
        serde_json::from_slice(&body).map_err(|_| ChApiError::InvalidJson)
    }

    pub async fn shutdown(&self) -> Result<(), ChApiError> {
        self.expect_success(Method::Put, Endpoint::VmShutdown, &[])
            .await
            .map(|_| ())
    }

    /// Exercise Cloud Hypervisor's native Landlock boundary without exposing
    /// a general-purpose hotplug method. A successful response is always an
    /// error: the requested path is deliberately outside the admitted VM tree.
    pub async fn assert_disk_addition_denied(
        &self,
        outside_path: &Path,
    ) -> Result<DeniedStatus, ChApiError> {
        if !outside_path.is_absolute() {
            return Err(ChApiError::EncodeRequest);
        }
        let body = serde_json::to_vec(&DiskAdditionProbe {
            path: outside_path,
            readonly: true,
            direct: false,
            vhost_user: false,
            id: "cw-landlock-negative-probe",
            serial: "CWLANDLOCKPROBE",
            backing_files: false,
            sparse: false,
            image_type: "Raw",
        })
        .map_err(|_| ChApiError::EncodeRequest)?;
        let response = self
            .request(Method::Put, Endpoint::VmAddDisk, &body)
            .await?;
        if (200..300).contains(&response.status) {
            return Err(ChApiError::ForbiddenDiskAccepted);
        }
        if response.status != 500 || !is_permission_denial(&response.body) {
            return Err(ChApiError::AmbiguousDiskDenial);
        }
        Ok(DeniedStatus(response.status))
    }

    async fn expect_success(
        &self,
        method: Method,
        endpoint: Endpoint,
        body: &[u8],
    ) -> Result<Vec<u8>, ChApiError> {
        let response = self.request(method, endpoint, body).await?;
        if !(200..300).contains(&response.status) {
            return Err(ChApiError::HttpStatus(response.status));
        }
        Ok(response.body)
    }

    async fn request(
        &self,
        method: Method,
        endpoint: Endpoint,
        body: &[u8],
    ) -> Result<HttpResponse, ChApiError> {
        if body.len() > MAX_BODY_BYTES {
            return Err(ChApiError::EncodeRequest);
        }
        self.identity.revalidate(&self.socket)?;
        let mut stream =
            tokio::time::timeout(self.connect_timeout, UnixStream::connect(&self.socket))
                .await
                .map_err(|_| ChApiError::ConnectTimeout)?
                .map_err(|_| ChApiError::Connect)?;

        let request = build_request(method, endpoint, body);
        tokio::time::timeout(self.request_timeout, async {
            stream
                .write_all(&request)
                .await
                .map_err(|_| ChApiError::Io)?;
            stream.flush().await.map_err(|_| ChApiError::Io)?;
            read_response(&mut stream).await
        })
        .await
        .map_err(|_| ChApiError::RequestTimeout)?
    }
}

fn is_permission_denial(body: &[u8]) -> bool {
    serde_json::from_slice::<Vec<String>>(body)
        .ok()
        .is_some_and(|messages| {
            messages.iter().any(|message| {
                let message = message.to_ascii_lowercase();
                message.contains("permission denied") || message.contains("operation not permitted")
            })
        })
}

#[derive(Debug, Clone, Copy)]
enum Method {
    Get,
    Put,
}

impl Method {
    fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Put => "PUT",
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum Endpoint {
    VmmPing,
    VmInfo,
    VmShutdown,
    VmAddDisk,
}

impl Endpoint {
    fn path(self) -> &'static str {
        match self {
            Self::VmmPing => "/api/v1/vmm.ping",
            Self::VmInfo => "/api/v1/vm.info",
            Self::VmShutdown => "/api/v1/vm.shutdown",
            Self::VmAddDisk => "/api/v1/vm.add-disk",
        }
    }
}

fn build_request(method: Method, endpoint: Endpoint, body: &[u8]) -> Vec<u8> {
    let mut request = format!(
        "{} {} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        method.as_str(),
        endpoint.path(),
        body.len()
    )
    .into_bytes();
    request.extend_from_slice(body);
    request
}

struct HttpResponse {
    status: u16,
    body: Vec<u8>,
}

async fn read_response(stream: &mut UnixStream) -> Result<HttpResponse, ChApiError> {
    let mut received = Vec::<u8>::new();
    let header_end = loop {
        if received.len() >= MAX_HEADER_BYTES {
            return Err(ChApiError::MalformedResponse);
        }
        let mut byte = [0_u8; 1];
        let count = stream.read(&mut byte).await.map_err(|_| ChApiError::Io)?;
        if count == 0 {
            return Err(ChApiError::MalformedResponse);
        }
        received.push(byte[0]);
        if received.ends_with(b"\r\n\r\n") {
            break received.len();
        }
    };

    let header =
        std::str::from_utf8(&received[..header_end]).map_err(|_| ChApiError::MalformedResponse)?;
    let mut lines = header[..header.len() - 4].split("\r\n");
    let status_line = lines.next().ok_or(ChApiError::MalformedResponse)?;
    let mut status_parts = status_line.split_ascii_whitespace();
    if status_parts.next() != Some("HTTP/1.1") {
        return Err(ChApiError::MalformedResponse);
    }
    let status = status_parts
        .next()
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|value| (100..=599).contains(value))
        .ok_or(ChApiError::MalformedResponse)?;

    let mut content_length = None::<usize>;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(ChApiError::MalformedResponse)?;
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(ChApiError::MalformedResponse);
        }
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(ChApiError::MalformedResponse);
            }
            let length = value
                .trim()
                .parse::<usize>()
                .ok()
                .filter(|length| *length <= MAX_BODY_BYTES)
                .ok_or(ChApiError::MalformedResponse)?;
            content_length = Some(length);
        }
    }

    let content_length = content_length.unwrap_or(0);
    let mut body = vec![0_u8; content_length];
    stream
        .read_exact(&mut body)
        .await
        .map_err(|_| ChApiError::MalformedResponse)?;
    Ok(HttpResponse { status, body })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;
    use tokio::net::UnixListener;
    use tokio::sync::Mutex;

    async fn fake_api(
        response: &'static [u8],
    ) -> (tempfile::TempDir, PathBuf, Arc<Mutex<Vec<u8>>>) {
        let temp = tempfile::tempdir().unwrap();
        let socket = temp.path().join("api.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        let captured = Arc::new(Mutex::new(Vec::new()));
        let server_captured = Arc::clone(&captured);
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut byte = [0_u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).await.unwrap();
                request.push(byte[0]);
            }
            let header = String::from_utf8_lossy(&request);
            let body_length = header
                .lines()
                .find_map(|line| {
                    line.strip_prefix("Content-Length: ")
                        .and_then(|value| value.parse::<usize>().ok())
                })
                .unwrap_or(0);
            let mut body = vec![0; body_length];
            stream.read_exact(&mut body).await.unwrap();
            request.extend(body);
            *server_captured.lock().await = request;
            stream.write_all(response).await.unwrap();
        });
        (temp, socket, captured)
    }

    #[tokio::test]
    async fn typed_info_is_bounded_and_decoded() {
        let body = br#"{"state":"Running","memory_actual_size":536870912}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            String::from_utf8_lossy(body)
        );
        let (_temp, socket, captured) =
            fake_api(Box::leak(response.into_bytes().into_boxed_slice())).await;
        let info = ChApiClient::new(socket).unwrap().info().await.unwrap();
        assert_eq!(info.state.as_deref(), Some("Running"));
        assert_eq!(info.memory_actual_size, Some(536_870_912));
        let request = captured.lock().await;
        assert!(request.starts_with(b"GET /api/v1/vm.info HTTP/1.1\r\n"));
    }

    #[tokio::test]
    async fn disk_probe_treats_non_success_as_required_denial() {
        let (_temp, socket, captured) =
            fake_api(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 75\r\n\r\n[\"The disk could not be added to the VM\",\"Permission denied (os error 13)\"]")
                .await;
        let status = ChApiClient::new(socket)
            .unwrap()
            .assert_disk_addition_denied(Path::new("/outside/private.img"))
            .await
            .unwrap();
        assert_eq!(status.get(), 500);
        let request = captured.lock().await;
        assert!(request.starts_with(b"PUT /api/v1/vm.add-disk HTTP/1.1\r\n"));
        assert!(String::from_utf8_lossy(&request).contains("cw-landlock-negative-probe"));
    }

    #[tokio::test]
    async fn disk_probe_fails_if_cloud_hypervisor_accepts_it() {
        let (_temp, socket, _) =
            fake_api(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n").await;
        assert!(matches!(
            ChApiClient::new(socket)
                .unwrap()
                .assert_disk_addition_denied(Path::new("/outside/private.img"))
                .await,
            Err(ChApiError::ForbiddenDiskAccepted)
        ));
    }

    #[tokio::test]
    async fn validation_and_routing_failures_are_not_landlock_evidence() {
        for status in [400, 404] {
            let response = format!("HTTP/1.1 {status} Failure\r\nContent-Length: 2\r\n\r\n[]");
            let (_temp, socket, _) =
                fake_api(Box::leak(response.into_bytes().into_boxed_slice())).await;
            assert!(matches!(
                ChApiClient::new(socket)
                    .unwrap()
                    .assert_disk_addition_denied(Path::new("/outside/private.img"))
                    .await,
                Err(ChApiError::AmbiguousDiskDenial)
            ));
        }
    }

    #[tokio::test]
    async fn oversized_body_is_rejected_without_allocation() {
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY_BYTES + 1
        );
        let (_temp, socket, _) =
            fake_api(Box::leak(response.into_bytes().into_boxed_slice())).await;
        assert!(matches!(
            ChApiClient::new(socket).unwrap().ping().await,
            Err(ChApiError::MalformedResponse)
        ));
    }
}
