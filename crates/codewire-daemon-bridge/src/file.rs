//! Shared public `FileService` adapter for the private guest daemon.
//!
//! Uploads are staged beside their destination and renamed only after the
//! complete stream arrives. A cancellation guard removes the staging object;
//! no public response or log contains its private name.

use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use buffa_types::Timestamp;
use codewire_gateway_proto::DAEMON_CAPABILITY_FILES;
use codewire_proto::codewire::v1 as proto;
use connectrpc::{InboundStream, RequestContext, ServiceRequest, ServiceResult, ServiceStream};
use futures::StreamExt as _;
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::client::{DaemonClient, DaemonClientError, v1};
use crate::session::FieldViolation;

const STREAM_BUFFER: usize = 8;
const DOWNLOAD_CHUNK_BYTES: i64 = 64 * 1024;
const UPLOAD_CHUNK_BYTES: usize = 64 * 1024;
const UPLOAD_MODE: u32 = 0o644;
const UPLOAD_DIRECTORY_MODE: u32 = 0o755;
const MAX_UPLOAD_PATH_BYTES: usize = 4096;
const MAX_UPLOAD_PATH_COMPONENTS: usize = 256;
const UPLOAD_STAGING_PREFIX: &str = ".codewire-upload-";
const GO_MODE_DIR: u32 = 1 << 31;
const GO_MODE_SYMLINK: u32 = 1 << 27;
const GO_MODE_DEVICE: u32 = 1 << 26;
const GO_MODE_NAMED_PIPE: u32 = 1 << 25;
const GO_MODE_SOCKET: u32 = 1 << 24;
const GO_MODE_CHAR_DEVICE: u32 = 1 << 21;
const GO_MODE_IRREGULAR: u32 = 1 << 19;
const GO_MODE_NON_REGULAR: u32 = GO_MODE_DIR
    | GO_MODE_SYMLINK
    | GO_MODE_DEVICE
    | GO_MODE_NAMED_PIPE
    | GO_MODE_SOCKET
    | GO_MODE_IRREGULAR;

#[async_trait]
pub trait FileBackend: Clone + Send + Sync + 'static {
    fn authorize(&self, ctx: &RequestContext) -> Result<(), connectrpc::ConnectError>;

    fn validation_error(
        &self,
        violations: Vec<FieldViolation>,
        request_id: Option<&str>,
    ) -> connectrpc::ConnectError;

    fn daemon_error(
        &self,
        error: DaemonClientError,
        request_id: Option<&str>,
    ) -> connectrpc::ConnectError;

    fn invalid_file_type(&self, request_id: Option<&str>) -> connectrpc::ConnectError;

    async fn daemon(
        &self,
        ctx: &RequestContext,
        org_id: &str,
        environment_id: &str,
    ) -> Result<DaemonClient, connectrpc::ConnectError>;
}

#[derive(Clone)]
pub struct FileBridge<B> {
    backend: B,
}

impl<B> FileBridge<B> {
    pub fn new(backend: B) -> Self {
        Self { backend }
    }
}

pub fn router<B>(backend: B) -> connectrpc::Router
where
    B: FileBackend,
{
    connectrpc::Router::new().add_service(Arc::new(FileBridge::new(backend)))
}

#[allow(refining_impl_trait)]
impl<B> proto::FileService for FileBridge<B>
where
    B: FileBackend,
{
    async fn list_files(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::ListFilesRequest>,
    ) -> ServiceResult<proto::ListFilesResponse> {
        self.backend.authorize(&ctx)?;
        let request_id = request_id(&ctx);
        let request = request.to_owned_message();
        let mut violations = coordinate_violations(
            &request.org_id,
            &request.environment_id,
            None,
            "/org_id",
            "/environment_id",
            "/path",
        );
        if !request.page_token.is_empty() {
            violations.push(FieldViolation {
                path: "/page_token",
                message: "is not recognized",
            });
        }
        if !violations.is_empty() {
            return Err(self.backend.validation_error(violations, request_id));
        }
        let daemon = self
            .backend
            .daemon(&ctx, &request.org_id, &request.environment_id)
            .await?;
        daemon
            .require_ready(&[DAEMON_CAPABILITY_FILES])
            .await
            .map_err(|error| self.backend.daemon_error(error, request_id))?;
        let entries = daemon
            .list_files(request.path)
            .await
            .map_err(|error| self.backend.daemon_error(error, request_id))?;
        connectrpc::Response::ok(proto::ListFilesResponse {
            entries: entries
                .into_iter()
                .filter(|entry| !entry.name.starts_with(UPLOAD_STAGING_PREFIX))
                .map(public_file_entry)
                .collect(),
            next_page_token: String::new(),
            ..Default::default()
        })
    }

    async fn download_file(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::DownloadFileRequest>,
    ) -> ServiceResult<ServiceStream<proto::DownloadFileResponse>> {
        self.backend.authorize(&ctx)?;
        let request_id = owned_request_id(&ctx);
        let request = request.to_owned_message();
        let violations = coordinate_violations(
            &request.org_id,
            &request.environment_id,
            Some(&request.path),
            "/org_id",
            "/environment_id",
            "/path",
        );
        if !violations.is_empty() {
            return Err(self
                .backend
                .validation_error(violations, request_id.as_deref()));
        }
        let daemon = self
            .backend
            .daemon(&ctx, &request.org_id, &request.environment_id)
            .await?;
        daemon
            .require_ready(&[DAEMON_CAPABILITY_FILES])
            .await
            .map_err(|error| self.backend.daemon_error(error, request_id.as_deref()))?;
        let metadata = daemon
            .stat_file(request.path.clone(), false)
            .await
            .map_err(|error| self.backend.daemon_error(error, request_id.as_deref()))?;
        if metadata.mode & GO_MODE_NON_REGULAR != 0 {
            return Err(self.backend.invalid_file_type(request_id.as_deref()));
        }
        let info = public_file_entry(metadata.clone());
        let (tx, rx) = mpsc::channel(STREAM_BUFFER);
        tokio::spawn(relay_download(
            daemon,
            request.path,
            metadata.size.max(0),
            info,
            self.backend.clone(),
            request_id,
            tx,
        ));
        connectrpc::Response::stream_ok(receiver_stream(rx))
    }

    async fn upload_file(
        &self,
        ctx: RequestContext,
        mut requests: InboundStream<proto::UploadFileRequest>,
    ) -> ServiceResult<proto::UploadFileResponse> {
        self.backend.authorize(&ctx)?;
        let request_id = owned_request_id(&ctx);
        let first = match requests.next().await {
            Some(Ok(message)) => message.to_owned_message(),
            Some(Err(error)) => return Err(error),
            None => {
                return Err(self.backend.validation_error(
                    vec![FieldViolation {
                        path: "/payload",
                        message: "header must be the first message",
                    }],
                    request_id.as_deref(),
                ));
            }
        };
        let header = match first.payload {
            Some(proto::upload_file_request::Payload::Header(header)) => *header,
            _ => {
                return Err(self.backend.validation_error(
                    vec![FieldViolation {
                        path: "/payload",
                        message: "header must be the first message",
                    }],
                    request_id.as_deref(),
                ));
            }
        };
        let violations = coordinate_violations(
            &header.org_id,
            &header.environment_id,
            Some(&header.path),
            "/header/org_id",
            "/header/environment_id",
            "/header/path",
        );
        if !violations.is_empty() {
            return Err(self
                .backend
                .validation_error(violations, request_id.as_deref()));
        }
        let destination = header.path.trim().to_owned();
        let staging_path = staging_path(&destination).map_err(|violation| {
            self.backend
                .validation_error(vec![violation], request_id.as_deref())
        })?;
        let daemon = self
            .backend
            .daemon(&ctx, &header.org_id, &header.environment_id)
            .await?;
        daemon
            .require_ready(&[DAEMON_CAPABILITY_FILES])
            .await
            .map_err(|error| self.backend.daemon_error(error, request_id.as_deref()))?;
        ensure_upload_parent(&daemon, &staging_path, &self.backend, request_id.as_deref()).await?;
        daemon
            .open_file(v1::OpenFileRequest {
                path: staging_path.clone(),
                options: Some(v1::FileOpenOptions {
                    write: true,
                    create: true,
                    truncate: true,
                    exclusive: true,
                    ..Default::default()
                }),
                perm: 0o600,
            })
            .await
            .map_err(|error| self.backend.daemon_error(error, request_id.as_deref()))?;
        let mut staging = UploadStaging::new(daemon, staging_path);
        let mut offset = 0_i64;

        while let Some(message) = requests.next().await {
            let message = match message {
                Ok(message) => message.to_owned_message(),
                Err(error) => {
                    staging.abort().await;
                    return Err(error);
                }
            };
            let chunk = match message.payload {
                Some(proto::upload_file_request::Payload::Chunk(chunk)) => chunk,
                Some(proto::upload_file_request::Payload::Header(_)) => {
                    staging.abort().await;
                    return Err(self.backend.validation_error(
                        vec![FieldViolation {
                            path: "/payload/header",
                            message: "must appear only once",
                        }],
                        request_id.as_deref(),
                    ));
                }
                None => {
                    staging.abort().await;
                    return Err(self.backend.validation_error(
                        vec![FieldViolation {
                            path: "/payload",
                            message: "is required",
                        }],
                        request_id.as_deref(),
                    ));
                }
            };
            for private_chunk in chunk.chunks(UPLOAD_CHUNK_BYTES) {
                let expected = match i64::try_from(private_chunk.len()) {
                    Ok(expected) => expected,
                    Err(_) => {
                        staging.abort().await;
                        return Err(self.backend.daemon_error(
                            DaemonClientError::InvalidFrame("file write length"),
                            request_id.as_deref(),
                        ));
                    }
                };
                let written = match staging
                    .client
                    .write_file(v1::WriteRequest {
                        path: staging.path().to_string(),
                        offset,
                        data: private_chunk.to_vec(),
                    })
                    .await
                {
                    Ok(written) => written,
                    Err(error) => {
                        staging.abort().await;
                        return Err(self.backend.daemon_error(error, request_id.as_deref()));
                    }
                };
                if written != expected {
                    staging.abort().await;
                    return Err(self.backend.daemon_error(
                        DaemonClientError::InvalidFrame("file write"),
                        request_id.as_deref(),
                    ));
                }
                offset = match offset.checked_add(written) {
                    Some(offset) => offset,
                    None => {
                        staging.abort().await;
                        return Err(self.backend.daemon_error(
                            DaemonClientError::InvalidFrame("file write offset"),
                            request_id.as_deref(),
                        ));
                    }
                };
            }
        }

        if let Err(error) = staging
            .client
            .set_stat(v1::SetStatRequest {
                path: staging.path().to_string(),
                mode: Some(UPLOAD_MODE),
                ..Default::default()
            })
            .await
        {
            staging.abort().await;
            return Err(self.backend.daemon_error(error, request_id.as_deref()));
        }
        if let Err(error) = staging
            .client
            .rename(v1::RenameRequest {
                old_path: staging.path().to_string(),
                new_path: destination.clone(),
            })
            .await
        {
            staging.abort().await;
            return Err(self.backend.daemon_error(error, request_id.as_deref()));
        }
        staging.commit();
        connectrpc::Response::ok(proto::UploadFileResponse {
            path: destination,
            size: offset,
            ..Default::default()
        })
    }
}

async fn ensure_upload_parent<B: FileBackend>(
    daemon: &DaemonClient,
    staging_path: &str,
    backend: &B,
    request_id: Option<&str>,
) -> Result<(), connectrpc::ConnectError> {
    let mut missing = Vec::new();
    let mut current = Path::new(staging_path)
        .parent()
        .unwrap_or_else(|| Path::new(""));

    loop {
        let path = current.to_string_lossy().into_owned();
        match daemon.stat_file(path.clone(), true).await {
            Ok(metadata) if metadata.mode & GO_MODE_DIR != 0 => break,
            Ok(_) => return Err(backend.invalid_file_type(request_id)),
            Err(DaemonClientError::Status(status)) if status.code() == tonic::Code::NotFound => {
                missing.push(path);
                current = current.parent().ok_or_else(|| {
                    backend.daemon_error(DaemonClientError::Status(status), request_id)
                })?;
            }
            Err(error) => return Err(backend.daemon_error(error, request_id)),
        }
    }

    for path in missing.into_iter().rev() {
        match daemon
            .mkdir(v1::MkdirRequest {
                path: path.clone(),
                perm: UPLOAD_DIRECTORY_MODE,
            })
            .await
        {
            Ok(()) => {}
            Err(DaemonClientError::Status(status))
                if status.code() == tonic::Code::AlreadyExists =>
            {
                let metadata = daemon
                    .stat_file(path, true)
                    .await
                    .map_err(|error| backend.daemon_error(error, request_id))?;
                if metadata.mode & GO_MODE_DIR == 0 {
                    return Err(backend.invalid_file_type(request_id));
                }
            }
            Err(error) => return Err(backend.daemon_error(error, request_id)),
        }
    }
    Ok(())
}

async fn relay_download<B: FileBackend>(
    daemon: DaemonClient,
    path: String,
    size: i64,
    info: proto::FileEntry,
    backend: B,
    request_id: Option<String>,
    tx: mpsc::Sender<Result<proto::DownloadFileResponse, connectrpc::ConnectError>>,
) {
    if tx
        .send(Ok(proto::DownloadFileResponse {
            payload: Some(proto::download_file_response::Payload::Info(Box::new(info))),
            ..Default::default()
        }))
        .await
        .is_err()
    {
        return;
    }
    let mut offset = 0_i64;
    while offset < size {
        let length = DOWNLOAD_CHUNK_BYTES.min(size - offset);
        let chunk = match daemon
            .read_file(v1::ReadRequest {
                path: path.clone(),
                offset,
                length,
            })
            .await
        {
            Ok(chunk) => chunk,
            Err(error) => {
                let _ = tx
                    .send(Err(backend.daemon_error(error, request_id.as_deref())))
                    .await;
                return;
            }
        };
        if chunk.is_empty() {
            let _ = tx
                .send(Err(backend.daemon_error(
                    DaemonClientError::InvalidFrame("file read ended before the advertised size"),
                    request_id.as_deref(),
                )))
                .await;
            return;
        }
        let Ok(chunk_len) = i64::try_from(chunk.len()) else {
            let _ = tx
                .send(Err(backend.daemon_error(
                    DaemonClientError::InvalidFrame("file read length"),
                    request_id.as_deref(),
                )))
                .await;
            return;
        };
        if chunk_len > length {
            let _ = tx
                .send(Err(backend.daemon_error(
                    DaemonClientError::InvalidFrame("file read length"),
                    request_id.as_deref(),
                )))
                .await;
            return;
        }
        offset = match offset.checked_add(chunk_len) {
            Some(offset) => offset,
            None => {
                let _ = tx
                    .send(Err(backend.daemon_error(
                        DaemonClientError::InvalidFrame("file read offset"),
                        request_id.as_deref(),
                    )))
                    .await;
                return;
            }
        };
        if tx
            .send(Ok(proto::DownloadFileResponse {
                payload: Some(proto::download_file_response::Payload::Chunk(chunk)),
                ..Default::default()
            }))
            .await
            .is_err()
        {
            return;
        }
    }
}

struct UploadStaging {
    client: DaemonClient,
    path: Option<String>,
}

impl UploadStaging {
    fn new(client: DaemonClient, path: String) -> Self {
        Self {
            client,
            path: Some(path),
        }
    }

    fn path(&self) -> &str {
        self.path.as_deref().expect("active upload staging path")
    }

    async fn abort(&mut self) {
        let Some(path) = self.path.take() else {
            return;
        };
        let _ = self
            .client
            .remove(v1::RemoveRequest { path, dir: false })
            .await;
    }

    fn commit(&mut self) {
        self.path = None;
    }
}

impl Drop for UploadStaging {
    fn drop(&mut self) {
        let Some(path) = self.path.take() else {
            return;
        };
        let client = self.client.clone();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let _ = client.remove(v1::RemoveRequest { path, dir: false }).await;
            });
        }
    }
}

fn coordinate_violations(
    org_id: &str,
    environment_id: &str,
    path: Option<&str>,
    org_path: &'static str,
    environment_path: &'static str,
    file_path: &'static str,
) -> Vec<FieldViolation> {
    let mut violations = Vec::new();
    if org_id.trim().is_empty() {
        violations.push(FieldViolation {
            path: org_path,
            message: "must not be empty",
        });
    }
    if environment_id.trim().is_empty() {
        violations.push(FieldViolation {
            path: environment_path,
            message: "must not be empty",
        });
    }
    if path.is_some_and(|path| path.trim().is_empty()) {
        violations.push(FieldViolation {
            path: file_path,
            message: "must not be empty",
        });
    } else if path.is_some_and(reserved_upload_path) {
        violations.push(FieldViolation {
            path: file_path,
            message: "uses a reserved internal name",
        });
    }
    violations
}

fn staging_path(destination: &str) -> Result<String, FieldViolation> {
    if destination.len() > MAX_UPLOAD_PATH_BYTES
        || Path::new(destination).components().count() > MAX_UPLOAD_PATH_COMPONENTS
        || destination.as_bytes().contains(&0)
    {
        return Err(FieldViolation {
            path: "/header/path",
            message: "is too long or contains an invalid character",
        });
    }
    if destination.ends_with('/') {
        return Err(FieldViolation {
            path: "/header/path",
            message: "must name a file",
        });
    }
    let destination = Path::new(destination);
    if destination
        .file_name()
        .filter(|name| !name.is_empty())
        .is_none()
    {
        return Err(FieldViolation {
            path: "/header/path",
            message: "must name a file",
        });
    }
    let temporary = format!("{UPLOAD_STAGING_PREFIX}{}", Uuid::new_v4().simple());
    let parent = destination.parent().unwrap_or_else(|| Path::new(""));
    let staging = if parent.as_os_str().is_empty() {
        temporary
    } else {
        parent.join(temporary).to_string_lossy().into_owned()
    };
    if staging.len() > MAX_UPLOAD_PATH_BYTES {
        return Err(FieldViolation {
            path: "/header/path",
            message: "is too long or contains an invalid character",
        });
    }
    Ok(staging)
}

fn reserved_upload_path(path: &str) -> bool {
    Path::new(path).components().any(|component| {
        let std::path::Component::Normal(component) = component else {
            return false;
        };
        component
            .to_str()
            .is_some_and(|component| component.starts_with(UPLOAD_STAGING_PREFIX))
    })
}

fn public_file_entry(entry: v1::FileMetadata) -> proto::FileEntry {
    proto::FileEntry {
        name: entry.name,
        size: entry.size,
        is_dir: entry.mode & GO_MODE_DIR != 0,
        mode: posix_mode(entry.mode),
        mod_time: entry
            .mod_time
            .map(|timestamp| Timestamp::from_unix(timestamp.seconds, timestamp.nanos))
            .into(),
        ..Default::default()
    }
}

fn posix_mode(mode: u32) -> u32 {
    let kind = if mode & GO_MODE_DIR != 0 {
        0o040000
    } else if mode & GO_MODE_SYMLINK != 0 {
        0o120000
    } else if mode & GO_MODE_SOCKET != 0 {
        0o140000
    } else if mode & GO_MODE_NAMED_PIPE != 0 {
        0o010000
    } else if mode & GO_MODE_DEVICE != 0 && mode & GO_MODE_CHAR_DEVICE != 0 {
        0o020000
    } else if mode & GO_MODE_DEVICE != 0 {
        0o060000
    } else {
        0o100000
    };
    kind | (mode & 0o7777)
}

fn request_id(ctx: &RequestContext) -> Option<&str> {
    ctx.headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
}

fn owned_request_id(ctx: &RequestContext) -> Option<String> {
    request_id(ctx).map(str::to_owned)
}

fn receiver_stream<T: Send + 'static>(
    rx: mpsc::Receiver<Result<T, connectrpc::ConnectError>>,
) -> impl futures::Stream<Item = Result<T, connectrpc::ConnectError>> + Send + 'static {
    futures::stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|item| (item, rx))
    })
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use tokio_stream::wrappers::ReceiverStream;

    use super::*;
    use crate::test_support::DaemonHarness;

    #[derive(Clone)]
    struct TestBackend {
        daemon: DaemonClient,
        deny_authorization: bool,
    }

    #[async_trait::async_trait]
    impl FileBackend for TestBackend {
        fn authorize(&self, _ctx: &RequestContext) -> Result<(), connectrpc::ConnectError> {
            if self.deny_authorization {
                Err(connectrpc::ConnectError::unauthenticated(
                    "test authorization required",
                ))
            } else {
                Ok(())
            }
        }

        fn validation_error(
            &self,
            _violations: Vec<FieldViolation>,
            _request_id: Option<&str>,
        ) -> connectrpc::ConnectError {
            connectrpc::ConnectError::invalid_argument("invalid test request")
        }

        fn daemon_error(
            &self,
            _error: DaemonClientError,
            _request_id: Option<&str>,
        ) -> connectrpc::ConnectError {
            connectrpc::ConnectError::internal("test daemon request failed")
        }

        fn invalid_file_type(&self, _request_id: Option<&str>) -> connectrpc::ConnectError {
            connectrpc::ConnectError::invalid_argument("invalid test file type")
        }

        async fn daemon(
            &self,
            _ctx: &RequestContext,
            _org_id: &str,
            _environment_id: &str,
        ) -> Result<DaemonClient, connectrpc::ConnectError> {
            Ok(self.daemon.clone())
        }
    }

    #[test]
    fn private_go_modes_preserve_public_posix_contract() {
        assert_eq!(posix_mode(0o755), 0o100755);
        assert_eq!(posix_mode(GO_MODE_DIR | 0o750), 0o040750);
        assert_eq!(posix_mode(GO_MODE_SYMLINK | 0o777), 0o120777);
    }

    #[test]
    fn every_generated_file_route_is_owned_by_the_bridge() {
        let expected = [
            proto::FILE_SERVICE_LIST_FILES_SPEC,
            proto::FILE_SERVICE_DOWNLOAD_FILE_SPEC,
            proto::FILE_SERVICE_UPLOAD_FILE_SPEC,
        ]
        .into_iter()
        .map(|spec| spec.method().to_owned())
        .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            crate::test_support::public_service_methods("FileService"),
            expected
        );
        assert_eq!(expected.len(), 3);
    }

    #[test]
    fn staging_name_stays_beside_destination_and_is_private() {
        let absolute = staging_path("/workspace/src/main.rs").expect("absolute staging");
        let absolute = PathBuf::from(absolute);
        assert_eq!(absolute.parent(), Some(Path::new("/workspace/src")));
        assert!(
            absolute
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(".codewire-upload-")
        );

        let relative = PathBuf::from(staging_path("main.rs").expect("relative staging"));
        assert_eq!(relative.parent(), Some(Path::new("")));
        assert!(relative.to_string_lossy().starts_with(".codewire-upload-"));
    }

    #[test]
    fn upload_path_must_name_a_file() {
        assert_eq!(staging_path("/").unwrap_err().path, "/header/path");
        assert_eq!(
            staging_path("/workspace/directory/").unwrap_err().path,
            "/header/path"
        );
        assert_eq!(
            staging_path(&format!("/workspace/{}", "x".repeat(MAX_UPLOAD_PATH_BYTES)))
                .unwrap_err()
                .path,
            "/header/path"
        );
        assert_eq!(
            staging_path("/workspace/invalid\0name").unwrap_err().path,
            "/header/path"
        );
        assert!(reserved_upload_path("/workspace/.codewire-upload-reserved"));
        assert_eq!(
            coordinate_violations(
                "org",
                "environment",
                Some("/workspace/.codewire-upload-reserved"),
                "/org_id",
                "/environment_id",
                "/path",
            )[0]
            .path,
            "/path"
        );
    }

    #[tokio::test]
    async fn authorization_precedes_upload_stream_validation() {
        let harness = DaemonHarness::spawn().await;
        let bridge = FileBridge::new(TestBackend {
            daemon: harness.client().await,
            deny_authorization: true,
        });
        let error = proto::FileService::upload_file(
            &bridge,
            RequestContext::default(),
            Box::pin(futures::stream::empty()),
        )
        .await
        .expect_err("unauthorized empty upload must fail at authorization");
        assert_eq!(error.code, connectrpc::ErrorCode::Unauthenticated);
        harness.shutdown().await;
    }

    #[tokio::test]
    async fn upload_creates_only_confined_parent_directories() {
        use std::os::unix::fs::symlink;

        let harness = DaemonHarness::spawn().await;
        let bridge = FileBridge::new(TestBackend {
            daemon: harness.client().await,
            deny_authorization: false,
        });
        let destination = harness
            .workspace_root()
            .join("nested/parent/upload.bin")
            .to_string_lossy()
            .into_owned();
        let payload = (0..(2 * UPLOAD_CHUNK_BYTES + 17))
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let uploaded = proto::FileService::upload_file(
            &bridge,
            RequestContext::default(),
            upload_stream(&destination, &payload),
        )
        .await
        .expect("upload beneath missing parents")
        .body;
        assert_eq!(uploaded.path, destination);
        assert_eq!(uploaded.size, i64::try_from(payload.len()).unwrap());
        assert_eq!(
            std::fs::read(harness.workspace_root().join("nested/parent/upload.bin"))
                .expect("read nested upload"),
            payload
        );

        let outside = harness
            .workspace_root()
            .parent()
            .expect("workspace parent")
            .join("outside");
        std::fs::create_dir(&outside).expect("outside directory");
        symlink(&outside, harness.workspace_root().join("escape"))
            .expect("outside directory symlink");
        let escaped = harness
            .workspace_root()
            .join("escape/created/upload.bin")
            .to_string_lossy()
            .into_owned();
        proto::FileService::upload_file(
            &bridge,
            RequestContext::default(),
            upload_stream(&escaped, b"must stay confined"),
        )
        .await
        .expect_err("upload parent symlink escape must fail");
        assert!(!outside.join("created").exists());

        harness.shutdown().await;
    }

    #[tokio::test]
    async fn canceled_upload_removes_private_staging_file() {
        let harness = DaemonHarness::spawn().await;
        let bridge = FileBridge::new(TestBackend {
            daemon: harness.client().await,
            deny_authorization: false,
        });
        let destination = harness.workspace_root().join("canceled.bin");
        let destination = destination.to_string_lossy().into_owned();
        let (tx, rx) = tokio::sync::mpsc::channel::<
            Result<connectrpc::StreamMessage<proto::UploadFileRequest>, connectrpc::ConnectError>,
        >(2);
        let upload = tokio::spawn(async move {
            proto::FileService::upload_file(
                &bridge,
                RequestContext::default(),
                Box::pin(ReceiverStream::new(rx)),
            )
            .await
        });
        tx.send(Ok(connectrpc::StreamMessage::from_message(
            &proto::UploadFileRequest {
                payload: Some(proto::upload_file_request::Payload::Header(Box::new(
                    proto::UploadFileHeader {
                        org_id: "local".into(),
                        environment_id: "environment".into(),
                        path: destination,
                        ..Default::default()
                    },
                ))),
                ..Default::default()
            },
        )))
        .await
        .expect("send upload header");

        let deadline = Instant::now() + Duration::from_secs(2);
        while !has_staging_file(harness.workspace_root()) {
            assert!(
                Instant::now() < deadline,
                "upload staging file was not created"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        upload.abort();
        assert!(
            upload
                .await
                .expect_err("upload task must be canceled")
                .is_cancelled()
        );
        drop(tx);

        let deadline = Instant::now() + Duration::from_secs(2);
        while has_staging_file(harness.workspace_root()) {
            assert!(
                Instant::now() < deadline,
                "canceled upload staging file remained"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(!harness.workspace_root().join("canceled.bin").exists());
        harness.shutdown().await;
    }

    fn has_staging_file(workspace: &Path) -> bool {
        std::fs::read_dir(workspace)
            .expect("read test workspace")
            .flatten()
            .any(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains(".codewire-upload-")
            })
    }

    fn upload_stream(destination: &str, data: &[u8]) -> InboundStream<proto::UploadFileRequest> {
        let requests = [
            proto::UploadFileRequest {
                payload: Some(proto::upload_file_request::Payload::Header(Box::new(
                    proto::UploadFileHeader {
                        org_id: "local".into(),
                        environment_id: "environment".into(),
                        path: destination.to_owned(),
                        ..Default::default()
                    },
                ))),
                ..Default::default()
            },
            proto::UploadFileRequest {
                payload: Some(proto::upload_file_request::Payload::Chunk(data.to_vec())),
                ..Default::default()
            },
        ]
        .map(|request| Ok(connectrpc::StreamMessage::from_message(&request)));
        Box::pin(futures::stream::iter(requests))
    }
}
