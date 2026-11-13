use std::pin::Pin;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::task::{Context, Poll};

use codewire_proto::codewire::v1::{
    DownloadFileRequest, FileEntry, FileService, ListFilesRequest, ListFilesResponse,
    UploadFilePartRequest, UploadFilePartResponse, UploadFileRequest, UploadFileResponse,
    upload_file_part_request, upload_file_request,
};
use connectrpc::{
    ConnectError, InboundStream, RequestContext, Response, ServiceRequest, ServiceResult,
    ServiceStream,
};

use super::*;

/// A reader of `len` patterned bytes that fails after `fail_after` bytes,
/// if set, and counts what it has handed out.
struct TestReader {
    len: usize,
    position: usize,
    fail_after: Option<usize>,
    read: Arc<AtomicU64>,
}

impl TestReader {
    fn new(len: usize) -> Self {
        Self {
            len,
            position: 0,
            fail_after: None,
            read: Arc::default(),
        }
    }
}

impl AsyncRead for TestReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.fail_after.is_some_and(|limit| self.position >= limit) {
            return Poll::Ready(Err(std::io::Error::other("disk went away")));
        }
        let end = self
            .fail_after
            .unwrap_or(self.len)
            .min(self.len)
            .min(self.position + buf.remaining());
        for index in self.position..end {
            buf.put_slice(&[pattern(index)]);
        }
        self.read
            .fetch_add((end - self.position) as u64, Ordering::Relaxed);
        self.position = end;
        Poll::Ready(Ok(()))
    }
}

fn pattern(index: usize) -> u8 {
    (index % 251) as u8
}

fn patterned(len: usize) -> Vec<u8> {
    (0..len).map(pattern).collect()
}

#[tokio::test]
async fn an_upload_streams_bounded_chunks_of_the_whole_file() {
    let len = 3 * CHUNK_BYTES + 17;
    let mut received = Vec::new();
    let sent = upload_from_reader(TestReader::new(len), |chunks| async {
        let chunks: Vec<_> = chunks.collect().await;
        assert!(chunks.iter().all(|chunk| chunk.len() <= CHUNK_BYTES));
        assert_eq!(chunks.len(), 4);
        received = chunks.concat();
        Ok(len as u64)
    })
    .await
    .unwrap();
    assert_eq!(sent, len as u64);
    assert_eq!(received, patterned(len));
}

#[tokio::test]
async fn an_upload_reads_the_file_only_as_it_is_sent() {
    let reader = TestReader::new(64 * CHUNK_BYTES);
    let read = Arc::clone(&reader.read);
    let error = upload_from_reader(reader, |mut chunks| async move {
        chunks.next().await.unwrap();
        assert_eq!(read.load(Ordering::Relaxed), CHUNK_BYTES as u64);
        chunks.next().await.unwrap();
        assert_eq!(read.load(Ordering::Relaxed), 2 * CHUNK_BYTES as u64);
        anyhow::bail!("the server refused")
    })
    .await
    .unwrap_err();
    assert_eq!(error.to_string(), "the server refused");
}

#[tokio::test]
async fn a_read_error_aborts_the_upload_instead_of_ending_it() {
    let mut reader = TestReader::new(4 * CHUNK_BYTES);
    reader.fail_after = Some(CHUNK_BYTES + 5);
    let ended = Arc::new(AtomicBool::new(false));
    let seen = Arc::new(AtomicU64::new(0));
    let error = upload_from_reader(reader, |mut chunks| {
        let (ended, seen) = (Arc::clone(&ended), Arc::clone(&seen));
        async move {
            while let Some(chunk) = chunks.next().await {
                seen.fetch_add(chunk.len() as u64, Ordering::Relaxed);
            }
            // A server would commit what it got here.
            ended.store(true, Ordering::Relaxed);
            Ok(seen.load(Ordering::Relaxed))
        }
    })
    .await
    .unwrap_err();
    assert_eq!(format!("{error:#}"), "read local file: disk went away");
    assert!(!ended.load(Ordering::Relaxed), "the stream never ends");
    assert_eq!(seen.load(Ordering::Relaxed), CHUNK_BYTES as u64);
}

#[tokio::test]
async fn an_upload_fails_when_the_server_stored_a_different_size() {
    let error = upload_from_reader(TestReader::new(10), |chunks| async {
        chunks.collect::<Vec<_>>().await;
        Ok(9)
    })
    .await
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        "the server stored 9 bytes of the 10 sent"
    );
}

fn info(size: usize) -> Result<DownloadFileResponse, anyhow::Error> {
    Ok(DownloadFileResponse {
        payload: Some(download_file_response::Payload::Info(Box::new(FileEntry {
            size: size as i64,
            ..Default::default()
        }))),
        ..Default::default()
    })
}

fn chunk(data: &[u8]) -> Result<DownloadFileResponse, anyhow::Error> {
    Ok(DownloadFileResponse {
        payload: Some(download_file_response::Payload::Chunk(data.to_vec())),
        ..Default::default()
    })
}

fn frames(data: &[u8], announced: usize) -> Vec<Result<DownloadFileResponse, anyhow::Error>> {
    std::iter::once(info(announced))
        .chain(data.chunks(CHUNK_BYTES).map(chunk))
        .collect()
}

fn entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[tokio::test]
async fn a_download_is_written_in_full_and_leaves_no_partial_file() {
    let dir = tempfile::tempdir().unwrap();
    let destination = dir.path().join("out.bin");
    let data = patterned(2 * CHUNK_BYTES + 3);
    let written = download_to_file(
        &destination,
        futures::stream::iter(frames(&data, data.len())),
    )
    .await
    .unwrap();
    assert_eq!(written, data.len() as u64);
    assert_eq!(std::fs::read(&destination).unwrap(), data);
    assert_eq!(entries(dir.path()), ["out.bin"]);
}

#[tokio::test]
async fn a_failed_download_leaves_the_destination_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let destination = dir.path().join("out.bin");
    std::fs::write(&destination, b"before").unwrap();
    let data = patterned(CHUNK_BYTES + 1);

    // Fewer bytes than announced.
    let error = download_to_file(
        &destination,
        futures::stream::iter(frames(&data, data.len() + 1)),
    )
    .await
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        format!(
            "received {} of the {} bytes the server announced",
            data.len(),
            data.len() + 1
        )
    );

    // The stream fails part way.
    let mut broken = frames(&data, data.len());
    broken.insert(2, Err(anyhow::anyhow!("connection reset")));
    let error = download_to_file(&destination, futures::stream::iter(broken))
        .await
        .unwrap_err();
    assert_eq!(error.to_string(), "connection reset");

    // A chunk before the file information.
    let error = download_to_file(&destination, futures::stream::iter(vec![chunk(b"x")]))
        .await
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "the server sent an unexpected download frame"
    );

    assert_eq!(std::fs::read(&destination).unwrap(), b"before");
    assert_eq!(entries(dir.path()), ["out.bin"]);
}

#[tokio::test]
async fn a_download_refuses_a_directory_destination_before_transferring() {
    let dir = tempfile::tempdir().unwrap();
    let error = download_to_file(dir.path(), futures::stream::iter(frames(b"data", 4)))
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .ends_with("is a directory; name the file to write"),
        "{error}"
    );
    assert!(entries(dir.path()).is_empty());
}

#[cfg(unix)]
#[tokio::test]
async fn a_download_keeps_an_existing_files_permissions_and_follows_a_link() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target.sh");
    std::fs::write(&target, b"old").unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o750)).unwrap();
    let link = dir.path().join("link.sh");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    download_to_file(&link, futures::stream::iter(frames(b"new", 3)))
        .await
        .unwrap();
    assert_eq!(std::fs::read(&target).unwrap(), b"new");
    assert!(
        std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    let mode = std::fs::metadata(&target).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o750);
}

/// A FileService with connectrpc's default limits, as the platform serves
/// it: at most 4 MiB a message.
#[derive(Default)]
struct FakeFiles {
    served: Vec<u8>,
    stored: Mutex<Vec<u8>>,
    largest_chunk: AtomicUsize,
}

#[allow(refining_impl_trait)]
impl FileService for FakeFiles {
    async fn list_files(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, ListFilesRequest>,
    ) -> ServiceResult<ListFilesResponse> {
        Err(ConnectError::unimplemented("list_files"))
    }

    async fn download_file(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, DownloadFileRequest>,
    ) -> ServiceResult<ServiceStream<DownloadFileResponse>> {
        let frames: Vec<_> = frames(&self.served, self.served.len())
            .into_iter()
            .map(|frame| Ok(frame.unwrap()))
            .collect();
        Response::stream_ok(futures::stream::iter(frames))
    }

    async fn upload_file(
        &self,
        _: RequestContext,
        mut requests: InboundStream<UploadFileRequest>,
    ) -> ServiceResult<UploadFileResponse> {
        let mut size = 0;
        while let Some(message) = requests.next().await {
            if let Some(upload_file_request::Payload::Chunk(chunk)) =
                message?.to_owned_message().payload
            {
                self.largest_chunk.fetch_max(chunk.len(), Ordering::Relaxed);
                size += chunk.len();
                self.stored.lock().unwrap().extend(chunk);
            }
        }
        Response::ok(UploadFileResponse {
            size: size as i64,
            ..Default::default()
        })
    }

    /// Appends each part's chunks; a part without chunks reports the size.
    async fn upload_file_part(
        &self,
        _: RequestContext,
        mut requests: InboundStream<UploadFilePartRequest>,
    ) -> ServiceResult<UploadFilePartResponse> {
        let mut finished = false;
        while let Some(message) = requests.next().await {
            match message?.to_owned_message().payload {
                Some(upload_file_part_request::Payload::Header(header)) => {
                    assert_eq!(header.offset as usize, self.stored.lock().unwrap().len());
                    finished = header.finish;
                }
                Some(upload_file_part_request::Payload::Chunk(chunk)) => {
                    self.largest_chunk.fetch_max(chunk.len(), Ordering::Relaxed);
                    self.stored.lock().unwrap().extend(chunk);
                }
                None => {}
            }
        }
        Response::ok(UploadFilePartResponse {
            size: self.stored.lock().unwrap().len() as i64,
            finished,
            ..Default::default()
        })
    }
}

#[tokio::test]
async fn cw_cp_moves_a_file_over_the_message_limit_both_ways_through_the_platform_client() {
    let len = 9 * 1024 * 1024 + 7;
    let data = patterned(len);
    let files = Arc::new(FakeFiles {
        served: data.clone(),
        ..Default::default()
    });
    let app = axum::Router::new().fallback_service(
        connectrpc::Router::new()
            .add_service(Arc::clone(&files))
            .into_axum_service(),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let platform = crate::config::ResolvedPlatformConfig::static_token(
        format!("http://{address}"),
        "synthetic-file-transfer-token",
        true,
        None,
    );
    let client = crate::environment_client::EnvironmentClient::new(&platform).unwrap();

    // The whole file as one message, as cw cp sent it before #3968, is refused.
    let whole = futures::stream::iter([data.clone()]);
    let error = client
        .upload_environment_file("org", "env", "/workspace/big.bin", whole)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("exceeds limit"), "{error:#}");
    files.stored.lock().unwrap().clear();

    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("big.bin");
    std::fs::write(&source, &data).unwrap();
    let sent = upload_from_file(&source, |chunks| {
        client.upload_environment_file("org", "env", "/workspace/big.bin", chunks)
    })
    .await
    .unwrap();
    assert_eq!(sent, len as u64);
    assert!(
        *files.stored.lock().unwrap() == data,
        "the server stored the file"
    );
    assert_eq!(files.largest_chunk.load(Ordering::Relaxed), CHUNK_BYTES);

    let destination = dir.path().join("downloaded.bin");
    let responses = client
        .download_environment_file("org", "env", "/workspace/big.bin")
        .await
        .unwrap();
    assert_eq!(
        download_to_file(&destination, responses).await.unwrap(),
        len as u64
    );
    assert!(std::fs::read(&destination).unwrap() == data);
}

/// A server holding one resumable upload, which can be told to drop the
/// connection part way through the next parts.
#[derive(Default)]
struct PartServer {
    held: Vec<u8>,
    published: Option<Vec<u8>>,
    /// For each coming part: keep this many of its bytes, then fail.
    fail_after: std::collections::VecDeque<usize>,
    unsupported: bool,
    offsets: Vec<(u64, bool)>,
}

impl PartServer {
    async fn part(
        server: &Mutex<Self>,
        offset: u64,
        finish: bool,
        chunks: BoxStream<'static, Vec<u8>>,
    ) -> Result<PartHeld, PartError> {
        if server.lock().unwrap().unsupported {
            return Err(PartError::Unsupported);
        }
        let incoming: Vec<u8> = chunks.collect::<Vec<_>>().await.concat();
        let mut server = server.lock().unwrap();
        server.offsets.push((offset, finish));
        if incoming.is_empty() && !finish {
            return Ok(PartHeld {
                size: server.held.len() as u64,
                finished: false,
            });
        }
        assert_eq!(
            offset,
            server.held.len() as u64,
            "a part starts where the held bytes end"
        );
        if let Some(keep) = server.fail_after.pop_front() {
            server
                .held
                .extend_from_slice(&incoming[..keep.min(incoming.len())]);
            return Err(PartError::Failed(anyhow::anyhow!("connection reset")));
        }
        server.held.extend(incoming);
        let size = server.held.len() as u64;
        if finish {
            server.published = Some(std::mem::take(&mut server.held));
        }
        Ok(PartHeld {
            size,
            finished: finish,
        })
    }
}

fn source_file(len: usize) -> (tempfile::TempDir, PathBuf, Vec<u8>) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("big.bin");
    let data = patterned(len);
    std::fs::write(&path, &data).unwrap();
    (dir, path, data)
}

const TEST_PART: u64 = 100 * 1024;

#[tokio::test(start_paused = true)]
async fn a_large_upload_goes_in_parts_and_a_failed_part_resumes_from_what_the_server_holds() {
    let (_dir, path, data) = source_file(3 * TEST_PART as usize + 17);
    let server = Mutex::new(PartServer {
        fail_after: [5_000].into(),
        ..Default::default()
    });
    let uploaded = upload_in_parts(&path, TEST_PART, |offset, finish, chunks| {
        PartServer::part(&server, offset, finish, chunks)
    })
    .await
    .unwrap();
    assert!(matches!(uploaded, Resumable::Uploaded));
    let server = server.into_inner().unwrap();
    assert!(server.published.unwrap() == data);
    let part = TEST_PART;
    assert_eq!(
        server.offsets,
        [
            (0, false),     // where to start
            (0, false),     // the part that failed after 5000 bytes
            (0, false),     // where to resume
            (5_000, false), // resumed
            (5_000 + part, false),
            (5_000 + 2 * part, true), // the shorter last part
        ]
    );
}

#[tokio::test(start_paused = true)]
async fn a_rerun_resumes_without_sending_what_the_server_already_holds() {
    let (_dir, path, data) = source_file(2 * TEST_PART as usize + 3);
    let held = 150 * 1024;
    let server = Mutex::new(PartServer {
        held: data[..held].to_vec(),
        ..Default::default()
    });
    upload_in_parts(&path, TEST_PART, |offset, finish, chunks| {
        PartServer::part(&server, offset, finish, chunks)
    })
    .await
    .unwrap();
    let server = server.into_inner().unwrap();
    assert!(server.published.unwrap() == data);
    assert_eq!(server.offsets, [(0, false), (held as u64, true)]);
}

#[tokio::test(start_paused = true)]
async fn a_server_without_resumable_uploads_gets_nothing_in_parts() {
    let (_dir, path, _) = source_file(2 * TEST_PART as usize);
    let server = Mutex::new(PartServer {
        unsupported: true,
        ..Default::default()
    });
    let uploaded = upload_in_parts(&path, TEST_PART, |offset, finish, chunks| {
        PartServer::part(&server, offset, finish, chunks)
    })
    .await
    .unwrap();
    assert!(matches!(uploaded, Resumable::Unsupported));
    assert!(server.into_inner().unwrap().offsets.is_empty());
}

#[tokio::test(start_paused = true)]
async fn an_upload_gives_up_after_failing_again_and_again() {
    let (_dir, path, _) = source_file(2 * TEST_PART as usize);
    let server = Mutex::new(PartServer {
        fail_after: std::iter::repeat_n(0, 10).collect(),
        ..Default::default()
    });
    let error = upload_in_parts(&path, TEST_PART, |offset, finish, chunks| {
        PartServer::part(&server, offset, finish, chunks)
    })
    .await
    .unwrap_err();
    assert_eq!(
        format!("{error:#}"),
        format!("the upload failed {PART_ATTEMPTS} times in a row: connection reset")
    );
    assert!(server.into_inner().unwrap().published.is_none());
}

#[test]
fn an_upload_id_names_one_copy_of_one_version_of_a_file() {
    let (_dir, path, _) = source_file(10);
    let id = upload_id(&path, "env", "/workspace/big.bin").unwrap();
    assert_eq!(id.len(), 32);
    assert!(id.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert_eq!(id, upload_id(&path, "env", "/workspace/big.bin").unwrap());
    assert_ne!(id, upload_id(&path, "other", "/workspace/big.bin").unwrap());
    assert_ne!(id, upload_id(&path, "env", "/workspace/else.bin").unwrap());
    std::fs::write(&path, b"changed!!!!").unwrap();
    assert_ne!(id, upload_id(&path, "env", "/workspace/big.bin").unwrap());
}

#[tokio::test]
async fn upload_parts_cross_the_wire_through_the_platform_client() {
    let files = Arc::new(FakeFiles::default());
    let app = axum::Router::new().fallback_service(
        connectrpc::Router::new()
            .add_service(Arc::clone(&files))
            .into_axum_service(),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let platform = crate::config::ResolvedPlatformConfig::static_token(
        format!("http://{address}"),
        "synthetic-file-transfer-token",
        true,
        None,
    );
    let client = crate::environment_client::EnvironmentClient::new(&platform).unwrap();
    let (_dir, path, data) = source_file(2 * TEST_PART as usize + 9);

    let uploaded = upload_in_parts(&path, TEST_PART, |offset, finish, chunks| {
        let client = &client;
        async move {
            client
                .upload_environment_file_part(
                    "org",
                    "env",
                    "/workspace/big.bin",
                    "wire-test-upload-0001",
                    offset,
                    finish,
                    chunks,
                )
                .await
                .map(|held| PartHeld {
                    size: held.size as u64,
                    finished: held.finished,
                })
                .map_err(|error| PartError::Failed(anyhow::anyhow!("{error}")))
        }
    })
    .await
    .unwrap();
    assert!(matches!(uploaded, Resumable::Uploaded));
    assert!(*files.stored.lock().unwrap() == data);
    assert_eq!(files.largest_chunk.load(Ordering::Relaxed), CHUNK_BYTES);
}
