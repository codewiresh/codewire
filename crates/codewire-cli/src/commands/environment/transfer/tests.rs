use std::pin::Pin;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::task::{Context, Poll};

use codewire_proto::codewire::v1::{
    DownloadFileRequest, FileEntry, FileService, ListFilesRequest, ListFilesResponse,
    UploadFileRequest, UploadFileResponse, upload_file_request,
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
