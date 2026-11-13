//! Resumable uploads in parts (#4373) against the actual confined daemon.

use std::os::unix::fs::PermissionsExt as _;

use super::*;

const UPLOAD_ID: &str = "part-test-upload-0001";

fn bridge(daemon: DaemonClient) -> FileBridge<TestBackend> {
    FileBridge::new(TestBackend {
        daemon,
        deny_authorization: false,
        restart_deadline: None,
    })
}

fn part_header(
    destination: &str,
    upload_id: &str,
    offset: usize,
    finish: bool,
) -> proto::UploadFilePartRequest {
    proto::UploadFilePartRequest {
        payload: Some(proto::upload_file_part_request::Payload::Header(Box::new(
            proto::UploadFilePartHeader {
                org_id: "local".into(),
                environment_id: "environment".into(),
                path: destination.to_owned(),
                upload_id: upload_id.to_owned(),
                offset: i64::try_from(offset).unwrap(),
                finish,
                ..Default::default()
            },
        ))),
        ..Default::default()
    }
}

fn part_chunk(data: &[u8]) -> proto::UploadFilePartRequest {
    proto::UploadFilePartRequest {
        payload: Some(proto::upload_file_part_request::Payload::Chunk(
            data.to_vec(),
        )),
        ..Default::default()
    }
}

fn part_stream(
    destination: &str,
    offset: usize,
    finish: bool,
    data: &[u8],
) -> InboundStream<proto::UploadFilePartRequest> {
    let mut requests = vec![part_header(destination, UPLOAD_ID, offset, finish)];
    requests.extend(data.chunks(UPLOAD_CHUNK_BYTES).map(part_chunk));
    Box::pin(futures::stream::iter(requests.into_iter().map(|request| {
        Ok(connectrpc::StreamMessage::from_message(&request))
    })))
}

async fn send_part(
    bridge: &FileBridge<TestBackend>,
    destination: &str,
    offset: usize,
    finish: bool,
    data: &[u8],
) -> ServiceResult<proto::UploadFilePartResponse> {
    proto::FileService::upload_file_part(
        bridge,
        RequestContext::default(),
        part_stream(destination, offset, finish, data),
    )
    .await
}

fn staging_files(workspace: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(workspace)
        .expect("read test workspace")
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(UPLOAD_PART_STAGING_PREFIX)
        })
        .collect()
}

fn payload(len: usize) -> Vec<u8> {
    (0..len).map(|index| (index % 251) as u8).collect()
}

#[tokio::test]
async fn parts_resume_where_the_held_bytes_end_and_publish_once() {
    let harness = DaemonHarness::spawn().await;
    let bridge = bridge(harness.client().await);
    let destination = harness.workspace_root().join("parts.bin");
    let path = destination.to_string_lossy().into_owned();
    let data = payload(3 * UPLOAD_CHUNK_BYTES + 11);
    let split = UPLOAD_CHUNK_BYTES + 5;

    let first = send_part(&bridge, &path, 0, false, &data[..split])
        .await
        .expect("first part")
        .body;
    assert_eq!((first.size, first.finished), (split as i64, false));
    assert_eq!(first.upload_id, UPLOAD_ID);
    assert!(!destination.exists(), "nothing is published before finish");
    assert_eq!(staging_files(harness.workspace_root()).len(), 1);

    // A part without chunks reports what is held, whatever its offset.
    let held = send_part(&bridge, &path, 0, false, &[])
        .await
        .expect("status")
        .body;
    assert_eq!((held.size, held.finished), (split as i64, false));

    // A part that does not start where the held bytes end is refused.
    let error = send_part(&bridge, &path, 0, false, &data[..10])
        .await
        .expect_err("a part at a stale offset");
    assert_eq!(error.code, connectrpc::ErrorCode::FailedPrecondition);
    assert!(
        error
            .message
            .as_deref()
            .is_some_and(|message| message.contains(&format!("holds {split} bytes"))),
        "{error:?}"
    );

    let last = send_part(&bridge, &path, split, true, &data[split..])
        .await
        .expect("last part")
        .body;
    assert_eq!((last.size, last.finished), (data.len() as i64, true));
    assert_eq!(std::fs::read(&destination).unwrap(), data);
    let mode = std::fs::metadata(&destination)
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, UPLOAD_MODE);
    assert!(staging_files(harness.workspace_root()).is_empty());

    // The same upload id starts afresh once published.
    let again = send_part(&bridge, &path, 0, false, &[]).await.unwrap().body;
    assert_eq!(again.size, 0);
    harness.shutdown().await;
}

#[tokio::test]
async fn a_canceled_part_keeps_its_bytes_for_the_next() {
    let harness = DaemonHarness::spawn().await;
    let bridge = bridge(harness.client().await);
    let destination = harness.workspace_root().join("resumed.bin");
    let path = destination.to_string_lossy().into_owned();
    let data = payload(2 * UPLOAD_CHUNK_BYTES);

    let (messages, receiver) = mpsc::channel(4);
    let task = {
        let bridge = bridge.clone();
        tokio::spawn(async move {
            proto::FileService::upload_file_part(
                &bridge,
                RequestContext::default(),
                Box::pin(tokio_stream::wrappers::ReceiverStream::new(receiver)),
            )
            .await
        })
    };
    for request in [
        part_header(&path, UPLOAD_ID, 0, false),
        part_chunk(&data[..UPLOAD_CHUNK_BYTES]),
    ] {
        messages
            .send(Ok(connectrpc::StreamMessage::from_message(&request)))
            .await
            .unwrap();
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let written = staging_files(harness.workspace_root())
            .first()
            .and_then(|staging| std::fs::metadata(staging).ok())
            .map_or(0, |metadata| metadata.len());
        if written == UPLOAD_CHUNK_BYTES as u64 {
            break;
        }
        assert!(Instant::now() < deadline, "the first chunk was not staged");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    task.abort();
    let _ = task.await;
    drop(messages);

    let held = send_part(&bridge, &path, 0, false, &[]).await.unwrap().body;
    assert_eq!(
        held.size, UPLOAD_CHUNK_BYTES as i64,
        "the canceled part's bytes are held"
    );
    send_part(
        &bridge,
        &path,
        UPLOAD_CHUNK_BYTES,
        true,
        &data[UPLOAD_CHUNK_BYTES..],
    )
    .await
    .expect("resumed part");
    assert_eq!(std::fs::read(&destination).unwrap(), data);
    assert!(staging_files(harness.workspace_root()).is_empty());
    harness.shutdown().await;
}

#[tokio::test]
async fn a_finishing_part_without_chunks_publishes_an_empty_file() {
    let harness = DaemonHarness::spawn().await;
    let bridge = bridge(harness.client().await);
    let destination = harness.workspace_root().join("empty.bin");
    let path = destination.to_string_lossy().into_owned();
    let error = send_part(&bridge, &path, 1, true, &[])
        .await
        .expect_err("finish at an offset past the held bytes");
    assert_eq!(error.code, connectrpc::ErrorCode::FailedPrecondition);
    assert!(!destination.exists());

    let done = send_part(&bridge, &path, 0, true, &[]).await.unwrap().body;
    assert_eq!((done.size, done.finished), (0, true));
    assert_eq!(std::fs::read(&destination).unwrap(), b"");
    harness.shutdown().await;
}

#[tokio::test]
async fn an_upload_id_is_checked_and_names_one_staging_file() {
    let harness = DaemonHarness::spawn().await;
    let bridge = bridge(harness.client().await);
    let path = harness
        .workspace_root()
        .join("checked.bin")
        .to_string_lossy()
        .into_owned();
    for upload_id in ["short", "has a space in it ok", &"x".repeat(65)] {
        let stream = Box::pin(futures::stream::iter([Ok(
            connectrpc::StreamMessage::from_message(&part_header(&path, upload_id, 0, false)),
        )]));
        let error =
            proto::FileService::upload_file_part(&bridge, RequestContext::default(), stream)
                .await
                .expect_err("an invalid upload id");
        assert_eq!(
            error.code,
            connectrpc::ErrorCode::InvalidArgument,
            "{upload_id}"
        );
    }
    harness.shutdown().await;

    let staging = |destination: &str, upload_id: &str| {
        part_staging_path(destination, "org", "environment", upload_id).unwrap()
    };
    let one = staging("/workspace/a.bin", UPLOAD_ID);
    assert_eq!(one, staging("/workspace/a.bin", UPLOAD_ID));
    assert_ne!(one, staging("/workspace/b.bin", UPLOAD_ID));
    assert_ne!(one, staging("/workspace/a.bin", "part-test-upload-0002"));
    assert_ne!(
        one,
        part_staging_path("/workspace/a.bin", "org", "other", UPLOAD_ID).unwrap()
    );
    assert!(one.starts_with("/workspace/.codewire-upload-part-"));
    assert!(reserved_upload_path(&one));
}

#[tokio::test]
async fn a_part_removes_abandoned_uploads_beside_it() {
    let harness = DaemonHarness::spawn().await;
    let bridge = bridge(harness.client().await);
    let workspace = harness.workspace_root();
    let abandoned = workspace.join(format!("{UPLOAD_PART_STAGING_PREFIX}abandoned"));
    let recent = workspace.join(format!("{UPLOAD_PART_STAGING_PREFIX}recent"));
    for file in [&abandoned, &recent] {
        std::fs::write(file, b"partial").unwrap();
    }
    std::fs::File::options()
        .write(true)
        .open(&abandoned)
        .unwrap()
        .set_modified(std::time::SystemTime::now() - UPLOAD_PART_EXPIRY - Duration::from_secs(60))
        .unwrap();

    let path = workspace.join("fresh.bin").to_string_lossy().into_owned();
    send_part(&bridge, &path, 0, false, &[]).await.unwrap();
    assert!(!abandoned.exists(), "an abandoned upload is removed");
    assert!(recent.exists(), "a recent upload is kept");
    harness.shutdown().await;
}
