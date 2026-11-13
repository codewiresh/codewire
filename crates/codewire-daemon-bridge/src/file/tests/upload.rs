//! Whole-file uploads batched into large daemon writes, and ended at the drain
//! deadline (#4460), through the actual confined daemon.

use super::*;

fn header(destination: &str) -> proto::UploadFileRequest {
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
    }
}

fn chunk(data: &[u8]) -> proto::UploadFileRequest {
    proto::UploadFileRequest {
        payload: Some(proto::upload_file_request::Payload::Chunk(data.to_vec())),
        ..Default::default()
    }
}

fn staging_entries(workspace: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(workspace)
        .expect("read test workspace")
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(UPLOAD_STAGING_PREFIX)
        })
        .collect()
}

#[tokio::test]
async fn an_upload_spanning_write_batches_arrives_whole() {
    let harness = DaemonHarness::spawn().await;
    let bridge = FileBridge::new(TestBackend {
        daemon: harness.client().await,
        deny_authorization: false,
        restart_deadline: None,
    });
    let destination = harness.workspace_root().join("batched.bin");
    let data = (0..(3 * staged::UPLOAD_WRITE_BYTES + 17))
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    let mut requests = vec![header(&destination.to_string_lossy())];
    requests.extend(data.chunks(UPLOAD_CHUNK_BYTES).map(chunk));
    let uploaded = proto::FileService::upload_file(
        &bridge,
        RequestContext::default(),
        Box::pin(futures::stream::iter(requests.into_iter().map(|request| {
            Ok(connectrpc::StreamMessage::from_message(&request))
        }))),
    )
    .await
    .expect("upload")
    .body;
    assert_eq!(uploaded.size, i64::try_from(data.len()).unwrap());
    assert_eq!(std::fs::read(&destination).unwrap(), data);
    assert!(staging_entries(harness.workspace_root()).is_empty());
    harness.shutdown().await;
}

#[tokio::test]
async fn an_upload_open_at_the_drain_deadline_ends_retryably_and_leaves_nothing() {
    let harness = DaemonHarness::spawn().await;
    let (deadline, restart_deadline) = tokio::sync::watch::channel(false);
    let bridge = FileBridge::new(TestBackend {
        daemon: harness.client().await,
        deny_authorization: false,
        restart_deadline: Some(restart_deadline),
    });
    let destination = harness.workspace_root().join("never.bin");
    let data = vec![7_u8; 2 * staged::UPLOAD_WRITE_BYTES];

    let (messages, receiver) = mpsc::channel(4);
    let task = tokio::spawn(async move {
        proto::FileService::upload_file(
            &bridge,
            RequestContext::default(),
            Box::pin(tokio_stream::wrappers::ReceiverStream::new(receiver)),
        )
        .await
    });
    for request in [header(&destination.to_string_lossy()), chunk(&data)] {
        messages
            .send(Ok(connectrpc::StreamMessage::from_message(&request)))
            .await
            .unwrap();
    }
    // Both batches written, the stream still open.
    let wait = Instant::now() + Duration::from_secs(5);
    while staging_entries(harness.workspace_root())
        .first()
        .and_then(|staging| std::fs::metadata(staging).ok())
        .map_or(0, |metadata| metadata.len())
        != data.len() as u64
    {
        assert!(Instant::now() < wait, "the upload was not staged");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    deadline.send_replace(true);
    let error = match task.await.expect("upload task") {
        Ok(_) => panic!("an upload open at the drain deadline must end"),
        Err(error) => error,
    };
    assert_eq!(error.code, connectrpc::ErrorCode::Unavailable);
    assert!(
        error
            .message
            .as_deref()
            .is_some_and(|message| message.contains("copy it again")),
        "{error:?}"
    );
    drop(messages);
    // A whole-file upload cannot resume: no staging file, no destination.
    let wait = Instant::now() + Duration::from_secs(5);
    while !staging_entries(harness.workspace_root()).is_empty() {
        assert!(Instant::now() < wait, "the staging file was not removed");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(!destination.exists());
    harness.shutdown().await;
}
