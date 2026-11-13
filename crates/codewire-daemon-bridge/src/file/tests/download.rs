//! Downloads through the actual confined daemon.

use buffa::{HasMessageView as _, Message as _};

use super::*;

#[tokio::test]
async fn download_streams_the_whole_file_uncompressed() {
    let harness = DaemonHarness::spawn().await;
    let bridge = FileBridge::new(TestBackend {
        daemon: harness.client().await,
        deny_authorization: false,
    });
    // More than one daemon read, ending in a short public chunk.
    let read_bytes = usize::try_from(DOWNLOAD_READ_BYTES).unwrap();
    let payload = (0..(read_bytes + 3 * DOWNLOAD_CHUNK_BYTES + 17))
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    let source = harness.workspace_root().join("download.bin");
    std::fs::write(&source, &payload).expect("write download source");
    let message = proto::DownloadFileRequest {
        org_id: "local".into(),
        environment_id: "environment".into(),
        path: source.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let body = bytes::Bytes::from(message.encode_to_vec());
    let view = proto::DownloadFileRequest::decode_view(&body).expect("decode download view");

    let response = proto::FileService::download_file(
        &bridge,
        RequestContext::default(),
        ServiceRequest::from_parts(&view, &body),
    )
    .await
    .expect("download a workspace file");
    // The override holds even when the client accepts gzip.
    assert_eq!(response.compress, Some(false));

    let mut frames = response.body;
    let info = match frames.next().await {
        Some(Ok(proto::DownloadFileResponse {
            payload: Some(proto::download_file_response::Payload::Info(info)),
            ..
        })) => info,
        _ => panic!("a download starts with the file information"),
    };
    assert_eq!(info.size, i64::try_from(payload.len()).unwrap());
    let mut received = Vec::new();
    let mut chunks = 0;
    while let Some(frame) = frames.next().await {
        match frame.expect("download frame").payload {
            Some(proto::download_file_response::Payload::Chunk(chunk)) => {
                assert!(chunk.len() <= DOWNLOAD_CHUNK_BYTES);
                received.extend_from_slice(&chunk);
                chunks += 1;
            }
            _ => panic!("only chunks follow the file information"),
        }
    }
    assert_eq!(chunks, payload.len().div_ceil(DOWNLOAD_CHUNK_BYTES));
    assert_eq!(received, payload);

    harness.shutdown().await;
}
