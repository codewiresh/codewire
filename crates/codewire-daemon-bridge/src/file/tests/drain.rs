//! A download still open when its server restarts (#4426), through the actual
//! confined daemon.

use buffa::{HasMessageView as _, Message as _};

use super::*;

#[tokio::test]
async fn a_download_open_at_the_drain_deadline_ends_with_a_retryable_error() {
    let harness = DaemonHarness::spawn().await;
    let (deadline, restart_deadline) = tokio::sync::watch::channel(false);
    let bridge = FileBridge::new(TestBackend {
        daemon: harness.client().await,
        deny_authorization: false,
        restart_deadline: Some(restart_deadline),
    });
    let payload = vec![7_u8; 4 * 1024 * 1024];
    let source = harness.workspace_root().join("large.bin");
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
    let mut frames = response.body;
    assert!(matches!(
        frames.next().await,
        Some(Ok(proto::DownloadFileResponse {
            payload: Some(proto::download_file_response::Payload::Info(_)),
            ..
        }))
    ));

    deadline.send_replace(true);
    let mut received = 0;
    let error = loop {
        match frames
            .next()
            .await
            .expect("the download ends with an error")
        {
            Ok(proto::DownloadFileResponse {
                payload: Some(proto::download_file_response::Payload::Chunk(chunk)),
                ..
            }) => received += chunk.len(),
            Ok(other) => panic!("unexpected frame {other:?}"),
            Err(error) => break error,
        }
    };
    assert_eq!(error.code, connectrpc::ErrorCode::Unavailable);
    assert!(
        error
            .message
            .as_deref()
            .is_some_and(|message| message.contains("download it again")),
        "{error:?}"
    );
    assert!(
        received < payload.len(),
        "the whole file arrived despite the deadline"
    );
    assert!(frames.next().await.is_none());

    harness.shutdown().await;
}
