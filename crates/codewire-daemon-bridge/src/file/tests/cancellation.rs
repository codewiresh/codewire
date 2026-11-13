//! Deterministic cancellation boundaries around the actual confined daemon.

use super::*;
use crate::test_support::{FILE_GATE_TIMEOUT, FileRpc, FileRpcGate, FileRpcGatePoint};

type UploadMessage =
    Result<connectrpc::StreamMessage<proto::UploadFileRequest>, connectrpc::ConnectError>;

struct UploadTask {
    task: tokio::task::JoinHandle<ServiceResult<proto::UploadFileResponse>>,
    messages: Option<mpsc::Sender<UploadMessage>>,
}

impl UploadTask {
    async fn start(harness: &DaemonHarness, destination: &Path) -> Self {
        let bridge = FileBridge::new(TestBackend {
            daemon: harness.client().await,
            deny_authorization: false,
            restart_deadline: None,
        });
        let (messages, receiver) = mpsc::channel(2);
        let task = tokio::spawn(async move {
            proto::FileService::upload_file(
                &bridge,
                RequestContext::default(),
                Box::pin(ReceiverStream::new(receiver)),
            )
            .await
        });
        let upload = Self {
            task,
            messages: Some(messages),
        };
        upload
            .send(proto::upload_file_request::Payload::Header(Box::new(
                proto::UploadFileHeader {
                    org_id: "local".into(),
                    environment_id: "environment".into(),
                    path: destination.to_string_lossy().into_owned(),
                    ..Default::default()
                },
            )))
            .await;
        upload
    }

    async fn send(&self, payload: proto::upload_file_request::Payload) {
        let message = connectrpc::StreamMessage::from_message(&proto::UploadFileRequest {
            payload: Some(payload),
            ..Default::default()
        });
        tokio::time::timeout(
            FILE_GATE_TIMEOUT,
            self.messages
                .as_ref()
                .expect("open upload stream")
                .send(Ok(message)),
        )
        .await
        .expect("upload fixture send timed out")
        .expect("upload fixture stream closed");
    }

    fn eof(&mut self) {
        self.messages = None;
    }

    async fn cancel(&mut self) {
        self.task.abort();
        let canceled = tokio::time::timeout(FILE_GATE_TIMEOUT, &mut self.task)
            .await
            .expect("public upload did not cancel");
        assert!(matches!(canceled, Err(error) if error.is_cancelled()));
        // Retain the message sender deliberately. Cancellation must come from
        // the missing response owner, not accidental input EOF in this fixture.
    }
}

impl Drop for UploadTask {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn destination(harness: &DaemonHarness) -> PathBuf {
    let destination = harness.workspace_root().join("existing.bin");
    std::fs::write(&destination, b"original-destination").expect("write destination canary");
    destination
}

fn assert_original(destination: &Path) {
    assert_eq!(
        std::fs::read(destination).expect("destination survived"),
        b"original-destination"
    );
}

fn assert_no_staging(harness: &DaemonHarness) {
    assert!(
        !has_staging_file(harness.workspace_root()),
        "canceled upload retained its private staging file"
    );
}

async fn open_cancellation(point: FileRpcGatePoint) {
    let gate = FileRpcGate::new(FileRpc::OpenFile, point);
    let harness = DaemonHarness::spawn_with_file_gate(Arc::clone(&gate)).await;
    let destination = destination(&harness);
    let mut upload = UploadTask::start(&harness, &destination).await;
    gate.wait().await;
    assert_eq!(
        has_staging_file(harness.workspace_root()),
        point == FileRpcGatePoint::AfterExecution
    );
    assert_original(&destination);
    upload.cancel().await;
    assert_original(&destination);
    gate.release();
    gate.wait_for_completion().await;
    gate.wait_for_removal().await;
    assert!(
        !gate.removed_before_pending_operation_finished(),
        "cleanup raced an unfinished OpenFile"
    );
    assert_no_staging(&harness);
    assert_original(&destination);
    drop(upload);
    harness.shutdown().await;
}

#[tokio::test]
async fn canceled_open_before_execution_waits_for_creation_then_removes_staging() {
    open_cancellation(FileRpcGatePoint::BeforeExecution).await;
}

#[tokio::test]
async fn canceled_open_after_creation_before_reply_removes_staging() {
    open_cancellation(FileRpcGatePoint::AfterExecution).await;
}

#[tokio::test]
async fn canceled_pending_write_settles_before_staging_cleanup() {
    let gate = FileRpcGate::new(FileRpc::Write, FileRpcGatePoint::AfterExecution);
    let harness = DaemonHarness::spawn_with_file_gate(Arc::clone(&gate)).await;
    let destination = destination(&harness);
    let mut upload = UploadTask::start(&harness, &destination).await;
    upload
        .send(proto::upload_file_request::Payload::Chunk(
            b"partial-upload".to_vec(),
        ))
        .await;
    gate.wait().await;
    assert!(has_staging_file(harness.workspace_root()));
    assert_original(&destination);
    upload.cancel().await;
    gate.release();
    gate.wait_for_completion().await;
    gate.wait_for_removal().await;
    assert!(
        !gate.removed_before_pending_operation_finished(),
        "cleanup raced an unfinished Write"
    );
    assert_no_staging(&harness);
    assert_original(&destination);
    drop(upload);
    harness.shutdown().await;
}

#[tokio::test]
async fn canceled_before_rename_is_issued_preserves_existing_destination() {
    let gate = FileRpcGate::new(FileRpc::SetStat, FileRpcGatePoint::AfterExecution);
    let harness = DaemonHarness::spawn_with_file_gate(Arc::clone(&gate)).await;
    let destination = destination(&harness);
    let mut upload = UploadTask::start(&harness, &destination).await;
    upload
        .send(proto::upload_file_request::Payload::Chunk(
            b"complete-upload".to_vec(),
        ))
        .await;
    upload.eof();
    gate.wait().await;
    assert_original(&destination);
    upload.cancel().await;
    gate.release();
    gate.wait_for_completion().await;
    gate.wait_for_removal().await;
    assert!(
        !gate.removed_before_pending_operation_finished(),
        "cleanup raced an unfinished SetStat"
    );
    assert_no_staging(&harness);
    assert_original(&destination);
    drop(upload);
    harness.shutdown().await;
}

#[tokio::test]
async fn canceled_after_rename_is_issued_keeps_the_complete_committed_destination() {
    for point in [
        FileRpcGatePoint::BeforeExecution,
        FileRpcGatePoint::AfterExecution,
    ] {
        let gate = FileRpcGate::new(FileRpc::Rename, point);
        let harness = DaemonHarness::spawn_with_file_gate(Arc::clone(&gate)).await;
        let destination = destination(&harness);
        let mut upload = UploadTask::start(&harness, &destination).await;
        upload
            .send(proto::upload_file_request::Payload::Chunk(
                b"complete-upload".to_vec(),
            ))
            .await;
        upload.eof();
        gate.wait().await;
        if point == FileRpcGatePoint::BeforeExecution {
            assert_original(&destination);
        } else {
            assert_eq!(std::fs::read(&destination).unwrap(), b"complete-upload");
        }
        upload.cancel().await;
        gate.release();
        gate.wait_for_completion().await;
        // A successful rename has no staging path left to clean. Wait for the
        // actual destination effect, not an expectation that cleanup deletes it.
        tokio::time::timeout(FILE_GATE_TIMEOUT, async {
            loop {
                if std::fs::read(&destination).ok().as_deref() == Some(b"complete-upload")
                    && !has_staging_file(harness.workspace_root())
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("issued rename did not finish atomically");
        assert_eq!(std::fs::read(&destination).unwrap(), b"complete-upload");
        assert_no_staging(&harness);
        drop(upload);
        harness.shutdown().await;
    }
}

#[tokio::test]
async fn canceled_during_error_cleanup_keeps_removal_owned_until_completion() {
    let gate = FileRpcGate::new(FileRpc::Remove, FileRpcGatePoint::BeforeExecution);
    let harness = DaemonHarness::spawn_with_file_gate(Arc::clone(&gate)).await;
    let destination = destination(&harness);
    let mut upload = UploadTask::start(&harness, &destination).await;
    // A duplicate header selects the explicit validation-error abort path.
    upload
        .send(proto::upload_file_request::Payload::Header(Box::default()))
        .await;
    gate.wait().await;
    assert!(has_staging_file(harness.workspace_root()));
    assert_eq!(gate.removal_count(), 0);
    upload.cancel().await;
    gate.release();
    gate.wait_for_completion().await;
    gate.wait_for_removal().await;
    assert_no_staging(&harness);
    assert_original(&destination);
    drop(upload);
    harness.shutdown().await;
}
