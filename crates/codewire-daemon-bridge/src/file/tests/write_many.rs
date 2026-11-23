//! WriteFiles (#5804) against the actual confined daemon; the requirements are
//! SPEC.md, "File transfer", and `files-write-many` in
//! docs/journeys/sdk-files.md.

use std::os::unix::fs::PermissionsExt as _;

use buffa::{HasMessageView as _, Message as _};

use super::*;
use crate::file::admission::{BodyBudget, BodyCharge, ORGANIZATION_SHARE_FULL, with_budget};
use crate::test_support::{FILE_GATE_TIMEOUT, FileRpc, FileRpcGate, FileRpcGatePoint};

const TEST_TIMEOUT: Duration = Duration::from_secs(60);

fn bridge(
    daemon: DaemonClient,
    restart_deadline: Option<tokio::sync::watch::Receiver<bool>>,
) -> FileBridge<TestBackend> {
    FileBridge::new(TestBackend {
        daemon,
        deny_authorization: false,
        restart_deadline,
    })
}

fn request(environment_id: &str, files: Vec<(String, Vec<u8>)>) -> proto::WriteFilesRequest {
    request_in("local", environment_id, files)
}

fn request_in(
    org_id: &str,
    environment_id: &str,
    files: Vec<(String, Vec<u8>)>,
) -> proto::WriteFilesRequest {
    proto::WriteFilesRequest {
        org_id: org_id.into(),
        environment_id: environment_id.into(),
        files: files
            .into_iter()
            .map(|(path, content)| proto::WriteFile {
                path,
                content,
                ..Default::default()
            })
            .collect(),
        ..Default::default()
    }
}

/// A call charged as the admission charges one, against a budget of its own.
async fn write_files(
    bridge: &FileBridge<TestBackend>,
    message: proto::WriteFilesRequest,
) -> Result<Vec<(String, i64)>, connectrpc::ConnectError> {
    let budget = BodyBudget::new(|_| None);
    write_charged(bridge, &budget, "account", 1024, message).await
}

/// A call whose `bytes` the admission charged to `account` in `budget`.
async fn write_charged(
    bridge: &FileBridge<TestBackend>,
    budget: &BodyBudget,
    account: &str,
    bytes: usize,
    message: proto::WriteFilesRequest,
) -> Result<Vec<(String, i64)>, connectrpc::ConnectError> {
    let charge = budget
        .try_take(Some(account.to_owned()), bytes)
        .expect("the charge fits the budget");
    let mut ctx = RequestContext::default();
    ctx.extensions_mut().insert(BodyCharge::new(charge));
    write_files_in(bridge, ctx, message).await
}

async fn write_files_in(
    bridge: &FileBridge<TestBackend>,
    ctx: RequestContext,
    message: proto::WriteFilesRequest,
) -> Result<Vec<(String, i64)>, connectrpc::ConnectError> {
    let body = bytes::Bytes::from(message.encode_to_vec());
    let view = proto::WriteFilesRequest::decode_view(&body).expect("decode write view");
    let response =
        proto::FileService::write_files(bridge, ctx, ServiceRequest::from_parts(&view, &body))
            .await?;
    Ok(response
        .body
        .files
        .into_iter()
        .map(|file| (file.path, file.size))
        .collect())
}

async fn write(
    bridge: &FileBridge<TestBackend>,
    files: Vec<(String, Vec<u8>)>,
) -> Result<Vec<(String, i64)>, connectrpc::ConnectError> {
    write_files(bridge, request("environment", files)).await
}

fn at(workspace: &Path, relative: &str) -> String {
    workspace.join(relative).to_string_lossy().into_owned()
}

/// Every staging name left anywhere beneath `root`.
fn staging_left(root: &Path) -> Vec<PathBuf> {
    let mut left = Vec::new();
    let mut folders = vec![root.to_owned()];
    while let Some(folder) = folders.pop() {
        for entry in std::fs::read_dir(&folder)
            .expect("read test folder")
            .flatten()
        {
            let path = entry.path();
            if entry.file_type().expect("entry type").is_dir() {
                folders.push(path);
            } else if entry
                .file_name()
                .to_string_lossy()
                .starts_with(UPLOAD_STAGING_PREFIX)
            {
                left.push(path);
            }
        }
    }
    left
}

async fn wait_until_no_staging(root: &Path) {
    tokio::time::timeout(FILE_GATE_TIMEOUT, async {
        while !staging_left(root).is_empty() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("staging files were not removed");
}

fn message(error: &connectrpc::ConnectError) -> &str {
    error.message.as_deref().unwrap_or_default()
}

#[tokio::test]
async fn three_files_land_in_order_with_a_new_folder_and_a_replaced_file() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let harness = DaemonHarness::spawn().await;
        let bridge = bridge(harness.client().await, None);
        let workspace = harness.workspace_root();
        std::fs::write(workspace.join("f.txt"), b"older").unwrap();

        let files = vec![
            (at(workspace, "proj/a.txt"), b"alpha".to_vec()),
            (at(workspace, "proj/src/b.txt"), b"bravo!".to_vec()),
            (at(workspace, "f.txt"), b"new".to_vec()),
        ];
        let written = write(&bridge, files.clone())
            .await
            .expect("write three files");
        assert_eq!(
            written,
            vec![
                (at(workspace, "proj/a.txt"), 5),
                (at(workspace, "proj/src/b.txt"), 6),
                (at(workspace, "f.txt"), 3),
            ]
        );
        for (path, content) in &files {
            assert_eq!(&std::fs::read(path).unwrap(), content, "{path}");
            let mode = std::fs::metadata(path).unwrap().permissions().mode();
            assert_eq!(mode & 0o7777, 0o644, "{path}");
        }
        assert!(workspace.join("proj/src").is_dir());
        assert!(staging_left(workspace).is_empty());
        harness.shutdown().await;
    })
    .await
    .expect("test timed out");
}

#[tokio::test]
async fn sixteen_mebibytes_in_all_are_written_and_one_byte_more_is_refused() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let harness = DaemonHarness::spawn().await;
        let bridge = bridge(harness.client().await, None);
        let workspace = harness.workspace_root();
        let half = WRITE_FILES_MAX_CONTENT_BYTES / 2;
        let content = (0..half)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();

        let written = write(
            &bridge,
            vec![
                (at(workspace, "big/one.bin"), content.clone()),
                (at(workspace, "big/two.bin"), content.clone()),
            ],
        )
        .await
        .expect("16 MiB in all is accepted");
        assert_eq!(written[1].1, i64::try_from(half).unwrap());
        assert_eq!(
            std::fs::read(workspace.join("big/two.bin")).unwrap(),
            content
        );

        let mut over = content.clone();
        over.push(0);
        let error = write(
            &bridge,
            vec![
                (at(workspace, "over/one.bin"), content),
                (at(workspace, "over/two.bin"), over),
            ],
        )
        .await
        .expect_err("one byte over 16 MiB is refused");
        assert_eq!(error.code, connectrpc::ErrorCode::InvalidArgument);
        assert!(message(&error).ends_with(": /files"), "{error:?}");
        assert!(!workspace.join("over").exists());
        harness.shutdown().await;
    })
    .await
    .expect("test timed out");
}

#[tokio::test]
async fn a_request_breaking_a_rule_is_refused_whole_and_writes_nothing() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let harness = DaemonHarness::spawn().await;
        let bridge = bridge(harness.client().await, None);
        let workspace = harness.workspace_root();
        let good = || (at(workspace, "made/good.txt"), b"good".to_vec());
        let many = (0..=WRITE_FILES_MAX_FILES)
            .map(|index| (at(workspace, &format!("made/{index}.txt")), b"x".to_vec()))
            .collect::<Vec<_>>();
        let cases = [
            ("no files", Vec::new(), "/files"),
            ("1,001 files", many, "/files"),
            (
                "a duplicate",
                vec![
                    good(),
                    (at(workspace, "made/x.txt"), b"1".to_vec()),
                    (at(workspace, "made/sub/../x.txt"), b"2".to_vec()),
                ],
                "/files/2/path",
            ),
            (
                "a reserved name",
                vec![good(), (at(workspace, ".codewire-upload-x"), b"x".to_vec())],
                "/files/1/path",
            ),
            (
                "a relative path",
                vec![good(), ("x.txt".to_owned(), b"x".to_vec())],
                "/files/1/path",
            ),
            (
                "a folder",
                vec![
                    good(),
                    (format!("{}/", at(workspace, "made")), b"x".to_vec()),
                ],
                "/files/1/path",
            ),
            (
                "an empty path",
                vec![good(), (" ".to_owned(), Vec::new())],
                "/files/1/path",
            ),
        ];
        for (case, files, field) in cases {
            let error = write(&bridge, files).await.expect_err(case);
            assert_eq!(error.code, connectrpc::ErrorCode::InvalidArgument, "{case}");
            assert!(
                message(&error).ends_with(&format!(": {field}")),
                "{case}: {error:?}"
            );
            assert!(!workspace.join("made").exists(), "{case} wrote");
        }

        // Confinement is the daemon's: a path outside the workspace is
        // refused while staging, and the good path beside it is not written.
        let error = write(&bridge, vec![good(), ("/etc/x".to_owned(), b"x".to_vec())])
            .await
            .expect_err("a path outside the workspace");
        assert_eq!(error.code, connectrpc::ErrorCode::InvalidArgument);
        assert!(!workspace.join("made/good.txt").exists());
        assert!(staging_left(workspace).is_empty());
        harness.shutdown().await;
    })
    .await
    .expect("test timed out");
}

#[tokio::test]
async fn a_staging_failure_puts_no_file_in_place() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let harness = DaemonHarness::spawn().await;
        let bridge = bridge(harness.client().await, None);
        let workspace = harness.workspace_root();
        std::fs::write(workspace.join("keep.txt"), b"original").unwrap();
        std::fs::write(workspace.join("blocker"), b"a file, not a folder").unwrap();

        write(
            &bridge,
            vec![
                (at(workspace, "keep.txt"), b"replaced".to_vec()),
                (at(workspace, "new/new.txt"), b"new".to_vec()),
                (at(workspace, "blocker/inner.txt"), b"x".to_vec()),
            ],
        )
        .await
        .expect_err("a parent that is a file fails staging");
        assert_eq!(
            std::fs::read(workspace.join("keep.txt")).unwrap(),
            b"original"
        );
        assert!(!workspace.join("new/new.txt").exists());
        assert!(staging_left(workspace).is_empty());
        harness.shutdown().await;
    })
    .await
    .expect("test timed out");
}

#[tokio::test]
async fn a_failure_putting_a_file_in_place_names_the_files_already_written() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let harness = DaemonHarness::spawn().await;
        let bridge = bridge(harness.client().await, None);
        let workspace = harness.workspace_root();
        // Staging beside a folder works; renaming a file over it does not.
        std::fs::create_dir(workspace.join("folder")).unwrap();
        std::fs::write(workspace.join("folder/child"), b"child").unwrap();

        let error = write(
            &bridge,
            vec![
                (at(workspace, "first.txt"), b"1".to_vec()),
                (at(workspace, "second.txt"), b"2".to_vec()),
                (at(workspace, "folder"), b"3".to_vec()),
                (at(workspace, "fourth.txt"), b"4".to_vec()),
            ],
        )
        .await
        .expect_err("renaming a file over a folder fails");
        let written = format!(
            "2 files were written before it stopped: {:?}, {:?}",
            at(workspace, "first.txt"),
            at(workspace, "second.txt")
        );
        assert!(message(&error).ends_with(&written), "{error:?}");
        assert_eq!(std::fs::read(workspace.join("first.txt")).unwrap(), b"1");
        assert_eq!(std::fs::read(workspace.join("second.txt")).unwrap(), b"2");
        assert!(workspace.join("folder/child").is_file());
        assert!(!workspace.join("fourth.txt").exists());
        assert!(staging_left(workspace).is_empty());
        harness.shutdown().await;
    })
    .await
    .expect("test timed out");
}

#[tokio::test]
async fn an_environment_runs_two_calls_at_once_and_refuses_a_third() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        // The first call is held at its first staging file.
        let gate = FileRpcGate::new(FileRpc::OpenFile, FileRpcGatePoint::BeforeExecution);
        let harness = DaemonHarness::spawn_with_file_gate(Arc::clone(&gate)).await;
        let bridge = bridge(harness.client().await, None);
        let workspace = harness.workspace_root().to_owned();
        let held = {
            let bridge = bridge.clone();
            let path = at(&workspace, "held.txt");
            tokio::spawn(async move { write(&bridge, vec![(path, b"held".to_vec())]).await })
        };
        gate.wait().await;
        let second = bridge
            .writes
            .try_acquire("local", "environment")
            .expect("a second call runs beside the first");

        let error = write(&bridge, vec![(at(&workspace, "third.txt"), b"3".to_vec())])
            .await
            .expect_err("a third call is refused");
        assert_eq!(error.code, connectrpc::ErrorCode::ResourceExhausted);
        assert!(!workspace.join("third.txt").exists());
        // Another environment has its own two.
        write_files(
            &bridge,
            request(
                "other-environment",
                vec![(at(&workspace, "other.txt"), b"other".to_vec())],
            ),
        )
        .await
        .expect("another environment is not refused");

        gate.release();
        held.await.expect("held call").expect("held call writes");
        drop(second);
        // Both a finished call and a failed one give their permit back.
        write(&bridge, vec![("/etc/x".to_owned(), b"x".to_vec())])
            .await
            .expect_err("a path outside the workspace");
        let permits = [
            bridge.writes.try_acquire("local", "environment"),
            bridge.writes.try_acquire("local", "environment"),
        ];
        assert!(permits.iter().all(Result::is_ok));
        drop(permits);
        harness.shutdown().await;
    })
    .await
    .expect("test timed out");
}

#[tokio::test]
async fn an_organization_runs_four_calls_at_once_across_its_environments() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let harness = DaemonHarness::spawn().await;
        let bridge = bridge(harness.client().await, None);
        let workspace = harness.workspace_root().to_owned();
        // Two environments of one organization hold two calls each.
        let held = ["one", "one", "two", "two"]
            .map(|environment| bridge.writes.try_acquire("local", environment));
        assert!(held.iter().all(Result::is_ok));

        let error = write_files(
            &bridge,
            request_in(
                "local",
                "three",
                vec![(at(&workspace, "fifth.txt"), b"5".to_vec())],
            ),
        )
        .await
        .expect_err("a fifth call in the organization is refused");
        assert_eq!(error.code, connectrpc::ErrorCode::ResourceExhausted);
        assert_eq!(
            message(&error),
            crate::file::write_many::TOO_MANY_ORGANIZATION_WRITES
        );
        assert!(!workspace.join("fifth.txt").exists());

        write_files(
            &bridge,
            request_in(
                "other-org",
                "three",
                vec![(at(&workspace, "other.txt"), b"other".to_vec())],
            ),
        )
        .await
        .expect("another organization has its own four");

        // Releasing one call in the organization admits another.
        drop(held);
        assert!(
            ["one", "one", "two", "two"]
                .map(|environment| bridge.writes.try_acquire("local", environment))
                .iter()
                .all(Result::is_ok)
        );
        harness.shutdown().await;
    })
    .await
    .expect("test timed out");
}

/// Two accounts of one organization each hold a call of the largest size, the
/// organization's whole share. A further call from either, which fits the
/// process budget and its account's share, is refused once its organization
/// is known, and its charge released; another organization's call gets in.
#[tokio::test]
async fn an_organization_holds_at_most_its_share_of_the_body_budget() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let harness = DaemonHarness::spawn().await;
        let bridge = bridge(harness.client().await, None);
        let workspace = harness.workspace_root().to_owned();
        let budget = BodyBudget::new(|_| None);
        // Charges made by the admission and assigned to the organization, as
        // two calls of the largest size held at the daemon would hold them.
        let held = ["account-a", "account-b"].map(|account| {
            let mut charge = budget
                .try_take(Some(account.to_owned()), WRITE_FILES_MAX_MESSAGE_BYTES)
                .expect("within the budget");
            charge
                .charge_organization("local")
                .expect("within the organization's share");
            charge
        });
        let full = 2 * WRITE_FILES_MAX_MESSAGE_BYTES;
        assert_eq!(budget.held_by_organization()["local"], full);

        let small = 64 * 1024;
        for account in ["account-a", "account-b"] {
            let error = write_charged(
                &bridge,
                &budget,
                account,
                small,
                request_in(
                    "local",
                    "environment",
                    vec![(at(&workspace, "third.txt"), b"3".to_vec())],
                ),
            )
            .await
            .expect_err("a call over the organization's share is refused");
            assert_eq!(error.code, connectrpc::ErrorCode::ResourceExhausted);
            assert_eq!(message(&error), ORGANIZATION_SHARE_FULL);
            assert!(!workspace.join("third.txt").exists());
            assert_eq!(budget.held().0, full, "the refused charge is released");
        }

        write_charged(
            &bridge,
            &budget,
            "account-a",
            small,
            request_in(
                "other-org",
                "environment",
                vec![(at(&workspace, "other.txt"), b"other".to_vec())],
            ),
        )
        .await
        .expect("another organization's call gets in");
        assert_eq!(
            std::fs::read(workspace.join("other.txt")).unwrap(),
            b"other"
        );
        assert_eq!(budget.held().0, full);

        drop(held);
        assert_eq!(budget.held().0, 0);
        assert!(budget.held_by_organization().is_empty());
        harness.shutdown().await;
    })
    .await
    .expect("test timed out");
}

/// A write still running at its deadline is abandoned with
/// `deadline_exceeded`. The body's charge, the account's and organization's
/// shares and the call's permits are released at once, while the daemon has
/// still not answered, and the staging file is removed.
#[tokio::test]
async fn a_write_still_running_at_its_deadline_is_abandoned_and_releases_its_hold() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        // The first file is staged and its mode set, and the daemon holds
        // that reply.
        let gate = FileRpcGate::new(FileRpc::SetStat, FileRpcGatePoint::AfterExecution);
        let harness = DaemonHarness::spawn_with_file_gate(Arc::clone(&gate)).await;
        let bridge =
            bridge(harness.client().await, None).with_write_timeout(Duration::from_millis(500));
        let workspace = harness.workspace_root().to_owned();
        std::fs::write(workspace.join("two.txt"), b"original").unwrap();
        let budget = Arc::new(BodyBudget::new(|_| None));
        let call = {
            let (bridge, budget) = (bridge.clone(), Arc::clone(&budget));
            let files = vec![
                (at(&workspace, "one.txt"), b"one".to_vec()),
                (at(&workspace, "two.txt"), b"two".to_vec()),
            ];
            tokio::spawn(async move {
                write_charged(
                    &bridge,
                    &budget,
                    "account",
                    1024,
                    request("environment", files),
                )
                .await
            })
        };
        gate.wait().await;
        assert_eq!(budget.held().0, 1024);
        assert_eq!(budget.held_by_organization()["local"], 1024);

        let error = tokio::time::timeout(FILE_GATE_TIMEOUT, call)
            .await
            .expect("the write was not abandoned at its deadline")
            .expect("call task")
            .expect_err("an abandoned write fails");
        assert_eq!(error.code, connectrpc::ErrorCode::DeadlineExceeded);
        assert_eq!(message(&error), crate::file::write_many::WRITES_TIMED_OUT);
        // Released at the deadline, though the daemon has not answered.
        assert_eq!(budget.held(), (0, Default::default()));
        assert!(budget.held_by_organization().is_empty());
        let permits = [
            bridge.writes.try_acquire("local", "environment"),
            bridge.writes.try_acquire("local", "environment"),
        ];
        assert!(permits.iter().all(Result::is_ok));
        drop(permits);

        gate.release();
        wait_until_no_staging(&workspace).await;
        assert!(!workspace.join("one.txt").exists());
        assert_eq!(
            std::fs::read(workspace.join("two.txt")).unwrap(),
            b"original"
        );
        harness.shutdown().await;
    })
    .await
    .expect("test timed out");
}

/// A request that reaches `write_files` without the admission's charge, on a
/// mount that lacks `write_files_admission`, is refused and writes nothing.
#[tokio::test]
async fn a_request_the_admission_did_not_charge_is_refused() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let harness = DaemonHarness::spawn().await;
        let bridge = bridge(harness.client().await, None);
        let workspace = harness.workspace_root().to_owned();
        let error = write_files_in(
            &bridge,
            RequestContext::default(),
            request(
                "environment",
                vec![(at(&workspace, "unbudgeted.txt"), b"x".to_vec())],
            ),
        )
        .await
        .expect_err("an uncharged request is refused");
        assert_eq!(error.code, connectrpc::ErrorCode::Internal);
        assert_eq!(message(&error), crate::file::write_many::NO_BODY_BUDGET);
        assert!(!workspace.join("unbudgeted.txt").exists());
        assert!(staging_left(&workspace).is_empty());
        let permits = [
            bridge.writes.try_acquire("local", "environment"),
            bridge.writes.try_acquire("local", "environment"),
        ];
        assert!(permits.iter().all(Result::is_ok));
        drop(permits);
        harness.shutdown().await;
    })
    .await
    .expect("test timed out");
}

/// A daemon that accepts the readiness check and never answers it holds
/// nothing past the deadline: the connected caller gets `deadline_exceeded`
/// at the bound, and by then the charge, both shares and the permits are
/// free, while the daemon still has not answered.
#[tokio::test]
async fn a_readiness_check_left_unanswered_is_abandoned_at_the_deadline() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let gate = FileRpcGate::new(FileRpc::GetCapabilities, FileRpcGatePoint::BeforeExecution);
        let harness = DaemonHarness::spawn_with_file_gate(Arc::clone(&gate)).await;
        let deadline = Duration::from_millis(500);
        let bridge = bridge(harness.client().await, None).with_write_timeout(deadline);
        let workspace = harness.workspace_root().to_owned();
        let budget = Arc::new(BodyBudget::new(|_| None));
        let started = tokio::time::Instant::now();
        let call = {
            let (bridge, budget) = (bridge.clone(), Arc::clone(&budget));
            let files = vec![(at(&workspace, "one.txt"), b"one".to_vec())];
            tokio::spawn(async move {
                write_charged(
                    &bridge,
                    &budget,
                    "account",
                    1024,
                    request("environment", files),
                )
                .await
            })
        };
        gate.wait().await;
        assert_eq!(budget.held().0, 1024);
        assert_eq!(budget.held_by_organization()["local"], 1024);

        let error = tokio::time::timeout(FILE_GATE_TIMEOUT, call)
            .await
            .expect("the unanswered readiness check was not abandoned")
            .expect("call task")
            .expect_err("an abandoned write fails");
        assert!(started.elapsed() >= deadline);
        assert_eq!(error.code, connectrpc::ErrorCode::DeadlineExceeded);
        assert_eq!(message(&error), crate::file::write_many::WRITES_TIMED_OUT);
        assert_eq!(budget.held(), (0, Default::default()));
        assert!(budget.held_by_organization().is_empty());
        let permits = [
            bridge.writes.try_acquire("local", "environment"),
            bridge.writes.try_acquire("local", "environment"),
        ];
        assert!(permits.iter().all(Result::is_ok));
        drop(permits);

        gate.release();
        wait_until_no_staging(&workspace).await;
        assert!(!workspace.join("one.txt").exists());
        harness.shutdown().await;
    })
    .await
    .expect("test timed out");
}

/// A caller that leaves while its files are being written leaves the body's
/// charge with the worker, which still holds the decoded files, until the
/// worker finishes.
#[tokio::test]
async fn a_caller_that_leaves_mid_write_leaves_its_charge_with_the_worker() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let gate = FileRpcGate::new(FileRpc::OpenFile, FileRpcGatePoint::BeforeExecution);
        let harness = DaemonHarness::spawn_with_file_gate(Arc::clone(&gate)).await;
        let workspace = harness.workspace_root().to_owned();
        let files = connectrpc::ConnectRpcService::new(router(TestBackend {
            daemon: harness.client().await,
            deny_authorization: false,
            restart_deadline: None,
        }));
        let budget = Arc::new(BodyBudget::new(|_| Some("account".to_owned())));
        let app = with_budget(
            axum::Router::new().route_service("/codewire.v1.FileService/{*method}", files),
            Arc::clone(&budget),
        );
        let body = request(
            "environment",
            vec![(at(&workspace, "held.txt"), b"held".to_vec())],
        )
        .encode_to_vec();
        let charged = body.len();
        let call = http::Request::post(proto::FILE_SERVICE_WRITE_FILES_SPEC.procedure)
            .header("content-type", "application/proto")
            .header("content-length", charged)
            .body(axum::body::Body::from(body))
            .expect("WriteFiles request");
        let call = tokio::spawn(tower::ServiceExt::oneshot(app, call));
        gate.wait().await;
        assert_eq!(budget.held().0, charged);

        call.abort();
        let left = tokio::time::timeout(FILE_GATE_TIMEOUT, call)
            .await
            .expect("the caller did not leave");
        assert!(left.is_err_and(|error| error.is_cancelled()));
        // The worker is held at the gate with the files, and so the charge.
        assert_eq!(budget.held().0, charged);

        gate.release();
        tokio::time::timeout(FILE_GATE_TIMEOUT, async {
            while budget.held().0 != 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the finished worker kept the charge");
        assert!(budget.held().1.is_empty());
        wait_until_no_staging(&workspace).await;
        assert!(!workspace.join("held.txt").exists());
        harness.shutdown().await;
    })
    .await
    .expect("test timed out");
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stop {
    Cancel,
    Restart,
}

/// A call stopped while its first file is being staged leaves neither file
/// nor staging name, and the existing file it would have replaced is kept.
async fn stopped_while_staging(stop: Stop) {
    let gate = FileRpcGate::new(FileRpc::SetStat, FileRpcGatePoint::AfterExecution);
    let harness = DaemonHarness::spawn_with_file_gate(Arc::clone(&gate)).await;
    let (deadline, restart_deadline) = tokio::sync::watch::channel(false);
    let bridge = bridge(harness.client().await, Some(restart_deadline));
    let workspace = harness.workspace_root().to_owned();
    std::fs::write(workspace.join("two.txt"), b"original").unwrap();
    let files = vec![
        (at(&workspace, "one.txt"), b"one".to_vec()),
        (at(&workspace, "two.txt"), b"two".to_vec()),
    ];
    let mut call = tokio::spawn(async move { write(&bridge, files).await });
    gate.wait().await;
    assert_eq!(staging_left(&workspace).len(), 1);
    match stop {
        Stop::Cancel => {
            call.abort();
            let canceled = tokio::time::timeout(FILE_GATE_TIMEOUT, &mut call)
                .await
                .expect("public call did not cancel");
            assert!(matches!(canceled, Err(error) if error.is_cancelled()));
        }
        Stop::Restart => {
            deadline.send_replace(true);
        }
    }
    gate.release();
    gate.wait_for_completion().await;
    gate.wait_for_removal().await;
    assert!(!gate.removed_before_pending_operation_finished());
    wait_until_no_staging(&workspace).await;
    if stop == Stop::Restart {
        let error = tokio::time::timeout(FILE_GATE_TIMEOUT, call)
            .await
            .expect("call did not end at the restart deadline")
            .expect("call task")
            .expect_err("a call at the restart deadline fails");
        assert_eq!(error.code, connectrpc::ErrorCode::Unavailable);
        assert!(message(&error).contains("no file was written"), "{error:?}");
    }
    assert!(!workspace.join("one.txt").exists());
    assert_eq!(
        std::fs::read(workspace.join("two.txt")).unwrap(),
        b"original"
    );
    harness.shutdown().await;
}

#[tokio::test]
async fn cancellation_while_staging_removes_every_staged_file() {
    tokio::time::timeout(TEST_TIMEOUT, stopped_while_staging(Stop::Cancel))
        .await
        .expect("test timed out");
}

#[tokio::test]
async fn the_restart_deadline_while_staging_removes_every_staged_file() {
    tokio::time::timeout(TEST_TIMEOUT, stopped_while_staging(Stop::Restart))
        .await
        .expect("test timed out");
}

#[test]
fn a_partial_write_message_names_a_few_files_and_counts_the_rest() {
    let written = (0..999)
        .map(|n| format!("/workspace/{n:03}/{}", "p".repeat(4_000)))
        .collect::<Vec<_>>();
    let text = written_files_message(Some("rename failed"), &written);
    assert!(text.len() < 2 * 1024, "{} bytes", text.len());
    assert_eq!(
        text,
        "rename failed; 999 files were written before it stopped"
    );

    let short = (0..8)
        .map(|n| format!("/workspace/{n}.txt"))
        .collect::<Vec<_>>();
    assert_eq!(
        written_files_message(None, &short),
        "writing the files failed; 8 files were written before it stopped: \
         \"/workspace/0.txt\", \"/workspace/1.txt\", \"/workspace/2.txt\", \
         \"/workspace/3.txt\", \"/workspace/4.txt\" and 3 more"
    );
    assert_eq!(
        written_files_message(None, &short[..1]),
        "writing the files failed; 1 file was written before it stopped: \"/workspace/0.txt\""
    );
}
