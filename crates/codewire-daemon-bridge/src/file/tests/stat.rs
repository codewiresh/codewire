//! StatFile (#5804) against the actual confined daemon; the requirements are
//! SPEC.md, "File transfer", and `files-stat` in docs/journeys/sdk-files.md.

use buffa::{HasMessageView as _, Message as _};

use super::*;

const TEST_TIMEOUT: Duration = Duration::from_secs(30);

fn bridge(daemon: DaemonClient) -> FileBridge<TestBackend> {
    FileBridge::new(TestBackend {
        daemon,
        deny_authorization: false,
        restart_deadline: None,
    })
}

fn stat_request(org_id: &str, environment_id: &str, path: &str) -> proto::StatFileRequest {
    proto::StatFileRequest {
        org_id: org_id.to_owned(),
        environment_id: environment_id.to_owned(),
        path: path.to_owned(),
        ..Default::default()
    }
}

async fn stat_message(
    bridge: &FileBridge<TestBackend>,
    message: proto::StatFileRequest,
) -> Result<proto::FileEntry, connectrpc::ConnectError> {
    let body = bytes::Bytes::from(message.encode_to_vec());
    let view = proto::StatFileRequest::decode_view(&body).expect("decode stat view");
    let response = proto::FileService::stat_file(
        bridge,
        RequestContext::default(),
        ServiceRequest::from_parts(&view, &body),
    )
    .await?;
    Ok(response
        .body
        .entry
        .into_option()
        .expect("a stat answer carries its entry"))
}

async fn stat(
    bridge: &FileBridge<TestBackend>,
    path: &Path,
) -> Result<proto::FileEntry, connectrpc::ConnectError> {
    stat_message(
        bridge,
        stat_request("local", "environment", &path.to_string_lossy()),
    )
    .await
}

async fn list(
    bridge: &FileBridge<TestBackend>,
    path: &Path,
) -> Result<Vec<proto::FileEntry>, connectrpc::ConnectError> {
    let message = proto::ListFilesRequest {
        org_id: "local".into(),
        environment_id: "environment".into(),
        path: path.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let body = bytes::Bytes::from(message.encode_to_vec());
    let view = proto::ListFilesRequest::decode_view(&body).expect("decode list view");
    let response = proto::FileService::list_files(
        bridge,
        RequestContext::default(),
        ServiceRequest::from_parts(&view, &body),
    )
    .await?;
    Ok(response.body.entries)
}

#[tokio::test]
async fn stat_gives_the_list_row_and_describes_a_symlink_as_itself() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let harness = DaemonHarness::spawn().await;
        let bridge = bridge(harness.client().await);
        let root = harness.workspace_root().to_owned();
        std::fs::write(root.join("file.txt"), b"hello").unwrap();
        std::fs::create_dir(root.join("folder")).unwrap();
        // The target's name is longer than the file, so following the link
        // would show a different size as well as a different kind.
        std::os::unix::fs::symlink("file.txt", root.join("link")).unwrap();

        let rows = list(&bridge, &root).await.expect("list the workspace");
        let row = |name: &str| {
            rows.iter()
                .find(|entry| entry.name == name)
                .cloned()
                .unwrap_or_else(|| panic!("{name} is listed"))
        };

        let file = stat(&bridge, &root.join("file.txt")).await.unwrap();
        assert_eq!(
            (file.name.as_str(), file.size, file.is_dir),
            ("file.txt", 5, false)
        );
        assert_eq!(file.mode & 0o170000, 0o100000);
        assert_eq!(file, row("file.txt"));

        let folder = stat(&bridge, &root.join("folder")).await.unwrap();
        assert!(folder.is_dir);
        assert_eq!(folder.mode & 0o170000, 0o040000);
        assert_eq!(folder, row("folder"));

        let link = stat(&bridge, &root.join("link")).await.unwrap();
        assert!(!link.is_dir);
        assert_eq!(link.mode & 0o170000, 0o120000);
        assert_eq!(link.size, i64::try_from("file.txt".len()).unwrap());
        assert_eq!(link, row("link"));

        harness.shutdown().await;
    })
    .await
    .expect("stat test finished in time");
}

#[tokio::test]
async fn a_missing_path_or_a_staging_name_is_not_found() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let harness = DaemonHarness::spawn().await;
        let bridge = bridge(harness.client().await);
        let root = harness.workspace_root().to_owned();

        let missing = stat(&bridge, &root.join("missing")).await.unwrap_err();
        assert_eq!(missing.code, connectrpc::ErrorCode::NotFound);

        // A staging file that exists is answered as missing, as ListFiles
        // leaves it out.
        let staging = format!("{UPLOAD_STAGING_PREFIX}0123456789abcdef");
        std::fs::write(root.join(&staging), b"partial").unwrap();
        assert!(
            list(&bridge, &root)
                .await
                .unwrap()
                .iter()
                .all(|entry| entry.name != staging)
        );
        let hidden = stat(&bridge, &root.join(&staging)).await.unwrap_err();
        assert_eq!(hidden.code, connectrpc::ErrorCode::NotFound);
        assert_eq!(hidden.message, missing.message);

        harness.shutdown().await;
    })
    .await
    .expect("stat test finished in time");
}

#[tokio::test]
async fn a_path_outside_the_roots_is_refused_as_list_files_refuses_it() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let harness = DaemonHarness::spawn().await;
        let bridge = bridge(harness.client().await);

        let listed = list(&bridge, Path::new("/etc")).await.unwrap_err();
        assert_eq!(listed.code, connectrpc::ErrorCode::InvalidArgument);
        // Whether the path exists outside makes no difference.
        for outside in ["/etc", "/etc/passwd", "/codewire-no-such-folder/file"] {
            let refused = stat(&bridge, Path::new(outside)).await.unwrap_err();
            assert_eq!(
                (refused.code, &refused.message),
                (listed.code, &listed.message),
                "{outside}"
            );
        }

        harness.shutdown().await;
    })
    .await
    .expect("stat test finished in time");
}

#[tokio::test]
async fn a_bad_coordinate_is_invalid_and_names_its_field() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let harness = DaemonHarness::spawn().await;
        let bridge = bridge(harness.client().await);
        let staging = format!("/workspace/{UPLOAD_STAGING_PREFIX}0123456789abcdef");

        for (request, field) in [
            (stat_request("", "environment", "/workspace/a"), "/org_id"),
            (
                stat_request("local", " ", "/workspace/a"),
                "/environment_id",
            ),
            (stat_request("local", "environment", ""), "/path"),
            // The coordinates are checked before a staging name is hidden.
            (stat_request("", "environment", &staging), "/org_id"),
        ] {
            let error = stat_message(&bridge, request).await.unwrap_err();
            assert_eq!(
                error.code,
                connectrpc::ErrorCode::InvalidArgument,
                "{field}"
            );
            assert_eq!(
                error.message.as_deref(),
                Some(format!("invalid test request: {field}").as_str())
            );
        }

        harness.shutdown().await;
    })
    .await
    .expect("stat test finished in time");
}
