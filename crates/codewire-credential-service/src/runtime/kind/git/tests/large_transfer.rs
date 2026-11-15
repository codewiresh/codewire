//! The large-transfer repository (#4280) with stock Git: a streamed push of a
//! pack over 4 MiB, and a fetch whose response streams back whole.

use std::os::unix::fs::PermissionsExt;

use axum::body::Bytes;
use futures::StreamExt as _;

use super::*;

const LARGE: &str = "https://github.com/synthetic-user/repository-large.git/";

fn large_headers(media: Option<&'static str>) -> HeaderMap {
    let mut headers = headers(false);
    if let Some(media) = media {
        headers.insert("content-type", HeaderValue::from_static(media));
    }
    headers
}

async fn collect(body: LargeBody) -> Vec<u8> {
    body.map(|chunk| chunk.unwrap().to_vec()).concat().await
}

/// A request body as the broker hands one over: 64 KiB frames.
fn frames(body: Vec<u8>) -> codewire_credential_broker::BrokerRequestBodyStream {
    let chunks = body
        .chunks(64 * 1024)
        .map(|chunk| Ok(Bytes::copy_from_slice(chunk)))
        .collect::<Vec<_>>();
    Box::pin(futures::stream::iter(chunks))
}

/// Run a local Git command whose output may exceed the small fixture's limit.
async fn output(fixture: &Fixture, args: &[&str], input: Vec<u8>) -> Vec<u8> {
    let (sender, mut receiver) = tokio::sync::mpsc::channel(16);
    let mut git = command(&fixture.root);
    git.args(args);
    let (result, bytes) = tokio::join!(
        process::run_streaming(
            &mut git,
            Box::pin(futures::stream::iter([Ok(Bytes::from(input))])),
            sender,
            &fixture.stop,
            std::time::Duration::from_secs(60),
        ),
        async {
            let mut bytes = Vec::new();
            while let Some(chunk) = receiver.recv().await {
                bytes.extend_from_slice(&chunk.unwrap());
            }
            bytes
        },
    );
    result.unwrap();
    bytes
}

#[test]
fn large_selection_is_exact() {
    assert!(large::Config::new("/var/lib/large".into(), "264").is_ok());
    for (directory, size) in [("relative", "1"), ("/a", "0"), ("/a", "2049"), ("/a", "x")] {
        assert!(large::Config::new(directory.into(), size).is_err());
    }
    let good = large_headers(None);
    let target = |rest: &str| format!("{LARGE}{rest}").parse::<url::Url>().unwrap();
    assert!(
        large::validate(
            &Method::GET,
            &target("info/refs?service=git-receive-pack"),
            &good,
            false
        )
        .is_ok()
    );
    assert!(
        large::validate(
            &Method::GET,
            &target("info/refs?service=git-receive-pack"),
            &good,
            true
        )
        .is_err()
    );
    assert!(large::validate(&Method::POST, &target("git-receive-pack"), &good, true).is_err());
    let push = large_headers(Some("application/x-git-receive-pack-request"));
    assert!(large::validate(&Method::POST, &target("git-receive-pack"), &push, true).is_ok());
    assert!(large::validate(&Method::POST, &target("git-receive-pack"), &push, false).is_err());
    assert!(large::validate(&Method::POST, &target("git-upload-pack"), &push, true).is_err());
    assert!(large::validate(&Method::POST, &target("other"), &push, true).is_err());
    let mut unauthenticated = push.clone();
    unauthenticated.remove("authorization");
    assert!(
        large::validate(
            &Method::POST,
            &target("git-receive-pack"),
            &unauthenticated,
            true
        )
        .is_err()
    );
}

#[tokio::test]
async fn large_repository_streams_a_push_over_four_mebibytes_and_its_fetch() {
    let runtime = tempfile::Builder::new()
        .prefix("kind-git-test-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in("/dev/shm")
        .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let fixture = Fixture::create_with_large(
        runtime.path(),
        Some(large::Config::new(directory.path().to_owned(), "6").unwrap()),
    )
    .await
    .unwrap();
    let commit = fixture.large.as_ref().unwrap().commit.clone();

    // Fetch: every blob, streamed back.
    let (operation, advertisement) = fixture
        .execute_large(
            &Method::GET,
            &format!("{LARGE}info/refs?service=git-upload-pack")
                .parse()
                .unwrap(),
            &large_headers(None),
            Vec::new(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(operation, large::Operation::FetchAdvertisement);
    let advertisement = collect(advertisement).await;
    assert!(
        advertisement
            .windows(40)
            .any(|window| window == commit.as_bytes())
    );
    let request = [
        packet(&format!("want {commit}\n")),
        b"0000".to_vec(),
        packet("done\n"),
    ]
    .concat();
    let (_, pack) = fixture
        .execute_large(
            &Method::POST,
            &format!("{LARGE}git-upload-pack").parse().unwrap(),
            &large_headers(Some("application/x-git-upload-pack-request")),
            Vec::new(),
            Some(frames(request)),
        )
        .await
        .unwrap();
    let pack = collect(pack).await;
    assert!(pack.starts_with(b"0008NAK\nPACK"));
    assert!(pack.len() > 6 * 1024 * 1024);
    run(
        command(&fixture.root).args(["init", "--quiet", "--bare", "--template=", "local.git"]),
        &[],
        &fixture.stop,
    )
    .await
    .unwrap();
    output(
        &fixture,
        &["--git-dir=local.git", "index-pack", "--stdin", "--strict"],
        pack[8..].to_vec(),
    )
    .await;
    output(
        &fixture,
        &[
            "--git-dir=local.git",
            "update-ref",
            "refs/heads/main",
            &commit,
        ],
        Vec::new(),
    )
    .await;
    output(
        &fixture,
        &["--git-dir=local.git", "fsck", "--strict"],
        Vec::new(),
    )
    .await;

    // Push: one new commit with 5 MiB of incompressible bytes.
    let mut state = 0x2545_F491_4F6C_DD1D_u64;
    let blob: Vec<u8> = (0..5 * 1024 * 1024 / 8)
        .flat_map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state.to_le_bytes()
        })
        .collect();
    let blob = String::from_utf8(
        output(
            &fixture,
            &["--git-dir=local.git", "hash-object", "-w", "--stdin"],
            blob,
        )
        .await,
    )
    .unwrap();
    let tree = String::from_utf8(
        output(
            &fixture,
            &["--git-dir=local.git", "mktree"],
            format!("100644 blob {}\tpushed.bin\n", blob.trim()).into_bytes(),
        )
        .await,
    )
    .unwrap();
    let pushed = String::from_utf8(
        output(
            &fixture,
            &[
                "--git-dir=local.git",
                "-c",
                "user.name=Synthetic",
                "-c",
                "user.email=synthetic@example.invalid",
                "commit-tree",
                tree.trim(),
                "-p",
                &commit,
                "-m",
                "pushed",
            ],
            Vec::new(),
        )
        .await,
    )
    .unwrap();
    let pushed = pushed.trim();
    let pack = output(
        &fixture,
        &[
            "--git-dir=local.git",
            "pack-objects",
            "--stdout",
            "--revs",
            "--thin",
        ],
        format!("{pushed}\n^{commit}\n").into_bytes(),
    )
    .await;
    assert!(pack.len() > 4 * 1024 * 1024);
    let zero = "0".repeat(40);
    let request = [
        packet(&format!(
            "{zero} {pushed} refs/heads/pushed\0report-status\n"
        )),
        b"0000".to_vec(),
        pack,
    ]
    .concat();
    let (operation, report) = fixture
        .execute_large(
            &Method::POST,
            &format!("{LARGE}git-receive-pack").parse().unwrap(),
            &large_headers(Some("application/x-git-receive-pack-request")),
            Vec::new(),
            Some(frames(request)),
        )
        .await
        .unwrap();
    assert_eq!(operation, large::Operation::ReceivePack);
    let report = collect(report).await;
    assert!(
        report.windows(9).any(|window| window == b"unpack ok"),
        "{}",
        String::from_utf8_lossy(&report)
    );
    assert!(
        report
            .windows(20)
            .any(|window| window == b"ok refs/heads/pushed")
    );
    // The large repository lives in its own selected directory.
    let stored = run(
        command(directory.path()).args([
            "--git-dir=repository-large.git",
            "rev-parse",
            "refs/heads/pushed",
        ]),
        &[],
        &fixture.stop,
    )
    .await
    .unwrap();
    assert_eq!(String::from_utf8(stored).unwrap().trim(), pushed);
    fixture.close().await.unwrap();
    assert!(fixture.tasks.is_empty());
}
