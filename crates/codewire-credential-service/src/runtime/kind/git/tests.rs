use std::io::Write;

use http::HeaderValue;

use super::*;

mod broker;

fn authorization() -> HeaderValue {
    HeaderValue::from_str(&format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD
            .encode("x-access-token:gho_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    ))
    .unwrap()
}

fn headers(post: bool) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("authorization", authorization());
    headers.insert(
        "user-agent",
        HeaderValue::from_static("Codewire-Credential-Broker"),
    );
    headers.insert("accept-encoding", HeaderValue::from_static("identity"));
    if post {
        headers.insert(
            "content-type",
            HeaderValue::from_static("application/x-git-upload-pack-request"),
        );
    }
    headers
}

fn gzip(body: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(body).unwrap();
    encoder.finish().unwrap()
}

fn packet(body: &str) -> Vec<u8> {
    format!("{:04x}{body}", body.len() + 4).into_bytes()
}

#[test]
fn fixed_routes_require_exact_authority_identity_and_fetch_semantics() {
    let good = headers(false);
    assert!(validate(&Method::GET, &ADVERTISEMENT.parse().unwrap(), &good, &[]).is_ok());
    for target in [
        "http://github.com/synthetic-user/repository-01.git/info/refs?service=git-upload-pack",
        "https://github.com:444/synthetic-user/repository-01.git/info/refs?service=git-upload-pack",
        "https://attacker@github.com/synthetic-user/repository-01.git/info/refs?service=git-upload-pack",
        "https://github.com/synthetic-user/repository-02.git/info/refs?service=git-upload-pack",
        "https://github.com/synthetic-user/repository-01.git/info/refs?service=git-receive-pack",
        "https://github.com/synthetic-user/repository-01.git/info/refs?service=git-upload-pack&other=1",
        "https://github.com/synthetic-user/repository-01.git/info/refs?service=git-upload-pack#fragment",
        "https://github.com/synthetic-user/repository-01.git/git-receive-pack",
        "https://github.com/synthetic-user/repository-01/info/refs?service=git-upload-pack",
    ] {
        assert!(validate(&Method::GET, &target.parse().unwrap(), &good, &[]).is_err());
    }
    assert!(validate(&Method::POST, &ADVERTISEMENT.parse().unwrap(), &good, &[]).is_err());
    assert!(validate(&Method::GET, &ADVERTISEMENT.parse().unwrap(), &good, b"x").is_err());
    for name in [
        "cookie",
        "proxy-authorization",
        "host",
        "if-none-match",
        "content-type",
        "content-encoding",
    ] {
        let mut bad = good.clone();
        bad.insert(name, HeaderValue::from_static("unexpected"));
        assert!(validate(&Method::GET, &ADVERTISEMENT.parse().unwrap(), &bad, &[]).is_err());
    }
    for value in [
        None,
        Some("Bearer gho_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        Some("Basic wrong"),
    ] {
        let mut bad = good.clone();
        bad.remove("authorization");
        if let Some(value) = value {
            bad.insert("authorization", HeaderValue::from_str(value).unwrap());
        }
        assert!(validate(&Method::GET, &ADVERTISEMENT.parse().unwrap(), &bad, &[]).is_err());
    }
    for name in [
        "authorization",
        "accept",
        "git-protocol",
        "user-agent",
        "accept-encoding",
    ] {
        let mut bad = good.clone();
        if name == "accept" {
            bad.insert(name, HeaderValue::from_static("*/*"));
        } else if name == "git-protocol" {
            bad.insert(name, HeaderValue::from_static("version=2"));
        }
        bad.append(name, HeaderValue::from_static("duplicate"));
        assert!(validate(&Method::GET, &ADVERTISEMENT.parse().unwrap(), &bad, &[]).is_err());
    }
    for name in ["user-agent", "accept-encoding"] {
        let mut bad = good.clone();
        bad.remove(name);
        assert!(validate(&Method::GET, &ADVERTISEMENT.parse().unwrap(), &bad, &[]).is_err());
        bad.insert(name, HeaderValue::from_static("untrusted"));
        assert!(validate(&Method::GET, &ADVERTISEMENT.parse().unwrap(), &bad, &[]).is_err());
    }
}

#[test]
fn gzip_is_single_member_bounded_and_only_for_fetch_post() {
    let mut headers = headers(true);
    let target = UPLOAD_PACK.parse().unwrap();
    let body = packet(&format!("want {REVISION}\n"));
    headers.insert("content-encoding", HeaderValue::from_static("gzip"));
    assert_eq!(
        validate(&Method::POST, &target, &headers, &gzip(&body))
            .unwrap()
            .body,
        body
    );
    for bad in [
        vec![0; 32],
        gzip(&[]),
        gzip(&vec![b'x'; IO_LIMIT + 1]),
        [gzip(&body), gzip(&body)].concat(),
        [gzip(&body), b"junk".to_vec()].concat(),
        vec![0; WIRE_LIMIT + 1],
    ] {
        assert!(validate(&Method::POST, &target, &headers, &bad).is_err());
    }
    for encoding in ["GZIP", "gzip, identity", "br", "deflate", ""] {
        headers.insert("content-encoding", HeaderValue::from_str(encoding).unwrap());
        assert!(validate(&Method::POST, &target, &headers, &body).is_err());
    }
    headers.insert("content-encoding", HeaderValue::from_static("identity"));
    assert_eq!(
        validate(&Method::POST, &target, &headers, &body)
            .unwrap()
            .body,
        body
    );
    headers.append("content-encoding", HeaderValue::from_static("identity"));
    assert!(validate(&Method::POST, &target, &headers, &body).is_err());
    headers.remove("content-encoding");
    assert!(validate(&Method::POST, &target, &headers, &vec![0; IO_LIMIT + 1]).is_err());
    headers.append(
        "content-type",
        HeaderValue::from_static("application/x-git-upload-pack-request"),
    );
    assert!(validate(&Method::POST, &target, &headers, &body).is_err());
}

#[test]
fn protocol_and_cgi_responses_fail_closed() {
    let mut headers = headers(false);
    for protocol in ["version=1", "version=2"] {
        headers.insert("git-protocol", HeaderValue::from_str(protocol).unwrap());
        assert!(validate(&Method::GET, &ADVERTISEMENT.parse().unwrap(), &headers, &[]).is_ok());
    }
    for protocol in ["version=3", "version=2:agent=custom", "version=2\t"] {
        headers.insert("git-protocol", HeaderValue::from_str(protocol).unwrap());
        assert!(validate(&Method::GET, &ADVERTISEMENT.parse().unwrap(), &headers, &[]).is_err());
    }
    let valid =
        "Content-Type: application/x-git-upload-pack-result\r\nCache-Control: no-cache\r\n\r\nPACK";
    assert_eq!(
        response_body(Operation::UploadPack, valid.as_bytes().to_vec()).unwrap(),
        b"PACK"
    );
    for response in [
        "Status: 302 Found\r\nLocation: https://example.invalid\r\n\r\nPACK",
        "Content-Type: application/x-git-upload-pack-result\r\nSet-Cookie: x=y\r\n\r\nPACK",
        "Content-Type: application/x-git-upload-pack-result\r\nContent-Encoding: gzip\r\n\r\nPACK",
        "Content-Type: application/x-git-upload-pack-result\r\nContent-Type: application/x-git-upload-pack-result\r\n\r\nPACK",
        "Content-Type: text/plain\r\n\r\nPACK",
        "Content-Type: application/x-git-upload-pack-result\r\n\r\n",
    ] {
        assert!(response_body(Operation::UploadPack, response.as_bytes().to_vec()).is_err());
    }
}

// Also invoked, by exact name, in the final non-root services-ci image. This
// must stay hermetic: no shell, socket, external provider, or ignored fallback.
#[tokio::test]
async fn stock_git_smart_http_round_trip() {
    let runtime = tempfile::Builder::new()
        .prefix("kind-git-test-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in("/dev/shm")
        .unwrap();
    let fixture = Fixture::create(runtime.path()).await.unwrap();
    let root = fixture.root.clone();
    let advertisement = broker::execute(
        &fixture,
        &Method::GET,
        &ADVERTISEMENT.parse().unwrap(),
        &headers(false),
        &[],
    )
    .await
    .unwrap()
    .1;
    assert!(
        advertisement
            .windows(REVISION.len())
            .any(|window| window == REVISION.as_bytes())
    );
    assert!(
        advertisement
            .windows(b"refs/heads/main".len())
            .any(|window| window == b"refs/heads/main")
    );

    let request = [
        packet(&format!("want {REVISION}\n")),
        b"0000".to_vec(),
        packet("done\n"),
    ]
    .concat();
    let mut post_headers = headers(true);
    for compressed in [false, true] {
        let body = if compressed {
            post_headers.insert("content-encoding", HeaderValue::from_static("gzip"));
            gzip(&request)
        } else {
            request.clone()
        };
        let response = broker::execute(
            &fixture,
            &Method::POST,
            &UPLOAD_PACK.parse().unwrap(),
            &post_headers,
            &body,
        )
        .await
        .unwrap()
        .1;
        assert!(response.starts_with(b"0008NAK\nPACK"));
        let destination = if compressed {
            "received-gzip.git"
        } else {
            "received.git"
        };
        run(
            command(&root).args([
                "init",
                "--quiet",
                "--bare",
                "--template=",
                "--object-format=sha1",
                destination,
            ]),
            &[],
            &fixture.stop,
        )
        .await
        .unwrap();
        let git_dir = format!("--git-dir={destination}");
        run(
            command(&root).args([&git_dir, "index-pack", "--stdin", "--strict"]),
            &response[8..],
            &fixture.stop,
        )
        .await
        .unwrap();
        let proof = run(
            command(&root).args([&git_dir, "show", &format!("{REVISION}:proof.txt")]),
            &[],
            &fixture.stop,
        )
        .await
        .unwrap();
        assert_eq!(proof, CONTENT);
    }
    let mut version_two = headers(false);
    version_two.insert("git-protocol", HeaderValue::from_static("version=2"));
    let advertisement = broker::execute(
        &fixture,
        &Method::GET,
        &ADVERTISEMENT.parse().unwrap(),
        &version_two,
        &[],
    )
    .await
    .unwrap()
    .1;
    assert!(
        advertisement
            .windows(b"version 2".len())
            .any(|window| window == b"version 2")
    );
    let mut version_two = headers(true);
    version_two.insert("git-protocol", HeaderValue::from_static("version=2"));
    let request = [
        packet("command=ls-refs\n"),
        b"0001".to_vec(),
        packet("ref-prefix refs/heads/main\n"),
        b"0000".to_vec(),
    ]
    .concat();
    let refs = broker::execute(
        &fixture,
        &Method::POST,
        &UPLOAD_PACK.parse().unwrap(),
        &version_two,
        &request,
    )
    .await
    .unwrap()
    .1;
    assert!(
        refs.windows(REVISION.len())
            .any(|window| window == REVISION.as_bytes())
    );
    fixture.close().await.unwrap();
    assert!(fixture.tasks.is_empty());
    assert!(!root.exists());
    assert!(
        fixture
            .execute(
                &Method::GET,
                &ADVERTISEMENT.parse().unwrap(),
                &headers(false),
                &[]
            )
            .await
            .is_err()
    );
}

#[tokio::test]
async fn backend_admission_is_bounded_and_shutdown_closes_it() {
    let runtime = tempfile::Builder::new()
        .prefix("kind-git-admission-test-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in("/dev/shm")
        .unwrap();
    let fixture = Fixture::create(runtime.path()).await.unwrap();
    let held = fixture.permits.clone().acquire_many_owned(2).await.unwrap();
    let result = fixture
        .execute(
            &Method::GET,
            &ADVERTISEMENT.parse().unwrap(),
            &headers(false),
            &[],
        )
        .await;
    assert!(matches!(result, Err(Error::ResourceLimit)));
    assert!(fixture.tasks.is_empty());
    drop(held);
    // Race ordinary request admission against close. The shared admission lock
    // must leave no backend task able to start after directory removal.
    let requests = (0..8)
        .map(|_| {
            let fixture = fixture.clone();
            tokio::spawn(async move {
                fixture
                    .execute(
                        &Method::GET,
                        &ADVERTISEMENT.parse().unwrap(),
                        &headers(false),
                        &[],
                    )
                    .await
            })
        })
        .collect::<Vec<_>>();
    fixture.close().await.unwrap();
    for request in requests {
        let _ = request.await.unwrap();
    }
    assert!(fixture.tasks.is_empty());
    assert!(!fixture.root.exists());
    assert!(!fixture.lifecycle.lock().unwrap().open);
}

#[tokio::test]
async fn unproven_child_cleanup_retains_the_private_directory() {
    let runtime = tempfile::Builder::new()
        .prefix("kind-git-retention-test-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in("/dev/shm")
        .unwrap();
    let fixture = Fixture::create(runtime.path()).await.unwrap();
    // Exercise the same unwind guard used by tracked requests, without an
    // intentional panic that could obscure the test runner's own exit status.
    drop(TaskCustody {
        failed: &fixture.cleanup_failed,
        completed: false,
    });
    assert!(fixture.close().await.is_err());
    assert!(fixture.root.is_dir());
    assert!(!fixture.lifecycle.lock().unwrap().open);
    // This test still owns its synthetic root and has spawned no failing child.
    fixture
        .lifecycle
        .lock()
        .unwrap()
        .directory
        .take()
        .unwrap()
        .close()
        .unwrap();
}
