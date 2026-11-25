//! The identity socket served on a real Unix socket, from a fake token
//! source, and read with the same client `cw identity token` uses.

use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::*;

const AUDIENCE: &str = "https://k8s.walk.example";
const TOKEN: &str = "eyJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJ4In0.c2ln";
const STEP: Duration = Duration::from_secs(10);

/// The clock every served socket in this module reads.
static NOW: AtomicI64 = AtomicI64::new(1_000);

fn test_now() -> i64 {
    NOW.load(Ordering::SeqCst)
}

/// Answers `TOKEN` for `AUDIENCE`, expiring 600 s after the test clock, or
/// the refusal its resource names.
#[derive(Clone, Default)]
struct Source {
    calls: Arc<AtomicUsize>,
    seen: Arc<Mutex<Vec<String>>>,
}

impl IdentityTokenSource for Source {
    async fn issue(&self, resource: &str) -> Result<IssuedIdentityToken, IdentityRefusal> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.seen.lock().unwrap().push(resource.to_owned());
        if let Some(refusal) = resource
            .strip_prefix("https://refuse.example/")
            .and_then(IdentityRefusal::from_name)
        {
            return Err(refusal);
        }
        Ok(IssuedIdentityToken {
            token: Zeroizing::new(TOKEN.to_owned()),
            expires_at: test_now() + 600,
        })
    }
}

struct Served {
    _directory: tempfile::TempDir,
    path: std::path::PathBuf,
    source: Source,
    _record: PlatformSocket,
}

async fn served() -> Served {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("identity.sock");
    let (listener, record) = bind(&path).unwrap();
    let source = Source::default();
    let app = router(source.clone(), test_now);
    tokio::spawn(async move { axum::serve(listener, app).await });
    Served {
        _directory: directory,
        path,
        source,
        _record: record,
    }
}

async fn ask(served: &Served, resource: &str) -> Result<Zeroizing<String>, FetchError> {
    tokio::time::timeout(STEP, fetch(&served.path, resource))
        .await
        .expect("the socket answers within its bound")
}

/// The raw status and body for `target`.
async fn raw(served: &Served, method: &str, target: &str) -> (u16, String) {
    let mut stream = tokio::net::UnixStream::connect(&served.path).await.unwrap();
    let request =
        format!("{method} {target} HTTP/1.1\r\nHost: identity\r\nConnection: close\r\n\r\n");
    let exchange = async {
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut answer = String::new();
        stream.read_to_string(&mut answer).await.unwrap();
        answer
    };
    let answer = tokio::time::timeout(STEP, exchange).await.unwrap();
    let (head, body) = answer.split_once("\r\n\r\n").unwrap();
    let status = head.split(' ').nth(1).unwrap().parse().unwrap();
    (status, body.to_owned())
}

#[tokio::test]
async fn the_socket_is_owner_only_and_a_platform_socket() {
    let served = served().await;
    let metadata = std::fs::symlink_metadata(&served.path).unwrap();
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    assert_eq!(
        crate::platform_sockets::named(metadata.dev(), metadata.ino()),
        Some("the daemon's identity socket")
    );
}

#[tokio::test]
async fn a_token_is_text_and_a_repeat_before_half_its_lifetime_asks_nothing() {
    let served = served().await;
    let (status, body) = raw(
        &served,
        "GET",
        "/token?resource=https%3A%2F%2Fk8s.walk.example",
    )
    .await;
    assert_eq!((status, body.as_str()), (200, TOKEN));
    assert_eq!(ask(&served, AUDIENCE).await.unwrap().as_str(), TOKEN);
    assert_eq!(served.source.calls.load(Ordering::SeqCst), 1);
    assert_eq!(*served.source.seen.lock().unwrap(), [AUDIENCE]);
}

#[tokio::test]
async fn each_refusal_is_its_status_with_its_name() {
    let served = served().await;
    for (name, status) in [
        ("invalid_target", 400),
        ("identity_stopped", 403),
        ("resource_exhausted", 429),
        ("identity_unavailable", 503),
        ("key_not_yet_published", 503),
        ("not_running", 503),
    ] {
        let target = format!("/token?resource=https://refuse.example/{name}");
        assert_eq!(
            raw(&served, "GET", &target).await,
            (status, name.to_owned()),
            "{name}"
        );
        let refusal = IdentityRefusal::from_name(name).unwrap();
        assert_eq!(
            ask(&served, &format!("https://refuse.example/{name}")).await,
            Err(FetchError::Refused(refusal))
        );
    }
    // A refusal is never cached: each one asked again.
    assert_eq!(served.source.calls.load(Ordering::SeqCst), 12);
}

#[tokio::test]
async fn a_request_without_a_usable_resource_is_invalid_target_and_asks_nothing() {
    let served = served().await;
    let long = "a".repeat(codewire_daemon_proto::IDENTITY_RESOURCE_MAX_BYTES + 1);
    for target in [
        "/token",
        "/token?resource=",
        "/token?other=1",
        &format!("/token?resource={long}"),
    ] {
        assert_eq!(
            raw(&served, "GET", target).await,
            (400, "invalid_target".to_owned()),
            "{target}"
        );
    }
    assert_eq!(raw(&served, "GET", "/other").await.0, 404);
    assert_eq!(raw(&served, "POST", "/token?resource=x").await.0, 405);
    assert_eq!(served.source.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn no_socket_is_not_a_cloud_sandbox() {
    let directory = tempfile::tempdir().unwrap();
    assert_eq!(
        fetch(&directory.path().join("identity.sock"), AUDIENCE).await,
        Err(FetchError::NoSocket)
    );
}

#[test]
fn the_cache_keeps_a_token_until_half_its_lifetime_and_is_bounded() {
    let shared = Shared {
        source: Source::default(),
        cache: Mutex::new(HashMap::new()),
        now: test_now,
    };
    let issued = |expires_at| IssuedIdentityToken {
        token: Zeroizing::new(TOKEN.to_owned()),
        expires_at,
    };
    shared.keep(AUDIENCE.to_owned(), issued(1_600), 1_000);
    assert!(shared.cached(AUDIENCE, 1_299).is_some());
    assert!(shared.cached(AUDIENCE, 1_300).is_none());

    for index in 0..=MAX_CACHED_AUDIENCES {
        let at = 2_000 + i64::try_from(index).unwrap();
        shared.keep(format!("https://{index}.example"), issued(at + 600), at);
    }
    let cache = shared.cache.lock().unwrap();
    assert_eq!(cache.len(), MAX_CACHED_AUDIENCES);
    assert!(
        !cache.contains_key("https://0.example"),
        "the soonest stale went first"
    );
}

#[test]
fn a_resource_is_query_encoded() {
    assert_eq!(
        query_encoded("https://k8s.walk.example:443/a b?c"),
        "https%3A%2F%2Fk8s.walk.example%3A443%2Fa%20b%3Fc"
    );
}

#[tokio::test]
async fn two_holders_of_one_cache_share_its_token() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("identity.sock");
    let (listener, _record) = bind(&path).unwrap();
    let source = Source::default();
    let tokens = Arc::new(IdentityTokens::with_clock(source.clone(), test_now));
    let app = router_for(Arc::clone(&tokens));
    tokio::spawn(async move { axum::serve(listener, app).await });

    // The other holder mints first; the socket then serves that token.
    let held = tokio::time::timeout(STEP, tokens.token(AUDIENCE))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(held.token.as_str(), TOKEN);
    assert_eq!(held.expires_at, test_now() + 600);
    assert_eq!(held.stale_at, test_now() + 300);
    let served = tokio::time::timeout(STEP, fetch(&path, AUDIENCE))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(served.as_str(), TOKEN);

    // And the other way round, for an audience the socket asked first.
    let other = "https://other.walk.example";
    tokio::time::timeout(STEP, fetch(&path, other))
        .await
        .unwrap()
        .unwrap();
    let again = tokio::time::timeout(STEP, tokens.token(other))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(again.stale_at, held.stale_at);
    assert_eq!(source.calls.load(Ordering::SeqCst), 2);
    assert_eq!(*source.seen.lock().unwrap(), [AUDIENCE, other]);
}
