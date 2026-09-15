use super::*;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use crate::{BrokerUpstreamError, BrokerUpstreamResponse};
use async_trait::async_trait;
use bytes::Bytes;
use serde_json::json;

struct AccountLease {
    metadata: CredentialMetadata,
    material: Zeroizing<Vec<u8>>,
    reads: Arc<AtomicUsize>,
}

impl GithubRepositoryAccountLease for AccountLease {
    fn metadata(&self) -> &CredentialMetadata {
        &self.metadata
    }
    fn with_material<T>(self, operation: impl FnOnce(&[u8]) -> T) -> T {
        self.reads.fetch_add(1, Ordering::SeqCst);
        operation(&self.material)
    }
}

fn lease() -> AccountLease {
    let fixture = crate::http_test_support::Lease::new(
        "github",
        CredentialAuthKind::OAuth,
        "github",
        "rest",
        "github-api",
    );
    AccountLease {
        metadata: fixture.metadata,
        material: fixture.material,
        reads: fixture.reads,
    }
}

struct Upstream {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
    polls: Arc<AtomicUsize>,
    calls: Arc<AtomicUsize>,
}

impl Upstream {
    fn new(status: StatusCode, body: Vec<u8>) -> Self {
        Self {
            status,
            headers: HeaderMap::from_iter([(
                http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            )]),
            body,
            polls: Arc::new(AtomicUsize::new(0)),
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }
}

#[async_trait]
impl BrokerUpstreamTransport for Upstream {
    async fn execute(
        &self,
        request: BrokerUpstreamRequest,
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        let (method, target, headers, body) = request.into_parts();
        assert_eq!(method, Method::GET);
        assert_eq!(
            target.origin().ascii_serialization(),
            "https://api.github.com"
        );
        assert_eq!(target.path(), "/user/repos");
        assert!(target.query().unwrap().starts_with("per_page="));
        assert!(
            headers
                .get(http::header::AUTHORIZATION)
                .unwrap()
                .to_str()
                .unwrap()
                == format!(
                    "Bearer {}",
                    std::str::from_utf8(crate::http_test_support::TOKEN).unwrap()
                )
        );
        assert!(body.is_empty());
        self.calls.fetch_add(1, Ordering::SeqCst);
        let polls = self.polls.clone();
        let body = self.body.clone();
        Ok(BrokerUpstreamResponse::new(
            self.status,
            self.headers.clone(),
            Box::pin(futures::stream::once(async move {
                polls.fetch_add(1, Ordering::SeqCst);
                Ok(Bytes::from(body))
            })),
        ))
    }
}

fn repository() -> serde_json::Value {
    json!({"id":42,"full_name":"owner/private-repo","default_branch":"main","private":true,"archived":false,"disabled":false,
        "clone_url":"https://attacker.example/credential-target", "temp_clone_token":"never-return-this-provider-secret", "unknown":{"token":"also-private"}})
}

#[tokio::test]
async fn account_discovery_is_finite_and_returns_only_reconstructed_metadata() {
    let upstream = Upstream::new(
        StatusCode::OK,
        serde_json::to_vec(&json!([repository()])).unwrap(),
    );
    let result = list_repositories(&upstream, lease(), 1, 1).await.unwrap();
    assert_eq!(
        result.repositories,
        vec![Repository {
            repository_id: "42".into(),
            full_name: "owner/private-repo".into(),
            default_branch: "main".into(),
            clone_url: "https://github.com/owner/private-repo.git".into(),
            is_private: true,
            archived: false,
            disabled: false,
        }]
    );
    assert!(result.has_more);
    assert!(!format!("{:?}", result.repositories).contains("provider-secret"));
    assert_eq!(upstream.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn invalid_account_request_or_identity_never_reads_material_or_calls_provider() {
    let upstream = Upstream::new(StatusCode::OK, b"[]".to_vec());
    for (page, size) in [(0, 50), (MAX_PAGE + 1, 50), (1, 0), (1, 101)] {
        let lease = lease();
        let reads = lease.reads.clone();
        assert!(matches!(
            list_repositories(&upstream, lease, page, size).await,
            Err(RepositoryDiscoveryError::InvalidRequest)
        ));
        assert_eq!(reads.load(Ordering::SeqCst), 0);
    }
    for invalid in 0..4 {
        let mut lease = lease();
        match invalid {
            0 => lease.metadata.status = CredentialStatus::Revoked,
            1 => lease.metadata.authentication_kind = CredentialAuthKind::ApiKey,
            2 => lease.metadata.expires_at_unix = Some(1),
            _ => lease.metadata.provider = codewire_access::ProviderId::parse("openai").unwrap(),
        }
        let reads = lease.reads.clone();
        assert!(matches!(
            list_repositories(&upstream, lease, 1, 50).await,
            Err(RepositoryDiscoveryError::Denied)
        ));
        assert_eq!(reads.load(Ordering::SeqCst), 0);
    }
    assert_eq!(upstream.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn provider_errors_are_closed_and_their_bodies_are_never_polled() {
    for (status, expected) in [
        (StatusCode::UNAUTHORIZED, RepositoryDiscoveryError::Denied),
        (StatusCode::FORBIDDEN, RepositoryDiscoveryError::Denied),
        (
            StatusCode::TOO_MANY_REQUESTS,
            RepositoryDiscoveryError::RateLimited,
        ),
        (
            StatusCode::TEMPORARY_REDIRECT,
            RepositoryDiscoveryError::Unavailable,
        ),
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            RepositoryDiscoveryError::Unavailable,
        ),
    ] {
        let upstream = Upstream::new(status, b"unfiltered-private-provider-error".to_vec());
        assert!(
            matches!(list_repositories(&upstream, lease(), 1, 50).await, Err(actual) if actual == expected)
        );
        assert_eq!(upstream.polls.load(Ordering::SeqCst), 0);
    }
    let mut upstream = Upstream::new(
        StatusCode::FORBIDDEN,
        b"private-rate-limit-diagnostic".to_vec(),
    );
    upstream
        .headers
        .insert("x-ratelimit-remaining", HeaderValue::from_static("0"));
    assert!(matches!(
        list_repositories(&upstream, lease(), 1, 50).await,
        Err(RepositoryDiscoveryError::RateLimited)
    ));
    assert_eq!(upstream.polls.load(Ordering::SeqCst), 0);
}

#[test]
fn malformed_metadata_duplicates_aliases_and_oversized_pages_fail_closed() {
    let parse_repositories = |bytes: &[u8], size| {
        super::parse_repositories(bytes, size, &RedactionSet::new(std::iter::empty::<&[u8]>()))
    };
    for full_name in [
        "owner/../repo",
        "owner/repo%2fother",
        "owner/repo?token=secret",
        "-owner/repo",
        "owner--name/repo",
        "owner/.",
        "owner/..",
        "owner/",
    ] {
        let mut value = repository();
        value["full_name"] = json!(full_name);
        assert!(parse_repositories(&serde_json::to_vec(&json!([value])).unwrap(), 50).is_err());
    }
    for branch in [
        "-option".to_owned(),
        "main\nsecret".to_owned(),
        "x".repeat(513),
    ] {
        let mut value = repository();
        value["default_branch"] = json!(branch);
        assert!(parse_repositories(&serde_json::to_vec(&json!([value])).unwrap(), 50).is_err());
    }
    let duplicate = serde_json::to_vec(&json!([repository(), repository()])).unwrap();
    assert!(parse_repositories(&duplicate, 50).is_err());
    assert!(parse_repositories(&duplicate, 1).is_err());
    assert!(parse_repositories(br#"{"secret":"not-an-array"}"#, 50).is_err());
    assert!(parse_repositories(br#"[{"id":42,"id":43}]"#, 50).is_err());
    let empty = parse_repositories(b"[]", 50).unwrap();
    assert!(empty.repositories.is_empty() && !empty.has_more);
}

#[tokio::test]
async fn reflected_selected_material_is_filtered_before_metadata_decoding() {
    let mut value = repository();
    value["default_branch"] = json!(std::str::from_utf8(crate::http_test_support::TOKEN).unwrap());
    let upstream = Upstream::new(StatusCode::OK, serde_json::to_vec(&json!([value])).unwrap());
    let result = list_repositories(&upstream, lease(), 1, 50).await.unwrap();
    assert!(
        !result.repositories[0]
            .default_branch
            .as_bytes()
            .windows(crate::http_test_support::TOKEN.len())
            .any(|window| window == crate::http_test_support::TOKEN)
    );
}

#[tokio::test]
async fn json_escaped_selected_material_is_rejected_after_metadata_decoding() {
    let token = std::str::from_utf8(crate::http_test_support::TOKEN).unwrap();
    let full_escape = token
        .bytes()
        .map(|byte| format!("\\u{byte:04x}"))
        .collect::<String>();
    let mixed_escape = format!("\\u{:04x}{}", token.as_bytes()[0], &token[1..]);
    for escaped in [full_escape, mixed_escape] {
        for field in ["default_branch", "full_name"] {
            let mut value = repository();
            value[field] = json!(if field == "full_name" {
                "owner/SYNTHETIC_PLACEHOLDER"
            } else {
                "SYNTHETIC_PLACEHOLDER"
            });
            let body = serde_json::to_string(&json!([value]))
                .unwrap()
                .replace("SYNTHETIC_PLACEHOLDER", &escaped);
            let upstream = Upstream::new(StatusCode::OK, body.into_bytes());
            assert!(matches!(
                list_repositories(&upstream, lease(), 1, 50).await,
                Err(RepositoryDiscoveryError::InvalidResponse)
            ));
        }
    }
}

#[test]
fn all_reconstructed_text_is_checked_against_selected_material() {
    let body = serde_json::to_vec(&json!([repository()])).unwrap();
    for material in [b"42".as_slice(), b"https://github.com".as_slice()] {
        assert!(super::parse_repositories(&body, 50, &RedactionSet::new([material])).is_err());
    }
}

#[tokio::test]
async fn discovery_rejects_encoded_or_oversized_bodies_without_decoding_them() {
    let mut encoded = Upstream::new(StatusCode::OK, b"opaque-compressed-content".to_vec());
    encoded.headers.insert(
        http::header::CONTENT_ENCODING,
        HeaderValue::from_static("gzip"),
    );
    assert!(matches!(
        list_repositories(&encoded, lease(), 1, 50).await,
        Err(RepositoryDiscoveryError::InvalidResponse)
    ));
    assert_eq!(encoded.polls.load(Ordering::SeqCst), 0);
    let oversized = Upstream::new(StatusCode::OK, vec![b'x'; MAX_RESPONSE_BYTES + 1]);
    assert!(matches!(
        list_repositories(&oversized, lease(), 1, 50).await,
        Err(RepositoryDiscoveryError::InvalidResponse)
    ));
    assert_eq!(oversized.polls.load(Ordering::SeqCst), 1);
}
