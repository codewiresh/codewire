use std::collections::{BTreeMap, VecDeque};
use std::error::Error as _;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::http::HeaderValue;
use k8s_openapi::api::authentication::v1::UserInfo;
use tokio::sync::Notify;

use super::*;

const PURPOSES: [PodIdentityPurpose; 3] = [
    PodIdentityPurpose::GatewayBinding,
    PodIdentityPurpose::CredentialGateway,
    PodIdentityPurpose::CredentialWorkspace,
];
const CANARY: &str = "synthetic-sensitive-pod-token-canary";

struct FakeReviewer {
    requests: Mutex<Vec<TokenReviewSpec>>,
    replies: Mutex<VecDeque<Result<TokenReview, PodIdentityError>>>,
}

impl FakeReviewer {
    fn reply(reply: Result<TokenReview, PodIdentityError>) -> Arc<Self> {
        Arc::new(Self {
            requests: Mutex::new(Vec::new()),
            replies: Mutex::new(VecDeque::from([reply])),
        })
    }

    fn status(status: TokenReviewStatus) -> Arc<Self> {
        Self::reply(Ok(TokenReview {
            status: Some(status),
            ..Default::default()
        }))
    }
}

#[async_trait]
impl TokenReviewer for FakeReviewer {
    async fn review(&self, request: &TokenReview) -> Result<TokenReview, PodIdentityError> {
        self.requests.lock().unwrap().push(request.spec.clone());
        self.replies
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Err(PodIdentityError::Unavailable))
    }
}

fn status(purpose: PodIdentityPurpose) -> TokenReviewStatus {
    TokenReviewStatus {
        authenticated: Some(true),
        audiences: Some(vec![purpose.audience().into()]),
        user: Some(UserInfo {
            username: Some(format!(
                "system:serviceaccount:runtime:{}",
                purpose.service_account()
            )),
            extra: Some(BTreeMap::from([
                (POD_NAME_EXTRA.into(), vec!["workspace-pod".into()]),
                (
                    POD_UID_EXTRA.into(),
                    vec!["7e7b20f6-0bd2-4f11-8b16-9c239851eb52".into()],
                ),
            ])),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn token(payload: &str) -> String {
    format!(
        "{}.{}.{}",
        URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256"}"#),
        URL_SAFE_NO_PAD.encode(payload),
        URL_SAFE_NO_PAD.encode(CANARY)
    )
}

fn future_token() -> String {
    token(&format!(r#"{{"exp":{}}}"#, unix_now().unwrap() + 600))
}

fn headers(token: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
    );
    headers
}

#[tokio::test]
async fn fixed_purposes_are_pairwise_separated_and_record_exact_review_input() {
    let exp = unix_now().unwrap() + 600;
    let token = token(&format!(r#"{{"exp":{exp}}}"#));
    for purpose in PURPOSES {
        for reviewed_purpose in PURPOSES {
            let reviewer = FakeReviewer::status(status(reviewed_purpose));
            let verifier = KubernetesPodIdentityVerifier::for_test(reviewer.clone(), purpose);
            let result = verifier.authenticate(&headers(&token)).await;
            if purpose != reviewed_purpose {
                assert_eq!(result, Err(PodIdentityError::Unauthenticated));
            } else {
                let identity = result.unwrap();
                assert_eq!(identity.namespace(), "runtime");
                assert_eq!(identity.pod_name(), "workspace-pod");
                assert_eq!(identity.pod_uid(), "7e7b20f6-0bd2-4f11-8b16-9c239851eb52");
                assert_eq!(identity.purpose(), purpose);
                assert_eq!(identity.expires_at_unix(), exp);
                assert!(!format!("{identity:?}").contains(CANARY));
            }
            let requests = reviewer.requests.lock().unwrap();
            assert_eq!(requests.len(), 1);
            assert_eq!(
                requests[0].audiences.as_deref(),
                Some(&[purpose.audience().to_owned()][..])
            );
            assert_eq!(requests[0].token.as_deref(), Some(token.as_str()));
        }
    }
}

#[tokio::test]
async fn duplicate_noncanonical_and_oversize_bearers_never_reach_review() {
    let purpose = PodIdentityPurpose::CredentialWorkspace;
    let reviewer = FakeReviewer::status(status(purpose));
    let verifier = KubernetesPodIdentityVerifier::for_test(reviewer.clone(), purpose);
    let mut duplicate = headers(&future_token());
    duplicate.append(AUTHORIZATION, HeaderValue::from_static("Bearer second"));
    let mut basic = HeaderMap::new();
    basic.insert(AUTHORIZATION, HeaderValue::from_static("Basic synthetic"));
    for invalid in [
        HeaderMap::new(),
        headers(""),
        headers("two words"),
        headers("tab\there"),
        headers(&"a".repeat(MAX_TOKEN_BYTES + 1)),
        duplicate,
        basic,
    ] {
        assert_eq!(
            verifier.authenticate(&invalid).await,
            Err(PodIdentityError::Unauthenticated)
        );
    }
    assert!(reviewer.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn review_authentication_and_single_exact_audience_are_mandatory() {
    let purpose = PodIdentityPurpose::CredentialGateway;
    for mutate in [
        |s: &mut TokenReviewStatus| s.authenticated = None,
        |s: &mut TokenReviewStatus| s.authenticated = Some(false),
        |s: &mut TokenReviewStatus| s.audiences = None,
        |s: &mut TokenReviewStatus| s.audiences = Some(Vec::new()),
        |s: &mut TokenReviewStatus| {
            s.audiences = Some(vec![
                CREDENTIAL_GATEWAY_TOKEN_AUDIENCE.into(),
                CREDENTIAL_GATEWAY_TOKEN_AUDIENCE.into(),
            ])
        },
        |s: &mut TokenReviewStatus| s.error = Some(CANARY.into()),
        |s: &mut TokenReviewStatus| s.user = None,
        |s: &mut TokenReviewStatus| s.user.as_mut().unwrap().username = None,
    ] {
        let mut reviewed = status(purpose);
        mutate(&mut reviewed);
        let verifier =
            KubernetesPodIdentityVerifier::for_test(FakeReviewer::status(reviewed), purpose);
        assert_eq!(
            verifier.authenticate(&headers(&future_token())).await,
            Err(PodIdentityError::Unauthenticated)
        );
    }
}

#[tokio::test]
async fn service_account_and_pod_coordinates_cannot_be_selected_by_the_caller() {
    let purpose = PodIdentityPurpose::GatewayBinding;
    for username in [
        "system:serviceaccount:runtime:other",
        "system:serviceaccount::codewire-sandbox",
        "system:serviceaccount:bad:namespace:codewire-sandbox",
        "runtime:codewire-sandbox",
    ] {
        let mut reviewed = status(purpose);
        reviewed.user.as_mut().unwrap().username = Some(username.into());
        assert_eq!(
            KubernetesPodIdentityVerifier::for_test(FakeReviewer::status(reviewed), purpose)
                .authenticate(&headers(&future_token()))
                .await,
            Err(PodIdentityError::PermissionDenied)
        );
    }
    for key in [POD_NAME_EXTRA, POD_UID_EXTRA] {
        for values in [
            None,
            Some(vec![]),
            Some(vec!["one".into(), "two".into()]),
            Some(vec!["".into()]),
            Some(vec!["bad value".into()]),
            Some(vec!["a".repeat(254)]),
        ] {
            let mut reviewed = status(purpose);
            let extra = reviewed.user.as_mut().unwrap().extra.as_mut().unwrap();
            if let Some(values) = values {
                extra.insert(key.into(), values);
            } else {
                extra.remove(key);
            }
            assert_eq!(
                KubernetesPodIdentityVerifier::for_test(FakeReviewer::status(reviewed), purpose)
                    .authenticate(&headers(&future_token()))
                    .await,
                Err(PodIdentityError::PermissionDenied)
            );
        }
    }
}

#[tokio::test]
async fn only_the_exact_reviewed_request_supplies_expiry_not_echo_or_payload_coordinates() {
    let purpose = PodIdentityPurpose::CredentialWorkspace;
    let exp = unix_now().unwrap() + 300;
    let original = token(&format!(
        r#"{{"exp":{exp},"pod_name":"attacker","namespace":"attacker"}}"#
    ));
    let reviewer = FakeReviewer::reply(Ok(TokenReview {
        spec: TokenReviewSpec {
            token: Some(token(r#"{"exp":9999999999}"#)),
            audiences: None,
        },
        status: Some(status(purpose)),
        ..Default::default()
    }));
    let identity = KubernetesPodIdentityVerifier::for_test(reviewer, purpose)
        .authenticate(&headers(&original))
        .await
        .unwrap();
    assert_eq!(identity.expires_at_unix(), exp);
    assert_eq!(identity.namespace(), "runtime");
    assert_eq!(identity.pod_name(), "workspace-pod");
}

#[tokio::test]
async fn authenticated_review_still_requires_strict_future_original_expiry() {
    let purpose = PodIdentityPurpose::CredentialWorkspace;
    let now = unix_now().unwrap();
    for payload in [
        "{}".to_owned(),
        r#"{"exp":null}"#.into(),
        r#"{"exp":"9999999999"}"#.into(),
        r#"{"exp":true}"#.into(),
        r#"{"exp":1.5}"#.into(),
        r#"{"exp":-1}"#.into(),
        r#"{"exp":0}"#.into(),
        format!(r#"{{"exp":{now}}}"#),
        r#"{"exp":18446744073709551615}"#.into(),
        r#"{"exp":18446744073709551616}"#.into(),
        r#"{"exp":9999999999,"exp":9999999999}"#.into(),
        CANARY.into(),
    ] {
        let verifier =
            KubernetesPodIdentityVerifier::for_test(FakeReviewer::status(status(purpose)), purpose);
        assert_eq!(
            verifier.authenticate(&headers(&token(&payload))).await,
            Err(PodIdentityError::Unauthenticated)
        );
    }
}

#[tokio::test]
async fn padded_noncanonical_and_malformed_jwt_payloads_are_rejected() {
    let purpose = PodIdentityPurpose::CredentialGateway;
    let encoded = URL_SAFE_NO_PAD.encode(br#"{"exp":9999999999}"#);
    // Alter only unused final bits of an otherwise valid JSON payload. A lax
    // base64 decoder would yield the same bytes; the canonical decoder rejects it.
    let mut noncanonical = URL_SAFE_NO_PAD.encode(br#"{"exp":9999999999} "#);
    let last = noncanonical.pop().unwrap() as u8;
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let index = alphabet.iter().position(|value| *value == last).unwrap();
    noncanonical.push(char::from(alphabet[index + 1]));
    for invalid in [
        "opaque-codewire-oauth-bearer".to_owned(),
        "a.b".into(),
        "a.b.c.d".into(),
        ".e30.c2ln".into(),
        "e30..c2ln".into(),
        "e30.e30.".into(),
        format!("e30.{encoded}=.c2ln"),
        format!("e30.{noncanonical}.c2ln"),
        "e30._x.c2ln".into(),
        "e30.***.c2ln".into(),
    ] {
        let verifier =
            KubernetesPodIdentityVerifier::for_test(FakeReviewer::status(status(purpose)), purpose);
        assert_eq!(
            verifier.authenticate(&headers(&invalid)).await,
            Err(PodIdentityError::Unauthenticated)
        );
    }
}

#[tokio::test]
async fn unauthenticated_payload_never_supplies_identity_or_expiry() {
    let purpose = PodIdentityPurpose::CredentialWorkspace;
    let reviewer = FakeReviewer::reply(Err(PodIdentityError::Unavailable));
    let result = KubernetesPodIdentityVerifier::for_test(reviewer.clone(), purpose)
        .authenticate(&headers("malformed-but-bounded"))
        .await;
    assert_eq!(result, Err(PodIdentityError::Unavailable));
    assert_eq!(reviewer.requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn missing_client_status_and_review_failures_are_closed() {
    let purpose = PodIdentityPurpose::GatewayBinding;
    let token = future_token();
    assert_eq!(
        KubernetesPodIdentityVerifier::new(None, purpose)
            .authenticate(&headers(&token))
            .await,
        Err(PodIdentityError::Unavailable)
    );
    for (reply, expected) in [
        (
            Err(PodIdentityError::Unavailable),
            PodIdentityError::Unavailable,
        ),
        (
            Ok(TokenReview::default()),
            PodIdentityError::Unauthenticated,
        ),
    ] {
        assert_eq!(
            KubernetesPodIdentityVerifier::for_test(FakeReviewer::reply(reply), purpose)
                .authenticate(&headers(&token))
                .await,
            Err(expected)
        );
    }
}

#[derive(Default)]
struct PendingReviewer {
    entered: Notify,
    dropped: AtomicBool,
}

struct PendingReviewGuard<'a>(&'a AtomicBool);
impl Drop for PendingReviewGuard<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[async_trait]
impl TokenReviewer for PendingReviewer {
    async fn review(&self, _: &TokenReview) -> Result<TokenReview, PodIdentityError> {
        let _guard = PendingReviewGuard(&self.dropped);
        self.entered.notify_one();
        std::future::pending().await
    }
}

#[tokio::test]
async fn review_timeout_and_request_cancellation_leave_no_detached_review() {
    let reviewer = Arc::new(PendingReviewer::default());
    let mut verifier = KubernetesPodIdentityVerifier::for_test(
        reviewer.clone(),
        PodIdentityPurpose::GatewayBinding,
    );
    verifier.timeout = Duration::from_millis(1);
    assert_eq!(
        verifier.authenticate(&headers(&future_token())).await,
        Err(PodIdentityError::Unavailable)
    );
    assert!(reviewer.dropped.load(Ordering::SeqCst));
    let reviewer = Arc::new(PendingReviewer::default());
    let verifier = KubernetesPodIdentityVerifier::for_test(
        reviewer.clone(),
        PodIdentityPurpose::CredentialGateway,
    );
    let request =
        tokio::spawn(async move { verifier.authenticate(&headers(&future_token())).await });
    tokio::time::timeout(Duration::from_secs(1), reviewer.entered.notified())
        .await
        .unwrap();
    request.abort();
    assert!(
        tokio::time::timeout(Duration::from_secs(1), request)
            .await
            .unwrap()
            .unwrap_err()
            .is_cancelled()
    );
    assert!(reviewer.dropped.load(Ordering::SeqCst));
}

#[test]
fn expiry_boundary_is_checked_without_inventing_a_projection_lifetime() {
    let token = token(r#"{"exp":2000}"#);
    assert_eq!(reviewed_expiry(&token, 1), Ok(2000));
    assert_eq!(reviewed_expiry(&token, 1999), Ok(2000));
    assert_eq!(
        reviewed_expiry(&token, 2000),
        Err(PodIdentityError::Unauthenticated)
    );
    assert_eq!(
        reviewed_expiry(&token, 2001),
        Err(PodIdentityError::Unauthenticated)
    );
}

#[test]
fn token_review_owner_clears_request_and_echo_tokens() {
    for original in [CANARY.to_owned(), future_token()] {
        let mut owned = SensitiveReview(TokenReview {
            spec: TokenReviewSpec {
                token: Some(original),
                audiences: None,
            },
            ..Default::default()
        });
        // This same zeroization runs from Drop on every return and cancellation.
        owned.zeroize();
        assert_eq!(owned.0.spec.token.as_deref(), Some(""));
    }
}

#[test]
fn identity_errors_are_value_blind_and_have_no_source() {
    for error in [
        PodIdentityError::Unauthenticated,
        PodIdentityError::PermissionDenied,
        PodIdentityError::Unavailable,
    ] {
        assert!(error.source().is_none());
        assert!(!error.to_string().contains(CANARY));
        assert!(!format!("{error:?}").contains(CANARY));
    }
}
