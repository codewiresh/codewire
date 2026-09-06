//! Fixed-purpose gateway-binding consumer of shared projected Pod identity.
//!
//! The shared verifier owns TokenReview, exact-purpose and expiry validation.
//! This module adapts only the non-secret coordinates required by the existing
//! binding service; that service still checks live Pod and environment state.

use async_trait::async_trait;
use axum::http::HeaderMap;
use codewire_server_core::pod_identity::{
    KubernetesPodIdentityVerifier, PodIdentityError, PodIdentityPurpose,
};
use kube::Client;
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GatewayPodIdentity {
    namespace: String,
    pod_name: String,
    pod_uid: String,
}

impl GatewayPodIdentity {
    pub(crate) fn namespace(&self) -> &str {
        &self.namespace
    }
    pub(crate) fn pod_name(&self) -> &str {
        &self.pod_name
    }
    pub(crate) fn pod_uid(&self) -> &str {
        &self.pod_uid
    }

    #[cfg(test)]
    pub(crate) fn for_test(namespace: &str, pod_name: &str, pod_uid: &str) -> Self {
        Self {
            namespace: namespace.to_owned(),
            pod_name: pod_name.to_owned(),
            pod_uid: pod_uid.to_owned(),
        }
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub(crate) enum GatewayBindingIdentityError {
    #[error("gateway binding identity was not authenticated")]
    Unauthenticated,
    #[error("gateway binding identity is not permitted")]
    PermissionDenied,
    #[error("Kubernetes TokenReview is unavailable")]
    Unavailable,
}

#[async_trait]
pub(crate) trait GatewayBindingAuthenticator: Send + Sync {
    async fn authenticate(
        &self,
        headers: &HeaderMap,
    ) -> Result<GatewayPodIdentity, GatewayBindingIdentityError>;
}

pub(crate) struct KubernetesGatewayBindingAuthenticator {
    verifier: KubernetesPodIdentityVerifier,
}

impl KubernetesGatewayBindingAuthenticator {
    pub(crate) fn new(client: Option<Client>) -> Self {
        Self {
            verifier: KubernetesPodIdentityVerifier::new(
                client,
                PodIdentityPurpose::GatewayBinding,
            ),
        }
    }
}

#[async_trait]
impl GatewayBindingAuthenticator for KubernetesGatewayBindingAuthenticator {
    async fn authenticate(
        &self,
        headers: &HeaderMap,
    ) -> Result<GatewayPodIdentity, GatewayBindingIdentityError> {
        let identity = self
            .verifier
            .authenticate(headers)
            .await
            .map_err(|error| match error {
                PodIdentityError::Unauthenticated => GatewayBindingIdentityError::Unauthenticated,
                PodIdentityError::PermissionDenied => GatewayBindingIdentityError::PermissionDenied,
                PodIdentityError::Unavailable => GatewayBindingIdentityError::Unavailable,
            })?;
        Ok(GatewayPodIdentity {
            namespace: identity.namespace().to_owned(),
            pod_name: identity.pod_name().to_owned(),
            pod_uid: identity.pod_uid().to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, VecDeque};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use axum::body::Body;
    use axum::http::{HeaderValue, Request, Response, StatusCode, header::AUTHORIZATION};
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use codewire_gateway_proto::{
        CREDENTIAL_GATEWAY_TOKEN_AUDIENCE, CREDENTIAL_WORKSPACE_TOKEN_AUDIENCE,
        GATEWAY_BINDING_SERVICE_ACCOUNT, GATEWAY_BINDING_TOKEN_AUDIENCE,
    };
    use k8s_openapi::api::authentication::v1::{
        TokenReview, TokenReviewSpec, TokenReviewStatus, UserInfo,
    };
    use tower::service_fn;

    use super::*;
    use crate::worker::gatewayauth::{SCOPE_COORDINATE, SCOPE_DAEMON, issue_token};

    // An in-process Kubernetes HTTP service, not a socket or replacement
    // authenticator: fixtures enter through the normal production kube client.
    struct FakeReviewer {
        requests: Mutex<Vec<TokenReviewSpec>>,
        responses: Mutex<VecDeque<Option<TokenReviewStatus>>>,
        pending: bool,
    }

    impl FakeReviewer {
        fn with_status(status: TokenReviewStatus) -> Arc<Self> {
            Arc::new(Self {
                requests: Mutex::new(Vec::new()),
                responses: Mutex::new(VecDeque::from([Some(status)])),
                pending: false,
            })
        }

        fn client(self: &Arc<Self>) -> Client {
            let reviewer = self.clone();
            let service = service_fn(move |request: Request<kube::client::Body>| {
                let reviewer = reviewer.clone();
                async move {
                    assert_eq!(request.method(), "POST");
                    assert_eq!(
                        request.uri().path(),
                        "/apis/authentication.k8s.io/v1/tokenreviews"
                    );
                    let bytes = request
                        .into_body()
                        .collect_bytes()
                        .await
                        .expect("synthetic request body");
                    let review: TokenReview =
                        serde_json::from_slice(&bytes).expect("synthetic TokenReview");
                    reviewer.requests.lock().unwrap().push(review.spec);
                    if reviewer.pending {
                        std::future::pending::<()>().await;
                    }
                    let status = reviewer.responses.lock().unwrap().pop_front().flatten();
                    let (code, body) = match status {
                        Some(status) => (StatusCode::CREATED, serde_json::to_vec(&TokenReview {
                            status: Some(status), ..Default::default()
                        }).unwrap()),
                        None => (StatusCode::SERVICE_UNAVAILABLE, br#"{"apiVersion":"v1","kind":"Status","status":"Failure","message":"synthetic opaque upstream canary","reason":"Unavailable","code":503}"#.to_vec()),
                    };
                    Ok::<_, std::convert::Infallible>(
                        Response::builder()
                            .status(code)
                            .header("content-type", "application/json")
                            .body(Body::from(body))
                            .unwrap(),
                    )
                }
            });
            Client::new(service, "test-namespace")
        }

        fn authenticator(self: &Arc<Self>) -> KubernetesGatewayBindingAuthenticator {
            KubernetesGatewayBindingAuthenticator::new(Some(self.client()))
        }
    }

    fn valid_status() -> TokenReviewStatus {
        TokenReviewStatus {
            authenticated: Some(true),
            audiences: Some(vec![GATEWAY_BINDING_TOKEN_AUDIENCE.to_owned()]),
            user: Some(UserInfo {
                username: Some(format!(
                    "system:serviceaccount:test-namespace:{GATEWAY_BINDING_SERVICE_ACCOUNT}"
                )),
                extra: Some(BTreeMap::from([
                    (
                        "authentication.kubernetes.io/pod-name".to_owned(),
                        vec!["cw-gateway-test".to_owned()],
                    ),
                    (
                        "authentication.kubernetes.io/pod-uid".to_owned(),
                        vec!["7e7b20f6-0bd2-4f11-8b16-9c239851eb52".to_owned()],
                    ),
                ])),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn token() -> String {
        let exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 600;
        format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256"}"#),
            URL_SAFE_NO_PAD.encode(format!(r#"{{"exp":{exp}}}"#)),
            URL_SAFE_NO_PAD.encode(b"synthetic-signature")
        )
    }

    fn authorization(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        headers
    }

    #[tokio::test]
    async fn exact_audience_review_derives_the_only_pod_identity() {
        let reviewer = FakeReviewer::with_status(valid_status());
        let token = token();
        let identity = reviewer
            .authenticator()
            .authenticate(&authorization(&token))
            .await
            .unwrap();
        assert_eq!(identity.namespace, "test-namespace");
        assert_eq!(identity.pod_name, "cw-gateway-test");
        assert_eq!(identity.pod_uid, "7e7b20f6-0bd2-4f11-8b16-9c239851eb52");
        let requests = reviewer.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].audiences.as_deref(),
            Some(&[GATEWAY_BINDING_TOKEN_AUDIENCE.to_owned()][..])
        );
        assert_eq!(requests[0].token.as_deref(), Some(token.as_str()));
    }

    #[tokio::test]
    async fn anonymous_and_noncanonical_bearers_never_reach_token_review() {
        let reviewer = FakeReviewer::with_status(valid_status());
        let authenticator = reviewer.authenticator();
        for headers in [
            HeaderMap::new(),
            authorization(""),
            authorization("two words"),
        ] {
            assert_eq!(
                authenticator.authenticate(&headers).await,
                Err(GatewayBindingIdentityError::Unauthenticated)
            );
        }
        let mut wrong_scheme = HeaderMap::new();
        wrong_scheme.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Basic synthetic.projected.token"),
        );
        assert_eq!(
            authenticator.authenticate(&wrong_scheme).await,
            Err(GatewayBindingIdentityError::Unauthenticated)
        );
        let mut repeated = authorization(&token());
        repeated.append(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer second.projected.token"),
        );
        assert_eq!(
            authenticator.authenticate(&repeated).await,
            Err(GatewayBindingIdentityError::Unauthenticated)
        );
        assert!(reviewer.requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn review_must_be_authenticated_for_the_exact_audience() {
        for mutate in [
            |status: &mut TokenReviewStatus| status.authenticated = Some(false),
            |status: &mut TokenReviewStatus| status.authenticated = None,
            |status: &mut TokenReviewStatus| status.audiences = None,
            |status: &mut TokenReviewStatus| {
                status.audiences = Some(vec!["https://kubernetes.default.svc".into()])
            },
            |status: &mut TokenReviewStatus| status.error = Some("rejected".into()),
            |status: &mut TokenReviewStatus| {
                status.audiences = Some(vec![CREDENTIAL_GATEWAY_TOKEN_AUDIENCE.into()])
            },
            |status: &mut TokenReviewStatus| {
                status.audiences = Some(vec![CREDENTIAL_WORKSPACE_TOKEN_AUDIENCE.into()])
            },
        ] {
            let mut status = valid_status();
            mutate(&mut status);
            assert_eq!(
                FakeReviewer::with_status(status)
                    .authenticator()
                    .authenticate(&authorization(&token()))
                    .await,
                Err(GatewayBindingIdentityError::Unauthenticated)
            );
        }
    }

    #[tokio::test]
    async fn service_account_and_singular_pod_extras_are_mandatory() {
        let mut wrong = valid_status();
        wrong.user.as_mut().unwrap().username =
            Some("system:serviceaccount:test-namespace:other".into());
        assert_eq!(
            FakeReviewer::with_status(wrong)
                .authenticator()
                .authenticate(&authorization(&token()))
                .await,
            Err(GatewayBindingIdentityError::PermissionDenied)
        );
        for key in [
            "authentication.kubernetes.io/pod-name",
            "authentication.kubernetes.io/pod-uid",
        ] {
            for duplicate in [false, true] {
                let mut status = valid_status();
                let extra = status.user.as_mut().unwrap().extra.as_mut().unwrap();
                if duplicate {
                    extra
                        .get_mut(key)
                        .unwrap()
                        .push("attacker-selected-value".into());
                } else {
                    extra.remove(key);
                }
                assert_eq!(
                    FakeReviewer::with_status(status)
                        .authenticator()
                        .authenticate(&authorization(&token()))
                        .await,
                    Err(GatewayBindingIdentityError::PermissionDenied)
                );
            }
        }
    }

    #[tokio::test]
    async fn codewire_environment_capabilities_have_no_binding_fallback() {
        let coordinate = issue_token(
            "synthetic-session-secret",
            "550e8400-e29b-41d4-a716-446655440000",
            SCOPE_COORDINATE,
        )
        .unwrap();
        let daemon = issue_token(
            "synthetic-session-secret",
            "550e8400-e29b-41d4-a716-446655440000",
            SCOPE_DAEMON,
        )
        .unwrap();
        let reviewer = FakeReviewer::with_status(TokenReviewStatus {
            authenticated: Some(false),
            ..Default::default()
        });
        reviewer
            .responses
            .lock()
            .unwrap()
            .push_back(Some(TokenReviewStatus {
                authenticated: Some(false),
                ..Default::default()
            }));
        let authenticator = reviewer.authenticator();
        for token in [&coordinate, &daemon] {
            assert_eq!(
                authenticator.authenticate(&authorization(token)).await,
                Err(GatewayBindingIdentityError::Unauthenticated)
            );
        }
        let requests = reviewer.requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].token.as_deref(), Some(coordinate.as_str()));
        assert_eq!(requests[1].token.as_deref(), Some(daemon.as_str()));
    }

    #[tokio::test]
    async fn absent_kubernetes_client_and_review_errors_fail_closed() {
        assert_eq!(
            KubernetesGatewayBindingAuthenticator::new(None)
                .authenticate(&authorization(&token()))
                .await,
            Err(GatewayBindingIdentityError::Unavailable)
        );
        let reviewer = FakeReviewer::with_status(valid_status());
        reviewer.responses.lock().unwrap().clear();
        assert_eq!(
            reviewer
                .authenticator()
                .authenticate(&authorization(&token()))
                .await,
            Err(GatewayBindingIdentityError::Unavailable)
        );
    }

    #[tokio::test]
    async fn token_review_is_bounded_by_a_fail_closed_timeout() {
        let reviewer = Arc::new(FakeReviewer {
            requests: Mutex::new(Vec::new()),
            responses: Mutex::new(VecDeque::new()),
            pending: true,
        });
        let result = tokio::time::timeout(
            Duration::from_secs(7),
            reviewer
                .authenticator()
                .authenticate(&authorization(&token())),
        )
        .await
        .expect("shared five-second review budget");
        assert_eq!(result, Err(GatewayBindingIdentityError::Unavailable));
    }

    #[tokio::test]
    async fn authenticated_review_without_valid_original_expiry_is_rejected() {
        for original in [
            "synthetic.projected.token".to_owned(),
            format!("e30.{}.c2ln", URL_SAFE_NO_PAD.encode(br#"{"exp":0}"#)),
            format!(
                "e30.{}.c2ln",
                URL_SAFE_NO_PAD.encode(br#"{"exp":"9999999999"}"#)
            ),
        ] {
            assert_eq!(
                FakeReviewer::with_status(valid_status())
                    .authenticator()
                    .authenticate(&authorization(&original))
                    .await,
                Err(GatewayBindingIdentityError::Unauthenticated)
            );
        }
    }
}
