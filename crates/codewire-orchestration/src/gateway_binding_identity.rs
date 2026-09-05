//! Kubernetes identity verification for the private gateway-binding service.
//!
//! A gateway authenticates with a short-lived, Pod-bound projected service
//! account token. The caller supplies no Pod coordinates: namespace, Pod name,
//! and Pod UID come exclusively from the exact-audience TokenReview response.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::http::HeaderMap;
use axum::http::header::AUTHORIZATION;
use codewire_gateway_proto::{GATEWAY_BINDING_SERVICE_ACCOUNT, GATEWAY_BINDING_TOKEN_AUDIENCE};
use k8s_openapi::api::authentication::v1::{TokenReview, TokenReviewSpec, TokenReviewStatus};
use kube::api::PostParams;
use kube::{Api, Client};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const MAX_BINDING_TOKEN_BYTES: usize = 16 * 1024;
const TOKEN_REVIEW_TIMEOUT: Duration = Duration::from_secs(5);
const POD_NAME_EXTRA: &str = "authentication.kubernetes.io/pod-name";
const POD_UID_EXTRA: &str = "authentication.kubernetes.io/pod-uid";
const SERVICE_ACCOUNT_USERNAME_PREFIX: &str = "system:serviceaccount:";

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

#[async_trait]
trait TokenReviewer: Send + Sync {
    async fn review(
        &self,
        request: &TokenReview,
    ) -> Result<TokenReview, GatewayBindingIdentityError>;
}

struct KubeTokenReviewer {
    token_reviews: Api<TokenReview>,
}

#[async_trait]
impl TokenReviewer for KubeTokenReviewer {
    async fn review(
        &self,
        request: &TokenReview,
    ) -> Result<TokenReview, GatewayBindingIdentityError> {
        self.token_reviews
            .create(&PostParams::default(), request)
            .await
            .map_err(|_| GatewayBindingIdentityError::Unavailable)
    }
}

pub(crate) struct KubernetesGatewayBindingAuthenticator {
    reviewer: Option<Arc<dyn TokenReviewer>>,
    timeout: Duration,
}

impl KubernetesGatewayBindingAuthenticator {
    pub(crate) fn new(client: Option<Client>) -> Self {
        let reviewer = client.map(|client| {
            Arc::new(KubeTokenReviewer {
                token_reviews: Api::all(client),
            }) as Arc<dyn TokenReviewer>
        });
        Self {
            reviewer,
            timeout: TOKEN_REVIEW_TIMEOUT,
        }
    }

    #[cfg(test)]
    fn new_for_test(reviewer: Arc<dyn TokenReviewer>) -> Self {
        Self {
            reviewer: Some(reviewer),
            timeout: TOKEN_REVIEW_TIMEOUT,
        }
    }
}

#[async_trait]
impl GatewayBindingAuthenticator for KubernetesGatewayBindingAuthenticator {
    async fn authenticate(
        &self,
        headers: &HeaderMap,
    ) -> Result<GatewayPodIdentity, GatewayBindingIdentityError> {
        let mut token = binding_bearer(headers)?;
        let reviewer = self
            .reviewer
            .as_ref()
            .ok_or(GatewayBindingIdentityError::Unavailable)?;
        let mut request = TokenReview {
            metadata: Default::default(),
            spec: TokenReviewSpec {
                audiences: Some(vec![GATEWAY_BINDING_TOKEN_AUDIENCE.to_owned()]),
                token: Some(std::mem::take(&mut *token)),
            },
            status: None,
        };
        let reviewed = tokio::time::timeout(self.timeout, reviewer.review(&request)).await;
        if let Some(token) = request.spec.token.as_mut() {
            token.zeroize();
        }
        let mut reviewed = reviewed.map_err(|_| GatewayBindingIdentityError::Unavailable)??;
        if let Some(token) = reviewed.spec.token.as_mut() {
            token.zeroize();
        }
        validated_identity(
            reviewed
                .status
                .take()
                .ok_or(GatewayBindingIdentityError::Unauthenticated)?,
        )
    }
}

fn binding_bearer(headers: &HeaderMap) -> Result<Zeroizing<String>, GatewayBindingIdentityError> {
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let value = values
        .next()
        .ok_or(GatewayBindingIdentityError::Unauthenticated)?;
    if values.next().is_some() {
        return Err(GatewayBindingIdentityError::Unauthenticated);
    }
    let value = value
        .to_str()
        .map_err(|_| GatewayBindingIdentityError::Unauthenticated)?;
    let token = value
        .strip_prefix("Bearer ")
        .ok_or(GatewayBindingIdentityError::Unauthenticated)?;
    if !valid_exact_value(token, MAX_BINDING_TOKEN_BYTES) {
        return Err(GatewayBindingIdentityError::Unauthenticated);
    }
    Ok(Zeroizing::new(token.to_owned()))
}

fn validated_identity(
    status: TokenReviewStatus,
) -> Result<GatewayPodIdentity, GatewayBindingIdentityError> {
    if status.authenticated != Some(true) || status.error.is_some() {
        return Err(GatewayBindingIdentityError::Unauthenticated);
    }
    if !matches!(
        status.audiences.as_deref(),
        Some([audience]) if audience == GATEWAY_BINDING_TOKEN_AUDIENCE
    ) {
        return Err(GatewayBindingIdentityError::Unauthenticated);
    }
    let user = status
        .user
        .ok_or(GatewayBindingIdentityError::Unauthenticated)?;
    let username = user
        .username
        .ok_or(GatewayBindingIdentityError::Unauthenticated)?;
    let service_account_suffix = format!(":{GATEWAY_BINDING_SERVICE_ACCOUNT}");
    let namespace = username
        .strip_prefix(SERVICE_ACCOUNT_USERNAME_PREFIX)
        .and_then(|value| value.strip_suffix(&service_account_suffix))
        .filter(|value| valid_exact_value(value, 63) && !value.contains(':'))
        .ok_or(GatewayBindingIdentityError::PermissionDenied)?;
    let extra = user
        .extra
        .ok_or(GatewayBindingIdentityError::PermissionDenied)?;
    let pod_name = singular_extra(&extra, POD_NAME_EXTRA, 253)?;
    let pod_uid = singular_extra(&extra, POD_UID_EXTRA, 128)?;

    Ok(GatewayPodIdentity {
        namespace: namespace.to_owned(),
        pod_name: pod_name.to_owned(),
        pod_uid: pod_uid.to_owned(),
    })
}

fn singular_extra<'a>(
    extra: &'a std::collections::BTreeMap<String, Vec<String>>,
    key: &str,
    max_len: usize,
) -> Result<&'a str, GatewayBindingIdentityError> {
    let values = extra
        .get(key)
        .ok_or(GatewayBindingIdentityError::PermissionDenied)?;
    let [value] = values.as_slice() else {
        return Err(GatewayBindingIdentityError::PermissionDenied);
    };
    if !valid_exact_value(value, max_len) {
        return Err(GatewayBindingIdentityError::PermissionDenied);
    }
    Ok(value)
}

fn valid_exact_value(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && value.is_ascii()
        && !value.chars().any(char::is_whitespace)
        && !value.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, VecDeque};
    use std::sync::Mutex;

    use axum::http::HeaderValue;
    use k8s_openapi::api::authentication::v1::UserInfo;

    use super::*;
    use crate::worker::gatewayauth::{SCOPE_COORDINATE, SCOPE_DAEMON, issue_token};

    struct FakeReviewer {
        requests: Mutex<Vec<TokenReviewSpec>>,
        responses: Mutex<VecDeque<Result<TokenReview, GatewayBindingIdentityError>>>,
    }

    impl FakeReviewer {
        fn with_status(status: TokenReviewStatus) -> Arc<Self> {
            Arc::new(Self {
                requests: Mutex::new(Vec::new()),
                responses: Mutex::new(VecDeque::from([Ok(TokenReview {
                    status: Some(status),
                    ..Default::default()
                })])),
            })
        }
    }

    #[async_trait]
    impl TokenReviewer for FakeReviewer {
        async fn review(
            &self,
            request: &TokenReview,
        ) -> Result<TokenReview, GatewayBindingIdentityError> {
            self.requests.lock().unwrap().push(request.spec.clone());
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(Err(GatewayBindingIdentityError::Unavailable))
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
                        POD_NAME_EXTRA.to_owned(),
                        vec!["cw-gateway-test".to_owned()],
                    ),
                    (
                        POD_UID_EXTRA.to_owned(),
                        vec!["7e7b20f6-0bd2-4f11-8b16-9c239851eb52".to_owned()],
                    ),
                ])),
                ..Default::default()
            }),
            ..Default::default()
        }
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
        let authenticator = KubernetesGatewayBindingAuthenticator::new_for_test(reviewer.clone());

        let identity = authenticator
            .authenticate(&authorization("synthetic.projected.token"))
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
        assert_eq!(
            requests[0].token.as_deref(),
            Some("synthetic.projected.token")
        );
    }

    #[tokio::test]
    async fn anonymous_and_noncanonical_bearers_never_reach_token_review() {
        let reviewer = FakeReviewer::with_status(valid_status());
        let authenticator = KubernetesGatewayBindingAuthenticator::new_for_test(reviewer.clone());

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
        let mut repeated = authorization("synthetic.projected.token");
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

    #[test]
    fn review_must_be_authenticated_for_the_exact_audience() {
        for mutate in [
            |status: &mut TokenReviewStatus| status.authenticated = Some(false),
            |status: &mut TokenReviewStatus| status.authenticated = None,
            |status: &mut TokenReviewStatus| status.audiences = None,
            |status: &mut TokenReviewStatus| {
                status.audiences = Some(vec!["https://kubernetes.default.svc".to_owned()])
            },
            |status: &mut TokenReviewStatus| status.error = Some("rejected".to_owned()),
        ] {
            let mut status = valid_status();
            mutate(&mut status);
            assert_eq!(
                validated_identity(status),
                Err(GatewayBindingIdentityError::Unauthenticated)
            );
        }
    }

    #[test]
    fn service_account_and_singular_pod_extras_are_mandatory() {
        let mut wrong_service_account = valid_status();
        wrong_service_account.user.as_mut().unwrap().username =
            Some("system:serviceaccount:test-namespace:some-other-service-account".to_owned());
        assert_eq!(
            validated_identity(wrong_service_account),
            Err(GatewayBindingIdentityError::PermissionDenied)
        );

        for key in [POD_NAME_EXTRA, POD_UID_EXTRA] {
            let mut missing = valid_status();
            missing
                .user
                .as_mut()
                .unwrap()
                .extra
                .as_mut()
                .unwrap()
                .remove(key);
            assert_eq!(
                validated_identity(missing),
                Err(GatewayBindingIdentityError::PermissionDenied)
            );

            let mut repeated = valid_status();
            repeated
                .user
                .as_mut()
                .unwrap()
                .extra
                .as_mut()
                .unwrap()
                .get_mut(key)
                .unwrap()
                .push("attacker-selected-value".to_owned());
            assert_eq!(
                validated_identity(repeated),
                Err(GatewayBindingIdentityError::PermissionDenied)
            );
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
        let reviewer = Arc::new(FakeReviewer {
            requests: Mutex::new(Vec::new()),
            responses: Mutex::new(VecDeque::from([
                Ok(TokenReview {
                    status: Some(TokenReviewStatus {
                        authenticated: Some(false),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                Ok(TokenReview {
                    status: Some(TokenReviewStatus {
                        authenticated: Some(false),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
            ])),
        });
        let authenticator = KubernetesGatewayBindingAuthenticator::new_for_test(reviewer.clone());

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
        let authenticator = KubernetesGatewayBindingAuthenticator::new(None);
        assert_eq!(
            authenticator
                .authenticate(&authorization("synthetic.projected.token"))
                .await,
            Err(GatewayBindingIdentityError::Unavailable)
        );

        let reviewer = Arc::new(FakeReviewer {
            requests: Mutex::new(Vec::new()),
            responses: Mutex::new(VecDeque::from([Err(
                GatewayBindingIdentityError::Unavailable,
            )])),
        });
        let authenticator = KubernetesGatewayBindingAuthenticator::new_for_test(reviewer);
        assert_eq!(
            authenticator
                .authenticate(&authorization("synthetic.projected.token"))
                .await,
            Err(GatewayBindingIdentityError::Unavailable)
        );
    }

    struct PendingReviewer;

    #[async_trait]
    impl TokenReviewer for PendingReviewer {
        async fn review(
            &self,
            _request: &TokenReview,
        ) -> Result<TokenReview, GatewayBindingIdentityError> {
            std::future::pending().await
        }
    }

    #[tokio::test]
    async fn token_review_is_bounded_by_a_fail_closed_timeout() {
        let mut authenticator =
            KubernetesGatewayBindingAuthenticator::new_for_test(Arc::new(PendingReviewer));
        authenticator.timeout = Duration::from_millis(1);

        assert_eq!(
            authenticator
                .authenticate(&authorization("synthetic.projected.token"))
                .await,
            Err(GatewayBindingIdentityError::Unavailable)
        );
    }
}
