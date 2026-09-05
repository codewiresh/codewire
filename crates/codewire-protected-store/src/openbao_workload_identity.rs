//! Short-lived Kubernetes identities for OpenBao Kubernetes auth.
//!
//! OpenBao's Dev auth mounts use the login JWT itself for TokenReview. The JWT
//! therefore needs both the exact OpenBao role audience and the Kubernetes API
//! audience. Kubernetes projected volumes can request only one audience, so
//! orchestration obtains the two-audience token from the TokenRequest API,
//! binds it to its current Pod, and keeps it only in zeroizing process memory.

use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use k8s_openapi::api::{
    authentication::v1::{BoundObjectReference, TokenRequest, TokenRequestSpec},
    core::v1::ServiceAccount,
};
use kube::{Api, Client, api::PostParams};
use thiserror::Error;
use zeroize::Zeroizing;

const TOKEN_EXPIRATION_SECONDS: i64 = 600;
const MINIMUM_USABLE_LIFETIME_SECONDS: i64 = 60;
const MAXIMUM_USABLE_LIFETIME_SECONDS: i64 = TOKEN_EXPIRATION_SECONDS + 60;
const TOKEN_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WorkloadIdentityError {
    #[error("invalid OpenBao workload identity configuration: {0}")]
    Configuration(&'static str),
    #[error("Kubernetes TokenRequest was unavailable")]
    RequestUnavailable,
    #[error("Kubernetes TokenRequest was rejected ({code})")]
    RequestRejected { code: u16 },
    #[error("Kubernetes TokenRequest returned an invalid response: {0}")]
    InvalidResponse(&'static str),
}

impl WorkloadIdentityError {
    pub fn failure_class(&self) -> &'static str {
        match self {
            Self::Configuration(_) => "openbao-workload-identity-invalid",
            Self::RequestUnavailable => "openbao-tokenrequest-unavailable",
            Self::RequestRejected { .. } => "openbao-tokenrequest-rejected",
            Self::InvalidResponse(_) => "openbao-tokenrequest-response-invalid",
        }
    }
}

#[async_trait]
pub trait OpenBaoWorkloadIdentity: Send + Sync {
    async fn token(&self) -> Result<Zeroizing<String>, WorkloadIdentityError>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct WorkloadIdentityConfig {
    namespace: String,
    service_account_name: String,
    pod_name: String,
    pod_uid: String,
    kubernetes_api_audience: String,
    openbao_audience: String,
}

impl WorkloadIdentityConfig {
    fn from_env(openbao_audience_env: &'static str) -> Result<Self, WorkloadIdentityError> {
        let required = |name: &'static str| {
            std::env::var(name)
                .ok()
                .filter(|value| valid_exact_value(value, 1024))
                .ok_or(WorkloadIdentityError::Configuration(name))
        };
        Self::new(
            required("POD_NAMESPACE")?,
            required("POD_SERVICE_ACCOUNT_NAME")?,
            required("POD_NAME")?,
            required("POD_UID")?,
            required("OPENBAO_KUBERNETES_API_AUDIENCE")?,
            required(openbao_audience_env)?,
        )
    }

    fn new(
        namespace: String,
        service_account_name: String,
        pod_name: String,
        pod_uid: String,
        kubernetes_api_audience: String,
        openbao_audience: String,
    ) -> Result<Self, WorkloadIdentityError> {
        for (name, value, max_len) in [
            ("POD_NAMESPACE", namespace.as_str(), 253),
            (
                "POD_SERVICE_ACCOUNT_NAME",
                service_account_name.as_str(),
                253,
            ),
            ("POD_NAME", pod_name.as_str(), 253),
            ("POD_UID", pod_uid.as_str(), 128),
            (
                "OPENBAO_KUBERNETES_API_AUDIENCE",
                kubernetes_api_audience.as_str(),
                1024,
            ),
            ("OpenBao audience", openbao_audience.as_str(), 1024),
        ] {
            if !valid_exact_value(value, max_len) {
                return Err(WorkloadIdentityError::Configuration(name));
            }
        }
        if kubernetes_api_audience == openbao_audience {
            return Err(WorkloadIdentityError::Configuration(
                "OpenBao and Kubernetes audiences must differ",
            ));
        }
        Ok(Self {
            namespace,
            service_account_name,
            pod_name,
            pod_uid,
            kubernetes_api_audience,
            openbao_audience,
        })
    }
}

fn valid_exact_value(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && !value.chars().any(char::is_whitespace)
        && !value.chars().any(char::is_control)
}

#[async_trait]
trait TokenRequester: Send + Sync {
    async fn request(
        &self,
        service_account_name: &str,
        request: &TokenRequest,
    ) -> Result<TokenRequest, WorkloadIdentityError>;
}

struct KubeTokenRequester {
    service_accounts: Api<ServiceAccount>,
}

fn map_token_request_error(error: kube::Error) -> WorkloadIdentityError {
    // Upstream Status text is not a redacted diagnostic contract. Retain only
    // the numeric code, never the reason, message, details, or source error.
    match error {
        kube::Error::Api(response) => WorkloadIdentityError::RequestRejected {
            code: response.code,
        },
        _ => WorkloadIdentityError::RequestUnavailable,
    }
}

#[async_trait]
impl TokenRequester for KubeTokenRequester {
    async fn request(
        &self,
        service_account_name: &str,
        request: &TokenRequest,
    ) -> Result<TokenRequest, WorkloadIdentityError> {
        self.service_accounts
            .create_token_request(service_account_name, &PostParams::default(), request)
            .await
            .map_err(map_token_request_error)
    }
}

pub struct KubernetesOpenBaoWorkloadIdentity {
    config: WorkloadIdentityConfig,
    requester: Arc<dyn TokenRequester>,
}

impl KubernetesOpenBaoWorkloadIdentity {
    pub fn from_env(
        client: Client,
        openbao_audience_env: &'static str,
    ) -> Result<Self, WorkloadIdentityError> {
        let config = WorkloadIdentityConfig::from_env(openbao_audience_env)?;
        let requester = Arc::new(KubeTokenRequester {
            service_accounts: Api::namespaced(client, &config.namespace),
        });
        Ok(Self { config, requester })
    }

    #[cfg(test)]
    fn new_for_test(config: WorkloadIdentityConfig, requester: Arc<dyn TokenRequester>) -> Self {
        Self { config, requester }
    }
}

#[async_trait]
impl OpenBaoWorkloadIdentity for KubernetesOpenBaoWorkloadIdentity {
    async fn token(&self) -> Result<Zeroizing<String>, WorkloadIdentityError> {
        let request = TokenRequest {
            metadata: Default::default(),
            spec: TokenRequestSpec {
                audiences: vec![
                    self.config.kubernetes_api_audience.clone(),
                    self.config.openbao_audience.clone(),
                ],
                bound_object_ref: Some(BoundObjectReference {
                    api_version: Some("v1".to_owned()),
                    kind: Some("Pod".to_owned()),
                    name: Some(self.config.pod_name.clone()),
                    uid: Some(self.config.pod_uid.clone()),
                }),
                expiration_seconds: Some(TOKEN_EXPIRATION_SECONDS),
            },
            status: None,
        };
        let response = tokio::time::timeout(
            TOKEN_REQUEST_TIMEOUT,
            self.requester
                .request(&self.config.service_account_name, &request),
        )
        .await
        .map_err(|_| WorkloadIdentityError::RequestUnavailable)??;
        let status = response
            .status
            .ok_or(WorkloadIdentityError::InvalidResponse("missing status"))?;
        let token = Zeroizing::new(status.token);
        if token.is_empty() || token.trim() != token.as_str() {
            return Err(WorkloadIdentityError::InvalidResponse("invalid token"));
        }
        let remaining = status
            .expiration_timestamp
            .0
            .duration_since(k8s_openapi::jiff::Timestamp::now())
            .as_secs();
        if !(MINIMUM_USABLE_LIFETIME_SECONDS..=MAXIMUM_USABLE_LIFETIME_SECONDS).contains(&remaining)
        {
            return Err(WorkloadIdentityError::InvalidResponse("invalid lifetime"));
        }
        Ok(token)
    }
}

#[cfg(any(test, feature = "platform-test-support"))]
pub fn static_workload_identity(token: &str) -> Arc<dyn OpenBaoWorkloadIdentity> {
    struct StaticIdentity(Zeroizing<String>);

    #[async_trait]
    impl OpenBaoWorkloadIdentity for StaticIdentity {
        async fn token(&self) -> Result<Zeroizing<String>, WorkloadIdentityError> {
            Ok(Zeroizing::new(self.0.to_string()))
        }
    }

    Arc::new(StaticIdentity(Zeroizing::new(token.to_owned())))
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, sync::Mutex};

    use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
    use k8s_openapi::jiff::{SignedDuration, Timestamp};

    use super::*;

    #[test]
    fn token_request_api_errors_discard_upstream_text() {
        let response = kube::core::Status::failure(
            "synthetic-sensitive-upstream-message",
            "synthetic-sensitive-upstream-reason\nforged-log-field=true",
        )
        .with_code(403);
        let error = map_token_request_error(kube::Error::Api(response.boxed()));

        assert!(matches!(
            error,
            WorkloadIdentityError::RequestRejected { code: 403, .. }
        ));
        assert_eq!(error.failure_class(), "openbao-tokenrequest-rejected");
        for rendered in [
            error.to_string(),
            format!("{error:?}"),
            format!("{error:#?}"),
        ] {
            assert!(!rendered.contains("synthetic-sensitive-upstream-message"));
            assert!(!rendered.contains("synthetic-sensitive-upstream-reason"));
            assert!(!rendered.contains("forged-log-field"));
        }
        assert_eq!(
            error.to_string(),
            "Kubernetes TokenRequest was rejected (403)"
        );
        assert_eq!(format!("{error:?}"), "RequestRejected { code: 403 }");
        assert!(std::error::Error::source(&error).is_none());
    }

    struct FakeRequester {
        requests: Mutex<Vec<(String, TokenRequest)>>,
        responses: Mutex<VecDeque<Result<TokenRequest, WorkloadIdentityError>>>,
    }

    impl FakeRequester {
        fn with_responses(responses: Vec<Result<TokenRequest, WorkloadIdentityError>>) -> Self {
            Self {
                requests: Mutex::new(Vec::new()),
                responses: Mutex::new(responses.into()),
            }
        }
    }

    #[async_trait]
    impl TokenRequester for FakeRequester {
        async fn request(
            &self,
            service_account_name: &str,
            request: &TokenRequest,
        ) -> Result<TokenRequest, WorkloadIdentityError> {
            self.requests
                .lock()
                .unwrap()
                .push((service_account_name.to_owned(), request.clone()));
            self.responses.lock().unwrap().pop_front().unwrap()
        }
    }

    fn config() -> WorkloadIdentityConfig {
        WorkloadIdentityConfig::new(
            "dev".to_owned(),
            "codewire-orchestration".to_owned(),
            "codewire-orchestration-abc".to_owned(),
            "6c2c791e-f0ad-49db-b754-bb7d25b12989".to_owned(),
            "https://10.60.0.100:6443".to_owned(),
            "openbao-codewire-tenant-dev-cluster".to_owned(),
        )
        .unwrap()
    }

    fn response(token: &str, expires_in_seconds: i64) -> TokenRequest {
        TokenRequest {
            metadata: Default::default(),
            spec: TokenRequestSpec::default(),
            status: Some(k8s_openapi::api::authentication::v1::TokenRequestStatus {
                expiration_timestamp: Time(
                    Timestamp::now()
                        .checked_add(SignedDuration::from_secs(expires_in_seconds))
                        .unwrap(),
                ),
                token: token.to_owned(),
            }),
        }
    }

    #[tokio::test]
    async fn requests_exact_dual_audience_pod_bound_identity_without_caching_jwt() {
        let requester = Arc::new(FakeRequester::with_responses(vec![
            Ok(response("jwt-one", 600)),
            Ok(response("jwt-two", 600)),
        ]));
        let identity = KubernetesOpenBaoWorkloadIdentity::new_for_test(config(), requester.clone());

        assert_eq!(identity.token().await.unwrap().as_str(), "jwt-one");
        assert_eq!(identity.token().await.unwrap().as_str(), "jwt-two");

        let requests = requester.requests.lock().unwrap();
        assert_eq!(requests.len(), 2, "workload JWTs must not be retained");
        let (service_account, request) = &requests[0];
        assert_eq!(service_account, "codewire-orchestration");
        assert_eq!(
            request.spec.audiences,
            [
                "https://10.60.0.100:6443",
                "openbao-codewire-tenant-dev-cluster"
            ]
        );
        assert_eq!(request.spec.expiration_seconds, Some(600));
        assert_eq!(
            request.spec.bound_object_ref,
            Some(BoundObjectReference {
                api_version: Some("v1".to_owned()),
                kind: Some("Pod".to_owned()),
                name: Some("codewire-orchestration-abc".to_owned()),
                uid: Some("6c2c791e-f0ad-49db-b754-bb7d25b12989".to_owned()),
            })
        );
    }

    #[tokio::test]
    async fn rejects_missing_invalid_or_out_of_range_responses() {
        let missing = TokenRequest {
            metadata: Default::default(),
            spec: TokenRequestSpec::default(),
            status: None,
        };
        let requester = Arc::new(FakeRequester::with_responses(vec![
            Ok(missing),
            Ok(response("", 600)),
            Ok(response("short", 30)),
            Ok(response("long", 3600)),
        ]));
        let identity = KubernetesOpenBaoWorkloadIdentity::new_for_test(config(), requester);

        assert_eq!(
            identity.token().await.unwrap_err(),
            WorkloadIdentityError::InvalidResponse("missing status")
        );
        assert_eq!(
            identity.token().await.unwrap_err(),
            WorkloadIdentityError::InvalidResponse("invalid token")
        );
        assert_eq!(
            identity.token().await.unwrap_err(),
            WorkloadIdentityError::InvalidResponse("invalid lifetime")
        );
        assert_eq!(
            identity.token().await.unwrap_err(),
            WorkloadIdentityError::InvalidResponse("invalid lifetime")
        );
    }

    #[test]
    fn rejects_ambiguous_or_non_exact_configuration() {
        let mut same_audience = config();
        same_audience.openbao_audience = same_audience.kubernetes_api_audience.clone();
        assert!(matches!(
            WorkloadIdentityConfig::new(
                same_audience.namespace,
                same_audience.service_account_name,
                same_audience.pod_name,
                same_audience.pod_uid,
                same_audience.kubernetes_api_audience,
                same_audience.openbao_audience,
            ),
            Err(WorkloadIdentityError::Configuration(_))
        ));
        assert!(!valid_exact_value(" audience", 1024));
        assert!(!valid_exact_value("audience\n", 1024));
    }
}
