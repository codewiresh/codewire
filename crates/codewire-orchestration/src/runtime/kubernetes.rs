//! The agent-sandbox driver: each method is one call on a [`SandboxClient`]
//! for the placement's namespace, which does no I/O to build.

use std::sync::Arc;

use async_trait::async_trait;

use super::{Placement, ProbeResult, RuntimeDriver, RuntimeLifecycle, RuntimePools};
use crate::sandbox::client::SandboxClient;

pub struct KubernetesDriver {
    client: kube::Client,
}

impl KubernetesDriver {
    pub fn shared(client: kube::Client) -> Arc<dyn RuntimeDriver> {
        Arc::new(Self { client })
    }

    fn sandbox_client(&self, placement: &Placement) -> SandboxClient {
        SandboxClient::new(self.client.clone(), &placement.namespace)
    }
}

#[async_trait]
impl RuntimePools for KubernetesDriver {
    async fn retire_legacy_shared_pools(&self, placement: &Placement) -> anyhow::Result<usize> {
        self.sandbox_client(placement)
            .retire_legacy_shared_warm_pools()
            .await
    }
}

#[async_trait]
impl RuntimeLifecycle for KubernetesDriver {
    async fn probe(
        &self,
        placement: &Placement,
        environment_id: &str,
    ) -> anyhow::Result<ProbeResult> {
        self.sandbox_client(placement)
            .probe_environment(environment_id)
            .await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, Response, StatusCode};
    use serde_json::json;

    use super::*;

    /// A driver over an API server that has nothing, and the requests it saw.
    fn driver_over_empty_cluster() -> (Arc<dyn RuntimeDriver>, Arc<Mutex<Vec<String>>>) {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = requests.clone();
        let service = Router::new().fallback(move |request: Request<Body>| {
            let seen = seen.clone();
            async move {
                let path = request.uri().path().to_string();
                seen.lock()
                    .unwrap()
                    .push(format!("{} {path}", request.method()));
                let (status, body) = if request.uri().query().is_some() {
                    let empty_list =
                        json!({"apiVersion": "v1", "kind": "List", "metadata": {}, "items": []});
                    (StatusCode::OK, empty_list)
                } else {
                    let not_found = json!({"apiVersion": "v1", "kind": "Status",
                        "status": "Failure", "reason": "NotFound", "code": 404});
                    (StatusCode::NOT_FOUND, not_found)
                };
                Response::builder()
                    .status(status)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap()
            }
        });
        let client = kube::Client::new(service, "the-default-namespace");
        (KubernetesDriver::shared(client), requests)
    }

    #[tokio::test]
    async fn probe_reads_the_placement_and_finds_nothing_in_one_request() {
        let (driver, requests) = driver_over_empty_cluster();

        let probe = driver
            .probe(&Placement::new("dev-sandboxes"), "env-1")
            .await
            .unwrap();

        assert!(!probe.claim_exists);
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 1, "{requests:?}");
        assert!(
            requests[0].starts_with("GET ")
                && requests[0].contains("/namespaces/dev-sandboxes/sandboxclaims/"),
            "{requests:?}"
        );
    }

    #[tokio::test]
    async fn retiring_reads_the_placement_and_stops_when_no_pool_is_left() {
        let (driver, requests) = driver_over_empty_cluster();

        let retired = driver
            .retire_legacy_shared_pools(&Placement::new("dev-sandboxes"))
            .await
            .unwrap();

        assert_eq!(retired, 0);
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 1, "{requests:?}");
        assert!(
            requests[0].starts_with("GET ")
                && requests[0].ends_with("/namespaces/dev-sandboxes/sandboxwarmpools"),
            "{requests:?}"
        );
    }
}
