//! The agent-sandbox driver: each method is one call on a [`SandboxClient`]
//! for the placement's namespace, which does no I/O to build, and reads what
//! comes back into the driver's own types.

pub(crate) mod members;
mod suspension;

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use super::{
    ClaimRef, MemberRef, Placement, ProbeResult, RuntimeAccess, RuntimeDriver, RuntimeLifecycle,
    RuntimeMember, RuntimePools, RuntimeTeardown, SuspendedRuntime,
};
use crate::sandbox::client::SandboxClient;
use crate::sandbox::host_keys::HostKeyStore;
use crate::sandbox::template::TemplateOpts;

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

    async fn list_members(&self, placement: &Placement) -> anyhow::Result<Vec<RuntimeMember>> {
        let sandboxes = self.sandbox_client(placement).list_sandboxes().await?;
        Ok(sandboxes.iter().map(members::runtime_member).collect())
    }

    async fn members(
        &self,
        placement: &Placement,
        environment_id: &str,
        known_member: &str,
    ) -> anyhow::Result<Vec<MemberRef>> {
        suspension::source_restart_pods(
            &self.sandbox_client(placement),
            environment_id,
            known_member,
        )
        .await
    }

    async fn suspend(&self, claim: &ClaimRef) -> anyhow::Result<()> {
        self.sandbox_client(&claim.placement)
            .suspend_workspace(&suspension::claim_opts(claim), &claim.name, &claim.uid)
            .await
    }

    async fn wait_suspended(
        &self,
        claim: &ClaimRef,
        known_member: &str,
        previous: &[MemberRef],
        timeout: Duration,
    ) -> anyhow::Result<SuspendedRuntime> {
        suspension::wait_for_workspace_suspension(
            &self.sandbox_client(&claim.placement),
            claim,
            known_member,
            previous,
            timeout,
        )
        .await
    }

    async fn reconcile_identity(&self, claim: &ClaimRef) -> anyhow::Result<()> {
        self.sandbox_client(&claim.placement)
            .reconcile_claim_runtime_identity(
                &suspension::claim_opts(claim),
                &claim.name,
                &claim.uid,
            )
            .await
    }

    async fn resume(
        &self,
        claim: &ClaimRef,
        suspended: &SuspendedRuntime,
        support_image: &str,
    ) -> anyhow::Result<()> {
        self.sandbox_client(&claim.placement)
            .set_replicas_for_identity(
                &suspension::claim_opts(claim),
                &claim.name,
                &claim.uid,
                suspended,
                1,
                support_image,
            )
            .await
    }

    async fn wait_ready(
        &self,
        placement: &Placement,
        environment_id: &str,
        timeout: Duration,
    ) -> anyhow::Result<()> {
        self.sandbox_client(placement)
            .wait_for_ready(environment_id, timeout)
            .await
    }

    async fn placement_exists(&self, placement: &Placement) -> anyhow::Result<bool> {
        self.sandbox_client(placement).namespace_exists().await
    }

    async fn tear_down(
        &self,
        placement: &Placement,
        teardown: &RuntimeTeardown<'_>,
    ) -> anyhow::Result<()> {
        self.sandbox_client(placement)
            .delete_environment_resources_with_recorded_storage(
                teardown.environment_id,
                teardown.known_member,
                teardown.per_environment_template,
                teardown.prove_confidential_storage_absent,
                teardown.recorded_volume_uid,
                teardown.timeout,
            )
            .await
    }
}

#[async_trait]
impl RuntimeAccess for KubernetesDriver {
    async fn ensure_access(
        &self,
        placement: &Placement,
        rendering: &TemplateOpts,
    ) -> anyhow::Result<()> {
        self.sandbox_client(placement)
            .ensure_access_stack(rendering)
            .await
    }

    async fn delete_access(
        &self,
        placement: &Placement,
        environment_id: &str,
    ) -> anyhow::Result<()> {
        self.sandbox_client(placement)
            .delete_access_stack(environment_id)
            .await
    }

    async fn wait_access_ready(
        &self,
        placement: &Placement,
        environment_id: &str,
        timeout: Duration,
        host_keys: &dyn HostKeyStore,
    ) -> anyhow::Result<()> {
        self.sandbox_client(placement)
            .wait_for_workspace_access_ready(environment_id, timeout, host_keys)
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
    async fn listing_members_reads_the_placement_in_one_request() {
        let (driver, requests) = driver_over_empty_cluster();

        let members = driver
            .list_members(&Placement::new("dev-sandboxes"))
            .await
            .unwrap();

        assert!(members.is_empty());
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 1, "{requests:?}");
        assert!(
            requests[0].starts_with("GET ")
                && requests[0].ends_with("/namespaces/dev-sandboxes/sandboxes"),
            "{requests:?}"
        );
    }

    #[tokio::test]
    async fn members_are_read_from_the_placement_with_the_known_member_rechecked() {
        let (driver, requests) = driver_over_empty_cluster();

        let members = driver
            .members(&Placement::new("dev-sandboxes"), "env-1", "known-pod")
            .await
            .unwrap();

        assert!(members.is_empty());
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 2, "{requests:?}");
        assert!(
            requests[0].ends_with("/namespaces/dev-sandboxes/pods")
                && requests[1].ends_with("/namespaces/dev-sandboxes/pods/known-pod"),
            "{requests:?}"
        );
    }

    #[tokio::test]
    async fn suspending_acts_only_on_the_claims_placement() {
        let (driver, requests) = driver_over_empty_cluster();
        let claim = ClaimRef {
            placement: Placement::new("dev-sandboxes"),
            environment_id: "env-1".into(),
            organization_id: "org-1".into(),
            operation_generation: 3,
            name: "claim-1".into(),
            uid: "claim-uid-1".into(),
        };

        // There is no claim to own, so it refuses after reading only.
        assert!(driver.suspend(&claim).await.is_err());

        let requests = requests.lock().unwrap();
        assert!(!requests.is_empty());
        for request in requests.iter() {
            assert!(
                request.starts_with("GET ") && request.contains("/namespaces/dev-sandboxes/"),
                "{requests:?}"
            );
        }
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
