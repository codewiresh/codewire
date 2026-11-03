//! The agent-sandbox driver: each method is one call on a [`SandboxClient`]
//! for the placement's namespace, which does no I/O to build, and reads what
//! comes back into the driver's own types.

pub(crate) mod members;
mod suspension;

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use super::{
    ClaimReadiness, ClaimRef, MemberRef, Placement, ProbeResult, RuntimeAccess, RuntimeDriver,
    RuntimeLifecycle, RuntimeMember, RuntimePools, RuntimeStream, RuntimeTeardown,
    SuspendedRuntime,
};
use crate::sandbox::client::SandboxClient;
use crate::sandbox::host_keys::HostKeyStore;
use crate::sandbox::sidecar::WORKSPACE_SSH_PORT;
use crate::sandbox::template::TemplateOpts;

const WORKSPACE_DAEMON_PORT: u16 = crate::sandbox::template::WORKSPACE_DAEMON_PORT as u16;

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

    async fn claim_readiness(
        &self,
        placement: &Placement,
        environment_id: &str,
    ) -> anyhow::Result<ClaimReadiness> {
        let (exists, ready, reason) = self
            .sandbox_client(placement)
            .get_sandbox_claim_ready_status(environment_id)
            .await?;
        Ok(match (exists, ready) {
            (false, _) => ClaimReadiness::Absent,
            (true, true) => ClaimReadiness::Ready,
            (true, false) => ClaimReadiness::NotReady { reason },
        })
    }

    async fn ssh_stream(
        &self,
        placement: &Placement,
        environment_id: &str,
    ) -> anyhow::Result<RuntimeStream> {
        self.sandbox_client(placement)
            .workspace_ssh_stream(environment_id, WORKSPACE_SSH_PORT)
            .await
    }

    async fn daemon_stream(
        &self,
        placement: &Placement,
        environment_id: &str,
    ) -> anyhow::Result<RuntimeStream> {
        self.sandbox_client(placement)
            .port_forward_stream(environment_id, WORKSPACE_DAEMON_PORT)
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

    /// A driver over an API server that has this one claim.
    fn driver_with_claim(status: serde_json::Value) -> Arc<dyn RuntimeDriver> {
        let service = Router::new().fallback(move |_: Request<Body>| {
            let status = status.clone();
            async move {
                let claim = json!({
                    "apiVersion": "extensions.agents.x-k8s.io/v1alpha1",
                    "kind": "SandboxClaim",
                    "metadata": {"name": "sandbox-env-1", "namespace": "dev-sandboxes"},
                    "status": status,
                });
                Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "application/json")
                    .body(Body::from(claim.to_string()))
                    .unwrap()
            }
        });
        KubernetesDriver::shared(kube::Client::new(service, "the-default-namespace"))
    }

    #[tokio::test]
    async fn a_missing_claim_is_absent_after_one_read_of_the_placement() {
        let (driver, requests) = driver_over_empty_cluster();

        let readiness = driver
            .claim_readiness(&Placement::new("dev-sandboxes"), "env-1")
            .await
            .unwrap();

        assert_eq!(readiness, ClaimReadiness::Absent);
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 1, "{requests:?}");
        assert!(
            requests[0].starts_with("GET ")
                && requests[0].ends_with("/namespaces/dev-sandboxes/sandboxclaims/sandbox-env-1"),
            "{requests:?}"
        );
    }

    #[tokio::test]
    async fn a_claims_ready_condition_decides_its_readiness() {
        let readiness = |condition| async move {
            driver_with_claim(json!({"conditions": [condition]}))
                .claim_readiness(&Placement::new("dev-sandboxes"), "env-1")
                .await
                .unwrap()
        };

        assert_eq!(
            readiness(json!({"type": "Ready", "status": "True", "reason": "Bound"})).await,
            ClaimReadiness::Ready
        );
        assert_eq!(
            readiness(json!({"type": "Ready", "status": "False", "reason": "PodPending"})).await,
            ClaimReadiness::NotReady {
                reason: "PodPending".into()
            }
        );
    }

    #[tokio::test]
    async fn streams_refuse_an_environment_with_no_claim_and_only_read_the_placement() {
        let (driver, requests) = driver_over_empty_cluster();
        let placement = Placement::new("dev-sandboxes");

        assert!(driver.ssh_stream(&placement, "env-1").await.is_err());
        assert!(driver.daemon_stream(&placement, "env-1").await.is_err());

        let requests = requests.lock().unwrap();
        assert!(!requests.is_empty());
        for request in requests.iter() {
            assert!(
                request.starts_with("GET ") && request.contains("/namespaces/dev-sandboxes/"),
                "{requests:?}"
            );
        }
    }

    /// A driver over a bound environment whose Pod has no address, so a stream
    /// falls through to a port-forward, whose request is recorded with its
    /// ports. `controller_uid` is the Sandbox the Pod says controls it.
    fn driver_over_addressless_pod(
        controller_uid: &str,
    ) -> (Arc<dyn RuntimeDriver>, Arc<Mutex<Vec<String>>>) {
        let namespace = "/namespaces/dev-sandboxes";
        let objects = [
            (
                format!(
                    "/apis/extensions.agents.x-k8s.io/v1beta1{namespace}/sandboxclaims/sandbox-env-1"
                ),
                json!({"apiVersion": "extensions.agents.x-k8s.io/v1beta1", "kind": "SandboxClaim",
                    "metadata": {"name": "sandbox-env-1", "namespace": "dev-sandboxes",
                        "uid": "c0ffee00-e29b-41d4-a716-446655440000"},
                    "status": {"sandbox": {"name": "sandbox-a"}}}),
            ),
            (
                format!("/apis/agents.x-k8s.io/v1beta1{namespace}/sandboxes/sandbox-a"),
                json!({"apiVersion": "agents.x-k8s.io/v1beta1", "kind": "Sandbox",
                    "metadata": {"name": "sandbox-a", "namespace": "dev-sandboxes",
                        "uid": "1f4e3a52-8d2b-4c7e-9a60-5b1d2e3f4a5b",
                        "annotations": {"agents.x-k8s.io/pod-name": "workspace-a"}}}),
            ),
            (
                format!("/api/v1{namespace}/pods/workspace-a"),
                json!({"apiVersion": "v1", "kind": "Pod",
                    "metadata": {"name": "workspace-a", "namespace": "dev-sandboxes",
                        "uid": "7e7b20f6-0bd2-4f11-8b16-9c23d4e5f607",
                        "ownerReferences": [{"apiVersion": "agents.x-k8s.io/v1beta1",
                            "kind": "Sandbox", "name": "sandbox-a", "uid": controller_uid,
                            "controller": true}]},
                    "status": {"phase": "Running"}}),
            ),
        ];
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = requests.clone();
        let service = Router::new().fallback(move |request: Request<Body>| {
            let seen = seen.clone();
            let objects = objects.clone();
            async move {
                seen.lock().unwrap().push(request.uri().to_string());
                let path = request.uri().path();
                let (status, body) = objects.iter().find(|(known, _)| known == path).map_or(
                    (
                        StatusCode::NOT_FOUND,
                        json!({"apiVersion": "v1", "kind": "Status", "status": "Failure",
                            "reason": "NotFound", "code": 404}),
                    ),
                    |(_, object)| (StatusCode::OK, object.clone()),
                );
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

    const CONTROLLING_SANDBOX: &str = "1f4e3a52-8d2b-4c7e-9a60-5b1d2e3f4a5b";

    fn port_forwards(requests: &Mutex<Vec<String>>) -> Vec<String> {
        requests
            .lock()
            .unwrap()
            .iter()
            .filter(|request| request.contains("/portforward"))
            .cloned()
            .collect()
    }

    #[tokio::test]
    async fn the_ssh_and_daemon_streams_each_reach_their_own_port() {
        let placement = Placement::new("dev-sandboxes");

        let (driver, requests) = driver_over_addressless_pod(CONTROLLING_SANDBOX);
        // The stub can't upgrade the connection, so the stream itself fails.
        assert!(driver.ssh_stream(&placement, "env-1").await.is_err());
        let forwards = port_forwards(&requests);
        assert_eq!(forwards.len(), 1, "{forwards:?}");
        assert!(
            forwards[0].contains("/namespaces/dev-sandboxes/pods/workspace-a/portforward")
                && forwards[0].contains("ports=2222"),
            "{forwards:?}"
        );

        let (driver, requests) = driver_over_addressless_pod(CONTROLLING_SANDBOX);
        assert!(driver.daemon_stream(&placement, "env-1").await.is_err());
        let forwards = port_forwards(&requests);
        assert_eq!(forwards.len(), 1, "{forwards:?}");
        assert!(
            forwards[0].contains("/namespaces/dev-sandboxes/pods/workspace-a/portforward")
                && forwards[0].contains("ports=7777"),
            "{forwards:?}"
        );
    }

    #[tokio::test]
    async fn the_ssh_stream_never_reaches_a_pod_its_sandbox_does_not_control() {
        let (driver, requests) = driver_over_addressless_pod("another-sandbox-uid");

        assert!(
            driver
                .ssh_stream(&Placement::new("dev-sandboxes"), "env-1")
                .await
                .is_err()
        );

        assert_eq!(port_forwards(&requests), Vec::<String>::new());
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
