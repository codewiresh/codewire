//! The agent-sandbox driver: each method is one call on a [`SandboxClient`]
//! for the placement's namespace, which does no I/O to build, and reads what
//! comes back into the driver's own types.

pub(crate) mod members;
mod suspension;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use k8s_openapi::api::core::v1::Pod;
use kube::api::{Api, LogParams};

use super::{
    ClaimReadiness, ClaimRef, MemberRef, MemberReplacement, Placement, ProbeResult, RuntimeAccess,
    RuntimeDriver, RuntimeExec, RuntimeLifecycle, RuntimeMember, RuntimePools, RuntimeStream,
    RuntimeTeardown, SuspendedRuntime,
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

    async fn current_member(
        &self,
        placement: &Placement,
        environment_id: &str,
    ) -> anyhow::Result<Option<MemberRef>> {
        self.sandbox_client(placement)
            .get_workspace_pod_identity(environment_id)
            .await
    }

    async fn member_name(
        &self,
        placement: &Placement,
        environment_id: &str,
    ) -> anyhow::Result<String> {
        self.sandbox_client(placement)
            .get_pod_name(environment_id)
            .await
    }

    async fn member_named(
        &self,
        placement: &Placement,
        member_name: &str,
    ) -> anyhow::Result<Option<MemberRef>> {
        self.sandbox_client(placement)
            .get_workspace_pod_identity_by_name(member_name)
            .await
    }

    async fn suspend_current(
        &self,
        placement: &Placement,
        environment_id: &str,
    ) -> anyhow::Result<()> {
        // A suspend re-pins nothing, so it names no image.
        self.sandbox_client(placement)
            .set_replicas(environment_id, 0, "")
            .await
    }

    async fn resume_current(
        &self,
        placement: &Placement,
        environment_id: &str,
        support_image: &str,
    ) -> anyhow::Result<()> {
        self.sandbox_client(placement)
            .set_replicas(environment_id, 1, support_image)
            .await
    }

    async fn replace_member(
        &self,
        placement: &Placement,
        environment_id: &str,
        member: &MemberRef,
        support_image: &str,
    ) -> anyhow::Result<MemberReplacement> {
        self.sandbox_client(placement)
            .replace_workspace_pod_if_uid(environment_id, &member.name, &member.uid, support_image)
            .await
    }

    async fn wait_replacement(
        &self,
        placement: &Placement,
        previous: &MemberRef,
        timeout: Duration,
    ) -> anyhow::Result<MemberRef> {
        self.sandbox_client(placement)
            .wait_for_replacement_workspace_pod(&previous.name, &previous.uid, timeout)
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

    async fn ssh_ready(
        &self,
        placement: &Placement,
        environment_id: &str,
        host_keys: &dyn HostKeyStore,
    ) -> anyhow::Result<()> {
        self.sandbox_client(placement)
            .check_sidecar_ready(environment_id, WORKSPACE_SSH_PORT, host_keys)
            .await
    }

    async fn start_exec(
        &self,
        placement: &Placement,
        member_name: &str,
        command: &[String],
        work_dir: &str,
        env: &BTreeMap<String, String>,
    ) -> anyhow::Result<RuntimeExec> {
        self.sandbox_client(placement)
            .start_workspace_exec_on_pod(member_name, command, work_dir, env)
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

    async fn workspace_logs(
        &self,
        placement: &Placement,
        member_name: &str,
        tail_lines: i64,
    ) -> anyhow::Result<Vec<u8>> {
        let pods: Api<Pod> = Api::namespaced(self.client.clone(), &placement.namespace);
        let logs = pods
            .logs(
                member_name,
                &LogParams {
                    container: Some("workspace".into()),
                    tail_lines: Some(tail_lines),
                    timestamps: true,
                    ..Default::default()
                },
            )
            .await?;
        Ok(logs.into_bytes())
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
                        "uid": "1f4e3a52-8d2b-4c7e-9a60-5b1d2e3f4a5b", "resourceVersion": "1",
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
                    "status": {"phase": "Running",
                        "containerStatuses": [{"name": "workspace", "ready": true,
                            "image": "", "imageID": "", "restartCount": 0}]}}),
            ),
        ];
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = requests.clone();
        let service = Router::new().fallback(move |request: Request<Body>| {
            let seen = seen.clone();
            let objects = objects.clone();
            async move {
                seen.lock()
                    .unwrap()
                    .push(format!("{} {}", request.method(), request.uri()));
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

    const STUB_POD_UID: &str = "7e7b20f6-0bd2-4f11-8b16-9c23d4e5f607";

    #[tokio::test]
    async fn the_current_member_is_the_claims_runtime_read_from_the_placement() {
        let (driver, requests) = driver_over_addressless_pod(CONTROLLING_SANDBOX);
        let placement = Placement::new("dev-sandboxes");

        assert_eq!(
            driver.member_name(&placement, "env-1").await.unwrap(),
            "workspace-a"
        );
        let member = driver
            .current_member(&placement, "env-1")
            .await
            .unwrap()
            .expect("a member");

        assert_eq!(member.name, "workspace-a");
        assert_eq!(member.uid, STUB_POD_UID);
        for request in requests.lock().unwrap().iter() {
            assert!(
                request.starts_with("GET ") && request.contains("/namespaces/dev-sandboxes/"),
                "{request}"
            );
        }
    }

    #[tokio::test]
    async fn workspace_logs_read_the_workspace_container_of_that_member() {
        let (driver, requests) = driver_over_addressless_pod(CONTROLLING_SANDBOX);

        // The stub has no log, so the read itself fails.
        assert!(
            driver
                .workspace_logs(&Placement::new("dev-sandboxes"), "workspace-a", 200)
                .await
                .is_err()
        );

        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 1, "{requests:?}");
        let request = &requests[0];
        assert!(
            request.starts_with("GET /api/v1/namespaces/dev-sandboxes/pods/workspace-a/log?")
                && request.contains("container=workspace")
                && request.contains("tailLines=200")
                && request.contains("timestamps=true"),
            "{request}"
        );
    }

    #[tokio::test]
    async fn replacing_an_incarnation_that_is_already_gone_writes_nothing() {
        let (driver, requests) = driver_over_addressless_pod(CONTROLLING_SANDBOX);
        let gone = MemberRef {
            name: "workspace-a".into(),
            uid: "an-earlier-incarnation".into(),
        };

        let replacement = driver
            .replace_member(
                &Placement::new("dev-sandboxes"),
                "env-1",
                &gone,
                "support-image",
            )
            .await
            .unwrap();

        assert_eq!(replacement, MemberReplacement::AlreadyReplaced);
        for request in requests.lock().unwrap().iter() {
            assert!(request.starts_with("GET "), "{request}");
        }
    }

    #[tokio::test]
    async fn replacing_the_current_incarnation_deletes_it_in_the_placement() {
        let (driver, requests) = driver_over_addressless_pod(CONTROLLING_SANDBOX);
        let current = MemberRef {
            name: "workspace-a".into(),
            uid: STUB_POD_UID.into(),
        };

        let replacement = driver
            .replace_member(
                &Placement::new("dev-sandboxes"),
                "env-1",
                &current,
                "support-image",
            )
            .await
            .unwrap();

        assert_eq!(replacement, MemberReplacement::Replaced);
        let requests = requests.lock().unwrap();
        assert!(
            requests.iter().any(|request| request
                .starts_with("DELETE /api/v1/namespaces/dev-sandboxes/pods/workspace-a")),
            "{requests:?}"
        );
    }

    #[tokio::test]
    async fn a_replacement_is_a_ready_member_with_another_uid() {
        let (driver, _) = driver_over_addressless_pod(CONTROLLING_SANDBOX);
        let placement = Placement::new("dev-sandboxes");
        let member = |uid: &str| MemberRef {
            name: "workspace-a".into(),
            uid: uid.into(),
        };

        let replacement = driver
            .wait_replacement(
                &placement,
                &member("an-earlier-incarnation"),
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        assert_eq!(replacement.uid, STUB_POD_UID);

        // The same UID has not been replaced, however ready it is.
        assert!(
            driver
                .wait_replacement(&placement, &member(STUB_POD_UID), Duration::from_millis(1))
                .await
                .is_err()
        );
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
    async fn a_named_member_is_whatever_holds_that_name_in_the_placement() {
        // The stub's Pod is controlled by another Sandbox: a name alone says
        // nothing about control.
        let (driver, requests) = driver_over_addressless_pod("another-sandbox-uid");
        let placement = Placement::new("dev-sandboxes");

        let member = driver
            .member_named(&placement, "workspace-a")
            .await
            .unwrap()
            .expect("a member");
        assert_eq!(member.name, "workspace-a");
        assert_eq!(member.uid, STUB_POD_UID);

        assert_eq!(
            driver
                .member_named(&placement, "workspace-gone")
                .await
                .unwrap(),
            None
        );
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 2, "{requests:?}");
        assert!(
            requests[0].ends_with("/namespaces/dev-sandboxes/pods/workspace-a"),
            "{requests:?}"
        );
    }

    const OLD_SUPPORT_IMAGE: &str = "registry.test/codewire/support@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const NEW_SUPPORT_IMAGE: &str = "registry.test/codewire/support@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    /// Each patch's path and body.
    type Patches = Arc<Mutex<Vec<(String, String)>>>;

    /// A claim and its running Sandbox, answering a patch with the operating
    /// mode it asked for.
    fn driver_over_patchable_sandbox() -> (Arc<dyn RuntimeDriver>, Patches) {
        let sandbox = "/apis/agents.x-k8s.io/v1beta1/namespaces/dev-sandboxes/sandboxes/sandbox-a";
        let patches = Arc::new(Mutex::new(Vec::new()));
        let seen = patches.clone();
        let service = Router::new().fallback(move |request: Request<Body>| {
            let seen = seen.clone();
            async move {
                let path = request.uri().path().to_owned();
                let is_patch = request.method() == axum::http::Method::PATCH;
                let body = axum::body::to_bytes(request.into_body(), usize::MAX)
                    .await
                    .unwrap();
                let body = String::from_utf8(body.to_vec()).unwrap();
                let mode = if body.contains("Suspended") {
                    "Suspended"
                } else {
                    "Running"
                };
                if is_patch {
                    seen.lock().unwrap().push((path.clone(), body));
                }
                let object = if path == sandbox {
                    json!({"apiVersion": "agents.x-k8s.io/v1beta1", "kind": "Sandbox",
                        "metadata": {"name": "sandbox-a", "namespace": "dev-sandboxes",
                            "uid": CONTROLLING_SANDBOX, "resourceVersion": "1"},
                        "spec": {"operatingMode": mode, "podTemplate": {"spec": {"volumes": [
                            {"name": crate::sandbox::template::DAEMON_VOLUME,
                                "image": {"reference": OLD_SUPPORT_IMAGE}}]}}}})
                } else {
                    json!({"apiVersion": "extensions.agents.x-k8s.io/v1beta1",
                        "kind": "SandboxClaim",
                        "metadata": {"name": "sandbox-env-1", "namespace": "dev-sandboxes",
                            "uid": "c0ffee00-e29b-41d4-a716-446655440000"},
                        "status": {"sandbox": {"name": "sandbox-a"}}})
                };
                Response::builder()
                    .header("content-type", "application/json")
                    .body(Body::from(object.to_string()))
                    .unwrap()
            }
        });
        let client = kube::Client::new(service, "the-default-namespace");
        (KubernetesDriver::shared(client), patches)
    }

    #[tokio::test]
    async fn the_current_runtime_is_patched_to_the_mode_asked_for_fenced_on_its_uid() {
        let placement = Placement::new("dev-sandboxes");
        for (mode, patches) in [
            ("Suspended", {
                let (driver, patches) = driver_over_patchable_sandbox();
                driver.suspend_current(&placement, "env-1").await.unwrap();
                patches
            }),
            ("Running", {
                let (driver, patches) = driver_over_patchable_sandbox();
                driver
                    .resume_current(&placement, "env-1", NEW_SUPPORT_IMAGE)
                    .await
                    .unwrap();
                patches
            }),
        ] {
            let patches = patches.lock().unwrap();
            assert_eq!(patches.len(), 1, "{patches:?}");
            let (path, body) = &patches[0];
            assert!(
                path.ends_with("/namespaces/dev-sandboxes/sandboxes/sandbox-a"),
                "{path}"
            );
            let operations: serde_json::Value = serde_json::from_str(body).unwrap();
            let operations = operations.as_array().unwrap();
            assert_eq!(
                operations.first().unwrap(),
                &json!({"op": "test", "path": "/metadata/uid", "value": CONTROLLING_SANDBOX})
            );
            assert_eq!(
                operations.last().unwrap(),
                &json!({"op": "add", "path": "/spec/operatingMode", "value": mode})
            );
            // Only a resume re-pins the daemon.
            assert_eq!(
                body.contains(NEW_SUPPORT_IMAGE),
                mode == "Running",
                "{body}"
            );
        }
    }

    struct OneHostKey;

    #[async_trait]
    impl HostKeyStore for OneHostKey {
        async fn current_host_key(
            &self,
            _environment_id: &str,
        ) -> Result<Option<(i64, String)>, sqlx::Error> {
            Ok(Some((
                1,
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
                    .into(),
            )))
        }
    }

    #[tokio::test]
    async fn the_ssh_check_reaches_the_ssh_port_of_a_runtime_its_sandbox_controls() {
        let placement = Placement::new("dev-sandboxes");

        let (driver, requests) = driver_over_addressless_pod(CONTROLLING_SANDBOX);
        // The stub can't upgrade the connection, so the check itself fails.
        assert!(
            driver
                .ssh_ready(&placement, "env-1", &OneHostKey)
                .await
                .is_err()
        );
        let forwards = port_forwards(&requests);
        assert_eq!(forwards.len(), 1, "{forwards:?}");
        assert!(
            forwards[0].contains("/namespaces/dev-sandboxes/pods/workspace-a/portforward")
                && forwards[0].contains("ports=2222"),
            "{forwards:?}"
        );

        let (driver, requests) = driver_over_addressless_pod("another-sandbox-uid");
        assert!(
            driver
                .ssh_ready(&placement, "env-1", &OneHostKey)
                .await
                .is_err()
        );
        assert_eq!(port_forwards(&requests), Vec::<String>::new());
    }

    #[tokio::test]
    async fn an_exec_runs_in_the_workspace_container_of_that_exact_member() {
        let placement = Placement::new("dev-sandboxes");
        let (driver, requests) = driver_over_addressless_pod(CONTROLLING_SANDBOX);

        // The stub can't upgrade the connection, so the attachment fails.
        let attached = driver
            .start_exec(
                &placement,
                "workspace-b",
                &["true".to_owned()],
                "/workspace",
                &BTreeMap::new(),
            )
            .await;

        assert!(attached.is_err());
        let requests = requests.lock().unwrap();
        assert_eq!(
            requests.len(),
            1,
            "no lookup, only the attach: {requests:?}"
        );
        assert!(
            requests[0].contains("/namespaces/dev-sandboxes/pods/workspace-b/exec")
                && requests[0].contains("container=workspace"),
            "{requests:?}"
        );
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
