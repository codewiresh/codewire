//! Suspending a workspace: which Pods it has, and proof they have gone. An
//! acknowledged suspend is not evidence of Pod termination.

use std::time::Duration;

use super::super::{ClaimRef, within_workspace_deadline};
use crate::sandbox::ClaimOpts;
use crate::sandbox::client::{SandboxClient, WorkspacePodIdentity, WorkspaceSandboxIdentity};

const SOURCE_RESTART_POD_POLL: Duration = Duration::from_millis(250);

pub(super) fn claim_opts(claim: &ClaimRef) -> ClaimOpts {
    ClaimOpts {
        environment_id: claim.environment_id.clone(),
        org_id: claim.organization_id.clone(),
        operation_generation: claim.operation_generation,
        ..Default::default()
    }
}

pub(super) async fn source_restart_pods(
    client: &SandboxClient,
    environment: &str,
    known_name: &str,
) -> anyhow::Result<Vec<WorkspacePodIdentity>> {
    let mut pods = client.list_workspace_pod_identities(environment).await?;
    if !known_name.is_empty()
        && let Some(pod) = client
            .get_workspace_pod_identity_by_name(known_name)
            .await?
        && !pods
            .iter()
            .any(|current| current.name == pod.name && current.uid == pod.uid)
    {
        pods.push(pod);
    }
    anyhow::ensure!(
        pods.iter()
            .all(|pod| !pod.name.is_empty() && !pod.uid.is_empty()),
        "workspace Pod identity is incomplete"
    );
    Ok(pods)
}

async fn source_restart_pods_absent(
    client: &SandboxClient,
    environment: &str,
    known_name: &str,
    previous: &[WorkspacePodIdentity],
) -> anyhow::Result<bool> {
    anyhow::ensure!(
        previous
            .iter()
            .all(|pod| !pod.name.is_empty() && !pod.uid.is_empty()),
        "previous workspace Pod identity is incomplete"
    );
    if !source_restart_pods(client, environment, known_name)
        .await?
        .is_empty()
    {
        return Ok(false);
    }
    for previous in previous {
        if client
            .get_workspace_pod_identity_by_name(&previous.name)
            .await?
            .is_some()
        {
            return Ok(false);
        }
    }
    Ok(true)
}

async fn wait_for_source_restart_pods_absent(
    client: &SandboxClient,
    environment: &str,
    known_name: &str,
    previous: &[WorkspacePodIdentity],
    timeout: Duration,
) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    within_workspace_deadline(deadline, async {
        loop {
            if source_restart_pods_absent(client, environment, known_name, previous).await? {
                return Ok(());
            }
            tokio::time::sleep(SOURCE_RESTART_POD_POLL).await;
        }
    })
    .await
}

pub(super) async fn wait_for_workspace_suspension(
    client: &SandboxClient,
    claim: &ClaimRef,
    known_name: &str,
    previous: &[WorkspacePodIdentity],
    timeout: Duration,
) -> anyhow::Result<WorkspaceSandboxIdentity> {
    let opts = claim_opts(claim);
    let deadline = tokio::time::Instant::now() + timeout;
    within_workspace_deadline(deadline, async {
        let suspended = loop {
            if let Some(identity) = client
                .workspace_suspension_observed(&opts, &claim.name, &claim.uid)
                .await?
            {
                break identity;
            }
            tokio::time::sleep(SOURCE_RESTART_POD_POLL).await;
        };
        wait_for_source_restart_pods_absent(
            client,
            &claim.environment_id,
            known_name,
            previous,
            deadline.saturating_duration_since(tokio::time::Instant::now()),
        )
        .await?;
        Ok(suspended)
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source_restart_client(
        responses: Vec<(axum::http::StatusCode, serde_json::Value)>,
    ) -> SandboxClient {
        source_restart_delayed_client(responses, Some(Duration::ZERO))
    }

    fn source_restart_delayed_client(
        responses: Vec<(axum::http::StatusCode, serde_json::Value)>,
        delay: Option<Duration>,
    ) -> SandboxClient {
        use axum::{
            Router,
            body::Body,
            http::{Request, Response, header},
        };
        use std::{
            collections::VecDeque,
            sync::{Arc, Mutex},
        };
        let queued = Arc::new(Mutex::new(VecDeque::from(responses)));
        let service = Router::new().fallback(move |request: Request<Body>| {
            let queued = queued.clone();
            async move {
                match delay {
                    Some(duration) => tokio::time::sleep(duration).await,
                    None => std::future::pending::<()>().await,
                }
                assert_eq!(
                    request.method(),
                    axum::http::Method::GET,
                    "termination observation must be read-only"
                );
                let (status, body) = queued
                    .lock()
                    .unwrap()
                    .pop_front()
                    .expect("unexpected Kubernetes request");
                Response::builder()
                    .status(status)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap()
            }
        });
        SandboxClient::new(kube::Client::new(service, "default"), "dev-sandboxes")
    }

    fn old_pod() -> WorkspacePodIdentity {
        WorkspacePodIdentity {
            name: "workspace-old".into(),
            uid: "uid-old".into(),
        }
    }

    fn pod_list(items: Vec<serde_json::Value>) -> serde_json::Value {
        serde_json::json!({"apiVersion":"v1","kind":"PodList","metadata":{},"items":items})
    }

    fn pod(uid: &str) -> serde_json::Value {
        serde_json::json!({"apiVersion":"v1","kind":"Pod","metadata":{"name":"workspace-old","uid":uid},"status":{"phase":"Running"}})
    }

    fn missing_pod() -> (axum::http::StatusCode, serde_json::Value) {
        (
            axum::http::StatusCode::NOT_FOUND,
            serde_json::json!({"apiVersion":"v1","kind":"Status","status":"Failure","message":"not found","reason":"NotFound","code":404}),
        )
    }

    #[tokio::test]
    async fn source_restart_requires_old_uid_and_every_workspace_pod_to_be_absent() {
        use axum::http::StatusCode;
        let mut terminating = pod("uid-old");
        terminating["metadata"]["deletionTimestamp"] = serde_json::json!("2026-09-07T12:00:00Z");
        let client = source_restart_client(vec![(StatusCode::OK, pod_list(vec![terminating]))]);
        assert!(
            !source_restart_pods_absent(&client, "environment", "", &[old_pod()])
                .await
                .unwrap()
        );
        // Losing an environment label cannot turn a still-present old Pod into
        // a successful termination observation. A new UID at the old stable
        // name also blocks scale-up until the suspended controller removes it.
        for uid in ["uid-old", "uid-replacement"] {
            let client = source_restart_client(vec![
                (StatusCode::OK, pod_list(vec![])),
                (StatusCode::OK, pod(uid)),
            ]);
            assert!(
                !source_restart_pods_absent(&client, "environment", "", &[old_pod()])
                    .await
                    .unwrap()
            );
        }
        let client = source_restart_client(vec![(StatusCode::OK, pod_list(vec![])), missing_pod()]);
        assert!(
            source_restart_pods_absent(&client, "environment", "", &[old_pod()])
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn source_restart_rechecks_known_backend_name_and_fails_closed_on_unknown_uid() {
        use axum::http::StatusCode;
        let client = source_restart_client(vec![
            (StatusCode::OK, pod_list(vec![])),
            (StatusCode::OK, pod("uid-old")),
        ]);
        let identities = source_restart_pods(&client, "environment", "workspace-old")
            .await
            .unwrap();
        assert_eq!(identities.len(), 1);
        assert_eq!(identities[0].uid, "uid-old");
        let client = source_restart_client(vec![(StatusCode::OK, pod_list(vec![pod("")]))]);
        assert!(
            source_restart_pods(&client, "environment", "")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn source_restart_deadline_bounds_stalled_gets_and_late_success() {
        use axum::http::StatusCode;
        for delay in [None, Some(Duration::from_millis(200))] {
            let client = source_restart_delayed_client(
                vec![(StatusCode::OK, pod_list(vec![])), missing_pod()],
                delay,
            );
            let result = tokio::time::timeout(
                Duration::from_secs(1),
                wait_for_source_restart_pods_absent(
                    &client,
                    "environment",
                    "",
                    &[old_pod()],
                    Duration::from_millis(20),
                ),
            )
            .await
            .expect("original deadline must interrupt the GET");
            assert!(result.unwrap_err().to_string().contains("timed out"));
        }
        let deadline = tokio::time::Instant::now() + Duration::from_millis(10);
        let result = within_workspace_deadline(deadline, async {
            std::thread::sleep(Duration::from_millis(20));
            Ok(())
        })
        .await;
        assert!(result.is_err(), "late-ready futures cannot bypass deadline");
    }

    #[tokio::test]
    async fn source_restart_does_not_treat_timeout_as_pod_deletion() {
        use axum::http::StatusCode;
        let client = source_restart_client(vec![(StatusCode::OK, pod_list(vec![pod("uid-old")]))]);
        assert!(
            wait_for_source_restart_pods_absent(
                &client,
                "environment",
                "",
                &[old_pod()],
                Duration::ZERO
            )
            .await
            .is_err()
        );
        let client = source_restart_client(vec![
            (StatusCode::OK, pod_list(vec![pod("uid-old")])),
            (StatusCode::OK, pod_list(vec![])),
            missing_pod(),
        ]);
        wait_for_source_restart_pods_absent(
            &client,
            "environment",
            "",
            &[old_pod()],
            Duration::from_secs(2),
        )
        .await
        .unwrap();
    }

    #[test]
    fn a_claims_opts_carry_its_identity_and_nothing_else() {
        let opts = claim_opts(&ClaimRef {
            placement: crate::runtime::Placement::new("dev-sandboxes"),
            environment_id: "env-a".into(),
            organization_id: "org-a".into(),
            operation_generation: 7,
            name: "claim-a".into(),
            uid: "uid-a".into(),
        });
        assert_eq!(opts.environment_id, "env-a");
        assert_eq!(opts.org_id, "org-a");
        assert_eq!(opts.operation_generation, 7);
        assert!(opts.template_ref.is_empty() && opts.warm_pool_ref.is_empty());
    }
}
