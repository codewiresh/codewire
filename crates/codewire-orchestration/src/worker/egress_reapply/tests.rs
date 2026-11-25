use std::time::Duration;

use super::*;
use crate::runtime::fake::FakeRuntimeDriver;

fn target(environment_id: &str) -> (Placement, RenderingIntent) {
    (
        Placement::new("dev-sandboxes"),
        RenderingIntent {
            image: "registry.example.invalid/workspace:1".into(),
            template_base: "workspace".into(),
            isolation: crate::runtime::Isolation::Standard,
            dedicated_cpu: false,
            systemd_workspace: false,
            systemd_opted_in: false,
            runtime_profile: "commodity".into(),
            shape: crate::runtime::WorkspaceShape {
                cpu_millicores: 1000,
                memory_mib: 4096,
                disk_gib: 10,
            },
            identity: crate::runtime::RenderingIdentity {
                environment_id: environment_id.into(),
                organization_id: "org-1".into(),
                operation_generation: 3,
                projection_selection_sha256: None,
                earlier_projection_selection_sha256: Vec::new(),
                managed_credential_clients: Default::default(),
                source_snapshot_id: None,
                confidential_storage_manifest_uri: String::new(),
            },
        },
    )
}

/// Every bound environment is applied again, a failure of one included, and
/// only then does the service decide.
#[tokio::test]
async fn every_bound_environment_is_applied_again_before_the_service_decides() {
    let runtime = FakeRuntimeDriver::default();
    runtime.reapply_fails.lock().unwrap().push("env-b".into());
    let reapplied = PoliciesReapplied::pending();
    let targets = [target("env-a"), target("env-b"), target("env-c")];
    finish_within(
        Duration::from_secs(5),
        &reapplied,
        reapply_each(&runtime, &targets),
    )
    .await;
    assert_eq!(
        *runtime.reapplied.lock().unwrap(),
        ["env-a", "env-b", "env-c"]
    );
    assert!(reapplied.is_finished());
}

/// A sweep that can't finish is cut at its bound and the service decides
/// anyway: a policy that differs is then refused, never admitted.
#[tokio::test]
async fn a_sweep_past_its_bound_lets_the_service_decide() {
    let runtime = FakeRuntimeDriver::default();
    runtime.reapply_hangs.lock().unwrap().push("env-a".into());
    let reapplied = PoliciesReapplied::pending();
    let targets = [target("env-a"), target("env-b")];
    let sweep = finish_within(
        Duration::from_millis(50),
        &reapplied,
        reapply_each(&runtime, &targets),
    );
    tokio::time::timeout(Duration::from_secs(5), sweep)
        .await
        .expect("the sweep ends at its bound");
    assert!(reapplied.is_finished());
    assert_eq!(*runtime.reapplied.lock().unwrap(), ["env-a"]);
}

/// A replaced policy is one that differed from its rendering, which a change
/// between restarts would also cause, so each is counted: the sweep returns
/// how many it replaced, and a failed one is not among them.
#[tokio::test]
async fn each_replaced_policy_is_counted() {
    let runtime = FakeRuntimeDriver::default();
    runtime.reapply_fails.lock().unwrap().push("env-b".into());
    let targets = [target("env-a"), target("env-b"), target("env-c")];
    assert_eq!(reapply_each(&runtime, &targets).await, 2);
}

/// A sweep that panics still lets the service decide: the guard marks it
/// finished as the panic unwinds, so no lockdown stays UNAVAILABLE.
#[tokio::test]
async fn a_sweep_that_panics_still_lets_the_service_decide() {
    let reapplied = PoliciesReapplied::pending();
    let task = tokio::spawn({
        let reapplied = reapplied.clone();
        async move {
            let sweep = async {
                if std::hint::black_box(true) {
                    panic!("a sweep that panics");
                }
            };
            finish_within(Duration::from_secs(5), &reapplied, sweep).await;
        }
    });
    assert!(task.await.unwrap_err().is_panic());
    assert!(reapplied.is_finished());
}
