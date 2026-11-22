//! A `standard` Sandbox is marked `existing` when its daemon's bind is
//! answered, and only then (#5602, change 7 of
//! `designs/vm-runtime-orchestration.md`).

use super::*;

/// The fixture's Sandbox as a `standard` one, its VM state `state`.
fn standard_sandbox(state: &str) -> Value {
    let mut sandbox = sandbox();
    sandbox["spec"] = json!({
        "podTemplate": {
            "spec": {
                "runtimeClassName": "standard",
                "containers": [{
                    "name": "workspace",
                    "env": [
                        { "name": "CODEWIRE_VM_STATE_DISK_MIB", "value": "14694" },
                        { "name": "CODEWIRE_VM_STATE", "value": state },
                    ],
                }],
            },
        },
    });
    sandbox
}

fn standard(state: &str) -> Arc<FakeCluster> {
    FakeCluster::new(
        valid_review(),
        vec![Some(workspace_pod())],
        vec![Some(standard_sandbox(state))],
    )
}

fn patches(fixture: &Fixture) -> Vec<Value> {
    fixture.cluster.sandbox_patches.lock().unwrap().clone()
}

#[tokio::test]
async fn a_standard_sandbox_is_marked_existing_before_its_daemon_is_answered() {
    let bound = fixture(
        standard("new"),
        FakeStore::bound(WorkspaceCredentialScope::Pod),
    );
    let response = bound.bind(20).await.unwrap();
    assert_eq!(response.pod_uid, POD_UID);
    let env = "/spec/podTemplate/spec/containers/0/env/1";
    assert_eq!(
        patches(&bound),
        vec![json!([
            { "op": "test", "path": "/metadata/uid", "value": SANDBOX_UID },
            { "op": "test", "path": format!("{env}/name"), "value": "CODEWIRE_VM_STATE" },
            { "op": "test", "path": format!("{env}/value"), "value": "new" },
            { "op": "replace", "path": format!("{env}/value"), "value": "existing" },
        ])]
    );
}

#[tokio::test]
async fn a_marked_standard_sandbox_and_any_other_are_never_written() {
    for cluster in [standard("existing"), FakeCluster::valid()] {
        let bound = fixture(cluster, FakeStore::bound(WorkspaceCredentialScope::Pod));
        bound.bind(20).await.unwrap();
        assert!(patches(&bound).is_empty());
    }
}

#[tokio::test]
async fn a_daemon_whose_sandbox_cannot_be_marked_is_not_answered() {
    let cluster = standard("new");
    *cluster.sandbox_patch_status.lock().unwrap() = StatusCode::UNPROCESSABLE_ENTITY;
    let failed = fixture(cluster, FakeStore::bound(WorkspaceCredentialScope::Pod));
    assert_eq!(failed.bind(20).await, Err(BindError::Unavailable));
    assert_eq!(patches(&failed).len(), 1);

    // A standard Sandbox whose state is neither value is refused unwritten.
    let unknown = fixture(
        standard("blank"),
        FakeStore::bound(WorkspaceCredentialScope::Pod),
    );
    assert_eq!(unknown.bind(20).await, Err(BindError::Unavailable));
    assert!(patches(&unknown).is_empty());
}
