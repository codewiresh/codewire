//! A `standard` Pod's host key, and so its `access_ready`, waits on its
//! guest's passing egress self-check (#5602), through the listener.

use super::*;
use crate::workspace_binding::self_check::Probe;

fn standard_pod() -> Pod {
    let mut pod = workspace_pod();
    pod.spec.as_mut().unwrap().runtime_class_name = Some("standard".into());
    pod
}

fn passing() -> Vec<Probe<'static>> {
    vec![
        Probe {
            name: "direct_dial",
            target: "1.1.1.1:443",
            refused: true,
        },
        Probe {
            name: "public_dns",
            target: "8.8.8.8:53",
            refused: true,
        },
        Probe {
            name: "cluster_dns",
            target: "10.96.0.10:53",
            refused: true,
        },
    ]
}

fn on(pod: Pod) -> Fixture {
    fixture(
        FakeCluster::new(valid_review(), vec![Some(pod)], vec![Some(sandbox())]),
        FakeStore::bound(WorkspaceCredentialScope::Pod),
    )
}

async fn record(fixture: &Fixture, check: Option<&[Probe<'_>]>) -> Result<(), BindError> {
    fixture
        .state
        .record_host_key(&valid_bearer(), Some(PEER), HOST_KEY, check)
        .await
        .map(|_| ())
}

fn recorded(fixture: &Fixture) -> bool {
    !fixture.store.host_keys.lock().unwrap().is_empty()
}

#[tokio::test]
async fn a_standard_pod_records_its_key_with_a_passing_check() {
    let fixture = on(standard_pod());
    assert_eq!(record(&fixture, Some(&passing())).await, Ok(()));
    assert!(recorded(&fixture));
}

#[tokio::test]
async fn a_standard_pod_without_a_passing_check_records_no_key() {
    let mut open = passing();
    open[0].refused = false;
    for (case, check) in [("no check", None), ("a way out", Some(open.as_slice()))] {
        let fixture = on(standard_pod());
        assert_eq!(
            record(&fixture, check).await,
            Err(BindError::FailedPrecondition),
            "{case}"
        );
        assert!(!recorded(&fixture), "{case}");
    }
}

#[tokio::test]
async fn any_other_pod_records_its_key_without_a_check_and_is_refused_one() {
    let fixture = on(workspace_pod());
    assert_eq!(record(&fixture, None).await, Ok(()));
    assert!(recorded(&fixture));

    let fixture = on(workspace_pod());
    assert_eq!(
        record(&fixture, Some(&passing())).await,
        Err(BindError::InvalidArgument)
    );
    assert!(!recorded(&fixture));
}

#[tokio::test]
async fn a_pod_read_without_its_spec_records_no_key() {
    let mut pod = workspace_pod();
    pod.spec = None;
    let fixture = on(pod);
    // Without its spec the Pod shows no service account, so bound() refuses
    // it before its class is read; either way nothing is recorded.
    assert!(record(&fixture, None).await.is_err());
    assert!(record(&fixture, Some(&passing())).await.is_err());
    assert!(!recorded(&fixture));
}

/// A `standard` Pod as the renderer makes it with hosted egress on: the broker
/// label, and its `workspace` container's egress mode.
fn standard_pod_in(mode: &str) -> Pod {
    let mut pod = standard_pod();
    pod.metadata
        .labels
        .get_or_insert_with(Default::default)
        .insert("codewire.sh/egress".into(), "broker".into());
    pod.spec.as_mut().unwrap().containers = vec![k8s_openapi::api::core::v1::Container {
        name: "workspace".into(),
        env: Some(vec![k8s_openapi::api::core::v1::EnvVar {
            name: "CODEWIRE_VM_EGRESS_MODE".into(),
            value: Some(mode.into()),
            ..Default::default()
        }]),
        ..Default::default()
    }];
    pod
}

#[tokio::test]
async fn a_broker_mode_standard_pod_records_its_key_without_a_check_and_is_refused_one() {
    let fixture = on(standard_pod_in("broker"));
    assert_eq!(record(&fixture, None).await, Ok(()));
    assert!(recorded(&fixture));

    let fixture = on(standard_pod_in("broker"));
    assert_eq!(
        record(&fixture, Some(&passing())).await,
        Err(BindError::InvalidArgument)
    );
    assert!(!recorded(&fixture));
}

#[tokio::test]
async fn the_broker_label_alone_never_waives_a_standard_pods_check() {
    // Every standard Pod carries the broker label while hosted egress is
    // on; only its egress mode says whether broker mode runs in the VM.
    for mode in ["guest-carried", "", "open"] {
        let fixture = on(standard_pod_in(mode));
        assert_eq!(
            record(&fixture, None).await,
            Err(BindError::FailedPrecondition),
            "{mode}"
        );
        assert!(!recorded(&fixture), "{mode}");

        let fixture = on(standard_pod_in(mode));
        assert_eq!(record(&fixture, Some(&passing())).await, Ok(()), "{mode}");
    }
}
