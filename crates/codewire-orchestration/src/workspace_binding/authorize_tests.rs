//! #3628 PR 5b: the fact-reading binding checks equal their object-reading
//! reference on every Pod, Sandbox, binding and peer of a corpus. The
//! identity comes from a TokenReview through the driver, the only way to get
//! one.

use super::*;
use crate::runtime::kubernetes::observation::{member_facts, runtime_facts};
use crate::workspace_binding::authorize;
use crate::workspace_binding::authorize_reference as reference;
use k8s_openapi::api::core::v1::PodIP;
use kube::api::DynamicObject;

fn pods() -> Vec<(&'static str, Pod)> {
    type Edit = fn(&mut Pod);
    let edits: Vec<(&'static str, Edit)> = vec![
        ("as reviewed", |_| {}),
        ("scheduled", |pod| {
            pod.spec.as_mut().unwrap().node_name = Some(NODE_NAME.into())
        }),
        ("another name", |pod| {
            pod.metadata.name = Some("sandbox-other".into())
        }),
        ("no name", |pod| pod.metadata.name = None),
        ("another namespace", |pod| {
            pod.metadata.namespace = Some("elsewhere".into())
        }),
        ("no namespace", |pod| pod.metadata.namespace = None),
        ("recreated under the same name", |pod| {
            pod.metadata.uid = Some(OTHER_POD_UID.into())
        }),
        ("no UID", |pod| pod.metadata.uid = None),
        ("terminating", |pod| {
            pod.metadata.deletion_timestamp = Some(Time(k8s_openapi::jiff::Timestamp::now()))
        }),
        ("another service account", |pod| {
            pod.spec.as_mut().unwrap().service_account_name = Some("default".into())
        }),
        ("no service account", |pod| {
            pod.spec.as_mut().unwrap().service_account_name = None
        }),
        ("no spec", |pod| pod.spec = None),
        ("gateway role", |pod| {
            pod.metadata
                .labels
                .as_mut()
                .unwrap()
                .insert(LABEL_TYPE.into(), "gateway".into());
        }),
        ("no labels", |pod| pod.metadata.labels = None),
        ("another environment", |pod| {
            pod.metadata.labels.as_mut().unwrap().insert(
                LABEL_ENV_ID.into(),
                "6ba7b810-9dad-11d1-80b4-00c04fd430c8".into(),
            );
        }),
        ("pending", |pod| {
            pod.status.as_mut().unwrap().phase = Some("Pending".into())
        }),
        ("no phase", |pod| pod.status.as_mut().unwrap().phase = None),
        ("no status", |pod| pod.status = None),
        ("no controller", |pod| pod.metadata.owner_references = None),
        ("an owner that is not the controller", |pod| {
            pod.metadata.owner_references.as_mut().unwrap()[0].controller = Some(false)
        }),
        ("a second controller", |pod| {
            pod.metadata
                .owner_references
                .as_mut()
                .unwrap()
                .push(controller("apps/v1", "ReplicaSet", "rs", OTHER_POD_UID))
        }),
        ("a second owner, not a controller", |pod| {
            let mut owner = controller("apps/v1", "ReplicaSet", "rs", OTHER_POD_UID);
            owner.controller = None;
            pod.metadata.owner_references.as_mut().unwrap().push(owner)
        }),
        ("controller of another API version", |pod| {
            pod.metadata.owner_references.as_mut().unwrap()[0].api_version =
                "agents.x-k8s.io/v1alpha1".into()
        }),
        ("controller of another kind", |pod| {
            pod.metadata.owner_references.as_mut().unwrap()[0].kind = "ReplicaSet".into()
        }),
        ("controller without a name", |pod| {
            pod.metadata.owner_references.as_mut().unwrap()[0].name = String::new()
        }),
        ("controller UID not canonical", |pod| {
            pod.metadata.owner_references.as_mut().unwrap()[0].uid = SANDBOX_UID.to_uppercase()
        }),
        ("controlled by another Sandbox", |pod| {
            pod.metadata.owner_references.as_mut().unwrap()[0].uid = OTHER_POD_UID.into()
        }),
        ("addresses listed only", |pod| {
            let status = pod.status.as_mut().unwrap();
            status.pod_ip = None;
            status.pod_ips = Some(vec![PodIP {
                ip: PEER.to_string(),
            }]);
        }),
        ("dual stack", |pod| {
            pod.status.as_mut().unwrap().pod_ips = Some(vec![
                PodIP {
                    ip: PEER.to_string(),
                },
                PodIP {
                    ip: "fd00::9".into(),
                },
            ]);
        }),
        ("an unparsable address", |pod| {
            pod.status.as_mut().unwrap().pod_ip = Some("not-an-address".into())
        }),
        ("another address", |pod| {
            pod.status.as_mut().unwrap().pod_ip = Some(OTHER_PEER.to_string())
        }),
    ];
    edits
        .into_iter()
        .map(|(label, edit)| {
            let mut pod = workspace_pod();
            edit(&mut pod);
            (label, pod)
        })
        .collect()
}

fn sandboxes() -> Vec<(&'static str, DynamicObject)> {
    type Edit = fn(&mut Value);
    let edits: Vec<(&'static str, Edit)> = vec![
        ("as recorded", |_| {}),
        ("another API version", |o| {
            o["apiVersion"] = json!("agents.x-k8s.io/v1alpha1")
        }),
        ("another kind", |o| o["kind"] = json!("SandboxTemplate")),
        ("another name", |o| {
            o["metadata"]["name"] = json!("sandbox-other")
        }),
        ("another namespace", |o| {
            o["metadata"]["namespace"] = json!("elsewhere")
        }),
        ("another UID", |o| {
            o["metadata"]["uid"] = json!(OTHER_POD_UID)
        }),
        ("no UID", |o| {
            o["metadata"].as_object_mut().unwrap().remove("uid");
        }),
        ("terminating", |o| {
            o["metadata"]["deletionTimestamp"] = json!("2026-11-11T00:00:00Z")
        }),
        ("no controller", |o| {
            o["metadata"]
                .as_object_mut()
                .unwrap()
                .remove("ownerReferences");
        }),
        ("claimed by another Claim", |o| {
            o["metadata"]["ownerReferences"][0]["uid"] = json!(OTHER_POD_UID)
        }),
        ("controller of another kind", |o| {
            o["metadata"]["ownerReferences"][0]["kind"] = json!("Sandbox")
        }),
        ("controller of another API version", |o| {
            o["metadata"]["ownerReferences"][0]["apiVersion"] = json!("agents.x-k8s.io/v1beta1")
        }),
        ("two controllers", |o| {
            let second = o["metadata"]["ownerReferences"][0].clone();
            o["metadata"]["ownerReferences"]
                .as_array_mut()
                .unwrap()
                .push(second);
        }),
    ];
    edits
        .into_iter()
        .map(|(label, edit)| {
            let mut value = sandbox();
            edit(&mut value);
            (label, serde_json::from_value(value).unwrap())
        })
        .collect()
}

fn bindings() -> Vec<(&'static str, LiveBinding)> {
    type Edit = fn(&mut LiveBinding);
    let edits: Vec<(&'static str, Edit)> = vec![
        ("as recorded", |_| {}),
        ("another environment", |b| {
            b.environment_id = "6ba7b810-9dad-11d1-80b4-00c04fd430c8".into()
        }),
        ("another Sandbox", |b| b.sandbox_uid = OTHER_POD_UID.into()),
        ("another Claim", |b| b.claim_uid = OTHER_POD_UID.into()),
        ("another namespace", |b| b.namespace = "elsewhere".into()),
    ];
    edits
        .into_iter()
        .map(|(label, edit)| {
            let mut binding = binding(WorkspaceCredentialScope::Pod);
            edit(&mut binding);
            (label, binding)
        })
        .collect()
}

#[tokio::test]
async fn every_fact_reading_check_equals_the_object_reading_one() {
    let driver =
        crate::runtime::kubernetes::KubernetesDriver::shared(FakeCluster::valid().client());
    let identity = driver
        .review_member_credential(&valid_bearer())
        .await
        .unwrap();
    let owners = [
        authorize::SandboxOwner {
            name: SANDBOX_NAME.into(),
            uid: SANDBOX_UID.into(),
        },
        authorize::SandboxOwner {
            name: "sandbox-other".into(),
            uid: SANDBOX_UID.into(),
        },
    ];
    let peers: [IpAddr; 4] = [
        PEER,
        OTHER_PEER,
        "::ffff:10.244.0.9".parse().unwrap(),
        "fd00::9".parse().unwrap(),
    ];
    let mut bindable = 0;
    for (label, pod) in pods() {
        let member = member_facts(&pod).unwrap();
        let expected = reference::bindable_pod(&pod, &identity);
        bindable += usize::from(expected.is_some());
        assert_eq!(
            authorize::bindable_pod(&member, &identity),
            expected,
            "{label}"
        );
        for (binding_label, binding) in bindings() {
            assert_eq!(
                authorize::bound_pod(&member, &identity, &binding),
                reference::bound_pod(&pod, &identity, &binding),
                "{label}, {binding_label}"
            );
        }
        for peer in peers {
            assert_eq!(
                authorize::peer_is_pod(&member, peer),
                reference::peer_is_pod(&pod, peer),
                "{label}, {peer}"
            );
        }
    }
    let mut bound = 0;
    for (label, sandbox) in sandboxes() {
        let runtime = runtime_facts(&sandbox).unwrap();
        for owner in &owners {
            for (binding_label, binding) in bindings() {
                let expected = reference::bound_sandbox(&sandbox, owner, &binding);
                bound += usize::from(expected);
                assert_eq!(
                    authorize::bound_sandbox(&runtime, owner, &binding),
                    expected,
                    "{label}, {}, {binding_label}",
                    owner.name
                );
            }
        }
    }
    // The corpus reaches both outcomes of each check.
    assert!(bindable > 1 && bound > 0, "{bindable} {bound}");
}
