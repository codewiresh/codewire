//! The fact-reading checks equal the object-reading ones they replaced
//! (#3628 PR 5a): every check, over a corpus of Pods and Sandboxes that each
//! change one thing a check reads.

use k8s_openapi::api::core::v1::Pod;
use kube::api::DynamicObject;
use serde_json::{Value, json};

use super::checks_reference as reference;
use super::*;
use crate::runtime::kubernetes::observation::{member_facts, runtime_facts};
use crate::sandbox::client::WorkspacePvc;
use codewire_daemon_proto::WORKSPACE_BINDING_TOKEN_AUDIENCE;

const POD_UID: &str = "2f0b1c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d";
const SANDBOX_UID: &str = "7a6b5c4d-3e2f-4a1b-9c8d-7e6f5a4b3c2d";
const PINNED: &str = "registry.example.invalid/workspace@sha256:1111111111111111111111111111111111111111111111111111111111111111";

fn base_pod() -> Value {
    json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {
            "name": "sandbox-a", "uid": POD_UID,
            "labels": {"codewire.sh/environment-operation-generation": "7"},
            "ownerReferences": [
                {"apiVersion": "agents.x-k8s.io/v1beta1", "kind": "Sandbox", "name": "sandbox-a",
                 "uid": SANDBOX_UID, "controller": true}
            ]
        },
        "spec": {
            "serviceAccountName": SANDBOX_SERVICE_ACCOUNT_NAME,
            "containers": [
                {"name": "workspace", "image": PINNED, "env": [
                    {"name": "CODEWIRE_DAEMON_AUTH_TOKEN", "value": "token"},
                    {"name": "CODEWIRE_ENVIRONMENT_OPERATION_GENERATION", "value": "7"}
                ]},
                {"name": "dind", "image": "docker:29"}
            ],
            "initContainers": [{"name": "mount-workspace", "image": "busybox:1"}],
            "volumes": [
                {"name": "workspace", "persistentVolumeClaim": {"claimName": "workspace-sandbox-a"}}
            ]
        },
        "status": {
            "podIP": "10.0.0.7",
            "containerStatuses": [
                {"name": "workspace", "image": PINNED, "imageID": format!("docker-pullable://{PINNED}"),
                 "ready": true, "restartCount": 0},
                {"name": "dind", "image": "docker:29", "imageID": "docker-pullable://docker@sha256:2222",
                 "ready": true, "restartCount": 0}
            ],
            "initContainerStatuses": [
                {"name": "mount-workspace", "image": "busybox:1", "imageID": "busybox@sha256:3333",
                 "ready": true, "restartCount": 0}
            ]
        }
    })
}

const SANDBOX_SERVICE_ACCOUNT_NAME: &str = codewire_daemon_proto::SANDBOX_SERVICE_ACCOUNT;

fn base_sandbox() -> Value {
    json!({
        "apiVersion": "agents.x-k8s.io/v1beta1", "kind": "Sandbox",
        "metadata": {"name": "sandbox-a", "uid": SANDBOX_UID, "labels": {"agents.x-k8s.io/launch-type": "warm"}},
        "spec": {"podTemplate": {"spec": {
            "containers": [
                {"name": "workspace", "image": PINNED},
                {"name": "dind", "image": "docker:29"}
            ],
            "initContainers": [{"name": "mount-workspace", "image": "busybox:1"}]
        }}}
    })
}

fn binding_volume(audience: &str) -> Value {
    json!({"name": WORKSPACE_BINDING_VOLUME, "projected": {"sources": [
        {"serviceAccountToken": {"audience": audience, "path": "token", "expirationSeconds": 600}}
    ]}})
}

/// The base Pod with one change applied at a JSON pointer, or a key removed.
fn pod_with(edit: impl FnOnce(&mut Value)) -> Pod {
    let mut pod = base_pod();
    edit(&mut pod);
    serde_json::from_value(pod).unwrap()
}

fn pods() -> Vec<(&'static str, Pod)> {
    let token = WORKSPACE_BINDING_TOKEN_AUDIENCE;
    vec![
        ("base", pod_with(|_| {})),
        (
            "no spec",
            pod_with(|pod| {
                pod.as_object_mut().unwrap().remove("spec");
            }),
        ),
        (
            "no uid",
            pod_with(|pod| {
                pod["metadata"].as_object_mut().unwrap().remove("uid");
            }),
        ),
        (
            "empty uid",
            pod_with(|pod| pod["metadata"]["uid"] = json!("")),
        ),
        (
            "terminating",
            pod_with(|pod| pod["metadata"]["deletionTimestamp"] = json!("2026-11-11T00:00:00Z")),
        ),
        (
            "other account",
            pod_with(|pod| pod["spec"]["serviceAccountName"] = json!("default")),
        ),
        (
            "no account",
            pod_with(|pod| {
                pod["spec"]
                    .as_object_mut()
                    .unwrap()
                    .remove("serviceAccountName");
            }),
        ),
        (
            "other controller kind",
            pod_with(|pod| pod["metadata"]["ownerReferences"][0]["kind"] = json!("ReplicaSet")),
        ),
        (
            "other controller uid",
            pod_with(|pod| pod["metadata"]["ownerReferences"][0]["uid"] = json!(POD_UID)),
        ),
        (
            "not controller",
            pod_with(|pod| pod["metadata"]["ownerReferences"][0]["controller"] = json!(false)),
        ),
        (
            "second controller",
            pod_with(|pod| {
                pod["metadata"]["ownerReferences"].as_array_mut().unwrap().push(
            json!({"apiVersion": "v1", "kind": "Sandbox", "name": "b", "uid": SANDBOX_UID, "controller": true}))
            }),
        ),
        (
            "binding volume",
            pod_with(|pod| {
                pod["spec"]["volumes"]
                    .as_array_mut()
                    .unwrap()
                    .push(binding_volume(token));
                pod["spec"]["containers"][0]["env"]
                    .as_array_mut()
                    .unwrap()
                    .remove(0);
            }),
        ),
        (
            "binding volume and token",
            pod_with(|pod| {
                pod["spec"]["volumes"]
                    .as_array_mut()
                    .unwrap()
                    .push(binding_volume(token))
            }),
        ),
        (
            "binding volume other audience",
            pod_with(|pod| {
                pod["spec"]["volumes"]
                    .as_array_mut()
                    .unwrap()
                    .push(binding_volume("other"));
                pod["spec"]["containers"][0]["env"]
                    .as_array_mut()
                    .unwrap()
                    .remove(0);
            }),
        ),
        (
            "binding volume other name",
            pod_with(|pod| {
                let mut volume = binding_volume(token);
                volume["name"] = json!("other");
                pod["spec"]["volumes"].as_array_mut().unwrap().push(volume);
                pod["spec"]["containers"][0]["env"]
                    .as_array_mut()
                    .unwrap()
                    .remove(0);
            }),
        ),
        (
            "no token, no volume",
            pod_with(|pod| {
                pod["spec"]["containers"][0]["env"]
                    .as_array_mut()
                    .unwrap()
                    .remove(0);
            }),
        ),
        (
            "token from a secret",
            pod_with(|pod| {
                pod["spec"]["containers"][0]["env"][0] = json!(
            {"name": "CODEWIRE_DAEMON_AUTH_TOKEN", "valueFrom": {"secretKeyRef": {"name": "s", "key": "k"}}})
            }),
        ),
        (
            "no generation env, label stands in",
            pod_with(|pod| {
                pod["spec"]["containers"][0]["env"]
                    .as_array_mut()
                    .unwrap()
                    .remove(1);
            }),
        ),
        (
            "no generation anywhere",
            pod_with(|pod| {
                pod["spec"]["containers"][0]["env"]
                    .as_array_mut()
                    .unwrap()
                    .remove(1);
                pod["metadata"].as_object_mut().unwrap().remove("labels");
            }),
        ),
        (
            "generation twice",
            pod_with(|pod| {
                pod["spec"]["containers"][0]["env"]
                    .as_array_mut()
                    .unwrap()
                    .push(
                        json!({"name": "CODEWIRE_ENVIRONMENT_OPERATION_GENERATION", "value": "7"}),
                    )
            }),
        ),
        (
            "generation from a source",
            pod_with(|pod| {
                pod["spec"]["containers"][0]["env"][1] = json!(
            {"name": "CODEWIRE_ENVIRONMENT_OPERATION_GENERATION", "valueFrom": {"fieldRef": {"fieldPath": "x"}}})
            }),
        ),
        (
            "generation with a value and a source",
            pod_with(|pod| {
                pod["spec"]["containers"][0]["env"][1]["valueFrom"] =
                    json!({"fieldRef": {"fieldPath": "x"}})
            }),
        ),
        (
            "clients from a source",
            pod_with(|pod| {
                pod["spec"]["containers"][0]["env"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!(
                        {"name": MANAGED_CLIENTS_ENV, "valueFrom": {"fieldRef": {"fieldPath": "x"}}}
                    ))
            }),
        ),
        (
            "generation zero",
            pod_with(|pod| pod["spec"]["containers"][0]["env"][1]["value"] = json!("0")),
        ),
        (
            "digest good",
            pod_with(|pod| {
                pod["spec"]["containers"][0]["env"].as_array_mut().unwrap().push(
            json!({"name": "CODEWIRE_ENVIRONMENT_PROJECTION_SHA256", "value": "a".repeat(64)}))
            }),
        ),
        (
            "digest short",
            pod_with(|pod| {
                pod["spec"]["containers"][0]["env"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({"name": "CODEWIRE_ENVIRONMENT_PROJECTION_SHA256", "value": "abc"}))
            }),
        ),
        (
            "digest uppercase",
            pod_with(|pod| {
                pod["spec"]["containers"][0]["env"].as_array_mut().unwrap().push(
            json!({"name": "CODEWIRE_ENVIRONMENT_PROJECTION_SHA256", "value": "A".repeat(64)}))
            }),
        ),
        (
            "clients malformed",
            pod_with(|pod| {
                pod["spec"]["containers"][0]["env"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({"name": MANAGED_CLIENTS_ENV, "value": "not-clients"}))
            }),
        ),
        (
            "no workspace container",
            pod_with(|pod| pod["spec"]["containers"][0]["name"] = json!("other")),
        ),
        (
            "image retagged",
            pod_with(|pod| pod["spec"]["containers"][1]["image"] = json!("docker:30")),
        ),
        (
            "image missing",
            pod_with(|pod| {
                pod["spec"]["containers"][1]
                    .as_object_mut()
                    .unwrap()
                    .remove("image");
            }),
        ),
        (
            "duplicate container",
            pod_with(|pod| {
                pod["spec"]["containers"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({"name": "dind", "image": "docker:29"}))
            }),
        ),
        (
            "extra init",
            pod_with(|pod| {
                pod["spec"]["initContainers"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({"name": "x", "image": "busybox:1"}))
            }),
        ),
        (
            "stale digest",
            pod_with(|pod| {
                pod["status"]["containerStatuses"][0]["imageID"] =
                    json!("docker-pullable://w@sha256:9999")
            }),
        ),
        (
            "digest unreported",
            pod_with(|pod| {
                pod["status"]["containerStatuses"]
                    .as_array_mut()
                    .unwrap()
                    .remove(0);
            }),
        ),
        (
            "no status",
            pod_with(|pod| {
                pod.as_object_mut().unwrap().remove("status");
            }),
        ),
        (
            "no workspace volume",
            pod_with(|pod| pod["spec"]["volumes"] = json!([])),
        ),
        (
            "workspace volume not a claim",
            pod_with(|pod| {
                pod["spec"]["volumes"][0] = json!({"name": "workspace", "emptyDir": {}})
            }),
        ),
        (
            "other claim",
            pod_with(|pod| {
                pod["spec"]["volumes"][0]["persistentVolumeClaim"]["claimName"] = json!("other")
            }),
        ),
    ]
}

fn sandboxes() -> Vec<(&'static str, DynamicObject)> {
    let with = |edit: &dyn Fn(&mut Value)| {
        let mut sandbox = base_sandbox();
        edit(&mut sandbox);
        serde_json::from_value::<DynamicObject>(sandbox).unwrap()
    };
    vec![
        ("base", with(&|_| {})),
        (
            "no init containers",
            with(&|sandbox| {
                sandbox["spec"]["podTemplate"]["spec"]
                    .as_object_mut()
                    .unwrap()
                    .remove("initContainers");
            }),
        ),
        (
            "template retagged",
            with(&|sandbox| {
                sandbox["spec"]["podTemplate"]["spec"]["containers"][1]["image"] =
                    json!("docker:30")
            }),
        ),
        (
            "template malformed",
            with(&|sandbox| {
                sandbox["spec"]["podTemplate"]["spec"]["containers"] = json!({"not": "a list"})
            }),
        ),
        (
            "template duplicate",
            with(&|sandbox| {
                sandbox["spec"]["podTemplate"]["spec"]["containers"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({"name": "dind", "image": "docker:29"}))
            }),
        ),
        (
            "template nameless",
            with(&|sandbox| {
                sandbox["spec"]["podTemplate"]["spec"]["containers"][1] =
                    json!({"image": "docker:29"})
            }),
        ),
    ]
}

fn volumes() -> Vec<WorkspacePvc> {
    vec![
        WorkspacePvc::VolumeLess,
        WorkspacePvc::Claim {
            name: "workspace-sandbox-a".into(),
            uid: "u".into(),
            bound: true,
        },
        WorkspacePvc::Claim {
            name: "workspace-sandbox-a".into(),
            uid: "u".into(),
            bound: false,
        },
        WorkspacePvc::Claim {
            name: "other".into(),
            uid: "u".into(),
            bound: true,
        },
    ]
}

#[test]
fn every_fact_reading_check_equals_the_object_reading_one() {
    let mut cases = 0;
    for (pod_case, pod) in pods() {
        let member = member_facts(&pod).unwrap();
        assert_eq!(
            credential_scope(&member),
            reference::credential_scope(&pod),
            "credential scope: {pod_case}"
        );
        assert_eq!(
            environment_scope_capture(&member),
            reference::environment_scope_capture(&pod),
            "capture: {pod_case}"
        );
        for (uid, runtime_uid) in [
            (POD_UID, SANDBOX_UID),
            (SANDBOX_UID, SANDBOX_UID),
            (POD_UID, POD_UID),
            ("", SANDBOX_UID),
        ] {
            assert_eq!(
                member_still_observed(&member, uid, runtime_uid),
                reference::pod_still_observed(&pod, uid, runtime_uid),
                "still observed: {pod_case} {uid} {runtime_uid}"
            );
        }
        for volume in volumes() {
            assert_eq!(
                volume_matches(&member, &volume),
                reference::pvc_matches(&pod, &volume),
                "volume: {pod_case} {volume:?}"
            );
        }
        for (sandbox_case, sandbox) in sandboxes() {
            assert_eq!(
                images_match(&runtime_facts(&sandbox).unwrap(), &member),
                reference::images_match(&sandbox, &pod),
                "images: {pod_case} on {sandbox_case}"
            );
            cases += 1;
        }
    }
    // The corpus exercises both answers of each check.
    assert!(cases > 100, "{cases}");
}
