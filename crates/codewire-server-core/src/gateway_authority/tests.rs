use std::collections::BTreeMap;

use k8s_openapi::api::apps::v1::DeploymentSpec;
use k8s_openapi::api::core::v1::PodTemplateSpec;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{OwnerReference, Time};

use super::*;

const NAMESPACE: &str = "runtime";
const ENVIRONMENT_ID: &str = "550e8400-e29b-41d4-a716-446655440000";
const OTHER_ENVIRONMENT_ID: &str = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
const ORGANIZATION_ID: &str = "org-chain";
const POD_UID: &str = "7e7b20f6-0bd2-4f11-8b16-9c239851eb52";
const REPLICA_SET_UID: &str = "3f2b1c0d-1111-4a2b-8c3d-4e5f6a7b8c9d";
const DEPLOYMENT_UID: &str = "9d8c7b6a-2222-4f5e-8d4c-3b2a1f0e9d8c";
const GENERATION: i64 = 4;

fn deployment_name() -> String {
    format!("cw-gateway-{ENVIRONMENT_ID}")
}

fn labels(generation: i64) -> BTreeMap<String, String> {
    BTreeMap::from([
        (ENVIRONMENT_LABEL.into(), ENVIRONMENT_ID.into()),
        (ORGANIZATION_LABEL.into(), ORGANIZATION_ID.into()),
        (TYPE_LABEL.into(), "gateway".into()),
        (OPERATION_GENERATION_LABEL.into(), generation.to_string()),
    ])
}

fn owner(kind: &str, name: &str, uid: &str) -> OwnerReference {
    OwnerReference {
        api_version: "apps/v1".into(),
        kind: kind.into(),
        name: name.into(),
        uid: uid.into(),
        controller: Some(true),
        ..Default::default()
    }
}

fn metadata(name: &str, uid: &str, labels: BTreeMap<String, String>) -> ObjectMeta {
    ObjectMeta {
        name: Some(name.into()),
        namespace: Some(NAMESPACE.into()),
        uid: Some(uid.into()),
        labels: Some(labels),
        ..Default::default()
    }
}

/// Environment A's `cw-gateway-<env>` chain, every label set at `GENERATION`.
fn gateway_objects(deployment_name: &str) -> (Pod, ReplicaSet, Deployment) {
    let mut pod = Pod {
        metadata: metadata("gateway-pod", POD_UID, labels(GENERATION)),
        ..Default::default()
    };
    pod.metadata.owner_references = Some(vec![owner("ReplicaSet", "gateway-rs", REPLICA_SET_UID)]);
    let mut replica_set = ReplicaSet {
        metadata: metadata("gateway-rs", REPLICA_SET_UID, labels(GENERATION)),
        ..Default::default()
    };
    replica_set.metadata.owner_references =
        Some(vec![owner("Deployment", deployment_name, DEPLOYMENT_UID)]);
    let deployment = Deployment {
        metadata: metadata(deployment_name, DEPLOYMENT_UID, labels(GENERATION)),
        spec: Some(DeploymentSpec {
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta {
                    labels: Some(labels(GENERATION)),
                    ..Default::default()
                }),
                spec: None,
            },
            ..Default::default()
        }),
        // Availability is never part of the rule: the daemon-credential path
        // must serve a gateway before it is available.
        status: None,
    };
    (pod, replica_set, deployment)
}

fn environment() -> GatewayEnvironment {
    GatewayEnvironment {
        environment_id: ENVIRONMENT_ID.into(),
        organization_id: ORGANIZATION_ID.into(),
        operation_generation: GENERATION,
        namespace: NAMESPACE.into(),
    }
}

fn decide(
    objects: &(Pod, ReplicaSet, Deployment),
    environment: &GatewayEnvironment,
) -> Result<(), GatewayDenied> {
    let chain = GatewayChain::verify(NAMESPACE, &objects.0, &objects.1, &objects.2)
        .expect("verified chain");
    authorize(&chain, environment)
}

#[test]
fn the_chain_is_matched_by_uid_from_pod_to_deployment() {
    let (pod, replica_set, deployment) = gateway_objects(&deployment_name());
    assert!(GatewayChain::verify(NAMESPACE, &pod, &replica_set, &deployment).is_some());
    assert_eq!(
        GatewayChain::controlling_replica_set(&pod),
        Some("gateway-rs")
    );
    assert_eq!(
        GatewayChain::controlling_deployment(&replica_set),
        Some(deployment_name().as_str())
    );

    let verify = |pod: &Pod, replica_set: &ReplicaSet, deployment: &Deployment| {
        GatewayChain::verify(NAMESPACE, pod, replica_set, deployment).is_some()
    };
    // A foreign ReplicaSet: the Pod's controller UID is not the live one.
    let mut foreign = replica_set.clone();
    foreign.metadata.uid = Some("0a1b2c3d-3333-4e5f-8a9b-0c1d2e3f4a5b".into());
    assert!(!verify(&pod, &foreign, &deployment));
    // A ReplicaSet controlled by another Deployment.
    let mut elsewhere = replica_set.clone();
    elsewhere.metadata.owner_references = Some(vec![owner(
        "Deployment",
        &format!("cw-gateway-{OTHER_ENVIRONMENT_ID}"),
        DEPLOYMENT_UID,
    )]);
    assert!(!verify(&pod, &elsewhere, &deployment));
    // A Deployment replaced under the same name.
    let mut replaced = deployment.clone();
    replaced.metadata.uid = Some("0a1b2c3d-4444-4e5f-8a9b-0c1d2e3f4a5b".into());
    assert!(!verify(&pod, &replica_set, &replaced));
    // A hand-made Pod without a ReplicaSet controller, an orphan ReplicaSet,
    // and two controllers.
    let mut hand_made = pod.clone();
    hand_made.metadata.owner_references = None;
    assert!(!verify(&hand_made, &replica_set, &deployment));
    let mut orphan = replica_set.clone();
    orphan.metadata.owner_references = None;
    assert!(!verify(&pod, &orphan, &deployment));
    let mut two = replica_set.clone();
    two.metadata.owner_references.as_mut().unwrap().push(owner(
        "Deployment",
        "other",
        REPLICA_SET_UID,
    ));
    assert!(!verify(&pod, &two, &deployment));
    // A non-controller owner and a controller of another kind.
    let mut not_controller = pod.clone();
    not_controller.metadata.owner_references.as_mut().unwrap()[0].controller = Some(false);
    assert!(!verify(&not_controller, &replica_set, &deployment));
    let mut stateful = pod.clone();
    stateful.metadata.owner_references.as_mut().unwrap()[0].kind = "StatefulSet".into();
    assert!(!verify(&stateful, &replica_set, &deployment));
    // Terminating members, and any member in another namespace.
    let now = || Some(Time(k8s_openapi::jiff::Timestamp::now()));
    let mut terminating = pod.clone();
    terminating.metadata.deletion_timestamp = now();
    assert!(!verify(&terminating, &replica_set, &deployment));
    let mut terminating = replica_set.clone();
    terminating.metadata.deletion_timestamp = now();
    assert!(!verify(&pod, &terminating, &deployment));
    let mut terminating = deployment.clone();
    terminating.metadata.deletion_timestamp = now();
    assert!(!verify(&pod, &replica_set, &terminating));
    let mut moved = deployment.clone();
    moved.metadata.namespace = Some("other".into());
    assert!(!verify(&pod, &replica_set, &moved));
    // A non-canonical UID never chains.
    let mut uppercase = deployment.clone();
    uppercase.metadata.uid = Some(DEPLOYMENT_UID.to_ascii_uppercase());
    assert!(!verify(&pod, &replica_set, &uppercase));
}

#[test]
fn the_environment_gateway_deployment_with_current_labels_is_authorized() {
    let objects = gateway_objects(&deployment_name());
    assert_eq!(decide(&objects, &environment()), Ok(()));
    assert_eq!(
        labelled_environment(&objects.0).as_deref(),
        Some(ENVIRONMENT_ID)
    );

    // Each of the four label sets must carry the environment, organization,
    // gateway role and current generation.
    let stale = labels(GENERATION - 1);
    let mut other_org = labels(GENERATION);
    other_org.insert(ORGANIZATION_LABEL.into(), "org-other".into());
    let mut workspace_role = labels(GENERATION);
    workspace_role.insert(TYPE_LABEL.into(), "workspace".into());
    let mut other_environment = labels(GENERATION);
    other_environment.insert(ENVIRONMENT_LABEL.into(), OTHER_ENVIRONMENT_ID.into());
    for wrong in [stale, other_org, workspace_role, other_environment] {
        for member in 0..4 {
            let mut objects = gateway_objects(&deployment_name());
            match member {
                0 => objects.0.metadata.labels = Some(wrong.clone()),
                1 => objects.1.metadata.labels = Some(wrong.clone()),
                2 => objects.2.metadata.labels = Some(wrong.clone()),
                _ => {
                    objects.2.spec.as_mut().unwrap().template.metadata = Some(ObjectMeta {
                        labels: Some(wrong.clone()),
                        ..Default::default()
                    })
                }
            }
            assert_eq!(
                decide(&objects, &environment()),
                Err(GatewayDenied),
                "member {member}: {wrong:?}"
            );
        }
    }
    // The Deployment must be this environment's cw-gateway-<env>.
    for name in [
        "cw-gateway-impostor".to_owned(),
        format!("cw-gateway-{OTHER_ENVIRONMENT_ID}"),
    ] {
        assert_eq!(
            decide(&gateway_objects(&name), &environment()),
            Err(GatewayDenied),
            "{name}"
        );
    }
    // A generation of zero is never served, and the namespace must match.
    let mut unborn = environment();
    unborn.operation_generation = 0;
    assert_eq!(decide(&objects, &unborn), Err(GatewayDenied));
    let mut elsewhere = environment();
    elsewhere.namespace = "other".into();
    assert_eq!(decide(&objects, &elsewhere), Err(GatewayDenied));
}

#[test]
fn the_label_environment_must_be_a_canonical_gateway_label() {
    let (mut pod, _, _) = gateway_objects(&deployment_name());
    pod.metadata
        .labels
        .as_mut()
        .unwrap()
        .insert(TYPE_LABEL.into(), "workspace".into());
    assert_eq!(labelled_environment(&pod), None);
    let (mut pod, _, _) = gateway_objects(&deployment_name());
    pod.metadata.labels.as_mut().unwrap().insert(
        ENVIRONMENT_LABEL.into(),
        ENVIRONMENT_ID.to_ascii_uppercase(),
    );
    assert_eq!(labelled_environment(&pod), None);
    let (mut pod, _, _) = gateway_objects(&deployment_name());
    pod.metadata
        .labels
        .as_mut()
        .unwrap()
        .remove(ENVIRONMENT_LABEL);
    assert_eq!(labelled_environment(&pod), None);
}
