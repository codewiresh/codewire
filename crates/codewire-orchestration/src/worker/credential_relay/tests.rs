use super::*;
use codewire_gateway_proto::CREDENTIAL_RELAY_SERVICE_ACCOUNT;
use serde::Deserialize;

fn target(environment: u128, pod_uid: &str, generation: u64) -> Target {
    Target {
        environment_id: Uuid::from_u128(environment),
        pod_uid: pod_uid.to_owned(),
        generation,
        scope: WorkspaceCredentialScope::Pod,
    }
}

#[test]
fn a_pass_starts_new_bindings_and_keeps_unchanged_relays() {
    let running = [target(1, "pod-a", 3)];
    let desired = [target(1, "pod-a", 3), target(2, "pod-b", 1)];
    assert_eq!(
        plan(running.iter(), &desired),
        Plan {
            stop: Vec::new(),
            start: vec![target(2, "pod-b", 1)],
        }
    );
    assert_eq!(plan(desired.iter(), &desired), Plan::default());
}

#[test]
fn a_released_binding_stops_its_relay() {
    let running = [target(1, "pod-a", 3), target(2, "pod-b", 1)];
    assert_eq!(
        plan(running.iter(), &[target(2, "pod-b", 1)]),
        Plan {
            stop: vec![Uuid::from_u128(1)],
            start: Vec::new(),
        }
    );
    let all = plan(running.iter(), &[]);
    assert_eq!(all.stop, [Uuid::from_u128(1), Uuid::from_u128(2)]);
    assert!(all.start.is_empty());
}

#[test]
fn a_replaced_pod_generation_or_scope_is_a_new_relay() {
    let current = target(1, "pod-a", 3);
    let mut environment_scope = current.clone();
    environment_scope.scope = WorkspaceCredentialScope::Environment;
    for changed in [
        target(1, "pod-b", 3),
        target(1, "pod-a", 4),
        environment_scope,
    ] {
        assert_eq!(
            plan([current.clone()].iter(), std::slice::from_ref(&changed)),
            Plan {
                stop: vec![Uuid::from_u128(1)],
                start: vec![changed],
            }
        );
    }
}

#[test]
fn only_a_canonical_live_binding_is_a_target() {
    let environment = "6f1d1e9a-0b1c-4a52-9a4e-2c1f00000001";
    let row = |environment: &str, generation: i64, scope: &str| {
        (
            environment.to_owned(),
            "pod-a".to_owned(),
            generation,
            scope.to_owned(),
        )
    };
    assert_eq!(
        target_from_row(row(environment, 3, "pod")),
        Some(Target {
            environment_id: Uuid::parse_str(environment).unwrap(),
            pod_uid: "pod-a".into(),
            generation: 3,
            scope: WorkspaceCredentialScope::Pod,
        })
    );
    assert_eq!(
        target_from_row(row(environment, 3, "environment")).map(|target| target.scope),
        Some(WorkspaceCredentialScope::Environment)
    );
    for invalid in [
        row("not-a-uuid", 3, "pod"),
        row(environment, 0, "pod"),
        row(environment, -1, "pod"),
        row(environment, 3, "node"),
    ] {
        assert_eq!(target_from_row(invalid), None);
    }
}

/// The orchestration Deployment mounts exactly the relay identity and broker
/// trust this module reads.
#[test]
fn the_deployment_mounts_the_relay_identity_and_broker_trust() {
    use codewire_gateway_proto::{
        CREDENTIAL_RELAY_TOKEN_AUDIENCE, CREDENTIAL_RELAY_TOKEN_EXPIRATION_SECONDS,
        CREDENTIAL_RELAY_TOKEN_MOUNT_PATH,
    };
    let manifest = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deployments/k8s/orchestration/deployment.yaml"
    ))
    .expect("orchestration Deployment");
    let deployment: serde_yaml::Value = serde_yaml::Deserializer::from_str(&manifest)
        .map(|document| serde_yaml::Value::deserialize(document).unwrap())
        .find(|document| document["kind"] == "Deployment")
        .expect("one Deployment");
    let spec = &deployment["spec"]["template"]["spec"];
    assert_eq!(spec["serviceAccountName"], CREDENTIAL_RELAY_SERVICE_ACCOUNT);
    let volume = |name: &str| {
        spec["volumes"]
            .as_sequence()
            .unwrap()
            .iter()
            .find(|volume| volume["name"] == name)
            .unwrap_or_else(|| panic!("volume {name}"))
            .clone()
    };
    let mount = |name: &str| {
        spec["containers"][0]["volumeMounts"]
            .as_sequence()
            .unwrap()
            .iter()
            .find(|mount| mount["name"] == name)
            .unwrap_or_else(|| panic!("mount {name}"))
            .clone()
    };
    let identity = volume("credential-relay-identity");
    let sources = identity["projected"]["sources"].as_sequence().unwrap();
    assert_eq!(sources.len(), 1);
    let token = &sources[0]["serviceAccountToken"];
    assert_eq!(token["audience"], CREDENTIAL_RELAY_TOKEN_AUDIENCE);
    assert_eq!(
        token["expirationSeconds"].as_i64(),
        Some(CREDENTIAL_RELAY_TOKEN_EXPIRATION_SECONDS)
    );
    assert_eq!(
        format!(
            "{}/{}",
            mount("credential-relay-identity")["mountPath"]
                .as_str()
                .unwrap(),
            token["path"].as_str().unwrap()
        ),
        CREDENTIAL_RELAY_TOKEN_PATH
    );
    assert_eq!(
        mount("credential-relay-identity")["mountPath"],
        CREDENTIAL_RELAY_TOKEN_MOUNT_PATH
    );
    assert_eq!(
        volume("credential-broker-roots")["configMap"]["name"],
        "codewire-credential-broker-roots"
    );
    assert_eq!(
        format!(
            "{}/ca.crt",
            mount("credential-broker-roots")["mountPath"]
                .as_str()
                .unwrap()
        ),
        CREDENTIAL_RELAY_BROKER_ROOTS_FILE
    );
    for name in ["credential-relay-identity", "credential-broker-roots"] {
        assert_eq!(mount(name)["readOnly"], true);
    }
}
