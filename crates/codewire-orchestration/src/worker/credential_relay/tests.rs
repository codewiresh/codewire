use super::*;
use codewire_daemon_proto::CREDENTIAL_RELAY_SERVICE_ACCOUNT;

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
            false,
        )
    };
    assert_eq!(
        live_from_row(row(environment, 3, "pod")),
        Some(Live {
            target: Target {
                environment_id: Uuid::parse_str(environment).unwrap(),
                pod_uid: "pod-a".into(),
                generation: 3,
                scope: WorkspaceCredentialScope::Pod,
            },
            admissible: false,
        })
    );
    assert_eq!(
        live_from_row(row(environment, 3, "environment")).map(|live| live.target.scope),
        Some(WorkspaceCredentialScope::Environment)
    );
    for invalid in [
        row("not-a-uuid", 3, "pod"),
        row(environment, 0, "pod"),
        row(environment, -1, "pod"),
        row(environment, 3, "node"),
    ] {
        assert_eq!(live_from_row(invalid), None);
    }
}

/// No relay of this configuration reaches the network: its daemon endpoint
/// does not parse, so each admitted epoch ends before a connection.
fn config() -> Arc<RelayConfig> {
    Arc::new(RelayConfig {
        namespace: "not a namespace".into(),
        session_secret: Zeroizing::new("synthetic-relay-session-secret".into()),
        relay_token: PathBuf::from("/nonexistent/relay-token"),
        broker: BrokerEndpoint::Preconfigured(
            tonic::transport::Endpoint::from_static("http://127.0.0.1:9").connect_lazy(),
        ),
        limits: Limits::DEFAULT,
    })
}

fn live(environment: u128, admissible: bool) -> Live {
    Live {
        target: target(environment, "6f1d1e9a-0b1c-4a52-9a4e-2c1f0000000a", 3),
        admissible,
    }
}

/// A relay starts at its binding but is told when its environment becomes
/// running; a notification pass over one environment leaves the others alone.
#[tokio::test]
async fn a_pass_tells_each_relay_whether_the_broker_can_admit_it() {
    let config = config();
    let mut relays = Relays::default();
    relays.reconcile(&config, &[live(1, false), live(2, false)], None);
    let admission = relays.running[&Uuid::from_u128(1)].admissible.subscribe();
    assert!(!*admission.borrow());
    // Not yet running: its log lines are worth a pass, as are those of an
    // environment with no relay yet.
    assert!(relays.awaits(Uuid::from_u128(1)));
    assert!(relays.awaits(Uuid::from_u128(3)));

    // A pass for environment 1 alone: it is running now, 2 is untouched.
    relays.reconcile(&config, &[live(1, true)], Some(Uuid::from_u128(1)));
    assert!(*admission.borrow());
    assert!(!relays.awaits(Uuid::from_u128(1)));
    assert!(relays.awaits(Uuid::from_u128(2)));
    assert_eq!(relays.running.len(), 2);

    // That environment's binding released: only its relay stops.
    relays.reconcile(&config, &[], Some(Uuid::from_u128(1)));
    assert_eq!(
        relays.running.keys().copied().collect::<Vec<_>>(),
        [Uuid::from_u128(2)]
    );
    relays.stop_all();
    for (_, task) in relays.stopping.drain() {
        tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .expect("a stopped relay ends")
            .unwrap();
    }
}

/// The orchestration Deployment mounts exactly the relay identity and broker
/// trust this module reads.
#[test]
fn the_deployment_mounts_the_relay_identity_and_broker_trust() {
    use codewire_daemon_proto::{
        CREDENTIAL_RELAY_TOKEN_AUDIENCE, CREDENTIAL_RELAY_TOKEN_EXPIRATION_SECONDS,
        CREDENTIAL_RELAY_TOKEN_MOUNT_PATH,
    };
    let manifest = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deployments/k8s/orchestration/deployment.yaml"
    ))
    .expect("orchestration Deployment");
    let deployment: serde_json::Value = serde_saphyr::from_multiple::<serde_json::Value>(&manifest)
        .unwrap()
        .into_iter()
        .find(|document| document["kind"] == "Deployment")
        .expect("one Deployment");
    let spec = &deployment["spec"]["template"]["spec"];
    assert_eq!(spec["serviceAccountName"], CREDENTIAL_RELAY_SERVICE_ACCOUNT);
    let volume = |name: &str| {
        spec["volumes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|volume| volume["name"] == name)
            .unwrap_or_else(|| panic!("volume {name}"))
            .clone()
    };
    let mount = |name: &str| {
        spec["containers"][0]["volumeMounts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|mount| mount["name"] == name)
            .unwrap_or_else(|| panic!("mount {name}"))
            .clone()
    };
    let identity = volume("credential-relay-identity");
    let sources = identity["projected"]["sources"].as_array().unwrap();
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
