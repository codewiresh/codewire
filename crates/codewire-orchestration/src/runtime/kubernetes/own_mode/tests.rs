//! #6070 through the driver: every write to an existing environment renders
//! in its Sandbox's own egress mode, against an in-process API server that
//! keeps what is written.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use serde_json::{Value, json};

use super::*;
use crate::egress::own_mode::{BrokerSettingsAbsent, HostedEgress};
use crate::runtime::kubernetes::rendering::KubernetesRenderConfig;
use crate::runtime::{RuntimeAccess, WorkspaceShape};
use crate::sandbox::template::{
    GatewayPeer, HostedEgressTemplate, RUNTIME_PROFILE_COMMODITY,
    workspace_daemon_network_policy_name,
};

const NAMESPACE: &str = "dev-sandboxes";
const ENV: &str = "8f0c3a52-6b1e-4f0e-9d3b-2a7c41e5d901";
const SANDBOX: &str = "sandbox-8f0c3a52";

fn settings() -> HostedEgressTemplate {
    crate::egress::gateway_check::assume_verified();
    HostedEgressTemplate {
        stream_addr: "10.44.0.89:8089".into(),
        binding_addr: "10.44.0.87:8087".into(),
        fence_revision: "4".into(),
        gateway: GatewayPeer {
            namespace: "gateway-proxies".into(),
            gateway_name: "public".into(),
            gateway_namespace: "gateway".into(),
            port: 10443,
        },
        derp_tls_port: 8443,
        gateway_addr: "10.44.0.43:443".into(),
        derp_addr: "derp.example.test=10.44.0.84:8443".into(),
        cluster_dns_ip: "10.44.0.10".into(),
        udp_relay_peers: Vec::new(),
    }
}

/// A deployment that manages workspace NetworkPolicies, with the switch as
/// given and the broker settings when `broker`.
fn config(enabled: bool, broker: bool) -> KubernetesRenderConfig {
    KubernetesRenderConfig {
        runtime_profile: RUNTIME_PROFILE_COMMODITY.into(),
        server_namespace: "dev".into(),
        workspace_binding_url: "https://binding.dev.svc.cluster.local:8443".into(),
        network_policy_management: "Managed".into(),
        hosted_egress: HostedEgress {
            enabled,
            broker: broker.then(settings),
        },
        ..Default::default()
    }
}

fn intent() -> RenderingIntent {
    RenderingIntent {
        image: crate::sandbox::canonical_workspace_runtime_image().into(),
        template_base: "workspace".into(),
        isolation: crate::runtime::Isolation::Standard,
        dedicated_cpu: false,
        systemd_workspace: false,
        systemd_opted_in: false,
        runtime_profile: "commodity".into(),
        shape: WorkspaceShape {
            cpu_millicores: 1000,
            memory_mib: 4096,
            disk_gib: 10,
        },
        identity: crate::runtime::RenderingIdentity {
            environment_id: ENV.into(),
            organization_id: "org-1".into(),
            operation_generation: 7,
            projection_selection_sha256: None,
            earlier_projection_selection_sha256: Vec::new(),
            managed_credential_clients: Default::default(),
            source_snapshot_id: None,
            confidential_storage_manifest_uri: String::new(),
        },
    }
}

/// The parts of the broker shape a Sandbox's pod template has.
#[derive(Clone, Copy, Debug)]
struct Shape {
    label: bool,
    fence: bool,
    tun: bool,
}

const WHOLE: Shape = Shape {
    label: true,
    fence: true,
    tun: true,
};
const DIRECT: Shape = Shape {
    label: false,
    fence: false,
    tun: false,
};
const HOLLOW: Shape = Shape {
    label: true,
    fence: false,
    tun: false,
};

fn sandbox(shape: Shape) -> Value {
    let mut sandbox = json!({
        "apiVersion": "agents.x-k8s.io/v1beta1", "kind": "Sandbox",
        "metadata": {"name": SANDBOX, "namespace": NAMESPACE, "uid": "4f7a", "resourceVersion": "7"},
        "spec": {"podTemplate": {
            "metadata": {"labels": {"codewire.sh/type": "workspace", "codewire.sh/environment-id": ENV}},
            "spec": {"runtimeClassName": "commodity", "containers": []}}},
    });
    let template = &mut sandbox["spec"]["podTemplate"];
    if shape.label {
        template["metadata"]["labels"]["codewire.sh/egress"] = json!("broker");
    }
    if shape.fence {
        template["metadata"]["annotations"] = json!({"codewire.sh/egress-fence-revision": "4"});
    }
    if shape.tun {
        template["spec"]["initContainers"] = json!([{"name": "hosted-egress-tun"}]);
    }
    sandbox
}

fn claim(bound: bool) -> Value {
    let mut claim = json!({
        "apiVersion": "extensions.agents.x-k8s.io/v1beta1", "kind": "SandboxClaim",
        "metadata": {"name": crate::sandbox::claim_name(ENV), "namespace": NAMESPACE},
    });
    if bound {
        claim["status"] = json!({"sandbox": {"name": SANDBOX}});
    }
    claim
}

/// An API server that keeps objects by path: a GET reads one, a POST to a
/// collection or a PUT stores one, a DELETE removes one. Every write is
/// recorded as its method and path.
#[derive(Clone, Default)]
struct Store {
    objects: Arc<Mutex<BTreeMap<String, Value>>>,
    writes: Arc<Mutex<Vec<String>>>,
}

impl Store {
    fn holding(claim: Value, sandbox: Option<Value>) -> Self {
        let store = Self::default();
        let base = format!("/namespaces/{NAMESPACE}");
        let mut objects = store.objects.lock().unwrap();
        objects.insert(
            format!(
                "/apis/extensions.agents.x-k8s.io/v1beta1{base}/sandboxclaims/{}",
                crate::sandbox::claim_name(ENV)
            ),
            claim,
        );
        if let Some(sandbox) = sandbox {
            objects.insert(
                format!("/apis/agents.x-k8s.io/v1beta1{base}/sandboxes/{SANDBOX}"),
                sandbox,
            );
        }
        drop(objects);
        store
    }

    fn client(&self) -> kube::Client {
        let store = self.clone();
        let service = Router::new().fallback(move |request: Request<Body>| {
            let store = store.clone();
            async move {
                let method = request.method().to_string();
                let path = request.uri().path().to_owned();
                let body = axum::body::to_bytes(request.into_body(), usize::MAX)
                    .await
                    .unwrap();
                let mut objects = store.objects.lock().unwrap();
                let not_found = (
                    StatusCode::NOT_FOUND,
                    json!({"apiVersion": "v1", "kind": "Status",
                        "status": "Failure", "reason": "NotFound", "code": 404}),
                );
                let (status, reply) = match method.as_str() {
                    "GET" => objects
                        .get(&path)
                        .map_or(not_found, |object| (StatusCode::OK, object.clone())),
                    "POST" | "PUT" => {
                        let object: Value = serde_json::from_slice(&body).unwrap();
                        let at = if method == "POST" {
                            format!("{path}/{}", object["metadata"]["name"].as_str().unwrap())
                        } else {
                            path.clone()
                        };
                        store.writes.lock().unwrap().push(format!("{method} {at}"));
                        objects.insert(at, object.clone());
                        (StatusCode::CREATED, object)
                    }
                    "DELETE" => match objects.remove(&path) {
                        Some(object) => {
                            store.writes.lock().unwrap().push(format!("DELETE {path}"));
                            (StatusCode::OK, object)
                        }
                        None => not_found,
                    },
                    _ => not_found,
                };
                Response::builder()
                    .status(status)
                    .header("content-type", "application/json")
                    .body(Body::from(reply.to_string()))
                    .unwrap()
            }
        });
        kube::Client::new(service, "the-default-namespace")
    }

    /// The environment's own NetworkPolicy's spec, as last written.
    fn policy(&self) -> Option<String> {
        let path = format!(
            "/apis/networking.k8s.io/v1/namespaces/{NAMESPACE}/networkpolicies/{}",
            workspace_daemon_network_policy_name(ENV)
        );
        self.objects
            .lock()
            .unwrap()
            .get(&path)
            .map(|policy| policy["spec"].to_string())
    }

    fn writes(&self) -> Vec<String> {
        self.writes.lock().unwrap().clone()
    }
}

fn driver(store: &Store, config: KubernetesRenderConfig) -> KubernetesDriver {
    KubernetesDriver::new(store.client(), config)
}

/// Whether a policy's spec is the broker one: no address range anywhere,
/// where the direct one opens the world by one.
fn broker_rules(spec: &str) -> bool {
    !spec.contains("ipBlock")
}

/// #6070: the running reconcile writes the environment's policy in its
/// Sandbox's own mode across off, on and off again: the same bytes every
/// time, broker for a whole broker Sandbox and direct for a direct or hollow
/// one.
#[tokio::test]
async fn reconciles_across_the_switch_write_the_sandboxs_own_policy_every_time() {
    for (shape, broker) in [(WHOLE, true), (DIRECT, false), (HOLLOW, false)] {
        let store = Store::holding(claim(true), Some(sandbox(shape)));
        let mut written = Vec::new();
        for enabled in [false, true, false, true, false] {
            driver(&store, config(enabled, true))
                .ensure_access(&Placement::new(NAMESPACE), &intent())
                .await
                .unwrap_or_else(|error| panic!("{shape:?} {enabled}: {error:#}"));
            written.push(store.policy().expect("the policy is written"));
        }
        assert!(
            written.iter().all(|policy| policy == &written[0]),
            "{shape:?}: {written:#?}"
        );
        assert_eq!(broker_rules(&written[0]), broker, "{shape:?}");
    }
}

/// The policy is exactly the one the environment renders in that mode, and
/// the one the egress lockdown check expects for a broker guest.
#[tokio::test]
async fn the_written_policy_is_the_sandboxs_own_rendering() {
    let store = Store::holding(claim(true), Some(sandbox(WHOLE)));
    let off = config(false, true);
    driver(&store, off.clone())
        .ensure_access(&Placement::new(NAMESPACE), &intent())
        .await
        .unwrap();
    let expected = off
        .workspace_network_policy(NAMESPACE, ENV, crate::runtime::Isolation::Standard)
        .unwrap();
    assert_eq!(store.policy().unwrap(), expected["spec"].to_string());
}

/// #6070, cw-security's amendment 2: with the broker settings absent, a
/// broker Sandbox is refused by name before anything is written, with the
/// switch off; a direct one is written direct.
#[tokio::test]
async fn without_the_settings_a_broker_sandbox_is_refused_and_nothing_written() {
    let store = Store::holding(claim(true), Some(sandbox(WHOLE)));
    let error = driver(&store, config(false, false))
        .ensure_access(&Placement::new(NAMESPACE), &intent())
        .await
        .unwrap_err();
    assert_eq!(
        error.downcast_ref::<BrokerSettingsAbsent>(),
        Some(&BrokerSettingsAbsent {
            sandbox: SANDBOX.into()
        }),
        "{error:#}"
    );
    assert_eq!(store.writes(), Vec::<String>::new());
    assert_eq!(store.policy(), None);
    let start = driver(&store, config(false, false))
        .render_start(&Placement::new(NAMESPACE), &intent(), None)
        .await
        .unwrap_err();
    assert!(start.downcast_ref::<BrokerSettingsAbsent>().is_some());

    for shape in [DIRECT, HOLLOW] {
        let store = Store::holding(claim(true), Some(sandbox(shape)));
        driver(&store, config(false, false))
            .ensure_access(&Placement::new(NAMESPACE), &intent())
            .await
            .unwrap();
        assert!(!broker_rules(&store.policy().unwrap()), "{shape:?}");
    }
}

/// With no Sandbox bound yet, as on a create whose Claim has not bound, the
/// write is a create's: the switch decides.
#[tokio::test]
async fn before_its_claim_binds_an_environment_renders_as_a_create() {
    for (claim, sandbox) in [
        (claim(false), None),
        (claim(true), None),
        (claim(false), Some(sandbox(WHOLE))),
    ] {
        for enabled in [true, false] {
            let store = Store::holding(claim.clone(), sandbox.clone());
            driver(&store, config(enabled, true))
                .ensure_access(&Placement::new(NAMESPACE), &intent())
                .await
                .unwrap();
            assert_eq!(broker_rules(&store.policy().unwrap()), enabled);
        }
    }
}

/// A start's bootstrap refresh renders create's options while the switch is
/// on, so a Sandbox made before it moves, and the Sandbox's own while it is
/// off, so a broker one never moves back to direct.
#[tokio::test]
async fn a_start_renders_create_with_the_switch_on_and_its_own_mode_off() {
    for (shape, enabled, broker) in [
        (DIRECT, true, true),
        (HOLLOW, true, true),
        (WHOLE, true, true),
        (WHOLE, false, true),
        (DIRECT, false, false),
        (HOLLOW, false, false),
    ] {
        let store = Store::holding(claim(true), Some(sandbox(shape)));
        let opts = driver(&store, config(enabled, true))
            .render_start(&Placement::new(NAMESPACE), &intent(), None)
            .await
            .unwrap();
        assert_eq!(
            opts.hosted_egress,
            broker.then(settings),
            "{shape:?} {enabled}"
        );
        assert_eq!(store.writes(), Vec::<String>::new());
    }
}
