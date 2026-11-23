use serde_json::json;

use super::*;
use crate::egress::admission::{EGRESS_MODE_BROKER, EGRESS_MODE_LABEL};
use crate::sandbox::template::{
    GatewayPeer, HOSTED_EGRESS_FENCE_REVISION_ANNOTATION, HOSTED_EGRESS_TUN_CONTAINER,
};

fn settings() -> HostedEgressTemplate {
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
    }
}

/// A Sandbox with the broker label, the fence annotation and the TUN init
/// as asked.
fn sandbox(label: bool, fence: bool, tun: bool) -> Value {
    let mut template = json!({
        "metadata": {"labels": {"codewire.sh/type": "workspace"}},
        "spec": {"runtimeClassName": "commodity", "containers": []},
    });
    if label {
        template["metadata"]["labels"][EGRESS_MODE_LABEL] = json!(EGRESS_MODE_BROKER);
    }
    if fence {
        template["metadata"]["annotations"] = json!({HOSTED_EGRESS_FENCE_REVISION_ANNOTATION: "4"});
    }
    if tun {
        template["spec"]["initContainers"] = json!([{"name": HOSTED_EGRESS_TUN_CONTAINER}]);
    }
    json!({
        "apiVersion": "agents.x-k8s.io/v1beta1", "kind": "Sandbox",
        "metadata": {"name": "sandbox-a", "namespace": "dev-sandboxes"},
        "spec": {"podTemplate": template},
    })
}

fn whole() -> Value {
    sandbox(true, true, true)
}

fn direct() -> Value {
    sandbox(false, false, false)
}

fn hollow() -> Value {
    sandbox(true, false, false)
}

#[test]
fn the_switch_decides_only_what_a_create_renders() {
    assert_eq!(HostedEgress::on(settings()).create(), Some(&settings()));
    let off = HostedEgress {
        enabled: false,
        broker: Some(settings()),
    };
    assert_eq!(off.create(), None);
    assert_eq!(HostedEgress::default().create(), None);
}

/// #6070: an existing Sandbox renders in its own mode with the switch on or
/// off. The broker label alone is direct.
#[test]
fn an_existing_sandbox_renders_in_its_own_mode_whatever_the_switch_says() {
    for enabled in [true, false] {
        let egress = HostedEgress {
            enabled,
            broker: Some(settings()),
        };
        let mode = |object: &Value| SandboxMode::of("sandbox-a", object);
        assert_eq!(egress.existing(&mode(&whole())), Ok(Some(&settings())));
        assert_eq!(egress.existing(&mode(&direct())), Ok(None), "{enabled}");
        for (index, hollow) in [
            hollow(),
            sandbox(true, true, false),
            sandbox(true, false, true),
            sandbox(false, true, true),
        ]
        .iter()
        .enumerate()
        {
            assert!(!mode(hollow).broker, "hollow {index}");
            assert_eq!(egress.existing(&mode(hollow)), Ok(None), "hollow {index}");
        }
    }
}

/// #6070, cw-security's amendment 2: without the settings a broker Sandbox
/// is refused by name, never rendered direct; a direct one is unaffected.
#[test]
fn without_the_settings_a_broker_sandbox_is_refused_never_rendered_direct() {
    let absent = HostedEgress::default();
    let refusal = absent
        .existing(&SandboxMode::of("sandbox-a", &whole()))
        .unwrap_err();
    assert_eq!(
        refusal,
        BrokerSettingsAbsent {
            sandbox: "sandbox-a".into()
        }
    );
    assert!(
        refusal
            .to_string()
            .contains("can't run until hosted egress is restored"),
        "{refusal}"
    );
    assert_eq!(
        absent.existing(&SandboxMode::of("sandbox-a", &direct())),
        Ok(None)
    );
    assert_eq!(
        absent.existing(&SandboxMode::of("sandbox-a", &hollow())),
        Ok(None)
    );
}

fn objects(sandboxes: &[Value]) -> Vec<DynamicObject> {
    sandboxes
        .iter()
        .map(|sandbox| serde_json::from_value(sandbox.clone()).unwrap())
        .collect()
}

#[test]
fn only_a_whole_broker_sandbox_counts_as_stranded() {
    assert_eq!(
        broker_sandboxes(&objects(&[whole(), direct(), hollow(), whole()])),
        2
    );
    assert_eq!(broker_sandboxes(&[]), 0);
}

/// An API server that lists `sandboxes` in `dev-sandboxes`, or fails.
fn client(sandboxes: Option<Vec<Value>>) -> kube::Client {
    let service = tower::service_fn(move |request: axum::http::Request<kube::client::Body>| {
        let sandboxes = sandboxes.clone();
        async move {
            assert_eq!(
                request.uri().path(),
                "/apis/agents.x-k8s.io/v1beta1/namespaces/dev-sandboxes/sandboxes"
            );
            let (status, body) = match sandboxes {
                Some(items) => (
                    200,
                    json!({"apiVersion": "agents.x-k8s.io/v1beta1", "kind": "SandboxList", "metadata": {}, "items": items}),
                ),
                None => (
                    500,
                    json!({"apiVersion": "v1", "kind": "Status", "status": "Failure", "code": 500}),
                ),
            };
            Ok::<_, std::convert::Infallible>(
                axum::http::Response::builder()
                    .status(status)
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(body.to_string()))
                    .unwrap(),
            )
        }
    });
    kube::Client::new(service, "dev")
}

/// The count is one gauge for the whole process, so one test owns it.
#[tokio::test]
async fn startup_counts_the_broker_sandboxes_the_absent_settings_strand() {
    report_stranded(
        client(Some(vec![whole(), direct(), hollow(), whole()])),
        "dev-sandboxes",
    )
    .await;
    assert_eq!(stranded(), 2);
    // A read that fails counts nothing new.
    report_stranded(client(None), "dev-sandboxes").await;
    assert_eq!(stranded(), 2);
    report_stranded(client(Some(vec![direct()])), "dev-sandboxes").await;
    assert_eq!(stranded(), 0);
}
