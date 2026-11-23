//! A start's move of a Sandbox made before hosted egress (#4000), against a
//! synthetic API server that stores what it is sent and applies the JSON
//! Patch operations the client emits.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, Response, StatusCode};
use serde_json::{Value, json};

use super::super::super::template::{
    CredentialRuntimeTemplateConfig, GatewayPeer, HostedEgressTemplate, RUNTIME_PROFILE_COMMODITY,
    render_template_network_policy,
};
use super::*;

const NS: &str = "dev-sandboxes";
const ENV: &str = "4b0d7d98-d965-4070-ae2b-04c98bde5cb7";
const ORG: &str = "org-move-fixture";
const CLAIM_UID: &str = "claim-incarnation";
const SANDBOX: &str = "workspace-moved";
const POD: &str = "workspace-moved-pod";
const DAEMON_IMAGE: &str = "registry.example.invalid/codewire/daemon@sha256:48549d19114407c712d043af3ba2136d97052a2c30c82935190f75a3a61f13ab";
/// What the controller and the claim's adoption put on a Sandbox's pod
/// template beside the render: the identity fields a Sandbox keeps.
const TEMPLATE_REF_HASH: &str = "agents.x-k8s.io/sandbox-template-ref-hash";
const CLAIM_UID_LABEL: &str = "agents.x-k8s.io/claim-uid";
/// The shared pool a pool-born environment was adopted from before the
/// switch, and so the template its Sandbox was built from.
const POOL: &str = "cw-pool-2000m-4096mi-40gi-3c6b81b3";

fn egress() -> HostedEgressTemplate {
    HostedEgressTemplate {
        stream_addr: "10.44.0.89:8089".into(),
        binding_addr: "10.44.0.87:8087".into(),
        fence_revision: "2".into(),
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

/// The environment as the deployment renders it with hosted egress `on`.
fn opts(on: bool) -> TemplateOpts {
    TemplateOpts {
        name: format!("workspace-{ENV}"),
        image: "ghcr.io/codewiresh/workspace:fixture".into(),
        support_image: DAEMON_IMAGE.into(),
        runtime_profile: RUNTIME_PROFILE_COMMODITY.into(),
        environment_id: ENV.into(),
        organization_id: ORG.into(),
        operation_generation: 7,
        server_namespace: "dev".into(),
        cpu_millicores: 2000,
        memory_mib: 4096,
        disk_gib: 40,
        workspace_storage_class: "local-path".into(),
        projection_selection_sha256: Some([0xab; 32]),
        credential_runtime: Some(CredentialRuntimeTemplateConfig::synthetic(NS)),
        workspace_binding_url:
            "https://codewire-orchestration-workspace-binding.dev.svc.cluster.local:8087".into(),
        hosted_egress: on.then(egress),
        ..Default::default()
    }
}

fn identity() -> WorkspaceSandboxIdentity {
    WorkspaceSandboxIdentity::synthetic(SANDBOX, "sandbox-incarnation")
}

fn mount_state(spec: &Value) -> &Value {
    &spec["initContainers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|init| init["name"] == MOUNT_WORKSPACE_CONTAINER)
        .expect("a Block workspace mounts in mount-workspace")["command"][4]
}

/// One environment made while hosted egress was off and stopped since: its
/// claim, environment shadow, template and suspended Sandbox, as a create
/// rendered them then, with no Pod. Its workspace volume was mounted, so the
/// Sandbox records it `existing`.
fn objects() -> BTreeMap<String, Value> {
    let opts = opts(false);
    let claim = claim_name(ENV);
    let shadow = super::super::super::shadow_warm_pool_name(&opts.name);
    let rendered = render_sandbox_template(NS, &opts);
    let mut pool = render_sandbox_shadow_pool(NS, &shadow, &opts.name, ENV);
    pool["metadata"]["uid"] = json!("pool-incarnation");
    let mut template = rendered.clone();
    template["metadata"]["uid"] = json!("template-incarnation");
    template["metadata"]["resourceVersion"] = json!("20");
    let mut pod_template = rendered["spec"]["podTemplate"].clone();
    for (key, value) in runtime_identity_labels(ENV, ORG, 6, "workspace") {
        pod_template["metadata"]["labels"][key] = json!(value);
    }
    pod_template["metadata"]["labels"][TEMPLATE_REF_HASH] = json!(sandbox_name_hash(&opts.name));
    pod_template["metadata"]["labels"][CLAIM_UID_LABEL] = json!(CLAIM_UID);
    let index = pod_template["spec"]["initContainers"]
        .as_array()
        .unwrap()
        .iter()
        .position(|init| init["name"] == MOUNT_WORKSPACE_CONTAINER)
        .unwrap();
    pod_template["spec"]["initContainers"][index]["command"][4] =
        json!(WorkspaceVolume::Existing.argument());
    let sandbox = json!({"apiVersion": "agents.x-k8s.io/v1beta1", "kind": "Sandbox",
        "metadata": {"name": SANDBOX, "namespace": NS, "uid": "sandbox-incarnation",
            "resourceVersion": "30", "generation": 9,
            "annotations": {"agents.x-k8s.io/pod-name": POD},
            "labels": {TEMPLATE_REF_HASH: sandbox_name_hash(&opts.name),
                "agents.x-k8s.io/launch-type": "cold"},
            "ownerReferences": [{"apiVersion": super::super::super::EXTENSIONS_API_VERSION,
                "kind": "SandboxClaim", "name": claim, "uid": CLAIM_UID, "controller": true}]},
        "spec": {"operatingMode": "Suspended", "podTemplate": pod_template,
            "volumeClaimTemplates": rendered["spec"]["volumeClaimTemplates"]},
        "status": {"conditions": [{"type": "Suspended", "status": "True",
            "reason": "PodTerminated", "observedGeneration": 9}]}});
    let claim_object = json!({"apiVersion": super::super::super::EXTENSIONS_API_VERSION,
        "kind": "SandboxClaim",
        "metadata": {"name": claim, "namespace": NS, "uid": CLAIM_UID, "resourceVersion": "10",
            "labels": runtime_identity_labels(ENV, ORG, 6, "sandbox")},
        "spec": {"warmPoolRef": {"name": shadow},
            "additionalPodMetadata": {"labels": runtime_identity_labels(ENV, ORG, 6, "workspace")}},
        "status": {"sandbox": {"name": SANDBOX}}});
    let extensions = format!("/apis/extensions.agents.x-k8s.io/v1beta1/namespaces/{NS}");
    BTreeMap::from([
        (format!("{extensions}/sandboxclaims/{claim}"), claim_object),
        (format!("{extensions}/sandboxwarmpools/{shadow}"), pool),
        (
            format!("{extensions}/sandboxtemplates/{}", opts.name),
            template,
        ),
        (sandbox_path(), sandbox),
    ])
}

fn extensions_path(kind: &str, name: &str) -> String {
    format!("/apis/extensions.agents.x-k8s.io/v1beta1/namespaces/{NS}/{kind}/{name}")
}

/// The same environment adopted from a shared pool before the switch, the
/// only kind Dev has: its Claim names the pool, whose template, identity-free
/// and direct, is the one its Sandbox was built from and is labelled with,
/// and it has no template of its own.
fn pool_born_objects() -> BTreeMap<String, Value> {
    let mut objects = objects();
    let opts = opts(false);
    let shadow = super::super::super::shadow_warm_pool_name(&opts.name);
    objects.remove(&extensions_path("sandboxwarmpools", &shadow));
    objects.remove(&extensions_path("sandboxtemplates", &opts.name));
    let pool_labels = json!({"app.kubernetes.io/managed-by": "codewire",
        "codewire.sh/type": "workspace-pool"});
    let mut template = render_sandbox_template(
        NS,
        &TemplateOpts {
            name: POOL.into(),
            ..opts.clone()
        },
    );
    template["metadata"]["labels"] = pool_labels.clone();
    template["metadata"]["uid"] = json!("pool-template-incarnation");
    template["metadata"]["resourceVersion"] = json!("40");
    let pool = json!({"apiVersion": super::super::super::EXTENSIONS_API_VERSION,
        "kind": "SandboxWarmPool",
        "metadata": {"name": POOL, "namespace": NS, "uid": "shared-pool-incarnation",
            "resourceVersion": "41", "labels": pool_labels},
        "spec": {"sandboxTemplateRef": {"name": POOL}, "replicas": 2}});
    objects.insert(extensions_path("sandboxtemplates", POOL), template);
    objects.insert(extensions_path("sandboxwarmpools", POOL), pool);
    objects
        .get_mut(&extensions_path("sandboxclaims", &claim_name(ENV)))
        .unwrap()["spec"]["warmPoolRef"]["name"] = json!(POOL);
    let sandbox = objects.get_mut(&sandbox_path()).unwrap();
    sandbox["metadata"]["labels"][TEMPLATE_REF_HASH] = json!(sandbox_name_hash(POOL));
    sandbox["metadata"]["labels"]["agents.x-k8s.io/launch-type"] = json!("warm");
    sandbox["spec"]["podTemplate"]["metadata"]["labels"][TEMPLATE_REF_HASH] =
        json!(sandbox_name_hash(POOL));
    objects
}

/// The labels the controller gives the Pod it builds from `sandbox` (the
/// fork's `controllers/sandbox_controller.go`, `reconcilePod` and
/// `computeExtensionPodLabels`): the pod template's own labels but its
/// reserved ones, and the template reference from the Sandbox's labels.
fn controller_pod_labels(sandbox: &Value) -> BTreeMap<String, String> {
    let mut labels: BTreeMap<String, String> = sandbox["spec"]["podTemplate"]["metadata"]["labels"]
        .as_object()
        .unwrap()
        .iter()
        .filter(|(key, _)| !key.starts_with("agents.x-k8s.io/"))
        .map(|(key, value)| (key.clone(), value.as_str().unwrap().to_owned()))
        .collect();
    if let Some(hash) = sandbox["metadata"]["labels"][TEMPLATE_REF_HASH].as_str() {
        labels.insert(TEMPLATE_REF_HASH.into(), hash.into());
    }
    labels
}

fn sandbox_path() -> String {
    format!("/apis/agents.x-k8s.io/v1beta1/namespaces/{NS}/sandboxes/{SANDBOX}")
}

fn pod_path() -> String {
    format!("/api/v1/namespaces/{NS}/pods/{POD}")
}

#[derive(Default)]
struct Server {
    objects: BTreeMap<String, Value>,
    /// Each write, in order: its method, path and body.
    writes: Vec<(Method, String, Value)>,
    /// A write to a path ending this way is refused, as admission would.
    deny: Option<&'static str>,
}

fn status(code: StatusCode, reason: &str) -> (StatusCode, Value) {
    (
        code,
        json!({"apiVersion": "v1", "kind": "Status", "status": "Failure", "reason": reason,
            "code": code.as_u16()}),
    )
}

/// Only the operations the client emits, on a clone, so a failed `test`
/// leaves nothing half-written.
fn apply(object: &Value, patch: &Value) -> Option<Value> {
    let mut next = object.clone();
    for operation in patch.as_array()? {
        let path = operation["path"].as_str()?;
        if operation["op"] == "test" {
            if next.pointer(path) != Some(&operation["value"]) {
                return None;
            }
            continue;
        }
        let (parent, key) = path.rsplit_once('/')?;
        let key = key.replace("~1", "/").replace("~0", "~");
        let parent = next.pointer_mut(parent)?;
        match (operation["op"].as_str()?, parent) {
            ("replace", Value::Array(values)) => {
                *values.get_mut(key.parse::<usize>().ok()?)? = operation["value"].clone();
            }
            ("replace", Value::Object(values)) => {
                *values.get_mut(&key)? = operation["value"].clone();
            }
            ("add", Value::Object(values)) => {
                values.insert(key, operation["value"].clone());
            }
            _ => return None,
        }
    }
    let version: u64 = next["metadata"]["resourceVersion"]
        .as_str()
        .unwrap_or("0")
        .parse()
        .ok()?;
    next["metadata"]["resourceVersion"] = json!((version + 1).to_string());
    if next["spec"] != object["spec"] {
        let generation = next["metadata"]["generation"].as_i64().unwrap_or(0);
        next["metadata"]["generation"] = json!(generation + 1);
    }
    Some(next)
}

fn client(server: Server) -> (SandboxClient, Arc<Mutex<Server>>) {
    let state = Arc::new(Mutex::new(server));
    let shared = state.clone();
    let service = Router::new().fallback(move |request: Request<Body>| {
        let shared = shared.clone();
        async move {
            let method = request.method().clone();
            let path = request.uri().path().to_owned();
            let bytes = to_bytes(request.into_body(), 256 * 1024).await.unwrap();
            let body: Value = if bytes.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(&bytes).unwrap()
            };
            let mut server = shared.lock().unwrap();
            if method != Method::GET {
                server
                    .writes
                    .push((method.clone(), path.clone(), body.clone()));
            }
            let denied = server.deny.is_some_and(|suffix| path.ends_with(suffix));
            let (code, reply) = match method {
                Method::GET => match server.objects.get(&path) {
                    Some(object) => (StatusCode::OK, object.clone()),
                    None => status(StatusCode::NOT_FOUND, "NotFound"),
                },
                _ if denied => status(StatusCode::FORBIDDEN, "Forbidden"),
                Method::PATCH => match server.objects.get(&path).and_then(|o| apply(o, &body)) {
                    Some(next) => {
                        server.objects.insert(path, next.clone());
                        (StatusCode::OK, next)
                    }
                    None => status(StatusCode::UNPROCESSABLE_ENTITY, "Invalid"),
                },
                Method::POST => {
                    let name = body["metadata"]["name"].as_str().unwrap().to_owned();
                    server
                        .objects
                        .insert(format!("{path}/{name}"), body.clone());
                    (StatusCode::CREATED, body)
                }
                Method::PUT => {
                    server.objects.insert(path, body.clone());
                    (StatusCode::OK, body)
                }
                Method::DELETE => match server.objects.remove(&path) {
                    Some(_) => (
                        StatusCode::OK,
                        json!({"apiVersion": "v1", "kind": "Status", "status": "Success"}),
                    ),
                    None => status(StatusCode::NOT_FOUND, "NotFound"),
                },
                _ => panic!("unexpected {method} {path}"),
            };
            Response::builder()
                .status(code)
                .header("content-type", "application/json")
                .body(Body::from(reply.to_string()))
                .unwrap()
        }
    });
    (
        SandboxClient::new(Client::new(service, "default"), NS),
        state,
    )
}

async fn refresh(client: &SandboxClient, on: bool) -> anyhow::Result<()> {
    tokio::time::timeout(
        Duration::from_secs(10),
        client.reconcile_workspace_bootstrap(&opts(on), &claim_name(ENV), CLAIM_UID, &identity()),
    )
    .await
    .expect("the refresh reads and writes one synthetic server")
}

fn sandbox_patches(server: &Server) -> usize {
    server
        .writes
        .iter()
        .filter(|(method, path, _)| *method == Method::PATCH && *path == sandbox_path())
        .count()
}

/// The moved Sandbox's pod template is create's render for the environment,
/// field by field: the whole Pod spec, and every label and annotation of
/// the render. The only differences are the identity fields the Sandbox
/// keeps (its identity and template-reference labels, its Pod name) and its
/// workspace volume's `existing` mark, which keeps the disk from being
/// formatted. Without the move the Sandbox keeps its direct pod template.
#[tokio::test]
async fn a_moved_sandbox_has_creates_render_for_its_environment() {
    let (client, state) = client(Server {
        objects: objects(),
        ..Default::default()
    });
    refresh(&client, true).await.unwrap();
    let state = state.lock().unwrap();
    assert_eq!(sandbox_patches(&state), 1, "{:?}", state.writes);
    let moved = &state.objects[&sandbox_path()]["spec"]["podTemplate"];
    let created = render_sandbox_template(NS, &opts(true));
    let created = &created["spec"]["podTemplate"];

    let mut expected = created["spec"].clone();
    let index = expected["initContainers"]
        .as_array()
        .unwrap()
        .iter()
        .position(|init| init["name"] == MOUNT_WORKSPACE_CONTAINER)
        .unwrap();
    assert_eq!(
        expected["initContainers"][index]["command"][4],
        json!(WorkspaceVolume::New.argument())
    );
    expected["initContainers"][index]["command"][4] = json!(WorkspaceVolume::Existing.argument());
    let fields = expected.as_object().unwrap();
    assert_eq!(
        moved["spec"]
            .as_object()
            .unwrap()
            .keys()
            .collect::<Vec<_>>(),
        fields.keys().collect::<Vec<_>>()
    );
    for (field, value) in fields {
        assert_eq!(&moved["spec"][field], value, "spec.{field}");
    }
    assert_eq!(
        mount_state(&moved["spec"]),
        &json!(WorkspaceVolume::Existing.argument())
    );

    let kept: BTreeMap<String, String> = runtime_identity_labels(ENV, ORG, 6, "workspace")
        .into_iter()
        .chain([
            (
                TEMPLATE_REF_HASH.to_owned(),
                sandbox_name_hash(&format!("workspace-{ENV}")),
            ),
            (CLAIM_UID_LABEL.to_owned(), CLAIM_UID.to_owned()),
        ])
        .collect();
    for field in ["labels", "annotations"] {
        let rendered = created["metadata"][field].as_object().unwrap();
        let moved = moved["metadata"][field].as_object().unwrap();
        for (key, value) in rendered {
            assert_eq!(moved.get(key), Some(value), "{field} {key}");
        }
        for (key, value) in moved {
            if !rendered.contains_key(key) {
                assert_eq!(
                    kept.get(key).map(|v| json!(v)),
                    Some(value.clone()),
                    "{field} {key}"
                );
            }
        }
    }
    assert_eq!(
        moved["metadata"]["labels"]["codewire.sh/egress"],
        json!("broker")
    );
    assert_eq!(
        moved["metadata"]["annotations"]["codewire.sh/egress-fence-revision"],
        json!("2")
    );
    // The volume claim templates, the workspace disk, are never written.
    assert_eq!(
        state.objects[&sandbox_path()]["spec"]["volumeClaimTemplates"],
        objects()[&sandbox_path()]["spec"]["volumeClaimTemplates"]
    );
}

/// The start's order (cw-security's condition 2): the environment's own
/// template, whose policy selects no Pod while there is none, then one
/// Sandbox patch, then the environment's NetworkPolicy, then the resume that
/// makes the Pod. With the switch off a start writes nothing before its
/// resume, as before.
#[tokio::test]
async fn a_start_moves_the_sandbox_in_one_patch_then_its_policies_then_its_pod() {
    for on in [true, false] {
        let (client, state) = client(Server {
            objects: objects(),
            ..Default::default()
        });
        refresh(&client, on).await.unwrap();
        let before_resume = state.lock().unwrap().writes.len();
        tokio::time::timeout(
            Duration::from_secs(10),
            client.set_replicas_for_identity(
                &ClaimOpts {
                    environment_id: ENV.into(),
                    org_id: ORG.into(),
                    operation_generation: 7,
                    ..Default::default()
                },
                &claim_name(ENV),
                CLAIM_UID,
                &identity(),
                1,
                DAEMON_IMAGE,
            ),
        )
        .await
        .unwrap()
        .unwrap();
        let state = state.lock().unwrap();
        let writes: Vec<String> = state
            .writes
            .iter()
            .map(|(method, path, _)| format!("{method} {path}"))
            .collect();
        let resume = &state.writes[before_resume..];
        assert!(
            resume
                .iter()
                .any(|(method, path, body)| *method == Method::PATCH
                    && *path == sandbox_path()
                    && body.to_string().contains("\"Running\"")),
            "{writes:?}"
        );
        if !on {
            assert_eq!(before_resume, 0, "{writes:?}");
            continue;
        }
        let first = |kind: &str| writes.iter().position(|write| write.contains(kind));
        let sandbox = first("/sandboxes/").unwrap();
        let template = first("/sandboxtemplates/").unwrap();
        let policy = first("/networkpolicies").unwrap();
        assert!(
            template < sandbox && sandbox < policy && policy < before_resume,
            "{writes:?}"
        );
        assert_eq!(
            writes[..before_resume]
                .iter()
                .filter(|write| write.contains("/sandboxes/"))
                .count(),
            1,
            "{writes:?}"
        );
        let template = &state.objects[&format!(
            "/apis/extensions.agents.x-k8s.io/v1beta1/namespaces/{NS}/sandboxtemplates/workspace-{ENV}"
        )];
        let created = render_sandbox_template(NS, &opts(true));
        assert_eq!(
            template["spec"]["podTemplate"],
            created["spec"]["podTemplate"]
        );
        assert_eq!(
            template["spec"]["networkPolicy"],
            created["spec"]["networkPolicy"]
        );
        let policy = state
            .objects
            .iter()
            .find(|(path, _)| path.contains("/networkpolicies/"))
            .unwrap()
            .1;
        assert_eq!(
            policy["spec"],
            render_workspace_daemon_network_policy(NS, &opts(true))["spec"]
        );
    }
}

/// A confidential environment's render can't be made while hosted egress
/// holds confidential guests: nothing is written, and the refusal is the
/// hold's typed error.
#[tokio::test]
async fn a_render_that_cant_be_made_sends_no_patch_and_refuses_the_start() {
    let (client, state) = client(Server {
        objects: objects(),
        ..Default::default()
    });
    let measured = TemplateOpts {
        runtime_profile: super::super::super::template::RUNTIME_PROFILE_CONFIDENTIAL.into(),
        measured_binding_roots: "-----BEGIN CERTIFICATE-----\nMIIBsynthetic\n-----END CERTIFICATE-----\n"
            .into(),
        confidential_storage_manifest_uri: "kbs:///default/codewire-storage-manifests/sha256-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
        kata_coco_init_data_enabled: true,
        kata_coco_kbs_url: "https://kbs.example.test".into(),
        ..opts(true)
    };
    let refused = pre_switch::moves(MoveOutcome::Refused);
    let error = tokio::time::timeout(
        Duration::from_secs(10),
        client.reconcile_workspace_bootstrap(&measured, &claim_name(ENV), CLAIM_UID, &identity()),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert!(error.is::<ConfidentialHeld>(), "{error:#}");
    assert!(pre_switch::moves(MoveOutcome::Refused) > refused);
    assert!(state.lock().unwrap().writes.is_empty());
}

/// A Sandbox moves only while it is suspended with no Pod and claimed: a
/// running one, one whose Pod still exists, and an unclaimed pool member are
/// never written, so nothing stops or replaces their Pods.
#[tokio::test]
async fn only_a_claimed_suspended_sandbox_without_a_pod_moves() {
    let running = |objects: &mut BTreeMap<String, Value>| {
        let sandbox = objects.get_mut(&sandbox_path()).unwrap();
        sandbox["spec"]["operatingMode"] = json!("Running");
        sandbox["status"]["conditions"] = json!([{"type": "Ready", "status": "True",
            "observedGeneration": 9}]);
        objects.insert(
            pod_path(),
            json!({"apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": POD, "namespace": NS, "uid": "pod-incarnation"}}),
        );
    };
    let with_pod = |objects: &mut BTreeMap<String, Value>| {
        objects.insert(
            pod_path(),
            json!({"apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": POD, "namespace": NS, "uid": "pod-incarnation"}}),
        );
    };
    let pool_member = |objects: &mut BTreeMap<String, Value>| {
        objects.get_mut(&sandbox_path()).unwrap()["metadata"]["labels"] = json!({crate::sandbox::warm_pool::MEMBER_POOL_LABEL: "cw-pool-1000m-4096mi-40gi-78909fe3"});
    };
    type Change<'a> = &'a dyn Fn(&mut BTreeMap<String, Value>);
    let cases: [(&str, Change, MoveRefused); 3] = [
        ("running", &running, MoveRefused::NotSuspended),
        ("a Pod left", &with_pod, MoveRefused::PodPresent),
        (
            "an unclaimed pool member",
            &pool_member,
            MoveRefused::PoolMember,
        ),
    ];
    for (case, change, refusal) in cases {
        let mut objects = objects();
        change(&mut objects);
        let (client, state) = client(Server {
            objects,
            ..Default::default()
        });
        let error = refresh(&client, true).await.unwrap_err();
        assert_eq!(
            error.downcast_ref::<MoveRefused>(),
            Some(&refusal),
            "{case}: {error:#}"
        );
        assert!(state.lock().unwrap().writes.is_empty(), "{case}");
    }
}

/// A patch admission refuses leaves the Sandbox as it was, and the start
/// fails; nothing after it, the policy, is written. The environment's own
/// template, moved before it, selects no Pod, and the next start finds it
/// moved and patches only the Sandbox.
#[tokio::test]
async fn a_move_admission_refuses_stops_the_start_with_nothing_else_written() {
    let (client, state) = client(Server {
        objects: objects(),
        deny: Some(SANDBOX),
        ..Default::default()
    });
    let not_admitted = pre_switch::moves(MoveOutcome::NotAdmitted);
    refresh(&client, true).await.unwrap_err();
    assert!(pre_switch::moves(MoveOutcome::NotAdmitted) > not_admitted);
    let state = state.lock().unwrap();
    let writes: Vec<String> = state
        .writes
        .iter()
        .map(|(method, path, _)| format!("{method} {path}"))
        .collect();
    assert_eq!(
        writes,
        [
            format!(
                "PATCH {}",
                extensions_path("sandboxtemplates", &format!("workspace-{ENV}"))
            ),
            format!("PATCH {}", sandbox_path()),
        ],
    );
    assert_eq!(state.objects[&sandbox_path()], objects()[&sandbox_path()]);
}

/// A Sandbox already moved, or created under the switch, is left alone: its
/// start writes no move.
#[tokio::test]
async fn a_broker_mode_sandbox_is_not_moved_again() {
    let (client, state) = client(Server {
        objects: objects(),
        ..Default::default()
    });
    refresh(&client, true).await.unwrap();
    // The controller observes the moved Sandbox suspended again.
    {
        let mut server = state.lock().unwrap();
        let sandbox = server.objects.get_mut(&sandbox_path()).unwrap();
        sandbox["status"]["conditions"][0]["observedGeneration"] =
            sandbox["metadata"]["generation"].clone();
    }
    let writes = state.lock().unwrap().writes.len();
    refresh(&client, true).await.unwrap();
    assert_eq!(state.lock().unwrap().writes.len(), writes);
}

/// Every environment on Dev was adopted from a shared pool. Its move gives it
/// its own template and shadow pool, as a cold create makes them, points its
/// Claim at that shadow, so the controller holds the Sandbox to that template
/// from then on, and patches the Sandbox once, after those, to create's
/// render with the label that selects it by that template. The shared pool's
/// template is never written. The controller then has no metadata to put
/// back, and the Pod it builds is selected only by policies the lockdown
/// check accepts, as for a created one; the old pool template's policy, with
/// its world egress, no longer selects it.
#[tokio::test]
async fn a_pool_born_sandbox_moves_onto_its_own_template_and_leaves_the_pools_policy() {
    let (client, state) = client(Server {
        objects: pool_born_objects(),
        ..Default::default()
    });
    refresh(&client, true).await.unwrap();
    let state = state.lock().unwrap();
    let own = format!("workspace-{ENV}");
    let shadow = super::super::super::shadow_warm_pool_name(&own);
    let writes: Vec<String> = state
        .writes
        .iter()
        .map(|(method, path, _)| format!("{method} {path}"))
        .collect();
    let at = |write: &str| writes.iter().position(|w| w == write);
    let template = at(&format!(
        "POST /apis/extensions.agents.x-k8s.io/v1beta1/namespaces/{NS}/sandboxtemplates"
    ))
    .unwrap();
    let pool = at(&format!(
        "POST /apis/extensions.agents.x-k8s.io/v1beta1/namespaces/{NS}/sandboxwarmpools"
    ))
    .unwrap();
    let claim = at(&format!(
        "PATCH {}",
        extensions_path("sandboxclaims", &claim_name(ENV))
    ))
    .unwrap();
    let sandbox = at(&format!("PATCH {}", sandbox_path())).unwrap();
    let policy = writes
        .iter()
        .position(|w| w.contains("/networkpolicies"))
        .unwrap();
    assert!(
        template < pool && pool < claim && claim < sandbox && sandbox < policy,
        "{writes:?}"
    );
    assert_eq!(sandbox_patches(&state), 1, "{writes:?}");
    assert!(!writes.iter().any(|w| w.ends_with(POOL)), "{writes:?}");

    let created = render_sandbox_template(NS, &opts(true));
    let template = &state.objects[&extensions_path("sandboxtemplates", &own)];
    assert_eq!(template["spec"], created["spec"]);
    let pool = &state.objects[&extensions_path("sandboxwarmpools", &shadow)];
    assert_eq!(pool["spec"]["sandboxTemplateRef"]["name"], json!(own));
    assert_eq!(pool["spec"]["replicas"], json!(0));
    let claim = &state.objects[&extensions_path("sandboxclaims", &claim_name(ENV))];
    assert_eq!(claim["spec"]["warmPoolRef"]["name"], json!(shadow));

    let moved = &state.objects[&sandbox_path()];
    let mut spec = created["spec"]["podTemplate"]["spec"].clone();
    let index = spec["initContainers"]
        .as_array()
        .unwrap()
        .iter()
        .position(|init| init["name"] == MOUNT_WORKSPACE_CONTAINER)
        .unwrap();
    spec["initContainers"][index]["command"][4] = json!(WorkspaceVolume::Existing.argument());
    assert_eq!(moved["spec"]["podTemplate"]["spec"], spec);
    let own_hash = sandbox_name_hash(&own);
    assert_eq!(
        moved["metadata"]["labels"][TEMPLATE_REF_HASH],
        json!(own_hash)
    );

    // What the controller computes for the claimed Sandbox from its Claim's
    // template (`reconcileActive`) is what it already has.
    let mut expected = template["spec"]["podTemplate"]["metadata"].clone();
    expected["labels"][CLAIM_UID_LABEL] = json!(CLAIM_UID);
    expected["labels"][TEMPLATE_REF_HASH] = json!(own_hash);
    for (key, value) in claim["spec"]["additionalPodMetadata"]["labels"]
        .as_object()
        .unwrap()
    {
        expected["labels"][key] = value.clone();
    }
    assert_eq!(moved["spec"]["podTemplate"]["metadata"], expected);

    // The Pod the controller builds, judged by the lockdown check against
    // every policy that could select it.
    let facts = |labels: BTreeMap<String, String>| crate::runtime::MemberFacts {
        name: Some(POD.into()),
        namespace: Some(NS.into()),
        uid: Some("pod-incarnation".into()),
        terminating: false,
        service_account: None,
        controllers: Vec::new(),
        labels,
        annotations: BTreeMap::new(),
        has_spec: true,
        volumes: Vec::new(),
        containers: Vec::new(),
        init_containers: Vec::new(),
        image_ids: Vec::new(),
        ip: String::new(),
        ips: Vec::new(),
        phase: Some("Running".into()),
        node_name: None,
        spec_json: Value::Null,
    };
    let policy_facts = |spec: &Value| crate::runtime::NetworkPolicyFacts { spec: spec.clone() };
    let named = |name: String, spec: &Value| crate::runtime::NamedNetworkPolicy {
        name,
        facts: policy_facts(spec),
    };
    let environment_policy = state
        .objects
        .iter()
        .find(|(path, _)| path.contains("/networkpolicies/"))
        .unwrap()
        .1;
    let pool_policy = render_template_network_policy(&opts(false), &sandbox_name_hash(POOL));
    let own_policy = render_template_network_policy(&opts(true), &own_hash);
    let live = [
        named(
            crate::egress::lockdown::policy_name(ENV),
            &environment_policy["spec"],
        ),
        named(format!("{POOL}-network-policy"), &pool_policy["spec"]),
        named(format!("{own}-network-policy"), &own_policy["spec"]),
    ];
    let rendered = policy_facts(&render_workspace_daemon_network_policy(NS, &opts(true))["spec"]);
    let judge = |labels: BTreeMap<String, String>| {
        let hash = labels[TEMPLATE_REF_HASH].clone();
        crate::egress::lockdown::lockdown_applied(
            &facts(labels),
            ENV,
            Some(&rendered),
            Some(&policy_facts(
                &render_template_network_policy(&opts(true), &hash)["spec"],
            )),
            None,
            &live,
        )
    };
    let pod = controller_pod_labels(moved);
    assert_eq!(pod[TEMPLATE_REF_HASH], own_hash);
    assert_eq!(judge(pod.clone()), Ok(()));
    // Still selected by the pool template's policy, as a Sandbox moved
    // without its own template would be, the Pod is refused.
    let mut on_the_pool = pod;
    on_the_pool.insert(TEMPLATE_REF_HASH.into(), sandbox_name_hash(POOL));
    assert_eq!(
        judge(on_the_pool),
        Err(crate::egress::lockdown::LockdownRefusal::PolicyDiffers {
            policy: format!("{POOL}-network-policy")
        })
    );
}

/// A Sandbox some other writer gave only the broker label, without the
/// shape, is not taken as moved: its start writes the whole render.
#[tokio::test]
async fn a_broker_label_without_the_shape_is_moved_all_the_same() {
    let mut objects = objects();
    objects.get_mut(&sandbox_path()).unwrap()["spec"]["podTemplate"]["metadata"]["labels"]["codewire.sh/egress"] =
        json!("broker");
    let (client, state) = client(Server {
        objects,
        ..Default::default()
    });
    refresh(&client, true).await.unwrap();
    let state = state.lock().unwrap();
    assert_eq!(sandbox_patches(&state), 1);
    let created = render_sandbox_template(NS, &opts(true));
    let moved = &state.objects[&sandbox_path()]["spec"]["podTemplate"];
    assert_eq!(moved["spec"]["initContainers"], {
        let mut inits = created["spec"]["podTemplate"]["spec"]["initContainers"].clone();
        let index = inits
            .as_array()
            .unwrap()
            .iter()
            .position(|init| init["name"] == MOUNT_WORKSPACE_CONTAINER)
            .unwrap();
        inits[index]["command"][4] = json!(WorkspaceVolume::Existing.argument());
        inits
    });
}

/// A deployment whose standard isolation now runs `standard` renders this
/// environment, made under `commodity`, on another runtime: its move is
/// refused before anything is written, the template, shadow pool and Claim
/// of a pool-born one included, since the VM's state would be made afresh
/// over a used workspace. Same-class moves are the tests above.
#[tokio::test]
async fn a_move_that_would_change_the_runtime_class_is_refused_before_any_write() {
    let standard = TemplateOpts {
        runtime_profile: super::super::super::template::RUNTIME_PROFILE_STANDARD.into(),
        standard_runtime: Some(
            super::super::super::template::StandardRuntime::parse(
                "registry.example.invalid/codewire/pod-runtime@sha256:1111111111111111111111111111111111111111111111111111111111111111",
                "registry.example.invalid/codewire/workspace-disk@sha256:2222222222222222222222222222222222222222222222222222222222222222 3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a 4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b registry.example.invalid/codewire/workspace@sha256:5555555555555555555555555555555555555555555555555555555555555555",
            )
            .unwrap()
            .unwrap(),
        ),
        ..opts(true)
    };
    for fixture in [objects(), pool_born_objects()] {
        let (client, state) = client(Server {
            objects: fixture,
            ..Default::default()
        });
        let error = tokio::time::timeout(
            Duration::from_secs(10),
            client.reconcile_workspace_bootstrap(
                &standard,
                &claim_name(ENV),
                CLAIM_UID,
                &identity(),
            ),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert_eq!(
            error.downcast_ref::<MoveRefused>(),
            Some(&MoveRefused::RuntimeClassChanged {
                from: "commodity".into(),
                to: "standard".into(),
            }),
            "{error:#}"
        );
        assert!(state.lock().unwrap().writes.is_empty());
    }
}

/// The volume state is read as `workspace_volume_existing` reads it: only
/// where the command names mount-workspace's own script.
#[test]
fn only_mount_workspaces_own_existing_mark_is_kept() {
    let rendered = render_sandbox_template(NS, &opts(true))["spec"]["podTemplate"]["spec"].clone();
    let index = rendered["initContainers"]
        .as_array()
        .unwrap()
        .iter()
        .position(|init| init["name"] == MOUNT_WORKSPACE_CONTAINER)
        .unwrap();
    let existing = json!(WorkspaceVolume::Existing.argument());
    let mut current = rendered.clone();
    current["initContainers"][index]["command"][4] = existing.clone();
    let mut moved = rendered.clone();
    keep_disk_state(&current, &mut moved).unwrap();
    assert_eq!(moved["initContainers"][index]["command"][4], existing);

    current["initContainers"][index]["command"][3] = json!("another-script");
    let mut moved = rendered.clone();
    keep_disk_state(&current, &mut moved).unwrap();
    assert_eq!(
        moved["initContainers"][index]["command"][4],
        json!(WorkspaceVolume::New.argument())
    );
}

/// The member admission policy's `wholeBroker`, as it reads a Sandbox.
const WHOLE_BROKER_CEL: &str = "variables.broker && \
    has(object.spec.podTemplate.metadata.annotations) && \
    'codewire.sh/egress-fence-revision' in object.spec.podTemplate.metadata.annotations && \
    has(object.spec.podTemplate.spec) && \
    (has(object.spec.podTemplate.spec.runtimeClassName) && object.spec.podTemplate.spec.runtimeClassName == 'standard' || \
    has(object.spec.podTemplate.spec.initContainers) && \
    object.spec.podTemplate.spec.initContainers.exists(c, c.name == 'hosted-egress-tun'))";

/// `hollow_broker_mode` and the member policy's `wholeBroker` are one
/// definition: the label, the fence revision annotation, and the TUN init or
/// a `standard` VM. The policy's text is pinned here, and every combination
/// of the four is judged as that text reads it.
#[test]
fn hollow_broker_mode_is_the_admission_policys_whole_broker_shape() {
    let policy = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deployments/k8s/orchestration/warm-pool-authz.yaml"
    ));
    let block = policy
        .split_once("    - name: wholeBroker\n      expression: >-\n")
        .expect("the member policy defines wholeBroker")
        .1
        .lines()
        .take_while(|line| line.starts_with("        "))
        .collect::<Vec<_>>()
        .join(" ");
    let compact = |text: &str| text.split_whitespace().collect::<Vec<_>>().join(" ");
    assert_eq!(compact(&block), compact(WHOLE_BROKER_CEL));
    for case in 0..16u8 {
        let (label, fenced, tun, standard) =
            (case & 1 != 0, case & 2 != 0, case & 4 != 0, case & 8 != 0);
        let mut labels = json!({"codewire.sh/type": "workspace"});
        if label {
            labels["codewire.sh/egress"] = json!("broker");
        }
        let mut annotations = json!({});
        if fenced {
            annotations["codewire.sh/egress-fence-revision"] = json!("2");
        }
        let mut inits = vec![json!({"name": MOUNT_WORKSPACE_CONTAINER})];
        if tun {
            inits.push(json!({"name": "hosted-egress-tun"}));
        }
        let class = if standard { "standard" } else { "commodity" };
        let sandbox: DynamicObject = serde_json::from_value(json!({
            "apiVersion": "agents.x-k8s.io/v1beta1", "kind": "Sandbox",
            "metadata": {"name": SANDBOX},
            "spec": {"podTemplate": {
                "metadata": {"labels": labels, "annotations": annotations},
                "spec": {"runtimeClassName": class, "initContainers": inits, "containers": []},
            }},
        }))
        .unwrap();
        let whole = label && fenced && (standard || tun);
        assert_eq!(
            hollow_broker_mode(&sandbox),
            label && !whole,
            "label {label}, fenced {fenced}, TUN {tun}, standard {standard}"
        );
    }
}
