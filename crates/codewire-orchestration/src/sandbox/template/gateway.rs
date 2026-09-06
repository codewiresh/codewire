//! Gateway services, deployment, environment, and host-key rendering.

use codewire_gateway_proto::{
    GATEWAY_BINDING_TOKEN_AUDIENCE, GATEWAY_BINDING_TOKEN_EXPIRATION_SECONDS,
    GATEWAY_BINDING_TOKEN_MOUNT_PATH,
};
use serde_json::{Map, Value, json};

use super::credentials;
use super::encoding::kata_policy_init_data_annotation;
use super::naming::{
    gateway_direct_udp_service_name, gateway_host_key_secret_name, gateway_labels,
    gateway_selector, gateway_service_name, gateway_workload_name, workspace_daemon_service_addr,
};
use super::runtime_policy::{
    RUNTIME_PROFILE_CONFIDENTIAL, kata_coco_kernel_params_annotation, uses_kata_policy_init_data,
};
use super::{
    DAEMON_AUTH_TOKEN_ENV, DEFAULT_GATEWAY_IMAGE, DEFAULT_GATEWAY_READYZ_PORT,
    DEFAULT_GATEWAY_SSH_PORT, GATEWAY_BINDING_URL_ENV, GATEWAY_DAEMON_CONNECT_TIMEOUT_SECONDS_ENV,
    GATEWAY_HOST_KEY_PATH, GATEWAY_HOST_KEY_SECRET_KEY, GATEWAY_HOST_KEY_SECRET_MOUNT_PATH,
    GATEWAY_TAILNET_DIRECT_UDP_ADVERTISE_ENDPOINTS_ENV, GATEWAY_TAILNET_UDP_LISTEN_ADDR,
    GATEWAY_TAILNET_UDP_LISTEN_ADDR_ENV, GATEWAY_TAILNET_UDP_PORT,
    GATEWAY_UDP_RELAY_ALLOCATOR_TOKEN_ENV, GATEWAY_UDP_RELAY_ALLOCATOR_URL_ENV,
    GATEWAY_UDP_RELAY_BIND_ADDRS_ENV, INTERNAL_DERP_TLS_PORT, KATA_COCO_INIT_DATA_ANNOTATION_KEY,
    KATA_HYPERVISOR_KERNEL_PARAMS_ANNOTATION_KEY, SANDBOX_SERVICE_ACCOUNT, TemplateOpts,
};

const GATEWAY_STARTUP_PROBE_PERIOD_SECONDS: i64 = 2;
pub(super) const GATEWAY_BINDING_TOKEN_VOLUME: &str = "gateway-binding-identity";
pub(super) const COMMODITY_GATEWAY_STARTUP_FAILURE_THRESHOLD: i64 = 45;
// Guest storage setup is bounded by the kubelet's 25-minute StartContainer
// horizon. Give the gateway the same daemon-connect budget, then leave one
// minute for it to become probe-ready and five minutes for the Deployment to
// report a terminal rollout failure.
pub(super) const CONFIDENTIAL_GATEWAY_DAEMON_CONNECT_TIMEOUT_SECONDS: i64 = 1_500;
const CONFIDENTIAL_GATEWAY_STARTUP_MARGIN_SECONDS: i64 = 60;
pub(super) const CONFIDENTIAL_GATEWAY_STARTUP_FAILURE_THRESHOLD: i64 =
    (CONFIDENTIAL_GATEWAY_DAEMON_CONNECT_TIMEOUT_SECONDS
        + CONFIDENTIAL_GATEWAY_STARTUP_MARGIN_SECONDS)
        / GATEWAY_STARTUP_PROBE_PERIOD_SECONDS;
pub(super) const CONFIDENTIAL_GATEWAY_PROGRESS_DEADLINE_SECONDS: i64 =
    CONFIDENTIAL_GATEWAY_DAEMON_CONNECT_TIMEOUT_SECONDS + 300;

pub(super) fn tailnet_udp_listener_enabled(opts: &TemplateOpts) -> bool {
    direct_udp_ingress_enabled(opts)
        || gateway_direct_udp_endpoint(opts).is_some()
        || !opts.udp_relay_allocator_url.trim().is_empty()
        || !opts.udp_relay_bind_addrs.trim().is_empty()
}

fn direct_udp_ingress_enabled(opts: &TemplateOpts) -> bool {
    !opts.stun_host.trim().is_empty() || !opts.stun_servers.trim().is_empty()
}

pub(super) fn gateway_direct_udp_endpoint(opts: &TemplateOpts) -> Option<String> {
    if !opts.direct_udp_lb_enabled {
        return None;
    }
    let ip = opts.direct_udp_lb_ip.trim();
    if ip.is_empty() || opts.direct_udp_lb_port <= 0 || opts.direct_udp_lb_port > 65535 {
        return None;
    }
    Some(format!("{ip}:{}", opts.direct_udp_lb_port))
}

fn gateway_http_probe(failure_threshold: i64) -> Value {
    json!({
        "httpGet": { "path": "/readyz", "port": DEFAULT_GATEWAY_READYZ_PORT },
        "periodSeconds": GATEWAY_STARTUP_PROBE_PERIOD_SECONDS,
        "timeoutSeconds": 2,
        "failureThreshold": failure_threshold,
    })
}

fn apply_sidecar_probes(gateway: &mut Value, confidential: bool) {
    let failure_threshold = if confidential {
        CONFIDENTIAL_GATEWAY_STARTUP_FAILURE_THRESHOLD
    } else {
        COMMODITY_GATEWAY_STARTUP_FAILURE_THRESHOLD
    };
    gateway["startupProbe"] = gateway_http_probe(failure_threshold);
    gateway["readinessProbe"] = gateway_http_probe(3);
}

pub(super) fn build_sidecar_env(opts: &TemplateOpts) -> Vec<Value> {
    codewire_gateway_proto::DaemonAuthToken::new(opts.daemon_auth_token.clone())
        .expect("hosted gateway requires a canonical daemon auth token");
    assert!(
        opts.gateway_token != opts.daemon_auth_token,
        "hosted coordinate and daemon capabilities must be distinct"
    );
    let mut env = vec![
        json!({
            "name": "CODEWIRE_WORKSPACE_SHIM_ADDR",
            "value": workspace_daemon_service_addr(&opts.environment_id),
        }),
        json!({ "name": DAEMON_AUTH_TOKEN_ENV, "value": opts.daemon_auth_token }),
        json!({ "name": "CODEWIRE_GATEWAY_TOKEN", "value": opts.gateway_token }),
    ];
    if opts.runtime_profile_spec().profile == RUNTIME_PROFILE_CONFIDENTIAL {
        env.push(json!({
            "name": GATEWAY_DAEMON_CONNECT_TIMEOUT_SECONDS_ENV,
            "value": CONFIDENTIAL_GATEWAY_DAEMON_CONNECT_TIMEOUT_SECONDS.to_string(),
        }));
    }
    if !opts.environment_id.is_empty() {
        env.push(json!({ "name": "CODEWIRE_ENVIRONMENT_ID", "value": opts.environment_id }));
    }
    if !opts.api_base_url.is_empty() {
        env.push(json!({ "name": "CODEWIRE_API_URL", "value": opts.api_base_url }));
    }
    if let Some(binding_url) = gateway_binding_url(opts) {
        env.push(json!({
            "name": GATEWAY_BINDING_URL_ENV,
            "value": binding_url,
        }));
    }
    if let Some(coordinator_url) = gateway_coordinator_url(opts) {
        env.push(json!({
            "name": "CODEWIRE_COORDINATOR_URL",
            "value": coordinator_url,
        }));
    }
    if !opts.server_namespace.is_empty() {
        env.push(json!({ "name": "CODEWIRE_SERVER_NAMESPACE", "value": opts.server_namespace }));
    }
    if let Some(derp_url) = gateway_derp_url(opts) {
        env.push(json!({ "name": "CODEWIRE_DERP_URL", "value": derp_url }));
    }
    if !opts.stun_host.is_empty() {
        env.push(json!({ "name": "CODEWIRE_STUN_HOST", "value": opts.stun_host }));
        env.push(json!({ "name": "CODEWIRE_STUN_PORT", "value": opts.stun_port.to_string() }));
    }
    if !opts.stun_servers.is_empty() {
        env.push(json!({ "name": "CODEWIRE_STUN_SERVERS", "value": opts.stun_servers }));
    }
    if tailnet_udp_listener_enabled(opts) {
        env.push(json!({
            "name": GATEWAY_TAILNET_UDP_LISTEN_ADDR_ENV,
            "value": GATEWAY_TAILNET_UDP_LISTEN_ADDR,
        }));
    }
    if let Some(endpoint) = gateway_direct_udp_endpoint(opts) {
        env.push(json!({
            "name": GATEWAY_TAILNET_DIRECT_UDP_ADVERTISE_ENDPOINTS_ENV,
            "value": endpoint,
        }));
    }
    if !opts.udp_relay_allocator_url.trim().is_empty() {
        env.push(json!({
            "name": GATEWAY_UDP_RELAY_ALLOCATOR_URL_ENV,
            "value": opts.udp_relay_allocator_url,
        }));
    }
    if !opts.udp_relay_allocator_token.trim().is_empty() {
        env.push(json!({
            "name": GATEWAY_UDP_RELAY_ALLOCATOR_TOKEN_ENV,
            "value": opts.udp_relay_allocator_token,
        }));
    }
    if !opts.udp_relay_bind_addrs.trim().is_empty() {
        env.push(json!({
            "name": GATEWAY_UDP_RELAY_BIND_ADDRS_ENV,
            "value": opts.udp_relay_bind_addrs,
        }));
    }
    if opts.debug_tailnet {
        env.push(json!({ "name": "CODEWIRE_DEBUG_TAILNET", "value": "1" }));
    }
    env.push(json!({
        "name": "CODEWIRE_SSH_HOST_KEY_PATH",
        "value": GATEWAY_HOST_KEY_PATH,
    }));
    env.extend(credentials::gateway_environment(opts));
    env
}

pub fn render_gateway_service(namespace: &str, opts: &TemplateOpts) -> Value {
    let mut service = json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": gateway_service_name(&opts.environment_id),
            "namespace": namespace,
            "labels": gateway_labels(opts),
        },
        "spec": {
            "type": "ClusterIP",
            "selector": gateway_selector(opts),
            "ports": [
                { "name": "ssh", "protocol": "TCP", "port": DEFAULT_GATEWAY_SSH_PORT, "targetPort": DEFAULT_GATEWAY_SSH_PORT },
                { "name": "readyz", "protocol": "TCP", "port": DEFAULT_GATEWAY_READYZ_PORT, "targetPort": DEFAULT_GATEWAY_READYZ_PORT },
                { "name": "tailnet-udp", "protocol": "UDP", "port": GATEWAY_TAILNET_UDP_PORT, "targetPort": GATEWAY_TAILNET_UDP_PORT },
            ],
        },
    });
    if let Some(config) = &opts.credential_runtime {
        config.assert_namespace(namespace);
        service["spec"]["ports"]
            .as_array_mut()
            .expect("gateway ports")
            .push(json!({
                "name":"credentials", "protocol":"TCP", "port":443,
                "targetPort":credentials::CREDENTIAL_GATEWAY_HTTPS_PORT,
            }));
    }
    service
}

pub fn render_gateway_direct_udp_service(namespace: &str, opts: &TemplateOpts) -> Option<Value> {
    let _endpoint = gateway_direct_udp_endpoint(opts)?;
    let lb_class = opts.direct_udp_lb_class.trim();
    let sharing_key = opts.direct_udp_lb_sharing_key.trim();
    let mut annotations = Map::new();
    annotations.insert(
        "lbipam.cilium.io/ips".into(),
        opts.direct_udp_lb_ip.trim().into(),
    );
    if !sharing_key.is_empty() {
        annotations.insert("lbipam.cilium.io/sharing-key".into(), sharing_key.into());
        annotations.insert(
            "lbipam.cilium.io/sharing-cross-namespace".into(),
            "*".into(),
        );
    }

    let mut labels = gateway_labels(opts);
    let labels_obj = labels.as_object_mut().expect("labels object");
    labels_obj.insert("codewire.sh/type".into(), "direct-udp-lb".into());
    labels_obj.insert("codewire.sh/runtime-network".into(), "direct-udp".into());
    labels_obj.insert("codewire.sh/transport".into(), "direct-udp".into());
    if !opts.direct_udp_transport_zone.trim().is_empty() {
        labels_obj.insert(
            "codewire.sh/transport-zone".into(),
            opts.direct_udp_transport_zone.trim().into(),
        );
    }

    let mut spec = json!({
        "type": "LoadBalancer",
        "allocateLoadBalancerNodePorts": false,
        "ipFamilyPolicy": "SingleStack",
        "ipFamilies": ["IPv4"],
        "externalTrafficPolicy": "Cluster",
        "selector": gateway_selector(opts),
        "ports": [
            {
                "name": "tailnet-udp",
                "protocol": "UDP",
                "port": opts.direct_udp_lb_port,
                "targetPort": GATEWAY_TAILNET_UDP_PORT,
            },
        ],
    });
    if !lb_class.is_empty() {
        spec["loadBalancerClass"] = lb_class.into();
    }

    Some(json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": gateway_direct_udp_service_name(&opts.environment_id),
            "namespace": namespace,
            "labels": labels,
            "annotations": annotations,
        },
        "spec": spec,
    }))
}

pub fn render_gateway_host_key_secret(
    namespace: &str,
    opts: &TemplateOpts,
    host_key_openssh: &str,
) -> Value {
    let mut string_data = Map::new();
    string_data.insert(GATEWAY_HOST_KEY_SECRET_KEY.into(), host_key_openssh.into());

    json!({
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": gateway_host_key_secret_name(&opts.environment_id),
            "namespace": namespace,
            "labels": {
                "app.kubernetes.io/name": "codewire-gateway",
                "app.kubernetes.io/component": "gateway-host-key",
                "app.kubernetes.io/managed-by": "codewire",
                "codewire.sh/environment-id": opts.environment_id,
                "codewire.sh/type": "gateway-host-key",
            },
        },
        "type": "Opaque",
        "stringData": Value::Object(string_data),
    })
}

fn gateway_host_key_init_container(support_image: &str) -> Value {
    json!({
        "name": "codewire-gateway-host-key-init",
        "image": support_image,
        "command": [
            "sh",
            "-ec",
            format!(
                "umask 077; mkdir -p /codewire/gateway/ssh; cp {}/{} {}; chmod 0600 {}",
                GATEWAY_HOST_KEY_SECRET_MOUNT_PATH,
                GATEWAY_HOST_KEY_SECRET_KEY,
                GATEWAY_HOST_KEY_PATH,
                GATEWAY_HOST_KEY_PATH,
            ),
        ],
        "volumeMounts": [
            { "name": "gateway-state", "mountPath": "/codewire/gateway" },
            { "name": "gateway-host-key", "mountPath": GATEWAY_HOST_KEY_SECRET_MOUNT_PATH, "readOnly": true },
        ],
        "resources": {
            "requests": { "cpu": "10m", "memory": "16Mi" },
            "limits": { "cpu": "50m", "memory": "64Mi" },
        },
    })
}

pub fn render_gateway_deployment(namespace: &str, opts: &TemplateOpts) -> Value {
    let runtime_spec = opts.runtime_profile_spec();
    let support_image = if opts.support_image.is_empty() {
        DEFAULT_GATEWAY_IMAGE
    } else {
        &opts.support_image
    };
    let labels = gateway_labels(opts);
    let mut gateway_container = json!({
        "name": "codewire-gateway",
        "image": support_image,
        "command": ["/usr/local/bin/codewire-gateway"],
        "env": build_sidecar_env(opts),
        "ports": [
            { "name": "ssh", "containerPort": DEFAULT_GATEWAY_SSH_PORT, "protocol": "TCP" },
            { "name": "readyz", "containerPort": DEFAULT_GATEWAY_READYZ_PORT, "protocol": "TCP" },
            { "name": "tailnet-udp", "containerPort": GATEWAY_TAILNET_UDP_PORT, "protocol": "UDP" },
        ],
        "volumeMounts": [
            { "name": "gateway-state", "mountPath": "/codewire/gateway" },
            {
                "name": GATEWAY_BINDING_TOKEN_VOLUME,
                "mountPath": GATEWAY_BINDING_TOKEN_MOUNT_PATH,
                "readOnly": true,
            },
        ],
        "resources": {
            "requests": { "cpu": "100m", "memory": "128Mi" },
            "limits": { "cpu": "500m", "memory": "256Mi" },
        },
    });
    if let Some(config) = &opts.credential_runtime {
        config.assert_namespace(namespace);
        gateway_container["ports"].as_array_mut().expect("gateway ports").push(json!({
            "name":"credentials", "protocol":"TCP", "containerPort":credentials::CREDENTIAL_GATEWAY_HTTPS_PORT,
        }));
        gateway_container["volumeMounts"]
            .as_array_mut()
            .expect("gateway mounts")
            .extend(credentials::gateway_mounts());
    }
    apply_sidecar_probes(
        &mut gateway_container,
        runtime_spec.profile == RUNTIME_PROFILE_CONFIDENTIAL,
    );

    let mut pod_spec = Map::new();
    pod_spec.insert("serviceAccountName".into(), SANDBOX_SERVICE_ACCOUNT.into());
    pod_spec.insert("automountServiceAccountToken".into(), false.into());
    pod_spec.insert(
        "securityContext".into(),
        json!({ "runAsUser": 1000, "runAsGroup": 1000, "fsGroup": 1000 }),
    );
    pod_spec.insert("dnsPolicy".into(), "ClusterFirst".into());
    pod_spec.insert(
        "initContainers".into(),
        json!([gateway_host_key_init_container(support_image)]),
    );
    pod_spec.insert("containers".into(), json!([gateway_container]));
    pod_spec.insert(
        "volumes".into(),
        json!([
            { "name": "gateway-state", "emptyDir": {} },
            {
                "name": "gateway-host-key",
                "secret": {
                    "secretName": gateway_host_key_secret_name(&opts.environment_id),
                    "items": [
                        {
                            "key": GATEWAY_HOST_KEY_SECRET_KEY,
                            "path": GATEWAY_HOST_KEY_SECRET_KEY,
                            "mode": 0o444,
                        },
                    ],
                },
            },
            {
                "name": GATEWAY_BINDING_TOKEN_VOLUME,
                "projected": {
                    "defaultMode": 0o440,
                    "sources": [
                        {
                            "serviceAccountToken": {
                                "audience": GATEWAY_BINDING_TOKEN_AUDIENCE,
                                "expirationSeconds": GATEWAY_BINDING_TOKEN_EXPIRATION_SECONDS,
                                "path": "token",
                            },
                        },
                    ],
                },
            },
        ]),
    );
    if opts.credential_runtime.is_some() {
        pod_spec
            .get_mut("volumes")
            .and_then(Value::as_array_mut)
            .expect("gateway volumes")
            .extend(credentials::gateway_volumes(opts));
    }
    if !runtime_spec.runtime_class_name.is_empty() {
        pod_spec.insert(
            "runtimeClassName".into(),
            runtime_spec.runtime_class_name.clone().into(),
        );
    }
    let mut pod_annotations = Map::new();
    if uses_kata_policy_init_data(opts, &runtime_spec) {
        pod_annotations.insert(
            KATA_COCO_INIT_DATA_ANNOTATION_KEY.into(),
            kata_policy_init_data_annotation(opts, false).into(),
        );
    }
    if let Some(kernel_params) = kata_coco_kernel_params_annotation(opts, &runtime_spec) {
        pod_annotations.insert(
            KATA_HYPERVISOR_KERNEL_PARAMS_ANNOTATION_KEY.into(),
            kernel_params.into(),
        );
    }
    let mut pod_metadata = Map::new();
    pod_metadata.insert("labels".into(), labels.clone());
    if !pod_annotations.is_empty() {
        pod_metadata.insert("annotations".into(), Value::Object(pod_annotations));
    }

    let mut deployment = json!({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": gateway_workload_name(&opts.environment_id),
            "namespace": namespace,
            "labels": labels,
        },
        "spec": {
            "replicas": 1,
            "selector": { "matchLabels": gateway_selector(opts) },
            "template": {
                "metadata": Value::Object(pod_metadata),
                "spec": Value::Object(pod_spec),
            },
        },
    });
    if runtime_spec.profile == RUNTIME_PROFILE_CONFIDENTIAL {
        // A shared-fs-none guest cannot reuse the host image store and its
        // encrypted workspace is initialized before the daemon can listen.
        // Keep all gateway startup clocks aligned; the ordinary gateway
        // retains its short process/probe behavior and Kubernetes' default.
        deployment["spec"]["progressDeadlineSeconds"] =
            CONFIDENTIAL_GATEWAY_PROGRESS_DEADLINE_SECONDS.into();
    }
    deployment
}

fn gateway_coordinator_url(opts: &TemplateOpts) -> Option<String> {
    let explicit = opts.coordinator_url.trim();
    if !explicit.is_empty() {
        return Some(explicit.to_string());
    }
    if opts.api_base_url.is_empty() {
        return None;
    }
    Some(opts.api_base_url.trim_end_matches('/').to_string())
}

fn gateway_binding_url(opts: &TemplateOpts) -> Option<String> {
    (!opts.server_namespace.is_empty()).then(|| {
        format!(
            "http://codewire-orchestration.{}.svc.cluster.local:8085",
            opts.server_namespace
        )
    })
}

/// Mirrors `sandbox.gatewayDERPURL`.
fn gateway_derp_url(opts: &TemplateOpts) -> Option<String> {
    if !opts.server_namespace.is_empty() {
        return Some(format!(
            "https://codewire-derp.{}.svc.cluster.local:{}",
            opts.server_namespace, INTERNAL_DERP_TLS_PORT
        ));
    }
    if !opts.derp_host.is_empty() && !is_loopback(&opts.derp_host) {
        let host = if opts.derp_port != 0 && opts.derp_port != 443 {
            format!("{}:{}", opts.derp_host, opts.derp_port)
        } else {
            opts.derp_host.clone()
        };
        return Some(format!("https://{host}"));
    }
    if !opts.api_base_url.is_empty()
        && let Ok(u) = url_host_scheme(&opts.api_base_url)
    {
        return Some(u);
    }
    None
}

fn url_host_scheme(raw: &str) -> Result<String, ()> {
    let (scheme, rest) = raw.split_once("://").ok_or(())?;
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    if host.is_empty() {
        return Err(());
    }
    Ok(format!("{scheme}://{host}"))
}

fn is_loopback(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}
