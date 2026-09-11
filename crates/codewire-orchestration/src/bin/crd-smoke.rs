//! CRD round-trip smoke for the kind-e2e job (#36 Stage A2).
//!
//! Exercises the Rust sandbox client against a REAL cluster: create a
//! SandboxClaim from the golden-pinned renderer, read it back and check
//! the spec survived the API server round-trip, strip the
//! deletion-protection finalizer, delete, and verify it is gone.
//! Exit code is the verdict; CI runs this with the kind kubeconfig
//! after applying deployments/k8s/agent-sandbox/base/crds.
//!
//! `CRD_SMOKE_GATEWAY_PHASE=setup|cleanup` lets the Kind harness restart the
//! real gateway between the existing stack-creation and lifecycle-cleanup
//! assertions. `CRD_SMOKE_LOCAL_GATEWAY=1` selects the side-loaded gateway
//! image and the diagnostic runc RuntimeClass for that disposable cluster.

use std::{collections::BTreeMap, time::Duration};

use codewire_orchestration::sandbox::client::SandboxClient;
use codewire_orchestration::sandbox::template::{
    CredentialRuntimeTemplateConfig, GATEWAY_HOST_KEY_SECRET_KEY, RUNTIME_PROFILE_COMMODITY,
    RUNTIME_PROFILE_RUNC, TemplateOpts, gateway_host_key_secret_name, gateway_network_policy_name,
    gateway_service_name, gateway_workload_name, render_sandbox_shadow_pool,
    render_sandbox_template, render_workspace_daemon_service, workspace_daemon_network_policy_name,
    workspace_daemon_service_name,
};
use codewire_orchestration::sandbox::{
    ClaimOpts, environment_template_name, render_sandbox_claim, shadow_warm_pool_name,
};
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{Secret, Service};
use k8s_openapi::api::networking::v1::NetworkPolicy;
use kube::Api;
use serde_json::{Value, json};

const RESIZE_TEMPLATE_BASE: &str = "resize-template";
const RESIZE_FIXTURE_IMAGE: &str = "codewire-gateway:e2e";
const RESIZE_MARKER_KEY: &str = "codewire.sh/resize-smoke-marker";
const RESIZE_MARKER_ENV: &str = "CODEWIRE_RESIZE_SMOKE_IDENTITY";
const RESIZE_MARKER_VALUE: &str = "preserved";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().json().init();

    let namespace = std::env::var("CRD_SMOKE_NAMESPACE").unwrap_or_else(|_| "codewire-e2e".into());
    if let Ok(phase) = std::env::var("CRD_SMOKE_RESIZE_PHASE") {
        let environment_id = required_resize_environment_id()?;
        match phase.as_str() {
            "render" => {
                let server_namespace = std::env::var("CRD_SMOKE_SERVER_NAMESPACE")
                    .unwrap_or_else(|_| namespace.clone());
                let gateway_token = required_resize_capability("CRD_SMOKE_GATEWAY_TOKEN")?;
                let daemon_auth_token = required_resize_capability("CRD_SMOKE_DAEMON_AUTH_TOKEN")?;
                let credential_runtime = CredentialRuntimeTemplateConfig::from_env(&namespace)?
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "resize fixture requires platform credential runtime configuration"
                        )
                    })?;
                let rendered = render_resize_fixture(
                    &namespace,
                    &server_namespace,
                    &environment_id,
                    &gateway_token,
                    &daemon_auth_token,
                    Some(credential_runtime),
                )?;
                println!("{}", serde_json::to_string(&rendered)?);
                return Ok(());
            }
            "release" => {
                let client = SandboxClient::from_env(&namespace).await?;
                client
                    .remove_deletion_protection_finalizer(&environment_id)
                    .await?;
                return Ok(());
            }
            _ => anyhow::bail!("CRD_SMOKE_RESIZE_PHASE must be render or release"),
        }
    }
    let client = SandboxClient::from_env(&namespace).await?;
    let gateway_phase = std::env::var("CRD_SMOKE_GATEWAY_PHASE").unwrap_or_else(|_| "full".into());
    anyhow::ensure!(
        matches!(gateway_phase.as_str(), "full" | "setup" | "cleanup"),
        "CRD_SMOKE_GATEWAY_PHASE must be full, setup, or cleanup"
    );
    let template_opts = gateway_template_opts(&namespace)?;

    if gateway_phase == "cleanup" {
        cleanup_gateway_stack(&client, &namespace, &template_opts).await?;
        println!("gateway companion object lifecycle cleanup verified — CRD smoke passed");
        return Ok(());
    }

    let opts = ClaimOpts {
        environment_id: "env-crd-smoke".into(),
        org_id: "org-crd-smoke".into(),
        operation_generation: 1,
        template_ref: "tmpl-crd-smoke".into(),
        cpu_millicores: 1000,
        memory_mib: 2048,
        disk_gib: 5,
        env_overrides: BTreeMap::from([(
            "workspace".into(),
            BTreeMap::from([("SMOKE".into(), "1".into())]),
        )]),
        ..Default::default()
    };

    let (name, uid) = create_sandbox_claim(&client, &namespace, &opts).await?;
    anyhow::ensure!(!uid.is_empty(), "created claim has no uid");
    println!("created {name} uid={uid}");

    let fetched = client
        .get_sandbox_claim(&opts.environment_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("claim not found after create"))?;
    let spec = &fetched.data["spec"];
    anyhow::ensure!(
        spec["warmPoolRef"]["name"] == "shadow-pool-tmpl-crd-smoke",
        "warmPoolRef did not round-trip: {spec}"
    );
    let workspace_resources = &spec["workspaceResources"][0];
    anyhow::ensure!(
        workspace_resources["containerName"] == "workspace"
            && workspace_resources["resources"]["requests"]["cpu"] == "1000m"
            && workspace_resources["resources"]["requests"]["memory"] == "2048Mi"
            && workspace_resources["resources"]["requests"]["ephemeral-storage"] == "5Gi"
            && workspace_resources["resources"]["limits"]["cpu"] == "1000m"
            && workspace_resources["resources"]["limits"]["memory"] == "2048Mi"
            && workspace_resources["resources"]["limits"]["ephemeral-storage"] == "5Gi",
        "workspaceResources did not round-trip: {spec}"
    );
    anyhow::ensure!(
        workspace_resources.get("cpuMillicores").is_none()
            && workspace_resources.get("memoryMiB").is_none()
            && workspace_resources.get("diskGiB").is_none(),
        "legacy workspaceResources fields unexpectedly survived: {spec}"
    );
    anyhow::ensure!(
        spec["env"]
            .as_array()
            .is_some_and(|env| env.iter().any(|entry| {
                entry["containerName"] == "workspace"
                    && entry["name"] == "SMOKE"
                    && entry["value"] == "1"
            })),
        "env did not round-trip: {spec}"
    );
    anyhow::ensure!(
        spec.get("envOverrides").is_none(),
        "legacy envOverrides unexpectedly survived: {spec}"
    );
    let finalizers = fetched.metadata.finalizers.clone().unwrap_or_default();
    anyhow::ensure!(
        finalizers
            .iter()
            .any(|f| f == "codewire.sh/deletion-protection"),
        "deletion-protection finalizer missing: {finalizers:?}"
    );
    println!("round-trip verified");

    // Idempotent create: AlreadyExists must be reused, not an error.
    let (name2, uid2) = create_sandbox_claim(&client, &namespace, &opts).await?;
    anyhow::ensure!(
        name2 == name && uid2 == uid,
        "re-create did not reuse the claim"
    );
    println!("already-exists reuse verified");

    client
        .remove_deletion_protection_finalizer(&opts.environment_id)
        .await?;
    client.delete_sandbox_claim(&opts.environment_id).await?;
    anyhow::ensure!(
        client
            .get_sandbox_claim(&opts.environment_id)
            .await?
            .is_none(),
        "claim still present after delete"
    );
    println!("delete verified");

    client
        .delete_gateway_stack(&template_opts.environment_id)
        .await?;
    client
        .delete_gateway_host_key_secret(&template_opts.environment_id)
        .await?;
    let gateway_result = verify_gateway_stack(&client, &namespace, &template_opts).await;
    if gateway_phase == "setup" {
        gateway_result?;
        println!("gateway companion object setup verified — awaiting restart smoke");
        return Ok(());
    }
    let cleanup_result = client
        .delete_gateway_stack(&template_opts.environment_id)
        .await;
    let secret_preserved_result =
        verify_gateway_host_key_secret(&namespace, &template_opts, "post-stack-delete").await;
    let secret_cleanup_result = client
        .delete_gateway_host_key_secret(&template_opts.environment_id)
        .await;
    gateway_result?;
    cleanup_result?;
    secret_preserved_result?;
    secret_cleanup_result?;
    println!("gateway companion object round-trip verified — CRD smoke passed");
    Ok(())
}

fn required_resize_environment_id() -> anyhow::Result<String> {
    let value = std::env::var("CRD_SMOKE_RESIZE_ENVIRONMENT_ID")
        .map_err(|_| anyhow::anyhow!("CRD_SMOKE_RESIZE_ENVIRONMENT_ID is required"))?;
    validate_resize_environment_id(&value)?;
    Ok(value)
}

fn validate_resize_environment_id(value: &str) -> anyhow::Result<()> {
    let parsed = uuid::Uuid::parse_str(value)
        .map_err(|_| anyhow::anyhow!("resize fixture environment identity must be a UUID"))?;
    anyhow::ensure!(
        !parsed.is_nil() && parsed.hyphenated().to_string() == value,
        "resize fixture environment identity must be a canonical non-nil UUID"
    );
    Ok(())
}

fn required_resize_capability(name: &str) -> anyhow::Result<String> {
    let value = std::env::var(name).map_err(|_| anyhow::anyhow!("{name} is required"))?;
    anyhow::ensure!(
        !value.trim().is_empty() && value.trim() == value,
        "{name} must be a non-empty canonical capability"
    );
    Ok(value)
}

fn render_resize_fixture(
    namespace: &str,
    server_namespace: &str,
    environment_id: &str,
    gateway_token: &str,
    daemon_auth_token: &str,
    credential_runtime: Option<CredentialRuntimeTemplateConfig>,
) -> anyhow::Result<Value> {
    validate_resize_environment_id(environment_id)?;
    anyhow::ensure!(
        !namespace.trim().is_empty()
            && namespace.trim() == namespace
            && !server_namespace.trim().is_empty()
            && server_namespace.trim() == server_namespace,
        "resize fixture namespaces must be non-empty canonical values"
    );
    anyhow::ensure!(
        !gateway_token.trim().is_empty()
            && gateway_token.trim() == gateway_token
            && !daemon_auth_token.trim().is_empty()
            && daemon_auth_token.trim() == daemon_auth_token
            && gateway_token != daemon_auth_token,
        "resize fixture requires distinct canonical coordinate and daemon capabilities"
    );

    let template_name = environment_template_name(RESIZE_TEMPLATE_BASE, environment_id);
    let shadow_pool_name = shadow_warm_pool_name(&template_name);
    let opts = TemplateOpts {
        name: template_name.clone(),
        image: RESIZE_FIXTURE_IMAGE.into(),
        image_command: vec!["sleep".into(), "infinity".into()],
        support_image: RESIZE_FIXTURE_IMAGE.into(),
        runtime_profile: RUNTIME_PROFILE_RUNC.into(),
        environment_id: environment_id.into(),
        organization_id: "org_contract_1".into(),
        operation_generation: 1,
        credential_runtime,
        gateway_token: gateway_token.into(),
        daemon_auth_token: daemon_auth_token.into(),
        server_namespace: server_namespace.into(),
        cpu_millicores: 250,
        memory_mib: 256,
        disk_gib: 1,
        workspace_storage_class: "standard".into(),
        ..Default::default()
    };
    let mut template = render_sandbox_template(namespace, &opts);
    let pod_labels = template
        .pointer_mut("/spec/podTemplate/metadata/labels")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| anyhow::anyhow!("rendered resize template has no Pod labels"))?;
    pod_labels.insert(RESIZE_MARKER_KEY.into(), RESIZE_MARKER_VALUE.into());
    let containers = template
        .pointer_mut("/spec/podTemplate/spec/containers")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| anyhow::anyhow!("rendered resize template has no containers"))?;
    let workspace_indexes = containers
        .iter()
        .enumerate()
        .filter_map(|(index, container)| (container["name"] == "workspace").then_some(index))
        .collect::<Vec<_>>();
    anyhow::ensure!(
        workspace_indexes.len() == 1,
        "rendered resize template requires exactly one workspace container"
    );
    let workspace = &mut containers[workspace_indexes[0]];
    anyhow::ensure!(
        workspace["image"] == RESIZE_FIXTURE_IMAGE,
        "rendered resize workspace image changed"
    );
    workspace["imagePullPolicy"] = "Never".into();
    workspace["readinessProbe"] = json!({
        "tcpSocket": {"port": 7777},
        "periodSeconds": 1,
        "timeoutSeconds": 1,
    });
    workspace["env"]
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("rendered resize workspace environment is malformed"))?
        .push(json!({"name": RESIZE_MARKER_ENV, "value": RESIZE_MARKER_VALUE}));
    let init_containers = template
        .pointer_mut("/spec/podTemplate/spec/initContainers")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| anyhow::anyhow!("rendered resize template has no init containers"))?;
    let daemon_init_indexes = init_containers
        .iter()
        .enumerate()
        .filter_map(|(index, container)| {
            (container["name"] == "codewire-daemon-init").then_some(index)
        })
        .collect::<Vec<_>>();
    anyhow::ensure!(
        daemon_init_indexes.len() == 1,
        "rendered resize template requires exactly one daemon init container"
    );
    let daemon_init = &mut init_containers[daemon_init_indexes[0]];
    anyhow::ensure!(
        daemon_init["image"] == RESIZE_FIXTURE_IMAGE,
        "rendered resize daemon init image changed"
    );
    daemon_init["imagePullPolicy"] = "Never".into();

    let claim = render_sandbox_claim(
        namespace,
        &ClaimOpts {
            environment_id: environment_id.into(),
            org_id: opts.organization_id.clone(),
            operation_generation: opts.operation_generation,
            warm_pool_ref: shadow_pool_name.clone(),
            template_ref: template_name.clone(),
            cpu_millicores: opts.cpu_millicores,
            memory_mib: opts.memory_mib,
            disk_gib: opts.disk_gib,
            ..Default::default()
        },
    );
    Ok(json!({
        "apiVersion": "v1",
        "kind": "List",
        "items": [
            template,
            render_sandbox_shadow_pool(
                namespace,
                &shadow_pool_name,
                &template_name,
                environment_id,
            ),
            claim,
            render_workspace_daemon_service(namespace, &opts),
        ],
    }))
}

async fn create_sandbox_claim(
    client: &SandboxClient,
    namespace: &str,
    opts: &ClaimOpts,
) -> anyhow::Result<(String, String)> {
    const ATTEMPTS: usize = 3;

    for attempt in 1..=ATTEMPTS {
        match client.create_sandbox_claim(namespace, opts).await {
            Ok(created) => return Ok(created),
            Err(error) => {
                let message = format!("{error:#}");
                if attempt == ATTEMPTS || !is_transient_apiserver_shutdown(&message) {
                    return Err(error);
                }
                eprintln!(
                    "transient Kind API shutdown while creating SandboxClaim; retrying ({attempt}/{ATTEMPTS})"
                );
                tokio::time::sleep(Duration::from_secs(attempt as u64)).await;
            }
        }
    }

    unreachable!("bounded SandboxClaim create loop always returns")
}

fn is_transient_apiserver_shutdown(message: &str) -> bool {
    message.contains("apiserver is shutting down")
        && (message.contains("ServiceUnavailable") || message.contains("503"))
}

fn gateway_template_opts(namespace: &str) -> anyhow::Result<TemplateOpts> {
    let local_gateway = std::env::var("CRD_SMOKE_LOCAL_GATEWAY").as_deref() == Ok("1");
    let server_namespace =
        std::env::var("CRD_SMOKE_SERVER_NAMESPACE").unwrap_or_else(|_| namespace.into());
    let workspace_image = std::env::var("CRD_SMOKE_WORKSPACE_IMAGE").unwrap_or_else(|_| {
        "ghcr.io/codewiresh/workspace@sha256:18af6b9ff1ac123754aff20b3229ecf882b5553117d9c5fbe43ab2f36f282cff".into()
    });
    let gateway_token =
        resolve_gateway_token(local_gateway, std::env::var("CRD_SMOKE_GATEWAY_TOKEN").ok())?;
    let daemon_auth_token = resolve_daemon_auth_token(
        local_gateway,
        std::env::var("CRD_SMOKE_DAEMON_AUTH_TOKEN").ok(),
    )?;
    anyhow::ensure!(
        gateway_token != daemon_auth_token,
        "CRD smoke coordinate and daemon capabilities must be distinct"
    );
    Ok(TemplateOpts {
        name: "tmpl-crd-smoke".into(),
        image: workspace_image,
        support_image: if local_gateway {
            "codewire-gateway:e2e".into()
        } else {
            "ghcr.io/codewiresh/gateway:crd-smoke".into()
        },
        runtime_profile: if local_gateway {
            "runc".into()
        } else {
            RUNTIME_PROFILE_COMMODITY.into()
        },
        environment_id: "env-crd-smoke".into(),
        gateway_token,
        organization_id: "org-crd-smoke".into(),
        operation_generation: 1,
        daemon_auth_token,
        api_base_url: if local_gateway {
            String::new()
        } else {
            "https://codewire-dev.sh".into()
        },
        server_namespace: server_namespace.clone(),
        derp_host: "derp.codewire-dev.sh".into(),
        derp_port: 443,
        stun_host: "stun.codewire-dev.sh".into(),
        stun_port: 3478,
        udp_relay_allocator_url: format!(
            "http://codewire-udp-relay.{server_namespace}.svc.cluster.local:8095/internal/udp-relay/allocations"
        ),
        udp_relay_bind_addrs: format!(
            "codewire-udp-relay.{server_namespace}.svc.cluster.local:41641"
        ),
        cpu_millicores: 1000,
        memory_mib: 2048,
        disk_gib: 5,
        workspace_storage_class: "standard".into(),
        ..Default::default()
    })
}

fn resolve_gateway_token(local_gateway: bool, token: Option<String>) -> anyhow::Result<String> {
    match token {
        Some(token) if !token.trim().is_empty() => Ok(token),
        _ if local_gateway => {
            anyhow::bail!("CRD_SMOKE_GATEWAY_TOKEN is required with CRD_SMOKE_LOCAL_GATEWAY=1")
        }
        _ => Ok("gateway-crd-smoke-token".into()),
    }
}

fn resolve_daemon_auth_token(local_gateway: bool, token: Option<String>) -> anyhow::Result<String> {
    match token {
        Some(token) if !token.trim().is_empty() => Ok(token),
        _ if local_gateway => {
            anyhow::bail!("CRD_SMOKE_DAEMON_AUTH_TOKEN is required with CRD_SMOKE_LOCAL_GATEWAY=1")
        }
        _ => Ok("daemon-crd-smoke-token".into()),
    }
}

async fn cleanup_gateway_stack(
    client: &SandboxClient,
    namespace: &str,
    opts: &TemplateOpts,
) -> anyhow::Result<()> {
    client.delete_gateway_stack(&opts.environment_id).await?;
    verify_gateway_host_key_secret(namespace, opts, "post-stack-delete").await?;
    client
        .delete_gateway_host_key_secret(&opts.environment_id)
        .await
}

async fn verify_gateway_stack(
    client: &SandboxClient,
    namespace: &str,
    opts: &TemplateOpts,
) -> anyhow::Result<()> {
    client.ensure_gateway_stack(opts).await?;

    let kube = kube::Client::try_default().await?;
    let services: Api<Service> = Api::namespaced(kube.clone(), namespace);
    let deployments: Api<Deployment> = Api::namespaced(kube.clone(), namespace);
    let secrets: Api<Secret> = Api::namespaced(kube.clone(), namespace);
    let network_policies: Api<NetworkPolicy> = Api::namespaced(kube, namespace);

    let gateway_host_key_secret = secrets
        .get(&gateway_host_key_secret_name(&opts.environment_id))
        .await?;
    let gateway_host_key_secret_value = serde_json::to_value(&gateway_host_key_secret)?;
    ensure_gateway_host_key_secret_shape(&gateway_host_key_secret_value, opts, "initial")?;

    let gateway_service = services
        .get(&gateway_service_name(&opts.environment_id))
        .await?;
    let gateway_service_value = serde_json::to_value(&gateway_service)?;
    ensure_service_is_cluster_ip_without_nodeports(&gateway_service_value, "gateway service")?;
    anyhow::ensure!(
        has_service_port(&gateway_service_value, "ssh", 2222, "TCP")
            && has_service_port(&gateway_service_value, "readyz", 2223, "TCP")
            && has_service_port(&gateway_service_value, "tailnet-udp", 31000, "UDP"),
        "gateway service missing expected ports: {gateway_service_value}"
    );

    let daemon_service = services
        .get(&workspace_daemon_service_name(&opts.environment_id))
        .await?;
    let daemon_service_value = serde_json::to_value(&daemon_service)?;
    ensure_service_is_cluster_ip_without_nodeports(
        &daemon_service_value,
        "workspace daemon service",
    )?;
    anyhow::ensure!(
        has_service_port(&daemon_service_value, "daemon", 7777, "TCP"),
        "workspace daemon service missing daemon port: {daemon_service_value}"
    );

    let gateway_deployment = deployments
        .get(&gateway_workload_name(&opts.environment_id))
        .await?;
    let gateway_deployment_value = serde_json::to_value(&gateway_deployment)?;
    anyhow::ensure!(
        gateway_deployment_value["spec"]["template"]["spec"]["containers"]
            .as_array()
            .map(|containers| {
                containers.len() == 1
                    && containers[0]["name"] == "codewire-gateway"
                    && containers[0]["env"].as_array().is_some_and(|env| {
                        env.iter().any(|entry| {
                            entry["name"] == "CODEWIRE_WORKSPACE_SHIM_ADDR"
                                && entry["value"]
                                    .as_str()
                                    .is_some_and(|value| value.contains(":7777"))
                        }) && env.iter().any(|entry| {
                            entry["name"] == "CODEWIRE_DAEMON_AUTH_TOKEN"
                                && entry["value"]
                                    .as_str()
                                    .is_some_and(|value| value == opts.daemon_auth_token)
                        }) && env.iter().any(|entry| {
                            entry["name"] == "CODEWIRE_GATEWAY_TOKEN"
                                && entry["value"]
                                    .as_str()
                                    .is_some_and(|value| value == opts.gateway_token)
                        })
                    })
            })
            .unwrap_or(false),
        "gateway deployment did not keep coordinate and daemon capabilities separated"
    );
    let expected_runtime_class = opts.runtime_profile_spec().runtime_class_name;
    anyhow::ensure!(
        gateway_deployment_value["spec"]["template"]["spec"]["runtimeClassName"]
            == expected_runtime_class,
        "gateway deployment runtime class did not match {:?}",
        expected_runtime_class
    );
    anyhow::ensure!(
        value_contains(&gateway_deployment_value, "gateway-host-key")
            && value_contains(&gateway_deployment_value, "codewire-gateway-host-key-init")
            && value_contains(
                &gateway_deployment_value,
                "/codewire/gateway/ssh/host_ed25519"
            ),
        "gateway deployment missing host-key Secret mount/init shape"
    );

    let gateway_policy = network_policies
        .get(&gateway_network_policy_name(&opts.environment_id))
        .await?;
    let gateway_policy_value = serde_json::to_value(&gateway_policy)?;
    anyhow::ensure!(
        gateway_policy_value["spec"]["podSelector"]["matchLabels"]["codewire.sh/type"] == "gateway",
        "gateway NetworkPolicy selector is wrong: {gateway_policy_value}"
    );
    anyhow::ensure!(
        value_contains(&gateway_policy_value, "7777")
            && value_contains(&gateway_policy_value, "31000")
            && value_contains(&gateway_policy_value, "3478"),
        "gateway NetworkPolicy missing daemon/UDP/STUN shape: {gateway_policy_value}"
    );

    let daemon_policy = network_policies
        .get(&workspace_daemon_network_policy_name(&opts.environment_id))
        .await?;
    let daemon_policy_value = serde_json::to_value(&daemon_policy)?;
    anyhow::ensure!(
        daemon_policy_value["spec"]["podSelector"]["matchLabels"]["codewire.sh/type"]
            == "workspace",
        "workspace daemon NetworkPolicy selector is wrong: {daemon_policy_value}"
    );
    anyhow::ensure!(
        value_contains(&daemon_policy_value, "gateway")
            && value_contains(&daemon_policy_value, "7777"),
        "workspace daemon NetworkPolicy missing gateway-to-daemon ingress: {daemon_policy_value}"
    );
    anyhow::ensure!(
        has_orchestration_daemon_and_preview_ingress(&daemon_policy_value, &opts.server_namespace),
        "workspace daemon NetworkPolicy missing orchestration-to-daemon/app-preview ingress: {daemon_policy_value}"
    );

    Ok(())
}

async fn verify_gateway_host_key_secret(
    namespace: &str,
    opts: &TemplateOpts,
    phase: &str,
) -> anyhow::Result<()> {
    let kube = kube::Client::try_default().await?;
    let secrets: Api<Secret> = Api::namespaced(kube, namespace);
    let secret = secrets
        .get(&gateway_host_key_secret_name(&opts.environment_id))
        .await?;
    let secret_value = serde_json::to_value(&secret)?;
    ensure_gateway_host_key_secret_shape(&secret_value, opts, phase)
}

fn ensure_gateway_host_key_secret_shape(
    value: &Value,
    opts: &TemplateOpts,
    phase: &str,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        value["metadata"]["labels"]["codewire.sh/environment-id"] == opts.environment_id,
        "gateway host key Secret missing environment label during {phase}"
    );
    anyhow::ensure!(
        value["metadata"]["labels"]["codewire.sh/type"] == "gateway-host-key",
        "gateway host key Secret missing type label during {phase}"
    );
    anyhow::ensure!(
        value["data"][GATEWAY_HOST_KEY_SECRET_KEY]
            .as_str()
            .is_some_and(|encoded| !encoded.trim().is_empty()),
        "gateway host key Secret missing data key during {phase}"
    );
    Ok(())
}

fn ensure_service_is_cluster_ip_without_nodeports(
    value: &Value,
    label: &str,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        value["spec"]["type"] == "ClusterIP",
        "{label} is not ClusterIP: {value}"
    );
    let has_nodeport = value["spec"]["ports"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|port| port.get("nodePort").is_some());
    anyhow::ensure!(!has_nodeport, "{label} unexpectedly has nodePort: {value}");
    Ok(())
}

fn has_service_port(value: &Value, name: &str, port: i64, protocol: &str) -> bool {
    value["spec"]["ports"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|entry| {
            entry["name"] == name && entry["port"] == port && entry["protocol"] == protocol
        })
}

fn has_orchestration_daemon_and_preview_ingress(value: &Value, server_namespace: &str) -> bool {
    value["spec"]["ingress"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|ingress| {
            let from_matches = ingress["from"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|from| {
                    from["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"]
                        == server_namespace
                        && from["podSelector"]["matchLabels"]["app.kubernetes.io/name"]
                            == "codewire"
                        && from["podSelector"]["matchLabels"]["app.kubernetes.io/component"]
                            == "orchestration"
                });
            let daemon_port_matches = ingress["ports"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|port| port["protocol"] == "TCP" && port["port"] == 7777);
            let preview_port_matches =
                ingress["ports"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .any(|port| {
                        port["protocol"] == "TCP" && port["port"] == 1 && port["endPort"] == 65535
                    });
            from_matches && daemon_port_matches && preview_port_matches
        })
}

fn value_contains(value: &Value, needle: &str) -> bool {
    serde_json::to_string(value)
        .map(|encoded| encoded.contains(needle))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::{
        RESIZE_MARKER_ENV, RESIZE_MARKER_KEY, RESIZE_MARKER_VALUE, RESIZE_TEMPLATE_BASE,
        is_transient_apiserver_shutdown, render_resize_fixture, resolve_daemon_auth_token,
        resolve_gateway_token, validate_resize_environment_id,
    };

    const RESIZE_ENV: &str = "00000000-0000-4000-8000-000000000123";

    fn resize_fixture() -> serde_json::Value {
        render_resize_fixture(
            "dev-sandboxes",
            "codewire-e2e",
            RESIZE_ENV,
            "synthetic-coordinate-capability",
            "synthetic-daemon-capability",
            None,
        )
        .unwrap()
    }

    fn item<'a>(fixture: &'a serde_json::Value, kind: &str) -> &'a serde_json::Value {
        fixture["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["kind"] == kind)
            .unwrap()
    }

    #[test]
    fn classifies_only_the_observed_transient_shutdown() {
        assert!(is_transient_apiserver_shutdown(
            "ApiError: apiserver is shutting down: ServiceUnavailable (code: 503)"
        ));
        assert!(!is_transient_apiserver_shutdown(
            "ApiError: admission denied: Forbidden (code: 403)"
        ));
        assert!(!is_transient_apiserver_shutdown(
            "ApiError: service unavailable for an unknown reason (code: 503)"
        ));
    }

    #[test]
    fn local_gateway_requires_distinct_coordinate_and_daemon_credentials() {
        assert!(resolve_gateway_token(true, None).is_err());
        assert!(resolve_gateway_token(true, Some("  ".into())).is_err());
        assert_eq!(
            resolve_gateway_token(true, Some("derived-environment-token".into())).unwrap(),
            "derived-environment-token"
        );
        assert_eq!(
            resolve_gateway_token(false, None).unwrap(),
            "gateway-crd-smoke-token"
        );
        assert!(resolve_daemon_auth_token(true, None).is_err());
        assert!(resolve_daemon_auth_token(true, Some("  ".into())).is_err());
        assert_eq!(
            resolve_daemon_auth_token(true, Some("derived-daemon-token".into())).unwrap(),
            "derived-daemon-token"
        );
        assert_eq!(
            resolve_daemon_auth_token(false, None).unwrap(),
            "daemon-crd-smoke-token"
        );
    }

    #[test]
    fn resize_fixture_uses_owned_hashed_shadow_and_exact_resources() {
        let fixture = resize_fixture();
        assert_eq!(fixture["apiVersion"], "v1");
        assert_eq!(fixture["kind"], "List");
        assert_eq!(fixture["items"].as_array().unwrap().len(), 4);

        let template = item(&fixture, "SandboxTemplate");
        let template_name = format!("{RESIZE_TEMPLATE_BASE}-{RESIZE_ENV}");
        assert_eq!(template["metadata"]["name"], template_name);
        assert_eq!(
            template["metadata"]["labels"]["codewire.sh/environment-id"],
            RESIZE_ENV
        );
        let pool = item(&fixture, "SandboxWarmPool");
        let pool_name = pool["metadata"]["name"].as_str().unwrap();
        assert_eq!(pool_name.len(), 63);
        assert_ne!(pool_name, format!("shadow-pool-{template_name}"));
        assert_eq!(pool["spec"]["replicas"], 0);
        assert_eq!(pool["spec"]["sandboxTemplateRef"]["name"], template_name);
        assert_eq!(
            pool["metadata"]["labels"]["codewire.sh/environment-id"],
            RESIZE_ENV
        );

        let claim = item(&fixture, "SandboxClaim");
        assert_eq!(claim["metadata"]["name"], format!("sandbox-{RESIZE_ENV}"));
        assert_eq!(claim["spec"]["warmPoolRef"]["name"], pool_name);
        assert_eq!(
            claim["metadata"]["finalizers"],
            serde_json::json!(["codewire.sh/deletion-protection"])
        );
        assert_eq!(
            claim["metadata"]["labels"]["codewire.sh/environment-id"],
            RESIZE_ENV
        );
        assert_eq!(
            claim["metadata"]["labels"]["codewire.sh/environment-operation-generation"],
            "1"
        );
        let resources = &claim["spec"]["workspaceResources"][0]["resources"];
        assert_eq!(resources["requests"]["cpu"], "250m");
        assert_eq!(resources["requests"]["memory"], "256Mi");
        assert_eq!(resources["requests"]["ephemeral-storage"], "1Gi");
        assert_eq!(resources["limits"], resources["requests"]);

        let service = item(&fixture, "Service");
        assert_eq!(
            service["metadata"]["name"],
            format!("cw-daemon-{RESIZE_ENV}")
        );
        assert_eq!(
            service["spec"]["selector"]["codewire.sh/environment-id"],
            RESIZE_ENV
        );
        assert_eq!(service["spec"]["selector"]["codewire.sh/type"], "workspace");
    }

    #[test]
    fn resize_fixture_keeps_daemon_bootstrap_mounts_and_only_synthetic_identity() {
        let fixture = resize_fixture();
        let template = item(&fixture, "SandboxTemplate");
        assert_eq!(
            template["spec"]["podTemplate"]["metadata"]["labels"][RESIZE_MARKER_KEY],
            RESIZE_MARKER_VALUE
        );
        let pod_spec = &template["spec"]["podTemplate"]["spec"];
        let init = pod_spec["initContainers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|container| container["name"] == "codewire-daemon-init")
            .unwrap();
        let init_mounts = init["volumeMounts"].as_array().unwrap();
        assert_eq!(init["image"], "codewire-gateway:e2e");
        assert_eq!(init["imagePullPolicy"], "Never");
        for name in ["codewire-bin", "codewire-run"] {
            assert!(init_mounts.iter().any(|mount| mount["name"] == name));
        }
        let workspace = pod_spec["containers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|container| container["name"] == "workspace")
            .unwrap();
        assert_eq!(workspace["image"], "codewire-gateway:e2e");
        assert_eq!(workspace["imagePullPolicy"], "Never");
        assert_eq!(
            workspace["readinessProbe"],
            serde_json::json!({
                "tcpSocket":{"port":7777},
                "periodSeconds":1,
                "timeoutSeconds":1,
            })
        );
        assert!(
            workspace["command"]
                .as_array()
                .unwrap()
                .iter()
                .any(|argument| argument.as_str().is_some_and(|argument| {
                    argument.contains("__hosted-daemon") && argument.contains("'sleep' 'infinity'")
                }))
        );
        for name in ["workspace", "codewire-bin", "codewire-run"] {
            assert!(
                workspace["volumeMounts"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|mount| mount["name"] == name)
            );
        }
        assert_eq!(workspace["resources"]["requests"]["cpu"], "250m");
        assert_eq!(workspace["resources"]["requests"]["memory"], "256Mi");
        assert_eq!(
            workspace["resizePolicy"],
            serde_json::json!([
                {"resourceName":"cpu","restartPolicy":"NotRequired"},
                {"resourceName":"memory","restartPolicy":"NotRequired"},
            ])
        );
        assert!(workspace["env"].as_array().unwrap().iter().any(|entry| {
            entry["name"] == RESIZE_MARKER_ENV && entry["value"] == RESIZE_MARKER_VALUE
        }));
        let encoded = serde_json::to_string(&fixture).unwrap();
        for provider_secret in [
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
            "GITHUB_TOKEN",
            "SSH_PRIVATE_KEY",
        ] {
            assert!(!encoded.contains(provider_secret));
        }
    }

    #[test]
    fn resize_fixture_rejects_noncanonical_or_ambiguous_identity() {
        for invalid in [
            "not-a-uuid",
            "00000000000040008000000000000123",
            "00000000-0000-0000-0000-000000000000",
            "00000000-0000-4000-8000-00000000012A",
        ] {
            assert!(validate_resize_environment_id(invalid).is_err());
        }
        assert!(
            render_resize_fixture(
                "dev-sandboxes",
                "codewire-e2e",
                RESIZE_ENV,
                "same-capability",
                "same-capability",
                None,
            )
            .is_err()
        );
    }
}
