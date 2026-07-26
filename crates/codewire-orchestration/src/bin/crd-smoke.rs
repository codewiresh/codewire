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

use std::collections::BTreeMap;

use codewire_orchestration::sandbox::ClaimOpts;
use codewire_orchestration::sandbox::client::SandboxClient;
use codewire_orchestration::sandbox::template::{
    GATEWAY_HOST_KEY_SECRET_KEY, RUNTIME_PROFILE_COMMODITY, TemplateOpts,
    gateway_host_key_secret_name, gateway_network_policy_name, gateway_service_name,
    gateway_workload_name, workspace_daemon_network_policy_name, workspace_daemon_service_name,
};
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{Secret, Service};
use k8s_openapi::api::networking::v1::NetworkPolicy;
use kube::Api;
use serde_json::Value;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().json().init();

    let namespace = std::env::var("CRD_SMOKE_NAMESPACE").unwrap_or_else(|_| "codewire-e2e".into());
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

    let (name, uid) = client.create_sandbox_claim(&namespace, &opts).await?;
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
    anyhow::ensure!(
        spec["workspaceResources"]["containerName"] == "workspace"
            && spec["workspaceResources"]["resources"]["requests"]["cpu"] == "1000m"
            && spec["workspaceResources"]["resources"]["requests"]["memory"] == "2048Mi"
            && spec["workspaceResources"]["resources"]["requests"]["ephemeral-storage"] == "5Gi"
            && spec["workspaceResources"]["resources"]["limits"]["cpu"] == "1000m"
            && spec["workspaceResources"]["resources"]["limits"]["memory"] == "2048Mi"
            && spec["workspaceResources"]["resources"]["limits"]["ephemeral-storage"] == "5Gi",
        "workspaceResources did not round-trip: {spec}"
    );
    anyhow::ensure!(
        spec["workspaceResources"].get("cpuMillicores").is_none()
            && spec["workspaceResources"].get("memoryMiB").is_none()
            && spec["workspaceResources"].get("diskGiB").is_none(),
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
    let (name2, uid2) = client.create_sandbox_claim(&namespace, &opts).await?;
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

fn gateway_template_opts(namespace: &str) -> anyhow::Result<TemplateOpts> {
    let local_gateway = std::env::var("CRD_SMOKE_LOCAL_GATEWAY").as_deref() == Ok("1");
    let server_namespace =
        std::env::var("CRD_SMOKE_SERVER_NAMESPACE").unwrap_or_else(|_| namespace.into());
    let gateway_token =
        resolve_gateway_token(local_gateway, std::env::var("CRD_SMOKE_GATEWAY_TOKEN").ok())?;
    Ok(TemplateOpts {
        name: "tmpl-crd-smoke".into(),
        image: "ghcr.io/codewiresh/workspace:latest".into(),
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
                                    .is_some_and(|value| !value.is_empty())
                        })
                    })
            })
            .unwrap_or(false),
        "gateway deployment missing daemon address/token env"
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
    use super::resolve_gateway_token;

    #[test]
    fn local_gateway_requires_and_preserves_the_shared_daemon_credential() {
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
    }
}
