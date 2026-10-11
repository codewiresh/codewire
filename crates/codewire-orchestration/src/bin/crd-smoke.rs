//! CRD round-trip smoke for the kind-e2e job (#36 Stage A2).
//!
//! Exercises the Rust sandbox client against a REAL cluster: create a
//! SandboxClaim from the golden-pinned renderer, read it back and check
//! the spec survived the API server round-trip, strip the
//! deletion-protection finalizer, delete, and verify it is gone.
//! Exit code is the verdict; CI runs this with the kind kubeconfig
//! after applying deployments/k8s/agent-sandbox/base/crds.
//!
//! It then proves the environment's access objects: the daemon Service and
//! the workspace NetworkPolicy (orchestration to the daemon, SSH and preview
//! ports; world-only tailnet UDP), since the workspace daemon hosts SSH and
//! the tailnet. `CRD_SMOKE_ACCESS_PHASE=
//! setup|cleanup` lets the Kind harness keep those objects for its daemon
//! fixture between the two assertions. `CRD_SMOKE_LOCAL_IMAGES=1` selects the
//! side-loaded daemon image and the diagnostic runc RuntimeClass for that
//! disposable cluster.

use std::{collections::BTreeMap, time::Duration};

use codewire_daemon_proto::{WORKSPACE_SSH_PORT, WORKSPACE_TAILNET_UDP_PORT};
use codewire_orchestration::sandbox::client::SandboxClient;
use codewire_orchestration::sandbox::template::{
    CredentialRuntimeTemplateConfig, RUNTIME_PROFILE_COMMODITY, RUNTIME_PROFILE_RUNC, TemplateOpts,
    WorkspaceIdentity, render_sandbox_shadow_pool, render_sandbox_template,
    render_workspace_daemon_service, workspace_daemon_network_policy_name,
    workspace_daemon_service_name,
};
use codewire_orchestration::sandbox::{
    ClaimOpts, environment_template_name, render_sandbox_claim, shadow_warm_pool_name,
};
use codewire_orchestration::worker::create::workspace_binding_url;
use k8s_openapi::api::core::v1::Service;
use k8s_openapi::api::networking::v1::NetworkPolicy;
use kube::Api;
use serde_json::{Value, json};

const RESIZE_TEMPLATE_BASE: &str = "resize-template";
const RESIZE_FIXTURE_IMAGE: &str = "codewire-daemon:e2e";
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
    let access_phase = std::env::var("CRD_SMOKE_ACCESS_PHASE").unwrap_or_else(|_| "full".into());
    anyhow::ensure!(
        matches!(access_phase.as_str(), "full" | "setup" | "cleanup"),
        "CRD_SMOKE_ACCESS_PHASE must be full, setup, or cleanup"
    );
    let template_opts = access_template_opts(&namespace);

    if access_phase == "cleanup" {
        cleanup_access_stack(&client, &namespace, &template_opts).await?;
        println!("access object cleanup verified — CRD smoke passed");
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
        .delete_access_stack(&template_opts.environment_id)
        .await?;
    let access_result = verify_access_stack(&client, &namespace, &template_opts).await;
    if access_phase == "setup" {
        access_result?;
        println!("access object setup verified — retaining them for the daemon fixture");
        return Ok(());
    }
    let cleanup_result = cleanup_access_stack(&client, &namespace, &template_opts).await;
    access_result?;
    cleanup_result?;
    println!("access object round-trip verified — CRD smoke passed");
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

/// The resize smoke's environment, rendered identity-free like every
/// commodity workspace: the Pod carries no capability or environment
/// identity, writes its readiness marker before it binds, and is bound by the
/// resize's own runtime-identity reconcile, as a start binds a replacement.
fn render_resize_fixture(
    namespace: &str,
    server_namespace: &str,
    environment_id: &str,
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
        workspace_identity: WorkspaceIdentity::Binding {
            binding_url: workspace_binding_url(server_namespace),
        },
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

/// The access objects the smoke renders for `env-crd-smoke`. Nothing here is
/// a capability: the daemon Service, its policy and the direct-UDP Service
/// carry none, and the daemon fixture receives its own.
fn access_template_opts(namespace: &str) -> TemplateOpts {
    let local_images = std::env::var("CRD_SMOKE_LOCAL_IMAGES").as_deref() == Ok("1");
    let server_namespace =
        std::env::var("CRD_SMOKE_SERVER_NAMESPACE").unwrap_or_else(|_| namespace.into());
    let workspace_image = std::env::var("CRD_SMOKE_WORKSPACE_IMAGE").unwrap_or_else(|_| {
        codewire_orchestration::sandbox::PUBLIC_CANONICAL_WORKSPACE_RUNTIME_IMAGE.into()
    });
    TemplateOpts {
        name: "tmpl-crd-smoke".into(),
        image: workspace_image,
        support_image: if local_images {
            "codewire-daemon:e2e".into()
        } else {
            "ghcr.io/codewiresh/daemon:crd-smoke".into()
        },
        runtime_profile: if local_images {
            "runc".into()
        } else {
            RUNTIME_PROFILE_COMMODITY.into()
        },
        environment_id: "env-crd-smoke".into(),
        organization_id: "org-crd-smoke".into(),
        operation_generation: 1,
        api_base_url: if local_images {
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
    }
}

/// Remove the access objects and prove they are gone.
async fn cleanup_access_stack(
    client: &SandboxClient,
    namespace: &str,
    opts: &TemplateOpts,
) -> anyhow::Result<()> {
    client.delete_access_stack(&opts.environment_id).await?;
    let kube = kube::Client::try_default().await?;
    let services: Api<Service> = Api::namespaced(kube.clone(), namespace);
    let network_policies: Api<NetworkPolicy> = Api::namespaced(kube, namespace);
    let daemon_service = workspace_daemon_service_name(&opts.environment_id);
    anyhow::ensure!(
        services.get_opt(&daemon_service).await?.is_none(),
        "workspace daemon Service {daemon_service} survived the access stack delete"
    );
    let daemon_policy = workspace_daemon_network_policy_name(&opts.environment_id);
    anyhow::ensure!(
        network_policies.get_opt(&daemon_policy).await?.is_none(),
        "workspace NetworkPolicy {daemon_policy} survived the access stack delete"
    );
    Ok(())
}

/// Apply the access objects and prove their shape: the daemon Service, the
/// workspace NetworkPolicy admitting orchestration to the daemon, SSH and
/// preview ports and the world (never the cluster) to the tailnet UDP port.
async fn verify_access_stack(
    client: &SandboxClient,
    namespace: &str,
    opts: &TemplateOpts,
) -> anyhow::Result<()> {
    client.ensure_access_stack(opts).await?;

    let kube = kube::Client::try_default().await?;
    let services: Api<Service> = Api::namespaced(kube.clone(), namespace);
    let network_policies: Api<NetworkPolicy> = Api::namespaced(kube, namespace);

    let daemon_service = services
        .get(&workspace_daemon_service_name(&opts.environment_id))
        .await?;
    let daemon_service_value = serde_json::to_value(&daemon_service)?;
    ensure_service_is_cluster_ip_without_nodeports(
        &daemon_service_value,
        "workspace daemon service",
    )?;
    anyhow::ensure!(
        has_service_port(&daemon_service_value, "daemon", 7777, "TCP")
            && daemon_service_value["spec"]["ports"]
                .as_array()
                .is_some_and(|ports| ports.len() == 1),
        "workspace daemon service must expose exactly the daemon port: {daemon_service_value}"
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
        has_orchestration_access_ingress(&daemon_policy_value, &opts.server_namespace),
        "workspace daemon NetworkPolicy missing orchestration-to-daemon/SSH/app-preview ingress: {daemon_policy_value}"
    );
    anyhow::ensure!(
        has_world_only_tailnet_ingress(&daemon_policy_value),
        "workspace daemon NetworkPolicy missing world-only tailnet UDP ingress: {daemon_policy_value}"
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

fn has_orchestration_access_ingress(value: &Value, server_namespace: &str) -> bool {
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
            let ports = || ingress["ports"].as_array().into_iter().flatten();
            let tcp_port =
                |want: i64| ports().any(|port| port["protocol"] == "TCP" && port["port"] == want);
            let preview_port_matches = ports().any(|port| {
                port["protocol"] == "TCP" && port["port"] == 1 && port["endPort"] == 65535
            });
            from_matches
                && tcp_port(7777)
                && tcp_port(i64::from(WORKSPACE_SSH_PORT))
                && preview_port_matches
        })
}

/// The tailnet UDP port admits only world addresses: every peer is an
/// `ipBlock` whose exceptions cover the private, carrier-grade NAT and
/// loopback ranges, so no cluster or Pod address can reach it.
fn has_world_only_tailnet_ingress(value: &Value) -> bool {
    value["spec"]["ingress"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|ingress| {
            let udp_tailnet = ingress["ports"].as_array().is_some_and(|ports| {
                ports.len() == 1
                    && ports[0]["protocol"] == "UDP"
                    && ports[0]["port"] == i64::from(WORKSPACE_TAILNET_UDP_PORT)
            });
            let world_only = ingress["from"].as_array().is_some_and(|from| {
                !from.is_empty()
                    && from.iter().all(|peer| {
                        peer.as_object().is_some_and(|peer| peer.len() == 1)
                            && match peer["ipBlock"]["cidr"].as_str() {
                                Some("0.0.0.0/0") => [
                                    "10.0.0.0/8",
                                    "100.64.0.0/10",
                                    "127.0.0.0/8",
                                    "172.16.0.0/12",
                                    "192.168.0.0/16",
                                ]
                                .iter()
                                .all(|range| value_contains(&peer["ipBlock"]["except"], range)),
                                Some("::/0") => {
                                    value_contains(&peer["ipBlock"]["except"], "fc00::/7")
                                }
                                _ => false,
                            }
                    })
            });
            udp_tailnet && world_only
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
        access_template_opts, has_orchestration_access_ingress, has_world_only_tailnet_ingress,
        is_transient_apiserver_shutdown, render_resize_fixture, validate_resize_environment_id,
    };
    use codewire_orchestration::sandbox::template::render_workspace_daemon_network_policy;

    const RESIZE_ENV: &str = "00000000-0000-4000-8000-000000000123";

    fn resize_fixture() -> serde_json::Value {
        render_resize_fixture("dev-sandboxes", "codewire-e2e", RESIZE_ENV, None).unwrap()
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
    fn access_policy_admits_orchestration_and_world_only_tailnet() {
        let opts = access_template_opts("dev-sandboxes");
        let policy = render_workspace_daemon_network_policy("dev-sandboxes", &opts);
        assert!(has_orchestration_access_ingress(
            &policy,
            &opts.server_namespace
        ));
        assert!(has_world_only_tailnet_ingress(&policy));

        let mut no_ssh = policy.clone();
        for ingress in no_ssh["spec"]["ingress"].as_array_mut().unwrap() {
            if let Some(ports) = ingress["ports"].as_array_mut() {
                ports.retain(|port| port["port"] != 2222);
            }
        }
        assert!(!has_orchestration_access_ingress(
            &no_ssh,
            &opts.server_namespace
        ));

        let mut cluster_peer = policy.clone();
        for ingress in cluster_peer["spec"]["ingress"].as_array_mut().unwrap() {
            if ingress["ports"][0]["protocol"] == "UDP" {
                ingress["from"]
                    .as_array_mut()
                    .unwrap()
                    .push(serde_json::json!({"podSelector": {}}));
            }
        }
        assert!(!has_world_only_tailnet_ingress(&cluster_peer));
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
        // Identity-free: the environment-owned shadow pool names the
        // template, which carries no environment label.
        assert_eq!(template["metadata"]["labels"], serde_json::json!({}));
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
    fn resize_fixture_keeps_daemon_bootstrap_mounts_and_renders_no_identity() {
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
        assert_eq!(init["image"], "codewire-daemon:e2e");
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
        assert_eq!(workspace["image"], "codewire-daemon:e2e");
        assert_eq!(workspace["imagePullPolicy"], "Never");
        // Ready on the daemon's local marker, written before it binds: the
        // resize's reconcile binds it, as a start binds a replacement Pod.
        assert_eq!(
            workspace["readinessProbe"]["exec"]["command"][2],
            "test -f /codewire/run/daemon/ready"
        );
        let env = workspace["env"].as_array().unwrap();
        let named = |name: &str| env.iter().find(|entry| entry["name"] == name);
        assert_eq!(
            named("CODEWIRE_WORKSPACE_BINDING_URL").unwrap()["value"],
            "https://codewire-orchestration-workspace-binding.codewire-e2e.svc.cluster.local:8087"
        );
        for absent in [
            "CODEWIRE_DAEMON_AUTH_TOKEN",
            "CODEWIRE_ENVIRONMENT_ID",
            "CODEWIRE_ENVIRONMENT_OPERATION_GENERATION",
        ] {
            assert!(named(absent).is_none(), "{absent} is rendered");
        }
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
        for (namespace, server_namespace) in [("", "codewire-e2e"), ("dev-sandboxes", " e2e")] {
            assert!(render_resize_fixture(namespace, server_namespace, RESIZE_ENV, None).is_err());
        }
    }
}
