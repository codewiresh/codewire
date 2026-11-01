//! User-facing trust report for environment runtime evidence.
//!
//! The first shipped surface is intentionally conservative: it reports durable
//! environment state plus best-effort live Kubernetes observations, and marks
//! current confidential evidence as dev proof until production trust roots and
//! persisted attestation records exist.

use std::collections::BTreeMap;

use axum::http::StatusCode;
use codewire_server_core::AppResult;
use codewire_server_core::auth::AuthUser;
use k8s_openapi::api::core::v1::{Node, Pod};
use kube::Api;
use sqlx::Row;

use crate::sandbox::template::{
    DAEMON_INIT_CONTAINER, DAEMON_VOLUME, RUNTIME_CLASS_CONFIDENTIAL, RUNTIME_CLASS_RUNC,
    RUNTIME_PROFILE_COMMODITY, RUNTIME_PROFILE_CONFIDENTIAL, RUNTIME_PROFILE_NONE,
    RUNTIME_PROFILE_RUNC, is_commodity_runtime_class, runtime_profile_spec,
};

use super::ApiState;
use super::environments::{coded, require_environment_access, require_org_member};

const TRUST_LEVEL_DEV_PROOF: &str = "dev_proof";
const TRUST_LEVEL_NOT_CONFIDENTIAL: &str = "not_confidential";
const TRUST_LEVEL_UNVERIFIED: &str = "unverified";

#[derive(Debug, Clone)]
pub struct EnvironmentTrustReport {
    pub environment: TrustReportEnvironment,
    pub runtime: TrustReportRuntime,
    pub placement: TrustReportPlacement,
    pub images: TrustReportImages,
    pub provenance: TrustReportProvenance,
    pub attestation: TrustReportAttestation,
    pub trustee: TrustReportTrustee,
    pub summary: TrustReportSummary,
}

#[derive(Debug, Clone)]
pub struct TrustReportEnvironment {
    pub id: String,
    pub org_id: String,
    pub env_type: String,
    pub state: String,
    pub isolation_tier: String,
}

#[derive(Debug, Clone)]
pub struct TrustReportRuntime {
    pub profile: String,
    pub runtime_class: String,
    pub handler: String,
    pub confidential: bool,
}

#[derive(Debug, Clone)]
pub struct TrustReportPlacement {
    pub namespace: Option<String>,
    pub workspace_pod: Option<String>,
    pub pod_ip: Option<String>,
    pub node: Option<String>,
    pub zone: Option<String>,
    pub region: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TrustReportImages {
    pub workspace_image: Option<String>,
    pub workspace_image_id: Option<String>,
    pub dind_image: Option<String>,
    pub dind_image_id: Option<String>,
    pub daemon_init_image: Option<String>,
    pub daemon_init_image_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TrustReportProvenance {
    pub status: String,
    pub guest_kernel: Option<String>,
    pub guest_initrd: Option<String>,
    pub guest_image: Option<String>,
    pub firmware: Option<String>,
    pub source: Option<String>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct TrustReportAttestation {
    pub status: String,
    pub tee: String,
    pub report_available: bool,
    pub report_source: Option<String>,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct TrustReportTrustee {
    pub status: String,
    pub resource_uri: Option<String>,
    pub reference_values: Option<String>,
    pub policy: Option<String>,
    pub evidence_issues: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct TrustReportSummary {
    pub trust_level: String,
    pub production_verified: bool,
    pub warnings: Vec<String>,
}

struct TrustReportRow {
    id: String,
    org_id: String,
    env_type: String,
    state: String,
    isolation_tier: String,
    namespace: Option<String>,
    pod_name: Option<String>,
    pod_ip: Option<String>,
    observed_runtime_class: Option<String>,
}

struct LiveObservation {
    runtime_class: Option<String>,
    node: Option<String>,
    pod_ip: Option<String>,
    zone: Option<String>,
    region: Option<String>,
    images: TrustReportImages,
}

pub(crate) async fn get_environment_trust_report_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    env_id: &str,
) -> AppResult<EnvironmentTrustReport> {
    require_org_member(&state.pool, user, org_id).await?;
    require_environment_access(&state.pool, user, env_id, org_id, "viewer", "access denied")
        .await?;

    let row = load_trust_report_row(state, org_id, env_id).await?;
    let live = observe_live_runtime(state, &row).await;

    let runtime_class = live
        .runtime_class
        .as_deref()
        .and_then(non_empty)
        .or_else(|| row.observed_runtime_class.as_deref().and_then(non_empty))
        .unwrap_or_default()
        .to_string();
    let runtime = runtime_from_class(&runtime_class);
    let confidential = runtime.profile == RUNTIME_PROFILE_CONFIDENTIAL;
    let (attestation, trustee, summary) = trust_sections(confidential, runtime.profile.as_str());

    let placement = TrustReportPlacement {
        namespace: row.namespace.clone().and_then(trimmed_optional),
        workspace_pod: row.pod_name.clone().and_then(trimmed_optional),
        pod_ip: live
            .pod_ip
            .clone()
            .or_else(|| row.pod_ip.clone())
            .and_then(trimmed_optional),
        node: live.node.clone().and_then(trimmed_optional),
        zone: live.zone.clone().and_then(trimmed_optional),
        region: live.region.clone().and_then(trimmed_optional),
    };

    Ok(EnvironmentTrustReport {
        environment: TrustReportEnvironment {
            id: row.id,
            org_id: row.org_id,
            env_type: row.env_type,
            state: row.state,
            isolation_tier: row.isolation_tier,
        },
        runtime,
        placement,
        images: live.images,
        provenance: provenance_section(),
        attestation,
        trustee,
        summary,
    })
}

async fn load_trust_report_row(
    state: &ApiState,
    org_id: &str,
    env_id: &str,
) -> AppResult<TrustReportRow> {
    let row = sqlx::query(
        r#"
        SELECT e.id, e.org_id, e.type, e.state, e.isolation_tier,
               b.namespace, b.pod_name, b.pod_ip,
               (
                 SELECT runtime_class
                   FROM sandbox_running_sessions s
                  WHERE s.environment_id = e.id
                    AND s.ended_at IS NULL
                  ORDER BY s.started_at DESC
                  LIMIT 1
               ) AS observed_runtime_class
          FROM environments e
          LEFT JOIN sandbox_environment_backend b ON b.environment_id = e.id
         WHERE e.id = $1 AND e.org_id = $2
        "#,
    )
    .bind(env_id)
    .bind(org_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, env_id, org_id, "trust report query failed");
        coded(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "failed to load trust report",
        )
    })?
    .ok_or_else(|| {
        coded(
            StatusCode::NOT_FOUND,
            "env_not_found",
            "environment not found",
        )
    })?;

    Ok(TrustReportRow {
        id: row.try_get("id")?,
        org_id: row.try_get("org_id")?,
        env_type: row.try_get("type")?,
        state: row.try_get("state")?,
        isolation_tier: row.try_get("isolation_tier")?,
        namespace: row.try_get("namespace")?,
        pod_name: row.try_get("pod_name")?,
        pod_ip: row.try_get("pod_ip")?,
        observed_runtime_class: row.try_get("observed_runtime_class")?,
    })
}

async fn observe_live_runtime(state: &ApiState, row: &TrustReportRow) -> LiveObservation {
    let mut observation = LiveObservation {
        runtime_class: None,
        node: None,
        pod_ip: None,
        zone: None,
        region: None,
        images: TrustReportImages {
            workspace_image: None,
            workspace_image_id: None,
            dind_image: None,
            dind_image_id: None,
            daemon_init_image: None,
            daemon_init_image_id: None,
        },
    };

    let Some(client) = state.kube.as_ref().cloned() else {
        return observation;
    };
    let Some(namespace) = row.namespace.as_deref().and_then(non_empty) else {
        return observation;
    };

    if let Some(pod_name) = row.pod_name.as_deref().and_then(non_empty) {
        let pods: Api<Pod> = Api::namespaced(client.clone(), namespace);
        match pods.get(pod_name).await {
            Ok(pod) => {
                observe_workspace_pod(&pod, &mut observation);
                if let Some(node_name) = observation
                    .node
                    .as_deref()
                    .and_then(non_empty)
                    .map(str::to_string)
                {
                    observe_node(client.clone(), &node_name, &mut observation).await;
                }
            }
            Err(err) => {
                tracing::debug!(%err, namespace, pod_name, "trust report live pod lookup failed");
            }
        }
    }

    observation
}

fn observe_workspace_pod(pod: &Pod, observation: &mut LiveObservation) {
    if let Some(spec) = pod.spec.as_ref() {
        observation.runtime_class = spec.runtime_class_name.clone();
        observation.node = spec.node_name.clone();
        observation.images.workspace_image = spec_container_image(pod, "workspace");
        observation.images.dind_image = spec_container_image(pod, "dind");
        observation.images.daemon_init_image =
            spec_init_container_image(pod, DAEMON_INIT_CONTAINER)
                .or_else(|| spec_daemon_volume_image(pod));
    }

    if let Some(status) = pod.status.as_ref() {
        observation.pod_ip = status.pod_ip.clone();
    }
    observation.images.workspace_image_id = status_container_image_id(pod, "workspace");
    observation.images.dind_image_id = status_container_image_id(pod, "dind");
    // An image-volume daemon has no init status; its digest-pinned reference
    // is the daemon image above.
    observation.images.daemon_init_image_id =
        status_init_container_image_id(pod, DAEMON_INIT_CONTAINER);
}

async fn observe_node(client: kube::Client, node_name: &str, observation: &mut LiveObservation) {
    let nodes: Api<Node> = Api::all(client);
    match nodes.get(node_name).await {
        Ok(node) => {
            let labels = node.metadata.labels.unwrap_or_default();
            observation.zone = first_label(
                &labels,
                &[
                    "topology.kubernetes.io/zone",
                    "failure-domain.beta.kubernetes.io/zone",
                ],
            );
            observation.region = first_label(
                &labels,
                &[
                    "topology.kubernetes.io/region",
                    "failure-domain.beta.kubernetes.io/region",
                ],
            );
        }
        Err(err) => {
            tracing::debug!(%err, node_name, "trust report node lookup failed");
        }
    }
}

fn first_label(labels: &BTreeMap<String, String>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| labels.get(*key).cloned())
        .and_then(trimmed_optional)
}

fn spec_container_image(pod: &Pod, name: &str) -> Option<String> {
    pod.spec
        .as_ref()?
        .containers
        .iter()
        .find(|container| container.name == name)
        .and_then(|container| container.image.clone())
        .and_then(trimmed_optional)
}

fn spec_init_container_image(pod: &Pod, name: &str) -> Option<String> {
    pod.spec
        .as_ref()?
        .init_containers
        .as_ref()?
        .iter()
        .find(|container| container.name == name)
        .and_then(|container| container.image.clone())
        .and_then(trimmed_optional)
}

/// The support image a commodity workspace mounts its daemon from.
fn spec_daemon_volume_image(pod: &Pod) -> Option<String> {
    pod.spec
        .as_ref()?
        .volumes
        .as_ref()?
        .iter()
        .find(|volume| volume.name == DAEMON_VOLUME)?
        .image
        .as_ref()?
        .reference
        .clone()
        .and_then(trimmed_optional)
}

fn status_container_image_id(pod: &Pod, name: &str) -> Option<String> {
    pod.status
        .as_ref()?
        .container_statuses
        .as_ref()?
        .iter()
        .find(|status| status.name == name)
        .map(|status| status.image_id.clone())
        .and_then(trimmed_optional)
}

fn status_init_container_image_id(pod: &Pod, name: &str) -> Option<String> {
    pod.status
        .as_ref()?
        .init_container_statuses
        .as_ref()?
        .iter()
        .find(|status| status.name == name)
        .map(|status| status.image_id.clone())
        .and_then(trimmed_optional)
}

fn runtime_from_class(runtime_class: &str) -> TrustReportRuntime {
    let observed = runtime_class.trim();
    let profile = match observed {
        "" => RUNTIME_PROFILE_NONE,
        RUNTIME_CLASS_RUNC => RUNTIME_PROFILE_RUNC,
        class if is_commodity_runtime_class(class) => RUNTIME_PROFILE_COMMODITY,
        RUNTIME_CLASS_CONFIDENTIAL => RUNTIME_PROFILE_CONFIDENTIAL,
        other => other,
    };
    let spec = runtime_profile_spec(profile, "profile-default", false);
    let profile = spec.profile;
    // Each commodity memory tier is its own class; the report names the tier.
    let runtime_class = if is_commodity_runtime_class(observed) {
        observed.to_string()
    } else {
        spec.runtime_class_name
    };
    let handler = match runtime_class.as_str() {
        RUNTIME_CLASS_CONFIDENTIAL => "kata-qemu-snp",
        class if is_commodity_runtime_class(class) => "kata-clh",
        RUNTIME_CLASS_RUNC => "runc",
        "" => "unknown",
        other => other,
    }
    .to_string();
    TrustReportRuntime {
        confidential: profile == RUNTIME_PROFILE_CONFIDENTIAL,
        profile,
        runtime_class,
        handler,
    }
}

fn trust_sections(
    confidential: bool,
    profile: &str,
) -> (
    TrustReportAttestation,
    TrustReportTrustee,
    TrustReportSummary,
) {
    if confidential {
        let metadata = BTreeMap::from([
            ("report_version".to_string(), "5".to_string()),
            ("vmpl".to_string(), "1".to_string()),
            ("signature_algorithm".to_string(), "1".to_string()),
            ("cpuid_family".to_string(), "25".to_string()),
            ("current_tcb_version".to_string(), "1.58.1".to_string()),
            ("committed_tcb_version".to_string(), "1.58.1".to_string()),
        ]);
        return (
            TrustReportAttestation {
                status: "dev_evidence_available".to_string(),
                tee: "sev-snp".to_string(),
                report_available: false,
                report_source: Some("Gitea #618 dev smoke".to_string()),
                metadata,
            },
            TrustReportTrustee {
                status: "dev_policy_matched".to_string(),
                resource_uri: Some("kbs:///default/codewire/runtime-test-resource".to_string()),
                reference_values: Some("dev_reference_values_registered".to_string()),
                policy: Some("claim_bound_dev_policy".to_string()),
                evidence_issues: vec![
                    "#619".to_string(),
                    "#620".to_string(),
                    "#621".to_string(),
                    "#622".to_string(),
                ],
            },
            TrustReportSummary {
                trust_level: TRUST_LEVEL_DEV_PROOF.to_string(),
                production_verified: false,
                warnings: vec![
                    "Current confidential evidence is dev-only; production trust roots and persisted per-environment attestation are not yet provisioned.".to_string(),
                    "Raw SEV-SNP reports, launch measurements, KBS tokens, and tenant material are intentionally not exposed.".to_string(),
                ],
            },
        );
    }

    let trust_level = if matches!(profile, RUNTIME_PROFILE_COMMODITY | RUNTIME_PROFILE_RUNC) {
        TRUST_LEVEL_NOT_CONFIDENTIAL
    } else {
        TRUST_LEVEL_UNVERIFIED
    };
    let warning = if profile == RUNTIME_PROFILE_COMMODITY {
        "Commodity runtime has a Kata VM boundary but does not make a TEE attestation claim."
    } else if profile == RUNTIME_PROFILE_RUNC {
        "runc is a diagnostic/runtime fallback and does not make a VM or TEE attestation claim."
    } else {
        "No supported runtime profile was observed for this environment."
    };
    (
        TrustReportAttestation {
            status: "not_applicable".to_string(),
            tee: "none".to_string(),
            report_available: false,
            report_source: None,
            metadata: BTreeMap::new(),
        },
        TrustReportTrustee {
            status: "not_applicable".to_string(),
            resource_uri: None,
            reference_values: None,
            policy: None,
            evidence_issues: Vec::new(),
        },
        TrustReportSummary {
            trust_level: trust_level.to_string(),
            production_verified: false,
            warnings: vec![warning.to_string()],
        },
    )
}

fn provenance_section() -> TrustReportProvenance {
    TrustReportProvenance {
        status: "not_available".to_string(),
        guest_kernel: None,
        guest_initrd: None,
        guest_image: None,
        firmware: None,
        source: None,
        notes: vec![
            "Guest kernel, initrd/image, and firmware provenance are not persisted by the runtime API yet.".to_string(),
        ],
    }
}

fn non_empty(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then_some(trimmed)
}

fn trimmed_optional(value: String) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_from_class_maps_shipped_profiles() {
        let confidential = runtime_from_class("confidential");
        assert_eq!(confidential.profile, "confidential");
        assert_eq!(confidential.runtime_class, "confidential");
        assert_eq!(confidential.handler, "kata-qemu-snp");
        assert!(confidential.confidential);

        let commodity = runtime_from_class("commodity");
        assert_eq!(commodity.profile, "commodity");
        assert_eq!(commodity.handler, "kata-clh");
        assert!(!commodity.confidential);
        // A memory tier keeps its own class name in the report.
        let tier = runtime_from_class("commodity-32g");
        assert_eq!(tier.profile, "commodity");
        assert_eq!(tier.runtime_class, "commodity-32g");
        assert_eq!(tier.handler, "kata-clh");
        assert!(!tier.confidential);

        let runc = runtime_from_class("runc");
        assert_eq!(runc.profile, "runc");
        assert_eq!(runc.handler, "runc");
    }

    #[test]
    fn daemon_image_is_reported_from_either_delivery_route() {
        let observe = |spec: serde_json::Value, status: serde_json::Value| {
            let pod: Pod = serde_json::from_value(serde_json::json!({
                "metadata": {"name": "workspace"},
                "spec": spec,
                "status": status,
            }))
            .unwrap();
            let mut observation = LiveObservation {
                runtime_class: None,
                node: None,
                pod_ip: None,
                zone: None,
                region: None,
                images: TrustReportImages {
                    workspace_image: None,
                    workspace_image_id: None,
                    dind_image: None,
                    dind_image_id: None,
                    daemon_init_image: None,
                    daemon_init_image_id: None,
                },
            };
            observe_workspace_pod(&pod, &mut observation);
            (
                observation.images.daemon_init_image,
                observation.images.daemon_init_image_id,
            )
        };
        let image = "registry.example/codewire/support@sha256:1111";
        let workspace = serde_json::json!({"name": "workspace", "image": "workspace"});
        assert_eq!(
            observe(
                serde_json::json!({
                    "containers": [workspace],
                    "volumes": [{"name": "codewire-bin", "image": {"reference": image}}],
                }),
                serde_json::json!({}),
            ),
            (Some(image.to_owned()), None)
        );
        assert_eq!(
            observe(
                serde_json::json!({
                    "containers": [workspace],
                    "initContainers": [{"name": "codewire-daemon-init", "image": image}],
                    "volumes": [{"name": "codewire-bin", "emptyDir": {}}],
                }),
                serde_json::json!({"initContainerStatuses": [{
                    "name": "codewire-daemon-init", "image": image, "imageID": "sha256:2222",
                    "ready": false, "restartCount": 0,
                }]}),
            ),
            (Some(image.to_owned()), Some("sha256:2222".to_owned()))
        );
    }

    #[test]
    fn confidential_trust_sections_are_dev_only_and_redacted() {
        let (attestation, trustee, summary) = trust_sections(true, "confidential");

        assert_eq!(attestation.status, "dev_evidence_available");
        assert_eq!(attestation.tee, "sev-snp");
        assert!(!attestation.report_available);
        assert_eq!(
            attestation.report_source.as_deref(),
            Some("Gitea #618 dev smoke")
        );
        assert_eq!(
            trustee.resource_uri.as_deref(),
            Some("kbs:///default/codewire/runtime-test-resource")
        );
        assert_eq!(summary.trust_level, "dev_proof");
        assert!(!summary.production_verified);
        assert!(
            summary
                .warnings
                .iter()
                .any(|warning| warning.contains("Raw SEV-SNP reports"))
        );
    }
}
