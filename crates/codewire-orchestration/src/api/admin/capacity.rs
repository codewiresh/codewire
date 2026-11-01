//! What each runtime node has reserved and used, and how many more sandboxes of
//! each shape fit, for the global admin capacity view (#3635).
//!
//! Reservations and usage come from the cluster's own Prometheus, the one source
//! that sees every Pod on a node without a cluster-wide Pod read. It is optional
//! and may be slow or down, so its reads are bounded, and a number it can't give
//! is absent: never zero, and never a count of what fits.

use std::collections::{BTreeMap, HashMap};
use std::time::Duration;

use anyhow::Context;
use codewire_server_core::{AppError, AppResult};
use futures::StreamExt;
use k8s_openapi::api::core::v1::{Node, Pod, Toleration};
use kube::Api;
use kube::api::ListParams;
use serde_json::Value;

use crate::sandbox::warm_pool::{MEMBER_POOL_LABEL, WorkspaceShape};
use crate::worker::create::render_configured_warm_pool;
use crate::worker::warm_pool::{
    ClassOverheads, Reservation, member_reservation, node_unfit, pod_overhead, quantity_millis,
    quantity_units, read_runtime_classes, selector_of,
};

use super::ApiState;

/// How long the whole read may take, so a slow Prometheus can't hold the page.
const PROMETHEUS_TIMEOUT: Duration = Duration::from_secs(3);
/// How long the Kubernetes reads may take.
const KUBERNETES_TIMEOUT: Duration = Duration::from_secs(5);
/// One answer's size limit. These queries return a few series per node.
const PROMETHEUS_RESPONSE_LIMIT: usize = 1024 * 1024;

/// The product's shapes people choose, by name. The disk doesn't affect what a
/// shape reserves on the node.
const SHAPES: [(&str, i64, i64); 4] = [
    ("small", 1000, 4096),
    ("default", 2000, 8192),
    ("large", 4000, 16384),
    ("xlarge", 8000, 32768),
];
const SHAPE_DISK_GIB: i64 = 80;

/// A Pod the scheduler still counts. The node comes from the series themselves,
/// so a Pod not yet placed reserves nothing, as for the scheduler.
const LIVE_PODS: &str =
    r#"max by (namespace, pod, uid) (kube_pod_status_phase{phase=~"Pending|Running"}) == 1"#;

fn requests_query() -> String {
    format!(
        r#"sum by (node, resource) (kube_pod_container_resource_requests{{resource=~"cpu|memory"}} * on (namespace, pod, uid) group_left () ({LIVE_PODS}))"#
    )
}

fn overhead_query(metric: &str) -> String {
    format!(
        "sum by (node) ({metric} * on (namespace, pod, uid) group_left (node) (kube_pod_info * on (namespace, pod, uid) group_left () ({LIVE_PODS})))"
    )
}

fn pods_query() -> String {
    format!(
        "count by (node) (kube_pod_info * on (namespace, pod, uid) group_left () ({LIVE_PODS}))"
    )
}

const REQUESTS_AT_QUERY: &str = "max by (node) (timestamp(kube_pod_info))";
const USED_CPU_QUERY: &str = r#"sum by (nodename) ((1 - rate(node_cpu_seconds_total{mode="idle"}[2m])) * on (instance) group_left (nodename) node_uname_info)"#;
const USED_MEMORY_QUERY: &str = "(node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes) * on (instance) group_left (nodename) node_uname_info";
const USED_AT_QUERY: &str = "timestamp(node_memory_MemAvailable_bytes) * on (instance) group_left (nodename) node_uname_info";

/// What the scheduler counts on one node, and when it was read.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct NodeReserved {
    pub cpu_millicores: i64,
    pub memory_bytes: i64,
    pub pods: i64,
    pub unix_seconds: i64,
}

/// What one node is really using, and when it was read.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct NodeUsed {
    pub cpu_millicores: i64,
    pub memory_bytes: i64,
    pub unix_seconds: i64,
}

/// How many more of one shape fit on a node. `more` is absent when the node's
/// reservations aren't known; then the limit is empty too.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShapeFit {
    pub shape: &'static str,
    pub more: Option<i64>,
    pub limit: &'static str,
}

#[derive(Clone, Debug, PartialEq)]
pub struct NodeCapacity {
    pub name: String,
    pub schedulable: bool,
    pub allocatable_cpu_millicores: i64,
    pub allocatable_memory_bytes: i64,
    pub allocatable_pods: i64,
    pub reserved: Option<NodeReserved>,
    pub used: Option<NodeUsed>,
    pub sandboxes: i64,
    pub idle_warm_members: i64,
    pub fits: Vec<ShapeFit>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ClusterCapacity {
    pub nodes: Vec<NodeCapacity>,
    /// Sandbox Pods no node has taken yet.
    pub unplaced_sandboxes: i64,
    /// Whether this deployment names a Prometheus at all.
    pub prometheus_configured: bool,
}

/// One instant query's vector, as (labels, value). A failed query, or any value
/// that isn't a finite number, fails the whole answer.
async fn instant_query(
    client: &reqwest::Client,
    base: &str,
    query: &str,
) -> anyhow::Result<Vec<(HashMap<String, String>, f64)>> {
    let response = client
        .get(format!("{base}/api/v1/query"))
        .query(&[("query", query)])
        .send()
        .await?
        .error_for_status()?;
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        anyhow::ensure!(
            body.len() + chunk.len() <= PROMETHEUS_RESPONSE_LIMIT,
            "Prometheus answer over {PROMETHEUS_RESPONSE_LIMIT} bytes"
        );
        body.extend_from_slice(&chunk);
    }
    let answer: Value = serde_json::from_slice(&body)?;
    anyhow::ensure!(
        answer["status"] == "success" && answer["data"]["resultType"] == "vector",
        "Prometheus answered without a vector"
    );
    answer["data"]["result"]
        .as_array()
        .context("Prometheus answered without a result")?
        .iter()
        .map(|series| {
            let labels = serde_json::from_value(series["metric"].clone())?;
            let value: f64 = series["value"][1]
                .as_str()
                .context("Prometheus series without a value")?
                .parse()?;
            anyhow::ensure!(value.is_finite(), "Prometheus value is not a number");
            Ok((labels, value))
        })
        .collect()
}

fn by_label(series: &[(HashMap<String, String>, f64)], label: &str) -> BTreeMap<String, f64> {
    series
        .iter()
        .filter_map(|(labels, value)| Some((labels.get(label)?.clone(), *value)))
        .filter(|(name, _)| !name.is_empty())
        .collect()
}

async fn read_reserved(
    client: &reqwest::Client,
    base: &str,
) -> anyhow::Result<BTreeMap<String, NodeReserved>> {
    let requests = requests_query();
    let pods = pods_query();
    let overhead_cpu = overhead_query("kube_pod_overhead_cpu_cores");
    let overhead_memory = overhead_query("kube_pod_overhead_memory_bytes");
    let (requests, overhead_cpu, overhead_memory, pods, read_at) = tokio::try_join!(
        instant_query(client, base, &requests),
        instant_query(client, base, &overhead_cpu),
        instant_query(client, base, &overhead_memory),
        instant_query(client, base, &pods),
        instant_query(client, base, REQUESTS_AT_QUERY),
    )?;
    let requested = |resource: &str| -> BTreeMap<String, f64> {
        let series: Vec<_> = requests
            .iter()
            .filter(|(labels, _)| labels.get("resource").map(String::as_str) == Some(resource))
            .cloned()
            .collect();
        by_label(&series, "node")
    };
    let (cpu, memory) = (requested("cpu"), requested("memory"));
    let (overhead_cpu, overhead_memory) = (
        by_label(&overhead_cpu, "node"),
        by_label(&overhead_memory, "node"),
    );
    let pods = by_label(&pods, "node");
    // A node missing any of these wasn't read. No Pod overhead is a real answer.
    Ok(by_label(&read_at, "node")
        .into_iter()
        .filter_map(|(node, at)| {
            let reserved = NodeReserved {
                cpu_millicores: ((cpu.get(&node)? + overhead_cpu.get(&node).unwrap_or(&0.0))
                    * 1000.0)
                    .ceil() as i64,
                memory_bytes: (memory.get(&node)? + overhead_memory.get(&node).unwrap_or(&0.0))
                    .ceil() as i64,
                pods: *pods.get(&node)? as i64,
                unix_seconds: at as i64,
            };
            Some((node, reserved))
        })
        .collect())
}

async fn read_used(
    client: &reqwest::Client,
    base: &str,
) -> anyhow::Result<BTreeMap<String, NodeUsed>> {
    let (cpu, memory, read_at) = tokio::try_join!(
        instant_query(client, base, USED_CPU_QUERY),
        instant_query(client, base, USED_MEMORY_QUERY),
        instant_query(client, base, USED_AT_QUERY),
    )?;
    let (cpu, memory) = (by_label(&cpu, "nodename"), by_label(&memory, "nodename"));
    Ok(by_label(&read_at, "nodename")
        .into_iter()
        .filter_map(|(node, at)| {
            let used = NodeUsed {
                cpu_millicores: (cpu.get(&node)? * 1000.0).round() as i64,
                memory_bytes: *memory.get(&node)? as i64,
                unix_seconds: at as i64,
            };
            Some((node, used))
        })
        .collect())
}

fn settle<T>(
    family: &'static str,
    result: Result<anyhow::Result<BTreeMap<String, T>>, tokio::time::error::Elapsed>,
) -> BTreeMap<String, T> {
    match result {
        Ok(Ok(nodes)) => nodes,
        Ok(Err(error)) => {
            tracing::warn!(family, error = %format!("{error:#}"), "capacity: Prometheus read failed");
            BTreeMap::new()
        }
        Err(_) => {
            tracing::warn!(family, "capacity: Prometheus read timed out");
            BTreeMap::new()
        }
    }
}

/// Each family alone within `timeout`. One failing leaves the other's numbers;
/// a failure says "not available" on the page and in the log, never a number.
async fn read_prometheus(
    client: &reqwest::Client,
    base: &str,
    timeout: Duration,
) -> (BTreeMap<String, NodeReserved>, BTreeMap<String, NodeUsed>) {
    if base.is_empty() {
        return Default::default();
    }
    let (reserved, used) = tokio::join!(
        tokio::time::timeout(timeout, read_reserved(client, base)),
        tokio::time::timeout(timeout, read_used(client, base)),
    );
    (settle("reserved", reserved), settle("used", used))
}

/// Each shape's reservation at the live ratio and overhead, the way the warm
/// pool reconciler counts a member. A shape that can't be rendered has none.
fn shape_reservations(
    state: &ApiState,
    overheads: &ClassOverheads,
) -> Vec<(&'static str, Option<Reservation>)> {
    SHAPES
        .iter()
        .map(|(name, cpu_millicores, memory_mib)| {
            let shape = WorkspaceShape {
                cpu_millicores: *cpu_millicores,
                memory_mib: *memory_mib,
                disk_gib: SHAPE_DISK_GIB,
            };
            let reservation = render_configured_warm_pool(&state.sandbox_cfg, shape, 0)
                .inspect_err(|error| {
                    tracing::warn!(shape = name, error = %format!("{error:#}"), "capacity: shape not rendered");
                })
                .ok()
                .and_then(|objects| {
                    let pod_spec = &objects.template["spec"]["podTemplate"]["spec"];
                    member_reservation(pod_spec, pod_overhead(pod_spec, overheads)?)
                });
            (*name, reservation)
        })
        .collect()
}

/// How many more of a shape fit, by the scheduler's arithmetic: the smallest of
/// free CPU, free memory and free Pod slots, each over what one reserves.
fn shape_fit(
    shape: &'static str,
    node: (i64, i64, i64),
    reserved: Option<NodeReserved>,
    schedulable: bool,
    each: Option<Reservation>,
) -> ShapeFit {
    let (Some(reserved), Some(each)) = (reserved, each) else {
        return ShapeFit {
            shape,
            more: None,
            limit: "",
        };
    };
    if !schedulable {
        return ShapeFit {
            shape,
            more: Some(0),
            limit: "node",
        };
    }
    if each.cpu_millis <= 0 || each.memory_bytes <= 0 {
        return ShapeFit {
            shape,
            more: None,
            limit: "",
        };
    }
    let (cpu, memory, pods) = node;
    let by_cpu = (i128::from(cpu - reserved.cpu_millicores) / each.cpu_millis).max(0) as i64;
    let by_memory = (i128::from(memory - reserved.memory_bytes) / each.memory_bytes).max(0) as i64;
    let by_pods = (pods - reserved.pods).max(0);
    let more = by_cpu.min(by_memory).min(by_pods);
    let limit = if more == by_cpu {
        "cpu"
    } else if more == by_memory {
        "memory"
    } else {
        "pods"
    };
    ShapeFit {
        shape,
        more: Some(more),
        limit,
    }
}

/// A node's allocatable CPU (millicores), memory (bytes) and Pod slots.
fn allocatable(node: &Node) -> Option<(i64, i64, i64)> {
    let values = node.status.as_ref()?.allocatable.as_ref()?;
    Some((
        i64::try_from(quantity_millis(&values.get("cpu")?.0)?).ok()?,
        i64::try_from(quantity_units(&values.get("memory")?.0)?).ok()?,
        i64::try_from(quantity_units(&values.get("pods")?.0)?).ok()?,
    ))
}

/// Sandbox Pods by node, as (sandboxes, idle warm members), and the unplaced.
fn count_sandbox_pods(pods: &[Pod]) -> (BTreeMap<String, (i64, i64)>, i64) {
    let mut by_node: BTreeMap<String, (i64, i64)> = BTreeMap::new();
    let mut unplaced = 0;
    for pod in pods {
        let phase = pod
            .status
            .as_ref()
            .and_then(|status| status.phase.as_deref());
        if !matches!(phase, Some("Pending" | "Running")) {
            continue;
        }
        let idle = pod
            .metadata
            .labels
            .as_ref()
            .is_some_and(|labels| labels.contains_key(MEMBER_POOL_LABEL));
        match pod.spec.as_ref().and_then(|spec| spec.node_name.clone()) {
            Some(node) => {
                let counts = by_node.entry(node).or_default();
                if idle {
                    counts.1 += 1;
                } else {
                    counts.0 += 1;
                }
            }
            None if !idle => unplaced += 1,
            None => {}
        }
    }
    (by_node, unplaced)
}

struct ClusterRead {
    nodes: Vec<Node>,
    pods: Vec<Pod>,
    overheads: ClassOverheads,
    tolerations: Vec<Toleration>,
}

async fn read_cluster(state: &ApiState, kube: &kube::Client) -> anyhow::Result<ClusterRead> {
    let cfg = &state.sandbox_cfg;
    // The RuntimeClasses the shapes render say where sandboxes go and what
    // each shape's tier adds.
    let mut tolerations = None;
    let mut classes: Vec<String> = Vec::new();
    for (_, cpu_millicores, memory_mib) in SHAPES {
        let template = render_configured_warm_pool(
            cfg,
            WorkspaceShape {
                cpu_millicores,
                memory_mib,
                disk_gib: SHAPE_DISK_GIB,
            },
            0,
        )?
        .template;
        let pod_spec = &template["spec"]["podTemplate"]["spec"];
        tolerations.get_or_insert_with(|| {
            serde_json::from_value(pod_spec["tolerations"].clone()).unwrap_or_default()
        });
        if let Some(class) = pod_spec["runtimeClassName"].as_str()
            && !class.is_empty()
            && !classes.iter().any(|known| known == class)
        {
            classes.push(class.to_owned());
        }
    }
    let tolerations = tolerations.unwrap_or_default();
    let names: Vec<&str> = classes.iter().map(String::as_str).collect();
    let (overheads, selector) = read_runtime_classes(kube, &names).await?;
    let node_api = Api::<Node>::all(kube.clone());
    let pod_api = Api::<Pod>::namespaced(kube.clone(), &cfg.sandbox_namespace);
    let node_params = ListParams::default().labels(&selector_of(&selector));
    let pod_params = ListParams::default();
    let (nodes, pods) = tokio::try_join!(node_api.list(&node_params), pod_api.list(&pod_params))?;
    Ok(ClusterRead {
        nodes: nodes.items,
        pods: pods.items,
        overheads,
        tolerations,
    })
}

fn assemble(
    read: &ClusterRead,
    shapes: &[(&'static str, Option<Reservation>)],
    reserved: &BTreeMap<String, NodeReserved>,
    used: &BTreeMap<String, NodeUsed>,
    prometheus_configured: bool,
) -> ClusterCapacity {
    let (sandboxes, unplaced_sandboxes) = count_sandbox_pods(&read.pods);
    let mut nodes: Vec<NodeCapacity> = read
        .nodes
        .iter()
        .filter_map(|node| {
            let name = node.metadata.name.clone()?;
            let totals = allocatable(node)?;
            let schedulable = !node_unfit(Some(node), &read.tolerations);
            let node_reserved = reserved.get(&name).copied();
            let (cpu, memory, pods) = totals;
            let (node_sandboxes, idle_warm_members) =
                sandboxes.get(&name).copied().unwrap_or_default();
            Some(NodeCapacity {
                schedulable,
                allocatable_cpu_millicores: cpu,
                allocatable_memory_bytes: memory,
                allocatable_pods: pods,
                reserved: node_reserved,
                used: used.get(&name).copied(),
                sandboxes: node_sandboxes,
                idle_warm_members,
                fits: shapes
                    .iter()
                    .map(|(shape, each)| {
                        shape_fit(shape, totals, node_reserved, schedulable, *each)
                    })
                    .collect(),
                name,
            })
        })
        .collect();
    nodes.sort_by(|left, right| left.name.cmp(&right.name));
    ClusterCapacity {
        nodes,
        unplaced_sandboxes,
        prometheus_configured,
    }
}

/// The capacity view's read: bounded and read-only.
pub async fn cluster_capacity_core(state: &ApiState) -> AppResult<ClusterCapacity> {
    let Some(kube) = state.kube.as_ref() else {
        return Err(AppError::ServiceUnavailable(
            "no sandbox cluster is configured".into(),
        ));
    };
    let base = state.sandbox_cfg.capacity_prometheus_url.as_str();
    let (cluster, (reserved, used)) = tokio::join!(
        tokio::time::timeout(KUBERNETES_TIMEOUT, read_cluster(state, kube)),
        read_prometheus(&state.http_client, base, PROMETHEUS_TIMEOUT),
    );
    let read = cluster
        .map_err(|_| AppError::Upstream("the cluster did not answer in time".into()))?
        .map_err(|error| {
            tracing::warn!(error = %format!("{error:#}"), "capacity: cluster read failed");
            AppError::Upstream("the cluster could not be read".into())
        })?;
    let shapes = shape_reservations(state, &read.overheads);
    Ok(assemble(&read, &shapes, &reserved, &used, !base.is_empty()))
}

#[cfg(test)]
#[path = "capacity_tests.rs"]
mod tests;
