//! Reads one Sandbox into a [`RuntimeMember`]: its phase, its identity labels
//! and the resources it declares. Billing decides what those mean.

use kube::api::DynamicObject;
use serde_json::Value;

use crate::runtime::{MemberPhase as Phase, Resources, RuntimeMember};
use crate::sandbox::snapshots::is_clearing_sandbox;
use crate::sandbox::{LABEL_ENV_ID, LABEL_ORG_ID};

/// Stable SandboxClaim UID label.
const LABEL_CLAIM_UID: &str = "agents.x-k8s.io/claim-uid";

pub(super) fn runtime_member(sandbox: &DynamicObject) -> RuntimeMember {
    let value = match serde_json::to_value(sandbox) {
        Ok(value) => value,
        Err(e) => {
            tracing::warn!(
                error = %e,
                sandbox = sandbox.metadata.name.as_deref().unwrap_or_default(),
                runtime_uid = sandbox.metadata.uid.as_deref().unwrap_or_default(),
                "billing-session: serialize Sandbox failed"
            );
            return unread_member(sandbox);
        }
    };
    let label = |key: &str| {
        value
            .pointer("/metadata/labels")
            .and_then(|labels| labels.get(key))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    let (phase, phase_reason) = classify(&value);
    let stopped_at = (phase == Phase::Terminated)
        .then(|| stopped_at(&value))
        .flatten();
    RuntimeMember {
        environment_id: label(LABEL_ENV_ID),
        organization_id: label(LABEL_ORG_ID),
        claim_uid: label(LABEL_CLAIM_UID),
        phase,
        phase_reason,
        stopped_at,
        declared: declared_resources(&value),
        workspace: workspace_declared_resources(&value),
        ..unread_member(sandbox)
    }
}

/// What is known of a Sandbox from its metadata alone.
pub(crate) fn unread_member(sandbox: &DynamicObject) -> RuntimeMember {
    let name = sandbox.metadata.name.clone().unwrap_or_default();
    RuntimeMember {
        namespace: sandbox.metadata.namespace.clone().unwrap_or_default(),
        uid: sandbox.metadata.uid.clone().unwrap_or_default(),
        snapshot_clearing: is_clearing_sandbox(&name),
        name,
        environment_id: String::new(),
        organization_id: String::new(),
        claim_uid: String::new(),
        phase: Phase::Pending,
        phase_reason: String::new(),
        stopped_at: None,
        declared: Resources::default(),
        workspace: Resources::default(),
    }
}

/// Mirrors `sessions.DeclaredResources`: sum container CPU/memory
/// requests across the pod spec and storage requests across the volume
/// claim templates, reading from the Sandbox CR's
/// `spec.podTemplate.spec`.
///
/// Go uses k8s `resource.Quantity`: `Cpu().MilliValue()`,
/// `Memory().Value() >> 20` (bytes → MiB), `storage.Value() >> 30`
/// (bytes → GiB). `parse_quantity_*` mirrors that arithmetic.
fn declared_resources(sb: &Value) -> Resources {
    let mut out = Resources::default();

    let spec = sb.pointer("/spec/podTemplate/spec");
    if let Some(containers) = spec
        .and_then(|s| s.get("containers"))
        .and_then(Value::as_array)
    {
        for c in containers {
            let requests = c.pointer("/resources/requests");
            let cpu = if c.get("name").and_then(Value::as_str) == Some("workspace") {
                workspace_billed_cpu(c)
            } else {
                requests.and_then(|r| r.get("cpu")).and_then(Value::as_str)
            };
            if let Some(cpu) = cpu {
                out.cpu_millicores += parse_quantity_millicores(cpu);
            }
            if let Some(mem) = requests
                .and_then(|r| r.get("memory"))
                .and_then(Value::as_str)
            {
                out.memory_mib += (parse_quantity_bytes(mem) >> 20) as i32;
            }
        }
    }

    if let Some(pvcs) = sb
        .pointer("/spec/volumeClaimTemplates")
        .and_then(Value::as_array)
    {
        for pvc in pvcs {
            if let Some(storage) = pvc
                .pointer("/spec/resources/requests/storage")
                .and_then(Value::as_str)
            {
                out.disk_gib += (parse_quantity_bytes(storage) >> 30) as i32;
            }
        }
    }

    if let Some(rc) = spec
        .and_then(|s| s.get("runtimeClassName"))
        .and_then(Value::as_str)
        && !rc.is_empty()
    {
        out.runtime_class = Some(rc.to_string());
    }

    out
}

/// A workspace is billed for its vCPUs: its CPU limit, which stays the full
/// shape when CPU sharing lowers its request (#3635).
fn workspace_billed_cpu(workspace: &Value) -> Option<&str> {
    workspace
        .pointer("/resources/limits/cpu")
        .or_else(|| workspace.pointer("/resources/requests/cpu"))
        .and_then(Value::as_str)
}

fn workspace_declared_resources(sb: &Value) -> Resources {
    let mut out = Resources::default();
    if let Some(workspace) = sb
        .pointer("/spec/podTemplate/spec/containers")
        .and_then(Value::as_array)
        .and_then(|containers| {
            containers.iter().find(|container| {
                container.get("name").and_then(Value::as_str) == Some("workspace")
            })
        })
    {
        let requests = workspace.pointer("/resources/requests");
        if let Some(cpu) = workspace_billed_cpu(workspace) {
            out.cpu_millicores = parse_quantity_millicores(cpu);
        }
        if let Some(memory) = requests
            .and_then(|value| value.get("memory"))
            .and_then(Value::as_str)
        {
            out.memory_mib = (parse_quantity_bytes(memory) >> 20) as i32;
        }
    }
    out.disk_gib = sb
        .pointer("/spec/volumeClaimTemplates")
        .and_then(Value::as_array)
        .and_then(|claims| {
            claims.iter().find(|claim| {
                claim.pointer("/metadata/name").and_then(Value::as_str) == Some("workspace")
            })
        })
        .and_then(|claim| claim.pointer("/spec/resources/requests/storage"))
        .and_then(Value::as_str)
        .map(|storage| (parse_quantity_bytes(storage) >> 30) as i32)
        .unwrap_or_default();
    out
}

/// Mirrors `sessions.Classify`: drive the (phase, reason) state machine
/// off the Sandbox's deletion timestamp, operatingMode, and Ready condition.
fn classify(sb: &Value) -> (Phase, String) {
    // Go's `sb == nil` → (Terminated, "deleted"); the caller never passes
    // null here, but keep the branch faithful.
    if sb.is_null() {
        return (Phase::Terminated, "deleted".to_string());
    }
    if sb
        .pointer("/metadata/deletionTimestamp")
        .map(|v| !v.is_null())
        .unwrap_or(false)
    {
        return (Phase::Terminated, "deleting".to_string());
    }
    if sb.pointer("/spec/operatingMode").and_then(Value::as_str) == Some("Suspended") {
        return (Phase::Terminated, "suspended".to_string());
    }

    let (ready, reason) = ready_condition(sb);
    if ready {
        return (Phase::Running, String::new());
    }
    if terminal_ready_reason(&reason) {
        return (Phase::Terminated, reason);
    }
    (Phase::Pending, reason)
}

/// When a stopped Sandbox records that it stopped running: its Ready
/// condition's last transition while Ready isn't True, or its deletion
/// timestamp, whichever is earlier. A suspended Sandbox whose controller
/// hasn't yet turned Ready off records neither.
fn stopped_at(sb: &Value) -> Option<chrono::DateTime<chrono::Utc>> {
    let time = |value: Option<&Value>| {
        value
            .and_then(Value::as_str)
            .and_then(|text| chrono::DateTime::parse_from_rfc3339(text).ok())
            .map(|time| time.with_timezone(&chrono::Utc))
    };
    let not_ready_since = sb
        .pointer("/status/conditions")
        .and_then(Value::as_array)
        .and_then(|conditions| {
            conditions
                .iter()
                .find(|cond| cond.get("type").and_then(Value::as_str) == Some("Ready"))
        })
        .filter(|cond| cond.get("status").and_then(Value::as_str) != Some("True"))
        .and_then(|cond| time(cond.get("lastTransitionTime")));
    let deleted_at = time(sb.pointer("/metadata/deletionTimestamp"));
    not_ready_since.into_iter().chain(deleted_at).min()
}

/// Mirrors `sessions.readyCondition`.
fn ready_condition(sb: &Value) -> (bool, String) {
    let Some(conditions) = sb.pointer("/status/conditions").and_then(Value::as_array) else {
        return (false, "Ready condition not found".to_string());
    };
    for cond in conditions {
        if cond.get("type").and_then(Value::as_str) != Some("Ready") {
            continue;
        }
        let status = cond
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let reason = cond
            .get("reason")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if status == "True" {
            return (true, reason.to_string());
        }
        if !reason.is_empty() {
            return (false, reason.to_string());
        }
        return (false, status.to_string());
    }
    (false, "Ready condition not found".to_string())
}

/// Mirrors `sessions.terminalReadyReason`.
fn terminal_ready_reason(reason: &str) -> bool {
    matches!(
        reason,
        "Failed"
            | "Error"
            | "Evicted"
            | "Expired"
            | "DeadlineExceeded"
            | "SandboxFailed"
            | "PodFailed"
            | "NodeLost"
    )
}

// ── k8s resource.Quantity parsing ──────────────────────────────────────

/// Mirrors `resource.Quantity.MilliValue()` for the CPU formats the
/// renderer emits: a bare millicpu string like `"1500m"`, or a whole/
/// fractional core count like `"2"` / `"0.5"`. Returns millicores.
fn parse_quantity_millicores(s: &str) -> i32 {
    let s = s.trim();
    if let Some(milli) = s.strip_suffix('m') {
        return milli
            .trim()
            .parse::<f64>()
            .map(|v| v.round() as i32)
            .unwrap_or(0);
    }
    s.parse::<f64>()
        .map(|cores| (cores * 1000.0).round() as i32)
        .unwrap_or(0)
}

/// Mirrors `resource.Quantity.Value()` (bytes) for the memory/storage
/// formats the renderer emits: binary-SI suffixes (`Ki`/`Mi`/`Gi`/`Ti`),
/// decimal-SI suffixes (`k`/`M`/`G`/`T`), or a bare byte count. Go's
/// Quantity rounds *up* to the nearest byte; these inputs are always
/// whole units so the distinction never bites, but parse the integer
/// magnitude faithfully.
fn parse_quantity_bytes(s: &str) -> i64 {
    let s = s.trim();
    let binary: &[(&str, i64)] = &[
        ("Ki", 1 << 10),
        ("Mi", 1 << 20),
        ("Gi", 1 << 30),
        ("Ti", 1i64 << 40),
        ("Pi", 1i64 << 50),
    ];
    for (suffix, mult) in binary {
        if let Some(num) = s.strip_suffix(suffix) {
            return num
                .trim()
                .parse::<f64>()
                .map(|v| (v * *mult as f64) as i64)
                .unwrap_or(0);
        }
    }
    let decimal: &[(&str, i64)] = &[
        ("k", 1_000),
        ("M", 1_000_000),
        ("G", 1_000_000_000),
        ("T", 1_000_000_000_000),
    ];
    for (suffix, mult) in decimal {
        if let Some(num) = s.strip_suffix(suffix) {
            return num
                .trim()
                .parse::<f64>()
                .map(|v| (v * *mult as f64) as i64)
                .unwrap_or(0);
        }
    }
    s.parse::<f64>().map(|v| v as i64).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // Mirrors `TestDeclaredResourcesSumsContainersAndPVCs`.
    #[test]
    fn declared_resources_sums_containers_and_pvcs_like_go() {
        let sb = json!({
            "spec": {
                "podTemplate": {
                    "spec": {
                        "runtimeClassName": "commodity",
                        "containers": [
                            { "name": "workspace", "resources": { "requests": {
                                "cpu": "1500m", "memory": "2Gi" } } },
                            { "name": "codewire-gateway", "resources": { "requests": {
                                "cpu": "250m", "memory": "512Mi" } } },
                        ],
                    },
                },
                "volumeClaimTemplates": [
                    { "spec": { "resources": { "requests": { "storage": "20Gi" } } } },
                ],
            },
        });
        let got = declared_resources(&sb);
        assert_eq!(got.cpu_millicores, 1750);
        assert_eq!(got.memory_mib, 2560);
        assert_eq!(got.disk_gib, 20);
        assert_eq!(got.runtime_class.as_deref(), Some("commodity"));
    }

    #[test]
    fn declared_resources_handles_fractional_and_decimal_cpu() {
        // "2" cores = 2000m; "0.5" cores = 500m (Quantity MilliValue).
        assert_eq!(parse_quantity_millicores("2"), 2000);
        assert_eq!(parse_quantity_millicores("0.5"), 500);
        assert_eq!(parse_quantity_millicores("1500m"), 1500);
        // Memory: 2Gi → bytes → MiB.
        assert_eq!(parse_quantity_bytes("2Gi") >> 20, 2048);
        assert_eq!(parse_quantity_bytes("512Mi") >> 20, 512);
        // Storage: 20Gi → bytes → GiB.
        assert_eq!(parse_quantity_bytes("20Gi") >> 30, 20);
    }

    fn triple(got: &Resources) -> (i32, i32, i32) {
        (got.cpu_millicores, got.memory_mib, got.disk_gib)
    }

    #[test]
    fn a_shared_workspace_declares_its_full_vcpus() {
        let sandbox = json!({
            "spec": {
                "podTemplate": { "spec": {
                    "containers": [
                        { "name": "workspace", "resources": {
                            "requests": { "cpu": "1000m", "memory": "8Gi" },
                            "limits": { "cpu": "2000m", "memory": "8Gi" } } },
                        { "name": "dind", "resources": {
                            "requests": { "cpu": "500m", "memory": "1Gi" },
                            "limits": { "cpu": "2", "memory": "4Gi" } } }
                    ]
                } },
                "volumeClaimTemplates": [{
                    "metadata": { "name": "workspace" },
                    "spec": { "resources": { "requests": { "storage": "80Gi" } } }
                }]
            }
        });
        assert_eq!(triple(&declared_resources(&sandbox)), (2500, 9216, 80));
        assert_eq!(
            triple(&workspace_declared_resources(&sandbox)),
            (2000, 8192, 80)
        );
    }

    #[test]
    fn the_workspace_share_excludes_its_sidecars() {
        let sandbox = json!({
            "spec": {
                "podTemplate": { "spec": {
                    "runtimeClassName": "commodity",
                    "containers": [
                        { "name": "workspace", "resources": { "requests": {
                            "cpu": "4", "memory": "8Gi" } } },
                        { "name": "codewire-gateway", "resources": { "requests": {
                            "cpu": "250m", "memory": "512Mi" } } }
                    ]
                } },
                "volumeClaimTemplates": [{
                    "metadata": { "name": "workspace" },
                    "spec": { "resources": { "requests": { "storage": "40Gi" } } }
                }]
            }
        });
        assert_eq!(triple(&declared_resources(&sandbox)), (4250, 8704, 40));
        assert_eq!(
            triple(&workspace_declared_resources(&sandbox)),
            (4000, 8192, 40)
        );
    }

    #[test]
    fn a_member_carries_its_labels_phase_and_resources() {
        let sandbox: DynamicObject = serde_json::from_value(json!({
            "apiVersion": "agents.x-k8s.io/v1alpha1",
            "kind": "Sandbox",
            "metadata": {
                "name": "sandbox-a",
                "namespace": "dev-sandboxes",
                "uid": "uid-a",
                "labels": {
                    (LABEL_ENV_ID): "env-a",
                    (LABEL_ORG_ID): "org-a",
                    (LABEL_CLAIM_UID): "claim-a"
                }
            },
            "spec": { "podTemplate": { "spec": { "containers": [
                { "name": "workspace", "resources": { "requests": {
                    "cpu": "2", "memory": "4Gi" } } }
            ] } } },
            "status": { "conditions": [
                { "type": "Ready", "status": "False", "reason": "PodFailed" } ] }
        }))
        .unwrap();

        let member = runtime_member(&sandbox);

        assert_eq!(member.namespace, "dev-sandboxes");
        assert_eq!(member.name, "sandbox-a");
        assert_eq!(member.uid, "uid-a");
        assert_eq!(member.environment_id, "env-a");
        assert_eq!(member.organization_id, "org-a");
        assert_eq!(member.claim_uid, "claim-a");
        assert!(!member.snapshot_clearing);
        assert_eq!(member.phase, Phase::Terminated);
        assert_eq!(member.phase_reason, "PodFailed");
        assert_eq!(triple(&member.declared), (2000, 4096, 0));
        assert_eq!(triple(&member.workspace), (2000, 4096, 0));
    }

    #[test]
    fn a_snapshots_clearing_sandbox_is_marked_from_its_name() {
        let sandbox = |name: String| -> DynamicObject {
            serde_json::from_value(json!({
                "apiVersion": "agents.x-k8s.io/v1alpha1",
                "kind": "Sandbox",
                "metadata": { "name": name, "uid": "uid-a" },
                "spec": {}
            }))
            .unwrap()
        };

        let clearing = crate::sandbox::snapshots::clearing_name("snapshot-a");
        assert!(runtime_member(&sandbox(clearing)).snapshot_clearing);
        assert!(!runtime_member(&sandbox("sandbox-a".into())).snapshot_clearing);
    }

    #[test]
    fn an_unread_member_is_pending_with_no_owner_and_keeps_its_identity() {
        let sandbox: DynamicObject = serde_json::from_value(json!({
            "apiVersion": "agents.x-k8s.io/v1alpha1",
            "kind": "Sandbox",
            "metadata": {
                "name": "sandbox-a",
                "namespace": "dev-sandboxes",
                "uid": "uid-a",
                "labels": { (LABEL_ENV_ID): "env-a" }
            }
        }))
        .unwrap();

        let member = unread_member(&sandbox);

        assert_eq!(
            (member.name.as_str(), member.uid.as_str()),
            ("sandbox-a", "uid-a")
        );
        assert_eq!(member.namespace, "dev-sandboxes");
        assert_eq!(member.phase, Phase::Pending);
        assert!(member.environment_id.is_empty() && member.claim_uid.is_empty());
        assert_eq!(member.declared, Resources::default());
    }

    // Mirrors `TestClassify`.
    fn ready_sb(operating_mode: Option<&str>, status: &str, reason: &str) -> Value {
        let mut sb = json!({
            "spec": {},
            "status": { "conditions": [
                { "type": "Ready", "status": status, "reason": reason } ] },
        });
        if let Some(mode) = operating_mode {
            sb["spec"]["operatingMode"] = json!(mode);
        }
        sb
    }

    #[test]
    fn classify_mirrors_go() {
        // ready
        assert_eq!(
            classify(&ready_sb(Some("Running"), "True", "")).0,
            Phase::Running
        );
        // suspended (even with Ready=True, operatingMode terminates)
        assert_eq!(
            classify(&ready_sb(Some("Suspended"), "True", "")).0,
            Phase::Terminated
        );
        // pending: false ready, non-terminal reason
        assert_eq!(
            classify(&ready_sb(None, "False", "SandboxNotReady")).0,
            Phase::Pending
        );
        // terminal: false ready, terminal reason
        assert_eq!(
            classify(&ready_sb(None, "False", "Failed")).0,
            Phase::Terminated
        );
    }

    fn at(text: &str) -> Option<chrono::DateTime<chrono::Utc>> {
        Some(text.parse().unwrap())
    }

    #[test]
    fn a_stopped_sandbox_records_when_ready_turned_off_or_deletion_began() {
        let ready = |status: &str, time: &str| {
            json!({ "type": "Ready", "status": status, "reason": "SandboxSuspended",
                    "lastTransitionTime": time })
        };
        let suspended = json!({
            "spec": { "operatingMode": "Suspended" },
            "status": { "conditions": [ ready("False", "2026-11-03T21:02:30Z") ] },
        });
        assert_eq!(stopped_at(&suspended), at("2026-11-03T21:02:30Z"));

        // Ready still True: the controller hasn't acted on the suspension yet.
        let not_yet = json!({
            "spec": { "operatingMode": "Suspended" },
            "status": { "conditions": [ ready("True", "2026-11-03T20:00:00Z") ] },
        });
        assert_eq!(stopped_at(&not_yet), None);

        // A deletion requested while ready ends at the request.
        let deleting = json!({
            "metadata": { "deletionTimestamp": "2026-11-03T21:05:00Z" },
            "status": { "conditions": [ ready("True", "2026-11-03T20:00:00Z") ] },
        });
        assert_eq!(stopped_at(&deleting), at("2026-11-03T21:05:00Z"));

        // Both recorded: the earlier one.
        let both = json!({
            "metadata": { "deletionTimestamp": "2026-11-03T21:05:00Z" },
            "status": { "conditions": [ ready("False", "2026-11-03T21:02:30Z") ] },
        });
        assert_eq!(stopped_at(&both), at("2026-11-03T21:02:30Z"));

        let unreadable = json!({
            "status": { "conditions": [ ready("False", "not a time") ] },
        });
        assert_eq!(stopped_at(&unreadable), None);
    }

    #[test]
    fn only_a_terminated_member_carries_a_stop_time() {
        let sandbox = |mode: &str, status: &str| -> DynamicObject {
            serde_json::from_value(json!({
                "apiVersion": "agents.x-k8s.io/v1alpha1",
                "kind": "Sandbox",
                "metadata": { "name": "sandbox-a", "uid": "uid-a" },
                "spec": { "operatingMode": mode },
                "status": { "conditions": [
                    { "type": "Ready", "status": status, "reason": "DependenciesNotReady",
                      "lastTransitionTime": "2026-11-03T21:02:30Z" } ] }
            }))
            .unwrap()
        };

        let stopped = runtime_member(&sandbox("Suspended", "False"));
        assert_eq!(stopped.phase, Phase::Terminated);
        assert_eq!(stopped.stopped_at, at("2026-11-03T21:02:30Z"));

        let pending = runtime_member(&sandbox("Running", "False"));
        assert_eq!(pending.phase, Phase::Pending);
        assert_eq!(pending.stopped_at, None);
    }

    #[test]
    fn classify_deletion_timestamp_terminates() {
        let sb = json!({
            "metadata": { "deletionTimestamp": "2026-06-17T00:00:00Z" },
            "spec": { "operatingMode": "Running" },
            "status": { "conditions": [ { "type": "Ready", "status": "True" } ] },
        });
        assert_eq!(classify(&sb), (Phase::Terminated, "deleting".to_string()));
    }

    #[test]
    fn classify_absent_operating_mode_is_not_suspended() {
        // No spec.operatingMode + Ready → Running, not Terminated.
        let sb = json!({
            "spec": {},
            "status": { "conditions": [ { "type": "Ready", "status": "True" } ] },
        });
        assert_eq!(classify(&sb).0, Phase::Running);
    }

    #[test]
    fn terminal_reasons_mirror_go() {
        for r in [
            "Failed",
            "Error",
            "Evicted",
            "Expired",
            "DeadlineExceeded",
            "SandboxFailed",
            "PodFailed",
            "NodeLost",
        ] {
            assert!(terminal_ready_reason(r), "{r}");
        }
        assert!(!terminal_ready_reason("SandboxNotReady"));
        assert!(!terminal_ready_reason(""));
    }
}
