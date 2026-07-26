//! Sandbox billing-session lifecycle controller.
//!
//! Opens and closes `sandbox_running_sessions` rows as a Sandbox CR
//! starts (Ready) and stops (terminated / deleted / suspended). The
//! aggregation side (`AggregateMonthlyUsage`) already lives in
//! `codewire-billing::metering`; this is the writer that produces the
//! rows that aggregation reads.
//!
//! ## Informer → poll adaptation
//!
//! The Go controller registers a k8s shared informer over Sandboxes
//! (Add/Update → `reconcile`, Delete → `CloseByName`) and, after the
//! initial cache sync, runs `recoverOpenSessions` to close DB rows whose
//! Sandbox no longer exists. The Rust orchestration substitutes a
//! leader-gated poll for every watch it owns (`wait_for_ready`,
//! `sandbox_liveness_loop`), so this is a poll loop: each tick lists all
//! Sandboxes, reconciles each (open/heartbeat or close), then runs the
//! recovery sweep over the open DB rows. Because the recovery sweep runs
//! every tick (not just at startup), the explicit DeleteFunc branch from
//! Go is unnecessary — a vanished Sandbox is closed by the sweep with
//! reason `controller_lost_track`. (Go closes deletes immediately with
//! reason `deleted`; the steady-state row shape is identical, only the
//! close reason for a hard-deleted CR differs. Documented accepted drift.)
//!
//! ## Gating
//!
//! Runs when `billing-session` is in `WORKER_LOOPS` (the default), under
//! the orchestration leader. The `ON CONFLICT (runtime_type, runtime_uid)
//! WHERE ended_at IS NULL` upsert is idempotent, so a concurrent writer
//! (e.g. the legacy Go controller during a deploy overlap) cannot corrupt
//! a row.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use kube::api::DynamicObject;
use serde_json::Value;
use sqlx::{PgPool, Row};

use super::WorkerContext;
use crate::sandbox::client::SandboxClient;
use crate::sandbox::{LABEL_ENV_ID, LABEL_ORG_ID};

/// Stable SandboxClaim UID label.
const LABEL_CLAIM_UID: &str = "agents.x-k8s.io/claim-uid";

/// Mirrors the retired Go billing-session controller's default
/// `ResyncInterval` of `time.Minute`.
pub const BILLING_SESSION_INTERVAL: Duration = Duration::from_secs(60);

/// Mirrors `sessions.Phase`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Pending,
    Running,
    Terminated,
}

/// Mirrors `sessions.Resources` — the declared (requested) compute the
/// row is billed against. Integer widths match the schema
/// (`cpu_millicores`/`memory_mib`/`disk_gib` are INT4 → i32).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Resources {
    pub cpu_millicores: i32,
    pub memory_mib: i32,
    pub disk_gib: i32,
    pub runtime_class: Option<String>,
}

/// Mirrors `sessions.Identity`.
#[derive(Debug, Clone)]
struct Identity {
    environment_id: String,
    org_id: String,
    runtime_uid: String,
    runtime_name: String,
    namespace: String,
}

/// Mirrors `sessions.OpenSession`.
struct OpenSession {
    id: String,
    runtime_uid: String,
}

// ── resources.go ───────────────────────────────────────────────────────

/// Mirrors `sessions.DeclaredResources`: sum container CPU/memory
/// requests across the pod spec and storage requests across the volume
/// claim templates, reading from the Sandbox CR's
/// `spec.podTemplate.spec`.
///
/// Go uses k8s `resource.Quantity`: `Cpu().MilliValue()`,
/// `Memory().Value() >> 20` (bytes → MiB), `storage.Value() >> 30`
/// (bytes → GiB). `parse_quantity_*` mirrors that arithmetic.
pub fn declared_resources(sb: &Value) -> Resources {
    let mut out = Resources::default();

    let spec = sb.pointer("/spec/podTemplate/spec");
    if let Some(containers) = spec
        .and_then(|s| s.get("containers"))
        .and_then(Value::as_array)
    {
        for c in containers {
            let requests = c.pointer("/resources/requests");
            if let Some(cpu) = requests.and_then(|r| r.get("cpu")).and_then(Value::as_str) {
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

/// Mirrors `sessions.Classify`: drive the (phase, reason) state machine
/// off the Sandbox's deletion timestamp, operatingMode, and Ready condition.
pub fn classify(sb: &Value) -> (Phase, String) {
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

// ── store.go ───────────────────────────────────────────────────────────

/// Mirrors `Store.ResolveIdentity`: derive (env, org, uid, name, ns) from
/// the Sandbox's labels, falling back to the `sandbox_environment_backend`
/// claim-uid join and the `environments` org lookup. Returns `Ok(None)`
/// when the Sandbox is not a billable Codewire environment (the Go
/// `(Identity{}, false, nil)` path).
async fn resolve_identity(
    pool: &PgPool,
    namespace: &str,
    runtime_name: &str,
    runtime_uid: &str,
    labels: &serde_json::Map<String, Value>,
) -> anyhow::Result<Option<Identity>> {
    let mut env_id = labels
        .get(LABEL_ENV_ID)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let mut org_id = labels
        .get(LABEL_ORG_ID)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let claim_uid = labels
        .get(LABEL_CLAIM_UID)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();

    if env_id.is_empty() && !claim_uid.is_empty() {
        let row = sqlx::query(
            "SELECT environment_id
               FROM sandbox_environment_backend
              WHERE sandbox_claim_uid = $1 AND namespace = $2",
        )
        .bind(&claim_uid)
        .bind(namespace)
        .fetch_optional(pool)
        .await
        .map_err(|e| anyhow::anyhow!("resolve environment by claim uid: {e}"))?;
        match row {
            None => return Ok(None),
            Some(r) => env_id = r.try_get::<String, _>(0).unwrap_or_default(),
        }
    }
    if env_id.is_empty() {
        return Ok(None);
    }

    if org_id.is_empty() {
        let row = sqlx::query("SELECT org_id FROM environments WHERE id = $1")
            .bind(&env_id)
            .fetch_optional(pool)
            .await
            .map_err(|e| anyhow::anyhow!("resolve organization by environment: {e}"))?;
        match row {
            None => return Ok(None),
            Some(r) => org_id = r.try_get::<String, _>(0).unwrap_or_default(),
        }
    }

    if org_id.is_empty()
        || runtime_uid.is_empty()
        || runtime_name.is_empty()
        || namespace.is_empty()
    {
        return Ok(None);
    }

    Ok(Some(Identity {
        environment_id: env_id,
        org_id,
        runtime_uid: runtime_uid.to_string(),
        runtime_name: runtime_name.to_string(),
        namespace: namespace.to_string(),
    }))
}

/// Mirrors `Store.OpenOrHeartbeat`: upsert the open row keyed by the
/// partial unique index `(runtime_type, runtime_uid) WHERE ended_at IS
/// NULL`. Idempotent: a re-observed running Sandbox refreshes resources
/// and `last_observed_at`/`updated_at` rather than inserting a duplicate.
async fn open_or_heartbeat(
    pool: &PgPool,
    id: &Identity,
    res: &Resources,
    observed_at: chrono::DateTime<chrono::Utc>,
) -> anyhow::Result<()> {
    sqlx::query(
        r#"INSERT INTO sandbox_running_sessions (
               environment_id, organization_id, runtime_type, runtime_uid, runtime_name,
               runtime_namespace, cpu_millicores, memory_mib, disk_gib, runtime_class,
               started_at, last_observed_at, updated_at
           )
           VALUES ($1, $2, 'sandbox', $3, $4, $5, $6, $7, $8, $9, $10, $10, $10)
           ON CONFLICT (runtime_type, runtime_uid) WHERE ended_at IS NULL
           DO UPDATE SET
               environment_id = EXCLUDED.environment_id,
               organization_id = EXCLUDED.organization_id,
               runtime_name = EXCLUDED.runtime_name,
               runtime_namespace = EXCLUDED.runtime_namespace,
               cpu_millicores = EXCLUDED.cpu_millicores,
               memory_mib = EXCLUDED.memory_mib,
               disk_gib = EXCLUDED.disk_gib,
               runtime_class = EXCLUDED.runtime_class,
               last_observed_at = EXCLUDED.last_observed_at,
               updated_at = EXCLUDED.updated_at"#,
    )
    .bind(&id.environment_id)
    .bind(&id.org_id)
    .bind(&id.runtime_uid)
    .bind(&id.runtime_name)
    .bind(&id.namespace)
    .bind(res.cpu_millicores)
    .bind(res.memory_mib)
    .bind(res.disk_gib)
    .bind(&res.runtime_class)
    .bind(observed_at)
    .execute(pool)
    .await
    .map_err(|e| anyhow::anyhow!("open/heartbeat sandbox session: {e}"))?;
    Ok(())
}

/// Mirrors `Store.CloseByUID`: set `ended_at`/`end_reason` on the open row
/// for this runtime UID. No-op when the UID is empty or already closed.
async fn close_by_uid(
    pool: &PgPool,
    runtime_uid: &str,
    reason: &str,
    ended_at: chrono::DateTime<chrono::Utc>,
) -> anyhow::Result<()> {
    if runtime_uid.is_empty() {
        return Ok(());
    }
    sqlx::query(
        r#"UPDATE sandbox_running_sessions
              SET ended_at = $1, end_reason = $2, updated_at = $1
            WHERE runtime_type = 'sandbox'
              AND runtime_uid = $3
              AND ended_at IS NULL"#,
    )
    .bind(ended_at)
    .bind(reason)
    .bind(runtime_uid)
    .execute(pool)
    .await
    .map_err(|e| anyhow::anyhow!("close sandbox session by uid: {e}"))?;
    Ok(())
}

/// Mirrors `Store.ListOpen`: open rows in (or across, when `namespace` is
/// empty) the namespace, for the recovery sweep.
async fn list_open(pool: &PgPool, namespace: &str) -> anyhow::Result<Vec<OpenSession>> {
    let rows = sqlx::query(
        r#"SELECT id, runtime_uid
             FROM sandbox_running_sessions
            WHERE runtime_type = 'sandbox'
              AND ended_at IS NULL
              AND ($1 = '' OR runtime_namespace = $1)"#,
    )
    .bind(namespace)
    .fetch_all(pool)
    .await
    .map_err(|e| anyhow::anyhow!("list open sandbox sessions: {e}"))?;
    Ok(rows
        .into_iter()
        .map(|r| OpenSession {
            id: r.try_get("id").unwrap_or_default(),
            runtime_uid: r.try_get("runtime_uid").unwrap_or_default(),
        })
        .collect())
}

// ── controller.go ──────────────────────────────────────────────────────

/// Mirrors `handler.reconcile`: resolve identity, classify, then open/
/// heartbeat (Running) or close (Terminated). Pending is a no-op.
async fn reconcile(pool: &PgPool, sb: &DynamicObject) {
    let value = match serde_json::to_value(sb) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "billing-session: serialize Sandbox failed");
            return;
        }
    };
    let namespace = sb.metadata.namespace.clone().unwrap_or_default();
    let name = sb.metadata.name.clone().unwrap_or_default();
    let uid = sb.metadata.uid.clone().unwrap_or_default();
    let empty = serde_json::Map::new();
    let labels_map = value
        .pointer("/metadata/labels")
        .and_then(Value::as_object)
        .unwrap_or(&empty);

    let id = match resolve_identity(pool, &namespace, &name, &uid, labels_map).await {
        Ok(Some(id)) => id,
        Ok(None) => return,
        Err(e) => {
            tracing::error!(namespace, name, error = %e, "billing-session: resolve identity");
            return;
        }
    };

    let (phase, reason) = classify(&value);
    let now = chrono::Utc::now();
    match phase {
        Phase::Running => {
            let res = declared_resources(&value);
            if let Err(e) = open_or_heartbeat(pool, &id, &res, now).await {
                tracing::error!(environment_id = id.environment_id, sandbox = name, error = %e, "billing-session: open/heartbeat session");
            }
        }
        Phase::Terminated => {
            let reason = if reason.is_empty() {
                "not_billable".to_string()
            } else {
                reason
            };
            if let Err(e) = close_by_uid(pool, &uid, &reason, now).await {
                tracing::error!(environment_id = id.environment_id, sandbox = name, reason, error = %e, "billing-session: close session");
            }
        }
        Phase::Pending => {}
    }
}

/// One reconcile cycle: list every Sandbox, reconcile it, then close DB
/// rows whose Sandbox is gone (mirrors `recoverOpenSessions`, run every
/// tick rather than only at cache sync — see the module note).
async fn run_cycle(ctx: &WorkerContext, namespace: &str) {
    let Some(kube) = &ctx.kube else { return };
    let client = SandboxClient::new(kube.clone(), namespace);

    let sandboxes = match client.list_sandboxes().await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(namespace, error = %e, "billing-session: list sandboxes");
            return;
        }
    };

    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for sb in &sandboxes {
        if let Some(uid) = &sb.metadata.uid {
            seen.insert(uid.clone());
        }
        reconcile(&ctx.pool, sb).await;
    }

    let open = match list_open(&ctx.pool, namespace).await {
        Ok(o) => o,
        Err(e) => {
            tracing::error!(error = %e, "billing-session: list open sessions for recovery");
            return;
        }
    };
    let now = chrono::Utc::now();
    for row in open {
        if seen.contains(&row.runtime_uid) {
            continue;
        }
        if let Err(e) =
            close_by_uid(&ctx.pool, &row.runtime_uid, "controller_lost_track", now).await
        {
            tracing::error!(session_id = row.id, runtime_uid = row.runtime_uid, error = %e, "billing-session: recover missing session");
        }
    }
}

/// Leader-gated poll loop. Mirrors `StartSandboxController`'s guards (no
/// kube client / no pool → skip) and resync cadence.
pub async fn billing_session_loop(
    ctx: Arc<WorkerContext>,
    is_leader: Arc<AtomicBool>,
    namespace: String,
) {
    if ctx.kube.is_none() {
        tracing::info!("billing-session: sandbox client unavailable, skipping");
        return;
    }
    tracing::info!(namespace, "billing-session controller: started");
    let mut ticker = tokio::time::interval(BILLING_SESSION_INTERVAL);
    ticker.tick().await; // align with Go's NewTicker (first fire after interval)
    loop {
        ticker.tick().await;
        if !is_leader.load(Ordering::SeqCst) {
            continue;
        }
        run_cycle(&ctx, &namespace).await;
    }
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
                        "runtimeClassName": "isol8",
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
        assert_eq!(got.runtime_class.as_deref(), Some("isol8"));
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
