//! Claim-time workspace bindings (Program #2238, design §5, §6, §10, §12 and
//! §16).
//!
//! `write_binding` is the only writer of `sandbox_workspace_bindings` and of
//! the backend pointer (`pod_uid`, `bound_at`). It runs inside a
//! generation-fenced environment transaction, after these checks:
//! - the converged Claim → Sandbox → Pod chain;
//! - images that equal the Sandbox template, with pinned digests matching;
//! - the workspace PVC resolved by UID.
//!
//! B2 enforces them on every lifecycle path: create, start, a replaced Pod
//! while running and daemon repair all call [`bind_workspace_runtime`] after
//! claim readiness and label convergence and before the gateway readiness
//! wait. A failed check fails the activity, and an unbound identity-free Pod
//! that failed is deleted with a UID precondition so it never serves. A legacy
//! Pod (environment scope) keeps its rendered token and is never deleted
//! here. Stop and destroy release the binding; a restore adoption is the one
//! path that moves the recorded PVC UID.
//!
//! The bounded leader loop still records legacy running environments in
//! shadow mode (counted and logged, never enforced) and records
//! `workspace_pvc_uid` the first time it resolves the PVC of any environment
//! that has a Sandbox, stopped ones included.

use std::collections::{BTreeMap, HashMap};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use codewire_daemon_proto::{SANDBOX_SERVICE_ACCOUNT, WORKSPACE_BINDING_TOKEN_AUDIENCE};
use k8s_openapi::api::core::v1::{Container, ContainerStatus, Pod};
use kube::api::DynamicObject;
use prometheus::{IntCounterVec, Opts, register_int_counter_vec};
use sqlx::{PgConnection, PgPool};

use super::WorkerContext;
use super::activity_authority::{ActivityAuthority, await_external_mutation, is_authority_lost};
use super::create::SandboxWorkerCfg;
use super::env_data::{BackendRow, EnvironmentRow, load_environment, load_environment_in};
use super::env_log::emit_authoritative_environment_log_for_states;
use super::environment_auth::{WorkspaceCredentialScope, daemon_credential_for};
use crate::sandbox::client::{
    RuntimeIdentityObservation, SandboxClient, WorkspacePodIdentity, WorkspacePvc,
};
use crate::sandbox::warm_pool::{
    LAUNCH_TYPE_LABEL, WarmPoolObjects, is_warm_pool_name, pod_spec_pool_revision,
    sandbox_matches_rendering,
};
use crate::sandbox::{ClaimOpts, LABEL_OPERATION_GENERATION};
use crate::start_metrics::StartPath;

/// Environments examined per pass.
const BACKFILL_BATCH: i64 = 16;
/// Name of the projected binding-token volume a binding-mode Pod mounts.
pub const WORKSPACE_BINDING_VOLUME: &str = "workspace-binding-identity";
const DAEMON_AUTH_TOKEN_ENV: &str = "CODEWIRE_DAEMON_AUTH_TOKEN";
const GENERATION_ENV: &str = "CODEWIRE_ENVIRONMENT_OPERATION_GENERATION";
const PROJECTION_SHA256_ENV: &str = "CODEWIRE_ENVIRONMENT_PROJECTION_SHA256";
const MANAGED_CLIENTS_ENV: &str = codewire_access::MANAGED_CREDENTIAL_CLIENTS_ENV;
const RUNNING: [&str; 1] = ["running"];

// ------------------------------------------------------------ telemetry

static RECORDS: OnceLock<IntCounterVec> = OnceLock::new();
static PVC_RECORDS: OnceLock<IntCounterVec> = OnceLock::new();

/// Outcome of one recording attempt. Labels are closed categories; no
/// environment, Pod or claim identifier is ever a label.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecordResult {
    Recorded,
    Unchanged,
    /// Not yet bindable (not running, labels not converged, authority moved).
    NotReady,
    /// A check failed. Counted, never enforced in B1.
    Denied,
    /// The Pod is already bound to another environment.
    Conflict,
    Unavailable,
}

impl RecordResult {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
            Self::Unchanged => "unchanged",
            Self::NotReady => "not_ready",
            Self::Denied => "denied",
            Self::Conflict => "conflict",
            Self::Unavailable => "unavailable",
        }
    }
}

fn observe(
    counter: &'static OnceLock<IntCounterVec>,
    name: &str,
    help: &str,
    result: RecordResult,
) {
    counter
        .get_or_init(|| {
            register_int_counter_vec!(Opts::new(name, help), &["result"])
                .expect("workspace binding record metric registration must be unique")
        })
        .with_label_values(&[result.as_str()])
        .inc();
}

fn observe_record(result: RecordResult) {
    observe(
        &RECORDS,
        "codewire_workspace_binding_records_total",
        "Workspace binding recording attempts by result.",
        result,
    );
}

fn observe_pvc_record(result: RecordResult) {
    observe(
        &PVC_RECORDS,
        "codewire_workspace_pvc_records_total",
        "First workspace PVC UID resolutions by result.",
        result,
    );
}

// --------------------------------------------------------------- writer

/// Every value one binding records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BindingRecord {
    pub environment_id: String,
    pub organization_id: String,
    pub pod_uid: String,
    pub namespace: String,
    pub pod_name: String,
    pub claim_uid: String,
    pub sandbox_uid: String,
    pub workspace_pvc_uid: Option<String>,
    pub operation_generation: i64,
    pub projection_selection_sha256: Option<String>,
    pub managed_credential_clients: String,
    pub credential_scope: WorkspaceCredentialScope,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WriteOutcome {
    Recorded,
    Unchanged,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum WriteRefused {
    #[error("Pod is bound to another environment")]
    BoundElsewhere,
    #[error("workspace binding was already released")]
    Released,
    #[error("workspace binding backend association changed")]
    BackendChanged,
    #[error("workspace PVC does not match the recorded UID")]
    PvcMismatch,
}

/// namespace, claim UID, organization, binding pointer, workspace PVC UID.
type LockedBackendRow = (
    String,
    Option<String>,
    String,
    Option<String>,
    Option<String>,
);

/// Records `record` inside the caller's transaction, which must already hold
/// the generation-fenced environment row lock (design §5.5). Pod UID →
/// environment is never overwritten; another environment's binding refuses
/// and mutates nothing. The notification is delivered at commit.
pub(crate) async fn write_binding(
    tx: &mut PgConnection,
    record: &BindingRecord,
) -> anyhow::Result<WriteOutcome> {
    let backend: Option<LockedBackendRow> = sqlx::query_as(
        "SELECT b.namespace, b.sandbox_claim_uid, e.org_id, b.pod_uid, b.workspace_pvc_uid
               FROM sandbox_environment_backend b
               JOIN environments e ON e.id = b.environment_id
              WHERE b.environment_id = $1
                FOR UPDATE OF b",
    )
    .bind(&record.environment_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((namespace, claim_uid, organization, pointer, recorded_pvc)) = backend else {
        return Err(WriteRefused::BackendChanged.into());
    };
    if namespace != record.namespace
        || claim_uid.as_deref() != Some(record.claim_uid.as_str())
        || organization != record.organization_id
    {
        return Err(WriteRefused::BackendChanged.into());
    }
    if recorded_pvc
        .as_deref()
        .is_some_and(|recorded| record.workspace_pvc_uid.as_deref() != Some(recorded))
    {
        return Err(WriteRefused::PvcMismatch.into());
    }

    let existing: Option<(String, bool)> = sqlx::query_as(
        "SELECT environment_id, released_at IS NOT NULL
           FROM sandbox_workspace_bindings WHERE pod_uid = $1 FOR UPDATE",
    )
    .bind(&record.pod_uid)
    .fetch_optional(&mut *tx)
    .await?;
    match existing {
        Some((environment, _)) if environment != record.environment_id => {
            return Err(WriteRefused::BoundElsewhere.into());
        }
        Some((_, true)) => return Err(WriteRefused::Released.into()),
        Some((_, false)) if pointer.as_deref() == Some(record.pod_uid.as_str()) => {
            // Idempotent re-record; only a first PVC resolution may be added.
            if recorded_pvc.is_none() && record.workspace_pvc_uid.is_some() {
                sqlx::query(
                    "UPDATE sandbox_environment_backend SET workspace_pvc_uid = $2
                      WHERE environment_id = $1 AND workspace_pvc_uid IS NULL",
                )
                .bind(&record.environment_id)
                .bind(&record.workspace_pvc_uid)
                .execute(&mut *tx)
                .await?;
                return Ok(WriteOutcome::Recorded);
            }
            return Ok(WriteOutcome::Unchanged);
        }
        Some((_, false)) => {}
        None => {
            // The partial unique index allows one live binding per
            // environment, so release the previous one first.
            sqlx::query(
                "UPDATE sandbox_workspace_bindings SET released_at = GREATEST(now(), bound_at)
                  WHERE environment_id = $1 AND released_at IS NULL",
            )
            .bind(&record.environment_id)
            .execute(&mut *tx)
            .await?;
            let inserted: Option<(String,)> = sqlx::query_as(
                "INSERT INTO sandbox_workspace_bindings
                    (pod_uid, environment_id, namespace, pod_name, claim_uid, sandbox_uid,
                     workspace_pvc_uid, operation_generation, projection_selection_sha256,
                     managed_credential_clients, credential_scope)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                 ON CONFLICT (pod_uid) DO NOTHING
                 RETURNING pod_uid",
            )
            .bind(&record.pod_uid)
            .bind(&record.environment_id)
            .bind(&record.namespace)
            .bind(&record.pod_name)
            .bind(&record.claim_uid)
            .bind(&record.sandbox_uid)
            .bind(&record.workspace_pvc_uid)
            .bind(record.operation_generation)
            .bind(&record.projection_selection_sha256)
            .bind(&record.managed_credential_clients)
            .bind(record.credential_scope.as_str())
            .fetch_optional(&mut *tx)
            .await?;
            if inserted.is_none() {
                // A concurrent insert won; the caller's transaction rolls back.
                return Err(WriteRefused::BoundElsewhere.into());
            }
        }
    }
    sqlx::query(
        "UPDATE sandbox_environment_backend
            SET pod_uid = $2, bound_at = now(),
                workspace_pvc_uid = COALESCE(workspace_pvc_uid, $3)
          WHERE environment_id = $1",
    )
    .bind(&record.environment_id)
    .bind(&record.pod_uid)
    .bind(&record.workspace_pvc_uid)
    .execute(&mut *tx)
    .await?;
    sqlx::query("SELECT pg_notify($1, $2)")
        .bind(crate::workspace_binding::WORKSPACE_BINDINGS_CHANNEL)
        .bind(&record.pod_uid)
        .execute(&mut *tx)
        .await?;
    Ok(WriteOutcome::Recorded)
}

/// Records the first resolved workspace PVC UID (NULL → UID) inside the
/// caller's generation-fenced transaction. Never moves a recorded UID.
pub(crate) async fn write_first_workspace_pvc(
    tx: &mut PgConnection,
    environment_id: &str,
    claim_uid: &str,
    pvc_uid: &str,
) -> anyhow::Result<WriteOutcome> {
    let updated = sqlx::query(
        "UPDATE sandbox_environment_backend SET workspace_pvc_uid = $3
          WHERE environment_id = $1 AND sandbox_claim_uid = $2 AND workspace_pvc_uid IS NULL",
    )
    .bind(environment_id)
    .bind(claim_uid)
    .bind(pvc_uid)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    Ok(if updated == 1 {
        WriteOutcome::Recorded
    } else {
        WriteOutcome::Unchanged
    })
}

// ---------------------------------------------------------- live checks

/// Which credential a Pod was rendered with (design §5.5). A binding-mode Pod
/// mounts the binding token; a legacy Pod carries the environment token in its
/// `workspace` container. Both or neither is refused.
pub(crate) fn credential_scope(pod: &Pod) -> Option<WorkspaceCredentialScope> {
    let spec = pod.spec.as_ref()?;
    let binding_volume = spec.volumes.iter().flatten().any(|volume| {
        volume.name == WORKSPACE_BINDING_VOLUME
            && volume
                .projected
                .as_ref()
                .and_then(|projected| projected.sources.as_ref())
                .is_some_and(|sources| {
                    sources.iter().any(|source| {
                        source.service_account_token.as_ref().is_some_and(|token| {
                            token.audience.as_deref() == Some(WORKSPACE_BINDING_TOKEN_AUDIENCE)
                        })
                    })
                })
    });
    let environment_token = workspace_container(pod).is_some_and(|container| {
        env_entries(container, DAEMON_AUTH_TOKEN_ENV)
            .next()
            .is_some()
    });
    match (binding_volume, environment_token) {
        (true, false) => Some(WorkspaceCredentialScope::Pod),
        (false, true) => Some(WorkspaceCredentialScope::Environment),
        _ => None,
    }
}

fn workspace_container(pod: &Pod) -> Option<&Container> {
    pod.spec
        .as_ref()?
        .containers
        .iter()
        .find(|container| container.name == "workspace")
}

fn env_entries<'a>(
    container: &'a Container,
    name: &'a str,
) -> impl Iterator<Item = &'a k8s_openapi::api::core::v1::EnvVar> + 'a {
    container
        .env
        .iter()
        .flatten()
        .filter(move |variable| variable.name == name)
}

/// One literal value, or absent. Duplicates and `valueFrom` are refused.
fn literal_env<'a>(container: &'a Container, name: &str) -> Result<Option<&'a str>, ()> {
    let mut values = container
        .env
        .iter()
        .flatten()
        .filter(|variable| variable.name == name);
    match (values.next(), values.next()) {
        (None, _) => Ok(None),
        (Some(variable), None) if variable.value_from.is_none() => {
            Ok(Some(variable.value.as_deref().unwrap_or_default()))
        }
        _ => Err(()),
    }
}

/// The operation generation, projection digest and canonical managed
/// clients a binding captures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CapturedBootstrap {
    pub operation_generation: i64,
    pub projection_selection_sha256: Option<String>,
    pub managed_credential_clients: String,
}

/// A legacy (environment-scope) Pod: what it was rendered with, so the record
/// matches what the broker reads from it today. A Pod rendered without a
/// projection carries no generation variable; its converged generation label
/// stands in.
pub(crate) fn environment_scope_capture(pod: &Pod) -> Option<CapturedBootstrap> {
    let container = workspace_container(pod)?;
    let generation = match literal_env(container, GENERATION_ENV).ok()? {
        Some(value) => value.parse::<i64>().ok()?,
        None => pod
            .metadata
            .labels
            .as_ref()?
            .get(LABEL_OPERATION_GENERATION)?
            .parse::<i64>()
            .ok()?,
    };
    let digest = literal_env(container, PROJECTION_SHA256_ENV).ok()?;
    if digest.is_some_and(|digest| {
        digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    }) {
        return None;
    }
    let clients = match literal_env(container, MANAGED_CLIENTS_ENV).ok()? {
        Some(value) => codewire_access::ManagedCredentialClients::decode(value).ok()?,
        None => codewire_access::ManagedCredentialClients::default(),
    };
    (generation > 0).then(|| CapturedBootstrap {
        operation_generation: generation,
        projection_selection_sha256: digest.map(str::to_owned),
        managed_credential_clients: clients.encode().to_owned(),
    })
}

/// A binding-mode Pod: the same environment row the template options use.
pub(crate) fn pod_scope_capture(env: &EnvironmentRow) -> Option<CapturedBootstrap> {
    let selection = env.projection_selection.as_ref().ok()?;
    let digest = match selection {
        Some(selection) => Some(
            selection
                .sha256()
                .ok()?
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        ),
        None => None,
    };
    let clients = env.managed_credential_clients.as_ref().ok()?;
    (env.operation_generation > 0).then(|| CapturedBootstrap {
        operation_generation: env.operation_generation,
        projection_selection_sha256: digest,
        managed_credential_clients: clients.encode().to_owned(),
    })
}

fn template_images(sandbox: &DynamicObject, pointer: &str) -> Option<BTreeMap<String, String>> {
    let Some(containers) = sandbox.data.pointer(pointer) else {
        return Some(BTreeMap::new());
    };
    let mut images = BTreeMap::new();
    for container in containers.as_array()? {
        let name = container.get("name")?.as_str()?.to_owned();
        let image = container.get("image")?.as_str()?.to_owned();
        if images.insert(name, image).is_some() {
            return None;
        }
    }
    Some(images)
}

fn pod_images(containers: &[Container]) -> Option<BTreeMap<String, String>> {
    let mut images = BTreeMap::new();
    for container in containers {
        if images
            .insert(container.name.clone(), container.image.clone()?)
            .is_some()
        {
            return None;
        }
    }
    Some(images)
}

fn pinned_digest(reference: &str) -> Option<&str> {
    reference
        .rsplit_once('@')
        .map(|(_, digest)| digest)
        .filter(|digest| digest.starts_with("sha256:"))
}

fn status_digest(image_id: &str) -> &str {
    image_id
        .rsplit_once('@')
        .map_or(image_id, |(_, digest)| digest)
}

/// Design §5.3: every container and init-container image equals the owning
/// Sandbox's pod template, and each digest-pinned reference matches the
/// digest the kubelet reports for that container.
pub(crate) fn images_match(sandbox: &DynamicObject, pod: &Pod) -> bool {
    let Some(spec) = pod.spec.as_ref() else {
        return false;
    };
    let (Some(containers), Some(init_containers)) = (
        pod_images(&spec.containers),
        pod_images(spec.init_containers.as_deref().unwrap_or_default()),
    ) else {
        return false;
    };
    if Some(&containers) != template_images(sandbox, "/spec/podTemplate/spec/containers").as_ref()
        || Some(&init_containers)
            != template_images(sandbox, "/spec/podTemplate/spec/initContainers").as_ref()
    {
        return false;
    }
    let status = pod.status.as_ref();
    let statuses: Vec<&ContainerStatus> = status
        .into_iter()
        .flat_map(|status| {
            status
                .container_statuses
                .iter()
                .flatten()
                .chain(status.init_container_statuses.iter().flatten())
        })
        .collect();
    containers
        .iter()
        .chain(init_containers.iter())
        .all(|(name, image)| match pinned_digest(image) {
            None => true,
            Some(digest) => statuses
                .iter()
                .find(|status| &status.name == name)
                .is_some_and(|status| status_digest(&status.image_id) == digest),
        })
}

/// Design §5.2 on a re-read Pod: the observed UID, not terminating, the
/// sandbox service account, and the observed Sandbox controller.
fn pod_still_observed(pod: &Pod, pod_uid: &str, sandbox_uid: &str) -> bool {
    pod.metadata.uid.as_deref() == Some(pod_uid)
        && pod.metadata.deletion_timestamp.is_none()
        && pod
            .spec
            .as_ref()
            .and_then(|spec| spec.service_account_name.as_deref())
            == Some(SANDBOX_SERVICE_ACCOUNT)
        && pod
            .metadata
            .owner_references
            .iter()
            .flatten()
            .filter(|owner| owner.controller == Some(true))
            .map(|owner| (owner.kind.as_str(), owner.uid.as_str()))
            .eq([("Sandbox", sandbox_uid)])
}

/// The PVC named by the Pod's `workspace` volume, or `None` when it has none.
fn workspace_volume_claim(pod: &Pod) -> Option<&str> {
    pod.spec
        .as_ref()?
        .volumes
        .iter()
        .flatten()
        .find(|volume| volume.name == "workspace")?
        .persistent_volume_claim
        .as_ref()
        .map(|claim| claim.claim_name.as_str())
}

/// Design §5.4: the Pod mounts exactly the resolved PVC, which is Bound, or
/// no workspace PVC at all for a volume-less environment.
fn pvc_matches(pod: &Pod, pvc: &WorkspacePvc) -> bool {
    match pvc {
        WorkspacePvc::VolumeLess => workspace_volume_claim(pod).is_none(),
        WorkspacePvc::Claim { name, bound, .. } => {
            *bound && workspace_volume_claim(pod) == Some(name.as_str())
        }
    }
}

// ------------------------------------------------------------- recorder

/// namespace, claim name, claim UID, workspace PVC UID.
type BackendFactsRow = (String, Option<String>, Option<String>, Option<String>);

struct BackendFacts {
    namespace: String,
    claim_name: String,
    claim_uid: String,
    workspace_pvc_uid: Option<String>,
}

async fn load_backend_facts(
    pool: &PgPool,
    environment_id: &str,
) -> anyhow::Result<Option<BackendFacts>> {
    let row: Option<BackendFactsRow> = sqlx::query_as(
        "SELECT namespace, sandbox_claim_name, sandbox_claim_uid, workspace_pvc_uid
           FROM sandbox_environment_backend WHERE environment_id = $1",
    )
    .bind(environment_id)
    .fetch_optional(pool)
    .await?;
    Ok(
        row.and_then(|(namespace, claim_name, claim_uid, workspace_pvc_uid)| {
            Some(BackendFacts {
                namespace,
                claim_name: claim_name.filter(|name| !name.is_empty())?,
                claim_uid: claim_uid.filter(|uid| !uid.is_empty())?,
                workspace_pvc_uid,
            })
        }),
    )
}

fn denied(environment_id: &str, reason: &str) -> RecordResult {
    tracing::warn!(env = %environment_id, reason, "workspace binding shadow check failed");
    RecordResult::Denied
}

/// One shadow recording attempt for a running environment.
pub(crate) async fn record_workspace_binding_shadow(
    ctx: &WorkerContext,
    environment_id: &str,
) -> RecordResult {
    let Some(kube) = ctx.kube.as_ref() else {
        observe_record(RecordResult::Unavailable);
        return RecordResult::Unavailable;
    };
    let attempt = tokio::time::timeout(
        RECORD_ATTEMPT_TIMEOUT,
        record_backfill(&ctx.pool, kube, environment_id),
    )
    .await;
    let result = match attempt.unwrap_or_else(|_| Err(anyhow::anyhow!("binding attempt timed out")))
    {
        Ok(result) => result,
        Err(error) if is_authority_lost(&error) => RecordResult::NotReady,
        Err(error) => match error.downcast_ref::<WriteRefused>() {
            Some(WriteRefused::BoundElsewhere) => {
                tracing::error!(env = %environment_id, "workspace Pod is bound to another environment");
                RecordResult::Conflict
            }
            Some(refused) => denied(environment_id, &refused.to_string()),
            None => {
                tracing::warn!(env = %environment_id, error = %error, "workspace binding shadow record failed");
                RecordResult::Unavailable
            }
        },
    };
    observe_record(result);
    result
}

/// The backfill's recording of a running environment. It records only a
/// legacy Pod's environment scope: a Pod-scope binding is served by the 8087
/// listener and the gateway RPC, so it is recorded only by the enforced
/// lifecycle path ([`record_workspace_binding`]), which re-checks the captured
/// projection under the lock and deletes a Pod that fails (review M1). An
/// identity-free Pod is left `NotReady` here, never bound or deleted.
async fn record_backfill(
    pool: &PgPool,
    kube: &kube::Client,
    environment_id: &str,
) -> anyhow::Result<RecordResult> {
    let env = load_environment(pool, environment_id).await?;
    if env.env_type != "sandbox"
        || env.state != "running"
        || env.desired_state != "started"
        || env.operation_generation <= 0
    {
        return Ok(RecordResult::NotReady);
    }
    let Some(backend) = load_backend_facts(pool, environment_id).await? else {
        return Ok(RecordResult::NotReady);
    };
    let authority =
        ActivityAuthority::capture(pool, environment_id, env.operation_generation).await?;
    let client = SandboxClient::new(kube.clone(), &backend.namespace);
    let opts = ClaimOpts {
        environment_id: env.id.clone(),
        org_id: env.org_id.clone(),
        operation_generation: env.operation_generation,
        ..Default::default()
    };

    // §5.1: the converged chain; Claim Ready alone never suffices.
    let runtime = match client
        .read_bindable_runtime(&opts, &backend.claim_name, &backend.claim_uid)
        .await
    {
        Ok(runtime) => runtime,
        Err(error) => return Ok(denied(environment_id, &error.to_string())),
    };
    if !runtime.converged {
        return Ok(RecordResult::NotReady);
    }
    let pod_uid = runtime.observation.pod().uid.clone();
    let pod_name = runtime.observation.pod().name.clone();
    let sandbox_uid = runtime.observation.sandbox_uid().to_owned();

    // §5.2: re-read the Pod.
    let Some(pod) = client.get_workspace_pod(&pod_name).await? else {
        return Ok(RecordResult::NotReady);
    };
    if !pod_still_observed(&pod, &pod_uid, &sandbox_uid) {
        return Ok(denied(
            environment_id,
            "workspace Pod changed after observation",
        ));
    }
    // M1: only the enforced lifecycle path records a Pod-scope binding.
    if credential_scope(&pod) == Some(WorkspaceCredentialScope::Pod) {
        return Ok(RecordResult::NotReady);
    }
    // §5.3: images.
    if !images_match(&runtime.sandbox, &pod) {
        return Ok(denied(
            environment_id,
            "workspace images differ from the Sandbox template",
        ));
    }
    // §5.4: the workspace PVC, by UID.
    let pvc = match client
        .resolve_workspace_pvc(
            &backend.claim_name,
            &backend.claim_uid,
            backend.workspace_pvc_uid.as_deref(),
        )
        .await
    {
        Ok(pvc) => pvc,
        Err(error) => return Ok(denied(environment_id, &error.to_string())),
    };
    if !pvc_matches(&pod, &pvc) {
        return Ok(denied(
            environment_id,
            "workspace Pod does not mount the resolved PVC",
        ));
    }
    // §5.5: scope and captured bootstrap.
    let Some(scope) = credential_scope(&pod) else {
        return Ok(denied(
            environment_id,
            "workspace credential scope is ambiguous",
        ));
    };
    let captured = match scope {
        WorkspaceCredentialScope::Pod => return Ok(RecordResult::NotReady),
        WorkspaceCredentialScope::Environment => environment_scope_capture(&pod),
    };
    let Some(captured) = captured else {
        return Ok(denied(
            environment_id,
            "workspace bootstrap capture is invalid",
        ));
    };
    let record = BindingRecord {
        environment_id: env.id.clone(),
        organization_id: env.org_id.clone(),
        pod_uid,
        namespace: backend.namespace.clone(),
        pod_name,
        claim_uid: backend.claim_uid.clone(),
        sandbox_uid,
        workspace_pvc_uid: match pvc {
            WorkspacePvc::VolumeLess => None,
            WorkspacePvc::Claim { uid, .. } => Some(uid),
        },
        operation_generation: captured.operation_generation,
        projection_selection_sha256: captured.projection_selection_sha256,
        managed_credential_clients: captured.managed_credential_clients,
        credential_scope: scope,
    };

    let mut guard = authority.begin_external_mutation(&RUNNING).await?;
    let outcome = write_binding(guard.transaction(), &record).await?;
    guard.commit().await?;
    Ok(match outcome {
        WriteOutcome::Recorded => {
            tracing::info!(
                env = %environment_id,
                scope = scope.as_str(),
                "workspace binding recorded (shadow)"
            );
            RecordResult::Recorded
        }
        WriteOutcome::Unchanged => RecordResult::Unchanged,
    })
}

/// First resolution of the workspace PVC UID for an environment that has a
/// Sandbox, running or stopped (design §6, §12).
pub(crate) async fn record_first_workspace_pvc(
    ctx: &WorkerContext,
    environment_id: &str,
) -> RecordResult {
    let attempt =
        tokio::time::timeout(RECORD_ATTEMPT_TIMEOUT, first_pvc(ctx, environment_id)).await;
    let result = match attempt.unwrap_or_else(|_| Err(anyhow::anyhow!("PVC attempt timed out"))) {
        Ok(result) => result,
        Err(error) if is_authority_lost(&error) => RecordResult::NotReady,
        Err(error) => {
            tracing::warn!(env = %environment_id, error = %error, "workspace PVC first resolution failed");
            RecordResult::Unavailable
        }
    };
    observe_pvc_record(result);
    result
}

async fn first_pvc(ctx: &WorkerContext, environment_id: &str) -> anyhow::Result<RecordResult> {
    let Some(kube) = ctx.kube.as_ref() else {
        return Ok(RecordResult::Unavailable);
    };
    let current: Option<(String, i64)> = sqlx::query_as(
        "SELECT state, environment_operation_generation FROM environments
          WHERE id = $1 AND type = 'sandbox' AND deletion_requested_at IS NULL",
    )
    .bind(environment_id)
    .fetch_optional(&ctx.pool)
    .await?;
    let Some((state, generation)) = current else {
        return Ok(RecordResult::NotReady);
    };
    if !matches!(state.as_str(), "running" | "stopped") || generation <= 0 {
        return Ok(RecordResult::NotReady);
    }
    let Some(backend) = load_backend_facts(&ctx.pool, environment_id).await? else {
        return Ok(RecordResult::NotReady);
    };
    if backend.workspace_pvc_uid.is_some() {
        return Ok(RecordResult::Unchanged);
    }
    let authority = ActivityAuthority::capture(&ctx.pool, environment_id, generation).await?;
    let client = SandboxClient::new(kube.clone(), &backend.namespace);
    let pvc = match client
        .resolve_workspace_pvc(&backend.claim_name, &backend.claim_uid, None)
        .await
    {
        Ok(pvc) => pvc,
        Err(error) => return Ok(denied(environment_id, &error.to_string())),
    };
    let WorkspacePvc::Claim { uid, .. } = pvc else {
        return Ok(RecordResult::Unchanged);
    };
    let mut guard = authority.begin_external_mutation(&[state.as_str()]).await?;
    let outcome = write_first_workspace_pvc(
        guard.transaction(),
        environment_id,
        &backend.claim_uid,
        &uid,
    )
    .await?;
    guard.commit().await?;
    Ok(match outcome {
        WriteOutcome::Recorded => RecordResult::Recorded,
        WriteOutcome::Unchanged => RecordResult::Unchanged,
    })
}

// ------------------------------------------------------- enforced (B2)

/// Lifecycle states a binding may be recorded and served in: create
/// (including a retried create, which resumes in `pending` without passing
/// through `creating` again), start, a running environment's replaced Pod,
/// and a resize that replaces the Pod (`resizing`). The listener lookup and
/// the gateway credential RPC use the same set.
pub(crate) const BINDABLE_STATES: [&str; 5] =
    ["pending", "creating", "starting", "running", "resizing"];

/// Why an enforced binding attempt did not record. Every reason is a closed,
/// value-blind category: no Kubernetes status, identifier or token text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum BindRefused {
    /// A §5 check failed for this Pod.
    #[error("workspace binding check failed: {0}")]
    Denied(&'static str),
    /// The Pod is already bound to another environment. Never deleted here.
    #[error("workspace Pod is bound to another environment")]
    BoundElsewhere,
    /// Claim and Pod are not Ready or labels have not converged.
    #[error("workspace runtime identity has not converged")]
    NotConverged,
    /// The observed Pod is gone or was replaced since the observation.
    #[error("workspace Pod changed after the runtime observation")]
    PodChanged,
    /// The Claim → Sandbox → Pod chain could not be read or verified (an API
    /// error, a replaced or terminating object). Never a reason to delete.
    #[error("workspace runtime chain could not be verified")]
    ChainUnverified,
}

/// A refused check: the reason, the Pod's rendered scope when known, and
/// whether the failure is definitive about the Pod itself. Only a definitive
/// failure on an unbound identity-free Pod deletes it; a read or resolution
/// error never does.
type Refusal = (BindRefused, Option<WorkspaceCredentialScope>, bool);

const DENIED_IMAGES: &str = "images";
const DENIED_VOLUME: &str = "workspace volume";
const DENIED_SCOPE: &str = "credential scope";
const DENIED_CAPTURE: &str = "bootstrap capture";
const DENIED_ENVIRONMENT_ID: &str = "environment id is not a canonical UUID";
/// Program #2238 C3: a pool-born Sandbox's first bind found a spec other than
/// this environment's expected rendering.
const DENIED_POOL_RENDERING: &str = "pool rendering";
/// Refusals that are definitive about the observed Sandbox and Pod: they
/// cannot clear by waiting. A read, resolution or write-time refusal is not
/// listed.
const DEFINITIVE_DENIALS: [&str; 5] = [
    DENIED_IMAGES,
    DENIED_VOLUME,
    DENIED_SCOPE,
    DENIED_CAPTURE,
    DENIED_POOL_RENDERING,
];

/// Whether a binding error is a definitive check failure on the observed
/// runtime (C3's cold re-claim acts only on these).
pub(crate) fn definitive_refusal(error: &anyhow::Error) -> bool {
    matches!(
        error.downcast_ref::<BindRefused>(),
        Some(BindRefused::Denied(reason)) if DEFINITIVE_DENIALS.contains(reason)
    )
}

/// Whether any binding, live or released, ever named this Sandbox for this
/// environment. A Sandbox bound once has held tenant data.
pub(crate) async fn sandbox_ever_bound(
    pool: &PgPool,
    environment_id: &str,
    sandbox_uid: &str,
) -> anyhow::Result<bool> {
    Ok(sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM sandbox_workspace_bindings
                         WHERE environment_id = $1 AND sandbox_uid = $2)",
    )
    .bind(environment_id)
    .bind(sandbox_uid)
    .fetch_one(pool)
    .await?)
}

/// Whether any environment's binding, live or released, ever named this
/// Sandbox. A cold re-claim never deletes such a Sandbox, and only a Sandbox
/// nothing ever bound counts as a warm start.
pub(crate) async fn sandbox_bound_by_any(pool: &PgPool, sandbox_uid: &str) -> anyhow::Result<bool> {
    Ok(sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM sandbox_workspace_bindings WHERE sandbox_uid = $1)",
    )
    .bind(sandbox_uid)
    .fetch_one(pool)
    .await?)
}

/// The expected pool of a pool-born environment (Program #2238 C3): the
/// identity-free pool of its exact shape on this replica, whose template
/// carries the pool revision marker. Routing sends an environment to a pool
/// only when its own rendering equals this one's, less the marker.
fn pool_born_rendering(
    cfg: &SandboxWorkerCfg,
    env: &EnvironmentRow,
    namespace: &str,
) -> anyhow::Result<WarmPoolObjects> {
    anyhow::ensure!(
        env.isolation_tier == "standard",
        "only standard environments are pool-born"
    );
    let shape = crate::sandbox::warm_pool::WorkspaceShape {
        cpu_millicores: i64::from(env.cpu_millicores),
        memory_mib: i64::from(env.memory_mb),
        disk_gib: i64::from(env.disk_gb),
    };
    let opts = super::create::warm_pool_template_opts(cfg, shape)?;
    crate::sandbox::warm_pool::render_warm_pool(namespace, &opts, 0, cfg.allow_diagnostic_runtime)
}

/// What one checked attempt would record, before the fenced write.
struct CheckedBinding {
    record: BindingRecord,
    pod: WorkspacePodIdentity,
    /// Warm only for the first bind of an adopted warm-pool member.
    path: StartPath,
}

/// The §5.1–§5.5 checks against live objects, shared by the enforced path.
/// `observation` pins the exact Sandbox and Pod incarnation the caller
/// observed and waited on; anything else is refused, never relabelled.
async fn check_bindable_runtime(
    client: &SandboxClient,
    pool: &PgPool,
    cfg: Option<&SandboxWorkerCfg>,
    env: &EnvironmentRow,
    backend: &BackendFacts,
    observation: &RuntimeIdentityObservation,
) -> anyhow::Result<Result<CheckedBinding, Refusal>> {
    let opts = ClaimOpts {
        environment_id: env.id.clone(),
        org_id: env.org_id.clone(),
        operation_generation: env.operation_generation,
        ..Default::default()
    };
    let refuse = |reason, scope, definitive| Ok(Err((reason, scope, definitive)));
    // §5.1 and §10 (amended): the exact chain, bind-ready. Claim Ready is not
    // required and never suffices.
    let runtime = match client
        .read_bindable_runtime(&opts, &backend.claim_name, &backend.claim_uid)
        .await
    {
        Ok(runtime) => runtime,
        Err(_) => return refuse(BindRefused::ChainUnverified, None, false),
    };
    if runtime.observation != *observation {
        return refuse(BindRefused::PodChanged, None, false);
    }
    if !runtime.bind_ready {
        return refuse(BindRefused::NotConverged, None, false);
    }
    let pod_identity = runtime.observation.pod().clone();
    let sandbox_uid = runtime.observation.sandbox_uid().to_owned();

    // §5.2: re-read the Pod.
    let Some(pod) = client.get_workspace_pod(&pod_identity.name).await? else {
        return refuse(BindRefused::PodChanged, None, false);
    };
    let scope = credential_scope(&pod);
    if !pod_still_observed(&pod, &pod_identity.uid, &sandbox_uid) {
        return refuse(BindRefused::PodChanged, scope, false);
    }
    // §5.3: images.
    if !images_match(&runtime.sandbox, &pod) {
        return refuse(BindRefused::Denied(DENIED_IMAGES), scope, true);
    }
    // Program #2238 C3: the first bind of a pool-born Sandbox (its Claim
    // selects a shared `cw-pool-` pool) requires the Claim to name this
    // environment's own pool, the Sandbox's spec to be exactly that pool's
    // rendering, and the Pod to have booted from that pool revision, read
    // from its immutable spec (review M1), so a stale, foreign or altered
    // member never binds. Without the configuration to render it, refuse
    // without deleting.
    let pool_born = is_warm_pool_name(&runtime.warm_pool_ref);
    if pool_born && !sandbox_ever_bound(pool, &env.id, &sandbox_uid).await? {
        let Some(cfg) = cfg else {
            return refuse(
                BindRefused::Denied("pool rendering unverified"),
                scope,
                false,
            );
        };
        let sandbox = serde_json::to_value(&runtime.sandbox)?;
        let pod_spec = serde_json::to_value(&pod.spec)?;
        let matched = pool_born_rendering(cfg, env, &backend.namespace)
            .map_err(|error| format!("{error:#}"))
            .and_then(|expected| {
                if runtime.warm_pool_ref != expected.name {
                    return Err("/spec/warmPoolRef/name".to_owned());
                }
                sandbox_matches_rendering(&sandbox, &expected.template)?;
                if pod_spec_pool_revision(&pod_spec) != Some(expected.revision.as_str()) {
                    return Err("pod /spec/containers/workspace/env".to_owned());
                }
                Ok(())
            });
        if let Err(path) = matched {
            tracing::warn!(env = %env.id, %path, "pool-born Sandbox differs from the expected rendering");
            return refuse(BindRefused::Denied(DENIED_POOL_RENDERING), scope, true);
        }
    }
    // §5.4: the workspace PVC, by UID. A resolution error may be an API
    // failure, so it refuses without deleting; the Pod mounting another claim
    // than the resolved one is definitive.
    let pvc = match client
        .resolve_workspace_pvc(
            &backend.claim_name,
            &backend.claim_uid,
            backend.workspace_pvc_uid.as_deref(),
        )
        .await
    {
        Ok(pvc) => pvc,
        Err(_) => return refuse(BindRefused::Denied("workspace PVC"), scope, false),
    };
    if !pvc_matches(&pod, &pvc) {
        return refuse(BindRefused::Denied(DENIED_VOLUME), scope, true);
    }
    // §5.5: scope and captured bootstrap.
    let Some(credential) = scope else {
        return refuse(BindRefused::Denied(DENIED_SCOPE), None, true);
    };
    let captured = match credential {
        WorkspaceCredentialScope::Pod => pod_scope_capture(env),
        WorkspaceCredentialScope::Environment => environment_scope_capture(&pod),
    };
    let Some(captured) = captured else {
        return refuse(BindRefused::Denied(DENIED_CAPTURE), scope, true);
    };
    // Review L2: an adopted member's launch-type label outlives its first
    // bind; a restart of the same Sandbox is not a warm start.
    let adopted = StartPath::from_launch_type(
        runtime
            .sandbox
            .metadata
            .labels
            .as_ref()
            .and_then(|labels| labels.get(LAUNCH_TYPE_LABEL))
            .map(String::as_str),
    );
    let path = if pool_born
        && adopted == StartPath::Warm
        && !sandbox_bound_by_any(pool, &sandbox_uid).await?
    {
        StartPath::Warm
    } else {
        StartPath::Cold
    };
    Ok(Ok(CheckedBinding {
        path,
        record: BindingRecord {
            environment_id: env.id.clone(),
            organization_id: env.org_id.clone(),
            pod_uid: pod_identity.uid.clone(),
            namespace: backend.namespace.clone(),
            pod_name: pod_identity.name.clone(),
            claim_uid: backend.claim_uid.clone(),
            sandbox_uid,
            workspace_pvc_uid: match pvc {
                WorkspacePvc::VolumeLess => None,
                WorkspacePvc::Claim { uid, .. } => Some(uid),
            },
            operation_generation: captured.operation_generation,
            projection_selection_sha256: captured.projection_selection_sha256,
            managed_credential_clients: captured.managed_credential_clients,
            credential_scope: credential,
        },
        pod: pod_identity,
    }))
}

/// Whether any binding row, live or released, names this Pod UID.
async fn pod_has_binding(pool: &PgPool, pod_uid: &str) -> anyhow::Result<bool> {
    Ok(sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM sandbox_workspace_bindings WHERE pod_uid = $1)",
    )
    .bind(pod_uid)
    .fetch_one(pool)
    .await?)
}

/// Record the binding of the exact observed Pod (design §5), enforced.
///
/// The caller has observed the runtime identity and waited for the Claim,
/// Sandbox and Pod to be Ready with converged labels; this runs before the
/// gateway readiness wait (§10), so a Pod-scope daemon can listen and the
/// gateway can fetch its credential. A refused check fails the activity.
/// An unbound identity-free Pod that failed a check is deleted with a UID
/// precondition so it never serves (§5.6); a Pod bound to another
/// environment and a legacy environment-scope Pod are never deleted here.
///
/// Returns the write outcome and the start path of the bound Sandbox (warm
/// for an adopted pool member). `cfg` renders a pool-born Sandbox's expected
/// spec for its first bind; without it such a bind is refused.
pub(crate) async fn record_workspace_binding(
    kube: &kube::Client,
    cfg: Option<&SandboxWorkerCfg>,
    env: &EnvironmentRow,
    backend: &BackendRow,
    authority: &ActivityAuthority,
    states: &[&str],
    observation: &RuntimeIdentityObservation,
) -> anyhow::Result<(WriteOutcome, StartPath)> {
    anyhow::ensure!(
        env.id == authority.environment_id()
            && env.operation_generation == authority.operation_generation()
            && env.operation_generation > 0
            && states.iter().all(|state| BINDABLE_STATES.contains(state)),
        "workspace binding authority does not match the environment"
    );
    // The daemon accepts only a canonical environment UUID from its bind
    // response; any other binding would be answered forever and never used.
    if !crate::workspace_binding::canonical_uid(&env.id) {
        return Err(BindRefused::Denied(DENIED_ENVIRONMENT_ID).into());
    }
    let pool = authority.pool();
    let facts = load_backend_facts(pool, &env.id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("workspace binding backend is incomplete"))?;
    anyhow::ensure!(
        facts.namespace == backend.namespace
            && facts.claim_name == backend.claim_name
            && facts.claim_uid == backend.claim_uid,
        "workspace binding backend association changed"
    );
    let client = SandboxClient::new(kube.clone(), &facts.namespace);
    let checked = match check_bindable_runtime(&client, pool, cfg, env, &facts, observation).await?
    {
        Ok(checked) => checked,
        Err((reason, scope, definitive)) => {
            if definitive
                && scope != Some(WorkspaceCredentialScope::Environment)
                && !pod_has_binding(pool, &observation.pod().uid).await?
            {
                // §5.6: an unbound identity-free Pod that failed a check never
                // serves. The UID precondition never deletes a replacement.
                let pod = observation.pod();
                // Its replacement starts on the current daemon. A failed
                // re-pin never keeps the failed Pod serving.
                if let Some(cfg) = cfg
                    && let Err(error) = authority
                        .run_external_mutation(
                            states,
                            client.repin_daemon_image(&env.id, cfg.support_image()),
                        )
                        .await
                {
                    tracing::warn!(env = %env.id, %error, "could not re-pin the daemon image of an unbound workspace Pod's Sandbox");
                }
                authority
                    .run_external_mutation(
                        states,
                        client.delete_workspace_pod_if_uid(&pod.name, &pod.uid),
                    )
                    .await?;
                tracing::warn!(env = %env.id, %reason, "deleted an unbound workspace Pod that failed binding");
            }
            return Err(reason.into());
        }
    };
    let mut guard = authority.begin_external_mutation(states).await?;
    let outcome = await_external_mutation(async {
        // A Pod-scope capture must still equal the environment row this
        // fenced transaction locked: the selection can be republished within
        // one operation generation.
        if checked.record.credential_scope == WorkspaceCredentialScope::Pod {
            let current = load_environment_in(guard.transaction(), &env.id).await?;
            let recaptured = pod_scope_capture(&current);
            anyhow::ensure!(
                recaptured.as_ref().is_some_and(|recaptured| {
                    recaptured.operation_generation == checked.record.operation_generation
                        && recaptured.projection_selection_sha256
                            == checked.record.projection_selection_sha256
                        && recaptured.managed_credential_clients
                            == checked.record.managed_credential_clients
                }),
                super::activity_authority::AuthorityLost
            );
        }
        match write_binding(guard.transaction(), &checked.record).await {
            Ok(outcome) => Ok(outcome),
            Err(error) => Err(match error.downcast_ref::<WriteRefused>() {
                Some(WriteRefused::BoundElsewhere) => BindRefused::BoundElsewhere.into(),
                Some(WriteRefused::Released) => BindRefused::Denied("released binding").into(),
                Some(WriteRefused::BackendChanged) => {
                    BindRefused::Denied("backend association").into()
                }
                Some(WriteRefused::PvcMismatch) => BindRefused::Denied("workspace PVC").into(),
                None => error,
            }),
        }
    })
    .await?;
    guard.commit().await?;
    debug_assert_eq!(checked.pod, *observation.pod());
    Ok((outcome, checked.path))
}

/// A binding this call recorded: how long it took, whether the Sandbox is an
/// adopted warm-pool member, and the Sandbox UID it recorded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RecordedBind {
    pub elapsed: Duration,
    pub path: StartPath,
    pub sandbox_uid: String,
}

/// [`record_workspace_binding`] with its environment log row
/// (`workspace_bind`, with `duration_ms`, which A0a's stage metric reads)
/// and its closed-category counter. A repeat for an already-bound Pod is
/// silent. Returns the elapsed time and start path of a newly recorded
/// binding.
pub(crate) async fn bind_workspace_runtime(
    kube: &kube::Client,
    cfg: Option<&SandboxWorkerCfg>,
    env: &EnvironmentRow,
    backend: &BackendRow,
    authority: &ActivityAuthority,
    states: &[&str],
    observation: &RuntimeIdentityObservation,
) -> anyhow::Result<Option<RecordedBind>> {
    let started = Instant::now();
    let result =
        record_workspace_binding(kube, cfg, env, backend, authority, states, observation).await;
    let elapsed = started.elapsed();
    let metadata = Some(serde_json::json!({
        "duration_ms": i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX),
    }));
    match result {
        Ok((WriteOutcome::Recorded, path)) => {
            observe_record(RecordResult::Recorded);
            emit_authoritative_environment_log_for_states(
                authority,
                states,
                "workspace_bind",
                "completed",
                "",
                metadata,
            )
            .await?;
            // The recorder refuses anything but the observed chain, so the
            // recorded Sandbox is the observed one.
            Ok(Some(RecordedBind {
                elapsed,
                path,
                sandbox_uid: observation.sandbox_uid().to_owned(),
            }))
        }
        Ok((WriteOutcome::Unchanged, _)) => {
            observe_record(RecordResult::Unchanged);
            Ok(None)
        }
        Err(error) if is_authority_lost(&error) => {
            observe_record(RecordResult::NotReady);
            Err(error)
        }
        Err(error) => {
            let (result, message) = match error.downcast_ref::<BindRefused>() {
                Some(BindRefused::BoundElsewhere) => {
                    tracing::error!(env = %env.id, "workspace Pod is bound to another environment");
                    (RecordResult::Conflict, error.to_string())
                }
                Some(
                    BindRefused::NotConverged
                    | BindRefused::PodChanged
                    | BindRefused::ChainUnverified,
                ) => (RecordResult::NotReady, error.to_string()),
                Some(BindRefused::Denied(_)) => (RecordResult::Denied, error.to_string()),
                None => (
                    RecordResult::Unavailable,
                    "workspace binding is unavailable".to_owned(),
                ),
            };
            observe_record(result);
            emit_authoritative_environment_log_for_states(
                authority,
                states,
                "workspace_bind",
                "failed",
                &message,
                metadata,
            )
            .await?;
            Err(error)
        }
    }
}

/// How often [`bind_before_ready`] re-reads the chain while the caller waits.
const EARLY_BIND_POLL: Duration = Duration::from_millis(500);

/// Design §10 (amended): while the caller waits for the gateway or for Claim
/// Ready, record an identity-free Pod's binding as soon as the exact chain is
/// bind-ready ([`BindableRuntime::bind_ready`]), so its daemon listens and the
/// gateway connects while DinD's Docker daemon is still starting. It records
/// through the enforced [`bind_workspace_runtime`], with every §5 check and
/// the locked re-check of the captured values.
///
/// Returns the record time and start path when this call recorded the
/// binding, or `None` when the Pod was already bound or is a legacy Pod,
/// which keeps the post-ready order unchanged. A refusal that can clear (labels not yet
/// converged, a replaced Pod, an unreadable chain) is retried; any other
/// refusal fails exactly as the post-ready bind does. The caller drops this
/// future once its own wait ends.
pub(crate) async fn bind_before_ready(
    kube: &kube::Client,
    cfg: Option<&SandboxWorkerCfg>,
    authority: &ActivityAuthority,
    states: &[&str],
) -> anyhow::Result<Option<RecordedBind>> {
    let pool = authority.pool();
    loop {
        let env = load_environment(pool, authority.environment_id()).await?;
        let backend = super::env_data::load_backend_row(pool, authority.environment_id())
            .await
            .ok()
            .filter(|backend| !backend.namespace.is_empty() && !backend.claim_uid.is_empty());
        if let Some(backend) = backend {
            let client = SandboxClient::new(kube.clone(), &backend.namespace);
            let opts = ClaimOpts {
                environment_id: env.id.clone(),
                org_id: env.org_id.clone(),
                operation_generation: authority.operation_generation(),
                ..Default::default()
            };
            if let Ok(runtime) = client
                .read_bindable_runtime(&opts, &backend.claim_name, &backend.claim_uid)
                .await
                && runtime.bind_ready
            {
                if credential_scope(&runtime.pod) != Some(WorkspaceCredentialScope::Pod) {
                    return Ok(None);
                }
                match bind_workspace_runtime(
                    kube,
                    cfg,
                    &env,
                    &backend,
                    authority,
                    states,
                    &runtime.observation,
                )
                .await
                {
                    Ok(elapsed) => return Ok(elapsed),
                    Err(error)
                        if matches!(
                            error.downcast_ref::<BindRefused>(),
                            Some(
                                BindRefused::NotConverged
                                    | BindRefused::PodChanged
                                    | BindRefused::ChainUnverified
                            )
                        ) => {}
                    Err(error) => return Err(error),
                }
            }
        }
        tokio::time::sleep(EARLY_BIND_POLL).await;
    }
}

/// Bind a workspace Pod that replaced the previous one while the environment
/// stays `running` (daemon repair, design §10): observe the exact chain for
/// the replacement, wait for it to converge, then record its binding before
/// any daemon or gateway wait. A legacy replacement records its environment
/// scope; an identity-free one gets the binding its daemon long-polls for.
pub(crate) async fn bind_replacement_runtime(
    kube: &kube::Client,
    authority: &ActivityAuthority,
    states: &[&str],
    replacement: &WorkspacePodIdentity,
    timeout: Duration,
) -> anyhow::Result<()> {
    let pool = authority.pool();
    let env = load_environment(pool, authority.environment_id()).await?;
    let backend = super::env_data::load_backend_row(pool, authority.environment_id()).await?;
    anyhow::ensure!(
        !backend.namespace.is_empty() && !backend.claim_uid.is_empty(),
        "workspace binding backend is incomplete"
    );
    let client = SandboxClient::new(kube.clone(), &backend.namespace);
    let opts = ClaimOpts {
        environment_id: env.id.clone(),
        org_id: env.org_id.clone(),
        operation_generation: authority.operation_generation(),
        ..Default::default()
    };
    let observation = client
        .observe_claim_runtime_identity(&opts, &backend.claim_name, &backend.claim_uid)
        .await?;
    if observation.pod() != replacement {
        return Err(BindRefused::PodChanged.into());
    }
    authority
        .run_while_authoritative_for_states(
            states,
            client.wait_for_claim_runtime_identity(
                &opts,
                &backend.claim_name,
                &backend.claim_uid,
                &observation,
                timeout,
            ),
        )
        .await?;
    // A replacement Pod belongs to a Sandbox this environment already bound,
    // so no pool rendering is needed; a first bind without one is refused.
    bind_workspace_runtime(kube, None, &env, &backend, authority, states, &observation).await?;
    Ok(())
}

/// The live binding's Pod is still present, so it is not released.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("the bound workspace Pod is still present")]
pub(crate) struct BoundPodPresent;

/// Whether the Pod a binding recorded is absent: its name no longer exists,
/// or now names a Pod with another UID. A terminating Pod is still present.
/// Pod UIDs are never reused, so an observed absence is final.
pub(crate) async fn bound_pod_absent(
    kube: &kube::Client,
    namespace: &str,
    pod_name: &str,
    pod_uid: &str,
) -> anyhow::Result<bool> {
    let pod = SandboxClient::new(kube.clone(), namespace)
        .get_workspace_pod(pod_name)
        .await?;
    Ok(pod.is_none_or(|pod| pod.metadata.uid.as_deref() != Some(pod_uid)))
}

/// Release exactly `pod_uid`'s live binding and clear a backend pointer to
/// it, inside a transaction that already holds the environment row lock.
async fn release_absent_binding(
    tx: &mut PgConnection,
    environment_id: &str,
    pod_uid: &str,
) -> anyhow::Result<bool> {
    let released = sqlx::query(
        "UPDATE sandbox_workspace_bindings SET released_at = GREATEST(now(), bound_at)
          WHERE environment_id = $1 AND pod_uid = $2 AND released_at IS NULL",
    )
    .bind(environment_id)
    .bind(pod_uid)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    sqlx::query(
        "UPDATE sandbox_environment_backend SET pod_uid = NULL, bound_at = NULL
          WHERE environment_id = $1 AND pod_uid = $2",
    )
    .bind(environment_id)
    .bind(pod_uid)
    .execute(&mut *tx)
    .await?;
    Ok(released > 0)
}

/// Release the environment's live binding once its Pod is observed absent
/// (design §10: stop, restart before resume, destroy), and clear the backend
/// pointer, inside the caller's generation fence. A present Pod refuses with
/// [`BoundPodPresent`] and changes nothing, so the caller retries after its
/// deletion. Idempotent: no live binding releases nothing.
pub(crate) async fn release_workspace_binding(
    kube: &kube::Client,
    authority: &ActivityAuthority,
    states: &[&str],
) -> anyhow::Result<bool> {
    let live: Option<(String, String, String)> = sqlx::query_as(
        "SELECT pod_uid, namespace, pod_name FROM sandbox_workspace_bindings
          WHERE environment_id = $1 AND released_at IS NULL",
    )
    .bind(authority.environment_id())
    .fetch_optional(authority.pool())
    .await?;
    let Some((pod_uid, namespace, pod_name)) = live else {
        return Ok(false);
    };
    if !bound_pod_absent(kube, &namespace, &pod_name, &pod_uid).await? {
        return Err(BoundPodPresent.into());
    }
    let mut guard = authority.begin_external_mutation(states).await?;
    let released =
        release_absent_binding(guard.transaction(), authority.environment_id(), &pod_uid).await?;
    guard.commit().await?;
    Ok(released)
}

/// The backfill's release of one live binding whose Pod is observed absent
/// (design §10's rule). It needs no generation: the absence of a Pod UID is
/// final, and it changes only that UID's row and a pointer to it, under the
/// environment row lock every binding writer takes first. A present Pod, or a
/// binding already released, is `Unchanged`.
pub(crate) async fn release_binding_if_pod_absent(
    pool: &PgPool,
    kube: &kube::Client,
    pod_uid: &str,
) -> anyhow::Result<RecordResult> {
    let live: Option<(String, String, String)> = sqlx::query_as(
        "SELECT environment_id, namespace, pod_name FROM sandbox_workspace_bindings
          WHERE pod_uid = $1 AND released_at IS NULL",
    )
    .bind(pod_uid)
    .fetch_optional(pool)
    .await?;
    let Some((environment_id, namespace, pod_name)) = live else {
        return Ok(RecordResult::Unchanged);
    };
    if !bound_pod_absent(kube, &namespace, &pod_name, pod_uid).await? {
        return Ok(RecordResult::Unchanged);
    }
    let mut tx = pool.begin().await?;
    sqlx::query("SET LOCAL lock_timeout = '5s'")
        .execute(&mut *tx)
        .await?;
    sqlx::query("SELECT 1 FROM environments WHERE id = $1 FOR NO KEY UPDATE")
        .bind(&environment_id)
        .fetch_optional(&mut *tx)
        .await?;
    let released = release_absent_binding(&mut tx, &environment_id, pod_uid).await?;
    tx.commit().await?;
    if !released {
        return Ok(RecordResult::Unchanged);
    }
    tracing::info!(
        env = %environment_id,
        pod_uid,
        "workspace binding released after its Pod was observed absent"
    );
    Ok(RecordResult::Recorded)
}

/// Why a restore adoption was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AdoptionRefused {
    #[error("restored workspace PVC UID is not canonical")]
    InvalidUid,
    #[error("a restore adoption needs a stopped workspace with no live binding")]
    Bound,
    #[error("the restored workspace PVC does not resolve for this environment")]
    NotResolvable,
    #[error("workspace binding backend association changed")]
    BackendChanged,
}

/// namespace, claim UID, binding pointer, recorded workspace PVC UID.
type AdoptionBackendRow = (String, Option<String>, Option<String>, Option<String>);

/// Restore-born PVC adoption (design §12): the single documented path that
/// moves `backend.workspace_pvc_uid` to a different PVC. The restore creates
/// a same-name PVC with the fork's tracking label and a `dataSource` of a
/// same-environment `VolumeSnapshot`; this records its UID, taken from the
/// create response, before resume. It is generation-fenced, requires no
/// live binding, and logs the old and new UIDs. The resolver then accepts
/// that PVC by UID through the adoption window until the fork adopts it; a
/// same-name PVC that no adoption recorded fails both resolve and bind.
pub async fn adopt_restored_workspace_pvc(
    kube: &kube::Client,
    authority: &ActivityAuthority,
    states: &[&str],
    backend: &BackendRow,
    restored_pvc_uid: &str,
) -> anyhow::Result<()> {
    if !crate::workspace_binding::canonical_uid(restored_pvc_uid) {
        return Err(AdoptionRefused::InvalidUid.into());
    }
    let client = SandboxClient::new(kube.clone(), &backend.namespace);
    // The restored PVC must already resolve under the adoption window.
    match client
        .resolve_workspace_pvc(
            &backend.claim_name,
            &backend.claim_uid,
            Some(restored_pvc_uid),
        )
        .await
    {
        Ok(WorkspacePvc::Claim { .. }) => {}
        _ => return Err(AdoptionRefused::NotResolvable.into()),
    }
    let mut guard = authority.begin_external_mutation(states).await?;
    let row: Option<AdoptionBackendRow> = sqlx::query_as(
        "SELECT namespace, sandbox_claim_uid, pod_uid, workspace_pvc_uid
           FROM sandbox_environment_backend WHERE environment_id = $1 FOR UPDATE",
    )
    .bind(authority.environment_id())
    .fetch_optional(&mut **guard.transaction())
    .await?;
    let Some((namespace, claim_uid, pointer, previous)) = row else {
        return Err(AdoptionRefused::BackendChanged.into());
    };
    if namespace != backend.namespace || claim_uid.as_deref() != Some(backend.claim_uid.as_str()) {
        return Err(AdoptionRefused::BackendChanged.into());
    }
    let live: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM sandbox_workspace_bindings
                         WHERE environment_id = $1 AND released_at IS NULL)",
    )
    .bind(authority.environment_id())
    .fetch_one(&mut **guard.transaction())
    .await?;
    if pointer.is_some() || live {
        return Err(AdoptionRefused::Bound.into());
    }
    sqlx::query(
        "UPDATE sandbox_environment_backend SET workspace_pvc_uid = $2 WHERE environment_id = $1",
    )
    .bind(authority.environment_id())
    .bind(restored_pvc_uid)
    .execute(&mut **guard.transaction())
    .await?;
    guard.commit().await?;
    tracing::info!(
        env = %authority.environment_id(),
        previous_pvc_uid = previous.as_deref().unwrap_or(""),
        restored_pvc_uid,
        "adopted the restored workspace PVC"
    );
    Ok(())
}

// --------------------------------------------------------------- readers

/// The live binding of an environment's current backend pointer.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct EnvironmentBinding {
    pub pod_uid: String,
    pub operation_generation: i64,
    pub projection_selection_sha256: Option<String>,
    pub managed_credential_clients: String,
    pub credential_scope: WorkspaceCredentialScope,
}

impl std::fmt::Debug for EnvironmentBinding {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EnvironmentBinding")
            .field("pod_uid", &self.pod_uid)
            .field("credential_scope", &self.credential_scope)
            .finish_non_exhaustive()
    }
}

type EnvironmentBindingRow = (String, i64, Option<String>, String, String);

const LIVE_ENVIRONMENT_BINDING: &str = "SELECT w.pod_uid, w.operation_generation,
              w.projection_selection_sha256, w.managed_credential_clients, w.credential_scope
         FROM sandbox_environment_backend b
         JOIN sandbox_workspace_bindings w
           ON w.environment_id = b.environment_id AND w.pod_uid = b.pod_uid
        WHERE b.environment_id = $1 AND b.bound_at IS NOT NULL AND w.released_at IS NULL";

fn environment_binding_from_row(
    (pod_uid, operation_generation, digest, clients, scope): EnvironmentBindingRow,
) -> anyhow::Result<EnvironmentBinding> {
    Ok(EnvironmentBinding {
        pod_uid,
        operation_generation,
        projection_selection_sha256: digest,
        managed_credential_clients: clients,
        credential_scope: WorkspaceCredentialScope::parse(&scope)
            .ok_or_else(|| anyhow::anyhow!("workspace binding scope is invalid"))?,
    })
}

/// The live binding the backend pointer names, if any.
pub(crate) async fn live_environment_binding(
    executor: impl sqlx::PgExecutor<'_>,
    environment_id: &str,
) -> anyhow::Result<Option<EnvironmentBinding>> {
    sqlx::query_as::<_, EnvironmentBindingRow>(LIVE_ENVIRONMENT_BINDING)
        .bind(environment_id)
        .fetch_optional(executor)
        .await?
        .map(environment_binding_from_row)
        .transpose()
}

/// The namespace and Sandbox UID of the live binding the backend pointer
/// names, if any (#2434). Read inside the caller's fence, it proves a
/// binding committed and is still current.
pub(crate) async fn live_binding_sandbox(
    executor: impl sqlx::PgExecutor<'_>,
    environment_id: &str,
) -> anyhow::Result<Option<(String, String)>> {
    Ok(sqlx::query_as(
        "SELECT w.namespace, w.sandbox_uid
           FROM sandbox_environment_backend b
           JOIN sandbox_workspace_bindings w
             ON w.environment_id = b.environment_id AND w.pod_uid = b.pod_uid
          WHERE b.environment_id = $1 AND b.bound_at IS NOT NULL AND w.released_at IS NULL",
    )
    .bind(environment_id)
    .fetch_optional(executor)
    .await?)
}

/// The current workspace Pod is not bound yet and is not a legacy Pod, so
/// no daemon credential is issued for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("the workspace daemon is not bound yet")]
pub(crate) struct DaemonNotBound;

/// The credential orchestration presents to the environment's daemon
/// (design §7). A live binding decides it. Without one, only a legacy Pod,
/// which renders the environment token itself, receives that token: an
/// identity-free Pod that is not bound yet, or a Pod whose scope cannot be
/// read, gets nothing, so the environment token never reaches a Pod that was
/// not rendered with it.
pub(crate) async fn environment_daemon_credential(
    pool: &PgPool,
    kube: Option<&kube::Client>,
    session_secret: &str,
    environment_id: &str,
) -> anyhow::Result<String> {
    if let Some(binding) = live_environment_binding(pool, environment_id).await? {
        return daemon_credential_for(
            session_secret,
            environment_id,
            &binding.pod_uid,
            binding.credential_scope,
        );
    }
    let namespace: Option<String> = sqlx::query_scalar(
        "SELECT namespace FROM sandbox_environment_backend WHERE environment_id = $1",
    )
    .bind(environment_id)
    .fetch_optional(pool)
    .await?;
    let (Some(namespace), Some(kube)) = (namespace.filter(|namespace| !namespace.is_empty()), kube)
    else {
        return Err(DaemonNotBound.into());
    };
    let pod = SandboxClient::new(kube.clone(), &namespace)
        .current_workspace_pod_object(environment_id)
        .await
        .map_err(|_| DaemonNotBound)?;
    if credential_scope(&pod) != Some(WorkspaceCredentialScope::Environment) {
        return Err(DaemonNotBound.into());
    }
    super::environment_auth::issue_token(
        session_secret,
        environment_id,
        super::environment_auth::SCOPE_DAEMON,
    )
}

/// Stale-bootstrap comparison for a bound Pod-scope runtime (design §12): the
/// binding row's captured generation, projection digest and managed clients
/// against the current template options, with the same rule as the rendered
/// environment check: the generation only matters while a projection is
/// selected.
pub(crate) fn binding_bootstrap_current(
    binding: &EnvironmentBinding,
    opts: &crate::sandbox::template::TemplateOpts,
) -> bool {
    let digest = opts.projection_selection_sha256.map(|digest| {
        digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    });
    binding.projection_selection_sha256 == digest
        && binding.managed_credential_clients == opts.managed_credential_clients.encode()
        && (digest.is_none() || binding.operation_generation == opts.operation_generation)
}

// ------------------------------------------------------------- backfill

/// Pause between backfill passes. The backfill runs as its own leader task,
/// never inside the reconciler's cadence.
pub(crate) const BACKFILL_INTERVAL: Duration = Duration::from_secs(30);
/// One pass starts no new attempt after this budget.
const BACKFILL_PASS_BUDGET: Duration = Duration::from_secs(20);
/// Upper bound on one attempt: its Kubernetes reads and its fenced write.
/// Dropping the attempt rolls its transaction back.
const RECORD_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(10);
/// A failing environment waits this long, doubling per failure up to the cap,
/// so persistent failures cannot crowd out everything else.
const BACKOFF_BASE: Duration = Duration::from_secs(30);
const BACKOFF_MAX: Duration = Duration::from_secs(30 * 60);
const MAX_BACKOFF_ENTRIES: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Backoff {
    failures: u32,
    retry_at: Instant,
}

fn backoff_delay(failures: u32) -> Duration {
    let doublings = failures.saturating_sub(1).min(16);
    BACKOFF_BASE
        .saturating_mul(1_u32 << doublings)
        .min(BACKOFF_MAX)
}

/// Per-environment failure backoff for one kind of attempt.
#[derive(Default)]
struct Backoffs(HashMap<String, Backoff>);

impl Backoffs {
    fn ready(&self, environment_id: &str, now: Instant) -> bool {
        self.0
            .get(environment_id)
            .is_none_or(|backoff| now >= backoff.retry_at)
    }

    fn observe(&mut self, environment_id: &str, result: RecordResult, now: Instant) {
        if matches!(result, RecordResult::Recorded | RecordResult::Unchanged) {
            self.0.remove(environment_id);
            return;
        }
        if !self.0.contains_key(environment_id) && self.0.len() >= MAX_BACKOFF_ENTRIES {
            self.0.retain(|_, backoff| backoff.retry_at > now);
            if self.0.len() >= MAX_BACKOFF_ENTRIES {
                // Untracked, it is simply retried on its next turn.
                return;
            }
        }
        let failures = self
            .0
            .get(environment_id)
            .map_or(1, |backoff| backoff.failures.saturating_add(1));
        self.0.insert(
            environment_id.to_owned(),
            Backoff {
                failures,
                retry_at: now + backoff_delay(failures),
            },
        );
    }
}

/// Rotation cursors and backoff of the bounded backfill, kept by its task.
#[derive(Default)]
pub(crate) struct BackfillState {
    unbound: Option<String>,
    bound: Option<String>,
    pvcs: Option<String>,
    releases: Option<String>,
    binding_backoff: Backoffs,
    pvc_backoff: Backoffs,
    release_backoff: Backoffs,
}

/// Running environments without a binding, then a rotation over the bound
/// ones so a Pod replaced since its binding is recorded too. Each query has
/// its own cursor, so no fixed set of failing environments is retried ahead
/// of everything else.
const UNBOUND_RUNNING: &str = "SELECT e.id FROM environments e
      JOIN sandbox_environment_backend b ON b.environment_id = e.id
     WHERE e.type = 'sandbox' AND e.state = 'running' AND e.desired_state = 'started'
       AND e.deletion_requested_at IS NULL AND b.sandbox_claim_uid IS NOT NULL
       AND b.pod_uid IS NULL AND e.id > $1
     ORDER BY e.id LIMIT $2";
const BOUND_RUNNING: &str = "SELECT e.id FROM environments e
      JOIN sandbox_environment_backend b ON b.environment_id = e.id
     WHERE e.type = 'sandbox' AND e.state = 'running' AND e.desired_state = 'started'
       AND e.deletion_requested_at IS NULL AND b.sandbox_claim_uid IS NOT NULL
       AND b.pod_uid IS NOT NULL AND e.id > $1
     ORDER BY e.id LIMIT $2";
const UNRESOLVED_PVC: &str = "SELECT e.id FROM environments e
      JOIN sandbox_environment_backend b ON b.environment_id = e.id
     WHERE e.type = 'sandbox' AND e.state IN ('running', 'stopped') AND e.disk_gb > 0
       AND e.deletion_requested_at IS NULL AND b.sandbox_claim_uid IS NOT NULL
       AND b.workspace_pvc_uid IS NULL AND e.id > $1
     ORDER BY e.id LIMIT $2";

/// Live bindings of environments that are not stably running, by Pod UID:
/// destroyed, stopped, failed or still changing. Each is released once its
/// Pod is observed absent, which also reaches bindings an earlier binary left
/// live. A running environment's replaced Pod is not swept here: the rebind
/// its liveness trigger enqueues releases it atomically with the new binding.
const UNRELEASED_INACTIVE: &str = "SELECT w.pod_uid FROM sandbox_workspace_bindings w
      JOIN environments e ON e.id = w.environment_id
     WHERE w.released_at IS NULL
       AND NOT (e.state = 'running' AND e.desired_state = 'started'
                AND e.deletion_requested_at IS NULL)
       AND w.pod_uid > $1
     ORDER BY w.pod_uid LIMIT $2";

async fn next_batch(
    pool: &PgPool,
    query: &str,
    after: Option<&str>,
    limit: i64,
) -> anyhow::Result<Vec<String>> {
    let rows: Vec<(String,)> = sqlx::query_as(query)
        .bind(after.unwrap_or_default())
        .bind(limit)
        .fetch_all(pool)
        .await?;
    Ok(rows.into_iter().map(|(id,)| id).collect())
}

/// Up to `limit` ids after the cursor, wrapping once to the start. The caller
/// moves the cursor past each id it takes its turn on.
async fn rotate(
    pool: &PgPool,
    query: &str,
    cursor: &mut Option<String>,
    limit: i64,
) -> anyhow::Result<Vec<String>> {
    if limit <= 0 {
        return Ok(Vec::new());
    }
    let ids = next_batch(pool, query, cursor.as_deref(), limit).await?;
    if ids.is_empty() && cursor.is_some() {
        *cursor = None;
        return next_batch(pool, query, None, limit).await;
    }
    Ok(ids)
}

/// One bounded backfill pass.
pub(crate) async fn backfill_pass(ctx: &WorkerContext, state: &mut BackfillState) {
    if ctx.kube.is_none() {
        return;
    }
    let deadline = Instant::now() + BACKFILL_PASS_BUDGET;
    let result: anyhow::Result<()> = async {
        let unbound = rotate(
            &ctx.pool,
            UNBOUND_RUNNING,
            &mut state.unbound,
            BACKFILL_BATCH,
        )
        .await?;
        let bound = rotate(
            &ctx.pool,
            BOUND_RUNNING,
            &mut state.bound,
            BACKFILL_BATCH - unbound.len() as i64,
        )
        .await?;
        for (id, bound_turn) in unbound
            .into_iter()
            .map(|id| (id, false))
            .chain(bound.into_iter().map(|id| (id, true)))
        {
            if Instant::now() >= deadline {
                return Ok(());
            }
            // The cursor moves past every environment that had its turn,
            // including one still backing off.
            if bound_turn {
                state.bound = Some(id.clone());
            } else {
                state.unbound = Some(id.clone());
            }
            if state.binding_backoff.ready(&id, Instant::now()) {
                let result = record_workspace_binding_shadow(ctx, &id).await;
                state.binding_backoff.observe(&id, result, Instant::now());
            }
        }
        for id in rotate(&ctx.pool, UNRESOLVED_PVC, &mut state.pvcs, BACKFILL_BATCH).await? {
            if Instant::now() >= deadline {
                return Ok(());
            }
            state.pvcs = Some(id.clone());
            if state.pvc_backoff.ready(&id, Instant::now()) {
                let result = record_first_workspace_pvc(ctx, &id).await;
                state.pvc_backoff.observe(&id, result, Instant::now());
            }
        }
        if let Some(kube) = ctx.kube.as_ref() {
            for pod_uid in rotate(
                &ctx.pool,
                UNRELEASED_INACTIVE,
                &mut state.releases,
                BACKFILL_BATCH,
            )
            .await?
            {
                if Instant::now() >= deadline {
                    return Ok(());
                }
                state.releases = Some(pod_uid.clone());
                if state.release_backoff.ready(&pod_uid, Instant::now()) {
                    let result = tokio::time::timeout(
                        RECORD_ATTEMPT_TIMEOUT,
                        release_binding_if_pod_absent(&ctx.pool, kube, &pod_uid),
                    )
                    .await
                    .unwrap_or_else(|_| Err(anyhow::anyhow!("binding release timed out")))
                    .unwrap_or_else(|error| {
                        tracing::warn!(pod_uid, error = %error, "workspace binding release failed");
                        RecordResult::Unavailable
                    });
                    state
                        .release_backoff
                        .observe(&pod_uid, result, Instant::now());
                }
            }
        }
        Ok(())
    }
    .await;
    if let Err(error) = result {
        tracing::warn!(error = %error, "workspace binding backfill pass failed");
    }
}

/// The leader-gated backfill task. It keeps its own cursors and backoff for as
/// long as this replica leads, and starts fresh after a leadership change.
pub(crate) async fn workspace_binding_backfill_loop(
    ctx: std::sync::Arc<WorkerContext>,
    is_leader: std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    let mut state = BackfillState::default();
    let mut ticker = tokio::time::interval(BACKFILL_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker.tick().await;
    loop {
        ticker.tick().await;
        if is_leader.load(std::sync::atomic::Ordering::SeqCst) {
            backfill_pass(&ctx, &mut state).await;
        } else {
            state = BackfillState::default();
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod database_tests;

// ------------------------------------------------ cw runtime capture reader

/// A read-only capture of the current backend pointer and its complete
/// immutable binding. Keep the mutable environment/backend gate values too:
/// a later admission must compare the original row, not resolve a new Pod.
/// This reader does not issue a credential or alter the B2 binding writer.
#[derive(Clone, PartialEq, Eq, sqlx::FromRow)]
pub(crate) struct CwRuntimeLiveBinding {
    pub organization_id: String,
    pub organization_deletion_state: String,
    pub organization_deletion_generation: i64,
    pub environment_id: String,
    pub environment_state: String,
    pub desired_state: String,
    pub environment_type: String,
    pub isolation_tier: String,
    pub environment_generation: i64,
    pub deletion_requested_at: Option<chrono::NaiveDateTime>,
    pub backend_namespace: String,
    pub backend_pod_name: String,
    pub backend_pod_ip: String,
    pub backend_pod_uid: String,
    pub backend_claim_uid: Option<String>,
    pub backend_pvc_uid: Option<String>,
    pub backend_bound_at: chrono::DateTime<chrono::Utc>,
    pub setup_complete: bool,
    pub setup_owner_status: Option<String>,
    pub pod_uid: String,
    pub namespace: String,
    pub pod_name: String,
    pub claim_uid: String,
    pub sandbox_uid: String,
    pub workspace_pvc_uid: Option<String>,
    pub binding_generation: i64,
    pub projection_selection_sha256: Option<String>,
    pub managed_credential_clients: String,
    pub credential_scope: String,
    pub binding_bound_at: chrono::DateTime<chrono::Utc>,
}

const LIVE_CW_RUNTIME_BINDING: &str = "SELECT
        e.org_id AS organization_id, e.id AS environment_id,
        o.deletion_state AS organization_deletion_state,
        o.deletion_generation AS organization_deletion_generation,
        e.state AS environment_state, e.desired_state,
        e.type AS environment_type, e.isolation_tier,
        e.environment_operation_generation AS environment_generation,
        e.deletion_requested_at,
        b.namespace AS backend_namespace,
        COALESCE(b.pod_name, '') AS backend_pod_name,
        COALESCE(b.pod_ip, '') AS backend_pod_ip,
        b.pod_uid AS backend_pod_uid,
        b.sandbox_claim_uid AS backend_claim_uid,
        b.workspace_pvc_uid AS backend_pvc_uid,
        b.bound_at AS backend_bound_at,
        COALESCE(b.setup_complete, false) AS setup_complete, b.setup_owner_status,
        w.pod_uid, w.namespace, w.pod_name, w.claim_uid, w.sandbox_uid,
        w.workspace_pvc_uid, w.operation_generation AS binding_generation,
        w.projection_selection_sha256, w.managed_credential_clients,
        w.credential_scope, w.bound_at AS binding_bound_at
    FROM environments e
    JOIN organizations o ON o.id = e.org_id
    JOIN sandbox_environment_backend b ON b.environment_id = e.id
    JOIN sandbox_workspace_bindings w
      ON w.environment_id = b.environment_id AND w.pod_uid = b.pod_uid
    WHERE e.org_id = $1 AND e.id = $2
      AND b.bound_at IS NOT NULL AND w.released_at IS NULL";

/// Query through a pool during capture, or through the future operation
/// owner's transaction during admission. A read alone is not a durable
/// admission lock: that owner must fence its own write in the same transaction.
pub(crate) async fn live_cw_runtime_binding(
    executor: impl sqlx::PgExecutor<'_>,
    organization_id: &str,
    environment_id: &str,
) -> Result<Option<CwRuntimeLiveBinding>, sqlx::Error> {
    sqlx::query_as(LIVE_CW_RUNTIME_BINDING)
        .bind(organization_id)
        .bind(environment_id)
        .fetch_optional(executor)
        .await
}
