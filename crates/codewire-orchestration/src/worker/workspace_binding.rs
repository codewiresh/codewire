//! Shadow recording of claim-time workspace bindings (Program #2238 B1,
//! design §5, §6 and §16).
//!
//! `write_binding` is the only writer of `sandbox_workspace_bindings` and of
//! the backend pointer (`pod_uid`, `bound_at`). It runs inside a
//! generation-fenced environment transaction. In B1 a bounded leader loop
//! drives it for running environments, after the same checks the cutover
//! will enforce:
//! - the converged Claim → Sandbox → Pod chain;
//! - images that equal the Sandbox template, with pinned digests matching;
//! - the workspace PVC resolved by UID.
//!
//! In shadow mode a failed check is counted and logged, never enforced: no Pod
//! is deleted, no activity fails, and no reader authorizes from bindings. The
//! loop also records `workspace_pvc_uid` the first time it resolves the PVC of
//! any environment that has a Sandbox, stopped ones included.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use codewire_gateway_proto::{GATEWAY_BINDING_SERVICE_ACCOUNT, WORKSPACE_BINDING_TOKEN_AUDIENCE};
use k8s_openapi::api::core::v1::{Container, ContainerStatus, Pod};
use kube::api::DynamicObject;
use prometheus::{IntCounterVec, Opts, register_int_counter_vec};
use sqlx::PgConnection;

use super::WorkerContext;
use super::activity_authority::{ActivityAuthority, is_authority_lost};
use super::env_data::{EnvironmentRow, load_environment};
use super::gatewayauth::WorkspaceCredentialScope;
use crate::sandbox::client::{SandboxClient, WorkspacePvc};
use crate::sandbox::{ClaimOpts, LABEL_OPERATION_GENERATION};

/// Environments examined per pass and per loop tick.
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
                "UPDATE sandbox_workspace_bindings SET released_at = now()
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
            == Some(GATEWAY_BINDING_SERVICE_ACCOUNT)
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
    ctx: &WorkerContext,
    environment_id: &str,
) -> anyhow::Result<Option<BackendFacts>> {
    let row: Option<BackendFactsRow> = sqlx::query_as(
        "SELECT namespace, sandbox_claim_name, sandbox_claim_uid, workspace_pvc_uid
           FROM sandbox_environment_backend WHERE environment_id = $1",
    )
    .bind(environment_id)
    .fetch_optional(&ctx.pool)
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
    let result = match record(ctx, environment_id).await {
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

async fn record(ctx: &WorkerContext, environment_id: &str) -> anyhow::Result<RecordResult> {
    let Some(kube) = ctx.kube.as_ref() else {
        return Ok(RecordResult::Unavailable);
    };
    let env = load_environment(&ctx.pool, environment_id).await?;
    if env.env_type != "sandbox"
        || env.state != "running"
        || env.desired_state != "started"
        || env.operation_generation <= 0
    {
        return Ok(RecordResult::NotReady);
    }
    let Some(backend) = load_backend_facts(ctx, environment_id).await? else {
        return Ok(RecordResult::NotReady);
    };
    let authority =
        ActivityAuthority::capture(&ctx.pool, environment_id, env.operation_generation).await?;
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
        WorkspaceCredentialScope::Pod => pod_scope_capture(&env),
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
    let result = match first_pvc(ctx, environment_id).await {
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
    let Some(backend) = load_backend_facts(ctx, environment_id).await? else {
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

// ------------------------------------------------------------- backfill

/// Rotation state of the bounded backfill, kept by the leader's loop.
#[derive(Default)]
pub(crate) struct BackfillCursor {
    bindings: Option<String>,
    pvcs: Option<String>,
}

async fn next_batch(
    ctx: &WorkerContext,
    query: &str,
    after: Option<&str>,
    limit: i64,
) -> anyhow::Result<Vec<String>> {
    let rows: Vec<(String,)> = sqlx::query_as(query)
        .bind(after.unwrap_or_default())
        .bind(limit)
        .fetch_all(&ctx.pool)
        .await?;
    Ok(rows.into_iter().map(|(id,)| id).collect())
}

/// Running environments without a binding first, then a rotating pass over
/// the bound ones, so a Pod replaced since its binding is recorded too.
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

/// Selects up to `limit` ids after the cursor, wrapping once to the start.
async fn rotate(
    ctx: &WorkerContext,
    query: &str,
    cursor: &mut Option<String>,
    limit: i64,
) -> anyhow::Result<Vec<String>> {
    let mut ids = next_batch(ctx, query, cursor.as_deref(), limit).await?;
    if ids.is_empty() && cursor.is_some() {
        ids = next_batch(ctx, query, None, limit).await?;
    }
    *cursor = ids.last().cloned();
    Ok(ids)
}

/// One bounded backfill pass, run by the leader on each reconciler tick.
pub(crate) async fn backfill_workspace_bindings(ctx: &WorkerContext, cursor: &mut BackfillCursor) {
    if ctx.kube.is_none() {
        return;
    }
    let result: anyhow::Result<()> = async {
        let mut ids = next_batch(ctx, UNBOUND_RUNNING, None, BACKFILL_BATCH).await?;
        let remaining = BACKFILL_BATCH - ids.len() as i64;
        if remaining > 0 {
            ids.extend(rotate(ctx, BOUND_RUNNING, &mut cursor.bindings, remaining).await?);
        }
        for id in ids {
            record_workspace_binding_shadow(ctx, &id).await;
        }
        for id in rotate(ctx, UNRESOLVED_PVC, &mut cursor.pvcs, BACKFILL_BATCH).await? {
            record_first_workspace_pvc(ctx, &id).await;
        }
        Ok(())
    }
    .await;
    if let Err(error) = result {
        tracing::warn!(error = %error, "workspace binding backfill pass failed");
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod database_tests;
