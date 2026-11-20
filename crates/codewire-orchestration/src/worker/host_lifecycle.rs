//! Environments on a host: the worker's side of their lifecycle (#3609
//! slice 2, design §4.4).
//!
//! Each lifecycle activity of a host environment sends one operation to its
//! host through the Postgres seam ([`crate::api::host_operations`]) and waits
//! for the host's result. The host's supervisor keeps every operation's result
//! by its ID forever, so an ID is the same across Temporal's retries of one
//! activity, and new for every command: [`operation_id`] derives it from the
//! workflow run and the activity's scheduled time, which the activity's claim
//! already uses to tell a retry from a new command.

use std::time::Duration;

use codewire_proto::codewire::v1 as proto;
use sha2::{Digest, Sha256};
use sqlx::PgPool;

use super::activity_authority::ActivityAuthority;
use tokio::time::Instant;

use crate::api::host_operations::{
    self, HostOperationError, HostOperationKind, HostOperationState, NewHostOperation,
};
use crate::lifecycle::{PgLifecycleStore, Service};

/// How long one wait for the host's answer lasts before the activity checks
/// its authority again; the activity's heartbeat keeps it alive meanwhile.
const ANSWER_SLICE: Duration = Duration::from_secs(20);

/// How long an activity waits for its host in all, short of the activity's
/// own 30-minute limit, so the environment ends with the reason instead of
/// a timed-out activity.
const ANSWER_DEADLINE: Duration = Duration::from_secs(25 * 60);

/// The longest host-written message and code shown as an environment's error.
const MAX_HOST_MESSAGE_CHARS: usize = 300;
const MAX_HOST_CODE_CHARS: usize = 64;

/// Why an activity gave up waiting.
const UNANSWERED: &str = "the host didn't answer within 25 minutes; it may be offline";

/// The guest Docker data disk a host environment gets, as `cw create
/// --local` and hosted sandboxes have Docker:
/// `codewire_local_vmm::state::DEFAULT_DOCKER_DISK_BYTES`.
const DOCKER_DISK_BYTES: u64 = 8 * 1024 * 1024 * 1024;

/// What names one activity's operation: its workflow run and the activity's
/// first scheduled time, both the same across its retries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OperationScope {
    pub workflow_run_id: String,
    pub scheduled_at_unix_nanos: i64,
}

/// The operation ID for `kind` of `environment_id` within `scope`: a UUID,
/// as the host contract asks, from a SHA-256 over all four.
pub(crate) fn operation_id(
    environment_id: &str,
    scope: &OperationScope,
    kind: HostOperationKind,
) -> String {
    let mut digest = Sha256::new();
    for part in [
        environment_id.as_bytes(),
        scope.workflow_run_id.as_bytes(),
        &scope.scheduled_at_unix_nanos.to_be_bytes(),
        kind.as_str().as_bytes(),
    ] {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part);
    }
    let bytes: [u8; 16] = digest.finalize()[..16]
        .try_into()
        .expect("a SHA-256 digest has 16 leading bytes");
    uuid::Builder::from_random_bytes(bytes)
        .into_uuid()
        .to_string()
}

/// What a create sends: the environment's shape, and its project as the
/// canonical JSON the host re-hashes. The host runs its own default image,
/// so the canonical workspace image is cleared; the API refused any other.
pub(crate) struct CreateRequest<'a> {
    pub environment_id: &'a str,
    pub operation_id: &'a str,
    pub project_spec: &'a codewire_project::ProjectSpec,
    pub cpu_millicores: i32,
    pub memory_mib: i32,
    pub disk_gib: i32,
}

/// The encoded `HostOperation` for a create.
pub(crate) fn create_operation(request: &CreateRequest<'_>) -> anyhow::Result<Vec<u8>> {
    let mut spec = request.project_spec.clone();
    if spec.image == crate::sandbox::canonical_workspace_runtime_image() {
        spec.image.clear();
    }
    anyhow::ensure!(
        spec.image.is_empty(),
        "a host runs its own default image; this environment names {:?}",
        spec.image
    );
    let project_spec_json = spec.canonical_json()?;
    let project_spec_sha256 = format!("{:x}", Sha256::digest(&project_spec_json));
    let positive = |value: i32, what: &str| {
        u32::try_from(value)
            .ok()
            .filter(|value| *value > 0)
            .ok_or_else(|| anyhow::anyhow!("environment {what} {value} is not positive"))
    };
    let create = proto::HostCreate {
        vcpus: positive(request.cpu_millicores, "cpu_millicores")?.div_ceil(1000),
        memory_mib: positive(request.memory_mib, "memory")?,
        disk_bytes: u64::from(positive(request.disk_gib, "disk")?) << 30,
        docker_disk_bytes: DOCKER_DISK_BYTES,
        project_spec_json,
        project_spec_sha256,
        ..Default::default()
    };
    let operation = proto::HostOperation {
        operation_id: request.operation_id.to_owned(),
        environment_id: request.environment_id.to_owned(),
        // A create names no VM yet and expects none.
        local_environment_id: String::new(),
        expected_generation: 0,
        kind: Some(create.into()),
        ..Default::default()
    };
    Ok(buffa::Message::encode_to_vec(&operation))
}

/// How a host answered an operation, as the lifecycle acts on it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Answer {
    /// The VM's state as the operation left it. The host's session records
    /// the rest of its report before completing the operation.
    Done { state: proto::HostEnvironmentState },
    /// The host's own reason, shown as it is.
    Failed { code: String, message: String },
    /// The host's generation moved on.
    Stale { expected: u64, current: u64 },
}

/// Reads an encoded `HostOperationResult` to `environment_id`'s operation.
/// A VM reported for another environment is an error: later operations
/// name the VM from this answer.
pub(crate) fn answer(environment_id: &str, result: &[u8]) -> anyhow::Result<Answer> {
    use proto::__buffa::oneof::host_operation_result::Outcome;

    let result: proto::HostOperationResult = buffa::Message::decode(&mut &result[..])
        .map_err(|error| anyhow::anyhow!("decode the host's operation result: {error}"))?;
    Ok(match result.outcome {
        Some(Outcome::Done(observation)) if observation.environment_id != environment_id => {
            anyhow::bail!(
                "the host answered with environment {:?}'s VM",
                observation.environment_id
            )
        }
        Some(Outcome::Done(observation)) => Answer::Done {
            state: observation.state.as_known().unwrap_or_default(),
        },
        Some(Outcome::Failed(failure)) => Answer::Failed {
            code: failure.code.clone(),
            message: failure.message.clone(),
        },
        Some(Outcome::StaleGeneration(stale)) => Answer::Stale {
            expected: stale.expected_generation,
            current: stale.current_generation,
        },
        None => anyhow::bail!("the host's operation result has no outcome"),
    })
}

/// Whether `environment_id` runs on a host. An unknown backend is an
/// error, never read as the cluster.
pub(crate) async fn is_host(pool: &PgPool, environment_id: &str) -> anyhow::Result<bool> {
    let backend: String =
        sqlx::query_scalar("SELECT runtime_backend FROM environments WHERE id = $1")
            .bind(environment_id)
            .fetch_one(pool)
            .await?;
    Ok(crate::runtime::RuntimeBackend::parse(&backend)? == crate::runtime::RuntimeBackend::Host)
}

/// Creates `authority`'s environment on its host: one create operation,
/// then the host's answer. RUNNING is the daemon ready, so the environment
/// is running; anything else is an error carrying the host's words.
pub(crate) async fn create(
    pool: &PgPool,
    authority: &ActivityAuthority,
    scope: &OperationScope,
) -> anyhow::Result<()> {
    create_until(pool, authority, scope, Instant::now() + ANSWER_DEADLINE).await
}

async fn create_until(
    pool: &PgPool,
    authority: &ActivityAuthority,
    scope: &OperationScope,
    deadline: Instant,
) -> anyhow::Result<()> {
    let env_id = authority.environment_id();
    let svc = Service::<PgLifecycleStore>::for_activity(pool.clone(), authority.clone());
    authority.ensure().await?;
    let env = super::env_data::load_environment(pool, env_id).await?;
    // A retry of a create that already ran has nothing left to do, as the
    // cluster's create ends `Done` on a running environment.
    if super::create::create_command_cancelled(&env.state, &env.desired_state)
        || env.state == "running"
    {
        return Ok(());
    }
    let host_id: String = sqlx::query_scalar(
        "SELECT host_id FROM environments WHERE id = $1 AND runtime_backend = 'host' \
         AND host_id IS NOT NULL",
    )
    .bind(env_id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| anyhow::anyhow!("environment {env_id} is not placed on a host"))?;
    if env.state == "pending" {
        svc.transition(env_id, "pending", "creating").await?;
    }
    let operation_id = operation_id(env_id, scope, HostOperationKind::Create);
    if !settle_open(pool, authority, env_id, &operation_id, deadline).await? {
        return svc.mark_error(env_id, UNANSWERED).await;
    }
    let payload = create_operation(&CreateRequest {
        environment_id: env_id,
        operation_id: &operation_id,
        project_spec: &env.project_spec,
        cpu_millicores: env.cpu_millicores,
        memory_mib: env.memory_mb,
        disk_gib: env.disk_gb,
    })?;
    if let Some(reason) = enqueue(
        pool,
        &NewHostOperation {
            operation_id: &operation_id,
            host_id: &host_id,
            environment_id: env_id,
            expected_generation: 0,
            kind: HostOperationKind::Create,
            payload: &payload,
        },
    )
    .await?
    {
        return svc.mark_error(env_id, reason).await;
    }
    match finished(pool, authority, env_id, &operation_id, deadline).await? {
        Finish::Answered(Answer::Done { state }) => {
            if state == proto::HostEnvironmentState::HOST_ENVIRONMENT_STATE_RUNNING {
                svc.transition(env_id, "creating", "running").await?;
                svc.mark_started(env_id).await?;
            } else {
                // A create satisfied by a VM made earlier may find it
                // stopped; it is never reported as running (#4640).
                svc.mark_error(
                    env_id,
                    &format!(
                        "the host's VM for this environment is {}, not running",
                        vm_state(state)
                    ),
                )
                .await?;
            }
        }
        Finish::Answered(other) => svc.mark_error(env_id, &failure_text(&other)).await?,
        Finish::Refused(reason) => svc.mark_error(env_id, &reason).await?,
        Finish::Unanswered => unanswered(pool, &svc, env_id, &operation_id).await?,
    }
    Ok(())
}

/// A host lifecycle operation other than create.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Change {
    Start,
    Stop,
    Destroy,
}

impl Change {
    fn kind(self) -> HostOperationKind {
        match self {
            Self::Start => HostOperationKind::Start,
            Self::Stop => HostOperationKind::Stop,
            Self::Destroy => HostOperationKind::Destroy,
        }
    }

    fn proto(self) -> proto::__buffa::oneof::host_operation::Kind {
        match self {
            Self::Start => proto::HostStart::default().into(),
            Self::Stop => proto::HostStop::default().into(),
            Self::Destroy => proto::HostDestroy::default().into(),
        }
    }
}

/// Starts, stops or destroys `authority`'s environment on its host, naming
/// the VM and generation from the host's last report of it. Stop and start
/// end as the cluster's do; destroy ends with the external cleanup marker,
/// which needs the host's word that the VM is absent.
#[tracing::instrument(level = "debug", skip_all, fields(environment_id = %authority.environment_id()))]
pub(crate) async fn change(
    pool: &PgPool,
    authority: &ActivityAuthority,
    scope: &OperationScope,
    change: Change,
) -> anyhow::Result<()> {
    change_until(
        pool,
        authority,
        scope,
        change,
        Instant::now() + ANSWER_DEADLINE,
    )
    .await
}

async fn change_until(
    pool: &PgPool,
    authority: &ActivityAuthority,
    scope: &OperationScope,
    change: Change,
    deadline: Instant,
) -> anyhow::Result<()> {
    let env_id = authority.environment_id();
    let svc = Service::<PgLifecycleStore>::for_activity(pool.clone(), authority.clone());
    authority.ensure().await?;
    let env = super::env_data::load_environment(pool, env_id).await?;
    let host_id: Option<String> = sqlx::query_scalar(
        "SELECT host_id FROM environments WHERE id = $1 AND runtime_backend = 'host'",
    )
    .bind(env_id)
    .fetch_optional(pool)
    .await?
    .flatten();
    // As on the cluster: the environment enters the change's state, or the
    // change is already over (a retry) or not this state's to make.
    let snapshot = super::lifecycle::snapshot(
        &env.id,
        &env.state,
        &env.desired_state,
        env.external_cleanup_completed_at.is_some(),
    );
    let proceed = match change {
        Change::Start => svc.prepare_start(&snapshot).await?,
        Change::Stop => svc.prepare_stop(&snapshot).await?,
        Change::Destroy => svc.prepare_destroy(&snapshot).await?,
    };
    if !proceed {
        return Ok(());
    }
    let proof = if change == Change::Destroy {
        Some(crate::lifecycle::RuntimeAbsenceProof::begin(pool).await?)
    } else {
        None
    };
    // A host deleted with its owner leaves no VM to reach: destroy has
    // nothing left to do there, and start or stop can't happen.
    let Some(host_id) = host_id else {
        return match proof {
            Some(proof) => {
                svc.complete_external_cleanup(env_id, env.state == "destroyed", proof)
                    .await
            }
            None => {
                svc.mark_error(env_id, "the environment's host was removed")
                    .await
            }
        };
    };
    let operation_id = operation_id(env_id, scope, change.kind());
    // An earlier command's operation ends first, so the host's report below
    // includes whatever it did.
    if !settle_open(pool, authority, env_id, &operation_id, deadline).await? {
        return svc.mark_error(env_id, UNANSWERED).await;
    }
    let Some((observed, _)) = host_operations::latest_observation(pool, &host_id, env_id).await?
    else {
        // No operation is open and the host never reported this VM: it was
        // never made.
        return match proof {
            Some(proof) => {
                svc.complete_external_cleanup(env_id, env.state == "destroyed", proof)
                    .await
            }
            None => {
                svc.mark_error(env_id, "the host has no VM for this environment")
                    .await
            }
        };
    };
    let operation = proto::HostOperation {
        operation_id: operation_id.clone(),
        environment_id: env_id.to_owned(),
        local_environment_id: observed.local_environment_id.to_string(),
        expected_generation: u64::try_from(observed.generation)?,
        kind: Some(change.proto()),
        ..Default::default()
    };
    if let Some(reason) = enqueue(
        pool,
        &NewHostOperation {
            operation_id: &operation_id,
            host_id: &host_id,
            environment_id: env_id,
            expected_generation: observed.generation,
            kind: change.kind(),
            payload: &buffa::Message::encode_to_vec(&operation),
        },
    )
    .await?
    {
        // A revoked host never connects again, and a host the environment
        // has left won't run it: as with a deleted host, destroy has nothing
        // left to reach, and start or stop can't happen.
        return match proof {
            Some(proof) => {
                svc.complete_external_cleanup(env_id, env.state == "destroyed", proof)
                    .await
            }
            None => svc.mark_error(env_id, reason).await,
        };
    }
    let answer = match finished(pool, authority, env_id, &operation_id, deadline).await? {
        Finish::Answered(answer) => answer,
        Finish::Refused(reason) => {
            // A host revoked after it took the destroy never answers, and
            // has nothing left to reach.
            return match proof {
                Some(proof) if reason == host_operations::HOST_REVOKED => {
                    svc.complete_external_cleanup(env_id, env.state == "destroyed", proof)
                        .await
                }
                _ => svc.mark_error(env_id, &reason).await,
            };
        }
        Finish::Unanswered => return unanswered(pool, &svc, env_id, &operation_id).await,
    };
    let Answer::Done { state } = &answer else {
        return svc.mark_error(env_id, &failure_text(&answer)).await;
    };
    use proto::HostEnvironmentState as Vm;
    match (change, state) {
        (Change::Start, Vm::HOST_ENVIRONMENT_STATE_RUNNING) => {
            svc.complete_start(env_id).await?;
            svc.mark_started(env_id).await
        }
        (Change::Stop, Vm::HOST_ENVIRONMENT_STATE_STOPPED) => {
            svc.complete_stop(env_id).await?;
            svc.mark_stopped(env_id).await
        }
        (Change::Destroy, Vm::HOST_ENVIRONMENT_STATE_ABSENT) => {
            let proof = proof.expect("a destroy holds its absence proof");
            svc.complete_external_cleanup(env_id, env.state == "destroyed", proof)
                .await
        }
        _ => svc.mark_error(env_id, &failure_text(&answer)).await,
    }
}

/// Records that `what` isn't available on a host yet, so the request ends
/// as an error the user sees instead of waiting.
pub(crate) async fn unsupported(
    pool: &PgPool,
    authority: &ActivityAuthority,
    what: &str,
) -> anyhow::Result<()> {
    Service::<PgLifecycleStore>::for_activity(pool.clone(), authority.clone())
        .mark_error(
            authority.environment_id(),
            &format!("{what} isn't available for environments on a host yet"),
        )
        .await
}

enum Finish {
    Answered(Answer),
    /// The seam failed the operation without the host's result, or the
    /// result can't be acted on.
    Refused(String),
    /// No answer by the activity's deadline.
    Unanswered,
}

/// Ends `environment_id`'s open operation other than `operation_id`, so
/// this command's can be enqueued: a pending one is withdrawn before the
/// host sees it; a sent one is waited for, since the host may be acting on
/// it. False when one is still unanswered at the deadline.
async fn settle_open(
    pool: &PgPool,
    authority: &ActivityAuthority,
    environment_id: &str,
    operation_id: &str,
    deadline: Instant,
) -> anyhow::Result<bool> {
    loop {
        authority.ensure().await?;
        let Some(open) = host_operations::open_for_environment(pool, environment_id).await? else {
            return Ok(true);
        };
        if open.operation_id == operation_id {
            return Ok(true);
        }
        if open.state == HostOperationState::Pending
            && host_operations::withdraw(pool, &open.operation_id).await?
        {
            continue;
        }
        // Whatever it answers, the host's report now says where its VM is.
        if let Finish::Unanswered = finished(
            pool,
            authority,
            environment_id,
            &open.operation_id,
            deadline,
        )
        .await?
        {
            return Ok(false);
        }
    }
}

/// Enqueues `operation`: `None` once it's queued, or the reason the host
/// can't be sent it, which ends the command.
async fn enqueue(
    pool: &PgPool,
    operation: &NewHostOperation<'_>,
) -> anyhow::Result<Option<&'static str>> {
    match host_operations::enqueue(pool, operation).await {
        Ok(_) => Ok(None),
        Err(HostOperationError::Revoked { .. }) => Ok(Some("the environment's host was revoked")),
        Err(HostOperationError::NotPlaced { .. }) => {
            Ok(Some("the environment is no longer placed on its host"))
        }
        Err(error) => Err(error.into()),
    }
}

/// Ends an activity whose host didn't answer: its operation is withdrawn
/// if the host never took it, so nothing runs later, and the environment
/// is in error with the reason.
async fn unanswered(
    pool: &PgPool,
    svc: &Service<PgLifecycleStore>,
    environment_id: &str,
    operation_id: &str,
) -> anyhow::Result<()> {
    host_operations::withdraw(pool, operation_id).await?;
    svc.mark_error(environment_id, UNANSWERED).await
}

/// Waits for the operation's end, a slice at a time, checking between
/// slices that this activity still holds the environment's authority.
async fn finished(
    pool: &PgPool,
    authority: &ActivityAuthority,
    environment_id: &str,
    operation_id: &str,
    deadline: Instant,
) -> anyhow::Result<Finish> {
    loop {
        authority.ensure().await?;
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Ok(Finish::Unanswered);
        }
        // TODO(#4762): `wait_finished` re-reads the row. It moves to the
        // live-state change notice once that trigger is on main, rather than
        // gaining a second notification mechanism of its own.
        match host_operations::wait_finished(pool, operation_id, ANSWER_SLICE.min(left)).await {
            Ok(operation) => {
                // An answer that can't be acted on never will be: the
                // environment ends in error rather than retrying it.
                let read = |result: Vec<u8>| match answer(environment_id, &result) {
                    Ok(answer) => Finish::Answered(answer),
                    Err(error) => Finish::Refused(format!("{error:#}")),
                };
                return Ok(match operation.state {
                    HostOperationState::Done { result } => read(result),
                    HostOperationState::Failed {
                        result: Some(result),
                        ..
                    } => read(result),
                    HostOperationState::Failed {
                        result: None,
                        reason,
                    } => Finish::Refused(reason),
                    HostOperationState::Pending | HostOperationState::Sent { .. } => continue,
                });
            }
            Err(HostOperationError::TimedOut { .. }) => continue,
            // A later command withdrew it before the host took it.
            Err(HostOperationError::Unknown { .. }) => {
                return Ok(Finish::Refused(
                    "a later command replaced this one before the host took it".into(),
                ));
            }
            Err(error) => return Err(error.into()),
        }
    }
}

/// The host's own words for an answer that isn't a finished VM.
fn failure_text(answer: &Answer) -> String {
    match answer {
        Answer::Failed { code, message } => {
            let code = host_code(code);
            match host_words(message) {
                words if words.is_empty() => format!("the host refused the operation ({code})"),
                words => format!("{words} ({code})"),
            }
        }
        Answer::Stale { expected, current } => format!(
            "the host's VM moved on: expected generation {expected}, the host has {current}"
        ),
        Answer::Done { state, .. } => format!("the host's VM is {}", vm_state(*state)),
    }
}

/// A host's message as an environment's error. The host's owner writes it
/// and every member the host is granted to reads it, so it is one line with
/// no control or invisible formatting characters, and bounded.
fn host_words(text: &str) -> String {
    let shown: String = text
        .chars()
        .filter(|character| !invisible(*character))
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect();
    shown
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(MAX_HOST_MESSAGE_CHARS)
        .collect()
}

/// Zero-width and text-direction characters, which can hide or reorder what
/// a reader sees.
fn invisible(character: char) -> bool {
    matches!(
        character,
        '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}'
    )
}

/// A host's failure code: letters, digits, `_`, `-` and `.` only, bounded.
fn host_code(code: &str) -> String {
    let code: String = code
        .chars()
        .filter(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.')
        })
        .take(MAX_HOST_CODE_CHARS)
        .collect();
    if code.is_empty() {
        "unknown".to_owned()
    } else {
        code
    }
}

/// A VM's state in a sentence.
fn vm_state(state: proto::HostEnvironmentState) -> &'static str {
    use proto::HostEnvironmentState as Vm;
    match state {
        Vm::HOST_ENVIRONMENT_STATE_STOPPED => "stopped",
        Vm::HOST_ENVIRONMENT_STATE_STARTING => "starting",
        Vm::HOST_ENVIRONMENT_STATE_RUNNING => "running",
        Vm::HOST_ENVIRONMENT_STATE_ERROR => "in error",
        Vm::HOST_ENVIRONMENT_STATE_ABSENT => "gone",
        _ => "in an unknown state",
    }
}

#[cfg(test)]
mod database_tests;
#[cfg(test)]
mod tests;
