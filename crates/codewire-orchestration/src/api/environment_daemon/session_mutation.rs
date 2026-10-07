//! Short deletion admission for durable session mutations, not attachment or
//! process-lifetime ownership. The caller prepares and authorizes the private
//! client before entering here. Only this owned task may dispatch and settle.

use std::future::Future;
use std::time::Duration;

use codewire_daemon_proto::daemon::v1;
use codewire_server_core::org_deletion::{
    OrganizationRuntimeMutationError, run_environment_runtime_mutation,
};
use codewire_server_core::{AppError, AppResult};
use sqlx::PgPool;
use uuid::Uuid;

// The shared helper bounds dispatch to 60 seconds. Private Launch/Restart allow
// the 30-second projection rendezvous plus cleanup; Stop/control retain five
// seconds. Bound admission and durable settlement as well.
// If this outer deadline wins, the shared helper's owner task still settles any
// acquired lease from the dispatch outcome; this caller only reports it as
// unknown. Never release on timeout or treat lease expiry as remote absence.
const OWNER_TIMEOUT: Duration = Duration::from_secs(75);
const SETUP_READINESS_TIMEOUT: Duration = Duration::from_secs(5);

pub(super) enum Acknowledgement {
    Launch,
    Stop(String),
    Restart(String),
}

pub(super) async fn run<F>(
    pool: &PgPool,
    org_id: &str,
    environment_id: &str,
    acknowledgement: Acknowledgement,
    dispatch: F,
) -> AppResult<v1::SessionRecord>
where
    F: Future<Output = Result<Option<v1::SessionRecord>, tonic::Status>> + Send + 'static,
{
    run_with_timeout(
        pool,
        org_id,
        environment_id,
        acknowledgement,
        dispatch,
        OWNER_TIMEOUT,
    )
    .await
}

async fn run_with_timeout<F>(
    pool: &PgPool,
    org_id: &str,
    environment_id: &str,
    acknowledgement: Acknowledgement,
    dispatch: F,
    owner_timeout: Duration,
) -> AppResult<v1::SessionRecord>
where
    F: Future<Output = Result<Option<v1::SessionRecord>, tonic::Status>> + Send + 'static,
{
    let pool = pool.clone();
    let org_id = org_id.to_string();
    let environment_id = environment_id.to_string();
    // Spawn before admission: there is no cancellation gap between acquiring
    // the lease and transferring it to the owner. Dropping a JoinHandle detaches
    // it; a vanished HTTP caller cannot cancel or compensate this mutation.
    tokio::spawn(async move {
        let operation_pool = pool.clone();
        let operation_environment_id = environment_id.clone();
        tokio::time::timeout(
            owner_timeout,
            run_environment_runtime_mutation(&pool, &org_id, &environment_id, async move {
                let (pool, environment_id) = (operation_pool, operation_environment_id);
                // This is a known local rejection after deletion admission but
                // before polling the mutating RPC. A running Pod may still be
                // replaced by its setup owner. Stop remains available then.
                if acknowledgement.requires_setup_ready() {
                    let setup = sqlx::query_as::<_, (bool, Option<String>)>(
                        "SELECT COALESCE(setup_complete, false), setup_owner_status \
                           FROM sandbox_environment_backend WHERE environment_id = $1",
                    )
                    .bind(&environment_id)
                    .fetch_optional(&pool);
                    check_setup_readiness(setup, SETUP_READINESS_TIMEOUT).await?;
                }
                let record = dispatch.await.map_err(classify_dispatch_error)?;
                acknowledgement
                    .validate(record)
                    .map_err(OrganizationRuntimeMutationError::ambiguous)
            }),
        )
        .await
        .map_err(|_| uncertain_outcome())?
    })
    .await
    .map_err(|_| uncertain_outcome())?
}

async fn check_setup_readiness<F>(
    read: F,
    deadline: Duration,
) -> Result<(), OrganizationRuntimeMutationError>
where
    F: Future<Output = Result<Option<(bool, Option<String>)>, sqlx::Error>>,
{
    // Expiring a local read cannot imply that the not-yet-polled mutation ran.
    let setup = tokio::time::timeout(deadline, read)
        .await
        .map_err(|_| setup_readiness_error())?;
    require_setup_ready(setup)
}

fn setup_readiness_error() -> OrganizationRuntimeMutationError {
    OrganizationRuntimeMutationError::Known(AppError::InternalMsg(
        "environment setup readiness could not be checked".into(),
    ))
}

fn require_setup_ready(
    setup: Result<Option<(bool, Option<String>)>, sqlx::Error>,
) -> Result<(), OrganizationRuntimeMutationError> {
    let setup = setup.map_err(|_| setup_readiness_error())?;
    match setup {
        Some((complete, owner))
            if super::daemon_repair_setup_is_idle(complete, owner.as_deref()) =>
        {
            Ok(())
        }
        _ => Err(OrganizationRuntimeMutationError::Known(
            AppError::Precondition(
                "environment setup is not ready; wait for setup to finish".into(),
            ),
        )),
    }
}

fn uncertain_outcome() -> AppError {
    // Not Upstream: the shared Connect renderer adds retry advice to Upstream.
    // Launch/Restart are not idempotent. List/Get must reconcile a lost reply.
    AppError::Precondition(
        "environment session outcome is unknown; refresh sessions before trying again".into(),
    )
}

fn classify_dispatch_error(error: tonic::Status) -> OrganizationRuntimeMutationError {
    // These codes originate only in daemon authorization, argument validation
    // or missing-handle lookup, before any session mutation. FailedPrecondition
    // is deliberately NOT here: Restart can already have stopped its old shell.
    // Do not log or persist raw status text (commands/paths/provider data).
    let known = match error.code() {
        tonic::Code::Unauthenticated => AppError::Unauthorized,
        tonic::Code::PermissionDenied => AppError::Forbidden,
        tonic::Code::InvalidArgument => {
            AppError::BadRequest("environment session request is invalid".into())
        }
        tonic::Code::NotFound => AppError::NotFound("environment session not found".into()),
        _ => return OrganizationRuntimeMutationError::ambiguous(uncertain_outcome()),
    };
    OrganizationRuntimeMutationError::Known(known)
}

impl Acknowledgement {
    fn requires_setup_ready(&self) -> bool {
        matches!(self, Self::Launch | Self::Restart(_))
    }

    fn validate(&self, record: Option<v1::SessionRecord>) -> AppResult<v1::SessionRecord> {
        let record = record.ok_or_else(uncertain_outcome)?;
        let valid_id = record
            .session_id
            .strip_prefix("session-")
            .is_some_and(|id| Uuid::parse_str(id).is_ok());
        let matching_id = match self {
            Self::Launch => true,
            Self::Stop(expected) | Self::Restart(expected) => expected == &record.session_id,
        };
        let state = v1::SessionLifecycleState::try_from(record.state).ok();
        let complete = match self {
            Self::Launch | Self::Restart(_) => match state {
                Some(v1::SessionLifecycleState::Running) => {
                    record.started_at.is_some()
                        && record.finished_at.is_none()
                        && record.exit_code.is_none()
                }
                // A persisted startup failure is a recorded launch outcome.
                // It does not certify child-process absence; unlike Stop, a
                // launch acknowledgement is not a termination guarantee.
                Some(v1::SessionLifecycleState::Failed) => {
                    record.started_at.is_none() && record.finished_at.is_some()
                }
                _ => false,
            },
            Self::Stop(_) => {
                matches!(
                    state,
                    Some(v1::SessionLifecycleState::Stopped | v1::SessionLifecycleState::Exited)
                ) && record.finished_at.is_some()
            }
        };
        if !valid_id || !matching_id || !complete || record.created_at.is_none() {
            return Err(uncertain_outcome());
        }
        Ok(record)
    }
}

#[cfg(test)]
mod tests;
