//! The session's side of host operations (#3609, slice 2), for a host of
//! capability version 2 or later.
//!
//! Every attach takes the host's next session generation, which supersedes
//! every earlier session. A session of a host that runs operations sends the operations an earlier
//! session was sent and not answered, unchanged, then claims and sends the
//! pending ones, and claims again on each signal and each ping. Only the
//! current session can claim: the claim and the generation check are one
//! statement ([`host_operations::claim_pending`]). The host's answers and
//! reports are recorded from any session of the host, since they are facts
//! about it.

use buffa::Message as _;
use codewire_proto::codewire::v1::{
    HostEnvironmentObservation as ProtoObservation, HostEnvironmentState as ProtoState,
    HostOperation as ProtoOperation, HostOperationResult, attach_host_response,
    host_operation_result,
};
use connectrpc::ConnectError;
use sqlx::PgPool;

use super::{End, Outbound, send, storage};
use crate::api::host_operations::{
    self, HostEnvironmentObservation, HostEnvironmentState, HostOperation, HostOperationOutcome,
};

/// The capability version that runs lifecycle operations.
pub(super) const OPERATIONS_CAPABILITY: i32 = 2;

/// The longest failure reason recorded.
const MAX_REASON_BYTES: usize = 1024;

/// The longest error code a report may carry, as `host_environments` holds.
const MAX_ERROR_CODE_BYTES: usize = 64;

/// One session's place among its host's sessions.
pub(super) struct Relay {
    host_id: String,
    session_generation: i64,
}

/// Whether the host may still be heard on this session.
pub(super) enum Heard {
    Current,
    Superseded,
    Revoked,
}

impl Relay {
    /// The relay of the session that took `session_generation`.
    pub(super) fn new(host_id: &str, session_generation: i64) -> Self {
        Self {
            host_id: host_id.to_owned(),
            session_generation,
        }
    }

    /// Records what the host's hello reported running. A malformed entry is
    /// skipped: the host sends the same inventory at every attach, so ending
    /// the session for it would keep the host out for good.
    pub(super) async fn record_inventory(
        self,
        pool: &PgPool,
        inventory: Vec<ProtoObservation>,
    ) -> Result<Self, End> {
        for observation in inventory {
            match parse_observation(observation) {
                Ok(observation) => self.record(pool, &observation).await?,
                Err(malformed) => tracing::warn!(
                    host_id = %self.host_id,
                    %malformed,
                    "host inventory entry is skipped"
                ),
            }
        }
        Ok(self)
    }

    /// Sends what an earlier session was sent and did not answer, then what
    /// is pending.
    pub(super) async fn send_outstanding(&self, pool: &PgPool, tx: &Outbound) -> Result<(), End> {
        let unanswered = host_operations::sent_unanswered(pool, &self.host_id)
            .await
            .map_err(operations_storage)?;
        for operation in &unanswered {
            self.send_operation(pool, tx, operation).await?;
        }
        self.claim_and_send(pool, tx).await
    }

    /// Claims this host's pending operations, while this session is current,
    /// and sends them.
    pub(super) async fn claim_and_send(&self, pool: &PgPool, tx: &Outbound) -> Result<(), End> {
        let claimed = host_operations::claim_pending(pool, &self.host_id, self.session_generation)
            .await
            .map_err(operations_storage)?;
        for operation in &claimed {
            self.send_operation(pool, tx, operation).await?;
        }
        Ok(())
    }

    /// Sends the stored operation as encoded. One that does not decode can
    /// never be sent, so it fails at once rather than leave its caller
    /// waiting.
    async fn send_operation(
        &self,
        pool: &PgPool,
        tx: &Outbound,
        operation: &HostOperation,
    ) -> Result<(), End> {
        let Ok(message) = ProtoOperation::decode(&mut operation.payload.as_slice()) else {
            tracing::error!(
                operation_id = %operation.operation_id,
                "stored host operation does not decode; it is failed, not sent"
            );
            let outcome = HostOperationOutcome::Failed {
                result: None,
                reason: "the stored operation does not decode".into(),
            };
            host_operations::complete(pool, &self.host_id, &operation.operation_id, &outcome)
                .await
                .map_err(storage)?;
            return Ok(());
        };
        send(
            tx,
            attach_host_response::Output::Operation(Box::new(message)),
        )
        .await
    }

    /// Records that the host was heard on this session, unless a newer
    /// session replaced it or the host was revoked.
    pub(super) async fn heard_from(&self, pool: &PgPool) -> Result<Heard, End> {
        let current: Option<bool> = sqlx::query_scalar(
            "UPDATE hosts SET last_seen_at = now() \
              WHERE id = $1 AND revoked_at IS NULL \
              RETURNING session_generation = $2",
        )
        .bind(&self.host_id)
        .bind(self.session_generation)
        .fetch_optional(pool)
        .await
        .map_err(storage)?;
        Ok(match current {
            None => Heard::Revoked,
            Some(true) => Heard::Current,
            Some(false) => Heard::Superseded,
        })
    }

    /// Records how the host says an operation ended, and the environment it
    /// left. An answer to an operation that is not this host's, or that was
    /// answered before, changes nothing. A done answer whose environment is
    /// malformed or not the operation's fails the operation, and its report
    /// is not recorded.
    pub(super) async fn record_result(
        &self,
        pool: &PgPool,
        result: HostOperationResult,
    ) -> Result<(), End> {
        let encoded = result.encode_to_vec();
        let (outcome, observed) = match result.outcome {
            Some(host_operation_result::Outcome::Done(observation)) => {
                match self
                    .answered(pool, &result.operation_id, *observation)
                    .await?
                {
                    Answer::Observed(observation) => (
                        HostOperationOutcome::Done { result: encoded },
                        Some(observation),
                    ),
                    Answer::Refused(reason) => (
                        HostOperationOutcome::Failed {
                            result: Some(encoded),
                            reason,
                        },
                        None,
                    ),
                }
            }
            Some(host_operation_result::Outcome::Failed(failure)) => (
                HostOperationOutcome::Failed {
                    result: Some(encoded),
                    reason: bounded(&format!("{}: {}", failure.code, failure.message)),
                },
                None,
            ),
            Some(host_operation_result::Outcome::StaleGeneration(stale)) => (
                HostOperationOutcome::Failed {
                    result: Some(encoded),
                    reason: format!(
                        "stale generation: expected {}, the host has {}",
                        stale.expected_generation, stale.current_generation
                    ),
                },
                None,
            ),
            None => {
                return Err(
                    ConnectError::invalid_argument("an operation result has no outcome").into(),
                );
            }
        };
        // The report first: the worker acts on the completed operation by
        // reading the host's latest report of its environment.
        if let Some(observation) = observed {
            self.record(pool, &observation).await?;
        }
        let recorded =
            host_operations::complete(pool, &self.host_id, &result.operation_id, &outcome)
                .await
                .map_err(storage)?;
        if !recorded {
            tracing::info!(
                host_id = %self.host_id,
                operation_id = %result.operation_id,
                "host answered an operation that was not awaiting its answer"
            );
        }
        Ok(())
    }

    /// The report a done answer carries, if it is well formed and of the
    /// operation's environment.
    async fn answered(
        &self,
        pool: &PgPool,
        operation_id: &str,
        observation: ProtoObservation,
    ) -> Result<Answer, End> {
        let observation = match parse_observation(observation) {
            Ok(observation) => observation,
            Err(malformed) => return Ok(Answer::Refused(malformed.to_string())),
        };
        let operation = host_operations::get(pool, operation_id)
            .await
            .map_err(operations_storage)?;
        Ok(match operation {
            Some(operation)
                if operation.host_id == self.host_id
                    && operation.environment_id != observation.environment_id =>
            {
                Answer::Refused(format!(
                    "the answer reports environment {}, not the operation's",
                    observation.environment_id
                ))
            }
            _ => Answer::Observed(observation),
        })
    }

    /// Records a host's report of one environment. A malformed one ends the
    /// session.
    pub(super) async fn record_observed(
        &self,
        pool: &PgPool,
        observation: ProtoObservation,
    ) -> Result<(), End> {
        self.record(pool, &parse_observation(observation)?).await
    }

    async fn record(
        &self,
        pool: &PgPool,
        observation: &HostEnvironmentObservation,
    ) -> Result<(), End> {
        host_operations::record_observation(pool, &self.host_id, observation)
            .await
            .map_err(storage)?;
        Ok(())
    }
}

/// A done answer's report, or why it cannot complete its operation.
enum Answer {
    Observed(HostEnvironmentObservation),
    Refused(String),
}

fn operations_storage(error: host_operations::HostOperationError) -> End {
    tracing::error!(error = %error, "host operation storage failed");
    End::Refused(ConnectError::internal("host session storage failed"))
}

fn bounded(text: &str) -> String {
    let mut end = text.len().min(MAX_REASON_BYTES);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

/// A field of a host's report that is not valid.
#[derive(Debug, PartialEq, Eq)]
struct Malformed(&'static str);

impl std::fmt::Display for Malformed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "an observation's {} is invalid", self.0)
    }
}

impl From<Malformed> for End {
    fn from(malformed: Malformed) -> Self {
        ConnectError::invalid_argument(malformed.to_string()).into()
    }
}

/// A report as stored. It must be exact: the host's word is the only
/// evidence of what runs there (design §8).
fn parse_observation(
    observation: ProtoObservation,
) -> Result<HostEnvironmentObservation, Malformed> {
    let environment_id = uuid::Uuid::parse_str(&observation.environment_id)
        .map_err(|_| Malformed("environment ID"))?;
    let local_environment_id = uuid::Uuid::parse_str(&observation.local_environment_id)
        .map_err(|_| Malformed("host environment ID"))?;
    let generation = i64::try_from(observation.generation).map_err(|_| Malformed("generation"))?;
    let state = match observation.state.as_known() {
        Some(ProtoState::HOST_ENVIRONMENT_STATE_STOPPED) => HostEnvironmentState::Stopped,
        Some(ProtoState::HOST_ENVIRONMENT_STATE_STARTING) => HostEnvironmentState::Starting,
        Some(ProtoState::HOST_ENVIRONMENT_STATE_RUNNING) => HostEnvironmentState::Running,
        Some(ProtoState::HOST_ENVIRONMENT_STATE_ERROR) => HostEnvironmentState::Error,
        Some(ProtoState::HOST_ENVIRONMENT_STATE_ABSENT) => HostEnvironmentState::Absent,
        _ => return Err(Malformed("state")),
    };
    if observation.error_code.len() > MAX_ERROR_CODE_BYTES {
        return Err(Malformed("error code"));
    }
    Ok(HostEnvironmentObservation {
        environment_id: environment_id.to_string(),
        local_environment_id,
        generation,
        state,
        error_code: Some(observation.error_code).filter(|code| !code.is_empty()),
        vcpus: i32::try_from(observation.vcpus).map_err(|_| Malformed("vCPU count"))?,
        memory_mib: i32::try_from(observation.memory_mib).map_err(|_| Malformed("memory"))?,
        disk_bytes: i64::try_from(observation.disk_bytes).map_err(|_| Malformed("disk size"))?,
        ssh_host_key: Some(observation.ssh_host_key).filter(|key| !key.is_empty()),
    })
}

#[cfg(test)]
mod tests;
