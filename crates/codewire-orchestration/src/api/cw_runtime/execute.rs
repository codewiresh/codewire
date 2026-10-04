//! Sole original-channel executor. No loader/observer creates an owner, and
//! every effect is dispatched once only after its known Issued commit.
use std::time::Duration;

use async_trait::async_trait;
use codewire_daemon_bridge::client::{
    DaemonClient, DaemonRunInput, DaemonRunOutput, DaemonRunStart,
};
use codewire_server_core::AppResult;
use codewire_server_core::auth::AuthUser;
use futures_util::{Stream, StreamExt as _};

use super::intake::Candidate;
use super::model::{EffectReceipt, RuntimeAction, RuntimeEffect};
use super::owner::{IssuedEffect, KnownFailure, RequestOwner, RuntimeJournal, RuntimeRequest};
use super::wire::{Action, Correlation, ExpectedSelection, Outcome, ReplyBody, RoleRequest};
use super::{CapturedPlatformCwRuntime, model, wire};
use crate::api::ApiState;

const ROLE_TIMEOUT: Duration = Duration::from_secs(130);
const OWNER_TIMEOUT: Duration = Duration::from_secs(600);
const MAX_STDERR: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Dispatch {
    Succeeded(ReplyBody),
    Refused,
    Unknown,
}

/// The command is fixed independently of public fields and current selection.
/// It launches the image source as the existing daemon's ordinary workload UID.
fn role_start() -> DaemonRunStart {
    DaemonRunStart {
        command: vec!["/codewire/bin/cw".into(), "__platform-cw-runtime".into()],
        working_dir: "/home/codewire".into(),
        env: vec![],
        allocate_tty: false,
        term: String::new(),
        columns: 0,
        rows: 0,
    }
}

pub(super) async fn role(
    client: &DaemonClient,
    correlation: &Correlation,
    action: Action,
    candidate: Option<&mut Candidate>,
) -> Dispatch {
    let Ok(frame) = RoleRequest::frame(correlation, action) else {
        return Dispatch::Unknown;
    };
    match tokio::time::timeout(
        ROLE_TIMEOUT,
        role_inner(client, correlation, frame, candidate),
    )
    .await
    {
        Ok(Ok(value)) => value,
        _ => Dispatch::Unknown,
    }
}

async fn role_inner(
    client: &DaemonClient,
    correlation: &Correlation,
    frame: Vec<u8>,
    mut candidate: Option<&mut Candidate>,
) -> AppResult<Dispatch> {
    let session = client
        .start_run(role_start())
        .await
        .map_err(|_| model::unavailable())?;
    let (sender, mut receiver) = session.into_split();
    let writer = async {
        sender
            .send_input(DaemonRunInput::Stdin(frame))
            .await
            .map_err(|_| model::unavailable())?;
        if let Some(candidate) = &mut candidate {
            candidate.rewind()?;
            let mut count = 0_u64;
            loop {
                let bytes = candidate.read_chunk()?;
                if bytes.is_empty() {
                    break;
                }
                count = count
                    .checked_add(bytes.len() as u64)
                    .ok_or_else(model::unavailable)?;
                if count > candidate.identity().size {
                    return Err(model::unavailable());
                }
                sender
                    .send_input(DaemonRunInput::Stdin(bytes))
                    .await
                    .map_err(|_| model::unavailable())?;
            }
            if count != candidate.identity().size {
                return Err(model::unavailable());
            }
            candidate.check()?;
        }
        sender
            .send_input(DaemonRunInput::CloseStdin)
            .await
            .map_err(|_| model::unavailable())?;
        Ok::<_, codewire_server_core::AppError>(())
    };
    let mut outputs = futures_util::stream::unfold(&mut receiver, |receiver| async move {
        match receiver.next_output().await {
            Ok(Some(message)) => Some((Ok(message), receiver)),
            Ok(None) => None,
            Err(_) => Some((Err(model::unavailable()), receiver)),
        }
    })
    .boxed();
    let reader = receive_until_exit(&mut outputs, correlation);
    let (sent, received) = tokio::join!(writer, reader);
    sent?;
    // CloseStdin is only a half-close. Retain the request stream through Exit
    // so dropping it cannot cancel an unfinished command. Only then close it
    // and require clean response EOF; a receipt without EOF is not an ACK.
    drop(sender);
    require_eof(&mut outputs).await?;
    Ok(match received? {
        Outcome::Succeeded { result } => Dispatch::Succeeded(result),
        Outcome::Refused { .. } => Dispatch::Refused,
        Outcome::Unknown { .. } => Dispatch::Unknown,
    })
}

async fn receive_until_exit<S>(outputs: &mut S, correlation: &Correlation) -> AppResult<Outcome>
where
    S: Stream<Item = AppResult<DaemonRunOutput>> + Unpin,
{
    let mut stdout = Vec::new();
    let mut stderr = 0_usize;
    loop {
        let message = outputs.next().await.ok_or_else(model::unavailable)??;
        match message {
            DaemonRunOutput::Stdout(bytes) => {
                if stdout
                    .len()
                    .checked_add(bytes.len())
                    .is_none_or(|n| n > wire::MAX_FRAME + 4)
                {
                    return Err(model::unavailable());
                }
                stdout.extend_from_slice(&bytes);
            }
            DaemonRunOutput::Stderr(bytes) => {
                stderr = stderr
                    .checked_add(bytes.len())
                    .filter(|n| *n <= MAX_STDERR)
                    .ok_or_else(model::unavailable)?;
            }
            DaemonRunOutput::Exit(code) => {
                if stderr != 0 {
                    return Err(model::unavailable());
                }
                return wire::reply(&stdout, correlation, code);
            }
        }
    }
}

async fn require_eof<S>(outputs: &mut S) -> AppResult<()>
where
    S: Stream<Item = AppResult<DaemonRunOutput>> + Unpin,
{
    if outputs.next().await.is_some() {
        return Err(model::unavailable());
    }
    Ok(())
}

pub(super) fn effects(request: &RuntimeRequest) -> Vec<RuntimeEffect> {
    match request.mutation.action {
        RuntimeAction::Update if request.mutation.expected_store_generation == 0 => vec![
            RuntimeEffect::Bootstrap,
            RuntimeEffect::Staging,
            RuntimeEffect::Update,
            RuntimeEffect::Cleanup,
        ],
        RuntimeAction::Update => vec![
            RuntimeEffect::Staging,
            RuntimeEffect::Update,
            RuntimeEffect::Cleanup,
        ],
        RuntimeAction::Rollback => vec![RuntimeEffect::Rollback, RuntimeEffect::Cleanup],
    }
}

pub(super) fn expected(request: &RuntimeRequest) -> ExpectedSelection {
    request
        .acknowledgements
        .iter()
        .rev()
        .find_map(|a| {
            if let EffectReceipt::Selected {
                sha256,
                generation,
                previous_sha256,
                ..
            } = &a.receipt
            {
                Some(ExpectedSelection {
                    generation: *generation,
                    current: Some(sha256.clone()),
                    previous: previous_sha256.clone(),
                })
            } else {
                None
            }
        })
        .unwrap_or_else(|| ExpectedSelection {
            generation: request.mutation.expected_store_generation,
            current: request.mutation.expected_current_sha256.clone(),
            previous: request.mutation.expected_previous_sha256.clone(),
        })
}

fn action(request: &RuntimeRequest, effect: RuntimeEffect) -> AppResult<Action> {
    let expected = expected(request);
    expected.validate()?;
    let identity = request.mutation.target_identity.clone();
    Ok(match effect {
        RuntimeEffect::Bootstrap => Action::Bootstrap {
            identity: request
                .mutation
                .bootstrap_identity
                .clone()
                .ok_or_else(model::invalid_request)?,
            expected,
        },
        RuntimeEffect::Staging => Action::Stage { identity, expected },
        RuntimeEffect::Update => Action::Update { identity, expected },
        RuntimeEffect::Rollback => Action::Rollback { identity, expected },
        RuntimeEffect::Cleanup => Action::Cleanup {
            bootstrap: request.mutation.bootstrap_identity.clone(),
            candidate: (request.mutation.action == RuntimeAction::Update).then_some(identity),
        },
    })
}

fn receipt(effect: RuntimeEffect, body: ReplyBody) -> AppResult<EffectReceipt> {
    match (effect, body) {
        (RuntimeEffect::Staging, ReplyBody::Staged { sha256, size }) => {
            Ok(EffectReceipt::Staged { sha256, size })
        }
        (
            RuntimeEffect::Bootstrap | RuntimeEffect::Update | RuntimeEffect::Rollback,
            ReplyBody::Selected {
                sha256,
                generation,
                previous_sha256,
                changed,
            },
        ) => Ok(EffectReceipt::Selected {
            sha256,
            generation,
            previous_sha256,
            changed,
        }),
        (RuntimeEffect::Cleanup, ReplyBody::Cleaned) => Ok(EffectReceipt::Cleaned),
        _ => Err(model::unavailable()),
    }
}

/// The test backend exercises dispatch/ACK/cancellation order, not SQL or
/// Kubernetes qualification. Production uses only the journal's genuine
/// nonserializable RequestOwner and IssuedEffect capabilities below.
#[async_trait]
pub(super) trait Backend: Send {
    type Permit: Send + Sync;
    fn request(&self) -> &RuntimeRequest;
    async fn recheck(&mut self) -> AppResult<()>;
    async fn issue(&mut self, effect: RuntimeEffect) -> AppResult<Self::Permit>;
    async fn dispatch(&mut self, permit: &Self::Permit, effect: RuntimeEffect) -> Dispatch;
    async fn acknowledge(&mut self, permit: &Self::Permit, receipt: EffectReceipt)
    -> AppResult<()>;
    async fn unknown(&mut self, permit: &Self::Permit) -> AppResult<RuntimeRequest>;
    async fn refused(&mut self, permit: &Self::Permit) -> AppResult<RuntimeRequest>;
    async fn cancel(&mut self) -> AppResult<RuntimeRequest>;
    async fn succeed(&mut self) -> AppResult<RuntimeRequest>;
}

pub(super) async fn run<B: Backend>(mut backend: B) -> AppResult<RuntimeRequest> {
    let sequence = effects(backend.request());
    let deadline = tokio::time::Instant::now() + OWNER_TIMEOUT;
    for effect in sequence {
        // Known pre-dispatch cancellation can settle an Admitted/Acknowledged
        // owner. An Issued COMMIT error/timeout is uncertain and is never
        // settled as a no-effect failure or retried.
        if !matches!(
            tokio::time::timeout_at(deadline, backend.recheck()).await,
            Ok(Ok(()))
        ) || backend.request().phase == model::RuntimePhase::Unknown
        {
            return backend.cancel().await;
        }
        // Recheck errors (including fresh revocation) stop before issue.
        // The second call is deliberately absent: one observation per effect.
        let issued = tokio::time::timeout_at(deadline, backend.issue(effect))
            .await
            .map_err(|_| model::unavailable())??;
        let result = tokio::time::timeout_at(deadline, backend.dispatch(&issued, effect))
            .await
            .unwrap_or(Dispatch::Unknown);
        match result {
            Dispatch::Unknown => return backend.unknown(&issued).await,
            Dispatch::Refused => return backend.refused(&issued).await,
            Dispatch::Succeeded(body) => {
                let Ok(receipt) = receipt(effect, body) else {
                    return backend.unknown(&issued).await;
                };
                // A lost ACK/COMMIT never reissues or advances another effect.
                tokio::time::timeout_at(deadline, backend.acknowledge(&issued, receipt))
                    .await
                    .map_err(|_| model::unavailable())??;
            }
        }
    }
    if !matches!(
        tokio::time::timeout_at(deadline, backend.recheck()).await,
        Ok(Ok(()))
    ) {
        return backend.cancel().await;
    }
    tokio::time::timeout_at(deadline, backend.succeed())
        .await
        .map_err(|_| model::unavailable())?
}

pub(super) struct PlatformBackend {
    pub state: ApiState,
    pub user: AuthUser,
    pub captured: CapturedPlatformCwRuntime,
    pub journal: RuntimeJournal,
    pub owner: RequestOwner,
    pub request: RuntimeRequest,
    pub correlation: Correlation,
    pub candidate: Option<Candidate>,
}

#[async_trait]
impl Backend for PlatformBackend {
    type Permit = IssuedEffect;
    fn request(&self) -> &RuntimeRequest {
        &self.request
    }
    async fn recheck(&mut self) -> AppResult<()> {
        self.captured.recheck(&self.state, &self.user).await?;
        if let Some(candidate) = &self.candidate {
            candidate.check()?;
        }
        let (supported, _, selection) = status(&self.captured.daemon(), &self.correlation).await?;
        if !supported
            || selection.pending
            || !selection.consistent
            || selection.expected()? != expected(&self.request)
        {
            return Err(model::unavailable());
        }
        Ok(())
    }
    async fn issue(&mut self, effect: RuntimeEffect) -> AppResult<IssuedEffect> {
        self.journal
            .issue(&self.owner, &self.user, self.request.checkpoint, effect)
            .await
    }
    async fn dispatch(&mut self, permit: &IssuedEffect, effect: RuntimeEffect) -> Dispatch {
        if permit.request_id() != self.request.mutation.request_id
            || permit.effect() != effect
            || permit.checkpoint() != self.request.checkpoint + 1
        {
            return Dispatch::Unknown;
        }
        let Ok(action) = action(&self.request, effect) else {
            return Dispatch::Unknown;
        };
        let candidate = if effect == RuntimeEffect::Staging {
            self.candidate.as_mut()
        } else {
            None
        };
        if effect == RuntimeEffect::Staging && candidate.is_none() {
            return Dispatch::Unknown;
        }
        role(
            &self.captured.daemon(),
            &self.correlation,
            action,
            candidate,
        )
        .await
    }
    async fn acknowledge(
        &mut self,
        permit: &IssuedEffect,
        receipt: EffectReceipt,
    ) -> AppResult<()> {
        self.request = self.journal.acknowledge(permit, receipt).await?;
        Ok(())
    }
    async fn unknown(&mut self, permit: &IssuedEffect) -> AppResult<RuntimeRequest> {
        self.journal.mark_unknown(permit).await
    }
    async fn refused(&mut self, permit: &IssuedEffect) -> AppResult<RuntimeRequest> {
        self.journal
            .fail_known(permit, KnownFailure::CommandRefused)
            .await
    }
    async fn cancel(&mut self) -> AppResult<RuntimeRequest> {
        self.journal.cancel(&self.owner).await
    }
    async fn succeed(&mut self) -> AppResult<RuntimeRequest> {
        self.journal.succeed(&self.owner).await
    }
}

pub(super) async fn status(
    client: &DaemonClient,
    correlation: &Correlation,
) -> AppResult<(
    bool,
    Option<codewire_cw_release::identity::CwPayloadIdentity>,
    wire::ObservedSelection,
)> {
    match role(client, correlation, Action::Status, None).await {
        Dispatch::Succeeded(ReplyBody::Status {
            supported_image,
            bootstrap,
            selection,
        }) => Ok((
            supported_image,
            bootstrap.map(|identity| *identity),
            *selection,
        )),
        _ => Err(model::unavailable()),
    }
}

#[cfg(test)]
#[path = "execute_tests.rs"]
mod tests;
