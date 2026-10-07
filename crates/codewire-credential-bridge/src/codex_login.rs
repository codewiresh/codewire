//! The sealed Codex login on the admitted epoch: the one listed direct
//! delivery exception (docs/dev/SECRETS-AND-CREDENTIALS.md, "Direct delivery
//! exceptions"). The workspace daemon asks for the Sandbox creator's own
//! personal Codex ChatGPT login to write Codex's `auth.json`.
//!
//! Deliberately absent from `respond`: no HTTP request can ask for it. The
//! request names no credential, owner or profile; the broker decides delivery.
//! A fresh recipient key is generated per request and consumed when opening,
//! so the relay never holds anything that could open the login.

use codewire_workload_secrets::{
    CodexLoginContext, MAX_CODEX_LOGIN_LIFETIME_MS, MAX_SEALED_CODEX_LOGIN_BYTES, OpenedCodexLogin,
    ProjectionRecipient,
};

use super::*;

/// How long one login request may take. It stays well inside the broker's
/// thirty-second window, leaving room for clock skew between the two.
pub const CODEX_LOGIN_REQUEST_LIFETIME: Duration = Duration::from_secs(20);
const _: () =
    assert!(CODEX_LOGIN_REQUEST_LIFETIME.as_millis() < MAX_CODEX_LOGIN_LIFETIME_MS as u128);

pub(super) struct PendingCodexLogin {
    pub epoch: u64,
    // None is a cancelled tombstone; it keeps its slot in the shared bound
    // until a response or epoch loss, like projections.
    pub response: Option<oneshot::Sender<Result<Vec<u8>, BridgeFailure>>>,
}

/// Why no login was delivered. Only [`Self::Denied`] is a decision about the
/// login; the writer removes what it wrote only then.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodexLoginFailure {
    /// This epoch's host did not list "codex-login" (an older broker or
    /// relay). Nothing was sent: an older host ends its epoch on an unknown
    /// frame.
    Unsupported,
    /// The broker denied delivery: no login is deliverable now (an API key, a
    /// credential needing Reconnect, a revoked, organization-owned or another
    /// user's credential, or Codex not selected).
    Denied,
    /// Transient: no admitted epoch, the epoch was lost or replaced, the
    /// request limit was reached, the deadline passed, or the broker was
    /// unavailable. Retry later.
    Unavailable,
}

impl CredentialBridge {
    /// Whether the currently admitted epoch's host serves [`Self::codex_login`].
    pub async fn supports_codex_login(&self) -> bool {
        self.inner
            .lock()
            .await
            .active
            .as_ref()
            .is_some_and(|active| active.codex_login)
    }

    /// Ask the broker for the Sandbox creator's personal Codex login, sealed
    /// to a fresh recipient key this call holds, and open it. Sent only on an
    /// epoch whose host listed "codex-login". The login is bound to this
    /// environment, generation, request, recipient and deadline; the result
    /// also names the credential version it came from.
    pub async fn codex_login(&self) -> Result<OpenedCodexLogin, CodexLoginFailure> {
        let recipient = ProjectionRecipient::new();
        let request_id = Uuid::new_v4();
        let deadline = tokio::time::Instant::now() + CODEX_LOGIN_REQUEST_LIFETIME;
        let context = CodexLoginContext {
            environment_id: *self.environment_id.as_bytes(),
            environment_generation: self.environment_generation,
            request_id: *request_id.as_bytes(),
            deadline_unix_ms: login_now_unix_ms()?
                .checked_add(CODEX_LOGIN_REQUEST_LIFETIME.as_millis() as u64)
                .ok_or(CodexLoginFailure::Unavailable)?,
        };
        let request_id = request_id.to_string();
        let (epoch, output) = {
            let state = self.inner.lock().await;
            let active = state
                .active
                .as_ref()
                .ok_or(CodexLoginFailure::Unavailable)?;
            if !active.codex_login {
                return Err(CodexLoginFailure::Unsupported);
            }
            if state.in_flight() >= CREDENTIAL_BRIDGE_MAX_IN_FLIGHT {
                return Err(CodexLoginFailure::Unavailable);
            }
            (active.epoch, active.output.clone())
        };
        // Reserve before registration: cancellation while the output queue is
        // full leaves no tombstone for a request that was never sent.
        let permit = tokio::time::timeout_at(
            deadline.min(tokio::time::Instant::now() + HOST_SEND_TIMEOUT),
            output.reserve_owned(),
        )
        .await
        .map_err(|_| CodexLoginFailure::Unavailable)?
        .map_err(|_| CodexLoginFailure::Unavailable)?;
        let (response_tx, response_rx) = oneshot::channel();
        {
            let mut state = self.inner.lock().await;
            // The epoch may have been replaced while waiting; its capability
            // is per epoch and must still hold for the one we send on.
            let active = state
                .active
                .as_ref()
                .filter(|active| active.epoch == epoch)
                .ok_or(CodexLoginFailure::Unavailable)?;
            if !active.codex_login {
                return Err(CodexLoginFailure::Unsupported);
            }
            if state.in_flight() >= CREDENTIAL_BRIDGE_MAX_IN_FLIGHT
                || state.contains_request(&request_id)
            {
                return Err(CodexLoginFailure::Unavailable);
            }
            state.codex_logins.insert(
                request_id.clone(),
                PendingCodexLogin {
                    epoch,
                    response: Some(response_tx),
                },
            );
            // No suspension between registration and dispatch.
            permit.send(Ok(guest_message(
                v1::credential_bridge_guest_message::Payload::CodexLogin(v1::CodexLoginRequest {
                    request_id: request_id.clone(),
                    recipient_public_key: recipient.public_key().to_vec(),
                    deadline_unix_ms: context.deadline_unix_ms,
                }),
            )));
        }
        let mut cancellation = PendingCancellation::new(self.clone(), request_id.clone(), epoch);
        let sealed = match tokio::time::timeout_at(deadline, response_rx).await {
            Ok(Ok(Ok(sealed))) => sealed,
            Ok(Ok(Err(BridgeFailure::Denied))) => {
                cancellation.disarm();
                return Err(CodexLoginFailure::Denied);
            }
            Ok(Ok(Err(_))) | Ok(Err(_)) => {
                cancellation.disarm();
                return Err(CodexLoginFailure::Unavailable);
            }
            Err(_) => {
                self.cancel(&request_id, epoch).await;
                cancellation.disarm();
                return Err(CodexLoginFailure::Unavailable);
            }
        };
        cancellation.disarm();
        // A login from a replaced (draining) or lost epoch is not released.
        require_active_epoch(&*self.inner.lock().await, epoch)
            .map_err(|_| CodexLoginFailure::Unavailable)?;
        recipient
            .open_codex_login(&sealed, &context, login_now_unix_ms()?)
            .map_err(|_| CodexLoginFailure::Unavailable)
    }

    pub(super) async fn apply_codex_login_response(
        &self,
        epoch: u64,
        response: v1::CodexLoginResponse,
    ) -> Result<(), Status> {
        use v1::codex_login_response::Result as LoginResult;
        let result = match response.result {
            // The codec bounds again before decrypting; this bound keeps an
            // oversized frame from being retained at all.
            Some(LoginResult::SealedLogin(bytes))
                if !bytes.is_empty() && bytes.len() <= MAX_SEALED_CODEX_LOGIN_BYTES =>
            {
                Ok(bytes)
            }
            Some(LoginResult::Failure(reason)) => {
                Err(match v1::CredentialBridgeFailureReason::try_from(reason) {
                    Ok(v1::CredentialBridgeFailureReason::Denied) => BridgeFailure::Denied,
                    Ok(v1::CredentialBridgeFailureReason::Unavailable) => {
                        BridgeFailure::Unavailable
                    }
                    _ => return Err(invalid_host_frame()),
                })
            }
            _ => return Err(invalid_host_frame()),
        };
        let pending = {
            let mut state = self.inner.lock().await;
            require_live_epoch(&state, epoch)?;
            take_registered(&mut state.codex_logins, &response.request_id, |pending| {
                pending.epoch == epoch
            })?
        };
        if let Some(sender) = pending.response {
            // A cancelled caller is normal and does not poison the epoch.
            let _ = sender.send(result);
        }
        Ok(())
    }
}

pub(super) fn take_codex_logins(state: &mut BridgeState, epoch: u64) -> Vec<PendingCodexLogin> {
    let ids: Vec<_> = state
        .codex_logins
        .iter()
        .filter(|(_, pending)| pending.epoch == epoch)
        .map(|(id, _)| id.clone())
        .collect();
    ids.into_iter()
        .filter_map(|id| state.codex_logins.remove(&id))
        .collect()
}

pub(super) fn fail_codex_logins(pending: Vec<PendingCodexLogin>) {
    for request in pending {
        if let Some(sender) = request.response {
            let _ = sender.send(Err(BridgeFailure::Unavailable));
        }
    }
}

fn login_now_unix_ms() -> Result<u64, CodexLoginFailure> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .ok_or(CodexLoginFailure::Unavailable)
}

#[cfg(test)]
mod tests;
