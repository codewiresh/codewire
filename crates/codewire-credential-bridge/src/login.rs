//! The sealed agent logins on the admitted epoch: the listed direct delivery
//! exceptions (docs/dev/SECRETS-AND-CREDENTIALS.md, "Direct delivery
//! exceptions"). The workspace daemon asks for the Sandbox creator's own
//! personal Codex ChatGPT login to write Codex's `auth.json`, and for the
//! creator's own Claude sign-in to write `claudeAiOauth` in Claude Code's
//! `.credentials.json`. Both share one path; only the frames and the sealed
//! format differ.
//!
//! Deliberately absent from `respond`: no HTTP request can ask for a login.
//! The request names no credential, owner or profile; the broker decides
//! delivery. A fresh recipient key is generated per request and consumed when
//! opening, so the relay never holds anything that could open the login.

use codewire_workload_secrets::{
    CodexLoginContext, MAX_CODEX_LOGIN_LIFETIME_MS, MAX_SEALED_CLAUDE_LOGIN_BYTES,
    MAX_SEALED_CODEX_LOGIN_BYTES, OpenedClaudeLogin, OpenedCodexLogin, ProjectionRecipient,
};

use super::*;

/// How long one login request may take. It stays well inside the broker's
/// thirty-second window, leaving room for clock skew between the two.
pub const LOGIN_REQUEST_LIFETIME: Duration = Duration::from_secs(20);
const _: () = assert!(LOGIN_REQUEST_LIFETIME.as_millis() < MAX_CODEX_LOGIN_LIFETIME_MS as u128);

/// Which agent's login a request asks for. A response frame of the other kind
/// never answers it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum LoginKind {
    Codex,
    Claude,
}

impl LoginKind {
    fn capability(self) -> &'static str {
        match self {
            Self::Codex => codewire_daemon_proto::CREDENTIAL_BRIDGE_CAPABILITY_CODEX_LOGIN,
            Self::Claude => codewire_daemon_proto::CREDENTIAL_BRIDGE_CAPABILITY_CLAUDE_LOGIN,
        }
    }

    fn max_sealed_bytes(self) -> usize {
        match self {
            Self::Codex => MAX_SEALED_CODEX_LOGIN_BYTES,
            Self::Claude => MAX_SEALED_CLAUDE_LOGIN_BYTES,
        }
    }

    fn request(self, request_id: String, recipient: Vec<u8>, deadline: u64) -> GuestPayload {
        match self {
            Self::Codex => GuestPayload::CodexLogin(v1::CodexLoginRequest {
                request_id,
                recipient_public_key: recipient,
                deadline_unix_ms: deadline,
            }),
            Self::Claude => GuestPayload::ClaudeLogin(v1::ClaudeLoginRequest {
                request_id,
                recipient_public_key: recipient,
                deadline_unix_ms: deadline,
            }),
        }
    }
}

type GuestPayload = v1::credential_bridge_guest_message::Payload;

/// The logins one epoch's host listed in its Open.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct LoginCapabilities {
    codex: bool,
    claude: bool,
}

impl LoginCapabilities {
    pub(super) fn from_open(capabilities: &[String]) -> Self {
        let listed = |kind: LoginKind| {
            capabilities
                .iter()
                .any(|capability| capability == kind.capability())
        };
        Self {
            codex: listed(LoginKind::Codex),
            claude: listed(LoginKind::Claude),
        }
    }

    fn serves(self, kind: LoginKind) -> bool {
        match kind {
            LoginKind::Codex => self.codex,
            LoginKind::Claude => self.claude,
        }
    }
}

pub(super) struct PendingLogin {
    pub epoch: u64,
    pub kind: LoginKind,
    // None is a cancelled tombstone; it keeps its slot in the shared bound
    // until a response or epoch loss, like projections.
    pub response: Option<oneshot::Sender<Result<Vec<u8>, BridgeFailure>>>,
}

/// Why no login was delivered. Only [`Self::Denied`] is a decision about the
/// login; a writer removes what it wrote only then.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoginFailure {
    /// This epoch's host did not list the login's capability (an older
    /// broker or relay). Nothing was sent: an older host ends its epoch on an
    /// unknown frame.
    Unsupported,
    /// The broker denied delivery: no login is deliverable now (another
    /// credential form, a credential needing Reconnect, a revoked,
    /// organization-owned or another user's credential, or the agent not
    /// selected).
    Denied,
    /// Transient: no admitted epoch, the epoch was lost or replaced, the
    /// request limit was reached, the deadline passed, or the broker was
    /// unavailable. Retry later.
    Unavailable,
}

impl CredentialBridge {
    /// Whether the currently admitted epoch's host serves [`Self::codex_login`].
    pub async fn supports_codex_login(&self) -> bool {
        self.supports_login(LoginKind::Codex).await
    }

    /// Whether the currently admitted epoch's host serves [`Self::claude_login`].
    pub async fn supports_claude_login(&self) -> bool {
        self.supports_login(LoginKind::Claude).await
    }

    async fn supports_login(&self, kind: LoginKind) -> bool {
        self.inner
            .lock()
            .await
            .active
            .as_ref()
            .is_some_and(|active| active.logins.serves(kind))
    }

    /// Ask the broker for the Sandbox creator's personal Codex login, sealed
    /// to a fresh recipient key this call holds, and open it. Sent only on an
    /// epoch whose host listed "codex-login". The login is bound to this
    /// environment, generation, request, recipient and deadline; the result
    /// also names the credential version it came from.
    pub async fn codex_login(&self) -> Result<OpenedCodexLogin, LoginFailure> {
        let (sealed, recipient, context) = self.sealed_login(LoginKind::Codex).await?;
        recipient
            .open_codex_login(&sealed, &context, login_now_unix_ms()?)
            .map_err(|_| LoginFailure::Unavailable)
    }

    /// [`Self::codex_login`] for the Sandbox creator's personal Claude
    /// sign-in, sent only on an epoch whose host listed "claude-login".
    pub async fn claude_login(&self) -> Result<OpenedClaudeLogin, LoginFailure> {
        let (sealed, recipient, context) = self.sealed_login(LoginKind::Claude).await?;
        recipient
            .open_claude_login(&sealed, &context, login_now_unix_ms()?)
            .map_err(|_| LoginFailure::Unavailable)
    }

    /// Send one login request of `kind` on the active epoch and wait for its
    /// sealed answer, which only the returned recipient can open.
    async fn sealed_login(
        &self,
        kind: LoginKind,
    ) -> Result<(Vec<u8>, ProjectionRecipient, CodexLoginContext), LoginFailure> {
        let recipient = ProjectionRecipient::new();
        let request_id = Uuid::new_v4();
        let deadline = tokio::time::Instant::now() + LOGIN_REQUEST_LIFETIME;
        let context = CodexLoginContext {
            environment_id: *self.environment_id.as_bytes(),
            environment_generation: self.environment_generation,
            request_id: *request_id.as_bytes(),
            deadline_unix_ms: login_now_unix_ms()?
                .checked_add(LOGIN_REQUEST_LIFETIME.as_millis() as u64)
                .ok_or(LoginFailure::Unavailable)?,
        };
        let request_id = request_id.to_string();
        let (epoch, output) = {
            let state = self.inner.lock().await;
            let active = state.active.as_ref().ok_or(LoginFailure::Unavailable)?;
            if !active.logins.serves(kind) {
                return Err(LoginFailure::Unsupported);
            }
            if state.in_flight() >= CREDENTIAL_BRIDGE_MAX_IN_FLIGHT {
                return Err(LoginFailure::Unavailable);
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
        .map_err(|_| LoginFailure::Unavailable)?
        .map_err(|_| LoginFailure::Unavailable)?;
        let (response_tx, response_rx) = oneshot::channel();
        {
            let mut state = self.inner.lock().await;
            // The epoch may have been replaced while waiting; its capability
            // is per epoch and must still hold for the one we send on.
            let active = state
                .active
                .as_ref()
                .filter(|active| active.epoch == epoch)
                .ok_or(LoginFailure::Unavailable)?;
            if !active.logins.serves(kind) {
                return Err(LoginFailure::Unsupported);
            }
            if state.in_flight() >= CREDENTIAL_BRIDGE_MAX_IN_FLIGHT
                || state.contains_request(&request_id)
            {
                return Err(LoginFailure::Unavailable);
            }
            state.logins.insert(
                request_id.clone(),
                PendingLogin {
                    epoch,
                    kind,
                    response: Some(response_tx),
                },
            );
            // No suspension between registration and dispatch.
            permit.send(Ok(guest_message(kind.request(
                request_id.clone(),
                recipient.public_key().to_vec(),
                context.deadline_unix_ms,
            ))));
        }
        let mut cancellation = PendingCancellation::new(self.clone(), request_id.clone(), epoch);
        let sealed = match tokio::time::timeout_at(deadline, response_rx).await {
            Ok(Ok(Ok(sealed))) => sealed,
            Ok(Ok(Err(BridgeFailure::Denied))) => {
                cancellation.disarm();
                return Err(LoginFailure::Denied);
            }
            Ok(Ok(Err(_))) | Ok(Err(_)) => {
                cancellation.disarm();
                return Err(LoginFailure::Unavailable);
            }
            Err(_) => {
                self.cancel(&request_id, epoch).await;
                cancellation.disarm();
                return Err(LoginFailure::Unavailable);
            }
        };
        cancellation.disarm();
        // A login from a replaced (draining) or lost epoch is not released.
        require_active_epoch(&*self.inner.lock().await, epoch)
            .map_err(|_| LoginFailure::Unavailable)?;
        Ok((sealed, recipient, context))
    }

    pub(super) async fn apply_codex_login_response(
        &self,
        epoch: u64,
        response: v1::CodexLoginResponse,
    ) -> Result<(), Status> {
        use v1::codex_login_response::Result as LoginResult;
        let result = match response.result {
            Some(LoginResult::SealedLogin(bytes)) => Some(Ok(bytes)),
            Some(LoginResult::Failure(reason)) => Some(Err(reason)),
            None => None,
        };
        self.apply_login_response(epoch, LoginKind::Codex, &response.request_id, result)
            .await
    }

    pub(super) async fn apply_claude_login_response(
        &self,
        epoch: u64,
        response: v1::ClaudeLoginResponse,
    ) -> Result<(), Status> {
        use v1::claude_login_response::Result as LoginResult;
        let result = match response.result {
            Some(LoginResult::SealedLogin(bytes)) => Some(Ok(bytes)),
            Some(LoginResult::Failure(reason)) => Some(Err(reason)),
            None => None,
        };
        self.apply_login_response(epoch, LoginKind::Claude, &response.request_id, result)
            .await
    }

    /// Release one login answer to its request. A malformed answer, or one
    /// for a request of another kind or epoch, ends the epoch.
    async fn apply_login_response(
        &self,
        epoch: u64,
        kind: LoginKind,
        request_id: &str,
        result: Option<Result<Vec<u8>, i32>>,
    ) -> Result<(), Status> {
        let result = match result {
            // The codec bounds again before decrypting; this bound keeps an
            // oversized frame from being retained at all.
            Some(Ok(bytes)) if !bytes.is_empty() && bytes.len() <= kind.max_sealed_bytes() => {
                Ok(bytes)
            }
            Some(Err(reason)) => Err(match v1::CredentialBridgeFailureReason::try_from(reason) {
                Ok(v1::CredentialBridgeFailureReason::Denied) => BridgeFailure::Denied,
                Ok(v1::CredentialBridgeFailureReason::Unavailable) => BridgeFailure::Unavailable,
                _ => return Err(invalid_host_frame()),
            }),
            _ => return Err(invalid_host_frame()),
        };
        let pending = {
            let mut state = self.inner.lock().await;
            require_live_epoch(&state, epoch)?;
            take_registered(&mut state.logins, request_id, |pending| {
                pending.epoch == epoch && pending.kind == kind
            })?
        };
        if let Some(sender) = pending.response {
            // A cancelled caller is normal and does not poison the epoch.
            let _ = sender.send(result);
        }
        Ok(())
    }
}

pub(super) fn take_logins(state: &mut BridgeState, epoch: u64) -> Vec<PendingLogin> {
    let ids: Vec<_> = state
        .logins
        .iter()
        .filter(|(_, pending)| pending.epoch == epoch)
        .map(|(id, _)| id.clone())
        .collect();
    ids.into_iter()
        .filter_map(|id| state.logins.remove(&id))
        .collect()
}

pub(super) fn fail_logins(pending: Vec<PendingLogin>) {
    for request in pending {
        if let Some(sender) = request.response {
            let _ = sender.send(Err(BridgeFailure::Unavailable));
        }
    }
}

fn login_now_unix_ms() -> Result<u64, LoginFailure> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .ok_or(LoginFailure::Unavailable)
}

#[cfg(test)]
mod claude_tests;
#[cfg(test)]
mod tests;
