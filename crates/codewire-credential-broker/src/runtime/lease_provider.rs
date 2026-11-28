//! The placement's side of the broker: admission for one provider
//! operation, refresh bookkeeping, and the failures each returns.

use async_trait::async_trait;
use codewire_access::{
    BrokerOperationId, BrokerRouteId, CapabilitySlot, DerivedGrant, FirstBindSecret,
};
use codewire_daemon_proto::codewire::bridge::v1;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::lease_error::BrokerLeaseError;
use crate::antigravity_oauth::CanonicalAntigravityOAuthBundle;
use crate::bound_secret::{
    BoundSecretLeaseError, BoundSecretRow, BoundSecretSwap, EpochBoundSecret,
};
use crate::claude_oauth::CanonicalClaudeOAuthBundle;
use crate::codex_oauth::CanonicalCodexOAuthBundle;
use crate::commit_failure::CommitFailure;
use crate::github_app::GitHubAppUserOAuthBundle;
use crate::{BrokerCredentialLease, BrokerRefreshError};

/// Metadata-only description of one exact OAuth generation to refresh.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrokerCredentialRefreshRequest {
    pub refresh_id: Uuid,
    pub request_id: Uuid,
    pub kind: BrokerCredentialRefreshKind,
    pub grant: DerivedGrant,
    pub operation: BrokerOperationId,
    pub route: BrokerRouteId,
    pub material_generation: u64,
}

/// Closed provider form for a durable refresh attempt. This is metadata only;
/// it cannot carry a provider token or select an arbitrary executor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BrokerCredentialRefreshKind {
    CodexOAuth,
    GitHubAppUserOAuth,
    /// A Claude sign-in (the Anthropic slot's `ClaudeSignIn` kind).
    ClaudeOAuth,
    /// An Antigravity sign-in (the Antigravity slot's Google `OAuth` kind).
    AntigravityOAuth,
}

/// Refresh ownership or completion of a previously staged result.
/// Recovery carries no material or authority to execute a provider operation.
pub enum BrokerRefreshAdmission<R> {
    Reserved(R),
    Recovered,
}

/// Placement-specific admission for one exact provider operation.
#[async_trait]
pub trait BrokerLeaseProvider: Send + Sync {
    type Lease: BrokerCredentialLease + Send;
    type RefreshReservation: Send;
    type StartedRefresh: Send;

    /// Closed selected-key SSH operation. Provider key material is never
    /// returned to this dispatcher; an authority retains worker ownership
    /// through cancellation and terminal drain, then rechecks its exact grant.
    async fn ssh_operation(
        &self,
        _request: v1::CredentialSshRequest,
        _cancellation: tokio_util::sync::CancellationToken,
    ) -> Result<v1::credential_ssh_response::Result, BrokerLeaseError> {
        Err(BrokerLeaseError::Denied)
    }

    /// Ciphertext for the immutable application sources bound to this runtime
    /// channel. Not a provider credential lease and not an HTTP operation.
    async fn project_environment(
        &self,
        _request: v1::EnvironmentProjectionRequest,
    ) -> Result<Vec<u8>, BrokerLeaseError> {
        Err(BrokerLeaseError::Denied)
    }

    async fn project_environment_fragment(
        &self,
        _request: v1::EnvironmentProjectionRequest,
    ) -> Result<v1::EnvironmentProjectionComposition, BrokerLeaseError> {
        Err(BrokerLeaseError::Denied)
    }

    async fn lease_operation(
        &self,
        request_id: Uuid,
        capability_slot: CapabilitySlot,
        operation: BrokerOperationId,
        route: BrokerRouteId,
    ) -> Result<Self::Lease, BrokerLeaseError>;

    /// This epoch's host-bound secret grants (#4003): each secret its Pod's
    /// first bind recorded and its selected sources hold, under the
    /// projection's authority, with the placeholder its record derives.
    /// Unavailable when the epoch has grants but its environment's key
    /// couldn't be read, so no placeholder can be told from another value.
    /// A placement that serves no bound secret has none.
    fn bound_secrets(&self) -> Result<&[EpochBoundSecret], BoundSecretLeaseError> {
        Ok(&[])
    }

    /// One lease's reread of `secret`'s row for a request to `host`: its
    /// binding now, checked against the record (`binding_id`, generation and
    /// the host), and its value's version. Nothing is decrypted.
    async fn lease_bound_secret_row(
        &self,
        _secret: &FirstBindSecret,
        _host: &str,
    ) -> Result<BoundSecretRow, BoundSecretLeaseError> {
        Err(BoundSecretLeaseError::Denied)
    }

    /// `secret`'s value for the lease that read `row`: reused only within
    /// the epoch for exactly that version, as the Invariants allow, or read
    /// again under the same checks and decrypted.
    async fn lease_bound_secret_value(
        &self,
        _secret: &FirstBindSecret,
        _host: &str,
        _row: &BoundSecretRow,
    ) -> Result<Zeroizing<Vec<u8>>, BoundSecretLeaseError> {
        Err(BoundSecretLeaseError::Denied)
    }

    /// Write one swap's closed audit line, naming the environment and the
    /// user the placement acts for beside `swap`.
    fn audit_bound_secret(&self, swap: BoundSecretSwap<'_>) {
        tracing::info!(
            event = "bound_secret_swap",
            key = swap.key,
            scope = swap.scope,
            host = swap.host,
            presentation = swap.presentation,
            outcome = swap.outcome,
        );
    }

    /// Lease the Codex slot's selected login for sealed delivery to the
    /// daemon of a hosted Sandbox or of the creator's own local VM: a listed
    /// direct delivery exception (docs/dev/SECRETS-AND-CREDENTIALS.md,
    /// "Direct delivery exceptions"). The request names nothing; the
    /// placement rederives the grant, requires its dedicated `codex-login`
    /// permission, and admits only the environment creator's own Active
    /// personal Codex OAuth login, selected by the creator's own profile,
    /// rechecked around the material read.
    /// Placements that do not implement that whole predicate deny.
    async fn lease_codex_login(&self, _request_id: Uuid) -> Result<Self::Lease, BrokerLeaseError> {
        Err(BrokerLeaseError::Denied)
    }

    /// [`Self::lease_codex_login`] for the Anthropic slot's Claude sign-in:
    /// the other listed direct delivery exception. The placement requires the
    /// dedicated `claude-login` permission and admits only the environment
    /// creator's own Active personal Claude sign-in (never an API key or a
    /// Claude subscription token), selected by the creator's own profile,
    /// rechecked around the material read. Placements that do not
    /// implement that whole predicate deny.
    async fn lease_claude_login(&self, _request_id: Uuid) -> Result<Self::Lease, BrokerLeaseError> {
        Err(BrokerLeaseError::Denied)
    }

    /// Lease the Antigravity slot's active personal Google OAuth sign-in so
    /// the broker can deliver its placeholder-only login file behind
    /// front-door interception. Real Google tokens never leave the broker.
    async fn lease_antigravity_login(
        &self,
        _request_id: Uuid,
    ) -> Result<Self::Lease, BrokerLeaseError> {
        Err(BrokerLeaseError::Denied)
    }

    /// Serialize a refresh for the exact credential generation selected by an
    /// already-admitted operation. This boundary carries metadata only.
    async fn begin_credential_refresh(
        &self,
        request: BrokerCredentialRefreshRequest,
    ) -> Result<BrokerRefreshAdmission<Self::RefreshReservation>, BrokerRefreshError>;

    /// Durably mark the exact reservation as possibly sent, rechecking its
    /// original request/grant binding before provider work. An uncertain Start
    /// acknowledgement must never release a possibly started attempt to retry.
    async fn start_credential_refresh(
        &self,
        reservation: Self::RefreshReservation,
    ) -> Result<Self::StartedRefresh, BrokerRefreshError>;

    /// Store and promote a validated provider bundle without returning it to
    /// the guest or a material-free authority RPC.
    /// Durably publish the provider's rotated material. Success is not an
    /// authorization to use it: the broker obtains a fresh operation lease
    /// after this call before preparing the original provider request.
    async fn commit_credential_refresh(
        &self,
        permit: Self::StartedRefresh,
        material: CanonicalCodexOAuthBundle,
    ) -> Result<(), CommitFailure<Self::StartedRefresh>>;

    /// Narrow GitHub App publication hook. The only accepted material is the
    /// canonical protected App bundle; raw CLI token bytes and arbitrary
    /// provider material cannot cross this boundary.
    async fn commit_github_app_refresh(
        &self,
        permit: Self::StartedRefresh,
        _material: GitHubAppUserOAuthBundle,
    ) -> Result<(), CommitFailure<Self::StartedRefresh>> {
        Err(CommitFailure::returned(permit, BrokerRefreshError::Denied))
    }

    /// Narrow Claude sign-in publication hook. The only accepted material is
    /// the canonical sign-in envelope. Placements without Claude sign-ins deny.
    async fn commit_claude_oauth_refresh(
        &self,
        permit: Self::StartedRefresh,
        _material: CanonicalClaudeOAuthBundle,
    ) -> Result<(), CommitFailure<Self::StartedRefresh>> {
        Err(CommitFailure::returned(permit, BrokerRefreshError::Denied))
    }

    /// Narrow Antigravity sign-in publication hook. The only accepted material
    /// is the canonical Google OAuth sign-in envelope.
    async fn commit_antigravity_oauth_refresh(
        &self,
        permit: Self::StartedRefresh,
        _material: CanonicalAntigravityOAuthBundle,
    ) -> Result<(), CommitFailure<Self::StartedRefresh>> {
        Err(CommitFailure::returned(permit, BrokerRefreshError::Denied))
    }

    /// Release a reservation only before Start. Absence of replacement material
    /// does not prove that a started provider request was safe to replay.
    async fn abort_credential_refresh(
        &self,
        reservation: Self::RefreshReservation,
    ) -> Result<(), BrokerRefreshError>;

    /// Invalidate the admitted generation after rejection or an ambiguous
    /// possibly-sent exchange. This must never make the old token retryable.
    async fn fail_credential_refresh(
        &self,
        permit: Self::StartedRefresh,
    ) -> Result<(), BrokerRefreshError>;

    /// Close the exact started attempt as rate-limited, its provider having
    /// answered 429 in full, so the sign-in waits `wait_seconds` instead of
    /// needing Reconnect (#4975). A placement without the record fails the
    /// attempt, as before: closed, never retried.
    async fn rate_limit_credential_refresh(
        &self,
        permit: Self::StartedRefresh,
        _wait_seconds: u64,
    ) -> Result<RateLimitClose, BrokerRefreshError> {
        self.fail_credential_refresh(permit)
            .await
            .map(|()| RateLimitClose::Failed)
    }

    /// Wait until every non-cancellable placement operation started by a
    /// broker request has finished. The bridge calls this only after it has
    /// stopped admitting requests and aborted the remaining request futures,
    /// before their authority channel is allowed to close.
    async fn wait_for_active_operations(&self) -> Result<(), BrokerRefreshError>;
}

/// How a rate-limited attempt was closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RateLimitClose {
    /// Recorded: the sign-in waits, and its next refresh is the one retry.
    Waiting,
    /// Failed instead (the retry itself, or a placement without the record).
    Failed,
}
