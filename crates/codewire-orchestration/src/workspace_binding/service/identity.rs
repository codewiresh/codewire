//! `IssueIdentityToken` (docs/dev/SANDBOX-IDENTITY.md, "Minting"). The
//! caller is authenticated exactly as every bound method's is: TokenReview of
//! the Pod-bound token, the live Pod called from its own address, and the
//! recorded binding confirmed against the live chain, while the reviewed
//! token is still valid. Its limits are minting's own
//! ([`crate::identity::mint::limits`]), never the binding's, so mints can't
//! starve binding renewals; the per-Sandbox and per-replica ones apply before
//! any TokenReview.

use std::net::IpAddr;

use axum::http::HeaderMap;
use codewire_proto::codewire::internal::v1::IssueIdentityTokenResponse;
use codewire_server_core::pod_identity::pre_review_bearer_filter;
use connectrpc::ServiceResult;

use super::{BindError, WorkspaceBindingState, identity_error, still_valid};
use crate::identity::audience::CanonicalAudience;
use crate::identity::mint::MintRefusal;
use crate::workspace_binding::metrics;

/// The longest `resource` an `IssueIdentityToken` names, in bytes.
pub(crate) const MAX_RESOURCE_BYTES: usize = codewire_daemon_proto::IDENTITY_RESOURCE_MAX_BYTES;

/// Why `IssueIdentityToken` answered no token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IdentityCallError {
    /// Authentication or the binding refused the caller, as for any bound
    /// method.
    Binding(BindError),
    /// Minting refused, under one of the spec's names.
    Refused(MintRefusal),
}

impl From<BindError> for IdentityCallError {
    fn from(error: BindError) -> Self {
        Self::Binding(error)
    }
}

impl From<MintRefusal> for IdentityCallError {
    fn from(refusal: MintRefusal) -> Self {
        Self::Refused(refusal)
    }
}

impl IdentityCallError {
    /// The metric's result code: the Connect code, never a refusal name.
    fn code(self) -> &'static str {
        match self {
            Self::Binding(error) => error.code(),
            Self::Refused(refusal) => match refusal {
                MintRefusal::InvalidTarget => "invalid_argument",
                MintRefusal::NotRunning => "failed_precondition",
                MintRefusal::IdentityStopped => "permission_denied",
                MintRefusal::ResourceExhausted => "resource_exhausted",
                MintRefusal::IdentityUnavailable | MintRefusal::KeyNotYetPublished => "unavailable",
            },
        }
    }

    pub(crate) fn connect(self) -> connectrpc::ConnectError {
        match self {
            Self::Binding(error) => error.connect(),
            Self::Refused(refusal) => refusal.connect(),
        }
    }
}

impl WorkspaceBindingState {
    pub(crate) async fn issue_identity_token(
        &self,
        headers: &HeaderMap,
        peer: Option<IpAddr>,
        resource: &str,
    ) -> Result<IssueIdentityTokenResponse, IdentityCallError> {
        let minting = self
            .identity
            .as_deref()
            .ok_or(MintRefusal::IdentityUnavailable)?;
        // The RPC's body limit fits a resource this long; a registration may
        // be longer, and is then unreachable from a Sandbox.
        if resource.len() > MAX_RESOURCE_BYTES {
            return Err(MintRefusal::InvalidTarget.into());
        }
        let audience =
            CanonicalAudience::parse(resource).map_err(|_| MintRefusal::InvalidTarget)?;

        // Before any TokenReview: the Sandbox's and the replica's limits,
        // then garbage.
        let peer = peer.ok_or(BindError::Unavailable)?;
        if !minting.limits().admit_peer(peer) {
            return Err(MintRefusal::ResourceExhausted.into());
        }
        pre_review_bearer_filter(headers).map_err(identity_error)?;
        let identity = {
            let _slot = minting
                .limits()
                .review_slot()
                .await
                .ok_or(MintRefusal::ResourceExhausted)?;
            self.review(headers).await?
        };
        self.in_sandbox_namespace(&identity)?;
        let caller = self.attest(identity, peer, None).await?;
        let bound = self.bound_caller(caller).await?;
        still_valid(&bound.caller.identity)?;

        let issued = minting
            .mint(
                &bound.binding.environment_id,
                audience.as_str(),
                chrono::Utc::now(),
            )
            .await?;
        Ok(IssueIdentityTokenResponse {
            token: issued.token.to_string(),
            expires_at: issued.expires_at,
            ..Default::default()
        })
    }
}

pub(super) fn observe(
    result: Result<IssueIdentityTokenResponse, IdentityCallError>,
) -> ServiceResult<IssueIdentityTokenResponse> {
    const METHOD: &str = "issue_identity_token";
    match result {
        Ok(response) => {
            metrics::observe_request(METHOD, "ok");
            connectrpc::Response::ok(response)
        }
        Err(error) => {
            metrics::observe_request(METHOD, error.code());
            Err(error.connect())
        }
    }
}
