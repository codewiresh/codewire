//! The bound daemon's sandbox identity socket
//! (`docs/dev/SANDBOX-IDENTITY.md`, "In the Sandbox"), served from the
//! binding client's `IssueIdentityToken`, and the token cache it shares with
//! the identity token files.

use std::path::Path;
use std::sync::Arc;

use codewire_daemon::identity_socket::{
    self, IdentityRefusal, IdentityTokenSource, IdentityTokens, IssuedIdentityToken,
};

use crate::hosted_binding::BindingClient;

pub(crate) struct BindingTokens(Arc<BindingClient>);

/// The one token cache of the bound daemon.
pub(crate) type SandboxTokens = Arc<IdentityTokens<BindingTokens>>;

/// The cache, minting through the binding client.
pub(crate) fn tokens(client: Arc<BindingClient>) -> SandboxTokens {
    Arc::new(IdentityTokens::new(BindingTokens(client)))
}

impl IdentityTokenSource for BindingTokens {
    async fn issue(&self, resource: &str) -> Result<IssuedIdentityToken, IdentityRefusal> {
        self.0.issue_identity_token(resource).await
    }
}

/// Serve the socket at `path` for the life of the daemon. A socket that
/// can't be bound is logged; `cw identity token` then says it is not in a
/// cloud Sandbox.
pub(crate) fn spawn(path: &Path, tokens: SandboxTokens) {
    match identity_socket::bind(path) {
        Ok((listener, platform)) => {
            tokio::spawn(async move {
                // Recorded while served, so SSH socket forwards refuse it.
                let _platform = platform;
                let served = identity_socket::serve(listener, tokens, std::future::pending()).await;
                if let Err(error) = served {
                    tracing::warn!(error = %error, "sandbox identity socket stopped");
                }
            });
        }
        Err(error) => tracing::warn!(error = %error, "sandbox identity socket unavailable"),
    }
}
