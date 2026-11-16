//! Telling a credential's provider when Codewire revokes it (#4717). One
//! owned worker reads the token, publishes Codewire's revoke and only then
//! asks the provider, so a provider that does not confirm leaves the
//! credential revoked in Codewire, and neither a client that disconnects nor
//! the mutation's deadline can cancel the ask once the revoke has committed.
//! Nothing retries: the held material is dropped, zeroed, once the provider
//! answers.

use std::sync::Arc;
use std::time::Duration;

use codewire_access::{
    CredentialAuthKind, CredentialId, CredentialMetadata, CredentialStatus, Owner,
};
use codewire_credential_broker::provider_oauth::{ProviderRevocation, RevocationFailure, codex};
use codewire_credential_broker::{BrokerUpstreamTransport, GitHubAppUserOAuthBundle};
use codewire_protected_store::ProtectedValue;
use codewire_proto::codewire::v1 as proto;
use codewire_server_core::auth::CredentialMutationAuthority;
use tokio::sync::oneshot;

use super::{CredentialMutationOwner, Error, Scope, Shared, publication};

/// How long a revoke waits for the provider's answer once Codewire's revoke
/// has committed: the revocation's own 8 s bound and a margin. The worker
/// still finishes the ask if this runs out.
const PROVIDER_WAIT: Duration = Duration::from_secs(10);

/// The one-route transports a provider revocation uses.
pub struct RevocationTransports {
    /// `HttpProvider::CodexTokenRevocation`.
    pub codex: Arc<dyn BrokerUpstreamTransport>,
    /// `HttpProvider::GitHubAppTokenRevocation`, when the GitHub App is
    /// configured.
    pub github: Option<Arc<dyn BrokerUpstreamTransport>>,
}

/// What the provider said when Codewire revoked the credential.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProviderOutcome {
    /// Nothing was asked: the credential was not active, or this service
    /// does not revoke at providers.
    NotAsked,
    /// The provider offers no revocation Codewire can ask for.
    NotAvailable,
    /// Codewire could not read the stored token, so the provider was not
    /// asked.
    NotRead,
    Asked(ProviderRevocation),
}

/// What Codewire read for the provider before revoking.
enum Held {
    Nothing,
    NoEndpoint,
    NotRead,
    Unreadable,
    Codex(ProtectedValue),
    GitHubApp(GitHubAppUserOAuthBundle),
}

impl CredentialMutationOwner {
    /// Revokes the exact revision, then asks its provider to revoke its
    /// token, both in one owned worker. Codewire's own revoke failing asks
    /// nothing.
    pub(crate) async fn revoke(
        &self,
        authority: CredentialMutationAuthority,
        id: String,
        revision: u64,
    ) -> Result<(Option<CredentialMetadata>, ProviderOutcome), Error> {
        let id = CredentialId::parse(id).map_err(|_| Error::InvalidInput)?;
        if revision == 0 || i64::try_from(revision).is_err() {
            return Err(Error::InvalidInput);
        }
        let scope = Scope::new(
            authority,
            self.stop.child_token(),
            self.shared.mutation_timeout,
        )?;
        let deadline = scope.deadline;
        let cancelled = scope.cancel.clone();
        let _guard = cancelled.clone().drop_guard();
        let (published, publication) = oneshot::channel();
        let (answered, answer) = oneshot::channel();
        {
            let accepting = self.accepting.lock().map_err(|_| Error::Unavailable)?;
            let permit = self.admit(*accepting)?;
            let shared = self.shared.clone();
            self.workers.spawn(async move {
                let _permit = permit;
                let held = held_for_revocation(&shared, &scope.owner, &id, revision).await;
                let result = publication::lifecycle(&shared, &scope, id, revision, false).await;
                let committed = result.is_ok();
                let _ = published.send(result);
                let outcome = if committed {
                    ask_provider(&shared, held).await
                } else {
                    ProviderOutcome::NotAsked
                };
                let _ = answered.send(outcome);
            });
        }
        let metadata = tokio::select! {
            biased;
            _ = cancelled.cancelled() => Err(Error::Cancelled),
            _ = tokio::time::sleep_until(deadline) => Err(Error::PublicationUnknown),
            result = publication => result.map_err(|_| Error::PublicationUnknown)?,
        }?;
        // Codewire's revoke has committed; the provider's answer is only
        // reported, and a missing one is reported as unconfirmed.
        let outcome = tokio::time::timeout(PROVIDER_WAIT, answer)
            .await
            .ok()
            .and_then(Result::ok)
            .unwrap_or(ProviderOutcome::Asked(ProviderRevocation::Failed(
                RevocationFailure::Unavailable,
            )));
        Ok((metadata, outcome))
    }
}

async fn held_for_revocation(
    shared: &Shared,
    owner: &Owner,
    id: &CredentialId,
    revision: u64,
) -> Held {
    if shared.revocation.is_none() {
        return Held::Nothing;
    }
    // A failed read is reported once the revoke commits; a missing or
    // foreign credential fails the revoke itself.
    let Ok(record) = shared.store.record(owner, id).await else {
        return Held::NotRead;
    };
    // The revoke itself answers a stale or inactive revision.
    if record.metadata.status != CredentialStatus::Active
        || record.version.revocation_generation != revision
    {
        return Held::Nothing;
    }
    let provider = record.metadata.provider.as_str();
    if record.metadata.authentication_kind != CredentialAuthKind::OAuth
        || !matches!(provider, "openai" | "github")
    {
        return Held::NoEndpoint;
    }
    let Ok(material) = shared
        .store
        .read_for_oauth_refresh(owner, id, record.version)
        .await
    else {
        return Held::NotRead;
    };
    if provider == "openai" {
        return Held::Codex(material);
    }
    // A connection from before the App holds a raw token the App cannot
    // revoke; its owner revokes it at GitHub.
    if !GitHubAppUserOAuthBundle::is_tagged(material.expose_secret()) {
        return Held::NoEndpoint;
    }
    GitHubAppUserOAuthBundle::parse(material.expose_secret())
        .map_or(Held::Unreadable, Held::GitHubApp)
}

async fn ask_provider(shared: &Shared, held: Held) -> ProviderOutcome {
    let Some(transports) = &shared.revocation else {
        return ProviderOutcome::NotAsked;
    };
    match held {
        Held::Nothing => ProviderOutcome::NotAsked,
        Held::NoEndpoint => ProviderOutcome::NotAvailable,
        Held::NotRead => ProviderOutcome::NotRead,
        Held::Unreadable => {
            ProviderOutcome::Asked(ProviderRevocation::Failed(RevocationFailure::Unreadable))
        }
        Held::Codex(material) => ProviderOutcome::Asked(
            codex::revoke_stored(&transports.codex, material.expose_secret()).await,
        ),
        Held::GitHubApp(bundle) => match (&shared.github_app_authorization, &transports.github) {
            (Some(owner), Some(github)) => owner
                .revoke_user_token(github, &bundle)
                .await
                .map_or(ProviderOutcome::NotAvailable, ProviderOutcome::Asked),
            _ => ProviderOutcome::NotAvailable,
        },
    }
}

impl ProviderOutcome {
    /// The response's `provider_revocation`; unset when nothing was asked.
    pub(crate) fn to_proto(self) -> Option<proto::ProviderRevocation> {
        use proto::{ProviderRevocationFailure as Failure, ProviderRevocationOutcome as Outcome};
        let (outcome, failure, http_status) = match self {
            Self::NotAsked => return None,
            Self::NotAvailable => (Outcome::NotAvailable, Failure::Unspecified, 0),
            Self::NotRead => (Outcome::Failed, Failure::NotRead, 0),
            Self::Asked(ProviderRevocation::Confirmed) => {
                (Outcome::Confirmed, Failure::Unspecified, 0)
            }
            Self::Asked(ProviderRevocation::Failed(RevocationFailure::Unavailable)) => {
                (Outcome::Failed, Failure::Unavailable, 0)
            }
            Self::Asked(ProviderRevocation::Failed(RevocationFailure::Refused(status))) => {
                (Outcome::Failed, Failure::Refused, u32::from(status))
            }
            Self::Asked(ProviderRevocation::Failed(RevocationFailure::Unreadable)) => {
                (Outcome::Failed, Failure::Unreadable, 0)
            }
            Self::Asked(ProviderRevocation::Failed(RevocationFailure::Expired)) => {
                (Outcome::Failed, Failure::Expired, 0)
            }
        };
        Some(proto::ProviderRevocation {
            outcome: outcome.into(),
            failure: failure.into(),
            http_status,
            ..Default::default()
        })
    }
}
