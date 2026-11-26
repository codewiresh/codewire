//! Telling a credential's provider when Codewire revokes it (#4717). One
//! owned worker reads the token, publishes Codewire's revoke and only then
//! asks the provider, so a provider that does not confirm leaves the
//! credential revoked in Codewire, and neither a client that disconnects nor
//! the mutation's deadline can cancel the ask once the revoke has committed.
//! Nothing retries: the held material is dropped, zeroed, once the provider
//! answers. The worker fences the refresh journal before it reads, so the
//! token asked about is the live one; when a refresh may already have rotated
//! it, the provider is not asked and the answer is NOT_READ.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use codewire_access::{
    CredentialAuthKind, CredentialId, CredentialMetadata, CredentialStatus, Owner,
};
use codewire_credential_broker::provider_oauth::{
    ProviderRevocation, RevocationFailure, antigravity, codex,
};
use codewire_credential_broker::{
    BrokerUpstreamTransport, GitHubAppAuthorizationOwner, GitHubAppUserOAuthBundle,
};
use codewire_platform_credentials::{CredentialVersion, RevocationFence};
use codewire_protected_store::ProtectedValue;
use codewire_proto::codewire::v1 as proto;
use codewire_server_core::auth::CredentialMutationAuthority;
use tokio::sync::oneshot;
use uuid::Uuid;

use super::{CredentialMutationOwner, Error, Scope, Shared, publication};

/// How long a revoke waits for the provider's answer once Codewire's revoke
/// has committed: the revocation's own 8 s bound and a margin. The worker
/// still finishes the ask if this runs out.
const PROVIDER_WAIT: Duration = Duration::from_secs(10);

/// The one-route transports a provider revocation uses.
#[derive(Clone)]
pub struct RevocationTransports {
    /// `HttpProvider::CodexTokenRevocation`.
    pub codex: Arc<dyn BrokerUpstreamTransport>,
    /// `HttpProvider::AntigravityTokenRevocation`.
    pub antigravity: Arc<dyn BrokerUpstreamTransport>,
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
    Antigravity(ProtectedValue),
    GitHubApp(GitHubAppUserOAuthBundle),
}

/// The journal fence a revoke holds while it reads the token, cancelled if
/// the revoke does not commit.
struct Fence {
    expected: CredentialVersion,
    attempt_id: Uuid,
}

impl CredentialMutationOwner {
    /// Revokes the exact revision, then asks its provider to revoke its
    /// token, both in one owned worker. Codewire's own revoke failing asks
    /// nothing. With `delete`, the revoke's transaction also deletes the
    /// credential (#6211): one a profile or binding still selects is refused
    /// as in use, stays as it was, and its provider is not asked.
    pub(crate) async fn revoke(
        &self,
        authority: CredentialMutationAuthority,
        id: String,
        revision: u64,
        delete: bool,
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
                let (held, fence) = held_for_revocation(&shared, &scope.owner, &id, revision).await;
                let check = fence.as_ref().map(|fence| publication::RevokeFence {
                    attempt_id: fence.attempt_id,
                    held: Arc::new(AtomicBool::new(false)),
                });
                let fence_held = check.as_ref().map(|check| Arc::clone(&check.held));
                let result = publication::fenced_revoke(
                    &shared,
                    &scope,
                    id.clone(),
                    revision,
                    check,
                    delete,
                )
                .await;
                let committed = result.is_ok();
                let _ = published.send(result);
                if let Some(fence) = fence.filter(|_| !committed) {
                    // Best effort: a fence left behind lapses in 60 s, and a
                    // revoke that did commit already removed it.
                    let _ = shared
                        .store
                        .cancel_oauth_refresh(&scope.owner, &id, fence.expected, fence.attempt_id)
                        .await;
                }
                let outcome = match fence_held {
                    _ if !committed => {
                        // A refused delete still holds the token it read:
                        // drop it, zeroed, without asking.
                        drop(held);
                        ProviderOutcome::NotAsked
                    }
                    // The fence lapsed and a refresh replaced it before the
                    // commit: the token read may no longer be the live one.
                    Some(fence_held) if !fence_held.load(Ordering::SeqCst) => {
                        ProviderOutcome::NotRead
                    }
                    _ => ask_provider(&shared, held).await,
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
) -> (Held, Option<Fence>) {
    if shared.revocation.is_none() {
        return (Held::Nothing, None);
    }
    // A failed read is reported once the revoke commits; a missing or
    // foreign credential fails the revoke itself.
    let Ok(record) = shared.store.record(owner, id).await else {
        return (Held::NotRead, None);
    };
    // The revoke itself answers a stale or inactive revision.
    if record.metadata.status != CredentialStatus::Active
        || record.version.revocation_generation != revision
    {
        return (Held::Nothing, None);
    }
    let provider = record.metadata.provider.as_str();
    if record.metadata.authentication_kind != CredentialAuthKind::OAuth
        || !matches!(provider, "openai" | "github" | "google")
    {
        return (Held::NoEndpoint, None);
    }
    // A refresh that may have rotated the stored token would make the
    // provider's answer about a token that is no longer the live one.
    let fence = match shared
        .store
        .fence_oauth_refresh_for_revocation(owner, id, record.version)
        .await
    {
        Ok(RevocationFence::Fenced { attempt_id }) => Fence {
            expected: record.version,
            attempt_id,
        },
        Ok(RevocationFence::RotationPossible) | Err(_) => return (Held::NotRead, None),
    };
    let Ok(material) = shared
        .store
        .read_for_oauth_refresh(owner, id, record.version)
        .await
    else {
        return (Held::NotRead, Some(fence));
    };
    let held = if provider == "openai" {
        Held::Codex(material)
    } else if provider == "google" {
        Held::Antigravity(material)
    } else if !GitHubAppUserOAuthBundle::is_tagged(material.expose_secret()) {
        // A connection from before the App holds a raw token the App cannot
        // revoke; its owner revokes it at GitHub.
        Held::NoEndpoint
    } else {
        GitHubAppUserOAuthBundle::parse(material.expose_secret())
            .map_or(Held::Unreadable, Held::GitHubApp)
    };
    (held, Some(fence))
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
        Held::Antigravity(material) => ProviderOutcome::Asked(
            antigravity::revoke_stored(&transports.antigravity, material.expose_secret()).await,
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

/// Asks the provider to revoke a sign-in it approved that Codewire did not
/// store, so no copy stays live (#4904). Once and best effort, on the
/// owner's workers so the enrollment's error is not held for it; only the
/// outcome class is logged. Claude offers no revocation; its sign-in expires
/// on its own.
pub(super) fn revoke_unstored(shared: &Shared, provider: &'static str, material: ProtectedValue) {
    let Some(transports) = shared.revocation.clone() else {
        return;
    };
    let github_app = shared.github_app_authorization.clone();
    shared.workers.spawn(async move {
        ask_unstored(&transports, github_app.as_deref(), provider, &material).await;
    });
}

pub(super) async fn ask_unstored(
    transports: &RevocationTransports,
    github_app: Option<&GitHubAppAuthorizationOwner>,
    provider: &str,
    material: &ProtectedValue,
) {
    let answer = match provider {
        "openai" => Some(codex::revoke_stored(&transports.codex, material.expose_secret()).await),
        "google" => Some(
            antigravity::revoke_stored(&transports.antigravity, material.expose_secret()).await,
        ),
        "github" => match (
            github_app,
            &transports.github,
            GitHubAppUserOAuthBundle::parse(material.expose_secret()),
        ) {
            (Some(owner), Some(github), Ok(bundle)) => {
                owner.revoke_user_token(github, &bundle).await
            }
            _ => None,
        },
        _ => None,
    };
    let outcome = match answer {
        None => "not_available",
        Some(ProviderRevocation::Confirmed) => "confirmed",
        Some(ProviderRevocation::Failed(_)) => "not_confirmed",
    };
    tracing::info!(
        provider,
        outcome,
        "asked the provider to revoke a sign-in that was not stored"
    );
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
