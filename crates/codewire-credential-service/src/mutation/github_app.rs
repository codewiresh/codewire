//! GitHub App browser callback completion, deliberately separate from the
//! GitHub CLI device enrollment in `github.rs`.

use std::sync::Arc;
use std::time::Duration;

use codewire_access::{CredentialAuthKind, CredentialId};
use codewire_credential_broker::GitHubAppAuthorizationError;
use tokio::sync::oneshot;
use zeroize::Zeroizing;

use super::enrollment::Completed;
use super::*;

const GITHUB_APP_AUTHORIZATION_TIMEOUT: Duration = Duration::from_secs(45);

impl CredentialMutationOwner {
    pub(super) async fn complete_github_app_authorization(
        &self,
        authority: CredentialMutationAuthority,
        code: Zeroizing<Vec<u8>>,
        credential_id: Option<String>,
        expected_revision: Option<u64>,
    ) -> Result<CredentialMetadata, Error> {
        if !authority.is_browser_session() {
            return Err(Error::Denied);
        }
        let replacement = replacement_selector(credential_id, expected_revision)?;
        if self.shared.github_app_authorization.is_none() {
            return Err(Error::Unavailable);
        }
        let scope = Scope::new(
            authority,
            self.stop.child_token(),
            GITHUB_APP_AUTHORIZATION_TIMEOUT,
        )?;
        let deadline = scope.deadline;
        let cancelled = scope.cancel.clone();
        let _guard = cancelled.clone().drop_guard();
        let (sender, receiver) = oneshot::channel();
        {
            let accepting = self.accepting.lock().map_err(|_| Error::Unavailable)?;
            let permit = self.admit(*accepting)?;
            let shared = self.shared.clone();
            self.workers.spawn(async move {
                let _permit = permit;
                let result = run(shared, &scope, code, replacement).await;
                let _ = sender.send(result);
            });
        }
        tokio::select! {
            biased;
            _ = cancelled.cancelled() => Err(Error::Cancelled),
            _ = tokio::time::sleep_until(deadline) => Err(Error::PublicationUnknown),
            result = receiver => result.map_err(|_| Error::PublicationUnknown)?,
        }
    }
}

async fn run(
    shared: Arc<Shared>,
    scope: &Scope,
    code: Zeroizing<Vec<u8>>,
    replacement: Option<(CredentialId, u64)>,
) -> Result<CredentialMetadata, Error> {
    let target = match replacement {
        Some((id, revision)) => reconnect_target(&shared, scope, id, revision).await?,
        None => EnrollmentTarget::CreateGithubAccount,
    };
    let owner = shared
        .github_app_authorization
        .as_ref()
        .ok_or(Error::Unavailable)?;
    let import = scope
        .wait(owner.complete(code))
        .await?
        .map_err(github_app_error)?;
    if let EnrollmentTarget::Reconnect(record) = &target
        && !reconnect_account_matches(
            record.metadata.account_hint.as_deref(),
            import.account_hint(),
        )
    {
        return Err(Error::EnrollmentFailed);
    }
    let mut completed = Completed::GithubApp(import);
    let publication = publication::enroll(&shared, scope, &mut completed, target).await;
    completed.finish(publication.outcome).await?;
    publication.result
}

fn reconnect_account_matches(expected: Option<&str>, actual: &str) -> bool {
    expected.is_none_or(|expected| expected == actual)
}

async fn reconnect_target(
    shared: &Shared,
    scope: &Scope,
    id: CredentialId,
    revision: u64,
) -> Result<EnrollmentTarget, Error> {
    let record = scope
        .wait(shared.store.record(&scope.owner, &id))
        .await?
        .map_err(store_error)?;
    if record.metadata.provider.as_str() != "github"
        || record.metadata.authentication_kind != CredentialAuthKind::OAuth
    {
        return Err(Error::InvalidInput);
    }
    if record.version.revocation_generation != revision {
        return Err(Error::StaleRevision);
    }
    Ok(EnrollmentTarget::Reconnect(record))
}

pub(super) fn github_app_error(error: GitHubAppAuthorizationError) -> Error {
    match error {
        GitHubAppAuthorizationError::Configuration
        | GitHubAppAuthorizationError::Unavailable
        | GitHubAppAuthorizationError::ExpiringTokensUnsupported => Error::Unavailable,
        GitHubAppAuthorizationError::InvalidAuthorizationCode => Error::InvalidInput,
        GitHubAppAuthorizationError::Denied => Error::EnrollmentFailed,
        GitHubAppAuthorizationError::InvalidResponse => Error::EnrollmentUnsupported,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn github_app_failures_never_leak_provider_details() {
        assert_eq!(
            github_app_error(GitHubAppAuthorizationError::InvalidAuthorizationCode),
            Error::InvalidInput
        );
        assert_eq!(
            github_app_error(GitHubAppAuthorizationError::Denied),
            Error::EnrollmentFailed
        );
        assert_eq!(
            github_app_error(GitHubAppAuthorizationError::InvalidResponse),
            Error::EnrollmentUnsupported
        );
        assert_eq!(
            github_app_error(GitHubAppAuthorizationError::Unavailable),
            Error::Unavailable
        );
        assert_eq!(
            github_app_error(GitHubAppAuthorizationError::ExpiringTokensUnsupported),
            Error::Unavailable
        );
    }

    #[test]
    fn reconnect_keeps_a_verified_github_identity_but_allows_legacy_unknowns() {
        assert!(reconnect_account_matches(Some("octo-user"), "octo-user"));
        assert!(!reconnect_account_matches(Some("octo-user"), "other-user"));
        assert!(reconnect_account_matches(None, "octo-user"));
    }
}
