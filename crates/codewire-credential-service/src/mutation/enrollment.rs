//! Provider-specific imports share the same publication transaction and fences.

use codewire_access::CredentialAuthKind;
use codewire_credential_broker::{
    ClaudeOAuthImport, CodexOAuthImport, GitHubAppAuthorizationImport,
};
use codewire_protected_store::ProtectedValue;

use super::Error;

/// A completed native login. Provider material lives only in zeroizing
/// memory until publication takes it; nothing outside this process holds it.
pub(super) enum Completed {
    Codex(Option<CodexOAuthImport>),
    GithubApp(GitHubAppAuthorizationImport),
    Claude(Option<ClaudeOAuthImport>),
}

#[derive(Clone, Copy)]
pub(super) enum Outcome {
    Published,
    NotPublished,
    Unknown,
}

impl Completed {
    pub(super) fn provider(&self) -> &'static str {
        match self {
            Self::Codex(_) => "openai",
            Self::GithubApp(_) => "github",
            Self::Claude(_) => "anthropic",
        }
    }

    /// The kind the login is stored as: a Claude sign-in is its own kind.
    pub(super) fn authentication_kind(&self) -> CredentialAuthKind {
        match self {
            Self::Codex(_) | Self::GithubApp(_) => CredentialAuthKind::OAuth,
            Self::Claude(_) => CredentialAuthKind::ClaudeSignIn,
        }
    }

    pub(super) fn take_material(&mut self) -> Result<(ProtectedValue, Option<String>), Error> {
        let (mut bytes, hint) = match self {
            Self::Codex(value) => {
                let (bundle, hint) = value.take().ok_or(Error::EnrollmentFailed)?.into_parts();
                (bundle.into_bytes(), hint)
            }
            Self::GithubApp(value) => value
                .take_import()
                .map_err(super::github_app::github_app_error)?,
            Self::Claude(value) => {
                let (bundle, hint) = value.take().ok_or(Error::EnrollmentFailed)?.into_parts();
                (bundle.into_bytes(), hint)
            }
        };
        let material = ProtectedValue::new(std::mem::take(&mut *bytes))
            .map_err(|_| Error::EnrollmentFailed)?;
        Ok((material, hint))
    }
}

/// Preserve uncertainty once a COMMIT may have been issued.  `NotPublished`
/// is different: publication establishes it only on paths that did not issue
/// the database COMMIT, and cleanup above has completed before this response is
/// rendered.
pub(super) fn unpublished_terminal_error(outcome: Outcome, error: Error) -> Error {
    if matches!(outcome, Outcome::NotPublished)
        && matches!(
            error,
            Error::Unavailable | Error::Denied | Error::Cancelled | Error::Expired
        )
    {
        Error::EnrollmentNotPublished
    } else {
        error
    }
}

/// Nothing is stored before publication begins, so an enrollment cancelled
/// there, by the drain's limit or a lost client, or one whose device code or
/// deadline ran out, ends with a definite reason rather than an uncertain one
/// (#6535).
pub(super) fn before_publication(error: Error) -> Error {
    match error {
        Error::Cancelled => Error::EnrollmentNotPublished,
        Error::Expired => Error::EnrollmentExpired,
        error => error,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unpublished_terminal_preserves_commit_uncertainty_and_other_failures() {
        for error in [
            Error::Unavailable,
            Error::Denied,
            Error::Cancelled,
            Error::Expired,
        ] {
            assert_eq!(
                unpublished_terminal_error(Outcome::NotPublished, error),
                Error::EnrollmentNotPublished
            );
        }
        for error in [
            Error::EnrollmentFailed,
            Error::EnrollmentUnsupported,
            Error::CleanupFailed,
            Error::PublicationUnknown,
        ] {
            assert_eq!(
                unpublished_terminal_error(Outcome::NotPublished, error),
                error
            );
        }
        assert_eq!(
            unpublished_terminal_error(Outcome::Unknown, Error::Unavailable),
            Error::Unavailable
        );
    }

    #[test]
    fn before_publication_a_cancelled_or_expired_enrollment_is_definite() {
        assert_eq!(
            before_publication(Error::Cancelled),
            Error::EnrollmentNotPublished
        );
        assert_eq!(before_publication(Error::Expired), Error::EnrollmentExpired);
        for error in [
            Error::Unavailable,
            Error::Denied,
            Error::EnrollmentFailed,
            Error::GitHubInstallationRequired,
            Error::StaleRevision,
        ] {
            assert_eq!(before_publication(error), error);
        }
    }
}
