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
