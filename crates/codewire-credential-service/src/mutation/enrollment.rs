//! Provider-specific imports share the same publication transaction and fences.

use codewire_credential_broker::{CodexOAuthImport, GitHubAppAuthorizationImport};
use codewire_protected_store::ProtectedValue;

use super::Error;

/// A completed native login. Provider material lives only in zeroizing
/// memory until publication takes it; nothing outside this process holds it.
pub(super) enum Completed {
    Codex(Option<CodexOAuthImport>),
    GithubApp(GitHubAppAuthorizationImport),
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
        };
        let material = ProtectedValue::new(std::mem::take(&mut *bytes))
            .map_err(|_| Error::EnrollmentFailed)?;
        Ok((material, hint))
    }
}
