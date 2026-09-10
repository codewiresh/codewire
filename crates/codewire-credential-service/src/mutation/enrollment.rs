//! Provider-specific imports share the same publication transaction and fences.

use std::future::Future;

use codewire_credential_broker::codex_enrollment::{
    CodexPublicationOutcome, CompletedCodexEnrollment,
};
use codewire_credential_broker::github_enrollment::{
    CompletedGitHubEnrollment, GitHubEnrollmentError, GitHubPublicationOutcome,
};
use codewire_protected_store::ProtectedValue;

use super::{Error, enrollment_error};

pub(super) enum Completed {
    Codex(CompletedCodexEnrollment),
    Github(CompletedGitHubEnrollment),
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
            Self::Github(_) => "github",
        }
    }

    pub(super) fn check_active(&self) -> Result<(), Error> {
        match self {
            Self::Codex(value) => value.check_active().map_err(enrollment_error),
            Self::Github(value) => value.check_active().map_err(github_error),
        }
    }

    pub(super) fn take_material(&mut self) -> Result<(ProtectedValue, Option<String>), Error> {
        let (mut bytes, hint) = match self {
            Self::Codex(value) => {
                let (bundle, hint) = value.take_import().map_err(enrollment_error)?.into_parts();
                (bundle.into_bytes(), hint)
            }
            Self::Github(value) => value.take_import().map_err(github_error)?.into_parts(),
        };
        let material = ProtectedValue::new(std::mem::take(&mut *bytes))
            .map_err(|_| Error::EnrollmentFailed)?;
        Ok((material, hint))
    }

    pub(super) async fn wait_for_publication<T>(
        &self,
        future: impl Future<Output = T>,
    ) -> Result<T, Error> {
        match self {
            Self::Codex(value) => value
                .wait_for_publication(future)
                .await
                .map_err(enrollment_error),
            Self::Github(value) => value
                .wait_for_publication(future)
                .await
                .map_err(github_error),
        }
    }

    pub(super) async fn finish(self, outcome: Outcome) -> Result<(), Error> {
        match self {
            Self::Codex(value) => value
                .finish(match outcome {
                    Outcome::Published => CodexPublicationOutcome::Published,
                    Outcome::NotPublished => CodexPublicationOutcome::NotPublished,
                    Outcome::Unknown => CodexPublicationOutcome::Unknown,
                })
                .await
                .map_err(enrollment_error),
            Self::Github(value) => value
                .finish(match outcome {
                    Outcome::Published => GitHubPublicationOutcome::Published,
                    Outcome::NotPublished => GitHubPublicationOutcome::NotPublished,
                    Outcome::Unknown => GitHubPublicationOutcome::Unknown,
                })
                .await
                .map_err(github_error),
        }
    }
}

pub(super) fn github_error(error: GitHubEnrollmentError) -> Error {
    match error {
        GitHubEnrollmentError::Cancelled => Error::Cancelled,
        GitHubEnrollmentError::Expired => Error::Expired,
        GitHubEnrollmentError::Configuration | GitHubEnrollmentError::Unavailable => {
            Error::Unavailable
        }
        GitHubEnrollmentError::Cleanup => Error::CleanupFailed,
        _ => Error::EnrollmentFailed,
    }
}
