//! GitHub device enrollment uses the same owner capacity and publication path.

use codewire_proto::codewire::v1::{
    EnrollGithubResponse, GithubDeviceChallenge, enroll_github_response,
};

use super::enrollment::{Completed, Outcome, github_error};
use super::*;

impl CredentialMutationOwner {
    pub(super) fn enroll_github(
        &self,
        authority: CredentialMutationAuthority,
        name: String,
        credential_id: Option<String>,
        expected_revision: Option<u64>,
    ) -> Result<Events<EnrollGithubResponse>, Error> {
        let replacement = replacement_selector(credential_id, expected_revision)?;
        // Existing named API callers remain supported. Only a create with no
        // name selects the verified provider account as its canonical name.
        // Reconnect still fences the exact previously observed name/version.
        if !name.is_empty() || replacement.is_some() {
            validate_name(&name)?;
        }
        let scope = Scope::new(authority, self.stop.child_token(), ENROLLMENT_TIMEOUT)?;
        let accepting = self.accepting.lock().map_err(|_| Error::Unavailable)?;
        let permit = self.admit(*accepting)?;
        let cancel = scope.cancel.clone().drop_guard();
        let (sender, receiver) = mpsc::channel(2);
        let shared = self.shared.clone();
        self.workers.spawn(async move {
            let _permit = permit;
            if let Err(error) = run(shared, &scope, name, replacement, &sender).await {
                let _ = sender.try_send(Err(error));
            }
        });
        drop(accepting);
        Ok(Events {
            receiver,
            _cancel: cancel,
        })
    }
}

async fn run(
    shared: Arc<Shared>,
    scope: &Scope,
    name: String,
    replacement: Option<(CredentialId, u64)>,
    sender: &mpsc::Sender<Result<EnrollGithubResponse, Error>>,
) -> Result<(), Error> {
    let target = if name.is_empty() && replacement.is_none() {
        scope.check()?;
        EnrollmentTarget::CreateGithubAccount
    } else {
        enrollment_target(&shared, scope, "github", name, replacement).await?
    };
    if !matches!(target, EnrollmentTarget::Reconnect(_)) {
        ensure_github_unconnected(&shared, scope).await?;
    }
    let mut pending = shared.github_enrollment.start().map_err(github_error)?;
    let challenge = scope
        .wait(pending.challenge())
        .await?
        .map_err(github_error)?;
    let response = EnrollGithubResponse {
        event: Some(enroll_github_response::Event::Challenge(Box::new(
            GithubDeviceChallenge {
                verification_url: challenge.verification_url().into(),
                user_code: challenge.user_code().into(),
                expires_at_unix: challenge.expires_at_unix().min(scope.expires_at_unix),
                ..Default::default()
            },
        ))),
        ..Default::default()
    };
    drop(challenge);
    scope
        .wait(sender.send(Ok(response)))
        .await?
        .map_err(|_| Error::Cancelled)?;
    let mut completed = Completed::Github(
        scope
            .wait(pending.complete())
            .await?
            .map_err(github_error)?,
    );
    let publication = publication::enroll(&shared, scope, &mut completed, target).await;
    completed
        .finish(publication.outcome)
        .await
        .map_err(|_| Error::CleanupFailed)?;
    let metadata = publication
        .result
        .map_err(|error| unpublished_terminal_error(publication.outcome, error))?;
    scope
        .wait(sender.send(Ok(EnrollGithubResponse {
            event: Some(enroll_github_response::Event::Credential(Box::new(
                wire::credential(metadata),
            ))),
            ..Default::default()
        })))
        .await?
        .map_err(|_| Error::PublicationUnknown)?;
    Ok(())
}

/// Preserve uncertainty once a COMMIT may have been issued.  `NotPublished`
/// is different: publication establishes it only on paths that did not issue
/// the database COMMIT, and cleanup above has completed before this response is
/// rendered.
fn unpublished_terminal_error(outcome: Outcome, error: Error) -> Error {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unpublished_github_terminal_preserves_commit_uncertainty_and_other_failures() {
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
}
