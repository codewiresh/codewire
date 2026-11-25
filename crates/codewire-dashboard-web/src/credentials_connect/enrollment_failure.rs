//! The closed reasons a failed enrollment or GitHub authorization shows,
//! never an upstream message.

use super::*;

pub(super) fn failed(uncertain: bool) -> OAuthEnrollmentEvent {
    OAuthEnrollmentEvent::Failed {
        reason: OAuthEnrollmentFailure::UnexpectedResponse,
        uncertain,
    }
}

pub(super) fn failed_error(error: &ConnectError, uncertain: bool) -> OAuthEnrollmentEvent {
    use OAuthEnrollmentFailure as Failure;
    // Do not render or retain an upstream message, detail metadata, provider
    // output or challenge. Only these closed reasons cross into the view.
    let trusted_reason = match codewire_reason(error) {
        Ok(reason) => reason,
        Err(()) => return failed(uncertain),
    };
    let reason = match (trusted_reason.as_deref(), error.code) {
        (Some("CREDENTIAL_REVISION_CHANGED"), ErrorCode::FailedPrecondition) => Failure::Changed,
        // Nothing was stored: the service ended the enrollment before
        // publication, for example when it stopped for a roll (#6535).
        (
            Some("CREDENTIAL_ENROLLMENT_FAILED" | "CREDENTIAL_ENROLLMENT_NOT_PUBLISHED"),
            ErrorCode::FailedPrecondition,
        ) => Failure::NotCompleted,
        (Some("CREDENTIAL_ENROLLMENT_EXPIRED"), ErrorCode::DeadlineExceeded) => {
            return OAuthEnrollmentEvent::Failed {
                reason: Failure::Expired,
                uncertain: false,
            };
        }
        (Some("CREDENTIAL_ENROLLMENT_UNSUPPORTED"), ErrorCode::FailedPrecondition) => {
            Failure::Unsupported
        }
        (Some("CREDENTIAL_ENROLLMENT_CLEANUP_FAILED"), ErrorCode::Unavailable)
        | (Some("CREDENTIAL_MUTATION_UNCERTAIN"), ErrorCode::Unknown) => {
            return failed(true);
        }
        (Some(_), _) => return failed(uncertain),
        (None, _) => match error.code {
            ErrorCode::Unauthenticated | ErrorCode::PermissionDenied => Failure::SignInRequired,
            ErrorCode::Unavailable | ErrorCode::ResourceExhausted => Failure::Unavailable,
            ErrorCode::AlreadyExists => Failure::AlreadyExists,
            ErrorCode::Aborted | ErrorCode::NotFound => Failure::Changed,
            ErrorCode::InvalidArgument => Failure::Invalid,
            ErrorCode::DeadlineExceeded => Failure::Expired,
            ErrorCode::Canceled => Failure::Cancelled,
            _ => Failure::UnexpectedResponse,
        },
    };
    // These failures are proven before publication. Other failures after a
    // challenge can leave publication uncertain, so preserve reconciliation.
    let uncertain = uncertain
        && !matches!(
            reason,
            Failure::AlreadyExists
                | Failure::Changed
                | Failure::Unsupported
                | Failure::NotCompleted
        );
    OAuthEnrollmentEvent::Failed { reason, uncertain }
}

pub(crate) fn github_authorization_feedback(error: &ConnectError) -> Option<&'static str> {
    if error.code != ErrorCode::FailedPrecondition {
        return None;
    }
    match codewire_reason(error).ok()?.as_deref()? {
        "CREDENTIAL_GITHUB_APP_NOT_CONFIGURED" => Some("github-app-unavailable"),
        "CREDENTIAL_GITHUB_INSTALLATION_REQUIRED" => Some("github-installation-required"),
        "CREDENTIAL_ENROLLMENT_FAILED" => Some("github-app-failed"),
        "CREDENTIAL_ENROLLMENT_UNSUPPORTED" => Some("github-app-response-invalid"),
        _ => None,
    }
}
