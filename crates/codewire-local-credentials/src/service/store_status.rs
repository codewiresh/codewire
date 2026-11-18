//! What the authority answers when its protected store refuses an operation.
//! A locked or missing store is a definite refusal (FailedPrecondition): the
//! authority answers only once the operation is undone, and names the cause
//! as a [`crate::StoreRefusal`] its caller words; the message is for the log.
//! A timeout is definite too (#5271): a write that timed out is never made
//! ready, and recovery deletes it, never completes it, so a stray value the
//! store may still hold is never used. Any other storage fault stays
//! Unavailable, which callers report as an unknown outcome.

use codewire_protected_store::ProtectedStoreError;
use tonic::Status;

use crate::StoreRefusal;

/// A locked store: on macOS the login keychain, which a remote (SSH) session
/// does not unlock (#4864).
#[cfg(target_os = "macos")]
const LOCKED: &str = "your login keychain is locked in this session; run `security unlock-keychain` and run this again";
#[cfg(not(target_os = "macos"))]
const LOCKED: &str = "local protected storage is locked or inaccessible; unlock it and retry";

pub(super) fn status(error: ProtectedStoreError) -> Status {
    match error {
        ProtectedStoreError::AccessDenied => {
            StoreRefusal::KeychainLocked.attach(Status::failed_precondition(LOCKED))
        }
        ProtectedStoreError::TimedOut => StoreRefusal::KeyringTimedOut.attach(
            Status::failed_precondition("local protected storage did not respond in time"),
        ),
        // The login keychain, or the file CODEWIRE_LOCAL_CREDENTIAL_KEYCHAIN
        // names, is absent (#4864).
        ProtectedStoreError::KeychainMissing => StoreRefusal::KeychainMissing.attach(
            Status::failed_precondition(
                "the keychain that holds local credentials doesn't exist: create the login keychain in Keychain Access, or unset CODEWIRE_LOCAL_CREDENTIAL_KEYCHAIN if it names a missing file, then run this again",
            ),
        ),
        ProtectedStoreError::InvalidEntryId
        | ProtectedStoreError::EmptyValue
        | ProtectedStoreError::ValueTooLarge
        | ProtectedStoreError::Unavailable
        | ProtectedStoreError::AmbiguousEntry
        | ProtectedStoreError::CorruptEntry
        | ProtectedStoreError::UnsupportedPlatform => {
            Status::unavailable("local credential authority storage is unavailable")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_keychain_is_a_definite_refusal_that_says_what_to_do() {
        let missing = status(ProtectedStoreError::KeychainMissing);
        assert_eq!(missing.code(), tonic::Code::FailedPrecondition);
        assert!(missing.message().contains("doesn't exist"));
        assert!(
            missing
                .message()
                .contains("CODEWIRE_LOCAL_CREDENTIAL_KEYCHAIN")
        );
        assert_eq!(
            crate::store_refusal_reason(&missing),
            Some("LOCAL_KEYCHAIN_MISSING")
        );
        let locked = status(ProtectedStoreError::AccessDenied);
        assert_eq!(locked.code(), tonic::Code::FailedPrecondition);
        assert_eq!(
            crate::store_refusal_reason(&locked),
            Some("LOCAL_KEYCHAIN_LOCKED")
        );
        // A timeout is a definite refusal (#5271); any other storage fault is
        // no refusal, so it names no reason.
        let timed_out = status(ProtectedStoreError::TimedOut);
        assert_eq!(timed_out.code(), tonic::Code::FailedPrecondition);
        assert_eq!(
            crate::store_refusal_reason(&timed_out),
            Some("LOCAL_KEYRING_TIMED_OUT")
        );
        let fault = status(ProtectedStoreError::Unavailable);
        assert_eq!(fault.code(), tonic::Code::Unavailable);
        assert_eq!(crate::store_refusal_reason(&fault), None);
        assert_eq!(locked.message(), LOCKED);
        #[cfg(target_os = "macos")]
        assert!(LOCKED.contains("`security unlock-keychain`"));
    }
}
