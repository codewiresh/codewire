//! What the authority answers when its protected store refuses an operation.
//! A locked or missing store is a definite refusal (FailedPrecondition): the
//! authority answers only once the operation is undone. A timeout or other
//! storage fault stays Unavailable, which callers report as an unknown
//! outcome.

use codewire_protected_store::ProtectedStoreError;
use tonic::Status;

/// A locked store: on macOS the login keychain, which a remote (SSH) session
/// does not unlock (#4864).
#[cfg(target_os = "macos")]
const LOCKED: &str = "your login keychain is locked in this session; run `security unlock-keychain` and run this again";
#[cfg(not(target_os = "macos"))]
const LOCKED: &str = "local protected storage is locked or inaccessible; unlock it and retry";

pub(super) fn status(error: ProtectedStoreError) -> Status {
    match error {
        ProtectedStoreError::AccessDenied => Status::failed_precondition(LOCKED),
        ProtectedStoreError::TimedOut => {
            Status::unavailable("local protected storage did not respond in time")
        }
        // The login keychain, or the file CODEWIRE_LOCAL_CREDENTIAL_KEYCHAIN
        // names, is absent (#4864).
        ProtectedStoreError::KeychainMissing => Status::failed_precondition(
            "the keychain that holds local credentials doesn't exist: create the login keychain in Keychain Access, or unset CODEWIRE_LOCAL_CREDENTIAL_KEYCHAIN if it names a missing file, then run this again",
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
        let locked = status(ProtectedStoreError::AccessDenied);
        assert_eq!(locked.code(), tonic::Code::FailedPrecondition);
        assert_eq!(locked.message(), LOCKED);
        #[cfg(target_os = "macos")]
        assert!(LOCKED.contains("`security unlock-keychain`"));
    }
}
