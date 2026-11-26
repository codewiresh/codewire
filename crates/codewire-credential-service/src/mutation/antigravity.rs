//! Antigravity sign-in by pasted callback URL or `code#state`: Google Desktop
//! OAuth for the Antigravity CLI (`agy`).
//!
//! Start creates the PKCE verifier and state and returns Google's authorize
//! URL with an opaque handle; nothing is sent to Google or stored, so either
//! replica can complete it. The handle is the verifier and state sealed with
//! the credential store's KEK, bound to the person who started the sign-in,
//! its purpose and its issue time, so Complete refuses another person's
//! handle, an altered one and one issued more than 15 minutes ago, before
//! Google is contacted. Complete checks the pasted callback URL or
//! `code#state` against the handle, exchanges the code with Google, verifies
//! the 6-scope allow-list and publishes the login through the same enrollment
//! fences as every other OAuth connection. A failed completion asks Google
//! once, best effort, to revoke any token issued that could not be stored.

use std::sync::Arc;
use std::time::Duration;

use codewire_access::{CredentialAuthKind, CredentialId, Owner};
use codewire_credential_broker::provider_oauth::antigravity::{
    ANTIGRAVITY_SIGN_IN_LIFETIME, AntigravitySignInError,
};
use codewire_platform_credentials::MAX_SEALED_TRANSIENT_TEXT_BYTES;
use tokio::sync::oneshot;
use zeroize::Zeroizing;

use super::claude::StartedSignIn;
use super::enrollment::Completed;
use super::*;

/// The code exchange and publication.
const ANTIGRAVITY_SIGN_IN_TIMEOUT: Duration = Duration::from_secs(75);
/// Sealing at Start: one KEK data-key request.
const ANTIGRAVITY_SIGN_IN_START_TIMEOUT: Duration = Duration::from_secs(35);
const MAX_AUTHORIZATION_CODE_BYTES: usize = 4096;
/// The handle's version prefix: `cwag1.<issued_at>.<sealed>`.
const HANDLE_VERSION: &str = "cwag1";
/// The purpose the handle is sealed under, bound as associated data.
const HANDLE_PURPOSE: &str = "antigravity-sign-in-handle";
/// A handle stamped this far in the future is refused (clock skew between
/// replicas is far smaller).
const MAX_HANDLE_CLOCK_SKEW_SECONDS: u64 = 60;
const MAX_SIGN_IN_HANDLE_BYTES: usize = HANDLE_VERSION.len() + 22 + MAX_SEALED_TRANSIENT_TEXT_BYTES;

impl CredentialMutationOwner {
    /// Begin an Antigravity sign-in for the authenticated person. The handle
    /// carries this sign-in's verifier and state, sealed to this person and
    /// its issue time, back to [`Self::complete_antigravity_sign_in`].
    pub(super) async fn start_antigravity_sign_in(
        &self,
        authority: CredentialMutationAuthority,
    ) -> Result<StartedSignIn, Error> {
        let scope = Scope::new(
            authority,
            self.stop.child_token(),
            ANTIGRAVITY_SIGN_IN_START_TIMEOUT,
        )?;
        let _permit = {
            let accepting = self.accepting.lock().map_err(|_| Error::Unavailable)?;
            self.admit(*accepting)?
        };
        let started = self
            .shared
            .antigravity_sign_in
            .start()
            .map_err(antigravity_sign_in_error)?;
        let issued_at = started
            .expires_at_unix()
            .checked_sub(ANTIGRAVITY_SIGN_IN_LIFETIME.as_secs())
            .ok_or(Error::Unavailable)?;
        let binding = issued_at.to_string();
        let sealed = scope
            .wait(self.shared.store.seal_transient(
                &scope.owner,
                HANDLE_PURPOSE,
                &binding,
                started.handle().as_bytes(),
            ))
            .await?
            .map_err(store_error)?;
        let mut handle = Zeroizing::new(String::with_capacity(
            HANDLE_VERSION.len() + binding.len() + sealed.len() + 2,
        ));
        handle.push_str(HANDLE_VERSION);
        handle.push('.');
        handle.push_str(&binding);
        handle.push('.');
        handle.push_str(&sealed);
        Ok(StartedSignIn {
            authorize_url: started.authorize_url().to_owned(),
            handle,
            expires_at_unix: started.expires_at_unix(),
        })
    }

    pub(super) async fn complete_antigravity_sign_in(
        &self,
        authority: CredentialMutationAuthority,
        name: String,
        handle: Zeroizing<String>,
        authorization_code: Zeroizing<Vec<u8>>,
        credential_id: Option<String>,
        expected_revision: Option<u64>,
    ) -> Result<CredentialMetadata, Error> {
        validate_name(&name)?;
        if handle.is_empty()
            || handle.len() > MAX_SIGN_IN_HANDLE_BYTES
            || authorization_code.is_empty()
            || authorization_code.len() > MAX_AUTHORIZATION_CODE_BYTES
        {
            return Err(Error::InvalidInput);
        }
        let pasted = Zeroizing::new(
            String::from_utf8(authorization_code.to_vec())
                .map_err(|_| Error::AntigravitySignInCodeInvalid)?,
        );
        drop(authorization_code);
        let replacement = replacement_selector(credential_id, expected_revision)?;
        validate_target_name(&name, replacement.is_some())?;
        handle_issued_at(&handle, unix_now()?)?;
        let scope = Scope::new(
            authority,
            self.stop.child_token(),
            ANTIGRAVITY_SIGN_IN_TIMEOUT,
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
                let result = run(shared, &scope, name, handle, pasted, replacement).await;
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
    name: String,
    handle: Zeroizing<String>,
    pasted: Zeroizing<String>,
    replacement: Option<(CredentialId, u64)>,
) -> Result<CredentialMetadata, Error> {
    let inner = scope
        .wait(open_handle(&shared, &scope.owner, &handle))
        .await??;
    drop(handle);
    let target = enrollment_target(
        &shared,
        scope,
        "google",
        CredentialAuthKind::OAuth,
        name,
        replacement,
    )
    .await?;
    let import = scope
        .wait(shared.antigravity_sign_in.complete(&inner, &pasted))
        .await?
        .map_err(antigravity_sign_in_error)?;
    drop(pasted);
    drop(inner);
    let mut completed = Completed::Antigravity(Some(import));
    publication::enroll(&shared, scope, &mut completed, target)
        .await
        .result
}

/// The issue time of an outer handle, checked against the clock before any
/// KEK work: an expired or future handle is refused at once.
fn handle_issued_at(handle: &str, now: u64) -> Result<u64, Error> {
    let mut parts = handle.splitn(3, '.');
    let (Some(HANDLE_VERSION), Some(issued), Some(sealed)) =
        (parts.next(), parts.next(), parts.next())
    else {
        return Err(Error::AntigravitySignInCodeInvalid);
    };
    let issued_at: u64 = issued
        .parse()
        .ok()
        .filter(|value: &u64| value.to_string() == issued && *value > 0)
        .ok_or(Error::AntigravitySignInCodeInvalid)?;
    if sealed.is_empty() || issued_at > now.saturating_add(MAX_HANDLE_CLOCK_SKEW_SECONDS) {
        return Err(Error::AntigravitySignInCodeInvalid);
    }
    if now >= issued_at.saturating_add(ANTIGRAVITY_SIGN_IN_LIFETIME.as_secs()) {
        return Err(Error::AntigravitySignInExpired);
    }
    Ok(issued_at)
}

/// Open an outer handle sealed to `owner` and return the sign-in's own
/// handle. Another person's, an altered or an expired handle opens nothing.
async fn open_handle(
    shared: &Shared,
    owner: &Owner,
    handle: &str,
) -> Result<Zeroizing<String>, Error> {
    let issued_at = handle_issued_at(handle, unix_now()?)?;
    let binding = issued_at.to_string();
    let sealed = &handle[HANDLE_VERSION.len() + binding.len() + 2..];
    let inner = shared
        .store
        .open_transient(owner, HANDLE_PURPOSE, &binding, sealed)
        .await
        .map_err(|error| match error {
            codewire_platform_credentials::PlatformCredentialError::InvalidInput => {
                Error::AntigravitySignInCodeInvalid
            }
            other => store_error(other),
        })?;
    let inner = Zeroizing::new(
        String::from_utf8(inner.to_vec()).map_err(|_| Error::AntigravitySignInCodeInvalid)?,
    );
    if !inner_handle_matches_binding(&inner, &binding) {
        return Err(Error::AntigravitySignInCodeInvalid);
    }
    Ok(inner)
}

/// Inner handle format from `provider_oauth::antigravity` is
/// `cwag1:<issued_at>:<state>:<verifier>`: verify its issue time matches the
/// outer handle's associated data binding.
fn inner_handle_matches_binding(inner: &str, binding: &str) -> bool {
    let mut parts = inner.split(':');
    matches!(
        (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ),
        (Some(HANDLE_VERSION), Some(issued), Some(_), Some(_), None) if issued == binding
    )
}

/// The sign-in's outcome. No provider text, code or token survives.
pub(super) fn antigravity_sign_in_error(error: AntigravitySignInError) -> Error {
    match error {
        AntigravitySignInError::InvalidCode => Error::AntigravitySignInCodeInvalid,
        AntigravitySignInError::Expired => Error::AntigravitySignInExpired,
        AntigravitySignInError::Unavailable => Error::Unavailable,
        AntigravitySignInError::Denied | AntigravitySignInError::InvalidResponse => {
            Error::EnrollmentFailed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_handle_is_checked_against_the_clock_before_it_is_opened() {
        let now = 1_800_000_000;
        assert_eq!(handle_issued_at(&format!("cwag1.{now}.ab"), now), Ok(now));
        assert_eq!(
            handle_issued_at(&format!("cwag1.{}.ab", now - 899), now),
            Ok(now - 899)
        );
        assert_eq!(
            handle_issued_at(&format!("cwag1.{}.ab", now - 900), now),
            Err(Error::AntigravitySignInExpired)
        );
        assert_eq!(
            handle_issued_at(&format!("cwag1.{}.ab", now + 60), now),
            Ok(now + 60)
        );
        for invalid in [
            format!("cwag1.{}.ab", now + 61),
            format!("cwag1.{now}."),
            format!("cwag1.{now}"),
            format!("cwag1.0{now}.ab"),
            "cwag1.0.ab".to_owned(),
            format!("cwcs2.{now}.ab"),
            format!("cwag1.+{now}.ab"),
            String::new(),
        ] {
            assert_eq!(
                handle_issued_at(&invalid, now),
                Err(Error::AntigravitySignInCodeInvalid),
                "{invalid}"
            );
        }
    }

    #[test]
    fn antigravity_sign_in_failures_are_closed_and_say_what_to_do() {
        assert_eq!(
            antigravity_sign_in_error(AntigravitySignInError::InvalidCode),
            Error::AntigravitySignInCodeInvalid
        );
        assert_eq!(
            antigravity_sign_in_error(AntigravitySignInError::Expired),
            Error::AntigravitySignInExpired
        );
        assert_eq!(
            antigravity_sign_in_error(AntigravitySignInError::Unavailable),
            Error::Unavailable
        );
        for error in [
            AntigravitySignInError::Denied,
            AntigravitySignInError::InvalidResponse,
        ] {
            assert_eq!(antigravity_sign_in_error(error), Error::EnrollmentFailed);
        }
    }

    #[test]
    fn inner_handle_binding_matches_real_started_handle_format() {
        let device = Arc::new(crate::mutation::tests::support::DeviceProvider::default());
        let sign_in = AntigravitySignIn::new(device);
        let started = sign_in.start().unwrap();
        let issued_at = started
            .expires_at_unix()
            .checked_sub(ANTIGRAVITY_SIGN_IN_LIFETIME.as_secs())
            .unwrap()
            .to_string();
        assert!(inner_handle_matches_binding(started.handle(), &issued_at));
        assert!(!inner_handle_matches_binding(started.handle(), "1"));
    }
}
