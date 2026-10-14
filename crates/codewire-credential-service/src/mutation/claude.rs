//! Claude sign-in by pasted code: Claude Code's own claude.ai OAuth login.
//!
//! Start creates the PKCE verifier and state and returns Claude's authorize
//! URL with an opaque handle; nothing is sent to Claude or stored, so either
//! replica can complete it. The handle is the verifier and state sealed with
//! the credential store's KEK, bound to the person who started the sign-in,
//! its purpose and its issue time, so Complete refuses another person's
//! handle, an altered one and one issued more than 15 minutes ago, before
//! Claude is contacted. Complete checks the pasted `code#state` against the
//! handle, exchanges the code, reads the plan and publishes the login through
//! the same enrollment fences as every other OAuth connection. A failed
//! completion stores nothing and drops the tokens from memory; nothing
//! revokes them.

use std::sync::Arc;
use std::time::Duration;

use codewire_access::{CredentialAuthKind, CredentialId, Owner};
use codewire_credential_broker::provider_oauth::claude::{
    CLAUDE_SIGN_IN_LIFETIME, ClaudeSignInError,
};
use codewire_platform_credentials::MAX_SEALED_TRANSIENT_TEXT_BYTES;
use tokio::sync::oneshot;
use zeroize::Zeroizing;

use super::enrollment::Completed;
use super::*;

/// The code exchange and the profile read, with their publication.
const CLAUDE_SIGN_IN_TIMEOUT: Duration = Duration::from_secs(75);
/// Sealing at Start: one KEK data-key request.
const CLAUDE_SIGN_IN_START_TIMEOUT: Duration = Duration::from_secs(35);
const MAX_AUTHORIZATION_CODE_BYTES: usize = 4096;
/// The handle's version prefix: `cwcs2.<issued_at>.<sealed>`.
const HANDLE_VERSION: &str = "cwcs2";
/// The purpose the handle is sealed under, bound as associated data.
const HANDLE_PURPOSE: &str = "claude-sign-in-handle";
/// A handle stamped this far in the future is refused (clock skew between
/// replicas is far smaller).
const MAX_HANDLE_CLOCK_SKEW_SECONDS: u64 = 60;
const MAX_SIGN_IN_HANDLE_BYTES: usize = HANDLE_VERSION.len() + 22 + MAX_SEALED_TRANSIENT_TEXT_BYTES;

/// A started sign-in as the service returns it.
pub(super) struct StartedSignIn {
    pub authorize_url: String,
    pub handle: Zeroizing<String>,
    pub expires_at_unix: u64,
}

impl CredentialMutationOwner {
    /// Begin a Claude sign-in for the authenticated person. The handle carries
    /// this sign-in's verifier and state, sealed to this person and its issue
    /// time, back to [`Self::complete_claude_sign_in`].
    pub(super) async fn start_claude_sign_in(
        &self,
        authority: CredentialMutationAuthority,
    ) -> Result<StartedSignIn, Error> {
        let scope = Scope::new(
            authority,
            self.stop.child_token(),
            CLAUDE_SIGN_IN_START_TIMEOUT,
        )?;
        // Sealing asks the KEK for a data key: admitted like other work.
        let _permit = {
            let accepting = self.accepting.lock().map_err(|_| Error::Unavailable)?;
            self.admit(*accepting)?
        };
        let started = self
            .shared
            .claude_sign_in
            .start()
            .map_err(claude_sign_in_error)?;
        let issued_at = started
            .expires_at_unix()
            .checked_sub(CLAUDE_SIGN_IN_LIFETIME.as_secs())
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

    pub(super) async fn complete_claude_sign_in(
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
                .map_err(|_| Error::ClaudeSignInCodeInvalid)?,
        );
        drop(authorization_code);
        let replacement = replacement_selector(credential_id, expected_revision)?;
        // A malformed, expired or future handle is refused before any work.
        handle_issued_at(&handle, unix_now()?)?;
        let scope = Scope::new(authority, self.stop.child_token(), CLAUDE_SIGN_IN_TIMEOUT)?;
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
    // Only this person's unaltered handle opens.
    let inner = scope
        .wait(open_handle(&shared, &scope.owner, &handle))
        .await??;
    drop(handle);
    // The exact owner, name, kind and version are checked before Claude is
    // contacted, and the record is kept through publication.
    let target = enrollment_target(
        &shared,
        scope,
        "anthropic",
        CredentialAuthKind::ClaudeSignIn,
        name,
        replacement,
    )
    .await?;
    let import = scope
        .wait(shared.claude_sign_in.complete(&inner, &pasted))
        .await?
        .map_err(claude_sign_in_error)?;
    drop(pasted);
    drop(inner);
    let mut completed = Completed::Claude(Some(import));
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
        return Err(Error::ClaudeSignInCodeInvalid);
    };
    let issued_at: u64 = issued
        .parse()
        .ok()
        .filter(|value: &u64| value.to_string() == issued && *value > 0)
        .ok_or(Error::ClaudeSignInCodeInvalid)?;
    if sealed.is_empty() || issued_at > now.saturating_add(MAX_HANDLE_CLOCK_SKEW_SECONDS) {
        return Err(Error::ClaudeSignInCodeInvalid);
    }
    if now >= issued_at.saturating_add(CLAUDE_SIGN_IN_LIFETIME.as_secs()) {
        return Err(Error::ClaudeSignInExpired);
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
                Error::ClaudeSignInCodeInvalid
            }
            other => store_error(other),
        })?;
    let inner = Zeroizing::new(
        String::from_utf8(inner.to_vec()).map_err(|_| Error::ClaudeSignInCodeInvalid)?,
    );
    // The sealed handle names the same issue time it was bound to.
    if inner.rsplit('.').next() != Some(binding.as_str()) {
        return Err(Error::ClaudeSignInCodeInvalid);
    }
    Ok(inner)
}

/// The sign-in's outcome. No provider text, code or token survives.
pub(super) fn claude_sign_in_error(error: ClaudeSignInError) -> Error {
    match error {
        ClaudeSignInError::InvalidCode => Error::ClaudeSignInCodeInvalid,
        ClaudeSignInError::Expired => Error::ClaudeSignInExpired,
        ClaudeSignInError::Unavailable => Error::Unavailable,
        // Claude refused the code (already used, or not for this sign-in), or
        // answered outside its protocol: this attempt failed.
        ClaudeSignInError::Denied | ClaudeSignInError::InvalidResponse => Error::EnrollmentFailed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_handle_is_checked_against_the_clock_before_it_is_opened() {
        let now = 1_800_000_000;
        assert_eq!(handle_issued_at(&format!("cwcs2.{now}.ab"), now), Ok(now));
        assert_eq!(
            handle_issued_at(&format!("cwcs2.{}.ab", now - 899), now),
            Ok(now - 899)
        );
        assert_eq!(
            handle_issued_at(&format!("cwcs2.{}.ab", now - 900), now),
            Err(Error::ClaudeSignInExpired)
        );
        assert_eq!(
            handle_issued_at(&format!("cwcs2.{}.ab", now + 60), now),
            Ok(now + 60)
        );
        for invalid in [
            format!("cwcs2.{}.ab", now + 61),
            format!("cwcs2.{now}."),
            format!("cwcs2.{now}"),
            format!("cwcs2.0{now}.ab"),
            "cwcs2.0.ab".to_owned(),
            format!("cwcs1.state.verifier.{now}"),
            format!("cwcs2.+{now}.ab"),
            String::new(),
        ] {
            assert_eq!(
                handle_issued_at(&invalid, now),
                Err(Error::ClaudeSignInCodeInvalid),
                "{invalid}"
            );
        }
    }

    #[test]
    fn claude_sign_in_failures_are_closed_and_say_what_to_do() {
        assert_eq!(
            claude_sign_in_error(ClaudeSignInError::InvalidCode),
            Error::ClaudeSignInCodeInvalid
        );
        assert_eq!(
            claude_sign_in_error(ClaudeSignInError::Expired),
            Error::ClaudeSignInExpired
        );
        assert_eq!(
            claude_sign_in_error(ClaudeSignInError::Unavailable),
            Error::Unavailable
        );
        for error in [
            ClaudeSignInError::Denied,
            ClaudeSignInError::InvalidResponse,
        ] {
            assert_eq!(claude_sign_in_error(error), Error::EnrollmentFailed);
        }
    }
}
