//! The placeholder-only sealed Antigravity login (#6555).
//!
//! Unlike Codex and Claude direct-delivery exceptions, real Google OAuth tokens
//! NEVER leave the broker: `antigravity_login` is admitted ONLY when the broker
//! is paired with the environment's front door (`LoginDelivery::Placeholder`),
//! and seals ONLY the environment's `cwp1_` placeholder, an optional account
//! email hint, and the broker's refresh timestamp. Non-intercepted boots
//! (`LoginDelivery::Real`) and unpaired restarts (`LoginDelivery::Refused`)
//! are both refused with `Denied`.

use codewire_workload_secrets::{AntigravityLogin, seal_antigravity_login};

use super::*;
use crate::antigravity_oauth::within_antigravity_scopes;

impl<P, U> OpenAiBroker<P, U>
where
    P: BrokerLeaseProvider + 'static,
    U: BrokerUpstreamTransport + 'static,
{
    /// Seal the placeholder-only Antigravity login for the workspace daemon to
    /// write `~/.gemini/antigravity-cli/antigravity-oauth-token`.
    pub(crate) async fn antigravity_login(
        &self,
        request: v1::AntigravityLoginRequest,
    ) -> Result<Vec<u8>, BrokerRequestError> {
        let login = LoginRequest::parse(
            &request.request_id,
            &request.recipient_public_key,
            request.deadline_unix_ms,
            timing::antigravity_login_refused,
        )?;
        // Antigravity has zero direct delivery: real Google tokens never leave
        // the broker. Only an intercepted session paired with a front door may
        // receive the placeholder-backed login file.
        if self.login_delivery != LoginDelivery::Placeholder {
            timing::antigravity_login_refused("front_door_not_paired");
            return Err(BrokerRequestError::Denied);
        }
        let purpose = OAuthPurpose::AntigravityLogin;
        let lease = self.lease_oauth(login.request_id, &purpose).await?;
        let placeholder = lease.placeholder().cloned().ok_or_else(|| {
            timing::antigravity_login_refused("no_placeholder_beside_front_door");
            BrokerRequestError::Denied
        })?;
        let admitted_grant = lease.grant().clone();
        let generation = refresh_generation(&lease);
        let credential = self.antigravity_oauth_credential(lease, &purpose)?;
        let (credential, generation) = if credential.should_refresh(current_unix_time()?) {
            drop(credential);
            self.fresh_oauth_credential(
                login.request_id,
                &purpose,
                |lease| self.antigravity_oauth_credential(lease, &purpose),
                None,
                &admitted_grant,
                ACCESS_TOKEN_REFRESH_WINDOW_SECONDS,
            )
            .await?
        } else {
            (credential, generation)
        };
        if !within_antigravity_scopes(credential.scopes()) {
            timing::antigravity_login_refused("scopes_outside_sign_in");
            return Err(BrokerRequestError::Denied);
        }
        let account_hint = credential
            .account_hint()
            .filter(|hint| crate::antigravity_oauth::is_valid_account_hint(hint))
            .map(str::to_owned);
        let antigravity = AntigravityLogin::new(
            Zeroizing::new(placeholder.as_str().to_owned()),
            account_hint,
            credential.refreshed_at_unix(),
        )
        .map_err(|_| BrokerRequestError::Denied)?;
        drop(credential);
        let (binding, context) = login.bind(&admitted_grant, &generation)?;
        seal_antigravity_login(
            &antigravity,
            &binding,
            &context,
            login.recipient,
            current_unix_time_ms()?,
        )
        .map_err(|error| match error {
            codewire_workload_secrets::AntigravityLoginError::InvalidContext => {
                timing::antigravity_login_refused("deadline_passed_before_seal");
                BrokerRequestError::AuthorityUnavailable
            }
            _ => BrokerRequestError::Denied,
        })
    }
}
