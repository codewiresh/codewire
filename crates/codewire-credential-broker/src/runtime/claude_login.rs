//! The sealed Claude login: a listed direct delivery exception, or beside
//! the environment's front door a login whose access token is the
//! environment's placeholder (#3999).

use super::*;

impl<P, U> OpenAiBroker<P, U>
where
    P: BrokerLeaseProvider + 'static,
    U: BrokerUpstreamTransport + 'static,
{
    /// Seal the environment creator's own personal Claude sign-in to the
    /// recipient key of a hosted Sandbox's workspace daemon or a local VM's
    /// guest daemon, which writes it as `claudeAiOauth` in Claude
    /// Code's `~/.claude/.credentials.json`: the other listed direct delivery
    /// exception. Claude Code shows `/usage` and its plan only with its own
    /// claude.ai login, whose account calls ignore `ANTHROPIC_BASE_URL`, so the
    /// proxy cannot answer them.
    ///
    /// The placement's `lease_claude_login` decides delivery: never an API key
    /// or a Claude subscription token. The access token is refreshed first,
    /// through the same serialized path proxied requests use, unless it stays
    /// valid for thirty minutes (capped at half its lifetime). The sealed
    /// plaintext carries the access token, its expiry, the granted scopes, the
    /// plan, the rate-limit tier and the refresh time, bound as the Codex
    /// login is. The refresh token never leaves the broker.
    pub(crate) async fn claude_login(
        &self,
        request: v1::ClaudeLoginRequest,
    ) -> Result<Vec<u8>, BrokerRequestError> {
        let login = LoginRequest::parse(
            &request.request_id,
            &request.recipient_public_key,
            request.deadline_unix_ms,
            timing::claude_login_refused,
        )?;
        if self.login_delivery == LoginDelivery::Refused {
            timing::claude_login_refused("front_door_not_paired");
            return Err(BrokerRequestError::Denied);
        }
        let purpose = OAuthPurpose::ClaudeLogin;
        let lease = self.lease_oauth(login.request_id, &purpose).await?;
        // Beside the front door the login's access token is this
        // environment's placeholder, and there is no login without one
        // (#3999): the front door swaps it for the sign-in's token on its way
        // to Anthropic. Everything else is the sign-in's own, so Claude Code
        // shows its plan and refreshes at its expiry.
        let placeholder = match self.login_delivery {
            LoginDelivery::Placeholder => Some(lease.placeholder().cloned().ok_or_else(|| {
                timing::claude_login_refused("no_placeholder_beside_front_door");
                BrokerRequestError::Denied
            })?),
            LoginDelivery::Real | LoginDelivery::Refused => None,
        };
        let admitted_grant = lease.grant().clone();
        let generation = refresh_generation(&lease);
        let credential = self.claude_oauth_credential(lease, &purpose)?;
        let (credential, generation) = if credential
            .should_refresh_within(current_unix_time()?, CLAUDE_LOGIN_MINIMUM_VALIDITY_SECONDS)
        {
            drop(credential);
            self.fresh_oauth_credential(
                login.request_id,
                &purpose,
                |lease| self.claude_oauth_credential(lease, &purpose),
                None,
                &admitted_grant,
                CLAUDE_LOGIN_MINIMUM_VALIDITY_SECONDS,
            )
            .await?
        } else {
            (credential, generation)
        };

        // Deliver only the scopes the sign-in asks for: a refresh may replace
        // the stored set, and a scope Claude adds later must not widen the
        // exception.
        if !crate::claude_oauth::within_sign_in_scopes(credential.scopes()) {
            timing::claude_login_refused("scopes_outside_sign_in");
            return Err(BrokerRequestError::Denied);
        }
        let access_token = match &placeholder {
            Some(placeholder) => placeholder.as_str(),
            None => credential.access_token(),
        };
        let claude = ClaudeLogin::new(
            Zeroizing::new(access_token.to_owned()),
            credential
                .expires_at_unix()
                .checked_mul(1_000)
                .ok_or(BrokerRequestError::Denied)?,
            credential.scopes().to_vec(),
            credential
                .subscription_type()
                .map(|plan| plan.as_str().to_owned()),
            credential.rate_limit_tier().map(str::to_owned),
            credential.refreshed_at_unix(),
        )
        .map_err(|_| BrokerRequestError::Denied)?;
        drop(credential);
        let (binding, context) = login.bind(&admitted_grant, &generation)?;
        seal_claude_login(
            &claude,
            &binding,
            &context,
            login.recipient,
            current_unix_time_ms()?,
        )
        .map_err(|error| match error {
            codewire_workload_secrets::ClaudeLoginError::InvalidContext => {
                timing::claude_login_refused("deadline_passed_before_seal");
                BrokerRequestError::AuthorityUnavailable
            }
            _ => BrokerRequestError::Denied,
        })
    }
}
