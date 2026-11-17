//! The sealed Codex login: a listed direct delivery exception, or beside the
//! environment's front door a login of placeholders (#3999).

use codewire_daemon_proto::codewire::bridge::v1;
use codewire_workload_secrets::{CodexLogin, seal_codex_login};
use zeroize::Zeroizing;

use super::{
    BrokerLeaseProvider, BrokerRequestError, BrokerUpstreamTransport,
    CODEX_LOGIN_MINIMUM_VALIDITY_SECONDS, LoginDelivery, LoginRequest, OAuthPurpose, OpenAiBroker,
    current_unix_time, current_unix_time_ms, refresh_generation, timing,
};
use crate::BrokerCredentialLease as _;

impl<P, U> OpenAiBroker<P, U>
where
    P: BrokerLeaseProvider + 'static,
    U: BrokerUpstreamTransport + 'static,
{
    /// Seal the environment creator's own personal Codex ChatGPT login to the
    /// recipient key of a hosted Sandbox's workspace daemon or a local VM's
    /// guest daemon: a listed direct delivery exception
    /// (docs/dev/SECRETS-AND-CREDENTIALS.md, "Direct delivery exceptions").
    /// Codex enables `/usage`, analytics and account routing only with its own
    /// login, which a proxy cannot supply.
    ///
    /// The placement's `lease_codex_login` decides delivery. The access token
    /// is refreshed first, through the same serialized path proxied requests
    /// use, unless it stays valid for thirty minutes (capped at half its
    /// lifetime). The sealed plaintext carries the access token, ID token,
    /// account ID and refresh time, and is bound to this environment and
    /// generation, the request, the recipient, its deadline and the exact
    /// credential version. The refresh token never leaves the broker.
    ///
    /// Beside the environment's front door (#3999) the access token is the
    /// lease's placeholder and the ID token holds only allow-listed claims,
    /// so the environment never sees the sign-in's tokens; a lease with no
    /// placeholder delivers nothing.
    pub(crate) async fn codex_login(
        &self,
        request: v1::CodexLoginRequest,
    ) -> Result<Vec<u8>, BrokerRequestError> {
        let login = LoginRequest::parse(
            &request.request_id,
            &request.recipient_public_key,
            request.deadline_unix_ms,
            timing::codex_login_refused,
        )?;
        if self.login_delivery == LoginDelivery::Refused {
            timing::codex_login_refused("front_door_not_paired");
            return Err(BrokerRequestError::Denied);
        }
        let purpose = OAuthPurpose::CodexLogin;
        let lease = self.lease_oauth(login.request_id, &purpose).await?;
        // Beside the front door the environment gets this placeholder in
        // place of the tokens, and nothing without one (#3999). Unpaired, a
        // lease may carry a placeholder too and is still served with the real
        // login: the authority attaches one to every lease once its key is
        // loaded for any environment on the host, so refusing it would break
        // direct delivery for every environment without a front door.
        let placeholder = match self.login_delivery {
            LoginDelivery::Placeholder => Some(lease.placeholder().cloned().ok_or_else(|| {
                timing::codex_login_refused("no_placeholder_beside_front_door");
                BrokerRequestError::Denied
            })?),
            LoginDelivery::Real | LoginDelivery::Refused => None,
        };
        let admitted_grant = lease.grant().clone();
        let generation = refresh_generation(&lease);
        let credential = self.codex_oauth_credential(lease, &purpose)?;
        let (credential, generation) = if credential
            .should_refresh_within(current_unix_time()?, CODEX_LOGIN_MINIMUM_VALIDITY_SECONDS)
        {
            drop(credential);
            self.fresh_oauth_credential(
                login.request_id,
                &purpose,
                |lease| self.codex_oauth_credential(lease, &purpose),
                None,
                &admitted_grant,
                CODEX_LOGIN_MINIMUM_VALIDITY_SECONDS,
            )
            .await?
        } else {
            (credential, generation)
        };

        let (access_token, id_token) = match &placeholder {
            Some(placeholder) => (
                Zeroizing::new(placeholder.as_str().to_owned()),
                credential
                    .placeholder_id_token()
                    .map_err(|_| BrokerRequestError::Denied)?,
            ),
            None => (
                Zeroizing::new(credential.access_token().to_owned()),
                Zeroizing::new(credential.id_token().to_owned()),
            ),
        };
        let codex = CodexLogin::new(
            access_token,
            id_token,
            credential.account_id().to_owned(),
            credential.refreshed_at_unix(),
        )
        .map_err(|_| BrokerRequestError::Denied)?;
        drop(credential);
        let (binding, context) = login.bind(&admitted_grant, &generation)?;
        seal_codex_login(
            &codex,
            &binding,
            &context,
            login.recipient,
            current_unix_time_ms()?,
        )
        .map_err(|error| match error {
            codewire_workload_secrets::CodexLoginError::InvalidContext => {
                timing::codex_login_refused("deadline_passed_before_seal");
                BrokerRequestError::AuthorityUnavailable
            }
            _ => BrokerRequestError::Denied,
        })
    }
}
