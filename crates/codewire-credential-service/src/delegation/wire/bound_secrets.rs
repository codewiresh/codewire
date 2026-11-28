//! A local VM's record of its platform sources' bound secrets (#4003;
//! docs/dev/SECRETS-AND-CREDENTIALS.md, "A local VM's platform sources"):
//! before the boot starts, every platform secret its projection would take,
//! and the platform's seal over them. The selection is admitted exactly as
//! the seed placeholders' is. Each call is counted by its outcome; no record
//! or seal is ever logged.

use std::time::Instant;

use codewire_credential_broker::BrokerUpstreamTransport;
use codewire_credential_broker::platform::bridge::PlatformBridgeAuthenticator;
use codewire_platform_credentials::PlatformAccessProfileStore;
use codewire_proto::codewire::v1 as proto;
use codewire_server_core::auth::OAuthBearerAuthority;

use super::seed::Refusal;
use super::{MAX_SELECTION_BYTES, Service, authority_error, selection};
use crate::delegation::OwnerLocalRuntimeAuthority;
use crate::delegation::boot_record::{SealRefusal, record_to_proto};

/// Why a call wasn't answered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum BoundRefusal {
    /// This service has no seal key, so it doesn't serve the question.
    NotConfigured,
    Admission(Refusal),
}

impl BoundRefusal {
    fn outcome(self) -> &'static str {
        match self {
            Self::NotConfigured => "not_configured",
            Self::Admission(Refusal::Denied) => "denied",
            Self::Admission(Refusal::Unavailable) => "unavailable",
            Self::Admission(Refusal::RateLimited) => "rate_limited",
        }
    }

    pub(super) fn status(self) -> connectrpc::ConnectError {
        match self {
            Self::NotConfigured => connectrpc::ConnectError::unimplemented(
                "this platform keeps no record of a local VM's bound secrets",
            ),
            Self::Admission(Refusal::Denied) => connectrpc::ConnectError::permission_denied(
                "bound secrets denied for this selection",
            ),
            Self::Admission(Refusal::Unavailable) => {
                connectrpc::ConnectError::unavailable("bound secrets unavailable")
            }
            Self::Admission(Refusal::RateLimited) => connectrpc::ConnectError::resource_exhausted(
                "too many bound secrets requests; try again in a minute",
            ),
        }
    }
}

impl From<Refusal> for BoundRefusal {
    fn from(refusal: Refusal) -> Self {
        Self::Admission(refusal)
    }
}

impl From<SealRefusal> for BoundRefusal {
    fn from(refusal: SealRefusal) -> Self {
        match refusal {
            SealRefusal::NotConfigured => Self::NotConfigured,
            SealRefusal::Denied => Self::Admission(Refusal::Denied),
            SealRefusal::Unavailable => Self::Admission(Refusal::Unavailable),
        }
    }
}

impl<A, U> Service<A, U>
where
    A: PlatformBridgeAuthenticator + 'static,
    U: BrokerUpstreamTransport + Clone + 'static,
{
    /// One call's answer, counted by its outcome.
    pub(super) async fn boot_bound_secrets(
        &self,
        oauth: OAuthBearerAuthority,
        request: connectrpc::ServiceRequest<'_, proto::EnvironmentBoundSecretsRequest>,
    ) -> Result<proto::EnvironmentBoundSecretsResponse, BoundRefusal> {
        let result = self.answer_bound_secrets(oauth, request).await;
        match &result {
            Ok(response) => tracing::info!(
                event = "boot_bound_secrets",
                outcome = "answered",
                secrets = response
                    .record
                    .as_option()
                    .map_or(0, |record| record.secrets.len()),
                "bound secrets answered for a local VM's boot"
            ),
            Err(refusal) => tracing::warn!(
                event = "boot_bound_secrets",
                outcome = refusal.outcome(),
                "bound secrets refused for a local VM's boot"
            ),
        }
        result
    }

    async fn answer_bound_secrets(
        &self,
        oauth: OAuthBearerAuthority,
        request: connectrpc::ServiceRequest<'_, proto::EnvironmentBoundSecretsRequest>,
    ) -> Result<proto::EnvironmentBoundSecretsResponse, BoundRefusal> {
        if !self.seal.configured() {
            return Err(BoundRefusal::NotConfigured);
        }
        if !self.bound_rate.admit(oauth.user_id(), Instant::now()) {
            return Err(Refusal::RateLimited.into());
        }
        if request.bytes().len() > MAX_SELECTION_BYTES {
            return Err(Refusal::Denied.into());
        }
        let request = request.to_owned_message();
        let open = request.selection.into_option().ok_or(Refusal::Denied)?;
        // The question is what makes a record; one can't come with it.
        if open.bound_secrets.as_option().is_some() {
            return Err(Refusal::Denied.into());
        }
        let selection = selection(open, oauth.user_id()).map_err(Refusal::from)?;
        let boot = selection.sealed_boot();
        let expiry = u64::try_from(oauth.expires_at().timestamp()).map_err(|_| Refusal::Denied)?;
        // Every check a delegation's admission of this boot makes, before
        // any source is read.
        let admitted = OwnerLocalRuntimeAuthority::new(
            self.pool.clone(),
            self.provider.clone(),
            PlatformAccessProfileStore::new(
                self.pool.clone(),
                codewire_access::builtin_provider_catalog(),
            ),
            oauth,
            selection,
            expiry,
        )
        .await
        .map_err(|error| Refusal::from(authority_error(error)))?;
        let secrets = admitted
            .boot_record()
            .await
            .map_err(|error| Refusal::from(authority_error(error)))?;
        let seal = self.seal.seal(&boot, &secrets).await?;
        Ok(proto::EnvironmentBoundSecretsResponse {
            record: Some(record_to_proto(codewire_access::PlatformBootRecord {
                secrets,
                seal,
            }))
            .into(),
            ..Default::default()
        })
    }
}
