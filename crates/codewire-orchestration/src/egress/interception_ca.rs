//! An intercepting sandbox's CA certificate at admission (#4001; N4 in
//! private-docs `designs/hosted-egress.md`, "The Sandbox's interception
//! trust"). The credential service makes the CA at its first ask and keeps
//! its key; orchestration asks with its relay token alone, the one call that
//! takes it (`EnsureInterceptionCa`), and hands cw-egress the certificate for
//! the guest's trust frame.

use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use codewire_daemon_proto::broker::v1::EnsureInterceptionCaRequest;
use codewire_daemon_proto::broker::v1::credential_broker_service_client::CredentialBrokerServiceClient;
use codewire_tls::ClientTlsEndpoint;
use tonic::metadata::MetadataValue;
use zeroize::Zeroizing;

use crate::worker::credential_relay::read_relay_token;

/// The longest the credential service may take; an admission waits for it.
const ENSURE_TIMEOUT: Duration = Duration::from_secs(10);
/// The largest certificate the trust frame carries
/// (`codewire_network_session::protocol`'s bound).
pub const MAX_CA_CERTIFICATE_BYTES: usize = 4096;

/// Where an intercepting sandbox's CA certificate comes from.
#[async_trait]
pub trait InterceptionCaSource: Send + Sync {
    /// The Pod's CA certificate in DER, made at the first ask and the same for
    /// the Pod's life.
    async fn ensure(&self, pod_uid: &str, pod_name: &str) -> Result<Vec<u8>, CaUnavailable>;
}

/// No CA certificate could be had. It names no Pod and no reason beyond its
/// class, so it may be logged.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CaUnavailable {
    #[error("the relay token could not be read")]
    Token,
    #[error("the credential service could not be reached")]
    Connect,
    #[error("the credential service refused or failed the request")]
    Refused,
    #[error("the credential service's certificate is empty or too large")]
    Malformed,
}

/// The credential service's `EnsureInterceptionCa`, asked over the relay's
/// private TLS endpoint with orchestration's relay token and nothing else.
pub struct RelayInterceptionCas {
    pub broker: ClientTlsEndpoint,
    pub relay_token: PathBuf,
}

#[async_trait]
impl InterceptionCaSource for RelayInterceptionCas {
    async fn ensure(&self, pod_uid: &str, pod_name: &str) -> Result<Vec<u8>, CaUnavailable> {
        let token = read_relay_token(&self.relay_token)
            .await
            .map_err(|()| CaUnavailable::Token)?;
        let authorization = Zeroizing::new(format!("Bearer {}", token.as_str()));
        let mut bearer =
            MetadataValue::try_from(authorization.as_str()).map_err(|_| CaUnavailable::Token)?;
        bearer.set_sensitive(true);
        let ask = async {
            let channel = self
                .broker
                .connect()
                .await
                .map_err(|_| CaUnavailable::Connect)?;
            let mut request = tonic::Request::new(EnsureInterceptionCaRequest {
                pod_uid: pod_uid.to_owned(),
                pod_name: pod_name.to_owned(),
            });
            request.metadata_mut().insert("authorization", bearer);
            CredentialBrokerServiceClient::new(channel)
                .ensure_interception_ca(request)
                .await
                .map_err(|_| CaUnavailable::Refused)
        };
        let response = tokio::time::timeout(ENSURE_TIMEOUT, ask)
            .await
            .map_err(|_| CaUnavailable::Connect)??;
        checked(response.into_inner().ca_certificate_der)
    }
}

/// A certificate the trust frame can carry: present and within its bound.
pub fn checked(certificate: Vec<u8>) -> Result<Vec<u8>, CaUnavailable> {
    if certificate.is_empty() || certificate.len() > MAX_CA_CERTIFICATE_BYTES {
        return Err(CaUnavailable::Malformed);
    }
    Ok(certificate)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_certificate_the_trust_frame_cannot_carry_is_refused() {
        assert_eq!(checked(Vec::new()), Err(CaUnavailable::Malformed));
        assert_eq!(
            checked(vec![1; MAX_CA_CERTIFICATE_BYTES + 1]),
            Err(CaUnavailable::Malformed)
        );
        assert_eq!(
            checked(vec![1; MAX_CA_CERTIFICATE_BYTES]).map(|certificate| certificate.len()),
            Ok(MAX_CA_CERTIFICATE_BYTES)
        );
    }
}
