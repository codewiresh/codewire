use std::fmt;
use std::net::SocketAddr;

use rustls::pki_types::{CertificateDer, ServerName};
use rustls::server::ParsedCertificate;

/// The peer of one connection accepted by [`crate::PeerTlsListener`].
#[derive(Clone, Debug)]
pub struct TlsPeer {
    pub address: SocketAddr,
    /// The client's verified certificate, or `None` when it offered none.
    pub client: Option<VerifiedClient>,
}

/// A client certificate the handshake verified against the listener's client
/// roots: it chains to them and is within its validity. Which client it
/// names is the caller's question.
///
/// Two limits make a dedicated authority the rule. A certificate that
/// restricts its extended key usage must allow client authentication, but
/// one with no such restriction is accepted. And [`Self::is_named`] honours
/// a wildcard name. So the client roots must belong to an authority that
/// signs only the intended clients, by exact name.
#[derive(Clone)]
pub struct VerifiedClient(CertificateDer<'static>);

impl fmt::Debug for VerifiedClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VerifiedClient([redacted])")
    }
}

impl VerifiedClient {
    pub(crate) fn new(leaf: CertificateDer<'static>) -> Self {
        Self(leaf)
    }

    /// Whether the certificate is valid for `dns_name`, by the rule a TLS
    /// client applies to a server name: a subject alternative DNS name must
    /// match, without regard to case and with `*` standing for one leading
    /// label, and the common name is never consulted.
    pub fn is_named(&self, dns_name: &str) -> bool {
        let Ok(name @ ServerName::DnsName(_)) = ServerName::try_from(dns_name) else {
            return false;
        };
        ParsedCertificate::try_from(&self.0)
            .is_ok_and(|leaf| rustls::client::verify_server_name(&leaf, &name).is_ok())
    }
}
