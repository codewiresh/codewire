//! The certificate of a local VM's egress CA (#3999), the one piece of the
//! TLS front door the guest receives.
//!
//! The front door generates the CA in its own memory at each boot, name
//! constrained to the hosts it intercepts, and the runner carries only its
//! certificate to the guest in the seed. A certificate is public trust
//! material: the key never leaves the front door, and the guest never learns
//! which hosts are bound beyond what the certificate's own name constraints
//! say. A seed without one is a boot without interception, exactly as before.

use std::fmt;

use thiserror::Error;
use x509_parser::prelude::{FromDer as _, X509Certificate};

mod subject_hash;

/// The most DER bytes the seed holds: everything between the credential
/// placeholders, after the longest daemon token, and the checksum. An ECDSA
/// P-256 CA constrained to a handful of hosts is about 600 bytes.
pub const MAX_EGRESS_CA_DER_BYTES: usize = 3084;

/// The DER of one X.509 CA certificate. It parses as a certificate, with
/// nothing after it, whose basic constraints mark it a CA, so neither a key
/// nor a leaf certificate can ever be taken for it. The host that sends it is
/// trusted; the full parse is there so that a host-side mistake can never
/// put a key in front of the workspace's trust. It is a parse only: the
/// guest links no signature verification and no C code.
#[derive(Clone, PartialEq, Eq)]
pub struct EgressCaCertificate(Vec<u8>);

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EgressCaError {
    #[error("the egress CA certificate is {actual} bytes; at most {MAX_EGRESS_CA_DER_BYTES} fit")]
    TooLarge { actual: usize },
    #[error("the egress CA certificate is not one DER X.509 certificate")]
    NotACertificate,
    #[error("the egress CA certificate is not a CA certificate")]
    NotACa,
    #[error("the egress CA certificate's subject has no OpenSSL subject hash")]
    UnsupportedSubject,
}

impl EgressCaCertificate {
    pub fn from_der(der: Vec<u8>) -> Result<Self, EgressCaError> {
        if der.len() > MAX_EGRESS_CA_DER_BYTES {
            return Err(EgressCaError::TooLarge { actual: der.len() });
        }
        let (rest, certificate) =
            X509Certificate::from_der(&der).map_err(|_| EgressCaError::NotACertificate)?;
        if !rest.is_empty() {
            return Err(EgressCaError::NotACertificate);
        }
        if !certificate.is_ca() {
            return Err(EgressCaError::NotACa);
        }
        Ok(Self(der))
    }

    pub fn der(&self) -> &[u8] {
        &self.0
    }

    /// OpenSSL's subject-hash name for this certificate, as
    /// `openssl x509 -subject_hash` prints it: a hashed certificate
    /// directory holds it as `<hash>.0`.
    pub fn subject_hash(&self) -> Result<String, EgressCaError> {
        subject_hash::subject_hash(&self.0)
    }

    /// The certificate as one PEM block, the form trust stores and
    /// `NODE_EXTRA_CA_CERTS` read.
    pub fn to_pem(&self) -> String {
        use base64::Engine as _;
        let encoded = base64::engine::general_purpose::STANDARD.encode(&self.0);
        let mut pem = String::with_capacity(encoded.len() + encoded.len() / 64 + 64);
        pem.push_str("-----BEGIN CERTIFICATE-----\n");
        for line in encoded.as_bytes().chunks(64) {
            // Base64 output is ASCII, so every chunk is valid UTF-8.
            pem.push_str(std::str::from_utf8(line).unwrap_or_default());
            pem.push('\n');
        }
        pem.push_str("-----END CERTIFICATE-----\n");
        pem
    }
}

impl fmt::Debug for EgressCaCertificate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "EgressCaCertificate({} bytes)", self.0.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn front_door_ca() -> Vec<u8> {
        codewire_egress_front_door::EnvironmentCa::generate(["api.anthropic.com"])
            .unwrap()
            .certificate_der()
            .to_vec()
    }

    #[test]
    fn a_front_door_ca_is_accepted_and_its_bytes_kept() {
        let der = front_door_ca();
        let certificate = EgressCaCertificate::from_der(der.clone()).unwrap();
        assert_eq!(certificate.der(), der);
    }

    #[test]
    fn a_key_is_never_taken_for_a_certificate() {
        let key = rcgen::KeyPair::generate().unwrap();
        assert_eq!(
            EgressCaCertificate::from_der(key.serialize_der()),
            Err(EgressCaError::NotACertificate)
        );
    }

    #[test]
    fn a_leaf_certificate_is_not_a_ca() {
        let key = rcgen::KeyPair::generate().unwrap();
        let leaf = rcgen::CertificateParams::new(vec!["api.anthropic.com".to_owned()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        assert_eq!(
            EgressCaCertificate::from_der(leaf.der().to_vec()),
            Err(EgressCaError::NotACa)
        );
    }

    #[test]
    fn anything_but_exactly_one_certificate_is_refused() {
        let mut trailing = front_door_ca();
        trailing.push(0);
        let mut short = front_door_ca();
        short.pop();
        for der in [Vec::new(), vec![0x30, 0x00], trailing, short] {
            assert_eq!(
                EgressCaCertificate::from_der(der),
                Err(EgressCaError::NotACertificate)
            );
        }
    }

    /// The seed's header grew by the runtime move's digest (#4980), which
    /// took 32 bytes from the CA's room (cw-security, 2026-11-16), and seed
    /// format 12's GitHub placeholder entry took 49 more (#4001).
    #[test]
    fn the_seed_holds_exactly_3084_bytes_of_ca() {
        assert_eq!(MAX_EGRESS_CA_DER_BYTES, 3084);
        assert_eq!(
            EgressCaCertificate::from_der(vec![0x30; 3085]),
            Err(EgressCaError::TooLarge { actual: 3085 })
        );
        assert_ne!(
            EgressCaCertificate::from_der(vec![0x30; 3084]),
            Err(EgressCaError::TooLarge { actual: 3084 })
        );
    }

    #[test]
    fn more_than_the_seed_holds_is_refused_before_parsing() {
        assert_eq!(
            EgressCaCertificate::from_der(vec![0x30; MAX_EGRESS_CA_DER_BYTES + 1]),
            Err(EgressCaError::TooLarge {
                actual: MAX_EGRESS_CA_DER_BYTES + 1
            })
        );
    }

    #[test]
    fn pem_wraps_the_der_at_64_columns() {
        let certificate = EgressCaCertificate::from_der(front_door_ca()).unwrap();
        let pem = certificate.to_pem();
        let body: Vec<&str> = pem.lines().collect();
        assert_eq!(body.first(), Some(&"-----BEGIN CERTIFICATE-----"));
        assert_eq!(body.last(), Some(&"-----END CERTIFICATE-----"));
        assert!(body[1..body.len() - 1].iter().all(|line| line.len() <= 64));
        use base64::Engine as _;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(body[1..body.len() - 1].concat())
            .unwrap();
        assert_eq!(decoded, certificate.der());
    }
}
