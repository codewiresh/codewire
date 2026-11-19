//! The TLS listener's certificates (#4000).
//!
//! The listener always holds a self-signed certificate for its in-cluster
//! names, made at start, as it always has. A deployment whose relay has a
//! public name can also give it a publicly trusted certificate for that name:
//! a client that asks for that name gets it, and every other client, one that
//! asks for an in-cluster name or for no name, gets the self-signed one
//! exactly as before. The files are read again every [`RELOAD_INTERVAL`], so a
//! renewed certificate is served without a restart, which would drop every
//! relayed connection. Files that are missing or don't parse never stop the
//! relay: it keeps the last good certificate, or the self-signed one, and a
//! client asking for the public name then fails its own verification.

use std::fmt;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::path::PathBuf;
use std::sync::{Arc, PoisonError, RwLock};
use std::time::Duration;

use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

use crate::{Error, Result};

/// How often the public certificate's files are read again.
pub const RELOAD_INTERVAL: Duration = Duration::from_secs(60);

/// A publicly trusted certificate for the relay's public name, as PEM files:
/// the chain with the end-entity certificate first, and its private key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicCertificate {
    pub hostname: String,
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
}

/// What one read of the public certificate's files did.
#[derive(Debug, PartialEq, Eq)]
pub enum Reload {
    /// No public certificate is configured.
    NotConfigured,
    /// The files are unchanged since the certificate being served.
    Unchanged,
    /// A new certificate is served from now on.
    Loaded,
    /// The files are missing or invalid; the previous certificate stays.
    Failed(String),
}

/// The listener's certificate resolver: the public certificate for the public
/// name, the self-signed one for everything else.
pub struct Certificates {
    fallback: Arc<CertifiedKey>,
    public: Option<PublicSlot>,
}

struct PublicSlot {
    source: PublicCertificate,
    current: RwLock<Option<Loaded>>,
}

struct Loaded {
    key: Arc<CertifiedKey>,
    /// A digest of the two files, to see a change without keeping a second
    /// copy of the private key.
    files: u64,
}

impl Certificates {
    pub fn new(fallback: Arc<CertifiedKey>, public: Option<PublicCertificate>) -> Self {
        Self {
            fallback,
            public: public.map(|source| PublicSlot {
                source,
                current: RwLock::new(None),
            }),
        }
    }

    /// Reads the public certificate's files and serves them if they changed
    /// and are valid.
    pub fn reload(&self) -> Reload {
        let Some(public) = &self.public else {
            return Reload::NotConfigured;
        };
        let files = match (
            std::fs::read(&public.source.cert_file),
            std::fs::read(&public.source.key_file),
        ) {
            (Ok(cert), Ok(key)) => (cert, key),
            (Err(err), _) | (_, Err(err)) => return Reload::Failed(err.to_string()),
        };
        let digest = {
            let mut hasher = DefaultHasher::new();
            files.hash(&mut hasher);
            hasher.finish()
        };
        let current = public
            .current
            .read()
            .unwrap_or_else(PoisonError::into_inner);
        if current
            .as_ref()
            .is_some_and(|loaded| loaded.files == digest)
        {
            return Reload::Unchanged;
        }
        drop(current);
        match certified_key(&files.0, &files.1) {
            Ok(key) => {
                *public
                    .current
                    .write()
                    .unwrap_or_else(PoisonError::into_inner) = Some(Loaded { key, files: digest });
                Reload::Loaded
            }
            Err(err) => Reload::Failed(err.to_string()),
        }
    }

    /// The public name, when a public certificate is configured.
    pub fn public_hostname(&self) -> Option<&str> {
        self.public
            .as_ref()
            .map(|public| public.source.hostname.as_str())
    }
}

impl ResolvesServerCert for Certificates {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        if let (Some(public), Some(name)) = (&self.public, hello.server_name())
            && name.eq_ignore_ascii_case(&public.source.hostname)
            && let Some(loaded) = public
                .current
                .read()
                .unwrap_or_else(PoisonError::into_inner)
                .as_ref()
        {
            return Some(loaded.key.clone());
        }
        Some(self.fallback.clone())
    }
}

impl fmt::Debug for Certificates {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Certificates")
            .field("public_hostname", &self.public_hostname())
            .finish_non_exhaustive()
    }
}

/// A served certificate from PEM files, its key checked against the chain's
/// end-entity certificate.
fn certified_key(cert_pem: &[u8], key_pem: &[u8]) -> Result<Arc<CertifiedKey>> {
    let chain = CertificateDer::pem_slice_iter(cert_pem)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|err| Error::Tls(format!("certificate file: {err}")))?;
    if chain.is_empty() {
        return Err(Error::Tls("certificate file holds no certificate".into()));
    }
    let key = PrivateKeyDer::from_pem_slice(key_pem)
        .map_err(|err| Error::Tls(format!("key file: {err}")))?;
    CertifiedKey::from_der(chain, key, &rustls::crypto::ring::default_provider())
        .map(Arc::new)
        .map_err(|err| Error::Tls(err.to_string()))
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::Mutex;

    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
    use rustls_pki_types::{ServerName, UnixTime};
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    use super::*;
    use crate::tls_config;

    const PUBLIC: &str = "derp.example.test";
    const IN_CLUSTER: &str = "codewire-derp.dev.svc.cluster.local";

    /// Accepts any server certificate and records the end-entity one, so a
    /// test can see which certificate the listener chose.
    #[derive(Debug, Default)]
    struct Recorder(Mutex<Option<Vec<u8>>>);

    impl ServerCertVerifier for Recorder {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            _: &[CertificateDer<'_>],
            _: &ServerName<'_>,
            _: &[u8],
            _: UnixTime,
        ) -> std::result::Result<ServerCertVerified, rustls::Error> {
            *self.0.lock().unwrap() = Some(end_entity.to_vec());
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    /// The end-entity certificate the listener presents to a client asking
    /// for `name`; an IP address sends no name at all.
    async fn presented(config: rustls::ServerConfig, name: &str) -> Vec<u8> {
        let recorder = Arc::new(Recorder::default());
        let client = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(recorder.clone())
            .with_no_client_auth();
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            TlsAcceptor::from(Arc::new(config))
                .accept(server_io)
                .await
                .map(drop)
        });
        // Held until the server's side completes: a TLS 1.3 server still
        // writes after the client's handshake returns.
        let _client = TlsConnector::from(Arc::new(client))
            .connect(ServerName::try_from(name.to_owned()).unwrap(), client_io)
            .await
            .unwrap();
        server.await.unwrap().unwrap();
        recorder.0.lock().unwrap().take().unwrap()
    }

    /// A fresh self-signed certificate for `name` as PEM, and its DER.
    fn issue(name: &str) -> (String, String, Vec<u8>) {
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec![name.to_owned()]).unwrap();
        (cert.pem(), key_pair.serialize_pem(), cert.der().to_vec())
    }

    struct Files {
        dir: PathBuf,
    }

    impl Files {
        fn new(test: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("codewire-derp-{test}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir(&dir).unwrap();
            Self { dir }
        }

        fn public(&self) -> PublicCertificate {
            PublicCertificate {
                hostname: PUBLIC.to_owned(),
                cert_file: self.dir.join("tls.crt"),
                key_file: self.dir.join("tls.key"),
            }
        }

        fn write(&self, cert: &str, key: &str) {
            write(&self.dir.join("tls.crt"), cert);
            write(&self.dir.join("tls.key"), key);
        }
    }

    impl Drop for Files {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn write(path: &Path, contents: &str) {
        std::fs::write(path, contents).unwrap();
    }

    #[tokio::test]
    async fn the_public_name_gets_the_public_certificate_and_every_other_name_the_self_signed_one()
    {
        let files = Files::new("names");
        let (cert, key, public_der) = issue(PUBLIC);
        files.write(&cert, &key);
        let (config, certificates) =
            tls_config(&[IN_CLUSTER.to_owned()], Some(files.public())).unwrap();
        assert_eq!(certificates.reload(), Reload::Loaded);

        assert_eq!(presented(config.clone(), PUBLIC).await, public_der);
        assert_eq!(
            presented(config.clone(), "DERP.Example.Test").await,
            public_der
        );
        let in_cluster = presented(config.clone(), IN_CLUSTER).await;
        assert_ne!(in_cluster, public_der);
        // An address sends no server name: the self-signed certificate, as before.
        assert_eq!(presented(config.clone(), "127.0.0.1").await, in_cluster);
        assert_eq!(presented(config, "other.example.test").await, in_cluster);
    }

    #[tokio::test]
    async fn without_a_loaded_certificate_the_public_name_gets_the_self_signed_one() {
        let files = Files::new("unloaded");
        let (config, certificates) =
            tls_config(&[IN_CLUSTER.to_owned()], Some(files.public())).unwrap();
        assert!(matches!(certificates.reload(), Reload::Failed(_)));
        assert_eq!(
            presented(config.clone(), PUBLIC).await,
            presented(config, IN_CLUSTER).await
        );

        let (config, certificates) = tls_config(&[IN_CLUSTER.to_owned()], None).unwrap();
        assert_eq!(certificates.reload(), Reload::NotConfigured);
        assert_eq!(certificates.public_hostname(), None);
        assert_eq!(
            presented(config.clone(), PUBLIC).await,
            presented(config, IN_CLUSTER).await
        );
    }

    #[tokio::test]
    async fn a_renewal_is_served_without_a_restart_and_bad_files_keep_the_last_good_certificate() {
        let files = Files::new("renewal");
        let (first_cert, first_key, first_der) = issue(PUBLIC);
        files.write(&first_cert, &first_key);
        let (config, certificates) =
            tls_config(&[IN_CLUSTER.to_owned()], Some(files.public())).unwrap();
        assert_eq!(certificates.reload(), Reload::Loaded);
        assert_eq!(certificates.reload(), Reload::Unchanged);
        assert_eq!(presented(config.clone(), PUBLIC).await, first_der);

        let (renewed_cert, renewed_key, renewed_der) = issue(PUBLIC);
        files.write(&renewed_cert, &renewed_key);
        assert_eq!(certificates.reload(), Reload::Loaded);
        assert_eq!(presented(config.clone(), PUBLIC).await, renewed_der);

        // A key that isn't the certificate's, a file that isn't PEM, and
        // missing files each leave the renewed certificate in place.
        let (_, other_key, _) = issue(PUBLIC);
        for (cert, key) in [
            (renewed_cert.as_str(), other_key.as_str()),
            ("not pem", renewed_key.as_str()),
        ] {
            files.write(cert, key);
            assert!(matches!(certificates.reload(), Reload::Failed(_)));
            assert_eq!(presented(config.clone(), PUBLIC).await, renewed_der);
        }
        std::fs::remove_file(files.dir.join("tls.key")).unwrap();
        assert!(matches!(certificates.reload(), Reload::Failed(_)));
        assert_eq!(presented(config, PUBLIC).await, renewed_der);
    }
}
