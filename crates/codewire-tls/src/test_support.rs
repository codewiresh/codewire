//! Synthetic per-test PKI for crates that test against a TLS listener. No
//! checked-in key, ambient trust or credential input; everything lives in a
//! temporary directory dropped with the value.

use std::net::SocketAddr;
use std::path::PathBuf;

use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use tempfile::TempDir;

use crate::{ServerTlsFiles, TlsListener};

/// A synthetic CA and a server identity it issued for one DNS name.
pub struct SyntheticPki {
    _directory: TempDir,
    /// The CA's public certificate, as a mounted roots file.
    pub roots: PathBuf,
    /// The server identity for the name passed to [`SyntheticPki::new`].
    pub files: ServerTlsFiles,
}

impl SyntheticPki {
    pub fn new(dns_name: &str) -> Self {
        let directory = tempfile::tempdir().expect("synthetic PKI directory");
        let ca_key = KeyPair::generate().expect("synthetic CA key");
        let mut ca = CertificateParams::new(Vec::<String>::new()).expect("synthetic CA");
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca = ca.self_signed(&ca_key).expect("synthetic CA certificate");
        let leaf_key = KeyPair::generate().expect("synthetic leaf key");
        let mut leaf = CertificateParams::new(vec![dns_name.to_owned()]).expect("synthetic leaf");
        leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        leaf.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let leaf = leaf
            .signed_by(&leaf_key, &ca, &ca_key)
            .expect("synthetic leaf certificate");
        let roots = directory.path().join("ca.crt");
        let certificate = directory.path().join("tls.crt");
        let key = directory.path().join("tls.key");
        std::fs::write(&roots, ca.pem()).expect("write synthetic roots");
        std::fs::write(&certificate, leaf.pem()).expect("write synthetic leaf");
        std::fs::write(&key, leaf_key.serialize_pem()).expect("write synthetic key");
        Self {
            _directory: directory,
            roots,
            files: ServerTlsFiles::new(certificate, key).expect("synthetic identity paths"),
        }
    }

    /// Serve `app` over TLS with this identity on an ephemeral loopback port
    /// until the runtime ends.
    pub async fn serve(&self, app: axum::Router) -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind synthetic TLS listener");
        let address = listener.local_addr().expect("synthetic TLS address");
        let listener =
            TlsListener::new(listener, self.files.clone()).expect("synthetic TLS listener");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        address
    }
}
