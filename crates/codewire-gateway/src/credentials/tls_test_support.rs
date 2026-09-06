//! Per-test synthetic PKI. No checked-in key, ambient trust or credential input.

use codewire_tls::ServerTlsFiles;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use std::path::PathBuf;

pub(crate) struct Identity {
    _directory: tempfile::TempDir,
    pub(crate) certificate: PathBuf,
    pub(crate) key: PathBuf,
    pub(crate) roots: PathBuf,
    pub(crate) root_pem: String,
}

impl Identity {
    pub(crate) fn new(name: &str) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let issuer_key = KeyPair::generate().unwrap();
        let mut issuer = CertificateParams::new(Vec::<String>::new()).unwrap();
        issuer.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        issuer.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let issuer = issuer.self_signed(&issuer_key).unwrap();
        let key = KeyPair::generate().unwrap();
        let mut certificate = CertificateParams::new(vec![name.to_owned()]).unwrap();
        certificate.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        certificate.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let certificate = certificate.signed_by(&key, &issuer, &issuer_key).unwrap();
        let cert_path = directory.path().join("tls.crt");
        let key_path = directory.path().join("tls.key");
        let roots = directory.path().join("ca.crt");
        std::fs::write(&cert_path, certificate.pem()).unwrap();
        std::fs::write(&key_path, key.serialize_pem()).unwrap();
        let root_pem = issuer.pem();
        std::fs::write(&roots, &root_pem).unwrap();
        Self {
            _directory: directory,
            certificate: cert_path,
            key: key_path,
            roots,
            root_pem,
        }
    }

    pub(crate) fn files(&self) -> ServerTlsFiles {
        ServerTlsFiles::new(self.certificate.clone(), self.key.clone()).unwrap()
    }

    pub(crate) fn client(&self) -> reqwest::Client {
        reqwest::Client::builder()
            .no_proxy()
            .https_only(true)
            .tls_built_in_root_certs(false)
            .add_root_certificate(reqwest::Certificate::from_pem(self.root_pem.as_bytes()).unwrap())
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap()
    }
}
