//! Per-test synthetic PKI. No checked-in key, ambient trust or credential input.

use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
use std::path::PathBuf;

/// One synthetic broker root bundle.
pub(crate) struct Identity {
    _directory: tempfile::TempDir,
    pub(crate) roots: PathBuf,
}

impl Identity {
    pub(crate) fn new(name: &str) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let issuer_key = KeyPair::generate().unwrap();
        let mut issuer = CertificateParams::new(vec![name.to_owned()]).unwrap();
        issuer.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        issuer.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let issuer = issuer.self_signed(&issuer_key).unwrap();
        let roots = directory.path().join("ca.crt");
        std::fs::write(&roots, issuer.pem()).unwrap();
        Self {
            _directory: directory,
            roots,
        }
    }
}
