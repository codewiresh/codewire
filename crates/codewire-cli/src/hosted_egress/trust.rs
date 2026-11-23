//! The hosted daemon's egress trust (#6072): the first egress session's
//! trust frame, installed before the daemon serves, as a local guest's PID 1
//! installs its boot's (`codewire_vmm_guest_probe::guest::egress_trust`).
//!
//! With a CA, [`HOSTED_EGRESS_TRUST_CA_PATH`] holds it and
//! [`HOSTED_EGRESS_TRUST_BUNDLE_PATH`] the container's own system bundle
//! followed by it, and the bind's interception is marked so that every
//! launch names them (`codewire_daemon::env`). Without one, the CA path holds
//! a comment and nothing is named. A trust that is not a CA certificate, or
//! a file that can't be written, stops the daemon before it serves: an
//! intercepted Sandbox whose agents can't trust their front door fails
//! closed at once rather than at every request.
//!
//! The files are in the Sandbox's own run directory. A workload that
//! replaces them changes only its own trust, which it can do with its own
//! variables anyway; that is within the Sandbox's trust boundary.

use std::path::Path;

use anyhow::Context as _;
use codewire_access::Interception;
use codewire_daemon_proto::{HOSTED_EGRESS_TRUST_BUNDLE_PATH, HOSTED_EGRESS_TRUST_CA_PATH};
use codewire_network_session::EgressTrust;
use codewire_vmm_guest_probe::EgressCaCertificate;

/// Install `trust` at the hosted trust paths and mark the bind's
/// `interception` when it carries a CA.
pub(crate) fn install_trust(
    trust: &EgressTrust,
    interception: &mut Option<Interception>,
) -> anyhow::Result<()> {
    install_trust_at(
        trust,
        interception,
        Path::new(HOSTED_EGRESS_TRUST_CA_PATH),
        Path::new(HOSTED_EGRESS_TRUST_BUNDLE_PATH),
    )
}

fn install_trust_at(
    trust: &EgressTrust,
    interception: &mut Option<Interception>,
    ca_path: &Path,
    bundle_path: &Path,
) -> anyhow::Result<()> {
    let certificate = match trust {
        EgressTrust::None => None,
        EgressTrust::Ca(der) => Some(
            EgressCaCertificate::from_der(der.clone())
                .context("the egress trust frame is not a CA certificate")?,
        ),
    };
    codewire_vmm_guest_probe::guest::egress_trust::publish_hosted(
        certificate.as_ref(),
        ca_path,
        bundle_path,
    )?;
    if certificate.is_none() {
        return Ok(());
    }
    match interception.take() {
        Some(intercepted) => {
            *interception = Some(intercepted.with_hosted_ca_installed());
            tracing::info!("hosted egress CA installed; launches trust the front door");
        }
        // A Pod admitted with a CA whose bind recorded no interception: the
        // front door intercepts nothing for it, so nothing needs the CA.
        None => tracing::info!("hosted egress CA installed for a bind that is not intercepted"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ca_der() -> Vec<u8> {
        let mut params = rcgen::CertificateParams::new(Vec::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let key = rcgen::KeyPair::generate().unwrap();
        params.self_signed(&key).unwrap().der().to_vec()
    }

    fn intercepted() -> Option<Interception> {
        Some(Interception::new(None))
    }

    fn installed(interception: &Option<Interception>) -> bool {
        interception
            .as_ref()
            .is_some_and(Interception::hosted_ca_installed)
    }

    struct Paths {
        _root: tempfile::TempDir,
        ca: std::path::PathBuf,
        bundle: std::path::PathBuf,
    }

    fn paths() -> Paths {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("egress-trust");
        Paths {
            ca: directory.join("ca.pem"),
            bundle: directory.join("ca-certificates.crt"),
            _root: root,
        }
    }

    #[test]
    fn an_intercepted_daemon_installs_its_ca_before_it_serves_and_its_launches_name_it() {
        let paths = paths();
        let mut interception = intercepted();
        let der = ca_der();
        install_trust_at(
            &EgressTrust::Ca(der.clone()),
            &mut interception,
            &paths.ca,
            &paths.bundle,
        )
        .unwrap();

        let pem = EgressCaCertificate::from_der(der).unwrap().to_pem();
        assert_eq!(std::fs::read_to_string(&paths.ca).unwrap(), pem);
        assert!(
            std::fs::read_to_string(&paths.bundle)
                .unwrap()
                .ends_with(&pem)
        );
        assert!(
            installed(&interception),
            "an intercepted daemon that installed its CA must name it in its launches"
        );
    }

    #[test]
    fn without_a_ca_the_trust_file_is_a_comment_and_nothing_is_named() {
        let paths = paths();
        std::fs::create_dir_all(paths.bundle.parent().unwrap()).unwrap();
        std::fs::write(&paths.bundle, "stale").unwrap();
        let mut interception = intercepted();
        install_trust_at(
            &EgressTrust::None,
            &mut interception,
            &paths.ca,
            &paths.bundle,
        )
        .unwrap();

        let comment = std::fs::read_to_string(&paths.ca).unwrap();
        assert!(comment.starts_with('#') && !comment.contains("BEGIN CERTIFICATE"));
        assert!(!paths.bundle.exists());
        assert!(!installed(&interception));
    }

    #[test]
    fn a_trust_that_is_not_a_ca_certificate_stops_the_daemon() {
        let paths = paths();
        let mut interception = intercepted();
        let error = install_trust_at(
            &EgressTrust::Ca(vec![0x30; 4]),
            &mut interception,
            &paths.ca,
            &paths.bundle,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("not a CA certificate"));
        assert!(!paths.ca.exists());
        assert!(!installed(&interception));
    }

    #[test]
    fn a_trust_file_that_cannot_be_written_stops_the_daemon() {
        let root = tempfile::tempdir().unwrap();
        // The trust directory's parent is a file, so nothing can be created.
        let blocked = root.path().join("run");
        std::fs::write(&blocked, "").unwrap();
        let mut interception = intercepted();
        let result = install_trust_at(
            &EgressTrust::Ca(ca_der()),
            &mut interception,
            &blocked.join("egress-trust/ca.pem"),
            &blocked.join("egress-trust/ca-certificates.crt"),
        );
        assert!(result.is_err());
        assert!(!installed(&interception));
    }
}
