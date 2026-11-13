//! The pinned CA's copy: saved private, reloaded and checked on every use,
//! carried to a host's agent, removed with the sign-in, and applied only to
//! the server it was pinned for.

use std::fs;
use std::path::Path;

use codewire_client::DeploymentCaError;
use codewire_tls::test_support::SyntheticPki;
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, date_time_ymd};
use sha2::{Digest, Sha256};

use super::super::{
    CODEWIRE_API_KEY_ENV, MapEnv, PlatformConfig, PlatformResolveOptions, ResolvePaths,
    resolve_platform, save_platform_config,
};
use super::{
    DEPLOYMENT_CA_FILE, DeploymentCaFileError, PinnedCa, copy_deployment_ca, delete_deployment_ca,
    host_client_config, load_deployment_ca, read_ca_file, save_deployment_ca,
};

/// Save the CA of a fresh synthetic PKI into `dir`, returning its pin.
fn pin_into(dir: &Path, pki: &SyntheticPki) -> PinnedCa {
    let (ca, pem) = read_ca_file(&pki.roots).expect("a synthetic CA file");
    save_deployment_ca(dir, &ca, &pem).expect("save the CA")
}

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;
    fs::metadata(path).expect("metadata").permissions().mode() & 0o777
}

#[test]
fn a_pinned_ca_is_saved_private_and_loads_back() {
    let home = tempfile::tempdir().expect("temporary directory");
    let dir = home.path().join("codewire");
    let pki = SyntheticPki::new("selfhost.test");
    let pinned = pin_into(&dir, &pki);
    #[cfg(unix)]
    {
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&dir.join(DEPLOYMENT_CA_FILE)), 0o600);
    }
    let loaded = load_deployment_ca(&dir, &pinned).expect("load the pinned CA");
    assert_eq!(loaded.fingerprints(), pinned.fingerprints.as_slice());
    assert_eq!(pinned.fingerprints.len(), 1);
}

#[test]
fn a_replaced_copy_is_refused() {
    let home = tempfile::tempdir().expect("temporary directory");
    let pinned = pin_into(home.path(), &SyntheticPki::new("selfhost.test"));
    let other = SyntheticPki::new("selfhost.test");
    fs::copy(&other.roots, home.path().join(DEPLOYMENT_CA_FILE)).expect("replace the copy");
    let error = load_deployment_ca(home.path(), &pinned).unwrap_err();
    assert!(
        matches!(error, DeploymentCaFileError::Changed { .. }),
        "{error}"
    );
    assert!(error.to_string().contains("cw login --ca-file"), "{error}");
}

#[test]
fn an_expired_copy_is_refused_with_its_own_error() {
    let home = tempfile::tempdir().expect("temporary directory");
    let key = KeyPair::generate().expect("key");
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.not_before = date_time_ymd(2000, 1, 1);
    params.not_after = date_time_ymd(2001, 1, 1);
    let expired = params.self_signed(&key).expect("expired CA");
    fs::write(home.path().join(DEPLOYMENT_CA_FILE), expired.pem()).expect("write the copy");
    let pinned = PinnedCa {
        fingerprints: vec![
            Sha256::digest(expired.der().as_ref())
                .iter()
                .map(|byte| format!("{byte:02X}"))
                .collect::<Vec<_>>()
                .join(":"),
        ],
    };
    let error = load_deployment_ca(home.path(), &pinned).unwrap_err();
    assert!(
        matches!(
            error,
            DeploymentCaFileError::Invalid {
                source: DeploymentCaError::OutOfDate { index: 1, .. },
                ..
            }
        ),
        "{error}"
    );
}

#[test]
fn a_key_file_or_a_server_certificate_is_refused_saying_why() {
    let home = tempfile::tempdir().expect("temporary directory");
    let issuer_key = KeyPair::generate().expect("issuer key");
    let mut issuer = CertificateParams::default();
    issuer.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let issuer = issuer.self_signed(&issuer_key).expect("issuer");
    let server_key = KeyPair::generate().expect("server key");
    let server = CertificateParams::new(vec!["selfhost.test".to_owned()])
        .expect("server params")
        .signed_by(&server_key, &issuer, &issuer_key)
        .expect("server certificate");
    let key = home.path().join("server.key");
    let certificate = home.path().join("server.crt");
    fs::write(&key, server_key.serialize_pem()).expect("write key");
    fs::write(&certificate, server.pem()).expect("write certificate");

    let error = read_ca_file(&key).unwrap_err();
    assert!(
        matches!(
            error,
            DeploymentCaFileError::Invalid {
                source: DeploymentCaError::PrivateKey,
                ..
            }
        ),
        "{error}"
    );
    assert!(error.to_string().contains("private key"), "{error}");
    let error = read_ca_file(&certificate).unwrap_err();
    assert!(
        matches!(
            error,
            DeploymentCaFileError::Invalid {
                source: DeploymentCaError::NotACertificateAuthority { index: 1 },
                ..
            }
        ),
        "{error}"
    );
}

#[test]
fn a_host_gets_a_checked_copy_of_the_pinned_ca() {
    let home = tempfile::tempdir().expect("temporary directory");
    let config_dir = home.path().join("config");
    let host_dir = home.path().join("host");
    let pinned = pin_into(&config_dir, &SyntheticPki::new("selfhost.test"));
    let copied = copy_deployment_ca(&config_dir, &host_dir, &pinned).expect("copy to the host");
    assert_eq!(copied, pinned);
    let config = host_client_config("https://selfhost.test", &host_dir, Some(&copied))
        .expect("host client config");
    assert_eq!(
        config.deployment_ca().map(|ca| ca.fingerprints().to_vec()),
        Some(pinned.fingerprints.clone())
    );
    let unpinned = host_client_config("https://selfhost.test", &host_dir, None).expect("config");
    assert!(unpinned.deployment_ca().is_none());

    let other = SyntheticPki::new("selfhost.test");
    fs::copy(&other.roots, config_dir.join(DEPLOYMENT_CA_FILE)).expect("replace the source");
    let error = copy_deployment_ca(&config_dir, &home.path().join("second"), &pinned).unwrap_err();
    assert!(
        matches!(error, DeploymentCaFileError::Changed { .. }),
        "{error}"
    );
}

#[test]
fn deleting_removes_the_copy_and_a_missing_one_is_already_removed() {
    let home = tempfile::tempdir().expect("temporary directory");
    pin_into(home.path(), &SyntheticPki::new("selfhost.test"));
    delete_deployment_ca(home.path()).expect("delete");
    assert!(!home.path().join(DEPLOYMENT_CA_FILE).exists());
    delete_deployment_ca(home.path()).expect("delete again");
}

#[test]
fn the_pin_applies_only_to_the_server_it_was_pinned_for() {
    let home = tempfile::tempdir().expect("temporary directory");
    let paths = ResolvePaths {
        platform_config_dir: home.path().join("config"),
        mesh_data_dir: home.path().join("mesh"),
    };
    let pinned = pin_into(
        &paths.platform_config_dir,
        &SyntheticPki::new("selfhost.test"),
    );
    save_platform_config(
        &paths.platform_config_dir,
        &PlatformConfig {
            server_url: "https://selfhost.test".into(),
            default_org: String::new(),
            deployment_ca: Some(pinned.clone()),
        },
    )
    .expect("save config");
    let env = MapEnv::new([(CODEWIRE_API_KEY_ENV, "cw_synthetic")]);
    let resolve = |server: Option<&str>| {
        resolve_platform(
            PlatformResolveOptions {
                server_url: server.map(str::to_owned),
                org: None,
            },
            &paths,
            &env,
        )
    };

    let saved = resolve(None).expect("the saved server");
    assert_eq!(
        saved.deployment_ca().map(|ca| ca.fingerprints().to_vec()),
        Some(pinned.fingerprints.clone())
    );
    assert!(
        saved
            .client_config()
            .expect("config")
            .deployment_ca()
            .is_some()
    );
    let named = resolve(Some("https://selfhost.test/")).expect("the saved server, named");
    assert!(named.deployment_ca().is_some());
    let other = resolve(Some("https://other.test")).expect("another server");
    assert!(other.deployment_ca().is_none());
    assert!(
        other
            .client_config()
            .expect("config")
            .deployment_ca()
            .is_none()
    );

    fs::copy(
        &SyntheticPki::new("selfhost.test").roots,
        paths.platform_config_dir.join(DEPLOYMENT_CA_FILE),
    )
    .expect("replace the copy");
    let error = resolve(None).unwrap_err();
    assert!(
        error.to_string().contains("not the CA pinned at login"),
        "{error}"
    );
    assert!(
        resolve(Some("https://other.test")).is_ok(),
        "another server never reads the pin"
    );
}
