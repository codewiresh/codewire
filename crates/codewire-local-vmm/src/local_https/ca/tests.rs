use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use codewire_egress_front_door::{CaError, CertifiedKey, LeafSource};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::{
    ClientConfig, ClientConnection, Connection, RootCertStore, ServerConfig, ServerConnection,
};
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::{FromDer, X509Certificate};

use super::{CA_CERTIFICATE_FILE, CA_DIRECTORY, CA_KEY_FILE, LocalCa, LocalCaError};

const HOST: &str = "web-shop-a.cw.localhost";

fn mode(path: &std::path::Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn stored_der(state_root: &std::path::Path) -> CertificateDer<'static> {
    let pem = fs::read(state_root.join(CA_DIRECTORY).join(CA_CERTIFICATE_FILE)).unwrap();
    let (_, block) = x509_parser::pem::parse_x509_pem(&pem).unwrap();
    CertificateDer::from(block.contents)
}

#[derive(Debug)]
struct Fixed(Arc<CertifiedKey>);

impl ResolvesServerCert for Fixed {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

/// A whole TLS handshake in memory, by a client that trusts only `root`.
fn handshake(
    root: CertificateDer<'static>,
    leaf: Arc<CertifiedKey>,
    name: &str,
) -> Result<(), rustls::Error> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = RootCertStore::empty();
    roots.add(root).unwrap();
    let client = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(Fixed(leaf)));
    let mut client = Connection::Client(
        ClientConnection::new(
            Arc::new(client),
            ServerName::try_from(name.to_owned()).unwrap(),
        )
        .unwrap(),
    );
    let mut server = Connection::Server(ServerConnection::new(Arc::new(server)).unwrap());
    for _ in 0..8 {
        transfer(&mut client, &mut server)?;
        transfer(&mut server, &mut client)?;
        if !client.is_handshaking() && !server.is_handshaking() {
            return Ok(());
        }
    }
    panic!("the handshake did not finish");
}

fn transfer(from: &mut Connection, to: &mut Connection) -> Result<(), rustls::Error> {
    let mut bytes = Vec::new();
    while from.wants_write() {
        from.write_tls(&mut bytes).unwrap();
    }
    let mut unread = bytes.as_slice();
    while !unread.is_empty() {
        to.read_tls(&mut unread).unwrap();
    }
    to.process_new_packets().map(|_| ())
}

#[test]
fn the_ca_is_made_once_owner_only_and_reloaded_unchanged() {
    let state = tempfile::tempdir().unwrap();
    let directory = state.path().join(CA_DIRECTORY);
    let ca = LocalCa::load_or_create(state.path()).unwrap();
    assert_eq!(mode(&directory), 0o700);
    assert_eq!(mode(&directory.join(CA_KEY_FILE)), 0o400);
    assert_eq!(mode(&directory.join(CA_CERTIFICATE_FILE)), 0o444);
    let key = fs::read(directory.join(CA_KEY_FILE)).unwrap();
    let certificate = fs::read(directory.join(CA_CERTIFICATE_FILE)).unwrap();
    drop(ca);

    LocalCa::load_or_create(state.path()).unwrap();
    assert_eq!(fs::read(directory.join(CA_KEY_FILE)).unwrap(), key);
    assert_eq!(
        fs::read(directory.join(CA_CERTIFICATE_FILE)).unwrap(),
        certificate
    );
    let names: Vec<_> = fs::read_dir(&directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(names.len(), 2, "no temporary file is left: {names:?}");
}

#[test]
fn a_leaf_from_a_reloaded_ca_chains_to_the_stored_certificate() {
    let state = tempfile::tempdir().unwrap();
    drop(LocalCa::load_or_create(state.path()).unwrap());
    let ca = LocalCa::load_or_create(state.path()).unwrap();
    let (host, leaf) = ca.leaf("Web-Shop-A.cw.localhost").unwrap();
    assert_eq!(host, HOST);
    handshake(stored_der(state.path()), leaf.clone(), HOST).unwrap();
    // The leaf names only its own host.
    assert!(handshake(stored_der(state.path()), leaf, "web-shop-b.cw.localhost").is_err());
    // A second request is served from the cache.
    let (_, again) = ca.leaf(HOST).unwrap();
    assert!(Arc::ptr_eq(&again, &ca.leaf(HOST).unwrap().1));
}

#[test]
fn the_ca_signs_nothing_outside_its_suffix() {
    let state = tempfile::tempdir().unwrap();
    let ca = LocalCa::load_or_create(state.path()).unwrap();
    for host in [
        "example.com",
        "cw.localhost",
        "a.b.cw.localhost",
        "-a.cw.localhost",
        "web_shop.cw.localhost",
        "web-shop-a.cw.localhost.example.com",
        "127.0.0.1",
    ] {
        assert_eq!(ca.leaf(host).err(), Some(CaError::UnboundHost), "{host}");
    }
}

#[test]
fn the_ca_certificate_is_name_constrained_to_its_suffix() {
    let state = tempfile::tempdir().unwrap();
    drop(LocalCa::load_or_create(state.path()).unwrap());
    let der = stored_der(state.path());
    let (_, certificate) = X509Certificate::from_der(&der).unwrap();
    let constraints = certificate
        .extensions()
        .iter()
        .find_map(|extension| match extension.parsed_extension() {
            ParsedExtension::NameConstraints(constraints) => {
                Some((extension.critical, constraints))
            }
            _ => None,
        })
        .expect("a name constraint");
    assert!(constraints.0, "the constraint is critical");
    let permitted: Vec<_> = constraints
        .1
        .permitted_subtrees
        .as_ref()
        .unwrap()
        .iter()
        .map(|subtree| subtree.base.clone())
        .collect();
    assert_eq!(permitted, [GeneralName::DNSName("cw.localhost")]);
    let excluded = constraints.1.excluded_subtrees.as_ref().unwrap();
    assert_eq!(excluded.len(), 2, "every IPv4 and IPv6 address is excluded");
    assert!(certificate.is_ca());
}

#[test]
fn a_certificate_that_does_not_match_the_key_is_refused_and_kept() {
    let state = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap();
    drop(LocalCa::load_or_create(state.path()).unwrap());
    drop(LocalCa::load_or_create(other.path()).unwrap());
    let path = state.path().join(CA_DIRECTORY).join(CA_CERTIFICATE_FILE);
    let foreign = fs::read(other.path().join(CA_DIRECTORY).join(CA_CERTIFICATE_FILE)).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    fs::write(&path, &foreign).unwrap();

    assert!(matches!(
        LocalCa::load_or_create(state.path()),
        Err(LocalCaError::Mismatch)
    ));
    assert_eq!(fs::read(&path).unwrap(), foreign);
}

#[test]
fn a_missing_certificate_is_made_again_from_the_stored_key() {
    let state = tempfile::tempdir().unwrap();
    drop(LocalCa::load_or_create(state.path()).unwrap());
    let directory = state.path().join(CA_DIRECTORY);
    let key = fs::read(directory.join(CA_KEY_FILE)).unwrap();
    fs::remove_file(directory.join(CA_CERTIFICATE_FILE)).unwrap();

    let ca = LocalCa::load_or_create(state.path()).unwrap();
    assert_eq!(fs::read(directory.join(CA_KEY_FILE)).unwrap(), key);
    let (_, leaf) = ca.leaf(HOST).unwrap();
    handshake(stored_der(state.path()), leaf, HOST).unwrap();
}

#[test]
fn a_key_others_may_read_or_a_link_in_its_place_is_refused() {
    let state = tempfile::tempdir().unwrap();
    drop(LocalCa::load_or_create(state.path()).unwrap());
    let key = state.path().join(CA_DIRECTORY).join(CA_KEY_FILE);
    fs::set_permissions(&key, fs::Permissions::from_mode(0o440)).unwrap();
    let refusal = LocalCa::load_or_create(state.path()).unwrap_err();
    assert!(matches!(refusal, LocalCaError::Exposed(..)), "{refusal}");
    assert!(
        refusal.to_string().contains("readable only by you"),
        "{refusal}"
    );

    fs::set_permissions(&key, fs::Permissions::from_mode(0o400)).unwrap();
    let moved = state.path().join("moved-key.pem");
    fs::rename(&key, &moved).unwrap();
    std::os::unix::fs::symlink(&moved, &key).unwrap();
    assert!(matches!(
        LocalCa::load_or_create(state.path()),
        Err(LocalCaError::Io(_))
    ));
}

#[test]
fn the_ca_is_for_tls_servers_only_and_every_serial_is_random() {
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    let ca = LocalCa::load_or_create(first.path()).unwrap();
    drop(LocalCa::load_or_create(second.path()).unwrap());
    let der = stored_der(first.path());
    let (_, certificate) = X509Certificate::from_der(&der).unwrap();
    let usage = certificate.extended_key_usage().unwrap().unwrap().value;
    assert!(usage.server_auth && !usage.client_auth && !usage.code_signing);
    assert!(usage.other.is_empty());
    let serial = certificate.raw_serial().to_vec();
    assert_eq!(serial.len(), 16);
    let other = stored_der(second.path());
    assert_ne!(
        X509Certificate::from_der(&other).unwrap().1.raw_serial(),
        serial.as_slice()
    );

    let (_, leaf) = ca.leaf(HOST).unwrap();
    let (_, leaf) = X509Certificate::from_der(&leaf.cert[0]).unwrap();
    assert_eq!(leaf.raw_serial().len(), 16);
    assert_ne!(leaf.raw_serial(), serial.as_slice());
    let names: Vec<_> = leaf
        .subject_alternative_name()
        .unwrap()
        .unwrap()
        .value
        .general_names
        .clone();
    assert_eq!(names, [GeneralName::DNSName(HOST)]);
    let common_name = leaf
        .subject()
        .iter_common_name()
        .next()
        .unwrap()
        .as_str()
        .unwrap();
    assert_eq!(common_name, HOST);
}
