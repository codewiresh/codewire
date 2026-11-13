//! What a CA file may hold, and that a client pinned to a deployment CA trusts
//! it for the pinned host alone and the public roots for every other host.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, IsCa, KeyPair, SanType, date_time_ymd,
};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{CertificateError, RootCertStore};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use super::{
    DeploymentCa, DeploymentCaError, DeploymentTrust, MAX_CA_CERTIFICATES, MAX_CA_PEM_BYTES,
    same_host,
};
use crate::ClientConfig;

const PINNED: &str = "pinned.test";
const OTHER: &str = "other.test";

/// A certificate and the key it was made with.
struct Issued {
    certificate: Certificate,
    key: KeyPair,
}

#[derive(Clone, Copy)]
enum Validity {
    Now,
    Expired,
    NotYetValid,
}

fn params(sans: Vec<SanType>, validity: Validity) -> CertificateParams {
    let mut params = CertificateParams::default();
    params.subject_alt_names = sans;
    match validity {
        Validity::Now => {}
        Validity::Expired => {
            params.not_before = date_time_ymd(2000, 1, 1);
            params.not_after = date_time_ymd(2001, 1, 1);
        }
        Validity::NotYetValid => {
            params.not_before = date_time_ymd(4000, 1, 1);
            params.not_after = date_time_ymd(4001, 1, 1);
        }
    }
    params
}

fn authority_with(name: &str, validity: Validity) -> Issued {
    let mut params = params(Vec::new(), validity);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.distinguished_name.push(DnType::CommonName, name);
    let key = KeyPair::generate().expect("authority key");
    let certificate = params.self_signed(&key).expect("authority certificate");
    Issued { certificate, key }
}

fn authority(name: &str) -> Issued {
    authority_with(name, Validity::Now)
}

fn dns(name: &str) -> SanType {
    SanType::DnsName(name.try_into().expect("DNS name"))
}

fn leaf_with(issuer: &Issued, sans: Vec<SanType>, validity: Validity) -> Issued {
    let key = KeyPair::generate().expect("leaf key");
    let certificate = params(sans, validity)
        .signed_by(&key, &issuer.certificate, &issuer.key)
        .expect("leaf certificate");
    Issued { certificate, key }
}

fn leaf(issuer: &Issued, sans: Vec<SanType>) -> Issued {
    leaf_with(issuer, sans, Validity::Now)
}

fn ca_of(authorities: &[&Issued]) -> DeploymentCa {
    let pem: String = authorities
        .iter()
        .map(|authority| authority.certificate.pem())
        .collect();
    DeploymentCa::from_pem(pem.as_bytes()).expect("a valid CA file")
}

fn response_ok() -> String {
    "HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok".to_owned()
}

fn response_redirect(location: &str) -> String {
    format!(
        "HTTP/1.1 302 Found\r\nlocation: {location}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
    )
}

/// Serve `response` to every HTTPS request, presenting `certificate`.
async fn serve(certificate: &Issued, response: String) -> SocketAddr {
    serve_counted(certificate, response).await.0
}

/// [`serve`], also counting the requests answered.
async fn serve_counted(certificate: &Issued, response: String) -> (SocketAddr, Arc<AtomicUsize>) {
    let chain = vec![certificate.certificate.der().clone()];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certificate.key.serialize_der()));
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("TLS versions")
    .with_no_client_auth()
    .with_single_cert(chain, key)
    .expect("server certificate");
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind");
    let address = listener.local_addr().expect("address");
    let answered = Arc::new(AtomicUsize::new(0));
    let counter = answered.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let response = response.clone();
            let counter = counter.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let mut request = Vec::new();
                let mut buffer = [0_u8; 1024];
                while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                    match tls.read(&mut buffer).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => request.extend_from_slice(&buffer[..read]),
                    }
                }
                counter.fetch_add(1, Ordering::SeqCst);
                let _ = tls.write_all(response.as_bytes()).await; // The client may have gone.
                let _ = tls.shutdown().await; // Likewise.
            });
        }
    });
    (address, answered)
}

/// A client of `https://{host}:{port}` pinned to `ca`, resolving each named
/// host to its test server.
fn pinned_client(
    host: &str,
    port: u16,
    ca: &DeploymentCa,
    resolve: &[(&str, SocketAddr)],
) -> reqwest::Client {
    let config = ClientConfig::new(format!("https://{host}:{port}"))
        .expect("server URL")
        .with_deployment_ca(ca.clone())
        .expect("deployment CA");
    let mut builder = config.http_client_builder().expect("client builder");
    for (name, address) in resolve {
        builder = builder.resolve(name, *address);
    }
    builder.build().expect("client")
}

async fn get(client: &reqwest::Client, url: String) -> Result<String, reqwest::Error> {
    client
        .get(url)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await
}

/// The certificate error rustls reported under a request's error, if any.
/// An `io::Error` reports its wrapped error's source rather than the wrapped
/// error itself, so the walk steps into `get_ref` instead.
fn certificate_error(error: &reqwest::Error) -> Option<CertificateError> {
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(current) = source {
        if let Some(rustls::Error::InvalidCertificate(certificate)) =
            current.downcast_ref::<rustls::Error>()
        {
            return Some(certificate.clone());
        }
        source = match current
            .downcast_ref::<std::io::Error>()
            .and_then(std::io::Error::get_ref)
        {
            Some(inner) => Some(inner),
            None => current.source(),
        };
    }
    None
}

fn refused_as(error: &reqwest::Error) -> CertificateError {
    certificate_error(error).unwrap_or_else(|| panic!("not a certificate error: {error:?}"))
}

#[test]
fn a_ca_file_is_read_with_each_certificates_sha256_fingerprint() {
    let first = authority("first");
    let second = authority("second");
    let ca = ca_of(&[&first, &second]);
    let expected: Vec<String> = [&first, &second]
        .iter()
        .map(|authority| {
            Sha256::digest(authority.certificate.der().as_ref())
                .iter()
                .map(|byte| format!("{byte:02X}"))
                .collect::<Vec<_>>()
                .join(":")
        })
        .collect();
    assert_eq!(ca.fingerprints(), expected.as_slice());
    assert_eq!(ca.certificates().len(), 2);
}

#[test]
fn a_private_key_anywhere_in_the_file_refuses_it() {
    let issued = authority("with a key");
    for pem in [
        format!("{}{}", issued.certificate.pem(), issued.key.serialize_pem()),
        format!("{}{}", issued.key.serialize_pem(), issued.certificate.pem()),
    ] {
        assert_eq!(
            DeploymentCa::from_pem(pem.as_bytes()).unwrap_err(),
            DeploymentCaError::PrivateKey
        );
    }
}

#[test]
fn a_certificate_that_is_not_an_authority_is_refused_by_its_position() {
    let issuer = authority("issuer");
    let server = leaf(&issuer, vec![dns(PINNED)]);
    assert_eq!(
        DeploymentCa::from_pem(server.certificate.pem().as_bytes()).unwrap_err(),
        DeploymentCaError::NotACertificateAuthority { index: 1 }
    );
    let pem = format!("{}{}", issuer.certificate.pem(), server.certificate.pem());
    assert_eq!(
        DeploymentCa::from_pem(pem.as_bytes()).unwrap_err(),
        DeploymentCaError::NotACertificateAuthority { index: 2 }
    );
}

#[test]
fn an_authority_outside_its_validity_period_is_refused() {
    for validity in [Validity::Expired, Validity::NotYetValid] {
        let issued = authority_with("out of date", validity);
        let error = DeploymentCa::from_pem(issued.certificate.pem().as_bytes()).unwrap_err();
        assert!(
            matches!(error, DeploymentCaError::OutOfDate { index: 1, .. }),
            "{error:?}"
        );
    }
}

#[test]
fn an_empty_oversized_overfull_or_malformed_file_is_refused() {
    assert_eq!(
        DeploymentCa::from_pem(b"").unwrap_err(),
        DeploymentCaError::Empty
    );
    assert_eq!(
        DeploymentCa::from_pem(b"no PEM here\n").unwrap_err(),
        DeploymentCaError::Empty
    );
    assert_eq!(
        DeploymentCa::from_pem(&vec![b'\n'; MAX_CA_PEM_BYTES + 1]).unwrap_err(),
        DeploymentCaError::TooLarge
    );
    let one = authority("one").certificate.pem();
    let overfull = one.repeat(MAX_CA_CERTIFICATES + 1);
    assert!(
        overfull.len() <= MAX_CA_PEM_BYTES,
        "the size bound must not hide the count"
    );
    assert_eq!(
        DeploymentCa::from_pem(overfull.as_bytes()).unwrap_err(),
        DeploymentCaError::TooMany
    );
    let malformed = "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n";
    assert_eq!(
        DeploymentCa::from_pem(malformed.as_bytes()).unwrap_err(),
        DeploymentCaError::InvalidPem
    );
    let key = KeyPair::generate().expect("key");
    let request = params(vec![dns(PINNED)], Validity::Now)
        .serialize_request(&key)
        .expect("certificate request")
        .pem()
        .expect("request PEM");
    assert_eq!(
        DeploymentCa::from_pem(request.as_bytes()).unwrap_err(),
        DeploymentCaError::NotACertificate
    );
}

#[test]
fn a_deployment_ca_needs_an_https_server_url() {
    let ca = ca_of(&[&authority("plain")]);
    let error = ClientConfig::new("http://pinned.test:8080")
        .expect("server URL")
        .with_deployment_ca(ca)
        .unwrap_err();
    assert_eq!(error.code(), connectrpc::ErrorCode::InvalidArgument);
}

#[test]
fn host_names_match_exactly_without_regard_to_case() {
    let pinned = ServerName::try_from(PINNED).expect("name");
    assert!(same_host(
        &pinned,
        &ServerName::try_from("PINNED.Test").expect("name")
    ));
    for other in ["other.test", "sub.pinned.test", "pinned.test.evil"] {
        assert!(!same_host(
            &pinned,
            &ServerName::try_from(other).expect("name")
        ));
    }
    let ip = ServerName::from(IpAddr::from(Ipv4Addr::LOCALHOST));
    assert!(same_host(
        &ip,
        &ServerName::from(IpAddr::from(Ipv4Addr::LOCALHOST))
    ));
    assert!(!same_host(
        &ip,
        &ServerName::try_from("localhost").expect("name")
    ));
}

#[tokio::test]
async fn the_pinned_host_is_trusted_through_the_ca() {
    let issuer = authority("deployment");
    let address = serve(&leaf(&issuer, vec![dns(PINNED)]), response_ok()).await;
    let client = pinned_client(
        PINNED,
        address.port(),
        &ca_of(&[&issuer]),
        &[(PINNED, address)],
    );
    let body = get(&client, format!("https://{PINNED}:{}/", address.port()))
        .await
        .expect("the pinned host verifies through its CA");
    assert_eq!(body, "ok");
}

#[tokio::test]
async fn another_host_signed_by_the_ca_is_refused() {
    let issuer = authority("deployment");
    let other = serve(&leaf(&issuer, vec![dns(OTHER)]), response_ok()).await;
    let client = pinned_client(PINNED, other.port(), &ca_of(&[&issuer]), &[(OTHER, other)]);
    let error = get(&client, format!("https://{OTHER}:{}/", other.port()))
        .await
        .unwrap_err();
    assert_eq!(refused_as(&error), CertificateError::UnknownIssuer);
}

#[tokio::test]
async fn the_pinned_host_never_falls_back_to_the_public_roots() {
    let deployment = authority("deployment");
    let public = authority("stands in for a public CA");
    let pinned = serve(&leaf(&public, vec![dns(PINNED)]), response_ok()).await;
    let other = serve(&leaf(&public, vec![dns(OTHER)]), response_ok()).await;
    let trust = DeploymentTrust::new(
        ca_of(&[&deployment]),
        ServerName::try_from(PINNED).expect("name"),
    );
    let mut public_roots = RootCertStore::empty();
    public_roots
        .add(public.certificate.der().clone())
        .expect("public root");
    let client = reqwest::Client::builder()
        .use_preconfigured_tls(
            trust
                .tls_config_with_public_roots(public_roots)
                .expect("TLS config"),
        )
        .resolve(PINNED, pinned)
        .resolve(OTHER, other)
        .build()
        .expect("client");

    let error = get(&client, format!("https://{PINNED}:{}/", pinned.port()))
        .await
        .unwrap_err();
    assert_eq!(refused_as(&error), CertificateError::UnknownIssuer);
    let body = get(&client, format!("https://{OTHER}:{}/", other.port()))
        .await
        .expect("an unpinned host verifies through the public roots");
    assert_eq!(body, "ok");
}

#[tokio::test]
async fn an_expired_certificate_for_the_pinned_host_is_refused() {
    let issuer = authority("deployment");
    let expired = leaf_with(&issuer, vec![dns(PINNED)], Validity::Expired);
    let address = serve(&expired, response_ok()).await;
    let client = pinned_client(
        PINNED,
        address.port(),
        &ca_of(&[&issuer]),
        &[(PINNED, address)],
    );
    let error = get(&client, format!("https://{PINNED}:{}/", address.port()))
        .await
        .unwrap_err();
    let refused = refused_as(&error);
    assert!(
        matches!(
            refused,
            CertificateError::Expired | CertificateError::ExpiredContext { .. }
        ),
        "{refused:?}"
    );
}

#[tokio::test]
async fn a_redirect_to_another_host_gets_no_ca() {
    let issuer = authority("deployment");
    let other = serve(&leaf(&issuer, vec![dns(OTHER)]), response_ok()).await;
    let redirect = response_redirect(&format!("https://{OTHER}:{}/", other.port()));
    let (pinned, redirects) = serve_counted(&leaf(&issuer, vec![dns(PINNED)]), redirect).await;
    let client = pinned_client(
        PINNED,
        pinned.port(),
        &ca_of(&[&issuer]),
        &[(PINNED, pinned), (OTHER, other)],
    );
    let error = get(&client, format!("https://{PINNED}:{}/", pinned.port()))
        .await
        .unwrap_err();
    // The pinned host verified and answered with the redirect, so the
    // refusal is its target's.
    assert_eq!(redirects.load(Ordering::SeqCst), 1);
    assert_eq!(refused_as(&error), CertificateError::UnknownIssuer);
}

#[tokio::test]
async fn an_ip_origin_is_trusted_only_for_its_ip_address() {
    let issuer = authority("deployment");
    let localhost = IpAddr::from(Ipv4Addr::LOCALHOST);
    let by_address = serve(
        &leaf(&issuer, vec![SanType::IpAddress(localhost)]),
        response_ok(),
    )
    .await;
    let client = pinned_client("127.0.0.1", by_address.port(), &ca_of(&[&issuer]), &[]);
    let body = get(&client, format!("https://127.0.0.1:{}/", by_address.port()))
        .await
        .expect("an IP origin verifies against its IP SAN");
    assert_eq!(body, "ok");

    let by_name = serve(&leaf(&issuer, vec![dns("localhost")]), response_ok()).await;
    let client = pinned_client("127.0.0.1", by_name.port(), &ca_of(&[&issuer]), &[]);
    let error = get(&client, format!("https://127.0.0.1:{}/", by_name.port()))
        .await
        .unwrap_err();
    assert!(
        matches!(
            refused_as(&error),
            CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. }
        ),
        "{error:?}"
    );
}
