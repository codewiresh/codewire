//! The CA's profile and the leaf signer's bounds, without a database: the
//! store's rows, seal and lifecycle are in `tests/interception_cas.rs`.

use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer, X509Certificate};

use super::*;

const HOST: &str = "api.example.com";
const SECOND: &str = "uploads.example.com";

/// A CA as the store opens one, valid from now for `validity`.
fn ca(validity: Duration) -> InterceptionCa {
    InterceptionCa::generate_for_test(validity)
}

/// A leaf key the front door would make, and its SubjectPublicKeyInfo.
fn leaf_key() -> Vec<u8> {
    KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        .unwrap()
        .public_key_der()
}

#[test]
fn the_ca_signs_for_one_step_excludes_every_address_and_lasts_400_days() {
    let ca = ca(CA_VALIDITY);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let (_, cert) = X509Certificate::from_der(ca.certificate_der()).unwrap();
    cert.verify_signature(None).unwrap();
    assert_eq!(cert.subject(), cert.issuer());
    let common_name = cert.subject().iter_common_name().next().unwrap();
    assert_eq!(common_name.as_str().unwrap(), CA_COMMON_NAME);

    let basic = cert.basic_constraints().unwrap().unwrap();
    assert!(basic.critical && basic.value.ca);
    assert_eq!(basic.value.path_len_constraint, Some(0));
    let usage = cert.key_usage().unwrap().unwrap().value;
    assert!(usage.key_cert_sign() && usage.crl_sign() && !usage.digital_signature());

    // No DNS subtree is permitted: the signer's binding record is the host
    // limit (cw-security, #4001). Every IPv4 and IPv6 address is excluded.
    let constraints = cert.name_constraints().unwrap().unwrap();
    assert!(constraints.critical);
    assert!(constraints.value.permitted_subtrees.is_none());
    let excluded: Vec<_> = constraints
        .value
        .excluded_subtrees
        .as_ref()
        .unwrap()
        .iter()
        .map(|subtree| match subtree.base {
            GeneralName::IPAddress(range) => range.to_vec(),
            ref other => panic!("excluded a non-address name: {other:?}"),
        })
        .collect();
    assert_eq!(excluded, [vec![0; 8], vec![0; 32]]);

    let validity = cert.validity();
    assert!((now - 5 * 60 - validity.not_before.timestamp()).abs() <= 5);
    assert!((validity.not_after.timestamp() - (now + 400 * 24 * 60 * 60)).abs() <= 5);
}

#[test]
fn a_leaf_chains_to_the_stored_ca_names_only_its_hosts_and_serves_only() {
    let ca = ca(CA_VALIDITY);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let (_, authority) = X509Certificate::from_der(ca.certificate_der()).unwrap();
    let der = ca
        .sign_leaf(&leaf_key(), &[HOST, SECOND], MAX_LEAF_LIFETIME)
        .unwrap();
    let (_, leaf) = X509Certificate::from_der(&der).unwrap();
    // Signed under the stored CA, though the issuer is rebuilt from the row.
    leaf.verify_signature(Some(authority.public_key())).unwrap();
    assert_eq!(leaf.issuer(), authority.subject());
    let authority_key = authority
        .iter_extensions()
        .find_map(|extension| match extension.parsed_extension() {
            x509_parser::extensions::ParsedExtension::SubjectKeyIdentifier(id) => Some(id.0),
            _ => None,
        })
        .unwrap();
    let leaf_authority = leaf
        .iter_extensions()
        .find_map(|extension| match extension.parsed_extension() {
            x509_parser::extensions::ParsedExtension::AuthorityKeyIdentifier(id) => {
                id.key_identifier.as_ref().map(|id| id.0)
            }
            _ => None,
        })
        .unwrap();
    assert_eq!(leaf_authority, authority_key);

    let names = leaf.subject_alternative_name().unwrap().unwrap();
    assert_eq!(
        names.value.general_names,
        [GeneralName::DNSName(HOST), GeneralName::DNSName(SECOND)]
    );
    let purposes = leaf.extended_key_usage().unwrap().unwrap().value;
    assert!(purposes.server_auth);
    assert!(!purposes.any && !purposes.client_auth && !purposes.code_signing);
    assert!(purposes.other.is_empty());
    assert!(!leaf.basic_constraints().unwrap().unwrap().value.ca);
    let validity = leaf.validity();
    assert!((now - 5 * 60 - validity.not_before.timestamp()).abs() <= 5);
    assert!((validity.not_after.timestamp() - (now + 60 * 60)).abs() <= 5);

    // Two leaves for one key never share a serial.
    let again = ca
        .sign_leaf(&leaf_key(), &[HOST], MAX_LEAF_LIFETIME)
        .unwrap();
    let (_, again) = X509Certificate::from_der(&again).unwrap();
    assert_ne!(again.raw_serial(), leaf.raw_serial());
}

/// The Codex slot's leaf names `chatgpt.com` and `*.chatgpt.com`, exactly as
/// given, and nothing else (#6195).
#[test]
fn the_codex_suffix_is_signed_as_its_one_label_wildcard() {
    let ca = ca(CA_VALIDITY);
    let der = ca
        .sign_leaf(
            &leaf_key(),
            &["chatgpt.com", "*.chatgpt.com"],
            MAX_LEAF_LIFETIME,
        )
        .unwrap();
    let (_, leaf) = X509Certificate::from_der(&der).unwrap();
    let names: Vec<String> = leaf
        .subject_alternative_name()
        .unwrap()
        .unwrap()
        .value
        .general_names
        .iter()
        .map(|name| match name {
            GeneralName::DNSName(name) => (*name).to_owned(),
            other => panic!("only DNS names: {other:?}"),
        })
        .collect();
    assert_eq!(names, ["chatgpt.com", "*.chatgpt.com"]);
}

#[test]
fn a_leaf_never_outlives_its_ca_and_an_expired_ca_signs_nothing() {
    let short = ca(Duration::from_secs(10 * 60));
    let der = short
        .sign_leaf(&leaf_key(), &[HOST], MAX_LEAF_LIFETIME)
        .unwrap();
    let (_, leaf) = X509Certificate::from_der(&der).unwrap();
    assert_eq!(
        leaf.validity().not_after.timestamp(),
        short.not_after().unix_timestamp()
    );

    let mut expired = ca(CA_VALIDITY);
    expired.not_after = OffsetDateTime::now_utc() - Duration::from_secs(1);
    assert_eq!(
        expired.sign_leaf(&leaf_key(), &[HOST], MAX_LEAF_LIFETIME),
        Err(LeafRefusal::Expired)
    );
}

#[test]
fn the_signer_refuses_anything_outside_the_profile() {
    let ca = ca(CA_VALIDITY);
    let key = leaf_key();
    for lifetime in [Duration::ZERO, MAX_LEAF_LIFETIME + Duration::from_secs(1)] {
        assert_eq!(
            ca.sign_leaf(&key, &[HOST], lifetime),
            Err(LeafRefusal::InvalidLifetime),
            "{lifetime:?}"
        );
    }
    let too_many: Vec<String> = (0..=MAX_LEAF_HOSTS)
        .map(|n| format!("h{n}.example.com"))
        .collect();
    let too_many: Vec<&str> = too_many.iter().map(String::as_str).collect();
    for hosts in [
        &[][..],
        &too_many[..],
        &[HOST, HOST][..],
        &["API.example.com"][..],
        &["api.example.com."][..],
        &["localhost"][..],
        &["10.0.0.1"][..],
        &["[::1]"][..],
        &["api.example.com:443"][..],
        &["a*.example.com"][..],
        &["*"][..],
        &["*.*.example.com"][..],
        &["*.com"][..],
    ] {
        assert!(
            matches!(
                ca.sign_leaf(&key, hosts, MAX_LEAF_LIFETIME),
                Err(LeafRefusal::InvalidHosts | LeafRefusal::WildcardNotInterceptable)
            ),
            "{hosts:?}"
        );
    }
    // The table's one suffix is chatgpt.com (#6195): every other well-formed
    // wildcard is refused as such, and a malformed one as invalid.
    for wildcard in [
        "*.openai.com",
        "*.api.openai.com",
        "*.a.chatgpt.com",
        "*.xchatgpt.com",
        "*.chatgpt.com.example",
        "*.xn--chatgt-frf.com",
        "*.anthropic.com",
    ] {
        assert_eq!(
            ca.sign_leaf(&key, &[wildcard], MAX_LEAF_LIFETIME),
            Err(LeafRefusal::WildcardNotInterceptable),
            "{wildcard}"
        );
    }
    for malformed in [
        "*.ChatGPT.com",
        "*.chatgpt.com.",
        "*..chatgpt.com",
        "**.chatgpt.com",
    ] {
        assert_eq!(
            ca.sign_leaf(&key, &[malformed], MAX_LEAF_LIFETIME),
            Err(LeafRefusal::InvalidHosts),
            "{malformed}"
        );
    }

    let p384 = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384)
        .unwrap()
        .public_key_der();
    let mut compressed = key.clone();
    compressed[P256_SPKI_PREFIX.len()] = 0x02;
    let mut trailing = key.clone();
    trailing.push(0);
    for public_key in [
        &p384[..],
        &compressed[..],
        &trailing[..],
        &key[1..],
        &[][..],
    ] {
        assert_eq!(
            ca.sign_leaf(public_key, &[HOST], MAX_LEAF_LIFETIME),
            Err(LeafRefusal::InvalidPublicKey)
        );
    }
}

#[test]
fn nothing_about_the_key_reaches_debug_or_a_refusal() {
    let ca = ca(CA_VALIDITY);
    let pkcs8 = ca.key.0.serialize_der();
    let shown = format!("{ca:?}");
    assert!(shown.starts_with("InterceptionCa"), "{shown}");
    assert!(!shown.contains("key"), "{shown}");
    for refusal in [
        LeafRefusal::InvalidHosts,
        LeafRefusal::WildcardNotInterceptable,
        LeafRefusal::InvalidLifetime,
        LeafRefusal::InvalidPublicKey,
        LeafRefusal::Expired,
        LeafRefusal::Sign,
    ] {
        let text = format!("{refusal} {refusal:?}");
        assert!(!text.contains(HOST), "{text}");
    }
    // The canary: no rendering above carries the key's own bytes.
    let canary = pkcs8
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert!(!shown.contains(&canary[canary.len() - 16..]));
}
