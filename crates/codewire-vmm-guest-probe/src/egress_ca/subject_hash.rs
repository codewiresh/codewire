//! OpenSSL's subject-hash name of a certificate (`X509_NAME_hash`, what
//! `openssl x509 -subject_hash` prints), under which a hashed certificate
//! directory such as `SSL_CERT_DIR` holds it as `<hash>.0`.
//!
//! The hash is SHA-1 over the subject's canonical encoding, its first four
//! bytes read little-endian and printed as eight hex digits. The canonical
//! encoding is each relative distinguished name's DER `SET`, concatenated
//! with no outer `SEQUENCE`, where every value of a text type is re-encoded
//! as a `UTF8String` with leading and trailing whitespace removed, each run
//! of inner whitespace made one space, and ASCII letters lowercased. Values
//! of other types keep their own encoding. It names a file, nothing more: a
//! tool that finds the certificate by it still compares the whole subject.

use sha1::{Digest as _, Sha1};
use x509_parser::asn1_rs::{Class, Tag};
use x509_parser::prelude::{FromDer as _, X509Certificate};
use x509_parser::x509::AttributeTypeAndValue;

use super::EgressCaError;

const SET: u8 = 0x31;
const SEQUENCE: u8 = 0x30;
const OBJECT_IDENTIFIER: u8 = 0x06;
const UTF8_STRING: u8 = 0x0c;

/// The subject-hash name of the certificate `der`, or
/// [`EgressCaError::UnsupportedSubject`] for a subject OpenSSL could not
/// canonicalize either.
pub(super) fn subject_hash(der: &[u8]) -> Result<String, EgressCaError> {
    let (_, certificate) =
        X509Certificate::from_der(der).map_err(|_| EgressCaError::NotACertificate)?;
    let mut canonical = Vec::new();
    for rdn in certificate.subject().iter() {
        let mut attributes = rdn
            .iter()
            .map(canonical_attribute)
            .collect::<Result<Vec<_>, _>>()?;
        // DER orders a SET OF by its members' encodings.
        attributes.sort();
        canonical.extend(tlv(SET, &attributes.concat()));
    }
    let digest = Sha1::digest(&canonical);
    let hash = u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]]);
    Ok(format!("{hash:08x}"))
}

fn canonical_attribute(attribute: &AttributeTypeAndValue<'_>) -> Result<Vec<u8>, EgressCaError> {
    let value = attribute.attr_value();
    let encoded = match canonical_text(value.header.tag(), value.data)? {
        Some(text) => tlv(UTF8_STRING, text.as_bytes()),
        None => {
            // Another type keeps its own encoding: only a primitive
            // universal type with a one-byte tag is expected here.
            let tag = u8::try_from(value.header.tag().0)
                .ok()
                .filter(|tag| *tag < 0x1f)
                .filter(|_| {
                    value.header.class() == Class::Universal && !value.header.is_constructed()
                })
                .ok_or(EgressCaError::UnsupportedSubject)?;
            tlv(tag, value.data)
        }
    };
    let oid = tlv(OBJECT_IDENTIFIER, attribute.attr_type().as_bytes());
    Ok(tlv(SEQUENCE, &[oid, encoded].concat()))
}

/// The canonical text of a value of one of OpenSSL's text types, or `None`
/// for a value of another type.
fn canonical_text(tag: Tag, data: &[u8]) -> Result<Option<String>, EgressCaError> {
    let unsupported = || EgressCaError::UnsupportedSubject;
    let text: String = match tag {
        Tag::Utf8String => std::str::from_utf8(data)
            .map_err(|_| unsupported())?
            .to_owned(),
        // OpenSSL reads these one byte per character.
        Tag::PrintableString | Tag::Ia5String | Tag::VisibleString | Tag::T61String => {
            data.iter().copied().map(char::from).collect()
        }
        Tag::BmpString => wide(data, 2)?,
        Tag::UniversalString => wide(data, 4)?,
        _ => return Ok(None),
    };
    Ok(Some(canonical(&text)))
}

/// Big-endian code points of `width` bytes each.
fn wide(data: &[u8], width: usize) -> Result<String, EgressCaError> {
    if !data.len().is_multiple_of(width) {
        return Err(EgressCaError::UnsupportedSubject);
    }
    data.chunks_exact(width)
        .map(|unit| {
            let point = unit
                .iter()
                .fold(0_u32, |point, byte| point << 8 | u32::from(*byte));
            char::from_u32(point).ok_or(EgressCaError::UnsupportedSubject)
        })
        .collect()
}

/// OpenSSL's `asn1_string_canon` on UTF-8 text: whitespace trimmed at both
/// ends and collapsed to one space inside, ASCII lowercased, every other
/// byte kept.
fn canonical(text: &str) -> String {
    // OpenSSL's `isspace`: space, tab, newline, vertical tab, form feed and
    // carriage return.
    let space = |character: char| matches!(character, ' ' | '\t' | '\n' | '\u{b}' | '\u{c}' | '\r');
    let mut canonical = String::with_capacity(text.len());
    let mut in_space = false;
    for character in text.trim_matches(space).chars() {
        if space(character) {
            if !in_space {
                canonical.push(' ');
            }
            in_space = true;
        } else {
            canonical.push(character.to_ascii_lowercase());
            in_space = false;
        }
    }
    canonical
}

/// One DER element: its one-byte tag, its definite length and `content`.
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut element = vec![tag];
    let length = content.len();
    if length < 0x80 {
        element.push(u8::try_from(length).expect("a short-form length is below 0x80"));
    } else {
        let bytes = length.to_be_bytes();
        let first = bytes
            .iter()
            .position(|byte| *byte != 0)
            .expect("a long-form length is not zero");
        let significant = &bytes[first..];
        element.push(0x80 | u8::try_from(significant.len()).expect("a usize has at most 8 bytes"));
        element.extend_from_slice(significant);
    }
    element.extend_from_slice(content);
    element
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;

    use super::*;

    fn der(pem: &str) -> Vec<u8> {
        let body: String = pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        base64::engine::general_purpose::STANDARD
            .decode(body)
            .unwrap()
    }

    /// Generated with OpenSSL 4.1.0 on 2026-11-23:
    /// `openssl req -x509 -multivalue-rdn -subj "/C=US/O=  Example   Org+OU=Ops Team /CN=  Codewire   ENVIRONMENT  egress CA  "`,
    /// and its hash read with `openssl x509 -subject_hash -noout`. A
    /// `PrintableString`, a two-valued RDN, and text with spaces to trim and
    /// collapse and capitals to lower.
    const MULTI_VALUED: &str = "-----BEGIN CERTIFICATE-----
MIIB8zCCAZmgAwIBAgIBATAKBggqhkjOPQQDAjBpMQswCQYDVQQGEwJVUzEqMBAG
A1UECwwJT3BzIFRlYW0gMBYGA1UECgwPICBFeGFtcGxlICAgT3JnMS4wLAYDVQQD
DCUgIENvZGV3aXJlICAgRU5WSVJPTk1FTlQgIGVncmVzcyBDQSAgMB4XDTI2MTEy
MzIxMTA1NloXDTM2MTEyMDIxMTA1NlowaTELMAkGA1UEBhMCVVMxKjAQBgNVBAsM
CU9wcyBUZWFtIDAWBgNVBAoMDyAgRXhhbXBsZSAgIE9yZzEuMCwGA1UEAwwlICBD
b2Rld2lyZSAgIEVOVklST05NRU5UICBlZ3Jlc3MgQ0EgIDBZMBMGByqGSM49AgEG
CCqGSM49AwEHA0IABBAk/5UxPRY1qwXcshXt/tRm1CmxeINHnwqG6IIAreAF7dxK
3diNPQU7hCu4GWpBjNqJeCtBj1ilPBUth4fglD6jMjAwMB0GA1UdDgQWBBTd9pXD
lmb/G+lFaA2/jE40limsnzAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gA
MEUCIDybYc64L0OkOvSXCiyCyTs06p6tutj/oL+Nbbuz1pnmAiEAnPQgfy3BXu5O
KifxiMcY+uUYmiVYilXEy6kdcD6CfQE=
-----END CERTIFICATE-----";

    /// The same, `-utf8 -subj "/CN=  ÄRGER  Straße /emailAddress=Ops@Example.COM"`:
    /// non-ASCII letters are kept as they are, and an `IA5String` is
    /// lowercased like the rest.
    const NON_ASCII: &str = "-----BEGIN CERTIFICATE-----
MIIBmzCCAUGgAwIBAgIBAzAKBggqhkjOPQQDAjA9MRswGQYDVQQDDBIgIMOEUkdF
UiAgU3RyYcOfZSAxHjAcBgkqhkiG9w0BCQEWD09wc0BFeGFtcGxlLkNPTTAeFw0y
NjExMjMyMTExMDJaFw0zNjExMjAyMTExMDJaMD0xGzAZBgNVBAMMEiAgw4RSR0VS
ICBTdHJhw59lIDEeMBwGCSqGSIb3DQEJARYPT3BzQEV4YW1wbGUuQ09NMFkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDQgAEECT/lTE9FjWrBdyyFe3+1GbUKbF4g0efCobo
ggCt4AXt3Erd2I09BTuEK7gZakGM2ol4K0GPWKU8FS2Hh+CUPqMyMDAwHQYDVR0O
BBYEFN32lcOWZv8b6UVoDb+MTjSWKayfMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZI
zj0EAwIDSAAwRQIhAOKd+YACb4gVyVd6zI+NbyN5Z0nvSB4Nc4lu48KOoBfHAiAs
WNTnJhChHtvRwVLYafYy7tcKwSv+jHHiYUxApJ7l+Q==
-----END CERTIFICATE-----";

    #[test]
    fn the_hash_is_the_one_openssl_prints() {
        assert_eq!(subject_hash(&der(MULTI_VALUED)).unwrap(), "e77b3fb8");
        assert_eq!(subject_hash(&der(NON_ASCII)).unwrap(), "ea157e4e");
    }

    /// The front door's own CA, `CN=Codewire environment egress CA`, whose
    /// hash OpenSSL 4.1.0 prints as `afb09785` for that subject.
    #[test]
    fn the_front_doors_ca_has_openssls_hash() {
        let ca = codewire_egress_front_door::EnvironmentCa::generate(["github.com"]).unwrap();
        assert_eq!(subject_hash(ca.certificate_der()).unwrap(), "afb09785");
    }

    #[test]
    fn text_is_canonicalized_as_openssl_does() {
        assert_eq!(canonical("  A\t\tB  c\r\n"), "a b c");
        assert_eq!(canonical("ÄB"), "Äb");
        assert_eq!(canonical(" \u{b} "), "");
        assert_eq!(wide(&[0, 0x41, 0, 0xe4], 2).unwrap(), "A\u{e4}");
        assert_eq!(
            wide(&[0xd8, 0x00], 2),
            Err(EgressCaError::UnsupportedSubject)
        );
        assert_eq!(wide(&[0, 0, 0], 2), Err(EgressCaError::UnsupportedSubject));
    }

    #[test]
    fn lengths_use_the_shortest_definite_form() {
        assert_eq!(tlv(0x04, &[7; 3]), [0x04, 3, 7, 7, 7]);
        assert_eq!(&tlv(0x04, &[0; 0x80])[..3], [0x04, 0x81, 0x80]);
        assert_eq!(&tlv(0x04, &[0; 0x100])[..4], [0x04, 0x82, 0x01, 0x00]);
    }
}
