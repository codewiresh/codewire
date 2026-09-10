//! Every fixture is a disposable synthetic key generated once with stock
//! ssh-keygen for these tests. Never use these public test keys for an account.
//! RSA generation, files, processes and ambient agents are absent from tests.
//! Encrypted fixtures use AES-CTR, bcrypt -a16 and PASSWORD below.

use std::cell::Cell;
use std::ops::Range;

use ssh_key::encoding::base64::{Base64, Encoding as _};
use ssh_key::private::{DsaKeypair, DsaPrivateKey, RsaPrivateKey};
use ssh_key::public::{DsaPublicKey, RsaPublicKey, SkEd25519};

use super::*;

const PASSWORD: &[u8] = b"codewire-synthetic-passphrase-only";
const COMMENT: &str = "codewire-synthetic-test-only";
const ED128: &[u8] = include_bytes!("fixtures/ed25519-aes128-ctr.openssh");
const ED192: &[u8] = include_bytes!("fixtures/ed25519-aes192-ctr.openssh");
const ED256: &[u8] = include_bytes!("fixtures/ed25519-aes256-ctr.openssh");
const RSA2048: &[u8] = include_bytes!("fixtures/rsa-2048.openssh");

fn secret(bytes: &[u8]) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(bytes.to_vec())
}

fn seeded_key() -> PrivateKey {
    let mut key = PrivateKey::from(Ed25519Keypair::from_seed(&[7; 32]));
    key.set_comment(COMMENT);
    key
}

fn encode(key: &PrivateKey) -> Zeroizing<Vec<u8>> {
    secret(key.to_openssh(LineEnding::LF).unwrap().as_bytes())
}

fn raw_openssh(binary: &[u8]) -> Zeroizing<Vec<u8>> {
    let body = Zeroizing::new(Base64::encode_string(binary));
    let mut result = Zeroizing::new(Vec::new());
    result.extend_from_slice(PEM_BEGIN.as_bytes());
    result.push(b'\n');
    for line in body.as_bytes().chunks(70) {
        result.extend_from_slice(line);
        result.push(b'\n');
    }
    result.extend_from_slice(PEM_END.as_bytes());
    result.push(b'\n');
    result
}

fn assert_public(actual: &SshPublicKey, expected: &str) {
    let expected = PublicKey::from_openssh(expected).unwrap();
    assert_eq!(actual.key_blob(), expected.to_bytes().unwrap());
    assert_eq!(
        actual.fingerprint(),
        expected.fingerprint(HashAlg::Sha256).to_string()
    );
    assert_eq!(actual.fingerprint().len(), 50);
    assert_eq!(actual.openssh().split_whitespace().count(), 2);
    assert!(!actual.openssh().contains(COMMENT));
    assert!(!actual.openssh().contains('\n'));
    assert!(actual.openssh().len() <= MAX_SSH_PUBLIC_KEY_BYTES);
}

#[test]
fn persisted_public_identity_is_parsed_and_fingerprint_bound_without_material() {
    for source in [
        seeded_key().public_key().to_openssh().unwrap(),
        include_str!("fixtures/rsa-2048.pub").trim().to_owned(),
    ] {
        let source = PublicKey::from_openssh(&source).unwrap();
        let public = PublicKey::from(source.key_data().clone());
        let expected = public.to_openssh().unwrap();
        let fingerprint = public.fingerprint(HashAlg::Sha256).to_string();
        let parsed = parse_public_key(&expected, &fingerprint).unwrap();
        assert_public(&parsed, &expected);

        let mut wrong_fingerprint = fingerprint.clone();
        wrong_fingerprint.replace_range(49..50, "A");
        if wrong_fingerprint == fingerprint {
            wrong_fingerprint.replace_range(49..50, "B");
        }
        assert_eq!(
            parse_public_key(&expected, &wrong_fingerprint),
            Err(SshMaterialError::InvalidKey)
        );
        assert_eq!(
            parse_public_key(&format!("{expected} imported-comment"), &fingerprint),
            Err(SshMaterialError::InvalidKey)
        );
        assert_eq!(
            parse_public_key(&format!("{expected}\n"), &fingerprint),
            Err(SshMaterialError::InvalidKey)
        );
    }
}

#[test]
fn generated_ed25519_roundtrips_through_one_protected_bundle() {
    let prepared = generate_with_entropy(|seed| {
        seed.fill(7);
        Ok(())
    })
    .unwrap();
    assert_eq!(prepared.public_key().algorithm(), SshKeyAlgorithm::Ed25519);
    assert_public(
        prepared.public_key(),
        &seeded_key().public_key().to_openssh().unwrap(),
    );
    let (public, protected) = prepared.into_parts();
    let material = decode_protected_material(protected).unwrap();
    assert_eq!(material.public_key(), &public);
    let (key, passphrase) = material.into_parts();
    assert!(passphrase.is_none());
    assert_eq!(
        parse_openssh(&key).unwrap().public_key().key_data(),
        seeded_key().public_key().key_data()
    );
}

#[test]
fn generation_uses_fresh_entropy_and_fails_closed_when_entropy_fails() {
    let first = generate_ed25519().unwrap();
    let second = generate_ed25519().unwrap();
    assert_ne!(first.public_key(), second.public_key());
    let failed = generate_with_entropy(|seed| {
        seed.fill(9);
        Err(SshMaterialError::EntropyUnavailable)
    })
    .unwrap_err();
    assert_eq!(failed, SshMaterialError::EntropyUnavailable);
}

#[test]
fn ordinary_rsa_sizes_import_without_key_generation() {
    for (bits, private, public) in [
        (2048, RSA2048, include_str!("fixtures/rsa-2048.pub")),
        (
            3072,
            include_bytes!("fixtures/rsa-3072.openssh").as_slice(),
            include_str!("fixtures/rsa-3072.pub"),
        ),
        (
            4096,
            include_bytes!("fixtures/rsa-4096.openssh").as_slice(),
            include_str!("fixtures/rsa-4096.pub"),
        ),
        (
            8192,
            include_bytes!("fixtures/rsa-8192.openssh").as_slice(),
            include_str!("fixtures/rsa-8192.pub"),
        ),
    ] {
        let prepared = import_openssh(secret(private), None).unwrap();
        assert_eq!(
            prepared.public_key().algorithm(),
            SshKeyAlgorithm::Rsa { bits }
        );
        assert_public(prepared.public_key(), public);
    }
}

#[test]
fn ordinary_encrypted_rsa_sizes_derive_the_same_public_identities() {
    for (bits, private, public) in [
        (
            2048,
            include_bytes!("fixtures/rsa-2048-encrypted.openssh").as_slice(),
            include_str!("fixtures/rsa-2048.pub"),
        ),
        (
            3072,
            include_bytes!("fixtures/rsa-3072-encrypted.openssh").as_slice(),
            include_str!("fixtures/rsa-3072.pub"),
        ),
        (
            4096,
            include_bytes!("fixtures/rsa-4096-encrypted.openssh").as_slice(),
            include_str!("fixtures/rsa-4096.pub"),
        ),
        (
            8192,
            include_bytes!("fixtures/rsa-8192-encrypted.openssh").as_slice(),
            include_str!("fixtures/rsa-8192.pub"),
        ),
    ] {
        let prepared = import_openssh(secret(private), Some(secret(PASSWORD))).unwrap();
        assert_eq!(
            prepared.public_key().algorithm(),
            SshKeyAlgorithm::Rsa { bits }
        );
        assert_public(prepared.public_key(), public);
    }
}

#[test]
fn supported_aes_ctr_ed25519_imports_match_stock_public_keys() {
    for (private, public) in [
        (ED128, include_str!("fixtures/ed25519-aes128-ctr.pub")),
        (ED192, include_str!("fixtures/ed25519-aes192-ctr.pub")),
        (ED256, include_str!("fixtures/ed25519-aes256-ctr.pub")),
    ] {
        let prepared = import_openssh(secret(private), Some(secret(PASSWORD))).unwrap();
        assert_eq!(prepared.public_key().algorithm(), SshKeyAlgorithm::Ed25519);
        assert_public(prepared.public_key(), public);
    }
    // Independently recorded using stock ssh-keygen -E sha256 -l.
    assert_eq!(
        import_openssh(secret(ED256), Some(secret(PASSWORD)))
            .unwrap()
            .public_key()
            .fingerprint(),
        "SHA256:Ks5CibofVqaO/aZJ+gtCpVHlSuwqM3rJAxhD4BGOmhE"
    );
}

#[test]
fn encrypted_payload_retains_passphrase_only_inside_protected_material() {
    let prepared = import_openssh(secret(ED256), Some(secret(PASSWORD))).unwrap();
    let (public, protected) = prepared.into_parts();
    assert!(
        protected
            .expose_secret()
            .windows(PASSWORD.len())
            .any(|part| part == PASSWORD)
    );
    assert!(!format!("{protected:?} {public:?}").contains(std::str::from_utf8(PASSWORD).unwrap()));
    let material = decode_protected_material(protected).unwrap();
    assert_eq!(material.public_key(), &public);
    assert_eq!(format!("{material:?}"), "SshAgentMaterial([REDACTED])");
    let (key, passphrase) = material.into_parts();
    assert_eq!(key.as_slice(), ED256);
    assert_eq!(passphrase.unwrap().as_slice(), PASSWORD);
}

fn armor_variants(original: &[u8]) -> Vec<Zeroizing<Vec<u8>>> {
    let mut crlf = Zeroizing::new(Vec::new());
    for byte in original {
        if *byte == b'\n' {
            crlf.push(b'\r');
        }
        crlf.push(*byte);
    }
    vec![
        secret(original),
        Zeroizing::new([b" \t\r\n".as_slice(), original, b"\r\n \t"].concat()),
        secret(original.strip_suffix(b"\n").unwrap()),
        crlf,
    ]
}

fn assert_canonical_agent_armor(actual: &[u8], expected: &PrivateKey) {
    assert!(actual.starts_with(b"-----BEGIN OPENSSH PRIVATE KEY-----\n"));
    assert!(actual.ends_with(b"\n-----END OPENSSH PRIVATE KEY-----\n"));
    assert!(!actual.contains(&b'\r'));
    // Do not call our whitespace-trimming parser here: these exact bytes must
    // already have the framing produced by stock OpenSSH fixtures.
    let parsed = PrivateKey::from_openssh(actual).unwrap();
    assert_eq!(parsed.cipher(), expected.cipher());
    assert_eq!(parsed.kdf(), expected.kdf());
    assert_eq!(parsed.is_encrypted(), expected.is_encrypted());
    assert_eq!(parsed.public_key(), expected.public_key());
    // Includes the ciphertext and KDF salt/rounds, not just algorithm labels.
    // Boolean assertions avoid dumping even synthetic private bytes on failure.
    assert!(parsed.to_bytes().unwrap() == expected.to_bytes().unwrap());
    assert!(actual == expected.to_openssh(LineEnding::LF).unwrap().as_bytes());
}

#[test]
fn import_publishes_canonical_armor_without_changing_encrypted_material() {
    for (original, password) in [
        (encode(&seeded_key()), None),
        (secret(ED256), Some(PASSWORD)),
        (secret(RSA2048), None),
    ] {
        let expected = PrivateKey::from_openssh(&original).unwrap();
        for variant in armor_variants(&original) {
            let prepared = import_openssh(variant, password.map(secret)).unwrap();
            let (public, protected) = prepared.into_parts();
            let mut fields = &protected.expose_secret()[BUNDLE_PREFIX.len()..];
            let stored_key = take_field(&mut fields, MAX_OPENSSH_PRIVATE_KEY_BYTES).unwrap();
            assert_canonical_agent_armor(stored_key, &expected);
            let stored_password = take_field(&mut fields, MAX_SSH_PASSPHRASE_BYTES).unwrap();
            assert!(stored_password == password.unwrap_or_default());
            assert!(fields.is_empty());

            let material = decode_protected_material(protected).unwrap();
            assert_eq!(material.public_key(), &public);
            let (key, passphrase) = material.into_parts();
            assert_canonical_agent_armor(&key, &expected);
            assert!(passphrase.as_deref().map(Vec::as_slice) == password);
        }
    }
}

#[test]
fn decoder_never_returns_noncanonical_armor_from_a_protected_payload() {
    for (original, password) in [
        (encode(&seeded_key()), None),
        (secret(ED256), Some(PASSWORD)),
    ] {
        let expected = PrivateKey::from_openssh(&original).unwrap();
        for variant in armor_variants(&original) {
            // Exercise decoder admission directly, bypassing import's framing.
            let protected = encode_bundle(&variant, password).unwrap();
            let material = decode_protected_material(protected).unwrap();
            assert_eq!(
                material.public_key().key_blob(),
                expected.public_key().to_bytes().unwrap()
            );
            let (key, passphrase) = material.into_parts();
            assert_canonical_agent_armor(&key, &expected);
            assert!(passphrase.as_deref().map(Vec::as_slice) == password);
        }
    }
}

#[test]
fn passphrases_are_required_only_for_encrypted_keys_and_never_guessed() {
    assert_eq!(
        import_openssh(secret(ED256), None).unwrap_err(),
        SshMaterialError::PassphraseRequired
    );
    assert_eq!(
        import_openssh(secret(ED256), Some(secret(b"wrong-synthetic-password"))).unwrap_err(),
        SshMaterialError::DecryptionFailed
    );
    assert_eq!(
        import_openssh(encode(&seeded_key()), Some(secret(PASSWORD))).unwrap_err(),
        SshMaterialError::InvalidPassphrase
    );
    for invalid in [
        Vec::new(),
        vec![b'x'; MAX_SSH_PASSPHRASE_BYTES + 1],
        b"x\0y".to_vec(),
        b"x\ny".to_vec(),
        b"x\ry".to_vec(),
    ] {
        assert_eq!(
            import_openssh(secret(ED256), Some(Zeroizing::new(invalid))).unwrap_err(),
            SshMaterialError::InvalidPassphrase
        );
    }
    // Whitespace is passphrase content, not an implicit default or trimming rule.
    let calls = Cell::new(0);
    let result = admit_with_decrypt(parse_openssh(ED256).unwrap(), Some(b"  "), |_, value| {
        calls.set(calls.get() + 1);
        assert_eq!(value, b"  ");
        Err(SshMaterialError::DecryptionFailed)
    });
    assert_eq!(result.unwrap_err(), SshMaterialError::DecryptionFailed);
    assert_eq!(calls.get(), 1);
}

fn field_range(bytes: &[u8], offset: &mut usize) -> Range<usize> {
    let length = u32::from_be_bytes(bytes[*offset..*offset + 4].try_into().unwrap()) as usize;
    *offset += 4;
    let start = *offset;
    *offset += length;
    assert!(*offset <= bytes.len());
    start..*offset
}

fn replace_field(bytes: &mut Vec<u8>, range: Range<usize>, value: &[u8]) {
    bytes[range.start - 4..range.start].copy_from_slice(&(value.len() as u32).to_be_bytes());
    bytes.splice(range, value.iter().copied());
}

fn altered_kdf(rounds: u32, salt: &[u8]) -> PrivateKey {
    let mut encoded = parse_openssh(ED256).unwrap().to_bytes().unwrap();
    let mut offset = b"openssh-key-v1\0".len();
    field_range(&encoded, &mut offset); // cipher
    field_range(&encoded, &mut offset); // KDF name
    let options = field_range(&encoded, &mut offset);
    let mut replacement = Vec::new();
    replacement.extend_from_slice(&(salt.len() as u32).to_be_bytes());
    replacement.extend_from_slice(salt);
    replacement.extend_from_slice(&rounds.to_be_bytes());
    replace_field(&mut encoded, options, &replacement);
    PrivateKey::from_bytes(&encoded).unwrap()
}

#[test]
fn over_limit_kdf_is_rejected_before_any_decryption_work() {
    for (rounds, salt) in [
        (0, vec![1; 16]),
        (65, vec![1; 16]),
        (u32::MAX, vec![1; 16]),
        (16, vec![]),
        (16, vec![1; 15]),
        (16, vec![1; 17]),
    ] {
        let calls = Cell::new(0);
        let result = admit_with_decrypt(altered_kdf(rounds, &salt), Some(PASSWORD), |_, _| {
            calls.set(calls.get() + 1);
            Err(SshMaterialError::DecryptionFailed)
        });
        assert_eq!(result.unwrap_err(), SshMaterialError::UnsupportedEncryption);
        assert_eq!(calls.get(), 0);
    }
    // Exercise inclusive accepted bounds without running a 64-round KDF.
    for rounds in [1, 16, MAX_SSH_BCRYPT_ROUNDS] {
        let calls = Cell::new(0);
        assert_eq!(
            admit_with_decrypt(altered_kdf(rounds, &[1; 16]), Some(PASSWORD), |_, _| {
                calls.set(calls.get() + 1);
                Err(SshMaterialError::DecryptionFailed)
            })
            .unwrap_err(),
            SshMaterialError::DecryptionFailed
        );
        assert_eq!(calls.get(), 1);
    }
}

#[test]
fn unsupported_cipher_is_rejected_without_decryption_or_conversion() {
    for (name, tag) in [
        ("aes128-cbc", false),
        ("aes192-cbc", false),
        ("aes256-cbc", false),
        ("aes128-gcm@openssh.com", true),
        ("aes256-gcm@openssh.com", true),
        ("chacha20-poly1305@openssh.com", true),
        ("3des-cbc", false),
    ] {
        let mut bytes = parse_openssh(ED256).unwrap().to_bytes().unwrap();
        let mut offset = b"openssh-key-v1\0".len();
        let cipher = field_range(&bytes, &mut offset);
        replace_field(&mut bytes, cipher, name.as_bytes());
        if tag {
            bytes.extend_from_slice(&[0; 16]);
        }
        let calls = Cell::new(0);
        assert_eq!(
            admit_with_decrypt(
                PrivateKey::from_bytes(&bytes).unwrap(),
                Some(PASSWORD),
                |_, _| {
                    calls.set(calls.get() + 1);
                    Err(SshMaterialError::DecryptionFailed)
                }
            )
            .unwrap_err(),
            SshMaterialError::UnsupportedEncryption
        );
        assert_eq!(calls.get(), 0);
        assert_eq!(
            import_openssh(raw_openssh(&bytes), Some(secret(PASSWORD))).unwrap_err(),
            SshMaterialError::UnsupportedEncryption
        );
    }
}

#[test]
fn input_requires_one_bounded_openssh_private_key_not_other_formats() {
    let valid = encode(&seeded_key());
    let combined = [valid.as_slice(), valid.as_slice()].concat();
    let trailing = [valid.as_slice(), b"unadmitted trailing data"].concat();
    let pem = b"-----BEGIN PRIVATE KEY-----\nsynthetic\n-----END PRIVATE KEY-----".to_vec();
    let ppk = b"PuTTY-User-Key-File-3: ssh-ed25519\nsynthetic".to_vec();
    for invalid in [
        Vec::new(),
        vec![b'x'; MAX_OPENSSH_PRIVATE_KEY_BYTES + 1],
        vec![0xff; 16],
        combined,
        trailing,
        pem,
        ppk,
        seeded_key().public_key().to_openssh().unwrap().into_bytes(),
    ] {
        assert_eq!(
            import_openssh(Zeroizing::new(invalid), None).unwrap_err(),
            SshMaterialError::InvalidKey
        );
    }
    let mut padded = valid.to_vec();
    padded.resize(MAX_OPENSSH_PRIVATE_KEY_BYTES, b' ');
    assert!(import_openssh(Zeroizing::new(padded), None).is_ok());
}

#[test]
fn dsa_ecdsa_security_keys_and_certificates_are_not_plain_identities() {
    assert_eq!(
        import_openssh(secret(include_bytes!("fixtures/ecdsa.openssh")), None).unwrap_err(),
        SshMaterialError::UnsupportedKey
    );
    let value = || Mpint::from_positive_bytes(&[3]);
    let dsa = DsaPublicKey::new(value(), value(), value(), value()).unwrap();
    let dsa_key = PrivateKey::from(
        DsaKeypair::new(dsa.clone(), DsaPrivateKey::new(value()).unwrap()).unwrap(),
    );
    assert_eq!(
        import_openssh(encode(&dsa_key), None).unwrap_err(),
        SshMaterialError::UnsupportedKey
    );
    let dsa = PublicKey::from(KeyData::Dsa(dsa));
    assert_eq!(
        validate_public_key(&dsa).unwrap_err(),
        SshMaterialError::UnsupportedKey
    );
    let key = seeded_key();
    let sk = PublicKey::from(KeyData::SkEd25519(SkEd25519::new(
        *key.public_key().key_data().ed25519().unwrap(),
        "ssh:",
    )));
    assert_eq!(
        validate_public_key(&sk).unwrap_err(),
        SshMaterialError::UnsupportedKey
    );
    let sk_key = PrivateKey::from(
        ssh_key::private::SkEd25519::new(
            sk.key_data().sk_ed25519().unwrap().clone(),
            0,
            vec![1; 32],
        )
        .unwrap(),
    );
    assert_eq!(
        import_openssh(encode(&sk_key), None).unwrap_err(),
        SshMaterialError::UnsupportedKey
    );
    let mut builder =
        ssh_key::certificate::Builder::new(vec![1; 16], key.public_key().key_data().clone(), 1, 2)
            .unwrap();
    builder.valid_principal("synthetic").unwrap();
    let certificate = builder.sign(&key).unwrap();
    let certificate = PublicKey::from(KeyData::Certificate(Box::new(certificate)));
    assert_eq!(
        validate_public_key(&certificate).unwrap_err(),
        SshMaterialError::UnsupportedKey
    );
}

fn rsa_pair() -> RsaKeypair {
    parse_openssh(RSA2048)
        .unwrap()
        .key_data()
        .rsa()
        .unwrap()
        .clone()
}

fn with_rsa_parts(public: RsaPublicKey, private: RsaPrivateKey) -> PrivateKey {
    PrivateKey::from(RsaKeypair::new(public, private).unwrap())
}

#[test]
fn rsa_bounds_check_actual_bits_and_bounded_exponents_before_bigint_work() {
    assert_eq!(
        import_openssh(secret(include_bytes!("fixtures/rsa-1024.openssh")), None).unwrap_err(),
        SshMaterialError::UnsupportedKey
    );
    let pair = rsa_pair();
    for (first, size) in [(0x7f, 256), (1, 1025)] {
        let mut n = vec![1; size];
        n[0] = first; // 2047 or 8193 actual bits, not rounded-up byte width.
        let public =
            RsaPublicKey::new(pair.public().e().clone(), Mpint::from_positive_bytes(&n)).unwrap();
        assert_eq!(
            import_openssh(
                encode(&with_rsa_parts(public, pair.private().clone())),
                None
            )
            .unwrap_err(),
            SshMaterialError::UnsupportedKey
        );
    }
    for e in [2_u64, 4, 1_u64 << 33, u64::MAX] {
        let public = RsaPublicKey::new(
            Mpint::from_positive_bytes(&e.to_be_bytes()),
            pair.public().n().clone(),
        )
        .unwrap();
        assert!(validate_public_key(&PublicKey::from(KeyData::Rsa(public))).is_err());
    }
    for e in [3_u64, 65537, MAX_RSA_EXPONENT] {
        let bytes = e.to_be_bytes();
        let bytes = &bytes[bytes.iter().position(|byte| *byte != 0).unwrap()..];
        let public =
            RsaPublicKey::new(Mpint::from_positive_bytes(bytes), pair.public().n().clone())
                .unwrap();
        assert_eq!(
            validate_public_key(&PublicKey::from(KeyData::Rsa(public))).unwrap(),
            SshKeyAlgorithm::Rsa { bits: 2048 }
        );
    }
}

#[test]
fn rsa_private_components_and_crt_coefficient_must_be_consistent() {
    let pair = rsa_pair();
    for index in 0..4 {
        let mut values = [
            pair.private().d().clone(),
            pair.private().iqmp().clone(),
            pair.private().p().clone(),
            pair.private().q().clone(),
        ];
        values[index] = Mpint::from_positive_bytes(&[3]);
        let [d, iqmp, p, q] = values;
        let private = RsaPrivateKey::new(d, iqmp, p, q).unwrap();
        let key = with_rsa_parts(pair.public().clone(), private);
        assert_eq!(
            import_openssh(encode(&key), None).err(),
            Some(SshMaterialError::InvalidKey),
            "changed RSA private component {index} was not rejected"
        );
    }
    for changed in ["n", "e"] {
        let mut n = pair.public().n().as_positive_bytes().unwrap().to_vec();
        if changed == "n" {
            *n.last_mut().unwrap() ^= 2;
        }
        let e = if changed == "e" {
            Mpint::from_positive_bytes(&[1, 0, 3])
        } else {
            pair.public().e().clone()
        };
        let public = RsaPublicKey::new(e, Mpint::from_positive_bytes(&n)).unwrap();
        assert_eq!(
            import_openssh(
                encode(&with_rsa_parts(public, pair.private().clone())),
                None
            )
            .unwrap_err(),
            SshMaterialError::InvalidKey
        );
    }
}

#[test]
fn rsa_import_rejects_crt_mismatch_preserved_by_parser_but_rebuilt_by_rsa() {
    let original = rsa_pair();
    let wrong_iqmp = Mpint::from_positive_bytes(&[3]);
    assert!(original.private().iqmp() != &wrong_iqmp);
    let malformed = with_rsa_parts(
        original.public().clone(),
        RsaPrivateKey::new(
            original.private().d().clone(),
            wrong_iqmp.clone(),
            original.private().p().clone(),
            original.private().q().clone(),
        )
        .unwrap(),
    );
    let encoded = encode(&malformed);
    let parsed = parse_openssh(&encoded).unwrap();
    let pair = parsed.key_data().rsa().unwrap();
    // Parsing/armor serialization preserve the bad coefficient. RSA conversion
    // instead derives iqmp from q and p, so a successful sign self-test alone
    // cannot establish that these original imported components are coherent.
    assert!(pair.private().iqmp() == &wrong_iqmp);
    let reconstructed = rsa::RsaPrivateKey::try_from(pair).unwrap();
    let reconstructed = RsaKeypair::try_from(&reconstructed).unwrap();
    assert!(reconstructed.private().iqmp() == original.private().iqmp());
    assert!(reconstructed.private().iqmp() != pair.private().iqmp());
    assert_eq!(
        validate_rsa_private(pair),
        Err(SshMaterialError::InvalidKey)
    );
    assert_eq!(
        import_openssh(secret(&encoded), None).err(),
        Some(SshMaterialError::InvalidKey)
    );
    assert_eq!(
        decode_protected_material(encode_bundle(&encoded, None).unwrap()).err(),
        Some(SshMaterialError::InvalidKey)
    );
}

#[test]
fn each_rsa_private_component_has_a_pre_arithmetic_size_bound() {
    let pair = rsa_pair();
    for index in 0..4 {
        let mut values = [
            pair.private().d().clone(),
            pair.private().iqmp().clone(),
            pair.private().p().clone(),
            pair.private().q().clone(),
        ];
        values[index] = Mpint::from_positive_bytes(&vec![1; MAX_RSA_COMPONENT_BYTES + 1]);
        let [d, iqmp, p, q] = values;
        let private = RsaPrivateKey::new(d, iqmp, p, q).unwrap();
        assert_eq!(
            import_openssh(
                encode(&with_rsa_parts(pair.public().clone(), private)),
                None
            )
            .unwrap_err(),
            SshMaterialError::UnsupportedKey
        );
    }
}

#[test]
fn ed25519_private_public_mismatch_and_multi_key_envelopes_are_rejected() {
    let mut binary = seeded_key().to_bytes().unwrap();
    let mut offset = b"openssh-key-v1\0".len();
    for _ in 0..3 {
        field_range(&binary, &mut offset);
    }
    let nkeys = offset;
    offset += 4;
    let public = field_range(&binary, &mut offset);
    let private = field_range(&binary, &mut offset);
    let mut private_offset = private.start + 8; // checkints
    field_range(&binary, &mut private_offset); // algorithm
    field_range(&binary, &mut private_offset); // repeated public key
    let secret = field_range(&binary, &mut private_offset);
    binary[secret.start] ^= 1;
    assert_eq!(
        import_openssh(raw_openssh(&binary), None).unwrap_err(),
        SshMaterialError::InvalidKey
    );
    let mut binary = seeded_key().to_bytes().unwrap();
    binary[public.end - 1] ^= 1;
    assert_eq!(
        import_openssh(raw_openssh(&binary), None).unwrap_err(),
        SshMaterialError::InvalidKey
    );
    let mut binary = seeded_key().to_bytes().unwrap();
    binary[nkeys..nkeys + 4].copy_from_slice(&2_u32.to_be_bytes());
    assert_eq!(
        import_openssh(raw_openssh(&binary), None).unwrap_err(),
        SshMaterialError::InvalidKey
    );
    let mut binary = seeded_key().to_bytes().unwrap();
    binary[public.start - 4..public.start].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(
        import_openssh(raw_openssh(&binary), None).unwrap_err(),
        SshMaterialError::InvalidKey
    );
}

#[test]
fn bundle_bounds_version_truncation_and_trailing_bytes_fail_closed() {
    let (_, protected) = generate_with_entropy(|seed| {
        seed.fill(7);
        Ok(())
    })
    .unwrap()
    .into_parts();
    let valid = protected.expose_secret();
    for length in 1..valid.len() {
        assert!(
            decode_protected_material(ProtectedValue::from_slice(&valid[..length]).unwrap())
                .is_err()
        );
    }
    let mut trailing = valid.to_vec();
    trailing.push(0);
    let mut version = valid.to_vec();
    version[BUNDLE_PREFIX.len() - 1] += 1;
    let mut huge_field = valid.to_vec();
    huge_field[BUNDLE_PREFIX.len()..BUNDLE_PREFIX.len() + 4]
        .copy_from_slice(&u32::MAX.to_be_bytes());
    for invalid in [trailing, version, huge_field, vec![0; MAX_BUNDLE_BYTES + 1]] {
        assert_eq!(
            decode_protected_material(ProtectedValue::new(invalid).unwrap()).unwrap_err(),
            SshMaterialError::InvalidBundle
        );
    }
    assert!(encode_bundle(&[], None).is_err());
    assert!(encode_bundle(&vec![0; MAX_OPENSSH_PRIVATE_KEY_BYTES + 1], None).is_err());
    assert!(encode_bundle(b"synthetic", Some(&vec![0; MAX_SSH_PASSPHRASE_BYTES + 1])).is_err());
    assert!(encode_bundle(b"synthetic", Some(&[])).is_err());
}

#[test]
fn errors_and_material_debug_never_contain_key_passphrase_or_comments() {
    let prepared = import_openssh(encode(&seeded_key()), None).unwrap();
    let debug = format!("{prepared:?} {:?}", prepared.public_key());
    for forbidden in [COMMENT, PEM_BEGIN, std::str::from_utf8(PASSWORD).unwrap()] {
        assert!(!debug.contains(forbidden));
    }
    for error in [
        SshMaterialError::InvalidKey,
        SshMaterialError::UnsupportedKey,
        SshMaterialError::UnsupportedEncryption,
        SshMaterialError::PassphraseRequired,
        SshMaterialError::InvalidPassphrase,
        SshMaterialError::DecryptionFailed,
        SshMaterialError::EntropyUnavailable,
        SshMaterialError::InvalidBundle,
    ] {
        let formatted = format!("{error} {error:?}");
        assert!(!formatted.contains(COMMENT));
        assert!(!formatted.contains(std::str::from_utf8(PASSWORD).unwrap()));
        assert!(std::error::Error::source(&error).is_none());
    }
}
