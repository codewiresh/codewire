use super::*;

fn slot(value: &str) -> CapabilitySlot {
    CapabilitySlot::parse(value).unwrap()
}

fn credential(value: &str) -> CredentialId {
    CredentialId::parse(value).unwrap()
}

fn environment(value: &str) -> EnvironmentId {
    EnvironmentId::parse(value).unwrap()
}

/// A key of one repeated byte, built at run time.
fn key(byte: u8) -> PlaceholderKey {
    PlaceholderKey::from_slice(&[byte; PLACEHOLDER_KEY_BYTES]).unwrap()
}

fn derived_in(
    key_byte: u8,
    environment_id: &str,
    generation: u64,
    slot_name: &str,
    credential_id: &str,
) -> CredentialPlaceholder {
    CredentialPlaceholder::derive(
        &key(key_byte),
        &environment(environment_id),
        generation,
        &slot(slot_name),
        &credential(credential_id),
    )
}

fn derived(key_byte: u8, slot_name: &str, credential_id: &str) -> CredentialPlaceholder {
    derived_in(key_byte, "environment-a", 7, slot_name, credential_id)
}

/// `value` with its character at `index` replaced by `replacement`.
fn replaced(value: &str, index: usize, replacement: &str) -> String {
    format!("{}{replacement}{}", &value[..index], &value[index + 1..])
}

#[test]
fn the_wire_form_is_the_tag_and_43_base64url_characters() {
    let placeholder = derived(7, "codex", "credential-a");
    assert_eq!(CREDENTIAL_PLACEHOLDER_LENGTH, 48);
    assert_eq!(placeholder.as_str().len(), CREDENTIAL_PLACEHOLDER_LENGTH);
    assert!(placeholder.as_str().starts_with("cwp1_"));
    let parsed = CredentialPlaceholder::parse(placeholder.as_str()).unwrap();
    assert!(parsed.ct_eq(&placeholder));
    assert_eq!(parsed.as_str(), placeholder.as_str());
    // Built at run time: 43 zero characters encode 32 zero bytes.
    let zeros = format!("{CREDENTIAL_PLACEHOLDER_TAG}{}", "A".repeat(43));
    assert_eq!(
        CredentialPlaceholder::parse(&zeros).unwrap().as_str(),
        zeros
    );
}

#[test]
fn parse_refuses_everything_but_the_exact_form_and_looks_like_agrees() {
    let valid = derived(7, "codex", "credential-a").as_str().to_owned();
    let body = &valid[CREDENTIAL_PLACEHOLDER_TAG.len()..];
    let last = valid.len() - 1;
    let refused = [
        String::new(),
        CREDENTIAL_PLACEHOLDER_TAG.to_owned(),
        body.to_owned(),
        format!("cwp2_{body}"),
        format!("CWP1_{body}"),
        format!("Cwp1_{body}"),
        format!("cwp1-{body}"),
        format!("cwp1__{body}"),
        valid[..last].to_owned(),
        format!("{valid}A"),
        format!("{}=", &valid[..last]),
        format!("{valid}="),
        format!("{valid}=="),
        replaced(&valid, 10, "+"),
        replaced(&valid, 10, "/"),
        replaced(&valid, 10, "."),
        replaced(&valid, 10, "\u{e9}"),
        replaced(&valid, 10, " "),
        format!(" {valid}"),
        format!("{valid}\n"),
        format!("{}\t", &valid[..last]),
        // Canonical encodings of 32 bytes end in a character whose value is a
        // multiple of four; any other leaves stray bits.
        replaced(&valid, last, "B"),
        replaced(&valid, last, "_"),
    ];
    for value in &refused {
        assert!(
            CredentialPlaceholder::parse(value).is_err(),
            "parse accepted {value:?}"
        );
        assert!(
            !CredentialPlaceholder::looks_like(value),
            "looks_like accepted {value:?}"
        );
    }
    for value in [
        valid.clone(),
        replaced(&valid, last, "A"),
        replaced(&valid, last, "w"),
    ] {
        assert!(CredentialPlaceholder::looks_like(&value));
        assert!(CredentialPlaceholder::parse(&value).is_ok());
    }
    // Every alphabet character in every body position: the shape test and
    // the parser decide alike.
    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    for index in CREDENTIAL_PLACEHOLDER_TAG.len()..valid.len() {
        for character in alphabet.chars() {
            let value = replaced(&valid, index, &character.to_string());
            assert_eq!(
                CredentialPlaceholder::looks_like(&value),
                CredentialPlaceholder::parse(&value).is_ok(),
                "{value:?}"
            );
        }
    }
}

#[test]
fn debug_never_prints_the_value() {
    let placeholder = derived(7, "codex", "credential-a");
    let body = &placeholder.as_str()[CREDENTIAL_PLACEHOLDER_TAG.len()..];
    let rendered = format!("{placeholder:?}");
    assert_eq!(rendered, "CredentialPlaceholder(cwp1_[REDACTED])");
    assert!(!rendered.contains(body));
    assert!(!rendered.contains(&body[..8]));

    assert_eq!(format!("{:?}", key(0x5a)), "PlaceholderKey([REDACTED])");
}

#[test]
fn ct_eq_holds_for_equal_values_and_fails_for_any_single_character_difference() {
    let placeholder = derived(7, "codex", "credential-a");
    let value = placeholder.as_str();
    assert!(placeholder.ct_eq(&CredentialPlaceholder::parse(value).unwrap()));
    assert!(placeholder.ct_eq(&placeholder.clone()));
    let last = value.len() - 1;
    for index in CREDENTIAL_PLACEHOLDER_TAG.len()..value.len() {
        let current = &value[index..=index];
        let replacement = match (index == last, current) {
            (true, "A") => "E",
            (true, _) => "A",
            (false, "B") => "C",
            (false, _) => "B",
        };
        let other = CredentialPlaceholder::parse(&replaced(value, index, replacement)).unwrap();
        assert!(!placeholder.ct_eq(&other), "index {index}");
        assert!(!other.ct_eq(&placeholder), "index {index}");
    }
}

#[test]
fn derivation_is_deterministic_and_separates_every_input() {
    let base = derived_in(7, "environment-a", 7, "codex", "credential-a");
    assert!(base.ct_eq(&derived_in(7, "environment-a", 7, "codex", "credential-a")));
    for other in [
        derived_in(8, "environment-a", 7, "codex", "credential-a"),
        derived_in(7, "environment-b", 7, "codex", "credential-a"),
        derived_in(7, "environment-a", 8, "codex", "credential-a"),
        derived_in(7, "environment-a", 7, "openai", "credential-a"),
        derived_in(7, "environment-a", 7, "codex", "credential-b"),
    ] {
        assert!(!base.ct_eq(&other));
        assert_ne!(base.as_str(), other.as_str());
        assert!(CredentialPlaceholder::looks_like(other.as_str()));
    }
}

/// One placeholder's inputs.
#[derive(Clone, Copy)]
struct Inputs {
    environment: &'static str,
    generation: u64,
    slot: &'static str,
    credential: &'static str,
}

/// The boundary between two adjacent inputs and what keeps it: a zero byte
/// after the environment and after the slot, and the generation's fixed width.
#[derive(Clone, Copy, Debug)]
enum Boundary {
    EnvironmentGeneration,
    GenerationSlot,
    SlotCredential,
}

impl Inputs {
    /// The documented HMAC input with what keeps `removed` taken away: its
    /// zero byte dropped, or the generation written without leading zeros.
    fn input_without(self, removed: Boundary) -> Vec<u8> {
        let generation = self.generation.to_be_bytes();
        let generation = match removed {
            Boundary::GenerationSlot => {
                let first = generation.iter().position(|&byte| byte != 0);
                generation[first.unwrap_or(generation.len())..].to_vec()
            }
            _ => generation.to_vec(),
        };
        let mut input = b"codewire.credential-placeholder/v1\0".to_vec();
        input.extend_from_slice(self.environment.as_bytes());
        if !matches!(removed, Boundary::EnvironmentGeneration) {
            input.push(0);
        }
        input.extend_from_slice(&generation);
        input.extend_from_slice(self.slot.as_bytes());
        if !matches!(removed, Boundary::SlotCredential) {
            input.push(0);
        }
        input.extend_from_slice(self.credential.as_bytes());
        input
    }

    fn derived(self) -> CredentialPlaceholder {
        derived_in(
            7,
            self.environment,
            self.generation,
            self.slot,
            self.credential,
        )
    }
}

/// For each boundary between adjacent inputs, two sets of inputs whose HMAC
/// input would be identical without what keeps that boundary derive
/// different values.
#[test]
fn shifted_boundaries_between_inputs_do_not_collide() {
    let pairs = [
        (
            Boundary::EnvironmentGeneration,
            // The environment's last character becomes the generation's
            // first byte, and the generation's last byte the slot's first.
            Inputs {
                environment: "environment-ab",
                generation: 0x63,
                slot: "odex",
                credential: "credential-a",
            },
            Inputs {
                environment: "environment-a",
                generation: 0x6200_0000_0000_0000,
                slot: "codex",
                credential: "credential-a",
            },
        ),
        (
            Boundary::GenerationSlot,
            Inputs {
                environment: "environment-a",
                generation: 0x63,
                slot: "odex",
                credential: "credential-a",
            },
            Inputs {
                environment: "environment-a",
                generation: 0,
                slot: "codex",
                credential: "credential-a",
            },
        ),
        (
            Boundary::SlotCredential,
            Inputs {
                environment: "environment-a",
                generation: 7,
                slot: "a",
                credential: "bc",
            },
            Inputs {
                environment: "environment-a",
                generation: 7,
                slot: "ab",
                credential: "c",
            },
        ),
    ];
    for (boundary, left, right) in pairs {
        assert_eq!(
            left.input_without(boundary),
            right.input_without(boundary),
            "{boundary:?}: the pair must collide without the boundary"
        );
        assert!(!left.derived().ct_eq(&right.derived()), "{boundary:?}");
    }
}

#[test]
fn a_key_is_exactly_32_bytes() {
    for length in [
        0,
        1,
        PLACEHOLDER_KEY_BYTES - 1,
        PLACEHOLDER_KEY_BYTES + 1,
        64,
    ] {
        assert!(
            PlaceholderKey::from_slice(&vec![7; length]).is_err(),
            "{length}"
        );
    }
    assert!(PlaceholderKey::from_slice(&[7; PLACEHOLDER_KEY_BYTES]).is_ok());
}

/// Pins the byte layout: the expected value is computed here from the
/// documented layout, independently of the implementation's own steps.
#[test]
fn derivation_matches_the_documented_layout() {
    let key_bytes = [0x2a_u8; PLACEHOLDER_KEY_BYTES];
    let mut input = Vec::new();
    input.extend_from_slice(b"codewire.credential-placeholder/v1");
    input.push(0);
    input.extend_from_slice(b"environment-a");
    input.push(0);
    input.extend_from_slice(&[0, 0, 0, 0, 0, 0, 1, 2]);
    input.extend_from_slice(b"codex");
    input.push(0);
    input.extend_from_slice(b"credential-a");
    let mut mac = Hmac::<Sha256>::new_from_slice(&key_bytes).unwrap();
    mac.update(&input);
    let expected = format!(
        "cwp1_{}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    );

    let placeholder = CredentialPlaceholder::derive(
        &PlaceholderKey::from_slice(&key_bytes).unwrap(),
        &environment("environment-a"),
        0x0102,
        &slot("codex"),
        &credential("credential-a"),
    );
    assert_eq!(placeholder.as_str(), expected);
}

/// A known answer, written out: a change of dependency, encoding or layout
/// changes it. Computed independently from the documented layout.
#[test]
fn derivation_matches_a_known_answer() {
    let key_bytes: [u8; PLACEHOLDER_KEY_BYTES] = std::array::from_fn(|index| index as u8);
    let placeholder = CredentialPlaceholder::derive(
        &PlaceholderKey::from_slice(&key_bytes).unwrap(),
        &environment("environment-a"),
        0x0102_0304_0506_0708,
        &slot("codex"),
        &credential("credential-a"),
    );
    assert_eq!(
        placeholder.as_str(),
        "cwp1_CrtskkVMKO8hWIv0dqtomFhFamB5zbu6Peo4NJ8QLZc"
    );
}
