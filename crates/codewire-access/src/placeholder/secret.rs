//! The placeholder a host-bound application secret reaches an environment as
//! (#4003; docs/dev/SECRETS-AND-CREDENTIALS.md, "The placeholder" and "The
//! application-secret key"). It is keyed by the environment's
//! [`ApplicationSecretKey`], derived from its [`PlaceholderKey`] under its own
//! label, so the code that projects application secrets never holds a key
//! that can compute a credential's placeholder. Its inputs are the
//! environment, the secret's slot, its `binding_id` and its
//! `binding_generation`, and no profile revision: a secret is selected
//! through a source, not a profile.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac as _};
use sha2::Sha256;
use zeroize::{Zeroize as _, Zeroizing};

use super::{CREDENTIAL_PLACEHOLDER_TAG, PLACEHOLDER_KEY_BYTES, PlaceholderKey};
use crate::{EnvironmentId, PlaceholderPrefix, SecretSlot};

/// HKDF info of the application-secret key. Nothing follows it: the
/// placeholder key it is expanded from is already one environment's.
const APPLICATION_KEY_INFO: &[u8] = b"codewire application bound secret key v1\0";

/// HMAC input prefix, distinct from the provider credentials' domain. The
/// environment, a zero byte, the slot, a zero byte, the 16 bytes of the
/// binding ID and the generation as eight big-endian bytes follow it.
const SECRET_DERIVATION_DOMAIN: &[u8] = b"codewire.secret-placeholder/v1\0";

/// One environment's application-secret key. Not `Clone`, zeroized when
/// dropped, and never sent anywhere; only placeholders derived from it are.
pub struct ApplicationSecretKey(Zeroizing<[u8; PLACEHOLDER_KEY_BYTES]>);

impl ApplicationSecretKey {
    /// HKDF-SHA256 Expand of one block with the environment's placeholder key
    /// as the pseudorandom key (32 uniformly random bytes, or a key already
    /// expanded from such a root, so no Extract step is needed) and the info
    /// `codewire application bound secret key v1\0`: HMAC-SHA256 keyed by
    /// `key` over the info and the block counter `0x01`.
    pub fn derive(key: &PlaceholderKey) -> Self {
        let mut mac = Hmac::<Sha256>::new_from_slice(&*key.0).expect("HMAC accepts any key length");
        mac.update(APPLICATION_KEY_INFO);
        mac.update(&[1]);
        let mut derived = mac.finalize().into_bytes();
        let mut application = Zeroizing::new([0_u8; PLACEHOLDER_KEY_BYTES]);
        application.copy_from_slice(&derived);
        derived.as_mut_slice().zeroize();
        Self(application)
    }
}

impl fmt::Debug for ApplicationSecretKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ApplicationSecretKey([REDACTED])")
    }
}

/// One environment's stand-in for one bound secret: the binding's prefix,
/// `cwp1_`, and the unpadded base64url of 32 derived bytes. It names nothing
/// outside the environment's own front door: never the key's name, its kind,
/// its collection ID or any part of its value. `Debug` never prints it.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretPlaceholder(String);

impl SecretPlaceholder {
    /// HMAC-SHA256 keyed by `key` over `codewire.secret-placeholder/v1\0`,
    /// the environment ID, a zero byte, the slot, a zero byte, `binding_id`
    /// (a UUID's 16 bytes) and `binding_generation` as eight big-endian
    /// bytes. Neither the environment ID nor the slot can contain a zero
    /// byte and the tail has a fixed width, so the input is unambiguous. The
    /// prefix is put in front and is no input: changing it moves the
    /// generation.
    pub fn derive(
        key: &ApplicationSecretKey,
        environment_id: &EnvironmentId,
        slot: &SecretSlot,
        binding_id: &[u8; 16],
        binding_generation: u64,
        prefix: Option<&PlaceholderPrefix>,
    ) -> Self {
        let mut mac = Hmac::<Sha256>::new_from_slice(&*key.0).expect("HMAC accepts any key length");
        mac.update(SECRET_DERIVATION_DOMAIN);
        mac.update(environment_id.as_str().as_bytes());
        mac.update(&[0]);
        mac.update(slot.to_string().as_bytes());
        mac.update(&[0]);
        mac.update(binding_id);
        mac.update(&binding_generation.to_be_bytes());
        // Not a secret: the environment holds it.
        Self(format!(
            "{}{CREDENTIAL_PLACEHOLDER_TAG}{}",
            prefix.map_or("", PlaceholderPrefix::as_str),
            URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
        ))
    }

    /// The wire form, prefix included.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretPlaceholder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretPlaceholder([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CREDENTIAL_PLACEHOLDER_LENGTH, CapabilitySlot, CredentialId, CredentialPlaceholder,
        SecretKind, known_answer,
    };

    const PROJECT: &str = "0f8a4c1e-3b2d-4e5f-8a9b-1c2d3e4f5a6b";
    const OTHER_PROJECT: &str = "7d1e2f3a-4b5c-4d6e-8f70-8192a3b4c5d6";
    const HEX: &str = "0f8a4c1e3b2d4e5f8a9b1c2d3e4f5a6b";
    const BINDING: [u8; 16] = [
        16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
    ];

    fn placeholder_key() -> PlaceholderKey {
        PlaceholderKey::from_slice(&known_answer::KEY).unwrap()
    }

    fn key() -> ApplicationSecretKey {
        ApplicationSecretKey::derive(&placeholder_key())
    }

    fn environment(value: &str) -> EnvironmentId {
        EnvironmentId::parse(value).unwrap()
    }

    fn slot(kind: SecretKind, collection: &str, name: &str) -> SecretSlot {
        SecretSlot::new(kind, collection, name).unwrap()
    }

    fn derived(
        environment_id: &str,
        slot: &SecretSlot,
        binding_id: &[u8; 16],
        generation: u64,
    ) -> String {
        SecretPlaceholder::derive(
            &key(),
            &environment(environment_id),
            slot,
            binding_id,
            generation,
            None,
        )
        .as_str()
        .to_owned()
    }

    fn fancy() -> SecretSlot {
        slot(SecretKind::Project, PROJECT, "FANCY_TOKEN")
    }

    /// Computed outside Rust (Python's `hmac`) from the layout the spec and
    /// the two `derive`s' documentation give, so both labels and the input
    /// order are pinned.
    #[test]
    fn a_worked_derivation_matches_the_written_layout() {
        assert_eq!(
            derived("environment-a", &fancy(), &BINDING, 3),
            "cwp1_GgIpw9_UqCTqnDGc1feLq-zHtKd0niDH02_9LSzRdoI"
        );
    }

    /// The application-secret key is not the placeholder key: the same
    /// provider derivation under each gives different placeholders, so what
    /// the application-secret path holds can't compute a credential's.
    #[test]
    fn the_application_secret_key_gives_other_placeholders_than_its_placeholder_key() {
        let original = placeholder_key();
        let application = PlaceholderKey(Zeroizing::new(*key().0));
        let environment_id = environment("environment-a");
        for (slot, credential) in [("codex", "credential-a"), ("anthropic", "fancy_token")] {
            let slot = CapabilitySlot::parse(slot).unwrap();
            let credential = CredentialId::parse(credential).unwrap();
            let under_original =
                CredentialPlaceholder::derive(&original, &environment_id, 3, &slot, &credential);
            let under_application =
                CredentialPlaceholder::derive(&application, &environment_id, 3, &slot, &credential);
            assert_ne!(under_original.as_str(), under_application.as_str());
        }
    }

    /// The two HMAC inputs start with different domains, and neither domain
    /// is a prefix of the other.
    #[test]
    fn its_domain_is_apart_from_the_provider_credentials() {
        let provider = super::super::DERIVATION_DOMAIN;
        assert!(!SECRET_DERIVATION_DOMAIN.starts_with(provider));
        assert!(!provider.starts_with(SECRET_DERIVATION_DOMAIN));
    }

    #[test]
    fn the_wire_form_is_the_prefix_the_marker_and_43_characters() {
        let plain = derived("environment-a", &fancy(), &BINDING, 3);
        assert_eq!(plain.len(), CREDENTIAL_PLACEHOLDER_LENGTH);
        assert!(CredentialPlaceholder::looks_like(&plain));
        let prefix = PlaceholderPrefix::parse("sk_").unwrap();
        let prefixed = SecretPlaceholder::derive(
            &key(),
            &environment("environment-a"),
            &fancy(),
            &BINDING,
            3,
            Some(&prefix),
        );
        assert_eq!(prefixed.as_str(), format!("sk_{plain}"));
    }

    /// The value is no input of `derive`, and a new value keeps the record's
    /// `binding_id` and generation, so it keeps the placeholder too.
    #[test]
    fn it_is_stable_and_changes_with_each_input() {
        let base = derived("environment-a", &fancy(), &BINDING, 3);
        assert_eq!(derived("environment-a", &fancy(), &BINDING, 3), base);
        let mut other_binding = BINDING;
        other_binding[15] ^= 1;
        for changed in [
            derived("environment-a", &fancy(), &BINDING, 4),
            derived("environment-a", &fancy(), &other_binding, 3),
            derived("environment-b", &fancy(), &BINDING, 3),
            derived(
                "environment-a",
                &slot(SecretKind::Project, PROJECT, "OTHER_TOKEN"),
                &BINDING,
                3,
            ),
            derived(
                "environment-a",
                &slot(SecretKind::Project, OTHER_PROJECT, "FANCY_TOKEN"),
                &BINDING,
                3,
            ),
            derived(
                "environment-a",
                &slot(SecretKind::Organization, HEX, "FANCY_TOKEN"),
                &BINDING,
                3,
            ),
        ] {
            assert_ne!(changed, base);
        }
        assert_ne!(
            derived(
                "environment-a",
                &slot(SecretKind::User, HEX, "FANCY_TOKEN"),
                &BINDING,
                3
            ),
            derived(
                "environment-a",
                &slot(SecretKind::Local, HEX, "FANCY_TOKEN"),
                &BINDING,
                3
            ),
        );
    }

    #[test]
    fn a_placeholder_never_contains_its_collection_id_key_or_kind() {
        for (kind, collection) in [
            (SecretKind::Project, PROJECT),
            (SecretKind::Organization, HEX),
            (SecretKind::User, HEX),
            (SecretKind::Local, HEX),
        ] {
            let value = derived(
                "environment-a",
                &slot(kind, collection, "FANCY_TOKEN"),
                &BINDING,
                3,
            );
            for part in [
                collection,
                &collection[..8],
                &collection[24..],
                "FANCY",
                "TOKEN",
                kind.as_str(),
                "secret",
            ] {
                assert!(!value.contains(part), "{part}");
            }
        }
    }

    #[test]
    fn debug_never_prints_it() {
        let placeholder = SecretPlaceholder::derive(
            &key(),
            &environment("environment-a"),
            &fancy(),
            &BINDING,
            3,
            None,
        );
        let printed = format!("{placeholder:?} {:?}", key());
        assert!(!printed.contains(&placeholder.as_str()[5..]));
        assert!(!printed.contains("cwp1_"));
    }
}
