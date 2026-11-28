//! A bound secret's part of a projection (#4003;
//! docs/dev/SECRETS-AND-CREDENTIALS.md, "Projection"): its placeholder in
//! place of its value. A bound row is never decrypted: its ciphertext isn't
//! even selected. Without the environment's application-secret key, or for a
//! set whose stored ID has no slot, it is refused by name and never projected
//! raw.

use codewire_access::{
    ApplicationSecretKey, EnvironmentId, PlaceholderPrefix, ReservedHosts, SecretPlaceholder,
    SecretSlot, StoredBinding,
};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::Error;

/// One key and the value a projection carries for it.
type ProjectedValue = (String, Zeroizing<Vec<u8>>);

/// Every placeholder is the prefix, `cwp1_` and 43 characters.
const PLACEHOLDER_BODY_BYTES: usize = codewire_access::CREDENTIAL_PLACEHOLDER_LENGTH;

/// One winning bound row, as captured: everything its placeholder is derived
/// from, and nothing of its value.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct BoundSecret {
    key: String,
    /// `None` when the set's stored ID isn't its kind's spelling: such a set
    /// has no slot, and the secret is refused by name.
    slot: Option<SecretSlot>,
    binding_id: Uuid,
    generation: u64,
    prefix: Option<PlaceholderPrefix>,
}

/// Why a bound secret was refused at projection. It names the key, never a
/// value or a placeholder.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub(super) enum BoundSecretRefused {
    #[error("bound secret {key} can't be projected: the environment has no application-secret key")]
    NoApplicationSecretKey { key: String },
    #[error("bound secret {key} can't be projected: its set's stored ID has no slot")]
    NoSlot { key: String },
}

impl BoundSecretRefused {
    fn key(&self) -> &str {
        match self {
            Self::NoApplicationSecretKey { key } | Self::NoSlot { key } => key,
        }
    }

    fn reason(&self) -> &'static str {
        match self {
            Self::NoApplicationSecretKey { .. } => "no_application_secret_key",
            Self::NoSlot { .. } => "no_slot",
        }
    }
}

impl BoundSecret {
    /// The row's binding columns for `key` stored at `path`. A binding that
    /// doesn't read back, or a bound row with no `binding_id`, is a corrupt
    /// record and refuses the projection.
    pub(super) fn from_row(
        path: &str,
        key: &str,
        binding: &str,
        binding_id: Option<Uuid>,
        generation: i64,
    ) -> Result<Self, Error> {
        let stored: StoredBinding = serde_json::from_str(binding).map_err(|_| Error::Denied)?;
        // The credential service holds no deployment's names; the hosts are
        // checked again where they're used, at bind and by the front door.
        let parsed = stored
            .parse(&ReservedHosts::default())
            .map_err(|_| Error::Denied)?;
        Ok(Self {
            key: key.to_owned(),
            slot: SecretSlot::for_platform_path(path, key).ok(),
            binding_id: binding_id.ok_or(Error::Denied)?,
            generation: u64::try_from(generation).map_err(|_| Error::Denied)?,
            prefix: parsed.prefix().cloned(),
        })
    }

    /// The bytes this entry adds to the projection's encoding.
    pub(super) fn encoded_len(&self) -> usize {
        8 + self.key.len()
            + self
                .prefix
                .as_ref()
                .map_or(0, |prefix| prefix.as_str().len())
            + PLACEHOLDER_BODY_BYTES
    }

    fn placeholder(
        &self,
        key: Option<&ApplicationSecretKey>,
        environment: &EnvironmentId,
    ) -> Result<SecretPlaceholder, BoundSecretRefused> {
        let key = key.ok_or_else(|| BoundSecretRefused::NoApplicationSecretKey {
            key: self.key.clone(),
        })?;
        let slot = self
            .slot
            .as_ref()
            .ok_or_else(|| BoundSecretRefused::NoSlot {
                key: self.key.clone(),
            })?;
        Ok(SecretPlaceholder::derive(
            key,
            environment,
            slot,
            self.binding_id.as_bytes(),
            self.generation,
            self.prefix.as_ref(),
        ))
    }
}

/// Each bound winner's placeholder, as the projection's value, or the first
/// refusal. Nothing here reads or decrypts a value.
pub(super) fn placeholders<'a>(
    bound: impl IntoIterator<Item = &'a BoundSecret>,
    key: Option<&ApplicationSecretKey>,
    environment: &EnvironmentId,
) -> Result<Vec<ProjectedValue>, BoundSecretRefused> {
    bound
        .into_iter()
        .map(|secret| {
            let placeholder = secret.placeholder(key, environment)?;
            Ok((
                secret.key.clone(),
                Zeroizing::new(placeholder.as_str().as_bytes().to_vec()),
            ))
        })
        .collect()
}

/// [`placeholders`] for a projection: a refusal is logged by key and reason,
/// and refuses the whole projection.
pub(super) fn placeholders_or_refuse<'a>(
    bound: impl IntoIterator<Item = &'a BoundSecret>,
    key: Option<&ApplicationSecretKey>,
    environment: &EnvironmentId,
) -> Result<Vec<ProjectedValue>, Error> {
    placeholders(bound, key, environment).map_err(|refused| {
        tracing::warn!(
            environment_id = environment.as_str(),
            key = refused.key(),
            reason = refused.reason(),
            "projection refused a bound secret by name"
        );
        Error::Denied
    })
}

#[cfg(test)]
mod tests {
    use codewire_access::{PLACEHOLDER_KEY_BYTES, PlaceholderKey};

    use super::*;

    const ORG: &str = "0f8a4c1e3b2d4e5f8a9b1c2d3e4f5a6b";
    const PROJECT: &str = "7d1e2f3a-4b5c-4d6e-8f70-8192a3b4c5d6";
    const BINDING: &str = r#"{"hosts":["api.fancy.example"],"presentation":{"kind":"header","headers":["Authorization"],"scheme":"Bearer"},"prefix":"ft_"}"#;

    fn bound(path: &str) -> BoundSecret {
        BoundSecret::from_row(path, "FANCY_TOKEN", BINDING, Some(Uuid::from_u128(7)), 2).unwrap()
    }

    fn key() -> ApplicationSecretKey {
        ApplicationSecretKey::derive(
            &PlaceholderKey::from_slice(&[9; PLACEHOLDER_KEY_BYTES]).unwrap(),
        )
    }

    fn environment() -> EnvironmentId {
        EnvironmentId::parse("a94ef1b4-bbbc-45dd-aa7f-143b8d1f8417").unwrap()
    }

    #[test]
    fn a_bound_secret_projects_its_prefixed_placeholder() {
        let secret = bound(&format!("/projects/{ORG}/{PROJECT}"));
        let values = placeholders([&secret], Some(&key()), &environment()).unwrap();
        let value = std::str::from_utf8(&values[0].1).unwrap();
        assert_eq!(values[0].0, "FANCY_TOKEN");
        assert!(value.starts_with("ft_cwp1_"));
        assert_eq!(value.len(), secret.encoded_len() - 8 - "FANCY_TOKEN".len());
        assert!(!value.contains(PROJECT) && !value.contains(ORG));
    }

    #[test]
    fn a_bound_secret_without_the_application_secret_key_is_refused_by_name() {
        let secret = bound(&format!("/org-secrets/{ORG}"));
        assert_eq!(
            placeholders([&secret], None, &environment()),
            Err(BoundSecretRefused::NoApplicationSecretKey {
                key: "FANCY_TOKEN".into()
            })
        );
    }

    /// A seeded owner whose stored ID isn't 32 lowercase hex has no slot.
    #[test]
    fn a_bound_secret_in_a_set_with_no_slot_is_refused_by_name() {
        for path in [
            "/users/synthetic-creator",
            "/org-secrets/synthetic-org",
            &format!("/projects/{ORG}/development"),
        ] {
            let secret = bound(path);
            assert_eq!(
                placeholders([&secret], Some(&key()), &environment()),
                Err(BoundSecretRefused::NoSlot {
                    key: "FANCY_TOKEN".into()
                }),
                "{path}"
            );
        }
    }

    #[test]
    fn a_corrupt_binding_refuses_the_row() {
        let path = format!("/org-secrets/{ORG}");
        for (binding, id, generation) in [
            ("{}", Some(Uuid::from_u128(7)), 0),
            (BINDING, None, 0),
            (BINDING, Some(Uuid::from_u128(7)), -1),
        ] {
            assert!(BoundSecret::from_row(&path, "KEY", binding, id, generation).is_err());
        }
    }
}
