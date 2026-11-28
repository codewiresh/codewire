//! A bound secret's part of a projection (#4003;
//! docs/dev/SECRETS-AND-CREDENTIALS.md, "Projection"): its placeholder in
//! place of its value. A bound row is never decrypted: its ciphertext isn't
//! even selected. Without the environment's application-secret key, or for a
//! set whose stored ID has no slot, it is refused by name and never projected
//! raw. A secret plain now is projected raw only when the Pod's first bind
//! recorded it plain ([`FirstBind`]); one it recorded bound projects the
//! placeholder the record derives, so a running Pod keeps it.

use codewire_access::{
    ApplicationSecretKey, EnvironmentId, FirstBindSecret, PlaceholderPrefix, ReservedHosts,
    SecretPlaceholder, SecretSlot, StoredBinding,
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
    /// Plain now and bound once, for a Pod whose first bind recorded
    /// nothing, or for a local VM's delegated projection, whose boot record
    /// never reaches the platform.
    #[error("secret {key} can't be projected raw: this environment recorded no bound secrets")]
    FirstBindUnrecorded { key: String },
}

impl BoundSecretRefused {
    fn key(&self) -> &str {
        match self {
            Self::NoApplicationSecretKey { key }
            | Self::NoSlot { key }
            | Self::FirstBindUnrecorded { key } => key,
        }
    }

    fn reason(&self) -> &'static str {
        match self {
            Self::NoApplicationSecretKey { .. } => "no_application_secret_key",
            Self::NoSlot { .. } => "no_slot",
            Self::FirstBindUnrecorded { .. } => "first_bind_unrecorded",
        }
    }

    /// Logs the refusal by key and reason, and refuses the projection.
    fn refuse(self, environment: &str) -> Error {
        tracing::warn!(
            environment_id = environment,
            key = self.key(),
            reason = self.reason(),
            "projection refused a bound secret by name"
        );
        Error::Denied
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

    /// The secret as the Pod's first bind recorded it, for a secret plain
    /// now: its placeholder from the record's binding, never its value. A
    /// record that doesn't read back is a corrupt binding and refuses.
    fn from_record(record: &FirstBindSecret) -> Result<Self, Error> {
        Ok(Self {
            key: record.key.clone(),
            slot: SecretSlot::for_platform_path(&record.path, &record.key).ok(),
            binding_id: Uuid::parse_str(&record.binding_id).map_err(|_| Error::Denied)?,
            generation: record.binding_generation,
            prefix: record
                .prefix
                .as_deref()
                .map(PlaceholderPrefix::parse)
                .transpose()
                .map_err(|_| Error::Denied)?,
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
    placeholders(bound, key, environment).map_err(|refused| refused.refuse(environment.as_str()))
}

/// What the projection's Pod recorded of its bound secrets at its first bind
/// (#4003, migration 0070), which every plain winner is checked against.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum FirstBind {
    /// A hosted Pod of `environment_id`: its record, or `None` for one whose
    /// first bind recorded nothing, bound before the record or by an
    /// orchestration older than it.
    Hosted {
        environment_id: String,
        recorded: Option<Vec<FirstBindSecret>>,
    },
    /// No hosted Pod: a local VM's delegated projection. Its boot records
    /// only its local sources' bound secrets, and that record never reaches
    /// the platform, so this projects as a Pod that recorded nothing: a
    /// secret ever bound is refused rather than projected raw.
    #[cfg(any(feature = "enrollment", test))]
    NotHosted,
}

impl FirstBind {
    /// `stored`, the Pod binding's `bound_secrets` as text, read back; a
    /// record that doesn't read back is a corrupt binding and refuses.
    pub(super) fn hosted(environment_id: &str, stored: Option<&str>) -> Result<Self, Error> {
        let recorded = stored
            .map(serde_json::from_str)
            .transpose()
            .map_err(|_| Error::Denied)?;
        Ok(Self::Hosted {
            environment_id: environment_id.to_owned(),
            recorded,
        })
    }

    /// What the plain secret stored at `path` under `key`, whose
    /// `binding_id` is set once it has ever been bound, projects: its value
    /// when the Pod recorded it plain, and the placeholder the record derives
    /// when the Pod recorded it bound. With no record, only a secret that was
    /// never bound projects its value; one that was has nothing to derive a
    /// placeholder from and is refused.
    pub(super) fn plain(
        &self,
        path: &str,
        key: &str,
        binding_id: Option<Uuid>,
    ) -> Result<Plain<'_>, BoundSecretRefused> {
        match self {
            Self::Hosted {
                recorded: Some(recorded),
                ..
            } => Ok(recorded
                .iter()
                .find(|secret| secret.is(path, key))
                .map_or(Plain::Value, Plain::Recorded)),
            Self::Hosted { recorded: None, .. } if binding_id.is_some() => {
                Err(BoundSecretRefused::FirstBindUnrecorded {
                    key: key.to_owned(),
                })
            }
            #[cfg(any(feature = "enrollment", test))]
            Self::NotHosted if binding_id.is_some() => {
                Err(BoundSecretRefused::FirstBindUnrecorded {
                    key: key.to_owned(),
                })
            }
            Self::Hosted { .. } => Ok(Plain::Value),
            #[cfg(any(feature = "enrollment", test))]
            Self::NotHosted => Ok(Plain::Value),
        }
    }

    /// [`Self::plain`] for a projection: a recorded secret is read back from
    /// its record, and a refusal is logged by key and reason and refuses the
    /// whole projection.
    pub(super) fn plain_or_refuse(
        &self,
        path: &str,
        key: &str,
        binding_id: Option<Uuid>,
    ) -> Result<Option<BoundSecret>, Error> {
        match self.plain(path, key, binding_id) {
            Ok(Plain::Value) => Ok(None),
            Ok(Plain::Recorded(record)) => BoundSecret::from_record(record).map(Some),
            Err(refused) => Err(refused.refuse(match self {
                Self::Hosted { environment_id, .. } => environment_id.as_str(),
                #[cfg(any(feature = "enrollment", test))]
                Self::NotHosted => "",
            })),
        }
    }
}

/// What a plain winner projects, by what the Pod's first bind recorded.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Plain<'a> {
    /// Its value: plain then, or no hosted Pod's record applies.
    Value,
    /// The placeholder this record derives: bound then.
    Recorded(&'a FirstBindSecret),
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

    fn record(path: &str) -> FirstBindSecret {
        FirstBindSecret {
            path: path.into(),
            key: "FANCY_TOKEN".into(),
            binding_id: Uuid::from_u128(7).to_string(),
            binding_generation: 2,
            prefix: Some("ft_".into()),
            hosts: vec!["api.fancy.example".into()],
        }
    }

    /// A plain winner the Pod recorded bound projects the placeholder its
    /// record derives, the same one the bound row gave; one it recorded
    /// plain projects its value. With no record, and in a local VM's
    /// delegated projection, only a secret never bound projects its value.
    #[test]
    fn a_plain_winner_follows_what_the_first_bind_recorded() {
        let path = format!("/projects/{ORG}/{PROJECT}");
        let hosted = |recorded| FirstBind::Hosted {
            environment_id: environment().as_str().to_owned(),
            recorded,
        };
        let recorded = hosted(Some(vec![record(&path)]));
        let Ok(Plain::Recorded(found)) = recorded.plain(&path, "FANCY_TOKEN", None) else {
            panic!("a secret recorded bound projects its record");
        };
        let from_record = BoundSecret::from_record(found).unwrap();
        assert_eq!(from_record, bound(&path));
        assert_eq!(
            placeholders([&from_record], Some(&key()), &environment()),
            placeholders([&bound(&path)], Some(&key()), &environment())
        );
        assert_eq!(
            recorded.plain(&path, "OTHER_TOKEN", Some(Uuid::from_u128(8))),
            Ok(Plain::Value)
        );
        assert_eq!(
            hosted(None).plain(&path, "FANCY_TOKEN", Some(Uuid::from_u128(7))),
            Err(BoundSecretRefused::FirstBindUnrecorded {
                key: "FANCY_TOKEN".into()
            })
        );
        assert_eq!(
            hosted(None).plain(&path, "FANCY_TOKEN", None),
            Ok(Plain::Value)
        );
        assert_eq!(
            FirstBind::NotHosted.plain(&path, "FANCY_TOKEN", Some(Uuid::from_u128(7))),
            Err(BoundSecretRefused::FirstBindUnrecorded {
                key: "FANCY_TOKEN".into()
            })
        );
        assert_eq!(
            FirstBind::NotHosted.plain(&path, "FANCY_TOKEN", None),
            Ok(Plain::Value)
        );
        let mut corrupt = record(&path);
        corrupt.binding_id = "not-a-uuid".into();
        assert!(BoundSecret::from_record(&corrupt).is_err());
    }
}
