//! A bound secret's part of a projection (#4003;
//! docs/dev/SECRETS-AND-CREDENTIALS.md, "Projection"): its placeholder in
//! place of its value. A bound row is never decrypted: its ciphertext isn't
//! even selected. Without the environment's application-secret key, or for a
//! set whose stored ID has no slot, it is refused by name and never projected
//! raw. A secret plain now is projected raw only when the Pod's first bind
//! recorded it plain ([`FirstBind`]); one it recorded bound projects the
//! placeholder the record derives, so a running Pod keeps it. A local VM's
//! delegated projection follows its boot's sealed record the same way, and
//! refuses what that record no longer describes.

#[cfg(any(feature = "enrollment", test))]
use codewire_access::PlatformBootSecret;
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
    /// nothing, or for a local VM's delegated projection that carried no
    /// boot record.
    #[error("secret {key} can't be projected raw: this environment recorded no bound secrets")]
    FirstBindUnrecorded { key: String },
    /// A local VM's delegated projection, for a secret plain now whose
    /// generation isn't its boot's record's, or one the record lacks that
    /// was ever bound.
    #[cfg(any(feature = "enrollment", test))]
    #[error(
        "secret {key} can't be projected: it changed since this environment's boot recorded it"
    )]
    RecordStale { key: String },
}

impl BoundSecretRefused {
    fn key(&self) -> &str {
        match self {
            Self::NoApplicationSecretKey { key }
            | Self::NoSlot { key }
            | Self::FirstBindUnrecorded { key } => key,
            #[cfg(any(feature = "enrollment", test))]
            Self::RecordStale { key } => key,
        }
    }

    fn reason(&self) -> &'static str {
        match self {
            Self::NoApplicationSecretKey { .. } => "no_application_secret_key",
            Self::NoSlot { .. } => "no_slot",
            Self::FirstBindUnrecorded { .. } => "first_bind_unrecorded",
            #[cfg(any(feature = "enrollment", test))]
            Self::RecordStale { .. } => "bound_secret_record_stale",
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
    /// A local VM's delegated projection whose Open carried no boot record,
    /// from a client older than the record or a platform that seals none:
    /// it projects as a Pod that recorded nothing, so a secret ever bound is
    /// refused rather than projected raw.
    #[cfg(any(feature = "enrollment", test))]
    NotHosted,
    /// A local VM's delegated projection whose boot's sealed record
    /// verified (docs/dev/SECRETS-AND-CREDENTIALS.md, "The delegation checks
    /// it"): every platform secret the boot's projection took, bound or
    /// plain, at its generation then.
    #[cfg(any(feature = "enrollment", test))]
    LocalBoot {
        environment_id: String,
        recorded: Vec<PlatformBootSecret>,
    },
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
    /// `binding_id` is set once it has ever been bound and whose binding is
    /// at `generation`, projects: its value when the Pod recorded it plain,
    /// and the placeholder the record derives when the Pod recorded it
    /// bound. With no record, only a secret that was never bound projects
    /// its value; one that was has nothing to derive a placeholder from and
    /// is refused. A local VM's boot record also holds each plain entry's
    /// generation: one that no longer matches, or a secret ever bound that
    /// the record lacks, is refused (docs/dev/SECRETS-AND-CREDENTIALS.md,
    /// "The invariant").
    pub(super) fn plain(
        &self,
        path: &str,
        key: &str,
        binding_id: Option<Uuid>,
        #[cfg_attr(not(any(feature = "enrollment", test)), allow(unused_variables))]
        generation: u64,
    ) -> Result<Plain, BoundSecretRefused> {
        #[cfg(any(feature = "enrollment", test))]
        let stale = || BoundSecretRefused::RecordStale {
            key: key.to_owned(),
        };
        match self {
            Self::Hosted {
                recorded: Some(recorded),
                ..
            } => Ok(recorded
                .iter()
                .find(|secret| secret.is(path, key))
                .map_or(Plain::Value, |secret| Plain::Recorded(secret.clone()))),
            #[cfg(any(feature = "enrollment", test))]
            Self::LocalBoot { recorded, .. } => {
                match recorded
                    .iter()
                    .find(|secret| secret.path == path && secret.key == key)
                {
                    // Recorded bound: its placeholder, which carries no
                    // value, whatever the generation; its lease is refused.
                    Some(secret) => match secret.first_bind() {
                        Some(record) => Ok(Plain::Recorded(record)),
                        None if secret.binding_generation == generation => Ok(Plain::Value),
                        None => Err(stale()),
                    },
                    None if binding_id.is_some() => Err(stale()),
                    None => Ok(Plain::Value),
                }
            }
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
        generation: u64,
    ) -> Result<Option<BoundSecret>, Error> {
        match self.plain(path, key, binding_id, generation) {
            Ok(Plain::Value) => Ok(None),
            Ok(Plain::Recorded(record)) => BoundSecret::from_record(&record).map(Some),
            Err(refused) => Err(refused.refuse(match self {
                Self::Hosted { environment_id, .. } => environment_id.as_str(),
                #[cfg(any(feature = "enrollment", test))]
                Self::LocalBoot { environment_id, .. } => environment_id.as_str(),
                #[cfg(any(feature = "enrollment", test))]
                Self::NotHosted => "",
            })),
        }
    }
}

/// What a plain winner projects, by what the Pod's first bind recorded.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Plain {
    /// Its value: plain then, or no hosted Pod's record applies.
    Value,
    /// The placeholder this record derives: bound then.
    Recorded(FirstBindSecret),
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
        let Ok(Plain::Recorded(found)) = recorded.plain(&path, "FANCY_TOKEN", None, 2) else {
            panic!("a secret recorded bound projects its record");
        };
        let from_record = BoundSecret::from_record(&found).unwrap();
        assert_eq!(from_record, bound(&path));
        assert_eq!(
            placeholders([&from_record], Some(&key()), &environment()),
            placeholders([&bound(&path)], Some(&key()), &environment())
        );
        assert_eq!(
            recorded.plain(&path, "OTHER_TOKEN", Some(Uuid::from_u128(8)), 1),
            Ok(Plain::Value)
        );
        assert_eq!(
            hosted(None).plain(&path, "FANCY_TOKEN", Some(Uuid::from_u128(7)), 2),
            Err(BoundSecretRefused::FirstBindUnrecorded {
                key: "FANCY_TOKEN".into()
            })
        );
        assert_eq!(
            hosted(None).plain(&path, "FANCY_TOKEN", None, 0),
            Ok(Plain::Value)
        );
        assert_eq!(
            FirstBind::NotHosted.plain(&path, "FANCY_TOKEN", Some(Uuid::from_u128(7)), 2),
            Err(BoundSecretRefused::FirstBindUnrecorded {
                key: "FANCY_TOKEN".into()
            })
        );
        assert_eq!(
            FirstBind::NotHosted.plain(&path, "FANCY_TOKEN", None, 0),
            Ok(Plain::Value)
        );
        let mut corrupt = record(&path);
        corrupt.binding_id = "not-a-uuid".into();
        assert!(BoundSecret::from_record(&corrupt).is_err());
    }

    /// The invariant for a local VM's delegated projection under its boot's
    /// verified record (docs/dev/SECRETS-AND-CREDENTIALS.md, "The
    /// invariant"): a secret plain now projects its value only when the
    /// record holds it plain at its current generation, or lacks it and it
    /// was never bound. Every other case is the record's placeholder or a
    /// refusal by name, over each of the spec's five cases at several
    /// generations.
    #[test]
    fn a_plain_secret_projects_raw_only_when_its_seal_records_it_plain_at_its_generation() {
        use codewire_access::PlatformBootBinding;
        let path = format!("/projects/{ORG}/{PROJECT}");
        let entry = |key: &str, generation, bound: bool| PlatformBootSecret {
            path: path.clone(),
            key: key.into(),
            binding_generation: generation,
            bound: bound.then(|| PlatformBootBinding {
                binding_id: Uuid::from_u128(7).to_string(),
                prefix: Some("ft_".into()),
                hosts: vec!["api.fancy.example".into()],
            }),
        };
        let boot = FirstBind::LocalBoot {
            environment_id: environment().as_str().to_owned(),
            recorded: vec![entry("FANCY_TOKEN", 2, true), entry("PLAIN_THEN", 5, false)],
        };
        let stale = |key: &str| {
            Err(BoundSecretRefused::RecordStale {
                key: key.to_owned(),
            })
        };
        let ever_bound = Some(Uuid::from_u128(9));
        for generation in [0, 1, 2, 3, 5, 6, 40] {
            // 1. Recorded bound, at any generation: the record's placeholder.
            let Ok(Plain::Recorded(found)) =
                boot.plain(&path, "FANCY_TOKEN", ever_bound, generation)
            else {
                panic!("a secret recorded bound keeps its record at generation {generation}");
            };
            assert_eq!(
                placeholders(
                    [&BoundSecret::from_record(&found).unwrap()],
                    Some(&key()),
                    &environment()
                ),
                placeholders([&bound(&path)], Some(&key()), &environment())
            );
            // 2 and 3. Recorded plain: its value at its own generation only.
            for binding_id in [None, ever_bound] {
                let plain = boot.plain(&path, "PLAIN_THEN", binding_id, generation);
                if generation == 5 {
                    assert_eq!(plain, Ok(Plain::Value));
                } else {
                    assert_eq!(plain, stale("PLAIN_THEN"), "{generation}");
                }
            }
            // 4. Missing and ever bound: refused.
            assert_eq!(
                boot.plain(&path, "NEW_TOKEN", ever_bound, generation),
                stale("NEW_TOKEN")
            );
            // 5. Missing and never bound: its value, as hosted.
            assert_eq!(
                boot.plain(&path, "NEW_TOKEN", None, generation),
                Ok(Plain::Value)
            );
        }
        assert_eq!(
            BoundSecretRefused::RecordStale { key: "K".into() }.reason(),
            "bound_secret_record_stale"
        );
    }
}
