//! What a hosted Pod's first bind records of each host-bound secret its
//! selected sources hold (#4003; docs/dev/SECRETS-AND-CREDENTIALS.md, "Hosts
//! and the front door"). Orchestration writes the list once, beside the
//! Pod's interception decision, and it is never changed for the Pod's life.
//! The credential service reads it to project a value raw only when the
//! secret is plain now and the Pod recorded it plain ("Projection"), and the
//! swap checks each lease against it.

use serde::{Deserialize, Serialize};

use crate::{
    ApplicationSecretKey, EnvironmentId, PlaceholderPrefix, SecretKind, SecretPlaceholder,
    SecretSlot,
};

/// One bound secret as the Pod's first bind found it: the set it is stored
/// in and its key (its slot's inputs), its binding's identity, its prefix and
/// its hosts: everything its placeholder is derived from beside the
/// environment's key, so a Pod keeps that placeholder if the secret is made
/// plain during its life. No value, placeholder or presentation.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirstBindSecret {
    /// The tenant-secret path of the set that stores it, such as
    /// `/projects/<organization>/<project>`.
    pub path: String,
    /// Its key, the variable name.
    pub key: String,
    /// Its `binding_id`, a canonical UUID.
    pub binding_id: String,
    pub binding_generation: u64,
    /// Its placeholder prefix, if its binding has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    /// Its hosts, canonical and sorted.
    pub hosts: Vec<String>,
}

impl FirstBindSecret {
    /// Whether this is the secret stored at `path` under `key`.
    pub fn is(&self, path: &str, key: &str) -> bool {
        self.path == path && self.key == key
    }

    /// Whether the Pod recorded `host` among this secret's hosts.
    pub fn names(&self, host: &str) -> bool {
        self.hosts.iter().any(|recorded| recorded == host)
    }

    /// The kind of set that stores it, from its path; `None` for a path no
    /// platform set has.
    pub fn kind(&self) -> Option<SecretKind> {
        SecretSlot::for_platform_path(&self.path, &self.key)
            .ok()
            .map(|slot| slot.kind())
    }

    /// The placeholder this record derives in `environment` under its
    /// application-secret `key`: the projection's for the same secret, from
    /// the record alone, so the front door matches what the Pod was given.
    /// `None` for a record that doesn't read back (no slot, a `binding_id`
    /// that isn't a canonical UUID, or a prefix out of grammar), which no
    /// projection could have given a placeholder either.
    pub fn placeholder(
        &self,
        key: &ApplicationSecretKey,
        environment: &EnvironmentId,
    ) -> Option<SecretPlaceholder> {
        let slot = SecretSlot::for_platform_path(&self.path, &self.key).ok()?;
        let binding_id = canonical_uuid_bytes(&self.binding_id)?;
        let prefix = self
            .prefix
            .as_deref()
            .map(PlaceholderPrefix::parse)
            .transpose()
            .ok()?;
        Some(SecretPlaceholder::derive(
            key,
            environment,
            &slot,
            &binding_id,
            self.binding_generation,
            prefix.as_ref(),
        ))
    }
}

/// The 16 bytes of a canonical UUID: lowercase, hyphenated 8-4-4-4-12.
fn canonical_uuid_bytes(text: &str) -> Option<[u8; 16]> {
    let bytes = text.as_bytes();
    if bytes.len() != 36 || [8, 13, 18, 23].iter().any(|&index| bytes[index] != b'-') {
        return None;
    }
    let digits: Vec<u8> = bytes.iter().copied().filter(|byte| *byte != b'-').collect();
    if digits.len() != 32 {
        return None;
    }
    let nibble = |byte: u8| match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    };
    let mut out = [0_u8; 16];
    for (index, pair) in digits.as_chunks::<2>().0.iter().enumerate() {
        out[index] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PLACEHOLDER_KEY_BYTES, PlaceholderKey};

    fn record() -> FirstBindSecret {
        FirstBindSecret {
            path: "/projects/0f8a4c1e3b2d4e5f8a9b1c2d3e4f5a6b/7d1e2f3a-4b5c-4d6e-8f70-8192a3b4c5d6"
                .into(),
            key: "FANCY_TOKEN".into(),
            binding_id: "00000000-0000-0000-0000-000000000007".into(),
            binding_generation: 2,
            prefix: Some("ft_".into()),
            hosts: vec!["api.fancy.example".into()],
        }
    }

    fn key(byte: u8) -> ApplicationSecretKey {
        ApplicationSecretKey::derive(
            &PlaceholderKey::from_slice(&[byte; PLACEHOLDER_KEY_BYTES]).unwrap(),
        )
    }

    fn environment() -> EnvironmentId {
        EnvironmentId::parse("a94ef1b4-bbbc-45dd-aa7f-143b8d1f8417").unwrap()
    }

    /// The record derives exactly what the projection derives from the same
    /// inputs: its slot, binding ID, generation and prefix.
    #[test]
    fn a_record_derives_the_projections_placeholder() {
        let secret = record();
        let slot = SecretSlot::for_platform_path(&secret.path, &secret.key).unwrap();
        let mut binding_id = [0_u8; 16];
        binding_id[15] = 7;
        let expected = SecretPlaceholder::derive(
            &key(9),
            &environment(),
            &slot,
            &binding_id,
            2,
            Some(&PlaceholderPrefix::parse("ft_").unwrap()),
        );
        assert_eq!(secret.placeholder(&key(9), &environment()), Some(expected));
        assert_ne!(
            secret.placeholder(&key(8), &environment()),
            secret.placeholder(&key(9), &environment())
        );
        let mut moved = record();
        moved.binding_generation = 3;
        assert_ne!(
            moved.placeholder(&key(9), &environment()),
            secret.placeholder(&key(9), &environment())
        );
    }

    #[test]
    fn a_record_that_does_not_read_back_derives_none() {
        for change in [
            |secret: &mut FirstBindSecret| secret.binding_id = "not-a-uuid".into(),
            |secret: &mut FirstBindSecret| {
                secret.binding_id = "00000000-0000-0000-0000-00000000000G".into();
            },
            |secret: &mut FirstBindSecret| secret.path = "/elsewhere/x".into(),
            |secret: &mut FirstBindSecret| secret.prefix = Some("has space".into()),
        ] {
            let mut secret = record();
            change(&mut secret);
            assert_eq!(secret.placeholder(&key(9), &environment()), None);
        }
    }

    #[test]
    fn names_only_its_recorded_hosts() {
        assert!(record().names("api.fancy.example"));
        assert!(!record().names("api.other.example"));
        assert!(!record().names("API.FANCY.EXAMPLE"));
    }
}
