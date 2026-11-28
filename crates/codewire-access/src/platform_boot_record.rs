//! A local VM boot's sealed record of its platform sources' secrets (#4003;
//! docs/dev/SECRETS-AND-CREDENTIALS.md, "A local VM's platform sources").
//!
//! The platform answers it before the boot starts, the boot keeps it for its
//! life beside its record of its local sources, and its delegation carries it
//! back, where the platform checks its seal before anything else. It names
//! every platform secret the boot's projection takes, bound or plain, with
//! its generation at that read: names, generations, hosts and prefixes only,
//! never a value or a placeholder.

use serde::{Deserialize, Serialize};

use crate::FirstBindSecret;

/// A boot's record and the platform's seal over it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformBootRecord {
    pub secrets: Vec<PlatformBootSecret>,
    /// OpenBao transit's `vault:vN:` string, carried unchanged: the boot
    /// never reads it.
    pub seal: String,
}

/// One platform secret the boot's projection takes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformBootSecret {
    /// Its set's platform path, such as `/projects/<organization>/<project>`.
    pub path: String,
    pub key: String,
    pub binding_generation: u64,
    /// Set for a secret that was bound at the read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound: Option<PlatformBootBinding>,
}

/// What a bound secret's record adds: everything its placeholder and its
/// hosts come from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformBootBinding {
    /// A canonical UUID.
    pub binding_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    pub hosts: Vec<String>,
}

impl PlatformBootSecret {
    /// This secret as a first-bind record, when it was bound.
    pub fn first_bind(&self) -> Option<FirstBindSecret> {
        let bound = self.bound.as_ref()?;
        Some(FirstBindSecret {
            path: self.path.clone(),
            key: self.key.clone(),
            binding_id: bound.binding_id.clone(),
            binding_generation: self.binding_generation,
            prefix: bound.prefix.clone(),
            hosts: bound.hosts.clone(),
        })
    }
}

impl PlatformBootRecord {
    /// The record's bound secrets as first-bind records: the hosts the boot
    /// binds, and the epoch's grants.
    pub fn bound(&self) -> Vec<FirstBindSecret> {
        self.secrets
            .iter()
            .filter_map(PlatformBootSecret::first_bind)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_bound_entries_are_first_bind_records() {
        let record = PlatformBootRecord {
            secrets: vec![
                PlatformBootSecret {
                    path: "/org-secrets/0f8a4c1e3b2d4e5f8a9b1c2d3e4f5a6b".into(),
                    key: "PLAIN_TOKEN".into(),
                    binding_generation: 3,
                    bound: None,
                },
                PlatformBootSecret {
                    path: "/org-secrets/0f8a4c1e3b2d4e5f8a9b1c2d3e4f5a6b".into(),
                    key: "FANCY_TOKEN".into(),
                    binding_generation: 2,
                    bound: Some(PlatformBootBinding {
                        binding_id: "00000000-0000-0000-0000-000000000007".into(),
                        prefix: Some("ft_".into()),
                        hosts: vec!["api.fancy.example".into()],
                    }),
                },
            ],
            seal: "vault:v1:synthetic".into(),
        };
        assert_eq!(
            record.bound(),
            vec![FirstBindSecret {
                path: "/org-secrets/0f8a4c1e3b2d4e5f8a9b1c2d3e4f5a6b".into(),
                key: "FANCY_TOKEN".into(),
                binding_id: "00000000-0000-0000-0000-000000000007".into(),
                binding_generation: 2,
                prefix: Some("ft_".into()),
                hosts: vec!["api.fancy.example".into()],
            }]
        );
    }
}
