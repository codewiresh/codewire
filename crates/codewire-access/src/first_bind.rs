//! What a hosted Pod's first bind records of each host-bound secret its
//! selected sources hold (#4003; docs/dev/SECRETS-AND-CREDENTIALS.md, "Hosts
//! and the front door"). Orchestration writes the list once, beside the
//! Pod's interception decision, and it is never changed for the Pod's life.
//! The credential service reads it to project a value raw only when the
//! secret is plain now and the Pod recorded it plain ("Projection"), and the
//! swap checks each lease against it.

use serde::{Deserialize, Serialize};

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
}
