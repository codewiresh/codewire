//! Host-bound secrets at a hosted Pod's first bind (#4003;
//! docs/dev/SECRETS-AND-CREDENTIALS.md, "Hosts and the front door"). The
//! bind reads each bound secret the Pod's selected sources hold, refuses a
//! selection whose union of hosts doesn't hold (a host the deployment now
//! reserves, two values on one host, or more hosts than an environment
//! carries), and records the rest beside the
//! interception decision, once for the Pod's life
//! ([`codewire_access::FirstBindSecret`], migration 0070).

use std::collections::{BTreeMap, BTreeSet};

use codewire_access::{
    BindingError, BoundHost, FirstBindSecret, MAX_BOUND_HOSTS_PER_ENVIRONMENT, ReservedHosts,
    StoredBinding,
};
use sqlx::PgPool;
use uuid::Uuid;

use super::store::BindingStoreUnavailable;
use crate::egress::assignment::Intercept;
use crate::lifecycle::{
    BOUND_HOST_CONFLICT_ERROR_CODE, BOUND_HOST_RESERVED_ERROR_CODE, TOO_MANY_BOUND_HOSTS_ERROR_CODE,
};

/// What a refusal says of a selected credential that names a bound host: its
/// hosts are the platform's own, so no key or credential name is needed.
const SELECTED_CREDENTIAL: &str = "a selected credential";

/// Why a first bind was refused for its bound secrets. The sentence names
/// the hosts and the keys, never a value.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum BoundSecretsRefusal {
    /// A bound secret names a host the deployment has reserved since it was
    /// bound: one of its own names is never served a secret.
    #[error("{host}, which {key} is sent to, is one of this deployment's own names")]
    HostReserved { host: String, key: String },
    /// Two values name one host: two bound secrets, or a bound secret and a
    /// selected credential.
    #[error("{host} is named by both {first} and {second}; one host carries only one of them")]
    HostConflict {
        host: String,
        first: String,
        second: String,
    },
    /// The bound secrets name more hosts than one environment carries.
    #[error(
        "the bound secrets {} name {count} hosts; an environment carries at most {MAX_BOUND_HOSTS_PER_ENVIRONMENT}",
        .keys.join(", ")
    )]
    TooManyHosts { count: usize, keys: Vec<String> },
}

impl BoundSecretsRefusal {
    /// The stable code: the environment's `error_code` when its create ends.
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::HostReserved { .. } => BOUND_HOST_RESERVED_ERROR_CODE,
            Self::HostConflict { .. } => BOUND_HOST_CONFLICT_ERROR_CODE,
            Self::TooManyHosts { .. } => TOO_MANY_BOUND_HOSTS_ERROR_CODE,
        }
    }
}

/// Whether `credential`, one of the hosts the selected credentials bind,
/// covers `host`: its exact name, or any name under a suffix route, all of
/// which the egress broker hands to the front door.
fn covers(credential: &Intercept, host: &str) -> bool {
    let name = credential.binding.hostname();
    if credential.suffix {
        host.strip_suffix(name)
            .is_some_and(|label| label.len() > 1 && label.ends_with('.'))
    } else {
        host == name
    }
}

/// Every host `secrets` bind, once the union with `credentials`, the hosts
/// the selected credentials bind, holds: none of the deployment's own names
/// (`reserved`, which may have grown since a secret was bound), no host named
/// twice, and at most [`MAX_BOUND_HOSTS_PER_ENVIRONMENT`] of them.
pub(crate) fn bound_hosts(
    secrets: &[FirstBindSecret],
    credentials: &[Intercept],
    reserved: &ReservedHosts,
) -> Result<BTreeSet<String>, BoundSecretsRefusal> {
    let mut named: BTreeMap<&str, &str> = BTreeMap::new();
    for secret in secrets {
        for host in &secret.hosts {
            if let Err(BindingError::DeploymentHost(_)) = BoundHost::parse(host, reserved) {
                return Err(BoundSecretsRefusal::HostReserved {
                    host: host.clone(),
                    key: secret.key.clone(),
                });
            }
            let conflict = |other: &str| BoundSecretsRefusal::HostConflict {
                host: host.clone(),
                first: other.to_owned(),
                second: secret.key.clone(),
            };
            if credentials
                .iter()
                .any(|credential| covers(credential, host))
            {
                return Err(conflict(SELECTED_CREDENTIAL));
            }
            if let Some(other) = named.insert(host, &secret.key) {
                return Err(conflict(other));
            }
        }
    }
    if named.len() > MAX_BOUND_HOSTS_PER_ENVIRONMENT {
        return Err(BoundSecretsRefusal::TooManyHosts {
            count: named.len(),
            keys: secrets.iter().map(|secret| secret.key.clone()).collect(),
        });
    }
    Ok(named.into_keys().map(str::to_owned).collect())
}

/// One tenant secret of a selected source, without its value.
#[derive(sqlx::FromRow)]
struct SecretRow {
    path: String,
    key: String,
    /// The binding as text; `None` for a plain secret.
    binding: Option<String>,
    binding_id: Option<Uuid>,
    binding_generation: i64,
}

/// Each bound secret the selection `environment_id`'s binding captured
/// (`digest`) projects, in key order: of every key its sources hold, the
/// one the projection takes (a later source overrides an earlier one, and a
/// key the environment sets itself is no secret's), when that one is bound.
///
/// Only a binding with no digest, which selects no sources and projects
/// nothing, records none. A digest that doesn't read, or one the
/// environment's selection no longer reproduces, is unavailable: its sources
/// can't be read, and recording none in their place would let a secret
/// bound now be projected raw once it is made plain. A bound row that
/// doesn't read back is a broken store.
pub(crate) async fn selected(
    pool: &PgPool,
    environment_id: &str,
    digest: Option<&str>,
) -> Result<Vec<FirstBindSecret>, BindingStoreUnavailable> {
    let Some(digest) = digest else {
        return Ok(Vec::new());
    };
    let unreadable = |why: &'static str| {
        tracing::warn!(
            environment_id,
            reason = why,
            "first-bind secret selection unreadable"
        );
        BindingStoreUnavailable
    };
    let digest = digest_bytes(digest).ok_or_else(|| unreadable("digest_malformed"))?;
    let environment = crate::worker::env_data::load_environment(pool, environment_id)
        .await
        .map_err(|error| {
            tracing::warn!(%error, environment_id, "first-bind secret selection read failed");
            BindingStoreUnavailable
        })?;
    let bound = match environment.projection_selection {
        Ok(Some(selection)) => selection.bound_to(&digest).ok().flatten(),
        Ok(None) | Err(_) => None,
    };
    let (_, selection) = bound.ok_or_else(|| unreadable("digest_not_reproduced"))?;
    let paths: Vec<String> = selection
        .source_identities()
        .into_iter()
        .map(|(_, path)| path)
        .collect();
    let rows: Vec<SecretRow> = sqlx::query_as(
        "SELECT path, key, binding::text AS binding, binding_id, binding_generation \
           FROM tenant_secrets WHERE path = ANY($1)",
    )
    .bind(&paths)
    .fetch_all(pool)
    .await
    .map_err(|error| {
        tracing::warn!(%error, environment_id, "first-bind secret read failed");
        BindingStoreUnavailable
    })?;
    let mut winners: BTreeMap<&str, &SecretRow> = BTreeMap::new();
    for path in &paths {
        for row in rows.iter().filter(|row| &row.path == path) {
            winners.insert(&row.key, row);
        }
    }
    winners.retain(|key, _| !selection.ordinary_keys.contains(*key));
    winners
        .into_values()
        .filter_map(|row| row.binding.as_deref().map(|binding| (row, binding)))
        .map(|(row, binding)| recorded(row, binding))
        .collect()
}

fn recorded(row: &SecretRow, binding: &str) -> Result<FirstBindSecret, BindingStoreUnavailable> {
    let broken = || {
        tracing::warn!(key = %row.key, "a bound secret's binding doesn't read back");
        BindingStoreUnavailable
    };
    let stored: StoredBinding = serde_json::from_str(binding).map_err(|_| broken())?;
    // Read back under no deployment names, as every stored binding is; the
    // provider hosts are refused by the parse itself.
    let parsed = stored
        .parse(&ReservedHosts::default())
        .map_err(|_| broken())?;
    Ok(FirstBindSecret {
        path: row.path.clone(),
        key: row.key.clone(),
        binding_id: row.binding_id.ok_or_else(broken)?.to_string(),
        binding_generation: u64::try_from(row.binding_generation).map_err(|_| broken())?,
        prefix: parsed.prefix().map(|prefix| prefix.as_str().to_owned()),
        hosts: parsed.hosts().map(ToString::to_string).collect(),
    })
}

fn digest_bytes(digest: &str) -> Option<[u8; 32]> {
    if digest.len() != 64 {
        return None;
    }
    let mut bytes = [0; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(digest.get(index * 2..index * 2 + 2)?, 16).ok()?;
    }
    Some(bytes)
}

#[cfg(test)]
#[path = "bound_secrets/database_tests.rs"]
mod database_tests;
#[cfg(test)]
#[path = "bound_secrets/tests.rs"]
mod tests;
