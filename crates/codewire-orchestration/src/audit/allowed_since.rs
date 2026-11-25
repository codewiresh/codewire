//! `allowed_since_revision` (SPEC "The API read"): a refusal under an older
//! revision of the environment's selected policy that its current revision
//! allows carries the first revision that allowed it, so a reader offers no
//! step for something already allowed.

use std::collections::HashMap;

use codewire_egress_policy::typed::TypedPolicy;
use codewire_egress_policy::{CompiledPolicy, PolicyDocument};
use codewire_server_core::AppResult;
use sqlx::PgPool;

use super::event::{Protocol, Refusal};

/// Revisions compiled per read, back from the current one; a refusal older
/// than that reads as allowed since the oldest of them that allows it.
const MAX_REVISIONS: u32 = 100;
/// A name refused at DNS is allowed when a rule lets it be dialed on 443,
/// the port `cw --cloud policy allow NAME` always opens.
const NAME_PORT: u16 = 443;

/// The selected stored policy: its id and current revision.
pub struct Selected {
    pub id: String,
    pub name: String,
    pub current: u32,
}

/// What a revision is asked: a name and a port.
fn question(refusal: &Refusal) -> Option<(&str, u16)> {
    let name = refusal.destination.as_deref()?;
    if name.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    match refusal.protocol {
        Protocol::Tcp => Some((name, refusal.port?)),
        Protocol::Dns => Some((name, NAME_PORT)),
        Protocol::Udp => None,
    }
}

/// For each refusal by id, the first revision after the one it was refused
/// under that allows it, when the current revision does.
pub async fn allowed_since(
    pool: &PgPool,
    selected: &Selected,
    refusals: &[(&str, &Refusal)],
) -> AppResult<HashMap<String, u32>> {
    let older: Vec<(&str, &Refusal, u32)> = refusals
        .iter()
        .filter_map(|(id, refusal)| {
            let revision = refusal.revision?;
            (refusal.policy.as_deref() == Some(selected.name.as_str())
                && revision < selected.current
                && question(refusal).is_some())
            .then_some((*id, *refusal, revision))
        })
        .collect();
    let Some(oldest) = older.iter().map(|(_, _, revision)| *revision).min() else {
        return Ok(HashMap::new());
    };
    let from = (oldest + 1).max(selected.current.saturating_sub(MAX_REVISIONS - 1));
    let rows: Vec<(i32, Vec<u8>)> = sqlx::query_as(
        "SELECT revision, document FROM platform_network_policy_revisions \
         WHERE policy_id = $1 AND revision BETWEEN $2 AND $3 ORDER BY revision",
    )
    .bind(&selected.id)
    .bind(i32::try_from(from).unwrap_or(i32::MAX))
    .bind(i32::try_from(selected.current).unwrap_or(i32::MAX))
    .fetch_all(pool)
    .await?;
    let compiled: Vec<(u32, CompiledPolicy)> = rows
        .into_iter()
        .filter_map(|(revision, document)| {
            let document: PolicyDocument = serde_json::from_slice(&document).ok()?;
            let policy = TypedPolicy::from_document(&document).ok()?;
            Some((u32::try_from(revision).ok()?, policy.compile()))
        })
        .collect();
    let allows = |policy: &CompiledPolicy, refusal: &Refusal| {
        question(refusal)
            .is_some_and(|(name, port)| policy.allows_by_rule(name, port, None).unwrap_or(false))
    };
    let Some((_, current)) = compiled
        .last()
        .filter(|(revision, _)| *revision == selected.current)
    else {
        return Ok(HashMap::new());
    };
    Ok(older
        .into_iter()
        .filter(|(_, refusal, _)| allows(current, refusal))
        .filter_map(|(id, refusal, revision)| {
            compiled
                .iter()
                .find(|(candidate, policy)| *candidate > revision && allows(policy, refusal))
                .map(|(candidate, _)| (id.to_owned(), *candidate))
        })
        .collect())
}
