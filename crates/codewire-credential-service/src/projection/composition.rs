//! Mixed native/platform projection planning. Caller inventories are only
//! names; this module derives a complete shared plan before reading material.

use std::collections::BTreeMap;

use codewire_daemon_proto::codewire::bridge::v1;
use codewire_daemon_proto::projection::{decode_local_inventories, encode_platform_inventories};
use codewire_project::PlatformProjectionSelection;
use codewire_workload_secrets::{
    ProjectionCompositionPlan, ProjectionContext, ProjectionContributor, ProjectionSourceInventory,
};
use sqlx::{Postgres, Transaction};

use super::{Capture, Error, KeyRow, capture_inventories_in, capture_winners_in, source_for_path};

#[derive(PartialEq, Eq)]
pub(crate) struct CompositionCapture {
    pub(crate) captured: Capture,
    pub(crate) platform_inventories: Vec<ProjectionSourceInventory>,
    pub(crate) plan: ProjectionCompositionPlan,
}

pub(crate) fn decode_local(
    inventories: &[v1::EnvironmentProjectionInventory],
) -> Result<Vec<ProjectionSourceInventory>, Error> {
    decode_local_inventories(inventories).map_err(|_| Error::Denied)
}

pub(crate) fn encode_platform(
    inventories: &[ProjectionSourceInventory],
) -> Result<Vec<v1::EnvironmentProjectionInventory>, Error> {
    encode_platform_inventories(inventories).map_err(|_| Error::Denied)
}

pub(crate) async fn capture_in(
    tx: &mut Transaction<'_, Postgres>,
    selection: &PlatformProjectionSelection,
    local_inventories: &[ProjectionSourceInventory],
    context: &ProjectionContext,
    request_id: [u8; 16],
    recipient: [u8; 32],
    now_unix_ms: u64,
) -> Result<CompositionCapture, Error> {
    let inventories = capture_inventories_in(tx, selection).await?;
    let platform_inventories = platform_inventories(&inventories)?;
    let plan = plan(
        selection,
        local_inventories,
        &platform_inventories,
        context,
        request_id,
        recipient,
        now_unix_ms,
    )?;
    let winner_paths = winner_paths(
        &inventories,
        plan.winning_keys(ProjectionContributor::Platform),
    )?;
    let captured = capture_winners_in(tx, inventories, winner_paths).await?;
    Ok(CompositionCapture {
        captured,
        platform_inventories,
        plan,
    })
}

fn plan(
    selection: &PlatformProjectionSelection,
    local_inventories: &[ProjectionSourceInventory],
    platform_inventories: &[ProjectionSourceInventory],
    context: &ProjectionContext,
    request_id: [u8; 16],
    recipient: [u8; 32],
    now_unix_ms: u64,
) -> Result<ProjectionCompositionPlan, Error> {
    let mut all = local_inventories.to_vec();
    all.extend(platform_inventories.iter().cloned());
    all.sort_by_key(|inventory| inventory.source);
    ProjectionCompositionPlan::new(
        context,
        request_id,
        recipient,
        &all,
        &selection.ordinary_keys,
        &selection.reserved_keys,
        now_unix_ms,
    )
    .map_err(|_| Error::Denied)
}

fn platform_inventories(
    inventories: &[(String, Vec<KeyRow>)],
) -> Result<Vec<ProjectionSourceInventory>, Error> {
    inventories
        .iter()
        .map(|(path, rows)| {
            Ok(ProjectionSourceInventory {
                contributor: ProjectionContributor::Platform,
                source: source_for_path(path)?,
                source_identity: path.clone(),
                keys: rows.iter().map(|row| row.key.clone()).collect(),
            })
        })
        .collect()
}

fn winner_paths(
    inventories: &[(String, Vec<KeyRow>)],
    winning_keys: &std::collections::BTreeSet<String>,
) -> Result<BTreeMap<String, String>, Error> {
    let mut paths = BTreeMap::new();
    for (path, rows) in inventories {
        for row in rows {
            if winning_keys.contains(&row.key) {
                // Inventories are canonical low-to-high source rank, so a
                // higher selected platform source replaces a lower one.
                paths.insert(row.key.clone(), path.clone());
            }
        }
    }
    if paths.len() != winning_keys.len() {
        return Err(Error::Denied);
    }
    Ok(paths)
}

#[cfg(test)]
mod tests;
