//! What a local VM's boot records of its platform sources (#4003;
//! docs/dev/SECRETS-AND-CREDENTIALS.md, "A local VM's platform sources"):
//! every platform secret the projection would take, bound or plain, with
//! its generation, and a bound one's `binding_id`, prefix and hosts. It is
//! read as the projection reads its winners, in the caller's authority
//! transaction, and no ciphertext is selected.

use codewire_access::{PlatformBootBinding, PlatformBootSecret, ReservedHosts, StoredBinding};
use codewire_project::PlatformProjectionSelection;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use super::{Error, capture_inventories_in, selected_winners};

#[derive(sqlx::FromRow)]
struct BindingRow {
    binding: Option<String>,
    binding_id: Option<Uuid>,
    binding_generation: i64,
}

const BINDING_QUERY: &str = "SELECT binding::text AS binding,binding_id,binding_generation \
     FROM public.tenant_secrets WHERE path=$1 AND key=$2";

/// The boot's record of `selection`'s platform sources, read in `tx`, which
/// holds the caller's identity, owner and source locks. A bound row whose
/// binding doesn't read back is a corrupt record and refuses the read.
pub(crate) async fn boot_record_in(
    tx: &mut Transaction<'_, Postgres>,
    selection: &PlatformProjectionSelection,
) -> Result<Vec<PlatformBootSecret>, Error> {
    let inventories = capture_inventories_in(tx, selection).await?;
    let winners = selected_winners(&inventories, selection)?;
    let mut recorded = Vec::with_capacity(winners.len());
    for (key, path) in winners {
        let row: BindingRow = sqlx::query_as(BINDING_QUERY)
            .bind(&path)
            .bind(&key)
            .fetch_optional(&mut **tx)
            .await
            .map_err(|_| Error::Unavailable)?
            .ok_or(Error::Denied)?;
        let binding_generation =
            u64::try_from(row.binding_generation).map_err(|_| Error::Denied)?;
        let bound = match &row.binding {
            None => None,
            Some(binding) => Some(bound_entry(binding, row.binding_id)?),
        };
        recorded.push(PlatformBootSecret {
            path,
            key,
            binding_generation,
            bound,
        });
    }
    Ok(recorded)
}

fn bound_entry(binding: &str, binding_id: Option<Uuid>) -> Result<PlatformBootBinding, Error> {
    let stored: StoredBinding = serde_json::from_str(binding).map_err(|_| Error::Denied)?;
    // As at projection: the deployment's names were checked at bind, and
    // are checked again by the boot that binds these hosts.
    let parsed = stored
        .parse(&ReservedHosts::default())
        .map_err(|_| Error::Denied)?;
    let mut hosts: Vec<String> = parsed
        .hosts()
        .map(|host| host.as_str().to_owned())
        .collect();
    hosts.sort_unstable();
    Ok(PlatformBootBinding {
        binding_id: binding_id.ok_or(Error::Denied)?.to_string(),
        prefix: parsed.prefix().map(|prefix| prefix.as_str().to_owned()),
        hosts,
    })
}
