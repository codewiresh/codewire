//! A local VM's platform bound secrets under its owner's delegation (#4003;
//! docs/dev/SECRETS-AND-CREDENTIALS.md, "A local VM's platform sources"):
//! the boot's record, read once before it starts, and, for an epoch whose
//! Open carried that record sealed, its grants and each lease's reread.

use std::time::Instant;

use codewire_access::{FirstBindSecret, PlatformBootSecret};
use codewire_credential_broker::platform::PlatformRuntimeError as Error;

use super::{OwnerLocalRuntimeAuthority, OwnerLocalSource};
use crate::bound_lease::{LeaseBounds, LeaseSource, selected_grants};
use crate::projection::boot_record_in;

impl OwnerLocalRuntimeAuthority {
    /// What the boot of this authority's selection records of its platform
    /// sources: read once, in one transaction under the admission's locks,
    /// and refused unless the authority is still the one first admitted.
    pub(crate) async fn boot_record(&self) -> Result<Vec<PlatformBootSecret>, Error> {
        let source = &self.source;
        source.ensure_live()?;
        let deadline = source.deadline.min(
            Instant::now()
                .checked_add(source.admission_timeout)
                .ok_or(Error::Denied)?,
        );
        let read = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), async {
            let mut tx = source.pool.begin().await.map_err(|_| Error::Unavailable)?;
            let admission = source.admit_in(&mut tx).await?;
            if admission.effective(&self.initial).is_none() {
                return Err(Error::Denied);
            }
            let record = boot_record_in(&mut tx, &source.selection.platform).await?;
            tx.commit().await.map_err(|_| Error::Unavailable)?;
            Ok(record)
        })
        .await;
        let record = match read {
            Ok(record) => record?,
            Err(_) => {
                source.ensure_live()?;
                return Err(Error::Unavailable);
            }
        };
        source.ensure_live()?;
        Ok(record)
    }

    /// The epoch's bound-secret grants: the bound entries of the boot's
    /// verified record, under the selection the epoch was admitted with. An
    /// Open that carried no record has none.
    pub(super) async fn boot_grants(&self) -> Result<Vec<FirstBindSecret>, Error> {
        use codewire_credential_broker::platform::PlatformRuntimeAuthority as _;
        self.current_session().await?;
        let selection = &self.source.selection;
        let Some(record) = &selection.boot_record else {
            return Ok(Vec::new());
        };
        Ok(selected_grants(
            record
                .secrets()
                .iter()
                .filter_map(PlatformBootSecret::first_bind),
            &selection.platform,
        ))
    }
}

impl OwnerLocalSource {
    /// Where this delegation's leases read.
    pub(super) fn lease_source(&self) -> LeaseSource<'_> {
        LeaseSource {
            pool: &self.pool,
            provider: self.provider.as_ref(),
            selection: &self.selection.platform,
            bounds: self,
        }
    }
}

/// Each read within one admission's bound, and never past the epoch's own
/// deadline.
impl LeaseBounds for OwnerLocalSource {
    fn ensure_live(&self) -> Result<(), Error> {
        OwnerLocalSource::ensure_live(self)
    }

    fn read_deadline(&self) -> Result<tokio::time::Instant, Error> {
        let deadline = self.deadline.min(
            Instant::now()
                .checked_add(self.admission_timeout)
                .ok_or(Error::Denied)?,
        );
        Ok(tokio::time::Instant::from_std(deadline))
    }
}
