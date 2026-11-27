//! The bound-profile read: an environment's binding, the revision it names
//! and that revision's entries, under the locks grant evaluation takes.

use super::*;

/// The binding read, then `profile_for_context` of the bound revision, and,
/// for runtime authority's owner (`$4` kind, `$5` id), `get_revision` of it,
/// in one statement. It runs after `ENVIRONMENT_FENCE`, so the binding is read
/// in a snapshot taken after binding writers were fenced, as before.
///
/// Every call is ordered by a LATERAL argument and gated by NULL on the SQL
/// result before it, as in `ENVIRONMENT_FENCE`. The first profile lock is the
/// only lock that can wait: the second re-locks that same row with its own
/// owner, and the owner and profile locks for `$4`/`$5` re-lock rows this
/// transaction already holds. The revision and entries are read in the
/// statement's snapshot. That is the same data: a binding names its revision
/// through a RESTRICT foreign key, so the revision exists in any snapshot
/// where the binding does, and a revision and its entries are never changed
/// after they are inserted.
///
/// Residual difference, which fails closed: the binding row's values are
/// validated in Rust (`binding_metadata`: profile ID, positive revision,
/// confirming owner ID), after this statement returns, where the separate code
/// validated them before it locked the profile. A binding row that fails that
/// validation now has its profile SHARE-locked first, and the statement may
/// wait for a profile writer within its `statement_timeout`, turning that
/// CorruptRecord (Denied) into DatabaseUnavailable (Unavailable). The same
/// holds for the profile's owner IDs, name and entries, which are parsed after
/// the re-locks; those take no new lock. Every such value is constrained by
/// the schema or written only by validated code.
const BOUND_PROFILE: &str = "SELECT b.profile_id, b.profile_revision, b.personal_owner_confirmed_by, \
    p.found AS profile_found, p.user_id AS profile_user, p.organization_id AS profile_organization, \
    q.found AS revision_profile_found, q.name AS profile_name, \
    q.current_revision AS profile_current_revision, \
    r.revision_exists, r.slots, r.credentials, \
    o.found AS owner_found, s.found AS owner_profile_found, s.name AS owner_profile_name, \
    s.current_revision AS owner_profile_current_revision \
    FROM public.platform_environment_access_bindings AS b \
    LEFT JOIN LATERAL (SELECT true AS found, f.* FROM public.codewire_platform_lock_profile( \
        b.profile_id, $2::text, $3::text) AS f LIMIT 1) AS p ON true \
    LEFT JOIN LATERAL (SELECT true AS found, f.* FROM public.codewire_platform_lock_profile( \
        CASE WHEN p.found AND (p.user_id IS NULL) <> (p.organization_id IS NULL) \
             THEN b.profile_id END, p.user_id, p.organization_id) AS f LIMIT 1) AS q ON true \
    LEFT JOIN LATERAL (SELECT EXISTS (SELECT 1 FROM public.platform_access_profile_revisions AS v \
            WHERE v.profile_id=b.profile_id AND v.revision=b.profile_revision) AS revision_exists, \
        n.slots, n.credentials \
        FROM (SELECT coalesce(array_agg(e.capability_slot ORDER BY e.capability_slot), '{}') AS slots, \
            coalesce(array_agg(e.credential_id ORDER BY e.capability_slot), '{}') AS credentials \
            FROM public.platform_access_profile_entries AS e \
            WHERE e.profile_id=b.profile_id AND e.revision=b.profile_revision) AS n \
        WHERE q.found) AS r ON true \
    LEFT JOIN LATERAL public.codewire_platform_lock_owner( \
        $4::text, CASE WHEN r.revision_exists THEN $5::text END) AS o(found) ON true \
    LEFT JOIN LATERAL (SELECT true AS found, f.* FROM public.codewire_platform_lock_profile( \
        CASE WHEN o.found THEN b.profile_id END, \
        CASE WHEN $4::text = 'user' THEN $5::text END, \
        CASE WHEN $4::text = 'organization' THEN $5::text END) AS f LIMIT 1) AS s ON true \
    WHERE b.environment_id=$1::text";

#[derive(sqlx::FromRow)]
struct BoundProfileRow {
    profile_id: String,
    profile_revision: i64,
    personal_owner_confirmed_by: Option<String>,
    profile_found: Option<bool>,
    profile_user: Option<String>,
    profile_organization: Option<String>,
    revision_profile_found: Option<bool>,
    profile_name: Option<String>,
    profile_current_revision: Option<i64>,
    revision_exists: Option<bool>,
    slots: Option<Vec<String>>,
    credentials: Option<Vec<String>>,
    owner_found: Option<bool>,
    owner_profile_found: Option<bool>,
    owner_profile_name: Option<String>,
    owner_profile_current_revision: Option<i64>,
}

pub(super) struct BoundProfile {
    pub(super) binding: PlatformBindingMetadata,
    /// `profile_for_context` of the bound revision.
    pub(super) profile: AccessProfile,
    /// `get_revision` of the bound revision for the requested owner.
    pub(super) owner_revision: Option<Result<AccessProfile, Error>>,
}

/// The binding read, then `profile_for_context`, with their errors in their
/// order; `None` when the environment has no binding.
pub(super) async fn load_bound_profile(
    tx: &mut Transaction<'_, Postgres>,
    context: &GrantContext,
    owner: Option<&Owner>,
) -> Result<Option<BoundProfile>, Error> {
    let (owner_kind, owner_id) = match owner {
        Some(Owner::User(id)) => (Some("user"), Some(id.as_str())),
        Some(Owner::Organization(id)) => (Some("organization"), Some(id.as_str())),
        None => (None, None),
    };
    let Some(row): Option<BoundProfileRow> = sqlx::query_as(BOUND_PROFILE)
        .bind(context.environment_id.as_str())
        .bind(context.user_id.as_str())
        .bind(context.organization_id.as_ref().map(OwnerId::as_str))
        .bind(owner_kind)
        .bind(owner_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(database_error)?
    else {
        return Ok(None);
    };
    let binding = binding_metadata(
        context,
        row.profile_id,
        row.profile_revision,
        row.personal_owner_confirmed_by,
    )?;
    if row.profile_found != Some(true) {
        return Err(Error::NotFound);
    }
    let profile_owner = match (row.profile_user, row.profile_organization) {
        (Some(user), None) => Owner::User(OwnerId::parse(user).map_err(|_| Error::CorruptRecord)?),
        (None, Some(org)) => {
            Owner::Organization(OwnerId::parse(org).map_err(|_| Error::CorruptRecord)?)
        }
        _ => return Err(Error::CorruptRecord),
    };
    let revision = PinnedRevision {
        binding: &binding.binding,
        exists: row.revision_exists,
        slots: row.slots.unwrap_or_default(),
        credentials: row.credentials.unwrap_or_default(),
    };
    let profile = revision.profile(
        &profile_owner,
        row.revision_profile_found,
        row.profile_name,
        row.profile_current_revision,
    )?;
    let owner_revision = owner.map(|owner| {
        // `get_revision` checks the revision before it opens its transaction.
        generation(binding.binding.profile_revision)?;
        if row.owner_found != Some(true) {
            return Err(Error::NotFound);
        }
        revision.profile(
            owner,
            row.owner_profile_found,
            row.owner_profile_name,
            row.owner_profile_current_revision,
        )
    });
    Ok(Some(BoundProfile {
        binding,
        profile,
        owner_revision,
    }))
}

/// One bound revision as `load_profile` reads it after its profile lock.
struct PinnedRevision<'a> {
    binding: &'a EnvironmentAccessBinding,
    exists: Option<bool>,
    slots: Vec<String>,
    credentials: Vec<String>,
}

impl PinnedRevision<'_> {
    /// `load_profile(owner, id, Some(revision))` from its profile lock's row,
    /// with its checks in its order.
    fn profile(
        &self,
        owner: &Owner,
        found: Option<bool>,
        name: Option<String>,
        current_revision: Option<i64>,
    ) -> Result<AccessProfile, Error> {
        if found != Some(true) {
            return Err(Error::NotFound);
        }
        let current = current_revision.ok_or(Error::DatabaseUnavailable)?;
        positive(current)?;
        let revision = self.binding.profile_revision;
        generation(revision)?;
        if self.exists != Some(true) {
            return Err(Error::NotFound);
        }
        // Both arrays aggregate the same scan of entries, each ordered by
        // capability slot, which the primary key makes unique per revision,
        // so the Nth slot and the Nth credential come from the same entry.
        if self.slots.len() != self.credentials.len() {
            return Err(Error::DatabaseUnavailable);
        }
        let mut entries = BTreeMap::new();
        for (slot, credential) in self.slots.iter().zip(&self.credentials) {
            entries.insert(
                CapabilitySlot::parse(slot.as_str()).map_err(|_| Error::CorruptRecord)?,
                CredentialId::parse(credential.as_str()).map_err(|_| Error::CorruptRecord)?,
            );
        }
        Ok(AccessProfile {
            id: self.binding.profile_id.clone(),
            placement: Placement::Platform,
            owner: owner.clone(),
            name: AccessProfileName::parse(name.ok_or(Error::DatabaseUnavailable)?)
                .map_err(|_| Error::CorruptRecord)?,
            revision,
            entries,
        })
    }
}
