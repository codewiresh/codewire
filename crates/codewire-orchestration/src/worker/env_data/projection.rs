//! One-statement, material-free launch selection capture. Validation failure is
//! retained on EnvironmentRow, never a new obstacle to stop/destroy cleanup.

use std::collections::BTreeSet;

use codewire_project::{
    PlatformProjectionSelection, PlatformProjectionSelectionError as Error, ProjectSpec,
    platform_projection_reserved_keys,
};

// ProjectSpec, its binding and the pinned revision's slots share one PostgreSQL
// statement snapshot. Do not replace this with independent reads or a lookup of
// the profile's current_revision/name. Slot allocation is capped at 64; a
// separate bounded existence probe rejects, rather than truncates, excess rows.
pub(super) const ENVIRONMENT_QUERY: &str = r#"
    SELECT e.id, e.org_id, e.preset_id, e.type, e.state, e.desired_state,
           e.external_cleanup_completed_at,
           e.cpu_millicores, e.memory_mb, e.disk_gb, e.isolation_tier, e.ttl_seconds,
           e.project_spec, e.created_by, e.environment_operation_generation,
           b.profile_id, b.profile_revision,
           r.profile_id IS NOT NULL AS profile_revision_exists,
           ARRAY(
               SELECT entry.capability_slot
               FROM platform_access_profile_entries AS entry
               WHERE entry.profile_id = b.profile_id AND entry.revision = b.profile_revision
               ORDER BY entry.capability_slot LIMIT 64
           ) AS profile_slots,
           EXISTS(
               SELECT 1 FROM platform_access_profile_entries AS entry
               WHERE entry.profile_id = b.profile_id AND entry.revision = b.profile_revision
               OFFSET 64 LIMIT 1
           ) AS profile_slots_overflow
    FROM environments AS e
    LEFT JOIN platform_environment_access_bindings AS b ON b.environment_id = e.id
    LEFT JOIN platform_access_profile_revisions AS r
        ON r.profile_id = b.profile_id AND r.revision = b.profile_revision
    WHERE e.id = $1
"#;

pub(super) struct ProjectionCapture {
    pub creator: Option<String>,
    pub profile_id: Option<String>,
    pub profile_revision: Option<i64>,
    pub profile_revision_exists: bool,
    pub profile_slots: Vec<String>,
    pub profile_slots_overflow: bool,
}

impl ProjectionCapture {
    pub(super) fn managed_credential_clients(
        &self,
        project: &ProjectSpec,
    ) -> Result<codewire_access::ManagedCredentialClients, Error> {
        let clients = codewire_access::ManagedCredentialClients::from_profile_slots(
            self.profile_slots.iter().map(String::as_str),
        )
        .map_err(|_| Error)?;
        clients
            .check_collisions(project.environment.keys().map(String::as_str))
            .map_err(|_| Error)?;
        Ok(clients)
    }

    pub(super) fn selection(
        &self,
        project: &ProjectSpec,
        organization: &str,
        operation_generation: i64,
    ) -> Result<Option<PlatformProjectionSelection>, Error> {
        if operation_generation <= 0
            || self.profile_slots_overflow
            || self.profile_slots.len() > 64
            || self.profile_slots.iter().collect::<BTreeSet<_>>().len() != self.profile_slots.len()
        {
            return Err(Error);
        }
        project.ensure_platform_compatible().map_err(|_| Error)?;
        // Declared ordinary routing inputs must not compete with the selected
        // machine clients. This examines names only, before any secret reads.
        self.managed_credential_clients(project)?;
        let profile = match (
            &project.credentials,
            &self.profile_id,
            self.profile_revision,
        ) {
            (None, None, None)
                if !self.profile_revision_exists && self.profile_slots.is_empty() =>
            {
                None
            }
            (Some(binding), Some(id), Some(revision))
                if revision > 0
                    && self.profile_revision_exists
                    && !self.profile_slots.is_empty() =>
            {
                if exact_platform_id(&binding.profile)? != *id {
                    return Err(Error);
                }
                Some((id.clone(), revision as u64))
            }
            _ => return Err(Error),
        };
        let selected = PlatformProjectionSelection {
            creator: self.creator.as_ref().ok_or(Error)?.clone(),
            organization: organization.to_owned(),
            organization_selected: project.secrets.organization,
            project_id: if project.secrets.project.is_empty() {
                None
            } else {
                Some(exact_platform_id(&project.secrets.project)?)
            },
            user_selected: project.secrets.user.is_some(),
            profile,
            ordinary_keys: project.environment.keys().cloned().collect(),
            reserved_keys: platform_projection_reserved_keys(
                self.profile_slots.iter().map(String::as_str),
            )?,
        };
        selected.validate()?;
        if project.secrets.is_empty() && selected.profile.is_none() {
            Ok(None)
        } else {
            Ok(Some(selected))
        }
    }
}

fn exact_platform_id(reference: &str) -> Result<String, Error> {
    let raw = reference.strip_prefix("platform:id:").ok_or(Error)?;
    let id = uuid::Uuid::parse_str(raw).map_err(|_| Error)?;
    if id.is_nil() || id.to_string() != raw {
        return Err(Error);
    }
    Ok(raw.to_owned())
}

#[cfg(test)]
mod tests;
