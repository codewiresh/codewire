//! One-statement, material-free launch selection capture. Validation failure is
//! retained on EnvironmentRow, never a new obstacle to stop/destroy cleanup.

use std::collections::BTreeSet;

use codewire_project::{
    PlatformProjectionSelection, PlatformProjectionSelectionError as Error, ProjectSpec,
    platform_projection_reserved_keys,
};

// ProjectSpec, its binding and the pinned revision's slots share one PostgreSQL
// statement snapshot. GitHub is the creator's one account connection. Every
// personal profile reserves GitHub's names, which the selection digest binds.
// The managed GitHub client is selected only while the creator has an active
// connection, so a missing one is omitted, never fabricated: for a personal
// profile, or with no profile when the project selects a GitHub repository.
// The rendered Pod records that choice; launch authority resolves the
// connection itself. Do not replace this with independent reads or a lookup of
// the profile's current_revision/name. Slot allocation is capped at 64; a
// separate bounded existence probe rejects, rather than truncates, excess rows.
// The pinned revision's Anthropic entry also fixes its client form: a Claude
// subscription token (the provider's OAuth kind) or a Claude sign-in selects
// Claude Code's subscription mode, in which the broker injects the stored
// token. A credential's kind never changes, so this is as immutable as the
// revision's slots; it is client configuration, not authority.
pub(super) const ENVIRONMENT_QUERY: &str = r#"
    SELECT e.id, e.org_id, e.preset_id, e.type, e.state, e.desired_state,
           e.external_cleanup_completed_at,
           e.state IN ('pending', 'creating') AND e.retry_count = 0
               AND e.started_at IS NULL AND e.stopped_at IS NULL AS never_ran,
           e.cpu_millicores, e.memory_mb, e.disk_gb, e.source_snapshot_id,
           e.isolation_tier, e.ttl_seconds,
           e.project_spec, e.created_by, e.environment_operation_generation,
           (SELECT o.dedicated_cpu FROM organizations AS o WHERE o.id = e.org_id) AS dedicated_cpu,
           b.profile_id, b.profile_revision,
           r.profile_id IS NOT NULL AS profile_revision_exists,
           ARRAY(
               SELECT selected.slot FROM (
                   SELECT entry.capability_slot AS slot
                   FROM platform_access_profile_entries AS entry
                   WHERE entry.profile_id = b.profile_id AND entry.revision = b.profile_revision
                   UNION ALL
                   SELECT 'github' WHERE p.user_id IS NOT NULL
               ) AS selected
               ORDER BY selected.slot LIMIT 64
           ) AS profile_slots,
           EXISTS(
               SELECT 1 FROM (
                   SELECT entry.capability_slot
                   FROM platform_access_profile_entries AS entry
                   WHERE entry.profile_id = b.profile_id AND entry.revision = b.profile_revision
                   UNION ALL
                   SELECT 'github' WHERE p.user_id IS NOT NULL
               ) AS selected
               OFFSET 64 LIMIT 1
           ) AS profile_slots_overflow,
           EXISTS(
               SELECT 1
               FROM platform_access_profile_entries AS entry
               JOIN platform_credentials AS c ON c.id = entry.credential_id
               WHERE entry.profile_id = b.profile_id AND entry.revision = b.profile_revision
                 AND entry.capability_slot = 'anthropic'
                 AND c.provider = 'anthropic'
                 AND c.authentication_kind = 'oauth'
           ) AS anthropic_subscription_token,
           EXISTS(
               SELECT 1
               FROM platform_access_profile_entries AS entry
               JOIN platform_credentials AS c ON c.id = entry.credential_id
               WHERE entry.profile_id = b.profile_id AND entry.revision = b.profile_revision
                 AND entry.capability_slot = 'anthropic'
                 AND c.provider = 'anthropic'
                 AND c.authentication_kind = 'claude_sign_in'
           ) AS anthropic_sign_in,
           (p.user_id IS NOT NULL OR b.environment_id IS NULL) AND EXISTS(
               SELECT 1 FROM platform_credentials AS c
               WHERE c.user_id = e.created_by AND c.organization_id IS NULL
                 AND c.provider = 'github' AND c.authentication_kind = 'oauth'
                 AND c.status = 'active'
                 AND (c.expires_at_unix IS NULL
                      OR c.expires_at_unix > extract(epoch FROM clock_timestamp()))
           ) AS github_connected
    FROM environments AS e
    LEFT JOIN platform_environment_access_bindings AS b ON b.environment_id = e.id
    LEFT JOIN platform_access_profile_revisions AS r
        ON r.profile_id = b.profile_id AND r.revision = b.profile_revision
    LEFT JOIN platform_access_profiles AS p ON p.id = r.profile_id
    WHERE e.id = $1
"#;

pub(super) struct ProjectionCapture {
    pub creator: Option<String>,
    pub profile_id: Option<String>,
    pub profile_revision: Option<i64>,
    pub profile_revision_exists: bool,
    pub profile_slots: Vec<String>,
    pub profile_slots_overflow: bool,
    pub github_connected: bool,
    /// The pinned revision's Anthropic slot holds a Claude subscription token.
    pub anthropic_subscription_token: bool,
    /// The pinned revision's Anthropic slot holds a Claude sign-in.
    pub anthropic_sign_in: bool,
}

impl ProjectionCapture {
    pub(super) fn managed_credential_clients(
        &self,
        project: &ProjectSpec,
    ) -> Result<codewire_access::ManagedCredentialClients, Error> {
        let clients = codewire_access::ManagedCredentialClients::from_profile_slots(
            self.profile_slots
                .iter()
                .map(String::as_str)
                .filter(|slot| *slot != "github" || self.github_connected)
                .chain(self.account_github(project).then_some("github")),
        )
        .map_err(|_| Error)?;
        let clients = match (self.anthropic_subscription_token, self.anthropic_sign_in) {
            (false, false) => clients,
            (true, false) => clients
                .with_anthropic_subscription_token()
                .map_err(|_| Error)?,
            (false, true) => clients.with_anthropic_sign_in().map_err(|_| Error)?,
            // One slot holds one credential.
            (true, true) => return Err(Error),
        };
        clients
            .check_collisions(project.environment.keys().map(String::as_str))
            .map_err(|_| Error)?;
        Ok(clients)
    }

    /// Selecting a GitHub repository needs no profile: without one, the
    /// creator's active connection is the environment's GitHub client.
    fn account_github(&self, project: &ProjectSpec) -> bool {
        self.profile_id.is_none()
            && self.github_connected
            && project.repositories.iter().any(|repository| {
                url::Url::parse(&repository.source).is_ok_and(|url| {
                    url.scheme() == "https"
                        && url.host_str().is_some_and(|host| {
                            host.trim_end_matches('.')
                                .eq_ignore_ascii_case("github.com")
                        })
                })
            })
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
                if revision > 0 && self.profile_revision_exists =>
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
        // Without a profile or secrets, a selection exists only to carry the
        // creator's GitHub client, decided once here at capture.
        if project.secrets.is_empty() && selected.profile.is_none() && !self.account_github(project)
        {
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
