//! Metadata-only, transaction-composable environment source admission.
//!
//! The public operation composes the transaction with the existing organization
//! mutation lease and durable lifecycle recovery. No path reads protected values
//! or creates a second environment operation generation. Production selection
//! gates stay closed until delivery is composed.

use std::collections::BTreeSet;

use codewire_access::{
    AccessProfile, AccessProfileId, AccessProfileName, EnvironmentAccessBinding, EnvironmentId,
    GrantContext, GrantPlacement, Owner, OwnerId,
};
use codewire_platform_credentials::{PlatformAccessProfileStore, PlatformProfileError};
use codewire_project::{CredentialBinding, ProjectSpec, SecretBindings};
use codewire_server_core::auth::AuthUser;
use codewire_server_core::org_deletion::{
    OrganizationRuntimeMutationError, run_environment_runtime_mutation,
};
use codewire_server_core::{AppError, AppResult};
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Row, Transaction};

use super::ApiState;
use super::create::CreateEnvironmentBody;
use super::environments::{require_org_member, trigger_environment};
use crate::access_profiles::profile_error;

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentSourceSelection {
    #[serde(default)]
    pub secrets: SecretBindings,
    #[serde(default)]
    pub credentials: Option<CredentialBinding>,
    #[serde(default)]
    pub profile_revision: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateEnvironmentSourcesBody {
    pub expected_operation_generation: u64,
    pub expected: EnvironmentSourceSelection,
    pub replacement: EnvironmentSourceSelection,
    #[serde(default)]
    pub allow_restart: bool,
    #[serde(default)]
    pub confirm_personal_credentials: bool,
    #[serde(default)]
    pub confirm_personal_secrets: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct EnvironmentSourcesUpdate {
    pub environment_id: String,
    pub operation_generation: u64,
    pub selection: EnvironmentSourceSelection,
    pub outcome: EnvironmentSourcesUpdateOutcome,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EnvironmentSourcesUpdateOutcome {
    Unchanged,
    Stored,
    RestartRequired,
}

/// Admission is implemented independently of enabling runtime delivery. This
/// gate must be removed only with the real in-workspace launcher composition.
pub(crate) fn ensure_source_delivery_available() -> AppResult<()> {
    Err(AppError::Precondition(
        "environment source changes are not yet available for platform delivery".into(),
    ))
}

pub(crate) async fn update_environment_sources_core(
    state: &ApiState,
    user: &AuthUser,
    organization: &str,
    environment: &str,
    body: UpdateEnvironmentSourcesBody,
) -> AppResult<EnvironmentSourcesUpdate> {
    ensure_source_delivery_available()?;
    require_org_member(&state.pool, user, organization).await?;
    let profiles = PlatformAccessProfileStore::new(
        state.pool.clone(),
        codewire_access::builtin_provider_catalog(),
    );
    run_environment_runtime_mutation(&state.pool, organization, environment, async {
        let mut tx = profiles.begin_transaction().await.map_err(profile_error)?;
        let result = replace_environment_sources_in(
            &mut tx,
            &profiles,
            user,
            organization,
            environment,
            &body,
        )
        .await?;
        // A failed COMMIT acknowledgement is ambiguous: the canonical
        // selection and durable restart intention may already be visible.
        tx.commit()
            .await
            .map_err(|_| OrganizationRuntimeMutationError::ambiguous(unavailable()))?;
        if result.outcome == EnvironmentSourcesUpdateOutcome::RestartRequired {
            trigger_environment(state, environment, "restart_sources")
                .await
                .map_err(|_| OrganizationRuntimeMutationError::ambiguous(unavailable()))?;
        }
        // Signal failure never undoes (stopping, started). Existing startup and
        // stuck-environment reconciliation resumes that same durable intent.
        Ok(result)
    })
    .await
}

/// Acquire the global user -> organization lock order before inserting/locking
/// an environment. The organization UPDATE lock also composes confidential
/// capacity admission without a SHARE-to-UPDATE lock-upgrade deadlock.
pub(crate) async fn lock_source_owners_in(
    tx: &mut Transaction<'_, Postgres>,
    user: &AuthUser,
    organization: &str,
) -> AppResult<()> {
    if !user.permits_organization(organization) {
        return Err(AppError::Forbidden);
    }
    let active: bool =
        sqlx::query_scalar("SELECT public.codewire_platform_lock_owner('user',$1::text)")
            .bind(&user.user_id)
            .fetch_one(&mut **tx)
            .await
            .map_err(database_error)?;
    if !active {
        return Err(not_found());
    }
    let organization: Option<String> = sqlx::query_scalar(
        "SELECT id FROM organizations WHERE id=$1 AND deletion_state='active' FOR UPDATE",
    )
    .bind(organization)
    .fetch_optional(&mut **tx)
    .await
    .map_err(database_error)?;
    if organization.is_none() {
        return Err(not_found());
    }
    Ok(())
}

async fn lock_membership_in(
    tx: &mut Transaction<'_, Postgres>,
    user: &AuthUser,
    organization: &str,
) -> AppResult<()> {
    let member: Option<String> =
        sqlx::query_scalar("SELECT id FROM org_members WHERE user_id=$1 AND org_id=$2 FOR SHARE")
            .bind(&user.user_id)
            .bind(organization)
            .fetch_optional(&mut **tx)
            .await
            .map_err(database_error)?;
    if member.is_none() {
        return Err(not_found());
    }
    Ok(())
}

/// Compose pending-generation-zero source/profile/creator-ACL publication with
/// the INSERT transaction. The row must belong to this authenticated creator;
/// selecting personal sources never changes that immutable ownership.
pub async fn admit_create_sources_in(
    tx: &mut Transaction<'_, Postgres>,
    profiles: &PlatformAccessProfileStore,
    user: &AuthUser,
    organization: &str,
    environment: &str,
    body: &mut CreateEnvironmentBody,
) -> AppResult<()> {
    lock_source_owners_in(tx, user, organization).await?;
    let pending: Option<bool> = sqlx::query_scalar(
        "SELECT environment_operation_generation=0 AND state='pending' AND desired_state='started' \
         AND deletion_requested_at IS NULL FROM environments \
         WHERE id=$1 AND created_by=$2 AND org_id=$3 AND type='sandbox' FOR UPDATE",
    )
    .bind(environment)
    .bind(&user.user_id)
    .bind(organization)
    .fetch_optional(&mut **tx)
    .await
    .map_err(database_error)?;
    if pending != Some(true) {
        return Err(stale());
    }
    lock_membership_in(tx, user, organization).await?;
    let selection = EnvironmentSourceSelection {
        secrets: body.project_spec.secrets.clone(),
        credentials: body.project_spec.credentials.clone(),
        profile_revision: body.expected_profile_revision,
    };
    let (selection, profile) =
        resolve_selection_in(tx, profiles, user, organization, &selection, None).await?;
    confirm_sources(
        user,
        &selection,
        body.confirm_personal_secrets,
        body.confirm_personal_credentials,
    )?;
    let context = context(user, organization, environment, 0, profile.as_ref())?;
    if let Some(profile) = profile {
        profiles
            .create_pending_binding_in(
                tx,
                &context,
                binding(&context.environment_id, &profile),
                Some(&context.user_id),
            )
            .await
            .map_err(profile_error)?;
    }
    body.project_spec.secrets = selection.secrets;
    body.project_spec.credentials = selection.credentials;
    sqlx::query("UPDATE environments SET project_spec=$2 WHERE id=$1")
        .bind(environment)
        .bind(serde_json::to_value(&body.project_spec).map_err(|_| unavailable())?)
        .execute(&mut **tx)
        .await
        .map_err(database_error)?;
    sqlx::query(
        "INSERT INTO environment_access (environment_id,user_id,permission,granted_by) \
         VALUES ($1,$2,'owner',$2)",
    )
    .bind(environment)
    .bind(&user.user_id)
    .execute(&mut **tx)
    .await
    .map_err(database_error)?;
    Ok(())
}

/// Exact operation AND canonical-selection CAS. The caller owns commit and
/// rollback. A RestartRequired result leaves a running environment fenced as
/// (stopping, started); before committing, the caller must compose durable
/// managed-restart recovery under its existing organization runtime lease.
/// Merely dispatching an in-memory task after commit is not sufficient.
pub async fn replace_environment_sources_in(
    tx: &mut Transaction<'_, Postgres>,
    profiles: &PlatformAccessProfileStore,
    user: &AuthUser,
    organization: &str,
    environment: &str,
    body: &UpdateEnvironmentSourcesBody,
) -> AppResult<EnvironmentSourcesUpdate> {
    let generation = positive(body.expected_operation_generation)?;
    require_canonical(&body.expected)?;
    lock_source_owners_in(tx, user, organization).await?;
    // Source changes are creator-only, matching personal profile binding
    // authority; an organization API key cannot borrow another creator's data.
    let row = sqlx::query(
        "SELECT environment_operation_generation,state,desired_state,project_spec FROM environments \
         WHERE id=$1 AND created_by=$2 AND org_id=$3 AND type='sandbox' \
         AND deletion_requested_at IS NULL AND desired_state<>'destroyed' \
         AND state NOT IN ('destroyed','destroying') FOR UPDATE",
    )
    .bind(environment).bind(&user.user_id).bind(organization)
    .fetch_optional(&mut **tx).await.map_err(database_error)?.ok_or_else(not_found)?;
    lock_membership_in(tx, user, organization).await?;
    if row
        .try_get::<i64, _>("environment_operation_generation")
        .map_err(database_error)?
        != generation
    {
        return Err(stale());
    }
    let mut spec: ProjectSpec =
        serde_json::from_value(row.try_get("project_spec").map_err(database_error)?)
            .map_err(|_| unavailable())?;
    let state: String = row.try_get("state").map_err(database_error)?;
    let desired: String = row.try_get("desired_state").map_err(database_error)?;
    // Match setup ownership's explicit environment -> backend row lock order.
    // All owner fields must be absent; partial or reaping ownership is not an
    // expired lease that this operation may steal. The locks remain held until
    // the same transaction publishes state=stopping, excluding a new setup owner.
    let running_setup_ready = if state == "running" {
        sqlx::query_scalar::<_, bool>(
            "SELECT setup_complete AND setup_owner_generation IS NULL \
             AND setup_owner_activity_id IS NULL AND setup_owner_attempt IS NULL \
             AND setup_owner_phase IS NULL AND setup_owner_status IS NULL \
             AND setup_owner_pod_uid IS NULL FROM sandbox_environment_backend \
             WHERE environment_id=$1 FOR UPDATE",
        )
        .bind(environment)
        .fetch_optional(&mut **tx)
        .await
        .map_err(database_error)?
    } else {
        None
    };
    let current_binding: Option<(String, i64)> = sqlx::query_as(
        "SELECT profile_id,profile_revision FROM platform_environment_access_bindings \
         WHERE environment_id=$1 FOR UPDATE",
    )
    .bind(environment)
    .fetch_optional(&mut **tx)
    .await
    .map_err(database_error)?;
    let current = selection_from_spec(&spec, current_binding.as_ref())?;
    if current.credentials.is_some() || current.secrets.user.is_some() {
        user.require_account_credential()?;
    }
    if current != body.expected {
        return Err(stale());
    }
    let (selection, profile) = resolve_selection_in(
        tx,
        profiles,
        user,
        organization,
        &body.replacement,
        Some(&current),
    )
    .await?;
    let outcome = update_outcome(&state, &desired, current == selection, body.allow_restart)?;
    let result = EnvironmentSourcesUpdate {
        environment_id: environment.to_owned(),
        operation_generation: body.expected_operation_generation,
        selection: selection.clone(),
        outcome,
    };
    if outcome == EnvironmentSourcesUpdateOutcome::Unchanged {
        return Ok(result);
    }
    if outcome == EnvironmentSourcesUpdateOutcome::RestartRequired
        && running_setup_ready != Some(true)
    {
        return Err(AppError::Precondition(
            "environment setup must finish before changing running sources".into(),
        ));
    }
    confirm_sources(
        user,
        &selection,
        body.confirm_personal_secrets,
        body.confirm_personal_credentials,
    )?;
    let context = context(
        user,
        organization,
        environment,
        body.expected_operation_generation,
        profile.as_ref(),
    )?;
    let expected_binding = current_binding
        .map(|(id, revision)| {
            Ok::<_, AppError>(EnvironmentAccessBinding {
                environment_id: context.environment_id.clone(),
                profile_id: AccessProfileId::parse(id).map_err(|_| unavailable())?,
                profile_revision: u64::try_from(revision).map_err(|_| unavailable())?,
            })
        })
        .transpose()?;
    match (expected_binding.as_ref(), profile.as_ref()) {
        (None, None) => {}
        (Some(expected), None) => profiles
            .delete_binding_in(tx, &context, expected)
            .await
            .map_err(profile_error)?,
        (None, Some(profile)) => {
            profiles
                .create_binding_in(
                    tx,
                    &context,
                    binding(&context.environment_id, profile),
                    Some(&context.user_id),
                )
                .await
                .map_err(profile_error)?;
        }
        (Some(expected), Some(profile)) => {
            profiles
                .replace_binding_in(
                    tx,
                    &context,
                    expected,
                    binding(&context.environment_id, profile),
                    Some(&context.user_id),
                )
                .await
                .map_err(profile_error)?;
        }
    }
    spec.secrets = selection.secrets;
    spec.credentials = selection.credentials;
    sqlx::query(
        "UPDATE environments SET project_spec=$2,state=CASE WHEN $3 THEN 'stopping' ELSE state END, \
         state_changed_at=CASE WHEN $3 THEN now() ELSE state_changed_at END,updated_at=now() WHERE id=$1",
    )
    .bind(environment)
    .bind(serde_json::to_value(spec).map_err(|_| unavailable())?)
    .bind(outcome == EnvironmentSourcesUpdateOutcome::RestartRequired)
    .execute(&mut **tx).await.map_err(database_error)?;
    Ok(result)
}

async fn resolve_selection_in(
    tx: &mut Transaction<'_, Postgres>,
    profiles: &PlatformAccessProfileStore,
    user: &AuthUser,
    organization: &str,
    requested: &EnvironmentSourceSelection,
    current: Option<&EnvironmentSourceSelection>,
) -> AppResult<(EnvironmentSourceSelection, Option<AccessProfile>)> {
    let spec = ProjectSpec {
        secrets: requested.secrets.clone(),
        credentials: requested.credentials.clone(),
        ..Default::default()
    };
    spec.ensure_platform_compatible().map_err(|_| invalid())?;
    let mut selected = requested.clone();
    if !selected.secrets.project.is_empty() {
        let reference = selected
            .secrets
            .project_reference()
            .map_err(|_| invalid())?;
        let (id, name) = match reference.selector.strip_prefix("id:") {
            Some(id) => (Some(id), None),
            None => (None, Some(reference.selector)),
        };
        let id: String = sqlx::query_scalar(
            "SELECT id FROM secret_projects WHERE org_id=$1 \
             AND (($2::text IS NOT NULL AND id=$2) OR ($3::text IS NOT NULL AND name=$3)) FOR SHARE",
        )
        .bind(organization).bind(id).bind(name)
        .fetch_optional(&mut **tx).await.map_err(database_error)?.ok_or_else(not_found)?;
        selected.secrets.project = canonical_id(&id);
    }
    let Some(credentials) = &selected.credentials else {
        if selected.profile_revision.is_some() {
            return Err(invalid());
        }
        require_canonical(&selected)?;
        return Ok((selected, None));
    };
    user.require_account_credential()?;
    let revision = selected.profile_revision.ok_or_else(invalid)?;
    positive(revision)?;
    let owner = Owner::User(OwnerId::parse(&user.user_id).map_err(|_| AppError::Unauthorized)?);
    let reference = credentials.reference().map_err(|_| invalid())?;
    // Existing platform profile CRUD is personal-only. An organization-qualified
    // request must not silently fall back to a same-name personal profile.
    let mut profile = if let Some(id) = reference.selector.strip_prefix("id:") {
        profiles
            .get_in(
                tx,
                &owner,
                &AccessProfileId::parse(id).map_err(|_| invalid())?,
                None,
            )
            .await
    } else {
        let name = reference
            .selector
            .strip_prefix("user/")
            .unwrap_or(reference.selector);
        if name.contains('/') {
            return Err(not_found());
        }
        profiles
            .resolve_in(
                tx,
                &owner,
                &AccessProfileName::parse(name).map_err(|_| invalid())?,
            )
            .await
    }
    .map_err(profile_error)?;
    selected.credentials = Some(CredentialBinding {
        profile: canonical_id(profile.id.as_str()),
    });
    if profile.revision != revision {
        // A pinned profile does not silently advance during an application-only
        // edit. A newly selected/rebound revision must still be current.
        if current.is_some_and(|current| {
            current.credentials == selected.credentials
                && current.profile_revision == Some(revision)
        }) {
            profile = profiles
                .get_in(tx, &owner, &profile.id, Some(revision))
                .await
                .map_err(profile_error)?;
        } else {
            return Err(profile_error(PlatformProfileError::StaleRevision));
        }
    }
    require_canonical(&selected)?;
    Ok((selected, Some(profile)))
}

fn confirm_sources(
    user: &AuthUser,
    selected: &EnvironmentSourceSelection,
    personal_secrets: bool,
    personal_credentials: bool,
) -> AppResult<()> {
    if selected.secrets.user.is_some() {
        user.require_account_credential()?;
        if !personal_secrets {
            return Err(AppError::Precondition(
                "explicit personal application-secret confirmation is required".into(),
            ));
        }
    }
    if selected.credentials.is_some() {
        user.require_account_credential()?;
        if !personal_credentials {
            return Err(AppError::Precondition(
                "explicit personal credential confirmation is required".into(),
            ));
        }
    }
    Ok(())
}

fn context(
    user: &AuthUser,
    organization: &str,
    environment: &str,
    generation: u64,
    profile: Option<&AccessProfile>,
) -> AppResult<GrantContext> {
    Ok(GrantContext {
        environment_id: EnvironmentId::parse(environment).map_err(|_| invalid())?,
        environment_generation: generation,
        placement: GrantPlacement::Platform,
        user_id: OwnerId::parse(&user.user_id).map_err(|_| AppError::Unauthorized)?,
        organization_id: Some(OwnerId::parse(organization).map_err(|_| invalid())?),
        allow_personal_credentials: true,
        authorized_credentials: profile
            .map(|profile| profile.entries.values().cloned().collect::<BTreeSet<_>>())
            .unwrap_or_default(),
    })
}

fn binding(environment: &EnvironmentId, profile: &AccessProfile) -> EnvironmentAccessBinding {
    EnvironmentAccessBinding {
        environment_id: environment.clone(),
        profile_id: profile.id.clone(),
        profile_revision: profile.revision,
    }
}

fn canonical_id(id: &str) -> String {
    format!("platform:id:{id}")
}

fn require_canonical(selection: &EnvironmentSourceSelection) -> AppResult<()> {
    let spec = ProjectSpec {
        secrets: selection.secrets.clone(),
        credentials: selection.credentials.clone(),
        ..Default::default()
    };
    spec.ensure_platform_compatible().map_err(|_| invalid())?;
    if (!selection.secrets.project.is_empty()
        && !selection.secrets.project.starts_with("platform:id:"))
        || selection
            .credentials
            .as_ref()
            .is_some_and(|binding| !binding.profile.starts_with("platform:id:"))
        || selection.credentials.is_some() != selection.profile_revision.is_some()
    {
        return Err(invalid());
    }
    if let Some(revision) = selection.profile_revision {
        positive(revision)?;
    }
    Ok(())
}

pub(crate) fn selection_from_spec(
    spec: &ProjectSpec,
    binding: Option<&(String, i64)>,
) -> AppResult<EnvironmentSourceSelection> {
    let selection = EnvironmentSourceSelection {
        secrets: spec.secrets.clone(),
        credentials: spec.credentials.clone(),
        profile_revision: binding
            .map(|(_, revision)| u64::try_from(*revision).map_err(|_| unavailable()))
            .transpose()?,
    };
    require_canonical(&selection).map_err(|_| unavailable())?;
    if binding.map(|(id, _)| canonical_id(id))
        != selection
            .credentials
            .as_ref()
            .map(|profile| profile.profile.clone())
    {
        return Err(unavailable());
    }
    Ok(selection)
}

fn update_outcome(
    state: &str,
    desired: &str,
    unchanged: bool,
    allow_restart: bool,
) -> AppResult<EnvironmentSourcesUpdateOutcome> {
    if !matches!(
        (state, desired),
        ("running", "started") | ("stopped", "stopped")
    ) {
        return Err(AppError::Precondition(
            "environment must be running or stopped before changing sources".into(),
        ));
    }
    if unchanged {
        return Ok(EnvironmentSourcesUpdateOutcome::Unchanged);
    }
    if state == "stopped" {
        return Ok(EnvironmentSourcesUpdateOutcome::Stored);
    }
    if !allow_restart {
        return Err(AppError::Precondition(
            "changing sources on a running environment requires restart confirmation".into(),
        ));
    }
    Ok(EnvironmentSourcesUpdateOutcome::RestartRequired)
}

fn positive(value: u64) -> AppResult<i64> {
    if value == 0 {
        return Err(invalid());
    }
    i64::try_from(value).map_err(|_| invalid())
}
fn invalid() -> AppError {
    AppError::BadRequest("invalid environment source selection or revision".into())
}
fn stale() -> AppError {
    AppError::Conflict("environment operation or source selection changed".into())
}
fn not_found() -> AppError {
    AppError::NotFound("source or authorized environment not found".into())
}
fn unavailable() -> AppError {
    AppError::ServiceUnavailable("environment source service unavailable".into())
}
fn database_error(_: sqlx::Error) -> AppError {
    unavailable()
}

#[cfg(test)]
mod tests {
    use super::*;
    use codewire_project::StoragePlacement;

    const PROFILE: &str = "platform:id:6bf8d155-e84c-4fc5-b479-b17022fe41dd";

    fn personal() -> AuthUser {
        AuthUser {
            user_id: "creator".into(),
            org_id: None,
            is_admin: false,
            via_api_key: false,
        }
    }

    #[test]
    fn canonical_expected_selection_requires_exact_platform_ids_and_revision_pair() {
        assert!(require_canonical(&EnvironmentSourceSelection::default()).is_ok());
        let selected = EnvironmentSourceSelection {
            secrets: SecretBindings {
                project: PROFILE.into(),
                organization: true,
                user: Some(StoragePlacement::Platform),
            },
            credentials: Some(CredentialBinding {
                profile: PROFILE.into(),
            }),
            profile_revision: Some(1),
        };
        assert!(require_canonical(&selected).is_ok());
        for project in ["work", "platform:work", "local:work", "platform:id:invalid"] {
            let mut bad = selected.clone();
            bad.secrets.project = project.into();
            assert!(require_canonical(&bad).is_err());
        }
        let mut bad = selected.clone();
        bad.credentials = None;
        assert!(require_canonical(&bad).is_err());
        let mut bad = selected.clone();
        bad.profile_revision = None;
        assert!(require_canonical(&bad).is_err());
        let mut bad = selected.clone();
        bad.profile_revision = Some(0);
        assert!(require_canonical(&bad).is_err());
        let mut bad = selected;
        bad.secrets.user = Some(StoragePlacement::Local);
        assert!(require_canonical(&bad).is_err());
    }

    #[test]
    fn operation_generation_and_profile_revision_are_distinct_positive_fences() {
        assert!(ensure_source_delivery_available().is_err());
        assert!(positive(0).is_err());
        assert!(positive(u64::MAX).is_err());
        assert_eq!(positive(7).unwrap(), 7);
        let request: UpdateEnvironmentSourcesBody = serde_json::from_value(serde_json::json!({
            "expected_operation_generation":7, "expected":{}, "replacement":{}
        }))
        .unwrap();
        assert!(
            !request.allow_restart
                && !request.confirm_personal_credentials
                && !request.confirm_personal_secrets
        );
        assert!(request.expected.profile_revision.is_none());
    }

    #[test]
    fn running_changes_require_restart_but_stopped_and_noop_never_start() {
        assert_eq!(
            update_outcome("running", "started", true, false).unwrap(),
            EnvironmentSourcesUpdateOutcome::Unchanged
        );
        assert_eq!(
            update_outcome("stopped", "stopped", true, true).unwrap(),
            EnvironmentSourcesUpdateOutcome::Unchanged
        );
        assert_eq!(
            update_outcome("stopped", "stopped", false, true).unwrap(),
            EnvironmentSourcesUpdateOutcome::Stored
        );
        assert!(update_outcome("running", "started", false, false).is_err());
        assert_eq!(
            update_outcome("running", "started", false, true).unwrap(),
            EnvironmentSourcesUpdateOutcome::RestartRequired
        );
        for (state, desired) in [
            ("pending", "started"),
            ("starting", "started"),
            ("stopping", "started"),
            ("resizing", "resized"),
            ("error", "started"),
            ("destroyed", "destroyed"),
        ] {
            assert!(update_outcome(state, desired, false, true).is_err());
            assert!(update_outcome(state, desired, true, true).is_err());
        }
    }

    #[test]
    fn personal_application_secrets_and_provider_confirmation_are_independent() {
        let mut selection = EnvironmentSourceSelection::default();
        selection.secrets.user = Some(StoragePlacement::Platform);
        assert!(confirm_sources(&personal(), &selection, false, true).is_err());
        assert!(confirm_sources(&personal(), &selection, true, false).is_ok());
        selection.credentials = Some(CredentialBinding {
            profile: PROFILE.into(),
        });
        selection.profile_revision = Some(1);
        assert!(confirm_sources(&personal(), &selection, true, false).is_err());
        assert!(confirm_sources(&personal(), &selection, true, true).is_ok());
        let mut machine = personal();
        machine.via_api_key = true;
        machine.org_id = Some("org".into());
        assert!(confirm_sources(&machine, &selection, true, true).is_err());
    }

    #[test]
    fn persisted_spec_and_profile_binding_must_agree_without_fallback() {
        let mut spec = ProjectSpec::default();
        let pinned = (PROFILE.strip_prefix("platform:id:").unwrap().into(), 2);
        assert!(selection_from_spec(&spec, Some(&pinned)).is_err());
        spec.credentials = Some(CredentialBinding {
            profile: PROFILE.into(),
        });
        assert!(selection_from_spec(&spec, None).is_err());
        assert_eq!(
            selection_from_spec(&spec, Some(&pinned))
                .unwrap()
                .profile_revision,
            Some(2)
        );
        spec.credentials.as_mut().unwrap().profile = "platform:user/work".into();
        assert!(selection_from_spec(&spec, Some(&pinned)).is_err());
    }

    #[test]
    fn replacement_contains_only_selection_and_confirmation_not_material_or_mapping() {
        for forbidden in [
            "environment",
            "exposures",
            "stored_exposures",
            "secret_value",
            "created_by",
            "credential_id",
        ] {
            let mut json = serde_json::json!({"expected_operation_generation":7,"expected":{},"replacement":{}});
            json["replacement"][forbidden] = serde_json::json!("synthetic-value-canary");
            assert!(serde_json::from_value::<UpdateEnvironmentSourcesBody>(json).is_err());
        }
        for error in [invalid(), stale(), not_found(), unavailable()] {
            assert!(!error.to_string().contains("synthetic-value-canary"));
        }
    }
}
