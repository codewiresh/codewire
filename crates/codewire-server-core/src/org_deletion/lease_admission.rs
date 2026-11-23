//! Admitting one organization mutation lease inside the caller's
//! transaction: the organization must be active, and a runtime dispatch
//! records this process as its owner (#4523).

use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use super::{OrganizationMutationClass, OrganizationMutationLease, state_conflict};
use crate::error::AppError;

pub(super) async fn admit_mutation_lease_in(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    mutation_class: OrganizationMutationClass,
    environment_id: Option<&str>,
) -> Result<OrganizationMutationLease, AppError> {
    let deletion_state: Option<String> =
        sqlx::query_scalar(r#"SELECT deletion_state FROM organizations WHERE id = $1 FOR UPDATE"#)
            .bind(organization_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(AppError::from)?;

    match deletion_state.as_deref() {
        Some("active") => {}
        Some("deleting" | "delete_failed") => {
            return Err(state_conflict("organization deletion is in progress"));
        }
        Some(_) => {
            return Err(AppError::Internal(anyhow::anyhow!(
                "organization {organization_id} has an unknown deletion state"
            )));
        }
        None => return Err(AppError::NotFound("organization not found".into())),
    }

    let lease_id = format!("organization-mutation/{}", Uuid::new_v4());
    let lease = sqlx::query_as::<_, OrganizationMutationLease>(
        r#"
        INSERT INTO organization_mutation_leases
            (id, organization_id, mutation_class, deadline_at, environment_id, owner_incarnation)
        VALUES ($1, $2, $3, NOW() + ($4 * INTERVAL '1 second'), $5, $6)
        RETURNING *
        "#,
    )
    .bind(&lease_id)
    .bind(organization_id)
    .bind(mutation_class.as_str())
    .bind(mutation_class.deadline_seconds())
    .bind(environment_id)
    // Only runtime dispatches are acted for by this process alone (#4523).
    .bind(
        (mutation_class == OrganizationMutationClass::EnvironmentRuntimeDispatch)
            .then(crate::lease_owner::incarnation)
            .flatten(),
    )
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::from)?;
    Ok(lease)
}
