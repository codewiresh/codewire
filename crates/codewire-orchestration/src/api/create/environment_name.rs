//! The name a create takes. Names are unique among an organization's live
//! environments, so every command that takes a name finds one environment;
//! a removed environment's name is free again (docs/dev/CLI-PARITY.md, R1).
//! The check runs under the create's organization row lock, which every
//! create takes before its insert, so two creates of one name cannot both
//! pass it.

use axum::http::StatusCode;
use codewire_server_core::{AppError, AppResult};

use super::generate_short_id;

/// A generated name is drawn again when it is taken. Four hex digits leave
/// so much room that this many draws all colliding means something is wrong.
const GENERATED_NAME_DRAWS: usize = 8;

/// The name the create records: the one asked for, refused when a live
/// environment in `org_id` has it, or a free generated `env-XXXX`. Called
/// with the organization row locked in `transaction`.
pub(super) async fn admitted_name(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    org_id: &str,
    requested: Option<&str>,
) -> AppResult<String> {
    if let Some(name) = requested.filter(|name| !name.is_empty()) {
        if in_use(transaction, org_id, name).await? {
            return Err(name_taken(name));
        }
        return Ok(name.to_owned());
    }
    for _ in 0..GENERATED_NAME_DRAWS {
        let name = format!("env-{}", generate_short_id());
        if !in_use(transaction, org_id, &name).await? {
            return Ok(name);
        }
    }
    Err(AppError::Coded {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        code: "internal_error",
        detail: "no free environment name was found; name it with --name".into(),
    })
}

async fn in_use(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    org_id: &str,
    name: &str,
) -> AppResult<bool> {
    Ok(sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM environments \
         WHERE org_id = $1 AND name = $2 AND state NOT IN ('destroyed', 'destroying'))",
    )
    .bind(org_id)
    .bind(name)
    .fetch_one(&mut **transaction)
    .await?)
}

fn name_taken(name: &str) -> AppError {
    AppError::Coded {
        status: StatusCode::CONFLICT,
        code: "environment_name_taken",
        detail: codewire_project::environment_name_taken(
            codewire_project::EnvironmentPlacement::Cloud,
            name,
        )
        .into(),
    }
}
