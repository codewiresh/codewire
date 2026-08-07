//! Environment ports CRUD (#38 slice 4) — port of the port handlers
//! in `environment_routes.go`. DNS fan-out keeps Go's best-effort
//! `pg_notify('port_dns_events', …)` (the channel's listener story is
//! tracked in the Temporal cutover doc).

use axum::http::StatusCode;
use codewire_server_core::auth::AuthUser;
use codewire_server_core::org_deletion::{
    OrganizationRuntimeMutationError, run_environment_runtime_mutation,
};
use codewire_server_core::{AppError, AppResult};
use schemars::JsonSchema;
use serde::Deserialize;
use sqlx::{PgPool, Row};
use std::sync::atomic::{AtomicBool, Ordering};

use super::ApiState;
use super::environments::{
    EnvironmentPort, coded, compute_preview_url, fetch_env_summary, format_time,
    require_environment_access, require_org_member,
};
use crate::confidential_storage::require_interactive_access;

/// Mirrors `reservedPorts` (gateway SSH + readyz).
fn is_reserved_port(port: i32) -> bool {
    port == 2222 || port == 2223
}

trait PortDnsNotifier {
    async fn notify(&self, env_id: &str, action: &'static str) -> Result<(), sqlx::Error>;
}

struct PgPortDnsNotifier<'a>(&'a PgPool);

impl PortDnsNotifier for PgPortDnsNotifier<'_> {
    async fn notify(&self, env_id: &str, action: &'static str) -> Result<(), sqlx::Error> {
        let payload = format!(r#"{{"environment_id":"{env_id}","action":"{action}"}}"#);
        sqlx::query("SELECT pg_notify('port_dns_events', $1)")
            .bind(payload)
            .execute(self.0)
            .await?;
        Ok(())
    }
}

async fn notify_port_dns(
    notifier: &impl PortDnsNotifier,
    env_id: &str,
    action: &'static str,
) -> Result<(), sqlx::Error> {
    notifier.notify(env_id, action).await
}

async fn get_org_slug(pool: &PgPool, org_id: &str) -> String {
    sqlx::query_scalar("SELECT slug FROM organizations WHERE id = $1")
        .bind(org_id)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .unwrap_or_default()
}

/// Mirrors `api.CreatePortBody`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct CreatePortBody {
    pub port: i32,
    pub label: String,
    #[serde(default)]
    pub access: String,
}

pub(crate) async fn create_port_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    env_id: &str,
    body: CreatePortBody,
) -> AppResult<EnvironmentPort> {
    let pool = &state.pool;
    require_org_member(pool, user, org_id).await?;
    require_environment_access(pool, user, env_id, org_id, "operator", "access denied").await?;
    let env = fetch_env_summary(pool, org_id, env_id).await?;
    require_interactive_access(state.confidential_storage_flags, user, &env.isolation_tier)?;

    if !(1..=65_535).contains(&body.port) {
        return Err(AppError::BadRequest(
            "port must be between 1 and 65535".into(),
        ));
    }

    if is_reserved_port(body.port) {
        return Err(coded(
            StatusCode::BAD_REQUEST,
            "port_reserved",
            "port is reserved by the agent",
        ));
    }

    let access = if body.access.is_empty() {
        "creator"
    } else {
        body.access.as_str()
    };
    if access != "public" && access != "org_members" && access != "creator" {
        return Err(coded(
            StatusCode::BAD_REQUEST,
            "invalid_access",
            "access must be public, org_members, or creator",
        ));
    }

    let dispatch_ambiguous = AtomicBool::new(false);
    run_environment_runtime_mutation(pool, org_id, env_id, async {
        let result: AppResult<EnvironmentPort> = async {
            let row = match sqlx::query(
                r#"INSERT INTO environment_ports (environment_id, port, label, access)
           VALUES ($1, $2, $3, $4)
           RETURNING id, environment_id, port, label, access, created_at"#,
            )
            .bind(&env.id)
            .bind(body.port)
            .bind(&body.label)
            .bind(access)
            .fetch_one(pool)
            .await
            {
                Ok(r) => r,
                Err(e)
                    if e.to_string().contains("duplicate key")
                        || e.to_string().contains("unique constraint") =>
                {
                    return Err(coded(
                        StatusCode::CONFLICT,
                        "port_conflict",
                        "port or label already registered for this environment",
                    ));
                }
                Err(e) => {
                    tracing::error!(error = %e, "insert port failed");
                    return Err(coded(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal_error",
                        "failed to register port",
                    ));
                }
            };

            let org_slug = get_org_slug(pool, org_id).await;
            let port = EnvironmentPort {
                id: row.try_get("id")?,
                environment_id: row.try_get("environment_id")?,
                port: row.try_get("port")?,
                label: row.try_get::<String, _>("label")?,
                access: row.try_get("access")?,
                preview_url: compute_preview_url(
                    &body.label,
                    &env.id,
                    &org_slug,
                    &state.preview_base_domain,
                ),
                created_at: format_time(row.try_get("created_at")?),
            };

            if notify_port_dns(&PgPortDnsNotifier(pool), &env.id, "create")
                .await
                .is_err()
            {
                dispatch_ambiguous.store(true, Ordering::Release);
                return Err(coded(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "failed to dispatch port DNS creation",
                ));
            }

            Ok(port)
        }
        .await;
        match result {
            Ok(port) => Ok(port),
            Err(error) if dispatch_ambiguous.load(Ordering::Acquire) => {
                Err(OrganizationRuntimeMutationError::ambiguous(error))
            }
            Err(error) => Err(error.into()),
        }
    })
    .await
}

pub(crate) async fn list_ports_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    env_id: &str,
) -> AppResult<Vec<EnvironmentPort>> {
    let pool = &state.pool;
    require_org_member(pool, user, org_id).await?;
    require_environment_access(pool, user, env_id, org_id, "viewer", "access denied").await?;
    let env = fetch_env_summary(pool, org_id, env_id).await?;
    require_interactive_access(state.confidential_storage_flags, user, &env.isolation_tier)?;

    let rows = sqlx::query(
        r#"SELECT id, environment_id, port, label, access, created_at
           FROM environment_ports
           WHERE environment_id = $1 AND deletion_requested_at IS NULL
           ORDER BY created_at"#,
    )
    .bind(env_id)
    .fetch_all(pool)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "list ports failed");
        coded(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "failed to list ports",
        )
    })?;

    let org_slug = get_org_slug(pool, org_id).await;
    let ports = rows
        .iter()
        .map(|r| -> Result<EnvironmentPort, sqlx::Error> {
            let label: String = r.try_get("label")?;
            Ok(EnvironmentPort {
                id: r.try_get("id")?,
                environment_id: r.try_get("environment_id")?,
                port: r.try_get("port")?,
                preview_url: compute_preview_url(
                    &label,
                    env_id,
                    &org_slug,
                    &state.preview_base_domain,
                ),
                label,
                access: r.try_get("access")?,
                created_at: format_time(r.try_get("created_at")?),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(ports)
}

pub(crate) async fn delete_port_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    env_id: &str,
    port_id: &str,
) -> AppResult<()> {
    let pool = &state.pool;
    require_org_member(pool, user, org_id).await?;
    require_environment_access(
        pool,
        user,
        env_id,
        org_id,
        "owner",
        "only environment owners can delete ports",
    )
    .await?;
    let env = fetch_env_summary(pool, org_id, env_id).await?;
    require_interactive_access(state.confidential_storage_flags, user, &env.isolation_tier)?;

    let dispatch_ambiguous = AtomicBool::new(false);
    run_environment_runtime_mutation(pool, org_id, env_id, async {
        let result: AppResult<()> = async {
            let result = sqlx::query(
                r#"UPDATE environment_ports
           SET deletion_requested_at = COALESCE(deletion_requested_at, NOW())
           WHERE id = $1 AND environment_id = $2
             AND deletion_requested_at IS NULL"#,
            )
            .bind(port_id)
            .bind(env_id)
            .execute(pool)
            .await
            .map_err(|_| {
                coded(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "failed to delete port",
                )
            })?;
            if result.rows_affected() == 0 {
                return Err(coded(
                    StatusCode::NOT_FOUND,
                    "port_not_found",
                    "port not found",
                ));
            }

            let pending_dns: bool = sqlx::query_scalar(
                "SELECT dns_record_id IS NOT NULL FROM environment_ports WHERE id = $1",
            )
            .bind(port_id)
            .fetch_one(pool)
            .await?;
            if !pending_dns {
                sqlx::query(
            "DELETE FROM environment_ports WHERE id = $1 AND deletion_requested_at IS NOT NULL",
        )
        .bind(port_id)
        .execute(pool)
        .await?;
                return Ok(());
            }

            if notify_port_dns(&PgPortDnsNotifier(pool), env_id, "delete")
                .await
                .is_err()
            {
                dispatch_ambiguous.store(true, Ordering::Release);
                return Err(coded(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "failed to dispatch port DNS deletion",
                ));
            }

            Ok(())
        }
        .await;
        match result {
            Ok(()) => Ok(()),
            Err(error) if dispatch_ambiguous.load(Ordering::Acquire) => {
                Err(OrganizationRuntimeMutationError::ambiguous(error))
            }
            Err(error) => Err(error.into()),
        }
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use codewire_server_core::validation::validate_value;
    use std::sync::Mutex;

    #[derive(Default)]
    struct RecordingNotifier(Mutex<Vec<(String, &'static str)>>);

    impl PortDnsNotifier for RecordingNotifier {
        async fn notify(&self, env_id: &str, action: &'static str) -> Result<(), sqlx::Error> {
            self.0.lock().unwrap().push((env_id.to_owned(), action));
            Ok(())
        }
    }

    #[test]
    fn create_port_schema_requires_go_required_fields() {
        let schema = serde_json::to_value(schemars::schema_for!(CreatePortBody)).unwrap();

        assert_eq!(schema["required"], serde_json::json!(["port", "label"]));
    }

    #[test]
    fn create_port_validation_rejects_missing_required_fields() {
        let Err(AppError::Validation { errors }) =
            validate_value::<CreatePortBody>(serde_json::json!({
                "port": 3000
            }))
        else {
            panic!("expected missing label to be rejected");
        };

        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].path, "/");
        assert!(errors[0].message.contains("label"));
    }

    #[test]
    fn create_port_validation_rejects_type_errors() {
        let Err(AppError::Validation { errors }) =
            validate_value::<CreatePortBody>(serde_json::json!({
                "port": "3000",
                "label": "web"
            }))
        else {
            panic!("expected type-invalid port to be rejected");
        };

        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].path, "/port");
        assert!(errors[0].message.contains("integer"));
    }

    #[test]
    fn create_port_validation_keeps_access_optional() {
        let parsed = validate_value::<CreatePortBody>(serde_json::json!({
            "port": 3000,
            "label": "web"
        }))
        .expect("access should remain optional");

        assert_eq!(parsed.port, 3000);
        assert_eq!(parsed.label, "web");
        assert_eq!(parsed.access, "");
    }

    #[tokio::test]
    async fn port_dns_notifications_keep_create_and_delete_actions() {
        let notifier = RecordingNotifier::default();

        notify_port_dns(&notifier, "env_port_contract", "create")
            .await
            .unwrap();
        notify_port_dns(&notifier, "env_port_contract", "delete")
            .await
            .unwrap();

        assert_eq!(
            *notifier.0.lock().unwrap(),
            vec![
                ("env_port_contract".to_owned(), "create"),
                ("env_port_contract".to_owned(), "delete"),
            ]
        );
    }
}
