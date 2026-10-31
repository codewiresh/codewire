//! Running sandboxes of an organization that has had no compute credit, and
//! no way to get it, for 24 hours are stopped (owner, 2026-10-24: "running
//! sandboxes stop after 24 hours. Storage is kept."; #3381). Billing records
//! when an organization ran out (`organizations.credit_exhausted_at`) and
//! clears it once credit returns; the reconciler stops what is still running.

use codewire_server_core::credit_enforcement::CreditEnforcement;
use sqlx::PgPool;

/// How long a charging organization may run without credit.
pub const CREDIT_EXHAUSTED_GRACE_HOURS: i32 = 24;

/// Environments to stop: started, not stopping already, in an organization
/// on a charging card that ran out of credit more than 24 hours ago. A
/// protected environment is stopped too: protection guards against
/// deletion, and stopping keeps its storage.
///
/// A deployment that does not enforce credit stops nothing.
pub async fn credit_exhausted_environment_ids(
    pool: &PgPool,
    enforcement: CreditEnforcement,
) -> Result<Vec<String>, sqlx::Error> {
    if !enforcement.is_on() {
        return Ok(Vec::new());
    }
    sqlx::query_scalar(
        r#"SELECT e.id FROM environments e
           JOIN organizations o ON o.id = e.org_id
           WHERE o.rate_card <> 'unlimited'
             AND o.credit_exhausted_at < NOW() - make_interval(hours => $1)
             AND e.desired_state = 'started'
             AND e.state NOT IN ('destroyed', 'destroying', 'error', 'stopped', 'archived')
           ORDER BY e.id"#,
    )
    .bind(CREDIT_EXHAUSTED_GRACE_HOURS)
    .fetch_all(pool)
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn with_enforcement_off_nothing_is_stopped_or_even_asked() {
        // Never connected: a query would fail.
        let pool = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_millis(100))
            .connect_lazy("postgres://codewire@127.0.0.1:1/codewire")
            .unwrap();
        assert!(
            credit_exhausted_environment_ids(&pool, CreditEnforcement::Off)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            credit_exhausted_environment_ids(&pool, CreditEnforcement::On)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn db_only_running_sandboxes_of_organizations_exhausted_a_day_ago_are_stopped() {
        let url = std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .unwrap();
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let user = format!("user_credit_stop_{suffix}");
        sqlx::query("INSERT INTO users (id, email) VALUES ($1, $2)")
            .bind(&user)
            .bind(format!("{user}@example.test"))
            .execute(&pool)
            .await
            .unwrap();
        // (organization, card, exhausted this long ago)
        let organizations = [
            ("day", "regular", Some("25 hours")),
            ("hour", "regular", Some("1 hour")),
            ("never", "regular", None),
            ("unlimited", "unlimited", Some("25 hours")),
            ("discounted", "discounted", Some("25 hours")),
        ];
        for (name, card, ago) in organizations {
            let org = format!("org_credit_stop_{name}_{suffix}");
            sqlx::query(
                "INSERT INTO organizations (id, name, slug, created_by, rate_card, credit_exhausted_at) \
                 VALUES ($1, $1, $2, $3, $4, now() - $5::interval)",
            )
            .bind(&org)
            .bind(format!("credit-stop-{name}-{}", &suffix[..8]))
            .bind(&user)
            .bind(card)
            .bind(ago)
            .execute(&pool)
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO environment_presets (id, org_id, name, build_status, project_spec) \
                 VALUES ($1, $1, 'Preset', 'ready', '{}'::jsonb)",
            )
            .bind(&org)
            .execute(&pool)
            .await
            .unwrap();
            for (environment, state, desired) in [
                ("running", "running", "started"),
                ("starting", "pending", "started"),
                ("stopped", "stopped", "stopped"),
                ("stopping", "running", "stopped"),
            ] {
                sqlx::query(
                    "INSERT INTO environments (id, org_id, created_by, type, preset_id, state, \
                     desired_state, project_spec) VALUES ($1, $2, $3, 'sandbox', $2, $4, $5, '{}'::jsonb)",
                )
                .bind(format!("{org}_{environment}"))
                .bind(&org)
                .bind(&user)
                .bind(state)
                .bind(desired)
                .execute(&pool)
                .await
                .unwrap();
            }
        }
        let due: Vec<String> = credit_exhausted_environment_ids(&pool, CreditEnforcement::On)
            .await
            .unwrap()
            .into_iter()
            .filter(|id| id.contains(&*suffix))
            .collect();
        let mut expected: Vec<String> = ["day", "discounted"]
            .iter()
            .flat_map(|name| {
                ["running", "starting"]
                    .map(|environment| format!("org_credit_stop_{name}_{suffix}_{environment}"))
            })
            .collect();
        expected.sort();
        assert_eq!(due, expected);

        for (name, ..) in organizations {
            let org = format!("org_credit_stop_{name}_{suffix}");
            for table in ["environments", "environment_presets"] {
                sqlx::query(&format!("DELETE FROM {table} WHERE org_id = $1"))
                    .bind(&org)
                    .execute(&pool)
                    .await
                    .unwrap();
            }
            sqlx::query("DELETE FROM organizations WHERE id = $1")
                .bind(&org)
                .execute(&pool)
                .await
                .unwrap();
        }
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(&user)
            .execute(&pool)
            .await
            .unwrap();
    }
}
