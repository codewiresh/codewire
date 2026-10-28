//! Rate cards and the credit ledger (0006, #3381): an upgrade from 0005 seeds
//! the three cards, puts every organization on Regular except those never
//! charged before, keeps each balance equal to the sum of its ledger, refuses
//! changes to the ledger and direct balance writes, deletes both with their
//! organization, never draws usage from before it, bounds automatic top-ups
//! and keeps one grant per card, and its rollback restores the 0005 schema.

use super::*;

async fn fingerprint(pool: &PgPool) -> anyhow::Result<String> {
    Ok(sqlx::query_scalar(include_str!(
        "../../../tests/data/application_schema_fingerprint.sql"
    ))
    .fetch_one(pool)
    .await?)
}

fn sqlstate(error: &sqlx::Error) -> Option<String> {
    error
        .as_database_error()
        .and_then(|e| e.code())
        .map(|code| code.into_owned())
}

async fn balance(pool: &PgPool, org: &str) -> anyhow::Result<Option<i64>> {
    Ok(sqlx::query_scalar(
        "SELECT balance_nano_eur FROM billing_credit_balances WHERE organization_id = $1",
    )
    .bind(org)
    .fetch_optional(pool)
    .await?)
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn billing_rate_cards_upgrade_keeps_uncharged_organizations_free_and_the_ledger_exact()
-> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        // The shape before 0006: the baseline and 0002 to 0005.
        let before = sqlx::migrate::Migrator {
            migrations: std::borrow::Cow::Owned(MIGRATOR.iter().take(5).cloned().collect()),
            ..sqlx::migrate::Migrator::DEFAULT
        };
        let mut connection = PgConnection::connect(&db.url).await?;
        before.run(&mut connection).await?;
        connection.close().await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        seed_platform_credential_owners(&pool).await?;
        // One organization for each way an organization was free before,
        // and two that were charged: one with no plan, one whose unlimited
        // subscription has ended.
        sqlx::raw_sql(
            "INSERT INTO organizations (id, name, slug, created_by, billing_exempt) VALUES \
               ('rate-exempt', 'Exempt', 'rate-exempt', 'credential-user-a', true); \
             INSERT INTO organizations (id, name, slug, created_by, billing_plan, billing_status) VALUES \
               ('rate-legacy-plan', 'Legacy', 'rate-legacy-plan', 'credential-user-a', 'unlimited', 'active'); \
             INSERT INTO organizations (id, name, slug, created_by) VALUES \
               ('rate-org-sub', 'Org sub', 'rate-org-sub', 'credential-user-a'), \
               ('rate-env-sub', 'Env sub', 'rate-env-sub', 'credential-user-a'), \
               ('rate-ended', 'Ended', 'rate-ended', 'credential-user-a'); \
             INSERT INTO org_subscriptions (org_id, plan, status) VALUES \
               ('rate-org-sub', 'unlimited', 'active'), \
               ('rate-ended', 'unlimited', 'canceled'); \
             INSERT INTO environment_subscriptions (org_id, plan, status) VALUES \
               ('rate-env-sub', 'unlimited', 'trialing'); \
             INSERT INTO environment_presets (id, org_id, name, build_status, project_spec) VALUES \
               ('rate-preset', 'rate-ended', 'Preset', 'ready', '{}'::jsonb); \
             INSERT INTO environments (id, org_id, created_by, type, preset_id, project_spec) VALUES \
               ('env-open', 'rate-ended', 'credential-user-a', 'sandbox', 'rate-preset', '{}'::jsonb), \
               ('env-closed', 'rate-ended', 'credential-user-a', 'sandbox', 'rate-preset', '{}'::jsonb); \
             INSERT INTO sandbox_running_sessions \
               (id, environment_id, organization_id, runtime_uid, runtime_name, \
                runtime_namespace, cpu_millicores, memory_mib, disk_gib, started_at, \
                last_observed_at, ended_at) VALUES \
               ('rate-open', 'env-open', 'rate-ended', 'uid-1', 'pod-1', 'ns', 2000, 8192, 10, \
                '2026-10-01 00:00:00+00', '2026-10-01 00:00:00+00', NULL), \
               ('rate-closed', 'env-closed', 'rate-ended', 'uid-2', 'pod-2', 'ns', 2000, 8192, 10, \
                '2026-10-01 00:00:00+00', '2026-10-02 00:00:00+00', '2026-10-02 00:00:00+00');",
        )
        .execute(&pool)
        .await?;
        let previous = fingerprint(&pool).await?;
        anyhow::ensure!(previous != ACCEPTED_APPLICATION_SCHEMA_FINGERPRINT);

        ensure_schema(&db.url).await?;
        anyhow::ensure!(fingerprint(&pool).await? == ACCEPTED_APPLICATION_SCHEMA_FINGERPRINT);

        let cards: Vec<(String, i64, i64, i64)> = sqlx::query_as(
            "SELECT rate_card, cpu_nano_eur_per_vcpu_hour, memory_nano_eur_per_gib_hour, \
             disk_nano_eur_per_gib_hour FROM billing_rate_cards ORDER BY rate_card",
        )
        .fetch_all(&pool)
        .await?;
        anyhow::ensure!(
            cards
                == [
                    ("discounted".to_owned(), 21_900_000, 7_050_000, 43_500),
                    ("regular".to_owned(), 43_800_000, 14_100_000, 87_000),
                    ("unlimited".to_owned(), 0, 0, 0),
                ],
            "{cards:?}"
        );
        let assigned: Vec<(String, String)> =
            sqlx::query_as("SELECT id, rate_card FROM organizations ORDER BY id")
                .fetch_all(&pool)
                .await?;
        let expected: Vec<(String, String)> = [
            ("credential-org-a", "regular"),
            ("credential-org-b", "regular"),
            ("rate-ended", "regular"),
            ("rate-env-sub", "unlimited"),
            ("rate-exempt", "unlimited"),
            ("rate-legacy-plan", "unlimited"),
            ("rate-org-sub", "unlimited"),
        ]
        .into_iter()
        .map(|(id, card)| (id.to_owned(), card.to_owned()))
        .collect();
        anyhow::ensure!(assigned == expected, "{assigned:?}");
        // Sessions from before credit existed are drawn from no earlier than
        // the upgrade: an open one from now, an ended one never.
        let watermarks: Vec<(String, bool)> = sqlx::query_as(
            "SELECT id, credit_drawn_through >= COALESCE(ended_at, now() - interval '1 minute') \
             FROM sandbox_running_sessions ORDER BY id",
        )
        .fetch_all(&pool)
        .await?;
        anyhow::ensure!(
            watermarks == [("rate-closed".to_owned(), true), ("rate-open".to_owned(), true)],
            "{watermarks:?}"
        );

        // A new organization starts on Regular with no balance.
        sqlx::raw_sql(
            "INSERT INTO organizations (id, name, slug, created_by) \
             VALUES ('rate-new', 'New', 'rate-new', 'credential-user-a');",
        )
        .execute(&pool)
        .await?;
        let card: String =
            sqlx::query_scalar("SELECT rate_card FROM organizations WHERE id = 'rate-new'")
                .fetch_one(&pool)
                .await?;
        anyhow::ensure!(card == "regular");
        anyhow::ensure!(balance(&pool, "rate-new").await?.is_none());

        // Each entry moves the balance; a retried entry is refused.
        sqlx::raw_sql(
            "INSERT INTO billing_credit_ledger \
               (organization_id, entry_kind, amount_nano_eur, idempotency_key, provider_object_id) \
             VALUES ('rate-new', 'grant', 50000000000, 'card_grant', 'seti_test'); \
             INSERT INTO billing_credit_ledger \
               (organization_id, entry_kind, amount_nano_eur, idempotency_key, rate_card, \
                usage_started_at, usage_ended_at) \
             VALUES ('rate-new', 'usage', -730000, 'usage:2026-10-28T12:00:00Z', 'regular', \
                     '2026-10-28 11:59:00+00', '2026-10-28 12:00:00+00'); \
             INSERT INTO billing_credit_ledger \
               (organization_id, entry_kind, amount_nano_eur, idempotency_key, actor_user_id, reason) \
             VALUES ('rate-new', 'adjustment', -1000000000, 'adjustment:1', 'credential-user-a', 'refund'); \
             INSERT INTO billing_credit_ledger \
               (organization_id, entry_kind, amount_nano_eur, idempotency_key, provider_object_id) \
             VALUES ('rate-new', 'top_up', 20000000000, 'top_up:in_test', 'in_test');",
        )
        .execute(&pool)
        .await?;
        anyhow::ensure!(
            balance(&pool, "rate-new").await? == Some(50_000_000_000 - 730_000 - 1_000_000_000 + 20_000_000_000)
        );

        // Each refusal in its own transaction.
        for (sql, code) in [
            // The same entry twice.
            (
                "INSERT INTO billing_credit_ledger \
                 (organization_id, entry_kind, amount_nano_eur, idempotency_key) \
                 VALUES ('rate-new', 'grant', 1, 'card_grant')",
                "23505",
            ),
            // A grant that takes credit, usage that adds it, a zero adjustment.
            (
                "INSERT INTO billing_credit_ledger \
                 (organization_id, entry_kind, amount_nano_eur, idempotency_key) \
                 VALUES ('rate-new', 'grant', -1, 'negative-grant')",
                "23514",
            ),
            (
                "INSERT INTO billing_credit_ledger \
                 (organization_id, entry_kind, amount_nano_eur, idempotency_key, rate_card, \
                  usage_started_at, usage_ended_at) \
                 VALUES ('rate-new', 'usage', 1, 'positive-usage', 'regular', \
                         '2026-10-28 11:00:00+00', '2026-10-28 11:01:00+00')",
                "23514",
            ),
            (
                "INSERT INTO billing_credit_ledger \
                 (organization_id, entry_kind, amount_nano_eur, idempotency_key, actor_user_id, reason) \
                 VALUES ('rate-new', 'adjustment', 0, 'zero', 'credential-user-a', 'nothing')",
                "23514",
            ),
            // Usage without its window or card; a window on another kind.
            (
                "INSERT INTO billing_credit_ledger \
                 (organization_id, entry_kind, amount_nano_eur, idempotency_key, rate_card) \
                 VALUES ('rate-new', 'usage', -1, 'no-window', 'regular')",
                "23514",
            ),
            (
                "INSERT INTO billing_credit_ledger \
                 (organization_id, entry_kind, amount_nano_eur, idempotency_key, rate_card, \
                  usage_started_at, usage_ended_at) \
                 VALUES ('rate-new', 'usage', -1, 'backwards', 'regular', \
                         '2026-10-28 11:01:00+00', '2026-10-28 11:00:00+00')",
                "23514",
            ),
            (
                "INSERT INTO billing_credit_ledger \
                 (organization_id, entry_kind, amount_nano_eur, idempotency_key, rate_card) \
                 VALUES ('rate-new', 'grant', 1, 'grant-with-card', 'regular')",
                "23514",
            ),
            // An adjustment with no actor or reason.
            (
                "INSERT INTO billing_credit_ledger \
                 (organization_id, entry_kind, amount_nano_eur, idempotency_key, reason) \
                 VALUES ('rate-new', 'adjustment', 1, 'anonymous', 'why')",
                "23514",
            ),
            (
                "INSERT INTO billing_credit_ledger \
                 (organization_id, entry_kind, amount_nano_eur, idempotency_key, actor_user_id, reason) \
                 VALUES ('rate-new', 'adjustment', 1, 'no-reason', 'credential-user-a', '')",
                "23514",
            ),
            ("UPDATE billing_credit_ledger SET amount_nano_eur = 1", "23514"),
            ("DELETE FROM billing_credit_ledger", "23514"),
            ("UPDATE billing_credit_balances SET balance_nano_eur = 0", "23514"),
            ("DELETE FROM billing_credit_balances", "23514"),
            (
                "INSERT INTO billing_credit_balances (organization_id, balance_nano_eur) \
                 VALUES ('credential-org-a', 1)",
                "23514",
            ),
            // An unknown card, a charging Unlimited, and a fourth card.
            ("UPDATE organizations SET rate_card = 'gold' WHERE id = 'rate-new'", "23503"),
            (
                "UPDATE billing_rate_cards SET cpu_nano_eur_per_vcpu_hour = 1 \
                 WHERE rate_card = 'unlimited'",
                "23514",
            ),
            (
                "UPDATE billing_rate_cards SET disk_nano_eur_per_gib_hour = -1 \
                 WHERE rate_card = 'regular'",
                "23514",
            ),
            (
                "INSERT INTO billing_rate_cards (rate_card, display_name, \
                 cpu_nano_eur_per_vcpu_hour, memory_nano_eur_per_gib_hour, \
                 disk_nano_eur_per_gib_hour) VALUES ('gold', 'Gold', 1, 1, 1)",
                "23514",
            ),
            ("UPDATE organizations SET rate_card = NULL WHERE id = 'rate-new'", "23502"),
        ] {
            let mut tx = pool.begin().await?;
            let error = sqlx::query(sql)
                .execute(&mut *tx)
                .await
                .expect_err("invalid write accepted");
            anyhow::ensure!(sqlstate(&error).as_deref() == Some(code), "{sql}: {error}");
            tx.rollback().await?;
        }
        anyhow::ensure!(
            balance(&pool, "rate-new").await? == Some(69_000_000_000 - 730_000),
            "a refused write moved the balance"
        );
        // An administrator switches a card.
        sqlx::query("UPDATE organizations SET rate_card = 'discounted' WHERE id = 'rate-new'")
            .execute(&pool)
            .await?;

        // Automatic top-up is on at EUR 20 by default; its amount is bounded.
        let top_up: (bool, i32, Option<chrono::DateTime<chrono::Utc>>) = sqlx::query_as(
            "SELECT auto_top_up_enabled, auto_top_up_cents, credit_exhausted_at \
             FROM organizations WHERE id = 'rate-new'",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(top_up == (true, 2000, None), "{top_up:?}");
        // A card grants once; one top-up is pending at a time; a paid one
        // names its invoice and a failed one its reason.
        sqlx::raw_sql(
            "INSERT INTO billing_card_grants (card_fingerprint, organization_id, setup_intent_id) \
             VALUES ('fp_1', 'rate-new', 'seti_1'); \
             INSERT INTO billing_top_ups (id, organization_id, amount_cents) \
             VALUES ('top-1', 'rate-new', 2000); \
             UPDATE billing_top_ups SET state = 'paid', stripe_invoice_id = 'in_1', \
               completed_at = now() WHERE id = 'top-1'; \
             INSERT INTO billing_top_ups (id, organization_id, amount_cents) \
             VALUES ('top-2', 'rate-new', 2000);",
        )
        .execute(&pool)
        .await?;
        for (sql, code) in [
            ("UPDATE organizations SET auto_top_up_cents = 499 WHERE id = 'rate-new'", "23514"),
            ("UPDATE organizations SET auto_top_up_cents = 100001 WHERE id = 'rate-new'", "23514"),
            (
                "INSERT INTO billing_card_grants (card_fingerprint, organization_id, setup_intent_id) \
                 VALUES ('fp_1', 'credential-org-a', 'seti_2')",
                "23505",
            ),
            (
                "INSERT INTO billing_top_ups (organization_id, amount_cents) VALUES ('rate-new', 2000)",
                "23505",
            ),
            (
                "UPDATE billing_top_ups SET state = 'paid', completed_at = now() WHERE id = 'top-2'",
                "23514",
            ),
            (
                "UPDATE billing_top_ups SET state = 'failed', completed_at = now(), \
                 failure_code = 'Card Declined' WHERE id = 'top-2'",
                "23514",
            ),
        ] {
            let mut tx = pool.begin().await?;
            let error = sqlx::query(sql)
                .execute(&mut *tx)
                .await
                .expect_err("invalid write accepted");
            anyhow::ensure!(sqlstate(&error).as_deref() == Some(code), "{sql}: {error}");
            tx.rollback().await?;
        }
        sqlx::query(
            "UPDATE billing_top_ups SET state = 'failed', completed_at = now(), \
             failure_code = 'card_declined' WHERE id = 'top-2'",
        )
        .execute(&pool)
        .await?;

        // Deleting the organization deletes its ledger and balance.
        sqlx::query("DELETE FROM organizations WHERE id = 'rate-new'")
            .execute(&pool)
            .await?;
        let left: (i64, i64) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM billing_credit_ledger), \
                    (SELECT count(*) FROM billing_credit_balances)",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(left == (0, 0), "{left:?}");
        // Its top-ups go too, but the card's grant stays, unowned.
        let kept: (i64, i64) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM billing_top_ups), \
                    (SELECT count(*) FROM billing_card_grants WHERE organization_id IS NULL)",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(kept == (0, 1), "{kept:?}");

        // Rollback: dropping what 0006 added restores the 0005 schema.
        sqlx::raw_sql(
            "DROP TABLE billing_top_ups; \
             DROP TABLE billing_card_grants; \
             ALTER TABLE organizations DROP COLUMN credit_exhausted_at, \
               DROP COLUMN auto_top_up_cents, DROP COLUMN auto_top_up_enabled; \
             DROP INDEX sandbox_running_sessions_credit_due_idx; \
             ALTER TABLE sandbox_running_sessions DROP COLUMN credit_drawn_through; \
             DROP TABLE billing_credit_balances; \
             DROP TABLE billing_credit_ledger; \
             ALTER TABLE organizations DROP COLUMN rate_card; \
             DROP TABLE billing_rate_cards; \
             DROP FUNCTION codewire_billing_credit_balance_derived(); \
             DROP FUNCTION codewire_billing_credit_ledger_apply(); \
             DROP FUNCTION codewire_billing_credit_ledger_immutable();",
        )
        .execute(&pool)
        .await?;
        anyhow::ensure!(fingerprint(&pool).await? == previous);
        let functions: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_proc WHERE proname LIKE 'codewire_billing_credit%'",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(functions == 0);
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}
