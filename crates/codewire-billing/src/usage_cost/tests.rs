use chrono::Duration;

use super::*;
use crate::credit::draw_organization;

const REGULAR: Rates = Rates {
    cpu_per_vcpu_hour: 43_800_000,
    memory_per_gib_hour: 14_100_000,
    disk_per_gib_hour: 87_000,
};

fn window(cpu_millicores: i32, memory_mib: i32, disk_gib: i32, seconds: i64) -> SessionWindow {
    SessionWindow {
        cpu_millicores,
        memory_mib,
        disk_gib,
        microseconds: seconds * 1_000_000,
    }
}

#[test]
fn a_sandbox_costs_its_sessions_and_its_hour_is_at_its_largest_size() {
    let cost = sandbox_cost(
        "env".into(),
        "Env".into(),
        REGULAR,
        &[window(2000, 8192, 10, 1800), window(4000, 8192, 10, 1800)],
    );
    // Half an hour at 2 vCPU and half at 4: three vCPU-hours of 43.8 m
    // halved, plus a full hour of 8 GiB and 10 GiB.
    assert_eq!(cost.running_seconds, 3600);
    assert_eq!(cost.cost_nano_eur, 131_400_000 + 112_800_000 + 870_000);
    assert_eq!((cost.cpu_millicores, cost.memory_mib), (4000, 8192));
    assert_eq!(cost.hourly_nano_eur, 175_200_000 + 112_800_000 + 870_000);
}

#[test]
fn a_short_run_costs_a_fraction_of_a_cent_not_nothing() {
    // #3954: a five-minute run showed EUR 0.00 in whole cents.
    let cost = sandbox_cost(
        "env".into(),
        "Env".into(),
        REGULAR,
        &[window(2000, 8192, 80, 302)],
    );
    // 2 x 43.8 m + 8 x 14.1 m + 80 x 0.087 m = 207.36 m an hour, for 302 s.
    assert_eq!(cost.cost_nano_eur, 17_395_200);
}

async fn test_pool() -> Option<PgPool> {
    let url = match std::env::var("DATABASE_URL") {
        Ok(url) if !url.is_empty() => url,
        _ => {
            eprintln!("DATABASE_URL unset; skipping the usage cost database flow");
            return None;
        }
    };
    Some(
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .expect("connect usage cost test database"),
    )
}

struct Fixture {
    organization_id: String,
    user_id: String,
}

async fn seed(pool: &PgPool, rate_card: &str) -> Fixture {
    let namespace: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
        .fetch_one(pool)
        .await
        .unwrap();
    let fixture = Fixture {
        organization_id: format!("org_usage_{namespace}"),
        user_id: format!("u_usage_{namespace}"),
    };
    sqlx::query("INSERT INTO users (id, email) VALUES ($1, $2)")
        .bind(&fixture.user_id)
        .bind(format!("{namespace}@example.test"))
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO organizations (id, name, slug, created_by, rate_card) \
         VALUES ($1, 'Usage', $2, $3, $4)",
    )
    .bind(&fixture.organization_id)
    .bind(format!("usage-{}", &namespace[..8]))
    .bind(&fixture.user_id)
    .bind(rate_card)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO environment_presets (id, org_id, name, build_status, project_spec) \
         VALUES ($1, $1, 'Preset', 'ready', '{}'::jsonb)",
    )
    .bind(&fixture.organization_id)
    .execute(pool)
    .await
    .unwrap();
    fixture
}

/// A sandbox with one session of `cpu_millicores` that started `started`
/// ago, was last observed `observed` ago and, when `ended` is set, ended
/// that long ago.
async fn session(
    pool: &PgPool,
    fixture: &Fixture,
    name: &str,
    cpu_millicores: i32,
    started: &str,
    observed: &str,
    ended: Option<&str>,
) {
    let environment_id = format!("{}-{name}", fixture.organization_id);
    sqlx::query(
        "INSERT INTO environments (id, org_id, created_by, type, preset_id, project_spec, name) \
         VALUES ($1, $2, $3, 'sandbox', $2, '{}'::jsonb, $4)",
    )
    .bind(&environment_id)
    .bind(&fixture.organization_id)
    .bind(&fixture.user_id)
    .bind(name)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO sandbox_running_sessions \
           (id, environment_id, organization_id, runtime_uid, runtime_name, \
            runtime_namespace, cpu_millicores, memory_mib, disk_gib, started_at, \
            last_observed_at, ended_at) \
         VALUES ($1, $1, $2, $1, $1, 'ns', $3, 8192, 10, now() - $4::interval, \
                 now() - $5::interval, now() - $6::interval)",
    )
    .bind(&environment_id)
    .bind(&fixture.organization_id)
    .bind(cpu_millicores)
    .bind(started)
    .bind(observed)
    .bind(ended)
    .execute(pool)
    .await
    .unwrap();
}

async fn cleanup(pool: &PgPool, fixture: Fixture) {
    for table in ["environments", "environment_presets"] {
        sqlx::query(&format!("DELETE FROM {table} WHERE org_id = $1"))
            .bind(&fixture.organization_id)
            .execute(pool)
            .await
            .unwrap();
    }
    sqlx::query("DELETE FROM organizations WHERE id = $1")
        .bind(&fixture.organization_id)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(&fixture.user_id)
        .execute(pool)
        .await
        .unwrap();
}

/// Seeds three hours of usage: one sandbox that ran two hours and ended an
/// hour ago, and one at twice the CPU that has run for 90 minutes and was
/// last observed a minute ago.
async fn seed_usage(pool: &PgPool, rate_card: &str) -> Fixture {
    let fixture = seed(pool, rate_card).await;
    session(
        pool,
        &fixture,
        "done",
        2000,
        "3 hours",
        "1 hour",
        Some("1 hour"),
    )
    .await;
    session(pool, &fixture, "open", 4000, "90 minutes", "1 minute", None).await;
    fixture
}

#[tokio::test]
async fn db_each_sandbox_and_each_hour_add_up_to_what_credit_drew() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let fixture = seed_usage(&pool, "regular").await;
    let org = fixture.organization_id.clone();
    let drawn = draw_organization(&pool, &org).await.unwrap();
    assert!(drawn > 0);

    let now = Utc::now();
    let month_start = now - Duration::days(1);
    let rates = charged_rates(&pool, &org).await.unwrap();
    assert_eq!(rates, REGULAR);
    assert_eq!(
        month_usage_nano_eur(&pool, &org, month_start)
            .await
            .unwrap(),
        drawn
    );

    let sandboxes = sandbox_costs(&pool, &org, rates, month_start, now)
        .await
        .unwrap();
    let names: Vec<&str> = sandboxes.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, ["done", "open"], "longest first");
    assert_eq!(sandboxes[0].running_seconds, 7200);
    // Each is rounded down on its own, the draw once over both.
    let sum: i64 = sandboxes.iter().map(|s| s.cost_nano_eur).sum();
    assert!((drawn - 1..=drawn).contains(&sum), "{sum} vs drawn {drawn}");

    let hours = hourly_costs(&pool, &org, rates, now - Duration::hours(72), now)
        .await
        .unwrap();
    assert!((3..=4).contains(&hours.len()), "{} hours", hours.len());
    let sum: i64 = hours.iter().map(|h| h.cost_nano_eur).sum();
    let slack = hours.len() as i64 + 1;
    assert!(
        (drawn - slack..=drawn).contains(&sum),
        "{sum} vs drawn {drawn}"
    );
    let cpu_hours: f64 = hours.iter().map(|h| h.cpu_hours).sum();
    // 2 h at 2 vCPU and 89 minutes at 4.
    assert!(
        (cpu_hours - (4.0 + 4.0 * 89.0 / 60.0)).abs() < 0.01,
        "{cpu_hours}"
    );

    cleanup(&pool, fixture).await;
}

#[tokio::test]
async fn db_discounted_shows_its_card_and_unlimited_shows_time_but_no_cost() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let now = Utc::now();
    let month_start = now - Duration::days(1);

    let discounted = seed_usage(&pool, "discounted").await;
    let org = discounted.organization_id.clone();
    let drawn = draw_organization(&pool, &org).await.unwrap();
    let rates = charged_rates(&pool, &org).await.unwrap();
    assert!(rates.cpu_per_vcpu_hour < REGULAR.cpu_per_vcpu_hour);
    let sandboxes = sandbox_costs(&pool, &org, rates, month_start, now)
        .await
        .unwrap();
    let sum: i64 = sandboxes.iter().map(|s| s.cost_nano_eur).sum();
    assert!((drawn - 1..=drawn).contains(&sum), "{sum} vs drawn {drawn}");
    cleanup(&pool, discounted).await;

    let unlimited = seed_usage(&pool, "unlimited").await;
    let org = unlimited.organization_id.clone();
    assert_eq!(draw_organization(&pool, &org).await.unwrap(), 0);
    let rates = charged_rates(&pool, &org).await.unwrap();
    let sandboxes = sandbox_costs(&pool, &org, rates, month_start, now)
        .await
        .unwrap();
    assert_eq!(sandboxes.len(), 2);
    assert!(sandboxes.iter().all(|s| s.running_seconds > 0));
    assert!(
        sandboxes
            .iter()
            .all(|s| s.cost_nano_eur == 0 && s.hourly_nano_eur == 0)
    );
    let hours = hourly_costs(&pool, &org, rates, now - Duration::hours(72), now)
        .await
        .unwrap();
    assert!(!hours.is_empty() && hours.iter().all(|h| h.cost_nano_eur == 0));
    assert_eq!(
        month_usage_nano_eur(&pool, &org, month_start)
            .await
            .unwrap(),
        0
    );
    cleanup(&pool, unlimited).await;
}

#[tokio::test]
async fn db_usage_before_the_month_is_not_this_months() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let fixture = seed_usage(&pool, "regular").await;
    let org = fixture.organization_id.clone();
    let now = Utc::now();
    // The month started two hours ago: "done" ran one hour of it.
    let sandboxes = sandbox_costs(&pool, &org, REGULAR, now - Duration::hours(2), now)
        .await
        .unwrap();
    let done = sandboxes.iter().find(|s| s.name == "done").unwrap();
    assert!(
        (3599..=3601).contains(&done.running_seconds),
        "{}",
        done.running_seconds
    );
    cleanup(&pool, fixture).await;
}
