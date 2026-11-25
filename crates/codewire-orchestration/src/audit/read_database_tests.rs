//! The audit log's read against PostgreSQL (#6189, SPEC "Who reads what" and
//! "The API read"): owners and admins read every Sandbox's events, a deleted
//! one's by id; a member reads one they can open; anyone else is told it
//! doesn't exist. Events come newest first from both tables, by kind and
//! page; a grouped read sums a subject across hours and is rate limited.

use anyhow::{Result, ensure};
use chrono::{DurationRound as _, TimeDelta, Utc};
use codewire_egress_policy::lease::RefusalReason;
use codewire_server_core::AppError;
use codewire_server_core::auth::AuthUser;
use sqlx::PgPool;

use super::read::{self, EnvironmentRef, Page, Query};
use super::store::{self, Event};
use super::*;
use crate::test_database_support::TestDatabase;

const ORG: &str = "audit-read-org";
const OTHER_ORG: &str = "audit-read-other";
const ENV: &str = "550e8400-e29b-41d4-a716-446655446190";
const OWNER: &str = "fixture-admin";
const MEMBER: &str = "audit-member";
const OUTSIDER: &str = "audit-outsider";

fn user(id: &str) -> AuthUser {
    AuthUser {
        user_id: id.into(),
        org_id: None,
        is_admin: false,
        via_api_key: false,
    }
}

fn query(environment: EnvironmentRef) -> Query {
    Query {
        org_id: ORG.into(),
        environment,
        kinds: Vec::new(),
        since: None,
        until: None,
        limit: 0,
        cursor: None,
        grouped: false,
    }
}

async fn page(pool: &PgPool, who: &str, query: &Query) -> std::result::Result<Page, AppError> {
    let reader = user(who);
    let environment = read::authorize(pool, &reader, query).await?;
    read::read(pool, &reader, query, environment).await
}

/// The organization's Sandbox `walk-audit`, made by the owner; a member of
/// the organization with no grant; and a member of another organization.
async fn seed(database: &TestDatabase) -> Result<()> {
    database.organization(ORG).await?;
    database.organization(OTHER_ORG).await?;
    for id in [MEMBER, OUTSIDER] {
        database.user(id).await?;
    }
    let pool = &database.pool;
    sqlx::raw_sql(&format!(
        "INSERT INTO org_members (id, org_id, user_id, role) VALUES \
           ('m-1', '{ORG}', '{MEMBER}', 'member'), ('m-2', '{OTHER_ORG}', '{OUTSIDER}', 'member'); \
         INSERT INTO environment_presets (id, org_id, name, slug, project_spec) \
         VALUES ('audit-preset', '{ORG}', 'P', 'p', \
           '{{\"schema_version\":1,\"working_directory\":\"/workspace\"}}'::jsonb); \
         INSERT INTO environments (id, org_id, created_by, preset_id, name, type, state, \
           desired_state, project_spec) \
         VALUES ('{ENV}', '{ORG}', '{OWNER}', 'audit-preset', 'walk-audit', 'sandbox', \
           'running', 'started', \
           '{{\"schema_version\":1,\"working_directory\":\"/workspace\"}}'::jsonb);"
    ))
    .execute(pool)
    .await?;
    store::ensure_partitions(pool).await?;
    Ok(())
}

async fn record(pool: &PgPool, event: &Event) -> Result<()> {
    let mut connection = pool.acquire().await?;
    super::record(&mut connection, event).await?;
    Ok(())
}

fn refusal(destination: &str) -> What {
    What::Refused(Refusal {
        destination: Some(destination.into()),
        withheld: false,
        address: None,
        port: Some(443),
        protocol: Protocol::Tcp,
        reason: RefusalReason::NameNotAllowed,
        source: RefusalSource::Network,
        policy: None,
        revision: None,
    })
}

fn not_found(result: &std::result::Result<Page, AppError>) -> bool {
    matches!(result, Err(AppError::NotFound(_)))
}

macro_rules! database_case {
    ($name:ident, $database:ident, $pool:ident, $body:block) => {
        #[tokio::test]
        #[ignore = "requires checked-in disposable TEST_DATABASE_URL"]
        async fn $name() -> Result<()> {
            let $database = TestDatabase::create().await?;
            let result = async {
                seed(&$database).await?;
                let $pool = &$database.pool;
                $body
                Ok(())
            }
            .await;
            $database.finish(result).await
        }
    };
}

database_case!(
    db_events_come_newest_first_from_both_tables_by_kind_and_page,
    database,
    pool,
    {
        let at = |minutes| Utc::now() - TimeDelta::minutes(minutes);
        record(
            pool,
            &Event::once(
                ORG,
                ENV,
                Actor::Platform,
                at(30),
                What::Lifecycle(Lifecycle::Started),
            ),
        )
        .await?;
        record(
            pool,
            &Event::once(ORG, ENV, Actor::Sandbox, at(20), refusal("pypi.org")),
        )
        .await?;
        record(
            pool,
            &Event::once(
                ORG,
                ENV,
                Actor::Platform,
                at(10),
                What::Lifecycle(Lifecycle::Started),
            ),
        )
        .await?;

        let all = page(
            pool,
            OWNER,
            &query(EnvironmentRef::Name("walk-audit".into())),
        )
        .await?;
        let kinds: Vec<&str> = all.events.iter().map(|event| event.kind.as_str()).collect();
        ensure!(kinds == ["lifecycle", "refused", "lifecycle"], "{kinds:?}");
        ensure!(all.next_cursor.is_none() && all.environment.name == "walk-audit");

        let mut refused = query(EnvironmentRef::Id(ENV.into()));
        refused.kinds = vec![Kind::Refused];
        let refused = page(pool, OWNER, &refused).await?;
        ensure!(refused.events.len() == 1 && refused.events[0].kind == "refused");

        let mut first = query(EnvironmentRef::Id(ENV.into()));
        first.limit = 2;
        let first_page = page(pool, OWNER, &first).await?;
        ensure!(first_page.events.len() == 2);
        first.cursor = first_page.next_cursor.clone();
        ensure!(first.cursor.is_some(), "a cursor to the third event");
        let second_page = page(pool, OWNER, &first).await?;
        ensure!(second_page.events.len() == 1 && second_page.next_cursor.is_none());
        ensure!(second_page.events[0].first_at < first_page.events[1].first_at);

        let mut too_many = query(EnvironmentRef::Id(ENV.into()));
        too_many.limit = 1_001;
        ensure!(matches!(
            page(pool, OWNER, &too_many).await,
            Err(AppError::BadRequest(_))
        ));
    }
);

database_case!(
    db_a_member_reads_only_a_sandbox_they_can_open,
    database,
    pool,
    {
        let by_name = query(EnvironmentRef::Name("walk-audit".into()));
        ensure!(
            not_found(&page(pool, MEMBER, &by_name).await),
            "no grant, no read"
        );
        sqlx::query(
            "INSERT INTO environment_access (id, environment_id, user_id, permission, granted_by) \
         VALUES ('g-1', $1, $2, 'operator', $3)",
        )
        .bind(ENV)
        .bind(MEMBER)
        .bind(OWNER)
        .execute(pool)
        .await?;
        page(pool, MEMBER, &by_name).await?;
        ensure!(
            not_found(&page(pool, OUTSIDER, &by_name).await),
            "another organization"
        );
        let mut theirs = query(EnvironmentRef::Id(ENV.into()));
        theirs.org_id = OTHER_ORG.into();
        ensure!(
            not_found(&page(pool, OUTSIDER, &theirs).await),
            "named under their own org"
        );
    }
);

database_case!(
    db_a_deleted_sandbox_is_read_by_id_by_owners_only,
    database,
    pool,
    {
        sqlx::query(
            "INSERT INTO environment_access (id, environment_id, user_id, permission, granted_by) \
         VALUES ('g-1', $1, $2, 'operator', $3)",
        )
        .bind(ENV)
        .bind(MEMBER)
        .bind(OWNER)
        .execute(pool)
        .await?;
        sqlx::query("UPDATE environments SET state = 'destroyed' WHERE id = $1")
            .bind(ENV)
            .execute(pool)
            .await?;
        let by_id = query(EnvironmentRef::Id(ENV.into()));
        let owners = page(pool, OWNER, &by_id).await?;
        ensure!(owners.environment.deleted);
        ensure!(
            not_found(&page(pool, MEMBER, &by_id).await),
            "a member can't open it now"
        );
        ensure!(
            not_found(
                &page(
                    pool,
                    OWNER,
                    &query(EnvironmentRef::Name("walk-audit".into()))
                )
                .await
            ),
            "a deleted Sandbox has no name to read by"
        );
    }
);

database_case!(
    db_a_grouped_read_sums_a_subject_across_hours_and_is_rate_limited,
    database,
    pool,
    {
        let hour = (Utc::now() - TimeDelta::hours(3)).duration_trunc(TimeDelta::hours(1))?;
        for (offset, count) in [(0, 5), (1, 7)] {
            let mut event = Event::once(
                ORG,
                ENV,
                Actor::Sandbox,
                hour + TimeDelta::hours(offset) + TimeDelta::minutes(5),
                refusal("crates.io"),
            );
            event.count = count;
            record(pool, &event).await?;
        }
        record(
            pool,
            &Event::once(ORG, ENV, Actor::Sandbox, hour, refusal("pypi.org")),
        )
        .await?;
        store::flush(pool, crate::lease_owner::INCARNATION_GRACE).await?;

        let mut grouped = query(EnvironmentRef::Id(ENV.into()));
        grouped.grouped = true;
        grouped.kinds = vec![Kind::Refused];
        let answer = page(pool, OWNER, &grouped).await?;
        ensure!(answer.events.len() == 2 && answer.left_out == 0);
        let crates = &answer.events[0];
        ensure!(crates.count == 12, "summed across hours: {}", crates.count);
        ensure!(
            crates.first_at < hour + TimeDelta::hours(1),
            "the earliest start"
        );

        // An hour's overflow is counted in `left_out`, never listed.
        sqlx::query(
            "INSERT INTO sandbox_audit_events (org_id, environment_id, kind, action, subject, \
         first_at, last_at, count, actor_type, detail) VALUES ($1, $2, 'refused', 'overflow', \
         'overflow', $3, $3, 400, 'sandbox', '{\"subjects\": 37, \"at_least\": false}')",
        )
        .bind(ORG)
        .bind(ENV)
        .bind(hour + TimeDelta::minutes(30))
        .execute(pool)
        .await?;
        let answer = page(pool, OWNER, &grouped).await?;
        ensure!(
            answer.events.len() == 2 && answer.left_out == 37,
            "{}",
            answer.left_out
        );

        for _ in 2..30 {
            page(pool, OWNER, &grouped).await?;
        }
        let refused = page(pool, OWNER, &grouped).await;
        ensure!(
            matches!(
                &refused,
                Err(AppError::Coded {
                    code: "rate_limited",
                    ..
                })
            ),
            "the 31st grouped read in a minute is refused: {:?}",
            refused.as_ref().err()
        );
    }
);

database_case!(
    db_a_refusal_the_current_revision_allows_names_the_first_that_did,
    database,
    pool,
    {
        use crate::api::network_policies::{
            RuleInput, Selector, create_policy, select_for_environment, update_policy,
        };
        let owner = user(OWNER);
        let docs = [RuleInput {
            target: "docs.rs",
            ports: &[443],
        }];
        let policy = create_policy(pool, &owner, ORG, "walk-docs", None, &docs).await?;
        select_for_environment(pool, &owner, ORG, ENV, "walk-docs").await?;
        let refused_under_one = |destination: &str| Refusal {
            destination: Some(destination.into()),
            withheld: false,
            address: None,
            port: Some(443),
            protocol: Protocol::Tcp,
            reason: RefusalReason::NameNotAllowed,
            source: RefusalSource::Network,
            policy: Some("walk-docs".into()),
            revision: Some(1),
        };
        let crates = refused_under_one("crates.io");
        let pypi = refused_under_one("pypi.org");
        let crates_allowed = [RuleInput {
            target: "crates.io",
            ports: &[443],
        }];
        update_policy(
            pool,
            &owner,
            ORG,
            Selector::Id(&policy.id),
            &crates_allowed,
            &[],
            Some(1),
        )
        .await?;
        let selected = super::allowed_since::Selected {
            id: policy.id.clone(),
            name: "walk-docs".into(),
            current: 2,
        };
        let allowed = super::allowed_since::allowed_since(
            pool,
            &selected,
            &[("crates", &crates), ("pypi", &pypi)],
        )
        .await?;
        ensure!(allowed.get("crates") == Some(&2), "{allowed:?}");
        ensure!(
            !allowed.contains_key("pypi"),
            "pypi.org is still refused: {allowed:?}"
        );
    }
);

database_case!(
    db_a_grouped_read_lists_the_newest_thousand_subjects_and_counts_the_rest,
    database,
    pool,
    {
        sqlx::query(
            "INSERT INTO sandbox_audit_events (org_id, environment_id, kind, action, subject, \
         first_at, last_at, count, actor_type, detail) \
         SELECT $1, $2, 'refused', 'refused', 'host-' || n, \
                now() - make_interval(mins => n), now() - make_interval(mins => n), 1, 'sandbox', \
                jsonb_build_object('destination', 'host-' || n || '.example', 'withheld', false, \
                  'address', null, 'port', 443, 'protocol', 'tcp', \
                  'reason', 'name_not_allowed', 'source', 'network', 'policy', null, \
                  'revision', null) \
           FROM generate_series(1, 1001) AS n",
        )
        .bind(ORG)
        .bind(ENV)
        .execute(pool)
        .await?;
        let mut grouped = query(EnvironmentRef::Id(ENV.into()));
        grouped.grouped = true;
        let answer = page(pool, OWNER, &grouped).await?;
        ensure!(answer.events.len() == 1_000, "{}", answer.events.len());
        ensure!(answer.left_out == 1, "{}", answer.left_out);
        ensure!(
            answer
                .events
                .iter()
                .all(|event| event.detail["destination"] != "host-1001.example"),
            "the oldest subject is the one left out"
        );
    }
);
