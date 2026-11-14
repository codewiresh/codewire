//! A create the platform ended is destroyed at once, so the default list
//! leaves it out. A caller that asks for failed creates sees it for
//! `FAILED_CREATE_LISTED_HOURS`, and no caller sees it otherwise (#4482).

use super::*;
use crate::api::runtime_lease_test_support::LeaseFixture;

/// One destroyed environment of the fixture's organization.
struct Destroyed<'a> {
    suffix: &'a str,
    error_code: Option<&'a str>,
    ran: bool,
    hours_ago: i32,
}

impl Destroyed<'_> {
    async fn insert(&self, fixture: &LeaseFixture) -> String {
        let id = format!("{}-{}", fixture.id, self.suffix);
        sqlx::query(
            "INSERT INTO environments \
                 (id, org_id, created_by, type, state, desired_state, preset_id, project_spec, \
                  environment_operation_generation, error_code, error_reason, started_at, \
                  destroyed_at, state_changed_at) \
             SELECT $1, e.org_id, e.created_by, e.type, 'destroyed', 'destroyed', e.preset_id, \
                    e.project_spec, 1, $3, 'why it ended', \
                    CASE WHEN $4 THEN NOW() - make_interval(hours => $5 + 1) END, \
                    NOW() - make_interval(hours => $5), NOW() - make_interval(hours => $5) \
             FROM environments e WHERE e.id = $2",
        )
        .bind(&id)
        .bind(&fixture.id)
        .bind(self.error_code)
        .bind(self.ran)
        .bind(self.hours_ago)
        .execute(&fixture.pool)
        .await
        .unwrap();
        id
    }
}

async fn listed(fixture: &LeaseFixture, q: ListEnvironmentsQuery) -> Vec<String> {
    let mut ids: Vec<String> = list_environment_rows(&fixture.pool, &fixture.id, &q)
        .await
        .unwrap()
        .into_iter()
        .map(|environment| environment.id)
        .collect();
    ids.sort();
    ids
}

fn query(include_failed_creates: bool) -> ListEnvironmentsQuery {
    ListEnvironmentsQuery {
        env_type: String::new(),
        state: String::new(),
        include_destroyed: false,
        include_failed_creates,
    }
}

#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL; run by the database capability gate"]
async fn db_a_failed_create_is_listed_for_a_day_and_only_on_request() {
    let fixture = LeaseFixture::seed("synthetic-failed-create-listing").await;
    let live = fixture.id.clone();
    let no_capacity = Destroyed {
        suffix: "no-capacity",
        error_code: Some(crate::lifecycle::NO_CAPACITY_ERROR_CODE),
        ran: false,
        hours_ago: 1,
    }
    .insert(&fixture)
    .await;
    let start_failed = Destroyed {
        suffix: "start-failed",
        error_code: Some(crate::lifecycle::CONTAINER_START_FAILED_ERROR_CODE),
        ran: false,
        hours_ago: FAILED_CREATE_LISTED_HOURS - 1,
    }
    .insert(&fixture)
    .await;
    // None of these is a recent failed create: too old, removed by its user,
    // ended for another reason, or one that ran before it was destroyed.
    let mut others = Vec::new();
    for other in [
        Destroyed {
            suffix: "aged-out",
            error_code: Some(crate::lifecycle::CONTAINER_START_FAILED_ERROR_CODE),
            ran: false,
            hours_ago: FAILED_CREATE_LISTED_HOURS + 1,
        },
        Destroyed {
            suffix: "removed",
            error_code: None,
            ran: false,
            hours_ago: 1,
        },
        Destroyed {
            suffix: "other-error",
            error_code: Some("sandbox_restarted"),
            ran: false,
            hours_ago: 1,
        },
        Destroyed {
            suffix: "ran",
            error_code: Some(crate::lifecycle::NO_CAPACITY_ERROR_CODE),
            ran: true,
            hours_ago: 1,
        },
    ] {
        others.push(other.insert(&fixture).await);
    }

    assert_eq!(
        listed(&fixture, query(false)).await,
        std::slice::from_ref(&live),
        "a caller that did not ask sees no destroyed environment"
    );
    let mut wanted = vec![live.clone(), no_capacity.clone(), start_failed.clone()];
    wanted.sort();
    assert_eq!(listed(&fixture, query(true)).await, wanted);

    let failed = list_environment_rows(&fixture.pool, &fixture.id, &query(true))
        .await
        .unwrap()
        .into_iter()
        .find(|environment| environment.id == start_failed)
        .unwrap();
    assert_eq!(failed.state, "destroyed", "the row keeps its true state");
    assert_eq!(
        failed.error_code.as_deref(),
        Some(crate::lifecycle::CONTAINER_START_FAILED_ERROR_CODE)
    );
    assert_eq!(failed.error_reason.as_deref(), Some("why it ended"));

    // A state filter is exact, so asking for failed creates adds nothing to it.
    let running = ListEnvironmentsQuery {
        state: "running".into(),
        ..query(true)
    };
    assert_eq!(listed(&fixture, running).await, [live]);

    for id in [no_capacity, start_failed].iter().chain(&others) {
        sqlx::query("DELETE FROM environments WHERE id = $1")
            .bind(id)
            .execute(&fixture.pool)
            .await
            .unwrap();
    }
    fixture.cleanup().await;
}
