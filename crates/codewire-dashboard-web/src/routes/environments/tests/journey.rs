//! The Sandbox page while a Sandbox starts (#3772): the step list, marked as
//! starting so the page follows a restart without replaying an earlier run.

use super::*;

const STARTING: &str = "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee";

#[test]
fn a_stopped_sandbox_being_started_shows_the_starting_list() {
    let organization = test_organization();
    let page = render_terminal(
        &organization,
        crate::view::EnvironmentRow {
            state: "stopped",
            desired_state: "started",
            ..resize_test_row(STARTING, 1_000, 2_048)
        },
    );
    assert!(page.contains("data-kind=\"setup\""));
    assert!(page.contains("data-setup-progress data-setup-starting data-setup-since=\""));
    assert!(page.contains(&format!("data-setup-environment-id=\"{STARTING}\"")));
    // No banner and no centred repeat: the notice text stays hidden.
    assert!(!page.contains("data-kind=\"banner\""));
    // The window and bar wait for the script, so a page without it shows no
    // empty block.
    assert!(page.contains("data-setup-window hidden>"));
    assert!(page.contains("data-setup-bar hidden>"));
}

#[test]
fn a_running_sandbox_in_setup_is_not_marked_starting() {
    let organization = test_organization();
    let page = render_terminal(
        &organization,
        crate::view::EnvironmentRow {
            setup_running: true,
            ..resize_test_row(STARTING, 1_000, 2_048)
        },
    );
    assert!(page.contains("data-setup-progress data-setup-environment-id"));
    assert!(!page.contains("data-setup-starting"));
}

/// A Retry setup that started (#4767), as its route returns it and the page
/// then renders: the step list follows it from when it was asked for, also
/// while the failure still shows, since a quick retry can finish before the
/// page renders. The time means nothing once the Sandbox stops.
#[test]
fn a_page_returning_from_a_retry_follows_it_from_when_it_was_asked_for() {
    let organization = test_organization();
    let asked_at = chrono::DateTime::parse_from_rfc3339("2026-10-06T10:00:00.25Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let location = crate::routes::setup_retry::retried_path(
        &format!("/{}/{STARTING}/?list_state=running", organization.slug),
        asked_at,
    );
    let axum::extract::Query(query) =
        axum::extract::Query::<crate::routes::terminal::TerminalQuery>::try_from_uri(
            &location.parse().unwrap(),
        )
        .unwrap();
    let render = |row: crate::view::EnvironmentRow| {
        let since = query.setup_retry_since(&row);
        render_terminal_with(&organization, row, since)
    };
    // Still running, or already done before the page rendered.
    for setup_running in [true, false] {
        let page = render(crate::view::EnvironmentRow {
            setup_running,
            ..resize_test_row(STARTING, 1_000, 2_048)
        });
        assert!(
            page.contains(
                " data-setup-progress data-setup-retry data-setup-since=\"2026-10-06T10:00:00.250Z\""
            ),
            "{setup_running}"
        );
        assert!(page.contains("<h2 id=\"setup-progress-title\">Starting your Sandbox</h2>"));
    }
    // The failure still shows: the retry hasn't claimed its setup yet, or
    // failed again. Either way its run is the one after the asked-for time.
    let failure_shown = render(crate::view::EnvironmentRow {
        setup_failure: "Setup failed at Running install command: workspace exec exited 1".into(),
        ..resize_test_row(STARTING, 1_000, 2_048)
    });
    assert!(failure_shown.contains(
        " data-setup-progress data-setup-retry data-setup-since=\"2026-10-06T10:00:00.250Z\""
    ));
    let stopped = render(crate::view::EnvironmentRow {
        state: "stopped",
        ..resize_test_row(STARTING, 1_000, 2_048)
    });
    assert!(!stopped.contains("data-setup-retry"));
}
