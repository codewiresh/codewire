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
    assert!(page.contains(&format!(
        "data-setup-progress data-setup-starting data-setup-environment-id=\"{STARTING}\""
    )));
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
