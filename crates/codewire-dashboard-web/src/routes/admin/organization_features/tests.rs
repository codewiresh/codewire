use super::*;

/// A settings form: each switch as (the value the page showed, if it could
/// read it; the box checked now).
fn submission(
    confidential: (Option<bool>, bool),
    systemd: (Option<bool>, bool),
    standard: (Option<bool>, bool),
    dedicated_cpu: (Option<bool>, bool),
    agent_chat: (Option<bool>, bool),
) -> FeaturesSubmission {
    let checked = |on: bool| on.then(|| "on".to_owned());
    FeaturesSubmission {
        csrf: "c".into(),
        organization_id: "org_a".into(),
        organization_slug: "a".into(),
        confidential_was: confidential.0,
        confidential: checked(confidential.1),
        systemd_was: systemd.0,
        systemd: checked(systemd.1),
        standard_was: standard.0,
        standard: checked(standard.1),
        dedicated_cpu_was: dedicated_cpu.0,
        dedicated_cpu: checked(dedicated_cpu.1),
        agent_chat_was: agent_chat.0,
        agent_chat: checked(agent_chat.1),
    }
}

#[test]
fn only_the_switches_whose_box_differs_from_the_page_are_changed() {
    // Nothing changed: every box as the page showed it.
    let unchanged = submission(
        (Some(true), true),
        (Some(false), false),
        (Some(false), false),
        (Some(true), true),
        (Some(false), false),
    );
    assert_eq!(changes(&unchanged), []);

    // Three boxes changed, in the list's order.
    let moved = submission(
        (Some(true), true),
        (Some(false), false),
        (Some(false), true),
        (Some(true), false),
        (Some(false), true),
    );
    assert_eq!(
        changes(&moved),
        [
            (Feature::Standard, true),
            (Feature::DedicatedCpu, false),
            (Feature::AgentChat, true),
        ]
    );
}

#[test]
fn a_switch_the_page_could_not_read_is_never_changed() {
    // No value shown for confidential or standard: their boxes are ignored.
    let partial = submission(
        (None, true),
        (Some(true), false),
        (None, true),
        (Some(false), false),
        (Some(false), false),
    );
    assert_eq!(changes(&partial), [(Feature::Systemd, false)]);
}
