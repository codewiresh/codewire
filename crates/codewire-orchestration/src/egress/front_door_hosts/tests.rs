use codewire_access::ManagedCredentialClients;

use super::*;
use crate::egress::assignment::interception_bindings;

fn binding(host: &str, suffix: bool) -> (&str, u32, bool) {
    (host, 443, suffix)
}

fn clients(slots: &[&str]) -> ManagedCredentialClients {
    ManagedCredentialClients::from_profile_slots(slots.iter().copied()).unwrap()
}

/// A report is read as exact names and suffixes on their port; one that names
/// something no front door could bind is unreadable as a whole.
#[test]
fn a_report_is_read_as_canonical_names_or_not_at_all() {
    let set = reported([
        binding("api.anthropic.com", false),
        binding("chatgpt.com", true),
    ])
    .unwrap();
    assert_eq!(
        set.into_iter().collect::<Vec<_>>(),
        ["*.chatgpt.com:443", "api.anthropic.com:443"]
    );
    assert_eq!(reported([]), Some(BTreeSet::new()));
    for bad in ["API.anthropic.com", "10.0.0.1", ""] {
        assert_eq!(reported([binding(bad, false)]), None, "{bad}");
    }
    assert_eq!(reported([("api.anthropic.com", 0, false)]), None);
    let too_many = vec![binding("api.anthropic.com", false); MAX_REPORTED + 1];
    assert_eq!(reported(too_many), None);
}

/// What a selection needs is what the assignment binds for it, compared in
/// the report's own form: a front door built from the same source serves it.
#[test]
fn a_front_door_built_from_the_same_list_serves_every_selection() {
    let built_in = front_door_routes();
    for slots in [
        &["anthropic"][..],
        &["codex", "openai"],
        &["github"],
        &["anthropic", "codex", "openai", "github"],
    ] {
        let needed = needed(&interception_bindings(true, clients(slots)).unwrap());
        assert!(
            missing(&needed, &built_in).is_empty(),
            "{slots:?}: {:?}",
            missing(&needed, &built_in)
        );
    }
}

/// A front door without GitHub's routes leaves exactly GitHub's two hosts
/// missing for a GitHub selection, and nothing for an Anthropic-only one.
#[test]
fn the_missing_names_are_exactly_the_selections_unserved_hosts() {
    let without_github: BTreeSet<String> = front_door_routes()
        .into_iter()
        .filter(|name| !name.contains("github.com"))
        .collect();
    let github = needed(&interception_bindings(true, clients(&["github"])).unwrap());
    assert_eq!(
        missing(&github, &without_github),
        ["api.github.com", "github.com"]
    );
    let anthropic = needed(&interception_bindings(true, clients(&["anthropic"])).unwrap());
    assert!(missing(&anthropic, &without_github).is_empty());
    // An older cw-egress reports nothing, so a selection that binds anything
    // misses all of it.
    assert_eq!(missing(&anthropic, &BTreeSet::new()), ["api.anthropic.com"]);
}

/// The widest built-in report a current cw-egress sends: every host the
/// shared selection can bind, and the `chatgpt.com` suffix.
fn front_door_routes() -> BTreeSet<String> {
    let widest = clients(&["codex", "openai", "anthropic", "ssh", "github"])
        .with_anthropic_sign_in()
        .unwrap();
    needed(&interception_bindings(true, widest).unwrap())
}
