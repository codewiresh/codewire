//! What a hosted network policy selection means for an environment, in the
//! user's terms. Moved out of `environment.rs` (#3997).

/// What a selection of `open` means since #3997, where before it allowed
/// only TCP 22, 80 and 443.
pub(crate) const OPEN_WIDENED: &str =
    "open now allows every public TCP port; select web to keep 22, 80 and 443.";

/// [`OPEN_WIDENED`] where it applies: a selection whose reference is `open`.
/// A hosted Sandbox that selects nothing has no reference and shows
/// `open (default)`, so it is not told. No selection records when it was
/// made, so one made after #3997 is told too. A local VM's store keeps no
/// difference between selecting `open` and selecting nothing, and both
/// widened, so every local VM on `open` is told.
pub(crate) fn open_widening_notice(reference: &str) -> Option<&'static str> {
    (reference == "open").then_some(OPEN_WIDENED)
}

/// After `--policy` on a hosted create or update (#4000): what the selection
/// means for the environment's outbound connections, or, when the reply
/// doesn't carry the selection asked for, that the server didn't record it
/// (a server older than #4211 ignores `--policy`). Without `--policy` there
/// is nothing to say: the default selection is not news.
pub(crate) fn report_policy_selection(
    asked: &str,
    environment: &str,
    selected: Option<&crate::presentation::EnvironmentNetworkPolicy>,
) {
    let style =
        crate::output::Capabilities::from_process(crate::output::OutputMode::Text).stderr_style();
    for notice in policy_selection_lines(asked, environment, selected) {
        eprintln!(
            "{} {notice}",
            style.status(crate::output::Status::Attention)
        );
    }
}

/// The lines `report_policy_selection` prints: the selection's notice, then,
/// for a recorded selection of `open`, that it widened (#3997).
fn policy_selection_lines(
    asked: &str,
    environment: &str,
    selected: Option<&crate::presentation::EnvironmentNetworkPolicy>,
) -> Vec<String> {
    let widened = selected
        .filter(|policy| policy.selects(asked))
        .and_then(|policy| open_widening_notice(&policy.reference));
    policy_selection_notice(asked, environment, selected)
        .into_iter()
        .chain(widened.map(str::to_owned))
        .collect()
}

/// The words `report_policy_selection` prints, without the status glyph.
pub(crate) fn policy_selection_notice(
    asked: &str,
    environment: &str,
    selected: Option<&crate::presentation::EnvironmentNetworkPolicy>,
) -> Option<String> {
    match selected {
        Some(policy) if policy.selects(asked) => enforcement_notice(policy),
        _ => Some(format!(
            "The server didn't record network policy {asked} for {environment}: it may not support network policies, so the environment has its default."
        )),
    }
}

/// What a selection's enforcement means for the environment, in the user's
/// terms; nothing once it is enforced. Not enforced is said only where the
/// deployment's hosted egress is off; with it on, a status nothing confirms
/// is unconfirmed (#3997).
pub(crate) fn enforcement_notice(
    policy: &crate::presentation::EnvironmentNetworkPolicy,
) -> Option<String> {
    let name = &policy.name;
    match policy.enforcement.as_str() {
        "enforced" => None,
        "enforcing" => Some(format!(
            "Network policy {name} is being applied: until it is, the environment's previous policy applies."
        )),
        "failed_closed" => Some(format!(
            "Network policy {name} couldn't be confirmed as enforced: this environment's outbound connections are refused until it is."
        )),
        "not_enforced" => Some(format!(
            "Network policy {name} isn't enforced on this deployment: outbound connections are not restricted."
        )),
        _ => Some(format!(
            "We can't confirm network policy {name} is applied to this environment right now."
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn selected(reference: &str, name: &str) -> crate::presentation::EnvironmentNetworkPolicy {
        crate::presentation::EnvironmentNetworkPolicy {
            reference: reference.into(),
            name: name.into(),
            enforcement: "enforced".into(),
            ..Default::default()
        }
    }

    /// #3997: only an explicit selection of `open` is told it widened.
    #[test]
    fn only_a_selection_of_open_is_told_it_widened() {
        assert_eq!(
            open_widening_notice("open"),
            Some("open now allows every public TCP port; select web to keep 22, 80 and 443.")
        );
        for reference in ["", "web", "locked", "platform:id:6f1c", "local:id:6f1c"] {
            assert_eq!(open_widening_notice(reference), None, "{reference:?}");
        }
    }

    /// After `--policy open` the widening follows the selection's own notice;
    /// a selection the server didn't record, or the default, says nothing
    /// of it.
    #[test]
    fn a_recorded_selection_of_open_says_it_widened_after_its_notice() {
        assert_eq!(
            policy_selection_lines("open", "app", Some(&selected("open", "open"))),
            [OPEN_WIDENED]
        );
        let unconfirmed = crate::presentation::EnvironmentNetworkPolicy {
            enforcement: "unconfirmed".into(),
            ..selected("open", "open")
        };
        assert_eq!(
            policy_selection_lines("open", "app", Some(&unconfirmed)),
            [
                "We can't confirm network policy open is applied to this environment right now.",
                OPEN_WIDENED
            ]
        );
        assert!(policy_selection_lines("web", "app", Some(&selected("web", "web"))).is_empty());
        let unrecorded = policy_selection_lines("open", "app", Some(&selected("locked", "locked")));
        assert_eq!(unrecorded.len(), 1);
        assert!(unrecorded[0].starts_with("The server didn't record network policy open"));
        assert!(policy_selection_lines("open", "app", Some(&selected("", "open"))).is_empty());
    }
}
