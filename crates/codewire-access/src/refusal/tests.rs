use super::*;

const ANTHROPIC: Option<RefusalProvider> = Some(RefusalProvider::Anthropic);
const HOST: Option<&str> = Some("api.anthropic.com");
const RECONNECT: &str = "Fix: in a local VM, run `cw credentials --local list` on the computer that runs it; in a hosted Sandbox, run `cw credentials --cloud list` wherever you're signed in to Codewire; then connect it again.\n";

/// Every refusal, its status and its body for Anthropic on
/// `api.anthropic.com`, as the spec's table writes them.
fn table() -> Vec<(Refusal, u16, String)> {
    vec![
        (
            Refusal::CredentialRevoked,
            403,
            format!("Codewire: the Anthropic credential this environment uses was revoked.\n{RECONNECT}"),
        ),
        (
            Refusal::CredentialExpired,
            403,
            format!("Codewire: the Anthropic credential this environment uses has expired.\n{RECONNECT}"),
        ),
        (
            Refusal::CredentialNeedsReconnect,
            403,
            format!("Codewire: the Anthropic credential this environment uses needs reconnecting.\n{RECONNECT}"),
        ),
        (
            Refusal::NoCredentialSelected,
            403,
            "Codewire: this environment's profile no longer has an Anthropic credential.\nFix: run `cw credentials --local profiles list` on the computer that runs the VM, or `cw credentials --cloud profiles list` for a hosted Sandbox.\n".to_owned(),
        ),
        (
            Refusal::CredentialUnavailable,
            503,
            "Codewire: the Anthropic credential can't be used right now; try again.\n".to_owned(),
        ),
        (
            Refusal::CredentialConflict,
            400,
            "Codewire: this request carries the Codewire placeholder and another credential; send only one.\n".to_owned(),
        ),
        (
            Refusal::PathNotServed,
            404,
            "Codewire: this path on api.anthropic.com isn't one Codewire forwards.\n".to_owned(),
        ),
        (
            Refusal::WebsocketNotServed,
            403,
            "Codewire: WebSockets to api.anthropic.com aren't carried yet.\n".to_owned(),
        ),
        (
            Refusal::RouteNotServed,
            403,
            "Codewire: requests to api.anthropic.com can't use this environment's credentials yet.\n".to_owned(),
        ),
        (
            Refusal::RouteLost,
            403,
            "Codewire: requests to api.anthropic.com can't use this environment's credentials until it restarts.\n".to_owned(),
        ),
        (
            Refusal::RequestNotForwarded(Unforwarded::Malformed),
            400,
            "Codewire: this request to api.anthropic.com isn't one Codewire forwards.\n".to_owned(),
        ),
        (
            Refusal::RequestNotForwarded(Unforwarded::Refused),
            403,
            "Codewire: this request to api.anthropic.com isn't one Codewire forwards.\n".to_owned(),
        ),
        (
            Refusal::RequestNotForwarded(Unforwarded::ClientStalled),
            408,
            "Codewire: this request to api.anthropic.com isn't one Codewire forwards.\n".to_owned(),
        ),
        (
            Refusal::RequestNotForwarded(Unforwarded::Misdirected),
            421,
            "Codewire: this request to api.anthropic.com isn't one Codewire forwards.\n".to_owned(),
        ),
        (
            Refusal::BodyTooLarge,
            413,
            "Codewire: this request's body is over the 4 MiB Codewire forwards to api.anthropic.com.\n".to_owned(),
        ),
        (
            Refusal::Busy,
            503,
            "Codewire: too many requests are in flight; try again.\n".to_owned(),
        ),
        (
            Refusal::UpstreamFailed(UpstreamFailure::Failed),
            502,
            "Codewire: Anthropic couldn't be reached; try again.\n".to_owned(),
        ),
        (
            Refusal::UpstreamFailed(UpstreamFailure::TimedOut),
            504,
            "Codewire: Anthropic couldn't be reached; try again.\n".to_owned(),
        ),
        (
            Refusal::NameNotAllowed,
            403,
            "Codewire: this environment's network policy doesn't allow this request to api.anthropic.com.\nFix: to send it, select a network policy with a rule that allows api.anthropic.com on port 443.\n".to_owned(),
        ),
        (
            Refusal::SelectedCredentialOnly,
            403,
            "Codewire: requests to api.anthropic.com from this environment must carry its Codewire credential.\n".to_owned(),
        ),
        (
            Refusal::Unavailable,
            503,
            "Codewire: this request to api.anthropic.com can't be checked against the network policy right now; try again.\n".to_owned(),
        ),
        (
            Refusal::Denied,
            403,
            "Codewire: this request was refused.\n".to_owned(),
        ),
        (
            Refusal::CredentialOwnerDeparted,
            403,
            "Codewire: this Sandbox's creator is no longer in its organization, so its credentials aren't used.\n".to_owned(),
        ),
        (
            Refusal::CredentialOwnerDisabled,
            403,
            "Codewire: this Sandbox's creator's account is disabled, so its credentials aren't used.\n".to_owned(),
        ),
    ]
}

#[test]
fn each_refusal_answers_with_the_specs_status_and_body() {
    for (refusal, status, body) in table() {
        assert_eq!(refusal.status(), status, "{refusal:?}");
        assert_eq!(refusal.body(ANTHROPIC, HOST), body, "{refusal:?}");
    }
}

#[test]
fn a_refusal_is_never_a_401_and_never_more_than_two_lines() {
    for (refusal, _, _) in table() {
        assert_ne!(refusal.status(), 401, "{refusal:?}");
        for (provider, host) in [(ANTHROPIC, HOST), (None, None)] {
            let body = refusal.body(provider, host);
            assert!(body.lines().count() <= 2, "{refusal:?}: {body}");
            assert!(body.starts_with("Codewire: ") && body.ends_with('\n'));
        }
    }
}

#[test]
fn without_a_bound_host_the_sentence_leaves_it_out() {
    assert_eq!(
        Refusal::BodyTooLarge.body(Some(RefusalProvider::GitHub), None),
        "Codewire: this request's body is over the 4 MiB Codewire forwards.\n"
    );
    assert_eq!(
        Refusal::RequestNotForwarded(Unforwarded::Refused).body(None, None),
        "Codewire: this request isn't one Codewire forwards.\n"
    );
    assert_eq!(
        Refusal::UpstreamFailed(UpstreamFailure::Failed).body(Some(RefusalProvider::OpenAi), None),
        "Codewire: OpenAI couldn't be reached; try again.\n"
    );
    // A routed origin's own-key request needs a rule for every name under
    // its suffix, so that is the rule the fix names.
    assert_eq!(
        Refusal::NameNotAllowed.body(None, Some("ab12.chatgpt.com")),
        "Codewire: this environment's network policy doesn't allow this request to ab12.chatgpt.com.\nFix: to send it, select a network policy with a rule that allows *.chatgpt.com on port 443.\n"
    );
    assert_eq!(
        Refusal::NameNotAllowed.body(None, None),
        "Codewire: this environment's network policy doesn't allow this request.\nFix: to send it, select a network policy with a rule that allows this host on port 443.\n"
    );
    assert_eq!(
        Refusal::SelectedCredentialOnly.body(None, None),
        "Codewire: these requests from this environment must carry its Codewire credential.\n"
    );
}

#[test]
fn each_reason_is_one_of_the_specs_names() {
    let reasons: Vec<_> = table()
        .iter()
        .map(|(refusal, _, _)| refusal.reason())
        .collect();
    for reason in [
        "credential_revoked",
        "credential_expired",
        "credential_needs_reconnect",
        "no_credential_selected",
        "credential_unavailable",
        "credential_conflict",
        "path_not_served",
        "websocket_not_served",
        "route_not_served",
        "request_not_forwarded",
        "body_too_large",
        "busy",
        "upstream_failed",
        "name_not_allowed",
        "selected_credential_only",
        "unavailable",
        "denied",
    ] {
        assert!(reasons.contains(&reason), "{reason}");
    }
}

#[test]
fn a_slot_names_its_provider() {
    assert_eq!(RefusalProvider::for_slot("anthropic"), ANTHROPIC);
    assert_eq!(
        RefusalProvider::for_slot("codex"),
        Some(RefusalProvider::OpenAi)
    );
    assert_eq!(
        RefusalProvider::for_slot("openai"),
        Some(RefusalProvider::OpenAi)
    );
    assert_eq!(
        RefusalProvider::for_slot("github"),
        Some(RefusalProvider::GitHub)
    );
    assert_eq!(RefusalProvider::for_slot("other"), None);
}

/// A log keeps a refusal's code alone: every refusal has the code its
/// header names, and every code round-trips through its text and its index.
#[test]
fn each_refusal_has_the_code_its_header_names() {
    for (refusal, _, _) in table() {
        assert_eq!(refusal.code().as_str(), refusal.reason(), "{refusal:?}");
        assert_eq!(
            RefusalCode::from_code(refusal.reason()),
            Some(refusal.code())
        );
    }
    for code in RefusalCode::ALL {
        assert_eq!(RefusalCode::from_code(code.as_str()), Some(code));
        assert_eq!(RefusalCode::at(code.index()), Some(code));
        assert!(!code.description().contains('_'), "{code:?}");
    }
    assert_eq!(RefusalCode::from_code("Path_Not_Served"), None);
    assert_eq!(RefusalCode::at(20), None);
}
