use super::*;

#[test]
fn repository_urls_reject_credentials_and_unsafe_schemes() {
    assert!(valid_repository_url("https://github.com/codewire/codewire"));
    assert!(valid_repository_url(
        "https://github.com/noeljackson/stocks"
    ));
    assert!(!valid_repository_url("https://token@example.test/private"));
    assert!(!valid_repository_url("file:///etc/passwd"));
}

#[test]
fn ttl_without_a_suffix_matches_the_react_minutes_default() {
    assert_eq!(parse_ttl("30"), Ok(Some(1_800)));
    assert_eq!(parse_ttl("infinity"), Ok(None));
    assert_eq!(parse_ttl("∞"), Ok(None));
    assert_eq!(parse_ttl("0"), Ok(None));
}

#[test]
fn preset_lifetimes_use_the_largest_exact_unit_and_parse_back() {
    for (seconds, expected) in [
        (60, "1m"),
        (90, "90s"),
        (3_600, "1h"),
        (5_400, "90m"),
        (86_400, "1d"),
        (90_000, "25h"),
        (604_800, "7d"),
        (31_536_000, "365d"),
    ] {
        assert_eq!(lifetime_field_value(seconds), expected);
        assert_eq!(parse_ttl(expected), Ok(Some(seconds)));
    }
}

#[test]
fn repository_mount_inputs_are_scoped_under_workspace() {
    assert_eq!(workspace_mount_path("codewire"), "/workspace/codewire");
    assert_eq!(
        workspace_mount_path("services/api"),
        "/workspace/services/api"
    );
    assert_eq!(
        workspace_mount_path("/workspace/legacy"),
        "/workspace/legacy"
    );
    assert_eq!(workspace_mount_path(""), "");
}

#[test]
fn ttl_and_port_validation_match_form_contract() {
    assert_eq!(parse_ttl("8h"), Ok(Some(28_800)));
    assert!(valid_port_label("web-ui"));
    assert!(!valid_port_label("Web UI"));
}
