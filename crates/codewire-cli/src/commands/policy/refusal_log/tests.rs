use codewire_local_vmm::control::v1;
use v1::egress_refusal::Destination as Wire;

use super::*;
use crate::output::Charset;

const NOW: i64 = 1_800_000_000_000;
const PLAIN: Style = Style::new(false, Charset::Unicode);

/// The current revisions the walk's policies are at.
fn current() -> HashMap<String, u32> {
    HashMap::from([
        ("walk-log".to_owned(), 1),
        ("work".to_owned(), 2),
        ("a-long-policy-name".to_owned(), 12),
    ])
}

fn refusal(
    destination: Wire,
    protocol: v1::EgressRefusalProtocol,
    port: u32,
    reason: &str,
    policy: (&str, u32),
    last_seconds_ago: i64,
) -> v1::EgressRefusal {
    v1::EgressRefusal {
        destination: Some(destination),
        address: "93.184.216.34".to_owned(),
        protocol: protocol as i32,
        port,
        reason: reason.to_owned(),
        policy_name: policy.0.to_owned(),
        policy_revision: policy.1,
        first_seen_unix_ms: NOW - 600_000,
        last_seen_unix_ms: NOW - last_seconds_ago * 1_000,
        count: 6,
    }
}

fn name(name: &str) -> Wire {
    Wire::Name(name.to_owned())
}

fn rows(refusals: &[v1::EgressRefusal]) -> Vec<Row> {
    refusals.iter().filter_map(Row::parse).collect()
}

fn walk_log() -> Vec<Row> {
    use v1::EgressRefusalProtocol::{Dns, Tcp};
    rows(&[
        refusal(
            Wire::AddressOnly("169.254.169.254".to_owned()),
            Tcp,
            80,
            "protected_address",
            ("walk-log", 1),
            5,
        ),
        refusal(
            name("example.com"),
            Tcp,
            8080,
            "port_not_allowed",
            ("walk-log", 1),
            10,
        ),
        v1::EgressRefusal {
            address: String::new(),
            ..refusal(
                name("example.org"),
                Dns,
                0,
                "name_not_allowed",
                ("walk-log", 1),
                120,
            )
        },
    ])
}

#[test]
fn each_refusal_is_one_row_most_recent_first_with_the_next_step_for_the_latest_a_rule_allows() {
    assert_eq!(
        text("walk-log", &walk_log(), 0, NOW, 120, PLAIN, &current()),
        "\
DESTINATION      PROTOCOL  PORT  REASON             POLICY            COUNT  FIRST    LAST
169.254.169.254  tcp       80    protected address  walk-log · rev 1  6      10m ago  5s ago
example.com      tcp       8080  port not allowed   walk-log · rev 1  6      10m ago  10s ago
example.org      dns       -     name not allowed   walk-log · rev 1  6      10m ago  2m ago

→ cw --local policy allow walk-log example.com:8080
"
    );
}

#[test]
fn nothing_refused_reads_as_empty() {
    assert_eq!(
        text("walk-log", &[], 0, NOW, 80, PLAIN, &current()),
        "Nothing refused since walk-log started.\n"
    );
}

#[test]
fn a_built_in_policy_gets_a_new_policy_and_a_protected_reason_no_step() {
    use v1::EgressRefusalProtocol::Tcp;
    let under = |policy: &str, reason: &str| {
        rows(&[refusal(
            name("example.com"),
            Tcp,
            8080,
            reason,
            (policy, 0),
            1,
        )])
    };
    assert_eq!(
        next_step(&under("locked", "name_not_allowed"), &current()).as_deref(),
        Some("cw --local policy create NAME --from locked --allow example.com:8080")
    );
    // `create` refuses `--from open`, and a policy from `locked` would drop
    // what `open` allows, so `open` gets no step.
    assert_eq!(
        next_step(&under("open", "port_not_allowed"), &current()),
        None
    );
    for reason in [
        "protected_address",
        "protected_answers_only",
        "lease_expired",
        "intercept_unavailable",
    ] {
        assert_eq!(
            next_step(&under("walk-log", reason), &current()),
            None,
            "{reason}"
        );
    }
    let v6 = rows(&[refusal(
        Wire::AddressOnly("2001:db8::1111".to_owned()),
        Tcp,
        8443,
        "address_not_allowed",
        ("work", 2),
        1,
    )]);
    assert_eq!(
        next_step(&v6, &current()).as_deref(),
        Some("cw --local policy allow work [2001:db8::1111]:8443")
    );
}

#[test]
fn a_name_carrying_an_escape_is_withheld_and_never_printed() {
    let refusals = rows(&[refusal(
        name("evil\u{1b}[2J.example.com"),
        v1::EgressRefusalProtocol::Dns,
        0,
        "name_not_allowed",
        ("walk-log", 1),
        1,
    )]);
    let shown = text("walk-log", &refusals, 0, NOW, 120, PLAIN, &current());
    assert!(shown.contains("(a name cw won't show)"), "{shown}");
    assert!(
        !shown.contains('\u{1b}') && !shown.contains("evil"),
        "{shown}"
    );
    // A withheld name has nothing a rule could allow.
    assert!(!shown.contains('→'), "{shown}");
    let json = json(&refusals, 0).unwrap();
    assert!(
        !json.contains("evil") && !json.contains("\\u001b"),
        "{json}"
    );
}

#[test]
fn piped_text_has_no_escapes_and_ascii_names_the_step_plainly() {
    let ascii = text(
        "walk-log",
        &walk_log(),
        0,
        NOW,
        120,
        Style::new(false, Charset::Ascii),
        &current(),
    );
    assert!(!ascii.contains('\u{1b}'));
    assert!(ascii.ends_with("-> cw --local policy allow walk-log example.com:8080\n"));
}

#[test]
fn the_table_fits_the_terminal() {
    use v1::EgressRefusalProtocol::Tcp;
    let long = format!("{}.example.com", "a".repeat(60));
    let refusals = rows(&[refusal(
        name(&long),
        Tcp,
        8080,
        "port_not_allowed",
        ("a-long-policy-name", 12),
        1,
    )]);
    let shown = text("walk-log", &refusals, 0, NOW, 100, PLAIN, &current());
    let mut lines = shown.lines();
    for line in lines.by_ref().take(2) {
        assert!(line.chars().count() <= 100, "{line}");
    }
    assert!(shown.contains('…'), "{shown}");
    // The step keeps the whole name.
    assert!(shown.contains(&format!("{long}:8080")), "{shown}");
}

#[test]
fn dropped_rows_are_said() {
    let shown = text("walk-log", &walk_log(), 100, NOW, 120, PLAIN, &current());
    assert!(
        shown.contains(
            "\n100 rows seen least recently were dropped; the log keeps the 1,000 seen last.\n"
        ),
        "{shown}"
    );
}

#[test]
fn json_holds_every_row_and_nothing_else() {
    let value: serde_json::Value = serde_json::from_str(&json(&walk_log(), 3).unwrap()).unwrap();
    assert_eq!(value["dropped"], 3);
    let refusals = value["refusals"].as_array().unwrap();
    assert_eq!(refusals.len(), 3);
    assert_eq!(
        refusals[1],
        serde_json::json!({
            "destination": "example.com",
            "withheld": false,
            "address": "93.184.216.34",
            "port": 8080,
            "protocol": "tcp",
            "reason": "port_not_allowed",
            "source": "network",
            "policy": "walk-log",
            "revision": 1,
            "first": "2027-01-15T07:50:00Z",
            "last": "2027-01-15T07:59:50Z",
            "count": 6,
        })
    );
    assert_eq!(refusals[2]["protocol"], "dns");
    assert!(refusals[2]["port"].is_null());
    assert!(refusals[2]["address"].is_null());
    assert_eq!(value.as_object().unwrap().len(), 2);
}

#[test]
fn a_row_this_cw_cannot_read_is_left_out() {
    use v1::EgressRefusalProtocol::{Dns, Tcp};
    assert!(
        rows(&[refusal(
            name("example.com"),
            Tcp,
            70_000,
            "port_not_allowed",
            ("w", 1),
            1
        )])
        .is_empty()
    );
    assert!(
        rows(&[refusal(
            name("example.com"),
            Dns,
            53,
            "name_not_allowed",
            ("w", 1),
            1
        )])
        .is_empty()
    );
    assert!(
        rows(&[refusal(
            name("example.com"),
            Tcp,
            443,
            "a_new_reason",
            ("w", 1),
            1
        )])
        .is_empty()
    );
    assert!(
        rows(&[refusal(
            Wire::AddressOnly("not an address".to_owned()),
            Tcp,
            443,
            "address_not_allowed",
            ("w", 1),
            1
        )])
        .is_empty()
    );
}

#[test]
fn a_vm_that_is_not_running_says_so_and_how_to_start_it() {
    let error = not_running("walk-log");
    assert_eq!(
        crate::error_report::sentence(&error),
        "there's no refusal log while walk-log isn't running"
    );
    assert_eq!(
        crate::error_report::next_step(&error).as_deref(),
        Some("cw --local start walk-log")
    );
}

#[test]
fn the_location_parses_before_or_after_policy() {
    use clap::Parser as _;
    for args in [
        [
            "cw", "--local", "policy", "log", "walk-log", "--output", "json",
        ],
        [
            "cw", "policy", "--local", "log", "walk-log", "--output", "json",
        ],
    ] {
        let cli = crate::Cli::try_parse_from(args).unwrap();
        assert!(cli.local, "{args:?}");
        let crate::Command::Policy(policy) = cli.command else {
            panic!("not cw policy: {args:?}");
        };
        let super::super::PolicyCommand::Log(log) = policy.command else {
            panic!("not cw policy log: {args:?}");
        };
        assert_eq!(log.env, "walk-log");
        assert_eq!(log.output, OutputFormat::Json);
    }
}

#[test]
fn a_refusal_under_an_older_revision_gets_no_step_since_an_edit_may_allow_it() {
    let stale = rows(&[refusal(
        name("example.com"),
        v1::EgressRefusalProtocol::Tcp,
        8080,
        "port_not_allowed",
        ("walk-log", 1),
        1,
    )]);
    let edited = HashMap::from([("walk-log".to_owned(), 2)]);
    assert_eq!(next_step(&stale, &edited), None);
    assert_eq!(next_step(&stale, &HashMap::new()), None);
}

#[test]
fn a_narrow_terminal_cuts_the_policy_first_and_never_an_address() {
    let shown = text("walk-log", &walk_log(), 0, NOW, 70, PLAIN, &current());
    assert!(shown.contains("169.254.169.254"), "{shown}");
    assert!(shown.contains("example.com"), "{shown}");
}
