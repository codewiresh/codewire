//! The design's outputs (`private-docs: designs/2026-11-22-host-bound-credentials.md`,
//! "The CLI"), exactly, with the `!` line as decided for #4003.

use chrono::TimeZone as _;
use codewire_access::BINDING_PRESETS;

use super::*;

const PLAIN: Style = Style::new(false, Charset::Unicode);
const ASCII: Style = Style::new(false, Charset::Ascii);
const COLOUR: Style = Style::new(true, Charset::Unicode);

fn binding(
    hosts: &[&str],
    presentation: StoredPresentation,
    prefix: Option<&str>,
) -> StoredBinding {
    StoredBinding {
        hosts: hosts.iter().map(|host| (*host).to_owned()).collect(),
        presentation,
        prefix: prefix.map(str::to_owned),
        preset: None,
    }
}

fn bearer() -> StoredPresentation {
    StoredPresentation::Header {
        headers: vec!["Authorization".into()],
        scheme: Some("Bearer".into()),
    }
}

fn outcome<'a>(
    before: Option<&'a StoredBinding>,
    after: Option<&'a StoredBinding>,
    value_changed: bool,
) -> SetOutcome<'a> {
    SetOutcome {
        key: "FANCY_TOKEN",
        place: " in project myapp".to_owned(),
        before,
        after,
        value_changed,
    }
}

#[test]
fn binding_a_project_secret() {
    let after = binding(&["api.fancy.com"], bearer(), Some("ft_"));
    assert_eq!(
        outcome(None, Some(&after), true).render(PLAIN),
        "✓ Secret FANCY_TOKEN set in project myapp · sent only to api.fancy.com\n\
         \x20 Sent as   Authorization: Bearer <value>\n\
         \x20 Inside    a placeholder, ft_cwp1_…; the value never enters an environment\n\
         \x20 ! In a cloud Sandbox, requests to api.fancy.com without this secret are refused.\n\
         → Environments already running get api.fancy.com when they start again: cw restart ENV\n"
    );
}

#[test]
fn changing_only_the_value_of_a_bound_secret() {
    let bound = binding(&["api.fancy.com"], bearer(), None);
    assert_eq!(
        outcome(Some(&bound), Some(&bound), true).render(PLAIN),
        "✓ Secret FANCY_TOKEN set in project myapp · sent only to api.fancy.com\n\
         \x20 Running environments use the new value from their next request.\n"
    );
}

#[test]
fn removing_a_host() {
    let before = binding(&["api.fancy.com", "api.old.example"], bearer(), None);
    let after = binding(&["api.fancy.com"], bearer(), None);
    assert_eq!(
        outcome(Some(&before), Some(&after), false).render(PLAIN),
        "✓ FANCY_TOKEN is no longer sent to api.old.example · still sent to api.fancy.com\n\
         \x20 Running environments stopped sending it there.\n"
    );
}

#[test]
fn making_a_secret_plain() {
    let before = binding(&["api.fancy.com"], bearer(), None);
    assert_eq!(
        outcome(Some(&before), None, true).render(PLAIN),
        "✓ Secret FANCY_TOKEN set in project myapp · plain\n\
         \x20 ! Every process in an environment can read a plain secret.\n\
         → Environments already running keep the placeholder until they start again: cw restart ENV\n"
    );
    // A key that was plain already has no placeholder to keep.
    assert_eq!(
        outcome(None, None, true).render(PLAIN),
        "✓ Secret FANCY_TOKEN set in project myapp · plain\n\
         \x20 ! Every process in an environment can read a plain secret.\n"
    );
}

#[test]
fn a_new_prefix_or_header_names_the_restart_without_a_new_host() {
    let before = binding(&["api.fancy.com"], bearer(), None);
    let after = binding(&["api.fancy.com"], bearer(), Some("sk_"));
    assert_eq!(
        outcome(Some(&before), Some(&after), false).render(PLAIN),
        "✓ Secret FANCY_TOKEN updated in project myapp · sent only to api.fancy.com\n\
         \x20 Sent as   Authorization: Bearer <value>\n\
         \x20 Inside    a placeholder, sk_cwp1_…; the value never enters an environment\n\
         → Environments already running get the change when they start again: cw restart ENV\n"
    );
    let basic = binding(
        &["git.example.com"],
        StoredPresentation::Basic {
            username: "x-access-token".into(),
        },
        None,
    );
    let rendered = outcome(None, Some(&basic), true).render(PLAIN);
    assert!(
        rendered.contains(
            "  Sent as   Authorization: Basic, user x-access-token and <value> as the password\n"
        ),
        "{rendered}"
    );
    let two = binding(
        &["api.fancy.com"],
        StoredPresentation::Header {
            headers: vec!["X-Api-Key".into(), "Authorization".into()],
            scheme: None,
        },
        None,
    );
    let rendered = outcome(None, Some(&two), true).render(PLAIN);
    assert!(
        rendered.contains("  Sent as   X-Api-Key: <value> · Authorization: <value>\n"),
        "{rendered}"
    );
}

#[test]
fn ascii_terminals_get_ascii_marks_and_pipes_get_no_escapes() {
    let after = binding(&["api.fancy.com"], bearer(), None);
    let ascii = outcome(None, Some(&after), true).render(ASCII);
    assert!(ascii.starts_with("+ Secret FANCY_TOKEN set in project myapp - sent only to"));
    assert!(ascii.contains("cwp1_...;"));
    assert!(ascii.contains("\n-> Environments already running"));
    assert!(ascii.is_ascii(), "{ascii}");
    let plain = outcome(None, Some(&after), true).render(PLAIN);
    assert!(!plain.contains('\x1b'));
    let coloured = outcome(None, Some(&after), true).render(COLOUR);
    assert!(coloured.contains('\x1b'));
}

fn row(key: &str, binding: Option<StoredBinding>, updated: &str) -> SecretMetadata {
    SecretMetadata {
        key: key.to_owned(),
        created_at: "2026-11-01T00:00:00Z".to_owned(),
        updated_at: updated.to_owned(),
        binding: binding.map(|binding| SecretBindingView::new(&binding, 3)),
    }
}

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 11, 24, 12, 0, 0).unwrap()
}

fn design_rows() -> Vec<SecretMetadata> {
    let mut stripe = binding(&["api.stripe.com"], bearer(), None);
    stripe.preset = Some("stripe".into());
    vec![
        row("DATABASE_URL", None, "2026-11-22T12:00:00Z"),
        row(
            "FANCY_TOKEN",
            Some(binding(&["api.fancy.com"], bearer(), Some("ft_"))),
            "2026-11-24T11:55:00Z",
        ),
        row(
            "FORGE_TOKEN",
            Some(binding(
                &["git.example.com"],
                StoredPresentation::Basic {
                    username: "x-access-token".into(),
                },
                None,
            )),
            "2026-11-24T11:00:00Z",
        ),
        row("STRIPE_KEY", Some(stripe), "2026-11-23T10:00:00Z"),
        row(
            "TWO_HOSTS",
            Some(binding(&["api.a.example", "api.b.example"], bearer(), None)),
            "2026-11-21T12:00:00Z",
        ),
    ]
}

#[test]
fn the_list_shows_each_keys_delivery() {
    assert_eq!(
        key_list(&design_rows(), false, now(), PLAIN),
        "KEY           DELIVERY                        UPDATED\n\
         DATABASE_URL  plain                           2 d ago\n\
         FANCY_TOKEN   api.fancy.com                   5 min ago\n\
         FORGE_TOKEN   git.example.com · Basic         1 h ago\n\
         STRIPE_KEY    api.stripe.com · preset stripe  1 d ago\n\
         TWO_HOSTS     api.a.example +1                3 d ago\n"
    );
}

#[test]
fn verbose_adds_the_header_scheme_prefix_created_and_every_host() {
    let listed = key_list(&design_rows(), true, now(), PLAIN);
    let lines: Vec<&str> = listed.lines().collect();
    assert_eq!(
        lines[0].split_whitespace().collect::<Vec<_>>(),
        [
            "KEY", "DELIVERY", "HEADER", "SCHEME", "PREFIX", "CREATED", "UPDATED"
        ]
    );
    assert!(lines[1].starts_with("DATABASE_URL  plain"), "{listed}");
    assert!(lines[2].contains("Authorization") && lines[2].contains("Bearer"));
    assert!(lines[2].contains("ft_"), "{listed}");
    assert!(lines[3].contains("Basic, user x-access-token"), "{listed}");
    assert!(
        lines[5].contains("api.a.example, api.b.example"),
        "{listed}"
    );
    assert!(lines[1].contains("23 d ago"), "{listed}");
}

#[test]
fn times_read_as_the_design_words_them() {
    let at = |seconds: i64| (now() - chrono::Duration::seconds(seconds)).to_rfc3339();
    assert_eq!(ago(&at(30), now()), "just now");
    assert_eq!(ago(&at(60), now()), "1 min ago");
    assert_eq!(ago(&at(5 * 60), now()), "5 min ago");
    assert_eq!(ago(&at(3_600), now()), "1 h ago");
    assert_eq!(ago(&at(30 * 3_600), now()), "1 d ago");
    assert_eq!(ago(&at(2 * 86_400), now()), "2 d ago");
    assert_eq!(ago("", now()), "-");
}

#[test]
fn json_rows_carry_the_binding_or_null() {
    let rows = design_rows();
    let json = serde_json::to_value(&rows).unwrap();
    assert_eq!(json[0]["binding"], serde_json::Value::Null);
    assert_eq!(
        json[1]["binding"]["hosts"],
        serde_json::json!(["api.fancy.com"])
    );
    assert_eq!(json[1]["binding"]["binding_generation"], 3);
    let set = SetRow {
        secret: &rows[1],
        value_changed: false,
        running_environments: None,
    };
    let json = serde_json::to_value(&set).unwrap();
    assert_eq!(json["key"], "FANCY_TOKEN");
    assert_eq!(json["binding"]["prefix"], "ft_");
    assert_eq!(json["value_changed"], false);
    assert_eq!(json["running_environments"], serde_json::Value::Null);
}

#[test]
fn the_presets_list_as_text_and_json() {
    assert_eq!(
        preset_list(&BINDING_PRESETS),
        "NAME         HOSTS           PRESENTATION              PREFIX\n\
         huggingface  huggingface.co  Authorization: Bearer     hf_\n\
         linear       api.linear.app  Authorization, no scheme  none\n\
         stripe       api.stripe.com  Authorization: Bearer     none\n"
    );
    let rows: Vec<PresetRow> = BINDING_PRESETS.iter().map(Into::into).collect();
    assert_eq!(
        serde_json::to_value(&rows).unwrap()[1],
        serde_json::json!({
            "name": "linear",
            "hosts": ["api.linear.app"],
            "presentation": "header",
            "headers": ["Authorization"],
            "scheme": "none",
            "prefix": null
        })
    );
}
