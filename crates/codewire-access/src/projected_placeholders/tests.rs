use super::*;
use crate::known_answer;

fn placeholder(text: &str) -> CredentialPlaceholder {
    CredentialPlaceholder::parse(text).unwrap()
}

/// A well-formed placeholder other than the known answer's.
const OTHER: &str = "cwp1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

#[test]
fn a_set_round_trips_through_its_header_value() {
    let set =
        ProjectedPlaceholders::default().with_anthropic(placeholder(known_answer::PLACEHOLDER));
    let value = set.header_value();
    assert_eq!(value, format!("anthropic={}", known_answer::PLACEHOLDER));
    assert!(
        ProjectedPlaceholders::from_header(&value)
            .unwrap()
            .ct_eq(&set)
    );

    let empty = ProjectedPlaceholders::default();
    assert_eq!(empty.header_value(), "");
    let read = ProjectedPlaceholders::from_header("").unwrap();
    assert!(read.is_empty() && read.ct_eq(&empty));
}

#[test]
fn anything_but_a_whole_well_formed_set_is_refused() {
    let good = format!("anthropic={}", known_answer::PLACEHOLDER);
    for value in [
        // An unknown or unprojected slot, alone or beside a good entry.
        format!("openai={}", known_answer::PLACEHOLDER),
        format!("github={}", known_answer::PLACEHOLDER),
        format!("{good},codex={OTHER}"),
        // A repeated slot, even with the same value.
        format!("{good},{good}"),
        format!("{good},anthropic={OTHER}"),
        // Malformed entries and placeholders.
        "anthropic".to_owned(),
        "anthropic=".to_owned(),
        format!("{good},"),
        format!(",{good}"),
        format!("Anthropic={}", known_answer::PLACEHOLDER),
        format!(" anthropic={}", known_answer::PLACEHOLDER),
        format!("anthropic={} ", known_answer::PLACEHOLDER),
        format!("anthropic=sk-ant-api03-{}", known_answer::PLACEHOLDER),
        format!("anthropic={}", &known_answer::PLACEHOLDER[..47]),
        format!("anthropic=={}", known_answer::PLACEHOLDER),
    ] {
        assert!(
            ProjectedPlaceholders::from_header(&value).is_err(),
            "accepted {value:?}"
        );
    }
    assert!(
        ProjectedPlaceholders::from_entries([("anthropic", OTHER), ("anthropic", OTHER)]).is_err()
    );
    assert!(ProjectedPlaceholders::from_entries([("", OTHER)]).is_err());
}

#[test]
fn equality_compares_every_slot() {
    let one =
        ProjectedPlaceholders::default().with_anthropic(placeholder(known_answer::PLACEHOLDER));
    let other = ProjectedPlaceholders::default().with_anthropic(placeholder(OTHER));
    assert!(one.ct_eq(&one.clone()));
    assert!(!one.ct_eq(&other));
    assert!(!one.ct_eq(&ProjectedPlaceholders::default()));
    assert!(!ProjectedPlaceholders::default().ct_eq(&one));
}

#[test]
fn debug_names_the_slots_and_never_a_placeholder() {
    let set =
        ProjectedPlaceholders::default().with_anthropic(placeholder(known_answer::PLACEHOLDER));
    let printed = format!("{set:?}");
    assert_eq!(printed, r#"["anthropic"]"#);
    assert!(!printed.contains(known_answer::PLACEHOLDER));
    assert_eq!(format!("{:?}", ProjectedPlaceholders::default()), "[]");
}
