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

    // Both slots, in wire order whatever order they were set in.
    let both = ProjectedPlaceholders::default()
        .with_github(placeholder(OTHER))
        .with_anthropic(placeholder(known_answer::PLACEHOLDER));
    let value = both.header_value();
    assert_eq!(
        value,
        format!("anthropic={},github={OTHER}", known_answer::PLACEHOLDER)
    );
    let read = ProjectedPlaceholders::from_header(&value).unwrap();
    assert!(read.ct_eq(&both));
    assert_eq!(read.github().unwrap().as_str(), OTHER);
    let github = ProjectedPlaceholders::from_header(&format!("github={OTHER}")).unwrap();
    assert!(github.anthropic().is_none() && !github.is_empty());
    assert_eq!(github.github().unwrap().as_str(), OTHER);
    assert!(
        ProjectedPlaceholders::from_header(&format!(
            "github={OTHER},anthropic={}",
            known_answer::PLACEHOLDER
        ))
        .unwrap()
        .ct_eq(&both)
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
        format!("ssh={}", known_answer::PLACEHOLDER),
        format!("{good},codex={OTHER}"),
        format!("{good},github={OTHER},codex={OTHER}"),
        // A repeated slot, even with the same value.
        format!("{good},{good}"),
        format!("{good},anthropic={OTHER}"),
        format!("github={OTHER},github={OTHER}"),
        format!("github={OTHER},{good},github={}", known_answer::PLACEHOLDER),
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
        "github=".to_owned(),
        format!("GitHub={OTHER}"),
        format!("{good},github=ghp_{}", &OTHER[5..]),
        format!("{good},github={}", &OTHER[..47]),
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
    assert!(ProjectedPlaceholders::from_entries([("github", OTHER), ("github", OTHER)]).is_err());
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
    // The github slot counts as much as the anthropic one.
    let with_github = one.clone().with_github(placeholder(OTHER));
    assert!(with_github.ct_eq(&with_github.clone()));
    assert!(!with_github.ct_eq(&one));
    assert!(!one.ct_eq(&with_github));
    assert!(
        !with_github.ct_eq(
            &one.clone()
                .with_github(placeholder(known_answer::PLACEHOLDER))
        )
    );
}

#[test]
fn debug_names_the_slots_and_never_a_placeholder() {
    let set =
        ProjectedPlaceholders::default().with_anthropic(placeholder(known_answer::PLACEHOLDER));
    let printed = format!("{set:?}");
    assert_eq!(printed, r#"["anthropic"]"#);
    assert!(!printed.contains(known_answer::PLACEHOLDER));
    let printed = format!("{:?}", set.with_github(placeholder(OTHER)));
    assert_eq!(printed, r#"["anthropic", "github"]"#);
    assert!(!printed.contains(OTHER));
    assert_eq!(format!("{:?}", ProjectedPlaceholders::default()), "[]");
}
