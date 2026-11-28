//! The binding flags against a key's current binding: the design's flag
//! table and refusals (`private-docs: designs/2026-11-22-host-bound-credentials.md`,
//! "The CLI"), and the spec's re-entry rule.

use clap::Parser as _;
use codewire_access::{BindingWrite, StoredBinding, StoredPresentation};

use super::*;
use crate::output::{Charset, Style};
use crate::{Cli, Command};

const COMMAND: &str = "cw secrets --cloud --project=myapp";
const PLAIN: Style = Style::new(false, Charset::Unicode);

/// The binding flags of `cw secrets --cloud --project=myapp set KEY FLAGS…`.
fn flags(words: &[&str]) -> SecretBindingArgs {
    let mut argv = vec!["cw", "secrets", "--cloud", "--project=myapp", "set", "KEY"];
    argv.extend(words);
    let Command::Secrets(args) = Cli::try_parse_from(argv).unwrap().command else {
        panic!("expected secrets");
    };
    let crate::commands::SecretsCommand::Set(set) = args.command else {
        panic!("expected set");
    };
    set.binding
}

fn bearer() -> StoredPresentation {
    StoredPresentation::Header {
        headers: vec!["Authorization".into()],
        scheme: Some("Bearer".into()),
    }
}

fn binding(hosts: &[&str], prefix: Option<&str>) -> StoredBinding {
    StoredBinding {
        hosts: hosts.iter().map(|host| (*host).to_owned()).collect(),
        presentation: bearer(),
        prefix: prefix.map(str::to_owned),
        preset: None,
    }
}

fn plain_key() -> Current {
    Current {
        exists: true,
        binding: None,
    }
}

fn bound_key(hosts: &[&str], prefix: Option<&str>) -> Current {
    Current {
        exists: true,
        binding: Some(binding(hosts, prefix)),
    }
}

fn planned(words: &[&str], current: Current) -> BindingPlan {
    plan(COMMAND, "KEY", &flags(words), current).unwrap()
}

fn refused(words: &[&str], current: Current) -> String {
    let error = plan(COMMAND, "KEY", &flags(words), current).unwrap_err();
    crate::error_report::render(&error, PLAIN)
}

#[test]
fn no_binding_flags_keep_the_binding_and_take_a_new_value() {
    let kept = planned(&[], bound_key(&["api.fancy.com"], None));
    assert_eq!(kept.write, BindingWrite::Keep);
    assert_eq!(kept.after, kept.before);
    assert_eq!(kept.value, ValueNeed::New);
    assert_eq!(planned(&[], plain_key()).after, None);
}

#[test]
fn binding_a_plain_key_needs_its_value_and_takes_the_defaults() {
    let bound = planned(&["--host", "API.Fancy.com", "--prefix", "ft_"], plain_key());
    let after = binding(&["api.fancy.com"], Some("ft_"));
    assert_eq!(bound.write, BindingWrite::Bind(after.clone()));
    assert_eq!(bound.after, Some(after));
    assert_eq!(bound.value, ValueNeed::Again(Reentry::Bind));
    // A key that isn't there yet takes its first value as any new key does.
    let new = planned(&["--host", "api.fancy.com"], Current::default());
    assert_eq!(new.value, ValueNeed::New);
}

#[test]
fn adding_a_host_adds_to_the_hosts_and_needs_the_value() {
    let added = planned(
        &["--host", "api.other.example"],
        bound_key(&["api.fancy.com"], None),
    );
    assert_eq!(
        added.after.unwrap().hosts,
        ["api.fancy.com", "api.other.example"]
    );
    assert_eq!(added.value, ValueNeed::Again(Reentry::AddHost));
}

#[test]
fn removing_a_host_or_changing_the_prefix_needs_no_value() {
    let two = || bound_key(&["api.fancy.com", "api.old.example"], Some("ft_"));
    let removed = planned(&["--remove-host", "api.old.example"], two());
    assert_eq!(
        removed.after,
        Some(binding(&["api.fancy.com"], Some("ft_")))
    );
    assert_eq!(removed.value, ValueNeed::None);
    let cleared = planned(&["--prefix", ""], two());
    assert_eq!(cleared.after.unwrap().prefix, None);
    assert_eq!(cleared.value, ValueNeed::None);
    let changed = planned(&["--prefix", "sk_"], two());
    assert_eq!(changed.after.unwrap().prefix.as_deref(), Some("sk_"));
    assert_eq!(changed.value, ValueNeed::None);
}

#[test]
fn removing_the_last_host_says_how_to_make_it_plain() {
    assert_eq!(
        refused(
            &["--remove-host", "api.fancy.com"],
            bound_key(&["api.fancy.com"], None)
        ),
        "✗ Host api.fancy.com is KEY's only host\n\
         → to make it plain: cw secrets --cloud --project=myapp set KEY --plain\n"
    );
    assert_eq!(
        refused(&["--remove-host", "api.fancy.com"], plain_key()),
        "✗ Secret KEY is plain: it has no hosts to remove\n"
    );
    assert_eq!(
        refused(
            &["--remove-host", "api.other.example"],
            bound_key(&["api.fancy.com"], None)
        ),
        "✗ Host api.other.example isn't one of KEY's hosts\n"
    );
}

#[test]
fn a_new_header_or_scheme_needs_the_value() {
    let changed = planned(
        &["--header", "X-Api-Key", "--scheme", "none"],
        bound_key(&["api.fancy.com"], None),
    );
    assert_eq!(
        changed.after.unwrap().presentation,
        StoredPresentation::Header {
            headers: vec!["X-Api-Key".into()],
            scheme: None,
        }
    );
    assert_eq!(changed.value, ValueNeed::Again(Reentry::Presentation));
    let scheme_only = planned(&["--scheme", "token"], bound_key(&["api.fancy.com"], None));
    assert_eq!(
        scheme_only.after.unwrap().presentation,
        StoredPresentation::Header {
            headers: vec!["Authorization".into()],
            scheme: Some("token".into()),
        }
    );
}

#[test]
fn basic_auth_takes_its_user_name_and_no_header() {
    let basic = planned(
        &["--host", "git.example.com", "--basic", "--username", "git"],
        plain_key(),
    );
    assert_eq!(
        basic.after.unwrap().presentation,
        StoredPresentation::Basic {
            username: "git".into()
        }
    );
    let default_user = planned(&["--host", "git.example.com", "--basic"], plain_key());
    assert_eq!(
        default_user.after.unwrap().presentation,
        StoredPresentation::Basic {
            username: "x-access-token".into()
        }
    );
    let user = planned(&["--host", "pay.example.com", "--basic-user"], plain_key());
    assert_eq!(
        user.after.unwrap().presentation,
        StoredPresentation::BasicUser
    );
    for (words, refusal) in [
        (
            &["--basic", "--basic-user"][..],
            "✗ --basic and --basic-user send the value two different ways; choose one\n",
        ),
        (
            &["--basic", "--header", "X-Api-Key"][..],
            "✗ With --basic, the value goes in Authorization, so --header and --scheme don't apply\n",
        ),
        (
            &["--username", "git"][..],
            "✗ --username names the Basic auth user name, with --basic\n",
        ),
    ] {
        assert_eq!(
            refused(words, bound_key(&["git.example.com"], None)),
            refusal
        );
    }
}

#[test]
fn plain_removes_every_host_and_needs_the_value() {
    let plain = planned(&["--plain"], bound_key(&["api.fancy.com"], None));
    assert_eq!(plain.write, BindingWrite::Plain);
    assert_eq!(plain.after, None);
    assert_eq!(plain.value, ValueNeed::Again(Reentry::Plain));
    // Already plain: a new value, as any plain set.
    assert_eq!(planned(&["--plain"], plain_key()).value, ValueNeed::New);
    assert_eq!(
        refused(&["--plain", "--host", "api.fancy.com"], plain_key()),
        "✗ --plain removes every host; give it without the other binding flags\n"
    );
}

#[test]
fn a_preset_fills_the_binding_and_a_flag_overrides_its_field() {
    let stripe = planned(&["--preset", "stripe"], plain_key());
    assert_eq!(
        stripe.after,
        Some(StoredBinding {
            preset: Some("stripe".into()),
            ..binding(&["api.stripe.com"], None)
        })
    );
    assert_eq!(stripe.value, ValueNeed::Again(Reentry::Bind));
    let hosts = planned(
        &["--preset", "stripe", "--host", "api.example.com"],
        plain_key(),
    );
    let hosts = hosts.after.unwrap();
    assert_eq!(hosts.hosts, ["api.example.com"]);
    assert_eq!(hosts.preset.as_deref(), Some("stripe"));
    let linear = planned(&["--preset", "linear", "--prefix", "lin_"], plain_key());
    let linear = linear.after.unwrap();
    assert_eq!(
        linear.presentation,
        StoredPresentation::Header {
            headers: vec!["Authorization".into()],
            scheme: None,
        }
    );
    assert_eq!(linear.prefix.as_deref(), Some("lin_"));
    // A preset whose way of sending it is overridden no longer names it.
    let header = planned(
        &["--preset", "stripe", "--header", "X-Api-Key"],
        plain_key(),
    );
    assert_eq!(header.after.unwrap().preset, None);
}

#[test]
fn an_unknown_preset_suggests_the_nearest() {
    assert_eq!(
        refused(&["--preset", "strpe"], plain_key()),
        "✗ No preset named strpe\n→ did you mean stripe?\n"
    );
    assert_eq!(
        refused(&["--preset", "anthropic"], plain_key()),
        "✗ No preset named anthropic\n→ cw secrets presets\n"
    );
}

#[test]
fn the_rules_refuse_in_their_own_words_and_name_the_provider_step() {
    assert_eq!(
        refused(&["--host", "*.fancy.com"], plain_key()),
        "✗ *.fancy.com can't be bound: name each host exactly\n"
    );
    assert_eq!(
        refused(&["--host", "api.anthropic.com"], plain_key()),
        "✗ api.anthropic.com is a provider host Codewire connects for you\n\
         → cw credentials connect claude\n"
    );
    assert_eq!(
        refused(&["--host", "github.com"], plain_key()),
        "✗ github.com is a provider host Codewire connects for you\n\
         → cw credentials connect github\n"
    );
    assert_eq!(
        refused(
            &["--host", "api.fancy.com", "--header", "Cookie"],
            plain_key()
        ),
        "✗ Cookie can't carry a bound secret: the proxy sets it, or servers log or echo it\n"
    );
    assert_eq!(
        refused(
            &[
                "--host",
                "a.example",
                "--header",
                "A",
                "--header",
                "B",
                "--header",
                "C"
            ],
            plain_key()
        ),
        "✗ A binding sends its value in at most 2 headers\n"
    );
    assert_eq!(
        refused(
            &["--host", "api.fancy.com", "--prefix", "cwp1_x"],
            plain_key()
        ),
        "✗ The prefix can use letters, digits, _ and -, up to 16, and not cwp1_\n"
    );
    let too_many: Vec<String> = (0..17).map(|n| format!("api{n}.example.com")).collect();
    let mut words = Vec::new();
    for host in &too_many {
        words.extend(["--host", host.as_str()]);
    }
    assert_eq!(
        refused(&words, plain_key()),
        "✗ A secret can be sent to at most 16 hosts\n"
    );
}

#[test]
fn a_binding_flag_on_a_key_with_no_hosts_asks_for_one() {
    assert_eq!(
        refused(&["--header", "X-Api-Key"], plain_key()),
        "✗ Secret KEY has no hosts yet: name one\n\
         → cw secrets --cloud --project=myapp set KEY --host HOST --header X-Api-Key\n"
    );
}

#[test]
fn the_reasons_name_the_change() {
    assert_eq!(
        Reentry::AddHost.needs_value("FANCY_TOKEN"),
        "adding a host to FANCY_TOKEN needs its value again"
    );
    assert_eq!(
        Reentry::AddHost.prompt("FANCY_TOKEN"),
        "Paste the value of FANCY_TOKEN again (adding a host sends it somewhere new): "
    );
    for reentry in [
        Reentry::Bind,
        Reentry::AddHost,
        Reentry::Presentation,
        Reentry::Plain,
    ] {
        assert!(
            reentry
                .needs_value("KEY")
                .ends_with("needs its value again")
        );
        assert!(
            reentry
                .prompt("KEY")
                .starts_with("Paste the value of KEY again (")
        );
    }
}

#[test]
fn the_flags_are_repeated_as_typed() {
    assert_eq!(
        flags(&[
            "--host",
            "a.example",
            "--prefix",
            "",
            "--preset",
            "stripe",
            "--basic",
            "--plain"
        ])
        .words(),
        "--preset stripe --host a.example --prefix '' --basic --plain"
    );
    assert!(!flags(&[]).any());
    for word in [
        &["--host", "a.example"][..],
        &["--remove-host", "a.example"],
        &["--header", "X"],
        &["--scheme", "none"],
        &["--prefix", ""],
        &["--basic"],
        &["--username", "git"],
        &["--basic-user"],
        &["--preset", "stripe"],
        &["--plain"],
    ] {
        assert!(flags(word).any(), "{word:?}");
    }
}
