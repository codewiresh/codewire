use clap::Parser;

use super::*;
use crate::output::Charset;

const PLAIN: Style = Style::new(false, Charset::Unicode);

fn parse(words: &[&str]) -> Result<IdentityCommand, clap::Error> {
    let mut argv = vec!["cw", "identity"];
    argv.extend_from_slice(words);
    crate::Cli::try_parse_from(argv).map(|cli| match cli.command {
        crate::Command::Identity(args) => args.command,
        other => panic!("not cw identity: {other:?}"),
    })
}

fn user(email: &str, reason: IdentityGroupUserReason) -> IdentityGroupUser {
    IdentityGroupUser {
        user_id: format!("id-{email}"),
        email: email.to_owned(),
        reason: reason.into(),
        ..Default::default()
    }
}

#[test]
fn groups_lists_and_set_replaces_or_clears() {
    assert!(matches!(
        parse(&["groups", "app"]).unwrap(),
        IdentityCommand::Groups(IdentityGroupsArgs { command: None, environment: Some(name), .. })
            if name == "app"
    ));
    let IdentityCommand::Groups(IdentityGroupsArgs {
        command: Some(IdentityGroupsCommand::Set(set)),
        ..
    }) = parse(&["groups", "set", "app", "data-readers", "builders"]).unwrap()
    else {
        panic!("groups set");
    };
    assert_eq!(set.environment, "app");
    assert_eq!(set.groups, ["data-readers", "builders"]);
    assert!(!set.clear);
    let IdentityCommand::Groups(IdentityGroupsArgs {
        command: Some(IdentityGroupsCommand::Set(clear)),
        ..
    }) = parse(&["groups", "set", "app", "--clear"]).unwrap()
    else {
        panic!("groups set --clear");
    };
    assert!(clear.clear && clear.groups.is_empty());

    // A set names its groups or --clear, never both and never neither, so
    // a slip of the fingers never clears them.
    assert!(parse(&["groups", "set", "app"]).is_err());
    assert!(parse(&["groups", "set", "app", "x", "--clear"]).is_err());
    assert!(parse(&["groups"]).is_err());
}

#[test]
fn audience_takes_its_registration_options() {
    let IdentityCommand::Audience(IdentityAudienceCommand::Add(add)) = parse(&[
        "audience",
        "add",
        "https://vault.example.com",
        "--groups",
        "readers,builders",
        "--lifetime",
        "5m",
        "--claim",
        "created_by",
        "--claim",
        "environment_name",
        "--file",
        "vault",
    ])
    .unwrap() else {
        panic!("audience add");
    };
    assert_eq!(add.audience, "https://vault.example.com");
    assert_eq!(
        add.groups.as_deref(),
        Some(&["readers".to_owned(), "builders".to_owned()][..])
    );
    assert_eq!(add.lifetime, Some(300));
    assert_eq!(
        add.claim,
        [IdentityClaim::CreatedBy, IdentityClaim::EnvironmentName]
    );
    assert_eq!(add.file.as_deref(), Some("vault"));

    let IdentityCommand::Audience(IdentityAudienceCommand::Add(plain)) =
        parse(&["audience", "add", "https://k8s.example"]).unwrap()
    else {
        panic!("audience add");
    };
    assert!(plain.groups.is_none() && plain.lifetime.is_none() && plain.claim.is_empty());
    assert!(parse(&["audience", "add", "https://k8s.example", "--claim", "email"]).is_err());
    for command in [["audience", "list"], ["audience", "ls"]] {
        assert!(matches!(
            parse(&command).unwrap(),
            IdentityCommand::Audience(IdentityAudienceCommand::List(_))
        ));
    }
    for command in [["audience", "remove"], ["audience", "rm"]] {
        let mut words = command.to_vec();
        words.push("https://k8s.example");
        assert!(matches!(
            parse(&words).unwrap(),
            IdentityCommand::Audience(IdentityAudienceCommand::Remove(_))
        ));
    }
}

#[test]
fn a_lifetime_is_minutes_or_seconds() {
    assert_eq!(parse_lifetime("10m"), Ok(600));
    assert_eq!(parse_lifetime("1m"), Ok(60));
    assert_eq!(parse_lifetime("90s"), Ok(90));
    for raw in [
        "",
        "m",
        "10",
        "10h",
        "1.5m",
        "-1m",
        "10 m",
        "99999999999m",
        "10é",
        "5ms",
    ] {
        assert!(parse_lifetime(raw).is_err(), "{raw:?}");
    }
}

#[test]
fn stop_and_resume_name_a_sandbox_or_the_organization() {
    for verb in ["stop", "resume"] {
        let args = match parse(&[verb, "app"]).unwrap() {
            IdentityCommand::Stop(args) | IdentityCommand::Resume(args) => args,
            other => panic!("{other:?}"),
        };
        assert_eq!(
            (args.environment.as_deref(), args.org),
            (Some("app"), false)
        );
        let args = match parse(&[verb, "--org"]).unwrap() {
            IdentityCommand::Stop(args) | IdentityCommand::Resume(args) => args,
            other => panic!("{other:?}"),
        };
        assert_eq!((args.environment, args.org), (None, true));
        assert!(parse(&[verb]).is_err(), "{verb} names its target");
        assert!(
            parse(&[verb, "app", "--org"]).is_err(),
            "{verb} names one target"
        );
    }
}

#[test]
fn setting_groups_says_who_can_run_code_and_so_use_them() {
    let users = [
        user(
            "alice@example.com",
            IdentityGroupUserReason::IDENTITY_GROUP_USER_REASON_CREATOR,
        ),
        user(
            "bob@example.com",
            IdentityGroupUserReason::IDENTITY_GROUP_USER_REASON_OPERATOR_GRANT,
        ),
        user(
            "carol@example.com",
            IdentityGroupUserReason::IDENTITY_GROUP_USER_REASON_ORGANIZATION_ADMIN,
        ),
    ];
    let text = set_groups_text(
        "app",
        &["builders".to_owned(), "data-readers".to_owned()],
        true,
        &users,
        PLAIN,
    );
    assert_eq!(
        text,
        "✓ Identity groups of app: builders, data-readers\n\
         \n\
         Who can run code in app, and so use these groups:\n  \
         alice@example.com · created it\n  \
         bob@example.com · granted operator\n  \
         carol@example.com · organization owner or admin\n  \
         and every process running in app.\n\
         \n\
         The Sandbox gets the change within 5 minutes, when it renews its token. Tokens already issued keep their groups until they expire, within 10 minutes.\n"
    );
    assert!(!text.contains("id-"), "text names no user ID");

    let cleared = set_groups_text("app", &[], true, &users, PLAIN);
    assert!(cleared.starts_with("✓ Removed every identity group from app.\n"));
    assert!(!cleared.contains("Who can run code"));
    let unchanged = set_groups_text("app", &["builders".to_owned()], false, &users, PLAIN);
    assert!(unchanged.starts_with("app already has these identity groups: builders\n"));
    assert!(unchanged.contains("and every process running in app."));
    assert!(!unchanged.contains("The next token"));
}

#[test]
fn the_read_and_empty_states_are_plain_when_piped() {
    assert_eq!(
        groups_text("app", &["a".to_owned(), "b".to_owned()], PLAIN),
        "a\nb\n"
    );
    assert_eq!(
        groups_text("app", &[], PLAIN),
        "app has no identity groups.\n\n→ cw identity groups set app GROUP…\n"
    );
    assert_eq!(
        audiences_text(&[], PLAIN),
        "No audiences are registered.\n\n→ cw identity audience add URI\n"
    );
    for text in [
        groups_text("app", &[], PLAIN),
        set_groups_text("app", &["a".to_owned()], true, &[], PLAIN),
        minting_text(Switch::Stop, "app", true, PLAIN),
    ] {
        assert!(!text.contains('\u{1b}'), "{text:?}");
    }
}

#[test]
fn audiences_show_their_groups_lifetime_and_file() {
    let every = IdentityAudience {
        audience: "https://k8s.example".to_owned(),
        lifetime: Some(codewire_client::ProtoDuration::from_secs(600)).into(),
        ..Default::default()
    };
    let vault = IdentityAudience {
        audience: "https://vault.example.com:8200/v1/auth/jwt".to_owned(),
        visible_groups: Some(IdentityAudienceGroups {
            names: vec!["readers".to_owned()],
            ..Default::default()
        })
        .into(),
        lifetime: Some(codewire_client::ProtoDuration::from_secs(90)).into(),
        claim_created_by: true,
        file_name: Some("vault".to_owned()),
        ..Default::default()
    };
    let none = IdentityAudience {
        audience: "https://none.example".to_owned(),
        visible_groups: Some(IdentityAudienceGroups::default()).into(),
        lifetime: Some(codewire_client::ProtoDuration::from_secs(60)).into(),
        ..Default::default()
    };
    assert_eq!(
        audiences_text(&[every.clone(), vault.clone(), none], PLAIN),
        "AUDIENCE                                    LIFETIME    GROUPS        FILE\n\
         https://k8s.example                         10 minutes  every group   -\n\
         https://vault.example.com:8200/v1/auth/jwt  90 seconds  readers       vault\n\
         https://none.example                        1 minute    none but all  -\n"
    );
    assert_eq!(
        registered_text(&vault, PLAIN),
        "✓ Registered https://vault.example.com:8200/v1/auth/jwt\n  \
         Groups:    readers\n  \
         Lifetime:  90 seconds\n  \
         Claims:    created_by\n  \
         File:      /codewire/run/identity/vault.jwt\n"
    );
    assert_eq!(
        audience_json(&every),
        json!({
            "audience": "https://k8s.example",
            "visible_groups": null,
            "lifetime_seconds": 600,
            "claims": [],
            "file_name": null,
            "version": 0,
        })
    );
}

#[test]
fn stopping_says_issued_tokens_run_out() {
    assert_eq!(
        minting_text(Switch::Stop, "app", true, PLAIN),
        "✓ Minting stopped for app.\nSandboxes stop getting tokens within 5 minutes, when they renew. Tokens already issued stay valid until they expire, within 10 minutes.\n"
    );
    assert_eq!(
        minting_text(Switch::Stop, "app", false, PLAIN),
        "Minting was already stopped for app.\n"
    );
    assert_eq!(
        minting_text(
            Switch::Resume,
            "every Sandbox in the organization",
            true,
            PLAIN
        ),
        "✓ Minting resumed for every Sandbox in the organization.\n"
    );
    assert_eq!(
        minting_text(Switch::Resume, "app", false, PLAIN),
        "Minting was not stopped for app.\n"
    );
}
