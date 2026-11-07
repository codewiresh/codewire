//! Missing metadata for addition commands. Complete the review before the
//! existing handler performs its mutation; piped input is never metadata.
use super::guided::{self, Choice};
use super::*;

pub(super) fn required(
    value: Option<String>,
    label: &str,
    output: OutputFormat,
    repair: &str,
) -> anyhow::Result<String> {
    if let Some(value) = value {
        return Ok(trimmed_required(&value, label)?.to_owned());
    }
    guided::require_available(output, repair)?;
    guided::text(label, None, nonempty)
}

fn nonempty(value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err("Enter a value, or press Esc to cancel.".to_owned())
    } else {
        Ok(())
    }
}

pub(super) fn review(title: &str, rows: &[(&str, String)]) -> anyhow::Result<()> {
    eprintln!("\n{title}\n");
    for (label, value) in rows {
        eprintln!("  {label:14} {}", progress::terminal_text(value));
    }
    anyhow::ensure!(guided::confirm(title)?, "canceled; nothing changed");
    Ok(())
}

pub(super) fn org_choice<'a>(
    orgs: &'a [OrgWithRole],
    selected: Option<&str>,
) -> anyhow::Result<&'a OrgWithRole> {
    if selected.is_some() || !guided::available(OutputFormat::Text) {
        return select_org(orgs, selected);
    }
    anyhow::ensure!(
        !orgs.is_empty(),
        "no organizations found; create one with `cw org create`"
    );
    let choices = orgs
        .iter()
        .map(|org| {
            Choice::new(
                org.name.clone(),
                format!("{} · {} · {}", org.slug, org.role, org.id),
            )
        })
        .collect::<Vec<_>>();
    let index = guided::choose("Choose an organization", &choices)?;
    Ok(&orgs[index])
}

pub(super) fn org_metadata(command: &mut Option<OrgCommand>) -> anyhow::Result<bool> {
    match command {
        Some(OrgCommand::Create(args)) => {
            let guided = args.name.is_none();
            args.name = Some(required(
                args.name.take(),
                "Organization name",
                OutputFormat::Text,
                "name the organization: `cw org create NAME`",
            )?);
            if guided && args.slug.is_none() {
                let default = slugify(args.name.as_deref().unwrap_or_default());
                args.slug = Some(guided::text(
                    "Organization slug",
                    Some(&default),
                    valid_slug,
                )?);
            }
            Ok(guided)
        }
        Some(OrgCommand::Invite(args)) => {
            let guided = args.email.is_none();
            args.email = Some(match args.email.take() {
                Some(email) => trimmed_required(&email, "email")?.to_owned(),
                None => {
                    guided::require_available(
                        OutputFormat::Text,
                        "name the invitation recipient: `cw org invite EMAIL [--role member|admin|owner]`",
                    )?;
                    guided::text("Email", None, invitation_email)?
                }
            });
            if guided && args.role.is_none() {
                args.role = Some(
                    ["member", "admin", "owner"][guided::choose(
                        "Role for this invitation",
                        &[
                            Choice::new("Member", "Work within the organization"),
                            Choice::new("Admin", "Manage the organization"),
                            Choice::new("Owner", "Full organization ownership"),
                        ],
                    )?]
                    .to_owned(),
                );
            }
            Ok(guided)
        }
        _ => Ok(false),
    }
}

pub(super) fn api_key_metadata(command: &mut ApiKeyCommand) -> anyhow::Result<bool> {
    let ApiKeyCommand::Create(args) = command else {
        return Ok(false);
    };
    let guided = args.name.is_none();
    args.name = Some(required(
        args.name.take(),
        "API key name",
        OutputFormat::Text,
        "name the API key: `cw api-keys create NAME [--expires DAYS]`",
    )?);
    if guided && args.expires.is_none() {
        args.expires = Some(
            [30, 90, 0][guided::choose(
                "When should this key expire?",
                &[
                    Choice::new("30 days", ""),
                    Choice::new("90 days", ""),
                    Choice::new("Never", "No automatic expiry"),
                ],
            )?],
        );
    }
    Ok(guided)
}

pub(super) fn preset_metadata(command: &mut PresetCommand) -> anyhow::Result<bool> {
    let PresetCommand::Create(args) = command else {
        return Ok(false);
    };
    let guided = args.slug.is_none() || args.image.is_none();
    if guided {
        guided::require_available(
            OutputFormat::Text,
            "name the preset and image: `cw preset create SLUG --image IMAGE`",
        )?;
    }
    args.slug = Some(match args.slug.take() {
        Some(slug) => trimmed_required(&slug, "preset slug")?.to_owned(),
        None => guided::text("Preset slug", None, valid_slug)?,
    });
    if args.image.is_none() {
        let options = ["workspace", "node", "python", "golang"];
        let index = guided::choose(
            "Default image",
            &[
                Choice::new("Workspace", "Codewire development tools"),
                Choice::new("Node", "Node.js"),
                Choice::new("Python", "Python"),
                Choice::new("Go", "Go"),
                Choice::new("Another image", "Enter a container image reference"),
            ],
        )?;
        args.image = Some(if index < options.len() {
            options[index].to_owned()
        } else {
            guided::text("Container image", None, nonempty)?
        });
    }
    if guided {
        while guided::choose(
            "Preset settings",
            &[
                Choice::new("Continue", "Review and create the preset"),
                Choice::new(
                    "Edit optional settings",
                    "Name, resources, TTL and setup commands",
                ),
            ],
        )? == 1
        {
            let setting = guided::choose(
                "Which setting?",
                &[
                    Choice::new(
                        "Display name",
                        args.name.as_deref().unwrap_or("Use the slug"),
                    ),
                    Choice::new(
                        "CPU cores",
                        args.cpu.as_deref().unwrap_or("Use the environment default"),
                    ),
                    Choice::new(
                        "Memory (MB)",
                        args.memory
                            .map(|v| v.to_string())
                            .unwrap_or_else(|| "Use the environment default".into()),
                    ),
                    Choice::new(
                        "Disk (GB)",
                        args.disk
                            .map(|v| v.to_string())
                            .unwrap_or_else(|| "Use the environment default".into()),
                    ),
                    Choice::new(
                        "Time to live",
                        args.ttl.as_deref().unwrap_or("Use the environment default"),
                    ),
                    Choice::new("Install command", args.install.as_deref().unwrap_or("None")),
                    Choice::new("Startup command", args.startup.as_deref().unwrap_or("None")),
                ],
            )?;
            match setting {
                0 => {
                    args.name = Some(guided::text(
                        "Display name",
                        args.name.as_deref().or(args.slug.as_deref()),
                        nonempty,
                    )?)
                }
                1 => {
                    args.cpu = Some(guided::text("CPU cores", args.cpu.as_deref(), |value| {
                        super::environment::parse_resize_cpu(value)
                            .map(|_| ())
                            .map_err(|e| e.to_string())
                    })?)
                }
                2 | 3 => {
                    let previous =
                        if setting == 2 { args.memory } else { args.disk }.map(|v| v.to_string());
                    let value = guided::text(
                        if setting == 2 {
                            "Memory (MB)"
                        } else {
                            "Disk (GB)"
                        },
                        previous.as_deref(),
                        |value| {
                            value
                                .parse::<i32>()
                                .ok()
                                .filter(|v| *v > 0)
                                .map(|_| ())
                                .ok_or_else(|| "Enter a positive whole number".to_owned())
                        },
                    )?
                    .parse::<i32>()?;
                    if setting == 2 {
                        args.memory = Some(value);
                    } else {
                        args.disk = Some(value);
                    }
                }
                4 => {
                    args.ttl = Some(guided::text(
                        "Time to live (for example 1h)",
                        args.ttl.as_deref(),
                        |value| {
                            parse_go_duration_seconds(value)
                                .map(|_| ())
                                .map_err(|e| e.to_string())
                        },
                    )?)
                }
                5 => {
                    args.install = Some(guided::text(
                        "Install command",
                        args.install.as_deref(),
                        nonempty,
                    )?)
                }
                6 => {
                    args.startup = Some(guided::text(
                        "Startup command",
                        args.startup.as_deref(),
                        nonempty,
                    )?)
                }
                _ => unreachable!(),
            }
        }
    }
    Ok(guided)
}

// Same lightweight shape check as the organization invitation form. The
// service remains authoritative for invitation policy and delivery.
fn invitation_email(value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 320 || !value.contains('@') {
        Err("Enter a valid email address".to_owned())
    } else {
        Ok(())
    }
}

fn valid_slug(value: &str) -> Result<(), String> {
    if !value.is_empty()
        && value.len() <= 48
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !value.starts_with('-')
        && !value.ends_with('-')
    {
        Ok(())
    } else {
        Err("Use 1–48 lowercase letters, digits or internal hyphens.".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supplied_metadata_never_needs_a_terminal() {
        assert_eq!(
            required(Some(" work ".into()), "Name", OutputFormat::Json, "repair").unwrap(),
            "work"
        );
        assert!(required(Some("  ".into()), "Name", OutputFormat::Text, "repair").is_err());
    }

    #[test]
    fn machine_mode_refuses_missing_metadata_before_any_input() {
        let error = required(None, "Name", OutputFormat::Json, "cw command NAME").unwrap_err();
        assert!(error.to_string().contains("cw command NAME"));
    }

    #[test]
    fn slug_validation_rejects_invalid_answers_for_correction() {
        for slug in ["", "My Project", "-work", "work-", "../work"] {
            assert!(valid_slug(slug).is_err(), "{slug}");
        }
        assert!(valid_slug("my-project-2").is_ok());
    }

    #[test]
    fn full_flag_additions_preserve_explicit_settings_without_prompts() {
        let Command::Org { command: mut org } = Cli::try_parse_from([
            "cw",
            "org",
            "invite",
            "person@example.invalid",
            "--role",
            "admin",
            "--org",
            "acme",
        ])
        .unwrap()
        .command
        else {
            panic!("org");
        };
        assert!(!org_metadata(&mut org).unwrap());
        let Some(OrgCommand::Invite(args)) = org else {
            panic!("invite");
        };
        assert_eq!(args.role.as_deref(), Some("admin"));
        assert_eq!(args.org.as_deref(), Some("acme"));

        let Command::Preset { mut command } = Cli::try_parse_from([
            "cw",
            "preset",
            "create",
            "Existing_Name",
            "--image",
            "registry.example.invalid/dev:1",
            "--cpu",
            "0.5",
        ])
        .unwrap()
        .command
        else {
            panic!("preset");
        };
        assert!(!preset_metadata(&mut command).unwrap());
        let PresetCommand::Create(args) = command else {
            panic!("create");
        };
        assert_eq!(args.slug.as_deref(), Some("Existing_Name"));
        assert_eq!(args.cpu.as_deref(), Some("0.5"));

        let Command::ApiKeys { mut command } =
            Cli::try_parse_from(["cw", "api-keys", "create", "work", "--expires", "365"])
                .unwrap()
                .command
        else {
            panic!("key");
        };
        assert!(!api_key_metadata(&mut command).unwrap());
        let ApiKeyCommand::Create(args) = command else {
            panic!("create");
        };
        assert_eq!(args.expires, Some(365));
    }

    #[test]
    fn addition_parser_reaches_guidance_with_omitted_metadata() {
        for args in [
            vec!["cw", "org", "create"],
            vec!["cw", "org", "invite"],
            vec!["cw", "api-keys", "create"],
            vec!["cw", "preset", "create"],
            vec!["cw", "policy", "create"],
            vec!["cw", "network", "create"],
            vec!["cw", "network", "use"],
            vec!["cw", "snapshot", "create"],
        ] {
            assert!(Cli::try_parse_from(&args).is_ok(), "{args:?}");
        }
    }

    #[test]
    fn invitation_email_check_matches_the_invitation_form() {
        for invalid in ["", "person", "person.example.invalid"] {
            assert!(invitation_email(invalid).is_err());
        }
        assert!(invitation_email("person@example.invalid").is_ok());
    }

    #[tokio::test]
    async fn json_additions_refuse_missing_targets_before_client_setup() {
        let globals = Globals {
            server: None,
            member: None,
            placement: None,
            org: None,
        };
        let Command::Policy(args) =
            Cli::try_parse_from(["cw", "policy", "create", "--output", "json"])
                .unwrap()
                .command
        else {
            panic!("policy");
        };
        let error = super::super::policy::handle_policy_command(&globals, args)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("cw --local policy create NAME"));
        let Command::Snapshot(args) =
            Cli::try_parse_from(["cw", "snapshot", "create", "--output", "json"])
                .unwrap()
                .command
        else {
            panic!("snapshot");
        };
        let error = super::super::snapshot::handle_snapshot_command(&globals, args)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("cw snapshot create ENV"));
    }

    #[test]
    fn automatic_network_attachment_remains_an_explicit_use_choice() {
        let Command::Network {
            command: NetworkCommand::Create(args),
        } = Cli::try_parse_from(["cw", "network", "create", "work", "--org", "org-work"])
            .unwrap()
            .command
        else {
            panic!("create");
        };
        assert!(!args.auto_connect);
        assert!(
            Cli::try_parse_from([
                "cw",
                "network",
                "create",
                "work",
                "--org",
                "org-work",
                "--auto-connect"
            ])
            .is_err()
        );
        let Command::Network {
            command: NetworkCommand::Use(args),
        } = Cli::try_parse_from(["cw", "network", "use", "--auto-connect"])
            .unwrap()
            .command
        else {
            panic!("use");
        };
        assert!(args.auto_connect);
        assert!(args.name.is_none());
    }
}
