//! Resolve omitted credential metadata before protected input or enrollment.

use codewire_access::{AccessProfileName, CredentialStatus, ProviderId};
use codewire_client::{self as rpc, CodewireClient};

use super::credential_input::{
    PROFILE_SLOTS, add_providers, execute_credential_operation, resolve_credential_operation,
    supported_profile_slot,
};
use super::guided::{self, Choice};
use super::storage_placement::StoragePlacement;
use super::*;

pub(super) fn missing(args: &CredentialsArgs) -> bool {
    match &args.command {
        CredentialsCommand::Add(a) => {
            a.provider.is_none()
                || a.name.is_none()
                || (a.provider.as_deref() == Some("ssh") && a.key_file.is_none())
        }
        CredentialsCommand::Connect(a) => a.provider.is_none() || a.name.is_none(),
        CredentialsCommand::Generate(a) => a.provider.is_none() || a.name.is_none(),
        CredentialsCommand::Set(a) => {
            args.profile.is_none() || a.slot.is_none() || a.credential.is_none()
        }
        _ => false,
    }
}

pub(super) async fn complete(
    globals: &Globals,
    args: &mut CredentialsArgs,
    placement: StoragePlacement,
    storage_missing: bool,
) -> anyhow::Result<()> {
    let was_missing = missing(args);
    if was_missing {
        guided::require_available(
            OutputFormat::Text,
            "supply the provider, --name NAME, and any required --profile/credential selector (see `cw credentials --help`)",
        )?;
    }
    match &mut args.command {
        CredentialsCommand::Add(a) => {
            a.guided = was_missing || storage_missing;
            if a.provider.is_none() {
                let providers = add_providers();
                let choices = providers
                    .iter()
                    .map(|(_, _, label)| Choice::new(*label, ""))
                    .collect::<Vec<_>>();
                a.provider = Some(
                    providers[guided::choose("Which provider?", &choices)?]
                        .0
                        .into(),
                );
            }
            fill_name(&mut a.name)?;
            if a.provider.as_deref() == Some("ssh") && a.key_file.is_none() {
                a.key_file = Some(
                    guided::text("OpenSSH private-key file", None, |value| {
                        let path = std::path::Path::new(value);
                        if path
                            .symlink_metadata()
                            .is_ok_and(|metadata| metadata.is_file())
                        {
                            Ok(())
                        } else {
                            Err("Choose an existing private-key file".into())
                        }
                    })?
                    .into(),
                );
            }
        }
        CredentialsCommand::Connect(a) => {
            a.guided = was_missing || storage_missing;
            if a.provider.is_none() {
                let providers = connect_rows();
                let choices = providers
                    .iter()
                    .map(|(_, label, detail)| Choice::new(*label, *detail))
                    .collect::<Vec<_>>();
                a.provider =
                    Some(providers[guided::choose("What do you want to connect?", &choices)?].0);
            }
            fill_name(&mut a.name)?;
        }
        CredentialsCommand::Generate(a) => {
            a.guided = was_missing || storage_missing;
            // SSH is the only identity Codewire generates.
            a.provider.get_or_insert_with(|| "ssh".into());
            fill_name(&mut a.name)?;
        }
        CredentialsCommand::Set(a) if a.slot.is_none() => {
            let slots = set_slots();
            let choices = slots
                .iter()
                .map(|slot| Choice::new(*slot, ""))
                .collect::<Vec<_>>();
            a.slot = Some(
                slots[guided::choose("Which provider should this profile use?", &choices)?].into(),
            );
        }
        _ => {}
    }
    if matches!(args.command, CredentialsCommand::Set(_))
        && (args.profile.is_none()
            || matches!(&args.command, CredentialsCommand::Set(a) if a.credential.is_none()))
    {
        complete_profile(globals, args, placement).await?;
    }
    Ok(())
}

/// The `connect` picker's rows: each provider `connect` takes, with its
/// label and detail, as the approved credentials screen 2 shows them
/// (owner, 2026-11-15, #4717), from the registry (#6286). The rows are
/// clap's own providers in their declared order, so a provider can't be
/// added to `connect` without its row (#5446); a test holds clap's providers
/// to the registry's `connect` types. `connect` takes the same providers in
/// both placements.
fn connect_rows() -> Vec<(CredentialConnectProviderArg, &'static str, &'static str)> {
    CredentialConnectProviderArg::value_variants()
        .iter()
        .map(|&provider| {
            let row = super::credential_input::connect::credential_type_of_arg(provider);
            (provider, row.label, row.detail)
        })
        .collect()
}

/// The `set` picker's rows: every slot `set` takes, in [`PROFILE_SLOTS`]'s
/// order. `set` takes each slot a profile has but GitHub's, which every
/// profile includes and both placements refuse to set
/// (`GITHUB_ALWAYS_INCLUDED`); a slot added to profiles is offered here
/// without a second list (#5446).
fn set_slots() -> Vec<&'static str> {
    PROFILE_SLOTS
        .into_iter()
        .filter(|slot| *slot != "github")
        .collect()
}

fn fill_name(name: &mut Option<String>) -> anyhow::Result<()> {
    if name.is_none() {
        *name = Some(guided::text(
            "Credential name (up to 256 bytes)",
            None,
            |value| {
                guided::required(value)?;
                if value.len() > 256 || value.chars().any(char::is_control) {
                    Err("A credential name is up to 256 bytes, with no control characters".into())
                } else {
                    Ok(())
                }
            },
        )?);
    }
    Ok(())
}

fn choose_profile(profiles: &[(String, String)]) -> anyhow::Result<String> {
    let mut choices = profiles
        .iter()
        .map(|(name, _)| Choice::new(name, "Existing profile"))
        .collect::<Vec<_>>();
    choices.push(Choice::new(
        "Create a profile",
        "Its first credential is saved with it",
    ));
    let index = guided::choose("Choose a profile", &choices)?;
    if let Some((_, selector)) = profiles.get(index) {
        return Ok(selector.clone());
    }
    guided::text("New profile name", None, |name| {
        AccessProfileName::parse(name)
            .map(|_| ())
            .map_err(|e| e.to_string())
    })
}

async fn complete_profile(
    globals: &Globals,
    args: &mut CredentialsArgs,
    placement: StoragePlacement,
) -> anyhow::Result<()> {
    let CredentialsCommand::Set(set) = &mut args.command else {
        return Ok(());
    };
    let slot = set.slot.as_deref().context("a provider is required")?;
    if placement == StoragePlacement::Local {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let mut client = connect_local_credential_authority().await?;
            if args.profile.is_none() {
                let profiles = profile_choices(globals, placement).await?;
                args.profile = Some(choose_profile(&profiles)?);
            }
            if set.credential.is_none() {
                let records = client
                    .list_credentials()
                    .await?
                    .into_iter()
                    .filter(|record| {
                        record.metadata.status == CredentialStatus::Active
                            && supported_profile_slot(
                                slot,
                                &record.metadata.provider,
                                record.metadata.authentication_kind,
                            )
                            .is_ok()
                    })
                    .collect::<Vec<_>>();
                if records.is_empty() {
                    set.credential = Some(enroll_for_profile(globals, placement, slot).await?);
                    return Ok(());
                }
                let choices = records
                    .iter()
                    .map(|record| {
                        Choice::new(
                            &record.metadata.display_name,
                            record.metadata.provider.to_string(),
                        )
                    })
                    .collect::<Vec<_>>();
                set.credential = Some(format!(
                    "id:{}",
                    records[guided::choose("Choose a compatible credential", &choices)?]
                        .metadata
                        .id
                ));
            }
        }
    } else {
        let client = platform_client(globals)?;
        if args.profile.is_none() {
            let profiles = profile_choices(globals, placement).await?;
            args.profile = Some(choose_profile(&profiles)?);
        }
        if set.credential.is_none() {
            let records = platform_credentials(&client)
                .await?
                .into_iter()
                .filter(|record| {
                    record.status == rpc::CredentialStatus::Active
                        && ProviderId::parse(&record.provider)
                            .ok()
                            .zip(
                                super::platform_profiles::platform_authentication_kind(record).ok(),
                            )
                            .is_some_and(|(provider, kind)| {
                                supported_profile_slot(slot, &provider, kind).is_ok()
                            })
                })
                .collect::<Vec<_>>();
            if records.is_empty() {
                set.credential = Some(enroll_for_profile(globals, placement, slot).await?);
                return Ok(());
            }
            let choices = records
                .iter()
                .map(|record| Choice::new(&record.name, &record.provider))
                .collect::<Vec<_>>();
            set.credential = Some(format!(
                "id:{}",
                records[guided::choose("Choose a compatible credential", &choices)?].id
            ));
        }
    }
    Ok(())
}

pub(super) fn platform_client(globals: &Globals) -> anyhow::Result<CodewireClient> {
    let paths = ResolvePaths::from_env(&OsEnv)?;
    let platform = resolve_platform(globals, &paths, &OsEnv)?;
    Ok(CodewireClient::with_token_provider(
        platform
            .client_config()?
            .with_user_agent(format!("codewire-cli/{CLI_VERSION}"))?,
        platform.token_provider()?,
    )?)
}

async fn platform_credentials(client: &CodewireClient) -> anyhow::Result<Vec<rpc::Credential>> {
    let mut records = Vec::new();
    let mut page_token = String::new();
    let mut cursors = BTreeSet::new();
    loop {
        let page = client
            .list_credentials(rpc::ListCredentialsRequest {
                page_size: 100,
                page_token,
                ..Default::default()
            })
            .await?;
        records.extend(page.credentials);
        if page.next_page_token.is_empty() {
            return Ok(records);
        }
        anyhow::ensure!(
            cursors.insert(page.next_page_token.clone()),
            "Codewire returned a repeated credential cursor"
        );
        page_token = page.next_page_token;
    }
}

async fn enroll_for_profile(
    globals: &Globals,
    placement: StoragePlacement,
    slot: &str,
) -> anyhow::Result<String> {
    if !guided::confirm("No compatible credentials. Set one up now?")? {
        anyhow::bail!(super::credentials::output::refusal::CANCELLED);
    }
    let command = match slot {
        "codex" => {
            let method = guided::choose(
                "How should this profile access Codex?",
                &[
                    Choice::new("Codex sign-in", "Sign in with your ChatGPT account"),
                    Choice::new("OpenAI API key", "Paste an API key"),
                ],
            )?;
            if method == 0 {
                CredentialsCommand::Connect(CredentialConnectArgs {
                    provider: Some(CredentialConnectProviderArg::Codex),
                    name: None,
                    yes: false,
                    output: crate::commands::OutputFormat::Text,
                    guided: false,
                })
            } else {
                CredentialsCommand::Add(CredentialAddArgs {
                    provider: Some("openai".into()),
                    name: None,
                    account_hint: None,
                    expires_at: None,
                    key_file: None,
                    guided: false,
                })
            }
        }
        "ssh" => {
            let action = guided::choose(
                "Set up an SSH identity",
                &[
                    Choice::new("Generate a key", "Codewire keeps the private key protected"),
                    Choice::new("Import a key", "Choose an existing private-key file"),
                ],
            )?;
            if action == 0 {
                CredentialsCommand::Generate(CredentialGenerateArgs {
                    provider: Some("ssh".into()),
                    name: None,
                    expires_at: None,
                    guided: false,
                })
            } else {
                CredentialsCommand::Add(CredentialAddArgs {
                    provider: Some("ssh".into()),
                    name: None,
                    account_hint: None,
                    expires_at: None,
                    key_file: None,
                    guided: false,
                })
            }
        }
        "anthropic" => {
            let options = [
                (Some(CredentialConnectProviderArg::Claude), "anthropic"),
                (Some(CredentialConnectProviderArg::ClaudeToken), "anthropic"),
                (None, "anthropic"),
            ];
            let labels = [
                Choice::new(
                    "Claude (sign-in)",
                    "your subscription; shows your plan and usage",
                ),
                Choice::new(
                    "Claude (token)",
                    "your subscription; lasts a year, for automation, model requests only",
                ),
                Choice::new("Anthropic API key", "Paste an API key"),
            ];
            match options[guided::choose("Connect Anthropic access", &labels)?] {
                (Some(provider), _) => CredentialsCommand::Connect(CredentialConnectArgs {
                    provider: Some(provider),
                    name: None,
                    yes: false,
                    output: crate::commands::OutputFormat::Text,
                    guided: false,
                }),
                (None, provider) => CredentialsCommand::Add(CredentialAddArgs {
                    provider: Some(provider.into()),
                    name: None,
                    account_hint: None,
                    expires_at: None,
                    key_file: None,
                    guided: false,
                }),
            }
        }
        "openai" => CredentialsCommand::Add(CredentialAddArgs {
            provider: Some(slot.into()),
            name: None,
            account_hint: None,
            expires_at: None,
            key_file: None,
            guided: false,
        }),
        _ => anyhow::bail!("unsupported provider; use codex, openai, github, anthropic or ssh"),
    };
    let mut args = CredentialsArgs {
        profile: None,
        command,
    };
    Box::pin(complete(globals, &mut args, placement, false)).await?;
    let operation = resolve_credential_operation(None, args.command, placement)?;
    match execute_credential_operation(globals, operation, placement).await? {
        super::credential_input::CredentialExecution::Saved(saved) => {
            Ok(format!("id:{}", saved.id))
        }
        super::credential_input::CredentialExecution::Unchanged => {
            anyhow::bail!(super::credentials::output::refusal::CANCELLED)
        }
    }
}

pub(super) fn assignment_slot(command: &CredentialsCommand) -> Option<String> {
    let slot = match command {
        CredentialsCommand::Add(a) if a.guided => match a.provider.as_deref()? {
            "claude-subscription" => "anthropic",
            provider => provider,
        },
        CredentialsCommand::Connect(a) if a.guided => match a.provider? {
            CredentialConnectProviderArg::Codex => "codex",
            CredentialConnectProviderArg::Claude | CredentialConnectProviderArg::ClaudeToken => {
                "anthropic"
            }
            CredentialConnectProviderArg::Github => return None,
        },
        CredentialsCommand::Generate(a) if a.guided => "ssh",
        _ => return None,
    };
    Some(slot.to_owned())
}

pub(super) async fn offer_assignment(
    globals: &Globals,
    placement: StoragePlacement,
    slot: &str,
    saved: &super::credential_input::SavedCredential,
) -> anyhow::Result<()> {
    eprintln!(
        "Credential {:?} saved. Profile assignment is optional.",
        saved.name
    );
    let action = guided::choose(
        "Use this credential in a profile?",
        &[
            Choice::new(
                "Choose or create a profile",
                "Select where this credential may be used",
            ),
            Choice::new("Finish", "Keep the credential without changing any profile"),
        ],
    )?;
    if action == 1 {
        return Ok(());
    }
    let mut args = CredentialsArgs {
        profile: None,
        command: CredentialsCommand::Set(CredentialProfileSetArgs {
            profile: String::new(),
            slot: Some(slot.into()),
            credential: Some(format!("id:{}", saved.id)),
        }),
    };
    complete_profile(globals, &mut args, placement)
        .await
        .context("credential saved; profile selection did not complete")?;
    let operation = resolve_credential_operation(args.profile, args.command, placement)?;
    execute_credential_operation(globals, operation, placement)
        .await
        .map(drop)
        .context("credential saved; profile assignment did not complete")
}

pub(super) async fn profile_choices(
    globals: &Globals,
    placement: StoragePlacement,
) -> anyhow::Result<Vec<(String, String)>> {
    if placement == StoragePlacement::Local {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let mut client = connect_local_credential_authority().await?;
            return Ok(client
                .list_profiles()
                .await?
                .into_iter()
                .map(|record| {
                    (
                        record.profile.name.to_string(),
                        format!("id:{}", record.profile.id),
                    )
                })
                .collect());
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        anyhow::bail!("local protected storage is unavailable on this host");
    }
    let client = platform_client(globals)?;
    Ok(super::platform_profiles::list_profiles(&client)
        .await?
        .into_iter()
        .map(|profile| (profile.name, format!("id:{}", profile.id)))
        .collect())
}

/// The configuration editor selects the protected store separately from VM placement.
pub(super) async fn choose_profile_reference(
    globals: &Globals,
    placement: StoragePlacement,
) -> anyhow::Result<String> {
    let profiles = profile_choices(globals, placement).await?;
    let mut choices = profiles
        .iter()
        .map(|(name, _)| Choice::new(name, "Profile"))
        .collect::<Vec<_>>();
    choices.push(Choice::new(
        "Set up a profile",
        "Choose its first provider credential",
    ));
    let index = guided::choose("Choose a profile", &choices)?;
    let selector = if let Some((_, selector)) = profiles.get(index) {
        selector.clone()
    } else {
        let mut args = CredentialsArgs {
            profile: None,
            command: CredentialsCommand::Set(CredentialProfileSetArgs {
                profile: String::new(),
                slot: None,
                credential: None,
            }),
        };
        complete(globals, &mut args, placement, false).await?;
        let selector = args.profile.clone().context("profile is required")?;
        if let CredentialsCommand::Set(set) = &args.command {
            eprintln!("  Profile       {}", progress::terminal_text(&selector));
            eprintln!(
                "  Provider      {}",
                progress::terminal_text(set.slot.as_deref().unwrap_or_default())
            );
            eprintln!(
                "  Credential    {}",
                progress::terminal_text(set.credential.as_deref().unwrap_or_default())
            );
        }
        anyhow::ensure!(
            guided::confirm("Put this credential in the profile?")?,
            super::credentials::output::refusal::CANCELLED
        );
        let operation = resolve_credential_operation(args.profile, args.command, placement)?;
        execute_credential_operation(globals, operation, placement).await?;
        selector
    };
    Ok(format!(
        "{}:{selector}",
        if placement == StoragePlacement::Local {
            "local"
        } else {
            "platform"
        }
    ))
}

#[cfg(test)]
mod tests {
    use super::super::credential_input::{PROVIDER_WORDS_FOR_TESTS, profile_set_credential};
    use super::*;

    #[test]
    fn omitted_credential_metadata_reaches_guided_resolution_but_flags_remain_direct() {
        for argv in [
            vec!["cw", "credentials", "add"],
            vec!["cw", "credentials", "connect"],
            vec!["cw", "credentials", "generate"],
            vec!["cw", "credentials", "set"],
        ] {
            let cli = Cli::try_parse_from(argv).unwrap();
            let Command::Credentials(args) = cli.command else {
                panic!("credentials");
            };
            assert!(missing(&args));
        }
        let cli = Cli::try_parse_from([
            "cw",
            "--local",
            "credentials",
            "add",
            "openai",
            "--name",
            "work",
        ])
        .unwrap();
        let Command::Credentials(args) = cli.command else {
            panic!("credentials");
        };
        assert!(!missing(&args));
    }

    /// Each picker shows the rows, in the order, it showed before #5446.
    #[test]
    fn each_picker_keeps_its_rows_and_their_order() {
        let connect = connect_rows()
            .into_iter()
            .map(|(provider, label, detail)| (word(provider), label, detail))
            .collect::<Vec<_>>();
        assert_eq!(
            connect,
            [
                (
                    "codex".to_owned(),
                    "Codex",
                    "sign in with your ChatGPT account"
                ),
                (
                    "github".to_owned(),
                    "GitHub",
                    "sign in with your GitHub account"
                ),
                (
                    "claude".to_owned(),
                    "Claude (sign-in)",
                    "your subscription; shows your plan and usage"
                ),
                (
                    "claude-token".to_owned(),
                    "Claude (token)",
                    "your subscription; lasts a year, for automation, model requests only"
                ),
            ]
        );
        assert_eq!(
            add_providers()
                .into_iter()
                .map(|(provider, _, label)| (provider, label))
                .collect::<Vec<_>>(),
            [
                ("openai", "OpenAI API key"),
                ("anthropic", "Anthropic API key"),
                ("ssh", "SSH private key"),
            ]
        );
        assert_eq!(set_slots(), ["codex", "openai", "anthropic", "ssh"]);
    }

    /// `connect` takes the registry's `connect` types, in its order (#6286).
    #[test]
    fn connect_takes_the_registrys_connect_types() {
        let taken = CredentialConnectProviderArg::value_variants()
            .iter()
            .map(|provider| word(*provider))
            .collect::<Vec<_>>();
        let registry =
            codewire_access::credential_types_for(codewire_access::CredentialVerb::Connect)
                .map(|row| row.word.to_owned())
                .collect::<Vec<_>>();
        assert_eq!(taken, registry);
    }

    /// `connect` takes, in either placement, exactly the providers its
    /// picker offers (#5446).
    #[test]
    fn the_connect_picker_offers_every_provider_connect_takes() {
        let offered = connect_rows()
            .into_iter()
            .map(|(provider, ..)| word(provider))
            .collect::<Vec<_>>();
        for placement in ["--local", "--cloud"] {
            for provider in PROVIDER_WORDS_FOR_TESTS {
                let taken = match Cli::try_parse_from([
                    "cw",
                    "credentials",
                    placement,
                    "connect",
                    provider,
                ]) {
                    Ok(Cli {
                        command:
                            Command::Credentials(CredentialsArgs {
                                command: CredentialsCommand::Connect(args),
                                ..
                            }),
                        ..
                    }) => args.provider.map(word),
                    _ => None,
                };
                assert_eq!(
                    taken.is_some(),
                    offered.iter().any(|row| row == provider),
                    "{placement} connect {provider}"
                );
                if let Some(taken) = taken {
                    assert_eq!(taken, provider);
                }
            }
        }
    }

    /// `set` takes, in either placement, exactly the slots its picker
    /// offers: clap takes a profile's slots, and the shared check both
    /// placements run refuses GitHub's (#5446).
    #[test]
    fn the_set_picker_offers_every_slot_set_takes() {
        let offered = set_slots();
        for placement in ["--local", "--cloud"] {
            for slot in PROVIDER_WORDS_FOR_TESTS {
                let taken = match Cli::try_parse_from([
                    "cw",
                    "credentials",
                    placement,
                    "--profile=work",
                    "set",
                    slot,
                    "selected-credential",
                ]) {
                    Ok(Cli {
                        command:
                            Command::Credentials(CredentialsArgs {
                                command: CredentialsCommand::Set(args),
                                ..
                            }),
                        ..
                    }) => profile_set_credential(&args).is_ok(),
                    _ => false,
                };
                assert_eq!(taken, offered.contains(&slot), "{placement} set {slot}");
            }
        }
    }

    fn word(provider: CredentialConnectProviderArg) -> String {
        provider
            .to_possible_value()
            .expect("every connect provider has a word")
            .get_name()
            .to_owned()
    }

    #[test]
    fn json_mode_never_offers_metadata_input() {
        assert!(!guided::available(OutputFormat::Json));
        assert!(
            guided::require_available(OutputFormat::Json, "supply a name")
                .unwrap_err()
                .to_string()
                .contains("JSON commands never prompt")
        );
    }
}
