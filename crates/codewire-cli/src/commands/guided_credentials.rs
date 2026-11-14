//! Resolve omitted credential metadata before protected input or enrollment.

use codewire_access::{AccessProfileName, CredentialStatus, ProviderId};
use codewire_client::{self as rpc, CodewireClient};

use super::credential_input::{
    execute_credential_operation, resolve_credential_operation, supported_profile_slot,
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
    if placement == StoragePlacement::Local {
        anyhow::ensure!(
            !matches!(&args.command, CredentialsCommand::Connect(a) if matches!(a.provider, Some(CredentialConnectProviderArg::Claude))),
            "Claude sign-ins are stored only in your Codewire account; use --cloud"
        );
        anyhow::ensure!(
            !matches!(&args.command, CredentialsCommand::Add(a) if a.provider.as_deref() == Some("claude-subscription")),
            "Claude subscription tokens are stored only in your Codewire account; use --cloud"
        );
    }
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
                let mut providers = vec![
                    ("openai", "OpenAI API key"),
                    ("anthropic", "Anthropic API key"),
                    ("ssh", "SSH private key"),
                ];
                if placement == StoragePlacement::Platform {
                    providers.push(("claude-subscription", "Claude subscription token"));
                }
                let choices = providers
                    .iter()
                    .map(|(_, label)| Choice::new(*label, ""))
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
                let mut providers = vec![
                    (
                        CredentialConnectProviderArg::Codex,
                        "Codex",
                        "Device sign-in",
                    ),
                    (
                        CredentialConnectProviderArg::Github,
                        "GitHub",
                        "Device sign-in",
                    ),
                ];
                if placement == StoragePlacement::Platform {
                    providers.push((
                        CredentialConnectProviderArg::Claude,
                        "Claude",
                        "Browser sign-in",
                    ));
                }
                let choices = providers
                    .iter()
                    .map(|(_, label, detail)| Choice::new(*label, *detail))
                    .collect::<Vec<_>>();
                a.provider =
                    Some(providers[guided::choose("Connect which provider?", &choices)?].0);
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
            let slots = ["codex", "openai", "anthropic", "ssh"];
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

fn fill_name(name: &mut Option<String>) -> anyhow::Result<()> {
    if name.is_none() {
        *name = Some(guided::text("Credential name", None, |value| {
            guided::required(value)?;
            if value.len() > 256 || value.chars().any(char::is_control) {
                Err("Use at most 256 bytes without control characters".into())
            } else {
                Ok(())
            }
        })?);
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
    let index = guided::choose("Choose a credential profile", &choices)?;
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
            "platform returned a repeated credential cursor"
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
        anyhow::bail!("canceled; no profile was changed");
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
        "anthropic" if placement == StoragePlacement::Platform => {
            let action = guided::choose(
                "Connect Anthropic access",
                &[
                    Choice::new("Claude sign-in", "Browser sign-in"),
                    Choice::new(
                        "Claude subscription token",
                        "Paste a token from claude setup-token",
                    ),
                    Choice::new("Anthropic API key", "Paste an API key"),
                ],
            )?;
            if action == 0 {
                CredentialsCommand::Connect(CredentialConnectArgs {
                    provider: Some(CredentialConnectProviderArg::Claude),
                    name: None,
                    yes: false,
                    guided: false,
                })
            } else {
                CredentialsCommand::Add(CredentialAddArgs {
                    provider: Some(
                        if action == 1 {
                            "claude-subscription"
                        } else {
                            "anthropic"
                        }
                        .into(),
                    ),
                    name: None,
                    account_hint: None,
                    expires_at: None,
                    key_file: None,
                    guided: false,
                })
            }
        }
        "openai" | "anthropic" => CredentialsCommand::Add(CredentialAddArgs {
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
            anyhow::bail!("canceled; no profile was changed")
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
            CredentialConnectProviderArg::Claude => "anthropic",
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
        .map(|(name, _)| Choice::new(name, "Credential profile"))
        .collect::<Vec<_>>();
    choices.push(Choice::new(
        "Set up a profile",
        "Choose its first provider credential",
    ));
    let index = guided::choose("Choose a credential profile", &choices)?;
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
            guided::confirm("Save this credential profile binding?")?,
            "canceled; profile binding was not saved"
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
