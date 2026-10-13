use std::collections::BTreeMap;
use std::io::IsTerminal as _;

use anyhow::Context as _;
#[cfg(test)]
use codewire_access::{AccessProfileId, CredentialId};
use codewire_access::{
    AccessProfileName, CapabilitySlot, CredentialAuthKind, CredentialStatus, Owner, ProviderId,
    builtin_provider_catalog,
};
use codewire_local_credentials::{
    AccessProfileRecord, AccessProfileRevisionRecord, CredentialRecord, LocalCredentialClient,
    NewCredential,
};
#[cfg(test)]
use codewire_protected_store::MAX_PROTECTED_VALUE_BYTES;
use codewire_protected_store::ProtectedStorePersistence;
use codewire_protected_store::ProtectedValue;
use serde::Serialize;

#[cfg(test)]
use super::CredentialsArgs;
#[cfg(test)]
use super::credential_input::CODEX_DEVICE_AUTHORIZATION_GUIDANCE;
use super::credential_input::{
    CredentialOperation, GITHUB_ALWAYS_INCLUDED, ParsedCredentialSelector, ParsedProfileSelector,
    parse_credential_selector, parse_profile_selector, profile_set_credential,
    prompt_credential_material, read_ssh_import, supported_profile_slot, validate_ssh_generation,
    validate_ssh_import,
};
#[cfg(test)]
use super::credential_input::{
    credential_command_json, read_protected_value, resolve_credential_operation,
};
#[cfg(test)]
use super::storage_placement::StoragePlacement;
#[cfg(test)]
use super::storage_placement::resolve_storage_placement;
use super::{
    CredentialAddArgs, CredentialConnectArgs, CredentialConnectProviderArg, CredentialDeleteArgs,
    CredentialListArgs, CredentialProfileCommand, CredentialProfileDeleteArgs,
    CredentialProfileSetArgs, CredentialProfileSlotArgs, CredentialRenameArgs,
    CredentialRotateArgs, CredentialSelectorArgs, CredentialsCommand, OutputFormat,
    connect_local_credential_authority, prompt_confirm_default_no, trimmed_required,
};

pub(crate) async fn handle_local_credentials_command(
    operation: CredentialOperation,
) -> anyhow::Result<()> {
    let mut client = connect_local_credential_authority().await?;
    let command = match operation {
        CredentialOperation::Profile(command) => {
            return profile_command(&mut client, command).await;
        }
        CredentialOperation::Credential(command) => command,
    };
    match command {
        CredentialsCommand::Connect(args) => connect_credential(&mut client, args).await,
        CredentialsCommand::Add(args) => add_credential(&mut client, args).await,
        CredentialsCommand::Generate(args) => {
            let name = validate_ssh_generation(&args)?;
            let record = client.generate_ssh_credential(name, args.expires_at).await
                .context("generate local SSH identity; inspect by name before retrying an uncertain acknowledgement")?;
            print_credentials(&[record], OutputFormat::Text)
        }
        CredentialsCommand::List(args) => list_credentials(&mut client, args).await,
        CredentialsCommand::Get(args) => {
            get_credential(
                &mut client,
                CredentialSelectorArgs {
                    credential: args
                        .credential
                        .context("get requires a credential selector or --profile")?,
                    output: args.output,
                },
            )
            .await
        }
        CredentialsCommand::Rename(args) => rename_credential(&mut client, args).await,
        CredentialsCommand::Rotate(args) => rotate_credential(&mut client, args).await,
        CredentialsCommand::Revoke(args) => revoke_credential(&mut client, args).await,
        CredentialsCommand::Delete(args) => delete_credential(&mut client, args).await,
        CredentialsCommand::Set(_)
        | CredentialsCommand::Unset(_)
        | CredentialsCommand::Revisions(_)
        | CredentialsCommand::Profiles { .. } => {
            unreachable!("profile operations have a separate dispatcher")
        }
    }
}

async fn connect_credential(
    client: &mut LocalCredentialClient,
    args: CredentialConnectArgs,
) -> anyhow::Result<()> {
    match args.provider {
        CredentialConnectProviderArg::Codex => connect_codex(client, args).await,
        CredentialConnectProviderArg::Github => connect_github(client, args).await,
    }
}

async fn connect_codex(
    client: &mut LocalCredentialClient,
    args: CredentialConnectArgs,
) -> anyhow::Result<()> {
    let Some(target) = prepare_oauth_connection(client, &args, "openai").await? else {
        return Ok(());
    };
    let (bundle, account_hint) = super::provider_login::codex_device_login()
        .await?
        .into_parts();
    let mut bytes = bundle.into_bytes();
    let material = ProtectedValue::new(std::mem::take(&mut *bytes))
        .context("prepare protected Codex credential")?;
    let record = publish_oauth_connection(client, target, material, account_hint)
        .await
        .context(
            "local Codex storage acknowledgement is unknown; inspect the credential list before retrying",
        )?;
    eprintln!(
        "Local Codex credential {:?} connected ({}).",
        record.metadata.display_name, record.metadata.id
    );
    Ok(())
}

async fn connect_github(
    client: &mut LocalCredentialClient,
    args: CredentialConnectArgs,
) -> anyhow::Result<()> {
    let Some(target) = prepare_oauth_connection(client, &args, "github").await? else {
        return Ok(());
    };
    let mut import = super::provider_login::github_device_login().await?;
    let reach = import.reach().to_vec();
    // A reconnect keeps the GitHub account its profiles already follow.
    if let Some(expected) = target
        .existing
        .as_ref()
        .and_then(|record| record.metadata.account_hint.as_deref())
    {
        anyhow::ensure!(
            expected == import.account_hint(),
            "the approved GitHub account {:?} is not the connected account {expected:?}; no credential was changed",
            import.account_hint(),
        );
    }
    let (mut bytes, account_hint) = import
        .take_import()
        .context("prepare protected GitHub credential")?;
    let material = ProtectedValue::new(std::mem::take(&mut *bytes))
        .context("prepare protected GitHub credential")?;
    let record = publish_oauth_connection(client, target, material, account_hint)
        .await
        .context(
            "local GitHub storage acknowledgement is unknown; inspect the credential list before retrying",
        )?;
    eprintln!(
        "Local GitHub credential {:?} connected ({}).",
        record.metadata.display_name, record.metadata.id
    );
    eprintln!("{}", github_reach_summary(&reach));
    report_github_pending(reach.iter().filter_map(|installation| {
        let pending = installation.pending_permissions.as_ref()?;
        Some((
            installation.account.as_str(),
            pending.installation_id,
            pending.account_kind,
        ))
    }));
    Ok(())
}

/// After a GitHub connect, name each installation that has not yet granted
/// what Codewire needs and, at a terminal, open the first one's settings page
/// to accept it, the way `cw login` opens its page (#2712). Elsewhere the
/// printed link is the way there.
pub(crate) fn report_github_pending<'a>(
    pending: impl IntoIterator<Item = (&'a str, u64, codewire_credential_broker::GitHubAccountKind)>,
) {
    let interactive = std::io::stdin().is_terminal() && std::io::stderr().is_terminal();
    let (notices, open) = github_pending_follow_up(pending, interactive);
    for notice in notices {
        eprintln!("{notice}");
    }
    if let Some(url) = open {
        eprintln!("Opening GitHub to accept the updated permissions...");
        let _ = super::platform_commands::open_browser(&url);
    }
}

/// The notices to print, and the settings page to open when `interactive`:
/// the first one there is. An enterprise has none.
fn github_pending_follow_up<'a>(
    pending: impl IntoIterator<Item = (&'a str, u64, codewire_credential_broker::GitHubAccountKind)>,
    interactive: bool,
) -> (Vec<String>, Option<String>) {
    let mut notices = Vec::new();
    let mut open = None;
    for (account, installation_id, kind) in pending {
        let Some(notice) = github_pending_notice(account, installation_id, kind) else {
            continue;
        };
        notices.push(notice);
        if interactive && open.is_none() {
            open = github_settings_page(account, installation_id, kind);
        }
    }
    (notices, open)
}

/// Said once when GitHub is connected: an installation that has not yet
/// granted what Codewire needs keeps reads working, but pushes and pull
/// requests fail until its owner accepts the updated permissions (#2712).
/// The link is built from the validated login and installation ID; an
/// enterprise accepts in its own settings, so it gets no link.
fn github_pending_notice(
    account: &str,
    installation_id: u64,
    kind: codewire_credential_broker::GitHubAccountKind,
) -> Option<String> {
    if !valid_github_installation(account, installation_id) {
        return None;
    }
    let accept = match github_settings_page(account, installation_id, kind) {
        Some(url) => format!("Accept the updated permissions on GitHub: {url}"),
        None => "Accept the updated permissions in the enterprise's GitHub settings.".to_owned(),
    };
    Some(format!(
        "GitHub has not yet given Codewire write access to code and pull requests on {account}. {accept}"
    ))
}

/// The installation's GitHub settings page, built only from a validated login
/// and numeric ID. An enterprise has none.
fn github_settings_page(
    account: &str,
    installation_id: u64,
    kind: codewire_credential_broker::GitHubAccountKind,
) -> Option<String> {
    if !valid_github_installation(account, installation_id) {
        return None;
    }
    codewire_credential_broker::GitHubAppPendingPermissions {
        installation_id,
        account_kind: kind,
    }
    .settings_url(account)
}

fn valid_github_installation(account: &str, installation_id: u64) -> bool {
    (1..=39).contains(&account.len())
        && !account.starts_with('-')
        && !account.ends_with('-')
        && !account.contains("--")
        && account
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && installation_id > 0
}

/// What the Codewire GitHub App can reach for this login, and where to change
/// it. GitHub decides access per installation, not per Codewire credential.
fn github_reach_summary(
    reach: &[codewire_credential_broker::GitHubAppInstallationReach],
) -> String {
    let accounts = reach
        .iter()
        .map(|installation| {
            let scope = if installation.all_repositories {
                "all repositories"
            } else {
                "selected repositories"
            };
            format!("{} ({scope})", installation.account)
        })
        .collect::<Vec<_>>();
    let reach = if accounts.is_empty() {
        "Codewire can read repositories where the Codewire GitHub App is installed.".to_owned()
    } else {
        format!(
            "Codewire can read repositories in: {}.",
            accounts.join(", ")
        )
    };
    format!(
        "{reach}\nTo add an account or organization, or choose repositories: {}",
        codewire_credential_broker::provider_oauth::github::codewire_github_app_install_url()
    )
}

struct OAuthConnectionTarget {
    provider: ProviderId,
    display_name: String,
    existing: Option<CredentialRecord>,
}

async fn prepare_oauth_connection(
    client: &mut LocalCredentialClient,
    args: &CredentialConnectArgs,
    provider: &str,
) -> anyhow::Result<Option<OAuthConnectionTarget>> {
    let display_name = trimmed_required(&args.name, "credential name")?;
    let records = client
        .list_credentials()
        .await
        .context("check local credential name before provider login")?;
    let target = select_oauth_connection_target(records, display_name, provider)?;
    let confirmed = confirm_oauth_connection_with(
        &target,
        args.yes,
        std::io::stdin().is_terminal() && std::io::stderr().is_terminal(),
        prompt_confirm_default_no,
    )?;
    if !confirmed {
        eprintln!("Canceled; no credential was changed.");
        return Ok(None);
    }
    Ok(Some(target))
}

fn select_oauth_connection_target(
    records: Vec<CredentialRecord>,
    display_name: &str,
    provider: &str,
) -> anyhow::Result<OAuthConnectionTarget> {
    let provider = ProviderId::parse(provider)?;
    // GitHub is one connection per store: reconnect it in place whatever name
    // was supplied, keeping its identity and name. Only create when absent.
    if provider.as_str() == "github" {
        let mut connections = records.iter().filter(|record| {
            record.metadata.provider == provider
                && record.metadata.authentication_kind == CredentialAuthKind::OAuth
        });
        if let Some(record) = connections.next() {
            anyhow::ensure!(
                connections.next().is_none(),
                "more than one local GitHub connection exists; delete all but one before reconnecting"
            );
            record.metadata.validate()?;
            return Ok(OAuthConnectionTarget {
                provider,
                display_name: record.metadata.display_name.clone(),
                existing: Some(record.clone()),
            });
        }
    }
    let mut matches = records.into_iter().filter(|record| {
        record
            .metadata
            .display_name
            .eq_ignore_ascii_case(display_name)
    });
    let existing = matches.next();
    anyhow::ensure!(
        matches.next().is_none(),
        "local credential name {display_name:?} is ambiguous; inspect and rename the records before reconnecting"
    );
    if let Some(record) = &existing {
        anyhow::ensure!(
            record.metadata.provider == provider
                && record.metadata.authentication_kind == CredentialAuthKind::OAuth,
            "local credential {display_name:?} belongs to a different provider or authentication kind; use a distinct name"
        );
        record.metadata.validate()?;
    }
    Ok(OAuthConnectionTarget {
        provider,
        display_name: display_name.to_owned(),
        existing,
    })
}

fn confirm_oauth_connection_with(
    target: &OAuthConnectionTarget,
    yes: bool,
    is_terminal: bool,
    prompt: impl FnOnce(&str) -> anyhow::Result<bool>,
) -> anyhow::Result<bool> {
    let Some(record) = &target.existing else {
        return Ok(true);
    };
    let message = format!(
        "Reconnect local OAuth credential {:?} ({}, revision {}, status {})? Its identity and profile bindings will be kept; the credential will become active and its hard expiry will be preserved.",
        record.metadata.display_name,
        record.metadata.id,
        record.metadata.revocation_generation,
        status_label(record.metadata.status),
    );
    if yes {
        eprintln!("{message}");
        return Ok(true);
    }
    anyhow::ensure!(
        is_terminal,
        "reconnecting an existing local OAuth credential requires terminal confirmation or --yes"
    );
    prompt(&message)
}

async fn publish_oauth_connection(
    client: &mut LocalCredentialClient,
    target: OAuthConnectionTarget,
    material: ProtectedValue,
    account_hint: Option<String>,
) -> Result<CredentialRecord, tonic::Status> {
    if let Some(record) = target.existing {
        // Do not resolve the name or retry a newer revision after provider
        // login. Confirmation authorized only this exact credential revision.
        client
            .rotate_credential_material(
                &record.metadata.id,
                record.metadata.revocation_generation,
                material,
                record.metadata.expires_at_unix,
                account_hint,
            )
            .await
    } else {
        client
            .add_credential(
                NewCredential {
                    provider: target.provider,
                    authentication_kind: CredentialAuthKind::OAuth,
                    display_name: target.display_name,
                    account_hint,
                    expires_at_unix: None,
                },
                material,
            )
            .await
    }
}

async fn add_credential(
    client: &mut LocalCredentialClient,
    args: CredentialAddArgs,
) -> anyhow::Result<()> {
    if args.provider == "ssh" {
        let name = validate_ssh_import(&args)?;
        anyhow::ensure!(
            !client
                .list_credentials()
                .await?
                .iter()
                .any(|record| record.metadata.display_name.eq_ignore_ascii_case(&name)),
            "credential name already exists"
        );
        let input = read_ssh_import(&args)?;
        let record = client.add_ssh_credential(name, input.private_key, input.passphrase, args.expires_at).await
            .context("import local SSH identity; inspect by name before retrying an uncertain acknowledgement")?;
        return print_credentials(&[record], OutputFormat::Text);
    }
    anyhow::ensure!(
        args.key_file.is_none(),
        "--key-file is only valid for add ssh"
    );
    let provider = ProviderId::parse(trimmed_required(&args.provider, "provider")?)
        .context("invalid credential provider")?;
    let authentication_kind = api_key_enrollment_kind(provider.as_str())?;
    let catalog = builtin_provider_catalog();
    let definition = catalog
        .get(&provider)
        .ok_or_else(|| anyhow::anyhow!("provider {provider} is not available"))?;
    if !definition.supports_authentication_kind(authentication_kind) {
        anyhow::bail!(
            "provider {provider} does not support {} credentials yet",
            authentication_kind_label(authentication_kind)
        );
    }

    let input = NewCredential {
        provider,
        authentication_kind,
        display_name: trimmed_required(&args.name, "credential name")?.to_owned(),
        account_hint: args
            .account_hint
            .as_deref()
            .map(|value| trimmed_required(value, "account hint").map(str::to_owned))
            .transpose()?,
        expires_at_unix: args.expires_at,
    };
    let material = prompt_credential_material()?;
    let record = client
        .add_credential(input, material)
        .await
        .context("add local credential")?;
    eprintln!(
        "Local credential {:?} added ({}).",
        record.metadata.display_name, record.metadata.id
    );
    Ok(())
}

async fn list_credentials(
    client: &mut LocalCredentialClient,
    args: CredentialListArgs,
) -> anyhow::Result<()> {
    let records = client
        .list_credentials()
        .await
        .context("list local credentials")?;
    print_credentials(&records, args.output)
}

async fn get_credential(
    client: &mut LocalCredentialClient,
    args: CredentialSelectorArgs,
) -> anyhow::Result<()> {
    let record = resolve_credential(client, &args.credential).await?;
    print_credentials(&[record], args.output)
}

async fn rename_credential(
    client: &mut LocalCredentialClient,
    args: CredentialRenameArgs,
) -> anyhow::Result<()> {
    let record = resolve_credential(client, &args.credential).await?;
    let name = trimmed_required(&args.name, "credential name")?.to_owned();
    let renamed = client
        .rename_credential(&record.metadata.id, name)
        .await
        .context("rename local credential")?;
    eprintln!(
        "Local credential renamed to {:?}.",
        renamed.metadata.display_name
    );
    Ok(())
}

async fn rotate_credential(
    client: &mut LocalCredentialClient,
    args: CredentialRotateArgs,
) -> anyhow::Result<()> {
    let record = resolve_credential(client, &args.credential).await?;
    if record.metadata.authentication_kind == CredentialAuthKind::SshKey {
        anyhow::bail!(
            "enroll a new SSH identity with generate ssh or add ssh, then select it in the credential profile; private keys cannot use raw rotation"
        );
    }
    if !manually_supplied_credential_kind(record.metadata.authentication_kind) {
        anyhow::bail!(
            "{} credential material cannot be entered manually; use credentials connect with the existing OAuth provider and --name to reconnect it",
            authentication_kind_label(record.metadata.authentication_kind)
        );
    }
    let material = prompt_credential_material()?;
    let rotated = client
        .rotate_credential_material(
            &record.metadata.id,
            record.metadata.revocation_generation,
            material,
            args.expires_at,
            record.metadata.account_hint.clone(),
        )
        .await
        .context("rotate local credential")?;
    eprintln!(
        "Local credential {:?} rotated to generation {}.",
        rotated.metadata.display_name, rotated.metadata.revocation_generation
    );
    Ok(())
}

async fn revoke_credential(
    client: &mut LocalCredentialClient,
    args: CredentialSelectorArgs,
) -> anyhow::Result<()> {
    let record = resolve_credential(client, &args.credential).await?;
    let revoked = client
        .revoke_credential(&record.metadata.id)
        .await
        .context("revoke local credential")?;
    print_credentials(&[revoked], args.output)
}

async fn delete_credential(
    client: &mut LocalCredentialClient,
    args: CredentialDeleteArgs,
) -> anyhow::Result<()> {
    let record = resolve_credential(
        client,
        args.credential
            .as_deref()
            .context("delete requires a credential selector")?,
    )
    .await?;
    if !args.yes
        && !prompt_confirm_default_no(&format!(
            "Delete local credential {:?}?",
            record.metadata.display_name
        ))?
    {
        eprintln!("Canceled.");
        return Ok(());
    }
    client
        .delete_credential(&record.metadata.id)
        .await
        .context("delete local credential")?;
    eprintln!(
        "Local credential {:?} deleted.",
        record.metadata.display_name
    );
    Ok(())
}

async fn profile_command(
    client: &mut LocalCredentialClient,
    command: CredentialProfileCommand,
) -> anyhow::Result<()> {
    match command {
        CredentialProfileCommand::List(args) => {
            let records = client
                .list_profiles()
                .await
                .context("list local access profiles")?;
            print_profiles(&records, args.output)
        }
        CredentialProfileCommand::Get(args) => {
            let record = resolve_profile(client, &args.profile).await?;
            if let Some(revision) = args.revision {
                let revision = client
                    .get_profile_revision(&record.profile.id, revision)
                    .await
                    .context("get exact local profile revision")?;
                print_profile_revisions(&[revision], args.output)
            } else {
                print_profiles(&[record], args.output)
            }
        }
        CredentialProfileCommand::Set(args) => set_profile_entry(client, args).await,
        CredentialProfileCommand::Unset(args) => unset_profile_entry(client, args).await,
        CredentialProfileCommand::Revisions(args) => {
            if args.revision.is_some() {
                anyhow::bail!("use --profile=NAME get --revision REVISION to inspect one revision");
            }
            let profile = resolve_profile(client, &args.profile).await?;
            let revisions = client
                .list_profile_revisions(&profile.profile.id)
                .await
                .context("list local access profile revisions")?;
            print_profile_revisions(&revisions, args.output)
        }
        CredentialProfileCommand::Delete(args) => delete_profile(client, args).await,
    }
}

async fn set_profile_entry(
    client: &mut LocalCredentialClient,
    args: CredentialProfileSetArgs,
) -> anyhow::Result<()> {
    let selector = profile_set_credential(&args)?;
    let credential = resolve_credential(client, selector).await?;
    let slot = supported_profile_slot(
        &args.slot,
        &credential.metadata.provider,
        credential.metadata.authentication_kind,
    )?;
    let (existing, name) = local_profile_for_set(client, &args.profile).await?;
    let mut entries = existing
        .as_ref()
        .map(|record| record.profile.entries.clone())
        .unwrap_or_default();
    entries.insert(slot, credential.metadata.id);
    // Creation publishes the first complete selection atomically. An existing
    // profile gets exactly one immutable CAS update, with no conflict retry.
    let updated = match existing {
        Some(profile) => client
            .update_profile(&profile.profile.id, profile.profile.revision, &entries)
            .await.context("update exact local access profile revision")?,
        None => client.create_profile(&name.context("new profiles require a name")?, &entries)
            .await.context("create local profile with its first selection; inspect before retrying an uncertain result")?,
    };
    eprintln!(
        "Local access profile {:?} updated to revision {}.",
        updated.profile.name.to_string(),
        updated.profile.revision
    );
    Ok(())
}

async fn local_profile_for_set(
    client: &mut LocalCredentialClient,
    selector: &str,
) -> anyhow::Result<(Option<AccessProfileRecord>, Option<AccessProfileName>)> {
    let name = match parse_profile_selector(selector)? {
        ParsedProfileSelector::Id(_) => {
            return Ok((Some(resolve_profile(client, selector).await?), None));
        }
        ParsedProfileSelector::Name(name) => name,
        ParsedProfileSelector::Reference(reference) => {
            anyhow::ensure!(
                reference.scope() == codewire_access::AccessProfileScope::User,
                "local storage supports user profiles only"
            );
            reference.name().clone()
        }
    };
    // A successful complete metadata listing proves absence; a backend failure
    // is never converted into permission to create a new profile.
    let profiles = client
        .list_profiles()
        .await
        .context("list local profiles before setting an exact selection")?;
    let profile = optional_profile_by_name(&profiles, name.as_str())?.cloned();
    Ok((profile, Some(name)))
}

async fn unset_profile_entry(
    client: &mut LocalCredentialClient,
    args: CredentialProfileSlotArgs,
) -> anyhow::Result<()> {
    anyhow::ensure!(args.slot != "github", GITHUB_ALWAYS_INCLUDED);
    let profile = resolve_profile(client, &args.profile).await?;
    let slot = CapabilitySlot::parse(trimmed_required(&args.slot, "capability slot")?)
        .context("invalid capability slot")?;
    let mut entries = profile.profile.entries.clone();
    if entries.remove(&slot).is_none() {
        anyhow::bail!(
            "local access profile {:?} does not select slot {slot}",
            profile.profile.name.to_string()
        );
    }
    let updated = client
        .update_profile(&profile.profile.id, profile.profile.revision, &entries)
        .await
        .context("update local access profile")?;
    eprintln!(
        "Local access profile {:?} updated to revision {}.",
        updated.profile.name.to_string(),
        updated.profile.revision
    );
    Ok(())
}

async fn delete_profile(
    client: &mut LocalCredentialClient,
    args: CredentialProfileDeleteArgs,
) -> anyhow::Result<()> {
    let record = resolve_profile(client, &args.profile).await?;
    if !args.yes
        && !prompt_confirm_default_no(&format!(
            "Delete local access profile {:?}?",
            record.profile.name.to_string()
        ))?
    {
        eprintln!("Canceled.");
        return Ok(());
    }
    client
        .delete_profile(&record.profile.id)
        .await
        .context("delete local access profile")?;
    eprintln!(
        "Local access profile {:?} deleted.",
        record.profile.name.to_string()
    );
    Ok(())
}

async fn resolve_credential(
    client: &mut LocalCredentialClient,
    selector: &str,
) -> anyhow::Result<CredentialRecord> {
    match parse_credential_selector(selector)? {
        ParsedCredentialSelector::Id(id) => client
            .get_credential(&id)
            .await
            .with_context(|| format!("get local credential by ID {id}")),
        ParsedCredentialSelector::Name(name) => {
            let records = client
                .list_credentials()
                .await
                .context("list local credentials")?;
            select_credential_by_name(&records, name)
        }
    }
}

async fn resolve_profile(
    client: &mut LocalCredentialClient,
    selector: &str,
) -> anyhow::Result<AccessProfileRecord> {
    match parse_profile_selector(selector)? {
        ParsedProfileSelector::Id(id) => client
            .get_profile(&id)
            .await
            .with_context(|| format!("get local access profile by ID {id}")),
        ParsedProfileSelector::Reference(reference) => client
            .resolve_profile(&reference)
            .await
            .with_context(|| format!("resolve local access profile {reference}")),
        ParsedProfileSelector::Name(name) => {
            let records = client
                .list_profiles()
                .await
                .context("list local access profiles")?;
            select_profile_by_name(&records, name.as_str())
        }
    }
}

fn select_credential_by_name(
    records: &[CredentialRecord],
    name: &str,
) -> anyhow::Result<CredentialRecord> {
    let mut matches = records
        .iter()
        .filter(|record| record.metadata.display_name.eq_ignore_ascii_case(name));
    let record = matches
        .next()
        .ok_or_else(|| anyhow::anyhow!("local credential name {name:?} was not found"))?;
    if matches.next().is_some() {
        anyhow::bail!("local credential name {name:?} is ambiguous");
    }
    Ok(record.clone())
}

fn select_profile_by_name(
    records: &[AccessProfileRecord],
    name: &str,
) -> anyhow::Result<AccessProfileRecord> {
    optional_profile_by_name(records, name)?
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("local access profile name {name:?} was not found"))
}

fn optional_profile_by_name<'a>(
    records: &'a [AccessProfileRecord],
    name: &str,
) -> anyhow::Result<Option<&'a AccessProfileRecord>> {
    let mut matches = records
        .iter()
        .filter(|record| record.profile.name.as_str().eq_ignore_ascii_case(name));
    let record = matches.next();
    if matches.next().is_some() {
        anyhow::bail!("local access profile name {name:?} is ambiguous");
    }
    Ok(record)
}

fn api_key_enrollment_kind(provider: &str) -> anyhow::Result<CredentialAuthKind> {
    match provider {
        "openai" | "anthropic" => Ok(CredentialAuthKind::ApiKey),
        "claude-subscription" => anyhow::bail!(
            "Claude subscription tokens are stored only on the Codewire platform; add one with --platform"
        ),
        "codex" | "github" => {
            anyhow::bail!("use connect {provider} --name NAME for OAuth credentials")
        }
        _ => anyhow::bail!("provider {provider} does not support API-key enrollment"),
    }
}

fn manually_supplied_credential_kind(value: CredentialAuthKind) -> bool {
    matches!(
        value,
        CredentialAuthKind::ApiKey | CredentialAuthKind::AccessToken
    )
}

fn authentication_kind_label(value: CredentialAuthKind) -> &'static str {
    match value {
        CredentialAuthKind::OAuth => "oauth",
        CredentialAuthKind::ApiKey => "api_key",
        CredentialAuthKind::AccessToken => "access_token",
        CredentialAuthKind::GitHubApp => "github_app",
        CredentialAuthKind::SshKey => "ssh_key",
    }
}

fn status_label(value: CredentialStatus) -> &'static str {
    match value {
        CredentialStatus::Active => "active",
        CredentialStatus::Expired => "expired",
        CredentialStatus::RefreshFailed => "refresh_failed",
        CredentialStatus::Revoked => "revoked",
    }
}

fn persistence_label(value: ProtectedStorePersistence) -> &'static str {
    match value {
        ProtectedStorePersistence::OperatingSystem => "operating_system",
        ProtectedStorePersistence::ProcessLifetime => "process_lifetime",
    }
}

fn owner_label(value: &Owner) -> String {
    match value {
        Owner::User(id) => format!("user/{id}"),
        Owner::Organization(id) => format!("organization/{id}"),
    }
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct CredentialView {
    id: String,
    placement: &'static str,
    owner: String,
    provider: String,
    authentication_kind: &'static str,
    name: String,
    account_hint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ssh_public_key: Option<codewire_access::SshPublicKeyMetadata>,
    status: &'static str,
    expires_at_unix: Option<u64>,
    revocation_generation: u64,
    protected_store_persistence: &'static str,
    cleanup_pending: bool,
    created_at_unix_ms: u64,
    updated_at_unix_ms: u64,
}

impl From<&CredentialRecord> for CredentialView {
    fn from(record: &CredentialRecord) -> Self {
        Self {
            id: record.metadata.id.to_string(),
            placement: "local",
            owner: owner_label(&record.metadata.owner),
            provider: record.metadata.provider.to_string(),
            authentication_kind: authentication_kind_label(record.metadata.authentication_kind),
            name: record.metadata.display_name.clone(),
            account_hint: record.metadata.account_hint.clone(),
            ssh_public_key: record.metadata.ssh_public_key.clone(),
            status: status_label(record.metadata.status),
            expires_at_unix: record.metadata.expires_at_unix,
            revocation_generation: record.metadata.revocation_generation,
            protected_store_persistence: persistence_label(record.persistence),
            cleanup_pending: record.protected_store_cleanup_pending,
            created_at_unix_ms: record.created_at_unix_ms,
            updated_at_unix_ms: record.updated_at_unix_ms,
        }
    }
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct AccessProfileView {
    id: String,
    placement: &'static str,
    owner: String,
    name: String,
    revision: u64,
    entries: BTreeMap<String, String>,
    profile_created_at_unix_ms: u64,
    revision_created_at_unix_ms: u64,
}

impl AccessProfileView {
    fn current(record: &AccessProfileRecord) -> Self {
        Self::new(
            &record.profile,
            record.created_at_unix_ms,
            record.updated_at_unix_ms,
        )
    }

    fn revision(record: &AccessProfileRevisionRecord) -> Self {
        Self::new(
            &record.profile,
            record.profile_created_at_unix_ms,
            record.revision_created_at_unix_ms,
        )
    }

    fn new(
        profile: &codewire_access::AccessProfile,
        profile_created_at_unix_ms: u64,
        revision_created_at_unix_ms: u64,
    ) -> Self {
        Self {
            id: profile.id.to_string(),
            placement: "local",
            owner: owner_label(&profile.owner),
            name: profile.name.to_string(),
            revision: profile.revision,
            entries: profile
                .entries
                .iter()
                .map(|(slot, credential)| (slot.to_string(), credential.to_string()))
                .collect(),
            profile_created_at_unix_ms,
            revision_created_at_unix_ms,
        }
    }
}

fn print_credentials(records: &[CredentialRecord], output: OutputFormat) -> anyhow::Result<()> {
    let views = records.iter().map(CredentialView::from).collect::<Vec<_>>();
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&views)?),
        OutputFormat::Text => print!("{}", format_credentials_text(&views)),
    }
    Ok(())
}

fn print_profiles(records: &[AccessProfileRecord], output: OutputFormat) -> anyhow::Result<()> {
    let views = records
        .iter()
        .map(AccessProfileView::current)
        .collect::<Vec<_>>();
    print_profile_views(&views, output)
}

fn print_profile_revisions(
    records: &[AccessProfileRevisionRecord],
    output: OutputFormat,
) -> anyhow::Result<()> {
    let views = records
        .iter()
        .map(AccessProfileView::revision)
        .collect::<Vec<_>>();
    print_profile_views(&views, output)
}

fn print_profile_views(views: &[AccessProfileView], output: OutputFormat) -> anyhow::Result<()> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(views)?),
        OutputFormat::Text => print!("{}", format_profiles_text(views)),
    }
    Ok(())
}

fn format_credentials_text(records: &[CredentialView]) -> String {
    let mut output = format!(
        "{:<36} {:<10} {:<18} {:<16} {:<24} {:<24} {:<16} {:<18} GENERATION\n",
        "ID", "PLACEMENT", "PROVIDER", "KIND", "NAME", "HINT", "STATUS", "STORE"
    );
    for record in records {
        output.push_str(&format!(
            "{:<36} {:<10} {:<18} {:<16} {:<24} {:<24} {:<16} {:<18} {}\n",
            record.id,
            record.placement,
            record.provider,
            record.authentication_kind,
            record.name,
            record.account_hint.as_deref().unwrap_or("-"),
            record.status,
            record.protected_store_persistence,
            record.revocation_generation
        ));
        if let Some(key) = &record.ssh_public_key {
            output.push_str(&format!("  {}\n  {}\n", key.openssh, key.fingerprint));
        }
    }
    output
}

fn format_profiles_text(records: &[AccessProfileView]) -> String {
    let mut output = format!(
        "{:<36} {:<10} {:<24} {:<10} ENTRIES\n",
        "ID", "PLACEMENT", "NAME", "REVISION"
    );
    for record in records {
        let entries = record
            .entries
            .iter()
            .map(|(slot, credential)| format!("{slot}={credential}"))
            .collect::<Vec<_>>()
            .join(",");
        output.push_str(&format!(
            "{:<36} {:<10} {:<24} {:<10} {}\n",
            record.id, record.placement, record.name, record.revision, entries
        ));
    }
    output
}

#[cfg(test)]
mod tests {
    #[test]
    fn oversized_stdin_after_maximum_crlf_is_not_silently_truncated() {
        let mut input = vec![b'x'; super::MAX_PROTECTED_VALUE_BYTES];
        input.extend_from_slice(b"\r\n");
        assert_eq!(
            super::read_protected_value(input.as_slice(), false)
                .unwrap()
                .expose_secret()
                .len(),
            super::MAX_PROTECTED_VALUE_BYTES
        );
        input.extend_from_slice(b"suffix");
        assert!(super::read_protected_value(input.as_slice(), false).is_err());
    }
    use std::io::Cursor;
    use std::path::Path;
    use std::time::Duration;

    use clap::Parser as _;
    use codewire_access::{
        AccessProfile, AccessProfileScope, CredentialMetadata, OwnerId, Placement,
    };

    use super::*;
    use crate::{Cli, Command};

    #[test]
    fn codex_connect_help_explains_device_authorization_for_both_placements() {
        for placement in ["--local", "--platform"] {
            let error = Cli::try_parse_from(["cw", "credentials", placement, "connect", "--help"])
                .unwrap_err();
            assert_eq!(error.kind(), clap::error::ErrorKind::DisplayHelp);
            let help = error
                .to_string()
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            assert!(help.contains(CODEX_DEVICE_AUTHORIZATION_GUIDANCE), "{help}");
        }
    }

    fn credential() -> CredentialRecord {
        credential_with("11111111-1111-4111-8111-111111111111", "work-openai")
    }

    fn credential_with(id: &str, display_name: &str) -> CredentialRecord {
        CredentialRecord {
            metadata: CredentialMetadata {
                id: CredentialId::parse(id).unwrap(),
                placement: Placement::Local,
                owner: Owner::User(OwnerId::parse("local-user").unwrap()),
                provider: ProviderId::parse("openai").unwrap(),
                authentication_kind: CredentialAuthKind::ApiKey,
                display_name: display_name.into(),
                account_hint: Some("work@example.test".into()),
                ssh_public_key: None,
                status: CredentialStatus::Active,
                expires_at_unix: None,
                revocation_generation: 1,
            },
            persistence: ProtectedStorePersistence::OperatingSystem,
            protected_store_cleanup_pending: false,
            created_at_unix_ms: 10,
            updated_at_unix_ms: 20,
        }
    }

    fn profile_with(id: &str, name: &str) -> AccessProfileRecord {
        AccessProfileRecord {
            profile: AccessProfile {
                id: AccessProfileId::parse(id).unwrap(),
                placement: Placement::Local,
                owner: Owner::User(OwnerId::parse("local-user").unwrap()),
                name: AccessProfileName::parse(name).unwrap(),
                revision: 1,
                entries: BTreeMap::new(),
            },
            created_at_unix_ms: 10,
            updated_at_unix_ms: 20,
        }
    }

    #[test]
    fn oauth_connection_name_selects_only_one_exact_matching_identity() {
        let mut record = credential();
        record.metadata.authentication_kind = CredentialAuthKind::OAuth;
        record.metadata.revocation_generation = 7;
        let target =
            select_oauth_connection_target(vec![record.clone()], "WORK-OPENAI", "openai").unwrap();
        assert_eq!(target.existing.unwrap(), record);
        for provider in ["github", "anthropic"] {
            assert!(
                select_oauth_connection_target(vec![record.clone()], "work-openai", provider,)
                    .is_err()
            );
        }
        let mut wrong_kind = record.clone();
        wrong_kind.metadata.authentication_kind = CredentialAuthKind::ApiKey;
        assert!(
            select_oauth_connection_target(vec![wrong_kind], "work-openai", "openai",).is_err()
        );
        let mut duplicate = record.clone();
        duplicate.metadata.id =
            CredentialId::parse("22222222-2222-4222-8222-222222222222").unwrap();
        let error =
            select_oauth_connection_target(vec![record, duplicate], "work-openai", "openai")
                .err()
                .unwrap();
        assert!(error.to_string().contains("ambiguous"));
    }

    #[test]
    fn new_oauth_name_needs_no_replacement_confirmation() {
        let target =
            select_oauth_connection_target(vec![credential()], "new-name", "github").unwrap();
        assert!(target.existing.is_none());
        assert!(
            confirm_oauth_connection_with(&target, false, false, |_| {
                panic!("new enrollment must not prompt for replacement");
            })
            .unwrap()
        );
    }

    #[test]
    fn oauth_reconnect_requires_yes_or_a_positive_terminal_confirmation() {
        let mut record = credential();
        record.metadata.authentication_kind = CredentialAuthKind::OAuth;
        record.metadata.status = CredentialStatus::Revoked;
        record.metadata.revocation_generation = 7;
        let target =
            select_oauth_connection_target(vec![record.clone()], "work-openai", "openai").unwrap();
        let error = confirm_oauth_connection_with(&target, false, false, |_| {
            panic!("noninteractive reconnect must not read stdin");
        })
        .unwrap_err();
        assert!(error.to_string().contains("--yes"));
        assert!(
            confirm_oauth_connection_with(&target, true, false, |_| {
                panic!("--yes must not read stdin");
            })
            .unwrap()
        );
        for answer in [false, true] {
            assert_eq!(
                confirm_oauth_connection_with(&target, false, true, |message| {
                    assert!(message.contains(record.metadata.id.as_str()));
                    assert!(message.contains("revision 7"));
                    assert!(message.contains("revoked"));
                    assert!(message.contains("profile bindings will be kept"));
                    assert!(message.contains("hard expiry will be preserved"));
                    Ok(answer)
                })
                .unwrap(),
                answer
            );
        }
        assert!(
            confirm_oauth_connection_with(&target, false, true, |_| {
                Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "synthetic EOF").into())
            })
            .is_err()
        );
    }

    #[test]
    fn oauth_connect_parser_accepts_explicit_reconnect_confirmation() {
        for placement in ["--local", "--platform"] {
            for provider in ["codex", "github"] {
                let parsed = Cli::try_parse_from([
                    "cw",
                    "credentials",
                    placement,
                    "connect",
                    provider,
                    "--name=work",
                    "--yes",
                ])
                .unwrap();
                assert!(matches!(
                    parsed.command,
                    Command::Credentials(CredentialsArgs {
                        command: CredentialsCommand::Connect(CredentialConnectArgs {
                            yes: true,
                            ..
                        }),
                        ..
                    })
                ));
            }
        }
    }

    #[tokio::test]
    async fn oauth_publication_reconnect_keeps_profile_and_fails_stale_without_retry() {
        let temp = tempfile::tempdir().unwrap();
        let config = codewire_local_credentials::AuthorityRuntimeConfig {
            root: temp.path().join("authority"),
            executable: std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap(),
        };
        let server = tokio::spawn(
            codewire_local_credentials::serve_local_credential_authority(
                config.clone(),
                codewire_protected_store::EphemeralProtectedStore::default(),
                builtin_provider_catalog(),
            ),
        );
        let mut client = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if let Ok(client) = LocalCredentialClient::connect(&config).await {
                    break client;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("synthetic authority ready");
        for (provider, slot) in [
            ("openai", CapabilitySlot::codex()),
            ("github", CapabilitySlot::github()),
        ] {
            let name = format!("work-{provider}");
            let target = select_oauth_connection_target(Vec::new(), &name, provider).unwrap();
            let created = publish_oauth_connection(
                &mut client,
                target,
                ProtectedValue::from_slice(b"synthetic-first-oauth").unwrap(),
                Some("first@example.test".into()),
            )
            .await
            .unwrap();
            assert!(client.list_profiles().await.unwrap().iter().all(|profile| {
                !profile
                    .profile
                    .entries
                    .values()
                    .any(|id| id == &created.metadata.id)
            }));
            let profile = client
                .create_profile(
                    &AccessProfileName::parse(&name).unwrap(),
                    &BTreeMap::from([(slot, created.metadata.id.clone())]),
                )
                .await
                .unwrap();
            let current = client
                .rotate_credential_material(
                    &created.metadata.id,
                    created.metadata.revocation_generation,
                    ProtectedValue::from_slice(b"synthetic-current-oauth").unwrap(),
                    Some(4_102_444_800),
                    created.metadata.account_hint.clone(),
                )
                .await
                .unwrap();
            let stale_target =
                select_oauth_connection_target(vec![current.clone()], &name, provider).unwrap();
            let revoked = client
                .revoke_credential(&current.metadata.id)
                .await
                .unwrap();
            let error = publish_oauth_connection(
                &mut client,
                stale_target,
                ProtectedValue::from_slice(b"synthetic-stale-oauth").unwrap(),
                None,
            )
            .await
            .unwrap_err();
            assert_eq!(error.code(), tonic::Code::FailedPrecondition);
            assert_eq!(
                client.get_credential(&current.metadata.id).await.unwrap(),
                revoked
            );
            let confirmed_target =
                select_oauth_connection_target(vec![revoked.clone()], &name, provider).unwrap();
            let reconnected = publish_oauth_connection(
                &mut client,
                confirmed_target,
                ProtectedValue::from_slice(b"synthetic-reconnected-oauth").unwrap(),
                None,
            )
            .await
            .unwrap();
            assert_eq!(reconnected.metadata.id, created.metadata.id);
            assert_eq!(
                reconnected.metadata.revocation_generation,
                revoked.metadata.revocation_generation + 1
            );
            assert_eq!(
                reconnected.metadata.expires_at_unix,
                current.metadata.expires_at_unix
            );
            assert_eq!(reconnected.metadata.account_hint, None);
            assert_eq!(reconnected.metadata.status, CredentialStatus::Active);
            assert_eq!(
                client.get_profile(&profile.profile.id).await.unwrap(),
                profile
            );
            assert_eq!(
                client
                    .list_profile_revisions(&profile.profile.id)
                    .await
                    .unwrap()
                    .len(),
                1
            );
        }
        assert_eq!(client.list_credentials().await.unwrap().len(), 2);
        client.shutdown().await.unwrap();
        tokio::time::timeout(Duration::from_secs(3), server)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[test]
    fn credential_commands_use_shared_storage_placement() {
        assert_eq!(
            resolve_storage_placement(true, false, false).unwrap(),
            StoragePlacement::Local
        );
        assert_eq!(
            resolve_storage_placement(false, true, false).unwrap(),
            StoragePlacement::Platform
        );
        assert!(resolve_storage_placement(false, false, true).is_err());
        assert!(resolve_storage_placement(true, true, false).is_err());
    }

    #[test]
    fn credential_metadata_json_commands_never_prompt_for_placement() {
        use clap::Parser as _;
        for tail in [
            vec!["list"],
            vec!["get", "work"],
            vec!["revoke", "work"],
            vec!["profiles", "list"],
            vec!["--profile=work", "get"],
            vec!["--profile=work", "list"],
            vec!["--profile=work", "revisions"],
        ] {
            let mut argv = vec!["cw", "credentials"];
            argv.extend(tail);
            argv.extend(["--output", "json"]);
            let crate::Command::Credentials(args) =
                crate::Cli::try_parse_from(argv).unwrap().command
            else {
                panic!("expected credentials command")
            };
            assert!(credential_command_json(&args.command));
            assert!(
                resolve_storage_placement(
                    args.local,
                    args.platform,
                    credential_command_json(&args.command)
                )
                .is_err()
            );
        }
    }

    #[test]
    fn credential_selectors_never_confuse_names_with_ids() {
        const FIRST_ID: &str = "11111111-1111-4111-8111-111111111111";
        const SECOND_ID: &str = "22222222-2222-4222-8222-222222222222";
        const THIRD_ID: &str = "33333333-3333-4333-8333-333333333333";
        let id_prefixed_name = format!("id:{FIRST_ID}");
        let records = vec![
            credential_with(FIRST_ID, "work-openai"),
            credential_with(SECOND_ID, FIRST_ID),
            credential_with(THIRD_ID, &id_prefixed_name),
        ];

        let ParsedCredentialSelector::Name(name) = parse_credential_selector(FIRST_ID).unwrap()
        else {
            panic!("a bare credential selector must be a name");
        };
        assert_eq!(
            select_credential_by_name(&records, name)
                .unwrap()
                .metadata
                .id
                .as_str(),
            SECOND_ID
        );

        let ParsedCredentialSelector::Id(id) =
            parse_credential_selector(&format!("id:{FIRST_ID}")).unwrap()
        else {
            panic!("an id: credential selector must be an ID");
        };
        assert_eq!(id.as_str(), FIRST_ID);

        let explicit_uuid_name = format!("name:{FIRST_ID}");
        let ParsedCredentialSelector::Name(name) =
            parse_credential_selector(&explicit_uuid_name).unwrap()
        else {
            panic!("a name: credential selector must be a name");
        };
        assert_eq!(
            select_credential_by_name(&records, name)
                .unwrap()
                .metadata
                .id
                .as_str(),
            SECOND_ID
        );

        let explicit_id_prefixed_name = format!("name:{id_prefixed_name}");
        let ParsedCredentialSelector::Name(name) =
            parse_credential_selector(&explicit_id_prefixed_name).unwrap()
        else {
            panic!("name: must escape a name beginning with id:");
        };
        assert_eq!(
            select_credential_by_name(&records, name)
                .unwrap()
                .metadata
                .id
                .as_str(),
            THIRD_ID
        );
    }

    #[test]
    fn credential_selectors_reject_malformed_prefixes_and_name_collisions() {
        const ID: &str = "11111111-1111-4111-8111-111111111111";
        for selector in [
            "id:",
            "id:not-a-uuid",
            "id:11111111-1111-4111-8111-11111111111A",
            "id:00000000-0000-0000-0000-000000000000",
            "name:",
            "name: work",
            "provider:work",
        ] {
            assert!(
                parse_credential_selector(selector).is_err(),
                "selector {selector:?} must fail"
            );
        }

        let records = vec![
            credential_with(ID, "work"),
            credential_with("22222222-2222-4222-8222-222222222222", "WORK"),
        ];
        let error = select_credential_by_name(&records, "work").unwrap_err();
        assert!(error.to_string().contains("ambiguous"));
    }

    #[test]
    fn profile_selectors_keep_names_ids_and_scope_references_distinct() {
        const FIRST_ID: &str = "11111111-1111-4111-8111-111111111111";
        const SECOND_ID: &str = "22222222-2222-4222-8222-222222222222";
        let records = vec![
            profile_with(FIRST_ID, "work"),
            profile_with(SECOND_ID, FIRST_ID),
        ];

        let ParsedProfileSelector::Name(name) = parse_profile_selector(FIRST_ID).unwrap() else {
            panic!("a bare profile selector must be a name");
        };
        assert_eq!(
            select_profile_by_name(&records, name.as_str())
                .unwrap()
                .profile
                .id
                .as_str(),
            SECOND_ID
        );

        let ParsedProfileSelector::Id(id) =
            parse_profile_selector(&format!("id:{FIRST_ID}")).unwrap()
        else {
            panic!("an id: profile selector must be an ID");
        };
        assert_eq!(id.as_str(), FIRST_ID);

        let ParsedProfileSelector::Reference(reference) =
            parse_profile_selector("user/work").unwrap()
        else {
            panic!("a scope-qualified profile selector must remain a reference");
        };
        assert_eq!(reference.scope(), AccessProfileScope::User);
        assert_eq!(reference.name().as_str(), "work");

        assert!(parse_profile_selector("name:work").is_err());
    }

    #[test]
    fn profile_selectors_reject_malformed_prefixes_and_name_collisions() {
        for selector in [
            "id:",
            "id:not-a-uuid",
            "id:11111111-1111-4111-8111-11111111111A",
            "id:00000000-0000-0000-0000-000000000000",
            "name:",
            "name:user/work",
            "profile:work",
            "user/",
            "team/work",
        ] {
            assert!(
                parse_profile_selector(selector).is_err(),
                "selector {selector:?} must fail"
            );
        }

        let records = vec![
            profile_with("11111111-1111-4111-8111-111111111111", "work"),
            profile_with("22222222-2222-4222-8222-222222222222", "work"),
        ];
        let error = select_profile_by_name(&records, "work").unwrap_err();
        assert!(error.to_string().contains("ambiguous"));
    }

    #[test]
    fn ssh_enrollment_uses_one_generate_or_explicit_import_in_both_stores() {
        for placement in ["--local", "--platform"] {
            let generated = Cli::try_parse_from([
                "cw",
                "credentials",
                placement,
                "generate",
                "ssh",
                "--name=work",
            ])
            .unwrap();
            assert!(
                matches!(generated.command, Command::Credentials(CredentialsArgs {
                command: CredentialsCommand::Generate(super::super::CredentialGenerateArgs { name, .. }), ..
            }) if name == "work")
            );
            let imported = Cli::try_parse_from([
                "cw",
                "credentials",
                placement,
                "add",
                "ssh",
                "--name=imported",
                "--key-file=./synthetic-key",
            ])
            .unwrap();
            assert!(
                matches!(imported.command, Command::Credentials(CredentialsArgs {
                command: CredentialsCommand::Add(CredentialAddArgs { key_file: Some(path), .. }), ..
            }) if path == Path::new("./synthetic-key"))
            );
            for provider in ["github", "openai", "rsa"] {
                assert!(
                    Cli::try_parse_from([
                        "cw",
                        "credentials",
                        placement,
                        "generate",
                        provider,
                        "--name=work",
                    ])
                    .is_err()
                );
            }
        }
    }

    #[test]
    fn api_key_enrollment_has_one_explicit_provider_path_without_a_kind_flag() {
        for provider in ["openai", "anthropic"] {
            assert_eq!(
                api_key_enrollment_kind(provider).unwrap(),
                CredentialAuthKind::ApiKey
            );
            for placement in ["--local", "--platform"] {
                let parsed = Cli::try_parse_from([
                    "cw",
                    "credentials",
                    placement,
                    "add",
                    provider,
                    "--name=work",
                ])
                .unwrap();
                assert!(
                    matches!(parsed.command, Command::Credentials(CredentialsArgs {
                    command: CredentialsCommand::Add(CredentialAddArgs { name, .. }), ..
                }) if name == "work")
                );
                assert!(
                    Cli::try_parse_from([
                        "cw",
                        "credentials",
                        placement,
                        "add",
                        provider,
                        "--name=work",
                        "--kind=api-key",
                    ])
                    .is_err()
                );
            }
        }
        for provider in ["codex", "github", "ssh", "unknown"] {
            assert!(api_key_enrollment_kind(provider).is_err());
        }
    }

    #[test]
    fn claude_subscription_tokens_parse_as_an_add_provider_and_are_platform_only() {
        let parsed = Cli::try_parse_from([
            "cw",
            "credentials",
            "--platform",
            "add",
            "claude-subscription",
            "--name=claude",
        ])
        .unwrap();
        assert!(
            matches!(parsed.command, Command::Credentials(CredentialsArgs {
            platform: true,
            command: CredentialsCommand::Add(CredentialAddArgs { provider, name, .. }), ..
        }) if provider == "claude-subscription" && name == "claude")
        );
        // The token is never an argument.
        assert!(
            Cli::try_parse_from([
                "cw",
                "credentials",
                "--platform",
                "add",
                "claude-subscription",
                "--name=claude",
                "--token=sk-ant-oat01-must-not-be-argv",
            ])
            .is_err()
        );
        let error = api_key_enrollment_kind("claude-subscription").unwrap_err();
        assert!(error.to_string().contains("--platform"));
    }

    #[test]
    fn parser_accepts_material_free_local_credential_and_profile_grammar() {
        let connect = Cli::try_parse_from([
            "cw",
            "credentials",
            "--local",
            "connect",
            "codex",
            "--name",
            "work-codex",
        ])
        .unwrap();
        assert!(matches!(
            connect.command,
            Command::Credentials(CredentialsArgs {
                local: true,
                platform: false,
                command: CredentialsCommand::Connect(CredentialConnectArgs {
                    provider: CredentialConnectProviderArg::Codex,
                    ..
                }),
                ..
            })
        ));

        let connect_github = Cli::try_parse_from([
            "cw",
            "credentials",
            "--local",
            "connect",
            "github",
            "--name",
            "work-github",
        ])
        .unwrap();
        assert!(matches!(
            connect_github.command,
            Command::Credentials(CredentialsArgs {
                local: true,
                platform: false,
                command: CredentialsCommand::Connect(CredentialConnectArgs {
                    provider: CredentialConnectProviderArg::Github,
                    ..
                }),
                ..
            })
        ));

        let add = Cli::try_parse_from([
            "cw",
            "credentials",
            "--local",
            "add",
            "openai",
            "--name",
            "work-openai",
        ])
        .unwrap();
        assert!(matches!(
            add.command,
            Command::Credentials(CredentialsArgs {
                local: true,
                platform: false,
                command: CredentialsCommand::Add(_),
                ..
            })
        ));
        for retired_kind in [
            "api-key",
            "oauth",
            "access-token",
            "ssh-private-key",
            "ssh-agent",
        ] {
            assert!(
                Cli::try_parse_from([
                    "cw",
                    "credentials",
                    "--local",
                    "add",
                    "example",
                    "--kind",
                    retired_kind,
                    "--name",
                    "retired",
                ])
                .is_err(),
                "retired credential kind {retired_kind} must not remain advertised",
            );
        }

        let profile = Cli::try_parse_from([
            "cw",
            "credentials",
            "--local",
            "--profile=work",
            "set",
            "codex",
            "work-openai",
        ])
        .unwrap();
        assert!(matches!(
            profile.command,
            Command::Credentials(CredentialsArgs {
                command: CredentialsCommand::Set(_),
                ..
            })
        ));

        assert!(
            Cli::try_parse_from([
                "cw",
                "credentials",
                "--local",
                "add",
                "openai",
                "--name",
                "work-openai",
                "must-not-be-material",
            ])
            .is_err()
        );
    }

    #[test]
    fn profile_operations_require_an_explicit_target_and_never_autobind_enrollment() {
        for placement in [StoragePlacement::Local, StoragePlacement::Platform] {
            for tail in [
                vec!["set", "codex", "work-codex"],
                vec!["unset", "codex"],
                vec!["revisions"],
                vec!["get"],
                vec!["delete"],
            ] {
                let mut argv = vec!["cw", "credentials"];
                argv.extend(tail);
                let Command::Credentials(args) = Cli::try_parse_from(argv).unwrap().command else {
                    panic!("credentials")
                };
                assert!(
                    resolve_credential_operation(args.profile, args.command, placement).is_err()
                );
            }
            for tail in [
                vec!["connect", "codex", "--name", "new"],
                vec!["add", "openai", "--name", "new"],
                vec!["get", "another-credential"],
                vec!["delete", "another-credential"],
                vec!["get", "--revision", "0"],
                vec!["profiles", "list"],
            ] {
                let mut argv = vec!["cw", "credentials", "--profile=work"];
                argv.extend(tail);
                let Command::Credentials(args) = Cli::try_parse_from(argv).unwrap().command else {
                    panic!("credentials")
                };
                assert!(
                    resolve_credential_operation(args.profile, args.command, placement).is_err()
                );
            }
        }
    }

    #[test]
    fn profile_storage_scope_and_revision_are_exact() {
        for (origin, placement) in [
            ("local", StoragePlacement::Local),
            ("platform", StoragePlacement::Platform),
        ] {
            for selector in [format!("{origin}:user/work"), format!("{origin}:work")] {
                let Command::Credentials(args) = Cli::try_parse_from([
                    "cw",
                    "credentials",
                    "--profile",
                    &selector,
                    "get",
                    "--revision",
                    "9007199254740993",
                ])
                .unwrap()
                .command
                else {
                    panic!("credentials")
                };
                let CredentialOperation::Profile(CredentialProfileCommand::Get(args)) =
                    resolve_credential_operation(args.profile, args.command, placement).unwrap()
                else {
                    panic!("profile get")
                };
                assert_eq!(args.revision, Some(9_007_199_254_740_993));
                assert!(!args.profile.starts_with(&format!("{origin}:")));
            }
            let other = if placement == StoragePlacement::Local {
                "platform:work"
            } else {
                "local:work"
            };
            for selector in [other, "organization/work"] {
                let Command::Credentials(args) =
                    Cli::try_parse_from(["cw", "credentials", "--profile", selector, "list"])
                        .unwrap()
                        .command
                else {
                    panic!("credentials")
                };
                assert!(
                    resolve_credential_operation(args.profile, args.command, placement).is_err()
                );
            }
        }
    }

    #[test]
    fn product_slots_require_a_compatible_credential_without_legacy_grammar() {
        for slot in ["codex", "openai", "github", "anthropic", "ssh"] {
            assert!(
                Cli::try_parse_from([
                    "cw",
                    "credentials",
                    "--local",
                    "--profile=work",
                    "set",
                    slot,
                    "selected-credential"
                ])
                .is_ok()
            );
        }
        let openai = ProviderId::parse("openai").unwrap();
        assert!(supported_profile_slot("codex", &openai, CredentialAuthKind::ApiKey).is_ok());
        assert!(supported_profile_slot("openai", &openai, CredentialAuthKind::ApiKey).is_ok());
        for slot in ["anthropic", "ssh", "github"] {
            assert!(supported_profile_slot(slot, &openai, CredentialAuthKind::ApiKey).is_err());
        }
        for tail in [
            vec!["profile", "list"],
            vec!["profile", "set", "work", "codex", "credential"],
            vec!["rm", "credential"],
            vec!["--profile=work", "rm"],
        ] {
            let mut argv = vec!["cw", "credentials", "--local"];
            argv.extend(tail);
            assert!(Cli::try_parse_from(argv).is_err());
        }
    }

    #[test]
    fn only_confirmed_unique_metadata_selects_an_existing_profile() {
        assert!(optional_profile_by_name(&[], "work").unwrap().is_none());
        let records = vec![profile_with("11111111-1111-4111-8111-111111111111", "work")];
        assert_eq!(
            optional_profile_by_name(&records, "WORK")
                .unwrap()
                .unwrap()
                .profile
                .id,
            records[0].profile.id
        );
        let records = vec![
            records[0].clone(),
            profile_with("22222222-2222-4222-8222-222222222222", "work"),
        ];
        assert!(optional_profile_by_name(&records, "work").is_err());
    }

    #[test]
    fn material_reader_is_bounded_and_debug_redacted() {
        let value = read_protected_value(Cursor::new(b"synthetic-api-key\n"), false).unwrap();
        assert_eq!(value.expose_secret(), b"synthetic-api-key");
        assert_eq!(format!("{value:?}"), "ProtectedValue([REDACTED])");

        assert!(read_protected_value(Cursor::new(Vec::<u8>::new()), false).is_err());
        assert!(
            read_protected_value(
                Cursor::new(vec![b'x'; MAX_PROTECTED_VALUE_BYTES + 1]),
                false
            )
            .is_err()
        );
    }

    #[test]
    fn oauth_and_app_references_cannot_use_the_opaque_material_prompt() {
        for kind in [CredentialAuthKind::OAuth, CredentialAuthKind::GitHubApp] {
            assert!(!manually_supplied_credential_kind(kind));
        }
        for kind in [CredentialAuthKind::ApiKey, CredentialAuthKind::AccessToken] {
            assert!(manually_supplied_credential_kind(kind));
        }
    }

    #[test]
    fn metadata_output_has_no_material_or_internal_store_reference() {
        let view = CredentialView::from(&credential());
        let json = serde_json::to_string(&view).unwrap();
        assert!(json.contains("work-openai"));
        assert!(!json.contains("synthetic"));
        assert!(!json.contains("entry_id"));
        assert!(!json.contains("material"));

        let text = format_credentials_text(&[view]);
        assert!(text.contains("PLACEMENT"));
        assert!(text.contains("work-openai"));
        assert!(text.contains("work@example.test"));
        assert!(text.contains("operating_system"));
        assert!(!text.contains("account_hint"));
    }

    #[test]
    fn github_pending_notice_names_the_installation_and_its_settings_page() {
        use codewire_credential_broker::GitHubAccountKind;
        assert_eq!(
            github_pending_notice("noeljackson", 12345, GitHubAccountKind::User).unwrap(),
            "GitHub has not yet given Codewire write access to code and pull requests on noeljackson. \
             Accept the updated permissions on GitHub: https://github.com/settings/installations/12345"
        );
        assert_eq!(
            github_pending_notice("octo-org", 678, GitHubAccountKind::Organization).unwrap(),
            "GitHub has not yet given Codewire write access to code and pull requests on octo-org. \
             Accept the updated permissions on GitHub: \
             https://github.com/organizations/octo-org/settings/installations/678"
        );
        assert_eq!(
            github_pending_notice("octo-ent", 9, GitHubAccountKind::Enterprise).unwrap(),
            "GitHub has not yet given Codewire write access to code and pull requests on octo-ent. \
             Accept the updated permissions in the enterprise's GitHub settings."
        );
        for (account, id) in [("", 1), ("-octo", 1), ("octo/evil", 1), ("octo", 0)] {
            assert!(
                github_pending_notice(account, id, GitHubAccountKind::User).is_none(),
                "{account}"
            );
            assert!(github_settings_page(account, id, GitHubAccountKind::User).is_none());
        }
    }

    #[test]
    fn a_github_connect_at_a_terminal_opens_the_first_page_to_accept() {
        use codewire_credential_broker::GitHubAccountKind::{Enterprise, Organization, User};
        let pending = [
            ("octo-ent", 9, Enterprise),
            ("octo-org", 678, Organization),
            ("noeljackson", 12345, User),
        ];
        let (notices, open) = github_pending_follow_up(pending, true);
        assert_eq!(notices.len(), 3);
        assert_eq!(
            open.as_deref(),
            Some("https://github.com/organizations/octo-org/settings/installations/678")
        );
        // Not at a terminal: the same notices, nothing opened.
        let (printed, open) = github_pending_follow_up(pending, false);
        assert_eq!(printed, notices);
        assert_eq!(open, None);
        // An enterprise has no page to open.
        let (notices, open) = github_pending_follow_up([("octo-ent", 9, Enterprise)], true);
        assert_eq!(notices.len(), 1);
        assert_eq!(open, None);
        // An invalid entry is neither printed nor opened.
        let (notices, open) = github_pending_follow_up([("octo/evil", 1, User)], true);
        assert!(notices.is_empty());
        assert_eq!(open, None);
    }

    #[test]
    fn github_reach_names_each_installation_and_the_install_page() {
        use codewire_credential_broker::GitHubAppInstallationReach;
        let summary = github_reach_summary(&[
            GitHubAppInstallationReach {
                account: "codewiresh".into(),
                all_repositories: true,
                pending_permissions: None,
            },
            GitHubAppInstallationReach {
                account: "noeljackson".into(),
                all_repositories: false,
                pending_permissions: None,
            },
        ]);
        assert_eq!(
            summary,
            "Codewire can read repositories in: codewiresh (all repositories), noeljackson (selected repositories).\n\
             To add an account or organization, or choose repositories: \
             https://github.com/apps/codewire-sh/installations/new"
        );
        assert!(github_reach_summary(&[]).starts_with(
            "Codewire can read repositories where the Codewire GitHub App is installed."
        ));
    }
}
