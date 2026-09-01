use std::collections::BTreeMap;
use std::io::{BufRead as _, IsTerminal as _, Read as _, Write as _};

use anyhow::Context as _;
use codewire_access::{
    AccessProfileName, AccessProfileReference, CapabilitySlot, CredentialAuthKind,
    CredentialStatus, Owner, ProviderId, builtin_provider_catalog,
};
use codewire_local_credentials::{
    AccessProfileRecord, AccessProfileRevisionRecord, CredentialRecord, LocalCredentialClient,
    NewCredential,
};
use codewire_protected_store::{
    MAX_PROTECTED_VALUE_BYTES, ProtectedStorePersistence, ProtectedValue,
};
use serde::Serialize;
use zeroize::Zeroizing;

use super::{
    CredentialAddArgs, CredentialAuthenticationKindArg, CredentialDeleteArgs, CredentialListArgs,
    CredentialProfileCommand, CredentialProfileDeleteArgs, CredentialProfileSetArgs,
    CredentialProfileSlotArgs, CredentialRenameArgs, CredentialRotateArgs, CredentialSelectorArgs,
    CredentialsArgs, CredentialsCommand, EchoGuard, OutputFormat,
    connect_local_credential_authority, prompt_confirm_default_no, trimmed_required,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CredentialPlacement {
    Local,
    Platform,
}

pub(crate) async fn handle_credentials_command(args: CredentialsArgs) -> anyhow::Result<()> {
    match credential_placement(args.local, args.platform)? {
        CredentialPlacement::Platform => anyhow::bail!(
            "platform credential management is not available yet; use --local for local credentials"
        ),
        CredentialPlacement::Local => {}
    }

    let mut client = connect_local_credential_authority().await?;
    match args.command {
        CredentialsCommand::Add(args) => add_credential(&mut client, args).await,
        CredentialsCommand::List(args) => list_credentials(&mut client, args).await,
        CredentialsCommand::Get(args) => get_credential(&mut client, args).await,
        CredentialsCommand::Rename(args) => rename_credential(&mut client, args).await,
        CredentialsCommand::Rotate(args) => rotate_credential(&mut client, args).await,
        CredentialsCommand::Revoke(args) => revoke_credential(&mut client, args).await,
        CredentialsCommand::Delete(args) => delete_credential(&mut client, args).await,
        CredentialsCommand::Profile { command } => profile_command(&mut client, command).await,
    }
}

fn credential_placement(local: bool, platform: bool) -> anyhow::Result<CredentialPlacement> {
    match (local, platform) {
        (true, false) => Ok(CredentialPlacement::Local),
        (false, true) => Ok(CredentialPlacement::Platform),
        (false, false) => {
            anyhow::bail!("credential placement is required: pass --local or --platform")
        }
        (true, true) => {
            anyhow::bail!("credential placement must be exactly one of --local or --platform")
        }
    }
}

async fn add_credential(
    client: &mut LocalCredentialClient,
    args: CredentialAddArgs,
) -> anyhow::Result<()> {
    let provider = ProviderId::parse(trimmed_required(&args.provider, "provider")?)
        .context("invalid credential provider")?;
    let authentication_kind = authentication_kind(args.kind);
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
    let material = prompt_credential_material()?;
    let rotated = client
        .rotate_credential_material(&record.metadata.id, material, args.expires_at)
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
    let record = resolve_credential(client, &args.credential).await?;
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
        CredentialProfileCommand::Create(args) => {
            let name = AccessProfileName::parse(trimmed_required(&args.name, "profile name")?)
                .context("invalid access profile name")?;
            let record = client
                .create_profile(&name, &BTreeMap::new())
                .await
                .context("create local access profile")?;
            eprintln!(
                "Local access profile {:?} created at revision {}.",
                record.profile.name.to_string(),
                record.profile.revision
            );
            Ok(())
        }
        CredentialProfileCommand::List(args) => {
            let records = client
                .list_profiles()
                .await
                .context("list local access profiles")?;
            print_profiles(&records, args.output)
        }
        CredentialProfileCommand::Get(args) => {
            let record = resolve_profile(client, &args.profile).await?;
            print_profiles(&[record], args.output)
        }
        CredentialProfileCommand::Set(args) => set_profile_entry(client, args).await,
        CredentialProfileCommand::Unset(args) => unset_profile_entry(client, args).await,
        CredentialProfileCommand::Revisions(args) => {
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
    let profile = resolve_profile(client, &args.profile).await?;
    let credential = resolve_credential(client, &args.credential).await?;
    let slot = CapabilitySlot::parse(trimmed_required(&args.slot, "capability slot")?)
        .context("invalid capability slot")?;
    let mut entries = profile.profile.entries.clone();
    entries.insert(slot, credential.metadata.id);
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

async fn unset_profile_entry(
    client: &mut LocalCredentialClient,
    args: CredentialProfileSlotArgs,
) -> anyhow::Result<()> {
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
    let selector = trimmed_required(selector, "credential")?;
    let records = client
        .list_credentials()
        .await
        .context("list local credentials")?;
    if let Some(record) = records
        .iter()
        .find(|record| record.metadata.id.as_str() == selector)
    {
        return Ok(record.clone());
    }
    records
        .into_iter()
        .find(|record| record.metadata.display_name.eq_ignore_ascii_case(selector))
        .ok_or_else(|| anyhow::anyhow!("local credential {selector:?} was not found"))
}

async fn resolve_profile(
    client: &mut LocalCredentialClient,
    selector: &str,
) -> anyhow::Result<AccessProfileRecord> {
    let selector = trimmed_required(selector, "access profile")?;
    if selector.contains('/') {
        let reference = selector
            .parse::<AccessProfileReference>()
            .context("invalid access profile reference")?;
        return client
            .resolve_profile(&reference)
            .await
            .context("resolve local access profile");
    }
    let records = client
        .list_profiles()
        .await
        .context("list local access profiles")?;
    if let Some(record) = records
        .iter()
        .find(|record| record.profile.id.as_str() == selector)
    {
        return Ok(record.clone());
    }
    records
        .into_iter()
        .find(|record| record.profile.name.as_str().eq_ignore_ascii_case(selector))
        .ok_or_else(|| anyhow::anyhow!("local access profile {selector:?} was not found"))
}

fn prompt_credential_material() -> anyhow::Result<ProtectedValue> {
    let interactive = std::io::stdin().is_terminal();
    if interactive {
        eprint!("Credential material: ");
        std::io::stderr()
            .flush()
            .context("flush credential prompt")?;
    }
    let echo_guard = if interactive {
        Some(EchoGuard::disable_if_tty()?)
    } else {
        None
    };
    let stdin = std::io::stdin();
    let value = read_protected_value(stdin.lock(), interactive);
    drop(echo_guard);
    value
}

fn read_protected_value<R: std::io::BufRead>(
    reader: R,
    single_line: bool,
) -> anyhow::Result<ProtectedValue> {
    let mut bytes = Zeroizing::new(Vec::new());
    let limit = u64::try_from(MAX_PROTECTED_VALUE_BYTES + 2).expect("protected-value limit");
    let mut reader = reader.take(limit);
    if single_line {
        reader
            .read_until(b'\n', &mut bytes)
            .context("read credential material")?;
    } else {
        reader
            .read_to_end(&mut bytes)
            .context("read credential material")?;
    }
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    ProtectedValue::new(std::mem::take(&mut *bytes)).context("invalid credential material")
}

fn authentication_kind(value: CredentialAuthenticationKindArg) -> CredentialAuthKind {
    match value {
        CredentialAuthenticationKindArg::Oauth => CredentialAuthKind::OAuth,
        CredentialAuthenticationKindArg::ApiKey => CredentialAuthKind::ApiKey,
        CredentialAuthenticationKindArg::AccessToken => CredentialAuthKind::AccessToken,
        CredentialAuthenticationKindArg::GithubApp => CredentialAuthKind::GitHubApp,
        CredentialAuthenticationKindArg::SshPrivateKey => CredentialAuthKind::SshPrivateKey,
        CredentialAuthenticationKindArg::SshAgent => CredentialAuthKind::SshAgent,
    }
}

fn authentication_kind_label(value: CredentialAuthKind) -> &'static str {
    match value {
        CredentialAuthKind::OAuth => "oauth",
        CredentialAuthKind::ApiKey => "api_key",
        CredentialAuthKind::AccessToken => "access_token",
        CredentialAuthKind::GitHubApp => "github_app",
        CredentialAuthKind::SshPrivateKey => "ssh_private_key",
        CredentialAuthKind::SshAgent => "ssh_agent",
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
    use std::io::Cursor;

    use clap::Parser as _;
    use codewire_access::{CredentialId, CredentialMetadata, OwnerId, Placement};

    use super::*;
    use crate::{Cli, Command};

    fn credential() -> CredentialRecord {
        CredentialRecord {
            metadata: CredentialMetadata {
                id: CredentialId::parse("11111111-1111-4111-8111-111111111111").unwrap(),
                placement: Placement::Local,
                owner: Owner::User(OwnerId::parse("local-user").unwrap()),
                provider: ProviderId::parse("openai").unwrap(),
                authentication_kind: CredentialAuthKind::ApiKey,
                display_name: "work-openai".into(),
                account_hint: Some("work@example.test".into()),
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

    #[test]
    fn credential_mutations_require_one_explicit_placement() {
        assert_eq!(
            credential_placement(true, false).unwrap(),
            CredentialPlacement::Local
        );
        assert_eq!(
            credential_placement(false, true).unwrap(),
            CredentialPlacement::Platform
        );
        assert!(credential_placement(false, false).is_err());
        assert!(credential_placement(true, true).is_err());
    }

    #[test]
    fn parser_accepts_material_free_local_credential_and_profile_grammar() {
        let add = Cli::try_parse_from([
            "cw",
            "credentials",
            "--local",
            "add",
            "openai",
            "--kind",
            "api-key",
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
            })
        ));

        let profile = Cli::try_parse_from([
            "cw",
            "credentials",
            "--local",
            "profile",
            "set",
            "work",
            "codex",
            "work-openai",
        ])
        .unwrap();
        assert!(matches!(
            profile.command,
            Command::Credentials(CredentialsArgs {
                command: CredentialsCommand::Profile {
                    command: CredentialProfileCommand::Set(_)
                },
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
                "--kind",
                "api-key",
                "--name",
                "work-openai",
                "must-not-be-material",
            ])
            .is_err()
        );
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
}
