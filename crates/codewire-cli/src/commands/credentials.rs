use std::collections::BTreeMap;
use std::io::{BufRead as _, IsTerminal as _, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::Context as _;
use codewire_access::{
    AccessProfileId, AccessProfileName, AccessProfileReference, CapabilitySlot, CredentialAuthKind,
    CredentialId, CredentialStatus, Owner, ProviderId, builtin_provider_catalog,
};
use codewire_credential_broker::codex_enrollment::{
    CodexEnrollmentConfig, CodexEnrollmentOwner, CodexPublicationOutcome, CompletedCodexEnrollment,
};
use codewire_credential_broker::provider_enrollment::{
    PrivateProviderHome, resolve_provider_executable,
};
use codewire_local_credentials::{
    AccessProfileRecord, AccessProfileRevisionRecord, CredentialRecord, LocalCredentialClient,
    NewCredential,
};
use codewire_protected_store::{
    MAX_PROTECTED_VALUE_BYTES, ProtectedStorePersistence, ProtectedValue,
};
use serde::Serialize;
use tokio::io::AsyncReadExt as _;
use zeroize::Zeroizing;

use super::{
    CredentialAddArgs, CredentialAuthenticationKindArg, CredentialConnectArgs,
    CredentialConnectProviderArg, CredentialDeleteArgs, CredentialListArgs,
    CredentialProfileCommand, CredentialProfileDeleteArgs, CredentialProfileSetArgs,
    CredentialProfileSlotArgs, CredentialRenameArgs, CredentialRotateArgs, CredentialSelectorArgs,
    CredentialsArgs, CredentialsCommand, EchoGuard, OutputFormat,
    connect_local_credential_authority, prompt_confirm_default_no, trimmed_required,
};

const GITHUB_HOST: &str = "github.com";
const GITHUB_CHILD_PATH: &str = "/usr/bin:/bin";
const GITHUB_TOKEN_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_GITHUB_TOKEN_BYTES: usize = 4 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CredentialPlacement {
    Local,
    Platform,
}

pub(crate) async fn handle_credentials_command(
    globals: &super::Globals,
    args: CredentialsArgs,
) -> anyhow::Result<()> {
    match credential_placement(args.local, args.platform)? {
        CredentialPlacement::Platform => {
            return super::platform_profiles::handle_platform_credentials(globals, args.command)
                .await;
        }
        CredentialPlacement::Local => {}
    }

    let mut client = connect_local_credential_authority().await?;
    match args.command {
        CredentialsCommand::Connect(args) => connect_credential(&mut client, args).await,
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
    let display_name = trimmed_required(&args.name, "credential name")?.to_owned();
    require_unique_credential_name(client, &display_name, "Codex").await?;
    let path = provider_search_path("Codex CLI")?;
    let executable = resolve_provider_executable("codex", &path)
        .context("resolve the official Codex CLI executable")?;
    let config = CodexEnrollmentConfig::new(executable, provider_login_runtime()?, path)
        .context("configure isolated Codex enrollment")?;
    // Install handlers before starting a child. The isolated process group
    // does not share the terminal's signals; its owner is responsible for drain.
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .context("install Codex enrollment interrupt handler")?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("install Codex enrollment termination handler")?;
    let mut hangup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        .context("install Codex enrollment hangup handler")?;
    let owner = CodexEnrollmentOwner::new(config);
    let result = tokio::select! {
        biased;
        _ = interrupt.recv() => Err(anyhow::anyhow!("Codex enrollment cancelled; any acknowledged or possibly stored credential was not revoked")),
        _ = terminate.recv() => Err(anyhow::anyhow!("Codex enrollment cancelled; any acknowledged or possibly stored credential was not revoked")),
        _ = hangup.recv() => Err(anyhow::anyhow!("Codex enrollment cancelled; any acknowledged or possibly stored credential was not revoked")),
        result = connect_codex_with_owner(client, display_name, &owner) => result,
    };
    // Even if the public future was cancelled during a placement RPC, the
    // worker drains and cleans using Unknown, never automatic provider logout.
    owner.shutdown().await.context(
        "drain isolated Codex enrollment; stored or possibly stored credentials were not revoked",
    )?;
    result
}

async fn connect_codex_with_owner(
    client: &mut LocalCredentialClient,
    display_name: String,
    owner: &CodexEnrollmentOwner,
) -> anyhow::Result<()> {
    let mut completed = run_isolated_codex_login(owner, true).await?;
    let imported = match completed.take_import() {
        Ok(imported) => imported,
        Err(error) => {
            completed
                .finish(CodexPublicationOutcome::NotPublished)
                .await
                .context("clean up unpublished Codex enrollment")?;
            return Err(error).context("admit completed Codex enrollment");
        }
    };
    let (bundle, account_hint) = imported.into_parts();
    let mut bytes = bundle.into_bytes();
    let material = match ProtectedValue::new(std::mem::take(&mut *bytes)) {
        Ok(material) => material,
        Err(error) => {
            completed
                .finish(CodexPublicationOutcome::NotPublished)
                .await
                .context("clean up unpublished Codex enrollment")?;
            return Err(error).context("prepare protected Codex credential");
        }
    };
    let publication = completed
        .wait_for_publication(client.add_credential(
            NewCredential {
                provider: ProviderId::parse("openai").expect("built-in OpenAI provider ID"),
                authentication_kind: CredentialAuthKind::OAuth,
                display_name,
                account_hint,
                expires_at_unix: None,
            },
            material,
        ))
        .await
        .map_err(anyhow::Error::from)
        .and_then(|result| result.map_err(anyhow::Error::from));
    let record = match publication {
        Ok(record) => record,
        Err(error) => {
            // The client also reports post-commit transport/response-decoding
            // failures as Status. No status code proves publication did not
            // occur. The original enrollment deadline also bounds this wait,
            // not the store's commit: an uncertain ACK must never revoke tokens.
            completed.finish(CodexPublicationOutcome::Unknown).await.context(
                "clean up Codex enrollment after an unknown storage acknowledgement; any stored credential was not revoked",
            )?;
            return Err(error).context(
                "local Codex storage acknowledgement is unknown; inspect the credential list before retrying; no credential was revoked",
            );
        }
    };
    completed.finish(CodexPublicationOutcome::Published).await.context(
        "local Codex credential was stored, but transient enrollment cleanup failed; the stored credential was not revoked",
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
    let display_name = trimmed_required(&args.name, "credential name")?.to_owned();
    require_unique_credential_name(client, &display_name, "GitHub").await?;
    let CompletedGitHubLogin {
        material,
        login_home,
    } = run_isolated_github_login().await?;
    let record = match client
        .add_credential(
            NewCredential {
                provider: ProviderId::parse("github").expect("built-in GitHub provider ID"),
                authentication_kind: CredentialAuthKind::OAuth,
                display_name,
                account_hint: None,
                expires_at_unix: None,
            },
            material,
        )
        .await
    {
        Ok(record) => record,
        Err(error) => {
            if let Err(cleanup_error) = login_home.remove() {
                return Err(cleanup_error).context(
                    "remove transient GitHub login material after protected-store failure; the completed authorization may remain active and can be revoked in GitHub settings",
                );
            }
            return Err(error).context(
                "store local GitHub credential; the completed GitHub CLI authorization may remain active and can be revoked in GitHub settings",
            );
        }
    };
    if let Err(error) = login_home.remove() {
        let _ = client.revoke_credential(&record.metadata.id).await;
        let _ = client.delete_credential(&record.metadata.id).await;
        return Err(error).context(
            "remove transient GitHub login material; the completed GitHub CLI authorization may remain active and can be revoked in GitHub settings",
        );
    }
    eprintln!(
        "Local GitHub credential {:?} connected ({}).",
        record.metadata.display_name, record.metadata.id
    );
    Ok(())
}

async fn require_unique_credential_name(
    client: &mut LocalCredentialClient,
    display_name: &str,
    provider_label: &str,
) -> anyhow::Result<()> {
    if client
        .list_credentials()
        .await
        .context("check local credential name")?
        .iter()
        .any(|record| {
            record
                .metadata
                .display_name
                .eq_ignore_ascii_case(display_name)
        })
    {
        anyhow::bail!(
            "local credential {display_name:?} already exists; use a distinct name for another {provider_label} identity"
        );
    }
    Ok(())
}

struct CompletedGitHubLogin {
    material: ProtectedValue,
    login_home: PrivateProviderHome,
}

async fn run_isolated_github_login() -> anyhow::Result<CompletedGitHubLogin> {
    let login_home = PrivateProviderHome::create_in(&provider_login_runtime()?)
        .context("create private GitHub login staging")?;
    let executable = resolve_github_executable()?;
    run_isolated_github_login_with(
        login_home,
        executable,
        std::ffi::OsString::from(GITHUB_CHILD_PATH),
        true,
    )
    .await
}

async fn run_isolated_github_login_with(
    login_home: PrivateProviderHome,
    executable: PathBuf,
    path: std::ffi::OsString,
    interactive: bool,
) -> anyhow::Result<CompletedGitHubLogin> {
    if interactive {
        eprintln!(
            "Starting an isolated GitHub CLI OAuth login. No ambient GitHub login will be read."
        );
    }
    let mut command = isolated_github_command(&executable, &path, &login_home);
    command.args([
        "auth",
        "login",
        "--hostname",
        GITHUB_HOST,
        "--git-protocol",
        "https",
        "--web",
        "--insecure-storage",
        "--skip-ssh-key",
    ]);
    if interactive {
        command
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
    } else {
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
    }
    let status = match command.status().await {
        Ok(status) => status,
        Err(error) => {
            login_home
                .remove()
                .context("remove GitHub login staging after launch failure")?;
            return Err(error).context("run isolated GitHub CLI login");
        }
    };
    if !status.success() {
        login_home
            .remove()
            .context("remove GitHub login staging after incomplete authorization")?;
        anyhow::bail!("GitHub CLI OAuth login did not complete; no local credential was stored");
    }
    let material = match read_isolated_github_token(&executable, &path, &login_home).await {
        Ok(material) => material,
        Err(error) => {
            login_home
                .remove()
                .context("remove GitHub login staging after token import failure")?;
            return Err(error).context(
                "import isolated GitHub CLI login; the completed authorization may remain active and can be revoked in GitHub settings",
            );
        }
    };
    Ok(CompletedGitHubLogin {
        material,
        login_home,
    })
}

fn isolated_github_command(
    executable: &Path,
    path: &std::ffi::OsStr,
    login_home: &PrivateProviderHome,
) -> tokio::process::Command {
    let mut command = tokio::process::Command::new(executable);
    command
        .env_clear()
        .env("PATH", path)
        .env("HOME", login_home.path())
        .env("GH_CONFIG_DIR", login_home.path())
        .env("XDG_CONFIG_HOME", login_home.path())
        .env("XDG_CACHE_HOME", login_home.path())
        .env("TMPDIR", login_home.path())
        .current_dir(login_home.path())
        .kill_on_drop(true);
    command
}

async fn read_isolated_github_token(
    executable: &Path,
    path: &std::ffi::OsStr,
    login_home: &PrivateProviderHome,
) -> anyhow::Result<ProtectedValue> {
    let mut command = isolated_github_command(executable, path, login_home);
    command
        .args(["auth", "token", "--hostname", GITHUB_HOST])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = command.spawn().context("read isolated GitHub CLI token")?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("GitHub CLI token output was unavailable"))?;
    let output_limit =
        u64::try_from(MAX_GITHUB_TOKEN_BYTES + 3).expect("GitHub token output bound fits u64");
    let output = tokio::time::timeout(GITHUB_TOKEN_TIMEOUT, async move {
        let mut output = Zeroizing::new(Vec::with_capacity(MAX_GITHUB_TOKEN_BYTES + 2));
        stdout
            .take(output_limit)
            .read_to_end(&mut output)
            .await
            .context("read isolated GitHub CLI token")?;
        if output.len() > MAX_GITHUB_TOKEN_BYTES + 2 {
            let _ = child.kill().await;
            let _ = child.wait().await;
            anyhow::bail!("GitHub CLI token output exceeded the safety limit");
        }
        let status = child
            .wait()
            .await
            .context("wait for isolated GitHub CLI token export")?;
        if !status.success() {
            anyhow::bail!("GitHub CLI could not export its isolated OAuth token");
        }
        Ok::<_, anyhow::Error>(output)
    })
    .await
    .map_err(|_| anyhow::anyhow!("GitHub CLI token export timed out"))??;
    parse_github_token_output(output)
}

fn parse_github_token_output(mut output: Zeroizing<Vec<u8>>) -> anyhow::Result<ProtectedValue> {
    if output.last() == Some(&b'\n') {
        output.pop();
        if output.last() == Some(&b'\r') {
            output.pop();
        }
    }
    if output.is_empty()
        || output.len() > MAX_GITHUB_TOKEN_BYTES
        || !output.iter().all(u8::is_ascii_graphic)
    {
        anyhow::bail!("GitHub CLI returned an invalid OAuth token");
    }
    ProtectedValue::new(std::mem::take(&mut *output)).context("prepare protected GitHub credential")
}

fn resolve_github_executable() -> anyhow::Result<PathBuf> {
    let path = provider_search_path("GitHub CLI")?;
    resolve_provider_executable("gh", &path).context("resolve the official GitHub CLI executable")
}

fn provider_search_path(label: &str) -> anyhow::Result<std::ffi::OsString> {
    std::env::var_os("PATH")
        .ok_or_else(|| anyhow::anyhow!("PATH is unavailable; install the official {label}"))
}

fn provider_login_runtime() -> anyhow::Result<PathBuf> {
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .ok_or_else(|| {
            anyhow::anyhow!("XDG_RUNTIME_DIR is required for private provider login staging")
        })
}

async fn run_isolated_codex_login(
    owner: &CodexEnrollmentOwner,
    interactive: bool,
) -> anyhow::Result<CompletedCodexEnrollment> {
    let mut pending = owner.start().context("start isolated Codex enrollment")?;
    let challenge = pending
        .challenge()
        .await
        .context("read Codex device challenge")?;
    if interactive {
        // Only the fixed provider URL, accepted code and bounded deadline are
        // displayed. No child stdout/stderr or imported material is forwarded.
        eprintln!(
            "Open {} and enter this one-time code: {}\nThe code expires within 15 minutes. Continue only if you started this login in Codewire.",
            challenge.verification_url(),
            challenge.user_code(),
        );
    }
    pending
        .complete()
        .await
        .context("complete isolated Codex enrollment")
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
    if !manually_supplied_credential_kind(authentication_kind) {
        anyhow::bail!(
            "{} credentials require a provider-specific connect command",
            authentication_kind_label(authentication_kind)
        );
    }
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
    if !manually_supplied_credential_kind(record.metadata.authentication_kind) {
        anyhow::bail!(
            "{} credential material cannot be entered manually; connect a new provider identity and update the access profile",
            authentication_kind_label(record.metadata.authentication_kind)
        );
    }
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
                anyhow::bail!(
                    "use profile get PROFILE --revision REVISION to inspect one revision"
                );
            }
            let profile = resolve_profile(client, &args.profile).await?;
            let revisions = client
                .list_profile_revisions(&profile.profile.id)
                .await
                .context("list local access profile revisions")?;
            print_profile_revisions(&revisions, args.output)
        }
        CredentialProfileCommand::Delete(args) => delete_profile(client, args).await,
        CredentialProfileCommand::Bind(_)
        | CredentialProfileCommand::Binding(_)
        | CredentialProfileCommand::Unbind(_) => {
            anyhow::bail!(
                "these binding commands require --platform; local profile selection uses cw env create --local --access-profile"
            )
        }
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

#[derive(Debug, PartialEq, Eq)]
pub(super) enum ParsedCredentialSelector<'a> {
    Name(&'a str),
    Id(CredentialId),
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum ParsedProfileSelector {
    Name(AccessProfileName),
    Reference(AccessProfileReference),
    Id(AccessProfileId),
}

pub(super) fn parse_credential_selector(
    selector: &str,
) -> anyhow::Result<ParsedCredentialSelector<'_>> {
    let selector = trimmed_required(selector, "credential selector")?;
    if let Some(name) = selector.strip_prefix("name:") {
        return Ok(ParsedCredentialSelector::Name(explicit_selector_name(
            name,
            "credential",
        )?));
    }
    if let Some(id) = selector.strip_prefix("id:") {
        let id = canonical_selector_id(id, "credential")?;
        return Ok(ParsedCredentialSelector::Id(
            CredentialId::parse(id).context("invalid credential ID")?,
        ));
    }
    reject_unknown_selector_prefix(selector, "credential")?;
    Ok(ParsedCredentialSelector::Name(selector))
}

pub(super) fn parse_profile_selector(selector: &str) -> anyhow::Result<ParsedProfileSelector> {
    let selector = trimmed_required(selector, "access profile selector")?;
    if let Some(name) = selector.strip_prefix("name:") {
        let name = explicit_selector_name(name, "access profile")?;
        return Ok(ParsedProfileSelector::Name(
            AccessProfileName::parse(name).context("invalid access profile name")?,
        ));
    }
    if let Some(id) = selector.strip_prefix("id:") {
        let id = canonical_selector_id(id, "access profile")?;
        return Ok(ParsedProfileSelector::Id(
            AccessProfileId::parse(id).context("invalid access profile ID")?,
        ));
    }
    reject_unknown_selector_prefix(selector, "access profile")?;
    if selector.contains('/') {
        return Ok(ParsedProfileSelector::Reference(
            selector
                .parse::<AccessProfileReference>()
                .context("invalid access profile reference")?,
        ));
    }
    Ok(ParsedProfileSelector::Name(
        AccessProfileName::parse(selector).context("invalid access profile name")?,
    ))
}

fn explicit_selector_name<'a>(name: &'a str, kind: &str) -> anyhow::Result<&'a str> {
    if name.is_empty() || name.trim() != name || name.chars().any(char::is_control) {
        anyhow::bail!("{kind} selector name must be non-empty and have no surrounding whitespace");
    }
    Ok(name)
}

fn canonical_selector_id<'a>(id: &'a str, kind: &str) -> anyhow::Result<&'a str> {
    let parsed =
        uuid::Uuid::parse_str(id).with_context(|| format!("invalid {kind} selector ID {id:?}"))?;
    if parsed.is_nil() || parsed.to_string() != id {
        anyhow::bail!("invalid {kind} selector ID {id:?}; expected a canonical non-nil UUID");
    }
    Ok(id)
}

fn reject_unknown_selector_prefix(selector: &str, kind: &str) -> anyhow::Result<()> {
    if let Some((prefix, _)) = selector.split_once(':') {
        anyhow::bail!(
            "invalid {kind} selector prefix {prefix:?}; use a bare name, name:<name>, or id:<canonical-uuid>"
        );
    }
    Ok(())
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
    let mut matches = records
        .iter()
        .filter(|record| record.profile.name.as_str().eq_ignore_ascii_case(name));
    let record = matches
        .next()
        .ok_or_else(|| anyhow::anyhow!("local access profile name {name:?} was not found"))?;
    if matches.next().is_some() {
        anyhow::bail!("local access profile name {name:?} is ambiguous");
    }
    Ok(record.clone())
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
    use std::os::unix::fs::PermissionsExt as _;

    use base64::Engine as _;
    use clap::Parser as _;
    use codewire_access::{
        AccessProfile, AccessProfileScope, CredentialMetadata, OwnerId, Placement,
    };

    use super::*;
    use crate::{Cli, Command};

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

    fn synthetic_jwt(payload: serde_json::Value) -> String {
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&payload).unwrap());
        format!("{header}.{payload}.synthetic-signature")
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

        let ParsedProfileSelector::Name(name) = parse_profile_selector("name:work").unwrap() else {
            panic!("a name: profile selector must be a name");
        };
        assert_eq!(name.as_str(), "work");
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
            })
        ));

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
        for retired_kind in ["ssh-private-key", "ssh-agent"] {
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
    fn oauth_and_app_references_cannot_use_the_opaque_material_prompt() {
        for kind in [CredentialAuthKind::OAuth, CredentialAuthKind::GitHubApp] {
            assert!(!manually_supplied_credential_kind(kind));
        }
        for kind in [CredentialAuthKind::ApiKey, CredentialAuthKind::AccessToken] {
            assert!(manually_supplied_credential_kind(kind));
        }
    }

    #[tokio::test]
    async fn isolated_codex_login_uses_only_its_private_tmpfs_home() {
        let root = tempfile::Builder::new()
            .prefix("codewire-codex-login-test-")
            .tempdir_in("/dev/shm")
            .expect("private tmpfs test root");
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("make tmpfs test root private");
        // A stable fixture avoids a write-then-execute race with concurrent test tooling.
        let executable = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/synthetic-codex-login.sh");
        let auth = serde_json::to_string(&serde_json::json!({
            "auth_mode": "chatgpt",
            "OPENAI_API_KEY": null,
            "tokens": {
                "id_token": synthetic_jwt(serde_json::json!({
                    "email": "developer@example.test",
                    "https://api.openai.com/auth": {
                        "chatgpt_account_id": "account-work",
                        "chatgpt_account_is_fedramp": false
                    }
                })),
                "access_token": "synthetic.access.token",
                "refresh_token": "synthetic-refresh-token",
                "account_id": "account-work"
            }
        }))
        .unwrap();
        assert!(!auth.contains('\''));
        std::fs::write(root.path().join("synthetic-auth.fixture.json"), auth)
            .expect("write synthetic Codex auth fixture");
        for outcome in [
            CodexPublicationOutcome::Published,
            CodexPublicationOutcome::Unknown,
            CodexPublicationOutcome::NotPublished,
        ] {
            let owner = CodexEnrollmentOwner::new(
                CodexEnrollmentConfig::new(
                    executable.clone(),
                    root.path().to_owned(),
                    std::ffi::OsString::from("/usr/bin:/bin"),
                )
                .expect("trusted synthetic enrollment configuration"),
            );
            let mut completed = run_isolated_codex_login(&owner, false)
                .await
                .expect("synthetic isolated login");
            assert_eq!(
                completed.take_import().unwrap().account_hint(),
                Some("developer@example.test")
            );
            let homes: Vec<_> = std::fs::read_dir(root.path())
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .filter(|path| path.is_dir())
                .collect();
            assert_eq!(homes.len(), 1);
            assert!(homes[0].join("auth.json").is_file());
            completed
                .finish(outcome)
                .await
                .expect("resolve synthetic publication outcome");
            owner
                .shutdown()
                .await
                .expect("await synthetic enrollment cleanup");
            assert!(!homes[0].exists());
            assert_eq!(
                root.path().join("logout.called").exists(),
                outcome == CodexPublicationOutcome::NotPublished
            );
        }
    }

    #[tokio::test]
    async fn isolated_github_login_uses_only_its_private_tmpfs_configuration() {
        let root = tempfile::Builder::new()
            .prefix("codewire-github-login-test-")
            .tempdir_in("/dev/shm")
            .expect("private tmpfs test root");
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("make tmpfs test root private");
        // A stable fixture avoids a write-then-execute race with concurrent test tooling.
        let executable = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/synthetic-github-login.sh");
        let login_home = PrivateProviderHome::create_in(root.path()).expect("isolated login home");
        let completed = run_isolated_github_login_with(
            login_home,
            executable,
            std::ffi::OsString::from("/usr/bin:/bin"),
            false,
        )
        .await
        .expect("synthetic isolated login");
        assert_eq!(
            completed.material.expose_secret(),
            b"synthetic-github-oauth-material"
        );
        let login_path = completed.login_home.path().to_owned();
        completed
            .login_home
            .remove()
            .expect("remove isolated login home");
        assert!(!login_path.exists());
    }

    #[test]
    fn github_token_import_is_single_line_ascii_and_bounded() {
        let token = parse_github_token_output(Zeroizing::new(b"synthetic-token\r\n".to_vec()))
            .expect("valid synthetic GitHub token");
        assert_eq!(token.expose_secret(), b"synthetic-token");

        for rejected in [
            Vec::new(),
            b"one\ntwo\n".to_vec(),
            b"contains space\n".to_vec(),
            vec![0xff, b'\n'],
            vec![b'x'; MAX_GITHUB_TOKEN_BYTES + 1],
        ] {
            assert!(parse_github_token_output(Zeroizing::new(rejected)).is_err());
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
}
