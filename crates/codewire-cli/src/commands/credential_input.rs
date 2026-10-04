//! Portable credential command grammar, selection, and protected input.
//!
//! Platform operations use this module on every supported CLI host. Linux-only
//! local authority processes and handlers remain in `credentials`.

use std::io::{BufRead, IsTerminal as _, Read, Write as _};
use std::path::Path;

use anyhow::Context as _;
use codewire_access::{
    AccessProfileId, AccessProfileName, AccessProfileReference, CapabilitySlot, CredentialAuthKind,
    CredentialId, ProviderId, builtin_provider_catalog,
};
use codewire_protected_store::{MAX_PROTECTED_VALUE_BYTES, ProtectedValue};
use zeroize::Zeroizing;

use super::storage_placement::{
    StoragePlacement, require_reference_placement, resolve_storage_placement,
};
use super::{
    CredentialProfileCommand, CredentialProfileDeleteArgs, CredentialProfileSelectorArgs,
    CredentialProfilesCommand, CredentialsArgs, CredentialsCommand, EchoGuard, Globals,
    OutputFormat, trimmed_required,
};

pub(super) const CODEX_DEVICE_AUTHORIZATION_GUIDANCE: &str = "Before connecting, turn on \"Enable device code authorization for Codex\" in ChatGPT Security settings: https://chatgpt.com/#settings/Security. For a managed workspace, your administrator may need to allow device code login.";

const MAX_SSH_KEY_BYTES: usize = 64 * 1024;
const MAX_SSH_PASSPHRASE_BYTES: usize = 1024;

#[derive(Debug)]
pub(super) enum CredentialOperation {
    Credential(CredentialsCommand),
    Profile(CredentialProfileCommand),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CredentialDispatch {
    Local,
    Platform,
}

pub(crate) async fn handle_credentials_command(
    globals: &Globals,
    args: CredentialsArgs,
) -> anyhow::Result<()> {
    let placement = resolve_storage_placement(
        args.local,
        args.platform,
        credential_command_json(&args.command),
    )?;
    // Decide host support before profile resolution and, more importantly,
    // before any authority configuration or protected input is touched.
    let dispatch = credential_dispatch(placement, cfg!(target_os = "linux"))?;
    let operation = resolve_credential_operation(args.profile, args.command, placement)?;
    match dispatch {
        CredentialDispatch::Platform => {
            super::platform_profiles::handle_platform_credentials(globals, operation).await
        }
        CredentialDispatch::Local => {
            #[cfg(target_os = "linux")]
            {
                super::credentials::handle_local_credentials_command(operation).await
            }
            #[cfg(not(target_os = "linux"))]
            {
                unreachable!("local credential dispatch was rejected on this host")
            }
        }
    }
}

fn credential_dispatch(
    placement: StoragePlacement,
    local_supported: bool,
) -> anyhow::Result<CredentialDispatch> {
    match placement {
        StoragePlacement::Platform => Ok(CredentialDispatch::Platform),
        StoragePlacement::Local if local_supported => Ok(CredentialDispatch::Local),
        StoragePlacement::Local => anyhow::bail!(
            "local protected credential storage is available only on Linux; use --platform explicitly for platform storage"
        ),
    }
}

pub(super) fn resolve_credential_operation(
    profile: Option<String>,
    command: CredentialsCommand,
    placement: StoragePlacement,
) -> anyhow::Result<CredentialOperation> {
    let Some(profile) = profile else {
        match &command {
            CredentialsCommand::Set(_)
            | CredentialsCommand::Unset(_)
            | CredentialsCommand::Revisions(_) => {
                anyhow::bail!("this operation requires --profile=NAME")
            }
            CredentialsCommand::Get(args) => {
                anyhow::ensure!(
                    args.credential.is_some(),
                    "get requires a credential selector or --profile=NAME"
                );
                anyhow::ensure!(
                    args.revision.is_none(),
                    "--revision requires --profile=NAME"
                );
            }
            CredentialsCommand::Delete(args) => anyhow::ensure!(
                args.credential.is_some(),
                "delete requires a credential selector or --profile=NAME"
            ),
            _ => {}
        }
        return Ok(match command {
            CredentialsCommand::Profiles {
                command: CredentialProfilesCommand::List(args),
            } => CredentialOperation::Profile(CredentialProfileCommand::List(args)),
            command => CredentialOperation::Credential(command),
        });
    };

    let profile = require_reference_placement(
        codewire_project::StorageReference::profile(&profile)?,
        placement,
    )?
    .to_owned();
    let parsed = parse_profile_selector(&profile)?;
    if let ParsedProfileSelector::Reference(reference) = parsed {
        anyhow::ensure!(
            reference.scope() == codewire_access::AccessProfileScope::User,
            "organization credential profiles are not supported by this storage adapter yet"
        );
    }
    let command = match command {
        CredentialsCommand::Set(mut args) => {
            args.profile = profile;
            CredentialProfileCommand::Set(args)
        }
        CredentialsCommand::Unset(mut args) => {
            args.profile = profile;
            CredentialProfileCommand::Unset(args)
        }
        CredentialsCommand::List(args) => {
            CredentialProfileCommand::Get(CredentialProfileSelectorArgs {
                profile,
                revision: None,
                output: args.output,
            })
        }
        CredentialsCommand::Get(args) => {
            anyhow::ensure!(
                args.credential.is_none(),
                "a credential selector cannot be combined with --profile get"
            );
            anyhow::ensure!(
                args.revision != Some(0),
                "profile revision must be positive"
            );
            CredentialProfileCommand::Get(CredentialProfileSelectorArgs {
                profile,
                revision: args.revision,
                output: args.output,
            })
        }
        CredentialsCommand::Revisions(args) => {
            CredentialProfileCommand::Revisions(CredentialProfileSelectorArgs {
                profile,
                revision: None,
                output: args.output,
            })
        }
        CredentialsCommand::Delete(args) => {
            anyhow::ensure!(
                args.credential.is_none(),
                "a credential selector cannot be combined with --profile delete"
            );
            CredentialProfileCommand::Delete(CredentialProfileDeleteArgs {
                profile,
                yes: args.yes,
            })
        }
        _ => anyhow::bail!(
            "--profile supports set, unset, list, get, revisions and delete; enrollment never binds a profile"
        ),
    };
    Ok(CredentialOperation::Profile(command))
}

pub(super) fn credential_command_json(command: &CredentialsCommand) -> bool {
    let output = match command {
        CredentialsCommand::List(args)
        | CredentialsCommand::Revisions(args)
        | CredentialsCommand::Profiles {
            command: CredentialProfilesCommand::List(args),
        } => Some(args.output),
        CredentialsCommand::Get(args) => Some(args.output),
        CredentialsCommand::Revoke(args) => Some(args.output),
        _ => None,
    };
    output == Some(OutputFormat::Json)
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
    let reference = codewire_project::StorageReference::profile(selector)?;
    anyhow::ensure!(
        reference.placement.is_none(),
        "resolve the profile storage origin before its metadata selector"
    );
    let selector = reference.selector;
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

/// Every profile includes the account's one GitHub connection, so GitHub is
/// never set or unset on a profile.
/// The one paste-based enrollment step for a Claude subscription token. The
/// owner runs Claude Code's own command; Codewire never drives its OAuth.
pub(super) const CLAUDE_SUBSCRIPTION_TOKEN_GUIDANCE: &str = "Run `claude setup-token` (requires a Claude Pro, Max, Team or Enterprise plan), then paste the token here. Codewire records an expiry one year from now; the token stays in Codewire and is never delivered to a Sandbox.";

pub(super) const GITHUB_ALWAYS_INCLUDED: &str = "every profile includes your one GitHub connection; connect or reconnect it with `credentials connect github`";

/// The credential a `profile set` selects; every slot names exactly one.
pub(super) fn profile_set_credential(
    args: &super::CredentialProfileSetArgs,
) -> anyhow::Result<&str> {
    anyhow::ensure!(args.slot != "github", GITHUB_ALWAYS_INCLUDED);
    args.credential
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("select a credential for this provider"))
}

pub(super) fn supported_profile_slot(
    value: &str,
    provider: &ProviderId,
    kind: CredentialAuthKind,
) -> anyhow::Result<CapabilitySlot> {
    anyhow::ensure!(
        matches!(value, "codex" | "openai" | "github" | "anthropic" | "ssh"),
        "unsupported credential profile provider"
    );
    let slot = CapabilitySlot::parse(value).context("invalid capability slot")?;
    let catalog = builtin_provider_catalog();
    let policy = catalog
        .get(provider)
        .and_then(|definition| definition.capabilities.get(&slot))
        .context("this provider identity/capability has no supported runtime adapter")?;
    anyhow::ensure!(
        policy.authentication_kinds.contains(&kind),
        "credential authentication kind is unsupported for this capability"
    );
    Ok(slot)
}

pub(super) fn prompt_credential_material() -> anyhow::Result<ProtectedValue> {
    prompt_named_material("Credential material")
}

/// Read one write-only value from a no-echo terminal prompt, or all of a piped
/// stdin. The value is never taken from argv.
pub(super) fn prompt_named_material(label: &str) -> anyhow::Result<ProtectedValue> {
    let interactive = std::io::stdin().is_terminal();
    if interactive {
        eprint!("{label}: ");
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

pub(super) fn read_protected_value<R: std::io::BufRead>(
    reader: R,
    single_line: bool,
) -> anyhow::Result<ProtectedValue> {
    let mut bytes = Zeroizing::new(Vec::new());
    let limit = u64::try_from(MAX_PROTECTED_VALUE_BYTES + 3).expect("protected-value limit");
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

pub(super) struct SshImport {
    pub(super) private_key: Zeroizing<Vec<u8>>,
    pub(super) passphrase: Option<Zeroizing<Vec<u8>>>,
}

fn ssh_enrollment_name(name: &str, expiry: Option<u64>) -> anyhow::Result<String> {
    let name = trimmed_required(name, "credential name")?;
    anyhow::ensure!(
        name.len() <= 256 && !name.chars().any(char::is_control),
        "invalid credential name"
    );
    if let Some(expiry) = expiry {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        anyhow::ensure!(
            expiry > now && i64::try_from(expiry).is_ok(),
            "credential expiry must be a future Unix timestamp"
        );
    }
    Ok(name.to_owned())
}

pub(super) fn validate_ssh_generation(
    args: &super::CredentialGenerateArgs,
) -> anyhow::Result<String> {
    anyhow::ensure!(args.provider == "ssh", "key generation supports ssh only");
    ssh_enrollment_name(&args.name, args.expires_at)
}

pub(super) fn validate_ssh_import(args: &super::CredentialAddArgs) -> anyhow::Result<String> {
    anyhow::ensure!(args.provider == "ssh", "SSH import requires provider ssh");
    anyhow::ensure!(
        args.account_hint.is_none(),
        "SSH credentials do not use --account-hint"
    );
    anyhow::ensure!(
        args.key_file
            .as_ref()
            .is_some_and(|path| !path.as_os_str().is_empty()),
        "add ssh requires an explicit --key-file PATH"
    );
    ssh_enrollment_name(&args.name, args.expires_at)
}

pub(super) fn read_ssh_import(args: &super::CredentialAddArgs) -> anyhow::Result<SshImport> {
    validate_ssh_import(args)?;
    let path = args.key_file.as_ref().expect("validated explicit key file");
    let file = open_explicit_ssh_key(path)?;
    let private_key = read_ssh_key(file)?;
    let interactive = std::io::stdin().is_terminal();
    if interactive {
        eprint!("SSH passphrase (empty for an unencrypted key): ");
        std::io::stderr()
            .flush()
            .context("flush SSH passphrase prompt")?;
    }
    let echo = if interactive {
        Some(EchoGuard::disable_if_tty()?)
    } else {
        None
    };
    let passphrase = read_ssh_passphrase(std::io::stdin().lock(), interactive);
    drop(echo);
    if interactive {
        eprintln!();
    }
    Ok(SshImport {
        private_key,
        passphrase: passphrase?,
    })
}

#[cfg(unix)]
fn open_explicit_ssh_key(path: &Path) -> anyhow::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .context("open explicit SSH key file (must be a regular file, not a symlink)")?;
    anyhow::ensure!(
        file.metadata()?.is_file(),
        "SSH key input must be a regular file"
    );
    Ok(file)
}

#[cfg(not(unix))]
fn open_explicit_ssh_key(path: &Path) -> anyhow::Result<std::fs::File> {
    let metadata = std::fs::symlink_metadata(path)
        .context("inspect explicit SSH key file (must be a regular file, not a symlink)")?;
    anyhow::ensure!(metadata.is_file(), "SSH key input must be a regular file");
    std::fs::OpenOptions::new()
        .read(true)
        .open(path)
        .context("open explicit SSH key file")
}

fn read_ssh_key(reader: impl Read) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    reader
        .take(MAX_SSH_KEY_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .context("read explicit SSH key")?;
    anyhow::ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_SSH_KEY_BYTES,
        "SSH key input is empty or exceeds 64 KiB"
    );
    Ok(bytes)
}

fn read_ssh_passphrase(
    reader: impl BufRead,
    interactive: bool,
) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    let mut reader = reader.take(MAX_SSH_PASSPHRASE_BYTES as u64 + 3);
    if interactive {
        reader.read_until(b'\n', &mut bytes)?;
    } else {
        reader.read_to_end(&mut bytes)?;
    }
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    anyhow::ensure!(
        bytes.len() <= MAX_SSH_PASSPHRASE_BYTES
            && !bytes.iter().any(|byte| matches!(byte, 0 | b'\r' | b'\n')),
        "invalid SSH passphrase input"
    );
    Ok((!bytes.is_empty()).then_some(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser as _;

    #[test]
    fn macos_dispatch_accepts_platform_and_rejects_local_without_fallback() {
        assert_eq!(
            credential_dispatch(StoragePlacement::Platform, false).unwrap(),
            CredentialDispatch::Platform
        );
        let error = credential_dispatch(StoragePlacement::Local, false).unwrap_err();
        assert!(error.to_string().contains("only on Linux"));
        assert_eq!(
            credential_dispatch(StoragePlacement::Local, true).unwrap(),
            CredentialDispatch::Local
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn local_rejection_precedes_key_input_and_platform_configuration() {
        let error = crate::run_from([
            "cw",
            "credentials",
            "--local",
            "add",
            "ssh",
            "--name=work",
            "--key-file=/deliberately-absent-sensitive-key",
        ])
        .await
        .unwrap_err();
        assert!(error.to_string().contains("available only on Linux"));
    }

    #[test]
    fn credential_parser_is_available_for_both_explicit_placements() {
        for placement in ["--local", "--platform"] {
            let parsed = crate::Cli::try_parse_from([
                "cw",
                "credentials",
                placement,
                "connect",
                "codex",
                "--name=work",
            ])
            .unwrap();
            assert!(matches!(
                parsed.command,
                crate::Command::Credentials(super::super::CredentialsArgs {
                    command: super::super::CredentialsCommand::Connect(_),
                    ..
                })
            ));
        }
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn linux_only_credential_and_launch_entrypoints_are_absent() {
        for command in [
            "__local-credential-authority",
            "__local-credential-authority-probe",
            "__local-credential-broker",
            "__local-credential-broker-confinement-probe",
            "__local-credential-broker-synthetic-smoke-check",
            "__local-git-repository-executor",
            "__local-git-credential-helper",
            "__environment-launch",
        ] {
            let error = crate::Cli::try_parse_from(["cw", command]).unwrap_err();
            assert_eq!(error.kind(), clap::error::ErrorKind::InvalidSubcommand);
        }
    }

    #[test]
    fn shared_selectors_keep_names_ids_and_scopes_distinct() {
        const ID: &str = "11111111-1111-4111-8111-111111111111";
        assert!(matches!(
            parse_credential_selector(ID).unwrap(),
            ParsedCredentialSelector::Name(ID)
        ));
        assert!(matches!(
            parse_credential_selector(&format!("id:{ID}")).unwrap(),
            ParsedCredentialSelector::Id(_)
        ));
        assert!(matches!(
            parse_profile_selector("user/work").unwrap(),
            ParsedProfileSelector::Reference(_)
        ));
        for invalid in ["id:", "id:not-a-uuid", "provider:work", "name: work"] {
            assert!(parse_credential_selector(invalid).is_err());
        }
    }

    #[test]
    fn protected_input_is_bounded_and_strips_one_line_ending() {
        assert_eq!(
            read_protected_value(b"synthetic-value\r\n".as_slice(), false)
                .unwrap()
                .expose_secret(),
            b"synthetic-value"
        );
        let mut oversized = vec![b'x'; MAX_PROTECTED_VALUE_BYTES];
        oversized.extend_from_slice(b"\r\nx");
        assert!(read_protected_value(oversized.as_slice(), false).is_err());
    }

    #[test]
    fn explicit_ssh_input_is_bounded_and_empty_passphrase_means_unencrypted() {
        assert!(read_ssh_key(&b""[..]).is_err());
        assert!(read_ssh_key(&vec![b'x'; MAX_SSH_KEY_BYTES][..]).is_ok());
        assert!(read_ssh_key(&vec![b'x'; MAX_SSH_KEY_BYTES + 1][..]).is_err());
        for input in [b"".as_slice(), b"\n", b"\r\n"] {
            assert!(read_ssh_passphrase(input, false).unwrap().is_none());
        }
        assert_eq!(
            &**read_ssh_passphrase(b"synthetic passphrase\r\n".as_slice(), false)
                .unwrap()
                .as_ref()
                .unwrap(),
            b"synthetic passphrase"
        );
        for input in [
            vec![b'x'; MAX_SSH_PASSPHRASE_BYTES + 1],
            b"one\ntwo".to_vec(),
            b"one\0two".to_vec(),
        ] {
            assert!(read_ssh_passphrase(input.as_slice(), false).is_err());
        }
        let mut hidden_suffix = vec![b'x'; MAX_SSH_PASSPHRASE_BYTES];
        hidden_suffix.extend_from_slice(b"\r\nx");
        assert!(read_ssh_passphrase(hidden_suffix.as_slice(), false).is_err());
    }

    #[test]
    fn ssh_selection_is_validated_without_opening_any_key_or_reading_stdin() {
        let mut args = super::super::CredentialAddArgs {
            provider: "ssh".into(),
            name: "work".into(),
            account_hint: None,
            expires_at: None,
            key_file: Some("/deliberately-absent-key".into()),
        };
        assert_eq!(validate_ssh_import(&args).unwrap(), "work");
        args.key_file = None;
        assert!(validate_ssh_import(&args).is_err());
        args.key_file = Some("/deliberately-absent-key".into());
        args.account_hint = Some("unexpected".into());
        assert!(validate_ssh_import(&args).is_err());
        args.account_hint = None;
        args.provider = "github".into();
        assert!(validate_ssh_import(&args).is_err());
        assert!(ssh_enrollment_name("name\ncontrol", None).is_err());
        assert!(ssh_enrollment_name("work", Some(1)).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn explicit_ssh_file_open_rejects_symlinks_and_nonregular_paths() {
        use std::ffi::CString;
        use std::io::Write as _;
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let key = directory.path().join("key");
        let link = directory.path().join("key-link");
        let fifo = directory.path().join("key-fifo");
        std::fs::File::create(&key)
            .unwrap()
            .write_all(b"synthetic-private-key")
            .unwrap();
        symlink(&key, &link).unwrap();
        let fifo_path = CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: `fifo_path` is a live, NUL-terminated path for this call.
        assert_eq!(unsafe { libc::mkfifo(fifo_path.as_ptr(), 0o600) }, 0);

        assert!(open_explicit_ssh_key(&key).is_ok());
        assert!(open_explicit_ssh_key(&link).is_err());
        assert!(open_explicit_ssh_key(&fifo).is_err());
        assert!(open_explicit_ssh_key(directory.path()).is_err());
    }
}
