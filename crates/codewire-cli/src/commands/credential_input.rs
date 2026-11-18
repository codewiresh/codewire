//! Portable credential command grammar, selection, and protected input.
//!
//! Platform operations use this module on every supported CLI host. Local
//! authority processes and handlers (Linux and macOS) remain in `credentials`.

use std::io::{BufRead, IsTerminal as _, Read, Write as _};
use std::path::Path;

use anyhow::Context as _;
use codewire_access::{
    AccessProfileId, AccessProfileName, AccessProfileReference, CapabilitySlot, CredentialAuthKind,
    CredentialId, ProviderId, builtin_provider_catalog,
};
use codewire_protected_store::{MAX_PROTECTED_VALUE_BYTES, ProtectedStoreBackend, ProtectedValue};
use zeroize::{Zeroize as _, Zeroizing};

use super::storage_placement::{
    StoragePlacement, require_reference_placement,
    resolve_credential_storage_placement as resolve_storage_placement,
};
use super::{
    CredentialGenerateArgs, CredentialProfileCommand, CredentialProfileDeleteArgs,
    CredentialProfileSelectorArgs, CredentialProfilesCommand, CredentialsArgs, CredentialsCommand,
    Globals, OutputFormat, trimmed_required,
};

pub(super) const CODEX_DEVICE_AUTHORIZATION_GUIDANCE: &str = "Before connecting, turn on \"Enable device code authorization for Codex\" in ChatGPT Security settings: https://chatgpt.com/#settings/Security. For a managed workspace, your administrator may need to allow device code login.";

const MAX_SSH_KEY_BYTES: usize = 64 * 1024;
const MAX_SSH_PASSPHRASE_BYTES: usize = 1024;

#[derive(Debug)]
pub(super) enum CredentialOperation {
    Credential(CredentialsCommand),
    Profile(CredentialProfileCommand),
    /// `--profile NAME generate ssh`: generate the identity, then set it as
    /// the profile's SSH key.
    GenerateIntoProfile(CredentialGenerateArgs, String),
}

/// Enrollment reports the identity returned by its save operation. A declined
/// reconnect never produces this receipt, and later menus bind its exact ID.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct SavedCredential {
    pub(super) id: String,
    pub(super) name: String,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(super) enum CredentialExecution {
    #[default]
    Unchanged,
    Saved(SavedCredential),
}

/// Printed after a generated SSH public key.
pub(super) const SSH_PUBLIC_KEY_GITHUB_HINT: &str =
    "Add the public key above to GitHub: https://github.com/settings/ssh/new";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CredentialDispatch {
    Local,
    Platform,
}

pub(crate) async fn handle_credentials_command(
    globals: &Globals,
    mut args: CredentialsArgs,
) -> anyhow::Result<()> {
    if matches!(&args.command, CredentialsCommand::Set(set) if set.slot.as_deref() == Some("github"))
    {
        anyhow::bail!(GITHUB_ALWAYS_INCLUDED);
    }
    if super::guided_credentials::missing(&args) && !super::guided::available(OutputFormat::Text) {
        super::guided::require_available(
            OutputFormat::Text,
            "supply the provider and --name NAME; profile changes also need --profile NAME and a credential selector",
        )?;
    }
    // A list reads: it never asks where to store something. Without
    // `--local` or `--cloud` it lists every store, each under its heading
    // (#4594). JSON still needs one store named.
    if globals.placement.is_none()
        && !credential_command_json(&args.command)
        && let Some(list) = list_command(&args.command)
    {
        return list_every_store(globals, args.profile, list).await;
    }
    // The global `--local` / `--cloud` is the explicit storage choice here.
    let placement = resolve_storage_placement(
        globals.placement == Some(super::EnvironmentPlacement::Local),
        globals.placement == Some(super::EnvironmentPlacement::Platform),
        credential_command_json(&args.command),
    )?;
    super::guided_credentials::complete(globals, &mut args, placement, globals.placement.is_none())
        .await?;
    let follow_up = if args.profile.is_none() {
        super::guided_credentials::assignment_slot(&args.command)
    } else {
        None
    };
    let operation = resolve_credential_operation(args.profile, args.command, placement)?;
    let execution = execute_credential_operation(globals, operation, placement).await?;
    if let (Some(slot), CredentialExecution::Saved(saved)) = (follow_up, execution) {
        super::guided_credentials::offer_assignment(globals, placement, &slot, &saved).await?;
    }
    Ok(())
}

/// The list a command asks for, as a command that can be made once per store.
fn list_command(command: &CredentialsCommand) -> Option<fn() -> CredentialsCommand> {
    match command {
        CredentialsCommand::List(_) => Some(|| {
            CredentialsCommand::List(super::CredentialListArgs {
                output: OutputFormat::Text,
            })
        }),
        CredentialsCommand::Profiles {
            command: super::CredentialProfilesCommand::List(_),
        } => Some(|| CredentialsCommand::Profiles {
            command: super::CredentialProfilesCommand::List(super::CredentialListArgs {
                output: OutputFormat::Text,
            }),
        }),
        _ => None,
    }
}

/// Lists every store under its heading. A store that can't be read says why
/// under its heading, and the others are still listed. Signed out is an
/// expected state; it fails only when no store could be read and one of them
/// failed for another reason, which its heading already showed.
async fn list_every_store(
    globals: &Globals,
    profile: Option<String>,
    list: fn() -> CredentialsCommand,
) -> anyhow::Result<()> {
    let mut read = 0;
    let mut failed = false;
    for (index, placement) in super::storage_placement::list_placements()
        .into_iter()
        .enumerate()
    {
        if index > 0 {
            println!();
        }
        let word = if placement == StoragePlacement::Platform {
            "cloud"
        } else {
            "local"
        };
        println!("{}", super::credentials::output::heading(word));
        let operation = resolve_credential_operation(profile.clone(), list(), placement)?;
        match execute_credential_operation(globals, operation, placement).await {
            Ok(_) => read += 1,
            Err(error) => {
                if signed_out(&error) {
                    // The approved screen 7 (#4717).
                    println!("Not signed in\n→ {}", super::NOT_SIGNED_IN_NEXT);
                } else {
                    println!("Could not be read: {error:#}");
                    failed = true;
                }
            }
        }
    }
    anyhow::ensure!(read > 0 || !failed, "no credential store could be read");
    Ok(())
}

/// Whether `error` is, at any depth, having no server or no sign-in.
fn signed_out(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<crate::config::ConfigError>(),
            Some(
                crate::config::ConfigError::NoPlatformServer { .. }
                    | crate::config::ConfigError::NoPlatformToken { .. }
            )
        )
    })
}

pub(super) async fn execute_credential_operation(
    globals: &Globals,
    operation: CredentialOperation,
    placement: StoragePlacement,
) -> anyhow::Result<CredentialExecution> {
    match credential_dispatch(
        placement,
        cfg!(any(target_os = "linux", target_os = "macos")),
    )? {
        CredentialDispatch::Platform => {
            super::platform_profiles::handle_platform_credentials(globals, operation).await
        }
        CredentialDispatch::Local => {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            {
                super::credentials::handle_local_credentials_command(operation).await
            }
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            {
                unreachable!("local credential dispatch was rejected on this host")
            }
        }
    }
}

/// The `local_credential_store` setting in the local Codewire config
/// (`~/.codewire/config.toml`), or the platform default when absent.
pub(crate) fn configured_local_credential_store(
    mesh_data_dir: &Path,
) -> anyhow::Result<ProtectedStoreBackend> {
    let setting = crate::config::load_mesh_config(mesh_data_dir)?.local_credential_store;
    resolve_local_credential_store(setting.as_deref())
}

pub(crate) fn resolve_local_credential_store(
    setting: Option<&str>,
) -> anyhow::Result<ProtectedStoreBackend> {
    let Some(value) = setting else {
        return ProtectedStoreBackend::platform_default()
            .context("local protected storage is unavailable on this operating system");
    };
    ProtectedStoreBackend::parse(value)
        .filter(|backend| backend.supported())
        .with_context(|| {
            let supported = [
                ProtectedStoreBackend::SecretService,
                ProtectedStoreBackend::Keychain,
                ProtectedStoreBackend::File,
            ]
            .into_iter()
            .filter(|backend| backend.supported())
            .map(|backend| format!("{:?}", backend.as_str()))
            .collect::<Vec<_>>()
            .join(" or ");
            format!("local_credential_store = {value:?} is not supported here; use {supported}")
        })
}

fn credential_dispatch(
    placement: StoragePlacement,
    local_supported: bool,
) -> anyhow::Result<CredentialDispatch> {
    match placement {
        StoragePlacement::Platform => Ok(CredentialDispatch::Platform),
        StoragePlacement::Local if local_supported => Ok(CredentialDispatch::Local),
        StoragePlacement::Local => anyhow::bail!(
            "local protected credential storage is available only on Linux and macOS; use --cloud explicitly for cloud storage"
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
            CredentialsCommand::Profiles {
                command: CredentialProfilesCommand::Default(args),
            } => CredentialOperation::Profile(CredentialProfileCommand::Default(args)),
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
        CredentialsCommand::Generate(args) => {
            return Ok(CredentialOperation::GenerateIntoProfile(args, profile));
        }
        _ => anyhow::bail!(
            "--profile supports set, unset, list, get, revisions, delete and generate ssh; connect and add never bind a profile"
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

/// What `connect claude` says before it prints Claude's sign-in link.
/// `connect`'s help for the two Claude subscription forms (owner,
/// 2026-11-15, #4945): what each is and the one difference that matters.
pub(super) const CLAUDE_SIGN_IN_HELP: &str =
    "Claude (sign-in): your subscription; shows your plan and usage";
pub(super) const CLAUDE_TOKEN_HELP: &str =
    "Claude (token): your subscription; lasts a year, for automation, model requests only";
/// The token screen's first line: no link to follow, only a paste.
pub(super) const CLAUDE_TOKEN_GUIDANCE: &str =
    "Run `claude setup-token`, then paste what it prints.";

/// A pasted value that is not Claude's `code#state`; one retry follows at a
/// terminal.
pub(super) const CLAUDE_CODE_SHAPE_HINT: &str = "That doesn't look like Claude's code (expected text with a # in the middle, like abc…#xyz…); copy the whole code and paste it again.";

/// The longest code or state part accepted from a paste.
const MAX_CLAUDE_CODE_PART_BYTES: usize = 4096;

/// The hidden prompt for a Claude subscription token.
pub(super) const CLAUDE_TOKEN_PROMPT: &str = "  Token > ";

/// Every profile includes the account's one GitHub connection, so GitHub is
/// never set or unset on a profile.
pub(super) const GITHUB_ALWAYS_INCLUDED: &str = "every profile includes your one GitHub connection; connect or reconnect it with `credentials connect github`";

/// The credential a `profile set` selects; every slot names exactly one.
pub(super) fn profile_set_credential(
    args: &super::CredentialProfileSetArgs,
) -> anyhow::Result<&str> {
    anyhow::ensure!(
        args.slot.as_deref() != Some("github"),
        GITHUB_ALWAYS_INCLUDED
    );
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
        "unsupported provider; use codex, openai, github, anthropic or ssh"
    );
    let slot = CapabilitySlot::parse(value)
        .context("unknown provider; use codex, openai, github, anthropic or ssh")?;
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

/// Asks for the value of a credential of `kind` for `provider`, in plain
/// words: what to paste and where to get it (#4715). The input is hidden.
pub(super) fn prompt_credential_material(
    provider: &str,
    kind: CredentialAuthKind,
) -> anyhow::Result<ProtectedValue> {
    prompt_named_material(&paste_prompt(provider, kind))
}

/// The prompt for a credential's value. Known providers name their own key
/// and where it is made; any other provider is named as configured.
pub(super) fn paste_prompt(provider: &str, kind: CredentialAuthKind) -> String {
    let what = match kind {
        CredentialAuthKind::AccessToken => "access token",
        _ => "API key",
    };
    match (provider, kind) {
        ("anthropic", CredentialAuthKind::ApiKey) => {
            "Paste your Anthropic API key (from console.anthropic.com/settings/keys)".to_owned()
        }
        ("openai", CredentialAuthKind::ApiKey) => {
            "Paste your OpenAI API key (from platform.openai.com/api-keys)".to_owned()
        }
        ("github", CredentialAuthKind::AccessToken) => {
            "Paste your GitHub access token (from github.com/settings/tokens)".to_owned()
        }
        (provider, _) => format!("Paste the {provider} {what}"),
    }
}

/// Read one write-only value from a no-echo terminal prompt, or all of a piped
/// stdin. The value is never taken from argv. At a terminal, nothing shows
/// while the value is pasted, so its length is confirmed once it is read; the
/// value itself is never echoed.
pub(super) fn prompt_named_material(label: &str) -> anyhow::Result<ProtectedValue> {
    prompt_hidden(&format!("{label}: "), "")
}

/// [`prompt_named_material`] with the prompt shown exactly as given, and its
/// confirmation under `indent`.
pub(super) fn prompt_hidden(prompt: &str, indent: &str) -> anyhow::Result<ProtectedValue> {
    prompt_hidden_copying(prompt, indent, None)
}

/// [`prompt_hidden`], where `c` typed first copies `copy`, the sign-in link
/// the prompt belongs to (#4850).
fn prompt_hidden_copying(
    prompt: &str,
    indent: &str,
    copy: Option<&str>,
) -> anyhow::Result<ProtectedValue> {
    let interactive = std::io::stdin().is_terminal();
    let value = if interactive {
        read_terminal_bytes(prompt, MAX_PROTECTED_VALUE_BYTES, copy).and_then(|mut bytes| {
            ProtectedValue::new(std::mem::take(&mut *bytes)).context("the pasted value isn't valid")
        })
    } else {
        read_protected_value(std::io::stdin().lock(), false)
    };
    if interactive {
        // The Enter that ended the hidden line was not echoed either.
        eprintln!();
        if let Ok(value) = &value {
            eprintln!("{indent}{}", received_confirmation(value.expose_secret()));
        }
    }
    value
}

/// Read protected terminal input without echo or ordinary widget/string state.
/// Raw mode turns Ctrl-C/Ctrl-D into cancellation bytes so RAII restores the
/// terminal, instead of a signal terminating before the echo guard can drop.
pub(super) fn read_hidden_terminal_bytes(
    prompt: &str,
    maximum: usize,
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    read_terminal_bytes(prompt, maximum, None)
}

fn read_terminal_bytes(
    prompt: &str,
    maximum: usize,
    copy: Option<&str>,
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    #[cfg(unix)]
    {
        use std::os::fd::{AsFd as _, AsRawFd as _};
        let mut input = std::fs::File::from(std::io::stdin().as_fd().try_clone_to_owned()?);
        let _terminal = crate::terminal_attach::RawModeGuard::enable()?;
        // Bracketed paste marks a paste, so a code that starts with `c` is
        // never taken for the copy key; it is turned off again on return.
        let _paste = copy.map(|_| BracketedPaste::enable());
        // Advertise the prompt only after echo is disabled, so immediate
        // paste cannot race the terminal transition.
        eprint!("{prompt}");
        std::io::stderr()
            .flush()
            .context("flush protected input prompt")?;
        let fd = input.as_raw_fd();
        let mut more = || super::login_screen::keys_readable(fd, PASTE_BURST_MS);
        let copied = |url: &str| {
            // Raw mode: a line ends with a carriage return too.
            eprint!("\r\n{}\r\n{prompt}", super::login_screen::copy_link(url));
            // Nothing can report a failed write to stderr; the screen just goes without it.
            let _ = std::io::stderr().flush();
        };
        match copy {
            Some(url) => read_hidden_bytes_with(
                &mut input,
                maximum,
                Some(CopyKey {
                    copy: &mut || copied(url),
                    more: &mut more,
                }),
            ),
            None => read_hidden_bytes(&mut input, maximum),
        }
    }
    #[cfg(not(unix))]
    {
        // No terminal to read from here, so these go unused.
        let _ = (prompt, maximum, copy);
        anyhow::bail!(
            "protected terminal input is unavailable on this host; pipe the value to stdin"
        )
    }
}

fn read_hidden_bytes(reader: &mut impl Read, maximum: usize) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    read_hidden_bytes_with(reader, maximum, None)
}

/// How long after a `c` more input means a paste rather than the copy key:
/// a paste arrives as one burst, a key press alone.
const PASTE_BURST_MS: i32 = 30;

/// The copy key at a sign-in's hidden prompt (#4850): `c` typed before
/// anything else, outside a bracketed paste and with no input right behind
/// it, calls `copy`. `more` says whether input is waiting.
struct CopyKey<'a> {
    copy: &'a mut dyn FnMut(),
    more: &'a mut dyn FnMut() -> bool,
}

/// Turns the terminal's bracketed paste on for its lifetime.
struct BracketedPaste;

impl BracketedPaste {
    fn enable() -> Self {
        eprint!("\x1b[?2004h");
        Self
    }
}

impl Drop for BracketedPaste {
    fn drop(&mut self) {
        eprint!("\x1b[?2004l");
        // Nothing can report a failed write to stderr; the screen just goes without it.
        let _ = std::io::stderr().flush();
    }
}

fn read_hidden_bytes_with(
    reader: &mut impl Read,
    maximum: usize,
    mut copy_key: Option<CopyKey<'_>>,
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let mut value = Zeroizing::new(Vec::with_capacity(maximum));
    let mut byte = Zeroizing::new([0u8; 1]);
    let mut pasting = false;
    loop {
        match reader.read(&mut *byte) {
            Ok(0) => anyhow::bail!("canceled; no protected value was saved"),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error).context("read protected terminal input"),
            Ok(_) => {}
        }
        if let Some(key) = copy_key.as_mut() {
            match byte[0] {
                // A bracketed paste's start or end; a lone Escape still
                // cancels, and any other sequence is ignored.
                0x1b if (key.more)() => {
                    match read_sequence(reader)?.as_slice() {
                        b"[200~" => pasting = true,
                        b"[201~" => pasting = false,
                        _ => {}
                    }
                    continue;
                }
                b'c' | b'C' if value.is_empty() && !pasting && !(key.more)() => {
                    (key.copy)();
                    continue;
                }
                _ => {}
            }
        }
        match byte[0] {
            b'\r' | b'\n' => return Ok(value),
            0x1b | 0x03 | 0x04 => anyhow::bail!("canceled; no protected value was saved"),
            0x15 => {
                value.as_mut_slice().zeroize();
                value.clear();
            }
            0x7f | 0x08 => {
                let start = std::str::from_utf8(&value)
                    .ok()
                    .and_then(|text| text.char_indices().next_back().map(|(index, _)| index))
                    .unwrap_or_else(|| value.len().saturating_sub(1));
                value[start..].zeroize();
                value.truncate(start);
            }
            byte => {
                anyhow::ensure!(value.len() < maximum, "protected input is too large");
                value.push(byte);
            }
        }
    }
}

/// The rest of an escape sequence after its ESC: `[` and parameters up to
/// the final byte, at most eight bytes.
fn read_sequence(reader: &mut impl Read) -> anyhow::Result<Vec<u8>> {
    let mut sequence = Vec::with_capacity(8);
    let mut byte = [0u8; 1];
    while sequence.len() < 8 {
        match reader.read(&mut byte) {
            Ok(0) => break,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error).context("read protected terminal input"),
            Ok(_) => {}
        }
        sequence.push(byte[0]);
        if sequence.len() > 1 && (0x40..=0x7e).contains(&byte[0]) {
            break;
        }
    }
    Ok(sequence)
}

/// What the hidden prompt says once it has read a value: its length only.
fn received_confirmation(value: &[u8]) -> String {
    let characters = std::str::from_utf8(value).map_or(value.len(), |text| text.chars().count());
    format!(
        "Got it ({characters} character{}).",
        if characters == 1 { "" } else { "s" }
    )
}

/// Read the code Claude shows after sign-in from the hidden prompt (or piped
/// stdin) and return it as `code#state`. Accepted, see [`normalize_claude_code`]:
/// the `code#state` itself with surrounding whitespace and a line ending, or
/// the full callback URL Claude's page was opened at. At a terminal a value of
/// another shape gets one retry; nothing is sent to Claude until it parses.
pub(super) fn prompt_claude_code(copy: Option<&str>) -> anyhow::Result<ProtectedValue> {
    let interactive = std::io::stdin().is_terminal();
    claude_code_with_retry(
        interactive,
        || {
            prompt_hidden_copying(
                super::login_screen::PASTE_CODE_PROMPT,
                super::login_screen::INDENT,
                copy,
            )
        },
        &mut std::io::stderr(),
    )
}

fn claude_code_with_retry(
    interactive: bool,
    mut read: impl FnMut() -> anyhow::Result<ProtectedValue>,
    out: &mut impl std::io::Write,
) -> anyhow::Result<ProtectedValue> {
    let attempts = if interactive { 2 } else { 1 };
    for attempt in 1..=attempts {
        let pasted = read()?;
        if let Some(mut code) = normalize_claude_code(pasted.expose_secret()) {
            return ProtectedValue::new(std::mem::take(&mut *code))
                .context("invalid code from Claude");
        }
        drop(pasted);
        if attempt < attempts {
            writeln!(
                out,
                "{}{CLAUDE_CODE_SHAPE_HINT}",
                super::login_screen::INDENT
            )
            .context("write the paste hint")?;
        }
    }
    anyhow::bail!(
        "that doesn't look like Claude's code (expected text with a # in the middle, like abc…#xyz…); nothing was sent to Claude. Run the command again and paste the whole code"
    )
}

/// Claude's `code#state` from what was pasted, or `None` for any other shape.
/// Accepted: `code#state` with surrounding whitespace, or an `http(s)` URL
/// whose query carries `code` and `state` (the callback page's address). Both
/// parts must be non-empty URL-safe text (`A-Z a-z 0-9 - _ . ~`), as Claude
/// issues them.
pub(super) fn normalize_claude_code(pasted: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let text = std::str::from_utf8(pasted).ok()?.trim();
    let (code, state) = match text
        .strip_prefix("https://")
        .or_else(|| text.strip_prefix("http://"))
    {
        Some(rest) => {
            let query = rest.split_once('?')?.1;
            let query = query.split('#').next().unwrap_or_default();
            let (mut code, mut state) = (None, None);
            for pair in query.split('&') {
                match pair.split_once('=') {
                    Some(("code", value)) if code.is_none() => code = Some(percent_decode(value)?),
                    Some(("state", value)) if state.is_none() => {
                        state = Some(percent_decode(value)?);
                    }
                    _ => {}
                }
            }
            (code?, state?)
        }
        None => {
            let (code, state) = text.split_once('#')?;
            (
                Zeroizing::new(code.as_bytes().to_vec()),
                Zeroizing::new(state.as_bytes().to_vec()),
            )
        }
    };
    let url_safe = |part: &[u8]| {
        !part.is_empty()
            && part.len() <= MAX_CLAUDE_CODE_PART_BYTES
            && part.iter().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~')
            })
    };
    if !url_safe(&code) || !url_safe(&state) {
        return None;
    }
    let mut normalized = Zeroizing::new(Vec::with_capacity(code.len() + 1 + state.len()));
    normalized.extend_from_slice(&code);
    normalized.push(b'#');
    normalized.extend_from_slice(&state);
    Some(normalized)
}

/// `%XX` decoding of one query value; any other byte is kept as is.
fn percent_decode(value: &str) -> Option<Zeroizing<Vec<u8>>> {
    let bytes = value.as_bytes();
    let mut decoded = Zeroizing::new(Vec::with_capacity(bytes.len()));
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hex = std::str::from_utf8(bytes.get(index + 1..index + 3)?).ok()?;
            decoded.push(u8::from_str_radix(hex, 16).ok()?);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    Some(decoded)
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
            .context("read the pasted value")?;
    } else {
        reader
            .read_to_end(&mut bytes)
            .context("read the pasted value")?;
    }
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    ProtectedValue::new(std::mem::take(&mut *bytes)).context("the pasted value isn't valid")
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
    anyhow::ensure!(
        args.provider.as_deref() == Some("ssh"),
        "key generation supports ssh only"
    );
    ssh_enrollment_name(
        args.name
            .as_deref()
            .context("credential name is required")?,
        args.expires_at,
    )
}

pub(super) fn validate_ssh_import(args: &super::CredentialAddArgs) -> anyhow::Result<String> {
    anyhow::ensure!(
        args.provider.as_deref() == Some("ssh"),
        "SSH import requires provider ssh"
    );
    anyhow::ensure!(
        args.account_hint.is_none(),
        super::credentials::output::refusal::ACCOUNT_HINT
    );
    anyhow::ensure!(
        args.key_file
            .as_ref()
            .is_some_and(|path| !path.as_os_str().is_empty()),
        "add ssh requires an explicit --key-file PATH"
    );
    ssh_enrollment_name(
        args.name
            .as_deref()
            .context("credential name is required")?,
        args.expires_at,
    )
}

pub(super) fn read_ssh_import(args: &super::CredentialAddArgs) -> anyhow::Result<SshImport> {
    validate_ssh_import(args)?;
    let path = args.key_file.as_ref().expect("validated explicit key file");
    let file = open_explicit_ssh_key(path)?;
    let private_key = read_ssh_key(file)?;
    let interactive = std::io::stdin().is_terminal();
    let passphrase = if interactive {
        read_hidden_terminal_bytes(
            "SSH passphrase (empty for an unencrypted key): ",
            MAX_SSH_PASSPHRASE_BYTES,
        )
        .and_then(|bytes| {
            anyhow::ensure!(
                !bytes.iter().any(|byte| matches!(byte, 0 | b'\r' | b'\n')),
                "invalid SSH passphrase input"
            );
            Ok((!bytes.is_empty()).then_some(bytes))
        })
    } else {
        read_ssh_passphrase(std::io::stdin().lock(), false)
    };
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

pub(super) mod connect;

#[cfg(test)]
mod tests {
    use super::*;

    /// Each provider's prompt says what to paste and where to get it, in the
    /// user's words (#4715).
    #[test]
    fn each_provider_prompt_says_what_to_paste_and_where_to_get_it() {
        use CredentialAuthKind::{AccessToken, ApiKey};
        assert_eq!(
            paste_prompt("anthropic", ApiKey),
            "Paste your Anthropic API key (from console.anthropic.com/settings/keys)"
        );
        assert_eq!(
            paste_prompt("openai", ApiKey),
            "Paste your OpenAI API key (from platform.openai.com/api-keys)"
        );
        assert_eq!(
            paste_prompt("github", AccessToken),
            "Paste your GitHub access token (from github.com/settings/tokens)"
        );
        assert_eq!(paste_prompt("acme", ApiKey), "Paste the acme API key");
        assert_eq!(
            paste_prompt("acme", AccessToken),
            "Paste the acme access token"
        );
        assert_eq!(CLAUDE_TOKEN_PROMPT, "  Token > ");
        for provider in ["anthropic", "openai", "github", "acme"] {
            for kind in [ApiKey, AccessToken] {
                let prompt = paste_prompt(provider, kind).to_lowercase();
                for internal in ["material", "slot", "projection"] {
                    assert!(!prompt.contains(internal), "{prompt}");
                }
            }
        }
    }
    use clap::Parser as _;

    #[test]
    fn a_credential_list_reads_every_store_and_never_asks_where_to_store() {
        // #4594: lists, never writes, are listed per store.
        let parse = |args: &[&str]| {
            let crate::Command::Credentials(credentials) =
                crate::Cli::try_parse_from(args).unwrap().command
            else {
                panic!("{args:?} is not a credentials command");
            };
            credentials.command
        };
        assert!(list_command(&parse(&["cw", "credentials", "list"])).is_some());
        assert!(list_command(&parse(&["cw", "credentials", "profiles", "list"])).is_some());
        assert!(list_command(&parse(&["cw", "credentials", "get", "work"])).is_none());
        let placements = crate::commands::storage_placement::list_placements();
        if cfg!(any(target_os = "linux", target_os = "macos")) {
            assert_eq!(
                placements,
                [StoragePlacement::Local, StoragePlacement::Platform]
            );
        }
        assert_eq!(placements.last(), Some(&StoragePlacement::Platform));
        assert!(signed_out(&anyhow::Error::new(
            crate::config::ConfigError::NoPlatformToken {
                cause: None,
                sandbox: None
            }
        )));
        assert!(!signed_out(&anyhow::anyhow!("connection refused")));
    }

    #[test]
    fn hidden_terminal_cancel_never_returns_partial_material() {
        for suffix in [0x1b, 0x03, 0x04] {
            let mut input =
                std::io::Cursor::new([b"synthetic-partial".as_slice(), &[suffix]].concat());
            let error = read_hidden_bytes(&mut input, 128).unwrap_err();
            assert!(error.to_string().contains("canceled"));
            assert!(!error.to_string().contains("synthetic-partial"));
        }
        assert!(read_hidden_bytes(&mut std::io::Cursor::new(b"partial"), 128).is_err());
    }

    #[test]
    fn hidden_terminal_unicode_backspace_clear_and_bounds() {
        let mut unicode = std::io::Cursor::new("synthetic-é\u{7f}x\r".as_bytes());
        assert_eq!(
            &*read_hidden_bytes(&mut unicode, 128).unwrap(),
            b"synthetic-x"
        );
        let mut clear = std::io::Cursor::new(b"discard\x15kept\r");
        assert_eq!(&*read_hidden_bytes(&mut clear, 128).unwrap(), b"kept");
        assert!(read_hidden_bytes(&mut std::io::Cursor::new(b"too-long\r"), 3).is_err());
    }

    /// The sign-in prompt's copy key (#4850), with `more` scripted: what
    /// `poll` would say each time the reader asks whether input is waiting.
    fn read_with_copy_key(input: &[u8], more: &[bool]) -> (String, usize) {
        let mut copies = 0;
        let mut answers = more.iter().copied();
        let value = read_hidden_bytes_with(
            &mut std::io::Cursor::new(input.to_vec()),
            128,
            Some(CopyKey {
                copy: &mut || copies += 1,
                more: &mut || answers.next().unwrap_or(false),
            }),
        )
        .unwrap();
        (String::from_utf8(value.to_vec()).unwrap(), copies)
    }

    #[test]
    fn c_alone_before_anything_is_typed_copies_the_link() {
        assert_eq!(
            read_with_copy_key(b"cab#cd\r", &[false]),
            ("ab#cd".to_owned(), 1)
        );
        // Typed after other text, c is part of the code.
        assert_eq!(read_with_copy_key(b"xc\r", &[]), ("xc".to_owned(), 0));
    }

    #[test]
    fn a_pasted_code_that_starts_with_c_is_the_code() {
        // Without bracketed paste: the rest of the paste is already waiting.
        assert_eq!(
            read_with_copy_key(b"cab#cd\r", &[true]),
            ("cab#cd".to_owned(), 0)
        );
        // With it: the markers say so, and are not part of the code.
        assert_eq!(
            read_with_copy_key(b"\x1b[200~cab#cd\x1b[201~\r", &[true, true]),
            ("cab#cd".to_owned(), 0)
        );
    }

    #[test]
    fn a_lone_escape_still_cancels_with_the_copy_key() {
        let mut copies = 0;
        let error = read_hidden_bytes_with(
            &mut std::io::Cursor::new(b"\x1b".to_vec()),
            128,
            Some(CopyKey {
                copy: &mut || copies += 1,
                more: &mut || false,
            }),
        )
        .unwrap_err();
        assert!(error.to_string().contains("canceled"), "{error}");
        assert_eq!(copies, 0);
    }

    #[test]
    fn unsupported_hosts_accept_platform_and_reject_local_without_fallback() {
        assert_eq!(
            credential_dispatch(StoragePlacement::Platform, false).unwrap(),
            CredentialDispatch::Platform
        );
        let error = credential_dispatch(StoragePlacement::Local, false).unwrap_err();
        assert!(error.to_string().contains("only on Linux and macOS"));
        assert_eq!(
            credential_dispatch(StoragePlacement::Local, true).unwrap(),
            CredentialDispatch::Local
        );
    }

    #[test]
    fn the_store_setting_names_only_backends_this_platform_supports() {
        assert_eq!(
            resolve_local_credential_store(None).unwrap(),
            ProtectedStoreBackend::platform_default().unwrap()
        );
        for value in ["", "keyring", "Keychain", "os"] {
            assert!(
                resolve_local_credential_store(Some(value)).is_err(),
                "{value}"
            );
        }
        #[cfg(target_os = "macos")]
        {
            assert_eq!(
                resolve_local_credential_store(Some("file")).unwrap(),
                ProtectedStoreBackend::File
            );
            let error = resolve_local_credential_store(Some("secret-service")).unwrap_err();
            assert!(
                error.to_string().contains("\"keychain\" or \"file\""),
                "{error}"
            );
        }
        #[cfg(target_os = "linux")]
        {
            let error = resolve_local_credential_store(Some("file")).unwrap_err();
            assert!(
                error.to_string().contains("use \"secret-service\""),
                "{error}"
            );
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn local_rejection_precedes_key_input_and_platform_configuration() {
        // A debug build of the whole CLI future needs more than a test thread's
        // 2 MiB stack; the cw binary runs it on the 8 MiB main thread.
        let error = std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(crate::run_from([
                        "cw",
                        "credentials",
                        "--local",
                        "add",
                        "ssh",
                        "--name=work",
                        "--key-file=/deliberately-absent-sensitive-key",
                    ]))
                    .unwrap_err()
            })
            .unwrap()
            .join()
            .unwrap();
        assert!(
            error
                .to_string()
                .contains("available only on Linux and macOS")
        );
    }

    #[test]
    fn credential_parser_is_available_for_both_explicit_placements() {
        for placement in ["--local", "--cloud"] {
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

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_has_the_credential_children_but_no_launch_entrypoint() {
        for command in [
            "__local-credential-authority",
            "__local-credential-authority-probe",
            "__local-credential-broker",
            "__local-git-repository-executor",
            "__local-provider-revocation-executor",
            "__local-git-credential-helper",
        ] {
            let error = crate::Cli::try_parse_from(["cw", command]).unwrap_err();
            assert_eq!(
                error.kind(),
                clap::error::ErrorKind::MissingRequiredArgument,
                "{command}"
            );
        }
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn linux_only_credential_and_launch_entrypoints_are_absent() {
        for command in [
            "__local-credential-broker-confinement-probe",
            "__local-credential-broker-synthetic-smoke-check",
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
    fn claude_code_accepts_the_shown_code_and_its_callback_url() {
        let normalized = |pasted: &str| {
            normalize_claude_code(pasted.as_bytes())
                .map(|code| String::from_utf8(code.to_vec()).unwrap())
        };
        assert_eq!(
            normalized("abc-DEF_1.2~3#st4te").as_deref(),
            Some("abc-DEF_1.2~3#st4te")
        );
        assert_eq!(normalized("  abc#xyz \r\n").as_deref(), Some("abc#xyz"));
        assert_eq!(
            normalized("https://platform.claude.com/oauth/code/callback?code=abc&state=xyz")
                .as_deref(),
            Some("abc#xyz")
        );
        assert_eq!(
            normalized(
                " https://platform.claude.com/oauth/code/callback?state=x%79z&code=a%62c#top\n"
            )
            .as_deref(),
            Some("abc#xyz")
        );
        for invalid in [
            "",
            "   ",
            "abc",
            "#xyz",
            "abc#",
            "abc#x#y",
            "ab c#xyz",
            "abc#xy z",
            "abc#xyz\u{e9}",
            "https://platform.claude.com/oauth/code/callback",
            "https://platform.claude.com/oauth/code/callback?code=abc",
            "https://platform.claude.com/oauth/code/callback?code=abc&state=%zz",
            "https://platform.claude.com/oauth/code/callback?code=abc&state=x%2",
        ] {
            assert!(normalized(invalid).is_none(), "{invalid:?}");
        }
        let long = format!("{}#xyz", "a".repeat(MAX_CLAUDE_CODE_PART_BYTES + 1));
        assert!(normalized(&long).is_none());
        let longest = format!("{}#xyz", "a".repeat(MAX_CLAUDE_CODE_PART_BYTES));
        assert!(normalized(&longest).is_some());
    }

    #[test]
    fn a_misshapen_claude_code_gets_one_retry_at_a_terminal_only() {
        let value = |text: &str| ProtectedValue::new(text.as_bytes().to_vec()).unwrap();

        let mut pastes = vec![value("not-a-code"), value(" abc#xyz ")].into_iter();
        let mut out = Vec::new();
        let code = claude_code_with_retry(true, || Ok(pastes.next().unwrap()), &mut out).unwrap();
        assert_eq!(code.expose_secret(), b"abc#xyz");
        assert_eq!(
            String::from_utf8(out).unwrap(),
            format!("  {CLAUDE_CODE_SHAPE_HINT}\n")
        );

        let mut pastes = vec![value("first-paste"), value("second-paste")].into_iter();
        let mut out = Vec::new();
        let error =
            claude_code_with_retry(true, || Ok(pastes.next().unwrap()), &mut out).unwrap_err();
        assert!(error.to_string().contains("nothing was sent to Claude"));
        assert!(!error.to_string().contains("first-paste"));
        assert!(!error.to_string().contains("second-paste"));
        assert_eq!(
            String::from_utf8(out).unwrap(),
            format!("  {CLAUDE_CODE_SHAPE_HINT}\n")
        );

        let mut reads = 0;
        let mut out = Vec::new();
        assert!(
            claude_code_with_retry(
                false,
                || {
                    reads += 1;
                    Ok(value("piped-not-a-code"))
                },
                &mut out
            )
            .is_err()
        );
        assert_eq!(reads, 1);
        assert!(out.is_empty());
    }

    #[test]
    fn the_hidden_prompt_confirms_only_the_length() {
        assert_eq!(received_confirmation(b"abc#xyz"), "Got it (7 characters).");
        assert_eq!(received_confirmation(b"x"), "Got it (1 character).");
        assert_eq!(
            received_confirmation("\u{e9}#\u{fc}".as_bytes()),
            "Got it (3 characters)."
        );
        assert!(!received_confirmation(b"synthetic-secret").contains("synthetic"));
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
            provider: Some("ssh".into()),
            name: Some("work".into()),
            account_hint: None,
            expires_at: None,
            key_file: Some("/deliberately-absent-key".into()),

            guided: false,
        };
        assert_eq!(validate_ssh_import(&args).unwrap(), "work");
        args.key_file = None;
        assert!(validate_ssh_import(&args).is_err());
        args.key_file = Some("/deliberately-absent-key".into());
        args.account_hint = Some("unexpected".into());
        assert!(validate_ssh_import(&args).is_err());
        args.account_hint = None;
        args.provider = Some("github".into());
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
