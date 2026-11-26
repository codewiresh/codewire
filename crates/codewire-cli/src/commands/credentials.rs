#[cfg(test)]
use std::collections::BTreeMap;

use anyhow::Context as _;
#[cfg(test)]
use codewire_access::{AccessProfileId, CredentialId, Owner};
use codewire_access::{
    AccessProfileName, CapabilitySlot, CredentialAuthKind, CredentialStatus, ProviderId,
    builtin_provider_catalog,
};
use codewire_local_credentials::{
    AccessProfileRecord, CredentialRecord, LocalCredentialClient, NewCredential,
};
#[cfg(test)]
use codewire_protected_store::MAX_PROTECTED_VALUE_BYTES;
#[cfg(test)]
use codewire_protected_store::ProtectedStorePersistence;
use codewire_protected_store::{ProtectedStoreBackend, ProtectedValue};

use crate::config::OsEnv;

pub(in crate::commands) mod confirm;
mod delete;
mod github_reach;
mod names;
pub(in crate::commands) mod output;
mod store_notice;
mod store_wait;

use names::{local_kind, local_lookups, resolve_credential};
use output::save_refusal::{Answer, Kind, Save, save_error};

#[cfg(test)]
use super::CredentialsArgs;
#[cfg(test)]
use super::credential_input::CODEX_DEVICE_AUTHORIZATION_GUIDANCE;
use super::credential_input::connect::{
    CLAUDE_SUBSCRIPTION_ALIAS, ConnectStore, ConnectTarget, Interrupt, Reconnecting,
    claude_token_from_alias, claude_token_rotate_refusal, connected_noun, provider_id,
    provider_label, read_claude_token,
};
#[cfg(test)]
use super::credential_input::supported_profile_slot;
use super::credential_input::{
    AddKind, CredentialName, CredentialOperation, GITHUB_ALWAYS_INCLUDED, ParsedProfileSelector,
    SSH_PUBLIC_KEY_GITHUB_HINT, add_kind, admit_name, name_taken, parse_profile_selector,
    profile_set_credential, profile_slot_for, prompt_credential_material, read_ssh_import,
    settle_name, slot_provider, validate_ssh_generation, validate_ssh_import,
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
    CredentialAddArgs, CredentialConnectArgs, CredentialConnectProviderArg, CredentialListArgs,
    CredentialProfileCommand, CredentialProfileDeleteArgs, CredentialProfileSetArgs,
    CredentialProfileSlotArgs, CredentialRenameArgs, CredentialRotateArgs, CredentialSelectorArgs,
    CredentialsCommand, OutputFormat, connect_local_credential_authority, trimmed_required,
};
use output::{authentication_kind_label, status_label};

pub(crate) async fn handle_local_credentials_command(
    operation: CredentialOperation,
) -> anyhow::Result<super::credential_input::CredentialExecution> {
    let mut execution = super::credential_input::CredentialExecution::Unchanged;
    handle_local_with_receipt(operation, &mut execution).await?;
    Ok(execution)
}

async fn handle_local_with_receipt(
    operation: CredentialOperation,
    execution: &mut super::credential_input::CredentialExecution,
) -> anyhow::Result<()> {
    let client = match authority_feature_needed(&operation) {
        Some((feature, needed_for)) => {
            super::connect_local_credential_authority_serving(feature, needed_for).await?
        }
        None => connect_local_credential_authority().await?,
    };
    let mut client = names::serving_names_per_provider(client, &operation).await?;
    // A connect checks the store first where it can (#4826), but an older
    // store left serving running VMs still saves a connect correctly, so it
    // goes on without the check.
    let store_probe = codewire_local_credentials::AuthorityFeature::StoreProbe;
    let mut store_check_explained = false;
    if matches!(
        operation,
        CredentialOperation::Credential(CredentialsCommand::Connect(_))
    ) && !store_probe.served_by(client.info().protocol_version)
    {
        drop(client);
        client = super::connect_local_credential_authority_preferring(store_probe).await?;
        if !store_probe.served_by(client.info().protocol_version) {
            store_check_explained = explain_previous_cws_store(&mut client).await?;
        }
    }
    #[cfg(target_os = "linux")]
    if store_notice::writes_material(&operation) {
        store_notice::warn_before_keyring_write(&client);
    }
    let command = match operation {
        CredentialOperation::Profile(command) => {
            return profile_command(&mut client, command).await;
        }
        CredentialOperation::GenerateIntoProfile(args, profile) => {
            return generate_local_ssh_into_profile(&mut client, &args, profile).await;
        }
        CredentialOperation::Credential(command) => command,
    };
    match command {
        CredentialsCommand::Connect(args) => {
            connect_credential(&mut client, args, execution, store_check_explained).await
        }
        CredentialsCommand::Add(args) => add_credential(&mut client, args, execution).await,
        CredentialsCommand::Generate(args) => generate_local_ssh(&mut client, &args)
            .await
            .map(|record| remember_local(&record, execution)),
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
        CredentialsCommand::Delete(args) => delete::delete_credential(&mut client, args).await,
        CredentialsCommand::Set(_)
        | CredentialsCommand::Unset(_)
        | CredentialsCommand::Revisions(_)
        | CredentialsCommand::Profiles { .. } => {
            unreachable!("profile operations have a separate dispatcher")
        }
    }
}

/// The newest authority feature a command needs before it asks a provider
/// anything, and what an older authority can't do. Every connect probes the
/// store first (which also covers storing a Claude sign-in), so a sign-in is
/// never spent on an authority that would refuse it.
fn authority_feature_needed(
    operation: &CredentialOperation,
) -> Option<(codewire_local_credentials::AuthorityFeature, &'static str)> {
    use codewire_local_credentials::AuthorityFeature;
    match operation {
        CredentialOperation::Profile(CredentialProfileCommand::Default(_)) => Some((
            AuthorityFeature::DefaultProfile,
            "a default credential profile",
        )),
        CredentialOperation::Credential(CredentialsCommand::Connect(CredentialConnectArgs {
            provider: Some(CredentialConnectProviderArg::Claude),
            ..
        })) => Some((AuthorityFeature::ClaudeSignIn, "a Claude sign-in")),
        CredentialOperation::Credential(CredentialsCommand::Connect(CredentialConnectArgs {
            provider: Some(CredentialConnectProviderArg::ClaudeToken),
            ..
        })) => Some((AuthorityFeature::ClaudeToken, "a Claude token")),
        CredentialOperation::Credential(CredentialsCommand::Connect(CredentialConnectArgs {
            provider: Some(CredentialConnectProviderArg::Antigravity),
            ..
        })) => Some((
            AuthorityFeature::AntigravitySignIn,
            "an Antigravity sign-in",
        )),
        CredentialOperation::Credential(CredentialsCommand::Add(add))
            if add.provider.as_deref() == Some(CLAUDE_SUBSCRIPTION_ALIAS) =>
        {
            Some((AuthorityFeature::ClaudeToken, "a Claude token"))
        }
        _ => None,
    }
}

/// What `profiles default` says once the local default is set: the cloud's
/// sentence with the placement word changed.
fn default_set_message(name: &str) -> String {
    format!("Default profile: {name:?}. A local `cw create` uses it when you name no profile.")
}

fn remember_local(
    record: &CredentialRecord,
    execution: &mut super::credential_input::CredentialExecution,
) {
    *execution = super::credential_input::CredentialExecution::Saved(
        super::credential_input::SavedCredential {
            id: record.metadata.id.to_string(),
            name: record.metadata.display_name.clone(),
        },
    );
}

async fn connect_credential(
    client: &mut LocalCredentialClient,
    args: CredentialConnectArgs,
    execution: &mut super::credential_input::CredentialExecution,
    store_check_explained: bool,
) -> anyhow::Result<()> {
    let json = matches!(args.output, OutputFormat::Json);
    let mut store = LocalConnectStore {
        client,
        json,
        store_check_explained,
    };
    super::credential_input::connect::connect(&mut store, args, execution).await
}

/// After a cw update, the store a connect would use is the previous cw's
/// while its VMs run there (`docs/dev/LINUX-LOCAL-VMS.md`, "Credentials after
/// an upgrade"): name them and the step that moves them, before any provider
/// link, and at a terminal offer that restart. Once they run on this cw, its
/// store replaces the previous one and the connect goes on with it. False
/// when no VM can be named, so the connect says only that the store is the
/// previous cw's.
async fn explain_previous_cws_store(client: &mut LocalCredentialClient) -> anyhow::Result<bool> {
    let Some((config, previous)) = super::previous_cw_with_vms().await else {
        return Ok(false);
    };
    let names: Vec<&str> = previous.stopping().collect();
    let style =
        crate::output::Capabilities::from_process(crate::output::OutputMode::Text).stderr_style();
    eprintln!(
        "{} {}",
        style.status(crate::output::Status::Attention),
        previous_cws_store_notice(&names)
    );
    eprintln!(
        "{} cw upgrade --vms",
        style.status(crate::output::Status::Next)
    );
    if super::offer_previous_vms_restart(&config, &previous).await? {
        *client = super::connect_local_credential_authority_preferring(
            codewire_local_credentials::AuthorityFeature::StoreProbe,
        )
        .await?;
    }
    Ok(true)
}

/// The store must accept a write before any provider step (#4826): a refusal
/// stops here in the words a save's refusal uses, and no sign-in is started.
async fn probe_local_store(
    client: &mut LocalCredentialClient,
    save: Save<'_>,
    json: bool,
) -> anyhow::Result<()> {
    match store_wait::waiting_on_store(json, client.probe_protected_store()).await {
        Ok(()) => Ok(()),
        Err(status) => match probe_refusal(save, &status) {
            Some(refusal) => Err(refusal),
            None => {
                print_store_check_skipped();
                Ok(())
            }
        },
    }
}

/// What a failed probe means: `None` for an authority without the call, which
/// the connect goes on without; otherwise why it stops, before any sign-in.
/// A probe saves nothing, so every answer is definite, and the store's own
/// message goes only to the log.
fn probe_refusal(save: Save<'_>, status: &tonic::Status) -> Option<anyhow::Error> {
    use std::error::Error as _;
    if status.code() == tonic::Code::Unimplemented {
        return None;
    }
    tracing::debug!(
        code = ?status.code(),
        message = status.message(),
        "the local credential store refused its probe"
    );
    if status.source().is_some() {
        let what = match save.kind {
            Kind::Connect(provider) => connected_noun(provider),
            Kind::Write { what, .. } | Kind::Rotate { what } => what,
        };
        return Some(anyhow::anyhow!(
            "couldn't reach the local credential store, so your {what} wasn't saved"
        ));
    }
    Some(save_error(
        save,
        Answer::Refused,
        codewire_local_credentials::store_refusal_reason(status),
        configured_keychain().as_deref(),
    ))
}

/// What a connect says while the previous cw's VMs keep its store.
fn previous_cws_store_notice(names: &[&str]) -> String {
    let (noun, run, them) = if names.len() == 1 {
        ("VM", "runs", "it")
    } else {
        ("VMs", "run", "them")
    };
    format!(
        "Your local {noun} {} still {run} on the cw you updated from, and so does your local credential store, so it can't be checked before you sign in. Restarting {them} on this cw moves it here.",
        names.join(", ")
    )
}

/// Said once when a connect goes on without checking the store first and no
/// VM on the previous cw can be named.
const STORE_CHECK_SKIPPED: &str = "Your local credential store is still the one the cw you updated from started, so it can't be checked before you sign in; it switches to this cw once no local VM runs.";

fn print_store_check_skipped() {
    let style =
        crate::output::Capabilities::from_process(crate::output::OutputMode::Text).stderr_style();
    eprintln!(
        "{} {STORE_CHECK_SKIPPED}",
        style.status(crate::output::Status::Attention)
    );
}

/// The local authority's side of `cw credentials connect`: the provider login
/// runs in this process and the result is saved to the authority.
struct LocalConnectStore<'a> {
    client: &'a mut LocalCredentialClient,
    json: bool,
    /// The previous cw's store was already explained before the connect.
    store_check_explained: bool,
}

/// A provider's answer, held only until it is saved.
struct LocalApproval {
    material: ProtectedValue,
    account_hint: Option<String>,
    reach: Vec<codewire_credential_broker::GitHubAppInstallationReach>,
}

impl ConnectStore for LocalConnectStore<'_> {
    const PLACEMENT: &'static str = "local";
    type Record = CredentialRecord;
    type Approval = LocalApproval;

    async fn named(
        &mut self,
        provider: CredentialConnectProviderArg,
        name: &str,
    ) -> anyhow::Result<Option<CredentialRecord>> {
        let records = store_wait::waiting_on_store(self.json, self.client.list_credentials())
            .await
            .context("check local credential name before provider login")?;
        Ok(select_oauth_connection_target(records, name, provider)?.existing)
    }

    async fn connections(
        &mut self,
        provider: CredentialConnectProviderArg,
    ) -> anyhow::Result<Vec<CredentialRecord>> {
        let kind = connected_kind(provider);
        let provider = ProviderId::parse(provider_id(provider))?;
        let records = store_wait::waiting_on_store(self.json, self.client.list_credentials())
            .await
            .context("check local credentials before provider login")?;
        records
            .into_iter()
            .filter(|record| {
                record.metadata.provider == provider && record.metadata.authentication_kind == kind
            })
            .map(|record| {
                record.metadata.validate()?;
                Ok(record)
            })
            .collect()
    }

    fn display_name(record: &CredentialRecord) -> &str {
        &record.metadata.display_name
    }

    fn describe(record: &CredentialRecord) -> anyhow::Result<Reconnecting> {
        Ok(Reconnecting {
            name: record.metadata.display_name.clone(),
            status: status_label(record.metadata.status),
        })
    }

    async fn ready(
        &mut self,
        provider: CredentialConnectProviderArg,
        name: &str,
    ) -> anyhow::Result<()> {
        if codewire_local_credentials::AuthorityFeature::StoreProbe
            .served_by(self.client.info().protocol_version)
        {
            let save = Save {
                placement: "local",
                kind: Kind::Connect(provider),
                name,
            };
            probe_local_store(self.client, save, self.json).await
        } else {
            if !self.store_check_explained {
                print_store_check_skipped();
            }
            Ok(())
        }
    }

    async fn approve(
        &mut self,
        target: &ConnectTarget<CredentialRecord>,
        interrupt: &mut Interrupt,
    ) -> anyhow::Result<LocalApproval> {
        let sign_in =
            super::login_screen::SignInScreen::local(provider_label(target.provider), &target.name);
        match target.provider {
            CredentialConnectProviderArg::ClaudeToken => Ok(LocalApproval {
                material: read_claude_token(sign_in)?,
                account_hint: None,
                reach: Vec::new(),
            }),
            CredentialConnectProviderArg::Claude => {
                let (bundle, account_hint) =
                    super::provider_login::claude_sign_in(sign_in, interrupt)
                        .await?
                        .into_parts();
                let mut bytes = bundle.into_bytes();
                let material = ProtectedValue::new(std::mem::take(&mut *bytes))
                    .context("prepare protected Claude sign-in")?;
                Ok(LocalApproval {
                    material,
                    account_hint,
                    reach: Vec::new(),
                })
            }
            CredentialConnectProviderArg::Antigravity => {
                let (bundle, account_hint) =
                    super::provider_login::antigravity_sign_in(sign_in, interrupt)
                        .await?
                        .into_parts();
                let mut bytes = bundle.into_bytes();
                let material = ProtectedValue::new(std::mem::take(&mut *bytes))
                    .context("prepare protected Antigravity sign-in")?;
                Ok(LocalApproval {
                    material,
                    account_hint,
                    reach: Vec::new(),
                })
            }
            CredentialConnectProviderArg::Codex => {
                let (bundle, account_hint) =
                    super::provider_login::codex_device_login(sign_in, interrupt)
                        .await?
                        .into_parts();
                let mut bytes = bundle.into_bytes();
                let material = ProtectedValue::new(std::mem::take(&mut *bytes))
                    .context("prepare protected Codex credential")?;
                Ok(LocalApproval {
                    material,
                    account_hint,
                    reach: Vec::new(),
                })
            }
            CredentialConnectProviderArg::Github => {
                let mut import =
                    match super::provider_login::github_device_login(sign_in, interrupt).await {
                        Ok(import) => import,
                        Err(error) => {
                            return Err(
                                match error.downcast::<super::provider_login::IssuedButNotSaved>() {
                                    Ok(issued) => {
                                        say_discarded(CredentialConnectProviderArg::Github, None);
                                        issued.0
                                    }
                                    Err(error) => error,
                                },
                            );
                        }
                    };
                let reach = import.reach().to_vec();
                // A reconnect keeps the GitHub account its profiles already follow.
                if let Some(expected) = target
                    .existing
                    .as_ref()
                    .and_then(|record| record.metadata.account_hint.as_deref())
                    && expected != import.account_hint()
                {
                    say_discarded(CredentialConnectProviderArg::Github, None);
                    anyhow::bail!(
                        "the approved GitHub account {:?} is not the connected account {expected:?}; no credential was changed",
                        import.account_hint(),
                    );
                }
                let (mut bytes, account_hint) = import
                    .take_import()
                    .context("prepare protected GitHub credential")?;
                let material = ProtectedValue::new(std::mem::take(&mut *bytes))
                    .context("prepare protected GitHub credential")?;
                Ok(LocalApproval {
                    material,
                    account_hint,
                    reach,
                })
            }
        }
    }

    async fn discard(
        &mut self,
        provider: CredentialConnectProviderArg,
        approval: LocalApproval,
    ) -> Option<String> {
        let revoked = revoke_unsaved(provider, Some(approval.material)).await;
        super::credential_input::connect::discarded_sign_in(provider, revoked)
    }

    async fn publish(
        &mut self,
        target: ConnectTarget<CredentialRecord>,
        approval: LocalApproval,
        _: &mut Interrupt,
        execution: &mut super::credential_input::CredentialExecution,
    ) -> anyhow::Result<()> {
        let label = provider_label(target.provider);
        let connecting = target.provider;
        let format = target.output;
        let provider = ProviderId::parse(provider_id(target.provider))?;
        let authentication_kind = connected_kind(target.provider);
        // A copy to revoke if the store definitely refuses the save.
        let revocable = matches!(
            connecting,
            CredentialConnectProviderArg::Codex | CredentialConnectProviderArg::Antigravity
        )
        .then(|| ProtectedValue::from_slice(approval.material.expose_secret()).ok())
        .flatten();
        let name = target.name.clone();
        // The verified GitHub login, to tell its own account from others'.
        let verified_login = approval.account_hint.clone();
        let saved = store_wait::waiting_on_store(
            matches!(format, OutputFormat::Json),
            publish_oauth_connection(
                self.client,
                OAuthConnectionTarget {
                    provider,
                    authentication_kind,
                    display_name: target.name,
                    existing: target.existing,
                },
                approval.material,
                approval.account_hint,
            ),
        )
        .await;
        let record = match saved {
            Ok(record) => record,
            Err(status) => {
                // A refusal saved nothing, so the approved sign-in is
                // discarded as a cancel's is; an uncertain save may hold it.
                if definitely_not_saved(&status) {
                    say_discarded(connecting, revoke_unsaved(connecting, revocable).await);
                }
                return Err(local_save_error(
                    Save {
                        placement: "local",
                        kind: Kind::Connect(connecting),
                        name: &name,
                    },
                    &status,
                ));
            }
        };
        remember_local(&record, execution);
        let metadata = &record.metadata;
        let (who, expires) = match target.provider {
            CredentialConnectProviderArg::ClaudeToken => {
                (metadata.display_name.as_str(), metadata.expires_at_unix)
            }
            _ => (
                super::login_screen::signed_in_account(
                    metadata.account_hint.as_deref(),
                    &metadata.display_name,
                ),
                None,
            ),
        };
        match format {
            OutputFormat::Json => print_credentials(std::slice::from_ref(&record), format)?,
            OutputFormat::Text => {
                eprintln!();
                output::print_done(&super::login_screen::connected_result(
                    super::login_screen::SignInScreen::local(label, &metadata.display_name),
                    who,
                    expires,
                ));
            }
        }
        if matches!(target.provider, CredentialConnectProviderArg::Github) {
            eprintln!(
                "{}",
                github_reach::github_reach_summary(verified_login.as_deref(), &approval.reach)
            );
            report_github_pending(approval.reach.iter().filter_map(|installation| {
                let pending = installation.pending_permissions.as_ref()?;
                Some((
                    installation.account.as_str(),
                    pending.installation_id,
                    pending.account_kind,
                ))
            }));
        }
        Ok(())
    }
}

/// After a GitHub connect, name each installation that has not yet granted
/// what Codewire needs and, at a terminal, open the first one's settings page
/// to accept it, the way `cw login` opens its page (#2712). Elsewhere, and
/// in a synthetic build (#5592), the printed link is the way there.
pub(crate) fn report_github_pending<'a>(
    pending: impl IntoIterator<Item = (&'a str, u64, codewire_credential_broker::GitHubAccountKind)>,
) {
    let interactive = super::login_screen::opens_browser_here();
    let (notices, open) = github_pending_follow_up(pending, interactive);
    for notice in notices {
        eprintln!("{notice}");
    }
    if let Some(url) = open {
        eprintln!("Opening GitHub to accept the updated permissions...");
        let _ = super::platform_commands::open_browser(&url);
    }
}

/// The notice for each installation, as `cw credentials --cloud list`
/// shows it.
pub(crate) fn github_pending_notices<'a>(
    pending: impl IntoIterator<Item = (&'a str, u64, codewire_credential_broker::GitHubAccountKind)>,
) -> Vec<String> {
    github_pending_follow_up(pending, false).0
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
    let waiting =
        format!("GitHub is waiting for you to accept Codewire's updated permissions on {account}.");
    Some(match github_settings_page(account, installation_id, kind) {
        Some(url) => format!("{waiting} Review on GitHub: {url}"),
        None => waiting,
    })
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

struct OAuthConnectionTarget {
    provider: ProviderId,
    authentication_kind: CredentialAuthKind,
    display_name: String,
    existing: Option<CredentialRecord>,
}

/// The kind a `connect` stores: a Claude sign-in for `claude`, an OAuth
/// login for every other provider, the setup token included.
fn connected_kind(provider: CredentialConnectProviderArg) -> CredentialAuthKind {
    match provider {
        CredentialConnectProviderArg::Claude => CredentialAuthKind::ClaudeSignIn,
        CredentialConnectProviderArg::Codex
        | CredentialConnectProviderArg::Github
        | CredentialConnectProviderArg::ClaudeToken
        | CredentialConnectProviderArg::Antigravity => CredentialAuthKind::OAuth,
    }
}

/// What a local connect or credential write says when the store answers its
/// save (#4826, #5271): the cause in the words both placements share, told by
/// the status code and the store's closed reason. The store's own message
/// goes only to the log.
fn local_save_error(save: Save<'_>, status: &tonic::Status) -> anyhow::Error {
    use tonic::Code;
    tracing::debug!(
        code = ?status.code(),
        message = status.message(),
        "the local credential store did not save a connect"
    );
    let answer = match status.code() {
        _ if !definitely_not_saved(status) => Answer::Uncertain,
        Code::AlreadyExists => Answer::AlreadyExists,
        Code::NotFound => Answer::NotFound,
        _ => Answer::Refused,
    };
    save_error(
        save,
        answer,
        codewire_local_credentials::store_refusal_reason(status),
        configured_keychain().as_deref(),
    )
}

/// The keychain file `CODEWIRE_LOCAL_CREDENTIAL_KEYCHAIN` names, if set.
fn configured_keychain() -> Option<std::path::PathBuf> {
    super::credential_authority::configured_authority_store(&OsEnv)
        .ok()
        .and_then(|store| store.keychain)
}

/// Whether the store's answer to a save is a definite refusal. A failure
/// after the request may have reached the store leaves the outcome unknown.
fn definitely_not_saved(status: &tonic::Status) -> bool {
    use tonic::Code;
    !matches!(
        status.code(),
        Code::Unavailable
            | Code::DeadlineExceeded
            | Code::Cancelled
            | Code::Unknown
            | Code::Internal
            | Code::Aborted
            | Code::DataLoss
            | Code::Ok
    )
}

/// Revokes what this process can of a sign-in approved and not saved: only
/// OpenAI takes a revocation from here. The GitHub App's secret is the
/// platform's, and Claude has no revocation.
async fn revoke_unsaved(
    provider: CredentialConnectProviderArg,
    material: Option<ProtectedValue>,
) -> Option<codewire_credential_broker::provider_oauth::ProviderRevocation> {
    let material = material?;
    match provider {
        CredentialConnectProviderArg::Codex => {
            eprintln!("Asking OpenAI to revoke the Codex sign-in you approved…");
            Some(super::provider_login::revoke_unsaved_codex(material).await)
        }
        CredentialConnectProviderArg::Antigravity => {
            eprintln!("Asking Google to revoke the Antigravity sign-in you approved…");
            Some(super::provider_login::revoke_unsaved_antigravity(material).await)
        }
        _ => None,
    }
}

fn say_discarded(
    provider: CredentialConnectProviderArg,
    revoked: Option<codewire_credential_broker::provider_oauth::ProviderRevocation>,
) {
    if let Some(line) = super::credential_input::connect::discarded_sign_in(provider, revoked) {
        eprintln!("{line}");
    }
}

fn select_oauth_connection_target(
    records: Vec<CredentialRecord>,
    display_name: &str,
    connect: CredentialConnectProviderArg,
) -> anyhow::Result<OAuthConnectionTarget> {
    let provider = ProviderId::parse(provider_id(connect))?;
    let authentication_kind = connected_kind(connect);
    // Only this provider's credentials: another provider's may share the
    // name (#4928). `PROVIDER/NAME` reconnects that provider's credential.
    let name = CredentialName::parse(display_name);
    let readings = name.readings(Some(provider.as_str()));
    let existing = settle_name(display_name, local_lookups(&records, &readings))?;
    let Some(record) = existing else {
        admit_name(provider.as_str(), display_name, &records, None, local_kind)?;
        return Ok(OAuthConnectionTarget {
            provider,
            authentication_kind,
            display_name: display_name.to_owned(),
            existing: None,
        });
    };
    if record.metadata.authentication_kind != authentication_kind {
        // This provider's other kind holds the name: a Claude sign-in and a
        // Claude token can't share one (cw-pm on #4928).
        return Err(name_taken(provider.as_str(), &record, &records, local_kind));
    }
    record.metadata.validate()?;
    Ok(OAuthConnectionTarget {
        provider,
        authentication_kind,
        display_name: record.metadata.display_name.clone(),
        existing: Some(record),
    })
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
                    authentication_kind: target.authentication_kind,
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
    execution: &mut super::credential_input::CredentialExecution,
) -> anyhow::Result<()> {
    if args.provider.as_deref() == Some(CLAUDE_SUBSCRIPTION_ALIAS) {
        return connect_credential(
            client,
            claude_token_from_alias("local", &args)?,
            execution,
            false,
        )
        .await;
    }
    if args.provider.as_deref().and_then(add_kind) == Some(AddKind::SshKey) {
        let name = validate_ssh_import(&args)?;
        let records = store_wait::waiting_on_store(false, client.list_credentials()).await?;
        admit_name("ssh", &name, &records, None, local_kind)?;
        let input = read_ssh_import(&args)?;
        let save = Save {
            placement: "local",
            kind: Kind::Write {
                command: "add ssh",
                provider: "ssh",
                what: "SSH key",
            },
            name: &name,
        };
        let record = store_wait::waiting_on_store(
            false,
            client.add_ssh_credential(
                name.clone(),
                input.private_key,
                input.passphrase,
                args.expires_at,
            ),
        )
        .await
        .map_err(|status| local_save_error(save, &status))?;
        remember_local(&record, execution);
        return print_credentials(&[record], OutputFormat::Text);
    }
    anyhow::ensure!(
        args.key_file.is_none(),
        "--key-file is only valid for add ssh"
    );
    let word = trimmed_required(
        args.provider
            .as_deref()
            .context("credential provider is required")?,
        "provider",
    )?;
    let authentication_kind = api_key_enrollment_kind(word)?;
    let provider_name = codewire_access::credential_type(word).map_or(word, |row| row.provider);
    let provider = ProviderId::parse(provider_name).context("invalid credential provider")?;
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

    anyhow::ensure!(args.account_hint.is_none(), output::refusal::ACCOUNT_HINT);
    let display_name = trimmed_required(
        args.name
            .as_deref()
            .context("credential name is required")?,
        "credential name",
    )?
    .to_owned();
    // The name is checked before the key is asked for, as in the cloud.
    let records = store_wait::waiting_on_store(false, client.list_credentials()).await?;
    admit_name(provider.as_str(), &display_name, &records, None, local_kind)?;
    let input = NewCredential {
        provider,
        authentication_kind,
        display_name,
        account_hint: None,
        expires_at_unix: args.expires_at,
    };
    let material = prompt_credential_material(input.provider.as_str(), input.authentication_kind)?;
    let provider = input.provider.to_string();
    let (command, what, name) = (
        format!("add {word}"),
        output::kind_label(
            input.provider.as_str(),
            authentication_kind_label(input.authentication_kind),
        ),
        input.display_name.clone(),
    );
    let save = Save {
        placement: "local",
        kind: Kind::Write {
            command: &command,
            provider: &provider,
            what: &what,
        },
        name: &name,
    };
    let record = store_wait::waiting_on_store(false, client.add_credential(input, material))
        .await
        .map_err(|status| local_save_error(save, &status))?;
    remember_local(&record, execution);
    print_credentials(&[record], OutputFormat::Text)
}

/// Refuses `name` if a local credential has it, before the key is asked for, as in the cloud.
/// The listing can wait behind another command's store call, so it shows the waiting line (#5271).
async fn list_credentials(
    client: &mut LocalCredentialClient,
    args: CredentialListArgs,
) -> anyhow::Result<()> {
    let records = client
        .list_credentials()
        .await
        .context("list local credentials")?;
    print_listing(client, &records, args.output).await
}

async fn get_credential(
    client: &mut LocalCredentialClient,
    args: CredentialSelectorArgs,
) -> anyhow::Result<()> {
    let record = resolve_credential(client, &args.credential, None).await?;
    print_listing(client, &[record], args.output).await
}

async fn rename_credential(
    client: &mut LocalCredentialClient,
    args: CredentialRenameArgs,
) -> anyhow::Result<()> {
    let record = resolve_credential(client, &args.credential, None).await?;
    let name = trimmed_required(&args.name, "credential name")?.to_owned();
    let records = client
        .list_credentials()
        .await
        .context("list local credentials")?;
    let provider = record.metadata.provider.as_str();
    admit_name(provider, &name, &records, Some(&record), local_kind)?;
    let renamed = client
        .rename_credential(&record.metadata.id, name)
        .await
        .map_err(|status| match status.code() {
            _ if codewire_local_credentials::store_refusal_reason(&status)
                == Some(
                    codewire_local_credentials::StoreRefusal::CredentialNameReservesProvider
                        .reason(),
                ) =>
            {
                anyhow::anyhow!(output::refusal::reserved_name(&args.name))
            }
            tonic::Code::AlreadyExists => anyhow::anyhow!(output::refusal::name_in_use(provider)),
            _ => anyhow::Error::new(status).context("rename local credential"),
        })?;
    print_credentials(&[renamed], OutputFormat::Text)
}

async fn rotate_credential(
    client: &mut LocalCredentialClient,
    args: CredentialRotateArgs,
) -> anyhow::Result<()> {
    let record =
        store_wait::waiting_on_store(false, resolve_credential(client, &args.credential, None))
            .await?;
    if record.metadata.authentication_kind == CredentialAuthKind::SshKey {
        anyhow::bail!(output::refusal::ROTATE_SSH);
    }
    if record.metadata.is_claude_subscription_token() {
        return Err(claude_token_rotate_refusal(
            "local",
            &record.metadata.display_name,
        ));
    }
    if !manually_supplied_credential_kind(record.metadata.authentication_kind) {
        anyhow::bail!(output::refusal::ROTATE_CONNECTED);
    }
    eprintln!(
        "{}",
        output::rotation_notice(
            "local",
            &record.metadata.display_name,
            &record.metadata.id.to_string(),
            record.metadata.revocation_generation,
            args.expires_at,
        )
    );
    let material = prompt_credential_material(
        record.metadata.provider.as_str(),
        record.metadata.authentication_kind,
    )?;
    let what = output::kind_label(
        record.metadata.provider.as_str(),
        authentication_kind_label(record.metadata.authentication_kind),
    );
    let save = Save {
        placement: "local",
        kind: Kind::Rotate { what: &what },
        name: &record.metadata.display_name,
    };
    let rotated = store_wait::waiting_on_store(
        false,
        client.rotate_credential_material(
            &record.metadata.id,
            record.metadata.revocation_generation,
            material,
            args.expires_at,
            record.metadata.account_hint.clone(),
        ),
    )
    .await
    .map_err(|status| local_save_error(save, &status))?;
    print_credentials(&[rotated], OutputFormat::Text)
}

/// `cw credentials --local revoke` (#4717 C6): asked once, then revoked, then
/// what its provider still holds is said, as the cloud's revoke says it.
async fn revoke_credential(
    client: &mut LocalCredentialClient,
    args: confirm::CredentialRevokeArgs,
) -> anyhow::Result<()> {
    let record = resolve_credential(client, &args.credential, None).await?;
    let name = &record.metadata.display_name;
    if !confirm::confirm(
        "local",
        name,
        confirm::Change::Revoke,
        args.yes,
        args.output,
    )? {
        return Ok(());
    }
    // An authority that serves it also asks the provider (#4717).
    let (revoked, answer) = if delete::authority_asks_provider(client.info().protocol_version) {
        let (revoked, reported) = client
            .revoke_credential_at_provider(&record.metadata.id)
            .await
            .context("revoke local credential")?;
        (revoked, delete::provider_answer(reported.as_ref()))
    } else {
        let revoked = client
            .revoke_credential(&record.metadata.id)
            .await
            .context("revoke local credential")?;
        (revoked, output::ProviderAnswer::NotAsked)
    };
    if matches!(args.output, OutputFormat::Json) {
        return print_credentials(&[revoked], args.output);
    }
    output::print_done(&output::revoked("local", name));
    if let Some(line) = output::at_provider(
        record.metadata.provider.as_str(),
        output::authentication_kind_label(record.metadata.authentication_kind),
        answer,
    ) {
        eprintln!("{line}");
    }
    Ok(())
}

/// Generates a local SSH identity and prints it with its public key.
async fn generate_local_ssh(
    client: &mut LocalCredentialClient,
    args: &super::CredentialGenerateArgs,
) -> anyhow::Result<CredentialRecord> {
    let name = validate_ssh_generation(args)?;
    let records = client
        .list_credentials()
        .await
        .context("list local credentials")?;
    admit_name("ssh", &name, &records, None, local_kind)?;
    let save = Save {
        placement: "local",
        kind: Kind::Write {
            command: "generate ssh",
            provider: "ssh",
            what: "SSH key",
        },
        name: &name,
    };
    let record = store_wait::waiting_on_store(
        false,
        client.generate_ssh_credential(name.clone(), args.expires_at),
    )
    .await
    .map_err(|status| local_save_error(save, &status))?;
    print_credentials(std::slice::from_ref(&record), OutputFormat::Text)?;
    eprintln!("{SSH_PUBLIC_KEY_GITHUB_HINT}");
    Ok(record)
}

/// `--profile NAME generate ssh`: generates the identity, then sets it as the
/// profile's SSH key, creating the profile on first use.
async fn generate_local_ssh_into_profile(
    client: &mut LocalCredentialClient,
    args: &super::CredentialGenerateArgs,
    profile: String,
) -> anyhow::Result<()> {
    let record = generate_local_ssh(client, args).await?;
    set_profile_entry(
        client,
        CredentialProfileSetArgs {
            profile,
            slot: Some("ssh".to_owned()),
            credential: Some(format!("id:{}", record.metadata.id)),
        },
    )
    .await
}

/// Before a local VM is created in a terminal with a local profile that has
/// no SSH key, asks whether to give the profile one (default no), then sets an
/// existing local SSH key or a newly generated one. VMs get SSH keys only
/// through their profile, so a VM without a profile key gets none.
pub(crate) async fn offer_local_profile_ssh_key(profile: &str) -> anyhow::Result<()> {
    let ssh = CapabilitySlot::parse("ssh").context("ssh capability slot")?;
    let mut client = connect_local_credential_authority().await?;
    let (existing, _) = local_profile_for_set(&mut client, profile).await?;
    if existing
        .as_ref()
        .is_some_and(|record| record.profile.entries.contains_key(&ssh))
    {
        return Ok(());
    }
    if !super::prompt_confirm_default_no(&format!(
        "Profile local:{profile} has no SSH key. Add one for VMs that use it?"
    ))? {
        return Ok(());
    }
    let keys = client
        .list_credentials()
        .await
        .context("list local credentials")?
        .into_iter()
        .filter(|record| {
            record.metadata.ssh_public_key.is_some()
                && record.metadata.status == CredentialStatus::Active
        })
        .collect::<Vec<_>>();
    for (index, record) in keys.iter().enumerate() {
        let fingerprint = record
            .metadata
            .ssh_public_key
            .as_ref()
            .map(|key| key.fingerprint.as_str())
            .unwrap_or_default();
        eprintln!(
            "  {}) {} {fingerprint}",
            index + 1,
            record.metadata.display_name
        );
    }
    let generate = keys.len() + 1;
    eprintln!("  {generate}) Generate a new key");
    let choice = super::prompt_default("SSH key", &generate.to_string())?;
    let index = choice
        .parse::<usize>()
        .ok()
        .filter(|choice| (1..=generate).contains(choice))
        .with_context(|| format!("choose a number from 1 to {generate}"))?;
    let credential = if index == generate {
        let name = super::prompt_default("New SSH key name", &format!("{profile}-ssh"))?;
        let args = super::CredentialGenerateArgs {
            provider: Some("ssh".to_owned()),
            name: Some(name),
            expires_at: None,
            guided: false,
        };
        generate_local_ssh(&mut client, &args).await?.metadata.id
    } else {
        keys[index - 1].metadata.id.clone()
    };
    set_profile_entry(
        &mut client,
        CredentialProfileSetArgs {
            profile: profile.to_owned(),
            slot: Some("ssh".to_owned()),
            credential: Some(format!("id:{credential}")),
        },
    )
    .await
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
                .context("list the profiles on this computer")?;
            print_profiles(client, &records, args.output).await
        }
        CredentialProfileCommand::Get(args) => {
            let record = resolve_profile(client, &args.profile).await?;
            if let Some(revision) = args.revision {
                let revision = client
                    .get_profile_revision(&record.profile.id, revision)
                    .await
                    .context("get exact local profile revision")?;
                print_profile_revisions(client, &[revision], args.output).await
            } else {
                print_profiles(client, &[record], args.output).await
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
                .context("list the revisions of the profile on this computer")?;
            print_profile_revisions(client, &revisions, args.output).await
        }
        CredentialProfileCommand::Delete(args) => delete_profile(client, args).await,
        CredentialProfileCommand::Default(args) => {
            let record = resolve_profile(client, &args.profile).await?;
            let selected = client
                .set_default_profile(&record.profile.id)
                .await
                .context("set the default profile on this computer")?;
            anyhow::ensure!(
                selected.profile.id == record.profile.id && selected.is_default,
                "the store on this computer returned a different default profile"
            );
            eprintln!(
                "{}",
                default_set_message(&selected.profile.name.to_string())
            );
            Ok(())
        }
    }
}

async fn set_profile_entry(
    client: &mut LocalCredentialClient,
    args: CredentialProfileSetArgs,
) -> anyhow::Result<()> {
    let selector = profile_set_credential(&args)?;
    let slot = args.slot.as_deref().context("a provider is required")?;
    let credential = resolve_credential(client, selector, slot_provider(slot)).await?;
    let slot = profile_slot_for(
        &credential.metadata.display_name,
        slot,
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
    let created = existing.is_none();
    let updated = match existing {
        Some(profile) => client
            .update_profile(&profile.profile.id, profile.profile.revision, &entries)
            .await.context("update the exact revision of the profile on this computer")?,
        None => client.create_profile(&name.context("new profiles require a name")?, &entries)
            .await.context("create local profile with its first selection; inspect before retrying an uncertain result")?,
    };
    let profile = updated.profile.name.to_string();
    let held = &credential.metadata.display_name;
    output::print_done(&if created {
        output::profile_created(&profile, held)
    } else {
        output::profile_now_holds(&profile, held)
    });
    if created && updated.is_default {
        eprintln!("{}", now_default_message(&updated.profile.name.to_string()));
    }
    Ok(())
}

/// What a set says when the profile it created is the store's first, and so
/// its default (#4717).
fn now_default_message(name: &str) -> String {
    format!(
        "{name:?} is now your default profile: a local `cw create` uses it when you name no profile."
    )
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
    let slot = CapabilitySlot::parse(trimmed_required(&args.slot, "provider")?)
        .context("unknown provider; use codex, openai, github, anthropic or ssh")?;
    let mut entries = profile.profile.entries.clone();
    if entries.remove(&slot).is_none() {
        anyhow::bail!(output::refusal::slot_not_selected(
            "local",
            &profile.profile.name.to_string(),
            slot.as_str()
        ));
    }
    let updated = client
        .update_profile(&profile.profile.id, profile.profile.revision, &entries)
        .await
        .context("update the profile on this computer")?;
    output::print_done(&output::profile_removed(
        &updated.profile.name.to_string(),
        slot.as_str(),
    ));
    Ok(())
}

async fn delete_profile(
    client: &mut LocalCredentialClient,
    args: CredentialProfileDeleteArgs,
) -> anyhow::Result<()> {
    let record = resolve_profile(client, &args.profile).await?;
    anyhow::ensure!(
        !record.is_default,
        super::platform_profiles::default_delete_refusal(
            &record.profile.name.to_string(),
            "--local"
        )
    );
    let name = record.profile.name.to_string();
    let question = format!("Delete local profile {name:?}?");
    let change = confirm::Change::DeleteProfile {
        question: &question,
    };
    if !confirm::confirm("local", &name, change, args.yes, OutputFormat::Text)? {
        return Ok(());
    }
    client
        .delete_profile(&record.profile.id)
        .await
        .context("delete the profile on this computer")?;
    output::print_done(&output::profile_deleted("local", &name));
    Ok(())
}

async fn resolve_profile(
    client: &mut LocalCredentialClient,
    selector: &str,
) -> anyhow::Result<AccessProfileRecord> {
    match parse_profile_selector(selector)? {
        ParsedProfileSelector::Id(id) => client
            .get_profile(&id)
            .await
            .with_context(|| format!("get the profile on this computer by ID {id}")),
        ParsedProfileSelector::Reference(reference) => client
            .resolve_profile(&reference)
            .await
            .with_context(|| format!("find the profile {reference} on this computer")),
        ParsedProfileSelector::Name(name) => {
            let records = client
                .list_profiles()
                .await
                .context("list the profiles on this computer")?;
            select_profile_by_name(&records, name.as_str())
        }
    }
}

fn select_profile_by_name(
    records: &[AccessProfileRecord],
    name: &str,
) -> anyhow::Result<AccessProfileRecord> {
    optional_profile_by_name(records, name)?
        .cloned()
        .ok_or_else(|| anyhow::anyhow!(output::refusal::profile_not_found("local", name)))
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
        anyhow::bail!("more than one profile on this computer is named {name:?}");
    }
    Ok(record)
}

fn api_key_enrollment_kind(provider: &str) -> anyhow::Result<CredentialAuthKind> {
    match provider {
        "claude-subscription" => {
            anyhow::bail!("use `connect claude-token --name NAME` for a Claude (token)")
        }
        _ if add_kind(provider) == Some(AddKind::ApiKey) => Ok(CredentialAuthKind::ApiKey),
        _ => anyhow::bail!(output::refusal::add_unsupported(provider)),
    }
}

fn manually_supplied_credential_kind(value: CredentialAuthKind) -> bool {
    matches!(
        value,
        CredentialAuthKind::ApiKey | CredentialAuthKind::AccessToken
    )
}

/// Print local credentials, as a command's result.
fn print_credentials(records: &[CredentialRecord], output: OutputFormat) -> anyhow::Result<()> {
    output::print_local_credentials(records, None, None, output)
}

/// Print a listing of local credentials, with the profiles that use them.
async fn print_listing(
    client: &mut LocalCredentialClient,
    records: &[CredentialRecord],
    output: OutputFormat,
) -> anyhow::Result<()> {
    let profiles = client
        .list_profiles()
        .await
        .context("list the profiles on this computer")?;
    let store = client.info().protected_store.map(|store| store.backend);
    output::print_local_credentials(records, store, Some(&output::local_uses(&profiles)), output)?;
    if store == Some(ProtectedStoreBackend::File)
        && matches!(output, OutputFormat::Text)
        && let Ok(root) = super::local_credential_root(&OsEnv)
    {
        eprintln!("{}", store_notice::file_store_line(&root));
    }
    Ok(())
}

/// Print local profiles with their credentials by name.
async fn print_profiles(
    client: &mut LocalCredentialClient,
    records: &[AccessProfileRecord],
    output: OutputFormat,
) -> anyhow::Result<()> {
    let credentials = client
        .list_credentials()
        .await
        .context("list local credentials")?;
    output::print_local_profiles(records, &output::local_names(&credentials), output)
}

async fn print_profile_revisions(
    client: &mut LocalCredentialClient,
    records: &[codewire_local_credentials::AccessProfileRevisionRecord],
    output: OutputFormat,
) -> anyhow::Result<()> {
    let credentials = client
        .list_credentials()
        .await
        .context("list local credentials")?;
    output::print_local_profile_revisions(records, &output::local_names(&credentials), output)
}

#[cfg(test)]
mod local_store_tests;
#[cfg(test)]
mod names_tests;
#[cfg(test)]
mod tests {
    #[test]
    fn a_connect_on_the_previous_cws_store_names_its_vms_and_the_move() {
        let one = super::previous_cws_store_notice(&["dev"]);
        assert_eq!(
            one,
            "Your local VM dev still runs on the cw you updated from, and so does your local credential store, so it can't be checked before you sign in. Restarting it on this cw moves it here."
        );
        let two = super::previous_cws_store_notice(&["dev", "web"]);
        assert!(
            two.starts_with("Your local VMs dev, web still run"),
            "{two}"
        );
        assert!(two.contains("Restarting them on this cw"), "{two}");
    }

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

    use super::super::credential_input::{ParsedCredentialSelector, parse_credential_selector};
    use super::names::select_credential_by_name;
    use super::*;
    use crate::{Cli, Command};

    /// Bounds a readiness wait in these tests. Readiness itself ends the wait
    /// and a server that ended fails it at once, so this only turns a hang
    /// into a failure. The 3 s guesses it replaces failed while a loaded CI
    /// host stalled I/O (#3231).
    const READINESS_HANG_GUARD: Duration = Duration::from_secs(120);

    /// Connects once the in-process synthetic authority listens.
    pub(super) async fn connect_ready_authority<T>(
        config: &codewire_local_credentials::AuthorityRuntimeConfig,
        server: &tokio::task::JoinHandle<T>,
    ) -> LocalCredentialClient {
        tokio::time::timeout(READINESS_HANG_GUARD, async {
            loop {
                if let Ok(client) = LocalCredentialClient::connect(config).await {
                    break client;
                }
                assert!(
                    !server.is_finished(),
                    "synthetic authority ended before it listened"
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("synthetic authority ready")
    }

    #[test]
    fn codex_connect_help_explains_device_authorization_for_both_placements() {
        for placement in ["--local", "--cloud"] {
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

    pub(super) fn credential_with(id: &str, display_name: &str) -> CredentialRecord {
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
            is_default: false,
        }
    }

    #[test]
    fn oauth_connection_name_selects_only_one_exact_matching_identity() {
        let mut record = credential();
        record.metadata.authentication_kind = CredentialAuthKind::OAuth;
        record.metadata.revocation_generation = 7;
        let target = select_oauth_connection_target(
            vec![record.clone()],
            "WORK-OPENAI",
            CredentialConnectProviderArg::Codex,
        )
        .unwrap();
        assert_eq!(target.existing.unwrap(), record);
        // Another provider's credential of that name is neither reconnected
        // nor in the way (#4928).
        for provider in [
            CredentialConnectProviderArg::Github,
            CredentialConnectProviderArg::Claude,
        ] {
            let target =
                select_oauth_connection_target(vec![record.clone()], "work-openai", provider)
                    .unwrap();
            assert!(target.existing.is_none());
        }
        let mut wrong_kind = record.clone();
        wrong_kind.metadata.authentication_kind = CredentialAuthKind::ApiKey;
        assert!(
            select_oauth_connection_target(
                vec![wrong_kind],
                "work-openai",
                CredentialConnectProviderArg::Codex,
            )
            .is_err()
        );
        let mut duplicate = record.clone();
        duplicate.metadata.id =
            CredentialId::parse("22222222-2222-4222-8222-222222222222").unwrap();
        let error = select_oauth_connection_target(
            vec![record, duplicate],
            "work-openai",
            CredentialConnectProviderArg::Codex,
        )
        .err()
        .unwrap();
        assert!(error.to_string().contains("names more than one credential"));
        let target = select_oauth_connection_target(
            vec![credential()],
            "new-name",
            CredentialConnectProviderArg::Github,
        )
        .unwrap();
        assert!(target.existing.is_none());
    }

    #[test]
    fn connecting_claude_targets_a_claude_sign_in_and_reconnects_only_one() {
        let target = select_oauth_connection_target(
            Vec::new(),
            "claude",
            CredentialConnectProviderArg::Claude,
        )
        .unwrap();
        assert_eq!(target.authentication_kind, CredentialAuthKind::ClaudeSignIn);
        assert!(target.existing.is_none());
        let mut sign_in = credential();
        sign_in.metadata.provider = ProviderId::parse("anthropic").unwrap();
        sign_in.metadata.authentication_kind = CredentialAuthKind::ClaudeSignIn;
        let target = select_oauth_connection_target(
            vec![sign_in.clone()],
            "WORK-OPENAI",
            CredentialConnectProviderArg::Claude,
        )
        .unwrap();
        assert_eq!(target.existing, Some(sign_in.clone()));
        // An Anthropic API key under that name is never replaced by a sign-in.
        let mut api_key = sign_in;
        api_key.metadata.authentication_kind = CredentialAuthKind::ApiKey;
        assert!(
            select_oauth_connection_target(
                vec![api_key],
                "work-openai",
                CredentialConnectProviderArg::Claude
            )
            .is_err()
        );
    }

    /// Only a Claude sign-in needs a newer authority; the store check is a
    /// preference a connect goes on without (#4826, #4967).
    #[test]
    fn only_a_claude_sign_in_needs_a_newer_authority() {
        use codewire_local_credentials::AuthorityFeature;
        let connect = |provider| {
            CredentialOperation::Credential(CredentialsCommand::Connect(CredentialConnectArgs {
                credential_type: None,
                provider: Some(provider),
                name: Some("work".into()),
                yes: false,
                output: crate::commands::OutputFormat::Text,
                expires_at: None,
                key_file: None,
                account_hint: None,
                guided: false,
            }))
        };
        let (feature, _) = authority_feature_needed(&connect(CredentialConnectProviderArg::Claude))
            .expect("a Claude sign-in names the feature it needs");
        assert_eq!(feature, AuthorityFeature::ClaudeSignIn);
        for provider in [
            CredentialConnectProviderArg::Codex,
            CredentialConnectProviderArg::Github,
        ] {
            assert_eq!(authority_feature_needed(&connect(provider)), None);
        }
    }

    /// An authority without the probe lets the connect go on; a store's
    /// refusal and a lost connection stop it, each in its own words.
    #[test]
    fn a_failed_probe_stops_the_connect_unless_the_authority_lacks_the_call() {
        let save = |provider| Save {
            placement: "local",
            kind: Kind::Connect(provider),
            name: "work",
        };
        let claude = save(CredentialConnectProviderArg::Claude);
        assert!(probe_refusal(claude, &tonic::Status::unimplemented("no such method")).is_none());
        // A probe saves nothing, so even an unavailable store is a definite
        // refusal, in the save's words and without the store's text.
        let store_text = "local credential authority storage is unavailable";
        let refused = probe_refusal(claude, &tonic::Status::unavailable(store_text))
            .expect("a refusal stops the connect");
        assert_eq!(
            crate::error_report::sentence(&refused),
            "the local credential store refused your Claude sign-in, so nothing was saved"
        );
        assert!(!format!("{refused:#}").contains(store_text));
        let lost = probe_refusal(
            save(CredentialConnectProviderArg::Codex),
            &tonic::Status::from_error(Box::new(std::io::Error::other("connection reset"))),
        )
        .expect("a lost connection stops the connect");
        assert_eq!(
            lost.to_string(),
            "couldn't reach the local credential store, so your Codex sign-in wasn't saved"
        );
    }

    #[test]
    fn a_local_connect_refusal_says_nothing_was_saved_without_store_text() {
        let save = Save {
            placement: "local",
            kind: Kind::Connect(CredentialConnectProviderArg::Claude),
            name: "work",
        };
        let store_text = "the store cannot hold this credential";
        let refused = local_save_error(save, &tonic::Status::failed_precondition(store_text));
        assert_eq!(
            crate::error_report::sentence(&refused),
            "the local credential store refused your Claude sign-in, so nothing was saved"
        );
        // A refusal the store names is worded here, never by the store.
        let mut locked = tonic::Status::failed_precondition(store_text);
        locked.metadata_mut().insert(
            codewire_local_credentials::STORE_REFUSAL_KEY,
            codewire_local_credentials::StoreRefusal::KeychainLocked
                .reason()
                .parse()
                .unwrap(),
        );
        let text = format!("{:#}", local_save_error(save, &locked));
        assert!(text.contains("locked"), "{text}");
        assert!(
            text.contains("so your Claude sign-in wasn't saved"),
            "{text}"
        );
        assert!(!text.contains(store_text), "{text}");
        // Unavailable is never definite: a timeout, a storage fault after the
        // commit, or a lost connection may each follow a save that landed.
        let mut refused_connection = tonic::Status::unavailable("gone");
        refused_connection.set_source(std::sync::Arc::new(std::io::Error::other(
            "connection refused",
        )));
        for status in [
            refused_connection,
            tonic::Status::unavailable("local protected storage did not respond in time"),
            tonic::Status::unavailable("local credential authority storage is unavailable"),
            tonic::Status::deadline_exceeded("deadline"),
            tonic::Status::cancelled("cancelled"),
        ] {
            assert_eq!(
                crate::error_report::sentence(&local_save_error(save, &status)),
                "the local credential store didn't confirm saving your Claude sign-in, so it may or may not be saved; check the list before connecting again"
            );
        }
        let uncertain = local_save_error(save, &tonic::Status::deadline_exceeded("x"));
        for error in [refused, uncertain] {
            assert_eq!(
                error
                    .downcast_ref::<crate::error_report::NextStep>()
                    .map(ToString::to_string)
                    .as_deref(),
                Some("cw credentials --local list")
            );
        }
    }

    #[test]
    fn oauth_connect_parser_accepts_explicit_reconnect_confirmation() {
        for placement in ["--local", "--cloud"] {
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
    async fn generate_ssh_binds_a_profile_only_when_one_is_named() {
        let temp = tempfile::tempdir().unwrap();
        let config = codewire_local_credentials::AuthorityRuntimeConfig {
            root: temp.path().join("authority"),
            executable: std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap(),
            socket_dir: temp.path().join("authority"),
        };
        let server = tokio::spawn(
            codewire_local_credentials::serve_local_credential_authority(
                config.clone(),
                codewire_protected_store::EphemeralProtectedStore::default(),
                builtin_provider_catalog(),
            ),
        );
        let mut client = connect_ready_authority(&config, &server).await;
        let generate = |name: &str| super::super::CredentialGenerateArgs {
            provider: Some("ssh".to_owned()),
            name: Some(name.to_owned()),
            expires_at: None,

            guided: false,
        };

        let loose = generate_local_ssh(&mut client, &generate("loose-ssh"))
            .await
            .unwrap();
        assert!(loose.metadata.ssh_public_key.is_some());
        assert!(client.list_profiles().await.unwrap().is_empty());

        generate_local_ssh_into_profile(&mut client, &generate("work-ssh"), "work".to_owned())
            .await
            .unwrap();
        let profiles = client.list_profiles().await.unwrap();
        assert_eq!(profiles.len(), 1);
        let work = &profiles[0].profile;
        assert_eq!(work.name.to_string(), "work");
        let bound = &work.entries[&CapabilitySlot::parse("ssh").unwrap()];
        let credentials = client.list_credentials().await.unwrap();
        let bound = credentials
            .iter()
            .find(|record| &record.metadata.id == bound)
            .unwrap();
        assert_eq!(bound.metadata.display_name, "work-ssh");
        assert_ne!(bound.metadata.id, loose.metadata.id);
        server.abort();
    }

    #[tokio::test]
    async fn oauth_publication_reconnect_keeps_profile_and_fails_stale_without_retry() {
        let temp = tempfile::tempdir().unwrap();
        let config = codewire_local_credentials::AuthorityRuntimeConfig {
            root: temp.path().join("authority"),
            executable: std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap(),
            socket_dir: temp.path().join("authority"),
        };
        let server = tokio::spawn(
            codewire_local_credentials::serve_local_credential_authority(
                config.clone(),
                codewire_protected_store::EphemeralProtectedStore::default(),
                builtin_provider_catalog(),
            ),
        );
        let mut client = connect_ready_authority(&config, &server).await;
        for (provider, slot) in [
            (CredentialConnectProviderArg::Codex, CapabilitySlot::codex()),
            (
                CredentialConnectProviderArg::Github,
                CapabilitySlot::github(),
            ),
        ] {
            let name = format!("work-{}", provider_id(provider));
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
        tokio::time::timeout(READINESS_HANG_GUARD, server)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn a_second_local_github_connection_is_refused_before_any_device_code() {
        let temp = tempfile::tempdir().unwrap();
        let config = codewire_local_credentials::AuthorityRuntimeConfig {
            root: temp.path().join("authority"),
            executable: std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap(),
            socket_dir: temp.path().join("authority"),
        };
        let server = tokio::spawn(
            codewire_local_credentials::serve_local_credential_authority(
                config.clone(),
                codewire_protected_store::EphemeralProtectedStore::default(),
                builtin_provider_catalog(),
            ),
        );
        let mut client = connect_ready_authority(&config, &server).await;
        let target = select_oauth_connection_target(
            Vec::new(),
            "work",
            CredentialConnectProviderArg::Github,
        )
        .unwrap();
        let connected = publish_oauth_connection(
            &mut client,
            target,
            ProtectedValue::from_slice(b"synthetic-github-oauth").unwrap(),
            Some("octocat".into()),
        )
        .await
        .unwrap();
        let mut execution = super::super::credential_input::CredentialExecution::Unchanged;
        let error = connect_credential(
            &mut client,
            CredentialConnectArgs {
                credential_type: None,
                provider: Some(CredentialConnectProviderArg::Github),
                name: Some("other".into()),
                yes: true,
                output: crate::commands::OutputFormat::Text,
                expires_at: None,
                key_file: None,
                account_hint: None,
                guided: false,
            },
            &mut execution,
            false,
        )
        .await
        .unwrap_err();
        assert_eq!(
            format!("{error:#}"),
            "GitHub is already connected as work; run `cw credentials --local connect github --name work --yes` to reconnect it"
        );
        assert!(matches!(
            execution,
            super::super::credential_input::CredentialExecution::Unchanged
        ));
        assert_eq!(client.list_credentials().await.unwrap(), [connected]);
        client.shutdown().await.unwrap();
        tokio::time::timeout(READINESS_HANG_GUARD, server)
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
            let cli = crate::Cli::try_parse_from(argv).unwrap();
            let (local, platform) = (cli.local, cli.cloud);
            let crate::Command::Credentials(args) = cli.command else {
                panic!("expected credentials command")
            };
            assert!(credential_command_json(&args.command));
            assert!(
                resolve_storage_placement(local, platform, credential_command_json(&args.command))
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
            select_credential_by_name(&records, name, None)
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
            select_credential_by_name(&records, name, None)
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
            select_credential_by_name(&records, name, None)
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
        let error =
            select_credential_by_name(&records, CredentialName::parse("work"), None).unwrap_err();
        assert!(
            error.to_string().contains("names more than one credential"),
            "{error}"
        );
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
        assert!(
            error
                .to_string()
                .contains("more than one profile on this computer is named \"work\"")
        );
    }

    #[test]
    fn ssh_enrollment_uses_one_generate_or_explicit_import_in_both_stores() {
        for placement in ["--local", "--cloud"] {
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
            }) if name.as_deref() == Some("work"))
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
            for placement in ["--local", "--cloud"] {
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
                }) if name.as_deref() == Some("work"))
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

    /// `add` on this computer takes exactly the providers its picker
    /// offers (#5446). An SSH key is taken only through `add_kind`, which
    /// reads the list the picker is built from; an API key goes through
    /// `api_key_enrollment_kind` too, whose own arm could take a provider
    /// the picker lacks. Every API key offered is one the catalog takes.
    #[test]
    fn the_add_picker_offers_every_provider_local_add_takes() {
        use crate::commands::credential_input::{PROVIDER_WORDS_FOR_TESTS, add_providers};
        let catalog = builtin_provider_catalog();
        for provider in PROVIDER_WORDS_FOR_TESTS {
            let offered = add_providers()
                .into_iter()
                .find(|(word, ..)| *word == provider)
                .map(|(_, kind, _)| kind);
            let api_key = api_key_enrollment_kind(provider).is_ok();
            assert_eq!(
                api_key,
                offered == Some(AddKind::ApiKey),
                "--local add {provider}"
            );
            if api_key {
                let provider_id =
                    codewire_access::credential_type(provider).map_or(provider, |row| row.provider);
                let id = ProviderId::parse(provider_id).unwrap();
                assert!(
                    catalog.get(&id).is_some_and(|definition| definition
                        .supports_authentication_kind(CredentialAuthKind::ApiKey)),
                    "{provider} takes no API key"
                );
            }
        }
    }

    #[test]
    fn a_claude_token_is_connected_in_both_placements_and_never_an_argument() {
        for placement in ["--local", "--cloud"] {
            let parsed = Cli::try_parse_from([
                "cw",
                "credentials",
                placement,
                "connect",
                "claude-token",
                "--name=claude",
            ])
            .unwrap();
            assert!(
                matches!(parsed.command, Command::Credentials(CredentialsArgs {
                command: CredentialsCommand::Connect(CredentialConnectArgs {
                    credential_type: Some(word), name, ..
                }), ..
            }) if word == "claude-token" && name.as_deref() == Some("claude"))
            );
            assert!(
                Cli::try_parse_from([
                    "cw",
                    "credentials",
                    placement,
                    "connect",
                    "claude-token",
                    "--name=claude",
                    "--token=sk-ant-oat01-must-not-be-argv",
                ])
                .is_err()
            );
        }
        let token =
            CredentialOperation::Credential(CredentialsCommand::Connect(CredentialConnectArgs {
                credential_type: None,
                provider: Some(CredentialConnectProviderArg::ClaudeToken),
                name: Some("claude".into()),
                yes: false,
                output: crate::commands::OutputFormat::Text,
                expires_at: None,
                key_file: None,
                account_hint: None,
                guided: false,
            }));
        let (feature, _) = authority_feature_needed(&token).expect("a token needs its feature");
        assert_eq!(
            feature,
            codewire_local_credentials::AuthorityFeature::ClaudeToken
        );
    }

    /// `add claude-subscription` is `connect claude-token` for one release
    /// (#4945): the name carries over, and what a token can't take is refused.
    #[test]
    fn the_old_add_claude_subscription_becomes_connect_claude_token() {
        let add = |expires_at| CredentialAddArgs {
            provider: Some("claude-subscription".into()),
            name: Some("claude".into()),
            account_hint: None,
            expires_at,
            key_file: None,
            yes: false,
            output: crate::commands::OutputFormat::Text,
            guided: false,
        };
        let connect = claude_token_from_alias("local", &add(None)).unwrap();
        assert!(matches!(
            connect.provider,
            Some(CredentialConnectProviderArg::ClaudeToken)
        ));
        assert_eq!(connect.name.as_deref(), Some("claude"));
        assert!(!connect.yes);
        assert!(claude_token_from_alias("local", &add(Some(4_102_444_800))).is_err());
        let gated = CredentialOperation::Credential(CredentialsCommand::Add(add(None)));
        assert_eq!(
            authority_feature_needed(&gated).map(|(feature, _)| feature),
            Some(codewire_local_credentials::AuthorityFeature::ClaudeToken)
        );
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
        assert!(connect.local && !connect.cloud);
        assert!(matches!(
            connect.command,
            Command::Credentials(CredentialsArgs {
                command: CredentialsCommand::Connect(CredentialConnectArgs {
                    credential_type: Some(word),
                    ..
                }),
                ..
            }) if word == "codex"
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
        assert!(connect_github.local && !connect_github.cloud);
        assert!(matches!(
            connect_github.command,
            Command::Credentials(CredentialsArgs {
                command: CredentialsCommand::Connect(CredentialConnectArgs {
                    credential_type: Some(word),
                    ..
                }),
                ..
            }) if word == "github"
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
        assert!(add.local && !add.cloud);
        assert!(matches!(
            add.command,
            Command::Credentials(CredentialsArgs {
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
            let Command::Credentials(args) = Cli::try_parse_from([
                "cw",
                "credentials",
                "--profile=work",
                "generate",
                "ssh",
                "--name",
                "work-ssh",
            ])
            .unwrap()
            .command
            else {
                panic!("credentials")
            };
            let CredentialOperation::GenerateIntoProfile(generate, profile) =
                resolve_credential_operation(args.profile, args.command, placement).unwrap()
            else {
                panic!("generate ssh with --profile binds that profile")
            };
            assert_eq!(
                (generate.name.as_deref().unwrap(), profile.as_str()),
                ("work-ssh", "work")
            );
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
    fn a_listing_names_a_file_store_and_omits_an_unknown_one() {
        let json = |store| {
            serde_json::to_value(output::local_views(&[credential()], store, None)).unwrap()
        };
        assert_eq!(
            json(Some(ProtectedStoreBackend::File))[0]["protected_store"],
            "file"
        );
        assert!(json(None)[0].get("protected_store").is_none());
    }

    #[test]
    fn metadata_output_has_no_material_or_internal_store_reference() {
        let view = output::CredentialView::from(&credential());
        let json = serde_json::to_string(&view).unwrap();
        assert!(json.contains("work-openai"));
        assert!(json.contains(r#""placement":"local""#));
        assert!(json.contains("operating_system"));
        assert!(!json.contains("synthetic"));
        assert!(!json.contains("entry_id"));
        assert!(!json.contains("material"));
    }

    #[test]
    fn github_pending_notice_names_the_installation_and_its_settings_page() {
        use codewire_credential_broker::GitHubAccountKind;
        assert_eq!(
            github_pending_notice("noeljackson", 12345, GitHubAccountKind::User).unwrap(),
            "GitHub is waiting for you to accept Codewire's updated permissions on noeljackson. \
             Review on GitHub: https://github.com/settings/installations/12345"
        );
        assert_eq!(
            github_pending_notice("octo-org", 678, GitHubAccountKind::Organization).unwrap(),
            "GitHub is waiting for you to accept Codewire's updated permissions on octo-org. \
             Review on GitHub: https://github.com/organizations/octo-org/settings/installations/678"
        );
        assert_eq!(
            github_pending_notice("octo-ent", 9, GitHubAccountKind::Enterprise).unwrap(),
            "GitHub is waiting for you to accept Codewire's updated permissions on octo-ent."
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

    /// The local default speaks the cloud's sentences with the placement
    /// word changed, and needs an authority that keeps one (#4717).
    #[test]
    fn the_local_default_says_what_the_cloud_says_and_needs_an_authority_that_keeps_one() {
        use codewire_local_credentials::AuthorityFeature;
        assert_eq!(
            now_default_message("work"),
            "\"work\" is now your default profile: a local `cw create` uses it when you name no profile."
        );
        assert_eq!(
            default_set_message("work"),
            "Default profile: \"work\". A local `cw create` uses it when you name no profile."
        );
        assert_eq!(
            super::super::platform_profiles::default_delete_refusal("work", "--local"),
            "\"work\" is your default profile and can't be deleted; make another profile the default first: cw credentials --local profiles default NAME"
        );
        let operation = CredentialOperation::Profile(CredentialProfileCommand::Default(
            super::super::CredentialProfileDefaultArgs {
                profile: "work".into(),
            },
        ));
        let (feature, _) = authority_feature_needed(&operation).expect("default needs a feature");
        assert_eq!(feature, AuthorityFeature::DefaultProfile);
        // The Claude sign-in authority (protocol 17) has no default.
        assert!(!feature.served_by(17));

        let mut marked = profile_with("33333333-3333-4333-8333-333333333333", "work");
        marked.is_default = true;
        let view = output::AccessProfileView::current(&marked);
        assert_eq!(serde_json::to_value(&view).unwrap()["is_default"], true);
    }
}
