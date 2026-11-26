//! Personal platform credential commands: write-only keys and managed OAuth.

use codewire_client::{self as rpc, CodewireClient};

use super::credential_input::connect::{
    ConnectStore, ConnectTarget, Interrupt, Reconnecting, claude_token_from_alias,
    claude_token_rotate_refusal, provider_id, provider_label, read_claude_token,
};
use super::credential_input::{
    AddKind, CredentialName, NameLookup, NameReading, NamedCredential, ParsedCredentialSelector,
    SSH_PUBLIC_KEY_GITHUB_HINT, add_kind, admit_name, admit_new_name, name_taken,
    parse_credential_selector, prompt_credential_material, read_ssh_import, settle_name,
    validate_ssh_generation, validate_ssh_import,
};
use super::credentials::output::save_refusal::{Answer, Kind, Save, save_error};
use super::login_screen;
use super::*;

/// Generates a cloud SSH identity and prints it with its public key.
pub(super) async fn generate_ssh(
    client: &CodewireClient,
    args: &CredentialGenerateArgs,
) -> anyhow::Result<rpc::Credential> {
    let name = validate_ssh_generation(args)?;
    admit_cloud_name(client, "ssh", &name, None).await?;
    let generated = client
        .generate_ssh_credential(rpc::GenerateSshCredentialRequest {
            name: name.clone(),
            expires_at_unix: args.expires_at,
            ..Default::default()
        })
        .await;
    let response = cloud_written(
        client,
        generated,
        "ssh",
        &name,
        None,
        "generate cloud SSH identity; inspect by name before retrying an uncertain acknowledgement",
    )
    .await?;
    let credential = response
        .credential
        .into_option()
        .context("cloud omitted SSH metadata")?;
    print(std::slice::from_ref(&credential), OutputFormat::Text)?;
    eprintln!("{SSH_PUBLIC_KEY_GITHUB_HINT}");
    Ok(credential)
}

/// The `add` provider word for a Claude subscription token: the anthropic
/// provider's OAuth kind, enrolled by paste.
const CLAUDE_SUBSCRIPTION: &str = "claude-subscription";

pub(super) async fn execute(
    client: &CodewireClient,
    command: CredentialsCommand,
) -> anyhow::Result<super::credential_input::CredentialExecution> {
    let mut execution = super::credential_input::CredentialExecution::Unchanged;
    handle_with_receipt(client, command, &mut execution).await?;
    Ok(execution)
}

fn remember_platform(
    record: &rpc::Credential,
    execution: &mut super::credential_input::CredentialExecution,
) {
    *execution = super::credential_input::CredentialExecution::Saved(
        super::credential_input::SavedCredential {
            id: record.id.clone(),
            name: record.name.clone(),
        },
    );
}

async fn handle_with_receipt(
    client: &CodewireClient,
    command: CredentialsCommand,
    execution: &mut super::credential_input::CredentialExecution,
) -> anyhow::Result<()> {
    match command {
        CredentialsCommand::Generate(args) => generate_ssh(client, &args)
            .await
            .map(|record| remember_platform(&record, execution)),
        CredentialsCommand::Connect(args) => {
            super::credential_input::connect::connect(
                &mut CloudConnectStore { client },
                args,
                execution,
            )
            .await
        }
        CredentialsCommand::List(args) => {
            let credentials = list_all(client).await?;
            print_listing(client, &credentials, args.output).await?;
            report_live_github_status(client, &credentials, args.output).await;
            Ok(())
        }
        CredentialsCommand::Get(args) => {
            let credential = resolve(
                client,
                args.credential
                    .as_deref()
                    .context("get requires a credential selector")?,
            )
            .await?;
            print_listing(client, std::slice::from_ref(&credential), args.output).await?;
            report_live_github_status(client, std::slice::from_ref(&credential), args.output).await;
            Ok(())
        }
        CredentialsCommand::Revoke(args) => revoke_credential(client, args).await,
        CredentialsCommand::Delete(args) => {
            let current = resolve(
                client,
                args.credential
                    .as_deref()
                    .context("delete requires a credential selector")?,
            )
            .await?;
            delete_credential(client, current, args.yes).await
        }
        CredentialsCommand::Add(args) => {
            if args.provider.as_deref().and_then(add_kind) == Some(AddKind::SshKey) {
                return import_ssh(client, &args, execution).await;
            }
            if args.provider.as_deref() == Some(CLAUDE_SUBSCRIPTION) {
                return super::credential_input::connect::connect(
                    &mut CloudConnectStore { client },
                    claude_token_from_alias("cloud", &args)?,
                    execution,
                )
                .await;
            }
            validate_key_arguments(&args)?;
            let word = args
                .provider
                .clone()
                .context("credential provider is required")?;
            let provider = codewire_access::credential_type(&word)
                .map_or(word.as_str(), |row| row.provider)
                .to_owned();
            let name = args
                .name
                .as_deref()
                .context("credential name is required")?
                .trim()
                .to_owned();
            // The name is checked before the key is asked for.
            admit_cloud_name(client, &provider, &name, None).await?;
            let material =
                prompt_credential_material(&provider, codewire_access::CredentialAuthKind::ApiKey)?;
            let added = client
                .add_api_key_credential(rpc::AddApiKeyCredentialRequest {
                    provider: provider.clone(),
                    name: name.clone(),
                    value: material.expose_secret().to_vec(),
                    expires_at_unix: args.expires_at,
                    ..Default::default()
                })
                .await;
            let response = cloud_written(client, added, &provider, &name, None, "add the cloud API key; inspect by name before retrying an uncertain acknowledgement").await?;
            print(
                &[response
                    .credential
                    .into_option()
                    .inspect(|record| remember_platform(record, execution))
                    .context("Codewire omitted the credential's details")?],
                OutputFormat::Text,
            )
        }
        CredentialsCommand::Rename(args) => {
            let name = trimmed_required(&args.name, "credential name")?.to_owned();
            let current = resolve(client, &args.credential).await?;
            admit_cloud_name(client, &current.provider, &name, Some(&current)).await?;
            let renamed = client
                .rename_credential(rpc::RenameCredentialRequest {
                    credential_id: current.id.clone(),
                    expected_revocation_generation: current.revocation_generation,
                    expected_name: current.name.clone(),
                    name: name.clone(),
                    ..Default::default()
                })
                .await;
            let response = cloud_written(client, renamed, &current.provider, &name, Some(&current), "rename the exact cloud credential; inspect metadata before retrying an uncertain result").await?;
            let renamed = response
                .credential
                .into_option()
                .context("Codewire omitted the renamed credential's details")?;
            let mut expected = current;
            expected.name = name;
            validate_update_ack(&expected, &renamed)?;
            print(&[renamed], OutputFormat::Text)
        }
        CredentialsCommand::Rotate(args) => {
            let current = resolve(client, &args.credential).await?;
            if is_subscription_token(&current) {
                return Err(claude_token_rotate_refusal("cloud", &current.name));
            }
            let expected = rotation_metadata(&current, args.expires_at)?;
            eprintln!("{}", rotation_notice(&current, args.expires_at));
            let material = prompt_credential_material(
                &current.provider,
                codewire_access::CredentialAuthKind::ApiKey,
            )?;
            let response = client.rotate_api_key_credential(rpc::RotateApiKeyCredentialRequest {
                credential_id: current.id,
                expected_revocation_generation: current.revocation_generation,
                value: material.expose_secret().to_vec(), expires_at_unix: args.expires_at,
                ..Default::default()
            }).await.context("replace the exact cloud API key; inspect metadata before retrying an uncertain result")?;
            let rotated = response
                .credential
                .into_option()
                .context("Codewire omitted the replaced credential's details")?;
            validate_update_ack(&expected, &rotated)?;
            print(&[rotated], OutputFormat::Text)
        }
        CredentialsCommand::Set(_)
        | CredentialsCommand::Unset(_)
        | CredentialsCommand::Revisions(_)
        | CredentialsCommand::Profiles { .. } => {
            unreachable!("profiles have a separate dispatcher")
        }
    }
}

/// `add ssh` in the cloud: the name is admitted before the key file or
/// passphrase is read.
async fn import_ssh(
    client: &CodewireClient,
    args: &CredentialAddArgs,
    execution: &mut super::credential_input::CredentialExecution,
) -> anyhow::Result<()> {
    let name = validate_ssh_import(args)?;
    // Confirm owner-scoped access and name availability before
    // reading the explicitly selected private file or passphrase.
    admit_cloud_name(client, "ssh", &name, None).await?;
    let mut input = read_ssh_import(args)?;
    let added = client
        .add_ssh_credential(rpc::AddSshCredentialRequest {
            name: name.clone(),
            private_key: std::mem::take(&mut *input.private_key),
            passphrase: input
                .passphrase
                .as_mut()
                .map(|value| std::mem::take(&mut **value)),
            expires_at_unix: args.expires_at,
            ..Default::default()
        })
        .await;
    let response = cloud_written(
        client,
        added,
        "ssh",
        &name,
        None,
        "import the cloud SSH key; inspect by name before retrying an uncertain acknowledgement",
    )
    .await?;
    print(
        &[response
            .credential
            .into_option()
            .inspect(|record| remember_platform(record, execution))
            .context("Codewire omitted the SSH key's details")?],
        OutputFormat::Text,
    )
}

/// A Claude subscription token: the anthropic provider's OAuth kind.
fn is_subscription_token(credential: &rpc::Credential) -> bool {
    credential.provider == "anthropic"
        && credential.authentication_kind == rpc::CredentialAuthenticationKind::Oauth
}

fn rotation_metadata(
    current: &rpc::Credential,
    expiry: Option<u64>,
) -> anyhow::Result<rpc::Credential> {
    if current.authentication_kind == rpc::CredentialAuthenticationKind::SshKey {
        anyhow::bail!(super::credentials::output::refusal::ROTATE_SSH);
    }
    anyhow::ensure!(
        matches!(current.provider.as_str(), "openai" | "anthropic" | "google")
            && current.authentication_kind == rpc::CredentialAuthenticationKind::ApiKey,
        super::credentials::output::refusal::ROTATE_CONNECTED
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    anyhow::ensure!(
        expiry.is_none_or(|expiry| expiry > now && expiry <= i64::MAX as u64),
        "--expires-at must be a future Unix timestamp"
    );
    anyhow::ensure!(
        current.revocation_generation > 0 && current.revocation_generation < i64::MAX as u64,
        "Codewire returned an invalid credential revision"
    );
    let mut expected = current.clone();
    expected.status = rpc::CredentialStatus::Active.into();
    expected.expires_at_unix = expiry;
    expected.revocation_generation += 1;
    Ok(expected)
}

fn rotation_notice(current: &rpc::Credential, expiry: Option<u64>) -> String {
    super::credentials::output::rotation_notice(
        "cloud",
        &current.name,
        &current.id,
        current.revocation_generation,
        expiry,
    )
}

fn validate_update_ack(expected: &rpc::Credential, actual: &rpc::Credential) -> anyhow::Result<()> {
    anyhow::ensure!(
        expected == actual,
        "Codewire returned unexpected credential details; check the credential before retrying the uncertain result"
    );
    Ok(())
}

/// Every credential of the signed-in user, across pages.
pub(super) async fn list_all(client: &CodewireClient) -> anyhow::Result<Vec<rpc::Credential>> {
    let mut credentials = Vec::new();
    let mut cursors = BTreeSet::new();
    let mut page_token = String::new();
    loop {
        let page = client
            .list_credentials(rpc::ListCredentialsRequest {
                page_size: 100,
                page_token,
                ..Default::default()
            })
            .await?;
        credentials.extend(page.credentials);
        if page.next_page_token.is_empty() {
            return Ok(credentials);
        }
        if !cursors.insert(page.next_page_token.clone()) {
            anyhow::bail!("Codewire returned a repeated credential cursor");
        }
        page_token = page.next_page_token;
    }
}

/// The credential service's side of `cw credentials connect`: it runs the
/// provider step and saves the result itself.
struct CloudConnectStore<'a> {
    client: &'a CodewireClient,
}

/// What the CLI holds between the provider step and the save. A device flow
/// holds nothing: the service completes and saves it within one request, so
/// the CLI has no point between the provider's answer and the save to stop at.
enum CloudApproval {
    Claude {
        sign_in: String,
        pasted: codewire_protected_store::ProtectedValue,
    },
    ClaudeToken(codewire_protected_store::ProtectedValue),
    Codex,
    Github,
}

/// The kind a provider's `connect` stores in the cloud.
fn cloud_connected_kind(
    provider: CredentialConnectProviderArg,
) -> rpc::CredentialAuthenticationKind {
    match provider {
        CredentialConnectProviderArg::Claude => rpc::CredentialAuthenticationKind::ClaudeSignIn,
        CredentialConnectProviderArg::Codex
        | CredentialConnectProviderArg::Github
        | CredentialConnectProviderArg::ClaudeToken => rpc::CredentialAuthenticationKind::Oauth,
    }
}

impl ConnectStore for CloudConnectStore<'_> {
    const PLACEMENT: &'static str = "cloud";
    type Record = rpc::Credential;
    type Approval = CloudApproval;

    async fn named(
        &mut self,
        provider: CredentialConnectProviderArg,
        name: &str,
    ) -> anyhow::Result<Option<rpc::Credential>> {
        // Only this provider's credentials: another provider's may share the
        // name (#4928). `PROVIDER/NAME` reconnects that provider's credential.
        let scope = provider_id(provider);
        let Some(current) = find_name(self.client, CredentialName::parse(name), Some(scope))
            .await
            .context("inspect existing platform credential before enrollment")?
        else {
            admit_new_name(name)?;
            return Ok(None);
        };
        if current.authentication_kind != cloud_connected_kind(provider) {
            // This provider's other kind holds the name: a Claude sign-in and
            // a Claude token can't share one (cw-pm on #4928).
            let held = provider_credentials(self.client, scope).await?;
            return Err(name_taken(scope, &current, &held, cloud_kind_label));
        }
        oauth_connection_request(
            scope,
            cloud_connected_kind(provider),
            &current.name,
            Some(&current),
        )?;
        Ok(Some(current))
    }

    async fn connections(
        &mut self,
        provider: CredentialConnectProviderArg,
    ) -> anyhow::Result<Vec<rpc::Credential>> {
        let kind = cloud_connected_kind(provider);
        let mut credentials = list_all(self.client)
            .await
            .context("inspect existing platform credentials before enrollment")?;
        credentials.retain(|credential| {
            credential.provider == provider_id(provider) && credential.authentication_kind == kind
        });
        Ok(credentials)
    }

    fn display_name(record: &rpc::Credential) -> &str {
        &record.name
    }

    fn describe(record: &rpc::Credential) -> anyhow::Result<Reconnecting> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        Ok(Reconnecting {
            name: record.name.clone(),
            status: super::credentials::output::CredentialView::cloud(record)?.status_at(now),
        })
    }

    async fn ready(&mut self, _: CredentialConnectProviderArg, _: &str) -> anyhow::Result<()> {
        Ok(())
    }

    async fn approve(
        &mut self,
        target: &ConnectTarget<rpc::Credential>,
        interrupt: &mut Interrupt,
    ) -> anyhow::Result<CloudApproval> {
        Ok(match target.provider {
            CredentialConnectProviderArg::Claude => {
                // The code is read before listening starts, so Ctrl-C at the
                // prompt simply exits.
                let (sign_in, pasted) = start_claude_sign_in(
                    self.client,
                    login_screen::SignInScreen::cloud(
                        provider_label(target.provider),
                        &target.name,
                    ),
                )
                .await?;
                interrupt.listen();
                CloudApproval::Claude { sign_in, pasted }
            }
            CredentialConnectProviderArg::ClaudeToken => {
                CloudApproval::ClaudeToken(read_claude_token(login_screen::SignInScreen::cloud(
                    provider_label(target.provider),
                    &target.name,
                ))?)
            }
            CredentialConnectProviderArg::Codex => CloudApproval::Codex,
            CredentialConnectProviderArg::Github => CloudApproval::Github,
        })
    }

    /// Nothing was issued here: the service runs Codex and GitHub, and
    /// revokes a sign-in it didn't store; a pasted Claude code is not yet
    /// exchanged.
    async fn discard(
        &mut self,
        _: CredentialConnectProviderArg,
        _: CloudApproval,
    ) -> Option<String> {
        None
    }
    async fn publish(
        &mut self,
        target: ConnectTarget<rpc::Credential>,
        approval: CloudApproval,
        interrupt: &mut Interrupt,
        execution: &mut super::credential_input::CredentialExecution,
    ) -> anyhow::Result<()> {
        let format = target.output;
        let screen =
            login_screen::SignInScreen::cloud(provider_label(target.provider), &target.name);
        let request = oauth_connection_request(
            provider_id(target.provider),
            cloud_connected_kind(target.provider),
            &target.name,
            target.existing.as_ref(),
        )?;
        let client = self.client;
        // `c` copies a device login's link while it waits (#4850).
        let keys: &Interrupt = interrupt;
        let enrollment = async {
            match approval {
                CloudApproval::Claude { sign_in, pasted } => client
                    .complete_claude_sign_in(rpc::CompleteClaudeSignInRequest {
                        name: request.name,
                        sign_in,
                        authorization_code: pasted.expose_secret().to_vec(),
                        credential_id: request.credential_id,
                        expected_revocation_generation: request.expected_revocation_generation,
                        ..Default::default()
                    })
                    .await
                    .and_then(|response| {
                        response.credential.into_option().ok_or_else(|| {
                            rpc::ClientError::new(
                                rpc::ErrorCode::Internal,
                                "platform omitted Claude sign-in metadata",
                            )
                        })
                    })
                    .map(|credential| (credential, Vec::new())),
                CloudApproval::ClaudeToken(token) => client
                    .add_claude_subscription_token_credential(
                        rpc::AddClaudeSubscriptionTokenCredentialRequest {
                            name: request.name,
                            token: token.expose_secret().to_vec(),
                            credential_id: request.credential_id,
                            expected_revocation_generation: request.expected_revocation_generation,
                            ..Default::default()
                        },
                    )
                    .await
                    .and_then(|response| {
                        response.credential.into_option().ok_or_else(|| {
                            rpc::ClientError::new(
                                rpc::ErrorCode::Internal,
                                "platform omitted Claude token metadata",
                            )
                        })
                    })
                    .map(|credential| (credential, Vec::new())),
                CloudApproval::Codex => client
                    .enroll_codex(
                        rpc::EnrollCodexRequest {
                            name: request.name,
                            credential_id: request.credential_id,
                            expected_revocation_generation: request.expected_revocation_generation,
                            ..Default::default()
                        },
                        |challenge| {
                            display_challenge(
                                screen,
                                &challenge.verification_url,
                                &challenge.user_code,
                                keys,
                            )
                        },
                    )
                    .await
                    .map(|credential| (credential, Vec::new())),
                CloudApproval::Github => client
                    .enroll_github(
                        rpc::EnrollGithubRequest {
                            name: request.name,
                            credential_id: request.credential_id,
                            expected_revocation_generation: request.expected_revocation_generation,
                            ..Default::default()
                        },
                        |challenge| {
                            display_challenge(
                                screen,
                                &challenge.verification_url,
                                &challenge.user_code,
                                keys,
                            )
                        },
                    )
                    .await
                    .map(|enrolled| (enrolled.credential, enrolled.pending_permissions)),
            }
        };
        let enrolled = tokio::select! {
            result = enrollment => result.map_err(Some),
            () = keys.pressed() => Err(None),
        };
        // The terminal is back before the result prints, or the service's
        // refusal is looked into.
        keys.stop_keys();
        let (credential, pending) = match enrolled {
            Ok(enrolled) => enrolled,
            Err(Some(error)) => return Err(refused_connect(client, &target, error).await),
            Err(None) => anyhow::bail!(
                "enrollment cancelled; inspect the credential by name before retrying because storage acknowledgement may be unknown"
            ),
        };
        let (who, expires) = match target.provider {
            CredentialConnectProviderArg::ClaudeToken => {
                (credential.name.as_str(), credential.expires_at_unix)
            }
            _ => (
                login_screen::signed_in_account(
                    credential.account_hint.as_deref(),
                    &credential.name,
                ),
                None,
            ),
        };
        match format {
            OutputFormat::Json => super::credentials::output::print_cloud_credentials(
                std::slice::from_ref(&credential),
                None,
                format,
            )?,
            OutputFormat::Text => {
                eprintln!();
                super::credentials::output::print_done(&login_screen::connected_result(
                    screen, who, expires,
                ));
            }
        }
        remember_platform(&credential, execution);
        super::credentials::report_github_pending(github_pending(&pending));
        Ok(())
    }
}

/// The ErrorInfo reason of a name the service would not choose a credential
/// for; its `providers` metadata lists theirs, comma-joined (#4928).
const CREDENTIAL_NAME_AMBIGUOUS: &str = "CREDENTIAL_NAME_AMBIGUOUS";

/// What the service holds of one reading of a name: the credential, none, or
/// the providers of the several it would not choose between. The service
/// answers only for credentials the caller may read.
async fn lookup_name(
    client: &CodewireClient,
    reading: NameReading<'_>,
) -> anyhow::Result<NameLookup<rpc::Credential>> {
    match client
        .get_credential(rpc::GetCredentialRequest {
            selector: Some(rpc::get_credential_request::Selector::Name(
                reading.name.to_owned(),
            )),
            provider: reading.provider.map(str::to_owned),
            ..Default::default()
        })
        .await
    {
        Ok(response) => Ok(NameLookup::Matches(vec![
            response
                .credential
                .into_option()
                .context("Codewire omitted the credential's details")?,
        ])),
        Err(error) if error.code() == rpc::ErrorCode::NotFound => {
            Ok(NameLookup::Matches(Vec::new()))
        }
        Err(error) => match ambiguous_providers(&error) {
            Some(providers) => Ok(NameLookup::Ambiguous(providers)),
            None => Err(error.into()),
        },
    }
}

/// The providers of the service's ambiguous-name refusal; none for any other
/// error, or one that lists no provider.
fn ambiguous_providers(error: &rpc::ClientError) -> Option<Vec<String>> {
    if error.code() != rpc::ErrorCode::FailedPrecondition
        || service_reason(error) != Some(CREDENTIAL_NAME_AMBIGUOUS)
    {
        return None;
    }
    let providers = error
        .error_info()?
        .metadata()
        .get("providers")?
        .split(',')
        .filter(|provider| !provider.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    (!providers.is_empty()).then_some(providers)
}

/// A refusal's closed reason from the credential service.
fn service_reason(error: &rpc::ClientError) -> Option<&str> {
    error
        .error_info()
        .filter(|info| info.domain() == "codewire.sh")
        .map(rpc::ErrorInfo::reason)
        .filter(|reason| !reason.is_empty())
}

/// The credential `name` names in its readings, as the local store resolves
/// it (#4928): one reading's credential, none, or a refusal naming each when
/// they find more than one. Within `scope` only that provider's credentials
/// are asked for.
async fn find_name(
    client: &CodewireClient,
    name: CredentialName<'_>,
    scope: Option<&str>,
) -> anyhow::Result<Option<rpc::Credential>> {
    let mut lookups = Vec::new();
    for reading in name.readings(scope) {
        lookups.push((reading, lookup_name(client, reading).await?));
    }
    settle_name(name.text, lookups)
}

/// Every credential of `provider` the caller may read.
async fn provider_credentials(
    client: &CodewireClient,
    provider: &str,
) -> anyhow::Result<Vec<rpc::Credential>> {
    let mut credentials = list_all(client)
        .await
        .context("list cloud credentials to suggest a free name")?;
    credentials.retain(|credential| credential.provider == provider);
    Ok(credentials)
}

/// Refuses `name` for a new credential of `provider`, or for `renaming`,
/// before anything is asked for or saved, as locally (#4928): a name that
/// starts with a provider id and `/`, or one this provider's credential the
/// caller may read holds, named with a free name. Any other holder is the
/// service's to refuse ([`cloud_written`]).
async fn admit_cloud_name(
    client: &CodewireClient,
    provider: &str,
    name: &str,
    renaming: Option<&rpc::Credential>,
) -> anyhow::Result<()> {
    if renaming.is_none_or(|renamed| renamed.name != name) {
        admit_new_name(name)?;
    }
    let reading = NameReading {
        name,
        provider: Some(provider),
    };
    let NameLookup::Matches(holders) = lookup_name(client, reading)
        .await
        .context("check the cloud credential name")?
    else {
        return Ok(());
    };
    if holders
        .iter()
        .all(|holder| renaming.is_some_and(|renamed| renamed.id == holder.id))
    {
        return Ok(());
    }
    let held = provider_credentials(client, provider).await?;
    admit_name(provider, name, &held, renaming, cloud_kind_label)
}

/// What a cloud write says when the service refuses its name (#4928): a
/// name that starts with a provider id and `/`, or one taken in `provider`
/// when this command could not look up who holds it, named by provider only
/// (cw-security on #4928). Any other error keeps its context.
fn cloud_name_error(
    error: rpc::ClientError,
    provider: &str,
    name: &str,
    context: &'static str,
) -> anyhow::Error {
    let reason = service_reason(&error);
    if reason
        == Some(codewire_local_credentials::StoreRefusal::CredentialNameReservesProvider.reason())
    {
        return anyhow::anyhow!(super::credentials::output::refusal::reserved_name(name));
    }
    if error.code() == rpc::ErrorCode::AlreadyExists && reason.is_none() {
        return anyhow::anyhow!(super::credentials::output::refusal::name_in_use(provider));
    }
    anyhow::Error::new(error).context(context)
}

/// A cloud write's result, with a refused name worded by
/// [`cloud_name_error`], or, when the service says the name is taken, by
/// who holds it ([`taken_name_holder`]).
async fn cloud_written<T>(
    client: &CodewireClient,
    result: Result<T, rpc::ClientError>,
    provider: &str,
    name: &str,
    renaming: Option<&rpc::Credential>,
    context: &'static str,
) -> anyhow::Result<T> {
    let error = match result {
        Ok(value) => return Ok(value),
        Err(error) => error,
    };
    if is_name_taken(&error) {
        match taken_name_holder(client, provider, name, renaming).await {
            TakenBy::Holder(refusal) => return Err(refusal),
            TakenBy::Unknown => {}
        }
    }
    Err(cloud_name_error(error, provider, name, context))
}

/// The service refused a name as taken, with no other reason.
fn is_name_taken(error: &rpc::ClientError) -> bool {
    error.code() == rpc::ErrorCode::AlreadyExists && service_reason(error).is_none()
}

/// Who holds a name the service refused as taken.
enum TakenBy {
    /// A credential of the requested provider the caller may read, named.
    Holder(anyhow::Error),
    /// No holder the caller may read, or the lookup failed: the refusal
    /// keeps the provider-only words.
    Unknown,
}

/// The cloud's name indexes are per provider (migration 0043, #4928), so a
/// name the service refuses as taken is held in `provider`. A holder the
/// caller may read is named with a free name, as before the write; one it
/// may not read, such as an organization's credential, is never described,
/// so the refusal names only the provider (cw-security on #4928).
/// `renaming` keeps its own name and is no holder.
async fn taken_name_holder(
    client: &CodewireClient,
    provider: &str,
    name: &str,
    renaming: Option<&rpc::Credential>,
) -> TakenBy {
    let reading = NameReading {
        name,
        provider: Some(provider),
    };
    let Ok(NameLookup::Matches(holders)) = lookup_name(client, reading).await else {
        return TakenBy::Unknown;
    };
    let Some(holder) = holders
        .into_iter()
        .find(|holder| renaming.is_none_or(|renamed| renamed.id != holder.id))
    else {
        return TakenBy::Unknown;
    };
    let held = provider_credentials(client, provider)
        .await
        .unwrap_or_else(|_| vec![holder.clone()]);
    TakenBy::Holder(name_taken(provider, &holder, &held, cloud_kind_label))
}

impl NamedCredential for rpc::Credential {
    fn credential_id(&self) -> &str {
        &self.id
    }

    fn provider_id(&self) -> &str {
        &self.provider
    }

    fn credential_name(&self) -> &str {
        &self.name
    }
}

/// A cloud credential's kind, as messages name it.
fn cloud_kind_label(credential: &rpc::Credential) -> String {
    super::credentials::output::CredentialView::cloud(credential)
        .map_or_else(|_| credential.provider.clone(), |view| view.kind_label())
}

/// A device flow's challenge (Codex, GitHub): the link screen, then the code
/// to enter on the provider's page, with `c` copying the link and the
/// waiting line while it waits.
fn display_challenge(
    screen: login_screen::SignInScreen<'_>,
    url: &str,
    code: &str,
    keys: &Interrupt,
) -> bool {
    login_screen::open_sign_in_link(screen, url);
    let style =
        crate::output::Capabilities::from_process(crate::output::OutputMode::Text).stderr_style();
    eprint!("{}", login_screen::device_code_lines(code, style));
    keys.watch_keys(url);
    true
}

/// Start a Claude sign-in, show where to sign in, and read the code Claude
/// shows from a no-echo prompt or stdin, never argv, as `code#state` (see
/// [`login_screen::claude_sign_in_code`]). The returned handle stays in this
/// process.
async fn start_claude_sign_in(
    client: &CodewireClient,
    screen: login_screen::SignInScreen<'_>,
) -> anyhow::Result<(String, codewire_protected_store::ProtectedValue)> {
    let started = client
        .start_claude_sign_in(rpc::StartClaudeSignInRequest::default())
        .await
        .context("start the Claude sign-in")?;
    anyhow::ensure!(
        started
            .authorize_url
            .starts_with("https://claude.com/cai/oauth/authorize?")
            && !started.sign_in.is_empty(),
        "platform returned an invalid Claude sign-in"
    );
    let pasted = login_screen::claude_sign_in_code(screen, &started.authorize_url)?;
    Ok((started.sign_in, pasted))
}

struct OAuthConnectionRequest {
    name: String,
    credential_id: Option<String>,
    expected_revocation_generation: Option<u64>,
}

fn oauth_connection_request(
    provider: &str,
    kind: rpc::CredentialAuthenticationKind,
    name: &str,
    existing: Option<&rpc::Credential>,
) -> anyhow::Result<OAuthConnectionRequest> {
    let mut request = OAuthConnectionRequest {
        name: name.to_owned(),
        credential_id: None,
        expected_revocation_generation: None,
    };
    if let Some(existing) = existing {
        anyhow::ensure!(
            existing.provider == provider
                && existing.authentication_kind == kind
                && existing.name.eq_ignore_ascii_case(name)
                && !existing.id.is_empty()
                && existing.revocation_generation > 0,
            "platform credential belongs to a different provider or authentication kind, or its metadata is invalid; inspect it before reconnecting"
        );
        request.name = existing.name.clone();
        request.credential_id = Some(existing.id.clone());
        request.expected_revocation_generation = Some(existing.revocation_generation);
    }
    Ok(request)
}

fn validate_key_arguments(args: &CredentialAddArgs) -> anyhow::Result<()> {
    anyhow::ensure!(
        args.key_file.is_none(),
        "--key-file is only valid for add ssh"
    );
    anyhow::ensure!(
        args.provider.as_deref().and_then(add_kind) == Some(AddKind::ApiKey),
        super::credentials::output::refusal::add_unsupported(
            args.provider.as_deref().unwrap_or("that provider")
        )
    );
    trimmed_required(
        args.name
            .as_deref()
            .context("credential name is required")?,
        "credential name",
    )?;
    anyhow::ensure!(
        args.account_hint.is_none(),
        super::credentials::output::refusal::ACCOUNT_HINT
    );
    Ok(())
}

pub(super) async fn resolve(
    client: &CodewireClient,
    selector: &str,
) -> anyhow::Result<rpc::Credential> {
    resolve_in(client, selector, None).await
}

/// The credential `selector` names. A name is looked up in each of its
/// readings, with the provider the service narrows it to (#4928). Within
/// `scope`, the provider a profile slot fixes, a bare name needs no
/// `PROVIDER/`; one only another provider's credential has is still found,
/// for the slot to refuse in its own words.
pub(super) async fn resolve_in(
    client: &CodewireClient,
    selector: &str,
    scope: Option<&str>,
) -> anyhow::Result<rpc::Credential> {
    let name = match parse_credential_selector(selector)? {
        ParsedCredentialSelector::Id(id) => {
            return client
                .get_credential(rpc::GetCredentialRequest {
                    selector: Some(rpc::get_credential_request::Selector::CredentialId(
                        id.to_string(),
                    )),
                    ..Default::default()
                })
                .await?
                .credential
                .into_option()
                .context("Codewire omitted the credential's details");
        }
        ParsedCredentialSelector::Name(name) => name,
    };
    let found = match find_name(client, name, scope).await? {
        None if scope.is_some() => find_name(client, name, None).await?,
        found => found,
    };
    found.ok_or_else(|| {
        anyhow::anyhow!(super::credentials::output::refusal::not_found(
            "cloud", name.text
        ))
    })
}

/// The service's pending entries as the notice takes them; an unknown kind
/// is dropped.
fn github_pending(
    pending: &[rpc::GithubAppPendingPermissions],
) -> impl Iterator<Item = (&str, u64, codewire_credential_broker::GitHubAccountKind)> {
    pending.iter().filter_map(|pending| {
        let kind = match pending.account_kind.as_known()? {
            rpc::GithubAppAccountKind::Organization => {
                codewire_credential_broker::GitHubAccountKind::Organization
            }
            rpc::GithubAppAccountKind::Enterprise => {
                codewire_credential_broker::GitHubAccountKind::Enterprise
            }
            rpc::GithubAppAccountKind::User => codewire_credential_broker::GitHubAccountKind::User,
            _ => return None,
        };
        Some((pending.account.as_str(), pending.installation_id, kind))
    })
}

/// While the listing includes the person's active GitHub connection, name
/// any installation still short of what Codewire needs, checked live by the
/// platform with that connection (#2712). Advisory and text-only: an error,
/// or no answer within two seconds, prints nothing.
async fn report_live_github_status(
    client: &CodewireClient,
    credentials: &[rpc::Credential],
    output: OutputFormat,
) {
    let connected = credentials.iter().any(|credential| {
        credential.provider == "github"
            && credential.authentication_kind == rpc::CredentialAuthenticationKind::Oauth
            && credential.status == rpc::CredentialStatus::Active
    });
    if output != OutputFormat::Text || !connected {
        return;
    }
    let Ok(Ok(response)) = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.list_github_pending_permissions(),
    )
    .await
    else {
        return;
    };
    for notice in
        super::credentials::github_pending_notices(github_pending(&response.pending_permissions))
    {
        eprintln!("{notice}");
    }
}

fn print(credentials: &[rpc::Credential], output: OutputFormat) -> anyhow::Result<()> {
    validate_ssh_metadata(credentials)?;
    super::credentials::output::print_cloud_credentials(credentials, None, output)
}

/// An SSH credential's metadata is consistent and carries a valid public key.
fn validate_ssh_metadata(credentials: &[rpc::Credential]) -> anyhow::Result<()> {
    for credential in credentials {
        if credential.provider == "ssh"
            || credential.authentication_kind == rpc::CredentialAuthenticationKind::SshKey
            || credential.ssh_public_key.is_set()
        {
            anyhow::ensure!(
                credential.provider == "ssh"
                    && credential.authentication_kind == rpc::CredentialAuthenticationKind::SshKey
                    && credential.account_hint.is_none(),
                "Codewire returned inconsistent SSH key details"
            );
            let key = credential
                .ssh_public_key
                .as_option()
                .context("Codewire omitted the SSH public key")?;
            codewire_access::SshPublicKeyMetadata {
                openssh: key.openssh.clone(),
                fingerprint: key.fingerprint.clone(),
            }
            .validate()?;
        }
    }
    Ok(())
}

/// A listing of cloud credentials, with the profiles that use them.
async fn print_listing(
    client: &CodewireClient,
    credentials: &[rpc::Credential],
    output: OutputFormat,
) -> anyhow::Result<()> {
    validate_ssh_metadata(credentials)?;
    let profiles = super::platform_profiles::list_profiles(client).await?;
    super::credentials::output::print_cloud_credentials(
        credentials,
        Some(&super::credentials::output::cloud_uses(&profiles)),
        output,
    )
}

/// `cw credentials --cloud delete` (#4717 C6, #6211), as the local delete: a
/// credential a profile selects, or a Sandbox made with an earlier revision
/// still uses, is refused before the question, naming what frees it. An
/// active one is then revoked and deleted in one step on the service, which
/// refuses it unchanged if anything still uses it, and asks its provider
/// too; then the provider's answer is said.
async fn delete_credential(
    client: &CodewireClient,
    current: rpc::Credential,
    yes: bool,
) -> anyhow::Result<()> {
    use super::credentials::confirm;
    use super::credentials::output::{self, refusal};
    let profiles = super::platform_profiles::list_profiles(client)
        .await
        .context("list cloud profiles before deleting a credential")?;
    let selected = profiles.iter().find_map(|profile| {
        profile
            .entries
            .iter()
            .find(|entry| entry.credential_id == current.id)
            .map(|entry| (profile.name.as_str(), entry.capability_slot.as_str()))
    });
    if let Some((profile, slot)) = selected {
        anyhow::bail!(refusal::in_use("cloud", &current.name, profile, slot));
    }
    let sandboxes = held_by_sandboxes(client, &current.id, &profiles).await?;
    if !sandboxes.is_empty() {
        anyhow::bail!(refusal::held_by_vms("cloud", &current.name, &sandboxes));
    }
    let active = current.status != rpc::CredentialStatus::Revoked;
    let change = confirm::Change::Delete { active };
    if !confirm::confirm("cloud", &current.name, change, yes, OutputFormat::Text)? {
        return Ok(());
    }
    let deleted = client
        .delete_credential(rpc::DeleteCredentialRequest {
            credential_id: current.id.clone(),
            expected_revocation_generation: current.revocation_generation,
            revoke_first: active,
            ..Default::default()
        })
        .await;
    let answer = match deleted {
        Ok(response) => provider_answer(response.provider_revocation.as_option()),
        Err(error) if service_reason(&error) == Some(CREDENTIAL_IN_USE) => {
            anyhow::bail!(refusal::still_in_use("cloud", &current.name))
        }
        // A service from before the one-step delete: revoke, then delete,
        // after the same check.
        Err(error) if active && refuses_active_delete(&error) => {
            revoke_then_delete(client, &current).await?
        }
        Err(error) => {
            return Err(anyhow::Error::from(error).context(
                "delete exact cloud credential revision; inspect metadata before retrying an uncertain result",
            ));
        }
    };
    output::print_done(&output::deleted("cloud", &current.name));
    // It is deleted: a kind this cw cannot name only drops the line after.
    if let Some(line) = output::CredentialView::cloud(&current)
        .ok()
        .and_then(|view| output::after_deleted(view.provider(), view.authentication_kind(), answer))
    {
        eprintln!("{line}");
    }
    Ok(())
}

/// The service's in-use refusal (#6211); nothing changed.
const CREDENTIAL_IN_USE: &str = "CREDENTIAL_IN_USE";

/// A service that predates `revoke_first` refuses an active credential's
/// delete, with no reason, and changes nothing.
fn refuses_active_delete(error: &rpc::ClientError) -> bool {
    error.code() == rpc::ErrorCode::FailedPrecondition
        && service_reason(error).is_none()
        && error.message() == "credential must be revoked before deletion"
}

/// The two steps a service that predates `revoke_first` needs: the revoke
/// asks the provider, and a delete that then fails says to run it again.
async fn revoke_then_delete(
    client: &CodewireClient,
    current: &rpc::Credential,
) -> anyhow::Result<super::credentials::output::ProviderAnswer> {
    use super::credentials::output::refusal;
    // Codewire's own revoke failing stops here: nothing is deleted.
    let revoked = client.revoke_credential(rpc::RevokeCredentialRequest {
        credential_id: current.id.clone(),
        expected_revocation_generation: current.revocation_generation,
        ..Default::default()
    }).await.context("revoke exact cloud credential revision; inspect metadata before retrying an uncertain result")?;
    let revision = revoked
        .credential
        .as_option()
        .context("the cloud omitted revoked metadata")?
        .revocation_generation;
    client
        .delete_credential(rpc::DeleteCredentialRequest {
            credential_id: current.id.clone(),
            expected_revocation_generation: revision,
            ..Default::default()
        })
        .await
        .context(refusal::revoked_not_deleted(
            "cloud",
            &current.provider,
            &current.name,
        ))?;
    Ok(provider_answer(revoked.provider_revocation.as_option()))
}

/// The Sandboxes, by name with their profile's, still bound to an earlier
/// revision of one of `profiles` that selected the credential: an `unset`
/// doesn't free them (#6211). Each organization's environments are listed
/// once, and a profile's revisions only when a Sandbox is on an earlier one.
async fn held_by_sandboxes(
    client: &CodewireClient,
    credential_id: &str,
    profiles: &[rpc::AccessProfile],
) -> anyhow::Result<Vec<(String, String)>> {
    let organizations = client
        .list_organizations(rpc::ListOrganizationsRequest::default())
        .await
        .context("list organizations before deleting a credential")?
        .organizations;
    let mut earlier = Vec::new();
    for organization in organizations
        .into_iter()
        .filter_map(|membership| membership.organization.into_option())
    {
        let environments = client
            .list_environments(rpc::ListEnvironmentsRequest {
                org_id: organization.id,
                ..Default::default()
            })
            .await
            .context("list Sandboxes before deleting a credential")?
            .environments;
        for environment in environments {
            let Some(selection) = environment.source_selection.as_option() else {
                continue;
            };
            let (Some(binding), Some(revision)) = (
                selection.credentials.as_option(),
                selection.profile_revision,
            ) else {
                continue;
            };
            let Some(profile) = profiles.iter().find(|profile| {
                binding.profile.strip_prefix("platform:id:") == Some(profile.id.as_str())
            }) else {
                continue;
            };
            if revision != profile.revision {
                earlier.push((environment.name, profile, revision));
            }
        }
    }
    let mut revisions = BTreeMap::new();
    let mut holders = Vec::new();
    for (environment, profile, revision) in earlier {
        if !revisions.contains_key(&profile.id) {
            let listed = super::platform_profiles::list_revisions(client, &profile.id).await?;
            revisions.insert(profile.id.clone(), listed);
        }
        let selects = revisions[&profile.id]
            .iter()
            .filter_map(|listed| listed.access_profile.as_option())
            .any(|listed| {
                listed.revision == revision
                    && listed
                        .entries
                        .iter()
                        .any(|entry| entry.credential_id == credential_id)
            });
        if selects {
            holders.push((environment, profile.name.clone()));
        }
    }
    Ok(holders)
}

/// `cw credentials --cloud revoke` (#4717 C6): asked once, then revoked at
/// the observed revision, which asks its provider too; then what it did is
/// said, in the sentences the delete uses.
async fn revoke_credential(
    client: &CodewireClient,
    args: super::credentials::confirm::CredentialRevokeArgs,
) -> anyhow::Result<()> {
    use super::credentials::confirm;
    use super::credentials::output;
    let current = resolve(client, &args.credential).await?;
    if !confirm::confirm(
        "cloud",
        &current.name,
        confirm::Change::Revoke,
        args.yes,
        args.output,
    )? {
        return Ok(());
    }
    let response = client.revoke_credential(rpc::RevokeCredentialRequest {
        credential_id: current.id.clone(),
        expected_revocation_generation: current.revocation_generation,
        ..Default::default()
    }).await.context("revoke exact cloud credential revision; inspect metadata before retrying an uncertain result")?;
    let answer = provider_answer(response.provider_revocation.as_option());
    let revoked = response
        .credential
        .into_option()
        .context("the cloud omitted revoked metadata")?;
    if matches!(args.output, OutputFormat::Json) {
        return print(&[revoked], args.output);
    }
    output::print_done(&output::revoked("cloud", &revoked.name));
    // It is revoked: a kind this cw cannot name only drops the line after.
    if let Some(line) = output::CredentialView::cloud(&revoked)
        .ok()
        .and_then(|view| output::at_provider(view.provider(), view.authentication_kind(), answer))
    {
        eprintln!("{line}");
    }
    Ok(())
}

/// What the platform reported the provider said; unset means not asked.
fn provider_answer(
    reported: Option<&rpc::ProviderRevocation>,
) -> super::credentials::output::ProviderAnswer {
    use super::credentials::output::{NotConfirmedBecause as Because, ProviderAnswer};
    let Some(reported) = reported else {
        return ProviderAnswer::NotAsked;
    };
    if reported.outcome == rpc::ProviderRevocationOutcome::Confirmed {
        return ProviderAnswer::Confirmed;
    }
    // NOT_READ: Codewire couldn't use its stored token, so the provider
    // wasn't asked, and the person reads what it still holds (#4908).
    if reported.outcome != rpc::ProviderRevocationOutcome::Failed
        || reported.failure == rpc::ProviderRevocationFailure::NotRead
    {
        return ProviderAnswer::NotAsked;
    }
    ProviderAnswer::NotConfirmed(
        if reported.failure == rpc::ProviderRevocationFailure::Refused {
            Because::Refused(u16::try_from(reported.http_status).unwrap_or(0))
        } else if reported.failure == rpc::ProviderRevocationFailure::Unreadable {
            Because::Unreadable
        } else if reported.failure == rpc::ProviderRevocationFailure::Expired {
            Because::Expired
        } else {
            Because::Unreachable
        },
    )
}

/// What a cloud connect says when the service refuses `target`
/// ([`cloud_connect_error`]).
async fn refused_connect(
    client: &CodewireClient,
    target: &ConnectTarget<rpc::Credential>,
    error: rpc::ClientError,
) -> anyhow::Error {
    let save = Save {
        placement: "cloud",
        kind: Kind::Connect(target.provider),
        name: &target.name,
    };
    cloud_connect_error(client, save, target.existing.as_ref(), error).await
}

/// What a cloud connect says when the service doesn't save it: a name it
/// refuses as taken is checked against the provider's own holder first
/// ([`taken_name_holder`]); anything else is [`cloud_save_error`]'s.
async fn cloud_connect_error(
    client: &CodewireClient,
    save: Save<'_>,
    existing: Option<&rpc::Credential>,
    error: rpc::ClientError,
) -> anyhow::Error {
    if let (true, Kind::Connect(provider)) = (is_name_taken(&error), save.kind) {
        match taken_name_holder(client, provider_id(provider), save.name, existing).await {
            TakenBy::Holder(refusal) => return refusal,
            TakenBy::Unknown => {}
        }
    }
    cloud_save_error(save, error)
}

/// What a cloud connect says when the service doesn't save a Claude sign-in
/// or token: the words a local connect uses for the same cause (#4826), told
/// by the code and the service's closed reason, never its message. Codex and
/// GitHub keep the fixed words the client gives their enrollment streams.
fn cloud_save_error(save: Save<'_>, error: rpc::ClientError) -> anyhow::Error {
    use rpc::ErrorCode;
    // A refused name says so for every connect (#4928): one taken in the
    // provider, by provider only, or one that starts with a provider id.
    let reason = service_reason(&error);
    let name_refused = (error.code() == ErrorCode::AlreadyExists && reason.is_none())
        || reason
            == Some(
                codewire_local_credentials::StoreRefusal::CredentialNameReservesProvider.reason(),
            );
    if !name_refused
        && !matches!(
            save.kind,
            Kind::Connect(
                CredentialConnectProviderArg::Claude | CredentialConnectProviderArg::ClaudeToken
            )
        )
    {
        return anyhow::Error::new(error).context("save the sign-in in your Codewire account");
    }
    tracing::debug!(
        code = ?error.code(),
        message = error.message(),
        "the credential service did not save a connect"
    );
    let answer = match error.code() {
        ErrorCode::AlreadyExists => Answer::AlreadyExists,
        ErrorCode::NotFound => Answer::NotFound,
        ErrorCode::Unavailable
        | ErrorCode::DeadlineExceeded
        | ErrorCode::Canceled
        | ErrorCode::Unknown
        | ErrorCode::Internal
        | ErrorCode::Aborted
        | ErrorCode::DataLoss => Answer::Uncertain,
        _ => Answer::Refused,
    };
    save_error(save, answer, reason, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use buffa::Message as _;
    use wiremock::matchers::{body_bytes, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const ID: &str = "fdd5612f-12ca-4a21-9557-dc4875f9c1f6";
    const REVISION: u64 = 9_007_199_254_740_993;

    #[tokio::test]
    async fn platform_rename_binds_exact_name_and_revision_and_checks_acknowledgement() {
        let server = MockServer::start().await;
        let client = client(&server);
        for invalid_ack in [false, true] {
            expect_metadata(
                &server,
                rpc::get_credential_request::Selector::Name("work".into()),
                rpc::CredentialStatus::Active,
            )
            .await;
            lookup(&server, "renamed", Some("openai"), Lookup::NotFound).await;
            let mut expected = metadata(rpc::CredentialStatus::Active);
            expected.name = "renamed".into();
            if invalid_ack {
                expected.revocation_generation += 1;
            }
            unary(
                &server,
                "CredentialMutationService",
                "RenameCredential",
                rpc::RenameCredentialRequest {
                    credential_id: ID.into(),
                    expected_revocation_generation: REVISION,
                    expected_name: "work".into(),
                    name: "renamed".into(),
                    ..Default::default()
                },
                rpc::RenameCredentialResponse {
                    credential: Some(expected).into(),
                    ..Default::default()
                },
            )
            .await;
            let result = execute(
                &client,
                CredentialsCommand::Rename(CredentialRenameArgs {
                    credential: "work".into(),
                    name: "renamed".into(),
                }),
            )
            .await;
            assert_eq!(result.is_err(), invalid_ack);
            server.verify().await;
            server.reset().await;
        }
    }

    #[test]
    fn platform_rotation_discloses_reactivation_and_expiry_and_rejects_wrong_kind_before_input() {
        let mut current = metadata(rpc::CredentialStatus::Revoked);
        assert!(rotation_metadata(&current, None).is_err());
        current.authentication_kind = rpc::CredentialAuthenticationKind::ApiKey.into();
        current.expires_at_unix = Some(4_000_000_000);
        let expected = rotation_metadata(&current, None).unwrap();
        assert_eq!(expected.status, rpc::CredentialStatus::Active);
        assert_eq!(expected.expires_at_unix, None);
        assert_eq!(expected.revocation_generation, REVISION + 1);
        for expiry in [0, 1, u64::MAX] {
            assert!(rotation_metadata(&current, Some(expiry)).is_err());
        }
        assert!(rotation_notice(&current, None).contains("including if revoked"));
        assert!(rotation_notice(&current, None).contains("clears the expiry date"));
        assert!(rotation_notice(&current, Some(4_000_000_000)).contains("2096-10-02 07:06 UTC"));
        let mut wrong = expected.clone();
        wrong.id = "different-identity".into();
        assert!(validate_update_ack(&expected, &wrong).is_err());
        current.provider = "github".into();
        assert!(rotation_metadata(&current, None).is_err());
    }

    #[test]
    fn an_api_key_add_never_accepts_the_claude_token_word() {
        let args = CredentialAddArgs {
            provider: Some(CLAUDE_SUBSCRIPTION.into()),
            name: Some("claude".into()),
            account_hint: None,
            expires_at: None,
            key_file: None,
            yes: false,
            output: crate::commands::OutputFormat::Text,
            guided: false,
        };
        assert!(validate_key_arguments(&args).is_err());
    }

    /// `add` in the cloud takes exactly the providers its picker offers
    /// (#5446). An SSH key is taken only through `add_kind`, which reads the
    /// list the picker is built from; an API key goes through
    /// `validate_key_arguments` too, which could take a provider the picker
    /// lacks.
    #[test]
    fn the_add_picker_offers_every_provider_cloud_add_takes() {
        use crate::commands::credential_input::{PROVIDER_WORDS_FOR_TESTS, add_providers};
        for provider in PROVIDER_WORDS_FOR_TESTS {
            let offered = add_providers()
                .into_iter()
                .find(|(word, ..)| *word == provider)
                .map(|(_, kind, _)| kind);
            let args = CredentialAddArgs {
                provider: Some(provider.into()),
                name: Some("work".into()),
                account_hint: None,
                expires_at: None,
                key_file: None,
                yes: false,
                output: crate::commands::OutputFormat::Text,
                guided: false,
            };
            assert_eq!(
                validate_key_arguments(&args).is_ok(),
                offered == Some(AddKind::ApiKey),
                "--cloud add {provider}"
            );
        }
    }

    #[test]
    fn a_claude_token_is_not_an_api_key_rotation() {
        let mut current = metadata(rpc::CredentialStatus::RefreshFailed);
        current.provider = "anthropic".into();
        current.authentication_kind = rpc::CredentialAuthenticationKind::Oauth.into();
        assert!(is_subscription_token(&current));
        assert!(rotation_metadata(&current, None).is_err());
        let mut api_key = current.clone();
        api_key.authentication_kind = rpc::CredentialAuthenticationKind::ApiKey.into();
        assert!(!is_subscription_token(&api_key));
        let mut codex = current;
        codex.provider = "openai".into();
        assert!(!is_subscription_token(&codex));
    }

    #[tokio::test]
    async fn platform_rotation_client_sends_exact_revision_without_retry_or_readback() {
        let server = MockServer::start().await;
        let client = client(&server);
        let mut current = metadata(rpc::CredentialStatus::Revoked);
        current.authentication_kind = rpc::CredentialAuthenticationKind::ApiKey.into();
        let expected = rotation_metadata(&current, None).unwrap();
        let request = rpc::RotateApiKeyCredentialRequest {
            credential_id: ID.into(),
            expected_revocation_generation: REVISION,
            value: b"synthetic-write-only-replacement".to_vec(),
            ..Default::default()
        };
        unary(
            &server,
            "CredentialMutationService",
            "RotateApiKeyCredential",
            request.clone(),
            rpc::RotateApiKeyCredentialResponse {
                credential: Some(expected.clone()).into(),
                ..Default::default()
            },
        )
        .await;
        let response = client.rotate_api_key_credential(request).await.unwrap();
        validate_update_ack(&expected, &response.credential.into_option().unwrap()).unwrap();
        server.verify().await;
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    /// The cloud's service runs the provider step and the save together, so
    /// a cloud connect asks nothing of the store first.
    #[tokio::test]
    async fn a_cloud_connect_asks_nothing_before_the_provider_step() {
        let server = MockServer::start().await;
        let client = client(&server);
        for provider in [
            CredentialConnectProviderArg::Claude,
            CredentialConnectProviderArg::Codex,
            CredentialConnectProviderArg::Github,
        ] {
            CloudConnectStore { client: &client }
                .ready(provider, "work")
                .await
                .unwrap();
        }
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    fn client(server: &MockServer) -> CodewireClient {
        CodewireClient::with_http(
            rpc::ClientConfig::new(server.uri()).unwrap(),
            rpc::StaticTokenProvider::new("synthetic-credential-cli-oauth").unwrap(),
            reqwest::Client::new(),
        )
        .unwrap()
    }

    fn metadata(status: rpc::CredentialStatus) -> rpc::Credential {
        rpc::Credential {
            id: ID.into(),
            name: "work".into(),
            provider: "openai".into(),
            status: status.into(),
            revocation_generation: REVISION,
            ..Default::default()
        }
    }

    async fn unary(
        server: &MockServer,
        service: &str,
        name: &str,
        request: impl buffa::Message,
        response: impl buffa::Message,
    ) {
        Mock::given(method("POST"))
            .and(path(format!("/codewire.v1.{service}/{name}")))
            .and(header(
                "authorization",
                "Bearer synthetic-credential-cli-oauth",
            ))
            .and(body_bytes(request.encode_to_vec()))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/proto")
                    .set_body_bytes(response.encode_to_vec()),
            )
            .expect(1)
            .mount(server)
            .await;
    }

    async fn expect_metadata(
        server: &MockServer,
        selector: rpc::get_credential_request::Selector,
        status: rpc::CredentialStatus,
    ) {
        unary(
            server,
            "CredentialService",
            "GetCredential",
            rpc::GetCredentialRequest {
                selector: Some(selector),
                ..Default::default()
            },
            rpc::GetCredentialResponse {
                credential: Some(metadata(status)).into(),
                ..Default::default()
            },
        )
        .await;
    }

    async fn expect_profiles(server: &MockServer, profiles: Vec<rpc::AccessProfile>) {
        unary(
            server,
            "AccessProfileService",
            "ListAccessProfiles",
            rpc::ListAccessProfilesRequest {
                page_size: 100,
                ..Default::default()
            },
            rpc::ListAccessProfilesResponse {
                access_profiles: profiles,
                ..Default::default()
            },
        )
        .await;
    }

    /// One organization whose Sandboxes are `environments`.
    async fn expect_sandboxes(server: &MockServer, environments: Vec<rpc::Environment>) {
        unary(
            server,
            "OrganizationService",
            "ListOrganizations",
            rpc::ListOrganizationsRequest::default(),
            rpc::ListOrganizationsResponse {
                organizations: vec![rpc::OrganizationMembership {
                    organization: Some(rpc::Organization {
                        id: "org-synthetic".into(),
                        ..Default::default()
                    })
                    .into(),
                    ..Default::default()
                }],
                ..Default::default()
            },
        )
        .await;
        unary(
            server,
            "EnvironmentService",
            "ListEnvironments",
            rpc::ListEnvironmentsRequest {
                org_id: "org-synthetic".into(),
                ..Default::default()
            },
            rpc::ListEnvironmentsResponse {
                environments,
                ..Default::default()
            },
        )
        .await;
    }

    const PROFILE: &str = "22222222-2222-4222-8222-222222222222";

    /// A Sandbox bound to `revision` of the profile [`PROFILE`].
    fn sandbox(name: &str, revision: u64) -> rpc::Environment {
        rpc::Environment {
            name: name.into(),
            source_selection: Some(rpc::EnvironmentSourceSelection {
                credentials: Some(rpc::ProjectCredentialBinding {
                    profile: format!("platform:id:{PROFILE}"),
                    ..Default::default()
                })
                .into(),
                profile_revision: Some(revision),
                ..Default::default()
            })
            .into(),
            ..Default::default()
        }
    }

    /// Profile [`PROFILE`], named "daily", at `revision` selecting `entries`.
    fn daily(revision: u64, entries: &[&str]) -> rpc::AccessProfile {
        rpc::AccessProfile {
            id: PROFILE.into(),
            name: "daily".into(),
            revision,
            entries: entries
                .iter()
                .map(|id| rpc::AccessProfileEntry {
                    capability_slot: "codex".into(),
                    credential_id: (*id).into(),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        }
    }

    /// An older service's answer to `revoke_first`: it refuses an active
    /// credential and changes nothing.
    fn must_be_revoked() -> ResponseTemplate {
        ResponseTemplate::new(400)
            .insert_header("content-type", "application/json")
            .set_body_json(serde_json::json!({
                "code": "failed_precondition",
                "message": "credential must be revoked before deletion",
            }))
    }

    async fn delete_answer(
        server: &MockServer,
        request: rpc::DeleteCredentialRequest,
        answer: ResponseTemplate,
    ) {
        Mock::given(method("POST"))
            .and(path(
                "/codewire.v1.CredentialMutationService/DeleteCredential",
            ))
            .and(body_bytes(request.encode_to_vec()))
            .respond_with(answer)
            .expect(1)
            .mount(server)
            .await;
    }

    fn delete(credential: &str) -> CredentialsCommand {
        CredentialsCommand::Delete(CredentialDeleteArgs {
            credential: Some(credential.into()),
            yes: true,
        })
    }

    #[tokio::test]
    async fn platform_delete_revokes_and_deletes_an_active_credential_in_one_step() {
        use rpc::get_credential_request::Selector;
        let server = MockServer::start().await;
        let client = client(&server);
        // Active (#6211): one delete at the observed revision, which the
        // service revokes, deletes and asks the provider about.
        expect_metadata(
            &server,
            Selector::Name("work".into()),
            rpc::CredentialStatus::Active,
        )
        .await;
        expect_profiles(&server, Vec::new()).await;
        expect_sandboxes(&server, Vec::new()).await;
        unary(
            &server,
            "CredentialMutationService",
            "DeleteCredential",
            rpc::DeleteCredentialRequest {
                credential_id: ID.into(),
                expected_revocation_generation: REVISION,
                revoke_first: true,
                ..Default::default()
            },
            rpc::DeleteCredentialResponse {
                provider_revocation: Some(rpc::ProviderRevocation {
                    outcome: rpc::ProviderRevocationOutcome::Confirmed.into(),
                    ..Default::default()
                })
                .into(),
                ..Default::default()
            },
        )
        .await;
        execute(&client, delete("name:work")).await.unwrap();
        server.verify().await;
        server.reset().await;

        // Already revoked: deleted at its own revision, with no revoke.
        expect_metadata(
            &server,
            Selector::Name("work".into()),
            rpc::CredentialStatus::Revoked,
        )
        .await;
        expect_profiles(&server, Vec::new()).await;
        expect_sandboxes(&server, Vec::new()).await;
        unary(
            &server,
            "CredentialMutationService",
            "DeleteCredential",
            rpc::DeleteCredentialRequest {
                credential_id: ID.into(),
                expected_revocation_generation: REVISION,
                ..Default::default()
            },
            rpc::DeleteCredentialResponse::default(),
        )
        .await;
        execute(&client, delete("work")).await.unwrap();
        server.verify().await;
    }

    #[tokio::test]
    async fn platform_delete_against_an_older_service_revokes_then_deletes() {
        use rpc::get_credential_request::Selector;
        let server = MockServer::start().await;
        expect_metadata(
            &server,
            Selector::Name("work".into()),
            rpc::CredentialStatus::Active,
        )
        .await;
        expect_profiles(&server, Vec::new()).await;
        expect_sandboxes(&server, Vec::new()).await;
        delete_answer(
            &server,
            rpc::DeleteCredentialRequest {
                credential_id: ID.into(),
                expected_revocation_generation: REVISION,
                revoke_first: true,
                ..Default::default()
            },
            must_be_revoked(),
        )
        .await;
        let mut revoked = metadata(rpc::CredentialStatus::Revoked);
        revoked.revocation_generation = REVISION + 1;
        unary(
            &server,
            "CredentialMutationService",
            "RevokeCredential",
            rpc::RevokeCredentialRequest {
                credential_id: ID.into(),
                expected_revocation_generation: REVISION,
                ..Default::default()
            },
            rpc::RevokeCredentialResponse {
                credential: Some(revoked).into(),
                ..Default::default()
            },
        )
        .await;
        unary(
            &server,
            "CredentialMutationService",
            "DeleteCredential",
            rpc::DeleteCredentialRequest {
                credential_id: ID.into(),
                expected_revocation_generation: REVISION + 1,
                ..Default::default()
            },
            rpc::DeleteCredentialResponse::default(),
        )
        .await;
        execute(&client(&server), delete("work")).await.unwrap();
        server.verify().await;
    }

    #[tokio::test]
    async fn platform_delete_whose_delete_fails_after_its_revoke_says_to_run_it_again() {
        use rpc::get_credential_request::Selector;
        let server = MockServer::start().await;
        expect_metadata(
            &server,
            Selector::Name("work".into()),
            rpc::CredentialStatus::Active,
        )
        .await;
        expect_profiles(&server, Vec::new()).await;
        expect_sandboxes(&server, Vec::new()).await;
        delete_answer(
            &server,
            rpc::DeleteCredentialRequest {
                credential_id: ID.into(),
                expected_revocation_generation: REVISION,
                revoke_first: true,
                ..Default::default()
            },
            must_be_revoked(),
        )
        .await;
        let mut revoked = metadata(rpc::CredentialStatus::Revoked);
        revoked.revocation_generation = REVISION + 1;
        unary(
            &server,
            "CredentialMutationService",
            "RevokeCredential",
            rpc::RevokeCredentialRequest {
                credential_id: ID.into(),
                expected_revocation_generation: REVISION,
                ..Default::default()
            },
            rpc::RevokeCredentialResponse {
                credential: Some(revoked).into(),
                ..Default::default()
            },
        )
        .await;
        delete_answer(
            &server,
            rpc::DeleteCredentialRequest {
                credential_id: ID.into(),
                expected_revocation_generation: REVISION + 1,
                ..Default::default()
            },
            refusal(400, "failed_precondition", None),
        )
        .await;
        let error = execute(&client(&server), delete("work")).await.unwrap_err();
        assert_eq!(
            error.to_string(),
            "cloud credential \"work\" was revoked, but may not have been deleted; run `cw credentials --cloud delete openai/work` again"
        );
        server.verify().await;
    }

    #[tokio::test]
    async fn platform_delete_held_by_a_sandbox_on_an_earlier_revision_names_it_and_changes_nothing()
    {
        let server = MockServer::start().await;
        expect_metadata(
            &server,
            rpc::get_credential_request::Selector::Name("work".into()),
            rpc::CredentialStatus::Active,
        )
        .await;
        // Revision 2 is after `unset`; the Sandbox stays on revision 1, and
        // another on revision 2 doesn't hold it.
        expect_profiles(&server, vec![daily(2, &[])]).await;
        expect_sandboxes(&server, vec![sandbox("dev", 1), sandbox("web", 2)]).await;
        unary(
            &server,
            "AccessProfileService",
            "ListAccessProfileRevisions",
            rpc::ListAccessProfileRevisionsRequest {
                access_profile_id: PROFILE.into(),
                page_size: 100,
                ..Default::default()
            },
            rpc::ListAccessProfileRevisionsResponse {
                revisions: [daily(2, &[]), daily(1, &[ID])]
                    .into_iter()
                    .map(|profile| rpc::AccessProfileRevision {
                        access_profile: Some(profile).into(),
                        ..Default::default()
                    })
                    .collect(),
                ..Default::default()
            },
        )
        .await;
        let error = execute(&client(&server), delete("work")).await.unwrap_err();
        assert_eq!(
            error.to_string(),
            "cloud credential \"work\" is still used by Sandbox dev, made with an earlier version of profile \"daily\"; move it to the profile as it is now with `cw update dev --profile platform:daily`, or remove it with `cw rm dev`"
        );
        // Checked before the question: no revoke and no delete.
        server.verify().await;
        assert_eq!(server.received_requests().await.unwrap().len(), 5);
    }

    #[tokio::test]
    async fn platform_delete_the_service_finds_in_use_is_refused_unrevoked() {
        let server = MockServer::start().await;
        expect_metadata(
            &server,
            rpc::get_credential_request::Selector::Name("work".into()),
            rpc::CredentialStatus::Active,
        )
        .await;
        expect_profiles(&server, Vec::new()).await;
        expect_sandboxes(&server, Vec::new()).await;
        delete_answer(
            &server,
            rpc::DeleteCredentialRequest {
                credential_id: ID.into(),
                expected_revocation_generation: REVISION,
                revoke_first: true,
                ..Default::default()
            },
            refusal(400, "failed_precondition", Some((CREDENTIAL_IN_USE, None))),
        )
        .await;
        let error = execute(&client(&server), delete("work")).await.unwrap_err();
        assert_eq!(
            error.to_string(),
            "cloud credential \"work\" was not deleted: a profile or a Sandbox still uses it, and it was not revoked; free it, then delete it again"
        );
        // No revoke follows the refusal.
        server.verify().await;
        assert_eq!(server.received_requests().await.unwrap().len(), 5);
    }

    #[tokio::test]
    async fn platform_delete_of_a_selected_credential_names_the_unset_and_changes_nothing() {
        let server = MockServer::start().await;
        let client = client(&server);
        expect_metadata(
            &server,
            rpc::get_credential_request::Selector::Name("work".into()),
            rpc::CredentialStatus::Active,
        )
        .await;
        expect_profiles(
            &server,
            vec![rpc::AccessProfile {
                name: "daily".into(),
                entries: vec![rpc::AccessProfileEntry {
                    capability_slot: "codex".into(),
                    credential_id: ID.into(),
                    ..Default::default()
                }],
                ..Default::default()
            }],
        )
        .await;
        let error = execute(
            &client,
            CredentialsCommand::Delete(CredentialDeleteArgs {
                credential: Some("work".into()),
                yes: true,
            }),
        )
        .await
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("`cw credentials --cloud --profile daily unset codex`"),
            "{error}"
        );
        assert_eq!(
            server.received_requests().await.unwrap().len(),
            2,
            "no revoke and no delete"
        );
    }

    #[test]
    fn the_platforms_report_reads_as_the_providers_answer() {
        use super::super::credentials::output::ProviderAnswer;
        assert!(matches!(provider_answer(None), ProviderAnswer::NotAsked));
        let report = |outcome: rpc::ProviderRevocationOutcome,
                      failure: rpc::ProviderRevocationFailure,
                      http_status: u32| rpc::ProviderRevocation {
            outcome: outcome.into(),
            failure: failure.into(),
            http_status,
            ..Default::default()
        };
        use rpc::{ProviderRevocationFailure as F, ProviderRevocationOutcome as O};
        assert!(matches!(
            provider_answer(Some(&report(O::Confirmed, F::Unspecified, 0))),
            ProviderAnswer::Confirmed
        ));
        for (outcome, failure) in [(O::NotAvailable, F::Unspecified), (O::Failed, F::NotRead)] {
            assert!(matches!(
                provider_answer(Some(&report(outcome, failure, 0))),
                ProviderAnswer::NotAsked
            ));
        }
        use super::super::credentials::output::NotConfirmedBecause as Because;
        for (failure, status, because) in [
            (F::Unavailable, 0, Because::Unreachable),
            (F::Refused, 404, Because::Refused(404)),
            (F::Refused, 70_000, Because::Refused(0)),
            (F::Unreadable, 0, Because::Unreadable),
            (F::Expired, 0, Because::Expired),
        ] {
            match provider_answer(Some(&report(O::Failed, failure, status))) {
                ProviderAnswer::NotConfirmed(said) => assert_eq!(said, because),
                _ => panic!("{failure:?} was not reported as not confirmed"),
            }
        }
    }

    #[tokio::test]
    async fn platform_revocation_conflict_never_refetches_or_retries() {
        let server = MockServer::start().await;
        expect_metadata(
            &server,
            rpc::get_credential_request::Selector::Name("work".into()),
            rpc::CredentialStatus::Active,
        )
        .await;
        Mock::given(method("POST"))
            .and(path(
                "/codewire.v1.CredentialMutationService/RevokeCredential",
            ))
            .and(body_bytes(
                rpc::RevokeCredentialRequest {
                    credential_id: ID.into(),
                    expected_revocation_generation: REVISION,
                    ..Default::default()
                }
                .encode_to_vec(),
            ))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "code": "failed_precondition", "message": "credential revision changed"
            })))
            .expect(1)
            .mount(&server)
            .await;
        assert!(
            execute(
                &client(&server),
                CredentialsCommand::Revoke(revoke_args("work", true, OutputFormat::Text))
            )
            .await
            .is_err()
        );
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
        server.verify().await;
    }

    fn revoke_args(
        credential: &str,
        yes: bool,
        output: OutputFormat,
    ) -> super::super::credentials::confirm::CredentialRevokeArgs {
        super::super::credentials::confirm::CredentialRevokeArgs {
            credential: credential.into(),
            yes,
            output,
        }
    }

    #[tokio::test]
    async fn platform_revoke_under_json_without_yes_refuses_and_revokes_nothing() {
        // #4717 C6, as `cw rm`: `--output json` never asks, so without
        // `--yes` the revoke fails at once and names it.
        let server = MockServer::start().await;
        expect_metadata(
            &server,
            rpc::get_credential_request::Selector::Name("work".into()),
            rpc::CredentialStatus::Active,
        )
        .await;
        let error = execute(
            &client(&server),
            CredentialsCommand::Revoke(revoke_args("work", false, OutputFormat::Json)),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("add `--yes` to revoke it"), "{error}");
        let requests = server.received_requests().await.unwrap();
        assert!(
            requests
                .iter()
                .all(|request| !request.url.path().ends_with("/RevokeCredential")),
            "nothing is revoked"
        );
    }

    #[tokio::test]
    async fn platform_revoke_with_yes_revokes_the_observed_revision_once() {
        let server = MockServer::start().await;
        expect_metadata(
            &server,
            rpc::get_credential_request::Selector::Name("work".into()),
            rpc::CredentialStatus::Active,
        )
        .await;
        let mut revoked = metadata(rpc::CredentialStatus::Revoked);
        revoked.revocation_generation = REVISION + 1;
        unary(
            &server,
            "CredentialMutationService",
            "RevokeCredential",
            rpc::RevokeCredentialRequest {
                credential_id: ID.into(),
                expected_revocation_generation: REVISION,
                ..Default::default()
            },
            rpc::RevokeCredentialResponse {
                credential: Some(revoked).into(),
                provider_revocation: Some(rpc::ProviderRevocation {
                    outcome: rpc::ProviderRevocationOutcome::Confirmed.into(),
                    ..Default::default()
                })
                .into(),
                ..Default::default()
            },
        )
        .await;
        execute(
            &client(&server),
            CredentialsCommand::Revoke(revoke_args("work", true, OutputFormat::Text)),
        )
        .await
        .unwrap();
        server.verify().await;
    }

    #[tokio::test]
    async fn platform_listing_rejects_repeated_cursor() {
        let server = MockServer::start().await;
        for page_token in ["", "same"] {
            unary(
                &server,
                "CredentialService",
                "ListCredentials",
                rpc::ListCredentialsRequest {
                    page_size: 100,
                    page_token: page_token.into(),
                    ..Default::default()
                },
                rpc::ListCredentialsResponse {
                    next_page_token: "same".into(),
                    ..Default::default()
                },
            )
            .await;
        }
        let error = execute(
            &client(&server),
            CredentialsCommand::List(CredentialListArgs {
                output: OutputFormat::Text,
            }),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("repeated credential cursor"));
        server.verify().await;
    }

    #[tokio::test]
    async fn platform_unsupported_material_paths_reject_before_raw_input() {
        let server = MockServer::start().await;
        let client = client(&server);
        let command = CredentialsCommand::Add(CredentialAddArgs {
            provider: Some("codex".into()),
            name: Some("work".into()),
            account_hint: None,
            expires_at: None,
            key_file: None,

            yes: false,

            output: crate::commands::OutputFormat::Text,

            guided: false,
        });
        assert!(execute(&client, command).await.is_err());
        assert!(server.received_requests().await.unwrap().is_empty());
        // Rotation must inspect the stored kind, then reject unsupported
        // material before prompting or sending any mutation.
        expect_metadata(
            &server,
            rpc::get_credential_request::Selector::Name("work".into()),
            rpc::CredentialStatus::Active,
        )
        .await;
        let error = execute(
            &client,
            CredentialsCommand::Rotate(CredentialRotateArgs {
                credential: "work".into(),
                expires_at: None,
            }),
        )
        .await
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("comes from a provider sign-in, so it isn't pasted")
        );
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
        server.verify().await;
    }

    #[test]
    fn reconnect_pins_canonical_identity_and_never_guesses_authentication_kind() {
        const OAUTH: rpc::CredentialAuthenticationKind = rpc::CredentialAuthenticationKind::Oauth;
        const SIGN_IN: rpc::CredentialAuthenticationKind =
            rpc::CredentialAuthenticationKind::ClaudeSignIn;
        let created = oauth_connection_request("openai", OAUTH, "Work", None).unwrap();
        assert!(created.credential_id.is_none());
        assert!(created.expected_revocation_generation.is_none());
        let mut current = metadata(rpc::CredentialStatus::Revoked);
        current.name = "Work".into();
        current.authentication_kind = OAUTH.into();
        let reconnect = oauth_connection_request("openai", OAUTH, "work", Some(&current)).unwrap();
        assert_eq!(reconnect.name, "Work");
        assert_eq!(reconnect.credential_id.as_deref(), Some(ID));
        assert_eq!(reconnect.expected_revocation_generation, Some(REVISION));
        assert!(oauth_connection_request("openai", OAUTH, "other", Some(&current)).is_err());
        assert!(oauth_connection_request("github", OAUTH, "work", Some(&current)).is_err());
        current.provider = "github".into();
        let github = oauth_connection_request("github", OAUTH, "work", Some(&current)).unwrap();
        assert_eq!(github.credential_id.as_deref(), Some(ID));
        assert_eq!(github.expected_revocation_generation, Some(REVISION));
        current.provider = "openai".into();
        current.authentication_kind = rpc::CredentialAuthenticationKind::ApiKey.into();
        assert!(oauth_connection_request("openai", OAUTH, "work", Some(&current)).is_err());
        current.authentication_kind = OAUTH.into();
        current.revocation_generation = 0;
        assert!(oauth_connection_request("openai", OAUTH, "work", Some(&current)).is_err());
        // A Claude sign-in reconnects only a sign-in: never a subscription
        // token, which is the provider's OAuth kind, nor an API key.
        current.revocation_generation = REVISION;
        current.provider = "anthropic".into();
        assert!(oauth_connection_request("anthropic", SIGN_IN, "work", Some(&current)).is_err());
        current.authentication_kind = rpc::CredentialAuthenticationKind::ApiKey.into();
        assert!(oauth_connection_request("anthropic", SIGN_IN, "work", Some(&current)).is_err());
        current.authentication_kind = SIGN_IN.into();
        let claude =
            oauth_connection_request("anthropic", SIGN_IN, "work", Some(&current)).unwrap();
        assert_eq!(claude.credential_id.as_deref(), Some(ID));
    }

    #[tokio::test]
    async fn a_second_cloud_github_connection_is_refused_before_any_device_code() {
        let server = MockServer::start().await;
        let mut github = metadata(rpc::CredentialStatus::Active);
        github.provider = "github".into();
        github.authentication_kind = rpc::CredentialAuthenticationKind::Oauth.into();
        let mut codex = metadata(rpc::CredentialStatus::Active);
        codex.id = "0b7d0f43-3a43-4d55-9a54-30a8b1a8e0c1".into();
        codex.name = "other".into();
        codex.authentication_kind = rpc::CredentialAuthenticationKind::Oauth.into();
        unary(
            &server,
            "CredentialService",
            "ListCredentials",
            rpc::ListCredentialsRequest {
                page_size: 100,
                ..Default::default()
            },
            rpc::ListCredentialsResponse {
                credentials: vec![codex, github],
                ..Default::default()
            },
        )
        .await;
        let error = execute(
            &client(&server),
            CredentialsCommand::Connect(CredentialConnectArgs {
                credential_type: None,
                provider: Some(CredentialConnectProviderArg::Github),
                name: Some("other".into()),
                yes: true,
                output: crate::commands::OutputFormat::Text,
                expires_at: None,
                key_file: None,
                account_hint: None,
                guided: false,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(
            format!("{error:#}"),
            "GitHub is already connected as work; run `cw credentials --cloud connect github --name work --yes` to reconnect it"
        );
        // Only the listing: no name lookup and no enrollment.
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
        server.verify().await;
    }

    /// The service's answer to a name lookup: a credential, not found, or
    /// its refusal to choose between providers (#4928).
    enum Lookup {
        Found(Box<rpc::Credential>),
        NotFound,
        Ambiguous(&'static str),
    }

    fn credential(
        id: &str,
        provider: &str,
        kind: rpc::CredentialAuthenticationKind,
        name: &str,
    ) -> rpc::Credential {
        rpc::Credential {
            id: id.into(),
            name: name.into(),
            provider: provider.into(),
            authentication_kind: kind.into(),
            status: rpc::CredentialStatus::Active.into(),
            revocation_generation: REVISION,
            ..Default::default()
        }
    }

    const CLAUDE_WALK: &str = "0f1c4a1e-6a51-4c5d-9f0c-6b2f7c1d2e01";
    const CODEX_WALK: &str = "0f1c4a1e-6a51-4c5d-9f0c-6b2f7c1d2e02";

    fn claude_walk() -> rpc::Credential {
        credential(
            CLAUDE_WALK,
            "anthropic",
            rpc::CredentialAuthenticationKind::ClaudeSignIn,
            "walk",
        )
    }

    fn codex_walk() -> rpc::Credential {
        credential(
            CODEX_WALK,
            "openai",
            rpc::CredentialAuthenticationKind::Oauth,
            "walk",
        )
    }

    /// Mounts the service's answer to one exact name lookup.
    async fn lookup(server: &MockServer, name: &str, provider: Option<&str>, answer: Lookup) {
        lookups(server, name, provider, vec![lookup_answer(answer)]).await;
    }

    /// Mounts the service's answers to an exact name lookup asked once for
    /// each, in turn.
    async fn lookups(
        server: &MockServer,
        name: &str,
        provider: Option<&str>,
        answers: Vec<ResponseTemplate>,
    ) {
        let request = rpc::GetCredentialRequest {
            selector: Some(rpc::get_credential_request::Selector::Name(name.into())),
            provider: provider.map(str::to_owned),
            ..Default::default()
        };
        for response in answers {
            Mock::given(method("POST"))
                .and(path("/codewire.v1.CredentialService/GetCredential"))
                .and(body_bytes(request.encode_to_vec()))
                .respond_with(response)
                .up_to_n_times(1)
                .expect(1)
                .mount(server)
                .await;
        }
    }

    fn lookup_answer(answer: Lookup) -> ResponseTemplate {
        match answer {
            Lookup::Found(credential) => ResponseTemplate::new(200)
                .insert_header("content-type", "application/proto")
                .set_body_bytes(
                    rpc::GetCredentialResponse {
                        credential: Some(*credential).into(),
                        ..Default::default()
                    }
                    .encode_to_vec(),
                ),
            Lookup::NotFound => refusal(404, "not_found", None),
            Lookup::Ambiguous(providers) => refusal(
                400,
                "failed_precondition",
                Some((CREDENTIAL_NAME_AMBIGUOUS, Some(providers))),
            ),
        }
    }

    fn refusal(status: u16, code: &str, reason: Option<(&str, Option<&str>)>) -> ResponseTemplate {
        let details = reason
            .map(|(reason, providers)| {
                let mut info = codewire_proto::google::rpc::ErrorInfo {
                    reason: reason.into(),
                    domain: "codewire.sh".into(),
                    ..Default::default()
                };
                if let Some(providers) = providers {
                    info.metadata.insert("providers".into(), providers.into());
                }
                vec![connectrpc::ErrorDetail::from_message(
                    "google.rpc.ErrorInfo",
                    &info,
                )]
            })
            .unwrap_or_default();
        ResponseTemplate::new(status)
            .insert_header("content-type", "application/json")
            .set_body_json(serde_json::json!({
                "code": code,
                "message": "synthetic refusal",
                "details": details,
            }))
    }

    async fn listing(server: &MockServer, credentials: Vec<rpc::Credential>) {
        unary(
            server,
            "CredentialService",
            "ListCredentials",
            rpc::ListCredentialsRequest {
                page_size: 100,
                ..Default::default()
            },
            rpc::ListCredentialsResponse {
                credentials,
                ..Default::default()
            },
        )
        .await;
    }

    /// A bare name the service finds under two providers is refused in the
    /// local words, and nothing is deleted; `PROVIDER/NAME` asks for that
    /// provider's credential only (#4928).
    #[tokio::test]
    async fn a_bare_shared_cloud_name_is_refused_with_the_choice_and_changes_nothing() {
        let server = MockServer::start().await;
        let client = client(&server);
        lookup(&server, "walk", None, Lookup::Ambiguous("anthropic,openai")).await;
        let error = execute(
            &client,
            CredentialsCommand::Delete(CredentialDeleteArgs {
                credential: Some("walk".into()),
                yes: true,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(
            format!("{error:#}"),
            "\"walk\" names more than one credential (anthropic, openai); name one, for example anthropic/walk"
        );
        // The lookup only: no profile listing, revoke or delete.
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
        server.verify().await;
        server.reset().await;

        lookup(&server, "openai/walk", None, Lookup::NotFound).await;
        lookup(
            &server,
            "walk",
            Some("openai"),
            Lookup::Found(Box::new(codex_walk())),
        )
        .await;
        assert_eq!(
            resolve(&client, "openai/walk").await.unwrap().id,
            CODEX_WALK
        );
        server.verify().await;
        server.reset().await;

        // A slot's provider narrows a bare name, so it needs no prefix.
        lookup(
            &server,
            "walk",
            Some("anthropic"),
            Lookup::Found(Box::new(claude_walk())),
        )
        .await;
        assert_eq!(
            resolve_in(&client, "walk", Some("anthropic"))
                .await
                .unwrap()
                .id,
            CLAUDE_WALK
        );
        server.verify().await;
    }

    /// cw-security's first condition on #4928, in the cloud: both readings
    /// are asked for, and two different credentials are refused naming both.
    #[tokio::test]
    async fn a_literal_cloud_provider_name_beside_that_providers_name_is_refused() {
        let server = MockServer::start().await;
        let client = client(&server);
        let literal = credential(
            "0f1c4a1e-6a51-4c5d-9f0c-6b2f7c1d2e03",
            "ssh",
            rpc::CredentialAuthenticationKind::SshKey,
            "github/work",
        );
        let github = credential(
            "0f1c4a1e-6a51-4c5d-9f0c-6b2f7c1d2e04",
            "github",
            rpc::CredentialAuthenticationKind::Oauth,
            "work",
        );
        lookup(
            &server,
            "github/work",
            None,
            Lookup::Found(Box::new(literal.clone())),
        )
        .await;
        lookup(
            &server,
            "work",
            Some("github"),
            Lookup::Found(Box::new(github)),
        )
        .await;
        assert_eq!(
            format!("{:#}", resolve(&client, "github/work").await.unwrap_err()),
            "\"github/work\" names more than one credential (github \"work\", ssh \"github/work\"); name one, for example ssh/github/work"
        );
        server.verify().await;
        server.reset().await;
        // With only the literal one, it acts on that.
        lookup(
            &server,
            "github/work",
            None,
            Lookup::Found(Box::new(literal.clone())),
        )
        .await;
        lookup(&server, "work", Some("github"), Lookup::NotFound).await;
        assert_eq!(resolve(&client, "github/work").await.unwrap(), literal);
        server.verify().await;
    }

    /// The owner's case in the cloud: a Codex connect named like a Claude
    /// sign-in asks only for an OpenAI credential of that name, and goes on.
    /// A Claude token under a Claude sign-in's name is refused naming it.
    #[tokio::test]
    async fn a_cloud_connect_collides_only_within_its_provider() {
        let server = MockServer::start().await;
        let client = client(&server);
        lookup(&server, "walk", Some("openai"), Lookup::NotFound).await;
        let found = CloudConnectStore { client: &client }
            .named(CredentialConnectProviderArg::Codex, "walk")
            .await
            .unwrap();
        assert!(found.is_none());
        server.verify().await;
        server.reset().await;

        lookup(
            &server,
            "walk",
            Some("anthropic"),
            Lookup::Found(Box::new(claude_walk())),
        )
        .await;
        listing(&server, vec![claude_walk(), codex_walk()]).await;
        let error = CloudConnectStore { client: &client }
            .named(CredentialConnectProviderArg::ClaudeToken, "walk")
            .await
            .unwrap_err();
        assert_eq!(
            format!("{error:#}"),
            "\"walk\" is in use in anthropic by a Claude (sign-in) credential; choose another name, for example walk-2"
        );
        server.verify().await;
        server.reset().await;

        // A new name with a provider prefix asks nothing more of the service.
        lookup(&server, "anthropic/walk", Some("openai"), Lookup::NotFound).await;
        let error = CloudConnectStore { client: &client }
            .named(CredentialConnectProviderArg::Codex, "anthropic/walk")
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "a credential's name can't start with anthropic/, which reads as a provider; choose another name"
        );
        server.verify().await;
    }

    /// The service's refusal of a rename to `walk`, after the CLI's own
    /// check found no OpenAI credential of that name.
    async fn refused_rename(server: &MockServer, client: &CodewireClient) -> anyhow::Error {
        expect_metadata(
            server,
            rpc::get_credential_request::Selector::Name("work".into()),
            rpc::CredentialStatus::Active,
        )
        .await;
        Mock::given(method("POST"))
            .and(path(
                "/codewire.v1.CredentialMutationService/RenameCredential",
            ))
            .respond_with(refusal(409, "already_exists", None))
            .expect(1)
            .mount(server)
            .await;
        execute(
            client,
            CredentialsCommand::Rename(CredentialRenameArgs {
                credential: "work".into(),
                name: "walk".into(),
            }),
        )
        .await
        .unwrap_err()
    }

    /// A Codex sign-in's save to `walk` that the service refused as taken.
    async fn refused_codex_save(client: &CodewireClient) -> String {
        let taken = rpc::ClientError::from(connectrpc::ConnectError::new(
            connectrpc::ErrorCode::AlreadyExists,
            "credential name already exists",
        ));
        let save = Save {
            placement: "cloud",
            kind: Kind::Connect(CredentialConnectProviderArg::Codex),
            name: "walk",
        };
        crate::error_report::sentence(&cloud_connect_error(client, save, None, taken).await)
    }

    /// After migration 0043 the cloud refuses only a name its provider holds
    /// (#4928). When the provider's own lookup, asked again, finds no holder
    /// the caller may read, the refusal names the provider and nothing of the
    /// holder, for a rename and a sign-in's save (cw-security on #4928).
    #[tokio::test]
    async fn a_name_the_cloud_refuses_with_no_readable_holder_names_only_its_provider() {
        let server = MockServer::start().await;
        let client = client(&server);
        let not_found = || lookup_answer(Lookup::NotFound);
        lookups(
            &server,
            "walk",
            Some("openai"),
            vec![not_found(), not_found()],
        )
        .await;
        assert_eq!(
            format!("{:#}", refused_rename(&server, &client).await),
            "that name is in use in openai; choose another name"
        );
        server.verify().await;
        server.reset().await;

        lookup(&server, "walk", Some("openai"), Lookup::NotFound).await;
        assert_eq!(
            refused_codex_save(&client).await,
            "that name is in use in openai, so your Codex sign-in wasn't saved"
        );
        server.verify().await;
    }

    /// When the lookup after the refusal finds a credential of the provider
    /// the caller may read, it is named with a free name, as before a write.
    #[tokio::test]
    async fn a_name_the_cloud_refuses_that_a_readable_credential_of_its_provider_holds_names_it() {
        let server = MockServer::start().await;
        let client = client(&server);
        lookups(
            &server,
            "walk",
            Some("openai"),
            vec![
                lookup_answer(Lookup::NotFound),
                lookup_answer(Lookup::Found(Box::new(codex_walk()))),
            ],
        )
        .await;
        listing(
            &server,
            vec![metadata(rpc::CredentialStatus::Active), codex_walk()],
        )
        .await;
        let taken = "\"walk\" is in use in openai by a Codex credential; choose another name, for example walk-2";
        assert_eq!(
            format!("{:#}", refused_rename(&server, &client).await),
            taken
        );
        server.verify().await;
        server.reset().await;

        lookup(
            &server,
            "walk",
            Some("openai"),
            Lookup::Found(Box::new(codex_walk())),
        )
        .await;
        listing(&server, vec![codex_walk()]).await;
        assert_eq!(refused_codex_save(&client).await, taken);
        server.verify().await;
    }

    /// When the lookup after the refusal fails, the refusal names the
    /// provider only, never a holder (cw-security on #4928); so does a
    /// sign-in's save, and the store's reserved name keeps its words.
    #[tokio::test]
    async fn a_name_the_cloud_refuses_whose_holder_cannot_be_looked_up_names_only_its_provider() {
        let server = MockServer::start().await;
        let client = client(&server);
        let unreadable = || refusal(403, "permission_denied", None);
        lookups(
            &server,
            "walk",
            Some("openai"),
            vec![lookup_answer(Lookup::NotFound), unreadable()],
        )
        .await;
        assert_eq!(
            format!("{:#}", refused_rename(&server, &client).await),
            "that name is in use in openai; choose another name"
        );
        server.verify().await;
        server.reset().await;

        lookups(&server, "walk", Some("openai"), vec![unreadable()]).await;
        assert_eq!(
            refused_codex_save(&client).await,
            "that name is in use in openai, so your Codex sign-in wasn't saved"
        );
        server.verify().await;

        let reserved = rpc::ClientError::from(
            connectrpc::ConnectError::new(connectrpc::ErrorCode::InvalidArgument, "reserved")
                .with_detail(connectrpc::ErrorDetail::from_message(
                    "google.rpc.ErrorInfo",
                    &codewire_proto::google::rpc::ErrorInfo {
                        reason: "CREDENTIAL_NAME_RESERVES_PROVIDER".into(),
                        domain: "codewire.sh".into(),
                        ..Default::default()
                    },
                )),
        );
        assert_eq!(
            format!("{:#}", cloud_name_error(reserved, "ssh", "github/x", "add")),
            "a credential's name can't start with github/, which reads as a provider; choose another name"
        );
    }

    #[tokio::test]
    async fn reconnect_metadata_failure_is_not_treated_as_a_missing_credential() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/codewire.v1.CredentialService/GetCredential"))
            .respond_with(ResponseTemplate::new(503).set_body_json(
                serde_json::json!({"code":"unavailable","message":"synthetic failure"}),
            ))
            .expect(1)
            .mount(&server)
            .await;
        let reading = NameReading {
            name: "work",
            provider: None,
        };
        assert!(lookup_name(&client(&server), reading).await.is_err());
        server.verify().await;
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
}
