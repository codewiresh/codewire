//! Personal platform credential commands: write-only keys and managed OAuth.

use codewire_client::{self as rpc, CodewireClient};

use super::credential_input::connect::{
    ConnectStore, ConnectTarget, Interrupt, Reconnecting, claude_token_from_alias,
    claude_token_rotate_refusal, provider_id, provider_label, read_claude_token,
};
use super::credential_input::{
    CODEX_DEVICE_AUTHORIZATION_GUIDANCE, ParsedCredentialSelector, SSH_PUBLIC_KEY_GITHUB_HINT,
    parse_credential_selector, prompt_credential_material, read_ssh_import,
    validate_ssh_generation, validate_ssh_import,
};
use super::login_screen;
use super::*;

/// Generates a cloud SSH identity and prints it with its public key.
pub(super) async fn generate_ssh(
    client: &CodewireClient,
    args: &CredentialGenerateArgs,
) -> anyhow::Result<rpc::Credential> {
    let name = validate_ssh_generation(args)?;
    let response = client.generate_ssh_credential(rpc::GenerateSshCredentialRequest {
        name, expires_at_unix: args.expires_at, ..Default::default()
    }).await.context("generate cloud SSH identity; inspect by name before retrying an uncertain acknowledgement")?;
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
        CredentialsCommand::Revoke(args) => {
            let current = resolve(client, &args.credential).await?;
            let response = client.revoke_credential(rpc::RevokeCredentialRequest {
                credential_id: current.id,
                expected_revocation_generation: current.revocation_generation,
                ..Default::default()
            }).await.context("revoke exact platform credential revision; inspect metadata before retrying an uncertain result")?;
            print(
                &[response
                    .credential
                    .into_option()
                    .context("platform omitted revoked metadata")?],
                args.output,
            )
        }
        CredentialsCommand::Delete(args) => {
            let current = resolve(
                client,
                args.credential
                    .as_deref()
                    .context("delete requires a credential selector")?,
            )
            .await?;
            if current.status != rpc::CredentialStatus::Revoked {
                anyhow::bail!("revoke the platform credential before deleting its stored record");
            }
            if !args.yes
                && !prompt_confirm_default_no(&format!(
                    "Delete platform credential {:?}?",
                    current.name
                ))?
            {
                eprintln!("Canceled.");
                return Ok(());
            }
            let token = is_subscription_token(&current);
            client.delete_credential(rpc::DeleteCredentialRequest {
                credential_id: current.id,
                expected_revocation_generation: current.revocation_generation,
                ..Default::default()
            }).await.context("delete exact revoked platform credential revision; inspect metadata before retrying an uncertain result")?;
            eprintln!(
                "{}",
                super::credentials::output::deleted("cloud", &current.name)
            );
            if token {
                eprintln!("{}", super::credential_input::connect::CLAUDE_TOKEN_DELETED);
            }
            Ok(())
        }
        CredentialsCommand::Add(args) => {
            if args.provider.as_deref() == Some("ssh") {
                let name = validate_ssh_import(&args)?;
                // Confirm owner-scoped access and name availability before
                // reading the explicitly selected private file or passphrase.
                anyhow::ensure!(
                    find_named(client, &name).await?.is_none(),
                    super::credentials::output::refusal::name_in_use("cloud", &name)
                );
                let mut input = read_ssh_import(&args)?;
                let response = client.add_ssh_credential(rpc::AddSshCredentialRequest {
                    name,
                    private_key: std::mem::take(&mut *input.private_key),
                    passphrase: input.passphrase.as_mut().map(|value| std::mem::take(&mut **value)),
                    expires_at_unix: args.expires_at,
                    ..Default::default()
                }).await.context("import platform SSH identity; inspect by name before retrying an uncertain acknowledgement")?;
                return print(
                    &[response
                        .credential
                        .into_option()
                        .inspect(|record| remember_platform(record, execution))
                        .context("platform omitted SSH metadata")?],
                    OutputFormat::Text,
                );
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
            let material = prompt_credential_material(
                args.provider.as_deref().unwrap_or_default(),
                codewire_access::CredentialAuthKind::ApiKey,
            )?;
            let response = client.add_api_key_credential(rpc::AddApiKeyCredentialRequest {
                provider: args.provider.context("credential provider is required")?,
                name: args.name.as_deref().context("credential name is required")?.trim().to_owned(),
                value: material.expose_secret().to_vec(),
                expires_at_unix: args.expires_at,
                ..Default::default()
            }).await.context("add platform API key; inspect by name before retrying an uncertain acknowledgement")?;
            print(
                &[response
                    .credential
                    .into_option()
                    .inspect(|record| remember_platform(record, execution))
                    .context("platform omitted credential metadata")?],
                OutputFormat::Text,
            )
        }
        CredentialsCommand::Rename(args) => {
            let name = trimmed_required(&args.name, "credential name")?.to_owned();
            let current = resolve(client, &args.credential).await?;
            let response = client.rename_credential(rpc::RenameCredentialRequest {
                credential_id: current.id.clone(),
                expected_revocation_generation: current.revocation_generation,
                expected_name: current.name.clone(), name: name.clone(), ..Default::default()
            }).await.context("rename exact platform credential; inspect metadata before retrying an uncertain result")?;
            let renamed = response
                .credential
                .into_option()
                .context("platform omitted renamed metadata")?;
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
            }).await.context("rotate exact platform API key; inspect metadata before retrying an uncertain result")?;
            let rotated = response
                .credential
                .into_option()
                .context("platform omitted rotated metadata")?;
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
        matches!(current.provider.as_str(), "openai" | "anthropic")
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
        "platform returned an invalid credential revision"
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
        "platform returned unexpected credential metadata; inspect the identity before retrying the uncertain result"
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
            anyhow::bail!("platform returned a repeated credential cursor");
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
        let current = find_named(self.client, name).await?;
        oauth_connection_request(
            provider_id(provider),
            cloud_connected_kind(provider),
            name,
            current.as_ref(),
        )?;
        Ok(current)
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
            id: record.id.clone(),
            revision: record.revocation_generation,
            status: super::credentials::output::CredentialView::cloud(record)?.status_at(now),
        })
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
        let screen =
            login_screen::SignInScreen::cloud(provider_label(target.provider), &target.name);
        let request = oauth_connection_request(
            provider_id(target.provider),
            cloud_connected_kind(target.provider),
            &target.name,
            target.existing.as_ref(),
        )?;
        let client = self.client;
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
                CloudApproval::Codex => {
                    eprintln!("{}", CODEX_DEVICE_AUTHORIZATION_GUIDANCE);
                    client
                        .enroll_codex(
                            rpc::EnrollCodexRequest {
                                name: request.name,
                                credential_id: request.credential_id,
                                expected_revocation_generation: request
                                    .expected_revocation_generation,
                                ..Default::default()
                            },
                            |challenge| {
                                display_challenge(
                                    screen,
                                    &challenge.verification_url,
                                    &challenge.user_code,
                                )
                            },
                        )
                        .await
                        .map(|credential| (credential, Vec::new()))
                }
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
                            )
                        },
                    )
                    .await
                    .map(|enrolled| (enrolled.credential, enrolled.pending_permissions)),
            }
        };
        let (credential, pending) = tokio::select! {
            result = enrollment => result.context("enroll platform OAuth credential")?,
            () = interrupt.pressed() => {
                anyhow::bail!("enrollment cancelled; inspect the credential by name before retrying because storage acknowledgement may be unknown");
            }
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
        let style = crate::output::Capabilities::from_process(crate::output::OutputMode::Text)
            .stderr_style();
        eprint!(
            "\n{}",
            login_screen::connected_line(screen, who, expires, style)
        );
        remember_platform(&credential, execution);
        super::credentials::report_github_pending(github_pending(&pending));
        Ok(())
    }
}

async fn find_named(
    client: &CodewireClient,
    name: &str,
) -> anyhow::Result<Option<rpc::Credential>> {
    match client
        .get_credential(rpc::GetCredentialRequest {
            selector: Some(rpc::get_credential_request::Selector::Name(name.to_owned())),
            ..Default::default()
        })
        .await
    {
        Ok(response) => Ok(Some(
            response
                .credential
                .into_option()
                .context("platform omitted credential metadata")?,
        )),
        Err(error) if error.code() == rpc::ErrorCode::NotFound => Ok(None),
        Err(error) => Err(error).context("inspect existing platform credential before enrollment"),
    }
}

/// A device flow's challenge (Codex, GitHub): the link screen, then the code
/// to enter on the provider's page.
fn display_challenge(screen: login_screen::SignInScreen<'_>, url: &str, code: &str) -> bool {
    login_screen::open_sign_in_link(screen, url);
    let style =
        crate::output::Capabilities::from_process(crate::output::OutputMode::Text).stderr_style();
    eprint!("{}", login_screen::device_code_lines(code, style));
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
        matches!(args.provider.as_deref(), Some("openai" | "anthropic")),
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
    let selector = match parse_credential_selector(selector)? {
        ParsedCredentialSelector::Id(id) => {
            rpc::get_credential_request::Selector::CredentialId(id.to_string())
        }
        ParsedCredentialSelector::Name(name) => {
            rpc::get_credential_request::Selector::Name(name.to_owned())
        }
    };
    let name = match &selector {
        rpc::get_credential_request::Selector::Name(name) => Some(name.clone()),
        _ => None,
    };
    client
        .get_credential(rpc::GetCredentialRequest {
            selector: Some(selector),
            ..Default::default()
        })
        .await
        .map_err(|error| match name {
            Some(name) if error.code() == rpc::ErrorCode::NotFound => {
                anyhow::anyhow!(super::credentials::output::refusal::not_found(
                    "cloud", &name
                ))
            }
            _ => error.into(),
        })?
        .credential
        .into_option()
        .context("platform omitted credential metadata")
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
                "platform returned inconsistent SSH metadata"
            );
            let key = credential
                .ssh_public_key
                .as_option()
                .context("platform omitted SSH public key")?;
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
        assert!(rotation_notice(&current, None).contains("clears the hard expiry"));
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
            guided: false,
        };
        assert!(validate_key_arguments(&args).is_err());
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

    #[tokio::test]
    async fn platform_lifecycle_uses_exact_observed_revision_and_requires_prior_revocation() {
        use rpc::get_credential_request::Selector;
        let server = MockServer::start().await;
        let client = client(&server);
        expect_metadata(
            &server,
            Selector::Name("work".into()),
            rpc::CredentialStatus::Active,
        )
        .await;
        let error = execute(
            &client,
            CredentialsCommand::Delete(CredentialDeleteArgs {
                credential: Some("name:work".into()),
                yes: true,
            }),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("revoke the platform credential"));
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
        server.verify().await;
        server.reset().await;

        expect_metadata(
            &server,
            Selector::CredentialId(ID.into()),
            rpc::CredentialStatus::Active,
        )
        .await;
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
                credential: Some(metadata(rpc::CredentialStatus::Revoked)).into(),
                ..Default::default()
            },
        )
        .await;
        execute(
            &client,
            CredentialsCommand::Revoke(CredentialSelectorArgs {
                credential: format!("id:{ID}"),
                output: OutputFormat::Json,
            }),
        )
        .await
        .unwrap();
        server.verify().await;
        server.reset().await;

        expect_metadata(
            &server,
            Selector::Name("work".into()),
            rpc::CredentialStatus::Revoked,
        )
        .await;
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
        execute(
            &client,
            CredentialsCommand::Delete(CredentialDeleteArgs {
                credential: Some("work".into()),
                yes: true,
            }),
        )
        .await
        .unwrap();
        server.verify().await;
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
                CredentialsCommand::Revoke(CredentialSelectorArgs {
                    credential: "work".into(),
                    output: OutputFormat::Text,
                })
            )
            .await
            .is_err()
        );
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
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
                provider: Some(CredentialConnectProviderArg::Github),
                name: Some("other".into()),
                yes: true,
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
        assert!(find_named(&client(&server), "work").await.is_err());
        server.verify().await;
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
}
