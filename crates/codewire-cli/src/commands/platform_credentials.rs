//! Personal platform credential commands: write-only keys and managed OAuth.

use codewire_client::{self as rpc, CodewireClient};

use super::credential_input::{
    CLAUDE_SUBSCRIPTION_TOKEN_GUIDANCE, CLAUDE_SUBSCRIPTION_TOKEN_PROMPT,
    CODEX_DEVICE_AUTHORIZATION_GUIDANCE, ParsedCredentialSelector, SSH_PUBLIC_KEY_GITHUB_HINT,
    parse_credential_selector, prompt_claude_code, prompt_credential_material,
    prompt_named_material, read_ssh_import, validate_ssh_generation, validate_ssh_import,
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

pub(super) async fn handle(
    client: &CodewireClient,
    command: CredentialsCommand,
) -> anyhow::Result<()> {
    match command {
        CredentialsCommand::Generate(args) => generate_ssh(client, &args).await.map(drop),
        CredentialsCommand::Connect(args) => {
            let (provider, kind, label) = match args.provider {
                CredentialConnectProviderArg::Codex => {
                    ("openai", rpc::CredentialAuthenticationKind::Oauth, "Codex")
                }
                CredentialConnectProviderArg::Github => {
                    ("github", rpc::CredentialAuthenticationKind::Oauth, "GitHub")
                }
                CredentialConnectProviderArg::Claude => (
                    "anthropic",
                    rpc::CredentialAuthenticationKind::ClaudeSignIn,
                    "Claude",
                ),
            };
            let name = trimmed_required(&args.name, "credential name")?.to_owned();
            let current = find_named(client, &name).await?;
            let request = oauth_connection_request(provider, kind, &name, current.as_ref())?;
            if let Some(current) = &current {
                anyhow::ensure!(
                    args.yes || (std::io::stdin().is_terminal() && std::io::stderr().is_terminal()),
                    "reconnecting an existing platform OAuth credential requires terminal confirmation or --yes"
                );
                let message = format!(
                    "Reconnect platform {label} credential {:?} ({}, revision {})? Its identity, profile bindings and hard expiry will be kept.",
                    current.name, current.id, current.revocation_generation
                );
                if args.yes {
                    eprintln!("{message}");
                } else if !prompt_confirm_default_no(&message)? {
                    eprintln!("Canceled; no credential was changed.");
                    return Ok(());
                }
            }
            // The Claude sign-in is started and its code read before the
            // cancellable exchange, so Ctrl-C at the prompt simply exits.
            let claude = match args.provider {
                CredentialConnectProviderArg::Claude => Some(start_claude_sign_in(client).await?),
                _ => None,
            };
            let enrollment = async {
                match args.provider {
                    CredentialConnectProviderArg::Claude => {
                        let (sign_in, pasted) = claude.expect("started above");
                        client
                            .complete_claude_sign_in(rpc::CompleteClaudeSignInRequest {
                                name: request.name,
                                sign_in,
                                authorization_code: pasted.expose_secret().to_vec(),
                                credential_id: request.credential_id,
                                expected_revocation_generation: request
                                    .expected_revocation_generation,
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
                            .map(|credential| (credential, Vec::new()))
                    }
                    CredentialConnectProviderArg::Codex => {
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
                                        label,
                                        &challenge.verification_url,
                                        &challenge.user_code,
                                    )
                                },
                            )
                            .await
                            .map(|credential| (credential, Vec::new()))
                    }
                    CredentialConnectProviderArg::Github => client
                        .enroll_github(
                            rpc::EnrollGithubRequest {
                                name: request.name,
                                credential_id: request.credential_id,
                                expected_revocation_generation: request
                                    .expected_revocation_generation,
                                ..Default::default()
                            },
                            |challenge| {
                                display_challenge(
                                    label,
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
                _ = tokio::signal::ctrl_c() => {
                    anyhow::bail!("enrollment cancelled; inspect the credential by name before retrying because storage acknowledgement may be unknown");
                }
            };
            eprint!(
                "\n{}",
                login_screen::success_screen(signed_in_account(&credential))
            );
            print(&[credential], OutputFormat::Text)?;
            super::credentials::report_github_pending(github_pending(&pending));
            Ok(())
        }
        CredentialsCommand::List(args) => {
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
                    break;
                }
                if !cursors.insert(page.next_page_token.clone()) {
                    anyhow::bail!("platform returned a repeated credential cursor");
                }
                page_token = page.next_page_token;
            }
            print(&credentials, args.output)?;
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
            print(std::slice::from_ref(&credential), args.output)?;
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
            client.delete_credential(rpc::DeleteCredentialRequest {
                credential_id: current.id,
                expected_revocation_generation: current.revocation_generation,
                ..Default::default()
            }).await.context("delete exact revoked platform credential revision; inspect metadata before retrying an uncertain result")?;
            eprintln!("Platform credential {:?} deleted.", current.name);
            Ok(())
        }
        CredentialsCommand::Add(args) => {
            if args.provider == "ssh" {
                let name = validate_ssh_import(&args)?;
                // Confirm owner-scoped access and name availability before
                // reading the explicitly selected private file or passphrase.
                anyhow::ensure!(
                    find_named(client, &name).await?.is_none(),
                    "credential name already exists"
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
                        .context("platform omitted SSH metadata")?],
                    OutputFormat::Text,
                );
            }
            if args.provider == CLAUDE_SUBSCRIPTION {
                let name = validate_subscription_token_arguments(&args)?;
                // Confirm owner-scoped access and name availability before
                // asking for the token.
                anyhow::ensure!(
                    find_named(client, &name).await?.is_none(),
                    "credential name already exists; replace its token with `credentials rotate`"
                );
                eprintln!("{CLAUDE_SUBSCRIPTION_TOKEN_GUIDANCE}");
                let token = prompt_named_material(CLAUDE_SUBSCRIPTION_TOKEN_PROMPT)?;
                let response = client
                    .add_claude_subscription_token_credential(
                        rpc::AddClaudeSubscriptionTokenCredentialRequest {
                            name,
                            token: token.expose_secret().to_vec(),
                            ..Default::default()
                        },
                    )
                    .await
                    .context("add platform Claude subscription token; inspect by name before retrying an uncertain acknowledgement")?;
                return print(
                    &[response
                        .credential
                        .into_option()
                        .context("platform omitted credential metadata")?],
                    OutputFormat::Text,
                );
            }
            validate_key_arguments(&args)?;
            let material = prompt_credential_material()?;
            let response = client.add_api_key_credential(rpc::AddApiKeyCredentialRequest {
                provider: args.provider,
                name: args.name.trim().to_owned(),
                value: material.expose_secret().to_vec(),
                expires_at_unix: args.expires_at,
                ..Default::default()
            }).await.context("add platform API key; inspect by name before retrying an uncertain acknowledgement")?;
            print(
                &[response
                    .credential
                    .into_option()
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
                return replace_subscription_token(client, current, args.expires_at).await;
            }
            let expected = rotation_metadata(&current, args.expires_at)?;
            eprintln!("{}", rotation_notice(&current, args.expires_at));
            let material = prompt_credential_material()?;
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

fn is_claude_sign_in(credential: &rpc::Credential) -> bool {
    credential.provider == "anthropic"
        && credential.authentication_kind == rpc::CredentialAuthenticationKind::ClaudeSignIn
}

fn validate_subscription_token_arguments(args: &CredentialAddArgs) -> anyhow::Result<String> {
    anyhow::ensure!(
        args.key_file.is_none(),
        "--key-file is only valid for add ssh"
    );
    anyhow::ensure!(
        args.account_hint.is_none(),
        "Claude subscription tokens do not use --account-hint"
    );
    anyhow::ensure!(
        args.expires_at.is_none(),
        "a Claude subscription token's expiry is recorded as one year after it is added; --expires-at is not accepted"
    );
    Ok(trimmed_required(&args.name, "credential name")?.to_owned())
}

/// Replace an exact existing Claude subscription token with a newly pasted
/// one. Its identity and profile bindings are kept, it is reactivated, and
/// its one-year expiry restarts.
async fn replace_subscription_token(
    client: &CodewireClient,
    current: rpc::Credential,
    expiry: Option<u64>,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        expiry.is_none(),
        "a Claude subscription token's replacement restarts its one-year expiry; --expires-at is not accepted"
    );
    anyhow::ensure!(
        current.revocation_generation > 0 && current.revocation_generation < i64::MAX as u64,
        "platform returned an invalid credential revision"
    );
    eprintln!(
        "Replacing the token of Claude subscription credential {:?} ({}, revision {}) sets its status to Active (including if revoked) and restarts its one-year expiry. {CLAUDE_SUBSCRIPTION_TOKEN_GUIDANCE}",
        current.name, current.id, current.revocation_generation
    );
    let token = prompt_named_material(CLAUDE_SUBSCRIPTION_TOKEN_PROMPT)?;
    let response = client
        .add_claude_subscription_token_credential(rpc::AddClaudeSubscriptionTokenCredentialRequest {
            name: current.name.clone(),
            token: token.expose_secret().to_vec(),
            credential_id: Some(current.id.clone()),
            expected_revocation_generation: Some(current.revocation_generation),
            ..Default::default()
        })
        .await
        .context("replace exact platform Claude subscription token; inspect metadata before retrying an uncertain result")?;
    drop(token);
    let replaced = response
        .credential
        .into_option()
        .context("platform omitted replaced metadata")?;
    anyhow::ensure!(
        replaced.id == current.id
            && replaced.name == current.name
            && is_subscription_token(&replaced)
            && replaced.status == rpc::CredentialStatus::Active
            && replaced.revocation_generation == current.revocation_generation + 1
            && replaced.expires_at_unix.is_some(),
        "platform returned unexpected credential metadata; inspect the identity before retrying the uncertain result"
    );
    print(&[replaced], OutputFormat::Text)
}

fn rotation_metadata(
    current: &rpc::Credential,
    expiry: Option<u64>,
) -> anyhow::Result<rpc::Credential> {
    anyhow::ensure!(
        matches!(current.provider.as_str(), "openai" | "anthropic")
            && current.authentication_kind == rpc::CredentialAuthenticationKind::ApiKey,
        "rotate supports OpenAI/Anthropic API keys and Claude subscription tokens; use connect to reconnect OAuth or generate/add for a new SSH identity"
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
    let deadline = expiry.map_or_else(
        || "clears the hard expiry".to_owned(),
        |expiry| format!("sets the hard expiry to Unix timestamp {expiry}"),
    );
    format!(
        "Rotating platform API key {:?} ({}, revision {}) sets its status to Active (including if revoked) and {deadline}. Enter the replacement key to proceed.",
        current.name, current.id, current.revocation_generation
    )
}

fn validate_update_ack(expected: &rpc::Credential, actual: &rpc::Credential) -> anyhow::Result<()> {
    anyhow::ensure!(
        expected == actual,
        "platform returned unexpected credential metadata; inspect the identity before retrying the uncertain result"
    );
    Ok(())
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
fn display_challenge(provider: &str, url: &str, code: &str) -> bool {
    show_sign_in_link(url);
    eprint!("{}", login_screen::device_code_lines(provider, code));
    true
}

/// The link screen, then the browser at a terminal. The link is on its own
/// line first, so it works when no browser opens; the browser is started
/// fully detached, so nothing it prints reaches a prompt.
fn show_sign_in_link(url: &str) {
    login_screen::show_link(url);
    if std::io::stdin().is_terminal() && std::io::stderr().is_terminal() {
        let _ = super::platform_commands::open_browser(url);
    }
}

/// The account a connected credential names: its account hint (an email or
/// login), or its name when the provider gave none. Metadata only.
fn signed_in_account(credential: &rpc::Credential) -> &str {
    credential
        .account_hint
        .as_deref()
        .map(str::trim)
        .filter(|hint| !hint.is_empty())
        .unwrap_or(&credential.name)
}

/// Start a Claude sign-in, show where to sign in, and read the code Claude
/// shows from a no-echo prompt or stdin, never argv, as `code#state` (see
/// [`prompt_claude_code`]). The returned handle stays in this process.
async fn start_claude_sign_in(
    client: &CodewireClient,
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
    show_sign_in_link(&started.authorize_url);
    eprintln!();
    let pasted = prompt_claude_code()?;
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
        matches!(args.provider.as_str(), "openai" | "anthropic"),
        "API-key enrollment supports openai or anthropic; use add claude-subscription for a Claude subscription token or connect for OAuth"
    );
    trimmed_required(&args.name, "credential name")?;
    anyhow::ensure!(
        args.account_hint.is_none(),
        "platform API keys do not use --account-hint"
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
    client
        .get_credential(rpc::GetCredentialRequest {
            selector: Some(selector),
            ..Default::default()
        })
        .await?
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
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(credentials)?),
        OutputFormat::Text => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            for credential in credentials {
                let status = text_status(credential, now)?;
                let provider = if is_subscription_token(credential) {
                    "anthropic (Claude subscription token)"
                } else if is_claude_sign_in(credential) {
                    "anthropic (Claude sign-in)"
                } else {
                    credential.provider.as_str()
                };
                println!(
                    "{}  {:?}  {}  {}  revision {}",
                    credential.id,
                    credential.name,
                    provider,
                    status,
                    credential.revocation_generation
                );
                if let Some(expiry) = credential.expires_at_unix.and_then(expiry_date) {
                    println!("  expires {expiry}");
                }
                if let Some(key) = credential.ssh_public_key.as_option() {
                    println!("  {}\n  {}", key.openssh, key.fingerprint);
                }
            }
        }
    }
    Ok(())
}

/// The status `list` and `get` print. The broker withholds a credential past
/// its recorded hard expiry whatever its stored status, so an Active one past
/// that moment reads expired.
fn text_status(credential: &rpc::Credential, now: u64) -> anyhow::Result<&'static str> {
    Ok(if credential.status == rpc::CredentialStatus::Active {
        if credential
            .expires_at_unix
            .is_some_and(|expiry| expiry <= now)
        {
            "expired"
        } else {
            "active"
        }
    } else if credential.status == rpc::CredentialStatus::Revoked {
        "revoked"
    } else if credential.status == rpc::CredentialStatus::Expired {
        "expired"
    } else if credential.status == rpc::CredentialStatus::RefreshFailed {
        "refresh_failed"
    } else {
        anyhow::bail!("platform returned an unsupported credential status")
    })
}

/// A recorded hard expiry as a UTC date and time.
fn expiry_date(expiry: u64) -> Option<String> {
    let expiry = i64::try_from(expiry).ok()?;
    chrono::DateTime::<chrono::Utc>::from_timestamp(expiry, 0)
        .map(|at| at.format("%Y-%m-%d %H:%M UTC").to_string())
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
            let result = handle(
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
        assert!(rotation_notice(&current, Some(4_000_000_000)).contains("4000000000"));
        let mut wrong = expected.clone();
        wrong.id = "different-identity".into();
        assert!(validate_update_ack(&expected, &wrong).is_err());
        current.provider = "github".into();
        assert!(rotation_metadata(&current, None).is_err());
    }

    #[test]
    fn subscription_token_add_rejects_argv_expiry_hint_and_key_file_before_input() {
        let args = |expires_at: Option<u64>, account_hint: Option<&str>, key_file: bool| {
            CredentialAddArgs {
                provider: CLAUDE_SUBSCRIPTION.into(),
                name: " claude ".into(),
                account_hint: account_hint.map(str::to_owned),
                expires_at,
                key_file: key_file.then(|| "/dev/null".into()),
            }
        };
        assert_eq!(
            validate_subscription_token_arguments(&args(None, None, false)).unwrap(),
            "claude"
        );
        for invalid in [
            args(Some(4_000_000_000), None, false),
            args(None, Some("person@example.test"), false),
            args(None, None, true),
        ] {
            assert!(validate_subscription_token_arguments(&invalid).is_err());
        }
        let mut blank = args(None, None, false);
        blank.name = "  ".into();
        assert!(validate_subscription_token_arguments(&blank).is_err());
        // An API-key add never accepts the subscription provider word.
        assert!(validate_key_arguments(&args(None, None, false)).is_err());
        assert!(CLAUDE_SUBSCRIPTION_TOKEN_GUIDANCE.contains("claude setup-token"));
    }

    #[test]
    fn listed_status_reads_expired_past_the_recorded_expiry_with_a_date() {
        let mut credential = metadata(rpc::CredentialStatus::Active);
        credential.provider = "anthropic".into();
        credential.authentication_kind = rpc::CredentialAuthenticationKind::Oauth.into();
        credential.expires_at_unix = Some(1_800_000_000);
        assert_eq!(text_status(&credential, 1_799_999_999).unwrap(), "active");
        assert_eq!(text_status(&credential, 1_800_000_000).unwrap(), "expired");
        credential.status = rpc::CredentialStatus::Revoked.into();
        assert_eq!(text_status(&credential, 1_900_000_000).unwrap(), "revoked");
        credential.expires_at_unix = None;
        credential.status = rpc::CredentialStatus::Active.into();
        assert_eq!(text_status(&credential, u64::MAX).unwrap(), "active");
        assert_eq!(
            expiry_date(1_800_000_000).as_deref(),
            Some("2027-01-15 08:00 UTC")
        );
        assert_eq!(expiry_date(u64::MAX), None);
    }

    #[tokio::test]
    async fn subscription_token_rotation_is_a_replacement_that_refuses_an_explicit_expiry() {
        let server = MockServer::start().await;
        let client = client(&server);
        let mut current = metadata(rpc::CredentialStatus::RefreshFailed);
        current.provider = "anthropic".into();
        current.authentication_kind = rpc::CredentialAuthenticationKind::Oauth.into();
        assert!(is_subscription_token(&current));
        // Refused before any prompt or request.
        let error = replace_subscription_token(&client, current.clone(), Some(4_000_000_000))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("--expires-at"));
        assert!(server.received_requests().await.unwrap().is_empty());
        // API-key rotation still refuses the subscription form.
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
        let error = handle(
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
        handle(
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
        handle(
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
            handle(
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
        let error = handle(
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
            provider: "codex".into(),
            name: "work".into(),
            account_hint: None,
            expires_at: None,
            key_file: None,
        });
        assert!(handle(&client, command).await.is_err());
        assert!(server.received_requests().await.unwrap().is_empty());
        // Rotation must inspect the stored kind, then reject unsupported
        // material before prompting or sending any mutation.
        expect_metadata(
            &server,
            rpc::get_credential_request::Selector::Name("work".into()),
            rpc::CredentialStatus::Active,
        )
        .await;
        let error = handle(
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
                .contains("rotate supports OpenAI/Anthropic API keys")
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
