//! Personal platform credential commands; protected values never cross this API.

use anyhow::Context as _;
use codewire_client::{self as rpc, CodewireClient};

use super::credentials::{ParsedCredentialSelector, parse_credential_selector};
use super::*;

pub(super) async fn handle(
    client: &CodewireClient,
    command: CredentialsCommand,
) -> anyhow::Result<()> {
    match command {
        CredentialsCommand::Connect(args) => {
            if !matches!(args.provider, CredentialConnectProviderArg::Codex) {
                anyhow::bail!("platform enrollment currently supports Codex only");
            }
            let name = trimmed_required(&args.name, "credential name")?.to_owned();
            let enrollment = client.enroll_codex(
                rpc::EnrollCodexRequest {
                    name,
                    ..Default::default()
                },
                |challenge| {
                    eprintln!(
                        "Open {} and enter {}",
                        challenge.verification_url, challenge.user_code
                    );
                    eprintln!("Continue only if you started this Codex login.");
                    true
                },
            );
            let credential = tokio::select! {
                result = enrollment => result.context("enroll platform Codex credential")?,
                _ = tokio::signal::ctrl_c() => {
                    anyhow::bail!("enrollment cancelled; inspect the credential by name before retrying because storage acknowledgement may be unknown");
                }
            };
            print(&[credential], OutputFormat::Text)
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
            print(&credentials, args.output)
        }
        CredentialsCommand::Get(args) => {
            print(&[resolve(client, &args.credential).await?], args.output)
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
            let current = resolve(client, &args.credential).await?;
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
        CredentialsCommand::Add(_) => anyhow::bail!(
            "platform credentials cannot be uploaded as raw values; use credentials --platform connect codex --name NAME"
        ),
        CredentialsCommand::Rename(_) | CredentialsCommand::Rotate(_) => {
            anyhow::bail!("platform credential rename and explicit rotation are not supported yet")
        }
        CredentialsCommand::Profile { .. } => unreachable!("profiles have a separate dispatcher"),
    }
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

fn print(credentials: &[rpc::Credential], output: OutputFormat) -> anyhow::Result<()> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(credentials)?),
        OutputFormat::Text => {
            for credential in credentials {
                let status = if credential.status == rpc::CredentialStatus::Active {
                    "active"
                } else if credential.status == rpc::CredentialStatus::Revoked {
                    "revoked"
                } else if credential.status == rpc::CredentialStatus::Expired {
                    "expired"
                } else if credential.status == rpc::CredentialStatus::RefreshFailed {
                    "refresh_failed"
                } else {
                    anyhow::bail!("platform returned an unsupported credential status")
                };
                println!(
                    "{}  {:?}  {}  {}  revision {}",
                    credential.id,
                    credential.name,
                    credential.provider,
                    status,
                    credential.revocation_generation
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use buffa::Message as _;
    use wiremock::matchers::{body_bytes, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const ID: &str = "fdd5612f-12ca-4a21-9557-dc4875f9c1f6";
    const REVISION: u64 = 9_007_199_254_740_993;

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
                credential: "name:work".into(),
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
                credential: "work".into(),
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
    async fn platform_unsupported_paths_never_read_raw_input_or_contact_server() {
        let server = MockServer::start().await;
        let client = client(&server);
        for command in [
            CredentialsCommand::Add(CredentialAddArgs {
                provider: "openai".into(),
                kind: CredentialAuthenticationKindArg::Oauth,
                name: "work".into(),
                account_hint: None,
                expires_at: None,
            }),
            CredentialsCommand::Connect(CredentialConnectArgs {
                provider: CredentialConnectProviderArg::Github,
                name: "work".into(),
            }),
            CredentialsCommand::Rename(CredentialRenameArgs {
                credential: "work".into(),
                name: "other".into(),
            }),
            CredentialsCommand::Rotate(CredentialRotateArgs {
                credential: "work".into(),
                expires_at: None,
            }),
        ] {
            assert!(handle(&client, command).await.is_err());
        }
        assert!(server.received_requests().await.unwrap().is_empty());
    }
}
