//! Personal platform profile commands over the shared generated Rust client.

use anyhow::Context as _;
use codewire_access::{AccessProfileScope, CapabilitySlot};
use codewire_client::{self as rpc, CodewireClient};

use super::credentials::{
    ParsedCredentialSelector, ParsedProfileSelector, parse_credential_selector,
    parse_profile_selector,
};
use super::*;

pub(super) async fn handle_platform_credentials(
    globals: &Globals,
    command: CredentialsCommand,
) -> anyhow::Result<()> {
    let env = OsEnv;
    let paths = ResolvePaths::from_env(&env);
    let platform = resolve_platform(globals, &paths, &env)?;
    let client = CodewireClient::with_token_provider(
        rpc::ClientConfig::new(&platform.server_url)?
            .with_user_agent(format!("codewire-cli/{CLI_VERSION}"))?,
        platform.token_provider()?,
    )?;
    match command {
        CredentialsCommand::Profile { command } => handle_profile(&client, command).await,
        command => super::platform_credentials::handle(&client, command).await,
    }
}

async fn handle_profile(
    client: &CodewireClient,
    command: CredentialProfileCommand,
) -> anyhow::Result<()> {
    match command {
        CredentialProfileCommand::Create(args) => {
            let response = client
                .create_access_profile(rpc::CreateAccessProfileRequest {
                    name: args.name,
                    ..Default::default()
                })
                .await?;
            let profile = response
                .access_profile
                .into_option()
                .context("platform returned no profile")?;
            print_profiles(&[profile], OutputFormat::Text)
        }
        CredentialProfileCommand::List(args) => {
            let mut profiles = Vec::new();
            let mut page_token = String::new();
            let mut cursors = BTreeSet::new();
            loop {
                let page = client
                    .list_access_profiles(rpc::ListAccessProfilesRequest {
                        page_size: 100,
                        page_token,
                        ..Default::default()
                    })
                    .await?;
                profiles.extend(page.access_profiles);
                if page.next_page_token.is_empty() {
                    break;
                }
                if !cursors.insert(page.next_page_token.clone()) {
                    anyhow::bail!("platform returned a repeated profile cursor");
                }
                page_token = page.next_page_token;
            }
            print_profiles(&profiles, args.output)
        }
        CredentialProfileCommand::Get(args) => print_profiles(
            &[resolve_profile(client, &args.profile, args.revision).await?],
            args.output,
        ),
        CredentialProfileCommand::Set(args) => {
            let mut profile = resolve_profile(client, &args.profile, None).await?;
            let slot = CapabilitySlot::parse(args.slot)?.to_string();
            let credential = match parse_credential_selector(&args.credential)? {
                ParsedCredentialSelector::Id(id) => id.to_string(),
                ParsedCredentialSelector::Name(_) => {
                    super::platform_credentials::resolve(client, &args.credential)
                        .await?
                        .id
                }
            };
            profile
                .entries
                .retain(|entry| entry.capability_slot != slot);
            profile.entries.push(rpc::AccessProfileEntry {
                capability_slot: slot,
                credential_id: credential,
                ..Default::default()
            });
            update_profile(client, profile).await
        }
        CredentialProfileCommand::Unset(args) => {
            let mut profile = resolve_profile(client, &args.profile, None).await?;
            let slot = CapabilitySlot::parse(args.slot)?.to_string();
            let before = profile.entries.len();
            profile
                .entries
                .retain(|entry| entry.capability_slot != slot);
            if profile.entries.len() == before {
                anyhow::bail!("platform profile does not select that capability slot");
            }
            update_profile(client, profile).await
        }
        CredentialProfileCommand::Delete(args) => {
            let profile = resolve_profile(client, &args.profile, None).await?;
            if !args.yes
                && !prompt_confirm_default_no(&format!(
                    "Delete platform access profile {:?}?",
                    profile.name
                ))?
            {
                eprintln!("Canceled.");
                return Ok(());
            }
            client
                .delete_access_profile(rpc::DeleteAccessProfileRequest {
                    access_profile_id: profile.id,
                    expected_revision: profile.revision,
                    ..Default::default()
                })
                .await?;
            eprintln!("Platform access profile deleted.");
            Ok(())
        }
        CredentialProfileCommand::Revisions(_) => anyhow::bail!(
            "inspect a platform revision with profile get PROFILE --revision REVISION"
        ),
        CredentialProfileCommand::Bind(args) => {
            if !args.confirm_personal_credentials {
                anyhow::bail!(
                    "binding personal credentials requires --confirm-personal-credentials"
                );
            }
            let environment = canonical_environment(&args.environment)?;
            let profile = resolve_profile(client, &args.profile, None).await?;
            let expected = if args.replace {
                Some(get_binding(client, &environment).await?)
            } else {
                None
            };
            let binding = rpc::EnvironmentAccessProfileBinding {
                environment_id: environment,
                access_profile_id: profile.id,
                access_profile_revision: profile.revision,
                ..Default::default()
            };
            let response = client
                .set_environment_access_profile(rpc::SetEnvironmentAccessProfileRequest {
                    binding: Some(binding).into(),
                    expected_binding: expected.into(),
                    confirm_personal_credentials: true,
                    ..Default::default()
                })
                .await?;
            print_binding(
                &response
                    .binding
                    .into_option()
                    .context("platform returned no binding")?,
                OutputFormat::Text,
            )
        }
        CredentialProfileCommand::Binding(args) => {
            let environment = canonical_environment(&args.environment)?;
            print_binding(&get_binding(client, &environment).await?, args.output)
        }
        CredentialProfileCommand::Unbind(args) => {
            let environment = canonical_environment(&args.environment)?;
            let binding = get_binding(client, &environment).await?;
            if !args.yes
                && !prompt_confirm_default_no(&format!(
                    "Clear the platform access profile for environment {environment}?"
                ))?
            {
                eprintln!("Canceled.");
                return Ok(());
            }
            client
                .clear_environment_access_profile(rpc::ClearEnvironmentAccessProfileRequest {
                    expected_binding: Some(binding).into(),
                    ..Default::default()
                })
                .await?;
            eprintln!("Platform environment access profile cleared.");
            Ok(())
        }
    }
}

async fn resolve_profile(
    client: &CodewireClient,
    selector: &str,
    revision: Option<u64>,
) -> anyhow::Result<rpc::AccessProfile> {
    let selector = profile_selector(selector)?;
    let response = client
        .get_access_profile(rpc::GetAccessProfileRequest {
            selector: Some(selector),
            revision,
            ..Default::default()
        })
        .await?;
    response
        .access_profile
        .into_option()
        .context("platform returned no profile")
}

fn profile_selector(selector: &str) -> anyhow::Result<rpc::get_access_profile_request::Selector> {
    use rpc::get_access_profile_request::Selector;
    Ok(match parse_profile_selector(selector)? {
        ParsedProfileSelector::Id(id) => Selector::AccessProfileId(id.to_string()),
        ParsedProfileSelector::Name(name) => Selector::Name(name.to_string()),
        ParsedProfileSelector::Reference(reference) => {
            if reference.scope() != AccessProfileScope::User {
                anyhow::bail!("only personal user/ profiles are supported on the platform");
            }
            Selector::Name(reference.name().to_string())
        }
    })
}

async fn update_profile(
    client: &CodewireClient,
    profile: rpc::AccessProfile,
) -> anyhow::Result<()> {
    // Exactly one read/modify/CAS attempt. A conflict is returned to the user;
    // never refetch and silently overwrite a concurrent owner's change.
    let response = client
        .update_access_profile(rpc::UpdateAccessProfileRequest {
            access_profile_id: profile.id,
            expected_revision: profile.revision,
            entries: profile.entries,
            ..Default::default()
        })
        .await?;
    print_profiles(
        &[response
            .access_profile
            .into_option()
            .context("platform returned no profile")?],
        OutputFormat::Text,
    )
}

async fn get_binding(
    client: &CodewireClient,
    environment: &str,
) -> anyhow::Result<rpc::EnvironmentAccessProfileBinding> {
    let response = client
        .get_environment_access_profile(rpc::GetEnvironmentAccessProfileRequest {
            environment_id: environment.to_owned(),
            ..Default::default()
        })
        .await?;
    response
        .binding
        .into_option()
        .context("platform returned no binding")
}

fn canonical_environment(value: &str) -> anyhow::Result<String> {
    let id = uuid::Uuid::parse_str(value)
        .context("binding commands require an exact environment UUID")?;
    if id.to_string() != value {
        anyhow::bail!("environment UUID must be canonical lowercase text");
    }
    Ok(id.to_string())
}

fn print_profiles(profiles: &[rpc::AccessProfile], output: OutputFormat) -> anyhow::Result<()> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(profiles)?),
        OutputFormat::Text => {
            for profile in profiles {
                println!(
                    "{}\tuser/{}\trevision {}",
                    profile.id, profile.name, profile.revision
                );
                for entry in &profile.entries {
                    println!("  {}\t{}", entry.capability_slot, entry.credential_id);
                }
            }
        }
    }
    Ok(())
}

fn print_binding(
    binding: &rpc::EnvironmentAccessProfileBinding,
    output: OutputFormat,
) -> anyhow::Result<()> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(binding)?),
        OutputFormat::Text => println!(
            "{}\t{}\trevision {}",
            binding.environment_id, binding.access_profile_id, binding.access_profile_revision
        ),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use buffa::Message as _;
    use wiremock::matchers::{body_bytes, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const ENVIRONMENT: &str = "3d6bb495-efac-419f-bf3a-91696e7c7ca4";
    const PROFILE: &str = "d0f68b45-7c8b-43eb-9b8c-62a33b279c88";
    const REPLACEMENT_PROFILE: &str = "b06643dd-b999-45ac-b0b2-f76cb5aabfe7";
    const REVISION: u64 = 9_007_199_254_740_993;

    fn client(server: &MockServer) -> CodewireClient {
        CodewireClient::with_http(
            rpc::ClientConfig::new(server.uri()).unwrap(),
            rpc::StaticTokenProvider::new("synthetic-profile-cli-token").unwrap(),
            reqwest::Client::new(),
        )
        .unwrap()
    }

    async fn expect_success(
        server: &MockServer,
        name: &str,
        request: impl buffa::Message,
        response: impl buffa::Message,
    ) {
        Mock::given(method("POST"))
            .and(path(format!("/codewire.v1.AccessProfileService/{name}")))
            .and(header(
                "authorization",
                "Bearer synthetic-profile-cli-token",
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

    fn binding() -> rpc::EnvironmentAccessProfileBinding {
        rpc::EnvironmentAccessProfileBinding {
            environment_id: ENVIRONMENT.into(),
            access_profile_id: PROFILE.into(),
            access_profile_revision: REVISION,
            ..Default::default()
        }
    }

    async fn expect_profile(server: &MockServer) {
        expect_success(
            server,
            "GetAccessProfile",
            rpc::GetAccessProfileRequest {
                selector: Some(rpc::get_access_profile_request::Selector::Name(
                    "work".into(),
                )),
                ..Default::default()
            },
            rpc::GetAccessProfileResponse {
                access_profile: Some(rpc::AccessProfile {
                    id: PROFILE.into(),
                    name: "work".into(),
                    revision: REVISION,
                    ..Default::default()
                })
                .into(),
                ..Default::default()
            },
        )
        .await;
    }

    #[tokio::test]
    async fn profile_set_resolves_personal_credential_name_before_exact_revision_update() {
        let server = MockServer::start().await;
        expect_profile(&server).await;
        let credential_id = "b419132c-641f-49b7-a7fc-0b7d4a135d63";
        Mock::given(method("POST"))
            .and(path("/codewire.v1.CredentialService/GetCredential"))
            .and(header(
                "authorization",
                "Bearer synthetic-profile-cli-token",
            ))
            .and(body_bytes(
                rpc::GetCredentialRequest {
                    selector: Some(rpc::get_credential_request::Selector::Name(
                        "codex-work".into(),
                    )),
                    ..Default::default()
                }
                .encode_to_vec(),
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/proto")
                    .set_body_bytes(
                        rpc::GetCredentialResponse {
                            credential: Some(rpc::Credential {
                                id: credential_id.into(),
                                ..Default::default()
                            })
                            .into(),
                            ..Default::default()
                        }
                        .encode_to_vec(),
                    ),
            )
            .expect(1)
            .mount(&server)
            .await;
        expect_success(
            &server,
            "UpdateAccessProfile",
            rpc::UpdateAccessProfileRequest {
                access_profile_id: PROFILE.into(),
                expected_revision: REVISION,
                entries: vec![rpc::AccessProfileEntry {
                    capability_slot: CapabilitySlot::codex().to_string(),
                    credential_id: credential_id.into(),
                    ..Default::default()
                }],
                ..Default::default()
            },
            rpc::UpdateAccessProfileResponse {
                access_profile: Some(rpc::AccessProfile {
                    id: PROFILE.into(),
                    name: "work".into(),
                    revision: REVISION + 1,
                    ..Default::default()
                })
                .into(),
                ..Default::default()
            },
        )
        .await;
        handle_profile(
            &client(&server),
            CredentialProfileCommand::Set(CredentialProfileSetArgs {
                profile: "user/work".into(),
                slot: CapabilitySlot::codex().to_string(),
                credential: "name:codex-work".into(),
            }),
        )
        .await
        .unwrap();
        server.verify().await;
        assert_eq!(server.received_requests().await.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn binding_requires_explicit_consent_before_any_network_request() {
        let server = MockServer::start().await;
        let error = handle_profile(
            &client(&server),
            CredentialProfileCommand::Bind(CredentialProfileBindArgs {
                profile: "user/work".into(),
                environment: ENVIRONMENT.into(),
                confirm_personal_credentials: false,
                replace: false,
            }),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("--confirm-personal-credentials"));
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn binding_create_and_clear_preserve_exact_observed_revision() {
        let server = MockServer::start().await;
        let client = client(&server);
        expect_profile(&server).await;
        expect_success(
            &server,
            "SetEnvironmentAccessProfile",
            rpc::SetEnvironmentAccessProfileRequest {
                binding: Some(binding()).into(),
                confirm_personal_credentials: true,
                ..Default::default()
            },
            rpc::SetEnvironmentAccessProfileResponse {
                binding: Some(binding()).into(),
                ..Default::default()
            },
        )
        .await;
        handle_profile(
            &client,
            CredentialProfileCommand::Bind(CredentialProfileBindArgs {
                profile: "user/work".into(),
                environment: ENVIRONMENT.into(),
                confirm_personal_credentials: true,
                replace: false,
            }),
        )
        .await
        .unwrap();
        expect_success(
            &server,
            "GetEnvironmentAccessProfile",
            rpc::GetEnvironmentAccessProfileRequest {
                environment_id: ENVIRONMENT.into(),
                ..Default::default()
            },
            rpc::GetEnvironmentAccessProfileResponse {
                binding: Some(binding()).into(),
                personal_credentials_confirmed: true,
                ..Default::default()
            },
        )
        .await;
        expect_success(
            &server,
            "ClearEnvironmentAccessProfile",
            rpc::ClearEnvironmentAccessProfileRequest {
                expected_binding: Some(binding()).into(),
                ..Default::default()
            },
            rpc::ClearEnvironmentAccessProfileResponse::default(),
        )
        .await;
        handle_profile(
            &client,
            CredentialProfileCommand::Unbind(CredentialProfileUnbindArgs {
                environment: ENVIRONMENT.into(),
                yes: true,
            }),
        )
        .await
        .unwrap();
        server.verify().await;
    }

    #[tokio::test]
    async fn replacement_reports_conflict_without_refetching_or_retrying() {
        let server = MockServer::start().await;
        expect_profile(&server).await;
        let expected = rpc::EnvironmentAccessProfileBinding {
            access_profile_id: REPLACEMENT_PROFILE.into(),
            access_profile_revision: REVISION - 2,
            ..binding()
        };
        expect_success(
            &server,
            "GetEnvironmentAccessProfile",
            rpc::GetEnvironmentAccessProfileRequest {
                environment_id: ENVIRONMENT.into(),
                ..Default::default()
            },
            rpc::GetEnvironmentAccessProfileResponse {
                binding: Some(expected.clone()).into(),
                personal_credentials_confirmed: true,
                ..Default::default()
            },
        )
        .await;
        Mock::given(method("POST"))
            .and(path(
                "/codewire.v1.AccessProfileService/SetEnvironmentAccessProfile",
            ))
            .and(body_bytes(
                rpc::SetEnvironmentAccessProfileRequest {
                    binding: Some(binding()).into(),
                    expected_binding: Some(expected).into(),
                    confirm_personal_credentials: true,
                    ..Default::default()
                }
                .encode_to_vec(),
            ))
            .respond_with(ResponseTemplate::new(409).set_body_json(serde_json::json!({
                "code": "already_exists", "message": "conflict"
            })))
            .expect(1)
            .mount(&server)
            .await;
        assert!(
            handle_profile(
                &client(&server),
                CredentialProfileCommand::Bind(CredentialProfileBindArgs {
                    profile: "user/work".into(),
                    environment: ENVIRONMENT.into(),
                    confirm_personal_credentials: true,
                    replace: true,
                })
            )
            .await
            .is_err()
        );
        server.verify().await;
        assert_eq!(server.received_requests().await.unwrap().len(), 3);
    }

    #[test]
    fn platform_profile_selectors_are_personal_and_exact() {
        assert_eq!(
            profile_selector("user/work").unwrap(),
            rpc::get_access_profile_request::Selector::Name("work".into())
        );
        assert!(profile_selector("organization/work").is_err());
        assert!(profile_selector("id:not-a-uuid").is_err());
        assert!(canonical_environment("environment-name").is_err());
        assert!(canonical_environment("3D6BB495-EFAC-419F-BF3A-91696E7C7CA4").is_err());
    }
}
