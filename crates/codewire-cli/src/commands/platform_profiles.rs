//! Platform profile metadata over the shared generated Rust client.
//! The current service is personal-only. Organization selectors fail explicitly
//! until the owner-aware public contract is composed; no fallback is permitted.

use anyhow::Context as _;
use codewire_access::{AccessProfileScope, CredentialAuthKind, ProviderId};
use codewire_client::{self as rpc, CodewireClient};

use super::credentials::{
    CredentialOperation, ParsedProfileSelector, parse_profile_selector, supported_profile_slot,
};
use super::*;

pub(super) async fn handle_platform_credentials(
    globals: &Globals,
    operation: CredentialOperation,
) -> anyhow::Result<()> {
    let env = OsEnv;
    let paths = ResolvePaths::from_env(&env);
    let platform = resolve_platform(globals, &paths, &env)?;
    let client = CodewireClient::with_token_provider(
        rpc::ClientConfig::new(&platform.server_url)?
            .with_user_agent(format!("codewire-cli/{CLI_VERSION}"))?,
        platform.token_provider()?,
    )?;
    match operation {
        CredentialOperation::Profile(command) => handle_profile(&client, command).await,
        CredentialOperation::Credential(command) => {
            super::platform_credentials::handle(&client, command).await
        }
    }
}

async fn handle_profile(
    client: &CodewireClient,
    command: CredentialProfileCommand,
) -> anyhow::Result<()> {
    match command {
        CredentialProfileCommand::List(args) => {
            print_profiles(&list_profiles(client).await?, args.output)
        }
        CredentialProfileCommand::Get(args) => print_profiles(
            &[resolve_profile(client, &args.profile, args.revision).await?],
            args.output,
        ),
        CredentialProfileCommand::Set(args) => {
            let credential = super::platform_credentials::resolve(client, &args.credential).await?;
            let kind = platform_authentication_kind(&credential)?;
            let slot = supported_profile_slot(
                &args.slot,
                &ProviderId::parse(&credential.provider)?,
                kind,
            )?
            .to_string();
            let (profile, name) = profile_for_set(client, &args.profile).await?;
            let entry = rpc::AccessProfileEntry {
                capability_slot: slot.clone(),
                credential_id: credential.id,
                ..Default::default()
            };
            if let Some(mut profile) = profile {
                profile
                    .entries
                    .retain(|entry| entry.capability_slot != slot);
                profile.entries.push(entry);
                update_profile(client, profile).await
            } else {
                // No empty revision is published first. A failed/uncertain
                // create is not retried as update or treated as success.
                let response = client.create_access_profile(rpc::CreateAccessProfileRequest {
                    name: name.context("new profiles require a name")?,
                    entries: vec![entry],
                    ..Default::default()
                }).await.context("create platform profile with its first selection; inspect before retrying an uncertain result")?;
                print_profiles(
                    &[response
                        .access_profile
                        .into_option()
                        .context("platform returned no profile")?],
                    OutputFormat::Text,
                )
            }
        }
        CredentialProfileCommand::Unset(args) => {
            let mut profile = resolve_profile(client, &args.profile, None).await?;
            let before = profile.entries.len();
            profile
                .entries
                .retain(|entry| entry.capability_slot != args.slot);
            anyhow::ensure!(
                profile.entries.len() != before,
                "platform profile does not select that capability slot"
            );
            update_profile(client, profile).await
        }
        CredentialProfileCommand::Delete(args) => {
            let profile = resolve_profile(client, &args.profile, None).await?;
            if !args.yes
                && !prompt_confirm_default_no(&format!(
                    "Delete platform user profile {:?} ({}) at revision {}?",
                    profile.name, profile.id, profile.revision
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
            "platform history listing is not supported; use --profile=NAME get --revision REVISION"
        ),
    }
}

fn platform_authentication_kind(
    credential: &rpc::Credential,
) -> anyhow::Result<CredentialAuthKind> {
    use rpc::CredentialAuthenticationKind as Kind;
    if credential.authentication_kind == Kind::Oauth {
        Ok(CredentialAuthKind::OAuth)
    } else if credential.authentication_kind == Kind::ApiKey {
        Ok(CredentialAuthKind::ApiKey)
    } else if credential.authentication_kind == Kind::AccessToken {
        Ok(CredentialAuthKind::AccessToken)
    } else if credential.authentication_kind == Kind::GithubApp {
        Ok(CredentialAuthKind::GitHubApp)
    } else if credential.authentication_kind == Kind::SshKey {
        Ok(CredentialAuthKind::SshKey)
    } else {
        anyhow::bail!("platform returned an unsupported credential authentication kind")
    }
}

async fn list_profiles(client: &CodewireClient) -> anyhow::Result<Vec<rpc::AccessProfile>> {
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
            return Ok(profiles);
        }
        anyhow::ensure!(
            cursors.insert(page.next_page_token.clone()),
            "platform returned a repeated profile cursor"
        );
        page_token = page.next_page_token;
    }
}

fn profile_selector(selector: &str) -> anyhow::Result<rpc::get_access_profile_request::Selector> {
    use rpc::get_access_profile_request::Selector;
    Ok(match parse_profile_selector(selector)? {
        ParsedProfileSelector::Id(id) => Selector::AccessProfileId(id.to_string()),
        ParsedProfileSelector::Name(name) => Selector::Name(name.to_string()),
        ParsedProfileSelector::Reference(reference) => {
            anyhow::ensure!(
                reference.scope() == AccessProfileScope::User,
                "organization platform profiles are not supported by the metadata API yet"
            );
            Selector::Name(reference.name().to_string())
        }
    })
}

fn optional_profile_by_name<'a>(
    profiles: &'a [rpc::AccessProfile],
    name: &str,
) -> anyhow::Result<Option<&'a rpc::AccessProfile>> {
    let mut matches = profiles
        .iter()
        .filter(|profile| profile.name.eq_ignore_ascii_case(name));
    let found = matches.next();
    anyhow::ensure!(
        matches.next().is_none(),
        "platform profile name is ambiguous; select an exact id"
    );
    Ok(found)
}

async fn profile_for_set(
    client: &CodewireClient,
    selector: &str,
) -> anyhow::Result<(Option<rpc::AccessProfile>, Option<String>)> {
    match profile_selector(selector)? {
        rpc::get_access_profile_request::Selector::AccessProfileId(id) => {
            Ok((Some(get_exact_profile(client, &id, None).await?), None))
        }
        rpc::get_access_profile_request::Selector::Name(name) => {
            // Only a successful complete listing proves a name is absent.
            // Authentication, transport, and pagination failures never create.
            let profiles = list_profiles(client).await?;
            Ok((
                optional_profile_by_name(&profiles, &name)?.cloned(),
                Some(name),
            ))
        }
    }
}

async fn resolve_profile(
    client: &CodewireClient,
    selector: &str,
    revision: Option<u64>,
) -> anyhow::Result<rpc::AccessProfile> {
    let id = match profile_selector(selector)? {
        rpc::get_access_profile_request::Selector::AccessProfileId(id) => id,
        rpc::get_access_profile_request::Selector::Name(name) => {
            let profiles = list_profiles(client).await?;
            optional_profile_by_name(&profiles, &name)?
                .context("platform profile name was not found")?
                .id
                .clone()
        }
    };
    get_exact_profile(client, &id, revision).await
}

async fn get_exact_profile(
    client: &CodewireClient,
    id: &str,
    revision: Option<u64>,
) -> anyhow::Result<rpc::AccessProfile> {
    anyhow::ensure!(revision != Some(0), "profile revision must be positive");
    let profile = client
        .get_access_profile(rpc::GetAccessProfileRequest {
            selector: Some(rpc::get_access_profile_request::Selector::AccessProfileId(
                id.to_owned(),
            )),
            revision,
            ..Default::default()
        })
        .await?
        .access_profile
        .into_option()
        .context("platform returned no profile")?;
    anyhow::ensure!(
        profile.id == id
            && profile.revision > 0
            && revision.is_none_or(|revision| revision == profile.revision),
        "platform returned a different profile or revision"
    );
    Ok(profile)
}

async fn update_profile(
    client: &CodewireClient,
    profile: rpc::AccessProfile,
) -> anyhow::Result<()> {
    // Exactly one read/modify/CAS attempt; preserve every other selected slot.
    // A conflict is returned, never refetched and silently overwritten.
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

fn print_profiles(profiles: &[rpc::AccessProfile], output: OutputFormat) -> anyhow::Result<()> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(profiles)?),
        OutputFormat::Text => {
            for profile in profiles {
                println!(
                    "{}\tplatform:user/{}\trevision {}",
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

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_bytes, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const PROFILE: &str = "d0f68b45-7c8b-43eb-9b8c-62a33b279c88";
    const CREDENTIAL: &str = "b419132c-641f-49b7-a7fc-0b7d4a135d63";
    const REVISION: u64 = 9_007_199_254_740_993;

    fn client(server: &MockServer) -> CodewireClient {
        CodewireClient::with_http(
            rpc::ClientConfig::new(server.uri()).unwrap(),
            rpc::StaticTokenProvider::new("synthetic-profile-cli-token").unwrap(),
            reqwest::Client::new(),
        )
        .unwrap()
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

    fn profile() -> rpc::AccessProfile {
        rpc::AccessProfile {
            id: PROFILE.into(),
            name: "work".into(),
            revision: REVISION,
            entries: vec![rpc::AccessProfileEntry {
                capability_slot: "github".into(),
                credential_id: "other-existing-credential".into(),
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    fn set_args() -> CredentialProfileCommand {
        CredentialProfileCommand::Set(CredentialProfileSetArgs {
            profile: "user/work".into(),
            slot: "codex".into(),
            credential: "name:codex-work".into(),
        })
    }

    async fn expect_credential(server: &MockServer) {
        unary(
            server,
            "CredentialService",
            "GetCredential",
            rpc::GetCredentialRequest {
                selector: Some(rpc::get_credential_request::Selector::Name(
                    "codex-work".into(),
                )),
                ..Default::default()
            },
            rpc::GetCredentialResponse {
                credential: Some(rpc::Credential {
                    id: CREDENTIAL.into(),
                    provider: "openai".into(),
                    authentication_kind: rpc::CredentialAuthenticationKind::Oauth.into(),
                    status: rpc::CredentialStatus::Active.into(),
                    ..Default::default()
                })
                .into(),
                ..Default::default()
            },
        )
        .await;
    }

    async fn expect_list(server: &MockServer, profiles: Vec<rpc::AccessProfile>) {
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

    async fn expect_exact(
        server: &MockServer,
        revision: Option<u64>,
        response: rpc::AccessProfile,
    ) {
        unary(
            server,
            "AccessProfileService",
            "GetAccessProfile",
            rpc::GetAccessProfileRequest {
                selector: Some(rpc::get_access_profile_request::Selector::AccessProfileId(
                    PROFILE.into(),
                )),
                revision,
                ..Default::default()
            },
            rpc::GetAccessProfileResponse {
                access_profile: Some(response).into(),
                ..Default::default()
            },
        )
        .await;
    }

    #[tokio::test]
    async fn first_set_creates_one_complete_revision_and_never_binds() {
        let server = MockServer::start().await;
        expect_credential(&server).await;
        expect_list(&server, vec![]).await;
        unary(
            &server,
            "AccessProfileService",
            "CreateAccessProfile",
            rpc::CreateAccessProfileRequest {
                name: "work".into(),
                entries: vec![rpc::AccessProfileEntry {
                    capability_slot: "codex".into(),
                    credential_id: CREDENTIAL.into(),
                    ..Default::default()
                }],
                ..Default::default()
            },
            rpc::CreateAccessProfileResponse {
                access_profile: Some(rpc::AccessProfile {
                    revision: 1,
                    ..profile()
                })
                .into(),
                ..Default::default()
            },
        )
        .await;
        handle_profile(&client(&server), set_args()).await.unwrap();
        server.verify().await;
        assert_eq!(server.received_requests().await.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn later_set_preserves_other_slots_in_one_exact_revision_cas() {
        let server = MockServer::start().await;
        expect_credential(&server).await;
        expect_list(&server, vec![profile()]).await;
        let mut entries = profile().entries;
        entries.push(rpc::AccessProfileEntry {
            capability_slot: "codex".into(),
            credential_id: CREDENTIAL.into(),
            ..Default::default()
        });
        unary(
            &server,
            "AccessProfileService",
            "UpdateAccessProfile",
            rpc::UpdateAccessProfileRequest {
                access_profile_id: PROFILE.into(),
                expected_revision: REVISION,
                entries,
                ..Default::default()
            },
            rpc::UpdateAccessProfileResponse {
                access_profile: Some(rpc::AccessProfile {
                    revision: REVISION + 1,
                    ..profile()
                })
                .into(),
                ..Default::default()
            },
        )
        .await;
        handle_profile(&client(&server), set_args()).await.unwrap();
        server.verify().await;
        assert_eq!(server.received_requests().await.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn last_unset_sends_explicit_empty_complete_set() {
        let server = MockServer::start().await;
        expect_list(&server, vec![profile()]).await;
        expect_exact(&server, None, profile()).await;
        unary(
            &server,
            "AccessProfileService",
            "UpdateAccessProfile",
            rpc::UpdateAccessProfileRequest {
                access_profile_id: PROFILE.into(),
                expected_revision: REVISION,
                entries: vec![],
                ..Default::default()
            },
            rpc::UpdateAccessProfileResponse {
                access_profile: Some(rpc::AccessProfile {
                    revision: REVISION + 1,
                    entries: vec![],
                    ..profile()
                })
                .into(),
                ..Default::default()
            },
        )
        .await;
        handle_profile(
            &client(&server),
            CredentialProfileCommand::Unset(CredentialProfileSlotArgs {
                profile: "work".into(),
                slot: "github".into(),
            }),
        )
        .await
        .unwrap();
        server.verify().await;
        assert_eq!(server.received_requests().await.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn failed_or_ambiguous_list_never_creates_a_profile() {
        for ambiguous in [false, true] {
            let server = MockServer::start().await;
            expect_credential(&server).await;
            if ambiguous {
                expect_list(
                    &server,
                    vec![
                        profile(),
                        rpc::AccessProfile {
                            id: "other-id".into(),
                            ..profile()
                        },
                    ],
                )
                .await;
            } else {
                Mock::given(method("POST"))
                    .and(path("/codewire.v1.AccessProfileService/ListAccessProfiles"))
                    .respond_with(ResponseTemplate::new(503))
                    .expect(1)
                    .mount(&server)
                    .await;
            }
            assert!(handle_profile(&client(&server), set_args()).await.is_err());
            server.verify().await;
            assert_eq!(server.received_requests().await.unwrap().len(), 2);
        }
    }

    #[tokio::test]
    async fn conflict_does_not_refetch_retry_or_create() {
        let server = MockServer::start().await;
        expect_credential(&server).await;
        expect_list(&server, vec![profile()]).await;
        Mock::given(method("POST"))
            .and(path(
                "/codewire.v1.AccessProfileService/UpdateAccessProfile",
            ))
            .respond_with(ResponseTemplate::new(409))
            .expect(1)
            .mount(&server)
            .await;
        assert!(handle_profile(&client(&server), set_args()).await.is_err());
        server.verify().await;
        assert_eq!(server.received_requests().await.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn exact_revision_mismatch_fails_and_id_never_falls_back_to_name() {
        let server = MockServer::start().await;
        expect_exact(
            &server,
            Some(REVISION),
            rpc::AccessProfile {
                revision: REVISION - 1,
                ..profile()
            },
        )
        .await;
        assert!(
            resolve_profile(&client(&server), &format!("id:{PROFILE}"), Some(REVISION))
                .await
                .is_err()
        );
        server.verify().await;
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn organization_scope_and_unsupported_history_fail_before_network() {
        let server = MockServer::start().await;
        assert!(
            resolve_profile(&client(&server), "organization/work", None)
                .await
                .is_err()
        );
        assert!(
            handle_profile(
                &client(&server),
                CredentialProfileCommand::Revisions(CredentialProfileSelectorArgs {
                    profile: "work".into(),
                    revision: None,
                    output: OutputFormat::Json,
                })
            )
            .await
            .is_err()
        );
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[test]
    fn selectors_are_exact_and_scope_aware() {
        assert_eq!(
            profile_selector("user/work").unwrap(),
            rpc::get_access_profile_request::Selector::Name("work".into())
        );
        assert!(profile_selector("organization/work").is_err());
        assert!(profile_selector("id:not-a-uuid").is_err());
        assert!(profile_selector("name:work").is_err());
    }
}
