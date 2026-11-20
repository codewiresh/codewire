//! Platform profile metadata over the shared generated Rust client.
//! The current service is personal-only. Organization selectors fail explicitly
//! until the owner-aware public contract is composed; no fallback is permitted.

use codewire_access::{AccessProfileScope, CredentialAuthKind, ProviderId};
use codewire_client::{self as rpc, CodewireClient};

use super::credential_input::{
    CredentialOperation, GITHUB_ALWAYS_INCLUDED, ParsedProfileSelector, parse_profile_selector,
    profile_set_credential, profile_slot_for, slot_provider,
};
use super::*;

pub(super) async fn handle_platform_credentials(
    globals: &Globals,
    operation: CredentialOperation,
) -> anyhow::Result<super::credential_input::CredentialExecution> {
    let env = OsEnv;
    let paths = ResolvePaths::from_env(&env)?;
    let platform = resolve_platform(globals, &paths, &env)?;
    let client = CodewireClient::with_token_provider(
        platform
            .client_config()?
            .with_user_agent(format!("codewire-cli/{CLI_VERSION}"))?,
        platform.token_provider()?,
    )?;
    match operation {
        CredentialOperation::Profile(command) => handle_profile(&client, command)
            .await
            .map(|_| super::credential_input::CredentialExecution::Unchanged),
        CredentialOperation::Credential(command) => {
            super::platform_credentials::execute(&client, command).await
        }
        CredentialOperation::GenerateIntoProfile(args, profile) => {
            let credential = super::platform_credentials::generate_ssh(&client, &args).await?;
            handle_profile(
                &client,
                CredentialProfileCommand::Set(CredentialProfileSetArgs {
                    profile,
                    slot: Some("ssh".to_owned()),
                    credential: Some(format!("id:{}", credential.id)),
                }),
            )
            .await
            .map(|_| super::credential_input::CredentialExecution::Unchanged)
        }
    }
}

async fn handle_profile(
    client: &CodewireClient,
    command: CredentialProfileCommand,
) -> anyhow::Result<()> {
    match command {
        CredentialProfileCommand::List(args) => {
            print_profiles(
                client,
                &default_first(list_profiles(client).await?),
                args.output,
            )
            .await
        }
        CredentialProfileCommand::Get(args) => {
            print_profiles(
                client,
                &[resolve_profile(client, &args.profile, args.revision).await?],
                args.output,
            )
            .await
        }
        CredentialProfileCommand::Set(args) => {
            let selector = profile_set_credential(&args)?;
            let slot = args.slot.as_deref().context("a provider is required")?;
            let credential =
                super::platform_credentials::resolve_in(client, selector, slot_provider(slot))
                    .await?;
            let kind = platform_authentication_kind(&credential)?;
            let slot = profile_slot_for(
                &credential.name,
                slot,
                &ProviderId::parse(&credential.provider)?,
                kind,
            )?
            .to_string();
            let (profile, name) = profile_for_set(client, &args.profile).await?;
            let held = credential.name.clone();
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
                let done = super::credentials::output::profile_now_holds(&profile.name, &held);
                update_profile(client, profile, &done).await
            } else {
                // No empty revision is published first. A failed/uncertain
                // create is not retried as update or treated as success.
                let response = client.create_access_profile(rpc::CreateAccessProfileRequest {
                    name: name.context("new profiles require a name")?,
                    entries: vec![entry],
                    ..Default::default()
                }).await.context("create the cloud profile with its first credential; inspect before retrying an uncertain result")?;
                let created = response
                    .access_profile
                    .into_option()
                    .context("Codewire returned no profile")?;
                super::credentials::output::print_done(
                    &super::credentials::output::profile_created(&created.name, &held),
                );
                Ok(())
            }
        }
        CredentialProfileCommand::Unset(args) if args.slot == "github" => {
            anyhow::bail!(GITHUB_ALWAYS_INCLUDED)
        }
        CredentialProfileCommand::Unset(args) => {
            let mut profile = resolve_profile(client, &args.profile, None).await?;
            let before = profile.entries.len();
            profile
                .entries
                .retain(|entry| entry.capability_slot != args.slot);
            anyhow::ensure!(
                profile.entries.len() != before,
                super::credentials::output::refusal::slot_not_selected(
                    "cloud",
                    &profile.name,
                    &args.slot
                )
            );
            {
                let done = super::credentials::output::profile_removed(&profile.name, &args.slot);
                update_profile(client, profile, &done).await
            }
        }
        CredentialProfileCommand::Delete(args) => {
            use super::credentials::{confirm, output};
            let profile = resolve_profile(client, &args.profile, None).await?;
            anyhow::ensure!(
                !profile.is_default,
                default_delete_refusal(&profile.name, "--cloud")
            );
            let question = format!(
                "Delete cloud profile {:?} ({}) at revision {}?",
                profile.name, profile.id, profile.revision
            );
            let change = confirm::Change::DeleteProfile {
                question: &question,
            };
            if !confirm::confirm("cloud", &profile.name, change, args.yes, OutputFormat::Text)? {
                return Ok(());
            }
            client
                .delete_access_profile(rpc::DeleteAccessProfileRequest {
                    access_profile_id: profile.id,
                    expected_revision: profile.revision,
                    ..Default::default()
                })
                .await?;
            output::print_done(&output::profile_deleted("cloud", &profile.name));
            Ok(())
        }
        CredentialProfileCommand::Default(args) => {
            let profile = resolve_profile(client, &args.profile, None).await?;
            let selected = client
                .set_default_access_profile(rpc::SetDefaultAccessProfileRequest {
                    access_profile_id: profile.id.clone(),
                    ..Default::default()
                })
                .await?
                .access_profile
                .into_option()
                .context("Codewire returned no profile")?;
            anyhow::ensure!(
                selected.id == profile.id && selected.is_default,
                "Codewire returned a different default profile"
            );
            eprintln!(
                "Default profile: {:?}. A cloud `cw create` uses it when you name no profile.",
                selected.name
            );
            Ok(())
        }
        CredentialProfileCommand::Revisions(args) => print_revisions(client, args).await,
    }
}

pub(super) fn platform_authentication_kind(
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
    } else if credential.authentication_kind == Kind::ClaudeSignIn {
        Ok(CredentialAuthKind::ClaudeSignIn)
    } else {
        anyhow::bail!("Codewire returned a credential kind this cw doesn't know; upgrade cw")
    }
}

/// Every revision of one profile, following the service's pages, oldest first
/// as the local listing prints them. The service pages newest first.
/// `--profile P revisions`: every revision of the profile, oldest first (#4717 C7).
async fn print_revisions(
    client: &CodewireClient,
    args: super::credential_profile_args::CredentialProfileSelectorArgs,
) -> anyhow::Result<()> {
    if args.revision.is_some() {
        anyhow::bail!("use --profile=NAME get --revision REVISION to inspect one revision");
    }
    let profile = resolve_profile(client, &args.profile, None).await?;
    let revisions = list_revisions(client, &profile.id).await?;
    let credentials = super::platform_credentials::list_all(client).await?;
    super::credentials::output::print_profile_revisions(
        &revision_views(&revisions)?,
        &super::credentials::output::cloud_names(&credentials),
        args.output,
    )
}

async fn list_revisions(
    client: &CodewireClient,
    id: &str,
) -> anyhow::Result<Vec<rpc::AccessProfileRevision>> {
    let mut revisions = Vec::new();
    let mut page_token = String::new();
    let mut cursors = BTreeSet::new();
    loop {
        let page = client
            .list_access_profile_revisions(rpc::ListAccessProfileRevisionsRequest {
                access_profile_id: id.to_owned(),
                page_size: 100,
                page_token,
                ..Default::default()
            })
            .await?;
        revisions.extend(page.revisions);
        if page.next_page_token.is_empty() {
            revisions.reverse();
            return Ok(revisions);
        }
        anyhow::ensure!(
            cursors.insert(page.next_page_token.clone()),
            "Codewire returned a repeated revision page"
        );
        page_token = page.next_page_token;
    }
}

/// Cloud revisions as the local `revisions` shows its own: the same columns
/// and JSON fields (#4717). The profile was created with its first revision.
fn revision_views(
    revisions: &[rpc::AccessProfileRevision],
) -> anyhow::Result<Vec<super::credentials::output::AccessProfileView>> {
    let created_at = |revision: &rpc::AccessProfileRevision| -> anyhow::Result<u64> {
        let at = revision
            .created_at
            .as_option()
            .context("Codewire returned a revision without its time")?;
        u64::try_from(at.seconds)
            .ok()
            .and_then(|seconds| seconds.checked_mul(1000))
            .and_then(|ms| ms.checked_add(u64::try_from(at.nanos / 1_000_000).ok()?))
            .context("Codewire returned a revision time before 1970")
    };
    let profile_created_at = match revisions.iter().find(|revision| {
        revision
            .access_profile
            .as_option()
            .is_some_and(|p| p.revision == 1)
    }) {
        Some(first) => created_at(first)?,
        None => 0,
    };
    revisions
        .iter()
        .map(|revision| {
            let profile = revision
                .access_profile
                .as_option()
                .context("Codewire returned a revision without its profile")?;
            Ok(
                super::credentials::output::AccessProfileView::cloud_revision(
                    profile,
                    profile_created_at,
                    created_at(revision)?,
                ),
            )
        })
        .collect()
}

pub(super) async fn list_profiles(
    client: &CodewireClient,
) -> anyhow::Result<Vec<rpc::AccessProfile>> {
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
            "Codewire returned a repeated profile cursor"
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
                "organization profiles in your Codewire account aren't supported yet"
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
        "more than one cloud profile has that name; select it by ID"
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
                .with_context(|| {
                    super::credentials::output::refusal::profile_not_found("cloud", &name)
                })?
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
        .context("Codewire returned no profile")?;
    anyhow::ensure!(
        profile.id == id
            && profile.revision > 0
            && revision.is_none_or(|revision| revision == profile.revision),
        "Codewire returned a different profile or revision"
    );
    Ok(profile)
}

async fn update_profile(
    client: &CodewireClient,
    profile: rpc::AccessProfile,
    done: &str,
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
    response
        .access_profile
        .into_option()
        .context("Codewire returned no profile")?;
    super::credentials::output::print_done(done);
    Ok(())
}

/// The default profile first; the rest keep the platform's order.
pub(super) fn default_first(mut profiles: Vec<rpc::AccessProfile>) -> Vec<rpc::AccessProfile> {
    profiles.sort_by_key(|profile| !profile.is_default);
    profiles
}

/// One sentence for deleting the default in either placement (`--cloud` or
/// `--local`), so the two say the same (#4717).
pub(super) fn default_delete_refusal(name: &str, placement: &str) -> String {
    format!(
        "{name:?} is your default profile and can't be deleted; make another profile the default first: cw credentials {placement} profiles default NAME"
    )
}

async fn print_profiles(
    client: &CodewireClient,
    profiles: &[rpc::AccessProfile],
    output: OutputFormat,
) -> anyhow::Result<()> {
    let credentials = super::platform_credentials::list_all(client).await?;
    super::credentials::output::print_cloud_profiles(
        profiles,
        &super::credentials::output::cloud_names(&credentials),
        output,
    )
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
                capability_slot: "ssh".into(),
                credential_id: "other-existing-credential".into(),
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    fn set_args() -> CredentialProfileCommand {
        CredentialProfileCommand::Set(CredentialProfileSetArgs {
            profile: "user/work".into(),
            slot: Some("codex".into()),
            credential: Some("name:codex-work".into()),
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
                // The codex slot's provider narrows the name (#4928).
                provider: Some("openai".into()),
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
                slot: "ssh".into(),
            }),
        )
        .await
        .unwrap();
        server.verify().await;
        assert_eq!(server.received_requests().await.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn github_is_always_included_and_never_set_or_unset() {
        let server = MockServer::start().await;
        for command in [
            CredentialProfileCommand::Set(CredentialProfileSetArgs {
                profile: "user/work".into(),
                slot: Some("github".into()),
                credential: None,
            }),
            CredentialProfileCommand::Set(CredentialProfileSetArgs {
                profile: "user/work".into(),
                slot: Some("github".into()),
                credential: Some("name:github-work".into()),
            }),
            CredentialProfileCommand::Unset(CredentialProfileSlotArgs {
                profile: "work".into(),
                slot: "github".into(),
            }),
        ] {
            let error = handle_profile(&client(&server), command).await.unwrap_err();
            assert!(error.to_string().contains("credentials connect github"));
        }
        assert!(server.received_requests().await.unwrap().is_empty());
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
    async fn organization_scope_and_one_revision_of_the_history_fail_before_network() {
        let server = MockServer::start().await;
        assert!(
            resolve_profile(&client(&server), "organization/work", None)
                .await
                .is_err()
        );
        // The history lists every revision (#4717); one revision is `get`'s.
        assert!(
            handle_profile(
                &client(&server),
                CredentialProfileCommand::Revisions(CredentialProfileSelectorArgs {
                    profile: "work".into(),
                    revision: Some(2),
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

    #[tokio::test]
    async fn default_command_sets_exactly_the_named_profile() {
        let server = MockServer::start().await;
        expect_list(&server, vec![profile()]).await;
        expect_exact(&server, None, profile()).await;
        unary(
            &server,
            "AccessProfileService",
            "SetDefaultAccessProfile",
            rpc::SetDefaultAccessProfileRequest {
                access_profile_id: PROFILE.into(),
                ..Default::default()
            },
            rpc::SetDefaultAccessProfileResponse {
                access_profile: Some(rpc::AccessProfile {
                    is_default: true,
                    ..profile()
                })
                .into(),
                ..Default::default()
            },
        )
        .await;
        handle_profile(
            &client(&server),
            CredentialProfileCommand::Default(CredentialProfileDefaultArgs {
                profile: "work".into(),
            }),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn the_default_is_refused_before_any_delete_request() {
        let server = MockServer::start().await;
        let default = rpc::AccessProfile {
            is_default: true,
            ..profile()
        };
        expect_list(&server, vec![default.clone()]).await;
        expect_exact(&server, None, default).await;
        let error = handle_profile(
            &client(&server),
            CredentialProfileCommand::Delete(CredentialProfileDeleteArgs {
                profile: "work".into(),
                yes: true,
            }),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("make another profile the default first"),
            "{error}"
        );
        assert!(
            !server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .any(|request| request.url.path().ends_with("/DeleteAccessProfile"))
        );
    }

    #[test]
    fn json_output_names_the_default_as_scripts_read_it() {
        let value = serde_json::to_value(rpc::AccessProfile {
            is_default: true,
            ..profile()
        })
        .unwrap();
        assert_eq!(value["isDefault"], true, "{value}");
    }

    #[test]
    fn lists_put_the_default_first_and_keep_the_rest_in_order() {
        let named = |id: &str, is_default| rpc::AccessProfile {
            id: id.into(),
            is_default,
            ..profile()
        };
        let ordered = default_first(vec![
            named("a", false),
            named("b", false),
            named("c", true),
            named("d", false),
        ]);
        assert_eq!(
            ordered
                .iter()
                .map(|profile| profile.id.as_str())
                .collect::<Vec<_>>(),
            ["c", "a", "b", "d"]
        );
    }

    fn revision(number: u64, seconds: i64, entries: &[(&str, &str)]) -> rpc::AccessProfileRevision {
        rpc::AccessProfileRevision {
            access_profile: Some(rpc::AccessProfile {
                id: PROFILE.into(),
                name: "work".into(),
                revision: number,
                entries: entries
                    .iter()
                    .map(|(slot, credential)| rpc::AccessProfileEntry {
                        capability_slot: (*slot).into(),
                        credential_id: (*credential).into(),
                        ..Default::default()
                    })
                    .collect(),
                ..Default::default()
            })
            .into(),
            created_at: Some(rpc::Timestamp::from_unix(seconds, 250_000_000)).into(),
            ..Default::default()
        }
    }

    /// Cloud revisions print as the local `revisions` does: the revision
    /// first, then what each held by name, and in JSON the profile with the
    /// profile's creation time taken from its first revision (#4717).
    #[test]
    fn cloud_revisions_render_as_the_local_revisions_do() {
        let views = revision_views(&[
            revision(2, 1_794_614_400, &[]),
            revision(1, 1_794_614_300, &[("codex", CREDENTIAL)]),
        ])
        .unwrap();
        let json = serde_json::to_value(&views).unwrap();
        assert_eq!(
            json[1],
            serde_json::json!({
                "id": PROFILE,
                "placement": "cloud",
                "name": "work",
                "revision": 1,
                "is_default": false,
                "entries": {"codex": CREDENTIAL},
                "github_connection": true,
                "profile_created_at_unix_ms": 1_794_614_300_250_u64,
                "revision_created_at_unix_ms": 1_794_614_300_250_u64,
            })
        );
        assert_eq!(json[0]["revision"], 2);
        assert_eq!(json[0]["entries"], serde_json::json!({}));
        assert_eq!(json[0]["profile_created_at_unix_ms"], 1_794_614_300_250_u64);
        assert_eq!(
            json[0]["revision_created_at_unix_ms"],
            1_794_614_400_250_u64
        );
        let names = [(CREDENTIAL.to_owned(), "Codex: work key".to_owned())].into();
        let text = super::super::credentials::output::format_revisions_text(&views, &names);
        let lines: Vec<&str> = text.lines().collect();
        assert!(lines[0].starts_with("REVISION"), "{text}");
        assert!(lines[1].starts_with('2'), "{text}");
        assert!(lines[1].contains("GitHub: account connection"), "{text}");
        assert!(lines[2].starts_with('1'), "{text}");
        assert!(
            lines[2].contains("Codex: work key, GitHub: account connection"),
            "{text}"
        );
        assert!(
            !text.contains(PROFILE) && !text.contains(CREDENTIAL),
            "{text}"
        );
    }

    /// The service pages newest first; the CLI follows every page and prints
    /// oldest first, as the local listing does (#4717).
    #[tokio::test]
    async fn cloud_revisions_follow_every_page_and_list_oldest_first() {
        let server = MockServer::start().await;
        let request = |page_token: &str| rpc::ListAccessProfileRevisionsRequest {
            access_profile_id: PROFILE.into(),
            page_size: 100,
            page_token: page_token.into(),
            ..Default::default()
        };
        let page = |revisions: Vec<rpc::AccessProfileRevision>, next: &str| {
            rpc::ListAccessProfileRevisionsResponse {
                revisions,
                next_page_token: next.into(),
                ..Default::default()
            }
        };
        let service = "AccessProfileService";
        let name = "ListAccessProfileRevisions";
        unary(
            &server,
            service,
            name,
            request(""),
            page(vec![revision(3, 30, &[]), revision(2, 20, &[])], "2"),
        )
        .await;
        unary(
            &server,
            service,
            name,
            request("2"),
            page(vec![revision(1, 10, &[])], ""),
        )
        .await;

        let revisions = list_revisions(&client(&server), PROFILE).await.unwrap();
        let numbers: Vec<u64> = revisions
            .iter()
            .map(|r| r.access_profile.as_option().unwrap().revision)
            .collect();
        assert_eq!(numbers, vec![1, 2, 3]);
    }
}
