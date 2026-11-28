//! Value-free source resolution for the native CLI. Stored origin descriptors
//! are identity constraints, never credentials or launch authorizations.

use codewire_access::{AccessProfileScope, Owner};
use codewire_project::{
    CredentialBinding, ProjectSpec, SecretBindings, StoragePlacement, StorageReference,
};

use super::*;
use crate::commands::lifecycle_output::source_preview::{self, SourceRows, UpdateEffect};
use crate::output::VmLocation;
use std::collections::BTreeSet;

const SOURCE_METADATA_PAGE_SIZE: i32 = 100;
const MAX_SOURCE_METADATA_PAGES: usize = 10;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(super) struct ResolvedProfile {
    pub(super) id: String,
    pub(super) reference: String,
    pub(super) revision: u64,
    pub(super) profile_slots: BTreeSet<String>,
    /// The platform profile revision's Anthropic credential kind:
    /// "subscription_token", "sign_in", or empty for an API key or no
    /// Anthropic slot.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(super) anthropic_form: String,
}

#[derive(Default)]
pub(super) struct ResolvedSources {
    pub(super) profile: Option<ResolvedProfile>,
    pub(super) platform: Option<v1::PlatformSourceAuthority>,
    /// The selected secret project's name, for display only; the request
    /// carries the canonical reference.
    pub(super) project_name: Option<String>,
}

#[derive(Clone, Copy)]
pub(super) struct SourceChanges {
    project: bool,
    profile: bool,
    platform_scopes: bool,
}

impl SourceChanges {
    pub(super) fn all() -> Self {
        Self {
            project: true,
            profile: true,
            platform_scopes: true,
        }
    }

    pub(super) fn update(args: &EnvUpdateArgs) -> Self {
        Self {
            project: args.secrets.is_some(),
            profile: args.profile.is_some(),
            platform_scopes: args.org_secrets
                || args.user_secrets == Some(StoragePlacementArg::Platform),
        }
    }
}

#[derive(Clone, Debug)]
struct Candidate {
    placement: StoragePlacement,
    id: String,
    name: String,
    profile: Option<ResolvedProfile>,
    /// A platform profile's Anthropic credential, read only once selected.
    anthropic_credential: Option<String>,
}

struct PlatformMetadata {
    config: config::ResolvedPlatformConfig,
    client: codewire_client::CodewireClient,
    authority: v1::PlatformSourceAuthority,
}

pub(super) fn apply_create_source_flags(
    spec: &mut ProjectSpec,
    args: &EnvCreateArgs,
) -> anyhow::Result<()> {
    if let Some(project) = &args.secrets {
        StorageReference::project(project)?;
        spec.secrets.project = project.clone();
    }
    if let Some(user) = args.user_secrets {
        spec.secrets.user = Some(storage_placement(user));
    }
    if args.org_secrets {
        spec.secrets.organization = true;
    }
    if let Some(profile) = &args.profile {
        StorageReference::profile(profile)?;
        spec.credentials = Some(CredentialBinding {
            profile: profile.clone(),
        });
    }
    if args.no_profile {
        spec.credentials = None;
    }
    spec.validate()?;
    Ok(())
}

/// What a local create's profile comes from when it names none.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum LocalDefault {
    /// The store's default, by name and exact ID.
    Profile { name: String, id: String },
    /// Profiles but no default: an upgraded store keeps today's create.
    NoneSet,
    /// No profiles at all, so nothing to say.
    NoProfiles,
}

impl LocalDefault {
    /// The store's default among `profiles`, as the authority marks it.
    pub(super) fn from_profiles(
        profiles: &[codewire_local_credentials::AccessProfileRecord],
    ) -> anyhow::Result<Self> {
        let mut defaults = profiles.iter().filter(|record| record.is_default);
        let default = defaults.next();
        anyhow::ensure!(
            defaults.next().is_none(),
            "local credential authority returned more than one default credential profile"
        );
        Ok(match default {
            Some(record) => Self::Profile {
                name: record.profile.name.to_string(),
                id: record.profile.id.to_string(),
            },
            None if profiles.is_empty() => Self::NoProfiles,
            None => Self::NoneSet,
        })
    }

    /// The line a text create prints, if any.
    pub(super) fn message(&self) -> Option<String> {
        match self {
            Self::Profile { name, .. } => Some(format!(
                "Credential profile: {name} (your default; --no-profile creates without one)"
            )),
            Self::NoneSet => Some(
                "Credential profile: none (no default; set one with cw credentials --local profiles default NAME)"
                    .to_owned(),
            ),
            Self::NoProfiles => None,
        }
    }
}

/// A local create's sources: its flags, then, when it names no profile, the
/// store's default (#4717).
pub(super) async fn apply_create_sources(
    spec: &mut ProjectSpec,
    args: &EnvCreateArgs,
) -> anyhow::Result<()> {
    apply_create_source_flags(spec, args)?;
    select_local_default_profile(spec, args.no_profile, args.output).await
}

/// A local create's profile, in order: `--profile`, then codewire.yaml (both
/// already in `spec`), then the store's default; `--no-profile` selects
/// none, as a cloud create's `select_default_profile`. A failure to read the
/// default fails the create; it never becomes "no profile".
pub(super) async fn select_local_default_profile(
    spec: &mut ProjectSpec,
    no_profile: bool,
    output: OutputFormat,
) -> anyhow::Result<()> {
    if no_profile || spec.credentials.is_some() {
        return Ok(());
    }
    let default = read_local_default().await?;
    apply_local_default(spec, &default);
    if matches!(output, OutputFormat::Text)
        && let Some(message) = default.message()
    {
        eprintln!("{message}");
    }
    Ok(())
}

/// The store's default. A store that was never created has no profiles, so
/// no authority is started for it. An authority older than the default
/// profile marks none, so it reads as no default.
pub(super) async fn read_local_default() -> anyhow::Result<LocalDefault> {
    let context = "read your default credential profile; --no-profile creates without one";
    let root = local_credential_root(&OsEnv)?;
    if !root
        .join(codewire_local_credentials::DATABASE_FILE)
        .exists()
    {
        return Ok(LocalDefault::NoProfiles);
    }
    let mut client = connect_local_credential_authority()
        .await
        .context(context)?;
    LocalDefault::from_profiles(&client.list_profiles().await.context(context)?)
}

/// The review's credential line for what the create will select: the named
/// profile, else the store's default, else none.
pub(super) fn review_profile(
    spec: &ProjectSpec,
    no_profile: bool,
    default: &LocalDefault,
) -> String {
    match (&spec.credentials, default) {
        (Some(binding), _) => binding.profile.clone(),
        (None, LocalDefault::Profile { name, .. }) if !no_profile => {
            format!("{name} (your default)")
        }
        _ => "none".to_owned(),
    }
}

/// Select the default's exact profile, or nothing.
pub(super) fn apply_local_default(spec: &mut ProjectSpec, default: &LocalDefault) {
    if let LocalDefault::Profile { id, .. } = default {
        spec.credentials = Some(CredentialBinding {
            profile: format!("local:id:{id}"),
        });
    }
}

fn storage_placement(value: StoragePlacementArg) -> StoragePlacement {
    match value {
        StoragePlacementArg::Local => StoragePlacement::Local,
        StoragePlacementArg::Platform => StoragePlacement::Platform,
    }
}

/// Whether `args` changes the environment's secrets or credential profile.
pub(super) fn selects_sources(args: &EnvUpdateArgs) -> bool {
    args.clear_secrets
        || args.clear_profile
        || args.secrets.is_some()
        || args.user_secrets.is_some()
        || args.org_secrets
        || args.profile.is_some()
}

pub(super) fn validate_update_args(args: &EnvUpdateArgs) -> anyhow::Result<()> {
    trimmed_required(&args.environment, "environment")?;
    anyhow::ensure!(
        selects_sources(args)
            || args.policy.is_some()
            || args.idle_suspend.is_some()
            || args.idle_hibernate.is_some(),
        "select --secrets, --profile, --user-secrets, --org-secrets, --clear-secrets, --clear-profile, --policy, --idle-suspend, or --idle-hibernate"
    );
    anyhow::ensure!(
        !(args.clear_secrets
            && (args.secrets.is_some() || args.user_secrets.is_some() || args.org_secrets)),
        "--clear-secrets conflicts with secret selections"
    );
    anyhow::ensure!(
        !(args.clear_profile && args.profile.is_some()),
        "--clear-profile conflicts with --profile"
    );
    if let Some(project) = &args.secrets {
        StorageReference::project(project)?;
    }
    if let Some(profile) = &args.profile {
        StorageReference::profile(profile)?;
    }
    Ok(())
}

pub(super) fn patch_sources(current: &ProjectSpec, args: &EnvUpdateArgs) -> ProjectSpec {
    let mut replacement = current.clone();
    if args.clear_secrets {
        replacement.secrets = SecretBindings::default();
    } else {
        if let Some(project) = &args.secrets {
            replacement.secrets.project = project.clone();
        }
        if let Some(user) = args.user_secrets {
            replacement.secrets.user = Some(storage_placement(user));
        }
        if args.org_secrets {
            replacement.secrets.organization = true;
        }
    }
    if args.clear_profile {
        replacement.credentials = None;
    } else if let Some(profile) = &args.profile {
        replacement.credentials = Some(CredentialBinding {
            profile: profile.clone(),
        });
    }
    replacement
}

fn platform_is_proven_unconfigured(error: &config::ConfigError) -> bool {
    matches!(error, config::ConfigError::NoPlatformServer { cause: Some(cause) }
        if matches!(cause.as_ref(), config::ConfigError::ReadConfig { reason: source, .. }
            if source.kind() == std::io::ErrorKind::NotFound))
}

async fn platform_metadata(
    globals: &Globals,
    paths: &ResolvePaths,
    env: &impl config::Env,
    required: bool,
) -> anyhow::Result<Option<PlatformMetadata>> {
    let platform = match config::resolve_platform(
        config::PlatformResolveOptions {
            server_url: globals.server.clone(),
            org: globals.org.clone(),
        },
        paths,
        env,
    ) {
        Ok(platform) => platform,
        Err(error) if !required && platform_is_proven_unconfigured(&error) => return Ok(None),
        Err(error) => return Err(error).context(
            "platform source availability could not be proven; qualify local sources with local:",
        ),
    };
    let client = codewire_client(&platform)?;
    let token = client
        .bearer_token()
        .await
        .context("authenticate platform source metadata")?;
    anyhow::ensure!(
        !token.expose_secret().starts_with("cw_"),
        "native platform-source delegation requires a personal `cw login`; organization API keys cannot select personal authority"
    );
    let user = platform.oauth_client()?.userinfo(&token).await.context(
        "verify the current platform account for native source delegation; use `cw login`",
    )?;
    validate_identity_component(&user.sub)?;
    let orgs = organization_client(&platform)?
        .list_orgs()
        .await
        .context("verify platform source organization membership")?;
    let organization_id = current_org_id(&platform, &orgs)?;
    validate_identity_component(&organization_id)?;
    Ok(Some(PlatformMetadata {
        authority: v1::PlatformSourceAuthority {
            server_url: config::normalize_server_url(&platform.server_url),
            organization_id,
            user_id: user.sub,
            profile_slots: Vec::new(),
            anthropic_form: String::new(),
        },
        config: platform,
        client,
    }))
}

/// The platform account this cw is signed in to, from local login state only
/// (no network call), or `None` when that cannot tell: a local disk snapshot
/// records it, and a create from one signed in to another account is refused
/// as a guard against mix-ups (#3046).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(super) fn signed_in_account(
    globals: &Globals,
    paths: &ResolvePaths,
    env: &impl config::Env,
) -> Option<v1::PlatformAccount> {
    config::local_account(globals.server.clone(), paths, env).map(|account| v1::PlatformAccount {
        server_url: account.server_url,
        organization_id: account.organization_id,
        user_id: account.user_id,
    })
}

fn validate_identity_component(value: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        !value.is_empty()
            && value.len() <= 256
            && value.trim() == value
            && !value.chars().any(char::is_control),
        "platform source identity metadata is invalid"
    );
    Ok(())
}

fn exact_id(value: &str) -> anyhow::Result<()> {
    let id =
        Uuid::parse_str(value).map_err(|_| anyhow::anyhow!("source metadata ID is invalid"))?;
    anyhow::ensure!(
        !id.is_nil() && id.to_string() == value,
        "source metadata ID must be canonical and non-nil"
    );
    Ok(())
}

fn local_authority(
    client: Option<&mut LocalCredentialClient>,
) -> anyhow::Result<&mut LocalCredentialClient> {
    client.context("selected local sources require the local credential authority")
}

async fn profile_candidates(
    local: Option<&mut LocalCredentialClient>,
    platform: Option<&PlatformMetadata>,
    reference: StorageReference<'_>,
) -> anyhow::Result<Vec<Candidate>> {
    if let Some((scope, _)) = reference.selector.split_once('/') {
        anyhow::ensure!(
            scope == "user",
            "organization credential profile metadata is not supported by the current platform API"
        );
    }
    let mut candidates = Vec::new();
    if reference.placement != Some(StoragePlacement::Platform) {
        for record in local_authority(local)?
            .list_profiles()
            .await
            .context("list local profile metadata")?
        {
            anyhow::ensure!(
                matches!(record.profile.owner, Owner::User(_)),
                "local profile metadata has an unsupported owner scope"
            );
            let id = record.profile.id.to_string();
            exact_id(&id)?;
            record.profile.validate()?;
            let name = record.profile.name.to_string();
            candidates.push(Candidate {
                placement: StoragePlacement::Local,
                id: id.clone(),
                name: name.clone(),
                profile: Some(ResolvedProfile {
                    id,
                    reference: format!("user/{name}"),
                    revision: record.profile.revision,
                    profile_slots: BTreeSet::new(),
                    anthropic_form: String::new(),
                }),
                anthropic_credential: None,
            });
        }
    }
    if reference.placement != Some(StoragePlacement::Local)
        && let Some(platform) = platform
    {
        let mut page_token = String::new();
        let mut seen = BTreeSet::new();
        for _ in 0..MAX_SOURCE_METADATA_PAGES {
            let response = platform
                .client
                .list_access_profiles(codewire_client::ListAccessProfilesRequest {
                    page_size: SOURCE_METADATA_PAGE_SIZE,
                    page_token,
                    ..Default::default()
                })
                .await
                .context("list platform personal profile metadata")?;
            anyhow::ensure!(
                response.access_profiles.len() <= SOURCE_METADATA_PAGE_SIZE as usize,
                "platform profile metadata exceeded its requested page bound"
            );
            for profile in response.access_profiles {
                exact_id(&profile.id)?;
                let name = codewire_access::AccessProfileName::parse(profile.name)?.to_string();
                let mut profile_slots = profile
                    .entries
                    .iter()
                    .map(|entry| entry.capability_slot.clone())
                    .collect::<BTreeSet<_>>();
                // GitHub is never a profile entry: every personal profile
                // includes the account's one connection, connected or not, as
                // `AccessProfile::reserved_slots` does for a hosted Sandbox.
                // The VM derives its reserved names from these slots, so
                // GitHub's are always reserved, and the delegation authority
                // authorizes GitHub only because this capture selected it.
                // Whether the guest is configured for GitHub follows the
                // account's connection at each start (the supervisor asks the
                // credential authority), never this capture.
                let exact_entries = profile_slots.len() == profile.entries.len()
                    && !profile_slots.contains("github");
                profile_slots.insert("github".to_owned());
                anyhow::ensure!(
                    profile.revision > 0
                        && exact_entries
                        && codewire_access::ManagedCredentialClients::from_profile_slots(
                            profile_slots.iter().map(String::as_str),
                        )
                        .is_ok(),
                    "platform profile metadata has no exact revision or canonical capability slots"
                );
                let anthropic_credential = profile
                    .entries
                    .iter()
                    .find(|entry| entry.capability_slot == "anthropic")
                    .map(|entry| entry.credential_id.clone());
                candidates.push(Candidate {
                    placement: StoragePlacement::Platform,
                    id: profile.id.clone(),
                    name: name.clone(),
                    profile: Some(ResolvedProfile {
                        id: profile.id,
                        reference: format!("user/{name}"),
                        revision: profile.revision,
                        profile_slots,
                        anthropic_form: String::new(),
                    }),
                    anthropic_credential,
                });
            }
            if response.next_page_token.is_empty() {
                return Ok(candidates);
            }
            anyhow::ensure!(
                seen.insert(response.next_page_token.clone()),
                "platform profile metadata pagination repeated a cursor"
            );
            page_token = response.next_page_token;
        }
        anyhow::bail!(
            "platform profile metadata exceeded the complete-list page bound; no selection was made"
        );
    }
    Ok(candidates)
}

async fn project_candidates(
    local: Option<&mut LocalCredentialClient>,
    platform: Option<&PlatformMetadata>,
    reference: StorageReference<'_>,
) -> anyhow::Result<Vec<Candidate>> {
    let mut candidates = Vec::new();
    if reference.placement != Some(StoragePlacement::Platform) {
        for project in local_authority(local)?
            .list_secret_projects()
            .await
            .context("list local secret project metadata")?
        {
            let id = project.id.to_string();
            exact_id(&id)?;
            candidates.push(Candidate {
                placement: StoragePlacement::Local,
                id,
                name: project.name,
                profile: None,
                anthropic_credential: None,
            });
        }
    }
    if reference.placement != Some(StoragePlacement::Local)
        && let Some(platform) = platform
    {
        for project in SecretClient::new(&platform.config)?
            .list_secret_projects(&platform.authority.organization_id)
            .await
            .context("list platform secret project metadata")?
        {
            anyhow::ensure!(
                project.org_id == platform.authority.organization_id,
                "platform secret project metadata has a different organization"
            );
            exact_id(&project.id)?;
            candidates.push(Candidate {
                placement: StoragePlacement::Platform,
                id: project.id,
                name: project.name,
                profile: None,
                anthropic_credential: None,
            });
        }
    }
    Ok(candidates)
}

/// What a source reference names, for the refusal when it names nothing,
/// and the command that lists them.
#[derive(Clone, Copy)]
enum SourceKind {
    Project,
    Profile,
}

fn select_candidate(
    candidates: Vec<Candidate>,
    reference: StorageReference<'_>,
    kind: SourceKind,
) -> anyhow::Result<Candidate> {
    let selector = reference
        .selector
        .strip_prefix("user/")
        .unwrap_or(reference.selector);
    let mut matches = candidates.into_iter().filter(|candidate| {
        reference
            .placement
            .is_none_or(|placement| placement == candidate.placement)
            && match selector.strip_prefix("id:") {
                Some(id) => candidate.id == id,
                None => candidate.name.eq_ignore_ascii_case(selector),
            }
    });
    let selected = matches
        .next()
        .ok_or_else(|| no_such_source(kind, reference.placement, selector))?;
    anyhow::ensure!(
        matches.next().is_none(),
        "source name or ID is ambiguous; qualify it with local: or platform: and, if needed, an exact id:"
    );
    Ok(selected)
}

/// That no `kind` is named `selector` where `placement` looks (both stores
/// when it names neither), and the command that lists them, in the words
/// a cloud create uses (docs/dev/CLI-PARITY.md, R4).
fn no_such_source(
    kind: SourceKind,
    placement: Option<StoragePlacement>,
    selector: &str,
) -> anyhow::Error {
    let (what, list) = match kind {
        SourceKind::Project => ("secret project", "secrets projects list"),
        SourceKind::Profile => ("credential profile", "credentials profiles list"),
    };
    let (place, flag) = match placement {
        Some(StoragePlacement::Local) => ("local ", "--local"),
        Some(StoragePlacement::Platform) => ("cloud ", "--cloud"),
        None => ("", "--local"),
    };
    let anywhere = if placement.is_none() {
        ", local or cloud"
    } else {
        ""
    };
    crate::error_report::with_next_step(
        anyhow::anyhow!("there is no {place}{what} {selector:?}{anywhere}"),
        format!("cw {flag} {list}"),
    )
}

fn canonical_reference(candidate: &Candidate) -> String {
    format!(
        "{}:id:{}",
        match candidate.placement {
            StoragePlacement::Local => "local",
            StoragePlacement::Platform => "platform",
        },
        candidate.id
    )
}

/// Resolve only explicitly changed fields. Retained references and immutable
/// revisions are not refreshed by an unrelated source edit.
pub(super) async fn resolve_requested_sources(
    globals: &Globals,
    paths: &ResolvePaths,
    env: &impl config::Env,
    mut local: Option<&mut LocalCredentialClient>,
    spec: &mut ProjectSpec,
    changes: SourceChanges,
) -> anyhow::Result<ResolvedSources> {
    spec.validate()?;
    let project = (changes.project && !spec.secrets.project.is_empty())
        .then(|| StorageReference::project(&spec.secrets.project))
        .transpose()?;
    let profile = if changes.profile {
        spec.credentials
            .as_ref()
            .map(|profile| StorageReference::profile(&profile.profile))
            .transpose()?
    } else {
        None
    };
    let platform_scope = changes.platform_scopes
        && (spec.secrets.organization || spec.secrets.user == Some(StoragePlacement::Platform));
    let needs_platform = platform_scope
        || [project, profile]
            .into_iter()
            .flatten()
            .any(|r| r.placement != Some(StoragePlacement::Local));
    let requires_platform = platform_scope
        || [project, profile]
            .into_iter()
            .flatten()
            .any(|r| r.placement == Some(StoragePlacement::Platform));
    let platform = if needs_platform {
        platform_metadata(globals, paths, env, requires_platform).await?
    } else {
        None
    };
    let mut selected = ResolvedSources::default();
    let mut used_platform = platform_scope;
    if let Some(reference) = project {
        let candidates =
            project_candidates(local.as_deref_mut(), platform.as_ref(), reference).await?;
        let candidate = select_candidate(candidates, reference, SourceKind::Project)?;
        used_platform |= candidate.placement == StoragePlacement::Platform;
        spec.secrets.project = canonical_reference(&candidate);
        selected.project_name = Some(candidate.name);
    }
    if let Some(reference) = profile {
        let candidates = profile_candidates(local, platform.as_ref(), reference).await?;
        let mut candidate = select_candidate(candidates, reference, SourceKind::Profile)?;
        used_platform |= candidate.placement == StoragePlacement::Platform;
        spec.credentials = Some(CredentialBinding {
            profile: canonical_reference(&candidate),
        });
        if let (Some(credential_id), Some(profile)) = (
            candidate.anthropic_credential.take(),
            candidate.profile.as_mut(),
        ) {
            let platform = platform
                .as_ref()
                .context("platform profile metadata has no authenticated platform")?;
            profile.anthropic_form = anthropic_form(&platform.client, credential_id).await?;
        }
        selected.profile = candidate.profile;
    }
    if used_platform {
        let mut authority = platform
            .context("platform source authority was not authenticated")?
            .authority;
        authority.profile_slots =
            platform_profile_slots(spec, selected.profile.as_ref(), changes.profile)?;
        authority.anthropic_form = if authority.profile_slots.is_empty() {
            String::new()
        } else {
            selected
                .profile
                .as_ref()
                .map(|profile| profile.anthropic_form.clone())
                .unwrap_or_default()
        };
        selected.platform = Some(authority);
    }
    Ok(selected)
}

/// The form Claude Code runs in for a platform profile's Anthropic credential,
/// chosen as hosted orchestration chooses it: "subscription_token" for a
/// Claude subscription token (the anthropic provider's OAuth kind), "sign_in"
/// for a Claude sign-in, and empty for an API key. Reads metadata only.
async fn anthropic_form(
    client: &codewire_client::CodewireClient,
    credential_id: String,
) -> anyhow::Result<String> {
    let credential = client
        .get_credential(codewire_client::GetCredentialRequest {
            selector: Some(
                codewire_client::get_credential_request::Selector::CredentialId(credential_id),
            ),
            ..Default::default()
        })
        .await
        .context("read the platform profile's Anthropic credential metadata")?
        .credential
        .into_option()
        .context("platform omitted the profile's Anthropic credential metadata")?;
    anyhow::ensure!(
        credential.provider == "anthropic",
        "the platform profile's Anthropic slot holds another provider's credential"
    );
    let kind = &credential.authentication_kind;
    Ok(
        if *kind == codewire_client::CredentialAuthenticationKind::Oauth {
            "subscription_token"
        } else if *kind == codewire_client::CredentialAuthenticationKind::ClaudeSignIn {
            "sign_in"
        } else if *kind == codewire_client::CredentialAuthenticationKind::ApiKey {
            ""
        } else {
            anyhow::bail!("the platform profile's Anthropic credential has an unsupported kind")
        }
        .to_owned(),
    )
}

fn platform_profile_slots(
    spec: &ProjectSpec,
    profile: Option<&ResolvedProfile>,
    profile_was_resolved: bool,
) -> anyhow::Result<Vec<String>> {
    if !spec
        .credentials
        .as_ref()
        .is_some_and(|profile| profile.profile.starts_with("platform:"))
    {
        return Ok(Vec::new());
    }
    match profile {
        Some(profile) => Ok(profile.profile_slots.iter().cloned().collect()),
        None if profile_was_resolved => {
            anyhow::bail!("platform profile metadata was not resolved")
        }
        // An unrelated platform application-source edit retains the existing
        // profile and its immutable slots in select_platform_authority.
        None => Ok(Vec::new()),
    }
}

pub(super) fn validate_created_environment(
    environment: &v1::Environment,
    request: &v1::CreateEnvironmentRequest,
) -> anyhow::Result<()> {
    exact_id(&environment.id)?;
    anyhow::ensure!(
        environment.name == request.name
            && environment.project_spec_json == request.project_spec_json
            && environment.project_spec_sha256 == request.project_spec_sha256
            && environment.access_profile_id == request.access_profile_id
            && environment.access_profile_revision == request.access_profile_revision
            && environment.access_profile == request.access_profile_reference
            && environment.platform_source_authority == request.platform_source_authority,
        "native environment creation returned different source metadata"
    );
    project_from_environment(environment)?;
    Ok(())
}

pub(super) fn uses_platform(spec: &ProjectSpec) -> bool {
    spec.secrets.organization
        || spec.secrets.user == Some(StoragePlacement::Platform)
        || spec.secrets.project.starts_with("platform:")
        || spec
            .credentials
            .as_ref()
            .is_some_and(|profile| profile.profile.starts_with("platform:"))
}

pub(super) fn retained_platform_source(spec: &ProjectSpec, args: &EnvUpdateArgs) -> bool {
    (!args.clear_secrets
        && ((args.secrets.is_none() && spec.secrets.project.starts_with("platform:"))
            || (args.user_secrets.is_none()
                && spec.secrets.user == Some(StoragePlacement::Platform))
            || (!args.org_secrets && spec.secrets.organization)))
        || (!args.clear_profile
            && args.profile.is_none()
            && spec
                .credentials
                .as_ref()
                .is_some_and(|profile| profile.profile.starts_with("platform:")))
}

pub(super) fn select_platform_authority(
    current: Option<&v1::PlatformSourceAuthority>,
    requested: Option<v1::PlatformSourceAuthority>,
    retained: bool,
    target: &ProjectSpec,
    profile: Option<&ResolvedProfile>,
) -> anyhow::Result<Option<v1::PlatformSourceAuthority>> {
    if !uses_platform(target) {
        return Ok(None);
    }
    if retained && let Some(requested) = &requested {
        let same_origin = current.is_some_and(|current| {
            current.server_url == requested.server_url
                && current.organization_id == requested.organization_id
                && current.user_id == requested.user_id
        });
        anyhow::ensure!(
            same_origin,
            "new platform selection has a different server, organization, or account; explicitly replace or clear all retained platform sources"
        );
    }
    let mut authority = requested
        .or_else(|| current.cloned())
        .context("platform source selection has no authenticated origin descriptor")?;
    (authority.profile_slots, authority.anthropic_form) = if target
        .credentials
        .as_ref()
        .is_some_and(|binding| binding.profile.starts_with("platform:"))
    {
        let profile = profile.context("platform profile selection has no exact metadata")?;
        (
            profile.profile_slots.iter().cloned().collect(),
            profile.anthropic_form.clone(),
        )
    } else {
        (Vec::new(), String::new())
    };
    Ok(Some(authority))
}

pub(super) fn profile_from_environment(environment: &v1::Environment) -> Option<ResolvedProfile> {
    (!environment.access_profile_id.is_empty()).then(|| ResolvedProfile {
        id: environment.access_profile_id.clone(),
        reference: environment.access_profile.clone(),
        revision: environment.access_profile_revision,
        profile_slots: environment
            .platform_source_authority
            .as_ref()
            .map(|authority| authority.profile_slots.iter().cloned().collect())
            .unwrap_or_default(),
        anthropic_form: environment
            .platform_source_authority
            .as_ref()
            .map(|authority| authority.anthropic_form.clone())
            .unwrap_or_default(),
    })
}

pub(super) fn validate_exact_sources(
    spec: &ProjectSpec,
    profile: Option<&ResolvedProfile>,
    platform: Option<&v1::PlatformSourceAuthority>,
) -> anyhow::Result<()> {
    spec.validate()?;
    for reference in [
        (!spec.secrets.project.is_empty()).then_some(spec.secrets.project.as_str()),
        spec.credentials.as_ref().map(|p| p.profile.as_str()),
    ]
    .into_iter()
    .flatten()
    {
        let id = reference
            .strip_prefix("local:id:")
            .or_else(|| reference.strip_prefix("platform:id:"))
            .context("native source metadata does not contain exact origin-qualified IDs")?;
        exact_id(id)?;
    }
    let authority_slots = platform
        .map(|authority| {
            let slots = authority
                .profile_slots
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>();
            anyhow::ensure!(
                slots.len() == authority.profile_slots.len()
                    && !authority
                        .profile_slots
                        .windows(2)
                        .any(|pair| pair[0] >= pair[1])
                    && codewire_access::ManagedCredentialClients::from_profile_slots(
                        slots.iter().map(String::as_str),
                    )
                    .is_ok(),
                "native platform profile capability slots are invalid"
            );
            Ok::<_, anyhow::Error>(slots)
        })
        .transpose()?
        .unwrap_or_default();
    match (&spec.credentials, profile) {
        (Some(binding), Some(profile)) => {
            exact_id(&profile.id)?;
            anyhow::ensure!(
                profile.revision > 0 && binding.profile.ends_with(&format!(":id:{}", profile.id)),
                "native credential selection and exact profile metadata differ"
            );
            let reference: AccessProfileReference = profile
                .reference
                .parse()
                .context("native credential scope/name metadata is invalid")?;
            if binding.profile.starts_with("local:") {
                anyhow::ensure!(
                    reference.scope() == AccessProfileScope::User
                        && profile.profile_slots.is_empty()
                        && authority_slots.is_empty(),
                    "local profile metadata must be personal"
                );
            } else {
                anyhow::ensure!(
                    binding.profile.starts_with("platform:")
                        && platform.is_some_and(|authority| {
                            authority.anthropic_form == profile.anthropic_form
                        })
                        && profile.profile_slots == authority_slots,
                    "platform profile capability slots differ from the exact selected metadata"
                );
            }
        }
        (None, None) => anyhow::ensure!(
            authority_slots.is_empty(),
            "native platform metadata has profile slots without a selected profile"
        ),
        _ => anyhow::bail!("native credential selection and exact profile metadata differ"),
    }
    anyhow::ensure!(
        uses_platform(spec) == platform.is_some(),
        "native platform origin descriptor does not match selected sources"
    );
    if let Some(authority) = platform {
        validate_identity_component(&authority.user_id)?;
        validate_identity_component(&authority.organization_id)?;
        let server = url::Url::parse(&authority.server_url)
            .context("native platform source server is invalid")?;
        anyhow::ensure!(
            matches!(server.scheme(), "http" | "https")
                && server.username().is_empty()
                && server.password().is_none()
                && server.query().is_none()
                && server.fragment().is_none(),
            "native platform source server must be a credential-free HTTP origin"
        );
    }
    Ok(())
}

pub(super) fn project_from_environment(
    environment: &v1::Environment,
) -> anyhow::Result<ProjectSpec> {
    anyhow::ensure!(
        !environment.project_spec_json.is_empty()
            && environment.project_spec_json.len() <= codewire_project::MAX_PROJECT_DOCUMENT_BYTES,
        "native environment did not return bounded source configuration metadata"
    );
    let spec: ProjectSpec = serde_json::from_slice(&environment.project_spec_json)
        .context("native source configuration metadata is invalid")?;
    anyhow::ensure!(
        spec.canonical_json()? == environment.project_spec_json
            && format!("{:x}", Sha256::digest(&environment.project_spec_json))
                == environment.project_spec_sha256,
        "native source configuration metadata is not canonical or its digest differs"
    );
    anyhow::ensure!(
        !(environment.access_profile_id.is_empty()
            && (!environment.access_profile.is_empty()
                || environment.access_profile_revision != 0)),
        "native credential selection metadata is incomplete"
    );
    validate_exact_sources(
        &spec,
        profile_from_environment(environment).as_ref(),
        environment.platform_source_authority.as_ref(),
    )?;
    Ok(spec)
}

pub(super) fn update_request(
    environment: &v1::Environment,
    target: &ProjectSpec,
    profile: Option<&ResolvedProfile>,
    platform: Option<&v1::PlatformSourceAuthority>,
) -> anyhow::Result<v1::UpdateEnvironmentSourcesRequest> {
    exact_id(&environment.id)?;
    anyhow::ensure!(
        !environment.name.trim().is_empty() && environment.generation > 0,
        "native environment identity or operation generation is missing"
    );
    anyhow::ensure!(
        matches!(
            v1::EnvironmentState::try_from(environment.state),
            Ok(v1::EnvironmentState::Running | v1::EnvironmentState::Stopped)
        ),
        "native source updates require a stable running or stopped environment; use the existing lifecycle commands first"
    );
    let current = project_from_environment(environment)?;
    let mut current_non_sources = current.clone();
    let mut target_non_sources = target.clone();
    current_non_sources.secrets = SecretBindings::default();
    current_non_sources.credentials = None;
    target_non_sources.secrets = SecretBindings::default();
    target_non_sources.credentials = None;
    anyhow::ensure!(
        current_non_sources == target_non_sources,
        "source updates cannot change unrelated project configuration"
    );
    validate_exact_sources(target, profile, platform)?;
    let project_spec_json = target.canonical_json()?;
    anyhow::ensure!(
        project_spec_json.len() <= codewire_project::MAX_PROJECT_DOCUMENT_BYTES,
        "native source update configuration exceeds the bounded project document size"
    );
    let project_spec_sha256 = format!("{:x}", Sha256::digest(&project_spec_json));
    let changed = sources_changed(environment, &current, target, profile, platform);
    Ok(v1::UpdateEnvironmentSourcesRequest {
        name: environment.name.clone(),
        request_id: Uuid::new_v4().to_string(),
        expected_environment_id: environment.id.clone(),
        expected_generation: environment.generation,
        expected_project_spec_sha256: environment.project_spec_sha256.clone(),
        expected_access_profile_id: environment.access_profile_id.clone(),
        expected_access_profile_revision: environment.access_profile_revision,
        project_spec_json,
        project_spec_sha256,
        access_profile_id: profile.map(|p| p.id.clone()).unwrap_or_default(),
        access_profile_revision: profile.map(|p| p.revision).unwrap_or_default(),
        access_profile_reference: profile.map(|p| p.reference.clone()).unwrap_or_default(),
        allow_restart: changed && environment.state == v1::EnvironmentState::Running as i32,
        expected_platform_source_authority: environment.platform_source_authority.clone(),
        platform_source_authority: platform.cloned(),
    })
}

/// The preview's rows for `spec`, with the selected project's name when it
/// is known, its profile and the cloud it reads cloud sources from.
fn preview_rows(
    spec: &ProjectSpec,
    project_name: Option<&str>,
    profile: Option<&ResolvedProfile>,
    platform: Option<&v1::PlatformSourceAuthority>,
) -> SourceRows {
    SourceRows::new(
        &spec.secrets,
        project_name,
        spec.credentials
            .as_ref()
            .map(|binding| binding.profile.as_str()),
        profile.map(|profile| profile.reference.as_str()),
        profile.map(|profile| profile.revision),
    )
    .with_cloud_server(platform.map(|platform| platform.server_url.as_str()))
}

pub(super) fn confirm_create_sources(
    name: &str,
    spec: &ProjectSpec,
    selected: &ResolvedSources,
    yes: bool,
    output: OutputFormat,
) -> anyhow::Result<()> {
    validate_exact_sources(spec, selected.profile.as_ref(), selected.platform.as_ref())?;
    let rows = preview_rows(
        spec,
        selected.project_name.as_deref(),
        selected.profile.as_ref(),
        selected.platform.as_ref(),
    );
    eprint!(
        "{}",
        source_preview::create_preview(name, VmLocation::Local, &rows)
    );
    source_preview::confirm(yes, output)
}

/// Whether `target`, `profile` and `platform` change what `environment`
/// has selected now.
pub(super) fn sources_changed(
    environment: &v1::Environment,
    current: &ProjectSpec,
    target: &ProjectSpec,
    profile: Option<&ResolvedProfile>,
    platform: Option<&v1::PlatformSourceAuthority>,
) -> bool {
    current != target
        || profile_from_environment(environment).as_ref() != profile
        || environment.platform_source_authority.as_ref() != platform
}

/// The request for `update`, once its preview is confirmed, or `None` when
/// it changes nothing, which is said and neither asked nor sent.
pub(super) fn reviewed_update(
    environment: &v1::Environment,
    current: &ProjectSpec,
    target: &ProjectSpec,
    resolved: ResolvedSources,
    args: &EnvUpdateArgs,
) -> anyhow::Result<Option<v1::UpdateEnvironmentSourcesRequest>> {
    let profile = if args.clear_profile {
        None
    } else if args.profile.is_some() {
        resolved.profile
    } else {
        profile_from_environment(environment)
    };
    let platform = select_platform_authority(
        environment.platform_source_authority.as_ref(),
        resolved.platform,
        retained_platform_source(current, args),
        target,
        profile.as_ref(),
    )?;
    let (profile, platform) = (profile.as_ref(), platform.as_ref());
    if !sources_changed(environment, current, target, profile, platform) {
        source_preview::report_unchanged(&environment.name, args.output);
        return Ok(None);
    }
    let request = update_request(environment, target, profile, platform)?;
    let now = preview_rows(
        current,
        None,
        profile_from_environment(environment).as_ref(),
        environment.platform_source_authority.as_ref(),
    );
    let then = preview_rows(target, resolved.project_name.as_deref(), profile, platform);
    eprint!(
        "{}",
        source_preview::update_preview(
            &environment.name,
            VmLocation::Local,
            &now,
            &then,
            effect(request.allow_restart),
        )
    );
    source_preview::confirm(args.yes, args.output)?;
    Ok(Some(request))
}

fn effect(restarts: bool) -> UpdateEffect {
    if restarts {
        UpdateEffect::Restart
    } else {
        UpdateEffect::NextStart
    }
}

/// After a source update: the environment in JSON, or the one result line.
pub(super) fn print_update_result(
    updated: &v1::Environment,
    restarts: bool,
    output: OutputFormat,
) -> anyhow::Result<()> {
    match output {
        OutputFormat::Json => super::print_native_environment(updated, output),
        OutputFormat::Text => {
            source_preview::print_result(&updated.name, VmLocation::Local, effect(restarts));
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct SourceView {
    secrets: SecretBindings,
    credentials: Option<CredentialView>,
    platform: Option<PlatformView>,
}

#[derive(Clone, Debug, Serialize)]
struct CredentialView {
    profile: String,
    reference: String,
    revision: u64,
}

#[derive(Clone, Debug, Serialize)]
struct PlatformView {
    server_url: String,
    organization_id: String,
    user_id: String,
}

pub(super) fn source_view(environment: &v1::Environment) -> anyhow::Result<Option<SourceView>> {
    if environment.project_spec_json.is_empty() {
        return Ok(None);
    }
    let spec = project_from_environment(environment)?;
    Ok(Some(SourceView {
        secrets: spec.secrets,
        credentials: spec.credentials.map(|profile| CredentialView {
            profile: profile.profile,
            reference: environment.access_profile.clone(),
            revision: environment.access_profile_revision,
        }),
        platform: environment
            .platform_source_authority
            .as_ref()
            .map(|platform| PlatformView {
                server_url: platform.server_url.clone(),
                organization_id: platform.organization_id.clone(),
                user_id: platform.user_id.clone(),
            }),
    }))
}

/// `credentials_note` goes on its own lines under the `Credentials` row:
/// what a running VM's agents hold (#4912).
pub(super) fn format_source_view(view: Option<&SourceView>, credentials_note: &[String]) -> String {
    use crate::commands::progress::terminal_text;
    use codewire_project::StoragePlacement;

    let under = credentials_note
        .iter()
        .map(|line| format!("             {line}\n"))
        .collect::<String>();
    let Some(view) = view else {
        // No row to put the note under, so its first line takes the label.
        return format!(
            "Sources:     metadata unavailable\n{}",
            under.replacen("             ", "Credentials: ", 1)
        );
    };
    let secrets = &view.secrets;
    let mut output = format!(
        "Secrets:     {}\n",
        if secrets.project.is_empty() {
            "none".to_owned()
        } else {
            terminal_text(&secrets.project)
        }
    );
    if let Some(placement) = secrets.user {
        output.push_str(match placement {
            StoragePlacement::Local => "User secrets: local\n",
            StoragePlacement::Platform => "User secrets: cloud\n",
        });
    }
    if secrets.organization {
        output.push_str("Org secrets: cloud organization\n");
    }
    if let Some(profile) = &view.credentials {
        output.push_str(&format!(
            "Credentials: {} ({}, revision {})\n",
            terminal_text(&profile.profile),
            terminal_text(&profile.reference),
            profile.revision
        ));
    } else {
        output.push_str("Credentials: none\n");
    }
    output.push_str(&under);
    if let Some(platform) = &view.platform {
        output.push_str(&format!(
            "Source server: {}\nSource org: {}\nSource account: {}\n",
            terminal_text(&platform.server_url),
            terminal_text(&platform.organization_id),
            terminal_text(&platform.user_id)
        ));
    }
    output
}

#[cfg(test)]
mod tests;
