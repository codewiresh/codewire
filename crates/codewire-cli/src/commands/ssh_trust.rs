//! `cw ssh known-hosts`, the managed OpenSSH block's only host-key trust
//! source (`KnownHostsCommand`).
//!
//! An environment's SSH server runs inside its sandbox and holds a host key
//! the daemon of its currently bound Pod generated; only the public key is
//! recorded with the platform. OpenSSH asks this command for the
//! key of the host it is about to trust, and this command answers with exactly
//! one known_hosts line built from the recorded key fetched through the
//! authenticated API. Every failure (an unknown host form, an unresolved
//! environment, no recorded key, an API error, a malformed key) prints nothing
//! and fails, so with `StrictHostKeyChecking yes` and no known_hosts files the
//! connection is refused rather than trusted on first use. Nothing is cached:
//! each connection reads the bound Pod's key.

use super::*;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;

#[derive(Debug, Subcommand)]
pub(crate) enum SshCommand {
    #[command(
        name = "known-hosts",
        about = "Print the recorded SSH host key of a Codewire host for OpenSSH's KnownHostsCommand"
    )]
    KnownHosts(SshKnownHostsArgs),
}

#[derive(Debug, Args)]
pub(crate) struct SshKnownHostsArgs {
    /// The host OpenSSH is checking (`%H`): `cw-cloud-<environment>`,
    /// `cw-<environment>`, or either as `[<alias>]:<port>`.
    #[arg(value_name = "HOST")]
    pub(crate) host: String,
}

pub(crate) async fn handle_ssh_command(
    globals: &Globals,
    command: SshCommand,
) -> anyhow::Result<()> {
    match command {
        SshCommand::KnownHosts(args) => handle_ssh_known_hosts(globals, &args.host).await,
    }
}

async fn handle_ssh_known_hosts(globals: &Globals, host: &str) -> anyhow::Result<()> {
    let target = KnownHostsTarget::parse(host)?;
    target.alias().check_placement(globals.placement)?;
    let line = if target.is_local(globals.placement) {
        let environment = local_ssh_target(globals, target.alias()).await?;
        local_known_hosts_line(
            &target,
            &super::native::native_ssh_host_key(&environment).await?,
        )?
    } else {
        cloud_known_hosts_line(globals, &target).await?
    };
    // The only write: nothing reaches stdout unless every check passed.
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(line.as_bytes())?;
    stdout.flush()?;
    Ok(())
}

async fn cloud_known_hosts_line(
    globals: &Globals,
    target: &KnownHostsTarget,
) -> anyhow::Result<String> {
    let env = OsEnv;
    let paths = ResolvePaths::from_env(&env)?;
    let platform = resolve_platform(globals, &paths, &env)?;
    let environment_client = EnvironmentClient::new(&platform)?;
    let orgs = organization_client(&platform)?
        .list_orgs()
        .await
        .context("list organizations")?;
    let org_id = resolve_org_id(&platform, &orgs, None)?;
    known_hosts_line(&environment_client, &org_id, target).await
}

/// A host key the platform recorded for an environment's bound Pod, with the
/// generation it was recorded at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RecordedHostKey {
    pub(crate) generation: u64,
    pub(crate) public_key_openssh: String,
}

/// The two platform reads `cw ssh known-hosts` needs.
pub(crate) trait EnvironmentHostKeys {
    /// The cloud environment an alias names; never a default target.
    async fn resolve_environment(
        &self,
        org_id: &str,
        alias: SshAlias<'_>,
    ) -> anyhow::Result<String>;

    /// The recorded host key of the environment's bound Pod, or `None` when
    /// none is recorded.
    async fn recorded_host_key(
        &self,
        org_id: &str,
        environment_id: &str,
    ) -> anyhow::Result<Option<RecordedHostKey>>;
}

impl EnvironmentHostKeys for EnvironmentClient {
    async fn resolve_environment(
        &self,
        org_id: &str,
        alias: SshAlias<'_>,
    ) -> anyhow::Result<String> {
        resolve_cloud_alias(self, org_id, alias).await
    }

    async fn recorded_host_key(
        &self,
        org_id: &str,
        environment_id: &str,
    ) -> anyhow::Result<Option<RecordedHostKey>> {
        self.get_environment_host_key(org_id, environment_id).await
    }
}

pub(crate) const CLOUD_ALIAS_PREFIX: &str = "cw-cloud-";
pub(crate) const LOCAL_ALIAS_PREFIX: &str = "cw-local-";

/// The placement an SSH host alias names (#3025). `cw-cloud-<ref>` is a
/// cloud environment and `cw-local-<ref>` a local VM; neither ever resolves
/// in the other placement. A bare `cw-<ref>`, or a plain reference, keeps
/// resolving in the cloud while the transition lasts, through at least
/// v0.5.x, because editors remember the aliases they connected to; ending it
/// is an owner decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AliasPlacement {
    Cloud,
    Local,
    Bare,
}

/// An SSH host alias, or a plain environment reference, split into the
/// placement it names and the environment reference after the prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SshAlias<'a> {
    pub(crate) placement: AliasPlacement,
    pub(crate) environment_ref: &'a str,
}

impl<'a> SshAlias<'a> {
    /// `value` as `cw shell --stdio`, `cw vscode` and `cw ssh known-hosts`
    /// take it. `None` for an empty value, or a prefix with nothing after it.
    pub(crate) fn parse(value: &'a str) -> Option<Self> {
        let value = trimmed_str(value)?;
        let (placement, environment_ref) =
            if let Some(rest) = value.strip_prefix(CLOUD_ALIAS_PREFIX) {
                (AliasPlacement::Cloud, rest)
            } else if let Some(rest) = value.strip_prefix(LOCAL_ALIAS_PREFIX) {
                (AliasPlacement::Local, rest)
            } else {
                (
                    AliasPlacement::Bare,
                    value.strip_prefix("cw-").unwrap_or(value),
                )
            };
        (!environment_ref.is_empty()).then_some(Self {
            placement,
            environment_ref,
        })
    }

    /// Refuses an alias that contradicts an explicit placement flag, before
    /// any lookup.
    pub(crate) fn check_placement(
        self,
        placement: Option<EnvironmentPlacement>,
    ) -> anyhow::Result<()> {
        match (self.placement, placement) {
            (AliasPlacement::Cloud, Some(EnvironmentPlacement::Local)) => anyhow::bail!(
                "`{CLOUD_ALIAS_PREFIX}{}` names a cloud environment, which --local does not reach",
                self.environment_ref
            ),
            (AliasPlacement::Local, Some(EnvironmentPlacement::Platform)) => anyhow::bail!(
                "`{LOCAL_ALIAS_PREFIX}{}` names a local VM, which --cloud does not reach",
                self.environment_ref
            ),
            _ => Ok(()),
        }
    }

    /// Whether this alias, under `placement`, names a local VM: a
    /// `cw-local-` alias always, any other only under `--local`.
    pub(crate) fn is_local(self, placement: Option<EnvironmentPlacement>) -> bool {
        self.placement == AliasPlacement::Local
            || (self.placement == AliasPlacement::Bare
                && placement == Some(EnvironmentPlacement::Local))
    }
}

/// The cloud environment a qualified `cw-cloud-<ref>` names: `<ref>` as any
/// reference resolves (ID, name, unique ID prefix), or, when that matches
/// nothing, the environment named exactly `cloud-<ref>`, which is what the
/// alias meant before it was qualified. When both exist it refuses rather
/// than pick one, because the trusted host key follows the choice.
pub(crate) fn resolve_qualified_cloud_ref(
    environments: &[Environment],
    environment_ref: &str,
) -> anyhow::Result<String> {
    let qualified = find_environment_match(environments, environment_ref)?.map(|(id, _)| id);
    let literal_name = format!("cloud-{environment_ref}");
    let literal = match environments
        .iter()
        .filter(|environment| environment.name.as_deref() == Some(literal_name.as_str()))
        .collect::<Vec<_>>()
        .as_slice()
    {
        [] => None,
        [environment] => Some(environment.id.clone()),
        many => anyhow::bail!(
            "multiple environments named {literal_name:?}, use ID: {}",
            many.iter()
                .map(|environment| environment.id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    };
    match (qualified, literal) {
        (Some(qualified), Some(literal)) if qualified != literal => anyhow::bail!(
            "`{CLOUD_ALIAS_PREFIX}{environment_ref}` matches two cloud environments: {environment_ref:?} ({qualified}) and {literal_name:?} ({literal}); connect by ID, for example `{CLOUD_ALIAS_PREFIX}{qualified}`"
        ),
        (Some(id), _) | (None, Some(id)) => Ok(id),
        (None, None) => anyhow::bail!(
            "no cloud environment matches {environment_ref:?} (from `{CLOUD_ALIAS_PREFIX}{environment_ref}`); `cw --cloud ls` lists yours"
        ),
    }
}

/// `cw-local-<ref>` named no local VM. When a cloud environment is named
/// exactly `local-<ref>`, which the alias meant before it was reserved, the
/// error names the aliases that reach it.
pub(crate) fn local_alias_not_found(
    environment_ref: &str,
    environments: Option<&[Environment]>,
) -> anyhow::Error {
    let mut message = format!(
        "no local VM matches {environment_ref:?} (from `{LOCAL_ALIAS_PREFIX}{environment_ref}`); `cw --local ls` lists yours"
    );
    let literal = format!("local-{environment_ref}");
    if let Some(environment) = environments.and_then(|environments| {
        environments
            .iter()
            .find(|environment| environment.name.as_deref() == Some(literal.as_str()))
    }) {
        message.push_str(&format!(
            ". The cloud environment {literal:?} is `{CLOUD_ALIAS_PREFIX}{literal}` or `cw-{}`",
            environment.id
        ));
    }
    anyhow::anyhow!(message)
}

/// The not-found error for a local alias, naming a same-named cloud
/// environment's aliases when the cloud can be read within a few seconds.
async fn local_alias_not_found_with_hint(
    globals: &Globals,
    environment_ref: &str,
) -> anyhow::Error {
    let environments = crate::commands::lifecycle_output::bounded(async {
        let env = OsEnv;
        let paths = ResolvePaths::from_env(&env)?;
        let platform = resolve_platform(globals, &paths, &env)?;
        let orgs = organization_client(&platform)?.list_orgs().await?;
        let org_id = resolve_org_id(&platform, &orgs, None)?;
        EnvironmentClient::new(&platform)?
            .list_environments(&org_id, false)
            .await
    })
    .await;
    local_alias_not_found(environment_ref, environments.as_deref())
}

/// The local VM a local alias, or a reference under `--local`, names. A
/// `cw-local-<ref>` that matches no local VM says where a same-named cloud
/// environment went.
pub(crate) async fn local_ssh_target(
    globals: &Globals,
    alias: SshAlias<'_>,
) -> anyhow::Result<codewire_local_vmm::control::v1::Environment> {
    if alias.placement != AliasPlacement::Local {
        return super::native::native_ssh_target(Some(alias.environment_ref)).await;
    }
    match super::native::native_environment(alias.environment_ref).await? {
        Some(environment) => Ok(environment),
        None => Err(local_alias_not_found_with_hint(globals, alias.environment_ref).await),
    }
}

/// The known_hosts line for a local VM's supervisor-held key, under the host
/// name OpenSSH asked about.
pub(crate) fn local_known_hosts_line(
    target: &KnownHostsTarget,
    public_key_openssh: &str,
) -> anyhow::Result<String> {
    let key = canonical_ed25519_public_key(public_key_openssh)?;
    Ok(format!("{} {key}\n", target.token))
}

/// The cloud environment `alias` names: a bare one as any reference
/// resolves, a qualified one by [`resolve_qualified_cloud_ref`]. A local
/// alias never resolves here.
pub(crate) async fn resolve_cloud_alias(
    client: &EnvironmentClient,
    org_id: &str,
    alias: SshAlias<'_>,
) -> anyhow::Result<String> {
    match alias.placement {
        AliasPlacement::Bare => resolve_environment_id(client, org_id, alias.environment_ref).await,
        AliasPlacement::Cloud => {
            let environments = client
                .list_environments(org_id, false)
                .await
                .context("list environments")?;
            resolve_qualified_cloud_ref(&environments, alias.environment_ref)
        }
        AliasPlacement::Local => Err(cloud_refuses_local_alias(alias.environment_ref)),
    }
}

/// The host OpenSSH asked about, kept verbatim for the known_hosts line, and
/// the placement and environment reference it names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct KnownHostsTarget {
    token: String,
    placement: AliasPlacement,
    environment_ref: String,
}

impl KnownHostsTarget {
    pub(crate) fn parse(host: &str) -> anyhow::Result<Self> {
        let name = match host.strip_prefix('[') {
            Some(bracketed) => {
                let (name, port) = bracketed
                    .split_once("]:")
                    .ok_or_else(|| anyhow::anyhow!("unsupported SSH host {host:?}"))?;
                anyhow::ensure!(
                    !port.is_empty()
                        && port.bytes().all(|byte| byte.is_ascii_digit())
                        && port.parse::<u16>().is_ok_and(|port| port != 0),
                    "unsupported SSH host {host:?}"
                );
                name
            }
            None => host,
        };
        let alias = name
            .strip_prefix("cw-")
            .filter(|rest| {
                rest.bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
            })
            .and_then(|_| SshAlias::parse(name))
            .ok_or_else(|| anyhow::anyhow!("unsupported SSH host {host:?}"))?;
        Ok(Self {
            token: host.to_string(),
            placement: alias.placement,
            environment_ref: alias.environment_ref.to_string(),
        })
    }

    fn is_local(&self, placement: Option<EnvironmentPlacement>) -> bool {
        self.alias().is_local(placement)
    }

    fn alias(&self) -> SshAlias<'_> {
        SshAlias {
            placement: self.placement,
            environment_ref: &self.environment_ref,
        }
    }
}

/// One known_hosts line for `target` from the environment's recorded key.
pub(crate) async fn known_hosts_line(
    source: &impl EnvironmentHostKeys,
    org_id: &str,
    target: &KnownHostsTarget,
) -> anyhow::Result<String> {
    // A local alias never vouches for a cloud key: refused before any read.
    if target.placement == AliasPlacement::Local {
        return Err(cloud_refuses_local_alias(&target.environment_ref));
    }
    let environment_id = source.resolve_environment(org_id, target.alias()).await?;
    let key = source
        .recorded_host_key(org_id, &environment_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("environment has no recorded SSH host key"))?;
    let key = canonical_ed25519_public_key(&key.public_key_openssh)?;
    Ok(format!("{} {key}\n", target.token))
}

/// A `cw-local-` alias reached a cloud lookup, which serves no local VM.
fn cloud_refuses_local_alias(environment_ref: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "`{LOCAL_ALIAS_PREFIX}{environment_ref}` names a local VM, which the cloud does not serve"
    )
}

const ED25519_KEY_TYPE: &str = "ssh-ed25519";
const ED25519_PUBLIC_KEY_LEN: usize = 32;

/// `ssh-ed25519 <base64>` re-encoded from a validated wire blob (RFC 8709):
/// the type string and one 32-byte key, nothing more. Any comment is dropped.
pub(crate) fn canonical_ed25519_public_key(openssh: &str) -> anyhow::Result<String> {
    let mut fields = openssh.split_ascii_whitespace();
    anyhow::ensure!(
        fields.next() == Some(ED25519_KEY_TYPE),
        "recorded SSH host key is not Ed25519"
    );
    let blob = fields
        .next()
        .and_then(|encoded| BASE64.decode(encoded).ok())
        .ok_or_else(|| anyhow::anyhow!("recorded SSH host key is malformed"))?;
    let mut expected_prefix = Vec::with_capacity(4 + ED25519_KEY_TYPE.len() + 4);
    expected_prefix.extend_from_slice(&(ED25519_KEY_TYPE.len() as u32).to_be_bytes());
    expected_prefix.extend_from_slice(ED25519_KEY_TYPE.as_bytes());
    expected_prefix.extend_from_slice(&(ED25519_PUBLIC_KEY_LEN as u32).to_be_bytes());
    anyhow::ensure!(
        blob.len() == expected_prefix.len() + ED25519_PUBLIC_KEY_LEN
            && blob.starts_with(&expected_prefix),
        "recorded SSH host key is malformed"
    );
    Ok(format!("{ED25519_KEY_TYPE} {}", BASE64.encode(&blob)))
}
