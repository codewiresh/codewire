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
    /// The host OpenSSH is checking (`%H`): `cw-<environment>` or
    /// `[cw-<environment>]:<port>`.
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
    let env = OsEnv;
    let paths = ResolvePaths::from_env(&env);
    let platform = resolve_platform(globals, &paths, &env)?;
    let environment_client = EnvironmentClient::new(&platform)?;
    let orgs = organization_client(&platform)?
        .list_orgs()
        .await
        .context("list organizations")?;
    let org_id = resolve_org_id(&platform, &orgs, None)?;
    let line = known_hosts_line(&environment_client, &org_id, &target).await?;
    // The only write: nothing reaches stdout unless every check passed.
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(line.as_bytes())?;
    stdout.flush()?;
    Ok(())
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
    /// The environment named by an explicit reference; never a default target.
    async fn resolve_environment(
        &self,
        org_id: &str,
        environment_ref: &str,
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
        environment_ref: &str,
    ) -> anyhow::Result<String> {
        resolve_environment_id(self, org_id, environment_ref).await
    }

    async fn recorded_host_key(
        &self,
        org_id: &str,
        environment_id: &str,
    ) -> anyhow::Result<Option<RecordedHostKey>> {
        self.get_environment_host_key(org_id, environment_id).await
    }
}

/// The host OpenSSH asked about, kept verbatim for the known_hosts line, and
/// the environment reference it names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct KnownHostsTarget {
    token: String,
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
        let environment_ref = name
            .strip_prefix("cw-")
            .filter(|environment_ref| {
                !environment_ref.is_empty()
                    && environment_ref.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
                    })
            })
            .ok_or_else(|| anyhow::anyhow!("unsupported SSH host {host:?}"))?;
        Ok(Self {
            token: host.to_string(),
            environment_ref: environment_ref.to_string(),
        })
    }
}

/// One known_hosts line for `target` from the environment's recorded key.
pub(crate) async fn known_hosts_line(
    source: &impl EnvironmentHostKeys,
    org_id: &str,
    target: &KnownHostsTarget,
) -> anyhow::Result<String> {
    let environment_id = source
        .resolve_environment(org_id, &target.environment_ref)
        .await?;
    let key = source
        .recorded_host_key(org_id, &environment_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("environment has no recorded SSH host key"))?;
    let key = canonical_ed25519_public_key(&key.public_key_openssh)?;
    Ok(format!("{} {key}\n", target.token))
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
