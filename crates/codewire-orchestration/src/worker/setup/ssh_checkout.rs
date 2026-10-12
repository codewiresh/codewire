//! Public per-repository SSH host trust for the existing managed setup exec.
//! This module neither grants an identity nor reads provider material.
//!
//! A selected SSH key is preferred: an SSH source always uses it, and so does
//! a canonical `https://github.com/` source, cloned as `git@github.com:…` with
//! GitHub's published host keys. The latter falls back to HTTPS only when the
//! server refuses the key or the repository ([`SSH_REFUSED_EXIT`]).

use codewire_access::{ManagedCredentialClient, ManagedCredentialClients};
use codewire_project::{
    canonical_repository_known_hosts, github_ssh_source, parse_repository_ssh_host,
};

use super::Repo;

const SCRIPT: &str = include_str!("ssh_checkout.sh");

/// The checkout script's status when the SSH server refused the key or the
/// repository. A network or host-key failure keeps Git's own status instead.
pub(super) const SSH_REFUSED_EXIT: i32 = 77;

/// One repository's SSH clone command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Command {
    pub argv: Vec<String>,
    /// The repository source is the user's `https://github.com/` URL, which
    /// remains its HTTPS fallback when the key is refused.
    pub https_fallback: bool,
}

/// Validate the complete set before setup can remove or launch any checkout.
/// Unavailable selection metadata is not an empty or ambient credential source.
pub(super) fn commands(
    repositories: &[Repo],
    clients: Option<ManagedCredentialClients>,
) -> anyhow::Result<Vec<Option<Command>>> {
    let ssh_selected =
        clients.is_some_and(|clients| clients.contains(ManagedCredentialClient::Ssh));
    repositories
        .iter()
        .map(|repository| {
            let canonical =
                canonical_repository_known_hosts(&repository.url, repository.known_hosts.clone())?;
            anyhow::ensure!(
                canonical == repository.known_hosts,
                "repository host trust must already be canonical"
            );
            if parse_repository_ssh_host(&repository.url)?.is_some() {
                anyhow::ensure!(
                    ssh_selected,
                    "SSH repository checkout needs an SSH key in the Sandbox's credential profile"
                );
                return Ok(Some(Command {
                    argv: argv(&repository.url, &repository.mount_path, canonical)?,
                    https_fallback: false,
                }));
            }
            match github_ssh_source(&repository.url) {
                Some(github) if ssh_selected => Ok(Some(Command {
                    argv: argv(&github.source, &repository.mount_path, github.known_hosts)?,
                    https_fallback: true,
                })),
                _ => Ok(None),
            }
        })
        .collect()
}

fn argv(source: &str, destination: &str, known_hosts: Vec<String>) -> anyhow::Result<Vec<String>> {
    let host = parse_repository_ssh_host(source)?
        .ok_or_else(|| anyhow::anyhow!("SSH checkout requires an SSH repository source"))?;
    let mut command = vec![
        "/bin/sh".into(),
        "-c".into(),
        SCRIPT.into(),
        "codewire-ssh-checkout".into(),
        source.into(),
        destination.into(),
        host.host().into(),
        host.port().to_string(),
        host.known_hosts_name(),
    ];
    // Keep each bounded public pin in its own argv entry. Shell-quoting
    // a 64KiB trust set into the script could exceed a single-arg limit.
    command.extend(known_hosts);
    Ok(command)
}

#[cfg(test)]
mod tests;
