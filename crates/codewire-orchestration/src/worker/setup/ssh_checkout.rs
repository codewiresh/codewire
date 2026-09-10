//! Public per-repository SSH host trust for the existing managed setup exec.
//! This module neither grants an identity nor reads provider material.

use codewire_access::{ManagedCredentialClient, ManagedCredentialClients};
use codewire_project::{canonical_repository_known_hosts, parse_repository_ssh_host};

use super::Repo;

const SCRIPT: &str = include_str!("ssh_checkout.sh");

/// Validate the complete set before setup can remove or launch any checkout.
/// Unavailable selection metadata is not an empty or ambient credential source.
pub(super) fn commands(
    repositories: &[Repo],
    clients: Option<ManagedCredentialClients>,
) -> anyhow::Result<Vec<Option<Vec<String>>>> {
    repositories
        .iter()
        .map(|repository| {
            let canonical =
                canonical_repository_known_hosts(&repository.url, repository.known_hosts.clone())?;
            anyhow::ensure!(
                canonical == repository.known_hosts,
                "repository host trust must already be canonical"
            );
            let Some(host) = parse_repository_ssh_host(&repository.url)? else {
                return Ok(None);
            };
            anyhow::ensure!(
                clients.is_some_and(|clients| clients.contains(ManagedCredentialClient::Ssh)),
                "SSH repository checkout requires a selected SSH credential"
            );
            let mut command = vec![
                "/bin/sh".into(),
                "-c".into(),
                SCRIPT.into(),
                "codewire-ssh-checkout".into(),
                repository.url.clone(),
                repository.mount_path.clone(),
                host.host().into(),
                host.port().to_string(),
                host.known_hosts_name(),
            ];
            // Keep each bounded public pin in its own argv entry. Shell-quoting
            // a 64KiB trust set into the script could exceed a single-arg limit.
            command.extend(canonical);
            Ok(Some(command))
        })
        .collect()
}

#[cfg(test)]
mod tests;
