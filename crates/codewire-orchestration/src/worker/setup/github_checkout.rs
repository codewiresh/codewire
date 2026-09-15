//! Protected initial GitHub checkout using the already-admitted loopback bridge.
//! The profile selection is metadata, not authority: the bridge/broker still
//! checks the bound operation and selected identity on every smart Git request.

use codewire_access::{
    MANAGED_GITHUB_GIT_PREFIX, MANAGED_HTTP_PORT, ManagedCredentialClient, ManagedCredentialClients,
};

use super::Repo;

pub(super) struct Commands {
    pub clone: Vec<String>,
    pub checkout: Option<Vec<String>>,
}

/// Validate the complete set before setup removes or launches any checkout.
/// An explicit unselected profile preserves ordinary public/custom HTTPS; lost
/// selection metadata must never silently downgrade a GitHub checkout.
pub(super) fn commands(
    repositories: &[Repo],
    clients: Option<ManagedCredentialClients>,
) -> anyhow::Result<Vec<Option<Commands>>> {
    repositories
        .iter()
        .map(|repo| {
            let url = url::Url::parse(&repo.url).ok();
            let github = url.as_ref().is_some_and(|url| {
                url.scheme() != "ssh"
                    && url.host_str().is_some_and(|host| {
                        host.trim_end_matches('.')
                            .eq_ignore_ascii_case("github.com")
                    })
            });
            if !github {
                return Ok(None);
            }
            let clients = clients.ok_or_else(|| {
                anyhow::anyhow!("GitHub repository checkout selection is unavailable")
            })?;
            if !clients.contains(ManagedCredentialClient::GitHub) {
                return Ok(None);
            }
            let path = repo
                .url
                .strip_prefix("https://github.com/")
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "managed GitHub checkout requires a canonical HTTPS repository URL"
                    )
                })?;
            let (owner, repository) = path.split_once('/').ok_or_else(|| {
                anyhow::anyhow!("managed GitHub checkout requires an owner and repository")
            })?;
            anyhow::ensure!(
                [owner, repository].iter().all(|part| {
                    !part.is_empty()
                        && part.len() <= 128
                        && !matches!(*part, "." | ".." | ".git")
                        && part.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
                        })
                }),
                "managed GitHub checkout requires a canonical owner and repository"
            );
            // Git stores the source argument in remote.origin.url. The exact
            // command-local rewrite changes only this clone's network destination.
            let bridge =
                format!("http://127.0.0.1:{MANAGED_HTTP_PORT}{MANAGED_GITHUB_GIT_PREFIX}{path}");
            let mut clone = isolated_git();
            clone.extend([
                "-c".into(),
                format!("url.{bridge}.insteadOf={}", repo.url),
                "clone".into(),
                "--template=".into(),
                "--".into(),
                repo.url.clone(),
                repo.mount_path.clone(),
            ]);
            let selector = if repo.revision.is_empty() {
                &repo.branch
            } else {
                &repo.revision
            };
            let checkout = if selector.is_empty() {
                None
            } else {
                // Selectors are normally validated at the project boundary; keep
                // option injection impossible at this launch boundary as well.
                anyhow::ensure!(
                    !selector.starts_with('-') && !selector.chars().any(char::is_control),
                    "invalid GitHub checkout selector"
                );
                let mut command = isolated_git();
                command.extend(["-C".into(), repo.mount_path.clone(), "checkout".into()]);
                if !repo.revision.is_empty() {
                    command.push("--detach".into());
                }
                command.extend([selector.clone(), "--".into()]);
                Some(command)
            };
            Ok(Some(Commands { clone, checkout }))
        })
        .collect()
}

fn isolated_git() -> Vec<String> {
    // Fixed executables match the existing hosted SSH checkout. Clear all
    // ambient Git/curl/SSH/proxy/askpass inputs, including HOME-based .netrc.
    // Only rewritten HTTP is allowed; redirects and recursive transports fail
    // closed. This is command isolation, not enforced workload egress policy.
    [
        "/usr/bin/env",
        "-i",
        "PATH=/usr/bin:/bin",
        "LC_ALL=C",
        "HOME=/dev/null",
        "XDG_CONFIG_HOME=/dev/null",
        "GIT_CONFIG_NOSYSTEM=1",
        "GIT_CONFIG_SYSTEM=/dev/null",
        "GIT_CONFIG_GLOBAL=/dev/null",
        "GIT_ATTR_NOSYSTEM=1",
        "GIT_TERMINAL_PROMPT=0",
        "GIT_ALLOW_PROTOCOL=http",
        "/usr/bin/git",
        "-C",
        "/",
        "-c",
        "credential.helper=",
        "-c",
        "credential.interactive=false",
        "-c",
        "http.proxy=",
        "-c",
        "http.followRedirects=false",
        "-c",
        "http.extraHeader=",
        "-c",
        "protocol.allow=never",
        "-c",
        "protocol.http.allow=always",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

#[cfg(test)]
mod tests;
