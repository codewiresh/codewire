//! Git trusts the repositories of a local VM's mounted shares (#5478;
//! docs/dev/LINUX-LOCAL-VMS.md, "Direct mounts"). A share's files can belong
//! to someone other than the workload user, root's on a Mac, so Git would
//! refuse every mounted repository with "dubious ownership".
//!
//! At every boot of a VM with a share, the workload user's global Git config
//! includes `~/.codewire/gitconfig`, a file the product owns and rewrites
//! whole, holding `safe.directory = *`. The image's Git (2.43) ignores a
//! trailing `/*`, so the share paths alone would leave nested repositories
//! and submodules refused; cw-security agreed to `*` for a single-user local
//! VM only, never as a pattern for anywhere else.
//!
//! The write runs as the workload user through the workload's own launch
//! path, in the environment a launched session gets, never from the root
//! daemon directly: Git follows a symlinked `~/.gitconfig`, and root would
//! write its target. Nothing goes to a system file or to root's config, so
//! root's Git keeps refusing a repository the workload controls.

use std::process::Stdio;
use std::time::Duration;

use crate::Config;
use crate::execution::PreparedProcess;

/// How long one attempt may take.
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(10);
/// The guest daemon starts before the workspace container, so an attempt
/// fails until the container runs; attempts go on for this long.
const BOOT_DEADLINE: Duration = Duration::from_secs(60);
const RETRY_INTERVAL: Duration = Duration::from_secs(1);

/// The product's file, then one `include.path` line for it, added only when
/// missing. `$1` is the file's first line, which says who owns it. An image
/// may get Git only after boot (an `apk add git`), so without `git` the line
/// is appended to the file Git reads as global: `GIT_CONFIG_GLOBAL`, or
/// `~/.gitconfig`, which Git reads beside an XDG config.
const SCRIPT: &str = r#"set -eu
dir="$HOME/.codewire"
file="$dir/gitconfig"
mkdir -p "$dir"
tmp="$dir/.gitconfig.$$"
printf '%s\n' "$1" '[safe]' '	directory = *' > "$tmp"
mv -f "$tmp" "$file"
if command -v git >/dev/null 2>&1; then
	git config --global --fixed-value --get-all include.path "$file" >/dev/null ||
		git config --global --add include.path "$file"
else
	global="${GIT_CONFIG_GLOBAL:-$HOME/.gitconfig}"
	grep -qxF "	path = $file" "$global" 2>/dev/null ||
		printf '[include]\n\tpath = %s\n' "$file" >> "$global"
fi"#;

const OWNER_LINE: &str = "# Codewire rewrites this file at every boot of a local VM with a mounted \
folder (#5478). Put your own Git settings in ~/.gitconfig.";

/// Makes the workload user's Git trust the shares' repositories, retrying
/// until the workspace container runs. Logs the outcome; never fails the boot.
pub async fn trust_shared_repositories(config: &Config) {
    let environment: Vec<_> = std::env::vars().collect();
    match trust_within(config, BOOT_DEADLINE, environment).await {
        Ok(()) => tracing::info!("git trusts the mounted shares' repositories"),
        Err(reason) => {
            tracing::warn!(
                reason,
                "git could not be set to trust the mounted shares' repositories"
            )
        }
    }
}

/// [`trust_shared_repositories`] with an explicit deadline and daemon
/// environment, as `workspace_defaults` does: a test passes a synthetic one,
/// so `git config --global` never reaches the home it runs in.
async fn trust_within(
    config: &Config,
    deadline: Duration,
    daemon_environment: impl IntoIterator<Item = (String, String)> + Clone,
) -> Result<(), &'static str> {
    let started = tokio::time::Instant::now();
    loop {
        let outcome = attempt(config, daemon_environment.clone()).await;
        if outcome.is_ok() || started.elapsed() + RETRY_INTERVAL > deadline {
            return outcome;
        }
        tokio::time::sleep(RETRY_INTERVAL).await;
    }
}

async fn attempt(
    config: &Config,
    daemon_environment: impl IntoIterator<Item = (String, String)>,
) -> Result<(), &'static str> {
    let process = crate::env::build_process_env_in(config, &[], "", daemon_environment)
        .map_err(|_| "no session environment")?;
    let command = [
        "/bin/sh".to_owned(),
        "-c".to_owned(),
        SCRIPT.to_owned(),
        "codewire-git-trust".to_owned(),
        OWNER_LINE.to_owned(),
    ];
    let home = config.home_root.display().to_string();
    let mut prepared = PreparedProcess::prepare(
        &config.process_execution,
        &command,
        &home,
        &process.entries,
        false,
        0,
        0,
    )
    .map_err(|_| "could not prepare")?;
    let mut command = prepared.tokio_command();
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = command.spawn().map_err(|_| "could not start")?;
    let _cleanup = prepared.spawned();
    let status = match tokio::time::timeout(ATTEMPT_TIMEOUT, child.wait()).await {
        Ok(status) => status.map_err(|_| "could not wait")?,
        Err(_) => {
            // A child already gone can't be killed; the attempt has timed
            // out either way, and the next attempt starts afresh.
            let _ = child.kill().await;
            return Err("timed out");
        }
    };
    if status.success() {
        Ok(())
    } else {
        Err("git refused")
    }
}

#[cfg(test)]
mod tests;
