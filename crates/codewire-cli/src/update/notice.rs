//! The once-a-day newer-release notice of a command run by a person at a
//! terminal (#4479).
//!
//! It never holds the command up. When a day has passed since the last
//! check, the command starts a detached `cw upgrade _check`, which asks the
//! release server for the newest stable release, waits at most
//! [`CHECK_DEADLINE`] and records it. The command itself only reads what an
//! earlier check recorded and, after it succeeds, says once a day on stderr
//! that a newer release exists. It never runs with `--output json`, unless
//! both stdout and stderr are terminals, for a hidden or helper command (such
//! as the ssh ProxyCommand), with `CW_NO_UPDATE_CHECK=1`, in CI (`CI` set) or
//! for a development build. Any failure is silent.

use std::io::{IsTerminal as _, Write as _};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// How long the detached check waits for the release server.
const CHECK_DEADLINE: Duration = Duration::from_secs(10);
const DAY_SECONDS: u64 = 24 * 60 * 60;
/// Visible commands that never give the notice: they upgrade cw themselves,
/// or their output is a script another program reads.
const QUIET_COMMANDS: &[&str] = &["upgrade", "install", "completion"];

/// A started check, finished with [`finish`].
struct NewerReleaseCheck {
    path: PathBuf,
    current: String,
    now: u64,
}

/// After the command, in the one call `run_from` makes: the once-a-day
/// notice and check, then the command's result as
/// [`crate::credit_refusal::report`] gives it. The check is detached, so
/// starting it after the command holds nothing up either.
pub(crate) fn report(
    command: &clap::Command,
    matches: &clap::ArgMatches,
    result: anyhow::Result<()>,
    json: bool,
) -> anyhow::Result<()> {
    finish(start(command, matches, json), &result);
    crate::credit_refusal::report(result, json)
}

/// Starts the check for the command `matches` selected from `command`, or
/// `None` when it must not run.
fn start(
    command: &clap::Command,
    matches: &clap::ArgMatches,
    json: bool,
) -> Option<NewerReleaseCheck> {
    if !eligible(command, matches, json)
        || !std::io::stdout().is_terminal()
        || !std::io::stderr().is_terminal()
        || check_off(|name| std::env::var_os(name))
    {
        return None;
    }
    let current = crate::build_record::CLI_VERSION;
    if !current.starts_with('v') || !codewire_cw_release::release::valid_release_tag(current) {
        return None;
    }
    let path = state_path()?;
    let now = unix_now();
    let mut state = read_state(&path);
    if check_due(&state, now) {
        // Counted when started, so a slow or failed check isn't started again
        // by every command that day; without a written record it isn't
        // started at all.
        state.checked_at = now;
        if write_state(&path, &state).is_ok() {
            start_detached_check();
        }
    }
    Some(NewerReleaseCheck {
        path,
        current: current.to_owned(),
        now,
    })
}

/// Whether the command `matches` selected may give the notice at all: a
/// visible everyday command, without `--output json`.
fn eligible(command: &clap::Command, matches: &clap::ArgMatches, json: bool) -> bool {
    let Some(name) = matches.subcommand_name() else {
        return false;
    };
    let hidden = command
        .find_subcommand(name)
        .is_none_or(clap::Command::is_hide_set);
    !json && !hidden && !QUIET_COMMANDS.contains(&name)
}

/// After the command: when it succeeded, says so if an earlier check found a
/// newer release and today's notice hasn't been given. A failed command's
/// error is the last thing it prints.
fn finish(check: Option<NewerReleaseCheck>, result: &anyhow::Result<()>) {
    let Some(check) = check.filter(|_| result.is_ok()) else {
        return;
    };
    // Read again: the detached check may have recorded since the start.
    let mut state = read_state(&check.path);
    if let Some(notice) = due_notice(&state, &check.current, check.now, super::upgrade_command()) {
        // A notice that can't be written to stderr has nowhere else to go.
        let _ = writeln!(std::io::stderr(), "{notice}");
        state.noticed_at = check.now;
        // Failing to record it only means it is given again.
        let _ = write_state(&check.path, &state);
    }
}

/// `cw upgrade _check`: learns the newest stable release and records it for
/// a later command's notice. Started detached; it prints nothing.
pub(crate) async fn run_check() -> anyhow::Result<()> {
    let Some(path) = state_path().filter(|_| !check_off(|name| std::env::var_os(name))) else {
        return Ok(());
    };
    let latest = crate::public_fetch::stable_release(CHECK_DEADLINE).await;
    record_latest(&path, latest)
}

/// Whether the check is turned off: `CW_NO_UPDATE_CHECK` set to anything but
/// `0` or empty, or `CI` set.
pub(super) fn check_off(var: impl Fn(&str) -> Option<std::ffi::OsString>) -> bool {
    let set = |name: &str| var(name).is_some_and(|value| !value.is_empty() && value != "0");
    set("CW_NO_UPDATE_CHECK") || set("CI")
}

/// What the check last learned and when it last said so.
#[derive(Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct NoticeState {
    checked_at: u64,
    latest: Option<String>,
    noticed_at: u64,
}

/// A day since the last check, or a check recorded in the future (the clock
/// moved back).
fn check_due(state: &NoticeState, now: u64) -> bool {
    state.checked_at > now || now - state.checked_at >= DAY_SECONDS
}

/// The notice to give now, if the recorded release is newer than `current`
/// and none was given in the last day. `upgrade` is the command that updates
/// this cw.
fn due_notice(state: &NoticeState, current: &str, now: u64, upgrade: &str) -> Option<String> {
    let latest = state.latest.as_deref()?;
    let noticed_recently = state.noticed_at <= now && now - state.noticed_at < DAY_SECONDS;
    (!noticed_recently && super::newer_release(current, latest)).then(|| notice(latest, upgrade))
}

/// The notice, with how to turn it off.
fn notice(latest: &str, upgrade: &str) -> String {
    format!(
        "a newer release, {latest}, is available: run `{upgrade}` (turn this notice off with CW_NO_UPDATE_CHECK=1)"
    )
}

/// Records what the release server said; a failed read records nothing.
fn record_latest(path: &Path, latest: anyhow::Result<String>) -> anyhow::Result<()> {
    let Ok(latest) = latest else {
        return Ok(());
    };
    let mut state = read_state(path);
    state.latest = Some(latest);
    write_state(path, &state)
}

/// Starts `cw upgrade _check` outside this command: no terminal, its own
/// process group so the terminal's Ctrl-C doesn't reach it, and not waited
/// for.
fn start_detached_check() {
    let Ok(cw) = std::env::current_exe() else {
        return;
    };
    let mut command = std::process::Command::new(cw);
    command
        .args(["upgrade", "_check"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    #[cfg(unix)]
    std::os::unix::process::CommandExt::process_group(&mut command, 0);
    // A check that can't start is tried again tomorrow; the command goes on.
    let _ = command.spawn();
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// `$XDG_STATE_HOME/codewire/upgrade-check.json`, or under `~/.local/state`.
fn state_path() -> Option<PathBuf> {
    let state = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| {
            std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/state"))
        })?;
    Some(state.join("codewire/upgrade-check.json"))
}

/// The recorded state; a missing or unreadable file reads as none.
fn read_state(path: &Path) -> NoticeState {
    std::fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

/// Writes the state whole: to a file beside it, then renamed over it, so the
/// detached check and the command never see half of the other's write.
fn write_state(path: &Path, state: &NoticeState) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("the path {} has no directory", path.display()))?;
    std::fs::create_dir_all(parent)?;
    let staged = parent.join(format!(".upgrade-check.{}.json", std::process::id()));
    std::fs::write(&staged, serde_json::to_vec(state)?)
        .and_then(|()| std::fs::rename(&staged, path))
        .inspect_err(|_| {
            // Nothing to clean if the staged file was never made or is gone.
            let _ = std::fs::remove_file(&staged);
        })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(
        pairs: &'static [(&'static str, &'static str)],
    ) -> impl Fn(&str) -> Option<std::ffi::OsString> {
        move |name| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| std::ffi::OsString::from(*value))
        }
    }

    #[test]
    fn the_check_is_off_by_variable_or_in_ci() {
        assert!(!check_off(env(&[])));
        assert!(check_off(env(&[("CW_NO_UPDATE_CHECK", "1")])));
        assert!(!check_off(env(&[("CW_NO_UPDATE_CHECK", "0")])));
        assert!(!check_off(env(&[("CW_NO_UPDATE_CHECK", "")])));
        assert!(check_off(env(&[("CI", "true")])));
        assert!(
            notice("v0.4.18", "cw upgrade")
                .ends_with("(turn this notice off with CW_NO_UPDATE_CHECK=1)")
        );
    }

    #[test]
    fn the_release_server_is_asked_at_most_once_a_day() {
        let now = 10 * DAY_SECONDS;
        let checked = |checked_at| NoticeState {
            checked_at,
            ..NoticeState::default()
        };
        assert!(check_due(&NoticeState::default(), now), "never checked");
        assert!(!check_due(&checked(now - DAY_SECONDS + 1), now));
        assert!(check_due(&checked(now - DAY_SECONDS), now));
        assert!(
            check_due(&checked(now + 60), now),
            "a future record is stale"
        );
    }

    #[test]
    fn the_notice_is_given_once_a_day_and_only_for_a_newer_release() {
        let now = 10 * DAY_SECONDS;
        let state = |latest: &str, noticed_at| NoticeState {
            checked_at: now,
            latest: Some(latest.into()),
            noticed_at,
        };
        assert_eq!(
            due_notice(&state("v0.4.18", 0), "v0.4.17", now, "cw upgrade"),
            Some(notice("v0.4.18", "cw upgrade"))
        );
        assert_eq!(
            due_notice(&state("v0.4.18", now - 60), "v0.4.17", now, "cw upgrade"),
            None,
            "already given today"
        );
        assert!(
            due_notice(
                &state("v0.4.18", now - DAY_SECONDS),
                "v0.4.17",
                now,
                "cw upgrade"
            )
            .is_some()
        );
        assert!(
            due_notice(&state("v0.4.18", now + 60), "v0.4.17", now, "cw upgrade").is_some(),
            "a future record is stale"
        );
        assert_eq!(
            due_notice(&state("v0.4.17", 0), "v0.4.17", now, "cw upgrade"),
            None
        );
        assert_eq!(
            due_notice(&state("v0.4.16", 0), "v0.4.17", now, "cw upgrade"),
            None,
            "an outdated record is never announced"
        );
        assert_eq!(
            due_notice(&NoticeState::default(), "v0.4.17", now, "cw upgrade"),
            None,
            "nothing learned yet"
        );
    }

    /// A cw installed by Nix is told to update with Nix (#5399).
    #[test]
    fn the_notice_names_the_command_that_updates_this_cw() {
        assert_eq!(
            notice("v0.4.25", super::super::NIX_UPGRADE),
            "a newer release, v0.4.25, is available: run `nix profile upgrade codewire` (turn this \
             notice off with CW_NO_UPDATE_CHECK=1)"
        );
    }

    #[test]
    fn the_detached_check_records_what_it_learned_whole() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state/codewire/upgrade-check.json");
        record_latest(&path, Err(anyhow::anyhow!("offline"))).unwrap();
        assert!(!path.exists(), "a failed read records nothing");

        write_state(
            &path,
            &NoticeState {
                checked_at: 5,
                latest: None,
                noticed_at: 3,
            },
        )
        .unwrap();
        record_latest(&path, Ok("v0.4.18".into())).unwrap();
        assert_eq!(
            read_state(&path),
            NoticeState {
                checked_at: 5,
                latest: Some("v0.4.18".into()),
                noticed_at: 3,
            }
        );
        let names: Vec<_> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, ["upgrade-check.json"], "no staged file is left");

        std::fs::write(&path, b"not json").unwrap();
        assert_eq!(read_state(&path), NoticeState::default());
    }

    #[test]
    fn only_a_visible_everyday_command_without_json_can_give_the_notice() {
        let command = crate::cli_command();
        let eligible_line = |line: &[&str], json| {
            let matches = command.clone().try_get_matches_from(line).unwrap();
            eligible(&command, &matches, json)
        };
        assert!(eligible_line(&["cw", "ls"], false));
        assert!(eligible_line(&["cw", "version"], false));
        assert!(!eligible_line(&["cw", "ls"], true), "--output json");
        assert!(!eligible_line(&["cw", "upgrade", "status"], false));
        assert!(!eligible_line(&["cw", "completion", "zsh"], false));
        assert!(
            !eligible_line(&["cw", "ssh", "known-hosts", "cw-cloud-x"], false),
            "a hidden helper"
        );
    }
}
