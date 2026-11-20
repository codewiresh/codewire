//! The names cache for cloud completions (journey `complete-bounds`). It holds
//! names only: no ID, value, token or hash. One file serves one server and
//! one organization at a time, so a switch of either never offers the
//! previous one's names, and `cw login` and `cw logout` remove it, so a
//! different user never sees them either. A command line that signs in with an
//! API key reads and writes no cache: nothing ties its names to one account.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// A cached list is used as it is for this long.
pub(super) const FRESH_FOR: Duration = Duration::from_secs(30);
/// When the cloud cannot answer in time, a list this old is still offered.
pub(super) const STALE_LIMIT: Duration = Duration::from_secs(60 * 60);

const VERSION: u32 = 1;

/// What a read takes back from the file, and of each list. A cache that has
/// grown past either was not written by `cw`.
const MAX_FILE_BYTES: u64 = 256 * 1024;
const MAX_NAMES: usize = 1000;

/// The names that are safe to hand to a shell: the rule every local
/// environment name follows. A hosted name is whatever the server sent, and
/// bash inserts a completion unquoted, so one with `;`, a space, `$(` or an
/// escape character would land on the user's command line.
pub(super) fn offerable(names: impl IntoIterator<Item = String>) -> Vec<String> {
    names
        .into_iter()
        .filter(|name| codewire_local_vmm::valid_environment_name(name))
        .take(MAX_NAMES)
        .collect()
}

/// A family of names the cache keeps.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Kind {
    Environments,
}

impl Kind {
    fn key(self) -> &'static str {
        match self {
            Kind::Environments => "environments",
        }
    }
}

/// Whose names these are: a user of a server and the organization the command
/// line and the saved settings select.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Owner {
    pub(super) server: String,
    pub(super) user: String,
    pub(super) organization: String,
}

#[derive(Default, Serialize, Deserialize)]
struct File {
    version: u32,
    server: String,
    user: String,
    organization: String,
    lists: BTreeMap<String, List>,
}

#[derive(Serialize, Deserialize)]
struct List {
    at_unix: u64,
    names: Vec<String>,
}

/// What the cache holds for one owner and family.
pub(super) enum Held {
    Fresh(Vec<String>),
    Stale(Vec<String>),
    Nothing,
}

impl Held {
    fn from_age(names: Vec<String>, age: Duration) -> Self {
        if age <= FRESH_FOR {
            Held::Fresh(names)
        } else if age <= STALE_LIMIT {
            Held::Stale(names)
        } else {
            Held::Nothing
        }
    }
}

/// Where the cache lives: beside the saved sign-in it belongs to.
pub(super) fn directory(config_dir: &Path) -> PathBuf {
    config_dir.join("completion")
}

fn file_in(directory: &Path) -> PathBuf {
    directory.join("names-v1.json")
}

fn unix(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map_or(0, |age| age.as_secs())
}

fn load(directory: &Path, owner: &Owner) -> Option<File> {
    let path = file_in(directory);
    if std::fs::metadata(&path).ok()?.len() > MAX_FILE_BYTES {
        return None;
    }
    let bytes = std::fs::read(path).ok()?;
    let file: File = serde_json::from_slice(&bytes).ok()?;
    (file.version == VERSION
        && file.server == owner.server
        && file.user == owner.user
        && file.organization == owner.organization)
        .then_some(file)
}

pub(super) fn read_in(directory: &Path, owner: &Owner, kind: Kind, now: SystemTime) -> Held {
    let Some(list) = load(directory, owner).and_then(|mut file| file.lists.remove(kind.key()))
    else {
        return Held::Nothing;
    };
    let age = Duration::from_secs(unix(now).saturating_sub(list.at_unix));
    Held::from_age(offerable(list.names), age)
}

/// Keeps `names` for `owner`. A file that belongs to another owner is replaced,
/// never extended. Any failure leaves the cache as it was: completion has
/// nowhere to report one.
#[cfg(unix)]
pub(super) fn write_in(
    directory: &Path,
    owner: &Owner,
    kind: Kind,
    names: &[String],
    now: SystemTime,
) {
    use std::io::Write as _;
    use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};

    let mut file = load(directory, owner).unwrap_or_else(|| File {
        version: VERSION,
        server: owner.server.clone(),
        user: owner.user.clone(),
        organization: owner.organization.clone(),
        lists: BTreeMap::new(),
    });
    file.lists.insert(
        kind.key().to_owned(),
        List {
            at_unix: unix(now),
            names: offerable(names.iter().cloned()),
        },
    );
    let Ok(bytes) = serde_json::to_vec(&file) else {
        return;
    };
    if std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(directory)
        .is_err()
    {
        return;
    }
    let target = file_in(directory);
    let staged = directory.join(format!("names-v1.json.{}", std::process::id()));
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&staged)
        .and_then(|mut staged| staged.write_all(&bytes));
    if written.is_err() || std::fs::rename(&staged, &target).is_err() {
        let _ = std::fs::remove_file(&staged);
    }
}

#[cfg(not(unix))]
pub(super) fn write_in(_: &Path, _: &Owner, _: Kind, _: &[String], _: SystemTime) {}

/// Removes every cached name. `cw login` and `cw logout` call it with the
/// config directory they already hold.
pub(crate) fn remove(config_dir: &Path) {
    let _ = std::fs::remove_file(file_in(&directory(config_dir)));
}

#[cfg(test)]
mod tests;
