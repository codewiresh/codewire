//! Sandbox identity token files (`docs/dev/SANDBOX-IDENTITY.md`, "In the
//! Sandbox", Files): for each audience the access grant lists with a file
//! name, the daemon keeps `/codewire/run/identity/NAME.jwt` current, the
//! token with no newline, 0600, in a directory at 0700 on a memory file
//! system. It mints through the identity socket's own
//! [`IdentityTokens`](crate::identity_socket::IdentityTokens), so a socket
//! request for a file's audience costs no second mint.
//!
//! A grant without the list keeps the files; an empty list deletes them all.
//! The daemon serves at most [`MAX_IDENTITY_FILES`], in file-name order, and
//! checks every name again. Logs name the audience and the file, never the
//! token. Like the socket, the files are no boundary: every process in the
//! Sandbox runs as the daemon's user.

use crate::access::IdentityFileFields;

/// The most files the daemon serves, whatever the grant lists: registration
/// refuses a ninth, so the renewals stay inside the Sandbox's minting limit.
pub const MAX_IDENTITY_FILES: usize = 8;
/// The longest file name, without `.jwt`.
const MAX_NAME_BYTES: usize = 63;
/// The most of an invalid audience a log line shows.
const LOGGED_AUDIENCE_CHARS: usize = 256;

/// One audience's file: its canonical audience, passed to orchestration as
/// it is, and a name of 1 to 63 lowercase letters, digits or `-`, written as
/// `NAME.jwt`. No valid name holds `/` or `.`, so it can't leave the
/// directory or collide with a temporary file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityFile {
    audience: String,
    name: String,
}

impl IdentityFile {
    fn parse(fields: &IdentityFileFields<'_>) -> Option<Self> {
        let audience = fields.audience;
        let name = fields.file_name;
        let audience_ok = audience.starts_with("https://")
            && audience.len() <= codewire_daemon_proto::IDENTITY_RESOURCE_MAX_BYTES
            && audience.bytes().all(|byte| byte.is_ascii_graphic());
        let name_ok = (1..=MAX_NAME_BYTES).contains(&name.len())
            && name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
        (audience_ok && name_ok).then(|| Self {
            audience: audience.to_owned(),
            name: name.to_owned(),
        })
    }

    pub fn audience(&self) -> &str {
        &self.audience
    }

    /// The name, without `.jwt`.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// `NAME.jwt`.
    pub fn file_name(&self) -> String {
        format!("{}.jwt", self.name)
    }

    /// `.NAME.jwt.tmp`, which is renamed into place.
    pub fn temporary_name(&self) -> String {
        format!(".{}.jwt.tmp", self.name)
    }
}

/// A grant's identity files: valid entries only, one per name, in file-name
/// order, at most [`MAX_IDENTITY_FILES`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IdentityFiles(Vec<IdentityFile>);

impl IdentityFiles {
    /// The valid entries of `fields`. An entry with a bad audience or name,
    /// a second entry for a name, and every entry past the eighth by name are
    /// dropped and logged by audience; the rest stand.
    pub fn from_fields(fields: &[IdentityFileFields<'_>]) -> Self {
        let mut files = Vec::with_capacity(fields.len().min(MAX_IDENTITY_FILES));
        for entry in fields {
            match IdentityFile::parse(entry) {
                Some(file) => files.push(file),
                None => tracing::warn!(
                    audience = ?logged_audience(entry.audience),
                    "sandbox identity file dropped: its audience or file name is invalid"
                ),
            }
        }
        files.sort_by(|left, right| left.name.cmp(&right.name));
        let mut kept: Vec<IdentityFile> = Vec::with_capacity(files.len());
        for file in files {
            if kept.last().is_some_and(|last| last.name == file.name) {
                tracing::warn!(
                    audience = %file.audience,
                    file = %file.file_name(),
                    "sandbox identity file dropped: another audience has its name"
                );
            } else if kept.len() >= MAX_IDENTITY_FILES {
                tracing::warn!(
                    audience = %file.audience,
                    file = %file.file_name(),
                    limit = MAX_IDENTITY_FILES,
                    "sandbox identity file dropped: past the most a Sandbox serves"
                );
            } else {
                kept.push(file);
            }
        }
        Self(kept)
    }

    pub fn files(&self) -> &[IdentityFile] {
        &self.0
    }
}

/// An audience that failed validation, cut short for a log line.
fn logged_audience(audience: &str) -> String {
    audience.chars().take(LOGGED_AUDIENCE_CHARS).collect()
}

#[cfg(target_os = "linux")]
mod directory;
#[cfg(target_os = "linux")]
mod renewal;

#[cfg(target_os = "linux")]
pub use renewal::serve;

#[cfg(all(test, target_os = "linux"))]
mod tests;

#[cfg(test)]
mod list_tests {
    use super::*;

    fn entry<'a>(audience: &'a str, file_name: &'a str) -> IdentityFileFields<'a> {
        IdentityFileFields {
            audience,
            file_name,
        }
    }

    fn names(files: &IdentityFiles) -> Vec<(&str, &str)> {
        files
            .files()
            .iter()
            .map(|file| (file.audience(), file.name()))
            .collect()
    }

    #[test]
    fn a_bad_name_or_audience_is_dropped_and_the_rest_stand() {
        let long_name = "a".repeat(64);
        let long_audience = format!(
            "https://{}",
            "a".repeat(codewire_daemon_proto::IDENTITY_RESOURCE_MAX_BYTES)
        );
        let files = IdentityFiles::from_fields(&[
            entry("https://k8s.walk.example", "k8s"),
            entry("https://a.example", "../token"),
            entry("https://a.example", "a.b"),
            entry("https://a.example", "A"),
            entry("https://a.example", ""),
            entry("https://a.example", &long_name),
            entry("https://a.example", "a/b"),
            entry("https://a.example", ".k8s"),
            entry("http://plain.example", "plain"),
            entry("https://space .example", "space"),
            entry("", "empty"),
            entry(&long_audience, "long"),
            entry("https://vault.example", "vault-0"),
        ]);
        assert_eq!(
            names(&files),
            [
                ("https://k8s.walk.example", "k8s"),
                ("https://vault.example", "vault-0")
            ]
        );
        let longest = "a".repeat(63);
        let files = IdentityFiles::from_fields(&[entry("https://a.example", &longest)]);
        assert_eq!(files.files()[0].file_name(), format!("{longest}.jwt"));
        assert_eq!(
            files.files()[0].temporary_name(),
            format!(".{longest}.jwt.tmp")
        );
    }

    #[test]
    fn at_most_eight_are_served_in_file_name_order_one_per_name() {
        let audiences: Vec<String> = (0..10)
            .map(|index| format!("https://{index}.example"))
            .collect();
        let names_in = ["j", "b", "a", "i", "c", "h", "d", "g", "e", "f"];
        let mut fields: Vec<_> = audiences
            .iter()
            .zip(names_in)
            .map(|(audience, name)| entry(audience, name))
            .collect();
        fields.push(entry("https://again.example", "a"));
        let files = IdentityFiles::from_fields(&fields);
        let served: Vec<&str> = files.files().iter().map(IdentityFile::name).collect();
        assert_eq!(served, ["a", "b", "c", "d", "e", "f", "g", "h"]);
        assert_eq!(files.files()[0].audience(), "https://2.example");
    }
}
