//! macOS Keychain protected store driven through Apple's `/usr/bin/security`.
//!
//! Codewire never links Security.framework: `cw` stays SDK-free for the
//! Linux-hosted Darwin cross-build, and the Keychain trusts the stable
//! Apple-signed `security` tool that creates each item, so replacing `cw`
//! does not prompt again. Values cross only the tool's stdin (`security -i`),
//! never its argv.
//!
//! `security -i` reads each command into a fixed 4096-byte line buffer and
//! runs any excess as a further command. Every command line is therefore
//! built from a closed alphabet and bounded below that limit, and a value is
//! stored as base64 split across `ENTRY` and, when needed, chunk items
//! `ENTRY:1`, `ENTRY:2`, ... The head item `ENTRY` records the chunk count and
//! the SHA-256 of the value, so a torn or foreign item reads as corrupt.
//! Entry IDs never contain `:`, so chunk accounts cannot collide with entries.

use std::fmt;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::{
    CODEWIRE_CREDENTIAL_SERVICE, MAX_PROTECTED_VALUE_BYTES, ProtectedEntryId, ProtectedStore,
    ProtectedStoreError, ProtectedStorePersistence, ProtectedValue, protected_value_from_store,
};

const SECURITY_TOOL: &str = "/usr/bin/security";
/// `security -i` truncates a line at 4095 bytes; stay well inside it.
const MAX_COMMAND_LINE_BYTES: usize = 4000;
const MAX_KEYCHAIN_PATH_BYTES: usize = 512;
/// Base64 characters per item, sized so the longest entry, chunk suffix,
/// head prefix and keychain path still fit in one command line.
const CHUNK_CHARS: usize = 3000;
const MAX_CHUNKS: usize = (MAX_PROTECTED_VALUE_BYTES.div_ceil(3) * 4).div_ceil(CHUNK_CHARS);
const ITEM_FORMAT: &str = "cw1";
const SECURITY_TIMEOUT: Duration = Duration::from_secs(120);
const POLL_INTERVAL: Duration = Duration::from_millis(2);
/// The longest expected stdout is one chunk or a deleted item's attributes.
const MAX_OUTPUT_BYTES: u64 = 64 * 1024;

// `security` exits with the low byte of the failing OSStatus.
const EXIT_ITEM_NOT_FOUND: i32 = 44; // errSecItemNotFound (-25300)
const EXIT_INTERACTION_NOT_ALLOWED: i32 = 36; // errSecInteractionNotAllowed (-25308)
const EXIT_AUTH_FAILED: i32 = 51; // errSecAuthFailed (-25293)
const EXIT_USER_CANCELED: i32 = 128; // errSecUserCanceled (-128)

/// Generic-password items under service `sh.codewire.credentials`, account
/// = exact entry ID. Without an explicit keychain, `security` adds to the
/// user's default (login) keychain and searches the user's search list.
#[derive(Clone, PartialEq, Eq)]
pub struct KeychainProtectedStore {
    keychain: Option<PathBuf>,
}

impl fmt::Debug for KeychainProtectedStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KeychainProtectedStore([REDACTED])")
    }
}

impl KeychainProtectedStore {
    /// The user's login keychain, as Claude Code uses it.
    pub fn login() -> Self {
        Self { keychain: None }
    }

    /// One explicit keychain file, for tests and synthetic acceptance with a
    /// throwaway keychain. Its path must be absolute, plain, free of symlinks
    /// and outside every `Library/Keychains` directory, so it can never name
    /// (or alias) the login keychain.
    pub fn with_keychain(path: PathBuf) -> Result<Self, ProtectedStoreError> {
        validate_keychain_path(&path)?;
        Ok(Self {
            keychain: Some(path),
        })
    }

    pub fn keychain(&self) -> Option<&Path> {
        self.keychain.as_deref()
    }

    fn keychain_argument(&self) -> Result<Option<&str>, ProtectedStoreError> {
        let Some(path) = &self.keychain else {
            return Ok(None);
        };
        // `security` treats a missing keychain file as "item not found";
        // require the file so absence is never mistaken for an empty store.
        let metadata =
            std::fs::symlink_metadata(path).map_err(|_| ProtectedStoreError::Unavailable)?;
        if !metadata.file_type().is_file()
            || std::fs::canonicalize(path).ok().as_deref() != Some(path.as_path())
        {
            return Err(ProtectedStoreError::Unavailable);
        }
        validate_keychain_path(path).map(Some)
    }

    fn find(&self, account: &str) -> Result<Option<Zeroizing<String>>, ProtectedStoreError> {
        let line = command_line(Operation::Find, account, None, self.keychain_argument()?)?;
        let (status, output) = run_security(&line)?;
        match status {
            0 => parse_password_output(output).map(Some),
            EXIT_ITEM_NOT_FOUND => Ok(None),
            other => Err(status_error(other)),
        }
    }

    fn add(&self, account: &str, password: &str) -> Result<(), ProtectedStoreError> {
        let line = command_line(
            Operation::Add,
            account,
            Some(password),
            self.keychain_argument()?,
        )?;
        match run_security(&line)?.0 {
            0 => Ok(()),
            other => Err(status_error(other)),
        }
    }

    /// Returns whether an item was deleted.
    fn remove(&self, account: &str) -> Result<bool, ProtectedStoreError> {
        let line = command_line(Operation::Delete, account, None, self.keychain_argument()?)?;
        match run_security(&line)?.0 {
            0 => Ok(true),
            EXIT_ITEM_NOT_FOUND => Ok(false),
            other => Err(status_error(other)),
        }
    }

    fn remove_chunks_from(
        &self,
        id: &ProtectedEntryId,
        first: usize,
    ) -> Result<(), ProtectedStoreError> {
        for index in first..=MAX_CHUNKS {
            if !self.remove(&chunk_account(id, index))? {
                return Ok(());
            }
        }
        Ok(())
    }
}

impl ProtectedStore for KeychainProtectedStore {
    fn persistence(&self) -> ProtectedStorePersistence {
        ProtectedStorePersistence::OperatingSystem
    }

    fn get(&self, id: &ProtectedEntryId) -> Result<Option<ProtectedValue>, ProtectedStoreError> {
        let Some(head) = self.find(id.expose_reference())? else {
            return Ok(None);
        };
        let head = parse_head(&head)?;
        let mut encoded = Zeroizing::new(String::with_capacity(head.count * CHUNK_CHARS));
        encoded.push_str(head.first);
        for index in 1..head.count {
            let chunk = self
                .find(&chunk_account(id, index))?
                .ok_or(ProtectedStoreError::CorruptEntry)?;
            if chunk.is_empty() || chunk.len() > CHUNK_CHARS {
                return Err(ProtectedStoreError::CorruptEntry);
            }
            encoded.push_str(&chunk);
        }
        decode_value(&encoded, &head.digest).map(Some)
    }

    fn put(
        &self,
        id: &ProtectedEntryId,
        value: &ProtectedValue,
    ) -> Result<(), ProtectedStoreError> {
        let items = encode_value(value);
        // Chunks first and the head last: a reader never sees a head whose
        // chunks were not written, and a torn rewrite fails its digest.
        for (index, chunk) in items.iter().enumerate().skip(1) {
            self.add(&chunk_account(id, index), chunk)?;
        }
        self.add(id.expose_reference(), &items[0])?;
        self.remove_chunks_from(id, items.len())
    }

    fn delete(&self, id: &ProtectedEntryId) -> Result<(), ProtectedStoreError> {
        self.remove(id.expose_reference())?;
        self.remove_chunks_from(id, 1)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Operation {
    Find,
    Add,
    Delete,
}

fn chunk_account(id: &ProtectedEntryId, index: usize) -> String {
    format!("{}:{index}", id.expose_reference())
}

/// Item passwords: the head `cw1:COUNT:SHA256:CHUNK` followed by raw chunks.
fn encode_value(value: &ProtectedValue) -> Vec<Zeroizing<String>> {
    let encoded = Zeroizing::new(BASE64.encode(value.expose_secret()));
    let digest = hex_digest(value.expose_secret());
    let chunks = encoded.as_bytes().chunks(CHUNK_CHARS).collect::<Vec<_>>();
    let count = chunks.len();
    chunks
        .into_iter()
        .enumerate()
        .map(|(index, chunk)| {
            // Base64 output is ASCII, so every byte boundary is a char boundary.
            let chunk = std::str::from_utf8(chunk).expect("base64 is ASCII");
            let mut item = Zeroizing::new(String::with_capacity(chunk.len() + 80));
            if index == 0 {
                item.push_str(ITEM_FORMAT);
                item.push(':');
                item.push_str(&count.to_string());
                item.push(':');
                item.push_str(&digest);
                item.push(':');
            }
            item.push_str(chunk);
            item
        })
        .collect()
}

struct Head<'a> {
    count: usize,
    digest: String,
    first: &'a str,
}

fn parse_head(head: &str) -> Result<Head<'_>, ProtectedStoreError> {
    let corrupt = || ProtectedStoreError::CorruptEntry;
    let mut parts = head.splitn(4, ':');
    if parts.next() != Some(ITEM_FORMAT) {
        return Err(corrupt());
    }
    let count = parts.next().ok_or_else(corrupt)?;
    if count.is_empty() || count.len() > 4 || !count.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(corrupt());
    }
    let count = count.parse::<usize>().map_err(|_| corrupt())?;
    let digest = parts.next().ok_or_else(corrupt)?;
    let first = parts.next().ok_or_else(corrupt)?;
    if !(1..=MAX_CHUNKS).contains(&count)
        || digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || first.is_empty()
        || first.len() > CHUNK_CHARS
    {
        return Err(corrupt());
    }
    Ok(Head {
        count,
        digest: digest.to_owned(),
        first,
    })
}

fn decode_value(encoded: &str, digest: &str) -> Result<ProtectedValue, ProtectedStoreError> {
    let value = Zeroizing::new(
        BASE64
            .decode(encoded.as_bytes())
            .map_err(|_| ProtectedStoreError::CorruptEntry)?,
    );
    if hex_digest(&value) != digest {
        return Err(ProtectedStoreError::CorruptEntry);
    }
    protected_value_from_store(value.to_vec())
}

fn hex_digest(value: &[u8]) -> String {
    Sha256::digest(value)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn validate_keychain_path(path: &Path) -> Result<&str, ProtectedStoreError> {
    let invalid = || ProtectedStoreError::Unavailable;
    let text = path.to_str().ok_or_else(invalid)?;
    if !path.is_absolute()
        || text.len() > MAX_KEYCHAIN_PATH_BYTES
        || !text.bytes().all(plain_path_byte)
        || text.split('/').any(|part| matches!(part, "." | ".."))
        || text.contains("/Library/Keychains/")
    {
        return Err(invalid());
    }
    Ok(text)
}

fn plain_path_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-')
}

fn account_byte(byte: u8) -> bool {
    byte.is_ascii_lowercase()
        || byte.is_ascii_digit()
        || matches!(byte, b'/' | b'.' | b'_' | b'-' | b':')
}

fn password_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=' | b':')
}

/// One `security -i` line. Every token comes from a closed alphabet without
/// whitespace, quotes or backslashes, so the tool's tokenizer cannot split
/// or join arguments, and the whole line fits its fixed buffer.
fn command_line(
    operation: Operation,
    account: &str,
    password: Option<&str>,
    keychain: Option<&str>,
) -> Result<Zeroizing<String>, ProtectedStoreError> {
    if account.is_empty() || !account.bytes().all(account_byte) {
        return Err(ProtectedStoreError::InvalidEntryId);
    }
    if let Some(keychain) = keychain
        && (!keychain.starts_with('/') || !keychain.bytes().all(plain_path_byte))
    {
        return Err(ProtectedStoreError::Unavailable);
    }
    let mut line = Zeroizing::new(String::with_capacity(MAX_COMMAND_LINE_BYTES));
    match (operation, password) {
        (Operation::Find, None) => {
            line.push_str("find-generic-password -s ");
            line.push_str(CODEWIRE_CREDENTIAL_SERVICE);
            line.push_str(" -a ");
            line.push_str(account);
            line.push_str(" -w");
        }
        (Operation::Add, Some(password)) => {
            if password.is_empty() || !password.bytes().all(password_byte) {
                return Err(ProtectedStoreError::CorruptEntry);
            }
            line.push_str("add-generic-password -U -s ");
            line.push_str(CODEWIRE_CREDENTIAL_SERVICE);
            line.push_str(" -a ");
            line.push_str(account);
            line.push_str(" -w ");
            line.push_str(password);
        }
        (Operation::Delete, None) => {
            line.push_str("delete-generic-password -s ");
            line.push_str(CODEWIRE_CREDENTIAL_SERVICE);
            line.push_str(" -a ");
            line.push_str(account);
        }
        _ => return Err(ProtectedStoreError::Unavailable),
    }
    if let Some(keychain) = keychain {
        line.push(' ');
        line.push_str(keychain);
    }
    if line.len() > MAX_COMMAND_LINE_BYTES {
        return Err(ProtectedStoreError::ValueTooLarge);
    }
    line.push('\n');
    Ok(line)
}

/// `find-generic-password -w` prints the password and one newline. Codewire
/// items are printable ASCII, so the tool never switches to hex output.
fn parse_password_output(
    output: Zeroizing<Vec<u8>>,
) -> Result<Zeroizing<String>, ProtectedStoreError> {
    let Some((&b'\n', password)) = output.split_last() else {
        return Err(ProtectedStoreError::CorruptEntry);
    };
    if password.is_empty() || !password.iter().copied().all(password_byte) {
        return Err(ProtectedStoreError::CorruptEntry);
    }
    let password = std::str::from_utf8(password).map_err(|_| ProtectedStoreError::CorruptEntry)?;
    Ok(Zeroizing::new(password.to_owned()))
}

fn status_error(status: i32) -> ProtectedStoreError {
    match status {
        EXIT_INTERACTION_NOT_ALLOWED | EXIT_AUTH_FAILED | EXIT_USER_CANCELED => {
            ProtectedStoreError::AccessDenied
        }
        _ => ProtectedStoreError::Unavailable,
    }
}

/// Run exactly one command in `security -i` with an empty environment. The
/// exit status is that command's status. Stderr is discarded unread.
fn run_security(line: &str) -> Result<(i32, Zeroizing<Vec<u8>>), ProtectedStoreError> {
    run_tool(Path::new(SECURITY_TOOL), line, SECURITY_TIMEOUT)
}

fn run_tool(
    program: &Path,
    line: &str,
    timeout: Duration,
) -> Result<(i32, Zeroizing<Vec<u8>>), ProtectedStoreError> {
    let mut child = Command::new(program)
        .arg("-i")
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| ProtectedStoreError::Unavailable)?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or(ProtectedStoreError::Unavailable)?;
    let reader = std::thread::spawn(move || {
        let mut output = Zeroizing::new(Vec::new());
        let result = (&mut stdout)
            .take(MAX_OUTPUT_BYTES + 1)
            .read_to_end(&mut output);
        result.map(|_| output)
    });
    let written = child
        .stdin
        .take()
        .ok_or(ProtectedStoreError::Unavailable)
        .and_then(|mut stdin| {
            stdin
                .write_all(line.as_bytes())
                .map_err(|_| ProtectedStoreError::Unavailable)
        });
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                break Err(ProtectedStoreError::TimedOut);
            }
            Ok(None) => std::thread::sleep(POLL_INTERVAL),
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                break Err(ProtectedStoreError::Unavailable);
            }
        }
    };
    let output = reader
        .join()
        .map_err(|_| ProtectedStoreError::Unavailable)?;
    let status = status?;
    written?;
    let output = output.map_err(|_| ProtectedStoreError::Unavailable)?;
    if output.len() as u64 > MAX_OUTPUT_BYTES {
        return Err(ProtectedStoreError::Unavailable);
    }
    let code = status.code().ok_or(ProtectedStoreError::Unavailable)?;
    Ok((code, output))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(value: &str) -> ProtectedEntryId {
        ProtectedEntryId::parse(value).unwrap()
    }

    fn longest_entry() -> ProtectedEntryId {
        let segment = "a".repeat(59);
        entry(&[segment.as_str(); 4].join("/"))
    }

    #[test]
    fn values_round_trip_through_bounded_chunked_items() {
        for size in [
            1,
            2,
            3,
            2249,
            2250,
            2251,
            4500,
            64 * 1024,
            MAX_PROTECTED_VALUE_BYTES,
        ] {
            let bytes = (0..size).map(|index| (index * 7 % 256) as u8).collect();
            let value = ProtectedValue::new(bytes).unwrap();
            let items = encode_value(&value);
            assert!(items.len() <= MAX_CHUNKS, "{size}");
            let head = parse_head(&items[0]).unwrap();
            assert_eq!(head.count, items.len());
            let mut encoded = head.first.to_owned();
            for item in &items[1..] {
                assert!(item.len() <= CHUNK_CHARS);
                encoded.push_str(item);
            }
            let decoded = decode_value(&encoded, &head.digest).unwrap();
            assert_eq!(decoded.expose_secret(), value.expose_secret(), "{size}");
            for (index, item) in items.iter().enumerate() {
                let account = if index == 0 {
                    longest_entry().expose_reference().to_owned()
                } else {
                    chunk_account(&longest_entry(), index)
                };
                let keychain = format!("/{}", "k".repeat(MAX_KEYCHAIN_PATH_BYTES - 1));
                let line =
                    command_line(Operation::Add, &account, Some(item), Some(&keychain)).unwrap();
                assert!(line.len() <= MAX_COMMAND_LINE_BYTES + 1, "{size}/{index}");
                assert_eq!(line.matches('\n').count(), 1);
                assert_eq!(line.split_ascii_whitespace().count(), 9);
            }
        }
    }

    #[test]
    fn torn_foreign_and_malformed_items_read_as_corrupt() {
        let value = ProtectedValue::from_slice(&[7; 5000]).unwrap();
        let items = encode_value(&value);
        assert_eq!(items.len(), 3);
        let head = parse_head(&items[0]).unwrap();
        let mut torn = head.first.to_owned();
        torn.push_str(&items[2]);
        torn.push_str(&items[1]);
        assert_eq!(
            decode_value(&torn, &head.digest).err(),
            Some(ProtectedStoreError::CorruptEntry)
        );
        for foreign in [
            "",
            "plain",
            "cw1",
            "cw1:1",
            "cw1:1:abc:AAAA",
            "cw2:1:0000000000000000000000000000000000000000000000000000000000000000:AAAA",
            "cw1:0:0000000000000000000000000000000000000000000000000000000000000000:AAAA",
            "cw1:99999:0000000000000000000000000000000000000000000000000000000000000000:AAAA",
            "cw1:1:0000000000000000000000000000000000000000000000000000000000000000:",
            "cw1:1:000000000000000000000000000000000000000000000000000000000000000G:AAAA",
        ] {
            assert!(parse_head(foreign).is_err(), "{foreign}");
        }
    }

    #[test]
    fn command_lines_reject_tokens_that_could_split_or_redirect_a_command() {
        let id = entry("local/credentials/a/material-v1");
        for account in ["", "a b", "a\"b", "a\\b", "A", "a\nb"] {
            assert!(command_line(Operation::Find, account, None, None).is_err());
        }
        for password in ["", "a b", "a\nfind-generic-password", "a\"", "a\\"] {
            assert!(
                command_line(Operation::Add, id.expose_reference(), Some(password), None).is_err()
            );
        }
        for keychain in ["relative", "/a b", "/a\"b", "/a\nb"] {
            assert!(
                command_line(Operation::Find, id.expose_reference(), None, Some(keychain)).is_err()
            );
        }
        let oversized = "A".repeat(MAX_COMMAND_LINE_BYTES);
        assert_eq!(
            command_line(
                Operation::Add,
                id.expose_reference(),
                Some(&oversized),
                None
            )
            .err(),
            Some(ProtectedStoreError::ValueTooLarge)
        );
        assert_eq!(
            command_line(Operation::Delete, id.expose_reference(), None, None)
                .unwrap()
                .as_str(),
            "delete-generic-password -s sh.codewire.credentials -a local/credentials/a/material-v1\n"
        );
        assert_eq!(
            command_line(
                Operation::Find,
                id.expose_reference(),
                None,
                Some("/private/tmp/t/k.keychain-db")
            )
            .unwrap()
            .as_str(),
            "find-generic-password -s sh.codewire.credentials -a local/credentials/a/material-v1 -w /private/tmp/t/k.keychain-db\n"
        );
    }

    #[test]
    fn explicit_keychains_must_be_plain_absolute_paths() {
        for path in [
            "relative.keychain-db",
            "/tmp/../k.keychain-db",
            "/tmp/./k.keychain-db",
            "/tmp/a b.keychain-db",
            "/Users/synthetic/Library/Keychains/login.keychain-db",
            "/Library/Keychains/System.keychain",
        ] {
            assert!(KeychainProtectedStore::with_keychain(path.into()).is_err());
        }
        let store =
            KeychainProtectedStore::with_keychain("/private/tmp/x.keychain-db".into()).unwrap();
        assert_eq!(format!("{store:?}"), "KeychainProtectedStore([REDACTED])");
        assert!(KeychainProtectedStore::login().keychain().is_none());
    }

    #[test]
    fn password_output_is_exact_and_tool_statuses_are_classified() {
        assert_eq!(
            parse_password_output(Zeroizing::new(b"cw1:abc\n".to_vec()))
                .unwrap()
                .as_str(),
            "cw1:abc"
        );
        for output in [&b""[..], b"cw1:abc", b"cw1 abc\n", b"\n", b"cw1:abc\n\n"] {
            assert!(parse_password_output(Zeroizing::new(output.to_vec())).is_err());
        }
        for status in [
            EXIT_INTERACTION_NOT_ALLOWED,
            EXIT_AUTH_FAILED,
            EXIT_USER_CANCELED,
        ] {
            assert_eq!(status_error(status), ProtectedStoreError::AccessDenied);
        }
        for status in [1, 2, 45, 50] {
            assert_eq!(status_error(status), ProtectedStoreError::Unavailable);
        }
    }

    #[test]
    fn tool_runs_are_bounded_by_a_deadline_and_report_exit_status() {
        let (status, output) =
            run_tool(Path::new("/bin/sh"), "exit 7\n", SECURITY_TIMEOUT).expect("shell runs");
        assert_eq!(status, 7);
        assert!(output.is_empty());
        let (status, output) =
            run_tool(Path::new("/bin/sh"), "echo cw1:abc\n", SECURITY_TIMEOUT).unwrap();
        assert_eq!((status, output.as_slice()), (0, &b"cw1:abc\n"[..]));
        assert_eq!(
            run_tool(
                Path::new("/bin/sh"),
                "exec sleep 5\n",
                Duration::from_millis(50)
            )
            .err(),
            Some(ProtectedStoreError::TimedOut)
        );
    }
}

/// Real `security` against a throwaway keychain with a synthetic password.
/// These tests never name, unlock or write the user's login keychain.
#[cfg(all(test, target_os = "macos"))]
mod macos_tests {
    use super::*;

    const SYNTHETIC_PASSWORD: &str = "synthetic-test-keychain-password";

    struct ThrowawayKeychain {
        _directory: tempfile::TempDir,
        path: PathBuf,
    }

    impl ThrowawayKeychain {
        fn create() -> Self {
            let directory = tempfile::tempdir().unwrap();
            let path = std::fs::canonicalize(directory.path())
                .unwrap()
                .join("codewire-test.keychain-db");
            security(
                &["create-keychain", "-p", SYNTHETIC_PASSWORD]
                    .into_iter()
                    .chain([path.to_str().unwrap()])
                    .collect::<Vec<_>>(),
            );
            // No auto-lock timeout, then unlock with the synthetic password.
            security(&["set-keychain-settings", path.to_str().unwrap()]);
            let keychain = Self {
                _directory: directory,
                path,
            };
            keychain.unlock();
            keychain
        }

        fn unlock(&self) {
            security(&[
                "unlock-keychain",
                "-p",
                SYNTHETIC_PASSWORD,
                self.path.to_str().unwrap(),
            ]);
        }

        fn lock(&self) {
            security(&["lock-keychain", self.path.to_str().unwrap()]);
        }

        fn store(&self) -> KeychainProtectedStore {
            KeychainProtectedStore::with_keychain(self.path.clone()).unwrap()
        }

        fn item_exists(&self, account: &str) -> bool {
            std::process::Command::new(SECURITY_TOOL)
                .args([
                    "find-generic-password",
                    "-s",
                    CODEWIRE_CREDENTIAL_SERVICE,
                    "-a",
                ])
                .arg(account)
                .arg(&self.path)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap()
                .success()
        }
    }

    impl Drop for ThrowawayKeychain {
        fn drop(&mut self) {
            let _ = std::process::Command::new(SECURITY_TOOL)
                .arg("delete-keychain")
                .arg(&self.path)
                .stderr(Stdio::null())
                .status();
        }
    }

    fn security(arguments: &[&str]) {
        let status = std::process::Command::new(SECURITY_TOOL)
            .args(arguments)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "security {}", arguments[0]);
    }

    fn entry(value: &str) -> ProtectedEntryId {
        ProtectedEntryId::parse(value).unwrap()
    }

    #[test]
    fn exact_entries_round_trip_and_delete_in_a_throwaway_keychain() {
        let keychain = ThrowawayKeychain::create();
        let store = keychain.store();
        let id = entry("local/workload-secrets/synthetic/material-v1");
        let other = entry("local/workload-secrets/synthetic/material-v2");
        assert!(store.get(&id).unwrap().is_none());
        store.delete(&id).unwrap();

        let large = (0..10_000)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        store
            .put(&id, &ProtectedValue::from_slice(&large).unwrap())
            .unwrap();
        assert!(keychain.item_exists(id.expose_reference()));
        assert!(keychain.item_exists(&chunk_account(&id, 4)));
        assert!(!keychain.item_exists(&chunk_account(&id, 5)));
        assert_eq!(store.get(&id).unwrap().unwrap().expose_secret(), large);

        // A shorter replacement removes the old tail chunks.
        store
            .put(
                &id,
                &ProtectedValue::from_slice(b"sk-synthetic-short").unwrap(),
            )
            .unwrap();
        assert!(!keychain.item_exists(&chunk_account(&id, 1)));
        assert_eq!(
            store.get(&id).unwrap().unwrap().expose_secret(),
            b"sk-synthetic-short"
        );
        store
            .put(&other, &ProtectedValue::from_slice(b"other").unwrap())
            .unwrap();

        store.delete(&id).unwrap();
        assert!(store.get(&id).unwrap().is_none());
        assert!(!keychain.item_exists(id.expose_reference()));
        assert_eq!(
            store.get(&other).unwrap().unwrap().expose_secret(),
            b"other"
        );
    }

    #[test]
    fn a_locked_keychain_is_access_denied_until_unlocked() {
        let keychain = ThrowawayKeychain::create();
        let store = keychain.store();
        let id = entry("local/credentials/synthetic/material-v1");
        store
            .put(
                &id,
                &ProtectedValue::from_slice(b"sk-synthetic-locked").unwrap(),
            )
            .unwrap();
        keychain.lock();
        assert_eq!(
            store.get(&id).err(),
            Some(ProtectedStoreError::AccessDenied)
        );
        assert_eq!(
            store
                .put(&id, &ProtectedValue::from_slice(b"replacement").unwrap())
                .err(),
            Some(ProtectedStoreError::AccessDenied)
        );
        keychain.unlock();
        assert_eq!(
            store.get(&id).unwrap().unwrap().expose_secret(),
            b"sk-synthetic-locked"
        );
    }

    #[test]
    fn foreign_items_and_missing_keychains_fail_closed() {
        let keychain = ThrowawayKeychain::create();
        let store = keychain.store();
        let id = entry("local/credentials/synthetic/material-v1");
        security(&[
            "add-generic-password",
            "-s",
            CODEWIRE_CREDENTIAL_SERVICE,
            "-a",
            id.expose_reference(),
            "-w",
            "not-a-codewire-item",
            keychain.path.to_str().unwrap(),
        ]);
        assert_eq!(
            store.get(&id).err(),
            Some(ProtectedStoreError::CorruptEntry)
        );
        store.delete(&id).unwrap();
        assert!(store.get(&id).unwrap().is_none());

        let missing = KeychainProtectedStore::with_keychain(
            keychain.path.with_file_name("absent.keychain-db"),
        )
        .unwrap();
        assert_eq!(
            missing.get(&id).err(),
            Some(ProtectedStoreError::Unavailable)
        );
        assert_eq!(
            missing.delete(&id).err(),
            Some(ProtectedStoreError::Unavailable)
        );

        let link = keychain.path.with_file_name("link.keychain-db");
        std::os::unix::fs::symlink(&keychain.path, &link).unwrap();
        let linked = KeychainProtectedStore::with_keychain(link).unwrap();
        assert_eq!(
            linked.get(&id).err(),
            Some(ProtectedStoreError::Unavailable)
        );
    }
}
