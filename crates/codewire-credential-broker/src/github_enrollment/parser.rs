//! Closed non-TTY transcript/config grammar for official gh 2.97.0.
//!
//! Source: cli/cli v2.97.0 internal/authflow/flow.go and
//! pkg/cmd/auth/shared/login_flow.go; cli/go-gh v2.13.0 config/yamlmap.
//! NO_COLOR is set and stdin is null, so prompts never include ANSI/browser
//! opening commands. Unknown output/config is unsupported, not forwarded.

use zeroize::{Zeroize, Zeroizing};

use super::{GitHubDeviceChallenge, GitHubEnrollmentError as Error, GitHubOAuthImport};

const MAX_OUTPUT_BYTES: usize = 64 * 1024;
const MAX_LINE_BYTES: usize = 4096;
const DEVICE_URL: &str =
    "Open this URL to continue in your web browser: https://github.com/login/device";
const SUCCESS: &[&str] = &[
    "✓ Authentication complete.",
    "- gh config set -h github.com git_protocol https",
    "✓ Configured git protocol",
    "! Authentication credentials saved in plain text",
];

pub(super) struct ChallengeParser {
    line: Zeroizing<Vec<u8>>,
    code: Option<Zeroizing<String>>,
    login: Option<String>,
    total: usize,
    phase: usize,
    expires_at_unix: u64,
}

impl ChallengeParser {
    pub(super) fn new(expires_at_unix: u64) -> Self {
        Self {
            line: Zeroizing::new(Vec::new()),
            code: None,
            login: None,
            total: 0,
            phase: 0,
            expires_at_unix,
        }
    }

    pub(super) fn push(&mut self, bytes: &[u8]) -> Result<Option<GitHubDeviceChallenge>, Error> {
        self.total = self.total.saturating_add(bytes.len());
        if self.total > MAX_OUTPUT_BYTES {
            return Err(Error::InvalidOutput);
        }
        let mut challenge = None;
        for &byte in bytes {
            if byte == b'\n' {
                if let Some(parsed) = self.finish_line()? {
                    challenge = Some(parsed);
                }
            } else if byte >= b' ' && byte != 0x7f && self.line.len() < MAX_LINE_BYTES {
                self.line.push(byte);
            } else {
                return Err(Error::InvalidOutput);
            }
        }
        Ok(challenge)
    }

    fn finish_line(&mut self) -> Result<Option<GitHubDeviceChallenge>, Error> {
        if self.line.is_empty() {
            return Ok(None);
        }
        let line = std::str::from_utf8(&self.line).map_err(|_| Error::InvalidOutput)?;
        let mut challenge = None;
        match self.phase {
            0 => {
                let code = line
                    .strip_prefix("! First copy your one-time code: ")
                    .ok_or(Error::InvalidOutput)?;
                if !valid_code(code) {
                    return Err(Error::InvalidOutput);
                }
                self.code = Some(Zeroizing::new(code.to_owned()));
            }
            1 if line == DEVICE_URL => {
                challenge = Some(GitHubDeviceChallenge {
                    user_code: self.code.take().ok_or(Error::InvalidOutput)?,
                    expires_at_unix: self.expires_at_unix,
                });
            }
            2..=5 if line == SUCCESS[self.phase - 2] => {}
            6 => {
                let login = line
                    .strip_prefix("✓ Logged in as ")
                    .ok_or(Error::InvalidOutput)?;
                if !valid_login(login) {
                    return Err(Error::InvalidOutput);
                }
                self.login = Some(login.to_owned());
            }
            _ => return Err(Error::InvalidOutput),
        }
        self.phase += 1;
        self.line.zeroize();
        self.line.clear();
        Ok(challenge)
    }

    pub(super) fn finish(self) -> Result<String, Error> {
        if self.phase != 7 || !self.line.is_empty() || self.code.is_some() {
            return Err(Error::InvalidOutput);
        }
        self.login.ok_or(Error::InvalidOutput)
    }
}

fn valid_code(code: &str) -> bool {
    code.len() == 9
        && code.as_bytes()[4] == b'-'
        && code
            .bytes()
            .enumerate()
            .all(|(i, byte)| i == 4 || byte.is_ascii_uppercase() || byte.is_ascii_digit())
}

fn valid_login(login: &str) -> bool {
    !login.is_empty()
        && login.len() <= 39
        && login.as_bytes()[0].is_ascii_alphanumeric()
        && login.as_bytes()[login.len() - 1].is_ascii_alphanumeric()
        && login
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && !login.contains("--")
}

pub(super) fn validate_version(bytes: &[u8]) -> Result<(), Error> {
    let text = std::str::from_utf8(bytes).map_err(|_| Error::UnsupportedVersion)?;
    let mut lines = text.lines();
    let first = lines.next().ok_or(Error::UnsupportedVersion)?;
    let date = first
        .strip_prefix("gh version 2.97.0 (")
        .and_then(|s| s.strip_suffix(')'))
        .ok_or(Error::UnsupportedVersion)?;
    if date.len() != 10
        || !date.bytes().enumerate().all(|(i, b)| {
            if i == 4 || i == 7 {
                b == b'-'
            } else {
                b.is_ascii_digit()
            }
        })
        || lines.next() != Some("https://github.com/cli/cli/releases/tag/v2.97.0")
        || lines.next().is_some()
        || !text.ends_with('\n')
    {
        return Err(Error::UnsupportedVersion);
    }
    Ok(())
}

// The pinned CLI emits this seven-line, single-host/single-user YAML mapping.
// Parse only that representation rather than permissive YAML (aliases, tags,
// duplicate keys, unexpected refresh/expiry fields or extra users). Token text
// stays borrowed from the zeroizing file buffer until its one protected copy.
pub(super) fn import_hosts(bytes: &[u8], verified_login: &str) -> Result<GitHubOAuthImport, Error> {
    if bytes.len() > super::MAX_HOSTS_BYTES || !valid_login(verified_login) {
        return Err(Error::InvalidResult);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| Error::InvalidResult)?;
    if !text.ends_with('\n') {
        return Err(Error::InvalidResult);
    }
    let mut lines = text.split_terminator('\n');
    if lines.next() != Some("github.com:") || lines.next() != Some("    users:") {
        return Err(Error::InvalidResult);
    }
    let user = lines
        .next()
        .and_then(|line| line.strip_prefix("        "))
        .and_then(|line| line.strip_suffix(':'))
        .ok_or(Error::InvalidResult)?;
    if scalar(user) != verified_login {
        return Err(Error::InvalidResult);
    }
    let user_token = lines
        .next()
        .and_then(|line| line.strip_prefix("            oauth_token: "))
        .ok_or(Error::InvalidResult)?;
    if lines.next() != Some("    git_protocol: https") {
        return Err(Error::InvalidResult);
    }
    let active_token = lines
        .next()
        .and_then(|line| line.strip_prefix("    oauth_token: "))
        .ok_or(Error::InvalidResult)?;
    let active_user = lines
        .next()
        .and_then(|line| line.strip_prefix("    user: "))
        .ok_or(Error::InvalidResult)?;
    let user_token = scalar(user_token);
    if lines.next().is_some()
        || scalar(active_user) != verified_login
        || scalar(active_token) != user_token
        || !valid_token(user_token)
    {
        return Err(Error::InvalidResult);
    }
    Ok(GitHubOAuthImport {
        token: Zeroizing::new(user_token.as_bytes().to_vec()),
        login: verified_login.to_owned(),
    })
}

// YAML may quote numeric/boolean-shaped usernames; escaping is not part of our
// bounded ASCII token/username grammar. Quotes inside a scalar remain invalid.
fn scalar(value: &str) -> &str {
    value
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .or_else(|| value.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
        .unwrap_or(value)
}

fn valid_token(token: &str) -> bool {
    token
        .strip_prefix("gho_")
        .is_some_and(|tail| tail.len() == 36 && tail.bytes().all(|b| b.is_ascii_alphanumeric()))
}
