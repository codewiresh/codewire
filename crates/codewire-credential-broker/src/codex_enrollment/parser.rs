use super::{CodexDeviceChallenge, CodexEnrollmentError};
use zeroize::{Zeroize, Zeroizing};

const MAX_OUTPUT_BYTES: usize = 64 * 1024;
const MAX_LINE_BYTES: usize = 4096;
const MAX_CODE_BYTES: usize = 64;

const BEFORE_CODE: &[&str] = &[
    "Welcome to Codex [v0.149.0]",
    "OpenAI's command-line coding agent",
    "Follow these steps to sign in with ChatGPT using device code authorization:",
    "1. Open this link in your browser and sign in to your account",
    "   https://auth.openai.com/codex/device",
    "2. Enter this one-time code (expires in 15 minutes)",
];
const WARNING: &str = "Continue only if you started this login in Codex. If a website or another person gave you this code, cancel.";

/// Incremental parser for the reviewed official 0.149.0/0.153.4/0.157.0/0.160.0 device stdout.
/// Unknown escapes, control characters, URLs, duplicate prompts and overflow
/// fail closed. No raw output is retained in a returned error or display value.
pub(super) struct ChallengeParser {
    line: Zeroizing<Vec<u8>>,
    escape: Vec<u8>,
    total: usize,
    phase: usize,
    carriage_return: bool,
    expires_at_unix: u64,
}

impl ChallengeParser {
    pub(super) fn new(expires_at_unix: u64) -> Self {
        Self {
            line: Zeroizing::new(Vec::new()),
            escape: Vec::new(),
            total: 0,
            phase: 0,
            carriage_return: false,
            expires_at_unix,
        }
    }

    pub(super) fn push(
        &mut self,
        bytes: &[u8],
    ) -> Result<Option<CodexDeviceChallenge>, CodexEnrollmentError> {
        self.total = self.total.saturating_add(bytes.len());
        if self.total > MAX_OUTPUT_BYTES {
            return Err(CodexEnrollmentError::InvalidOutput);
        }
        let mut challenge = None;
        for &byte in bytes {
            if !self.escape.is_empty() {
                self.escape.push(byte);
                let accepted = [b"\x1b[94m".as_slice(), b"\x1b[90m", b"\x1b[0m"];
                if accepted.contains(&self.escape.as_slice()) {
                    self.escape.clear();
                } else if !accepted.iter().any(|item| item.starts_with(&self.escape)) {
                    return Err(CodexEnrollmentError::InvalidOutput);
                }
                continue;
            }
            if self.carriage_return && byte != b'\n' {
                return Err(CodexEnrollmentError::InvalidOutput);
            }
            match byte {
                b'\x1b' => self.escape.push(byte),
                b'\r' => self.carriage_return = true,
                b'\n' => {
                    self.carriage_return = false;
                    if let Some(parsed) = self.finish_line()? {
                        challenge = Some(parsed);
                    }
                }
                b' '..=b'~' if self.line.len() < MAX_LINE_BYTES => self.line.push(byte),
                _ => return Err(CodexEnrollmentError::InvalidOutput),
            }
        }
        Ok(challenge)
    }

    fn finish_line(&mut self) -> Result<Option<CodexDeviceChallenge>, CodexEnrollmentError> {
        if self.line.is_empty() {
            return Ok(None);
        }
        let line =
            std::str::from_utf8(&self.line).map_err(|_| CodexEnrollmentError::InvalidOutput)?;
        let challenge = if self.phase < BEFORE_CODE.len() {
            // The reviewed rust-v0.153.4, rust-v0.157.0 and rust-v0.160.0
            // login/device_code_auth.rs prompts match rust-v0.149.0 except for
            // the rendered package version.
            // Keep exact version admission; unknown future prompts remain denied.
            let additional_version = self.phase == 0
                && matches!(
                    line,
                    "Welcome to Codex [v0.153.4]"
                        | "Welcome to Codex [v0.157.0]"
                        | "Welcome to Codex [v0.160.0]"
                );
            if line != BEFORE_CODE[self.phase] && !additional_version {
                if self.phase == 0 && line.starts_with("Welcome to Codex [v") {
                    return Err(CodexEnrollmentError::UnsupportedVersion);
                }
                return Err(CodexEnrollmentError::InvalidOutput);
            }
            None
        } else if self.phase == BEFORE_CODE.len() {
            let code = line
                .strip_prefix("   ")
                .ok_or(CodexEnrollmentError::InvalidOutput)?;
            if code.is_empty()
                || code.len() > MAX_CODE_BYTES
                || !code
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                || !code.bytes().any(|byte| byte.is_ascii_alphanumeric())
            {
                return Err(CodexEnrollmentError::InvalidOutput);
            }
            Some(CodexDeviceChallenge {
                user_code: Zeroizing::new(code.to_owned()),
                expires_at_unix: self.expires_at_unix,
            })
        } else if self.phase == BEFORE_CODE.len() + 1 && line == WARNING {
            None
        } else {
            return Err(CodexEnrollmentError::InvalidOutput);
        };
        self.phase += 1;
        self.line.zeroize();
        self.line.clear();
        Ok(challenge)
    }

    pub(super) fn finish(&self) -> Result<(), CodexEnrollmentError> {
        if self.phase != BEFORE_CODE.len() + 2
            || !self.line.is_empty()
            || !self.escape.is_empty()
            || self.carriage_return
        {
            return Err(CodexEnrollmentError::InvalidOutput);
        }
        Ok(())
    }
}
