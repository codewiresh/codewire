//! `Debug` for the sealed login responses, whose `sealed_login` is marked
//! `debug_redact`, which prost's derived `Debug` ignores (#5034). build.rs
//! names them in `skip_debug`, which drops the derive from each message and
//! its `result` oneof.

use std::fmt;

use crate::codewire::bridge::v1::{
    AntigravityLoginResponse, ClaudeLoginResponse, CodexLoginResponse,
    CredentialBridgeFailureReason, antigravity_login_response, claude_login_response,
    codex_login_response,
};

struct Failure(i32);

impl fmt::Debug for Failure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match CredentialBridgeFailureReason::try_from(self.0) {
            Ok(reason) => fmt::Debug::fmt(&reason, formatter),
            Err(_) => fmt::Debug::fmt(&self.0, formatter),
        }
    }
}

impl fmt::Debug for CodexLoginResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CodexLoginResponse")
            .field("request_id", &self.request_id)
            .field("result", &self.result)
            .finish()
    }
}

impl fmt::Debug for codex_login_response::Result {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SealedLogin(_) => formatter
                .debug_tuple("SealedLogin")
                .field(&"[REDACTED]")
                .finish(),
            Self::Failure(reason) => formatter
                .debug_tuple("Failure")
                .field(&Failure(*reason))
                .finish(),
        }
    }
}

impl fmt::Debug for ClaudeLoginResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClaudeLoginResponse")
            .field("request_id", &self.request_id)
            .field("result", &self.result)
            .finish()
    }
}

impl fmt::Debug for claude_login_response::Result {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SealedLogin(_) => formatter
                .debug_tuple("SealedLogin")
                .field(&"[REDACTED]")
                .finish(),
            Self::Failure(reason) => formatter
                .debug_tuple("Failure")
                .field(&Failure(*reason))
                .finish(),
        }
    }
}

impl fmt::Debug for AntigravityLoginResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AntigravityLoginResponse")
            .field("request_id", &self.request_id)
            .field("result", &self.result)
            .finish()
    }
}

impl fmt::Debug for antigravity_login_response::Result {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SealedLogin(_) => formatter
                .debug_tuple("SealedLogin")
                .field(&"[REDACTED]")
                .finish(),
            Self::Failure(reason) => formatter
                .debug_tuple("Failure")
                .field(&Failure(*reason))
                .finish(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MARKER: &[u8] = b"synthetic-sealed-login";

    fn assert_redacted(printed: &str) {
        assert!(printed.contains("[REDACTED]"), "{printed}");
        assert!(
            !printed.contains(&format!("{MARKER:?}")),
            "prints the sealed login: {printed}"
        );
    }

    #[test]
    fn a_codex_login_response_never_prints_its_sealed_login() {
        let result = codex_login_response::Result::SealedLogin(MARKER.to_vec());
        assert_redacted(&format!("{result:?}"));
        let response = CodexLoginResponse {
            request_id: "request-1".to_owned(),
            result: Some(result),
        };
        let printed = format!("{response:?}");
        assert_redacted(&printed);
        assert!(printed.contains("request-1"));
    }

    #[test]
    fn a_claude_login_response_never_prints_its_sealed_login() {
        let result = claude_login_response::Result::SealedLogin(MARKER.to_vec());
        assert_redacted(&format!("{result:?}"));
        let response = ClaudeLoginResponse {
            request_id: "request-1".to_owned(),
            result: Some(result),
        };
        let printed = format!("{response:?}");
        assert_redacted(&printed);
        assert!(printed.contains("request-1"));
    }

    #[test]
    fn an_antigravity_login_response_never_prints_its_sealed_login() {
        let result = antigravity_login_response::Result::SealedLogin(MARKER.to_vec());
        assert_redacted(&format!("{result:?}"));
        let response = AntigravityLoginResponse {
            request_id: "request-1".to_owned(),
            result: Some(result),
        };
        let printed = format!("{response:?}");
        assert_redacted(&printed);
        assert!(printed.contains("request-1"));
    }

    #[test]
    fn a_refusal_still_shows_its_reason() {
        let denied = CredentialBridgeFailureReason::Denied as i32;
        let printed = format!(
            "{:?}",
            CodexLoginResponse {
                request_id: String::new(),
                result: Some(codex_login_response::Result::Failure(denied)),
            }
        );
        assert!(printed.contains("Failure(Denied)"), "{printed}");
        let printed = format!("{:?}", claude_login_response::Result::Failure(i32::MAX));
        assert!(printed.contains(&i32::MAX.to_string()), "{printed}");
    }
}
