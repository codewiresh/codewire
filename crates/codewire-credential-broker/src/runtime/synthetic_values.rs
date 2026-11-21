//! The synthetic smoke transport's own credential values: every one carries
//! this boot's id, which the Linux smokes scan for.

use http::HeaderMap;

use super::{BrokerUpstreamError, SYNTHETIC_CODEX_ACCOUNT_ID, SyntheticProviderHost};

/// This boot's id, which every synthetic credential carries and the
/// Linux smokes scan for. Synthetic macOS journeys have no such file, so
/// their canary suffix is fixed.
pub(super) fn boot_id() -> Result<String, BrokerUpstreamError> {
    if cfg!(target_os = "linux") {
        std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .ok()
            .map(|id| id.trim().replace('-', ""))
            .filter(|id| id.len() == 32)
            .ok_or(BrokerUpstreamError::Protocol)
    } else {
        Ok("0123456789abcdef0123456789abcdef".to_owned())
    }
}

pub(super) fn canary(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(|suffix| {
        suffix.len() == 32
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

/// An unserved request still carries exactly the credential this fixture
/// expects the broker to inject for that host, and nothing a guest could
/// have supplied in its place.
pub(super) fn unserved_credential(host: SyntheticProviderHost, headers: &HeaderMap) -> bool {
    let single = |name: &str| headers.get_all(name).iter().count() == 1;
    let bearer = |accepts: &dyn Fn(&str) -> bool| {
        single("authorization")
            && headers
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.strip_prefix("Bearer "))
                .is_some_and(accepts)
    };
    if ["cookie", "proxy-authorization", "host"]
        .iter()
        .any(|name| headers.contains_key(*name))
    {
        return false;
    }
    match host {
        SyntheticProviderHost::Codex => {
            !headers.contains_key("x-api-key")
                && bearer(&super::synthetic_refresh::codex_bearer)
                && single("chatgpt-account-id")
                && headers
                    .get("chatgpt-account-id")
                    .and_then(|value| value.to_str().ok())
                    == Some(SYNTHETIC_CODEX_ACCOUNT_ID)
        }
        SyntheticProviderHost::OpenAi => {
            !headers.contains_key("x-api-key")
                && !headers.contains_key("chatgpt-account-id")
                && bearer(&|value| canary(value, "cwlocalopenai"))
        }
        SyntheticProviderHost::Anthropic => {
            !headers.contains_key("authorization")
                && single("x-api-key")
                && headers
                    .get("x-api-key")
                    .and_then(|value| value.to_str().ok())
                    .is_some_and(|value| canary(value, "cwlocalanthropic"))
        }
    }
}
