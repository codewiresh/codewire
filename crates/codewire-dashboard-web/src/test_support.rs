//! Shared by the crate's route tests.

use std::time::Duration;

/// A hang guard for a route test's request to its own in-process server on
/// 127.0.0.1, not a speed expectation (docs/dev/AGENT-WORKFLOW.md "Failure
/// convergence"). The routes answer well under a second, but on a starved CI
/// guest fixed 5 s client timeouts failed requests that were still being
/// served (#4225, #4169).
pub(crate) const LOOPBACK_HANG_GUARD: Duration = Duration::from_secs(60);

/// A dashboard whose every backend is a closed port, for walking routes
/// without a server behind them.
pub(crate) fn unreachable_config() -> crate::Config {
    let unused = "http://127.0.0.1:9";
    crate::Config {
        listen_addr: "127.0.0.1:0".parse().expect("loopback listen address"),
        runtime_mode: crate::RuntimeMode::CurrentThread,
        public_origin: "https://codewire.test".into(),
        api_origin: unused.parse().expect("closed-port origin"),
        credential_origin: unused.parse().expect("closed-port origin"),
        identity_origin_string: unused.into(),
        browser_api_origin: "https://codewire.test".into(),
        billing_origin: unused.parse().expect("closed-port origin"),
        docs_root: std::path::PathBuf::new(),
        confidential_storage_enabled: false,
        turnstile_site_key: String::new(),
        github_app_slug: String::new(),
        github_app_client_id: String::new(),
        support_email: None,
        updates_site: None,
        analytics: None,
    }
}
