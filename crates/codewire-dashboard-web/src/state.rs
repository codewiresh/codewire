use std::{path::PathBuf, time::Duration};

use crate::{Config, RuntimeMode};

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) public_origin: String,
    pub(crate) api_origin: http::Uri,
    pub(crate) credential_origin: http::Uri,
    pub(crate) identity_origin_string: String,
    pub(crate) browser_api_origin: String,
    pub(crate) billing_origin: http::Uri,
    pub(crate) docs_root: PathBuf,
    pub(crate) inline_docs_io: bool,
    pub(crate) confidential_storage_enabled: bool,
    pub(crate) turnstile_site_key: String,
    pub(crate) github_app_slug: String,
    pub(crate) github_app_client_id: String,
    /// The header's Support link; empty hides it.
    pub(crate) support_mailto: String,
    pub(crate) http: reqwest::Client,
    pub(crate) credential_http: reqwest::Client,
    pub(crate) session_http: reqwest::Client,
    pub(crate) account_http: reqwest::Client,
    /// Long-lived reads such as the setup-progress relay. No total timeout:
    /// each use bounds its own lifetime.
    pub(crate) stream_http: reqwest::Client,
    /// HTTP/2 streaming client for bidirectional Connect RPCs (AttachSession).
    pub(crate) bidi_http: reqwest::Client,
    /// The sign-up credit the pricing page last read.
    pub(crate) signup_credit: std::sync::Arc<crate::billing_connect::SignupCreditCache>,
    /// Regular's rates the pricing page last read.
    pub(crate) public_rates: std::sync::Arc<crate::public_rates::PublicRatesCache>,
    /// The sign-in providers the IdP last named.
    pub(crate) oauth_providers: std::sync::Arc<crate::raw_auth::OAuthProvidersCache>,
    /// How the IdP admits a sign-up, as it last said.
    pub(crate) signup_mode: std::sync::Arc<crate::raw_auth::SignupModeCache>,
    /// What each person's GitHub permission check last found (#5206).
    pub(crate) github_checks: std::sync::Arc<crate::github_check::GithubChecks>,
    /// The public Updates page's source; `None` turns the page off.
    pub(crate) updates: Option<std::sync::Arc<crate::updates_connect::Updates>>,
    /// The public pages' analytics tag; `None` leaves them untagged.
    pub(crate) analytics: Option<crate::analytics::Analytics>,
}

impl AppState {
    pub(crate) fn new(config: Config) -> Self {
        let is_cleartext_api = config.api_origin.scheme_str() == Some("http");
        let bidi_builder = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none());
        let bidi_http = if is_cleartext_api {
            bidi_builder.http2_prior_knowledge()
        } else {
            bidi_builder
        }
        .build()
        .expect("static dashboard bidi HTTP client configuration");
        Self {
            public_origin: config.public_origin,
            api_origin: config.api_origin,
            credential_origin: config.credential_origin,
            identity_origin_string: config.identity_origin_string,
            browser_api_origin: config.browser_api_origin,
            billing_origin: config.billing_origin,
            docs_root: config.docs_root,
            inline_docs_io: config.runtime_mode == RuntimeMode::CurrentThread,
            confidential_storage_enabled: config.confidential_storage_enabled,
            turnstile_site_key: config.turnstile_site_key,
            github_app_slug: config.github_app_slug,
            support_mailto: config
                .support_email
                .as_deref()
                .map(|address| crate::mailto::mailto(address, "[Support]"))
                .unwrap_or_default(),
            github_app_client_id: config.github_app_client_id,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("static dashboard HTTP client configuration"),
            credential_http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("static dashboard credential HTTP client configuration"),
            session_http: reqwest::Client::builder()
                .timeout(Duration::from_secs(80))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("static dashboard session HTTP client configuration"),
            account_http: reqwest::Client::builder()
                .timeout(Duration::from_secs(6))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("static dashboard account HTTP client configuration"),
            stream_http: reqwest::Client::builder()
                .connect_timeout(Duration::from_secs(10))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("static dashboard stream HTTP client configuration"),
            bidi_http,
            signup_credit: std::sync::Arc::default(),
            public_rates: std::sync::Arc::default(),
            oauth_providers: std::sync::Arc::default(),
            signup_mode: std::sync::Arc::default(),
            github_checks: std::sync::Arc::default(),
            updates: config
                .updates_site
                .map(|site| std::sync::Arc::new(crate::updates_connect::Updates::new(site))),
            analytics: config.analytics,
        }
    }
}
