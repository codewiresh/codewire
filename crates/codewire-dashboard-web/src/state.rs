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
    pub(crate) confidential_admin_only: bool,
    pub(crate) turnstile_site_key: String,
    pub(crate) github_app_slug: String,
    pub(crate) github_app_client_id: String,
    pub(crate) http: reqwest::Client,
    pub(crate) credential_http: reqwest::Client,
    pub(crate) session_http: reqwest::Client,
    pub(crate) account_http: reqwest::Client,
}

impl AppState {
    pub(crate) fn new(config: Config) -> Self {
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
            confidential_admin_only: config.confidential_admin_only,
            turnstile_site_key: config.turnstile_site_key,
            github_app_slug: config.github_app_slug,
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
        }
    }
}
