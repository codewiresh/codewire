use std::{path::PathBuf, time::Duration};

use crate::{Config, RuntimeMode};

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) public_origin: String,
    pub(crate) api_origin: http::Uri,
    pub(crate) identity_origin_string: String,
    pub(crate) browser_api_origin: String,
    pub(crate) billing_origin: http::Uri,
    pub(crate) docs_root: PathBuf,
    pub(crate) inline_docs_io: bool,
    pub(crate) http: reqwest::Client,
}

impl AppState {
    pub(crate) fn new(config: Config) -> Self {
        Self {
            public_origin: config.public_origin,
            api_origin: config.api_origin,
            identity_origin_string: config.identity_origin_string,
            browser_api_origin: config.browser_api_origin,
            billing_origin: config.billing_origin,
            docs_root: config.docs_root,
            inline_docs_io: config.runtime_mode == RuntimeMode::CurrentThread,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("static dashboard HTTP client configuration"),
        }
    }
}
