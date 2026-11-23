//! What a process the daemon starts for a user starts from: `cw exec`, a PTY
//! (`cw shell`, SSH) and a durable session's PTY alike (#6179). A launch that
//! built its environment from the daemon's configuration as it is would miss
//! what the credential bridge adds to it, such as an intercepted Sandbox's
//! Anthropic placeholder (#4001). A durable pipe session takes the same
//! configuration (`SessionEngine::launch_config`) and builds over the
//! daemon environment it is given.

use std::borrow::Cow;
use std::io;

use crate::config::Config;
use crate::credential_bridge::CredentialBridge;
use crate::env::{ProcessEnvironment, build_process_env};

/// One launch's configuration and the environment built under it. The
/// process is prepared under the same configuration.
pub(crate) struct Launch<'a> {
    pub(crate) config: Cow<'a, Config>,
    pub(crate) environment: ProcessEnvironment,
}

/// [`CredentialBridge::launch_config`] for `config`, then the shared builder
/// over the request's `extra` variables and `term`, then the desktop's
/// display.
pub(crate) async fn prepare<'a>(
    bridge: &CredentialBridge,
    config: &'a Config,
    extra: &[String],
    term: &str,
    display: &crate::desktop::Display,
) -> io::Result<Launch<'a>> {
    let config = bridge.launch_config(config).await;
    let mut environment = build_process_env(&config, extra, term)?;
    display.apply(extra, &mut environment);
    Ok(Launch {
        config,
        environment,
    })
}
