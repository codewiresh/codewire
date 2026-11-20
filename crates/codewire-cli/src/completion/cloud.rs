//! Cloud environment names for completion (journey `complete-bounds`).
//!
//! It never signs in and never refreshes: a stored access token that has
//! expired makes no request, and only the names already cached are offered.

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use codewire_client::{CredentialStore as _, FileCredentialStore};

use super::cache::{self, Held, Kind, Owner};
use crate::config::{
    self, Env, OsEnv, PlatformResolveOptions, ResolvePaths, ResolvedPlatformConfig,
};

/// One request to the cloud, from organization to list. Past it the cache's
/// stale names are offered, or none.
const REQUEST_BOUND: Duration = Duration::from_millis(400);

/// The platform as the command line selects it, with the stored access token
/// read as it is. `None` when signed out, or when the token has run out: a
/// refresh would rewrite the saved sign-in, and completion changes nothing.
fn read_only_platform(paths: &ResolvePaths, env: &impl Env, now: SystemTime) -> Option<Resolved> {
    let platform = config::resolve_platform(PlatformResolveOptions::default(), paths, env).ok()?;
    let Some(credentials_path) = platform.oauth_credentials_path.as_deref() else {
        // An API key from the environment: it names its own organization, and
        // nothing ties its names to one account for a cache to keep.
        return Some(Resolved {
            platform,
            cacheable: false,
            usable: true,
        });
    };
    let credentials = FileCredentialStore::at(credentials_path)
        .load()
        .ok()
        .flatten()?;
    let expires = UNIX_EPOCH + Duration::from_secs(credentials.expires_at_unix());
    let token = credentials.bearer_token().ok()?;
    let platform = ResolvedPlatformConfig::static_token(
        platform.server_url.clone(),
        token.expose_secret(),
        true,
        platform.default_org.clone(),
    )
    .with_deployment_ca(platform.deployment_ca().cloned());
    Some(Resolved {
        platform,
        cacheable: true,
        usable: expires > now,
    })
}

struct Resolved {
    platform: ResolvedPlatformConfig,
    cacheable: bool,
    /// False when the stored access token has expired.
    usable: bool,
}

/// The user ID the sign-in on this machine verified, read from local state
/// only. `None` when there is none.
fn saved_user_id(config_dir: &Path) -> Option<String> {
    let data = std::fs::read(config_dir.join(config::ACCOUNT_FILE)).ok()?;
    let account: config::SavedAccount = serde_json::from_slice(&data).ok()?;
    Some(account.user_id)
}

pub(super) fn environment_names() -> Vec<String> {
    let Ok(paths) = ResolvePaths::from_env(&OsEnv) else {
        return Vec::new();
    };
    names_in(&paths, &OsEnv, SystemTime::now(), fetch_environments)
}

/// The cloud's environment names under the cache's rules. `fetch` is the one
/// bounded request; a test gives it a stand-in.
fn names_in(
    paths: &ResolvePaths,
    env: &impl Env,
    now: SystemTime,
    fetch: impl FnOnce(&ResolvedPlatformConfig) -> Option<Vec<String>>,
) -> Vec<String> {
    let config_dir = &paths.platform_config_dir;
    let Some(resolved) = read_only_platform(paths, env, now) else {
        return Vec::new();
    };
    let directory = cache::directory(config_dir);
    let user = saved_user_id(config_dir);
    let owner = Owner {
        server: resolved.platform.server_url.clone(),
        user: user.clone().unwrap_or_default(),
        organization: crate::commands::configured_org(&resolved.platform)
            .unwrap_or_default()
            .to_owned(),
    };
    let cacheable = resolved.cacheable && user.is_some();
    let held = if cacheable {
        cache::read_in(&directory, &owner, Kind::Environments, now)
    } else {
        Held::Nothing
    };
    if let Held::Fresh(names) = held {
        return names;
    }
    // Every name from the cloud passes the rule here, so no source can offer
    // one a shell would run.
    let fetched = resolved
        .usable
        .then(|| fetch(&resolved.platform))
        .flatten()
        .map(cache::offerable);
    match (fetched, held) {
        (Some(names), _) => {
            if cacheable {
                cache::write_in(&directory, &owner, Kind::Environments, &names, now);
            }
            names
        }
        (None, Held::Stale(names)) => names,
        (None, _) => Vec::new(),
    }
}

/// The names of the organization's environments, or `None` when the cloud did
/// not answer within [`REQUEST_BOUND`] or refused.
fn fetch_environments(platform: &ResolvedPlatformConfig) -> Option<Vec<String>> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .ok()?;
    runtime.block_on(async {
        tokio::time::timeout(REQUEST_BOUND, async {
            let organizations = crate::organization_client::OrganizationClient::new(platform)
                .ok()?
                .list_orgs()
                .await
                .ok()?;
            let organization = crate::commands::current_org_id(platform, &organizations).ok()?;
            let environments = crate::environment_client::EnvironmentClient::new(platform)
                .ok()?
                .list_environments(&organization, false)
                .await
                .ok()?;
            Some(
                environments
                    .into_iter()
                    .filter_map(|environment| environment.name)
                    .collect(),
            )
        })
        .await
        .ok()
        .flatten()
    })
}

#[cfg(test)]
mod tests;
