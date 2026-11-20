use std::cell::Cell;
use std::path::PathBuf;

use codewire_client::OAuthCredentials;

use super::*;
use crate::config::{MapEnv, PlatformConfig, SavedAccount, save_account, save_platform_config};

const SERVER: &str = "https://api.codewire.example";
const NOW: u64 = 1_000_000;

fn at(seconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(seconds)
}

struct Home {
    _directory: tempfile::TempDir,
    paths: ResolvePaths,
}

impl Home {
    fn signed_out() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let paths = ResolvePaths {
            platform_config_dir: directory.path().join("config"),
            mesh_data_dir: directory.path().join("mesh"),
        };
        Self {
            _directory: directory,
            paths,
        }
    }

    fn signed_in(expires_at_unix: u64, organization: &str) -> Self {
        let home = Self::signed_out();
        let config_dir = &home.paths.platform_config_dir;
        save_platform_config(
            config_dir,
            &PlatformConfig {
                server_url: SERVER.to_owned(),
                default_org: organization.to_owned(),
                deployment_ca: None,
            },
        )
        .unwrap();
        save_account(
            config_dir,
            &SavedAccount {
                server_url: SERVER.to_owned(),
                user_id: "user-1".to_owned(),
            },
        )
        .unwrap();
        let credentials = OAuthCredentials::new(
            SERVER,
            codewire_client::CODEWIRE_CLI_OAUTH_CLIENT_ID,
            "synthetic-access",
            "synthetic-refresh",
            expires_at_unix,
            codewire_client::CODEWIRE_CLI_OAUTH_SCOPES,
        )
        .unwrap();
        FileCredentialStore::new(config_dir)
            .save(&credentials)
            .unwrap();
        home
    }

    fn owner(&self, organization: &str) -> Owner {
        Owner {
            server: SERVER.to_owned(),
            user: "user-1".to_owned(),
            organization: organization.to_owned(),
        }
    }

    fn cache(&self) -> PathBuf {
        cache::directory(&self.paths.platform_config_dir)
    }

    fn keep(&self, organization: &str, names: &[&str], seconds: u64) {
        let names: Vec<String> = names.iter().map(|name| (*name).to_owned()).collect();
        cache::write_in(
            &self.cache(),
            &self.owner(organization),
            Kind::Environments,
            &names,
            at(seconds),
        );
    }
}

fn answers(
    names: &'static [&'static str],
) -> impl FnOnce(&ResolvedPlatformConfig) -> Option<Vec<String>> {
    move |_| Some(names.iter().map(|name| (*name).to_owned()).collect())
}

fn is_silent(_: &ResolvedPlatformConfig) -> Option<Vec<String>> {
    None
}

fn no_env() -> MapEnv {
    MapEnv::default()
}

#[test]
fn signed_out_offers_nothing_and_asks_nobody() {
    let home = Home::signed_out();
    let asked = Cell::new(false);
    let names = names_in(&home.paths, &no_env(), at(NOW), |_| {
        asked.set(true);
        None
    });
    assert!(names.is_empty());
    assert!(!asked.get());
}

#[test]
fn a_fresh_cache_is_offered_without_asking_the_cloud() {
    let home = Home::signed_in(NOW + 600, "acme");
    home.keep("acme", &["app", "db"], NOW - 10);
    let asked = Cell::new(false);
    let names = names_in(&home.paths, &no_env(), at(NOW), |_| {
        asked.set(true);
        None
    });
    assert_eq!(names, ["app", "db"]);
    assert!(!asked.get());
}

#[test]
fn an_answer_from_the_cloud_is_offered_and_cached() {
    let home = Home::signed_in(NOW + 600, "acme");
    let names = names_in(&home.paths, &no_env(), at(NOW), answers(&["web"]));
    assert_eq!(names, ["web"]);

    let kept = cache::read_in(
        &home.cache(),
        &home.owner("acme"),
        Kind::Environments,
        at(NOW + 1),
    );
    assert!(matches!(kept, Held::Fresh(names) if names == ["web"]));
}

#[test]
fn a_cloud_that_does_not_answer_leaves_the_stale_names_and_none_when_there_are_none() {
    let home = Home::signed_in(NOW + 600, "acme");
    assert!(names_in(&home.paths, &no_env(), at(NOW), is_silent).is_empty());

    home.keep("acme", &["app"], NOW - 600);
    assert_eq!(
        names_in(&home.paths, &no_env(), at(NOW), is_silent),
        ["app"]
    );

    home.keep("acme", &["app"], NOW - 4_000);
    assert!(names_in(&home.paths, &no_env(), at(NOW), is_silent).is_empty());
}

#[test]
fn an_expired_token_asks_nobody_and_never_refreshes() {
    let home = Home::signed_in(NOW - 1, "acme");
    home.keep("acme", &["app"], NOW - 600);
    let before = std::fs::read(config::oauth_credentials_path(
        &home.paths.platform_config_dir,
    ))
    .unwrap();
    let asked = Cell::new(false);

    let names = names_in(&home.paths, &no_env(), at(NOW), |_| {
        asked.set(true);
        None
    });

    assert_eq!(names, ["app"]);
    assert!(!asked.get());
    let after = std::fs::read(config::oauth_credentials_path(
        &home.paths.platform_config_dir,
    ))
    .unwrap();
    assert_eq!(before, after, "the saved sign-in is left as it was");
}

#[test]
fn another_organization_never_sees_the_cached_names() {
    let home = Home::signed_in(NOW + 600, "globex");
    home.keep("acme", &["app"], NOW - 10);
    assert!(names_in(&home.paths, &no_env(), at(NOW), is_silent).is_empty());
}

#[test]
fn an_api_key_reads_and_writes_no_cache() {
    let home = Home::signed_in(NOW + 600, "acme");
    home.keep("acme", &["cached"], NOW - 10);
    let env = MapEnv::new([("CODEWIRE_API_KEY", "synthetic-key")]);

    let names = names_in(&home.paths, &env, at(NOW), answers(&["live"]));

    assert_eq!(names, ["live"]);
    let kept = cache::read_in(
        &home.cache(),
        &home.owner("acme"),
        Kind::Environments,
        at(NOW + 1),
    );
    assert!(
        matches!(kept, Held::Fresh(names) if names == ["cached"]),
        "the cache is untouched"
    );
}

#[test]
fn hostile_names_from_the_cloud_are_dropped_and_no_account_means_no_cache() {
    let home = Home::signed_in(NOW + 600, "acme");
    let names = names_in(
        &home.paths,
        &no_env(),
        at(NOW),
        answers(&["app", "dev;touch pwned"]),
    );
    assert_eq!(names, ["app"], "the name is dropped before it is returned");
    let kept = cache::read_in(
        &home.cache(),
        &home.owner("acme"),
        Kind::Environments,
        at(NOW + 1),
    );
    assert!(matches!(kept, Held::Fresh(names) if names == ["app"]));

    let nobody = Home::signed_in(NOW + 600, "acme");
    std::fs::remove_file(nobody.paths.platform_config_dir.join("account.json")).unwrap();
    let names = names_in(&nobody.paths, &no_env(), at(NOW), answers(&["app", "a b"]));
    assert_eq!(names, ["app"]);
    assert!(!nobody.cache().exists(), "no user id, no cache");

    let env = MapEnv::new([("CODEWIRE_API_KEY", "synthetic-key")]);
    let names = names_in(&home.paths, &env, at(NOW), answers(&["live", "x$(y)"]));
    assert_eq!(
        names,
        ["live"],
        "a sign-in that keeps no cache is filtered too"
    );
}
