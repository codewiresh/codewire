use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::*;

fn at(seconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(seconds)
}

fn owner(server: &str, organization: &str) -> Owner {
    Owner {
        server: server.to_owned(),
        user: "user-1".to_owned(),
        organization: organization.to_owned(),
    }
}

fn names_of(held: Held) -> (&'static str, Vec<String>) {
    match held {
        Held::Fresh(names) => ("fresh", names),
        Held::Stale(names) => ("stale", names),
        Held::Nothing => ("nothing", Vec::new()),
    }
}

fn strings(names: &[&str]) -> Vec<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
}

#[test]
fn names_are_fresh_for_thirty_seconds_then_stale_for_an_hour_then_gone() {
    let directory = tempfile::tempdir().unwrap();
    let who = owner("https://codewire.example", "acme");
    write_in(
        directory.path(),
        &who,
        Kind::Environments,
        &strings(&["app", "db"]),
        at(1_000),
    );

    let read = |seconds| {
        names_of(read_in(
            directory.path(),
            &who,
            Kind::Environments,
            at(seconds),
        ))
    };
    assert_eq!(read(1_000), ("fresh", strings(&["app", "db"])));
    assert_eq!(read(1_030), ("fresh", strings(&["app", "db"])));
    assert_eq!(read(1_031), ("stale", strings(&["app", "db"])));
    assert_eq!(read(1_000 + 3_600), ("stale", strings(&["app", "db"])));
    assert_eq!(read(1_000 + 3_601).0, "nothing");
}

#[test]
fn another_server_or_organization_never_sees_the_names() {
    let directory = tempfile::tempdir().unwrap();
    let who = owner("https://codewire.example", "acme");
    write_in(
        directory.path(),
        &who,
        Kind::Environments,
        &strings(&["app"]),
        at(1_000),
    );

    for other in [
        owner("https://other.example", "acme"),
        owner("https://codewire.example", "globex"),
    ] {
        assert_eq!(
            names_of(read_in(
                directory.path(),
                &other,
                Kind::Environments,
                at(1_001)
            ))
            .0,
            "nothing",
            "{other:?}"
        );
    }
}

#[test]
fn another_user_of_the_same_server_and_organization_never_sees_the_names() {
    let directory = tempfile::tempdir().unwrap();
    let who = owner("https://codewire.example", "acme");
    write_in(
        directory.path(),
        &who,
        Kind::Environments,
        &strings(&["app"]),
        at(1_000),
    );

    let other = Owner {
        user: "user-2".to_owned(),
        ..who
    };
    assert_eq!(
        names_of(read_in(
            directory.path(),
            &other,
            Kind::Environments,
            at(1_001)
        ))
        .0,
        "nothing"
    );
}

#[test]
fn a_write_for_another_owner_replaces_the_file_and_never_extends_it() {
    let directory = tempfile::tempdir().unwrap();
    let acme = owner("https://codewire.example", "acme");
    let globex = owner("https://codewire.example", "globex");
    write_in(
        directory.path(),
        &acme,
        Kind::Environments,
        &strings(&["app"]),
        at(1_000),
    );
    write_in(
        directory.path(),
        &globex,
        Kind::Environments,
        &strings(&["web"]),
        at(1_001),
    );

    assert_eq!(
        names_of(read_in(
            directory.path(),
            &acme,
            Kind::Environments,
            at(1_002)
        ))
        .0,
        "nothing"
    );
    assert_eq!(
        names_of(read_in(
            directory.path(),
            &globex,
            Kind::Environments,
            at(1_002)
        )),
        ("fresh", strings(&["web"]))
    );
}

#[test]
fn removing_the_cache_forgets_every_name() {
    let config_dir = tempfile::tempdir().unwrap();
    let who = owner("https://codewire.example", "acme");
    let directory = directory(config_dir.path());
    write_in(
        &directory,
        &who,
        Kind::Environments,
        &strings(&["app"]),
        at(1_000),
    );

    remove(config_dir.path());

    assert_eq!(
        names_of(read_in(&directory, &who, Kind::Environments, at(1_001))).0,
        "nothing"
    );
    remove(config_dir.path());
}

#[test]
fn a_damaged_or_foreign_file_offers_nothing() {
    let directory = tempfile::tempdir().unwrap();
    let who = owner("https://codewire.example", "acme");
    std::fs::write(file_in(directory.path()), b"{ not json").unwrap();
    assert_eq!(
        names_of(read_in(
            directory.path(),
            &who,
            Kind::Environments,
            at(1_000)
        ))
        .0,
        "nothing"
    );

    std::fs::write(
        file_in(directory.path()),
        br#"{"version":99,"server":"https://codewire.example","organization":"acme","lists":{}}"#,
    )
    .unwrap();
    assert_eq!(
        names_of(read_in(
            directory.path(),
            &who,
            Kind::Environments,
            at(1_000)
        ))
        .0,
        "nothing"
    );
}

#[cfg(unix)]
#[test]
fn the_cache_is_private_to_the_user_and_holds_nothing_but_names() {
    use std::os::unix::fs::PermissionsExt as _;

    let directory = tempfile::tempdir().unwrap();
    let cache = directory.path().join("completion");
    let who = owner("https://codewire.example", "acme");
    write_in(
        &cache,
        &who,
        Kind::Environments,
        &strings(&["app"]),
        at(1_000),
    );

    let file_mode = std::fs::metadata(file_in(&cache))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    let directory_mode = std::fs::metadata(&cache).unwrap().permissions().mode() & 0o777;
    assert_eq!(file_mode, 0o600);
    assert_eq!(directory_mode, 0o700);

    let text = std::fs::read_to_string(file_in(&cache)).unwrap();
    let keys = serde_json::from_str::<serde_json::Value>(&text).unwrap();
    assert_eq!(
        keys["lists"]["environments"]["names"],
        serde_json::json!(["app"])
    );
    assert_eq!(
        std::fs::read_dir(&cache).unwrap().count(),
        1,
        "no staged file is left behind"
    );
}

const HOSTILE: [&str; 7] = [
    "dev;touch pwned",
    "dev touch",
    "dev$(touch pwned)",
    "dev\ntouch pwned",
    "dev\u{1b}[2J",
    "`touch`",
    "-rf",
];

#[test]
fn a_name_a_shell_would_run_is_neither_kept_nor_offered() {
    let directory = tempfile::tempdir().unwrap();
    let who = owner("https://codewire.example", "acme");
    let mut names = strings(&["app"]);
    names.extend(HOSTILE.iter().map(|name| (*name).to_owned()));
    assert_eq!(offerable(names.clone()), ["app"]);

    write_in(
        directory.path(),
        &who,
        Kind::Environments,
        &names,
        at(1_000),
    );
    let kept = std::fs::read_to_string(file_in(directory.path())).unwrap();
    assert!(!kept.contains("touch"), "{kept}");

    // A file another process wrote is filtered again where it is read.
    let planted = serde_json::json!({
        "version": VERSION, "server": who.server, "user": who.user, "organization": who.organization,
        "lists": {"environments": {"at_unix": 1_000, "names": names}},
    });
    std::fs::write(file_in(directory.path()), planted.to_string()).unwrap();
    assert_eq!(
        names_of(read_in(
            directory.path(),
            &who,
            Kind::Environments,
            at(1_001)
        )),
        ("fresh", strings(&["app"]))
    );
}

#[test]
fn a_cache_file_or_list_past_its_bound_is_ignored_or_cut() {
    let directory = tempfile::tempdir().unwrap();
    let who = owner("https://codewire.example", "acme");
    let many: Vec<String> = (0..MAX_NAMES + 50).map(|n| format!("env-{n}")).collect();
    assert_eq!(offerable(many).len(), MAX_NAMES);

    std::fs::write(
        file_in(directory.path()),
        vec![b' '; MAX_FILE_BYTES as usize + 1],
    )
    .unwrap();
    assert_eq!(
        names_of(read_in(
            directory.path(),
            &who,
            Kind::Environments,
            at(1_000)
        ))
        .0,
        "nothing"
    );
}
