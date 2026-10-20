//! The delegation skill: only a conversation with its own identity is given
//! it, in its own driver directory, owner-only, naming the running `cw`.
//! Every launch writes it again, and no symlink in its place is followed.
use super::*;
use delegation::{NAME, SKILL, prepare};

const CW: &str = "/opt/codewire/bin/cw";

fn own() -> ConversationIdentity {
    ConversationIdentity::Own([
        ("CW_ENVIRONMENT", "environment".into()),
        ("CW_SESSION_ID", "session".into()),
    ])
}

/// A conversation's owner-private driver directory.
fn driver_dir(temporary: &tempfile::TempDir) -> PathBuf {
    let dir = temporary.path().join("driver");
    private_directory(&dir).unwrap();
    dir
}

fn mode(path: &Path) -> u32 {
    fs::symlink_metadata(path).unwrap().permissions().mode() & 0o7777
}

/// The command lines of the skill's `sh` blocks.
fn commands(text: &str) -> Vec<&str> {
    let mut commands = Vec::new();
    let mut fenced = false;
    for line in text.lines() {
        match (fenced, line) {
            (false, "```sh") => fenced = true,
            (true, "```") => fenced = false,
            (true, command) => commands.push(command),
            (false, _) => {}
        }
    }
    assert!(!fenced, "an sh block is not closed");
    commands
}

#[test]
fn the_embedded_text_is_a_skill_whose_every_command_names_the_running_cw() {
    let (frontmatter, body) = SKILL
        .strip_prefix("---\n")
        .and_then(|rest| rest.split_once("\n---\n"))
        .expect("the skill starts with frontmatter");
    let fields: Vec<(&str, &str)> = frontmatter
        .lines()
        .map(|line| line.split_once(": ").expect("a frontmatter field"))
        .collect();
    let [("name", name), ("description", description)] = fields.as_slice() else {
        panic!("the frontmatter is not a name and a description: {fields:?}");
    };
    assert_eq!(*name, NAME);
    // The Agent Skills rules noel checks: a name of lowercase letters,
    // digits and single hyphens, and a description of 1 to 1024 characters.
    assert!(name.split('-').all(|word| {
        !word.is_empty()
            && word
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    }));
    assert!((1..=1024).contains(&description.trim().chars().count()));
    // A plain YAML scalar ends at ": " and at " #".
    assert!(!description.contains(": ") && !description.contains(" #"));

    let commands = commands(body);
    assert_eq!(commands.len(), 10, "{commands:?}");
    for command in &commands {
        assert!(command.starts_with("{{cw}} "), "{command}");
    }
    // Each launch is detached, under this conversation, in its environment.
    for (launch, agent) in commands.iter().zip(["codex", "claude", "noel"]) {
        assert!(
            launch.starts_with(&format!(
                "{{{{cw}}}} run --in \"$CW_ENVIRONMENT\" --agent {agent} "
            )),
            "{launch}"
        );
        assert!(
            launch.ends_with(" --parent \"$CW_SESSION_ID\" --name NAME --detach --prompt 'TASK'"),
            "{launch}"
        );
        assert_eq!(launch.contains(" --model "), agent == "noel", "{launch}");
    }
    assert!(commands[3..].iter().all(|other| !other.contains(" run ")));
    // A worker is named with --session, never by a second positional.
    for control in ["interrupt", "stop"] {
        let lines: Vec<_> = commands
            .iter()
            .filter(|command| command.starts_with(&format!("{{{{cw}}}} {control} ")))
            .collect();
        assert!(!lines.is_empty(), "{control}");
        for line in lines {
            assert!(
                line.starts_with(&format!(
                    "{{{{cw}}}} {control} \"$CW_ENVIRONMENT\" --session NAME"
                )),
                "{line}"
            );
        }
    }
}

#[test]
fn only_a_conversation_with_its_own_identity_is_given_the_skill() {
    let temporary = tempfile::tempdir().unwrap();
    let dir = driver_dir(&temporary);
    for identity in [
        ConversationIdentity::Removed,
        ConversationIdentity::Unchanged,
    ] {
        assert_eq!(prepare(&identity, &dir, Path::new(CW)).unwrap(), None);
        assert!(!dir.join("skills").exists(), "{identity:?}");
    }
    assert_eq!(
        arguments(SESSION, "faux/echo", Some("high"), None),
        [
            "--mode",
            "rpc",
            "--session-id",
            SESSION,
            "--model",
            "faux/echo",
            "--thinking",
            "high"
        ]
    );

    let skill = prepare(&own(), &dir, Path::new(CW)).unwrap().unwrap();
    let skill_dir = dir.join("skills").join(NAME);
    assert_eq!(Path::new(&skill), skill_dir);
    assert_eq!(mode(&dir.join("skills")), 0o700);
    assert_eq!(mode(&skill_dir), 0o700);
    let file = skill_dir.join("SKILL.md");
    assert!(fs::symlink_metadata(&file).unwrap().is_file());
    assert_eq!(mode(&file), 0o600);
    // Nothing but the skill is left there: no temporary file.
    let entries: Vec<_> = fs::read_dir(&skill_dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(entries, ["SKILL.md"]);
    assert_eq!(
        arguments(SESSION, "faux/echo", Some("high"), Some(&skill)),
        [
            "--mode",
            "rpc",
            "--session-id",
            SESSION,
            "--model",
            "faux/echo",
            "--thinking",
            "high",
            "--skill",
            skill.as_str()
        ]
    );
}

#[test]
fn the_written_skill_names_cw_by_its_absolute_path_quoted_for_a_shell() {
    use std::os::unix::ffi::OsStrExt as _;
    let temporary = tempfile::tempdir().unwrap();
    let dir = driver_dir(&temporary);
    let file = dir.join("skills").join(NAME).join("SKILL.md");
    for (cw, word) in [
        (CW, CW),
        ("/home/a b/it's/cw", r"'/home/a b/it'\''s/cw'"),
        ("/srv/$HOME/cw", "'/srv/$HOME/cw'"),
    ] {
        prepare(&own(), &dir, Path::new(cw)).unwrap().unwrap();
        let written = fs::read_to_string(&file).unwrap();
        assert_eq!(written, SKILL.replace("{{cw}}", word));
        assert!(!written.contains("{{"), "{written}");
        let commands = commands(&written);
        assert_eq!(commands.len(), 10);
        for command in commands {
            assert!(command.starts_with(&format!("{word} ")), "{command}");
        }
        assert!(written.contains(&format!(
            "{word} run --in \"$CW_ENVIRONMENT\" --agent noel --model PROVIDER/ID --parent \"$CW_SESSION_ID\" --name NAME --detach --prompt 'TASK'\n"
        )));
    }
    // A path that is not text cannot be written into the skill.
    let unreadable = std::ffi::OsStr::from_bytes(b"/opt/\xff/cw");
    assert!(prepare(&own(), &dir, Path::new(unreadable)).is_err());
}

#[test]
fn every_launch_rewrites_the_skill_and_follows_no_symlink() {
    use std::os::unix::fs::symlink;
    let temporary = tempfile::tempdir().unwrap();
    let dir = driver_dir(&temporary);
    let skill_dir = dir.join("skills").join(NAME);
    let file = skill_dir.join("SKILL.md");
    let outside = temporary.path().join("outside");
    fs::create_dir(&outside).unwrap();
    let target = outside.join("target.md");

    // An older cw's skill, left readable by others, is replaced.
    prepare(&own(), &dir, Path::new("/old/cw"))
        .unwrap()
        .unwrap();
    assert!(fs::read_to_string(&file).unwrap().contains("/old/cw run "));
    fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
    prepare(&own(), &dir, Path::new(CW)).unwrap().unwrap();
    let current = SKILL.replace("{{cw}}", CW);
    assert_eq!(fs::read_to_string(&file).unwrap(), current);
    assert_eq!(mode(&file), 0o600);

    // A symlink where the file belongs is replaced, and its target is kept.
    fs::write(&target, "untouched").unwrap();
    fs::remove_file(&file).unwrap();
    symlink(&target, &file).unwrap();
    prepare(&own(), &dir, Path::new(CW)).unwrap().unwrap();
    assert!(fs::symlink_metadata(&file).unwrap().is_file());
    assert_eq!(fs::read_to_string(&file).unwrap(), current);
    assert_eq!(fs::read_to_string(&target).unwrap(), "untouched");

    // A symlink where either directory belongs is refused: nothing is
    // written through it.
    for linked in [&skill_dir, &dir.join("skills")] {
        fs::remove_dir_all(dir.join("skills")).unwrap();
        if linked == &skill_dir {
            private_directory(&dir.join("skills")).unwrap();
        }
        symlink(&outside, linked).unwrap();
        assert!(prepare(&own(), &dir, Path::new(CW)).is_err());
        let left: Vec<_> = fs::read_dir(&outside)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(left, ["target.md"], "{}", linked.display());
        fs::remove_file(linked).unwrap();
    }
    // So is a directory that others can enter.
    fs::create_dir_all(&skill_dir).unwrap();
    fs::set_permissions(dir.join("skills"), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(prepare(&own(), &dir, Path::new(CW)).is_err());
}

#[test]
fn a_host_users_noel_conversation_is_launched_with_the_skill_and_no_other_is() {
    // The host user's own conversation: the skill names the running cw.
    let h = takedown::host(AgentKind::Noel);
    let skill = h.driver.delegation_skill().unwrap().unwrap();
    let skill_dir = h.driver.dir.join("skills").join(NAME);
    assert_eq!(Path::new(&skill), skill_dir);
    let cw = env::current_exe().unwrap();
    assert_eq!(
        fs::read_to_string(skill_dir.join("SKILL.md")).unwrap(),
        delegation::text(&cw).unwrap()
    );
    // Off a host no conversation has its own identity, and none is given it.
    let guest = harness();
    assert_eq!(guest.driver.delegation_skill().unwrap(), None);
    assert!(!guest.driver.dir.join("skills").exists());
}

/// Linux names an executable replaced on disk `PATH (deleted)`. A driver
/// that starts noel again after a crash writes the skill again, with the
/// path it resolved when it started, never one it resolves then.
#[test]
fn every_later_write_names_the_cw_the_driver_resolved_when_it_started() {
    let mut h = takedown::host(AgentKind::Noel);
    let now = env::current_exe().unwrap();
    assert_eq!(h.driver.cw.as_deref(), Some(now.as_path()));
    h.driver.cw = Some(PathBuf::from(CW));
    let file = h.driver.dir.join("skills").join(NAME).join("SKILL.md");
    let resolved_first = SKILL.replace("{{cw}}", CW);
    for write in ["the launch", "noel started again"] {
        h.driver.delegation_skill().unwrap().unwrap();
        let written = fs::read_to_string(&file).unwrap();
        assert_eq!(written, resolved_first, "{write}");
        assert!(!written.contains(now.to_str().unwrap()), "{write}");
        fs::write(&file, "replaced between the writes").unwrap();
    }
    // A driver that found no cw when it started writes no skill: the
    // launch fails instead of naming a path resolved later.
    h.driver.cw = None;
    assert!(h.driver.delegation_skill().is_err());
    assert_eq!(
        fs::read_to_string(&file).unwrap(),
        "replaced between the writes"
    );
}

/// Codex and Claude are launched as before: neither takes a skill, on a
/// trusted host or in a Sandbox.
#[test]
fn codex_and_claude_are_launched_without_a_skill() {
    assert_eq!(
        codex_app_server_arguments("/workspace"),
        [
            "-c",
            "projects={\"/workspace\"={trust_level=\"trusted\"}}",
            "app-server"
        ]
    );
    let claude = harness_for(AgentKind::Claude).driver.config.clone();
    assert_eq!(
        claude_arguments(&claude, false, false, SESSION),
        [
            "-p",
            "--input-format",
            "stream-json",
            "--output-format",
            "stream-json",
            "--verbose",
            "--replay-user-messages",
            "--model",
            "faux/echo",
            "--session-id",
            SESSION
        ]
    );
    for (sandbox, established) in [(false, true), (true, false), (true, true)] {
        let arguments = claude_arguments(&claude, sandbox, established, SESSION);
        assert!(!arguments.iter().any(|a| a == "--skill"), "{arguments:?}");
    }
}
