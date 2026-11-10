//! The debugfs file step on real e2fsprogs images.

use std::fs;
use std::io;
use std::path::PathBuf;
use std::process::Command;

use super::*;
use crate::SystemTools;

fn tool(name: &str) -> PathBuf {
    ["/usr/sbin", "/usr/bin", "/sbin"]
        .iter()
        .map(|directory| Path::new(directory).join(name))
        .find(|path| path.is_file())
        .unwrap_or_else(|| panic!("{name} for ext4 scrub tests"))
}

fn image(scratch: &Path, features: &[&str]) -> PathBuf {
    let disk = scratch.join("disk.img");
    fs::File::create(&disk)
        .unwrap()
        .set_len(32 * 1024 * 1024)
        .unwrap();
    let mut command = Command::new(tool("mkfs.ext4"));
    command.args(["-q", "-F", "-b", "4096", "-E", "nodiscard"]);
    for feature in features {
        command.args(["-O", feature]);
    }
    let status = command
        .arg(&disk)
        .env_clear()
        .env("LC_ALL", "C")
        .status()
        .unwrap();
    assert!(status.success());
    disk
}

/// Run debugfs on `disk` unconfined, as a test's own setup.
fn debugfs_setup(disk: &Path, request: &str) -> Vec<u8> {
    let output = Command::new(tool("debugfs"))
        .args(["-w", "-R", request])
        .arg(disk)
        .env_clear()
        .env("LC_ALL", "C")
        .env("PAGER", "__none__")
        .output()
        .unwrap();
    assert!(output.status.success());
    output.stdout
}

fn plant(disk: &Path, scratch: &Path, destination: &str, contents: &[u8]) {
    let host = scratch.join("planted");
    fs::write(&host, contents).unwrap();
    debugfs_setup(
        disk,
        &format!("write {} {destination}", host.to_str().unwrap()),
    );
    fs::remove_file(host).unwrap();
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn names(lookup: &Lookup) -> Vec<String> {
    let Lookup::Directory(entries) = lookup else {
        panic!("{lookup:?}")
    };
    let mut names = entries
        .iter()
        .filter_map(|entry| entry.name.clone())
        .collect::<Vec<_>>();
    names.sort();
    names
}

/// The system's e2fsprogs, except that each `rm` and every request session
/// does nothing: a removal that can't be proven.
struct RemovalIgnored;

impl Tools for RemovalIgnored {
    fn program(&self, name: &'static str) -> Option<PathBuf> {
        SystemTools.program(name)
    }

    fn command(
        &self,
        program: &Path,
        leading_args: &[&str],
        disk: &Path,
    ) -> io::Result<tokio::process::Command> {
        let ignored = |argument: &&str| argument.starts_with("rm ") || *argument == "-f";
        let arguments = if leading_args.iter().any(ignored) {
            vec!["-R", "stats"]
        } else {
            leading_args.to_vec()
        };
        SystemTools.command(program, &arguments, disk)
    }
}

#[test]
fn a_listing_keeps_each_entrys_kind_and_only_names_debugfs_can_take_back() {
    let listing = b"/2/040755/0/0/./0/\n\
        /2/040755/0/0/../0/\n\
        /12/100600/0/0/auth.json/123/\n\
        /13/040700/0/0/sessions/0/\n\
        /14/120777/0/0/link/0/\n\
        /15/010644/0/0/fifo/0/\n\
        /16/100600/0/0/has space/7/\n\
        not a listing line\n";
    assert_eq!(
        parse_listing(listing),
        vec![
            Entry {
                name: Some("auth.json".into()),
                kind: EntryKind::File,
                size: 123
            },
            Entry {
                name: Some("sessions".into()),
                kind: EntryKind::Directory,
                size: 0
            },
            Entry {
                name: Some("link".into()),
                kind: EntryKind::SymbolicLink,
                size: 0
            },
            Entry {
                name: Some("fifo".into()),
                kind: EntryKind::Other,
                size: 0
            },
            Entry {
                name: Some("has space".into()),
                kind: EntryKind::File,
                size: 7
            },
        ]
    );
    // A name with a newline, or that is not UTF-8, cannot be Codewire's: its
    // pieces are skipped or it stays nameless, and nothing fails.
    let odd = parse_listing(
        b"/16/100600/1000/1000/notes\nmore/3/\n/17/100600/1000/1000/\xff\xfe/4/\n/18/100600/1000/1000/with space/5/\ngarbage\n",
    );
    assert_eq!(
        odd.iter()
            .map(|entry| entry.name.as_deref())
            .collect::<Vec<_>>(),
        [None, Some("with space")]
    );
    let quote = parse_listing(b"/19/100600/0/0/say \"hi\"/2/\n/20/100600/0/0/back\\slash/2/\n");
    assert_eq!(quote.len(), 2);
    assert!(quote.iter().all(|entry| entry.name.is_none()), "{quote:?}");
    assert!(parse_listing(b"").is_empty());
}

#[tokio::test]
async fn a_lookup_walks_each_component_and_never_follows_a_symbolic_link() {
    let scratch = tempfile::tempdir().unwrap();
    let disk = image(scratch.path(), &[]);
    debugfs_setup(&disk, "mkdir /agent");
    debugfs_setup(&disk, "mkdir /agent/.codex");
    plant(&disk, scratch.path(), "/agent/.codex/auth.json", b"{}");
    debugfs_setup(&disk, "symlink /agent/.claude /agent/.codex");

    let tools = SystemTools;
    let codex = lookup_directory(&tools, &disk, &["agent", ".codex"])
        .await
        .unwrap();
    assert_eq!(names(&codex), ["auth.json"]);
    assert_eq!(
        lookup_directory(&tools, &disk, &["agent", ".claude"])
            .await
            .unwrap(),
        Lookup::NotDirectory(EntryKind::SymbolicLink)
    );
    assert_eq!(
        lookup_directory(&tools, &disk, &["agent", ".codex", "auth.json"])
            .await
            .unwrap(),
        Lookup::NotDirectory(EntryKind::File)
    );
    assert_eq!(
        lookup_directory(&tools, &disk, &["agent", "missing"])
            .await
            .unwrap(),
        Lookup::Absent
    );
    assert_eq!(block_size(&tools, &disk).await.unwrap(), 4096);
    assert_eq!(
        read_file(&tools, &disk, &["agent", ".codex"], "auth.json")
            .await
            .unwrap(),
        b"{}"
    );
}

#[tokio::test]
async fn a_removed_file_is_zeroed_on_the_disk_and_proven_gone() {
    let scratch = tempfile::tempdir().unwrap();
    let disk = image(scratch.path(), &[]);
    let token = b"cw-ext4-files-test-token-a91f";
    debugfs_setup(&disk, "mkdir /agent");
    plant(&disk, scratch.path(), "/agent/auth.json", token);
    plant(&disk, scratch.path(), "/agent/kept", b"kept");
    assert!(contains(&fs::read(&disk).unwrap(), token));

    zero_and_remove(
        &SystemTools,
        &disk,
        &["agent"],
        "auth.json",
        token.len() as u64,
        4096,
    )
    .await
    .unwrap();

    assert!(!contains(&fs::read(&disk).unwrap(), token));
    let agent = lookup_directory(&SystemTools, &disk, &["agent"])
        .await
        .unwrap();
    assert_eq!(names(&agent), ["kept"]);
}

/// `e2fsck -f -n` on `disk`: whether it found nothing to fix.
fn fsck_clean(disk: &Path) -> bool {
    Command::new(tool("e2fsck"))
        .args(["-f", "-n"])
        .arg(disk)
        .env_clear()
        .env("LC_ALL", "C")
        .output()
        .unwrap()
        .status
        .success()
}

#[tokio::test]
async fn a_fragmented_file_is_removed_whole_and_leaves_the_filesystem_consistent() {
    let scratch = tempfile::tempdir().unwrap();
    let disk = image(scratch.path(), &[]);
    // One-block files with every other one removed leave one-block holes,
    // which the next file fills first: 128 extents, more than the inode
    // holds, so its extent tree has a block of its own.
    debugfs_setup(&disk, "mkdir /fill");
    for index in 0..256 {
        plant(
            &disk,
            scratch.path(),
            &format!("/fill/{index}"),
            &[b'f'; 4096],
        );
    }
    for index in (1..256).step_by(2) {
        debugfs_setup(&disk, &format!("rm /fill/{index}"));
    }
    let token = b"cw-ext4-files-fragmented-token";
    let mut contents = Vec::new();
    while contents.len() < 128 * 4096 {
        contents.extend_from_slice(token);
    }
    contents.truncate(128 * 4096);
    debugfs_setup(&disk, "mkdir /agent");
    plant(&disk, scratch.path(), "/agent/auth.json", &contents);
    let blocks = String::from_utf8(debugfs_setup(&disk, "blocks /agent/auth.json")).unwrap();
    assert!(
        blocks.split_whitespace().count() > 128,
        "the file has an extent tree block: {blocks}"
    );
    assert!(fsck_clean(&disk));

    zero_and_remove(
        &SystemTools,
        &disk,
        &["agent"],
        "auth.json",
        contents.len() as u64,
        4096,
    )
    .await
    .unwrap();

    assert!(
        fsck_clean(&disk),
        "every block the file held was freed by its removal"
    );
    assert!(!contains(&fs::read(&disk).unwrap(), token));
}

#[tokio::test]
async fn a_removal_that_cannot_be_proven_fails() {
    let scratch = tempfile::tempdir().unwrap();
    let disk = image(scratch.path(), &[]);
    debugfs_setup(&disk, "mkdir /agent");
    plant(&disk, scratch.path(), "/agent/auth.json", b"token");
    debugfs_setup(&disk, "mkdir /agent/tree");
    plant(&disk, scratch.path(), "/agent/tree/file", b"file");

    let error = zero_and_remove(&RemovalIgnored, &disk, &["agent"], "auth.json", 5, 4096)
        .await
        .unwrap_err();
    assert!(matches!(error, Error::NotRemoved), "{error}");
    let error = remove_tree(&RemovalIgnored, &disk, &["agent", "tree"])
        .await
        .unwrap_err();
    assert!(matches!(error, Error::NotRemoved), "{error}");
}

#[tokio::test]
async fn a_file_whose_data_lives_in_its_inode_is_refused() {
    let scratch = tempfile::tempdir().unwrap();
    let disk = image(scratch.path(), &["inline_data"]);
    debugfs_setup(&disk, "mkdir /agent");
    plant(&disk, scratch.path(), "/agent/auth.json", b"inline token");

    let error = zero_and_remove(&SystemTools, &disk, &["agent"], "auth.json", 12, 4096)
        .await
        .unwrap_err();
    assert!(matches!(error, Error::DataNotInBlocks), "{error}");
}

#[tokio::test]
async fn a_tree_is_removed_whole_and_a_symbolic_link_to_or_on_the_way_is_refused() {
    let scratch = tempfile::tempdir().unwrap();
    let disk = image(scratch.path(), &[]);
    for directory in [
        "/c",
        "/c/daemon",
        "/c/daemon/sessions",
        "/c/daemon/sessions/1",
    ] {
        debugfs_setup(&disk, &format!("mkdir {directory}"));
    }
    plant(&disk, scratch.path(), "/c/daemon/sessions/1/log", b"log");
    plant(&disk, scratch.path(), "/c/daemon/sessions/index", b"index");
    plant(&disk, scratch.path(), "/c/daemon/kept", b"kept");
    debugfs_setup(&disk, "symlink /c/daemon/sessions/1/out /etc");
    debugfs_setup(&disk, "mkdir /real");
    debugfs_setup(&disk, "symlink /linked /real");
    debugfs_setup(&disk, "symlink /c/tmp /real");
    plant(
        &disk,
        scratch.path(),
        "/c/file-tree",
        b"a file where a tree was",
    );
    debugfs_setup(&disk, "mkdir /c/tmp-names");
    plant(&disk, scratch.path(), "\"/c/tmp-names/a b\"", b"spaced");
    plant(&disk, scratch.path(), "/c/tmp-names/c+d@e", b"symbols");
    debugfs_setup(&disk, "mkdir /c/odd");
    plant(&disk, scratch.path(), "\"/c/odd/back\\\\slash\"", b"odd");

    let tools = SystemTools;
    assert!(
        remove_tree(&tools, &disk, &["c", "daemon", "sessions"])
            .await
            .unwrap()
    );
    let daemon = lookup_directory(&tools, &disk, &["c", "daemon"])
        .await
        .unwrap();
    assert_eq!(names(&daemon), ["kept"]);
    assert!(
        !remove_tree(&tools, &disk, &["c", "daemon", "sessions"])
            .await
            .unwrap()
    );
    assert!(
        remove_tree(&tools, &disk, &["c", "file-tree"])
            .await
            .unwrap()
    );
    // A user's names in /tmp are removed; one debugfs can't be handed back
    // fails the removal.
    assert!(
        remove_tree(&tools, &disk, &["c", "tmp-names"])
            .await
            .unwrap()
    );
    let error = remove_tree(&tools, &disk, &["c", "odd"]).await.unwrap_err();
    assert!(matches!(error, Error::Unreadable(_)), "{error}");
    for refused in [&["c", "tmp"][..], &["linked", "anything"]] {
        let error = remove_tree(&tools, &disk, refused).await.unwrap_err();
        assert!(matches!(error, Error::SymbolicLink), "{refused:?}: {error}");
    }
    assert!(
        !remove_tree(&tools, &disk, &["absent", "tree"])
            .await
            .unwrap()
    );
}
