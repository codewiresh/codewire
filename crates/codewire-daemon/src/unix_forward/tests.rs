use std::io::{Read as _, Write as _};
use std::os::unix::net::UnixListener as StdUnixListener;

use super::*;

fn peer_uid(stream: &std::os::unix::net::UnixStream) -> u32 {
    use std::os::fd::AsRawFd as _;
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: SO_PEERCRED fills a `ucred` of the length given.
    let read = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut credentials).cast(),
            &raw mut length,
        )
    };
    assert_eq!(read, 0, "{}", std::io::Error::last_os_error());
    credentials.uid
}

/// A socket the test serves as itself, answering each caller with its peer
/// credentials' uid.
fn served(path: &Path) -> std::thread::JoinHandle<u32> {
    let listener = StdUnixListener::bind(path).unwrap();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let uid = peer_uid(&stream);
        stream.write_all(b"hello").unwrap();
        uid
    })
}

#[test]
fn a_users_socket_is_reached_and_sees_the_caller() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("user.sock");
    let server = served(&path);
    let mut stream = connect(&path).unwrap();
    let mut answer = String::new();
    stream.read_to_string(&mut answer).unwrap();
    assert_eq!(answer, "hello");
    assert_eq!(server.join().unwrap(), rustix::process::geteuid().as_raw());
}

#[test]
fn a_link_to_a_users_socket_is_followed() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("user.sock");
    let link = directory.path().join("link.sock");
    let server = served(&path);
    std::os::unix::fs::symlink(&path, &link).unwrap();
    let mut answer = String::new();
    connect(&link).unwrap().read_to_string(&mut answer).unwrap();
    assert_eq!(answer, "hello");
    server.join().unwrap();
}

#[tokio::test]
async fn a_platform_socket_is_refused_by_path_symlink_and_hard_link() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("platform.sock");
    let (_listener, _record) = platform_sockets::bind(&path, "the test's platform socket").unwrap();
    let symlink = directory.path().join("symlink.sock");
    std::os::unix::fs::symlink(&path, &symlink).unwrap();
    // A hard link has a name of its own, so only the identity can catch it.
    let hard = directory.path().join("hard.sock");
    std::fs::hard_link(&path, &hard).unwrap();
    for target in [&path, &symlink, &hard] {
        let refused = connect(target).unwrap_err();
        assert!(
            matches!(&refused, UnixForwardError::Refused(reason)
                if reason.contains("is the test's platform socket, which belongs to the platform")),
            "{target:?}: {refused}"
        );
    }
}

#[tokio::test]
async fn a_platform_socket_bound_again_is_still_refused() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("platform.sock");
    let first = platform_sockets::bind(&path, "the test's platform socket").unwrap();
    drop(first);
    std::fs::remove_file(&path).unwrap();
    let (_listener, _record) = platform_sockets::bind(&path, "the test's platform socket").unwrap();
    assert!(matches!(connect(&path), Err(UnixForwardError::Refused(_))));
}

#[test]
fn what_is_not_a_listening_socket_is_named() {
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("file");
    std::fs::write(&file, b"").unwrap();
    assert_eq!(
        connect(&file).unwrap_err(),
        UnixForwardError::Refused(format!(
            "{} is not a socket",
            shown(&file.to_string_lossy())
        ))
    );
    let missing = directory.path().join("missing.sock");
    assert!(
        matches!(connect(&missing), Err(UnixForwardError::Failed(reason))
        if reason.starts_with("nothing in the environment is at"))
    );
    // A socket whose server has gone.
    let gone = directory.path().join("gone.sock");
    drop(StdUnixListener::bind(&gone).unwrap());
    assert!(
        matches!(connect(&gone), Err(UnixForwardError::Failed(reason))
        if reason.starts_with("nothing is listening on"))
    );
}

#[test]
fn a_target_is_an_absolute_path_short_enough_for_a_socket() {
    assert_eq!(
        target("/home/codewire/rex.sock").unwrap(),
        Path::new("/home/codewire/rex.sock")
    );
    for refused in ["rex.sock", "./rex.sock", "@abstract", "", "/a\0b"] {
        assert!(
            matches!(target(refused), Err(UnixForwardError::Refused(_))),
            "{refused:?}"
        );
    }
    let longest = format!("/{}", "x".repeat(MAX_PATH_BYTES - 1));
    assert!(target(&longest).is_ok());
    assert!(matches!(
        target(&format!("{longest}x")),
        Err(UnixForwardError::Refused(_))
    ));
}

#[test]
fn a_shown_path_is_escaped_and_bounded() {
    assert_eq!(shown("/a\nb\"c"), "\"/a\\nb\\\"c\"");
    let long = "x".repeat(1000);
    let shown = shown(&long);
    assert!(
        shown.ends_with('…') && shown.chars().count() < 200,
        "{shown}"
    );
}
