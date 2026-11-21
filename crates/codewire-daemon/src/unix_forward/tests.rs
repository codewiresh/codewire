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

#[test]
fn every_refusal_code_parses_back_and_nothing_else_does() {
    let refusals = [
        Refusal::NotSocket,
        Refusal::PlatformSocket(0),
        Refusal::PlatformSocket(2),
        Refusal::PlatformDirectory(1),
        Refusal::NotFound,
        Refusal::PermissionDenied,
        Refusal::NotListening,
        Refusal::Failed,
    ];
    for refusal in refusals {
        let code = refusal.code();
        assert!(code.len() < MAX_STATUS_BYTES, "{code}");
        assert_eq!(Refusal::parse(&code, 3), Some(Err(refusal)), "{code}");
    }
    assert_eq!(Refusal::parse(CONNECTED, 0), Some(Ok(())));
    for unknown in [
        "",
        "Connected",
        "connected ",
        "ok",
        "platform-socket 3",
        "platform-socket 01",
        "platform-socket -1",
        "platform-socket",
        "platform-directory 3",
        "not-found: /etc/shadow",
        "the helper's own words",
    ] {
        assert_eq!(Refusal::parse(unknown, 3), None, "{unknown:?}");
    }
}

#[test]
fn a_refusal_is_described_in_the_daemons_words_with_its_own_copy_of_the_target() {
    let shown = shown("/home/codewire/a\nb.sock");
    assert_eq!(
        Refusal::PlatformSocket(1).describe(&shown, &["the first", "the second"]),
        UnixForwardError::Refused(format!(
            "{shown} is the second, which belongs to the platform; forwarding cannot reach it"
        ))
    );
    assert_eq!(
        Refusal::PlatformDirectory(1).describe(&shown, &[]),
        UnixForwardError::Refused(format!(
            "{shown} is in /run/codewire, the platform's own directory; forwarding cannot reach it"
        ))
    );
}

#[test]
fn a_socket_among_the_given_identities_is_refused_by_its_index() {
    use std::os::unix::fs::MetadataExt as _;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("given.sock");
    let _listener = StdUnixListener::bind(&path).unwrap();
    let metadata = std::fs::metadata(&path).unwrap();
    let hard = directory.path().join("hard.sock");
    std::fs::hard_link(&path, &hard).unwrap();
    for target in [&path, &hard] {
        assert_eq!(
            connect_among(target, &[(0, 0), (metadata.dev(), metadata.ino())]).unwrap_err(),
            Refusal::PlatformSocket(1)
        );
    }
}

#[test]
fn the_helper_reports_connected_and_relays_both_ways() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("echo.sock");
    let listener = StdUnixListener::bind(&path).unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = Vec::new();
        stream.read_to_end(&mut request).unwrap();
        stream.write_all(&request).unwrap();
    });
    let (mut status, mut output) = (Vec::new(), Vec::new());
    relay(
        &[path.to_string_lossy().into_owned()],
        &mut status,
        &b"through the helper"[..],
        &mut output,
    )
    .unwrap();
    server.join().unwrap();
    assert_eq!(status, b"connected\n");
    assert_eq!(output, b"through the helper");
}

#[test]
fn the_helper_passes_on_what_the_socket_sends_while_the_connection_stays_open() {
    // The helper's output is its stdout, which holds back everything after
    // the last newline. A server's message without one, such as a WebSocket
    // frame, has to reach the caller while the connection is still open.
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("greeting.sock");
    let listener = StdUnixListener::bind(&path).unwrap();
    let (seen, wait_until_seen) = std::sync::mpsc::channel::<()>();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.write_all(b"hello").unwrap();
        let _ = wait_until_seen.recv_timeout(std::time::Duration::from_secs(10));
    });
    let (input, held_open) = UnixStream::pair().unwrap();
    let (output, mut caller) = UnixStream::pair().unwrap();
    let arguments = [path.to_string_lossy().into_owned()];
    let helper = std::thread::spawn(move || {
        let mut status = Vec::new();
        relay(&arguments, &mut status, input, io::LineWriter::new(output)).unwrap();
        status
    });
    caller
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    let mut greeting = [0; 5];
    let read = caller.read_exact(&mut greeting);
    seen.send(()).unwrap();
    drop(held_open);
    server.join().unwrap();
    assert_eq!(helper.join().unwrap(), b"connected\n");
    read.expect("the greeting reached the caller while the connection was open");
    assert_eq!(&greeting, b"hello");
}

#[test]
fn the_helper_reports_a_refusal_as_its_code_only() {
    use std::os::unix::fs::MetadataExt as _;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("platform.sock");
    let _listener = StdUnixListener::bind(&path).unwrap();
    let metadata = std::fs::metadata(&path).unwrap();
    for (arguments, code) in [
        (
            vec![
                path.to_string_lossy().into_owned(),
                format!("{}:{}", metadata.dev(), metadata.ino()),
            ],
            "platform-socket 0\n",
        ),
        (
            vec![
                directory
                    .path()
                    .join("missing.sock")
                    .to_string_lossy()
                    .into_owned(),
            ],
            "not-found\n",
        ),
        (vec!["relative.sock".to_owned()], "failed\n"),
        (
            vec![
                path.to_string_lossy().into_owned(),
                "not-an-identity".to_owned(),
            ],
            "failed\n",
        ),
        (Vec::new(), "failed\n"),
    ] {
        let (mut status, mut output) = (Vec::new(), Vec::new());
        relay(&arguments, &mut status, &b""[..], &mut output).unwrap();
        assert_eq!(String::from_utf8(status).unwrap(), code, "{arguments:?}");
        assert!(output.is_empty());
    }
}

#[test]
fn a_platform_socket_is_refused_even_in_the_one_exempt_directory() {
    // The Docker directory passes the directory check, but a socket there
    // whose identity is a platform socket's is still refused as one.
    let docker = Path::new("/run/codewire-docker/docker.sock");
    assert_eq!(admit(Some(0), docker), Err(Refusal::PlatformSocket(0)));
    assert_eq!(admit(None, docker), Ok(()));
    assert_eq!(
        admit(None, Path::new("/run/codewire-host/poweroff.sock")),
        Err(Refusal::PlatformDirectory(2))
    );
    assert_eq!(
        admit(None, Path::new("/run/codewire-docker-data/x.sock")),
        Err(Refusal::PlatformDirectory(2))
    );
}
