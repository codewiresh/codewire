//! The forward against stand-ins: a listener for the desktop's end of the
//! path, and a process that lives until told to go for OpenSSH.

use super::*;
use tokio::io::AsyncWriteExt as _;

/// A loopback listener that sends `first` to every connection.
async fn answering(first: &'static [u8]) -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind a loopback port");
    let port = listener.local_addr().expect("the bound address").port();
    let serving = tokio::spawn(async move {
        while let Ok((mut connection, _)) = listener.accept().await {
            connection.write_all(first).await.ok();
        }
    });
    (port, serving)
}

/// A stand-in for OpenSSH: its own process group, and it lives until ended.
fn standing_in(port: u16) -> Forward {
    let mut command = crate::process::tokio_command("sleep", &[]);
    command.arg("600");
    Forward::start(command, port).expect("start the stand-in")
}

fn is_alive(pid: u32) -> bool {
    let pid = rustix::process::Pid::from_raw(i32::try_from(pid).expect("a process ID"))
        .expect("a process ID above zero");
    rustix::process::test_kill_process(pid).is_ok()
}

#[test]
fn openssh_is_given_one_loopback_forward_and_no_session() {
    assert_eq!(
        ssh_arguments("cw-cloud-0b6c", 49_152),
        [
            "-N",
            "-o",
            "ExitOnForwardFailure=yes",
            "-L",
            "127.0.0.1:49152:127.0.0.1:5901",
            "cw-cloud-0b6c"
        ]
    );
}

#[tokio::test]
async fn a_free_port_can_be_bound_again_at_once() {
    let port = free_loopback_port().await.expect("a free port");
    TcpListener::bind((Ipv4Addr::LOCALHOST, port))
        .await
        .expect("the port is free for the forward");
}

#[tokio::test]
async fn the_forward_is_ready_once_a_vnc_server_greets_through_it() {
    let (port, serving) = answering(b"RFB 003.008\n").await;
    let mut forward = standing_in(port);
    forward
        .ready_within(Duration::from_secs(10))
        .await
        .expect("greeted by the desktop");
    forward.close().await;
    serving.abort();
}

#[tokio::test]
async fn another_service_on_the_port_is_not_taken_for_the_desktop() {
    let (port, serving) = answering(b"HTTP/1.1 400 Bad Request\r\n").await;
    let mut forward = standing_in(port);
    let refused = forward.ready_within(Duration::from_secs(10)).await;
    assert!(
        matches!(refused, Err(ForwardError::NotADesktop)),
        "{refused:?}"
    );
    forward.close().await;
    serving.abort();
}

#[tokio::test]
async fn a_path_that_never_greets_is_not_ready_within_its_bound() {
    // Accepted and closed without a byte, as OpenSSH does while the channel
    // cannot be opened.
    let (port, serving) = answering(b"").await;
    let mut forward = standing_in(port);
    let refused = forward.ready_within(Duration::from_millis(600)).await;
    assert!(
        matches!(refused, Err(ForwardError::NotReady)),
        "{refused:?}"
    );
    forward.close().await;
    serving.abort();
}

#[tokio::test]
async fn openssh_ending_first_is_told_apart_from_a_slow_desktop() {
    let port = free_loopback_port().await.expect("a free port");
    let mut forward =
        Forward::start(crate::process::tokio_command("true", &[]), port).expect("start");
    forward.ssh.wait().await.expect("it ends by itself");
    let refused = forward.ready_within(Duration::from_secs(10)).await;
    assert!(matches!(refused, Err(ForwardError::Ended)), "{refused:?}");
    forward.close().await;
}

#[tokio::test]
async fn no_ssh_on_the_computer_is_its_own_refusal() {
    let refused = Forward::start(
        crate::process::tokio_command("/nonexistent/cw-desktop-test/ssh", &[]),
        1,
    );
    assert!(matches!(refused, Err(ForwardError::NoSsh)));
}

#[tokio::test]
async fn closing_ends_the_process_and_leaves_nothing_behind() {
    let port = free_loopback_port().await.expect("a free port");
    let forward = standing_in(port);
    let pid = forward.ssh.id().expect("a running process");
    assert!(is_alive(pid));
    forward.close().await;
    assert!(!is_alive(pid), "the forward's process outlived its close");
}

#[tokio::test]
async fn a_process_that_ignores_the_request_is_killed() {
    let port = free_loopback_port().await.expect("a free port");
    let mut command = crate::process::tokio_command("sh", &[]);
    command.args(["-c", "trap '' TERM; sleep 600"]);
    let forward = Forward::start(command, port).expect("start");
    let pid = forward.ssh.id().expect("a running process");
    // Until the shell has set its trap, the request would end it.
    tokio::time::sleep(Duration::from_millis(300)).await;
    forward.close().await;
    assert!(!is_alive(pid), "the forward's process outlived its close");
}
