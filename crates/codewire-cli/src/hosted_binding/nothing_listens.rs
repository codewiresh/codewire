//! Nothing listens before an accepted binding (#3626).
//!
//! SSH on 2222 has `none` auth, and the warm-pool NetworkPolicy admits
//! orchestration's identity to unbound members on TCP 7777 and 2222 from
//! birth. So an unbound daemon must hold no listening socket at all.
//!
//! Each test runs the real binding-mode daemon in a child process: this test
//! binary again, running only [`unbound_daemon_process`]. The fake binding
//! listener stays in the parent, so every socket the child owns is the
//! daemon's. The parent joins the child's socket inodes (`/proc/<pid>/fd`)
//! with its network tables (`/proc/<pid>/net/*`). Loopback probes would
//! depend on what else the host runs.

use std::collections::HashSet;
use std::process::{Child, Command, Stdio};

use super::*;
use codewire_daemon::hosted_state::HostedStatePaths;

const CHILD_ROOT_ENV: &str = "CODEWIRE_TEST_UNBOUND_DAEMON_ROOT";
const CHILD_URL_ENV: &str = "CODEWIRE_TEST_UNBOUND_DAEMON_URL";
const CHILD_ROOTS_ENV: &str = "CODEWIRE_TEST_UNBOUND_DAEMON_ROOTS";
const CHILD_TEST: &str = "hosted_binding::tests::nothing_listens::unbound_daemon_process";

/// The ports the bound daemon serves: its gRPC, SSH, the tailnet's UDP and
/// the bridge's loopback.
const BOUND_PORTS: [u16; 4] = [7777, 2222, 31000, 38081];

/// How long the parent waits, from spawn, for the daemon to be ready and to
/// make its attempts before it calls the daemon hung: a hang guard, not a
/// speed expectation (`docs/dev/AGENT-WORKFLOW.md` "Failure convergence").
/// The child is this test binary started again, and on a loaded workstation
/// it made three attempts in the former 20 s (#4385).
const SETTLE_HANG: Duration = Duration::from_secs(120);

/// Fast pacing, so the parent sees many attempts within a second. A hung
/// call times out after the margin.
fn child_timing() -> BindTiming {
    BindTiming {
        wait_seconds: 0,
        deadline_margin: Duration::from_millis(300),
        initial_backoff: Duration::from_millis(40),
        max_backoff: Duration::from_millis(80),
        minimum_attempt: Duration::from_millis(40),
    }
}

/// The daemon side. It does nothing unless a parent test started it.
#[test]
fn unbound_daemon_process() {
    let Some(root) = std::env::var_os(CHILD_ROOT_ENV) else {
        return;
    };
    let root = PathBuf::from(root);
    let values = [
        (
            WORKSPACE_BINDING_URL_ENV,
            std::env::var(CHILD_URL_ENV).unwrap(),
        ),
        (WORKSPACE_POD_UID_ENV, POD.to_owned()),
    ];
    let HostedDaemonMode::Binding(config) = HostedDaemonMode::from_lookup(|name| {
        values
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| OsString::from(value))
    })
    .unwrap() else {
        panic!("binding mode expected");
    };
    let config = config
        .with_token_path(root.join("token"))
        .with_tls_roots_file(std::env::var_os(CHILD_ROOTS_ENV).unwrap());
    let outcome = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(crate::run_bound_hosted_daemon_with(
            config,
            HostedStatePaths::under(&root),
            child_timing(),
        ));
    // Unbound, the daemon never returns. The parent sees this exit.
    eprintln!("unbound daemon returned: {outcome:?}");
    std::process::exit(1);
}

/// One socket a process holds that accepts traffic from any peer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Listening {
    table: &'static str,
    port: u16,
    inode: u64,
}

/// The socket inodes `pid` holds open.
fn socket_inodes(pid: u32) -> HashSet<u64> {
    let mut inodes = HashSet::new();
    for entry in std::fs::read_dir(format!("/proc/{pid}/fd")).unwrap() {
        // A descriptor may close between the listing and the read.
        let Ok(target) = std::fs::read_link(entry.unwrap().path()) else {
            continue;
        };
        if let Some(inode) = target
            .to_str()
            .and_then(|target| target.strip_prefix("socket:["))
            .and_then(|target| target.strip_suffix(']'))
            .and_then(|inode| inode.parse().ok())
        {
            inodes.insert(inode);
        }
    }
    inodes
}

/// `pid`'s own listening sockets: TCP in `LISTEN`, unconnected UDP (which
/// takes datagrams from anyone) and listening Unix sockets. Only sockets in
/// `pid`'s descriptor table count, not others in its network namespace.
fn listening_sockets(pid: u32) -> Vec<Listening> {
    // TCP_LISTEN, and TCP_ESTABLISHED, which a connected UDP socket shows.
    const LISTEN: u8 = 0x0A;
    const CONNECTED: u8 = 0x01;
    // __SO_ACCEPTCON in /proc/net/unix's flags.
    const UNIX_ACCEPTING: u32 = 0x0001_0000;
    let tables: Vec<_> = ["tcp", "tcp6", "udp", "udp6", "unix"]
        .into_iter()
        .map(|table| {
            let path = format!("/proc/{pid}/net/{table}");
            (table, std::fs::read_to_string(&path).unwrap())
        })
        .collect();
    let owned = socket_inodes(pid);
    let mut listening = Vec::new();
    for (table, contents) in tables {
        for line in contents.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let (inode, port, open) = if table == "unix" {
                // Num RefCount Protocol Flags Type St Inode [Path]
                let flags = u32::from_str_radix(fields[3], 16).unwrap();
                (fields[6], 0, flags & UNIX_ACCEPTING != 0)
            } else {
                // sl local_address rem_address st ... uid timeout inode
                let port = fields[1].rsplit_once(':').unwrap().1;
                let port = u16::from_str_radix(port, 16).unwrap();
                let state = u8::from_str_radix(fields[3], 16).unwrap();
                let open = if table.starts_with("tcp") {
                    state == LISTEN
                } else {
                    state != CONNECTED
                };
                (fields[9], port, open)
            };
            let inode: u64 = inode.parse().unwrap();
            if open && owned.contains(&inode) {
                listening.push(Listening { table, port, inode });
            }
        }
    }
    listening
}

/// Kills the daemon child however the test ends.
struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Daemon {
    fn assert_waiting(&mut self, attempts: usize) {
        if let Some(status) = self.0.try_wait().unwrap() {
            panic!("unbound daemon exited ({status}) after {attempts} binding attempts");
        }
    }
}

/// Run the daemon against a listener that answers `then` in turn and never
/// with an accepted binding. From spawn until the daemon has been waiting
/// past its readiness marker for three more attempts, half a second and ten
/// samples, it must hold no listening socket.
async fn assert_nothing_listens_while_unbound(then: Vec<Answer>) {
    let (recorded, pki, url) = scripted_listener(Vec::new(), then).await;
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("token"), SYNTHETIC_PROJECTED_TOKEN).unwrap();
    let paths = HostedStatePaths::under(root.path());
    let mut daemon = Daemon(
        Command::new(std::env::current_exe().unwrap())
            .args([CHILD_TEST, "--exact", "--nocapture", "--test-threads=1"])
            .env(CHILD_ROOT_ENV, root.path())
            .env(CHILD_URL_ENV, &url)
            .env(CHILD_ROOTS_ENV, &pki.roots)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let pid = daemon.0.id();
    let started = tokio::time::Instant::now();
    // (attempts, when, samples) once the daemon was ready and calling.
    let mut waiting: Option<(usize, tokio::time::Instant, u32)> = None;
    // Unconnected UDP seen in the last sample. A UDP socket counts once it
    // lasts two samples: a resolver's address-sorting probe is unconnected
    // for an instant between its autobind and its connect.
    let mut udp_seen = HashSet::new();
    let mut samples = 0_u32;
    loop {
        let attempts = recorded.lock().unwrap().at.len();
        daemon.assert_waiting(attempts);
        let mut udp_now = HashSet::new();
        for socket in listening_sockets(pid) {
            let lasting = udp_seen.contains(&socket) || BOUND_PORTS.contains(&socket.port);
            if socket.table.starts_with("udp") && !lasting {
                udp_now.insert(socket);
                continue;
            }
            panic!(
                "unbound daemon holds {socket:?} after {attempts} binding attempts \
                 (bound ports {BOUND_PORTS:?})"
            );
        }
        udp_seen = udp_now;
        samples += 1;
        let ready = paths.ready_file.exists();
        match waiting {
            None if ready && attempts >= 1 => {
                waiting = Some((attempts, tokio::time::Instant::now(), samples));
            }
            Some((first, since, first_sample))
                if attempts >= first + 3
                    && since.elapsed() >= Duration::from_millis(500)
                    && samples >= first_sample + 10 =>
            {
                break;
            }
            _ => {}
        }
        assert!(
            started.elapsed() < SETTLE_HANG,
            "daemon never settled into waiting: ready {ready}, {attempts} attempts, \
             {samples} samples"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let attempts = recorded.lock().unwrap().at.len();
    daemon.assert_waiting(attempts);
    // It never installed a credential either.
    assert!(!paths.credential_file.exists());
    assert!(
        recorded
            .lock()
            .unwrap()
            .authorizations
            .iter()
            .all(|value| value == &format!("Bearer {SYNTHETIC_PROJECTED_TOKEN}"))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn nothing_listens_while_the_listener_answers_not_yet() {
    assert_nothing_listens_while_unbound(vec![Answer::Error(ErrorCode::NotFound)]).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn nothing_listens_while_the_listener_never_answers() {
    assert_nothing_listens_while_unbound(vec![Answer::Hang]).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn nothing_listens_after_invalid_binding_responses() {
    assert_nothing_listens_while_unbound(vec![
        Answer::BoundFor(OTHER_POD),
        Answer::Malformed,
        Answer::BoundWithExpiredAccess,
    ])
    .await;
}

/// The inspection is not vacuous: it finds a process's own TCP listener,
/// unconnected UDP socket and Unix listener, and skips a connected UDP
/// socket and a TCP connection.
#[test]
fn the_socket_inspection_finds_each_kind_of_listener() {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt as _;

    let inode = |socket: &dyn AsRawFd| {
        std::fs::metadata(format!("/proc/self/fd/{}", socket.as_raw_fd()))
            .unwrap()
            .ino()
    };
    let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let client = std::net::TcpStream::connect(tcp.local_addr().unwrap()).unwrap();
    let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let connected = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    connected.connect(udp.local_addr().unwrap()).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let unix = std::os::unix::net::UnixListener::bind(directory.path().join("socket")).unwrap();
    let listening = listening_sockets(std::process::id());
    let found = |inode: u64| listening.iter().find(|socket| socket.inode == inode);
    let tcp_found = found(inode(&tcp)).expect("TCP listener");
    assert_eq!(
        (tcp_found.table, tcp_found.port),
        ("tcp", tcp.local_addr().unwrap().port())
    );
    let udp_found = found(inode(&udp)).expect("unconnected UDP socket");
    assert_eq!(
        (udp_found.table, udp_found.port),
        ("udp", udp.local_addr().unwrap().port())
    );
    assert_eq!(found(inode(&unix)).expect("Unix listener").table, "unix");
    assert!(found(inode(&connected)).is_none(), "{listening:?}");
    assert!(found(inode(&client)).is_none(), "{listening:?}");
}
