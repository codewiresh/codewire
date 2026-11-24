use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::AsyncReadExt as _;
use tokio::net::UnixStream;

use super::*;

/// A writer that never accepts a byte, as a stalled Pod log would.
struct Stalled;

impl AsyncWrite for Stalled {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Poll::Pending
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }
}

fn text(line: &str) -> &str {
    line.strip_prefix(PREFIX)
        .and_then(|rest| rest.strip_suffix('\n'))
        .unwrap()
}

#[test]
fn every_byte_that_could_end_or_fake_a_line_is_escaped() {
    let raw = b"a\\b\nc\rd\te\x1b[31mf\x7fg\xc2\x85h\xe2\x80\xa8i\xff\x00j";
    let line = escape_line(raw);
    assert_eq!(
        text(&line),
        "a\\\\b\\nc\\rd\\te\\u{001b}[31mf\\u{007f}g\\u{0085}h\\u{2028}i\u{fffd}\\u{0000}j"
    );
    // Exactly one newline, at the end, and nothing else that ends a line.
    assert_eq!(line.matches('\n').count(), 1);
    assert!(line.ends_with('\n'));
    assert!(!line.contains('\r') && !line.contains('\u{2028}') && !line.contains('\u{85}'));
}

#[test]
fn an_escaped_backslash_cannot_be_read_as_an_escape() {
    // The guest printing the text of an escape is told apart from the escape.
    assert_eq!(text(&escape_line(b"\\n")), "\\\\n");
    assert_eq!(text(&escape_line(b"\n")), "\\n");
}

#[test]
fn a_long_line_is_cut_and_marked_and_a_full_one_is_not() {
    let full = vec![b'a'; HOSTED_LOG_MAX_LINE];
    assert_eq!(text(&escape_line(&full)).len(), HOSTED_LOG_MAX_LINE);
    let long = vec![b'a'; HOSTED_LOG_MAX_LINE + 1];
    let cut = escape_line(&long);
    assert_eq!(
        text(&cut),
        format!("{}{TRUNCATED}", "a".repeat(HOSTED_LOG_MAX_LINE))
    );
    // Escapes count toward the limit, and none is cut in half.
    let slashes = vec![b'\\'; HOSTED_LOG_MAX_LINE];
    let cut = escape_line(&slashes);
    let body = text(&cut).strip_suffix(TRUNCATED).unwrap();
    assert_eq!(body, "\\\\".repeat(HOSTED_LOG_MAX_LINE / 2));
}

#[test]
fn the_gate_caps_lines_and_bytes_a_second_and_counts_what_it_drops() {
    let start = Instant::now();
    let mut gate = Gate::new(start);
    for _ in 0..MAX_LINES_PER_SECOND {
        assert!(gate.admit(start, 10));
    }
    assert!(!gate.admit(start, 10));
    gate.dropped(7);
    assert_eq!(gate.take_dropped(), Some((1, 7)));
    assert_eq!(gate.take_dropped(), None);
    // A new second, a new budget; bytes run out before lines do.
    let next = start + WINDOW;
    assert!(gate.admit(next, MAX_BYTES_PER_SECOND - 1));
    assert!(!gate.admit(next, 2));
    assert!(gate.admit(next, 1));
}

#[test]
fn the_host_end_is_the_vsock_socket_with_the_port_appended() {
    assert_eq!(
        host_socket(Path::new("/run/vm/vsock.sock"), 7_783),
        PathBuf::from("/run/vm/vsock.sock_7783")
    );
}

async fn listening() -> (tempfile::TempDir, PathBuf, UnixListener) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("log.sock");
    let listener = UnixListener::bind(&path).unwrap();
    (directory, path, listener)
}

#[tokio::test]
async fn lines_reach_the_log_escaped_and_the_host_never_writes_back() {
    let (_directory, path, listener) = listening().await;
    let (out, mut log) = tokio::io::duplex(64 * 1024);
    tokio::spawn(serve(listener, out));
    let mut guest = UnixStream::connect(&path).await.unwrap();
    guest.write_all(b"started\nfake\rline\n").await.unwrap();
    let mut seen = String::new();
    let mut buffer = [0_u8; 1024];
    while seen.matches('\n').count() < 2 {
        let read = tokio::time::timeout(Duration::from_secs(5), log.read(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        seen.push_str(std::str::from_utf8(&buffer[..read]).unwrap());
    }
    assert_eq!(seen, format!("{PREFIX}started\n{PREFIX}fake\\rline\n"));
    // Nothing ever comes back on the guest's connection.
    let back = tokio::time::timeout(Duration::from_millis(200), guest.read(&mut buffer)).await;
    assert!(back.is_err(), "the host wrote to the guest: {back:?}");
}

#[tokio::test]
async fn a_stalled_log_drops_lines_and_never_slows_the_guest() {
    let (_directory, path, listener) = listening().await;
    tokio::spawn(serve(listener, Stalled));
    let mut guest = UnixStream::connect(&path).await.unwrap();
    let lines = "x".repeat(99) + "\n";
    let many = lines.repeat(20_000);
    // Two megabytes, far more than any buffer between here and the log.
    tokio::time::timeout(Duration::from_secs(10), guest.write_all(many.as_bytes()))
        .await
        .expect("the guest's writes were held up")
        .unwrap();
}

#[tokio::test]
async fn lines_over_the_budget_are_dropped_and_counted_once_a_second() {
    let (_directory, path, listener) = listening().await;
    let (out, mut log) = tokio::io::duplex(1024 * 1024);
    tokio::spawn(serve(listener, out));
    let mut guest = UnixStream::connect(&path).await.unwrap();
    let over = MAX_LINES_PER_SECOND + 50;
    guest
        .write_all("x\n".repeat(usize::try_from(over).unwrap()).as_bytes())
        .await
        .unwrap();
    // The summary comes from a once-a-second tick, so it can arrive before
    // the last queued lines and, on a busy host, in more than one part: read
    // until every line is accounted for.
    let (mut written, mut dropped_lines, mut dropped_bytes) = (0_u64, 0_u64, 0_u64);
    let mut pending = String::new();
    let mut buffer = [0_u8; 4096];
    while written + dropped_lines < over {
        let read = tokio::time::timeout(Duration::from_secs(5), log.read(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        pending.push_str(std::str::from_utf8(&buffer[..read]).unwrap());
        while let Some(end) = pending.find('\n') {
            let line: String = pending.drain(..=end).collect();
            let line = line.trim_end_matches('\n');
            if line == format!("{PREFIX}x") {
                written += 1;
            } else if let Some(counts) = line.strip_prefix(&format!("{PREFIX}dropped ")) {
                let (lines, bytes) = counts.split_once(" lines, ").unwrap();
                dropped_lines += lines.parse::<u64>().unwrap();
                dropped_bytes += bytes
                    .strip_suffix(" bytes")
                    .unwrap()
                    .parse::<u64>()
                    .unwrap();
            } else {
                panic!("unexpected log line: {line:?}");
            }
        }
    }
    assert_eq!(written, MAX_LINES_PER_SECOND);
    assert_eq!((dropped_lines, dropped_bytes), (50, 50));
}

#[tokio::test]
async fn a_second_connection_is_closed_unread() {
    let (_directory, path, listener) = listening().await;
    let (out, _log) = tokio::io::duplex(1024);
    tokio::spawn(serve(listener, out));
    let _first = UnixStream::connect(&path).await.unwrap();
    // Let the first connection be accepted before the second.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut second = UnixStream::connect(&path).await.unwrap();
    let mut buffer = [0_u8; 16];
    let read = tokio::time::timeout(Duration::from_secs(5), second.read(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(read, 0);
}

#[tokio::test]
async fn forwarding_replaces_a_stale_socket_and_binds_the_host_end() {
    let directory = tempfile::tempdir().unwrap();
    let vsock = directory.path().join("vsock.sock");
    let stale = host_socket(&vsock, HOSTED_LOG_VSOCK_PORT);
    std::fs::write(&stale, b"").unwrap();
    let task = forward(&vsock).unwrap();
    UnixStream::connect(&stale).await.unwrap();
    task.abort();
}
