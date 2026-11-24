//! The hosted workload's output from a guest-carried boot (#5602,
//! cw-security's conditions on comment 134050), written to this container's
//! stdout as the Pod log, where a Kata Pod's daemon writes its own.
//!
//! The guest connects to [`HOSTED_LOG_VSOCK_PORT`] and only writes; this side
//! only reads, one connection at a time, and never writes back. Everything it
//! reads is untrusted guest text: each line is escaped so no guest byte can
//! end it or start another, cut to [`HOSTED_LOG_MAX_LINE`] bytes and marked
//! when cut, and prefixed [`PREFIX`] so it is never read as this runtime's
//! own lines, which go to stderr. At most [`MAX_LINES_PER_SECOND`] lines and
//! [`MAX_BYTES_PER_SECOND`] bytes a second are written, and what is dropped
//! is counted in one line a second. Writing never holds up reading: lines
//! that find the writer behind are dropped, so the guest is never slowed.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use codewire_vmm_guest_probe::hosted_control::{HOSTED_LOG_MAX_LINE, HOSTED_LOG_VSOCK_PORT};
use tokio::io::{AsyncBufReadExt as _, AsyncRead, AsyncWrite, AsyncWriteExt as _, BufReader};
use tokio::net::UnixListener;
use tokio::sync::mpsc;
use tokio::time::Instant;

/// What starts every forwarded line.
pub(super) const PREFIX: &str = "guest-daemon: ";
pub(super) const MAX_LINES_PER_SECOND: u64 = 200;
pub(super) const MAX_BYTES_PER_SECOND: u64 = 64 * 1024;
const TRUNCATED: &str = "…[truncated]";
/// Lines between reading and writing; more are dropped.
const QUEUED_LINES: usize = 256;
const WINDOW: Duration = Duration::from_secs(1);

/// The host end Cloud Hypervisor connects a guest's connection to host port
/// `port` to: the VM's hybrid vsock socket path with `_<port>` appended.
pub(super) fn host_socket(vsock_socket: &Path, port: u32) -> PathBuf {
    let mut path = vsock_socket.as_os_str().to_owned();
    path.push(format!("_{port}"));
    PathBuf::from(path)
}

/// Listens for the guest's output and writes it to stdout until the Pod
/// ends.
pub(super) fn forward(vsock_socket: &Path) -> std::io::Result<tokio::task::JoinHandle<()>> {
    let path = host_socket(vsock_socket, HOSTED_LOG_VSOCK_PORT);
    // A socket left by this Pod's last boot would refuse the bind.
    match std::fs::remove_file(&path) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error),
        _ => {}
    }
    let listener = UnixListener::bind(&path)?;
    Ok(tokio::spawn(serve(listener, tokio::io::stdout())))
}

/// Reads each connection in turn and writes what it accepts to `out`.
pub(super) async fn serve<W>(listener: UnixListener, out: W)
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    let gate = Arc::new(Mutex::new(Gate::new(Instant::now())));
    let (lines, queued) = mpsc::channel(QUEUED_LINES);
    tokio::spawn(write_lines(queued, out, Arc::clone(&gate)));
    let reading = Arc::new(tokio::sync::Semaphore::new(1));
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            // An accept error such as EMFILE would otherwise spin.
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        };
        // One connection at a time; another is closed unread.
        let Ok(permit) = Arc::clone(&reading).try_acquire_owned() else {
            continue;
        };
        let lines = lines.clone();
        let gate = Arc::clone(&gate);
        tokio::spawn(async move {
            let _permit = permit;
            read_lines(stream, &lines, &gate).await;
        });
    }
}

/// Reads whole lines until the guest closes, passing on those the gate
/// admits and the writer has room for.
async fn read_lines<R: AsyncRead + Unpin>(
    stream: R,
    lines: &mpsc::Sender<String>,
    gate: &Mutex<Gate>,
) {
    let mut reader = BufReader::new(stream);
    loop {
        let Ok(Some(raw)) = read_line(&mut reader).await else {
            return;
        };
        let line = escape_line(&raw);
        let raw_bytes = u64::try_from(raw.len()).unwrap_or(u64::MAX);
        let mut gate = gate.lock().unwrap_or_else(PoisonError::into_inner);
        if gate.admit(
            Instant::now(),
            u64::try_from(line.len()).unwrap_or(u64::MAX),
        ) {
            if lines.try_send(line).is_err() {
                gate.dropped(raw_bytes);
            }
        } else {
            gate.dropped(raw_bytes);
        }
    }
}

/// One line without its newline, at most one byte more than
/// [`HOSTED_LOG_MAX_LINE`] so a longer one can be marked; the rest of it is
/// read and dropped. `None` at the end.
async fn read_line<R: AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
) -> std::io::Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    let mut seen = false;
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Ok(seen.then_some(line));
        }
        seen = true;
        let (taken, ended) = match available.iter().position(|byte| *byte == b'\n') {
            Some(newline) => (newline + 1, true),
            None => (available.len(), false),
        };
        let room = (HOSTED_LOG_MAX_LINE + 1).saturating_sub(line.len());
        line.extend(
            available[..taken]
                .iter()
                .take(room)
                .filter(|byte| **byte != b'\n'),
        );
        reader.consume(taken);
        if ended {
            return Ok(Some(line));
        }
    }
}

/// `raw` as one safe line: [`PREFIX`], then the text with backslash, every
/// control character and the Unicode line and paragraph separators escaped,
/// and invalid UTF-8 replaced, cut to [`HOSTED_LOG_MAX_LINE`] bytes of text
/// with [`TRUNCATED`] after a cut, then a newline.
pub(super) fn escape_line(raw: &[u8]) -> String {
    let text = String::from_utf8_lossy(raw);
    let mut escaped = String::with_capacity(PREFIX.len() + raw.len().min(HOSTED_LOG_MAX_LINE) + 16);
    escaped.push_str(PREFIX);
    let mut truncated = raw.len() > HOSTED_LOG_MAX_LINE;
    for character in text.chars() {
        let unit = match character {
            '\\' => "\\\\".to_owned(),
            '\n' => "\\n".to_owned(),
            '\r' => "\\r".to_owned(),
            '\t' => "\\t".to_owned(),
            '\u{2028}' | '\u{2029}' => format!("\\u{{{:04x}}}", u32::from(character)),
            control if control.is_control() => format!("\\u{{{:04x}}}", u32::from(control)),
            other => other.to_string(),
        };
        if escaped.len() - PREFIX.len() + unit.len() > HOSTED_LOG_MAX_LINE {
            truncated = true;
            break;
        }
        escaped.push_str(&unit);
    }
    if truncated {
        escaped.push_str(TRUNCATED);
    }
    escaped.push('\n');
    escaped
}

/// Writes queued lines, and once a second a count of what was dropped.
async fn write_lines<W: AsyncWrite + Unpin>(
    mut queued: mpsc::Receiver<String>,
    mut out: W,
    gate: Arc<Mutex<Gate>>,
) {
    let mut tick = tokio::time::interval(WINDOW);
    loop {
        tokio::select! {
            line = queued.recv() => {
                let Some(line) = line else { return };
                if out.write_all(line.as_bytes()).await.is_err() {
                    return;
                }
            }
            _ = tick.tick() => {
                let summary = gate.lock().unwrap_or_else(PoisonError::into_inner).take_dropped();
                if let Some((lines, bytes)) = summary
                    && out
                        .write_all(format!("{PREFIX}dropped {lines} lines, {bytes} bytes\n").as_bytes())
                        .await
                        .is_err()
                {
                    return;
                }
            }
        }
        // The Pod log is line-buffered by its reader; flushing each write
        // keeps a line whole on its way there.
        if out.flush().await.is_err() {
            return;
        }
    }
}

/// The per-second budget of lines and bytes, and what it has dropped.
#[derive(Debug)]
pub(super) struct Gate {
    window_start: Instant,
    lines: u64,
    bytes: u64,
    dropped_lines: u64,
    dropped_bytes: u64,
}

impl Gate {
    pub(super) fn new(now: Instant) -> Self {
        Self {
            window_start: now,
            lines: 0,
            bytes: 0,
            dropped_lines: 0,
            dropped_bytes: 0,
        }
    }

    /// Whether a line of `bytes` written bytes fits this second's budget;
    /// counts it when it does.
    pub(super) fn admit(&mut self, now: Instant, bytes: u64) -> bool {
        if now.duration_since(self.window_start) >= WINDOW {
            self.window_start = now;
            self.lines = 0;
            self.bytes = 0;
        }
        if self.lines + 1 > MAX_LINES_PER_SECOND || self.bytes + bytes > MAX_BYTES_PER_SECOND {
            return false;
        }
        self.lines += 1;
        self.bytes += bytes;
        true
    }

    pub(super) fn dropped(&mut self, raw_bytes: u64) {
        self.dropped_lines += 1;
        self.dropped_bytes += raw_bytes;
    }

    /// What was dropped since the last call, if anything.
    pub(super) fn take_dropped(&mut self) -> Option<(u64, u64)> {
        let dropped = (self.dropped_lines, self.dropped_bytes);
        self.dropped_lines = 0;
        self.dropped_bytes = 0;
        (dropped.0 > 0).then_some(dropped)
    }
}

#[cfg(test)]
mod tests;
