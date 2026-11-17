//! The keys beside a device sign-in's wait (#4850): at an interactive
//! terminal, `c` copies the sign-in link, Ctrl-C cancels, and a second Ctrl-C
//! exits at once (130). Under the screen, the approved waiting line counts
//! the time. The terminal is in raw mode only while the watch lasts, and
//! nothing else prints then.

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::Notify;

/// Watches the keys while a sign-in waits. Dropping it stops the watch and
/// gives the terminal back before anything else prints. A Ctrl-C, as a key
/// or as the interrupt signal, is remembered from `new` on, so a flow can
/// ask [`KeyWatch::was_cancelled`] right before it saves anything.
pub(in crate::commands) struct KeyWatch {
    stop: Arc<AtomicBool>,
    cancel: Arc<Cancel>,
    thread: Mutex<Option<std::thread::JoinHandle<()>>>,
    signal: Option<tokio::task::JoinHandle<()>>,
}

/// Whether Ctrl-C came, and a wake-up for whoever waits on it.
#[derive(Default)]
struct Cancel {
    set: AtomicBool,
    notify: Notify,
}

impl Cancel {
    fn cancel(&self) {
        self.set.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }
}

/// The second Ctrl-C ends `cw` at once, as a shell's would (#4991).
fn exit_on_second_press() -> ! {
    std::process::exit(130)
}

impl KeyWatch {
    pub(in crate::commands) fn new() -> Self {
        let cancel = Arc::new(Cancel::default());
        // The interrupt signal outside raw mode; raw mode turns Ctrl-C into
        // a key the reader sees instead.
        let signal = tokio::runtime::Handle::try_current().ok().map(|runtime| {
            let cancel = cancel.clone();
            runtime.spawn(async move {
                while tokio::signal::ctrl_c().await.is_ok() {
                    if cancel.set.load(Ordering::SeqCst) {
                        exit_on_second_press();
                    }
                    cancel.cancel();
                }
            })
        });
        Self {
            stop: Arc::new(AtomicBool::new(false)),
            cancel,
            thread: Mutex::new(None),
            signal,
        }
    }

    /// Whether Ctrl-C came at any time since `new`.
    pub(in crate::commands) fn was_cancelled(&self) -> bool {
        self.cancel.set.load(Ordering::SeqCst)
    }

    /// Start reading keys for `url`, only at an interactive terminal. A
    /// second call keeps the first watch.
    pub(in crate::commands) fn watch(&self, url: &str) {
        if !super::screen_caps().keys {
            return;
        }
        let Ok(mut thread) = self.thread.lock() else {
            return;
        };
        if thread.is_some() {
            return;
        }
        let (stop, cancel, url) = (self.stop.clone(), self.cancel.clone(), url.to_owned());
        // The blank line above the waiting line, before raw mode.
        eprintln!();
        *thread = Some(std::thread::spawn(move || {
            read_keys(&url, &stop, &cancel);
        }));
    }

    /// Stop reading keys and give the terminal back; the signal listener and
    /// what it heard stay.
    pub(in crate::commands) fn stop_keys(&self) {
        self.stop.store(true, Ordering::Relaxed);
        let thread = self.thread.lock().ok().and_then(|mut thread| thread.take());
        if let Some(thread) = thread {
            // A key thread that panicked has no terminal state left to give back.
            let _ = thread.join();
        }
    }

    /// Resolves on Ctrl-C, at once when one already came: the key while the
    /// watch runs, which raw mode turns into a byte, or the interrupt signal
    /// otherwise.
    pub(in crate::commands) async fn cancelled(&self) {
        loop {
            let woken = self.cancel.notify.notified();
            tokio::pin!(woken);
            // Registered before the flag is read, so a press between the two
            // still wakes this wait.
            woken.as_mut().enable();
            if self.was_cancelled() {
                return;
            }
            woken.await;
        }
    }
}

impl Drop for KeyWatch {
    fn drop(&mut self) {
        if let Some(signal) = self.signal.take() {
            signal.abort();
        }
        self.stop_keys();
    }
}

/// What a key does during the wait.
#[derive(Debug, PartialEq, Eq)]
enum Action {
    Copy,
    Cancel,
}

fn action(key: crate::output::Key) -> Option<Action> {
    use crate::output::Key;
    match key {
        Key::Char('c' | 'C') => Some(Action::Copy),
        Key::CtrlC => Some(Action::Cancel),
        _ => None,
    }
}

/// The waiting line, screen 3: a turning circle, the time waited, and how to
/// cancel. Raw mode: it is redrawn in place with a carriage return.
fn waiting_line(waited: std::time::Duration, frame: usize, ascii: bool) -> String {
    const UNICODE: [&str; 4] = ["◐", "◓", "◑", "◒"];
    const ASCII: [&str; 4] = ["|", "/", "-", "\\"];
    let glyph = if ascii { ASCII } else { UNICODE }[frame % 4];
    let ellipsis = if ascii { "..." } else { "…" };
    let seconds = waited.as_secs();
    format!(
        "\r{}{glyph} Waiting for you to approve in the browser{ellipsis} {}:{:02} · Ctrl-C to cancel\x1b[K",
        super::INDENT,
        seconds / 60,
        seconds % 60
    )
}

#[cfg(unix)]
fn read_keys(url: &str, stop: &AtomicBool, cancel: &Cancel) {
    use std::io::Write as _;
    use std::os::fd::AsRawFd as _;
    let Ok(raw) = crate::terminal_attach::RawModeGuard::enable() else {
        return;
    };
    let ascii = crate::output::Capabilities::from_process(crate::output::OutputMode::Text).charset
        == crate::output::Charset::Ascii;
    let started = std::time::Instant::now();
    let mut drawn: Option<std::time::Instant> = None;
    let mut frame = 0;
    let fd = std::io::stdin().as_raw_fd();
    let mut buffer = [0u8; 64];
    while !stop.load(Ordering::Relaxed) {
        if drawn.is_none_or(|at| at.elapsed() >= std::time::Duration::from_secs(1)) {
            eprint!("{}", waiting_line(started.elapsed(), frame, ascii));
            // Nothing can report a failed write to stderr; the screen just goes without it.
            let _ = std::io::stderr().flush();
            frame += 1;
            drawn = Some(std::time::Instant::now());
        }
        if !readable(fd, 100) {
            continue;
        }
        // SAFETY: `buffer` is a live, writable buffer of the given length.
        let read = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
        let Ok(read) = usize::try_from(read) else {
            continue;
        };
        if read == 0 {
            break;
        }
        for key in crate::output::decode_keys(&buffer[..read]) {
            match action(key) {
                Some(Action::Copy) => {
                    // Raw mode: a line ends with a carriage return too.
                    eprint!("\r\x1b[2K{}\r\n", super::copy_link(url));
                    drawn = None;
                }
                Some(Action::Cancel) if cancel.set.load(Ordering::SeqCst) => {
                    // The terminal is given back, cursor shown, before exit
                    // skips every destructor.
                    eprint!("\r\x1b[2K\x1b[?25h");
                    drop(raw);
                    exit_on_second_press();
                }
                Some(Action::Cancel) => cancel.cancel(),
                None => {}
            }
        }
    }
    eprint!("\r\x1b[2K");
    // Nothing can report a failed write to stderr; the screen just goes without it.
    let _ = std::io::stderr().flush();
}

#[cfg(not(unix))]
fn read_keys(_: &str, _: &AtomicBool, _: &Cancel) {}

/// Whether `fd` has input within `timeout_ms`.
#[cfg(unix)]
pub(in crate::commands) fn readable(fd: std::os::fd::RawFd, timeout_ms: i32) -> bool {
    let mut poll = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: `poll` is one live pollfd.
    let ready = unsafe { libc::poll(&mut poll, 1, timeout_ms) };
    ready > 0 && poll.revents & libc::POLLIN != 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::{Key, decode_keys};

    #[test]
    fn c_copies_ctrl_c_cancels_and_other_keys_do_nothing() {
        let actions: Vec<_> = decode_keys(b"xc\x03")
            .into_iter()
            .filter_map(action)
            .collect();
        assert_eq!(actions, [Action::Copy, Action::Cancel]);
        assert_eq!(action(Key::Enter), None);
        assert_eq!(action(Key::Char('v')), None);
    }

    /// A Ctrl-C is remembered: `cancelled` returns at once after it, and a
    /// flow can ask before it saves anything.
    #[tokio::test]
    async fn a_ctrl_c_is_remembered_after_it_came() {
        let watch = KeyWatch::new();
        assert!(!watch.was_cancelled());
        watch.cancel.cancel();
        assert!(watch.was_cancelled());
        tokio::time::timeout(std::time::Duration::from_secs(30), watch.cancelled())
            .await
            .expect("cancelled returns at once once Ctrl-C came");
    }

    #[test]
    fn the_waiting_line_counts_minutes_and_seconds_and_says_how_to_cancel() {
        let line = waiting_line(std::time::Duration::from_secs(74), 0, false);
        assert_eq!(
            line,
            "\r  ◐ Waiting for you to approve in the browser… 1:14 · Ctrl-C to cancel\x1b[K"
        );
        let ascii = waiting_line(std::time::Duration::from_secs(5), 3, true);
        assert!(
            ascii.contains("\\ Waiting for you to approve in the browser... 0:05"),
            "{ascii}"
        );
    }

    #[tokio::test]
    async fn a_watch_off_a_terminal_reads_nothing_and_drops_cleanly() {
        // The test's stdin is not an interactive terminal.
        let watch = KeyWatch::new();
        watch.watch("https://example.test/a");
        assert!(watch.thread.lock().unwrap().is_none());
        drop(watch);
    }
}
