//! The interactive widgets on a real pseudo-terminal.
//!
//! Each test starts this test binary again as a child on a new pseudo
//! terminal, running only [`interactive_child_process`], which opens the
//! requested widget on its real stdin and stderr. The parent waits for each
//! frame before it types, so every key arrives while the widget owns the
//! terminal in raw mode. The child compares `stty -g` before and after the
//! widget and prints the outcome.

use std::io::{Read as _, Write as _};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use portable_pty::{CommandBuilder, PtySize, native_pty_system};

use super::caps::{Capabilities, OutputMode};
use super::checklist::{Checklist, ChecklistItem, run_checklist};
use super::picker::{Picker, PickerRow, run_picker};

/// Names the widget the child opens: `picker` or `checklist`.
const CHILD_ENV: &str = "CW_OUTPUT_PTY_CHILD";
const CHILD_TEST: &str = "output::pty_tests::interactive_child_process";
const RESULT: &str = "WIDGET-RESULT ";
const DEADLINE: Duration = Duration::from_secs(60);
const PICKER_TITLE: &str = "Choose an environment";
const CHECKLIST_TITLE: &str = "Upgrade Codewire";

fn environments() -> Picker {
    let row = |cells: [&str; 3]| {
        PickerRow::new(
            cells.iter().map(|cell| (*cell).to_owned()).collect(),
            cells.join(" "),
        )
    };
    Picker::new(
        PICKER_TITLE,
        ["NAME", "LOCATION", "STATE"].map(str::to_owned).to_vec(),
        vec![
            row(["app", "local", "running"]),
            row(["review", "cloud", "stopped"]),
            row(["scratch", "local", "stopped"]),
        ],
    )
}

fn upgrade() -> Checklist {
    Checklist::new(
        CHECKLIST_TITLE,
        vec![
            ChecklistItem::new("Codewire CLI v0.3.391 → v0.4.0", true),
            ChecklistItem::new("Restart 2 local VMs onto v0.4.0", false)
                .with_detail("ends the work running in them"),
        ],
    )
}

fn stty_state() -> String {
    let output = Command::new("stty")
        .arg("-g")
        .stdin(Stdio::inherit())
        .output()
        .expect("run stty -g");
    assert!(output.status.success(), "stty -g failed");
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

/// The child half. A no-op unless started by a test below.
#[test]
fn interactive_child_process() {
    let Some(widget) = std::env::var_os(CHILD_ENV) else {
        return;
    };
    let before = stty_state();
    let caps = Capabilities::from_process(OutputMode::Text);
    let outcome = match widget.to_str() {
        Some("picker") => format!("{:?}", run_picker(environments(), &caps)),
        Some("checklist") => format!("{:?}", run_checklist(upgrade(), &caps)),
        other => panic!("unknown widget {other:?}"),
    };
    let after = stty_state();
    println!("{RESULT}{outcome} restored={}", before == after);
}

struct Session {
    title: &'static str,
    output: Arc<Mutex<Vec<u8>>>,
    writer: Box<dyn std::io::Write + Send>,
    child: Box<dyn portable_pty::Child + Send + Sync>,
    _master: Box<dyn portable_pty::MasterPty + Send>,
}

impl Session {
    fn start(widget: &str, title: &'static str) -> Self {
        let pty = native_pty_system()
            .openpty(PtySize {
                rows: 24,
                cols: 100,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("open a pseudo-terminal");
        let mut command = CommandBuilder::new(std::env::current_exe().unwrap());
        command.args([
            "--exact",
            CHILD_TEST,
            "--nocapture",
            "--test-threads=1",
            "--quiet",
        ]);
        command.cwd(std::env::current_dir().unwrap());
        command.env(CHILD_ENV, widget);
        command.env("TERM", "xterm-256color");
        command.env("NO_COLOR", "1");
        command.env("LC_ALL", "C.UTF-8");
        command.env_remove("CODEWIRE_REDUCED_MOTION");
        let child = pty.slave.spawn_command(command).expect("start the child");
        drop(pty.slave);
        let mut reader = pty.master.try_clone_reader().unwrap();
        let writer = pty.master.take_writer().unwrap();
        let output = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&output);
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(read @ 1..) = reader.read(&mut buf) {
                sink.lock().unwrap().extend_from_slice(&buf[..read]);
            }
        });
        Self {
            title,
            output,
            writer,
            child,
            _master: pty.master,
        }
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.output.lock().unwrap()).into_owned()
    }

    /// Waits until `pattern` has appeared at least `count` times.
    fn wait_for(&mut self, pattern: &str, count: usize) {
        self.wait_until(&format!("{pattern:?} x{count}"), |text| {
            text.matches(pattern).count() >= count
        });
    }

    /// Waits until the most recent frame contains `pattern`. Each frame
    /// redraws every line from the title, so the last one shows the current
    /// state.
    fn wait_frame(&mut self, pattern: &str) {
        let title = self.title;
        self.wait_until(&format!("a frame with {pattern:?}"), |text| {
            text.rsplit_once(title)
                .is_some_and(|(_, frame)| frame.contains(pattern))
        });
    }

    fn wait_until(&mut self, what: &str, done: impl Fn(&str) -> bool) {
        let started = Instant::now();
        while !done(&self.text()) {
            if let Ok(Some(status)) = self.child.try_wait() {
                panic!("child exited ({status:?}) before {what}: {:?}", self.text());
            }
            if started.elapsed() > DEADLINE {
                let _ = self.child.kill();
                panic!("timed out waiting for {what}: {:?}", self.text());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn send(&mut self, bytes: &[u8]) {
        self.writer.write_all(bytes).unwrap();
        self.writer.flush().unwrap();
    }

    /// Waits for the child's result line and its successful exit.
    fn finish(mut self) -> (String, String) {
        self.wait_for(RESULT, 1);
        let started = Instant::now();
        let status = loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                break status;
            }
            if started.elapsed() > DEADLINE {
                let _ = self.child.kill();
                panic!("child did not exit: {:?}", self.text());
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let text = self.text();
        assert!(status.success(), "child failed ({status:?}): {text:?}");
        let result = text
            .split_once(RESULT)
            .map(|(_, rest)| rest.lines().next().unwrap_or("").trim().to_owned())
            .unwrap();
        (result, text)
    }
}

/// The widget drew, then erased its lines and showed the cursor again
/// before the child printed its result.
fn assert_erased(text: &str, title: &str) {
    let last_frame = text.rfind(title).expect("a frame");
    let restore = text.rfind("\x1b[J\x1b[?25h\x1b[?7h").expect("a restore");
    let result = text.find(RESULT).unwrap();
    assert!(last_frame < restore && restore < result, "{text:?}");
    assert!(text.contains("\x1b[?25l"), "the cursor was hidden");
}

fn picker() -> Session {
    let mut session = Session::start("picker", PICKER_TITLE);
    session.wait_frame("Filter: type to search");
    session
}

fn checklist() -> Session {
    let mut session = Session::start("checklist", CHECKLIST_TITLE);
    session.wait_frame("› [x] Codewire CLI");
    session
}

#[test]
fn picker_filter_arrows_and_enter_select_the_original_row() {
    let mut session = picker();
    session.send(b"stopped");
    session.wait_frame("Filter: stopped");
    session.send(b"\x1b[B");
    session.wait_frame("› scratch");
    session.send(b"\x1bOA");
    session.wait_frame("› review");
    session.send(b"\x1b[B");
    session.wait_frame("› scratch");
    session.send(b"\r");
    let (result, text) = session.finish();
    assert_eq!(result, "Ok(Chosen(2)) restored=true", "{text:?}");
    assert_erased(&text, PICKER_TITLE);
}

#[test]
fn picker_escape_cancels_and_restores_the_terminal() {
    let mut session = picker();
    session.send(b"rev");
    session.wait_frame("Filter: rev");
    session.send(b"\x1b");
    let (result, text) = session.finish();
    assert_eq!(result, "Ok(Canceled) restored=true", "{text:?}");
    assert_erased(&text, PICKER_TITLE);
}

#[test]
fn picker_ctrl_c_cancels_without_a_signal_and_restores_the_terminal() {
    let mut session = picker();
    session.send(b"\x03");
    let (result, text) = session.finish();
    assert_eq!(result, "Ok(Canceled) restored=true", "{text:?}");
    assert_erased(&text, PICKER_TITLE);
}

#[test]
fn checklist_toggles_and_applies_the_checked_items() {
    let mut session = checklist();
    session.send(b"\x1b[B");
    session.wait_frame("› [ ] Restart");
    session.send(b" ");
    session.wait_frame("› [x] Restart");
    session.send(b"\x1bOA");
    session.wait_frame("› [x] Codewire CLI");
    session.send(b" ");
    session.wait_frame("› [ ] Codewire CLI");
    session.send(b"\r");
    let (result, text) = session.finish();
    assert_eq!(result, "Ok(Applied([1])) restored=true", "{text:?}");
    assert_erased(&text, CHECKLIST_TITLE);
}

#[test]
fn checklist_escape_cancels_after_a_toggle() {
    let mut session = checklist();
    session.send(b" ");
    session.wait_frame("› [ ] Codewire CLI");
    session.send(b"\x1b");
    let (result, text) = session.finish();
    assert_eq!(result, "Ok(Canceled) restored=true", "{text:?}");
    assert_erased(&text, CHECKLIST_TITLE);
}

#[test]
fn checklist_ctrl_c_cancels_and_restores_the_terminal() {
    let mut session = checklist();
    session.send(b"\x03");
    let (result, text) = session.finish();
    assert_eq!(result, "Ok(Canceled) restored=true", "{text:?}");
    assert_erased(&text, CHECKLIST_TITLE);
}
