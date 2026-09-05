//! Terminal backend: PTY + alacritty_terminal parser.
//!
//! Owns the `alacritty_terminal::Term` grid and pumps bytes from a local PTY
//! through the VTE parser to update it.

use alacritty_terminal::Term;
use alacritty_terminal::event::EventListener;
use alacritty_terminal::grid::Dimensions;
use alacritty_terminal::term::Config as TermConfig;
use portable_pty::MasterPty;
use std::io::Read as IoRead;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

/// Terminal size in cells.
#[derive(Clone, Copy, Debug)]
pub struct TermSize {
    pub cols: usize,
    pub rows: usize,
}

impl Dimensions for TermSize {
    fn total_lines(&self) -> usize {
        self.rows
    }

    fn screen_lines(&self) -> usize {
        self.rows
    }

    fn columns(&self) -> usize {
        self.cols
    }
}

/// No-op event listener — we poll the grid directly from the render loop.
pub struct Listener;
impl EventListener for Listener {}

/// Shared terminal state: the alacritty_terminal grid wrapped in a mutex.
pub type SharedTerm = Arc<Mutex<Term<Listener>>>;

/// Stateful ANSI parser shared by local PTY and typed Connect terminal
/// transports. Rendering remains transport-neutral.
pub struct TerminalOutputParser {
    parser: alacritty_terminal::vte::ansi::Processor<alacritty_terminal::vte::ansi::StdSyncHandler>,
}

impl Default for TerminalOutputParser {
    fn default() -> Self {
        Self {
            parser: alacritty_terminal::vte::ansi::Processor::new(),
        }
    }
}

impl TerminalOutputParser {
    pub fn feed(&mut self, term: &SharedTerm, bytes: &[u8]) {
        if let Ok(mut term) = term.lock() {
            self.parser.advance(&mut *term, bytes);
        }
    }
}

/// Create a new terminal grid with the given dimensions.
pub fn new_term(size: TermSize) -> SharedTerm {
    let config = TermConfig {
        scrolling_history: 10_000,
        ..TermConfig::default()
    };
    let term = Term::new(config, &size, Listener);
    Arc::new(Mutex::new(term))
}

/// Messages sent from the UI to the backend write task.
pub enum PtyInput {
    /// Raw bytes to write to the PTY (keyboard input).
    Data(Vec<u8>),
    /// Terminal was resized to new dimensions.
    Resize { cols: u32, rows: u32 },
    /// Shut down the PTY.
    Shutdown,
}

/// Spawn an arbitrary command in a PTY.
///
/// Returns the child process, a reader, a writer, and the master PTY handle
/// (needed for resize).
pub fn spawn_pty(
    size: TermSize,
    command: &str,
    args: &[&str],
    env: &[(&str, &str)],
) -> Result<
    (
        Box<dyn portable_pty::Child + Send + Sync>,
        Box<dyn IoRead + Send>,
        Box<dyn std::io::Write + Send>,
        Box<dyn MasterPty + Send>,
    ),
    String,
> {
    use portable_pty::{CommandBuilder, NativePtySystem, PtySize, PtySystem};

    let pty_system = NativePtySystem::default();
    let pty_pair = pty_system
        .openpty(PtySize {
            rows: size.rows as u16,
            cols: size.cols as u16,
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|e| format!("Failed to open PTY: {}", e))?;

    let mut cmd = CommandBuilder::new(command);
    cmd.args(args);
    cmd.env("TERM", "xterm-256color");
    for (key, val) in env {
        cmd.env(key, val);
    }

    let child = pty_pair
        .slave
        .spawn_command(cmd)
        .map_err(|e| format!("Failed to spawn command: {}", e))?;

    let reader = pty_pair
        .master
        .try_clone_reader()
        .map_err(|e| format!("Failed to clone PTY reader: {}", e))?;

    let writer = pty_pair
        .master
        .take_writer()
        .map_err(|e| format!("Failed to take PTY writer: {}", e))?;

    Ok((child, reader, writer, pty_pair.master))
}

/// Read loop: reads bytes from the PTY master, parses them into the terminal
/// grid, and signals repaint.
///
/// Runs on a blocking thread since PTY reads are blocking I/O.
pub fn read_loop(
    term: SharedTerm,
    mut reader: Box<dyn IoRead + Send>,
    repaint: Box<dyn Fn() + Send>,
) {
    let mut parser = TerminalOutputParser::default();
    let mut buf = [0u8; 4096];

    loop {
        match reader.read(&mut buf) {
            Ok(0) => break, // EOF
            Ok(n) => {
                parser.feed(&term, &buf[..n]);
                repaint();
            }
            Err(_) => break,
        }
    }
}

/// Write loop: reads PtyInput and writes to the PTY master.
pub fn write_loop(
    rx: mpsc::Receiver<PtyInput>,
    mut writer: Box<dyn std::io::Write + Send>,
    master: Box<dyn MasterPty + Send>,
) {
    use portable_pty::PtySize;
    use std::io::Write;

    while let Ok(msg) = rx.recv() {
        match msg {
            PtyInput::Data(data) => {
                if writer.write_all(&data).is_err() {
                    break;
                }
                let _ = writer.flush();
            }
            PtyInput::Resize { cols, rows } => {
                let _ = master.resize(PtySize {
                    rows: rows as u16,
                    cols: cols as u16,
                    pixel_width: 0,
                    pixel_height: 0,
                });
            }
            PtyInput::Shutdown => break,
        }
    }
}
