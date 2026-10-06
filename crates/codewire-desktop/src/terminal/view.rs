//! Terminal view component backed by alacritty_terminal.
//!
//! Renders the terminal grid from a SharedTerm and forwards keyboard
//! input to the PTY backend via an mpsc channel.

use crate::terminal::backend::{self, PtyInput, SharedTerm, TermSize, TerminalOutputParser};
use crate::theme::{self, Theme};
use alacritty_terminal::grid::{Dimensions, Scroll};
use alacritty_terminal::index::{Column, Line};
use alacritty_terminal::term::cell::Flags as CellFlags;
use alacritty_terminal::term::{TermMode, point_to_viewport};
use codewire_client::{RunRequest, RunResize, run_request, run_response};
use futures::StreamExt;
use gpui::{
    AnyElement, App, Bounds, Context, Element, ElementId, Entity, FocusHandle, Focusable,
    GlobalElementId, HighlightStyle, InspectorElementId, IntoElement, KeyDownEvent, LayoutId,
    Overflow, Pixels, ScrollDelta, ScrollWheelEvent, SharedString, Size, Style, StyledText, Window,
    div, font, prelude::*, px,
};
use std::sync::mpsc;

/// The input half of a terminal transport. Local terminals keep their PTY;
/// platform environments use the typed Connect Run stream directly.
enum TerminalInputSender {
    Pty(mpsc::Sender<PtyInput>),
    Connect(tokio::sync::mpsc::UnboundedSender<PtyInput>),
}

impl TerminalInputSender {
    fn send(&self, input: PtyInput) {
        match self {
            Self::Pty(sender) => {
                let _ = sender.send(input);
            }
            Self::Connect(sender) => {
                let _ = sender.send(input);
            }
        }
    }
}

/// Events sent from the background PTY thread back to the GPUI foreground.
enum TermEvent {
    Connected,
    Repaint,
    Error(String),
    Disconnected,
}

/// Monospace font for terminal rendering
const TERMINAL_FONT: &str = "Menlo";
/// Terminal font size in pixels
const TERMINAL_FONT_SIZE: f32 = 13.0;
/// Default grid size (used before first layout)
const DEFAULT_COLS: usize = 80;
const DEFAULT_ROWS: usize = 24;
/// Padding inside the terminal grid container (p_1 = 4px each side)
const GRID_PADDING: f32 = 8.0;

/// Terminal view component
pub struct TerminalView {
    /// Shared terminal grid state (written by backend, read by render)
    term: SharedTerm,
    /// Channel to send input bytes to the active terminal transport.
    pty_tx: Option<TerminalInputSender>,
    /// Connection metadata
    host: Option<String>,
    session_name: Option<String>,
    session_type: Option<String>,
    connected: bool,
    status: String,
    /// Current grid size in cells
    grid_cols: usize,
    grid_rows: usize,
    focus_handle: FocusHandle,
    /// Measured cell dimensions (width, height) in pixels
    cell_size: Option<(f32, f32)>,
    /// Actual rendered bounds of the terminal grid area (set by TerminalGridElement)
    last_grid_bounds: Option<Size<Pixels>>,
    /// Cached styled rows from the last successful render (used when try_lock fails)
    cached_rows: Vec<(SharedString, Vec<(std::ops::Range<usize>, HighlightStyle)>)>,
    /// Cached grid dimensions from the last successful render
    cached_cols: usize,
    cached_screen_rows: usize,
    #[cfg(test)]
    pty_fixtures: crate::tests::PtyFixtures,
}

impl TerminalView {
    pub fn new(cx: &mut Context<Self>) -> Self {
        let size = TermSize {
            cols: DEFAULT_COLS,
            rows: DEFAULT_ROWS,
        };
        let term = backend::new_term(size);

        Self {
            term,
            pty_tx: None,
            host: None,
            session_name: None,
            session_type: None,
            connected: false,
            status: "Not connected".to_string(),
            grid_cols: DEFAULT_COLS,
            grid_rows: DEFAULT_ROWS,
            focus_handle: cx.focus_handle(),
            cell_size: None,
            last_grid_bounds: None,
            cached_rows: Vec::new(),
            cached_cols: DEFAULT_COLS,
            cached_screen_rows: DEFAULT_ROWS,
            #[cfg(test)]
            pty_fixtures: crate::tests::PtyFixtures::default(),
        }
    }

    /// Measure the actual monospace cell size for the terminal font.
    fn measure_cell(window: &Window, cx: &App) -> (f32, f32) {
        let font_size = px(TERMINAL_FONT_SIZE);
        let f = font(TERMINAL_FONT);
        let font_id = cx.text_system().resolve_font(&f);
        let cell_width: f32 = cx
            .text_system()
            .ch_advance(font_id, font_size)
            .unwrap_or(px(7.8))
            .into();
        let cell_height: f32 = window.line_height().into();
        (cell_width, cell_height)
    }

    /// Resize the terminal grid and notify the PTY of the new dimensions.
    fn resize(&mut self, cols: usize, rows: usize, cx: &mut Context<Self>) {
        if cols == self.grid_cols && rows == self.grid_rows {
            return;
        }
        if cols < 10 || rows < 3 {
            return;
        }

        self.grid_cols = cols;
        self.grid_rows = rows;

        let size = TermSize { cols, rows };
        if let Ok(mut term) = self.term.lock() {
            term.resize(size);
        }

        if let Some(tx) = &self.pty_tx {
            tx.send(PtyInput::Resize {
                cols: cols as u32,
                rows: rows as u32,
            });
        }

        cx.notify();
    }

    /// Spawn a command in a local PTY and wire up read/write loops.
    ///
    /// This is the entry point for commands running in a local PTY.
    fn spawn(&mut self, command: &str, args: &[&str], label: &str, cx: &mut Context<Self>) {
        self.spawn_with_env(command, args, &[], label, cx);
    }

    fn spawn_with_env(
        &mut self,
        command: &str,
        args: &[&str],
        env: &[(&str, &str)],
        label: &str,
        cx: &mut Context<Self>,
    ) {
        self.status = format!("Connecting to {}...", label);
        cx.notify();

        let term = self.term.clone();
        let size = TermSize {
            cols: self.grid_cols,
            rows: self.grid_rows,
        };

        // Create the input channel (std mpsc)
        let (tx, rx) = mpsc::channel();
        #[cfg(test)]
        let fixture_tx = tx.clone();
        #[cfg(test)]
        let (fixture_child_tx, fixture_child_rx) = mpsc::channel();
        self.pty_tx = Some(TerminalInputSender::Pty(tx));

        // Event channel: background threads -> GPUI foreground
        let (event_tx, event_rx) = futures::channel::mpsc::unbounded::<TermEvent>();

        let command = command.to_string();
        let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        let env: Vec<(String, String)> = env
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();

        // Spawn on a background thread (blocking I/O)
        let worker = std::thread::spawn(move || {
            let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            let env_refs: Vec<(&str, &str)> =
                env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
            let (mut child, reader, writer, master) =
                match backend::spawn_pty(size, &command, &arg_refs, &env_refs) {
                    Ok(v) => v,
                    Err(e) => {
                        let _ = event_tx.unbounded_send(TermEvent::Error(format!("Failed: {}", e)));
                        return;
                    }
                };
            #[cfg(test)]
            let child = std::sync::Arc::new(std::sync::Mutex::new(child));
            #[cfg(test)]
            let _ = fixture_child_tx.send(child.clone());

            // Read loop on this thread — send Connected on first output
            let first_output = std::sync::atomic::AtomicBool::new(true);
            let connected_tx = event_tx.clone();
            let read_event_tx = event_tx.clone();
            let repaint = Box::new(move || {
                if first_output.swap(false, std::sync::atomic::Ordering::Relaxed) {
                    let _ = connected_tx.unbounded_send(TermEvent::Connected);
                }
                let _ = read_event_tx.unbounded_send(TermEvent::Repaint);
            });

            // Write loop on a separate thread
            let write_handle = std::thread::spawn(move || {
                backend::write_loop(rx, writer, master);
            });

            backend::read_loop(term, reader, repaint);

            // Process exited
            #[cfg(not(test))]
            let _ = child.wait();
            #[cfg(test)]
            let _ = child.lock().expect("PTY fixture child owner").wait();
            let _ = event_tx.unbounded_send(TermEvent::Disconnected);
            let _ = write_handle.join();
        });
        #[cfg(test)]
        self.pty_fixtures.push(fixture_tx, fixture_child_rx, worker);
        #[cfg(not(test))]
        drop(worker);

        self.watch_terminal_events(label.to_string(), event_rx, cx);
    }

    /// Process transport events on the GPUI foreground with frame-rate
    /// throttled repaints. Both PTY and Connect transports share this state.
    fn watch_terminal_events(
        &mut self,
        label: String,
        mut event_rx: futures::channel::mpsc::UnboundedReceiver<TermEvent>,
        cx: &mut Context<Self>,
    ) {
        cx.spawn(async move |this, cx| {
            use std::time::{Duration, Instant};
            const MIN_REPAINT_INTERVAL: Duration = Duration::from_millis(8);

            let mut pending_repaint = false;
            let mut last_repaint = Instant::now() - MIN_REPAINT_INTERVAL;
            loop {
                let event = if pending_repaint {
                    // Try non-blocking first to coalesce queued repaints
                    match futures::FutureExt::now_or_never(event_rx.next()) {
                        Some(Some(event)) => event,
                        _ => {
                            // No more queued events — throttle and flush
                            let elapsed = last_repaint.elapsed();
                            if elapsed < MIN_REPAINT_INTERVAL {
                                cx.background_executor()
                                    .timer(MIN_REPAINT_INTERVAL - elapsed)
                                    .await;
                            }
                            pending_repaint = false;
                            last_repaint = Instant::now();
                            let _ = this.update(cx, |_, cx| cx.notify());
                            continue;
                        }
                    }
                } else {
                    match event_rx.next().await {
                        Some(event) => event,
                        None => break,
                    }
                };

                match event {
                    TermEvent::Connected => {
                        let lbl = label.clone();
                        let _ = this.update(cx, |this, cx| {
                            this.connected = true;
                            this.status = lbl;
                            cx.notify();
                        });
                    }
                    TermEvent::Repaint => {
                        // Don't notify yet — loop back to drain more queued repaints
                        pending_repaint = true;
                    }
                    TermEvent::Error(msg) => {
                        let _ = this.update(cx, |this, cx| {
                            this.status = msg;
                            this.connected = false;
                            this.pty_tx = None;
                            cx.notify();
                        });
                        break;
                    }
                    TermEvent::Disconnected => {
                        let _ = this.update(cx, |this, cx| {
                            this.connected = false;
                            this.status = "Disconnected".to_string();
                            this.pty_tx = None;
                            cx.notify();
                        });
                        break;
                    }
                }
            }
        })
        .detach();
    }

    /// Open a local terminal (spawns the user's shell via PTY).
    pub fn connect_local(&mut self, cx: &mut Context<Self>) {
        self.host = None;
        self.session_name = Some("local".to_string());
        self.session_type = None;

        let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/zsh".into());
        self.spawn(&shell, &[], "local shell", cx);
    }

    /// Open a platform environment shell over the typed Connect Run stream.
    pub fn connect_codewire_env(
        &mut self,
        org_id: &str,
        env_id: &str,
        env_name: &str,
        cx: &mut Context<Self>,
    ) {
        self.host = Some(env_id.to_string());
        self.session_name = Some(env_name.to_string());
        self.session_type = Some("codewire-env".to_string());

        let label = format!("environment shell {}", env_name);
        self.status = format!("Connecting to {}...", label);
        cx.notify();

        let term = self.term.clone();
        let columns = self.grid_cols as u32;
        let rows = self.grid_rows as u32;
        let (input_tx, mut input_rx) = tokio::sync::mpsc::unbounded_channel();
        self.pty_tx = Some(TerminalInputSender::Connect(input_tx));
        let (event_tx, event_rx) = futures::channel::mpsc::unbounded::<TermEvent>();
        let org_id = org_id.to_string();
        let env_id = env_id.to_string();

        std::thread::spawn(move || {
            let stream_events = event_tx.clone();
            let result = tokio::runtime::Runtime::new()
                .map_err(|_| "could not start the desktop terminal runtime".to_string())
                .and_then(|runtime| {
                    runtime.block_on(async move {
                        let Some(client) = crate::native_client()? else {
                            return Err("Sign in to Codewire before opening an environment terminal".to_string());
                        };
                        let mut session = client
                            .start_environment_shell(org_id, env_id, columns, rows)
                            .await
                            .map_err(|_| "could not open the environment terminal".to_string())?;
                        let input = session.input_handle();
                        let _ = stream_events.unbounded_send(TermEvent::Connected);
                        let mut parser = TerminalOutputParser::default();
                        loop {
                            tokio::select! {
                                command = input_rx.recv() => {
                                    let Some(command) = command else { break; };
                                    let shutting_down = matches!(command, PtyInput::Shutdown);
                                    let request = match command {
                                        PtyInput::Data(data) => RunRequest {
                                            input: Some(run_request::Input::Stdin(data)),
                                            ..Default::default()
                                        },
                                        PtyInput::Resize { cols, rows } => RunRequest {
                                            input: Some(run_request::Input::Resize(Box::new(RunResize {
                                                columns: cols,
                                                rows,
                                                ..Default::default()
                                            }))),
                                            ..Default::default()
                                        },
                                        PtyInput::Shutdown => RunRequest {
                                            input: Some(run_request::Input::CloseStdin(Box::default())),
                                            ..Default::default()
                                        },
                                    };
                                    input
                                        .send(request)
                                        .await
                                        .map_err(|_| "environment terminal stream closed".to_string())?;
                                    if shutting_down { break; }
                                }
                                response = session.next_output() => match response {
                                    Ok(Some(response)) => match response.event {
                                        Some(run_response::Event::Stdout(data)) | Some(run_response::Event::Stderr(data)) => {
                                            parser.feed(&term, &data);
                                            let _ = stream_events.unbounded_send(TermEvent::Repaint);
                                        }
                                        Some(run_response::Event::ExitCode(_)) | None => break,
                                    },
                                    Ok(None) => break,
                                    Err(_) => return Err("environment terminal stream failed".to_string()),
                                },
                            }
                        }
                        Ok(())
                    })
                });
            match result {
                Ok(()) => {
                    let _ = event_tx.unbounded_send(TermEvent::Disconnected);
                }
                Err(error) => {
                    let _ = event_tx.unbounded_send(TermEvent::Error(error));
                }
            }
        });

        self.watch_terminal_events(label, event_rx, cx);
    }

    /// Disconnect from current session
    pub fn disconnect(&mut self, cx: &mut Context<Self>) {
        if let Some(tx) = self.pty_tx.take() {
            tx.send(PtyInput::Shutdown);
        }
        self.connected = false;
        self.status = "Disconnected".to_string();
        self.host = None;
        self.session_name = None;
        self.session_type = None;
        cx.notify();
    }

    /// Send raw bytes to the PTY
    fn send_bytes(&self, bytes: Vec<u8>) {
        if let Some(tx) = &self.pty_tx {
            tx.send(PtyInput::Data(bytes));
        }
    }

    /// Handle key press — translate GPUI key events to PTY bytes
    fn handle_key_down(
        &mut self,
        event: &KeyDownEvent,
        _window: &mut Window,
        _cx: &mut Context<Self>,
    ) {
        if !self.connected {
            return;
        }

        // Map GPUI key events to terminal byte sequences
        let bytes: Vec<u8> = match event.keystroke.key.as_str() {
            "escape" => vec![0x1b],
            "enter" => vec![0x0d],
            "backspace" => vec![0x7f],
            "tab" => vec![0x09],
            "up" => vec![0x1b, b'[', b'A'],
            "down" => vec![0x1b, b'[', b'B'],
            "right" => vec![0x1b, b'[', b'C'],
            "left" => vec![0x1b, b'[', b'D'],
            "home" => vec![0x1b, b'[', b'H'],
            "end" => vec![0x1b, b'[', b'F'],
            "pageup" => vec![0x1b, b'[', b'5', b'~'],
            "pagedown" => vec![0x1b, b'[', b'6', b'~'],
            "delete" => vec![0x1b, b'[', b'3', b'~'],
            _ => {
                if event.keystroke.modifiers.control {
                    // Ctrl+key: derive control byte from key_char or key name
                    let ch = event
                        .keystroke
                        .key_char
                        .as_ref()
                        .and_then(|s| s.chars().next())
                        .or_else(|| {
                            let k = event.keystroke.key.as_str();
                            if k.len() == 1 { k.chars().next() } else { None }
                        });
                    if let Some(ch) = ch {
                        if ch.is_ascii_alphabetic() {
                            vec![(ch.to_ascii_lowercase() as u8) - b'a' + 1]
                        } else {
                            // Ctrl+[ = ESC, Ctrl+] = 0x1d, etc.
                            match ch {
                                '[' => vec![0x1b],
                                '\\' => vec![0x1c],
                                ']' => vec![0x1d],
                                _ => return,
                            }
                        }
                    } else {
                        return;
                    }
                } else if let Some(ref key_char) = event.keystroke.key_char {
                    key_char.as_bytes().to_vec()
                } else {
                    return; // Modifier-only key, ignore
                }
            }
        };

        self.send_bytes(bytes);
    }
}

impl Focusable for TerminalView {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus_handle.clone()
    }
}

impl Render for TerminalView {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = Theme::dark();

        // Measure cell size once (needs window for line_height)
        if self.cell_size.is_none() {
            self.cell_size = Some(Self::measure_cell(window, cx));
        }
        let (cell_w, cell_h) = self.cell_size.unwrap();

        // Resize based on actual grid bounds (set by TerminalGridElement on previous frame)
        if let Some(grid_size) = self.last_grid_bounds {
            let w: f32 = grid_size.width.into();
            let h: f32 = grid_size.height.into();
            let padding = GRID_PADDING;
            let cols = ((w - padding) / cell_w) as usize;
            let rows = ((h - padding) / cell_h) as usize;
            let cols = cols.clamp(10, 500);
            let rows = rows.clamp(3, 200);
            if cols != self.grid_cols || rows != self.grid_rows {
                self.resize(cols, rows, cx);
            }
        }

        // Try to acquire the terminal lock without blocking the UI thread.
        // If the read_loop thread holds it, fall back to cached content.
        let styled_rows = if let Ok(term) = self.term.try_lock() {
            let cols = term.columns();
            let rows = term.screen_lines();
            let show_cursor = term.mode().contains(TermMode::SHOW_CURSOR);
            let cursor_point = term.grid().cursor.point;
            let display_offset = term.grid().display_offset();
            let cursor_viewport = if show_cursor {
                point_to_viewport(display_offset, cursor_point)
            } else {
                None
            };

            let mut styled_rows: Vec<(
                SharedString,
                Vec<(std::ops::Range<usize>, HighlightStyle)>,
            )> = Vec::with_capacity(rows);

            for row_idx in 0..rows {
                let line = Line(row_idx as i32) - display_offset;
                let mut text = String::with_capacity(cols * 4);
                let mut highlights: Vec<(std::ops::Range<usize>, HighlightStyle)> = Vec::new();

                let mut run_start: usize = 0;
                let mut run_fg: Option<gpui::Hsla> = None;
                let mut run_bg: Option<gpui::Hsla> = None;
                let mut run_weight: Option<gpui::FontWeight> = None;

                for col_idx in 0..cols {
                    let cell = &term.grid()[line][Column(col_idx)];
                    let ch = if cell.c == ' ' || cell.c == '\0' {
                        '\u{00A0}'
                    } else {
                        cell.c
                    };

                    let is_cursor = cursor_viewport
                        .map(|vp| row_idx == vp.line && col_idx == vp.column.0)
                        .unwrap_or(false);
                    let fg_raw = theme::ansi_color_to_hsla(&cell.fg, theme);
                    let bg_raw = theme::ansi_color_to_hsla(&cell.bg, theme);
                    let bold = cell.flags.contains(CellFlags::BOLD);
                    let inverse = cell.flags.contains(CellFlags::INVERSE);

                    let (fg, bg) = if is_cursor {
                        (Some(theme.background), Some(theme.term_cursor))
                    } else if inverse {
                        (Some(bg_raw), Some(fg_raw))
                    } else {
                        (
                            Some(fg_raw),
                            if bg_raw != theme.background {
                                Some(bg_raw)
                            } else {
                                None
                            },
                        )
                    };
                    let weight = if bold {
                        Some(gpui::FontWeight::BOLD)
                    } else {
                        None
                    };

                    let byte_start = text.len();
                    text.push(ch);

                    if run_fg == fg && run_bg == bg && run_weight == weight && byte_start > 0 {
                        continue;
                    }

                    if byte_start > 0 {
                        let mut style = HighlightStyle::default();
                        style.color = run_fg;
                        style.background_color = run_bg;
                        style.font_weight = run_weight;
                        highlights.push((run_start..byte_start, style));
                    }

                    run_start = byte_start;
                    run_fg = fg;
                    run_bg = bg;
                    run_weight = weight;
                }

                let byte_end = text.len();
                if byte_end > run_start {
                    let mut style = HighlightStyle::default();
                    style.color = run_fg;
                    style.background_color = run_bg;
                    style.font_weight = run_weight;
                    highlights.push((run_start..byte_end, style));
                }

                styled_rows.push((SharedString::from(text), highlights));
            }
            drop(term);

            // Cache for next frame
            self.cached_rows = styled_rows.clone();
            self.cached_cols = cols;
            self.cached_screen_rows = rows;
            styled_rows
        } else {
            // Lock contended — use cached rows from the previous frame
            self.cached_rows.clone()
        };

        let cols = self.cached_cols;
        let rows = self.cached_screen_rows;

        // Build row children for the grid element
        let row_children: Vec<AnyElement> = styled_rows
            .into_iter()
            .map(|(text, highlights)| {
                div()
                    .h(px(cell_h))
                    .whitespace_nowrap()
                    .overflow_hidden()
                    .child(StyledText::new(text).with_highlights(highlights))
                    .into_any_element()
            })
            .collect();

        // Render the grid
        let term_for_scroll = self.term.clone();
        let scroll_cell_h = cell_h;

        div()
            .id("terminal-view")
            .debug_selector(|| "terminal-view".to_string())
            .flex()
            .flex_col()
            .size_full()
            .bg(theme.surface)
            .font_family(TERMINAL_FONT)
            .text_size(px(TERMINAL_FONT_SIZE))
            .text_color(theme.foreground)
            .track_focus(&self.focus_handle(cx))
            .on_key_down(cx.listener(Self::handle_key_down))
            .on_scroll_wheel(cx.listener(move |_this, event: &ScrollWheelEvent, _, cx| {
                let lines = match event.delta {
                    ScrollDelta::Lines(pt) => pt.y as i32,
                    ScrollDelta::Pixels(pt) => (pt.y / px(scroll_cell_h)) as i32,
                };
                if lines != 0 {
                    if let Ok(mut term) = term_for_scroll.lock() {
                        term.scroll_display(Scroll::Delta(-lines));
                    }
                    cx.notify();
                }
            }))
            // Status bar
            .child(
                div()
                    .px_3()
                    .py_1()
                    .bg(theme.surface)
                    .border_b_1()
                    .border_color(theme.border)
                    .flex()
                    .items_center()
                    .justify_between()
                    .child(
                        div()
                            .text_xs()
                            .text_color(if self.connected {
                                theme.status_running
                            } else if self.pty_tx.is_some() {
                                theme.foreground
                            } else {
                                theme.muted
                            })
                            .child(self.status.clone()),
                    )
                    .child(
                        div()
                            .text_xs()
                            .text_color(theme.muted)
                            .child(format!("{}x{}", cols, rows)),
                    ),
            )
            // Terminal grid or connecting indicator
            .child(if self.pty_tx.is_some() && !self.connected {
                div()
                    .flex_1()
                    .flex()
                    .flex_col()
                    .items_center()
                    .justify_center()
                    .child(
                        div()
                            .text_size(px(13.0))
                            .text_color(theme.muted)
                            .child(self.status.clone()),
                    )
                    .into_any_element()
            } else {
                TerminalGridElement {
                    terminal: cx.entity().clone(),
                    children: row_children,
                }
                .into_any_element()
            })
    }
}

// ---------------------------------------------------------------------------
// TerminalGridElement — captures actual rendered bounds for correct PTY sizing
// ---------------------------------------------------------------------------

/// A thin wrapper element that measures the actual pixel bounds of the terminal
/// grid area during layout, then stores them on TerminalView so the resize
/// logic uses real dimensions instead of guessing from the window viewport.
struct TerminalGridElement {
    terminal: Entity<TerminalView>,
    children: Vec<AnyElement>,
}

struct TerminalGridLayoutState {
    // Stored to keep child layout IDs alive for taffy
    _child_layout_ids: Vec<LayoutId>,
}

impl IntoElement for TerminalGridElement {
    type Element = Self;

    fn into_element(self) -> Self::Element {
        self
    }
}

impl Element for TerminalGridElement {
    type RequestLayoutState = TerminalGridLayoutState;
    type PrepaintState = ();

    fn id(&self) -> Option<ElementId> {
        None
    }

    fn source_location(&self) -> Option<&'static std::panic::Location<'static>> {
        None
    }

    fn request_layout(
        &mut self,
        _id: Option<&GlobalElementId>,
        _inspector_id: Option<&InspectorElementId>,
        window: &mut Window,
        cx: &mut App,
    ) -> (LayoutId, Self::RequestLayoutState) {
        // Request layout for all children first
        let child_layout_ids: Vec<LayoutId> = self
            .children
            .iter_mut()
            .map(|child| child.request_layout(window, cx))
            .collect();

        // This element fills available space in flex layout
        let mut style = Style::default();
        style.flex_grow = 1.0;
        style.overflow.x = Overflow::Hidden;
        style.overflow.y = Overflow::Hidden;
        style.padding.top = px(4.0).into();
        style.padding.bottom = px(4.0).into();
        style.padding.left = px(4.0).into();
        style.padding.right = px(4.0).into();

        let layout_id = window.request_layout(style, child_layout_ids.iter().copied(), cx);
        (
            layout_id,
            TerminalGridLayoutState {
                _child_layout_ids: child_layout_ids,
            },
        )
    }

    fn prepaint(
        &mut self,
        _id: Option<&GlobalElementId>,
        _inspector_id: Option<&InspectorElementId>,
        bounds: Bounds<Pixels>,
        _request_layout: &mut Self::RequestLayoutState,
        window: &mut Window,
        cx: &mut App,
    ) -> Self::PrepaintState {
        // Store actual bounds on the TerminalView entity
        let grid_size = bounds.size;
        self.terminal.update(cx, |tv, _cx| {
            tv.last_grid_bounds = Some(grid_size);
        });

        // Prepaint children
        for child in &mut self.children {
            child.prepaint(window, cx);
        }
    }

    fn paint(
        &mut self,
        _id: Option<&GlobalElementId>,
        _inspector_id: Option<&InspectorElementId>,
        _bounds: Bounds<Pixels>,
        _request_layout: &mut Self::RequestLayoutState,
        _prepaint: &mut Self::PrepaintState,
        window: &mut Window,
        cx: &mut App,
    ) {
        for child in &mut self.children {
            child.paint(window, cx);
        }
    }
}
