use std::io::IsTerminal as _;
use std::process::{Command as ProcessCommand, Stdio};

use anyhow::Context as _;

pub(crate) fn terminal_size() -> anyhow::Result<(u16, u16)> {
    let output = ProcessCommand::new("stty")
        .arg("size")
        .stdin(Stdio::inherit())
        .stderr(Stdio::piped())
        .output()
        .context("run stty size")?;
    if !output.status.success() {
        anyhow::bail!(
            "stty size failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    parse_stty_size(&String::from_utf8(output.stdout)?)
}

fn parse_stty_size(raw: &str) -> anyhow::Result<(u16, u16)> {
    let mut parts = raw.split_whitespace();
    let rows: u16 = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing terminal rows"))?
        .parse()
        .context("parse terminal rows")?;
    let cols: u16 = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing terminal cols"))?
        .parse()
        .context("parse terminal cols")?;
    if parts.next().is_some() {
        anyhow::bail!("unexpected stty size output {raw:?}");
    }
    Ok((cols, rows))
}

/// The controlling terminal's size as (columns, rows), read from stdin.
#[cfg(unix)]
fn window_size() -> Option<(u16, u16)> {
    // SAFETY: TIOCGWINSZ fills exactly one `winsize`, which lives for the call.
    let mut size: libc::winsize = unsafe { std::mem::zeroed() };
    // SAFETY: stdin is an open descriptor for the process's lifetime, and the
    // request writes only into `size`.
    let status = unsafe { libc::ioctl(libc::STDIN_FILENO, libc::TIOCGWINSZ, &mut size) };
    (status == 0 && size.ws_col > 0 && size.ws_row > 0).then_some((size.ws_col, size.ws_row))
}

#[cfg(not(unix))]
fn window_size() -> Option<(u16, u16)> {
    terminal_size()
        .ok()
        .filter(|(columns, rows)| *columns > 0 && *rows > 0)
}

/// Follows the attached terminal's size for a session's PTY: the size when
/// the attachment opens, then each change (SIGWINCH), never the same size
/// twice in a row. Disabled, it reports nothing and never wakes.
pub(crate) struct WindowSizeWatch {
    #[cfg(unix)]
    signal: Option<tokio::signal::unix::Signal>,
    enabled: bool,
    last: Option<(u16, u16)>,
}

impl WindowSizeWatch {
    pub(crate) fn new(enabled: bool) -> Self {
        #[cfg(unix)]
        let signal = enabled
            .then(|| {
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change()).ok()
            })
            .flatten();
        Self {
            #[cfg(unix)]
            signal,
            enabled,
            last: None,
        }
    }

    /// The current size when it differs from the last one reported.
    pub(crate) fn current(&mut self) -> Option<(u16, u16)> {
        if !self.enabled {
            return None;
        }
        let size = window_size()?;
        self.report(size)
    }

    fn report(&mut self, size: (u16, u16)) -> Option<(u16, u16)> {
        (self.last != Some(size)).then(|| {
            self.last = Some(size);
            size
        })
    }

    /// Waits for the terminal to change size and returns the new size, or
    /// `None` when the change left it as last reported.
    pub(crate) async fn changed(&mut self) -> Option<(u16, u16)> {
        #[cfg(unix)]
        if let Some(signal) = self.signal.as_mut() {
            if signal.recv().await.is_some() {
                return self.current();
            }
            self.signal = None;
        }
        std::future::pending().await
    }
}

pub(crate) struct RawModeGuard {
    state: String,
    restore: fn(&str),
}

impl RawModeGuard {
    pub(crate) fn enable() -> anyhow::Result<Self> {
        if !std::io::stdin().is_terminal() {
            anyhow::bail!("stdin is not a terminal");
        }
        let state = stty_capture(&["-g"])?;
        stty_status(&["raw", "-echo"])?;
        Ok(Self {
            state,
            restore: restore_terminal,
        })
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        (self.restore)(&self.state);
    }
}

fn restore_terminal(state: &str) {
    let _ = ProcessCommand::new("stty")
        .arg(state.trim())
        .stdin(Stdio::inherit())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn stty_capture(args: &[&str]) -> anyhow::Result<String> {
    let output = ProcessCommand::new("stty")
        .args(args)
        .stdin(Stdio::inherit())
        .stderr(Stdio::piped())
        .output()
        .with_context(|| format!("run stty {}", args.join(" ")))?;
    if !output.status.success() {
        anyhow::bail!(
            "stty {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_string())
}

fn stty_status(args: &[&str]) -> anyhow::Result<()> {
    let output = ProcessCommand::new("stty")
        .args(args)
        .stdin(Stdio::inherit())
        .stderr(Stdio::piped())
        .output()
        .with_context(|| format!("run stty {}", args.join(" ")))?;
    if !output.status.success() {
        anyhow::bail!(
            "stty {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_window_size_is_reported_once_per_change() {
        let mut watch = WindowSizeWatch::new(false);
        assert_eq!(watch.current(), None, "disabled watches report nothing");
        assert_eq!(watch.report((80, 24)), Some((80, 24)));
        assert_eq!(watch.report((80, 24)), None);
        assert_eq!(watch.report((120, 40)), Some((120, 40)));
        assert_eq!(watch.report((80, 24)), Some((80, 24)));
    }

    #[test]
    fn stty_size_is_rows_then_columns() {
        assert_eq!(parse_stty_size("24 80\n").unwrap(), (80, 24));
        assert!(parse_stty_size("24").is_err());
        assert!(parse_stty_size("24 80 extra").is_err());
    }
}
