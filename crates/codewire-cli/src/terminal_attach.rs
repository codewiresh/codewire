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
    fn stty_size_is_rows_then_columns() {
        assert_eq!(parse_stty_size("24 80\n").unwrap(), (80, 24));
        assert!(parse_stty_size("24").is_err());
        assert!(parse_stty_size("24 80 extra").is_err());
    }
}
