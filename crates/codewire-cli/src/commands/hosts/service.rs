//! The opt-in service that keeps `cw host run` running: a systemd user
//! unit on Linux, a LaunchAgent on macOS. Only files this module wrote
//! (marked as such) are ever replaced or removed.

use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::Context as _;

pub(crate) const MARKER: &str = "Written by `cw host service install`";
#[cfg(target_os = "linux")]
const UNIT: &str = "codewire-host.service";
#[cfg(target_os = "macos")]
const LABEL: &str = "sh.codewire.host";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ServiceState {
    NotInstalled,
    Installed,
    Running,
}

impl fmt::Display for ServiceState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotInstalled => {
                "not installed (`cw host service install` to keep the agent running)"
            }
            Self::Installed => "installed, not running",
            Self::Running => "installed and running",
        })
    }
}

/// Refuses a value a service file cannot carry as written: whitespace
/// splits a systemd assignment, `%` is a systemd specifier, a control
/// character (a newline above all) starts a new directive, and quotes,
/// `\\`, `$`, `<`, `>` and `&` change a unit or a plist.
pub(crate) fn service_value(value: &str, what: &str) -> anyhow::Result<()> {
    let refused = value.chars().find(|&c| {
        c.is_whitespace()
            || c.is_control()
            || matches!(c, '%' | '"' | '\'' | '\\' | '$' | '<' | '>' | '&')
    });
    match refused {
        Some(c) => anyhow::bail!(
            "{what} `{}` has a character a service file cannot carry ({c:?}); use a path without it",
            value.escape_debug()
        ),
        None => Ok(()),
    }
}

/// The configuration directory the agent must use, when it isn't the
/// default: absolute and existing, since the service runs elsewhere.
fn config_dir_override() -> anyhow::Result<Option<String>> {
    let Some(dir) =
        std::env::var_os(crate::config::CW_CONFIG_DIR_ENV).filter(|dir| !dir.is_empty())
    else {
        return Ok(None);
    };
    let dir = PathBuf::from(dir)
        .canonicalize()
        .context("resolve CW_CONFIG_DIR")?;
    let text = dir
        .to_str()
        .context("CW_CONFIG_DIR is not UTF-8")?
        .to_owned();
    service_value(&text, "CW_CONFIG_DIR")?;
    Ok(Some(text))
}

fn executable() -> anyhow::Result<PathBuf> {
    let path = std::env::current_exe()?.canonicalize()?;
    service_value(
        path.to_str().context("the cw path is not UTF-8")?,
        "the cw path",
    )?;
    Ok(path)
}

/// The systemd user unit that runs the agent. Rendered on every platform
/// so both renderings are tested everywhere.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn systemd_unit(executable: &Path, config_dir: Option<&str>) -> String {
    let environment = config_dir
        .map(|dir| format!("Environment=CW_CONFIG_DIR={dir}\n"))
        .unwrap_or_default();
    format!(
        "# {MARKER}; `cw host service uninstall` removes it.\n\
         [Unit]\n\
         Description=Codewire host agent (cw host run)\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         ExecStart={} host run\n\
         {environment}\
         Restart=on-failure\n\
         RestartSec=10\n\
         \n\
         [Install]\n\
         WantedBy=default.target\n",
        executable.display()
    )
}

/// The LaunchAgent that runs the agent.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn launch_agent(
    label: &str,
    executable: &Path,
    config_dir: Option<&str>,
    log: &Path,
) -> String {
    let environment = config_dir
        .map(|dir| {
            format!(
                "  <key>EnvironmentVariables</key>\n  <dict>\n    <key>CW_CONFIG_DIR</key>\n    <string>{dir}</string>\n  </dict>\n"
            )
        })
        .unwrap_or_default();
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!-- {MARKER}; `cw host service uninstall` removes it. -->\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n<dict>\n\
         \x20 <key>Label</key>\n  <string>{label}</string>\n\
         \x20 <key>ProgramArguments</key>\n  <array>\n    <string>{}</string>\n    <string>host</string>\n    <string>run</string>\n  </array>\n\
         {environment}\
         \x20 <key>RunAtLoad</key>\n  <true/>\n\
         \x20 <key>KeepAlive</key>\n  <dict>\n    <key>SuccessfulExit</key>\n    <false/>\n  </dict>\n\
         \x20 <key>StandardOutPath</key>\n  <string>{}</string>\n\
         \x20 <key>StandardErrorPath</key>\n  <string>{}</string>\n\
         </dict>\n</plist>\n",
        executable.display(),
        log.display(),
        log.display()
    )
}

fn home() -> anyhow::Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("HOME is not set")
}

fn service_file() -> anyhow::Result<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .map_or_else(|| home().map(|home| home.join(".config")), Ok)?;
        Ok(base.join("systemd/user").join(UNIT))
    }
    #[cfg(target_os = "macos")]
    {
        Ok(home()?
            .join("Library/LaunchAgents")
            .join(format!("{LABEL}.plist")))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        anyhow::bail!("a host service needs Linux or macOS")
    }
}

/// Whether `path` is a file this module wrote.
fn ours(path: &Path) -> anyhow::Result<bool> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(text.contains(MARKER)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("read {}", path.display())),
    }
}

fn run(program: &str, args: &[&str]) -> anyhow::Result<std::process::Output> {
    Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("run {program}"))
}

fn checked(program: &str, args: &[&str]) -> anyhow::Result<()> {
    let output = run(program, args)?;
    anyhow::ensure!(
        output.status.success(),
        "`{program} {}` failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}

#[cfg(target_os = "macos")]
fn domain() -> String {
    format!("gui/{}", rustix::process::getuid().as_raw())
}

pub(crate) fn state() -> ServiceState {
    let Ok(path) = service_file() else {
        return ServiceState::NotInstalled;
    };
    if !ours(&path).unwrap_or(false) {
        return ServiceState::NotInstalled;
    }
    #[cfg(target_os = "linux")]
    let running = run("systemctl", &["--user", "is-active", "--quiet", UNIT])
        .is_ok_and(|output| output.status.success());
    #[cfg(target_os = "macos")]
    let running =
        run("launchctl", &["print", &format!("{}/{LABEL}", domain())]).is_ok_and(|output| {
            output.status.success()
                && String::from_utf8_lossy(&output.stdout).contains("state = running")
        });
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let running = false;
    if running {
        ServiceState::Running
    } else {
        ServiceState::Installed
    }
}

pub(crate) fn handle(command: super::HostServiceCommand) -> anyhow::Result<()> {
    match command {
        super::HostServiceCommand::Install => install(),
        super::HostServiceCommand::Uninstall => uninstall(),
        super::HostServiceCommand::Status => {
            println!("Service: {}", state());
            Ok(())
        }
    }
}

fn install() -> anyhow::Result<()> {
    super::enrolled(&super::config_dir()?)?;
    let path = service_file()?;
    anyhow::ensure!(
        !path.exists() || ours(&path)?,
        "{} exists and was not written by cw; it is left alone",
        path.display()
    );
    let executable = executable()?;
    let config_dir = config_dir_override()?;
    std::fs::create_dir_all(path.parent().context("service file parent")?)?;
    #[cfg(target_os = "linux")]
    {
        std::fs::write(&path, systemd_unit(&executable, config_dir.as_deref()))?;
        checked("systemctl", &["--user", "daemon-reload"])?;
        checked("systemctl", &["--user", "enable", "--now", UNIT])?;
        println!("Wrote {} and started it.", path.display());
        println!("Logs: journalctl --user -u {UNIT}");
        let user = std::env::var("USER").unwrap_or_default();
        let linger = run("loginctl", &["show-user", &user, "--property=Linger"])
            .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
            .unwrap_or_default();
        if linger != "Linger=yes" {
            println!(
                "To keep the agent running when you are logged out, and to start it at boot, run:\n  loginctl enable-linger {user}"
            );
        }
    }
    #[cfg(target_os = "macos")]
    {
        let log = home()?.join("Library/Logs/codewire-host.log");
        std::fs::write(
            &path,
            launch_agent(LABEL, &executable, config_dir.as_deref(), &log),
        )?;
        // Replace a loaded copy, so an updated file takes effect.
        let _ = run("launchctl", &["bootout", &format!("{}/{LABEL}", domain())]);
        checked(
            "launchctl",
            &["bootstrap", &domain(), path.to_str().context("plist path")?],
        )?;
        println!("Wrote {} and started it.", path.display());
        println!("Logs: {}", log.display());
    }
    Ok(())
}

pub(crate) fn uninstall() -> anyhow::Result<()> {
    let path = service_file()?;
    if !ours(&path)? {
        println!("No host service is installed.");
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    {
        let _ = run("systemctl", &["--user", "disable", "--now", UNIT]);
        std::fs::remove_file(&path)?;
        let _ = run("systemctl", &["--user", "daemon-reload"]);
    }
    #[cfg(target_os = "macos")]
    {
        let _ = run("launchctl", &["bootout", &format!("{}/{LABEL}", domain())]);
        std::fs::remove_file(&path)?;
    }
    println!("Stopped the host service and removed {}.", path.display());
    Ok(())
}
