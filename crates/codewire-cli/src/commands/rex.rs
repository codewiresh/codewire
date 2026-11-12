//! Codewire in Rex, Superlogical's terminal multiplexer.
//!
//! `cw setup rex` writes a Lua plugin beside Rex's config and a marked
//! section in its init.lua that loads it; the plugin's actions then show up
//! in Rex's command palette. `cw setup rex remove` takes both out again.
//!
//! An attachment inside a Rex pane reports its session to Rex with OSC 7501
//! program status records ([`RexStatus`]), which Rex shows with the pane and
//! the plugin reads to find the session a pane shows.

use std::ffi::OsString;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::Context as _;
use base64::Engine as _;

use super::{RexSetupArgs, RexSetupCommand};
use crate::config::{OsEnv, ResolvePaths};

/// The plugin, written to `plugins/codewire/init.lua` beside Rex's config.
const PLUGIN: &str = include_str!("rex/codewire.lua");
const BEGIN: &str = "-- >>> codewire >>>";
const END: &str = "-- <<< codewire <<<";

/// `cw setup rex` and `cw setup rex remove`: the result on stdout.
pub(crate) fn handle_setup_rex_command(args: RexSetupArgs) -> anyhow::Result<()> {
    let rex = rex_program(&|name| std::env::var_os(name))?;
    let files = RexFiles::resolve(&|name| std::env::var_os(name))?;
    let outcome = match args.command {
        Some(RexSetupCommand::Remove) => remove(&rex, &files)?,
        None => install(&rex, &files, &super::current_cw_executable()?)?,
    };
    let caps = crate::output::Capabilities::from_process(crate::output::OutputMode::Text);
    print!("{}", outcome.render(&files, caps.stdout_style()));
    Ok(())
}

/// Rex's config and where the plugin goes beside it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct RexFiles {
    config: PathBuf,
    plugin: PathBuf,
}

impl RexFiles {
    /// The config Rex reads: `REX_CONFIG`, else `rex/init.lua` in the
    /// configuration directory, as `rex config --help` describes.
    fn resolve(var: &dyn Fn(&str) -> Option<OsString>) -> anyhow::Result<Self> {
        let set = |name: &str| var(name).filter(|value| !value.is_empty());
        let config = if let Some(path) = set("REX_CONFIG") {
            PathBuf::from(path)
        } else if cfg!(windows) {
            PathBuf::from(
                set("APPDATA").context("APPDATA is not set, so Rex's config cannot be found")?,
            )
            .join("rex")
            .join("init.lua")
        } else if let Some(dir) = set("XDG_CONFIG_HOME") {
            PathBuf::from(dir).join("rex").join("init.lua")
        } else {
            PathBuf::from(set("HOME").context("HOME is not set, so Rex's config cannot be found")?)
                .join(".config")
                .join("rex")
                .join("init.lua")
        };
        let plugin = config
            .parent()
            .unwrap_or(Path::new("."))
            .join("plugins")
            .join("codewire")
            .join("init.lua");
        Ok(Self { config, plugin })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Change {
    Written,
    Unchanged,
    Removed,
    NothingToRemove,
}

#[derive(Debug)]
struct Outcome {
    change: Change,
    /// Why Rex did not reload its config, when it did not.
    not_reloaded: Option<String>,
}

impl Outcome {
    fn render(&self, files: &RexFiles, style: crate::output::Style) -> String {
        use crate::output::{Role, Status};
        let config = super::progress::terminal_text(&files.config.display().to_string());
        let plugin = super::progress::terminal_text(&files.plugin.display().to_string());
        let (status, headline, detail) = match self.change {
            Change::Written => (
                Status::Done,
                "Codewire is in Rex's command palette",
                format!("{config}{}loads {plugin}", style.separator()),
            ),
            Change::Unchanged => (
                Status::Done,
                "Codewire is already in Rex's command palette",
                format!("{config}{}loads {plugin}", style.separator()),
            ),
            Change::Removed => (
                Status::Done,
                "Removed Codewire from Rex's command palette",
                config.clone(),
            ),
            Change::NothingToRemove => (
                Status::Done,
                "Codewire was not in Rex's command palette",
                config.clone(),
            ),
        };
        let mut out = format!(
            "{} {headline}\n  {}\n",
            style.status(status),
            style.paint(Role::Dim, &detail)
        );
        if let Some(reason) = &self.not_reloaded {
            out.push_str(&format!(
                "{} Rex did not reload its config: {}\n  It takes effect when Rex next starts, or after `rex config reload`.\n",
                style.status(Status::Attention),
                super::progress::terminal_text(reason)
            ));
        }
        if matches!(self.change, Change::Written | Change::Unchanged) {
            out.push_str(&format!(
                "\n{} In Rex, open the command palette and type Codewire. Remove it with `cw setup rex remove`.\n",
                style.status(Status::Next)
            ));
        }
        out
    }
}

fn install(rex: &Path, files: &RexFiles, cw: &Path) -> anyhow::Result<Outcome> {
    let config = read_optional(&files.config)?;
    let plugin = read_optional(&files.plugin)?;
    let next = with_section(
        config.as_deref().unwrap_or_default(),
        Some(&loader(&files.plugin, cw, selected_environment().as_ref())?),
    )
    .map_err(|error| error.context(incomplete(&files.config, "cw setup rex")))?;
    if config.as_deref() == Some(next.as_str()) && plugin.as_deref() == Some(PLUGIN) {
        return Ok(Outcome {
            change: Change::Unchanged,
            not_reloaded: None,
        });
    }
    let path = files.config.to_string_lossy();
    let check = ["config", "check", &path];
    // A config Rex already refuses would refuse Codewire too, for its reasons.
    if config.is_some() {
        rex_run(rex, &check).map_err(|error| {
            error.context(format!(
                "Rex's config {} already has errors, so cw left it unchanged; fix them, then run `cw setup rex` again",
                files.config.display()
            ))
        })?;
    }
    replace(&files.plugin, PLUGIN)?;
    replace(&files.config, &next)?;
    if let Err(error) = rex_run(rex, &check) {
        match plugin.as_deref() {
            Some(plugin) => replace(&files.plugin, plugin)?,
            None => remove_plugin(files)?,
        }
        restore(&files.config, config.as_deref())?;
        return Err(error.context(format!(
            "Rex refused the config with Codewire in it, so {} was put back as it was",
            files.config.display()
        )));
    }
    Ok(Outcome {
        change: Change::Written,
        not_reloaded: reload(rex),
    })
}

/// Takes out only the managed section and the plugin; the rest of the config
/// is left as it is, so it is not checked again.
fn remove(rex: &Path, files: &RexFiles) -> anyhow::Result<Outcome> {
    let config = read_optional(&files.config)?;
    let next = match config.as_deref() {
        Some(config) => with_section(config, None)
            .map_err(|error| error.context(incomplete(&files.config, "cw setup rex remove")))?,
        None => String::new(),
    };
    let edited = config.as_deref().is_some_and(|config| config != next);
    if edited {
        replace(&files.config, &next)?;
    }
    let had_plugin = files.plugin.is_file();
    remove_plugin(files)?;
    if !edited && !had_plugin {
        return Ok(Outcome {
            change: Change::NothingToRemove,
            not_reloaded: None,
        });
    }
    Ok(Outcome {
        change: Change::Removed,
        not_reloaded: edited.then(|| reload(rex)).flatten(),
    })
}

/// Removes the plugin, and its folder and `plugins` when nothing else is in them.
fn remove_plugin(files: &RexFiles) -> anyhow::Result<()> {
    restore(&files.plugin, None)?;
    let folder = files.plugin.parent();
    for dir in [folder, folder.and_then(Path::parent)]
        .into_iter()
        .flatten()
    {
        let _ = fs::remove_dir(dir);
    }
    Ok(())
}

fn incomplete(config: &Path, rerun: &str) -> String {
    format!(
        "{} was not changed. Delete the leftover `{BEGIN}` or `{END}` line, then run `{rerun}` again",
        config.display()
    )
}

/// The managed section: it loads the plugin and gives it this `cw` and the
/// selected environment, whose line [`refresh_rex_selection`] rewrites.
fn loader(
    plugin: &Path,
    cw: &Path,
    environment: Option<&SelectedEnvironment>,
) -> anyhow::Result<String> {
    let text = |path: &Path| {
        path.to_str().map(lua_string).ok_or_else(|| {
            anyhow::anyhow!(
                "{} is not UTF-8, so Rex's config cannot name it",
                path.display()
            )
        })
    };
    Ok(format!(
        "{BEGIN}\n-- Managed by `cw setup rex`; `cw setup rex remove` takes it out.\ndofile({}).setup({{\n  cw = {},\n{}}})\n{END}\n",
        text(plugin)?,
        text(cw)?,
        environment_line(environment)
    ))
}

/// The environment `cw use` selected, as the plugin names it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct SelectedEnvironment {
    name: String,
    /// Where it runs, as an attachment reports it: `local VM`, `cloud` or `host`.
    location: &'static str,
}

fn selected_environment() -> Option<SelectedEnvironment> {
    use crate::config::selection::{self, SelectionLocation};
    let paths = ResolvePaths::from_env(&OsEnv).ok()?;
    let selection = selection::load(&paths.mesh_data_dir).ok()??;
    Some(SelectedEnvironment {
        name: selection.name,
        location: match selection.location {
            SelectionLocation::Local => "local VM",
            SelectionLocation::Cloud => "cloud",
            SelectionLocation::Host => "host",
        },
    })
}

const ENVIRONMENT: &str = "  environment = ";

fn environment_line(environment: Option<&SelectedEnvironment>) -> String {
    match environment {
        Some(environment) => format!(
            "{ENVIRONMENT}{{ name = {}, location = {} }},\n",
            lua_string(&environment.name),
            lua_string(environment.location)
        ),
        None => format!("{ENVIRONMENT}nil,\n"),
    }
}

/// `content` with the managed section's environment line replaced by
/// `line`; `None` without a section or such a line, as a section an older
/// `cw` wrote has none.
fn with_environment(content: &str, line: &str) -> Option<String> {
    let mut inside = false;
    let mut found = false;
    let mut out = String::with_capacity(content.len());
    for current in content.split_inclusive('\n') {
        match current.trim() {
            BEGIN => inside = true,
            END => inside = false,
            _ if inside && !found && current.starts_with(ENVIRONMENT) => {
                out.push_str(line);
                found = true;
                continue;
            }
            _ => {}
        }
        out.push_str(current);
    }
    found.then_some(out)
}

/// After the selection changes, names the new one in Rex's config and
/// reloads it, so the palette's Codewire actions follow it. Does nothing
/// unless `cw setup rex` added the section; a failure never fails the
/// command that changed the selection.
pub(crate) fn refresh_rex_selection() {
    let refreshed = (|| -> anyhow::Result<()> {
        let files = RexFiles::resolve(&|name| std::env::var_os(name))?;
        let Some(config) = read_optional(&files.config)? else {
            return Ok(());
        };
        let line = environment_line(selected_environment().as_ref());
        let Some(next) = with_environment(&config, &line) else {
            return Ok(());
        };
        if next != config {
            replace(&files.config, &next)?;
            let rex = rex_program(&|name| std::env::var_os(name))?;
            if let Some(reason) = reload(&rex) {
                tracing::debug!(reason, "Rex did not reload its config");
            }
        }
        Ok(())
    })();
    if let Err(error) = refreshed {
        tracing::debug!(error = %format!("{error:#}"), "Rex config not refreshed");
    }
}

/// `value` as a Lua string literal.
fn lua_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            c if c.is_ascii_control() => out.push_str(&format!("\\{:03}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// `content` with the managed section replaced by `section`, appended when
/// there is none, or taken out when `section` is `None`. Fails without a
/// change when a marker line has lost its partner or there are two sections.
fn with_section(content: &str, section: Option<&str>) -> anyhow::Result<String> {
    let lines: Vec<&str> = content.split_inclusive('\n').collect();
    let begins: Vec<usize> = (0..lines.len())
        .filter(|&i| lines[i].trim() == BEGIN)
        .collect();
    let ends: Vec<usize> = (0..lines.len())
        .filter(|&i| lines[i].trim() == END)
        .collect();
    match (begins.as_slice(), ends.as_slice()) {
        ([], []) => Ok(match section {
            None => content.to_owned(),
            Some(section) if content.trim().is_empty() => section.to_owned(),
            Some(section) => format!("{}\n\n{section}", content.trim_end_matches('\n')),
        }),
        ([begin], [end]) if begin < end => {
            let mut out: String = lines[..*begin].concat();
            let mut after: String = lines[end + 1..].concat();
            match section {
                Some(section) => out.push_str(section),
                // Without the section, the blank line that set it apart goes too.
                None if after.trim().is_empty() => {
                    out = out.trim_end_matches('\n').to_owned();
                    if !out.is_empty() {
                        out.push('\n');
                    }
                    after.clear();
                }
                None => {}
            }
            out.push_str(&after);
            Ok(out)
        }
        _ => anyhow::bail!(
            "the Codewire section of Rex's config is incomplete or repeated: each `{BEGIN}` line needs one `{END}` line after it"
        ),
    }
}

fn read_optional(path: &Path) -> anyhow::Result<Option<String>> {
    match fs::read(path) {
        Ok(bytes) => String::from_utf8(bytes).map(Some).map_err(|_| {
            anyhow::anyhow!(
                "{} is not UTF-8 text, so cw cannot edit it without changing it; it was not changed",
                path.display()
            )
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("read {}", path.display())),
    }
}

/// Replaces the file `path` leads to, so a config kept as a symlink, such as
/// one in a dotfiles repository, stays a link. The new text is written beside
/// it and renamed into place with the old file's permissions.
fn replace(path: &Path, content: &str) -> anyhow::Result<()> {
    let target = fs::canonicalize(path).unwrap_or_else(|_| path.to_owned());
    let dir = target
        .parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    let permissions = fs::metadata(&target)
        .ok()
        .map(|metadata| metadata.permissions());
    let name = target
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let staged = dir.join(format!(".{name}.cw-{}", std::process::id()));
    let written = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staged)?;
        file.write_all(content.as_bytes())?;
        if let Some(permissions) = permissions {
            file.set_permissions(permissions)?;
        }
        file.sync_all()?;
        fs::rename(&staged, &target)
    })();
    if let Err(error) = written {
        let _ = fs::remove_file(&staged);
        return Err(error).with_context(|| format!("replace {}", target.display()));
    }
    Ok(())
}

/// Puts back what `path` held before, or removes what was not there.
fn restore(path: &Path, previous: Option<&str>) -> anyhow::Result<()> {
    match previous {
        Some(previous) => replace(path, previous),
        None => match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).with_context(|| format!("remove {}", path.display())),
        },
    }
}

/// Asks the running Rex server to read its config again; why it did not, if
/// it did not. A server that isn't running reads it when it starts.
fn reload(rex: &Path) -> Option<String> {
    rex_run(rex, &["config", "reload"])
        .err()
        .map(|error| format!("{error:#}"))
}

/// Runs `rex` with `args`, never starting a server; the error is what it said.
fn rex_run(rex: &Path, args: &[&str]) -> anyhow::Result<()> {
    let output = Command::new(rex)
        .arg("--autostart=false")
        .args(args)
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("run {}", rex.display()))?;
    if output.status.success() {
        return Ok(());
    }
    // `rex config check` reports each complaint on stdout as `error: ...`
    // and only a summary on stderr.
    let stdout = String::from_utf8_lossy(&output.stdout);
    let complaints = stdout
        .lines()
        .filter(|line| line.starts_with("error:"))
        .map(|line| line.trim_start_matches("error:").trim());
    let stderr = String::from_utf8_lossy(&output.stderr);
    let said: Vec<&str> = complaints
        .chain(
            stderr
                .lines()
                .map(|line| line.trim_start_matches("Error:").trim()),
        )
        .filter(|line| !line.is_empty())
        .collect();
    anyhow::bail!("rex {} failed: {}", args.join(" "), said.join("; "))
}

/// The `rex` program: on `PATH`, in `REX_BIN_DIR` (set in Rex's panes), or
/// where the Mac app keeps it.
fn rex_program(var: &dyn Fn(&str) -> Option<OsString>) -> anyhow::Result<PathBuf> {
    let name = format!("rex{}", std::env::consts::EXE_SUFFIX);
    let mut candidates = Vec::new();
    if let Some(dir) = var("REX_BIN_DIR").filter(|dir| !dir.is_empty()) {
        candidates.push(PathBuf::from(dir).join(&name));
    }
    if let Some(paths) = var("PATH") {
        candidates.extend(std::env::split_paths(&paths).map(|dir| dir.join(&name)));
    }
    // The Mac app's own copies; elsewhere these paths do not exist.
    if let Some(home) = var("HOME") {
        candidates.push(PathBuf::from(home).join(
            "Library/Application Support/com.superlogical.rex/RexServer/Versions/Current/Rex Server.app/Contents/MacOS/rex",
        ));
    }
    for app in ["Rex", "Rex Beta"] {
        candidates.push(PathBuf::from(format!(
            "/Applications/{app}.app/Contents/Helpers/Rex Server.rex/Contents/MacOS/rex"
        )));
    }
    candidates
        .into_iter()
        .find(|candidate| candidate.is_absolute() && candidate.is_file())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Rex isn't installed here: no `rex` on PATH. Install Rex from superlogical.com, then run `cw setup rex` again"
            )
        })
}

/// What an attachment says about its session to the Rex pane it runs in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RexState {
    /// Attached to a running session.
    Attached,
    /// The connection was lost; cw is reconnecting.
    Reconnecting,
    /// The session exited with status 0.
    Done,
    /// The session failed or exited with another status.
    Failed,
}

/// Reports the attached session to Rex as the program status record
/// `codewire/session`, whose title is ENV/SESSION; while attached, its
/// message is where the environment runs (`local VM`, `cloud` or `host`).
/// Outside Rex, or when stdout is not a terminal, it writes nothing. Dropping
/// it withdraws the record, so a pane cw has left shows no session.
pub(crate) struct RexStatus {
    title: String,
    enabled: bool,
    reported: bool,
}

impl RexStatus {
    pub(crate) fn new(environment: &str, session: &str) -> Self {
        use std::io::IsTerminal as _;
        let inside = std::env::var_os("REX_SESSION").is_some_and(|session| !session.is_empty());
        Self {
            title: format!("{environment}/{session}"),
            enabled: inside && std::io::stdout().is_terminal(),
            reported: false,
        }
    }

    /// Reports another session, such as after switching to the next one.
    pub(crate) fn retitle(&mut self, environment: &str, session: &str) {
        self.title = format!("{environment}/{session}");
    }

    pub(crate) fn report(&mut self, state: RexState, message: &str) {
        if self.enabled {
            emit(&status_record(state, &self.title, message));
            self.reported = true;
        }
    }

    /// Reports how the session ended and leaves that in the pane.
    pub(crate) fn finish(mut self, state: RexState, message: &str) {
        self.report(state, message);
        self.reported = false;
    }
}

impl Drop for RexStatus {
    fn drop(&mut self) {
        if self.reported {
            emit(WITHDRAWAL);
        }
    }
}

const RECORD: &str = "codewire/session";
const WITHDRAWAL: &str = "\x1b]7501;id=codewire/session:state=clear\x1b\\";

/// One OSC 7501 report. Title and message are base64, as Rex reads them, and
/// cut short: Rex shows one line of each.
fn status_record(state: RexState, title: &str, message: &str) -> String {
    let state = match state {
        RexState::Attached => "idle",
        RexState::Reconnecting => "working",
        RexState::Done => "done",
        RexState::Failed => "error",
    };
    let encode = |text: &str| {
        let text: String = text.chars().filter(|c| !c.is_control()).take(180).collect();
        base64::engine::general_purpose::STANDARD.encode(text)
    };
    let mut record = format!(
        "\x1b]7501;id={RECORD}:state={state}:app=cw:title={}",
        encode(title)
    );
    if !message.is_empty() {
        record.push_str(&format!(":msg={}", encode(message)));
    }
    record.push_str("\x1b\\");
    record
}

fn emit(sequence: &str) {
    let mut stdout = std::io::stdout();
    let _ = stdout.write_all(sequence.as_bytes());
    let _ = stdout.flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> {
        let pairs: Vec<(String, OsString)> = pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), OsString::from(value)))
            .collect();
        move |name| {
            pairs
                .iter()
                .find(|(candidate, _)| candidate == name)
                .map(|(_, value)| value.clone())
        }
    }

    #[cfg(unix)]
    #[test]
    fn rex_config_follows_rex_config_then_xdg_then_home() {
        let named = RexFiles::resolve(&vars(&[
            ("REX_CONFIG", "/etc/rex/mine.lua"),
            ("HOME", "/home/u"),
        ]))
        .unwrap();
        assert_eq!(named.config, PathBuf::from("/etc/rex/mine.lua"));
        assert_eq!(
            named.plugin,
            PathBuf::from("/etc/rex/plugins/codewire/init.lua")
        );
        let xdg = RexFiles::resolve(&vars(&[
            ("REX_CONFIG", ""),
            ("XDG_CONFIG_HOME", "/home/u/.cfg"),
            ("HOME", "/home/u"),
        ]))
        .unwrap();
        assert_eq!(xdg.config, PathBuf::from("/home/u/.cfg/rex/init.lua"));
        let home = RexFiles::resolve(&vars(&[("HOME", "/home/u")])).unwrap();
        assert_eq!(home.config, PathBuf::from("/home/u/.config/rex/init.lua"));
        assert!(RexFiles::resolve(&vars(&[])).is_err());
    }

    #[test]
    fn a_section_is_appended_replaced_and_removed_keeping_the_rest() {
        let own = "rex.bind(\"cmd+b\", \"client.sidebar.toggle\")\n";
        let first = with_section(own, Some(&format!("{BEGIN}\nold\n{END}\n"))).unwrap();
        assert_eq!(first, format!("{own}\n{BEGIN}\nold\n{END}\n"));
        let replaced = with_section(&first, Some(&format!("{BEGIN}\nnew\n{END}\n"))).unwrap();
        assert_eq!(replaced, format!("{own}\n{BEGIN}\nnew\n{END}\n"));
        assert_eq!(with_section(&replaced, None).unwrap(), own);
        assert_eq!(with_section(own, None).unwrap(), own);
        let middle = format!("a\n{BEGIN}\nx\n{END}\nb\n");
        assert_eq!(with_section(&middle, None).unwrap(), "a\nb\n");
        let only = format!("{BEGIN}\nx\n{END}\n");
        assert_eq!(with_section("", Some(&only)).unwrap(), only);
        assert_eq!(with_section(&only, None).unwrap(), "");
    }

    #[test]
    fn a_broken_or_repeated_section_is_refused() {
        assert!(with_section(&format!("a\n{BEGIN}\nx\n"), None).is_err());
        assert!(with_section(&format!("{END}\nx\n{BEGIN}\n"), Some("s")).is_err());
        let twice = format!("{BEGIN}\n{END}\n{BEGIN}\n{END}\n");
        assert!(with_section(&twice, Some("s")).is_err());
    }

    #[test]
    fn the_loader_names_the_plugin_cw_and_environment_as_lua_strings() {
        let app = SelectedEnvironment {
            name: "app".into(),
            location: "local VM",
        };
        let loader = loader(
            Path::new("/home/u/.config/rex/plugins/codewire/init.lua"),
            Path::new("/opt/My \"tools\"\\cw"),
            Some(&app),
        )
        .unwrap();
        assert_eq!(
            loader,
            format!(
                "{BEGIN}\n-- Managed by `cw setup rex`; `cw setup rex remove` takes it out.\ndofile(\"/home/u/.config/rex/plugins/codewire/init.lua\").setup({{\n  cw = \"/opt/My \\\"tools\\\"\\\\cw\",\n  environment = {{ name = \"app\", location = \"local VM\" }},\n}})\n{END}\n"
            )
        );
        assert_eq!(lua_string("a\nb"), "\"a\\010b\"");
    }

    #[test]
    fn a_refresh_rewrites_only_the_environment_line_of_the_section() {
        let plugin = Path::new("/p/init.lua");
        let none = loader(plugin, Path::new("/bin/cw"), None).unwrap();
        assert!(none.contains("\n  environment = nil,\n"));
        let own = "  environment = \"mine\"\n";
        let config = format!("{own}\n{none}{own}");
        let review = SelectedEnvironment {
            name: "review".into(),
            location: "cloud",
        };
        let line = environment_line(Some(&review));
        let next = with_environment(&config, &line).unwrap();
        let expected = loader(plugin, Path::new("/bin/cw"), Some(&review)).unwrap();
        assert_eq!(next, format!("{own}\n{expected}{own}"));
        assert_eq!(with_environment(&next, &line).unwrap(), next);
        // An older section, or none at all, is left for `cw setup rex`.
        let old = format!("{BEGIN}\ndofile(\"/p\").setup({{ cw = \"/bin/cw\" }})\n{END}\n");
        assert_eq!(with_environment(&old, &line), None);
        assert_eq!(with_environment(own, &line), None);
    }

    #[test]
    fn a_status_record_is_osc_7501_with_base64_text() {
        let record = status_record(RexState::Attached, "app/lead", "");
        assert_eq!(
            record,
            "\x1b]7501;id=codewire/session:state=idle:app=cw:title=YXBwL2xlYWQ=\x1b\\"
        );
        let failed = status_record(RexState::Failed, "app/tests", "exited with status 2");
        assert!(failed.contains(":state=error:"));
        assert!(failed.ends_with(":msg=ZXhpdGVkIHdpdGggc3RhdHVzIDI=\x1b\\"));
        let noisy = status_record(RexState::Done, "a\x1b]0;x\x07/b", "");
        assert!(!noisy[2..noisy.len() - 2].contains('\x1b'));
    }

    #[test]
    fn the_plugin_defines_its_actions_and_reads_the_status_record() {
        for action in [
            "codewire_run",
            "codewire_shell",
            "codewire_attach",
            "codewire_use",
            "codewire_msg",
        ] {
            assert!(PLUGIN.contains(&format!("name = \"{action}\"")), "{action}");
        }
        assert!(PLUGIN.contains(&format!("local RECORD = \"{RECORD}\"")));
    }
}
