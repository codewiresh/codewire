//! `cw run COMMAND [ARG]...`: where cw's own options end and the command
//! begins.
//!
//! cw's options go before the command and everything after it belongs to
//! the command, so `--` is optional. Before clap parses, [`separate_command`]
//! finds the first word that is neither an option nor an option's value and
//! puts `--` in front of it, so `cw run npm test` parses exactly as
//! `cw run -- npm test` always has. `claude` and `codex` there are still the
//! agent positional, so `cw run claude --in app` keeps its meaning.
//!
//! An option of cw's after a command it separated, as in
//! `cw run npm test --in app`, is refused with the line that means it,
//! because passing it to the program silently would surprise as much as
//! taking it from the program would. `cw run -- npm test --in app` gives it
//! to the program.

use std::ffi::OsString;

use clap::CommandFactory as _;

/// Subcommands whose first plain word starts the command.
const RUNS: &[&str] = &["run"];
/// First words that are `cw run`'s agent positional, not a command.
const AGENTS: &[&str] = &["claude", "codex"];
/// cw's options that a program is unlikely to take: after a separated
/// command they are refused rather than passed on.
const MISPLACED: &[&str] = &[
    "--in", "--name", "--parent", "--detach", "--local", "--cloud",
];

/// `args` with `--` before a run's command, or the refusal of an option of
/// cw's written after the command. Anything else is returned unchanged for
/// clap to parse or refuse.
pub(crate) fn separate_command(args: Vec<OsString>) -> anyhow::Result<Vec<OsString>> {
    let root = crate::Cli::command();
    let Some((index, name)) = subcommand_at(&args, &root) else {
        return Ok(args);
    };
    if !RUNS.contains(&name.as_str()) {
        return Ok(args);
    }
    let Some(subcommand) = root.find_subcommand(&name) else {
        return Ok(args);
    };
    let options = Options::of(&root).and(subcommand);
    let Some(start) = first_word(&args, index + 1, &options) else {
        return Ok(args);
    };
    let first = args[start].to_string_lossy();
    if name == "run" && AGENTS.contains(&first.as_ref()) {
        return Ok(args);
    }
    if let Some(at) = (start..args.len())
        .take_while(|&at| args[at] != "--")
        .find(|&at| misplaced(&args[at]))
    {
        anyhow::bail!(misplaced_refusal(&args, start, at, &options));
    }
    let mut separated = args;
    separated.insert(start, OsString::from("--"));
    Ok(separated)
}

/// The index and name of the subcommand, after any root options.
fn subcommand_at(args: &[OsString], root: &clap::Command) -> Option<(usize, String)> {
    let options = Options::of(root);
    let at = first_word(args, 1, &options)?;
    Some((at, args[at].to_str()?.to_owned()))
}

/// The first word from `from` on that is not an option or an option's
/// value; `None` at `--`, at the end, or at an option clap does not know.
fn first_word(args: &[OsString], from: usize, options: &Options) -> Option<usize> {
    let mut at = from;
    while at < args.len() {
        let word = args[at].to_str()?;
        if word == "--" {
            return None;
        }
        if let Some(long) = word.strip_prefix("--") {
            if long.contains('=') {
                at += 1;
                continue;
            }
            let takes_value = options.long(long)?;
            at += if takes_value { 2 } else { 1 };
            continue;
        }
        if let Some(shorts) = word.strip_prefix('-').filter(|shorts| !shorts.is_empty()) {
            let mut value_follows = false;
            for (offset, short) in shorts.char_indices() {
                if options.short(short)? {
                    // The rest of the word is the value, or the next word is.
                    value_follows = offset + short.len_utf8() == shorts.len();
                    break;
                }
            }
            at += if value_follows { 2 } else { 1 };
            continue;
        }
        return Some(at);
    }
    None
}

fn misplaced(word: &OsString) -> bool {
    let word = word.to_string_lossy();
    let name = word.split('=').next().unwrap_or_default();
    MISPLACED.contains(&name)
}

/// The refusal naming the line that means it: the misplaced option, with
/// its value, moved in front of the command, or left out when the same
/// option is already there.
fn misplaced_refusal(args: &[OsString], start: usize, at: usize, options: &Options) -> String {
    let option = args[at].to_string_lossy().into_owned();
    let name = option.split('=').next().unwrap_or_default().to_owned();
    let takes_value = !option.contains('=')
        && options.long(name.trim_start_matches('-')).unwrap_or(false)
        && at + 1 < args.len();
    let moved_end = if takes_value { at + 2 } else { at + 1 };
    let word = |arg: &OsString| crate::commands::shell_word(&arg.to_string_lossy());
    let mut line: Vec<String> = std::iter::once("cw".to_owned())
        .chain(args[1..start].iter().map(word))
        .collect();
    let given = args[1..start]
        .iter()
        .any(|arg| arg.to_string_lossy().split('=').next() == Some(name.as_str()));
    if !given {
        line.extend(args[at..moved_end].iter().map(word));
    }
    line.extend(args[start..at].iter().map(word));
    line.extend(args[moved_end..].iter().map(word));
    let mut literal: Vec<String> = std::iter::once("cw".to_owned())
        .chain(args[1..start].iter().map(word))
        .collect();
    literal.push("--".to_owned());
    literal.extend(args[start..].iter().map(word));
    format!(
        "`{name}` goes before the command: `{}`. To give `{name}` to the program instead, put `--` before the command: `{}`",
        line.join(" "),
        literal.join(" ")
    )
}

/// The options clap knows at one level: whether each takes a value.
struct Options {
    longs: Vec<(String, bool)>,
    shorts: Vec<(char, bool)>,
}

impl Options {
    fn of(command: &clap::Command) -> Self {
        Self {
            longs: Vec::new(),
            shorts: Vec::new(),
        }
        .and(command)
    }

    fn and(mut self, command: &clap::Command) -> Self {
        for arg in command.get_arguments() {
            if arg.is_positional() {
                continue;
            }
            let takes_value = arg.get_action().takes_values();
            for long in arg.get_long_and_visible_aliases().into_iter().flatten() {
                self.longs.push((long.to_owned(), takes_value));
            }
            for short in arg.get_short_and_visible_aliases().into_iter().flatten() {
                self.shorts.push((short, takes_value));
            }
        }
        // clap adds these when it builds the command.
        self.longs.push(("help".to_owned(), false));
        self.shorts.push(('h', false));
        if command.get_version().is_some() {
            self.longs.push(("version".to_owned(), false));
            self.shorts.push(('V', false));
        }
        self
    }

    fn long(&self, name: &str) -> Option<bool> {
        self.longs
            .iter()
            .find(|(long, _)| long == name)
            .map(|(_, takes)| *takes)
    }

    fn short(&self, name: char) -> Option<bool> {
        self.shorts
            .iter()
            .find(|(short, _)| *short == name)
            .map(|(_, takes)| *takes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn separated(line: &str) -> Result<String, String> {
        let args: Vec<OsString> = line.split(' ').map(OsString::from).collect();
        separate_command(args)
            .map(|args| {
                args.iter()
                    .map(|arg| arg.to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .map_err(|error| error.to_string())
    }

    #[test]
    fn a_command_after_run_is_separated_from_cw_options() {
        for (line, expected) in [
            ("cw run npm test", "cw run -- npm test"),
            ("cw run --in app npm test", "cw run --in app -- npm test"),
            (
                "cw --local run -d -e K=V -w /src --name dev npm run dev",
                "cw --local run -d -e K=V -w /src --name dev -- npm run dev",
            ),
            ("cw run -eK=V -t make", "cw run -eK=V -t -- make"),
            ("cw run --in=app make -j8", "cw run --in=app -- make -j8"),
            (
                "cw -s https://cw.example run ls -la",
                "cw -s https://cw.example run -- ls -la",
            ),
            // A program's own options after the command are its own.
            ("cw run grep -e x -d", "cw run -- grep -e x -d"),
        ] {
            assert_eq!(separated(line).as_deref(), Ok(expected), "{line}");
        }
    }

    #[test]
    fn agents_explicit_separators_and_other_commands_are_left_to_clap() {
        for line in [
            "cw run claude --in app",
            "cw run codex --name review -- --full-auto",
            "cw run --in app -- npm test --in x",
            "cw run --agent claude --prompt fix",
            "cw run",
            "cw run --help",
            "cw ls app",
            "cw attach app --session lead",
            "cw run --unknown npm",
        ] {
            assert_eq!(separated(line).as_deref(), Ok(line), "{line}");
        }
    }

    #[test]
    fn an_option_of_cws_after_the_command_is_refused_with_the_line_that_means_it() {
        assert_eq!(
            separated("cw run npm test --in app").unwrap_err(),
            "`--in` goes before the command: `cw run --in app npm test`. To give `--in` to the program instead, put `--` before the command: `cw run -- npm test --in app`"
        );
        assert_eq!(
            separated("cw --local run make --name=dev build").unwrap_err(),
            "`--name` goes before the command: `cw --local run --name=dev make build`. To give `--name` to the program instead, put `--` before the command: `cw --local run -- make --name=dev build`"
        );
        // Already given before the command: the line leaves the copy out.
        assert!(
            separated("cw run --in r1 echo hi --in r1")
                .unwrap_err()
                .starts_with("`--in` goes before the command: `cw run --in r1 echo hi`.")
        );
        assert!(
            separated("cw run npm start --detach")
                .unwrap_err()
                .starts_with("`--detach` goes before the command: `cw run --detach npm start`")
        );
    }

    #[test]
    fn every_separated_line_parses_as_the_explicit_one() {
        use clap::Parser as _;
        let separated = separate_command(
            "cw run --in app npm test -x"
                .split(' ')
                .map(OsString::from)
                .collect(),
        )
        .unwrap();
        let cli = crate::Cli::try_parse_from(separated).unwrap();
        let crate::Command::Run(args) = cli.command else {
            panic!("not cw run");
        };
        assert_eq!(args.environment.as_deref(), Some("app"));
        assert_eq!(args.native_agent, None);
        assert_eq!(args.command, ["npm", "test", "-x"]);
    }
}
