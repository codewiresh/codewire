//! The target `cw msg` and `cw steer` name: the environment, the session and
//! the text, read from [`AgentMessageArgs`] before any lookup.

use super::{AgentMessageArgs, trimmed_str};

/// What a message names before any lookup (#5085). The words after the
/// environment are the text, joined as `echo` joins its arguments, wherever
/// `--session` sits: `cw msg app --session lead just continue` sends "just
/// continue". Without `--session`, the session is chosen from what runs.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct MessageTarget<'a> {
    pub(crate) environment: Option<&'a str>,
    pub(crate) session: Option<&'a str>,
    pub(crate) text: String,
    /// One word and no `--in`: the text for the selected environment, unless
    /// it names an environment, when no text was given.
    pub(crate) lone_word: bool,
}

impl AgentMessageArgs {
    pub(crate) fn target(&self) -> MessageTarget<'_> {
        let session = self.session.as_deref().and_then(trimmed_str);
        let (environment, words) = match (
            self.in_environment.as_deref().and_then(trimmed_str),
            self.positionals.as_slice(),
        ) {
            (Some(environment), words) => (Some(environment), words),
            (None, [environment, words @ ..]) if !words.is_empty() => {
                (Some(environment.as_str()), words)
            }
            (None, words) => (None, words),
        };
        MessageTarget {
            environment,
            session,
            text: words.join(" "),
            lone_word: environment.is_none() && words.len() == 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use super::MessageTarget;
    use crate::{Cli, Command};

    fn target(argv: &[&str]) -> MessageTarget<'static> {
        let cli = Box::leak(Box::new(Cli::try_parse_from(argv).unwrap()));
        let Command::Msg(args) = &cli.command else {
            panic!("msg expected");
        };
        args.target()
    }

    #[test]
    fn the_words_after_the_environment_are_the_text_wherever_session_sits() {
        let expected = |environment, session, text: &str, lone_word| MessageTarget {
            environment,
            session,
            text: text.to_owned(),
            lone_word,
        };
        // The owner's session (#5085): unquoted words after --session.
        assert_eq!(
            target(&[
                "cw",
                "msg",
                "redteam-codex-handoff",
                "--session",
                "redteam",
                "just",
                "continue"
            ]),
            expected(
                Some("redteam-codex-handoff"),
                Some("redteam"),
                "just continue",
                false
            )
        );
        assert_eq!(
            target(&["cw", "msg", "app", "--session", "redteam", "just continue"]),
            expected(Some("app"), Some("redteam"), "just continue", false)
        );
        assert_eq!(
            target(&[
                "cw",
                "msg",
                "--session",
                "redteam",
                "app",
                "test",
                "and",
                "ignore"
            ]),
            expected(Some("app"), Some("redteam"), "test and ignore", false)
        );
        // No --session: chosen from what runs.
        assert_eq!(
            target(&["cw", "msg", "redteam-codex-handoff", "test"]),
            expected(Some("redteam-codex-handoff"), None, "test", false)
        );
        // --in names the environment, so every word is text.
        assert_eq!(
            target(&["cw", "msg", "--in", "app", "run", "the", "tests"]),
            expected(Some("app"), None, "run the tests", false)
        );
        // One word: the text, or an environment with nothing said yet.
        assert_eq!(
            target(&["cw", "msg", "continue"]),
            expected(None, None, "continue", true)
        );
        // Bare `cw msg` parses; it prints its usage, not clap's error.
        assert_eq!(target(&["cw", "msg"]), expected(None, None, "", false));
    }
}
