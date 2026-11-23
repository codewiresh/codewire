//! `--env` entries (#5222). `cw run` and `cw exec` take `KEY=VALUE`, or
//! `KEY` alone, which sends the value `KEY` has in `cw`'s own environment, so
//! a secret stays out of `cw`'s arguments. `cw create` and `cw init` save
//! the variables in an environment's settings, so they take `KEY=VALUE` only.
//!
//! No error here shows a value. An entry without `=` is named only once it
//! has a variable name's shape, so a value given without its `KEY=` is never
//! echoed back.

use std::collections::BTreeMap;

use crate::config::Env;
use crate::error_report::with_next_step;

use super::trimmed_required;

/// The variables `--env` sets for one `cw run` or `cw exec`. `env` is `cw`'s
/// own environment ([`crate::config::OsEnv`]) outside tests.
pub(crate) fn parse_env_overrides(
    entries: &[String],
    env: &impl Env,
) -> anyhow::Result<BTreeMap<String, String>> {
    let mut parsed = BTreeMap::new();
    for entry in entries {
        let entry = trimmed_required(entry, "environment override")?;
        let (key, value) = match entry.split_once('=') {
            Some((key, value)) => (
                trimmed_required(key, "environment override key")?,
                value.to_owned(),
            ),
            None => (entry, inherited_value(entry, env)?),
        };
        parsed.insert(key.to_owned(), value);
    }
    Ok(parsed)
}

/// The variables `--env` saves in an environment's settings, for `command`
/// (`cw create` or `cw init`). A setting is stored where its value can be
/// read back, so `KEY` alone is refused and a secret is sent to `cw secrets`.
pub(crate) fn parse_env_settings(
    entries: &[String],
    command: &str,
) -> anyhow::Result<BTreeMap<String, String>> {
    let mut parsed = BTreeMap::new();
    for entry in entries {
        let entry = trimmed_required(entry, "environment override")?;
        let Some((key, value)) = entry.split_once('=') else {
            return Err(with_next_step(
                anyhow::anyhow!(
                    "`{command} --env` needs KEY=VALUE, since it saves a plain variable in the environment's settings; keep a secret with `cw secrets`"
                ),
                "cw secrets set",
            ));
        };
        let key = trimmed_required(key, "environment override key")?;
        parsed.insert(key.to_owned(), value.to_owned());
    }
    Ok(parsed)
}

fn inherited_value(key: &str, env: &impl Env) -> anyhow::Result<String> {
    anyhow::ensure!(
        is_variable_name(key),
        "--env takes KEY=VALUE, or KEY alone, the name of a variable set where cw runs"
    );
    match env.checked_var(key) {
        Ok(Some(value)) => Ok(value),
        Ok(None) => Err(with_next_step(
            anyhow::anyhow!("the variable {key} isn't set, so `--env {key}` has nothing to send"),
            format!("export {key}=VALUE"),
        )),
        // The error holds the value; it is dropped unread.
        Err(_) => {
            anyhow::bail!("the variable {key} isn't UTF-8 text, so `--env {key}` can't send it")
        }
    }
}

/// A POSIX shell variable name: a letter or `_`, then letters, digits or `_`.
fn is_variable_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::MapEnv;

    const CANARY: &str = "synthetic-bearer-do-not-render";

    fn entries(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    /// The whole error as the printer sees it: chain and next step.
    fn rendered(error: &anyhow::Error) -> String {
        format!(
            "{error:#} {}",
            crate::error_report::next_step(error).unwrap_or_default()
        )
    }

    #[test]
    fn key_value_entries_are_sent_as_given() {
        let parsed = parse_env_overrides(
            &entries(&["FOO=bar", "EMPTY=", "URL=a=b"]),
            &MapEnv::new([("FOO", "from-cw")]),
        )
        .unwrap();
        assert_eq!(parsed.get("FOO").map(String::as_str), Some("bar"));
        assert_eq!(parsed.get("EMPTY").map(String::as_str), Some(""));
        assert_eq!(parsed.get("URL").map(String::as_str), Some("a=b"));
    }

    #[test]
    fn a_key_alone_sends_the_value_it_has_in_cws_environment() {
        let env = MapEnv::new([("WALK_TOKEN", CANARY), ("EMPTY", ""), ("_x1", "y")]);
        let parsed =
            parse_env_overrides(&entries(&["WALK_TOKEN", " EMPTY ", "_x1"]), &env).unwrap();
        assert_eq!(parsed.get("WALK_TOKEN").map(String::as_str), Some(CANARY));
        assert_eq!(parsed.get("EMPTY").map(String::as_str), Some(""));
        assert_eq!(parsed.get("_x1").map(String::as_str), Some("y"));
    }

    #[test]
    fn an_unset_key_is_refused_by_its_name_and_never_sent_empty() {
        let env = MapEnv::new([("OTHER", CANARY)]);
        let error = parse_env_overrides(&entries(&["OTHER", "WALK_TOKEN"]), &env).unwrap_err();
        assert_eq!(
            crate::error_report::sentence(&error),
            "the variable WALK_TOKEN isn't set, so `--env WALK_TOKEN` has nothing to send"
        );
        assert_eq!(
            crate::error_report::next_step(&error).as_deref(),
            Some("export WALK_TOKEN=VALUE")
        );
        assert!(!rendered(&error).contains(CANARY));
    }

    #[test]
    fn a_value_that_is_not_utf8_is_refused_without_showing_it() {
        struct NotUnicode;
        impl Env for NotUnicode {
            fn var(&self, _: &str) -> Option<String> {
                None
            }
            fn checked_var(&self, _: &str) -> Result<Option<String>, std::env::VarError> {
                Err(std::env::VarError::NotUnicode(CANARY.into()))
            }
        }
        let error = parse_env_overrides(&entries(&["WALK_TOKEN"]), &NotUnicode).unwrap_err();
        assert_eq!(
            crate::error_report::sentence(&error),
            "the variable WALK_TOKEN isn't UTF-8 text, so `--env WALK_TOKEN` can't send it"
        );
        assert!(!rendered(&error).contains(CANARY));
    }

    /// A value given without its `KEY=` is not a name, and is not echoed.
    #[test]
    fn an_entry_that_is_no_name_is_refused_without_showing_it() {
        let env = MapEnv::new([(CANARY, "set")]);
        for entry in [CANARY, "1KEY", "KEY NAME", "kéy"] {
            let error = parse_env_overrides(&entries(&[entry]), &env).unwrap_err();
            assert_eq!(
                crate::error_report::sentence(&error),
                "--env takes KEY=VALUE, or KEY alone, the name of a variable set where cw runs",
                "{entry}"
            );
            assert!(!rendered(&error).contains(entry), "{entry}");
        }
    }

    #[test]
    fn create_and_init_save_key_value_entries_and_refuse_a_key_alone() {
        let parsed = parse_env_settings(&entries(&["FOO=bar", "EMPTY="]), "cw create").unwrap();
        assert_eq!(parsed.get("FOO").map(String::as_str), Some("bar"));
        assert_eq!(parsed.get("EMPTY").map(String::as_str), Some(""));

        for command in ["cw create", "cw init"] {
            let error = parse_env_settings(&entries(&["FOO=bar", CANARY]), command).unwrap_err();
            assert_eq!(
                crate::error_report::sentence(&error),
                format!(
                    "`{command} --env` needs KEY=VALUE, since it saves a plain variable in the environment's settings; keep a secret with `cw secrets`"
                )
            );
            assert_eq!(
                crate::error_report::next_step(&error).as_deref(),
                Some("cw secrets set")
            );
            assert!(!rendered(&error).contains(CANARY));
        }
    }
}
