//! What is said when a container of a sandbox could not start (#4483): one
//! short sentence for the user, and the runtime's own text for operators.
//!
//! The sentence is built only from fixed words and a few checked values: the
//! container's name, the image the create asked for, a reason from a known
//! list, an exit code and an HTTP status from a known list. Nothing from the
//! runtime's message is copied into it, so it cannot carry escaped or nested
//! runtime output, or a secret the runtime quoted. A message that matches no
//! known cause gets the general sentence: a wrong guess is worse than none.
//!
//! The runtime's message goes only to the server's log, through [`scrub`].
//! It is stored in no column and returned by no API.

use crate::sandbox::client::ContainerStartFailed;

/// The most characters of runtime text one log line carries.
pub(crate) const LOG_TEXT_MAX_CHARS: usize = 4_000;
/// The most characters of runtime text [`scrub`] is given. A message is
/// partly written by a registry its user chose, so the work is bounded
/// before it starts. It is more than a log line carries because removing a
/// long value brings later text forward.
const SCRUB_INPUT_MAX_CHARS: usize = 4 * LOG_TEXT_MAX_CHARS;
/// Ends log text that was cut at [`LOG_TEXT_MAX_CHARS`].
pub(crate) const LOG_TEXT_TRUNCATED: &str = "… (truncated)";
/// The most characters of an image or container name the sentence shows.
const NAME_MAX_CHARS: usize = 200;
/// Stands in for a value [`scrub`] removed.
const REDACTED: &str = "[redacted]";

/// The reasons the sentence repeats. Any other reads `other`.
const KNOWN_REASONS: &[&str] = &[
    "ErrImagePull",
    "ImagePullBackOff",
    "InvalidImageName",
    "CreateContainerConfigError",
    "CreateContainerError",
    "RunContainerError",
    "CrashLoopBackOff",
    "StartError",
    "ContainerCannotRun",
    "Error",
    "OOMKilled",
    "DeadlineExceeded",
    "Evicted",
    "NodeShutdown",
    "NodeAffinity",
    "Preempting",
    "Shutdown",
    "Terminated",
    "UnexpectedAdmissionError",
];

/// The HTTP statuses the sentence repeats, with the words that follow each
/// in a registry client's message.
const KNOWN_HTTP_STATUSES: &[(u16, &str)] = &[
    (401, "unauthorized"),
    (403, "forbidden"),
    (404, "not found"),
    (429, "too many requests"),
    (500, "internal server error"),
    (502, "bad gateway"),
    (503, "service unavailable"),
    (504, "gateway timeout"),
];

/// The sentence for the user: what failed, why where it is recognised, and
/// what to do next.
pub(crate) fn summary(failure: &ContainerStartFailed) -> String {
    let container = shown(&failure.container);
    let image = shown_image(&failure.image);
    let reason = known_reason(&failure.reason);
    let message = failure.message.to_ascii_lowercase();
    let says = |needles: &[&str]| needles.iter().any(|needle| message.contains(needle));
    match failure.reason.as_str() {
        "ErrImagePull" | "ImagePullBackOff" => {
            let subject = if image.is_empty() {
                "The image could not be pulled".to_owned()
            } else {
                format!("The image `{image}` could not be pulled")
            };
            let status = http_status(&message);
            let told = status.map_or_else(String::new, |status| format!(" (HTTP {status})"));
            let (cause, next) = if matches!(status, Some(401 | 403))
                || says(&[
                    "unauthorized",
                    "access denied",
                    "denied:",
                    "authentication required",
                ]) {
                (
                    ": access denied",
                    "Check the image name and who may pull it.",
                )
            } else if status == Some(429) {
                (": its registry is limiting requests", "Try again later.")
            } else if matches!(status, Some(500..=599)) {
                (": its registry answered with an error", "Try again later.")
            } else if says(&[
                "no such host",
                "i/o timeout",
                "connection refused",
                "network is unreachable",
            ]) {
                (
                    ": its registry could not be reached",
                    "Check the registry's address.",
                )
            } else if status == Some(404) || says(&["not found", "manifest unknown"]) {
                (": not found", "Check the image name and tag.")
            } else {
                ("", "Check the image name and tag.")
            };
            format!("{subject}{cause}{told}. {next}")
        }
        "InvalidImageName" if image.is_empty() => {
            "The image name is not valid. Check the image name.".to_owned()
        }
        "InvalidImageName" => {
            format!("The image name `{image}` is not valid. Check the image name.")
        }
        "CreateContainerConfigError" | "CreateContainerError" | "RunContainerError" => format!(
            "The container `{container}` could not be created ({reason}). Try again; if it keeps failing, contact support."
        ),
        "CrashLoopBackOff" => match failure.exit_code {
            Some(code) => format!(
                "The container `{container}` keeps exiting right after it starts (exit code {code}). Check the image's command."
            ),
            None => format!(
                "The container `{container}` keeps exiting right after it starts. Check the image's command."
            ),
        },
        // A Pod that was over before its claim was ready names no container.
        _ if failure.exit_code.is_none() && failure.image.is_empty() => {
            format!("The sandbox stopped before it was ready ({reason}). Try again.")
        }
        _ => {
            if says(&["no space left on device"]) {
                return format!(
                    "The container `{container}` could not start: its node is out of disk space. Try again."
                );
            }
            if says(&["executable file not found"])
                || (says(&["exec"]) && says(&["no such file or directory", ": not found"]))
            {
                return format!(
                    "The container `{container}` could not start: its command was not found in the image. Check the image's command."
                );
            }
            match failure.exit_code {
                Some(code) => format!(
                    "The container `{container}` could not start ({reason}, exit code {code}). Try again."
                ),
                None => {
                    format!("The container `{container}` could not start ({reason}). Try again.")
                }
            }
        }
    }
}

/// Writes the runtime's own reason and message to the server's log, for an
/// operator who wants to dig. This line is the only place they go.
pub(super) fn log(env_id: &str, failure: &ContainerStartFailed) {
    tracing::warn!(
        environment_id = env_id,
        container = %shown(&failure.container),
        runtime = %log_text(failure),
        "environment.create container could not start"
    );
}

/// The runtime's reason and message as [`log`] writes them: scrubbed of
/// anything shaped like a secret, and cut at [`LOG_TEXT_MAX_CHARS`]
/// characters with [`LOG_TEXT_TRUNCATED`] at the end.
pub(crate) fn log_text(failure: &ContainerStartFailed) -> String {
    let text = if failure.message.trim().is_empty() {
        failure.reason.clone()
    } else {
        format!("{}: {}", failure.reason, failure.message.trim())
    };
    let scrubbed = scrub(bounded_input(&text));
    if scrubbed.chars().count() <= LOG_TEXT_MAX_CHARS {
        return scrubbed;
    }
    let kept = LOG_TEXT_MAX_CHARS - LOG_TEXT_TRUNCATED.chars().count();
    let mut cut: String = scrubbed.chars().take(kept).collect();
    cut.push_str(LOG_TEXT_TRUNCATED);
    cut
}

/// `text` cut at [`SCRUB_INPUT_MAX_CHARS`] characters and then back to the
/// end of its last whole word, so that [`scrub`] never judges half a token.
fn bounded_input(text: &str) -> &str {
    let Some((cut, _)) = text.char_indices().nth(SCRUB_INPUT_MAX_CHARS) else {
        return text;
    };
    let kept = &text[..cut];
    &kept[..kept.rfind(char::is_whitespace).unwrap_or(0)]
}

/// The metadata of the log row that ends a wait: `meta`, with a `kind` when
/// the wait ended because a container could not start. A client reads `kind`
/// to name the stage for what failed, the sandbox's start, whichever wait
/// happened to see it.
pub(super) fn log_meta(
    error: &anyhow::Error,
    meta: Option<serde_json::Value>,
) -> Option<serde_json::Value> {
    if super::container_start_failure(error).is_none() {
        return meta;
    }
    let mut meta = meta.unwrap_or_else(|| serde_json::json!({}));
    if let Some(fields) = meta.as_object_mut() {
        fields.insert(
            "kind".to_owned(),
            crate::lifecycle::CONTAINER_START_FAILED_ERROR_CODE.into(),
        );
    }
    Some(meta)
}

/// A name as the sentence shows it: no control characters and no backticks,
/// which would end the quoting, and bounded.
fn shown(name: &str) -> String {
    name.chars()
        .filter(|c| !c.is_control() && *c != '`')
        .take(NAME_MAX_CHARS)
        .collect()
}

/// An image reference as the sentence shows it, or nothing when it is longer
/// than [`NAME_MAX_CHARS`] or holds a character no image reference has.
fn shown_image(image: &str) -> &str {
    let fits = image.len() <= NAME_MAX_CHARS
        && image
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/' | ':' | '@'));
    if fits { image } else { "" }
}

/// `reason` when it is one of [`KNOWN_REASONS`], else `other`.
fn known_reason(reason: &str) -> &'static str {
    KNOWN_REASONS
        .iter()
        .find(|known| **known == reason)
        .copied()
        .unwrap_or("other")
}

/// The first of [`KNOWN_HTTP_STATUSES`] that `message`, in lower case, names
/// as a status: `401 unauthorized` or `status code 401`.
fn http_status(message: &str) -> Option<u16> {
    KNOWN_HTTP_STATUSES
        .iter()
        .find(|(status, words)| {
            message.contains(&format!("{status} {words}"))
                || message.contains(&format!("status code {status}"))
                || message.contains(&format!("status: {status}"))
        })
        .map(|(status, _)| *status)
}

/// Words in a key that mark its value as a secret.
const SECRET_KEY_WORDS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "_key",
    "-key",
    "authorization",
    "credential",
    "signature",
    "cookie",
];
/// Endings of a key that mark its value as a secret, such as the
/// `X-Registry-Auth` header. As a part of a word they would catch
/// `www-authenticate`.
const SECRET_KEY_ENDINGS: &[&str] = &["-auth", "_auth"];
/// Whole keys that mark their value as a secret. `auth` is the credential of
/// a registry configuration; as a part of a word it would catch `author`.
const SECRET_KEYS: &[&str] = &["auth", "pass", "pwd", "pat", "key"];
/// How well-known kinds of token begin.
const TOKEN_PREFIXES: &[&str] = &[
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "github_pat_",
    "glpat-",
    "sk_live_",
    "rk_live_",
    "xoxb-",
    "xoxp-",
    "AKIA",
];
/// The characters [`scrub`] reads as punctuation between keys and values.
const MARKS: &[char] = &[
    '=', ':', '"', '\'', '\\', '[', '{', '(', ']', '}', ')', ',', '&', ';',
];

/// Removes what is shaped like a secret from runtime text before it is
/// logged. A container runtime's message can quote a registry request or a
/// configuration, so it can carry what they carried:
///
/// - a PEM block;
/// - the user and password of a URL (`https://user:pass@host`), or of a host
///   written without a scheme after a colon (`user:pass@host`);
/// - a URL's query string, where registries put signed download tokens;
/// - the value after `Bearer` or `Basic`;
/// - the value of a key whose name says it is a secret, however the pair is
///   written: `token=…`, `"password": "…"`, `Authorization:[Bearer …]`,
///   `--password …`, alone or among other pairs;
/// - a word that is itself a token: a JWT, or one with a well-known prefix.
///
/// It keeps the text around each removed value, so the message still reads.
/// It is a second guard, not the only one: this text reaches operators only.
pub(crate) fn scrub(text: &str) -> String {
    let text = scrub_pem(text);
    let text: String = split_keeping_whitespace(&text).map(scrub_url).collect();
    let tokens = tokens(&text);
    let mut out = String::with_capacity(text.len());
    // The word a following `=` or `:` would make a key.
    let mut key: Option<&str> = None;
    let mut awaiting = Awaiting::Nothing;
    // The quote that opened the awaited value.
    let mut quote: Option<char> = None;
    // The awaited value is an `Authorization` header's: a scheme this
    // function does not know, then the credential.
    let mut two_words = false;
    let mut after_colon = false;
    let mut at = 0;
    while let Some(token) = tokens.get(at).copied() {
        at += 1;
        let was_after_colon = std::mem::take(&mut after_colon);
        match (awaiting, token) {
            (_, Token::Space(space)) => {
                out.push_str(space);
                key = None;
            }
            (Awaiting::Nothing, Token::Mark(mark)) => {
                out.push(mark);
                match mark {
                    '=' | ':' => {
                        if let Some(key) = key.filter(|key| names_a_secret(key)) {
                            awaiting = Awaiting::Value;
                            quote = None;
                            two_words = key.to_ascii_lowercase().contains("authorization");
                        }
                        key = None;
                        after_colon = mark == ':';
                    }
                    // A quoted key is still the key: `"password":`.
                    '"' | '\'' | '\\' => {}
                    _ => key = None,
                }
            }
            (Awaiting::Nothing, Token::Atom(atom)) => {
                key = None;
                if is_scheme(atom) {
                    out.push_str(atom);
                    awaiting = Awaiting::SchemeValue;
                    quote = None;
                } else if is_a_token(atom) {
                    out.push_str(REDACTED);
                } else if let Some(host) = userinfo_end(atom).filter(|_| was_after_colon) {
                    out.push_str(REDACTED);
                    out.push_str(&atom[host..]);
                } else if atom.starts_with('-')
                    && names_a_secret(atom)
                    && matches!(tokens.get(at), Some(Token::Space(_)))
                {
                    // `--password hunter2`.
                    out.push_str(atom);
                    awaiting = Awaiting::Value;
                    quote = None;
                } else {
                    out.push_str(atom);
                    key = Some(atom);
                }
            }
            (_, Token::Mark(mark)) => {
                out.push(mark);
                match mark {
                    '"' | '\'' if quote == Some(mark) => {
                        // An empty quoted value.
                        awaiting = Awaiting::Nothing;
                        quote = None;
                    }
                    '"' | '\'' => quote = Some(mark),
                    ']' | '}' | ')' | ',' | '&' | ';' => awaiting = Awaiting::Nothing,
                    _ => {}
                }
            }
            (state, Token::Atom(atom)) => {
                if is_scheme(atom) {
                    // `Authorization: Bearer …`: the scheme stays, and the
                    // value is still to come.
                    out.push_str(atom);
                    awaiting = Awaiting::Value;
                    two_words = false;
                } else if state == Awaiting::SchemeValue
                    && atom.eq_ignore_ascii_case("realm")
                    && tokens.get(at) == Some(&Token::Mark('='))
                {
                    // `www-authenticate: Bearer realm="…"` is a challenge,
                    // not a credential.
                    out.push_str(atom);
                    awaiting = Awaiting::Nothing;
                } else {
                    out.push_str(REDACTED);
                    at = value_end(&tokens, at, quote);
                    if std::mem::take(&mut two_words)
                        && matches!(tokens.get(at), Some(Token::Space(_)))
                        && matches!(tokens.get(at + 1), Some(Token::Atom(_)))
                    {
                        at = value_end(&tokens, at + 2, quote);
                    }
                    awaiting = Awaiting::Nothing;
                    quote = None;
                }
            }
        }
    }
    out
}

/// What [`scrub`] expects next.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Awaiting {
    Nothing,
    /// The value of a secret key.
    Value,
    /// The value after a bare `Bearer` or `Basic`.
    SchemeValue,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Token<'a> {
    Space(&'a str),
    Atom(&'a str),
    Mark(char),
}

/// `text` as whitespace runs, [`MARKS`] and the words between them.
fn tokens(text: &str) -> Vec<Token<'_>> {
    let mut tokens = Vec::new();
    let mut rest = text;
    while let Some(first) = rest.chars().next() {
        if MARKS.contains(&first) {
            tokens.push(Token::Mark(first));
            rest = &rest[first.len_utf8()..];
            continue;
        }
        let space = first.is_whitespace();
        let end = rest
            .find(|c: char| MARKS.contains(&c) || c.is_whitespace() != space)
            .unwrap_or(rest.len());
        let (piece, tail) = rest.split_at(end);
        tokens.push(if space {
            Token::Space(piece)
        } else {
            Token::Atom(piece)
        });
        rest = tail;
    }
    tokens
}

/// The index after the value that starts before `at`: up to its closing
/// quote when `quote` opened it, else up to whitespace or the punctuation
/// that ends a pair.
fn value_end(tokens: &[Token<'_>], mut at: usize, quote: Option<char>) -> usize {
    while let Some(token) = tokens.get(at) {
        let ends = match (quote, token) {
            (Some(quote), Token::Mark(mark)) => {
                *mark == quote || (*mark == '\\' && tokens.get(at + 1) == Some(&Token::Mark(quote)))
            }
            (Some(_), _) | (None, Token::Atom(_)) => false,
            (None, Token::Space(_)) => true,
            (None, Token::Mark(mark)) => {
                matches!(mark, ',' | '&' | ';' | ']' | '}' | ')' | '"' | '\'')
            }
        };
        if ends {
            break;
        }
        at += 1;
    }
    at
}

fn is_scheme(atom: &str) -> bool {
    atom.eq_ignore_ascii_case("bearer") || atom.eq_ignore_ascii_case("basic")
}

/// Whether a key, or a flag such as `--password`, names a secret.
fn names_a_secret(key: &str) -> bool {
    let key = key.trim_start_matches('-').to_ascii_lowercase();
    SECRET_KEYS.contains(&key.as_str())
        || SECRET_KEY_WORDS.iter().any(|word| key.contains(word))
        || SECRET_KEY_ENDINGS.iter().any(|end| key.ends_with(end))
}

/// Whether a word is itself a token: a JWT, or one of [`TOKEN_PREFIXES`].
fn is_a_token(atom: &str) -> bool {
    (atom.starts_with("eyJ") && atom.matches('.').count() >= 2)
        || (atom.len() >= 16 && TOKEN_PREFIXES.iter().any(|prefix| atom.starts_with(prefix)))
}

/// Where the host starts in `pass@host/path`, the rest of `user:pass@host`.
fn userinfo_end(atom: &str) -> Option<usize> {
    atom.find('@')
        .filter(|at| *at > 0 && !atom[..*at].contains('/'))
}

/// `text` with each PEM block replaced by [`REDACTED`]. A block that never
/// ends is removed to the end of the text.
fn scrub_pem(text: &str) -> String {
    const BEGIN: &str = "-----BEGIN ";
    const END: &str = "-----END ";
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find(BEGIN) {
        out.push_str(&rest[..start]);
        out.push_str(REDACTED);
        let block = &rest[start..];
        let end = block
            .find(END)
            .and_then(|end| {
                let label = end + END.len();
                block[label..].find("-----").map(|close| label + close + 5)
            })
            .unwrap_or(block.len());
        rest = &block[end..];
    }
    out.push_str(rest);
    out
}

/// A URL inside `word` without its user and password and without its query
/// string. A word with no URL is returned as it is.
fn scrub_url(word: &str) -> String {
    let Some(scheme_end) = word.find("://") else {
        return word.to_owned();
    };
    let (head, rest) = word.split_at(scheme_end + 3);
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(authority_end);
    let authority = match authority.rfind('@') {
        Some(at) => format!("{REDACTED}{}", &authority[at..]),
        None => authority.to_owned(),
    };
    let tail = match tail.find('?') {
        Some(query) => format!(
            "{}?{}",
            &tail[..query],
            keep_closing_punctuation(&tail[query + 1..])
        ),
        None => tail.to_owned(),
    };
    format!("{head}{authority}{tail}")
}

/// [`REDACTED`] in place of `value`, with the quotes and brackets that
/// opened and closed it kept so the surrounding text still parses by eye.
fn keep_closing_punctuation(value: &str) -> String {
    let is_wrapping = |c: char| {
        matches!(
            c,
            '"' | '\'' | '\\' | ',' | ';' | ')' | ']' | '}' | '.' | ':'
        )
    };
    let opening: String = value
        .chars()
        .take_while(|c| matches!(c, '"' | '\'' | '\\'))
        .collect();
    let closing: String = value
        .chars()
        .rev()
        .take_while(|c| is_wrapping(*c))
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    if opening.len() + closing.len() >= value.len() {
        // Nothing but punctuation: there is no value here to remove.
        return value.to_owned();
    }
    format!("{opening}{REDACTED}{closing}")
}

/// `text` as alternating runs of whitespace and of everything else.
fn split_keeping_whitespace(text: &str) -> impl Iterator<Item = &str> {
    let mut rest = text;
    std::iter::from_fn(move || {
        let first = rest.chars().next()?;
        let space = first.is_whitespace();
        let end = rest
            .find(|c: char| c.is_whitespace() != space)
            .unwrap_or(rest.len());
        let (piece, tail) = rest.split_at(end);
        rest = tail;
        Some(piece)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn failure(reason: &str, message: &str) -> ContainerStartFailed {
        ContainerStartFailed {
            container: "workspace".into(),
            image: "registry.example/team/app:1".into(),
            reason: reason.into(),
            message: message.into(),
            exit_code: None,
        }
    }

    /// The three messages are the kubelet's own, read on a development
    /// cluster on 2026-11-13 and 2026-11-14.
    #[test]
    fn a_pull_failure_names_the_image_and_the_cause_it_recognises() {
        let missing = failure(
            "ErrImagePull",
            "rpc error: code = NotFound desc = failed to pull and unpack image \
             \"registry.example/team/app:1\": failed to resolve reference \
             \"registry.example/team/app:1\": registry.example/team/app:1: not found",
        );
        assert_eq!(
            summary(&missing),
            "The image `registry.example/team/app:1` could not be pulled: not found. Check the image name and tag."
        );
        let unreachable = failure(
            "ErrImagePull",
            "failed to pull and unpack image \"registry.example/team/app:1\": failed to resolve \
             reference \"registry.example/team/app:1\": failed to do request: Head \
             \"https://registry.example/v2/team/app/manifests/1\": dial tcp: lookup \
             registry.example on 10.0.0.10:53: no such host",
        );
        assert_eq!(
            summary(&unreachable),
            "The image `registry.example/team/app:1` could not be pulled: its registry could not be reached. Check the registry's address."
        );
        let denied = failure(
            "ImagePullBackOff",
            "failed to authorize: failed to fetch anonymous token: unexpected status from GET \
             request to https://auth.example/token?scope=repository: 401 Unauthorized",
        );
        assert_eq!(
            summary(&denied),
            "The image `registry.example/team/app:1` could not be pulled: access denied (HTTP 401). Check the image name and who may pull it."
        );
        let unknown = failure("ImagePullBackOff", "Back-off pulling image");
        assert_eq!(
            summary(&unknown),
            "The image `registry.example/team/app:1` could not be pulled. Check the image name and tag."
        );
        for (message, told) in [
            (
                "unexpected status code 429 Too Many Requests",
                "The image `registry.example/team/app:1` could not be pulled: its registry is limiting requests (HTTP 429). Try again later.",
            ),
            (
                "unexpected status from HEAD request: 503 Service Unavailable",
                "The image `registry.example/team/app:1` could not be pulled: its registry answered with an error (HTTP 503). Try again later.",
            ),
            (
                "unexpected status from HEAD request: 404 Not Found",
                "The image `registry.example/team/app:1` could not be pulled: not found (HTTP 404). Check the image name and tag.",
            ),
            // A status outside the known list is not repeated.
            (
                "unexpected status from HEAD request: 418 I'm a teapot",
                "The image `registry.example/team/app:1` could not be pulled. Check the image name and tag.",
            ),
        ] {
            assert_eq!(summary(&failure("ErrImagePull", message)), told);
        }
        let no_image = ContainerStartFailed {
            image: String::new(),
            ..unknown
        };
        assert_eq!(
            summary(&no_image),
            "The image could not be pulled. Check the image name and tag."
        );
        assert_eq!(
            summary(&failure("InvalidImageName", "couldn't parse image name")),
            "The image name `registry.example/team/app:1` is not valid. Check the image name."
        );
    }

    #[test]
    fn a_start_error_says_what_it_recognises_and_otherwise_only_its_reason_and_exit() {
        let start_error = |message: &str| ContainerStartFailed {
            exit_code: Some(128),
            ..failure("StartError", message)
        };
        let nested = "exit code 128: failed to create containerd task: failed to create shim \
                      task: Others(\"failed to handle message create container\\n\\nCaused by:\\n \
                      0: agent create container\\n 1: rpc status: Status { code: INTERNAL, \
                      message: \\\"roll back container storage\\\" }\")";
        let told = summary(&start_error(nested));
        assert_eq!(
            told,
            "The container `workspace` could not start (StartError, exit code 128). Try again."
        );
        assert!(!told.contains("containerd") && !told.contains('\\'));
        assert_eq!(
            summary(&start_error(
                "exit code 128: exec: \"/usr/local/bin/missing\": stat /usr/local/bin/missing: \
                 no such file or directory"
            )),
            "The container `workspace` could not start: its command was not found in the image. Check the image's command."
        );
        assert_eq!(
            summary(&start_error(
                "exit code 127: exec: \"start\": executable file not found in $PATH"
            )),
            "The container `workspace` could not start: its command was not found in the image. Check the image's command."
        );
        assert_eq!(
            summary(&start_error(
                "exit code 128: write /var/lib/x: no space left on device"
            )),
            "The container `workspace` could not start: its node is out of disk space. Try again."
        );
        assert_eq!(
            summary(&failure(
                "CreateContainerConfigError",
                "secret \"x\" not found"
            )),
            "The container `workspace` could not be created (CreateContainerConfigError). Try again; if it keeps failing, contact support."
        );
    }

    #[test]
    fn a_crash_loop_and_a_pod_that_ended_have_their_own_sentences() {
        let looping = ContainerStartFailed {
            exit_code: Some(1),
            ..failure("CrashLoopBackOff", "exit code 1")
        };
        assert_eq!(
            summary(&looping),
            "The container `workspace` keeps exiting right after it starts (exit code 1). Check the image's command."
        );
        let pod = ContainerStartFailed {
            container: "workspace Pod".into(),
            image: String::new(),
            reason: "Evicted".into(),
            message: "The node was low on resource: memory.".into(),
            exit_code: None,
        };
        assert_eq!(
            summary(&pod),
            "The sandbox stopped before it was ready (Evicted). Try again."
        );
    }

    #[test]
    fn a_name_cannot_break_out_of_the_sentence() {
        // An image that is no image reference is not shown at all.
        for image in ["evil`\u{1b}[31m\nimage".to_owned(), "a".repeat(5_000)] {
            let hostile = ContainerStartFailed {
                image,
                ..failure("InvalidImageName", "")
            };
            assert_eq!(
                summary(&hostile),
                "The image name is not valid. Check the image name."
            );
        }
        let container = ContainerStartFailed {
            container: "work`\u{1b}[31m\nspace".into(),
            exit_code: Some(1),
            ..failure("StartError", "")
        };
        assert_eq!(
            summary(&container),
            "The container `work[31mspace` could not start (StartError, exit code 1). Try again."
        );
    }

    /// The runtime writes the reason and the message. Neither reaches the
    /// sentence: an unknown reason reads `other`, and a secret the message
    /// quotes, here in the form Go prints a header map, stays out.
    #[test]
    fn nothing_the_runtime_wrote_reaches_the_sentence() {
        let jwt = concat!("ey", "Jabc.def.ghi");
        let quoted = format!(
            "failed to do request: Head \"https://registry.example/v2/\": request headers \
             map[Authorization:[Bearer {jwt}] User-Agent:[containerd]]: 401 Unauthorized"
        );
        for reason in [
            "ErrImagePull",
            "StartError",
            "CreateContainerError",
            "CrashLoopBackOff",
        ] {
            let told = summary(&ContainerStartFailed {
                exit_code: Some(1),
                ..failure(reason, &quoted)
            });
            assert!(!told.contains(jwt) && !told.contains("Bearer"), "{told}");
            assert!(
                !told.contains("map[") && !told.contains("containerd"),
                "{told}"
            );
        }
        let unknown = ContainerStartFailed {
            exit_code: Some(3),
            ..failure("Bearer-abc123", "")
        };
        assert_eq!(
            summary(&unknown),
            "The container `workspace` could not start (other, exit code 3). Try again."
        );
        // The operator's log line carries the message without the token.
        let logged = log_text(&failure("ErrImagePull", &quoted));
        assert!(logged.contains("map[Authorization:[Bearer [redacted]] User-Agent:[containerd]]"));
        assert!(!logged.contains(jwt), "{logged}");
    }

    #[test]
    fn log_text_keeps_the_runtime_text_and_is_cut_at_a_character() {
        assert_eq!(
            log_text(&failure("ErrImagePull", " not found \n")),
            "ErrImagePull: not found"
        );
        assert_eq!(log_text(&failure("StartError", "")), "StartError");
        let long = log_text(&failure("StartError", &"é".repeat(10_000)));
        assert_eq!(long.chars().count(), LOG_TEXT_MAX_CHARS);
        assert!(long.ends_with(LOG_TEXT_TRUNCATED));
        let exact = log_text(&failure("E", &"é".repeat(LOG_TEXT_MAX_CHARS - 3)));
        assert_eq!(exact.chars().count(), LOG_TEXT_MAX_CHARS);
        assert!(!exact.ends_with(LOG_TEXT_TRUNCATED));
    }

    #[test]
    fn scrub_removes_what_is_shaped_like_a_secret_and_keeps_the_rest() {
        for (raw, kept) in [
            (
                "Head \"https://builder:hunter2@registry.example/v2/app/manifests/1\": denied",
                "Head \"https://[redacted]@registry.example/v2/app/manifests/1\": denied",
            ),
            (
                "Get \"https://blobs.example/sha256/ab?X-Signature=abc123&Expires=9\": EOF",
                "Get \"https://blobs.example/sha256/ab?[redacted]\": EOF",
            ),
            (
                "request header Authorization: Bearer eyJhbGciOi.payload.sig rejected",
                "request header Authorization: Bearer [redacted] rejected",
            ),
            (
                "www-authenticate: Basic dXNlcjpwYXNz, realm",
                "www-authenticate: Basic [redacted], realm",
            ),
            (
                "env REGISTRY_PASSWORD=hunter2 and API_KEY='abc' set",
                "env REGISTRY_PASSWORD=[redacted] and API_KEY='[redacted]' set",
            ),
            (
                "config {\"auth_token\": \"abc.def\", \"name\": \"app\"}",
                "config {\"auth_token\": \"[redacted]\", \"name\": \"app\"}",
            ),
            (
                "pull secret token:abc123 was refused",
                "pull secret token:[redacted] was refused",
            ),
            // The scheme word after a secret key stays; its value goes.
            (
                "headers map[Authorization:[Bearer abc.def] User-Agent:[containerd]]",
                "headers map[Authorization:[Bearer [redacted]] User-Agent:[containerd]]",
            ),
            (
                "map[Authorization:[Basic dXNlcjpwYXNz]]",
                "map[Authorization:[Basic [redacted]]]",
            ),
            (
                "Authorization:\"Bearer abc\" sent",
                "Authorization:\"Bearer [redacted]\" sent",
            ),
            ("Authorization=Bearer%20abc", "Authorization=[redacted]"),
            ("Authorization: token abc123", "Authorization: [redacted]"),
            // Every pair of a word is checked.
            (
                "{\"username\":\"u\",\"password\":\"hunter2\"}",
                "{\"username\":\"u\",\"password\":\"[redacted]\"}",
            ),
            (
                "scope=repository&token=abc123",
                "scope=repository&token=[redacted]",
            ),
            ("foo:token=abc123", "foo:token=[redacted]"),
            ("a=1,password=b=c,d=2", "a=1,password=[redacted],d=2"),
            (
                r#"\"password\":\"hunter2\""#,
                r#"\"password\":\"[redacted]\""#,
            ),
            (
                "\"password\": \"two words\" end",
                "\"password\": \"[redacted]\" end",
            ),
            (
                "\"password\":\"\",\"name\":\"app\"",
                "\"password\":\"\",\"name\":\"app\"",
            ),
            // `auth` is a key by itself, never a part of one.
            (
                "config {\"auths\":{\"reg.example\":{\"auth\":\"dXNlcjpwYXNz\"}}}",
                "config {\"auths\":{\"reg.example\":{\"auth\":\"[redacted]\"}}}",
            ),
            ("author=someone oauth=off", "author=someone oauth=off"),
            (
                "X-Registry-Auth: dXNlcjpwYXNz sent",
                "X-Registry-Auth: [redacted] sent",
            ),
            (
                "PASS=a AUTH=b PAT=c KEY=d SSH_KEY=e",
                "PASS=[redacted] AUTH=[redacted] PAT=[redacted] KEY=[redacted] SSH_KEY=[redacted]",
            ),
            (
                "x-amz-security-token:AQoDYXdz",
                "x-amz-security-token:[redacted]",
            ),
            (
                "login --password hunter2 failed",
                "login --password [redacted] failed",
            ),
            // A host with a user and password but no scheme.
            (
                "user:hunter2@registry.example/v2/app",
                "user:[redacted]@registry.example/v2/app",
            ),
            (
                "Get https://u:p@a/b@c/d?x=1",
                "Get https://[redacted]@a/b@c/d?[redacted]",
            ),
            // A challenge is not a credential.
            (
                "www-authenticate: Bearer realm=\"https://auth.example/token\",service=\"registry\"",
                "www-authenticate: Bearer realm=\"https://auth.example/token\",service=\"registry\"",
            ),
        ] {
            assert_eq!(scrub(raw), kept, "{raw}");
        }
        // Words that are tokens by themselves. They are built in pieces so
        // that no scanner reads this file as holding one.
        let jwt = concat!("ey", "JhbGciOiJIUzI1NiJ9.ey", "JzdWIiOiJ4In0.c2ln");
        let prefixed = concat!("gh", "p_abcdefghijklmnopqrstuvwxyz0123456789");
        let pem = concat!(
            "-----BEGIN PRIV",
            "ATE KEY-----\nMIIEvQ\nIBADAN\n-----END PRIV",
            "ATE KEY-----"
        );
        assert_eq!(
            scrub(&format!("body: {jwt} rejected")),
            "body: [redacted] rejected"
        );
        assert_eq!(
            scrub(&format!("{prefixed} in message")),
            "[redacted] in message"
        );
        assert_eq!(scrub(&format!("key {pem} read")), "key [redacted] read");
        assert_eq!(
            scrub("cert -----BEGIN CERTIFICATE-----\nMIIB"),
            "cert [redacted]"
        );
        // Ordinary runtime text passes through unchanged, whitespace and all.
        for plain in [
            "exit code 128: failed to create containerd task: failed to create shim task",
            "failed to resolve reference \"docker.io/library/busybox:missing\": not found",
            "dial tcp: lookup registry.example on 10.0.0.10:53: no such host",
            "line one\n  line two\ttabbed",
            "Status { code: INTERNAL, message: \"roll back container storage\" }",
            "",
        ] {
            assert_eq!(scrub(plain), plain);
        }
    }

    /// A registry its user chose writes part of the message, so neither its
    /// length nor the number of blocks in it may cost more than a bounded
    /// amount of work.
    #[test]
    fn a_huge_message_is_bounded_before_it_is_scrubbed() {
        let blocks = "-----BEGIN X-----\nAAAA\n-----END X----- ".repeat(200_000);
        assert_eq!(scrub_pem(&blocks), "[redacted] ".repeat(200_000));
        let logged = log_text(&failure("ErrImagePull", &blocks));
        assert!(logged.chars().count() <= LOG_TEXT_MAX_CHARS);
        assert!(!logged.contains("AAAA"), "{logged}");
        // The cut never leaves half a token for the scrub to judge: here a
        // long block is removed, which brings a token at the cut forward.
        let jwt = concat!("ey", "Jhbcdefgh.ey", "Jzdwijkl.c2ln");
        let block = format!(
            "-----BEGIN X-----{}-----END X-----",
            "A".repeat(SCRUB_INPUT_MAX_CHARS - 50)
        );
        let cut_inside = format!("{block} {jwt} tail");
        assert!(cut_inside.chars().count() > SCRUB_INPUT_MAX_CHARS);
        assert_eq!(log_text(&failure("E", &cut_inside)), "E: [redacted]");
        assert_eq!(bounded_input("short text"), "short text");
    }

    #[test]
    fn log_text_is_scrubbed_before_it_is_cut() {
        let secret = failure(
            "ErrImagePull",
            "Get \"https://u:p@registry.example/v2/?token=abc\": 401",
        );
        assert_eq!(
            log_text(&secret),
            "ErrImagePull: Get \"https://[redacted]@registry.example/v2/?[redacted]\": 401"
        );
    }
}
