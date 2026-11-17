//! The screens `credentials connect` shows, the same in both placements, as
//! the owner approved them (private-docs
//! `designs/2026-11-15-credentials-screens.html`): one title line naming the
//! provider, the credential's name and its store, then the link to sign in
//! (copied to the clipboard with OSC 52 at a terminal), a device code alone on
//! its line or a hidden paste prompt, then one result line. Nothing here
//! prints a token or a pasted code.

use std::io::{IsTerminal as _, Write as _};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;

use crate::output::{Role, Status, Style};

/// The indent of every line under the screen's title.
pub(super) const INDENT: &str = "  ";

/// The hidden prompt for the code Claude shows after sign-in.
pub(super) const PASTE_CODE_PROMPT: &str = "  Paste the code Claude shows after you sign in > ";

/// What a sign-in screen is for: the provider, the name the credential is
/// saved under, and where it is saved.
#[derive(Clone, Copy)]
pub(super) struct SignInScreen<'a> {
    provider: &'a str,
    name: &'a str,
    in_account: bool,
}

impl<'a> SignInScreen<'a> {
    /// A sign-in saved to this computer's local credential store.
    pub(super) const fn local(provider: &'a str, name: &'a str) -> Self {
        Self {
            provider,
            name,
            in_account: false,
        }
    }

    /// A sign-in saved to the user's Codewire account.
    pub(super) const fn cloud(provider: &'a str, name: &'a str) -> Self {
        Self {
            provider,
            name,
            in_account: true,
        }
    }

    /// The title line: what is connected, under which name, and where.
    pub(super) fn heading(self) -> String {
        let place = if self.in_account {
            "in your Codewire account"
        } else {
            "on this computer"
        };
        format!("Connect {} as {}, {place}\n\n", self.provider, self.name)
    }
}

/// The link screen: the title, then where to sign in, true whether or not a
/// browser opened.
pub(super) fn link_screen(sign_in: SignInScreen<'_>, url: &str) -> String {
    format!(
        "{}{INDENT}Open this link to sign in:\n{INDENT}{url}\n",
        sign_in.heading()
    )
}

/// The device-code lines under the link screen of a device flow (Codex,
/// GitHub): the code alone on its line, so a double-click takes exactly the
/// code, and bold where `style` has colour.
pub(super) fn device_code_lines(code: &str, style: Style) -> String {
    format!(
        "\n{INDENT}Enter this code:\n{INDENT}{}\n",
        style.paint(Role::Strong, code)
    )
}

/// The one result line once a credential is saved: who signed in (or, for a
/// token, its name), and a token's expiry date.
pub(super) fn connected_line(
    sign_in: SignInScreen<'_>,
    who: &str,
    expires_at_unix: Option<u64>,
    style: Style,
) -> String {
    let expires = expires_at_unix
        .and_then(|at| i64::try_from(at).ok())
        .and_then(|at| chrono::DateTime::<chrono::Utc>::from_timestamp(at, 0))
        .map(|at| format!(" · expires {}", at.format("%-d %b %Y")))
        .unwrap_or_default();
    format!(
        "{} {} connected as {who}{expires}\n",
        style.status(Status::Done),
        sign_in.provider
    )
}

/// The account a result line names: the credential's account hint (an email
/// or login), or its name when the provider gave none.
pub(super) fn signed_in_account<'a>(account_hint: Option<&'a str>, name: &'a str) -> &'a str {
    account_hint
        .map(str::trim)
        .filter(|hint| !hint.is_empty())
        .unwrap_or(name)
}

/// The OSC 52 sequence that asks the terminal to put `text` on the clipboard.
pub(super) fn osc52_copy(text: &str) -> String {
    format!("\x1b]52;c;{}\x07", BASE64.encode(text))
}

/// The link screen, then the browser at a terminal. The link is on its own
/// line first, so it works when no browser opens; the browser is started
/// fully detached, so nothing it prints reaches a prompt.
pub(super) fn open_sign_in_link(sign_in: SignInScreen<'_>, url: &str) {
    show_link(sign_in, url);
    if std::io::stdin().is_terminal() && std::io::stderr().is_terminal() {
        // The link above is the way there when no browser starts.
        let _ = super::platform_commands::open_browser(url);
    }
}

/// The Claude sign-in page, in both placements: the authorize link, then
/// the code Claude shows, read as `code#state` from a no-echo prompt or
/// stdin, never argv ([`super::credential_input::prompt_claude_code`]).
pub(super) fn claude_sign_in_code(
    sign_in: SignInScreen<'_>,
    authorize_url: &str,
) -> anyhow::Result<codewire_protected_store::ProtectedValue> {
    open_sign_in_link(sign_in, authorize_url);
    eprintln!();
    super::credential_input::prompt_claude_code()
}

/// Show the link screen on stderr, after copying the link with OSC 52 when
/// stdout is a terminal (the sequence goes to stdout only then, so a piped
/// stdout never receives it).
pub(super) fn show_link(sign_in: SignInScreen<'_>, url: &str) {
    if std::io::stdout().is_terminal() {
        let mut stdout = std::io::stdout();
        // A terminal that ignores OSC 52 still shows the link to select.
        let _ = stdout
            .write_all(osc52_copy(url).as_bytes())
            .and_then(|()| stdout.flush());
    }
    eprint!("{}", link_screen(sign_in, url));
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::output::Charset;

    const URL: &str = "https://claude.com/cai/oauth/authorize?code=true&state=s";
    const PLAIN: Style = Style::new(false, Charset::Unicode);

    #[test]
    fn the_title_names_the_provider_the_name_and_the_store() {
        assert_eq!(
            link_screen(
                SignInScreen::local("Claude (sign-in)", "n@example.com"),
                URL
            ),
            format!(
                "Connect Claude (sign-in) as n@example.com, on this computer\n\n  Open this link to sign in:\n  {URL}\n"
            )
        );
        assert!(
            SignInScreen::cloud("Claude (token)", "ci")
                .heading()
                .starts_with("Connect Claude (token) as ci, in your Codewire account\n")
        );
        // The link is alone on its line, so it can be selected whole.
        assert!(
            link_screen(SignInScreen::local("Codex", "work"), URL)
                .lines()
                .any(|line| line.trim() == URL)
        );
    }

    #[test]
    fn the_device_code_is_alone_on_its_line_and_bold_only_with_colour() {
        let plain = device_code_lines("K7QF-2M9XD", PLAIN);
        assert_eq!(plain, "\n  Enter this code:\n  K7QF-2M9XD\n");
        assert!(!plain.contains('\x1b'));
        let coloured = device_code_lines("K7QF-2M9XD", Style::new(true, Charset::Unicode));
        assert!(
            coloured
                .lines()
                .any(|line| line == "  \x1b[1mK7QF-2M9XD\x1b[0m")
        );
    }

    #[test]
    fn the_result_line_names_who_connected_and_a_tokens_expiry() {
        assert_eq!(
            connected_line(
                SignInScreen::local("Claude (sign-in)", "n@example.com"),
                "n@example.com",
                None,
                PLAIN
            ),
            "✓ Claude (sign-in) connected as n@example.com\n"
        );
        // 2027-11-15 00:00 UTC.
        assert_eq!(
            connected_line(
                SignInScreen::local("Claude (token)", "ci"),
                "ci",
                Some(1_826_236_800),
                PLAIN
            ),
            "✓ Claude (token) connected as ci · expires 15 Nov 2027\n"
        );
    }

    #[test]
    fn the_signed_in_account_is_the_hint_unless_the_provider_gave_none() {
        assert_eq!(
            signed_in_account(Some(" person@example.test "), "work"),
            "person@example.test"
        );
        assert_eq!(signed_in_account(Some("  "), "work"), "work");
        assert_eq!(signed_in_account(None, "work"), "work");
    }

    #[test]
    fn osc52_carries_the_link_base64_encoded() {
        let sequence = osc52_copy(URL);
        let encoded = sequence
            .strip_prefix("\x1b]52;c;")
            .and_then(|rest| rest.strip_suffix('\x07'))
            .unwrap();
        assert_eq!(BASE64.decode(encoded).unwrap(), URL.as_bytes());
    }

    #[test]
    fn the_paste_prompt_says_where_the_code_comes_from() {
        assert_eq!(
            PASTE_CODE_PROMPT,
            "  Paste the code Claude shows after you sign in > "
        );
    }
}
