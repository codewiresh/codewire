//! The screens `credentials connect` shows while a person signs in
//! to a provider in their browser, laid out like Claude Code's own login:
//! the sign-in link on its own line (copied to the clipboard with OSC 52 at a
//! terminal), then a hidden paste prompt or a device code, then the account
//! that signed in. Nothing here prints a token or a pasted code.

use std::io::{IsTerminal as _, Write as _};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;

use crate::output::{Role, Style};

/// The indent of every line under the screen's title.
pub(super) const INDENT: &str = "   ";

/// The hidden prompt for the code Claude shows after sign-in.
pub(super) const PASTE_CODE_PROMPT: &str = "   Paste code here if prompted > ";

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

    fn heading(self) -> String {
        let place = if self.in_account {
            "in your Codewire account"
        } else {
            "on this computer"
        };
        format!(
            " Connect {}\n\n{INDENT}Saving as {:?} {place}\n\n",
            self.provider, self.name
        )
    }
}

/// The link screen: what is being connected, then where to sign in when no
/// browser opens. `copied` says whether the link was also sent to the
/// clipboard with OSC 52.
pub(super) fn link_screen(sign_in: SignInScreen<'_>, url: &str, copied: bool) -> String {
    let mut screen = sign_in.heading();
    screen.push_str(INDENT);
    screen.push_str("Browser didn't open? Use the url below to sign in\n");
    if copied {
        screen.push_str(INDENT);
        screen.push_str("(Sent via OSC 52 \u{b7} select the URL manually if paste fails)\n");
    }
    screen.push('\n');
    screen.push_str(url);
    screen.push_str("\n\n");
    screen.push_str(INDENT);
    screen.push_str("Hold Shift while selecting to use your terminal's native copy\n");
    screen
}

/// The device-code lines under the link screen of a device flow (Codex,
/// GitHub): no paste, the person enters this code on the provider's page.
/// The code is alone on its line, so selecting the line copies only the
/// code, and bold where `style` has colour.
pub(super) fn device_code_lines(sign_in: SignInScreen<'_>, code: &str, style: Style) -> String {
    format!(
        "\n{INDENT}Enter this code on that page:\n\n{INDENT}{}\n\n{INDENT}Continue only if you started this {} sign-in.\n",
        style.paint(Role::Strong, code),
        sign_in.provider,
    )
}

/// The screen once the provider accepted the sign-in. `account` is the
/// credential's account hint (an email or login), or its name when the
/// provider gave none.
pub(super) fn success_screen(sign_in: SignInScreen<'_>, account: &str) -> String {
    format!(
        " {} connected\n\n{INDENT}Signed in as {account}\n",
        sign_in.provider
    )
}

/// The account a success screen names: the credential's account hint (an
/// email or login), or its name when the provider gave none.
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
    let copied = std::io::stdout().is_terminal() && {
        let mut stdout = std::io::stdout();
        stdout.write_all(osc52_copy(url).as_bytes()).is_ok() && stdout.flush().is_ok()
    };
    eprint!("{}", link_screen(sign_in, url, copied));
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::output::Charset;

    const URL: &str = "https://claude.com/cai/oauth/authorize?code=true&state=s";

    #[test]
    fn the_link_screen_names_what_is_connected_and_where_it_is_saved() {
        assert_eq!(
            link_screen(SignInScreen::local("Claude", "work"), URL, true),
            format!(
                " Connect Claude\n\n   Saving as \"work\" on this computer\n\n   Browser didn't open? Use the url below to sign in\n   (Sent via OSC 52 \u{b7} select the URL manually if paste fails)\n\n{URL}\n\n   Hold Shift while selecting to use your terminal's native copy\n"
            )
        );
        assert!(
            link_screen(SignInScreen::cloud("Codex", "work"), URL, false).starts_with(
                " Connect Codex\n\n   Saving as \"work\" in your Codewire account\n\n"
            )
        );
        let uncopied = link_screen(SignInScreen::local("Claude", "work"), URL, false);
        assert!(!uncopied.contains("OSC 52"));
        // The link is alone on its line, so it can be selected whole and
        // found by scripts.
        assert!(uncopied.lines().any(|line| line == URL));
    }

    #[test]
    fn the_device_code_is_alone_on_its_line_and_bold_only_with_colour() {
        let sign_in = SignInScreen::local("Codex", "work");
        let plain = device_code_lines(sign_in, "ABCD-1234", Style::new(false, Charset::Unicode));
        assert_eq!(
            plain,
            "\n   Enter this code on that page:\n\n   ABCD-1234\n\n   Continue only if you started this Codex sign-in.\n"
        );
        assert!(plain.lines().any(|line| line.trim() == "ABCD-1234"));
        assert!(!plain.contains('\x1b'));
        let coloured = device_code_lines(sign_in, "ABCD-1234", Style::new(true, Charset::Unicode));
        assert!(
            coloured
                .lines()
                .any(|line| line == "   \x1b[1mABCD-1234\x1b[0m")
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
    fn the_success_screen_names_the_provider_and_the_account() {
        assert_eq!(
            success_screen(SignInScreen::cloud("GitHub", "work"), "person@example.test"),
            " GitHub connected\n\n   Signed in as person@example.test\n"
        );
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
    fn the_paste_prompt_matches_the_claude_code_layout() {
        assert_eq!(PASTE_CODE_PROMPT, "   Paste code here if prompted > ");
    }
}
