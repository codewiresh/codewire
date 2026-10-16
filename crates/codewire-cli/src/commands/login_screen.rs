//! The screens `credentials --cloud connect` shows while a person signs in
//! to a provider in their browser, laid out like Claude Code's own login:
//! the sign-in link on its own line (copied to the clipboard with OSC 52 at a
//! terminal), then a hidden paste prompt or a device code, then the account
//! that signed in. Nothing here prints a token or a pasted code.

use std::io::{IsTerminal as _, Write as _};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;

/// The indent of every line under the screen's title.
pub(super) const INDENT: &str = "   ";

/// The hidden prompt for the code Claude shows after sign-in.
pub(super) const PASTE_CODE_PROMPT: &str = "   Paste code here if prompted > ";

/// The link screen: where to sign in when no browser opens. `copied` says
/// whether the link was also sent to the clipboard with OSC 52.
pub(super) fn link_screen(url: &str, copied: bool) -> String {
    let mut screen = String::from(" Login\n\n");
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
pub(super) fn device_code_lines(provider: &str, code: &str) -> String {
    format!(
        "\n{INDENT}Enter this code: {code}\n{INDENT}Continue only if you started this {provider} login.\n"
    )
}

/// The screen once the provider accepted the sign-in. `account` is the
/// credential's account hint (an email or login), or its name when the
/// provider gave none.
pub(super) fn success_screen(account: &str) -> String {
    format!(" Login\n\n{INDENT}Logged in as {account}\n{INDENT}Login successful.\n")
}

/// The OSC 52 sequence that asks the terminal to put `text` on the clipboard.
pub(super) fn osc52_copy(text: &str) -> String {
    format!("\x1b]52;c;{}\x07", BASE64.encode(text))
}

/// Show the link screen on stderr, after copying the link with OSC 52 when
/// stdout is a terminal (the sequence goes to stdout only then, so a piped
/// stdout never receives it).
pub(super) fn show_link(url: &str) {
    let copied = std::io::stdout().is_terminal() && {
        let mut stdout = std::io::stdout();
        stdout.write_all(osc52_copy(url).as_bytes()).is_ok() && stdout.flush().is_ok()
    };
    eprint!("{}", link_screen(url, copied));
}

#[cfg(test)]
mod tests {
    use super::*;

    const URL: &str = "https://claude.com/cai/oauth/authorize?code=true&state=s";

    #[test]
    fn the_link_screen_matches_the_claude_code_layout() {
        assert_eq!(
            link_screen(URL, true),
            format!(
                " Login\n\n   Browser didn't open? Use the url below to sign in\n   (Sent via OSC 52 \u{b7} select the URL manually if paste fails)\n\n{URL}\n\n   Hold Shift while selecting to use your terminal's native copy\n"
            )
        );
        let uncopied = link_screen(URL, false);
        assert!(!uncopied.contains("OSC 52"));
        // The link is alone on its line, so it can be selected whole and
        // found by scripts.
        assert!(uncopied.lines().any(|line| line == URL));
    }

    #[test]
    fn the_device_and_success_lines_name_only_the_code_and_the_account() {
        assert_eq!(
            device_code_lines("Codex", "ABCD-1234"),
            "\n   Enter this code: ABCD-1234\n   Continue only if you started this Codex login.\n"
        );
        assert_eq!(
            success_screen("person@example.test"),
            " Login\n\n   Logged in as person@example.test\n   Login successful.\n"
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
