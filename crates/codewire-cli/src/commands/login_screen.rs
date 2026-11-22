//! The screens `credentials connect` shows, the same in both placements, as
//! the owner approved them (private-docs
//! `designs/2026-11-15-credentials-screens.html`): one title line naming the
//! provider, the credential's name and its store, then the link to sign in,
//! clickable at a terminal with "Press c to copy the link" under it (#4850), a
//! device code alone on its line or a hidden paste prompt, then one result
//! line. `cw login`'s device sign-in uses the same link and copy key. Nothing
//! here prints a token or a pasted code.

use std::io::{IsTerminal as _, Write as _};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;

use crate::output::{Capabilities, OutputMode, Role, Status, Style};

mod keys;

pub(super) use keys::KeyWatch;
#[cfg(unix)]
pub(super) use keys::readable as keys_readable;

/// The indent of every line under the screen's title.
pub(super) const INDENT: &str = "  ";

/// The hidden prompt for the code Claude shows after sign-in.
pub(super) const PASTE_CODE_PROMPT: &str = "  Paste the code Claude shows after you sign in > ";

/// The hint under the link while `c` copies it.
pub(super) const COPY_HINT: &str = "Press c to copy the link";

/// Where ChatGPT turns on the device-code sign-in Codex needs.
const CODEX_DEVICE_SETTINGS: &str = "https://chatgpt.com/#settings/Security";

/// What the sign-in screen may draw on stderr.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ScreenCaps {
    /// The link as an OSC 8 hyperlink: stderr is a live terminal.
    pub(super) link: bool,
    /// The copy key, its hint and the waiting line: an interactive
    /// terminal, and no JSON.
    pub(super) keys: bool,
}

#[cfg(test)]
impl ScreenCaps {
    /// Piped, or under `--output json`: the plain URL, no hint, no keys.
    pub(super) const PLAIN: Self = Self {
        link: false,
        keys: false,
    };
}

pub(super) fn screen_caps() -> ScreenCaps {
    let caps = Capabilities::from_process(OutputMode::Text);
    ScreenCaps {
        link: caps.live,
        keys: caps.live
            && caps.interactive
            && !crate::error_report::json_requested(std::env::args_os().skip(1)),
    }
}

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
/// browser opened. At a terminal the link is clickable and `c` copies it.
pub(super) fn link_screen(sign_in: SignInScreen<'_>, url: &str, caps: ScreenCaps) -> String {
    let link = if caps.link {
        hyperlink(url)
    } else {
        url.to_owned()
    };
    let hint = if caps.keys {
        format!("{INDENT}{COPY_HINT}\n")
    } else {
        String::new()
    };
    // Codex's device code works only once the account allows it (screen 3).
    let first_time = if sign_in.provider == "Codex" {
        let settings = if caps.link {
            hyperlink(CODEX_DEVICE_SETTINGS)
        } else {
            CODEX_DEVICE_SETTINGS.to_owned()
        };
        format!(
            "{INDENT}First time? Turn on \"Enable device code authorization for Codex\" here:\n{INDENT}{settings}\n\n"
        )
    } else {
        String::new()
    };
    format!(
        "{}{first_time}{INDENT}Open this link to sign in:\n{INDENT}{link}\n{hint}",
        sign_in.heading()
    )
}

/// `url` as an OSC 8 hyperlink whose text is the URL itself; anything but
/// a [`safe_link`] stays plain text.
pub(super) fn hyperlink(url: &str) -> String {
    if !safe_link(url) {
        return url.to_owned();
    }
    format!("\x1b]8;;{url}\x1b\\{url}\x1b]8;;\x1b\\")
}

/// A link a terminal may be handed: `https://`, or `http://` to the loopback
/// address a local Kind cluster serves on (#5422), with no control character
/// or space that could end the escape sequence or hide part of the link.
pub(super) fn safe_link(url: &str) -> bool {
    if url.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return false;
    }
    url.starts_with("https://") || (url.starts_with("http://") && loopback_link(url))
}

/// `127.0.0.1` or `[::1]`, read from the parsed link. The authority as
/// written must be exactly that host and an optional port, so a link whose
/// text names another host or a user (`127.0.0.1.example.com`,
/// `127.0.0.1@example.com`) or spells the address another way (`0x7f.0.0.1`,
/// `2130706433`) is refused: the person reads the host the browser opens.
fn loopback_link(url: &str) -> bool {
    let Ok(parsed) = url::Url::parse(url) else {
        return false;
    };
    let loopback = match parsed.host() {
        Some(url::Host::Ipv4(address)) => address == std::net::Ipv4Addr::LOCALHOST,
        Some(url::Host::Ipv6(address)) => address == std::net::Ipv6Addr::LOCALHOST,
        Some(url::Host::Domain(_)) | None => false,
    };
    let (Some(host), Some(rest)) = (parsed.host_str(), url.strip_prefix("http://")) else {
        return false;
    };
    let written = rest.split(['/', '?', '#']).next().unwrap_or_default();
    loopback
        && match written.strip_prefix(host) {
            Some("") => true,
            Some(port) => port.strip_prefix(':').is_some_and(|port| {
                !port.starts_with('0') && port.parse::<u16>().ok() == parsed.port_or_known_default()
            }),
            None => false,
        }
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
pub(super) fn connected_result(
    sign_in: SignInScreen<'_>,
    who: &str,
    expires_at_unix: Option<u64>,
) -> String {
    let expires = expires_at_unix
        .and_then(|at| i64::try_from(at).ok())
        .and_then(|at| chrono::DateTime::<chrono::Utc>::from_timestamp(at, 0))
        .map(|at| format!(" · expires {}", at.format("%-d %b %Y")))
        .unwrap_or_default();
    format!("{} connected as {who}{expires}", sign_in.provider)
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

/// Copy `url` for the person who pressed `c`: OSC 52 to the terminal on
/// stderr, which reaches their own clipboard over SSH too, and the platform
/// clipboard when this is their own desktop. Returns the line that says so.
pub(super) fn copy_link(url: &str) -> String {
    let mut stderr = std::io::stderr();
    // Best effort: a terminal that drops OSC 52 still has the platform copy.
    let _ = stderr.write_all(osc52_copy(url).as_bytes());
    let _ = stderr.flush();
    platform_copy(url);
    let style = Capabilities::from_process(OutputMode::Text).stderr_style();
    format!("{INDENT}{} Copied", style.status(Status::Done))
}

/// The desktop's clipboard tool, if this session is on the desktop: over SSH
/// that clipboard is the remote machine's, so OSC 52 alone serves.
fn platform_copy(url: &str) {
    use std::process::{Command, Stdio};
    let var = |name: &str| std::env::var_os(name).filter(|value| !value.is_empty());
    if var("SSH_CONNECTION").is_some() || var("SSH_TTY").is_some() {
        return;
    }
    let tool: &[&str] = if cfg!(target_os = "macos") {
        &["pbcopy"]
    } else if var("WAYLAND_DISPLAY").is_some() {
        &["wl-copy"]
    } else if var("DISPLAY").is_some() {
        &["xclip", "-selection", "clipboard"]
    } else {
        return;
    };
    let Ok(mut child) = Command::new(tool[0])
        .args(&tool[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else {
        return;
    };
    if let Some(mut stdin) = child.stdin.take() {
        // A tool that can't take the link copies nothing; OSC 52 already did.
        let _ = stdin.write_all(url.as_bytes());
    }
    // wl-copy and xclip serve the selection from a child of their own and
    // return at once; pbcopy returns when done.
    // Bounded: a tool that hangs is stopped, and the copy is OSC 52's alone.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while std::time::Instant::now() < deadline {
        if !matches!(child.try_wait(), Ok(None)) {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    // A hung tool is stopped and reaped as far as it lets us; the copy stands.
    let _ = child.kill();
    let _ = child.wait();
}

/// The link screen, then the browser at a terminal. The link is on its own
/// line first, so it works when no browser opens; the browser is started
/// fully detached, so nothing it prints reaches a prompt.
pub(super) fn open_sign_in_link(sign_in: SignInScreen<'_>, url: &str) {
    show_link(sign_in, url);
    if SYNTHETIC_SIGN_IN {
        eprintln!("{SYNTHETIC_SIGN_IN_NOTE}");
    }
    if opens_browser_here() {
        // The link above is the way there when no browser starts.
        let _ = super::platform_commands::open_browser(url);
    }
}

/// A build with the non-shipping `local-broker-synthetic-smoke` feature
/// answers its sign-ins in process, so it never opens a provider's page:
/// loading it alone would reach the provider with the person's own cookies
/// (#5592).
const SYNTHETIC_SIGN_IN: bool = cfg!(feature = "local-broker-synthetic-smoke");
const SYNTHETIC_SIGN_IN_NOTE: &str =
    "This test build answers the sign-in itself; don't open the link.";

/// Whether this process starts the browser for a sign-in: at a terminal,
/// and not in a synthetic build.
pub(super) fn opens_browser_here() -> bool {
    opens_browser(
        SYNTHETIC_SIGN_IN,
        std::io::stdin().is_terminal() && std::io::stderr().is_terminal(),
    )
}

/// Whether a sign-in starts the browser: only at a terminal, and never in a
/// synthetic build.
fn opens_browser(synthetic: bool, at_terminal: bool) -> bool {
    at_terminal && !synthetic
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
    let copy = screen_caps().keys.then_some(authorize_url);
    super::credential_input::prompt_claude_code(copy)
}

/// `cw login`'s device sign-in: the page, the code and the wait for `polled`.
/// Scripts read the three stdout lines from a pipe, so they stay as they
/// are; at a terminal the link is clickable and `c` copies it while the
/// login waits (#4850).
pub(super) async fn device_login_wait<T>(
    url: &str,
    code: &str,
    polled: impl std::future::Future<Output = anyhow::Result<T>>,
) -> anyhow::Result<T> {
    // The server names the page; nothing else reaches the terminal or the
    // browser.
    anyhow::ensure!(
        safe_link(url),
        "the server sent a sign-in page that isn't a plain https link; nothing was opened"
    );
    let screen = screen_caps();
    let link = if screen.link && std::io::IsTerminal::is_terminal(&std::io::stdout()) {
        hyperlink(url)
    } else {
        url.to_owned()
    };
    let opens = opens_browser_here();
    print!("{}", device_page_lines(&link, code, opens));
    if opens {
        // The link printed above is the way there when no browser starts.
        let _ = super::platform_commands::open_browser(url);
    }
    if screen.keys {
        // The key watch draws the waiting line under the hint.
        eprintln!("{INDENT}{COPY_HINT}");
    } else {
        eprintln!("Waiting for authorization...");
    }
    let keys = KeyWatch::new();
    keys.watch(url);
    let polled = tokio::select! {
        result = polled => result,
        () = keys.cancelled() => anyhow::bail!("login cancelled; nothing was saved"),
    };
    // A Ctrl-C that came as the login finished still saves nothing.
    anyhow::ensure!(!keys.was_cancelled(), "login cancelled; nothing was saved");
    polled
}

/// The device sign-in's stdout lines. "Opening browser" only when it opens
/// one; the link and code lines keep their words, which scripts read.
fn device_page_lines(link: &str, code: &str, opens_browser: bool) -> String {
    let opening = if opens_browser {
        "Opening browser to authorize...\n"
    } else {
        ""
    };
    format!("{opening}If browser doesn't open, visit: {link}\nYour code: {code}\n")
}

/// Show the link screen on stderr. The link is copied only when `c` is
/// pressed ([`copy_link`]), not when the screen appears.
pub(super) fn show_link(sign_in: SignInScreen<'_>, url: &str) {
    eprint!("{}", link_screen(sign_in, url, screen_caps()));
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::output::Charset;

    const URL: &str = "https://claude.com/cai/oauth/authorize?code=true&state=s";
    const PLAIN: Style = Style::new(false, Charset::Unicode);

    /// A sign-in opens the browser only at a terminal, and a synthetic build
    /// never opens it, so its connect never loads a provider's real page
    /// (#5592).
    #[test]
    fn a_synthetic_build_never_opens_the_browser() {
        assert!(opens_browser(false, true));
        assert!(!opens_browser(false, false));
        assert!(!opens_browser(true, true));
        assert!(!opens_browser(true, false));
        assert_eq!(
            SYNTHETIC_SIGN_IN,
            cfg!(feature = "local-broker-synthetic-smoke")
        );
    }

    /// The device sign-in says it opens a browser only when it does: never
    /// without a terminal, where `cw setup` and `cw login` run in scripts.
    #[test]
    fn the_device_page_says_it_opens_a_browser_only_when_it_does() {
        let url = "https://codewire.test/device?user_code=ABCD-1234";
        assert_eq!(
            device_page_lines(url, "ABCD-1234", false),
            format!("If browser doesn't open, visit: {url}\nYour code: ABCD-1234\n")
        );
        assert_eq!(
            device_page_lines(url, "ABCD-1234", true),
            format!(
                "Opening browser to authorize...\nIf browser doesn't open, visit: {url}\nYour code: ABCD-1234\n"
            )
        );
    }

    #[test]
    fn the_title_names_the_provider_the_name_and_the_store() {
        assert_eq!(
            link_screen(
                SignInScreen::local("Claude (sign-in)", "n@example.com"),
                URL,
                ScreenCaps::PLAIN
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
            link_screen(SignInScreen::local("Codex", "work"), URL, ScreenCaps::PLAIN)
                .lines()
                .any(|line| line.trim() == URL)
        );
    }

    /// At a terminal the link is an OSC 8 hyperlink with the copy hint under
    /// it; piped, it is the plain URL with no hint and no escape sequence.
    #[test]
    fn the_link_is_clickable_with_the_copy_hint_only_at_a_terminal() {
        let screen = SignInScreen::local("Codex", "n@example.com");
        let terminal = ScreenCaps {
            link: true,
            keys: true,
        };
        assert_eq!(
            link_screen(screen, URL, terminal),
            format!(
                "Connect Codex as n@example.com, on this computer\n\n  First time? Turn on \"Enable device code authorization for Codex\" here:\n  {}\n\n  Open this link to sign in:\n  \x1b]8;;{URL}\x1b\\{URL}\x1b]8;;\x1b\\\n  Press c to copy the link\n",
                hyperlink(CODEX_DEVICE_SETTINGS)
            )
        );
        let piped = link_screen(screen, URL, ScreenCaps::PLAIN);
        assert!(!piped.contains('\x1b'), "{piped:?}");
        assert!(!piped.contains(COPY_HINT));
    }

    #[test]
    fn the_hyperlink_is_osc_8_around_the_url() {
        assert_eq!(
            hyperlink("https://example.test/a"),
            "\x1b]8;;https://example.test/a\x1b\\https://example.test/a\x1b]8;;\x1b\\"
        );
    }

    /// A link from a server is handed to the terminal only when it is a
    /// plain https link, or plain http to the loopback address (#5422).
    #[test]
    fn only_a_plain_https_or_loopback_http_link_becomes_a_hyperlink() {
        for unsafe_link in [
            "http://example.test/a",
            "http://127.0.0.1.example.com/device",
            "http://127.0.0.1@example.com/device",
            "http://user@127.0.0.1/device",
            "http://user:pass@127.0.0.1/device",
            "http://example.com/#127.0.0.1",
            "http://example.com/?next=http://127.0.0.1/",
            "http://192.168.1.10/device",
            "http://10.0.0.1:8080/device",
            "http://127.0.0.2/device",
            "http://2130706433/device",
            "http://0x7f.0.0.1/device",
            "http://0177.0.0.1/device",
            "http://127.1/device",
            "http://[0:0:0:0:0:0:0:1]/device",
            "http://[::ffff:127.0.0.1]/device",
            "http://127.0.0.1:080/device",
            "http://localhost/device",
            "http://localhost:8080/device",
            "HTTP://127.0.0.1/device",
            "http://127.0.0.1/device b",
            "http://127.0.0.1/\x1b]8;;https://evil.test\x1b\\",
            "javascript:alert(1)",
            "https://example.test/a\x1b]8;;https://evil.test\x1b\\",
            "https://example.test/a b",
            "https://example.test/\x07",
        ] {
            assert!(!safe_link(unsafe_link), "{unsafe_link:?}");
            assert_eq!(hyperlink(unsafe_link), unsafe_link);
        }
        for link in [
            "https://codewire-dev.sh/device?user_code=ABCD-1234",
            "http://127.0.0.1/device?user_code=ABCD-1234",
            "http://127.0.0.1:8080/device?user_code=ABCD-1234",
            "http://127.0.0.1",
            "http://[::1]/device",
            "http://[::1]:8080/device#code",
            "http://127.0.0.1:80/device",
        ] {
            assert!(safe_link(link), "{link:?}");
            assert!(hyperlink(link).starts_with("\x1b]8;;"), "{link:?}");
        }
    }

    /// Loopback is the only plain-http exception: the same link on any other
    /// host is still refused.
    #[test]
    fn plain_http_is_refused_everywhere_but_loopback() {
        assert!(safe_link("http://127.0.0.1:8080/device"));
        assert!(!safe_link("http://example.com/device"));
        assert!(!safe_link("http://example.com:8080/device"));
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
            connected_result(
                SignInScreen::local("Claude (sign-in)", "n@example.com"),
                "n@example.com",
                None,
            ),
            "Claude (sign-in) connected as n@example.com"
        );
        // 2027-11-15 00:00 UTC.
        assert_eq!(
            connected_result(
                SignInScreen::local("Claude (token)", "ci"),
                "ci",
                Some(1_826_236_800)
            ),
            "Claude (token) connected as ci · expires 15 Nov 2027"
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
